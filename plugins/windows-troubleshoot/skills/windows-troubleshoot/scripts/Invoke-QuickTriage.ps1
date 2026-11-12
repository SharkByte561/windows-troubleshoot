<#
.SYNOPSIS
Read-only Windows health snapshot: system facts, recent errors, crashes, disks, services, updates, network basics.

.DESCRIPTION
Changes nothing on the machine: no registry writes, no service changes, no traces, no cache flushes. Works without
admin (a few checks, such as the Security log and the domain secure channel, are skipped when not elevated).
Network checks send a ping to the default gateway, a DNS lookup and one HTTP GET to Microsoft's connectivity-test
URL; use -NoNetworkTests to skip them.

Writes triage.json (full data) and triage.md (summary with "flags") to -OutDir and prints the summary path.

.EXAMPLE
.\Invoke-QuickTriage.ps1                       # last 72 hours
.\Invoke-QuickTriage.ps1 -Hours 24 -NoNetworkTests
#>
[CmdletBinding()]
param(
    [int]$Hours = 72,
    [string]$OutDir = (Join-Path $env:TEMP ("win-triage\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$NoNetworkTests,
    [int]$MaxEventGroups = 25
)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$ErrorActionPreference = 'Stop'
$OutDir = (New-Item -ItemType Directory -Force $OutDir).FullName
$since = (Get-Date).AddHours(-$Hours)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$result = [ordered]@{ collected = (Get-Date).ToString('s'); hours = $Hours; elevated = $isAdmin; sections = [ordered]@{}; errors = [ordered]@{} }
$flags = [System.Collections.Generic.List[object]]::new()
function Flag([string]$severity, [string]$area, [string]$text, [string]$hint) { $flags.Add([pscustomobject]@{ severity = $severity; area = $area; finding = $text; next = $hint }) }
function Section([string]$name, [scriptblock]$body) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { $result.sections[$name] = & $body } catch { $result.errors[$name] = $_.Exception.Message }
    Write-Verbose ("{0}: {1:n1}s" -f $name, $sw.Elapsed.TotalSeconds)
}
function Get-Events([string]$log, [int[]]$levels, [object[]]$ids, [string]$provider) {
    $filter = @{ LogName = $log; StartTime = $since }
    if ($levels) { $filter.Level = $levels }
    if ($ids) { $filter.Id = $ids }
    if ($provider) { $filter.ProviderName = $provider }
    try { @(Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw } }
}
function Short([string]$s, [int]$n = 240) { if (-not $s) { return '' }; $s = ($s -replace '\s+', ' ').Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) + '...' } else { $s } }

# --- System ---
Section 'system' {
    $os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS; $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $uptime = (Get-Date) - $os.LastBootUpTime
    if ($uptime.TotalDays -gt 30) { Flag 'info' 'system' ("Up {0:n0} days without a restart." -f $uptime.TotalDays) 'Pending updates and leaks accumulate; a restart is a cheap first test.' }
    $memPct = [math]::Round(100 * (1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize), 0)
    if ($memPct -ge 90) { Flag 'warn' 'performance' "Memory in use: $memPct%." 'Check top memory processes below; PRF_General for leaks.' }
    # Commit charge vs commit limit (RAM + page file): a machine can feel slow and fail allocations well before physical RAM looks full.
    $commitGB = [math]::Round(($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1MB, 1); $limitGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 1)
    $commitPct = if ($limitGB) { [math]::Round(100 * $commitGB / $limitGB, 0) } else { 0 }
    if ($commitPct -ge 90) { Flag 'warn' 'performance' "Commit charge $commitGB of $limitGB GB ($commitPct%) - near the commit limit." 'Too much allocated memory for RAM + page file: find the biggest committers (Private Bytes) in the process list; a growing one is a leak (PRF_General).' }
    elseif ($commitPct -ge 80) { Flag 'info' 'performance' "Commit charge $commitGB of $limitGB GB ($commitPct%)." 'High allocated memory; expect paging/compression under load.' }
    [ordered]@{
        computer = $env:COMPUTERNAME; os = $os.Caption; displayVersion = $cv.DisplayVersion
        build = "$($cv.CurrentBuild).$($cv.UBR)"; edition = $cv.EditionID; installDate = $os.InstallDate.ToString('s')
        lastBoot = $os.LastBootUpTime.ToString('s'); uptimeDays = [math]::Round($uptime.TotalDays, 1)
        commitGB = $commitGB; commitLimitGB = $limitGB; commitPct = $commitPct
        manufacturer = $cs.Manufacturer; model = $cs.Model; bios = "$($bios.SMBIOSBIOSVersion) ($($bios.ReleaseDate.ToString('yyyy-MM-dd')))"
        cpu = $cpu.Name.Trim(); cores = $cpu.NumberOfLogicalProcessors
        ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1); memoryInUsePct = $memPct
        domainJoined = $cs.PartOfDomain; domain = $cs.Domain; user = "$env:USERDOMAIN\$env:USERNAME"
    }
}

# --- Disks ---
Section 'disks' {
    $vols = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        $pct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { $null }
        if ($pct -ne $null -and ($pct -lt 10 -or $_.FreeSpace -lt 10GB)) {
            Flag $(if ($pct -lt 5) { 'high' } else { 'warn' }) 'disk' ("{0} has {1:n1} GB free ({2}%)." -f $_.DeviceID, ($_.FreeSpace / 1GB), $pct) 'Low space breaks updates, profiles and paging; free space before deeper tracing.'
        }
        [ordered]@{ drive = $_.DeviceID; label = $_.VolumeName; fs = $_.FileSystem; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1); freePct = $pct }
    }
    $phys = try { Get-PhysicalDisk | ForEach-Object { [ordered]@{ name = $_.FriendlyName; media = "$($_.MediaType)"; health = "$($_.HealthStatus)"; status = "$($_.OperationalStatus)" } } } catch { @() }
    foreach ($p in $phys) { if ($p.health -and $p.health -ne 'Healthy') { Flag 'high' 'disk' "Physical disk '$($p.name)' health: $($p.health) / $($p.status)." 'Back up first; then check SMART/vendor tools. Not a TSS problem.' } }
    [ordered]@{ volumes = @($vols); physical = @($phys) }
}

# --- Pending reboot (registry reads only) ---
Section 'pendingReboot' {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'CBS RebootPending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update RebootRequired' }
    $pfr = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfr) { $reasons += "PendingFileRenameOperations ($(@($pfr).Count) entries)" }
    # PendingFileRenameOperations alone is often permanently non-empty (installers, AV), so it only rates 'info'.
    if ($reasons) { Flag $(if ($reasons -match '^(CBS|Windows Update)') { 'warn' } else { 'info' }) 'servicing' ("Reboot pending: " + ($reasons -join ', ') + '.') 'Restart before collecting data; many update/setup symptoms clear after the pending reboot.' }
    [ordered]@{ pending = [bool]$reasons; reasons = $reasons }
}

# --- Crashes, unexpected shutdowns, hardware errors ---
Section 'stability' {
    $kp = Get-Events 'System' -ids 41 -provider 'Microsoft-Windows-Kernel-Power'
    $dirty = Get-Events 'System' -ids 6008
    $bug = Get-Events 'System' -ids 1001 -provider 'Microsoft-Windows-WER-SystemErrorReporting'
    $whea = Get-Events 'System' -provider 'Microsoft-Windows-WHEA-Logger'
    $diskErr = Get-Events 'System' -levels 1, 2, 3 -ids 7, 11, 50, 51, 129, 140, 153, 157, 55, 98
    $appCrash = @(Get-Events 'Application' -ids 1000 -provider 'Application Error') + @(Get-Events 'Application' -ids 1002 -provider 'Application Hang')
    if ($bug) { Flag 'high' 'stability' "$($bug.Count) bugcheck(s) (blue screens) since $($since.ToString('g')). Latest: $(Short $bug[0].Message 160)" 'Analyze C:\Windows\Minidump / MEMORY.DMP with WinDbg (!analyze -v); the bugcheck code and faulting driver usually name the culprit. Do not use TSS -Crash.' }
    elseif ($kp) { Flag 'high' 'stability' "$($kp.Count) unexpected power loss/reset(s) (Kernel-Power 41)." 'No bugcheck recorded: think power supply, firmware/BIOS, overheating, or a hard hang (check dump settings in CrashControl). Not a TSS trace problem at first.' }
    if ($whea) { Flag 'high' 'hardware' "$($whea.Count) WHEA hardware error event(s)." 'Hardware/firmware (CPU, memory, PCIe). Update BIOS/drivers; vendor diagnostics.' }
    # Name the drive behind each storage event: "31 storage events" alone doesn't say which disk is failing
    $storage = @()
    if ($diskErr) {
        $letterByDevice = @{}; $diskByLetter = @{}; $lettersByDisk = @{}; $diskName = @{}
        try {
            if (-not ('TriageNative.Dos' -as [type])) { Add-Type -Namespace TriageNative -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern uint QueryDosDevice(string name, System.Text.StringBuilder target, int max);' }
            foreach ($v in Get-CimInstance Win32_LogicalDisk) {
                $sb = New-Object System.Text.StringBuilder 1024
                if ([TriageNative.Dos]::QueryDosDevice($v.DeviceID, $sb, 1024)) { $letterByDevice[($sb.ToString() -replace '^\\Device\\', '')] = $v.DeviceID }
            }
        } catch { }
        try {
            foreach ($p in Get-Partition | Where-Object DriveLetter) { $l = "$($p.DriveLetter):"; $diskByLetter[$l] = [int]$p.DiskNumber; $lettersByDisk[[int]$p.DiskNumber] = @($lettersByDisk[[int]$p.DiskNumber]) + $l | Where-Object { $_ } }
            foreach ($d in Get-Disk) { $diskName[[int]$d.Number] = "$($d.FriendlyName), $($d.BusType)" }
        } catch { }
        # Windows renumbers HarddiskVolumeN at every boot (and when a USB drive reconnects), so only map events since the last boot
        $boot = try { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } catch { Get-Date }
        # For a volume we can't map, the file paths in its events often identify the drive: find their top folder on today's drives.
        # One hint per volume, so its events stay in one group. NTFS metadata ($Mft, $LogFile) exists on every volume and is skipped.
        $localLetters = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2 or DriveType=3' | ForEach-Object DeviceID)
        $devHint = @{}
        foreach ($e in $diskErr) {
            if ($e.Message -match '\\Device\\(HarddiskVolume\d+)\\([^\\\s$][^\\\s]*)\\' -and -not $devHint.ContainsKey($Matches[1])) {
                $dev = $Matches[1]; $top = $Matches[2]
                $hits = @($localLetters | Where-Object { Test-Path -LiteralPath "$_\$top" })
                $devHint[$dev] = if ($hits.Count -eq 1) { "; files under \$top\, probably $($hits[0]), the only drive with that folder now" } else { "; files under \$top\" }
            }
        }
        $storage = @($diskErr | ForEach-Object {
                $m = $_.Message; $letter = $null; $disk = $null
                if ($m -match 'VolumeId:\s*([A-Z]:)') { $letter = $Matches[1] }
                elseif ($m -match '\\Device\\(HarddiskVolume\d+)') {
                    $dev = $Matches[1]
                    if ($_.TimeCreated -ge $boot) { $letter = $letterByDevice[$dev] }
                    if (-not $letter) { $letter = "$dev (" + $(if ($_.TimeCreated -lt $boot) { 'before the last restart' } else { 'no longer mounted' }) + "$($devHint[$dev]))" }
                }
                elseif ($m -match '\\Device\\Harddisk(\d+)\\') { $disk = [int]$Matches[1] }
                elseif ($m -match '\bDisk (\d+)\b') { $disk = [int]$Matches[1] }
                if ($letter -and $diskByLetter.ContainsKey($letter)) { $disk = $diskByLetter[$letter] }
                $target = if ($null -ne $disk) {
                    $parts = @(); if ($diskName.ContainsKey($disk)) { $parts += $diskName[$disk] }; if ($lettersByDisk[$disk]) { $parts += ($lettersByDisk[$disk] -join ' ') }
                    "disk $disk" + $(if ($parts) { " ($($parts -join ', '))" })
                } elseif ($letter) { $letter } else { 'unknown disk' }
                [pscustomobject]@{ target = $target; letters = @($(if ($null -ne $disk) { $lettersByDisk[$disk] } elseif ($letter -match '^[A-Z]:$') { $letter })); event = "$($_.ProviderName -replace '^Microsoft-Windows-', '') $($_.Id)" }
            } | Group-Object target | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | ForEach-Object {
                [ordered]@{ target = $_.Name; count = $_.Count; letters = @($_.Group[0].letters | Where-Object { $_ }); events = (($_.Group | Group-Object event | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ') }
            })
        $where = ($storage | ForEach-Object { "$($_.target) x$($_.count) [$($_.events)]" }) -join '; '
        Flag 'warn' 'disk' "$($diskErr.Count) storage error/warning event(s): $where." 'On external USB drives (disk 157 surprise removal, disk 153 retried I/O, Ntfs 50/140 delayed write or failed flush) suspect cable, hub, USB selective suspend or drive firmware. Back up that drive first; chkdsk <X:> /scan is a read-only scan.'
    }
    $badLetters = @($storage | ForEach-Object { $_.letters } | Where-Object { $_ })
    # Application Error 1000: Properties[6] = exception code, [10] = application path
    $crashGroups = $appCrash | Group-Object { $kind = if ($_.Id -eq 1000) { 'crash' } else { 'hang' }; "${kind}: $($_.Properties[0].Value)" } | Sort-Object Count -Descending | Select-Object -First 10 |
        ForEach-Object {
            $first = $_.Group[0]
            $path = if ($first.Id -eq 1000) { [string]$first.Properties[10].Value } else { $null }
            $codes = @($_.Group | Where-Object Id -eq 1000 | ForEach-Object { [string]$_.Properties[6].Value } | Select-Object -Unique)
            [ordered]@{ app = $_.Name; count = $_.Count; latest = $first.TimeCreated.ToString('s'); path = $path; exceptionCodes = $codes; sample = Short $first.Message 300 }
        }
    foreach ($g in $crashGroups | Where-Object { $_.count -ge 3 }) { Flag 'warn' 'apps' "$($g.app) x$($g.count)." 'Faulting module in the sample tells you whether it is the app, a plugin, or a system DLL. PRF_UWP for Store/inbox apps; -ProcDump for a specific exe.' }
    # A crash that runs from a drive with storage errors, or dies with an in-page I/O error, is a disk problem, not an app bug
    foreach ($g in $crashGroups) {
        $onBad = $g.path -and $g.path -match '^([A-Za-z]:)' -and ($badLetters -contains $Matches[1].ToUpper())
        $inPage = $g.exceptionCodes -match '^(0x)?c0000006$'
        if ($onBad -or $inPage) {
            $why = @(); if ($onBad) { $why += "runs from $($g.path.Substring(0, 2)), the drive with storage errors" }; if ($inPage) { $why += 'exception c0000006 (in-page I/O error: Windows could not read the program from disk)' }
            Flag 'high' 'disk' "$($g.app) x$($g.count) $($why -join '; ')." 'Treat the drive, not the app: back it up, check the cable/hub, and move the app to an internal disk if the drive keeps dropping.'
        }
    }
    $dumps = @(Get-ChildItem "$env:SystemRoot\Minidump" -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) $($_.LastWriteTime.ToString('s'))" })
    [ordered]@{
        bugchecks = @($bug | Select-Object -First 5 | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); message = Short $_.Message 400 } })
        kernelPower41 = @($kp | Select-Object -First 10 | ForEach-Object { $_.TimeCreated.ToString('s') })
        unexpectedShutdown6008 = $dirty.Count; whea = $whea.Count; storageEvents = $diskErr.Count
        appCrashes = @($crashGroups); minidumps = $dumps
    }
}

# --- Error/critical events, grouped ---
Section 'events' {
    $out = [ordered]@{}
    foreach ($log in 'System', 'Application') {
        $ev = Get-Events $log -levels 1, 2
        $out[$log] = @($ev | Group-Object ProviderName, Id | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | Select-Object -First $MaxEventGroups | ForEach-Object {
            $f = $_.Group[0]
            # For crash/hang events the total mixes several apps; break it down so "x7" isn't read as one app crashing 7 times
            # (1000/1002 only: other IDs from these providers, such as 1005, carry no app name in Properties[0])
            $byApp = if ($f.ProviderName -in 'Application Error', 'Application Hang' -and $f.Id -in 1000, 1002) { ($_.Group | Group-Object { [string]$_.Properties[0].Value } | Where-Object Name | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ' }
            [ordered]@{ provider = $f.ProviderName; id = $f.Id; level = $f.LevelDisplayName; count = $_.Count; byApp = $byApp; first = $_.Group[-1].TimeCreated.ToString('s'); latest = $f.TimeCreated.ToString('s'); message = Short $f.Message }
        })
        foreach ($g in $out[$log] | Where-Object { $_.count -ge 50 }) { Flag 'warn' 'events' "$log $($g.provider) $($g.id) logged $($g.count)x." (Short $g.message 140) }
    }
    if ($isAdmin) {
        $fail = Get-Events 'Security' -ids 4625, 4740
        $out['SecurityFailedLogons4625'] = @($fail | Where-Object Id -eq 4625).Count
        $out['SecurityLockouts4740'] = @($fail | Where-Object Id -eq 4740 | Select-Object -First 10 | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); account = $_.Properties[0].Value; caller = $_.Properties[1].Value } })
        if ($out['SecurityLockouts4740']) { Flag 'warn' 'auth' "$(@($out['SecurityLockouts4740']).Count) account lockout(s) (4740) on this machine." 'The caller computer field shows the source; ADS_AccountLockout on the DC if it is not obvious.' }
    } else { $out['Security'] = 'skipped (not elevated)' }
    $out
}

# --- Services ---
Section 'services' {
    # Auto-start services that are stopped. Delayed/trigger services that stop by design are common, so this is a lead, not a verdict.
    $ignore = 'gupdate|edgeupdate|MapsBroker|RemoteRegistry|sppsvc|wuauserv|BITS|TrustedInstaller|UsoSvc|WbioSrvc|tiledatamodelsvc|ShellHWDetection|CDPSvc|clr_optimization|GoogleUpdater|MozillaMaintenance|WMPNetworkSvc|DoSvc|AGMService'
    $stopped = Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" | Where-Object { $_.Name -notmatch $ignore } |
        ForEach-Object { [ordered]@{ name = $_.Name; display = $_.DisplayName; state = $_.State; exitCode = $_.ExitCode; account = $_.StartName } }
    $core = 'Dnscache', 'Dhcp', 'LanmanWorkstation', 'EventLog', 'RpcSs', 'Winmgmt', 'Spooler', 'W32Time', 'NlaSvc', 'BFE', 'mpssvc', 'CryptSvc', 'ProfSvc', 'Schedule'
    foreach ($s in $stopped | Where-Object { $_.name -in $core }) { Flag 'high' 'services' "Core service $($s.name) ($($s.display)) is $($s.state), exit code $($s.exitCode)." 'Check System log 7000-7043 for why it failed to start.' }
    $scm = Get-Events 'System' -ids 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034 -provider 'Service Control Manager'
    [ordered]@{
        autoNotRunning = @($stopped)
        scmFailures = @($scm | Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [ordered]@{ service = $_.Name; count = $_.Count; latest = $_.Group[0].TimeCreated.ToString('s'); message = Short $_.Group[0].Message 200 } })
    }
}

# --- Top processes ---
Section 'processes' {
    $p = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
    $cores = [Environment]::ProcessorCount
    $sample1 = @{}; $p | ForEach-Object { try { $sample1[$_.Id] = $_.TotalProcessorTime.TotalMilliseconds } catch {} }
    Start-Sleep -Milliseconds 1500
    $cpuAll = @(Get-Process | Where-Object { $sample1.ContainsKey($_.Id) } | ForEach-Object {
            try { [pscustomobject]@{ name = $_.ProcessName; pid = $_.Id; cpuPct = [math]::Round(($_.TotalProcessorTime.TotalMilliseconds - $sample1[$_.Id]) / 15 / $cores, 1) } } catch {}
        })
    $nowByPid = @{}; foreach ($c in $cpuAll) { $nowByPid[$c.pid] = $c.cpuPct }
    $cpu = $cpuAll | Sort-Object cpuPct -Descending | Select-Object -First 8
    foreach ($c in $cpu | Where-Object { $_.cpuPct -ge 50 }) { Flag 'warn' 'performance' "$($c.name) (PID $($c.pid)) using ~$($c.cpuPct)% of total CPU right now." $(if ($c.name -match 'WmiPrvSE') { 'UEX_WMIHighCPU' } else { 'PRF_HighCPU / -WPR CPU while it is high.' }) }
    # Cumulative CPU since each process started: catches steady hogs that a 1.5 s sample misses.
    $cumulative = $p | ForEach-Object { try { $age = ((Get-Date) - $_.StartTime).TotalSeconds; if ($age -gt 600) { [pscustomobject]@{ name = $_.ProcessName; pid = $_.Id; runningHours = [math]::Round($age / 3600, 1); cpuSeconds = [math]::Round($_.TotalProcessorTime.TotalSeconds); avgPctOfOneCore = [math]::Round(100 * $_.TotalProcessorTime.TotalSeconds / $age, 1); avgPctOfTotal = [math]::Round(100 * $_.TotalProcessorTime.TotalSeconds / $age / $cores, 1); nowPctOfTotal = $nowByPid[$_.Id] } } } catch {} } | Sort-Object avgPctOfOneCore -Descending | Select-Object -First 8
    # An average since start can't tell steady load from bursts, so the flag also shows the live sample taken above
    foreach ($c in $cumulative | Where-Object { $_.avgPctOfOneCore -ge 50 -and $_.name -notin 'System', 'Idle', 'Registry', 'MemCompression' }) {
        $now = if ($null -ne $c.nowPctOfTotal) { "; in the 1.5 s sample just now: $($c.nowPctOfTotal)% of total" } else { '' }
        $shape = if ($null -eq $c.nowPctOfTotal) { 'Watch it in Task Manager to see whether the load is steady or comes in bursts.' }
            elseif ($c.nowPctOfTotal -ge $c.avgPctOfTotal / 2) { 'Busy now as well, so the load looks steady.' }
            else { 'Quiet right now, so the load comes in bursts (sync, scans, indexing). Rerun triage or watch Task Manager to catch a burst.' }
        Flag 'warn' 'performance' "$($c.name) (PID $($c.pid)) averaged ~$($c.avgPctOfOneCore)% of one core over its $($c.runningHours) h run (~$($c.avgPctOfTotal)% of total CPU on $cores logical processors)$now." "$shape Identify the product (sync client, AV scan, indexer, audio enhancement) and update, pause or reconfigure it."
    }
    $procCount = $p.Count
    if ($procCount -gt 600) { Flag 'info' 'performance' "$procCount processes running." ('Most common: ' + (($p | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ') + '. Leftover helper processes add memory and handle pressure.') }
    $mem = $p | Sort-Object WorkingSet64 -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ name = $_.ProcessName; pid = $_.Id; workingSetMB = [math]::Round($_.WorkingSet64 / 1MB); handles = $_.HandleCount } }
    [ordered]@{ processCount = $procCount; topCpu = @($cpu); topCpuSinceStart = @($cumulative); topMemory = @($mem); handleHogs = @($p | Where-Object HandleCount -gt 20000 | ForEach-Object { "$($_.ProcessName) ($($_.Id)): $($_.HandleCount) handles" }) }
}

# --- Updates ---
Section 'updates' {
    $hf = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 8 | ForEach-Object { [ordered]@{ id = $_.HotFixID; type = $_.Description; installed = $_.InstalledOn.ToString('yyyy-MM-dd') } }
    $wuFail = Get-Events 'System' -ids 20 -provider 'Microsoft-Windows-WindowsUpdateClient'
    $fails = @($wuFail | Select-Object -First 8 | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); message = Short $_.Message 220 } })
    # Store app updates (package IDs like 9NKSQGP7F2NH-...) failing with 0x80073D02 just mean the app was open: not a Windows Update problem.
    $osFails = @($wuFail | Where-Object { $_.Message -notmatch '\b9[A-Z0-9]{11}-|\b0x80073D02\b' })
    if ($wuFail.Count -gt $osFails.Count) { Flag 'info' 'apps' "$($wuFail.Count - $osFails.Count) Store app update(s) failed (usually 0x80073D02 = app was running)." 'Usually harmless; close the app and retry from the Store.' }
    $wuFail = $osFails
    if ($wuFail) { Flag 'warn' 'servicing' "$($wuFail.Count) Windows Update install failure(s). Latest: $(Short $wuFail[0].Message 140)" 'Look up the 0x code; DND_Servicing scenario or -CollectLog DND_SetupReport.' }
    $latest = $hf | Select-Object -First 1
    if ($latest -and ((Get-Date) - [datetime]$latest.installed).TotalDays -gt 60) { Flag 'warn' 'servicing' "Newest installed update is from $($latest.installed)." 'Machine may be behind on patches; check WU/WSUS/Intune policy.' }
    [ordered]@{ recentHotfixes = @($hf); installFailures = $fails }
}

# --- Network ---
Section 'network' {
    $cfg = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
        [ordered]@{ alias = $_.InterfaceAlias; description = $_.InterfaceDescription; ipv4 = @($_.IPv4Address.IPAddress); gateway = @($_.IPv4DefaultGateway.NextHop); dns = @($_.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object ServerAddresses); profile = "$($_.NetProfile.NetworkCategory)"; ncsi = "$($_.NetProfile.IPv4Connectivity)" }
    }
    foreach ($c in $cfg) { foreach ($ip in $c.ipv4) { if ($ip -like '169.254.*') { Flag 'high' 'network' "$($c.alias) has an APIPA address ($ip): DHCP did not answer." 'NET_DHCPcli; check cable/Wi-Fi/VLAN and the DHCP server.' } } }
    $winhttp = (netsh winhttp show proxy) -join ' ' -replace '\s+', ' '
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $tests = [ordered]@{}
    if (-not $NoNetworkTests) {
        $gw = ($cfg | ForEach-Object { $_.gateway } | Where-Object { $_ } | Select-Object -First 1)
        # .NET Ping, not Test-Connection: its -TargetName/-TimeoutSeconds exist only in PowerShell 7
        if ($gw) {
            $tests.gatewayPing = $false
            $ping = New-Object System.Net.NetworkInformation.Ping
            foreach ($i in 1..2) { try { if ($ping.Send($gw, 2000).Status -eq 'Success') { $tests.gatewayPing = $true; break } } catch { } }
        }
        try { $tests.dnsLookup = (Resolve-DnsName www.msftconnecttest.com -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1).IPAddress } catch { $tests.dnsLookup = "FAILED: $($_.Exception.Message)" }
        try { $r = Invoke-WebRequest 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 8; $tests.http = "$($r.StatusCode) $($r.Content.Trim())" } catch { $tests.http = "FAILED: $($_.Exception.Message)" }
        if ($tests.Contains('gatewayPing') -and -not $tests.gatewayPing) { Flag 'warn' 'network' "Default gateway $gw did not answer ping." 'Some gateways block ICMP; if DNS/HTTP also fail, it is local connectivity (NET_WinSock / NET_WLAN).' }
        if ("$($tests.dnsLookup)" -like 'FAILED*') { Flag 'high' 'network' "DNS lookup failed: $($tests.dnsLookup)" 'NET_DNScli; check DNS servers listed above, VPN/NRPT.' }
        elseif ("$($tests.http)" -like 'FAILED*') { Flag 'warn' 'network' "DNS works but HTTP test failed: $($tests.http)" 'Proxy/firewall/TLS inspection. NET_Proxy or NET_WebIO.' }
    }
    [ordered]@{ adapters = @($cfg); winhttpProxy = $winhttp; userProxy = [ordered]@{ enabled = [bool]$ie.ProxyEnable; server = $ie.ProxyServer; autoConfig = $ie.AutoConfigURL }; tests = $tests }
}

# --- Domain / identity ---
Section 'identity' {
    $o = [ordered]@{}
    $o.dsreg = ((dsregcmd /status) | Select-String 'AzureAdJoined|DomainJoined|EnterpriseJoined|WorkplaceJoined|DeviceAuthStatus|TenantName|AzureAdPrt ' | ForEach-Object { ($_.Line -replace '\s+', ' ').Trim() })
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        if ($isAdmin) {
            try { $o.secureChannel = Test-ComputerSecureChannel } catch { $o.secureChannel = "error: $($_.Exception.Message)" }
            if ($o.secureChannel -eq $false) { Flag 'high' 'auth' 'Domain secure channel is broken.' 'Test-ComputerSecureChannel -Repair (with consent) or rejoin; ADS_AuthEx if it keeps breaking.' }
        } else { $o.secureChannel = 'skipped (not elevated)' }
        $o.gpoErrors = @(Get-Events 'System' -levels 1, 2 -provider 'Microsoft-Windows-GroupPolicy' | Select-Object -First 5 | ForEach-Object { [ordered]@{ time = $_.TimeCreated.ToString('s'); id = $_.Id; message = Short $_.Message 200 } })
        if ($o.gpoErrors) { Flag 'warn' 'gpo' "$($o.gpoErrors.Count)+ Group Policy errors." 'gpresult /h for details; ADS_GPOEx scenario.' }
    }
    $t = Get-Events 'System' -levels 2, 3 -provider 'Microsoft-Windows-Time-Service'
    if ($t.Count -ge 3) { Flag 'warn' 'time' "$($t.Count) time-service warnings/errors." 'Clock skew > 5 min breaks Kerberos; w32tm /query /status.' }
    $o
}

# --- Security products ---
Section 'security' {
    $av = try { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { @('n/a (server SKU or no SecurityCenter2)') }
    $mp = try { Get-MpComputerStatus -ErrorAction Stop } catch { $null }
    if ($mp -and -not $mp.RealTimeProtectionEnabled -and $av.Count -le 1) { Flag 'warn' 'security' 'Defender real-time protection is off and no other AV is registered.' 'Confirm this is intended.' }
    [ordered]@{ antivirus = $av; defender = if ($mp) { [ordered]@{ realTime = $mp.RealTimeProtectionEnabled; signatureAgeDays = $mp.AntivirusSignatureAge; engine = $mp.AMEngineVersion } } else { $null } }
}

# --- Write output ---
$order = @{ high = 0; warn = 1; info = 2 }
$result.flags = @($flags | Sort-Object { $order[$_.severity] })
$jsonPath = Join-Path $OutDir 'triage.json'
$result | ConvertTo-Json -Depth 8 | Set-Content $jsonPath -Encoding utf8

$s = $result.sections.system
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# Quick triage: $($s.computer)  ($($result.collected))")
[void]$md.AppendLine('')
[void]$md.AppendLine("$($s.os) $($s.displayVersion), build $($s.build) · $($s.manufacturer) $($s.model) · $($s.ramGB) GB RAM · up $($s.uptimeDays) days · window: last $Hours h · elevated: $isAdmin")
[void]$md.AppendLine('')
[void]$md.AppendLine('## Flags'); [void]$md.AppendLine('')
if ($result.flags) {
    [void]$md.AppendLine('| Severity | Area | Finding | Next |'); [void]$md.AppendLine('|---|---|---|---|')
    foreach ($f in $result.flags) { [void]$md.AppendLine("| $($f.severity) | $($f.area) | $($f.finding -replace '\|','/') | $($f.next -replace '\|','/') |") }
} else { [void]$md.AppendLine('No automatic flags. Read the event groups below against the user''s symptom.') }
foreach ($log in 'System', 'Application') {
    [void]$md.AppendLine(''); [void]$md.AppendLine("## Top $log errors"); [void]$md.AppendLine('')
    foreach ($g in @($result.sections.events.$log) | Select-Object -First 10) {
        $split = if ($g.byApp) { " ($($g.byApp))" } else { '' }
        [void]$md.AppendLine("- **$($g.provider) $($g.id)** x$($g.count) in total$split. Latest, $($g.latest): $(Short $g.message 180)")
    }
}
if ($result.errors.Count) { [void]$md.AppendLine(''); [void]$md.AppendLine('## Sections that failed'); foreach ($k in $result.errors.Keys) { [void]$md.AppendLine("- $($k): $($result.errors[$k])") } }
[void]$md.AppendLine(''); [void]$md.AppendLine('Full data: `triage.json`, next to this file.')
$mdPath = Join-Path $OutDir 'triage.md'
$md.ToString() | Set-Content $mdPath -Encoding utf8
Write-Output "Triage written: $mdPath"
Write-Output ("Flags: {0} high, {1} warn, {2} info" -f @($flags | Where-Object severity -eq 'high').Count, @($flags | Where-Object severity -eq 'warn').Count, @($flags | Where-Object severity -eq 'info').Count)
