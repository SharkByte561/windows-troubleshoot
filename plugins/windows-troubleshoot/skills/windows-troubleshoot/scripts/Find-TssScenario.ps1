<#
.SYNOPSIS
Finds the TSS scenario, CollectLog, SDP report or component that fits a symptom. Reads the skill's tss-index.json only.

.DESCRIPTION
Scores every catalog entry against the words in the query (plus a small synonym map for everyday phrasing such as
"wifi", "printer", "locked out", "slow"). Returns the best matches with the exact command, a one-line "use when",
and the sentences of the TSS description that describe system changes (audit policy, registry, log size, reboots...),
so you can warn the user before anything runs. Nothing on the machine is touched.

.EXAMPLE
.\Find-TssScenario.ps1 "users keep getting locked out"
.\Find-TssScenario.ps1 "start menu doesn't open" -Kind scenario -Top 3
.\Find-TssScenario.ps1 -Name NET_DNScli          # full entry for one name
#>
[CmdletBinding(DefaultParameterSetName = 'Query')]
param(
    [Parameter(ParameterSetName = 'Query', Position = 0, Mandatory)] [string]$Query,
    [Parameter(ParameterSetName = 'Name', Mandatory)] [string]$Name,
    [ValidateSet('all', 'scenario', 'collectlog', 'sdp', 'component')] [string]$Kind = 'all',
    [int]$Top = 6,
    [switch]$IncludeDeprecated,
    [switch]$AsJson,
    [string]$IndexPath   # default: the skill's references\tss-index.json
)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$ErrorActionPreference = 'Stop'
# Set here, not in param(): Windows PowerShell 5.1 leaves $PSScriptRoot empty there
if (-not $IndexPath) { $IndexPath = Join-Path $PSScriptRoot '..\references\tss-index.json' }
# With -AsJson, notes go to stderr: Windows PowerShell 5.1 writes warnings into stdout, which breaks the JSON
function Write-Note([string]$msg) { if ($AsJson) { [Console]::Error.WriteLine("NOTE: $msg") } else { Write-Warning $msg } }
$index = Get-Content $IndexPath -Raw | ConvertFrom-Json
$all = @($index.scenarios) + @($index.collectLogs) + @($index.sdp) + @($index.components)

# TSS refuses to start 90 days after its build date. Prefer the version of the copy on disk over the indexed one.
if (-not $AsJson) {
    $tssRoot = & (Join-Path $PSScriptRoot 'Resolve-TssRoot.ps1')
    $ver = $index.tssVersion
    $tssPs1 = if ($tssRoot) { Join-Path $tssRoot 'TSS.ps1' }
    if ($tssPs1 -and (Test-Path $tssPs1)) {
        $m = Select-String -Path $tssPs1 -Pattern '\$global:TssVerDate\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { $ver = $m.Matches.Groups[1].Value }
    }
    if (-not $tssRoot) { Write-Host "No local TSS found - using the bundled catalog (TSS $ver). To get TSS: scripts\Update-Tss.ps1" -ForegroundColor DarkGray }
    elseif ($ver -match '^(\d{4}\.\d{2}\.\d{2})') {
        $expires = [datetime]::ParseExact($Matches[1], 'yyyy.MM.dd', $null).AddDays(90)
        $left = [int][math]::Floor(($expires - (Get-Date).Date).TotalDays)
        if ($ver -ne $index.tssVersion) { Write-Warning "Index is for TSS $($index.tssVersion) but $tssRoot has ${ver}: run Build-TssIndex.ps1." }
        if ($left -lt 0) { Write-Warning "TSS $ver expired on $($expires.ToString('yyyy-MM-dd')) and will refuse to run. Update: scripts\Update-Tss.ps1 (or .\TSS.ps1 -Update). One-off override: add -noExpire to the TSS command." }
        elseif ($left -le 14) { Write-Warning "TSS $ver expires in $left days ($($expires.ToString('yyyy-MM-dd'))). Update soon: scripts\Update-Tss.ps1 -CheckOnly." }
        else { Write-Host "TSS $ver - expires $($expires.ToString('yyyy-MM-dd')) ($left days left)" -ForegroundColor DarkGray }
    }
}

$sideEffectPattern = '(?i)\b(sets?|enables?|turns? on|turns? off|changes?|modif\w+|restart\w*|reboot\w*|not restored|does not restore|promiscuous|flush\w*|deletes?|bugcheck|crash\w*|registry|audit\w*|debug logging|resets?|stops? the|clears?)\b'
function Get-SideEffects([string]$text) {
    if (-not $text) { return @() }
    @(($text -split '(?<=[.;])\s+') | Where-Object { $_ -match $sideEffectPattern -and $_ -notmatch '^(Use when|Collects)' } | Select-Object -First 4)
}
function Format-Entry($e) {
    $use = ($e.description -split '(?<=\.)\s')[0]
    [pscustomobject]@{
        Kind = $e.kind; Name = $e.name; Pod = $e.pod; Category = $e.category; Score = $e.__score
        Command = $e.command
        UseWhen = $use
        Adds = (@($e.tools) -join ', ')
        SideEffects = (Get-SideEffects $e.description)
        Deprecated = $e.deprecated
        Description = $e.description
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Name') {
    $hits = $all | Where-Object { $_.name -eq $Name -or $_.name -like $Name }
    if (-not $hits) { Write-Note "No entry named '$Name'."; return }
    $out = $hits | ForEach-Object { $_ | Add-Member __score 100 -Force -PassThru } | ForEach-Object { Format-Entry $_ }
    if ($AsJson) { $out | ConvertTo-Json -Depth 4 } else { $out | Format-List Kind, Name, Pod, Category, Command, Adds, SideEffects, Description }
    return
}

# Everyday words -> TSS vocabulary. Keep entries short and obvious; the description text does the rest.
$synonyms = @{
    'locked' = 'lockout'; 'lockouts' = 'lockout'; 'lock' = 'lockout'; 'password' = 'auth kerberos ntlm'
    'login' = 'logon'; 'signin' = 'logon'; 'sign' = 'logon'; 'profile' = 'profile logon'
    'wifi' = 'wlan wireless'; 'wireless' = 'wlan'; 'ethernet' = 'lan 802dot1x'; 'internet' = 'ncsi proxy winsock'
    'share' = 'smb'; 'shares' = 'smb'; 'mapped' = 'smb'; 'drive' = 'smb'; 'unc' = 'smb unchard'
    'printer' = 'print'; 'printing' = 'print'; 'spooler' = 'print'
    'rdp' = 'rds rdscli remote desktop'; 'remote' = 'rds'; 'avd' = 'avd'; 'cloudpc' = 'w365'; 'w365' = 'w365'
    'slow' = 'slowness slow delays'; 'slowness' = 'slowness'; 'hang' = 'hangs unresponsive'; 'hangs' = 'hangs unresponsive'; 'freeze' = 'hangs unresponsive'
    'freezes' = 'hangs unresponsive'; 'frozen' = 'hangs unresponsive'; 'intermittent' = 'intermittent'; 'reboot' = 'bugcheck crash'; 'reboots' = 'bugcheck crash'; 'restarts' = 'bugcheck crash'; 'cpu' = 'highcpu'; 'memory' = 'leak memory'; 'leak' = 'leak'
    'boot' = 'boot'; 'startup' = 'boot'; 'bsod' = 'bugcheck crash'; 'bluescreen' = 'bugcheck crash'; 'crash' = 'crash bugcheck'
    'update' = 'servicing setup windows update'; 'updates' = 'servicing setup'; 'wsus' = 'servicing'; 'upgrade' = 'setup servicing'
    'activation' = 'activation licensing license setupreport sareport'; 'activate' = 'activation license setupreport'; 'license' = 'licensing activation setupreport'; 'kms' = 'activation license setupreport'; 'slmgr' = 'activation license setupreport'
    'gpo' = 'group policy gpo'; 'policy' = 'gpo'; 'gpupdate' = 'gpo'
    'cert' = 'certificate adcs pki'; 'certificate' = 'adcs pki ssl'; 'tls' = 'ssl schannel'
    'domain' = 'domain join'; 'join' = 'domain join'; 'replication' = 'replication'
    'start' = 'startmenu'; 'menu' = 'startmenu'; 'taskbar' = 'shell startmenu'; 'search' = 'search'
    'store' = 'store uwp'; 'apps' = 'uwp'; 'app' = 'uwp'; 'winget' = 'winget'; 'camera' = 'mediacamera'; 'photos' = 'photo'
    'clipboard' = 'clipboard'; 'black' = 'uwp shell logon'
    'dns' = 'dns dnscli'; 'dhcp' = 'dhcp dhcpcli'; 'vpn' = 'vpn ras'; 'firewall' = 'firewall wfp'; 'proxy' = 'proxy webio'
    'bluetooth' = 'bluetooth'; 'usb' = 'usb dnd'; 'audio' = 'audio'; 'sound' = 'audio'
    'hyper-v' = 'hyperv hyphost'; 'hyperv' = 'hyphost hypvm'; 'vm' = 'hypvm'; 'cluster' = 'cluster mscluster'
    'sql' = 'sql'; 'wmi' = 'wmi'; 'winrm' = 'winrm'; 'powershell' = 'powershell'; 'task' = 'tsched'; 'scheduled' = 'tsched'
    'applocker' = 'applocker'; 'laps' = 'winlaps'; 'fslogix' = 'fslogix'; 'teams' = 'teams'
}
$stop = 'a an the is are was were be my our i we it its to of in on for and or with not no keep keeps getting get got doesnt dont cant wont when after every some all from this that machine computer pc windows issue issues problem problems help please'.Split(' ')

$synonyms['bsod'] = 'bugcheck crash'; $synonyms['unexpectedreboot'] = 'bugcheck crash'

# Phrases become one token first, so "blue screen" can't match Bluetooth or ScreenSaver by name
$q = $Query.ToLower()
$phrases = [ordered]@{
    'blue\s*screens?(\s+of\s+death)?|green\s*screens?|bug\s*checks?|stop\s+(codes?|errors?)' = ' bsod '
    '\w*(irql_|page_fault_in|kmode_exception|system_service_exception|system_thread_exception|critical_process_died|memory_management|whea_uncorrectable|video_tdr|dpc_watchdog|clock_watchdog|kernel_security_check|inaccessible_boot_device|driver_power_state|unexpected_kernel_mode_trap|bad_pool_|ntfs_file_system)\w*' = ' bsod '
    '\b0x0{4,}[0-9a-f]{1,4}\b' = ' bsod '   # stop codes such as 0x0000007e (Windows Update codes have no leading zeros)
    'unexpected(ly)?\s+(shut\s*downs?|restarts?|reboots?|power\s*off)|kernel-power|event\s*(id\s*)?41\b|(random|spontaneous)(ly)?\s+(reboots?|restarts?|shut\s*downs?)|(reboots?|restarts?|shuts?\s+down)\s+(by\s+itself|on\s+its\s+own|randomly)' = ' unexpectedreboot '
}
foreach ($k in $phrases.Keys) { $q = $q -replace $k, $phrases[$k] }
$systemCrash = $q -match '\bbsod\b'
$unexpectedReboot = $q -match '\bunexpectedreboot\b'
$appCrash = -not ($systemCrash -or $unexpectedReboot) -and $q -match '\bcrash(es|ed|ing)?\b'

# TSS has no scenario that traces a blue screen or a reset, so say what does work instead of forcing a match
$guidance = @()
if ($systemCrash) {
    $guidance += 'TSS has no scenario that traces a blue screen. Blue screens are solved from the dump: run Invoke-QuickTriage.ps1 (it lists the bugchecks and minidumps), then open C:\Windows\Minidump\*.dmp or C:\Windows\MEMORY.DMP in WinDbg and run !analyze -v. If no dump is written, check the Startup and Recovery dump settings and the page file size.'
}
if ($unexpectedReboot) {
    $guidance += 'Unexpected restarts: run Invoke-QuickTriage.ps1 first. Kernel-Power 41 with a bugcheck (WER 1001) is a blue screen: analyze the dump. Kernel-Power 41 without one means Windows wrote no dump: suspect the power supply, overheating, firmware/BIOS or a hard hang. For sleep and power-plan data, see -Name DND_Power.'
}
if ($appCrash) {
    $guidance += 'If an application crashes, add -ProcDump <name.exe> -ProcDumpOption Both to the scenario for its area to capture the crash dump, and read the WER reports that Invoke-QuickTriage.ps1 lists.'
}
if ($guidance) {
    foreach ($g in $guidance) { if ($AsJson) { Write-Note $g } else { Write-Host $g -ForegroundColor Yellow } }
    if (-not $AsJson) { Write-Host '' }
}

$words = ($q -replace "[^a-z0-9_\-\s]", ' ' -split '\s+') | Where-Object { $_ -and $_ -notin $stop }
$terms = [System.Collections.Generic.List[string]]::new()
foreach ($w in $words) {
    $terms.Add($w)
    if ($synonyms.ContainsKey($w)) { $synonyms[$w].Split(' ') | ForEach-Object { $terms.Add($_) } }
}
# Error-code families -> areas (users often paste only the code)
$codeHints = [ordered]@{ '0xc004[cdef]' = 'activation license setupreport'; '0x8024|0x800f08|0x800f09|0x8007000d|0x80073712' = 'servicing wu setup'
    '0xc19|0x8007001f|0xc1900' = 'setup upgrade setupreport'; '0x80073c|0x80073d|0x80070490' = 'uwp store appx'; '0xc000006|0xc0000234' = 'auth lockout kerberos ntlm' }
foreach ($k in $codeHints.Keys) { if ($Query -match $k) { $codeHints[$k].Split(' ') | ForEach-Object { $terms.Add($_) } } }
$terms = $terms | Select-Object -Unique
# Niche product areas only rank when the query names them; otherwise their *_General scenarios crowd out Windows ones.
$niche = @{ CRM = 'crm|dynamics|iis'; SPS = 'sharepoint|sps'; INT = 'msmq|integration|queue'; MCM = 'sccm|configmgr|mecm|mcm' }
if (-not $terms) { throw 'Query had no searchable words.' }

$kindWeight = @{ scenario = 1.0; collectlog = 0.8; sdp = 0.9; component = 0.6 }
$scored = foreach ($e in $all) {
    if ($Kind -ne 'all' -and $e.kind -ne $Kind) { continue }
    if ($e.deprecated -and -not $IncludeDeprecated) { continue }
    if ($e.pod -eq 'DEV') { continue }
    $n = $e.name.ToLower(); $c = "$($e.category)".ToLower(); $d = "$($e.description)".ToLower()
    $score = 0.0
    foreach ($t in $terms) {
        if ($t.Length -lt 3) { continue }
        $esc = [regex]::Escape($t)
        if ($n -match $esc) { $score += 6 }
        if ($c -match $esc) { $score += 3 }
        $hits = [regex]::Matches($d, "\b$esc").Count
        if ($hits) { $score += [math]::Min(3, 1 + 0.5 * ($hits - 1)) }
        # The "Use when" sentence is the author's own intent statement; matches there count extra.
        $first = ($d -split '(?<=\.)\s')[0]
        if ($first -match "\b$esc") { $score += 1.5 }
    }
    if ($score -le 0) { continue }
    if ($niche.ContainsKey($e.pod) -and $Query -notmatch $niche[$e.pod]) { $score *= 0.3 }
    if ("$($e.recommended)" -match '^(yes|true)$') { $score += 1 }
    $e | Add-Member __score ([math]::Round($score * $kindWeight[$e.kind], 1)) -Force -PassThru
}
# Ties go to the shorter name (the base scenario, not its heavier "Ex" variant), so 5.1 and 7 rank the same
$out = @($scored | Sort-Object @{ Expression = '__score'; Descending = $true }, @{ Expression = { $_.name.Length } }, name | Select-Object -First $Top | ForEach-Object { Format-Entry $_ })
# For a blue screen or reset the guidance above is the answer; keep only scenarios that clearly fit something else in the query
if ($systemCrash -or $unexpectedReboot) { $out = @($out | Where-Object Score -ge 12); if (-not $out) { return } }
if (-not $out) { Write-Note "No match for '$Query'. Try other words, or -Kind component."; return }
if ($out[0].Score -lt 8) { Write-Note "Weak matches only (best score $($out[0].Score)). No scenario clearly fits: rephrase with the component (DNS, SMB, logon...), or rely on triage / dump analysis instead of a trace." }
if ($AsJson) { $out | Select-Object -ExcludeProperty Description | ConvertTo-Json -Depth 4 }
else { $out | Format-List Score, Kind, Name, Category, Command, UseWhen, Adds, SideEffects }
