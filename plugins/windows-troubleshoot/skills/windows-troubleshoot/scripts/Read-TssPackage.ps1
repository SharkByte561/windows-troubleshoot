<#
.SYNOPSIS
Summarizes a collected TSS / MS_DATA package (zip or folder) without running anything from it.

.DESCRIPTION
Offline analysis of the data TSS already collected, on any machine:
  * inventory: what kinds of data are inside, sizes, and which files are sensitive (dumps, packet captures,
    Security log, ProcMon, PSR/video) so they can be reviewed before sharing
  * package metadata: computer, timestamp and scenario from the TSS_<computer>_<yyMMdd-HHmmss>_<scenario> folder name,
    OS build, TSS's own warning/error log
  * xray: the known issues xray reported during collection (xray_ISSUES-FOUND_*.txt, xray_report_*.xml)
  * event logs: every exported *.evtx, errors/criticals grouped by provider+ID, plus key stability/auth/update IDs
  * text logs: the most frequent 0x error codes and failure lines in *.txt/*.log (setupact, CBS, WU, TSS command output)
ETL/pcap/ProcMon/BLG/dump files are listed but not decoded; see references/package-anatomy.md for the right tool.

The input is only read. A zip is extracted to -ExtractDir (default %TEMP%\tssx\<id>: kept short because TSS file names are long and Get-WinEvent fails past MAX_PATH); the package itself is not modified. Summaries go to -OutDir.

.EXAMPLE
.\Read-TssPackage.ps1 C:\MS_DATA\TSS_PC01_261107-101500_NET_DNScli.zip
.\Read-TssPackage.ps1 D:\cases\1234\TSS_PC01_261107-101500_NET_DNScli -OutDir D:\cases\1234\analysis
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)] [string]$Path,
    [string]$OutDir,
    [string]$ExtractDir,   # where a zip is unpacked (and over-long .evtx copied); keep it short, e.g. C:\cases\x
    [int]$MaxEventsPerLog = 20000,
    [int]$MaxTextFileMB = 50
)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $Path
if (-not $OutDir) { $OutDir = Join-Path $env:TEMP ("tss-analysis\" + [IO.Path]::GetFileNameWithoutExtension($item.Name)) }
# Windows PowerShell 5.1 can't use paths over 260 characters, and TSS file names are long. Fail now, not after the analysis.
if ($PSVersionTable.PSEdition -ne 'Core') {
    $full = [IO.Path]::GetFullPath($OutDir)
    if ($full.Length -gt 200) { throw "-OutDir is $($full.Length) characters, too long for Windows PowerShell 5.1. Use a short folder such as C:\cases\x." }
    if ($ExtractDir -and [IO.Path]::GetFullPath($ExtractDir).Length -gt 80) { throw "-ExtractDir must stay under 80 characters on Windows PowerShell 5.1 (TSS file names are long). Use something like C:\cases\x, or leave it out to use %TEMP%\tssx." }
}
$OutDir = (New-Item -ItemType Directory -Force $OutDir).FullName
# Summaries get pasted into tickets and chats, so personal identifiers in quoted event text are masked.
# The sensitive-files section still counts them, from the raw text.
function Redact([string]$s) {
    $s = $s -replace '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<e-mail>'
    $s = $s -replace '\bS-1-5-21-[0-9-]+', '<SID>'
    $s = $s -replace '\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<MAC>'
    $s -replace '(?i)\b([A-Z]:\\Users\\)(?!(?:Public|Default|All Users)\\)[^\\\s"]+', '$1<user>'
}
function Short([string]$s, [int]$n = 240) { if (-not $s) { return '' }; $s = (Redact ($s -replace '\s+', ' ')).Trim(); if ($s.Length -gt $n) { $s.Substring(0, $n) + '...' } else { $s } }

# --- Resolve input ---
if ($item.PSIsContainer) { $root = $item.FullName }
elseif ($item.Extension -eq '.zip') {
    # Extract to a short path: TSS file names are long, and Get-WinEvent cannot open .evtx files past MAX_PATH (260).
    $hash = [BitConverter]::ToString([Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($item.FullName))).Replace('-', '').Substring(0, 8)
    $root = if ($ExtractDir) { $ExtractDir } else { Join-Path $env:TEMP "tssx\$hash" }
    if (-not (Test-Path $root) -or -not (Get-ChildItem $root -Recurse -File | Select-Object -First 1)) {
        Write-Host "Extracting $($item.Name) ($([math]::Round($item.Length/1MB,1)) MB) to $root"
        try { Expand-Archive -LiteralPath $item.FullName -DestinationPath $root -Force }
        catch {
            # Remove the partial copy, or the next run would skip extraction and analyze an incomplete tree
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            throw "Extracting $($item.Name) to $root failed: $($_.Exception.Message) Try a shorter -ExtractDir."
        }
    }
    # Nested zips (TSS sometimes zips sub-collections such as SDP output); expand next to themselves, one level.
    foreach ($z in Get-ChildItem $root -Recurse -Filter *.zip) {
        $dest = Join-Path $z.DirectoryName ($z.BaseName + '_unzipped')
        if (-not (Test-Path $dest)) { try { Expand-Archive -LiteralPath $z.FullName -DestinationPath $dest -Force } catch { Write-Warning "Could not expand $($z.Name): $($_.Exception.Message)" } }
    }
} else { throw "Expected a .zip or a folder: $Path" }

$files = @(Get-ChildItem $root -Recurse -File)
$summary = [ordered]@{ source = $item.FullName; root = $root; analyzed = (Get-Date).ToString('s'); fileCount = $files.Count; totalMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1) }

# --- Metadata from folder/file naming ---
$tssDir = Get-ChildItem $root -Recurse -Directory -Filter 'TSS_*' | Select-Object -First 1
$nameSource = if ($tssDir) { $tssDir.Name } elseif ($item.BaseName -like 'TSS_*') { $item.BaseName } else { $null }
$meta = [ordered]@{}
if ($nameSource -match '^TSS_(?<pc>[^_]+)_(?<ts>\d{6}-\d{6})_?(?<scn>.*)$') {
    $meta.computer = $Matches.pc; $meta.scenario = ($Matches.scn.Trim('_'))
    $meta.collected = try { [datetime]::ParseExact($Matches.ts, 'yyMMdd-HHmmss', $null).ToString('s') } catch { $Matches.ts }
}
$osv = $files | Where-Object Name -match 'OSVersion-Build\.txt$' | Select-Object -First 1
if ($osv) { $meta.osVersion = Short ((Get-Content $osv.FullName -Raw)) 200 }
$tssErr = $files | Where-Object Name -match '(Log|LogStart|LogStop)-Warn-Err-Info\.txt$'
$meta.tssWarnings = @($tssErr | ForEach-Object { Get-Content $_.FullName } | Where-Object { $_ -match '\b(ERROR|WARNING)\b' } | Select-Object -First 25 | ForEach-Object { Short $_ 220 })
$cmdErr = $files | Where-Object Name -match 'Command-Error\.txt$' | Select-Object -First 1
if ($cmdErr) { $meta.commandErrors = @(Get-Content $cmdErr.FullName | Where-Object { $_.Trim() } | Select-Object -First 15 | ForEach-Object { Short $_ 200 }) }
$summary.metadata = $meta

# --- Inventory by data type ---
# Most specific first: each file is counted once, under the first type it matches
$types = [ordered]@{
    'xray reports'                = '^xray_'
    'packet captures'             = '\.(pcap|pcapng|cap)$|NetTrace.*\.etl$|PktMon.*\.etl$'
    'screen recording / PSR'      = '\.(mp4|wmv|avi)$|psr.*\.zip$|\.mht$'
    'event logs (.evtx)'          = '\.evtx$'
    'ETW traces (.etl)'           = '\.etl$'
    'ProcMon (.pml)'              = '\.pml$'
    'PerfMon (.blg)'              = '\.blg$'
    'memory/process dumps (.dmp)' = '\.dmp$'
    'SDP / HTML / XML reports'    = '\.(htm|html|xml)$'
    'text / command output'       = '\.(txt|log|csv|nfo|out)$'
}
$byType = [ordered]@{}
foreach ($f in $files) { foreach ($k in $types.Keys) { if ($f.Name -match $types[$k]) { $byType[$k] = @($byType[$k]) + $f | Where-Object { $_ }; break } } }
$inventory = foreach ($k in $byType.Keys) {
    $m = @($byType[$k])
    [ordered]@{ type = $k; count = $m.Count; MB = [math]::Round(($m | Measure-Object Length -Sum).Sum / 1MB, 1); examples = @($m | Sort-Object Length -Descending | Select-Object -First 3 | ForEach-Object Name) }
}
$summary.inventory = @($inventory)
# Near-empty trace files usually mean the tool never started (not elevated, aborted run, or stopped by a separate -Stop).
$summary.emptyTraces = @($files | Where-Object { $_.Name -match '\.(etl|pcapng|pcap|blg|pml|dmp)$' -and $_.Length -lt 8KB } | ForEach-Object { "{0} ({1} bytes)" -f $_.Name, $_.Length })
$summary.largestFiles = @($files | Sort-Object Length -Descending | Select-Object -First 8 | ForEach-Object { "{0} ({1:n1} MB)" -f $_.FullName.Substring($root.Length).TrimStart('\'), ($_.Length / 1MB) })

# --- Sensitive content (review before sharing) ---
$sensitive = [System.Collections.Generic.List[object]]::new()
foreach ($f in $files) {
    # A near-empty capture/dump/ProcMon file holds no data (the tool never ran); it is listed under emptyTraces instead
    if ($f.Name -match '\.(etl|pcapng|pcap|cap|pml|dmp)$' -and $f.Length -lt 8KB) { continue }
    $why = switch -Regex ($f.Name) {
        '\.dmp$' { 'memory dump: may contain passwords, tokens, documents in memory' ; break }
        '\.(pcap|pcapng|cap)$|NetTrace|PktMon' { 'packet capture: traffic contents, hostnames, possibly credentials in clear-text protocols'; break }
        '_evt_Security\.evtx$|Security\.evtx$' { 'Security log: user names, logon sources, IPs'; break }
        '\.pml$' { 'ProcMon: full file/registry/process activity incl. user paths'; break }
        '\.(mp4|wmv|avi)$|psr' { 'screen recording / screenshots'; break }
        'Environment_User|Whoami|_Reg_Profilelist|UserProfile' { 'user identity / profile details'; break }
        '(VPN|Wlan|wlan).*(Profile|profile)' { 'network profiles (may include Wi-Fi/VPN config)'; break }
    }
    if ($why) { $sensitive.Add([ordered]@{ file = $f.FullName.Substring($root.Length).TrimStart('\'); reason = $why; MB = [math]::Round($f.Length / 1MB, 1) }) }
}
# --- xray results ---
$xr = [ordered]@{ issuesFound = @(); diagnostics = @() }
foreach ($f in $files | Where-Object Name -like 'xray_ISSUES-FOUND_*') { $xr.issuesFound += [ordered]@{ file = $f.Name; text = [IO.File]::ReadAllText($f.FullName) } }   # not Get-Content: on 5.1 its PSPath/PSDrive notes bloat the JSON to megabytes
foreach ($f in $files | Where-Object Name -like 'xray_report_*.xml') {
    try {
        [xml]$x = Get-Content $f.FullName -Raw
        $x.SelectNodes("//*[local-name()='Diagnostic' and @Name]") | ForEach-Object {
            # Result: 0 = ran OK, other = skipped/failed. Reported: set when an issue was found.
            # GetAttribute returns plain strings; the adapted properties drag whole XML nodes into the JSON
            $xr.diagnostics += [ordered]@{ name = $_.GetAttribute('Name'); result = $_.GetAttribute('Result'); reported = $_.GetAttribute('Reported') }
        }
    } catch { $xr.parseError = $_.Exception.Message }
}
$xr.issueCount = @($xr.diagnostics | Where-Object { $_.reported }).Count
$summary.xray = $xr

# --- Event logs ---
# Key events: log, provider (regex), id, meaning. Provider matters: the same ID means different things per provider.
$keyEvents = @(
    @('System', 'Kernel-Power', 41, 'unexpected reboot/power loss'), @('System', 'EventLog', 6008, 'previous shutdown was unexpected')
    @('System', 'WER-SystemErrorReporting', 1001, 'bugcheck (blue screen) recorded'), @('System', 'WHEA-Logger', 0, 'hardware error (WHEA)')
    @('System', 'Service Control Manager', 7031, 'service crashed'), @('System', 'Service Control Manager', 7034, 'service terminated unexpectedly')
    @('System', 'Service Control Manager', 7000, 'service failed to start'), @('System', 'Service Control Manager', 7009, 'service start timeout')
    @('System', 'WindowsUpdateClient', 20, 'Windows Update install failure'), @('System', '^(storahci|stornvme|iaStor\w*|disk|storport)$', 129, 'storage reset (IO timeout)')
    @('System', '^disk$', 153, 'disk IO retried'), @('System', '^disk$', 7, 'bad block'), @('System', '^Ntfs$|Microsoft-Windows-Ntfs', 55, 'NTFS corruption')
    @('System', 'NETLOGON', 5719, 'Netlogon: no domain controller available'), @('System', 'GroupPolicy', 1129, 'Group Policy: no network/DC')
    @('System', 'GroupPolicy', 1058, 'Group Policy: cannot read gpt.ini'), @('System', 'DNS-Client', 1014, 'DNS name resolution timeout')
    @('System', 'Tcpip', 4199, 'IP address conflict'), @('System', 'Tcpip', 4227, 'TCP/IP: ephemeral port reuse failed (port pressure)'), @('System', 'Tcpip', 4231, 'TCP/IP: ephemeral port allocation failed (port exhaustion)')
    @('System', 'Tcpip', 4266, 'TCP/IP: UDP/TCP ephemeral ports exhausted'), @('System', '^disk$', 157, 'disk surprise-removed (USB/cable/power)'), @('System', '^Ntfs$|Microsoft-Windows-Ntfs', 50, 'delayed write failed (data lost)'), @('System', '^Ntfs$|Microsoft-Windows-Ntfs', 140, 'NTFS failed to flush data (delayed write)')
    @('System', 'NDIS', 10400, 'NIC reset'), @('System', 'Time-Service', 0, 'time service problem')
    @('Application', '^Application Error$', 1000, 'application crash'), @('Application', '^Application Hang$', 1002, 'application hang')
    @('Application', '\.NET Runtime', 1026, '.NET unhandled exception'), @('Application', 'User Profiles? Service', 1511, 'temporary profile loaded')
    @('Security', 'Security-Auditing', 4625, 'failed logon'), @('Security', 'Security-Auditing', 4740, 'account locked out')
    @('Security', 'Security-Auditing', 4771, 'Kerberos pre-auth failed'), @('Security', 'Security-Auditing', 4776, 'NTLM credential validation')
) | ForEach-Object { [pscustomobject]@{ log = $_[0]; provider = $_[1]; id = $_[2]; meaning = $_[3] } }   # id 0 = any ID from that provider (errors only)
$evtSummary = foreach ($f in $files | Where-Object Extension -eq '.evtx') {
    $logName = if ($f.Name -match '_evt_(.+)\.evtx$') { $Matches[1] } else { $f.BaseName }
    $short = ($logName -split '[-_ ]')[0]
    $evtPath = $f.FullName
    if ($evtPath.Length -gt 240) { $tmp = if ($ExtractDir) { Join-Path $ExtractDir "_evt" } else { Join-Path $env:TEMP "tssx\evt" }; New-Item -ItemType Directory -Force $tmp | Out-Null; $evtPath = Join-Path $tmp $f.Name; if ($evtPath.Length -gt 240) { $evtPath = Join-Path $tmp ("{0}.evtx" -f [guid]::NewGuid().ToString('N').Substring(0, 8)) }; Copy-Item -LiteralPath "\\?\$($f.FullName)" $evtPath -Force }
    try { $ev = @(Get-WinEvent -Path $evtPath -MaxEvents $MaxEventsPerLog -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { $ev = @() } else { [ordered]@{ log = $logName; error = $_.Exception.Message }; continue } }
    if (-not $ev) { continue }
    $bad = @($ev | Where-Object { $_.Level -in 1, 2 })
    # Personal data inside event text (Outlook/Office events name mailboxes; many events carry profile paths).
    $text = ($ev | Select-Object -First 8000 | ForEach-Object Message) -join "`n"
    $emails = @([regex]::Matches($text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}') | ForEach-Object { $_.Value.ToLower() } | Select-Object -Unique)
    $profiles = @([regex]::Matches($text, '(?i)[A-Z]:\\Users\\([^\\\s"]+)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^(Public|Default|All Users)$' } | Select-Object -Unique)
    if ($emails -or $profiles) { $sensitive.Add([ordered]@{ file = $f.FullName.Substring($root.Length).TrimStart('\'); reason = "event text contains personal data: $($emails.Count) e-mail address(es), $($profiles.Count) user profile name(s)"; MB = [math]::Round($f.Length / 1MB, 1) }) }
    $keys = foreach ($k in $keyEvents | Where-Object log -eq $short) {
        $hit = @($ev | Where-Object { $_.ProviderName -match $k.provider -and ($(if ($k.id) { $_.Id -eq $k.id } else { $_.Level -in 1, 2 })) })
        if ($hit) { [ordered]@{ id = $(if ($k.id) { $k.id } else { 'any' }); provider = $hit[0].ProviderName; meaning = $k.meaning; count = $hit.Count; latest = $hit[0].TimeCreated.ToString('s'); sample = Short $hit[0].Message 260 } }
    }
    [ordered]@{
        log = $logName; file = $f.Name; events = $ev.Count; errors = $bad.Count
        from = $ev[-1].TimeCreated.ToString('s'); to = $ev[0].TimeCreated.ToString('s')
        keyEvents = @($keys | Sort-Object @{ Expression = { $_.count }; Descending = $true }, @{ Expression = { $_.id } })
        topErrors = @($bad | Group-Object ProviderName, Id | Sort-Object @{ Expression = 'Count'; Descending = $true }, Name | Select-Object -First 12 | ForEach-Object {
            [ordered]@{ provider = $_.Group[0].ProviderName; id = $_.Group[0].Id; count = $_.Count; latest = $_.Group[0].TimeCreated.ToString('s'); message = Short $_.Group[0].Message } })
    }
}
$summary.eventLogs = @($evtSummary | Sort-Object { -1 * [int]$_.errors })
$summary.sensitive = @($sensitive | Sort-Object { $_.file })   # set here, after the event-log scan has added its personal-data entries

# --- Text logs: error codes and failure lines ---
$codes = @{}; $failLines = [System.Collections.Generic.List[object]]::new()
$textFiles = $files | Where-Object { $_.Name -match '\.(txt|log|csv|out)$' -and $_.Length -lt ($MaxTextFileMB * 1MB) -and $_.Name -notlike 'xray_*' }
foreach ($f in $textFiles) {
    foreach ($m in Select-String -LiteralPath $f.FullName -Pattern '0x8[0-9a-f]{7}|0xC0[0-9a-f]{6}' -AllMatches -ErrorAction SilentlyContinue) {
        foreach ($v in $m.Matches.Value) { $k = $v.ToLower(); if (-not $codes[$k]) { $codes[$k] = [ordered]@{ code = $k; count = 0; files = [System.Collections.Generic.HashSet[string]]::new(); sample = Short $m.Line 200 } }; $codes[$k].count++; [void]$codes[$k].files.Add($f.Name) }
    }
    if ($f.Name -match 'setupact|setuperr|CBS|WindowsUpdate|dism|Panther|MoSetup|ReportingEvents') {
        Select-String -LiteralPath $f.FullName -Pattern '\b(Error|FAILED|Failure|fatal)\b' -ErrorAction SilentlyContinue | Select-Object -Last 15 | ForEach-Object { $failLines.Add([ordered]@{ file = $f.Name; line = $_.LineNumber; text = Short $_.Line 220 }) }
    }
}
$summary.errorCodes = @($codes.Values | Sort-Object @{ Expression = { $_.count }; Descending = $true }, @{ Expression = { $_.code } } | Select-Object -First 15 | ForEach-Object { [ordered]@{ code = $_.code; count = $_.count; files = @($_.files | Select-Object -First 4); sample = $_.sample } })
$summary.setupFailureLines = @($failLines | Select-Object -Last 40)

# --- Write output ---
$jsonPath = Join-Path $OutDir 'package-summary.json'
$summary | ConvertTo-Json -Depth 8 | Set-Content $jsonPath -Encoding utf8

$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# TSS package summary: $($item.Name)"); [void]$md.AppendLine('')
[void]$md.AppendLine("Computer: **$($meta.computer)** · scenario: **$(if($meta.scenario){$meta.scenario}else{'n/a'})** · collected: $($meta.collected) · $($summary.fileCount) files, $($summary.totalMB) MB")
if ($meta.osVersion) { [void]$md.AppendLine(''); [void]$md.AppendLine("OS: $($meta.osVersion)") }
[void]$md.AppendLine(''); [void]$md.AppendLine('## xray known issues'); [void]$md.AppendLine('')
if ($xr.issuesFound) { foreach ($i in $xr.issuesFound) { [void]$md.AppendLine('```'); [void]$md.AppendLine($(if ($i.text.Length -gt 4000) { $i.text.Substring(0, 4000) + ' ...' } else { $i.text.TrimEnd() })); [void]$md.AppendLine('```') } }
elseif ($xr.diagnostics) { [void]$md.AppendLine("xray ran $($xr.diagnostics.Count) check(s); none reported an issue.") }
else { [void]$md.AppendLine('No xray output in the package (collected with -noXray, or xray had no checks for this area).') }
[void]$md.AppendLine(''); [void]$md.AppendLine('## Event logs'); [void]$md.AppendLine('')
foreach ($e in $summary.eventLogs) {
    if ($e.error) { [void]$md.AppendLine("- **$($e.log)**: could not read ($($e.error))"); continue }
    [void]$md.AppendLine("### $($e.log): $($e.errors) errors of $($e.events) events ($($e.from) to $($e.to))")
    foreach ($k in $e.keyEvents) { [void]$md.AppendLine("- KEY $($k.id) $($k.meaning) x$($k.count), latest $($k.latest): $(Short $k.sample 160)") }
    foreach ($t in $e.topErrors | Select-Object -First 6) { [void]$md.AppendLine("- $($t.provider) $($t.id) x$($t.count), latest $($t.latest): $(Short $t.message 160)") }
    [void]$md.AppendLine('')
}
if ($summary.errorCodes) { [void]$md.AppendLine('## Most frequent error codes in text logs'); [void]$md.AppendLine(''); foreach ($c in $summary.errorCodes | Select-Object -First 10) { [void]$md.AppendLine("- ``$($c.code)`` x$($c.count) in $(@($c.files) -join ', ')") }; [void]$md.AppendLine('') }
if ($summary.setupFailureLines) { [void]$md.AppendLine('## Last failure lines in setup/servicing logs'); [void]$md.AppendLine(''); foreach ($l in $summary.setupFailureLines | Select-Object -Last 12) { [void]$md.AppendLine("- $($l.file):$($l.line) $($l.text)") }; [void]$md.AppendLine('') }
if ($summary.emptyTraces) { [void]$md.AppendLine('## Empty or near-empty trace files (capture did not run)'); [void]$md.AppendLine(''); $summary.emptyTraces | ForEach-Object { [void]$md.AppendLine("- $_") }; [void]$md.AppendLine('') }
if ($meta.tssWarnings) { [void]$md.AppendLine('## TSS collection warnings (data may be incomplete)'); [void]$md.AppendLine(''); $meta.tssWarnings | Select-Object -First 10 | ForEach-Object { [void]$md.AppendLine("- $_") }; [void]$md.AppendLine('') }
[void]$md.AppendLine('## What is in the package'); [void]$md.AppendLine('')
[void]$md.AppendLine('| Data | Files | MB |'); [void]$md.AppendLine('|---|---|---|')
foreach ($i in $summary.inventory) { [void]$md.AppendLine("| $($i.type) | $($i.count) | $($i.MB) |") }
[void]$md.AppendLine(''); [void]$md.AppendLine("## Sensitive before sharing ($($sensitive.Count) files)"); [void]$md.AppendLine('')
foreach ($g in $sensitive | Sort-Object { $_.file } | Group-Object { $_.reason } | Sort-Object Name) { [void]$md.AppendLine("- $($g.Name): $($g.Count) file(s), e.g. ``$($g.Group[0].file)``") }
[void]$md.AppendLine(''); [void]$md.AppendLine('Full data: `package-summary.json`, next to this file.')   # no full path: it would put the analyst's user name into a file meant for sharing
$mdPath = Join-Path $OutDir 'package-summary.md'
$md.ToString() | Set-Content $mdPath -Encoding utf8
Write-Output "Package summary written: $mdPath"
Write-Output ("{0} event logs, {1} xray issue report(s), {2} error codes, {3} sensitive files" -f @($summary.eventLogs).Count, @($xr.issuesFound).Count, @($summary.errorCodes).Count, $sensitive.Count)
