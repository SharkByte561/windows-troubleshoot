<#
.SYNOPSIS
Regenerates the skill's TSS catalog (references/tss-index.json and the Markdown indexes) from a TSS folder.

.DESCRIPTION
Reads only the help JSON files and the xray diag_*.psm1 sources of an extracted TSS.zip. Runs nothing from TSS.
Re-run after downloading a newer TSS so lookups match the version you will actually execute.

.EXAMPLE
.\Build-TssIndex.ps1 -TssRoot C:\TSS
#>
[CmdletBinding()]
param(
    # Default: the folder Resolve-TssRoot.ps1 finds ($env:TSS_ROOT, the saved location, or C:\TSS)
    [string]$TssRoot,
    # Default: the skill's references folder
    [string]$OutDir
)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$ErrorActionPreference = 'Stop'
# Defaults are set here, not in param(): Windows PowerShell 5.1 leaves $PSScriptRoot empty there
if (-not $TssRoot) { $TssRoot = & (Join-Path $PSScriptRoot 'Resolve-TssRoot.ps1') }
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot '..\references' }
if (-not $TssRoot) { throw 'No TSS folder found. Pass -TssRoot, set $env:TSS_ROOT, or get one with Update-Tss.ps1.' }
$help = Join-Path $TssRoot 'help'
if (-not (Test-Path (Join-Path $help 'TSS_Scenarios.json'))) { throw "No TSS help folder under $TssRoot" }
$OutDir = (New-Item -ItemType Directory -Force $OutDir).FullName

function Read-Help([string]$name) { Get-Content (Join-Path $help $name) -Raw | ConvertFrom-Json }
function Yes($v) { $v -and "$v" -ne 'no' }
# UTF-8 without BOM, so pwsh 7 and Windows PowerShell 5.1 write identical files
function Write-Utf8([string]$name, [string]$text) { [IO.File]::WriteAllText((Join-Path $OutDir $name), ($text + [Environment]::NewLine), [Text.UTF8Encoding]::new($false)) }

# TSS version from the script header
$version = (Select-String -Path (Join-Path $TssRoot 'TSS.ps1') -Pattern '\$global:TssVerDate\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
if (-not $version) { $version = (Get-Item (Join-Path $TssRoot 'TSS.ps1')).LastWriteTime.ToString('yyyy.MM.dd') }

# --- Scenarios (-Scenario) ---
$scenarios = foreach ($p in (Read-Help 'TSS_Scenarios.json').scenarios.allScenarios.PSObject.Properties) {
    $s = $p.Value; $par = $s.parameters
    $tools = @('netsh','procmon','perfMon','psr','video','wpr','xperf','pktMon','sdp','gPresult') | Where-Object { Yes $par.$_ }
    [pscustomobject]@{
        kind = 'scenario'; name = $s.name; pod = $s.pod; category = $s.category
        deprecated = [bool]$s.deprecated; recommended = "$($s.recommended)"
        tools = @($tools); xray = (Yes $par.xray)
        description = $s.description
        command = ".\TSS.ps1 -Scenario $($s.name)"
    }
}

# --- Components (-Start -<Name> / -CollectLog <Name>) ---
$collectLogOnly = @{}
$cl = (Read-Help 'TSS_CollectLogs.json').logs
foreach ($c in $cl.collectLogOnlyComponents.components) { $collectLogOnly[$c.name] = $c }

$components = foreach ($pod in (Read-Help 'TSS_Components.json').components.byPOD.PSObject.Properties) {
    foreach ($p in $pod.Value.components.PSObject.Properties) {
        $c = $p.Value
        $rec = @($c.recommended) -join '; '
        [pscustomobject]@{
            kind = 'component'; name = $c.name; pod = $pod.Name; category = $c.category
            deprecated = [bool]$c.deprecated; recommended = $rec
            parent = $c.parentComponent
            description = $c.description
            command = ".\TSS.ps1 -Start -$($c.name)"
            collectLog = $collectLogOnly.ContainsKey($c.name)
        }
    }
}
$compNames = @{}; $components | ForEach-Object { $compNames[$_.name] = 1 }
$collectLogs = foreach ($c in $cl.collectLogOnlyComponents.components) {
    [pscustomobject]@{
        kind = 'collectlog'; name = $c.name; pod = $c.pod; category = $c.category
        deprecated = [bool]$c.deprecated; recommended = "$($c.recommended)"
        description = $c.description
        command = ".\TSS.ps1 -CollectLog $($c.name)"
    }
}

# --- SDP reports ---
$sdpJson = (Read-Help 'TSS_SDP.json').sdp
$sdp = foreach ($p in $sdpJson.reports.PSObject.Properties) {
    [pscustomobject]@{ kind = 'sdp'; name = $p.Value.name; pod = 'SDP'; category = 'SDP report'
        deprecated = [bool]$p.Value.deprecated; description = $p.Value.description
        command = ".\TSS.ps1 -SDP $($p.Value.name)" }
}

# --- WaitEvent stop triggers ---
$waitEvents = foreach ($p in (Read-Help 'TSS_Monitoring.json').monitoring.eventTypes.PSObject.Properties) {
    $e = $p.Value
    [pscustomobject]@{ name = $p.Name; type = $e.type; format = $e.format; description = $e.description
        examples = @($e.examples | ForEach-Object { if ($_.command) { "$($_.command)  # $($_.description)" } else { "$_" } }) }
}

# --- xray known-issue checks (parsed from source, not executed) ---
$xray = foreach ($f in Get-ChildItem (Join-Path $TssRoot 'xray') -Filter 'diag_*.psm1') {
    if ($f.Name -in 'diag_api.psm1','diag_test.psm1') { continue }
    $text = Get-Content $f.FullName -Raw
    $ms = [regex]::Matches($text, '(?ms)^function\s+((ads|dnd|net|prf|sha|uex)_(\w+?)_(KB\d+))\s*\{(.*?)(?=^function\s|\z)')
    foreach ($m in $ms) {
        if ($m.Groups[1].Value -like '*_sample') { continue }
        $body = $m.Groups[5].Value
        $mm = [regex]::Match($body, '(?s)\$issueMsg\s*=\s*(?:@"(.*?)"@|@''(.*?)''@|"(.*?)")')
        $msg = ($mm.Groups[1].Value, $mm.Groups[2].Value, $mm.Groups[3].Value | Where-Object { $_ } | Select-Object -First 1)
        $summary = (($msg -split "`r?`n") | ForEach-Object Trim | Where-Object { $_ } | Select-Object -First 3) -join ' '
        [pscustomobject]@{
            name = $m.Groups[1].Value; area = $m.Groups[2].Value.ToUpper(); component = $m.Groups[3].Value
            kb = $m.Groups[4].Value; offline = ($body -notmatch 'Cannot run offline')
            summary = ($summary -replace '`t', ' ' -replace '\s+', ' ')
        }
    }
}

$index = [ordered]@{
    generated = (Get-Date).ToString('yyyy-MM-dd'); tssVersion = $version
    scenarios = @($scenarios); components = @($components); collectLogs = @($collectLogs)
    sdp = @($sdp); waitEvents = @($waitEvents); xray = @($xray)
}
Write-Utf8 'tss-index.json' ($index | ConvertTo-Json -Depth 6)

# --- Markdown: scenario index grouped by POD ---
$podNames = @{ ADS='Active Directory, auth, GPO, certificates'; NET='Networking'; PRF='Performance, shell, apps'
    UEX='User experience: RDS/AVD/W365, logon, print, WMI, WinRM'; SHA='Storage, Hyper-V, clustering'
    DND='Devices, servicing, setup, power'; CRM='Dynamics CRM'; INT='Integration / MSMQ'; SPS='SharePoint'; DEV='Developer test (ignore)' }
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# TSS scenario index (TSS $version, generated $($index.generated))")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Generated by `scripts/Build-TssIndex.ps1` from `help/TSS_Scenarios.json`. One scenario per run (they are mutually exclusive).')
[void]$sb.AppendLine('Search this with `scripts/Find-TssScenario.ps1 "<symptom>"` rather than reading it top to bottom. Full text, side effects and component lists are in `tss-index.json`.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Contents: ' + (($scenarios | Group-Object pod | ForEach-Object { "[$($_.Name)](#$($_.Name.ToLower()))" }) -join ' · '))
foreach ($g in $scenarios | Where-Object { -not $_.deprecated } | Group-Object pod) {
    [void]$sb.AppendLine(''); [void]$sb.AppendLine("## $($g.Name)"); [void]$sb.AppendLine('')
    if ($podNames[$g.Name]) { [void]$sb.AppendLine("_$($podNames[$g.Name])_"); [void]$sb.AppendLine('') }
    [void]$sb.AppendLine('| Scenario | Use when | Adds |'); [void]$sb.AppendLine('|---|---|---|')
    foreach ($s in $g.Group) {
        $use = ($s.description -split '(?<=\.)\s')[0] -replace '\|', '/'
        if ($use.Length -gt 220) { $use = $use.Substring(0, 217) + '...' }
        [void]$sb.AppendLine("| ``$($s.name)`` | $use | $(($s.tools) -join ', ') |")
    }
}
[void]$sb.AppendLine(''); [void]$sb.AppendLine('## SDP reports (`-SDP <name>`)'); [void]$sb.AppendLine('')
foreach ($s in $sdp) { $d = ($s.description -split '(?<=\.)\s')[0]; [void]$sb.AppendLine("- ``$($s.name)``: $d") }
Write-Utf8 'scenario-index.md' $sb.ToString()

# --- Markdown: xray checks ---
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# xray known-issue checks (TSS $version)"); [void]$sb.AppendLine('')
[void]$sb.AppendLine('xray runs automatically with every TSS collection (unless `-noXray`) and writes `xray_ISSUES-FOUND_*.txt` and `xray_report_*.xml` into the data folder. It can also be run on its own: `.\xray\xray.ps1 -Component <component> -DataPath <folder> -AcceptEula`.')
[void]$sb.AppendLine('"Offline" = the check can work from collected data files (`-Offline`); the others need to run on the affected machine.'); [void]$sb.AppendLine('')
[void]$sb.AppendLine('| Check | Component | KB | Offline | What it detects |'); [void]$sb.AppendLine('|---|---|---|---|---|')
foreach ($x in $xray | Sort-Object area, component) {
    $sum = $x.summary -replace '\|', '/'; if ($sum.Length -gt 200) { $sum = $sum.Substring(0, 197) + '...' }
    [void]$sb.AppendLine("| ``$($x.name)`` | $($x.area)/$($x.component) | [$($x.kb)](https://support.microsoft.com/help/$($x.kb -replace 'KB','')) | $(if($x.offline){'yes'}else{'no'}) | $sum |")
}
Write-Utf8 'xray-checks.md' $sb.ToString()

# --- Markdown: WaitEvent recipes ---
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Stop triggers for intermittent problems (-WaitEvent), TSS $version"); [void]$sb.AppendLine('')
[void]$sb.AppendLine('Pattern: `.\TSS.ps1 -Scenario <Name> -WaitEvent <Type>:<params>` starts the trace and stops it automatically when the condition hits. Add `-StartNoWait` to return the console immediately. Source: `help/TSS_Monitoring.json`.')
foreach ($w in $waitEvents) {
    [void]$sb.AppendLine(''); [void]$sb.AppendLine("## $($w.name) ($($w.type))"); [void]$sb.AppendLine('')
    if ($w.description) { [void]$sb.AppendLine($w.description); [void]$sb.AppendLine('') }
    [void]$sb.AppendLine("Format: ``$($w.format)``")
    if ($w.examples) { [void]$sb.AppendLine(''); [void]$sb.AppendLine('```powershell'); $w.examples | Select-Object -First 4 | ForEach-Object { [void]$sb.AppendLine($_) }; [void]$sb.AppendLine('```') }
}
Write-Utf8 'waitevent-recipes.md' $sb.ToString()

[pscustomobject]@{ TssVersion = $version; Scenarios = @($scenarios).Count; Components = @($components).Count
    CollectLogs = @($collectLogs).Count; Sdp = @($sdp).Count; WaitEvents = @($waitEvents).Count; Xray = @($xray).Count; OutDir = $OutDir }
