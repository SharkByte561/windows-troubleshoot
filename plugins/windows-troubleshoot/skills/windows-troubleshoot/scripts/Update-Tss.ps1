<#
.SYNOPSIS
Checks whether a newer TSS is published and, if so, downloads, verifies and unpacks it next to the current copy, then rebuilds the skill's catalog.

.DESCRIPTION
-CheckOnly is read-only: it reads the local TSS version and the version Microsoft publishes (aka.ms/getTSS/TSS.ver, a few bytes).

Without -CheckOnly (tier 2: needs internet, writes ~25 MB; ask the user first):
  1. Stops if the published version is not newer (use -Force to re-download anyway).
  2. Downloads TSS.zip from aka.ms/getTSS to %TEMP%.
  3. Compares its SHA256 with the hash Microsoft publishes (aka.ms/getTSSHash). Mismatch or missing hash = abort.
  4. Extracts to a staging folder; every .ps1/.psm1/.psd1 must have a Valid Authenticode signature from
     O=Microsoft Corporation, otherwise abort. Unsigned/invalid binaries are listed as warnings (SQLCheck.exe is a known one).
  5. Copies it to <parent of current TSS>\TSS_<version> (first install: C:\TSS or -TssRoot), and saves that folder
     for the other scripts (Resolve-TssRoot.ps1). The old copy is never modified or deleted.
  6. Runs Build-TssIndex.ps1 against the new folder (skip with -NoRebuild).
Nothing from the download is executed.

.EXAMPLE
.\Update-Tss.ps1 -CheckOnly
.\Update-Tss.ps1
.\Update-Tss.ps1 -TssRoot C:\TSS -Force
#>
[CmdletBinding()]
param(
    [string]$TssRoot,
    [switch]$CheckOnly,
    [switch]$Force,
    [switch]$NoRebuild
)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$base = 'https://aka.ms/getTSS'

if (-not $TssRoot) { $TssRoot = & (Join-Path $PSScriptRoot 'Resolve-TssRoot.ps1') }
function Get-LocalVersion([string]$root) {
    $f = Join-Path $root 'TSS.ps1'
    if (-not (Test-Path $f)) { return $null }
    (Select-String -Path $f -Pattern '\$global:TssVerDate\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
}
function Get-Text([string]$url) {
    $b = (Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 30).RawContentStream.ToArray()
    $enc = if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode } else { [Text.Encoding]::UTF8 }
    $enc.GetString($b).Trim([char]0xFEFF, ' ', "`r", "`n", "`t")
}
function VerNum([string]$v) { if ($v -match '^(\d{4})\.(\d{2})\.(\d{2})\.(\d+)') { [long]("{0}{1}{2}{3:D3}" -f $Matches[1], $Matches[2], $Matches[3], [int]$Matches[4]) } else { 0 } }
function Expiry([string]$v) { if ($v -match '^(\d{4}\.\d{2}\.\d{2})') { ([datetime]::ParseExact($Matches[1], 'yyyy.MM.dd', $null)).AddDays(90) } }

$local = if ($TssRoot) { Get-LocalVersion $TssRoot }
$online = try { Get-Text "$base/TSS.ver" } catch { Write-Warning "Could not read the published version: $($_.Exception.Message)"; $null }
$exp = if ($local) { Expiry $local }
$status = [pscustomobject]@{
    TssRoot       = $TssRoot
    LocalVersion  = $local
    Expires       = $(if ($exp) { $exp.ToString('yyyy-MM-dd') })
    DaysLeft      = $(if ($exp) { [int][math]::Floor(($exp - (Get-Date).Date).TotalDays) })
    OnlineVersion = $online
    UpdateNeeded  = [bool]($online -and ((-not $local) -or (VerNum $online) -gt (VerNum $local)))
}
$status | Format-List
if ($CheckOnly) { return }

if (-not $online) { throw 'Cannot continue without the published version (no internet, or aka.ms unreachable).' }
if (-not $status.UpdateNeeded -and -not $Force) { Write-Host "Already on the latest TSS ($local). Nothing downloaded."; return }
if (-not $TssRoot) { $TssRoot = 'C:\TSS' }   # first install: the location Microsoft's docs use
$fresh = -not (Test-Path (Join-Path $TssRoot 'TSS.ps1'))

$work = Join-Path $env:TEMP "tss-update-$(Get-Date -Format yyMMdd-HHmmss)"
New-Item -ItemType Directory -Force $work | Out-Null
$zip = Join-Path $work 'TSS.zip'
try {
    Write-Host "Downloading $base/TSS.zip ..."
    Invoke-WebRequest "$base/TSS.zip" -OutFile $zip -UseBasicParsing -TimeoutSec 600

    # Published hash: first hex run of SHA1/256/512 length
    $hashText = Get-Text 'https://aka.ms/getTSSHash'
    $pub = ([regex]::Matches(($hashText -replace '(?<=[0-9A-Fa-f]{2}) (?=[0-9A-Fa-f]{2})', ''), '\b[0-9A-Fa-f]{40,128}\b') | Select-Object -First 1).Value
    if (-not $pub -or $pub.Length -notin 40, 64, 128) { throw "Published hash not found or unreadable: '$hashText'" }
    $alg = @{ 40 = 'SHA1'; 64 = 'SHA256'; 128 = 'SHA512' }[$pub.Length]
    $got = (Get-FileHash $zip -Algorithm $alg).Hash
    if ($got -ne $pub.ToUpper()) { throw "Hash mismatch: published $alg $pub, downloaded $got. Update aborted." }
    Write-Host "Hash OK ($alg $got)."

    $stage = Join-Path $work 'TSS'
    Expand-Archive $zip -DestinationPath $stage -Force
    # The zip may contain a top-level TSS folder or the files directly
    $newRoot = (Get-ChildItem $stage -Recurse -Filter TSS.ps1 -File | Sort-Object { $_.FullName.Length } | Select-Object -First 1).DirectoryName
    if (-not $newRoot) { throw 'TSS.ps1 not found in the downloaded zip.' }

    $scripts = Get-ChildItem $newRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1 | Get-AuthenticodeSignature
    $bad = @($scripts | Where-Object { $_.Status -ne 'Valid' -or $_.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation' })
    if ($bad) { throw ("$($bad.Count) of $($scripts.Count) scripts are not validly Microsoft-signed; update aborted:`n" + (($bad | Select-Object -First 15 | ForEach-Object { "  $($_.Status)  $($_.Path.Substring($newRoot.Length))" }) -join "`n")) }
    Write-Host "Signatures OK ($($scripts.Count) scripts, all Microsoft Corporation)."
    $bins = Get-ChildItem $newRoot -Recurse -File -Include *.exe, *.dll, *.sys | Get-AuthenticodeSignature | Where-Object Status -ne 'Valid'
    foreach ($b in $bins) { Write-Warning "Binary not validly signed (do not run on its own): $($b.Status)  $($b.Path.Substring($newRoot.Length))" }

    $newVer = Get-LocalVersion $newRoot
    $dest = if ($fresh -and -not (Test-Path $TssRoot)) { $TssRoot } else { Join-Path (Split-Path $TssRoot -Parent) "TSS_$newVer" }
    if ($dest -ne $TssRoot -and (Test-Path $dest)) { $dest = "$dest-$(Get-Date -Format yyMMdd-HHmmss)" }
    # robocopy, not Copy-Item: Move-Item fails across volumes, and 5.1's Copy-Item can't write paths over 260 characters
    $null = robocopy $newRoot $dest /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) {
        Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue   # $dest is always a new folder, so nothing else is lost
        throw "Copying TSS to $dest failed (robocopy exit code $LASTEXITCODE). Nothing was installed; try a shorter -TssRoot such as C:\TSS."
    }
    Write-Host ("Installed TSS $newVer to $dest" + $(if ($dest -ne $TssRoot) { " (old copy left untouched at $TssRoot)." } else { '.' }))
    [void](& (Join-Path $PSScriptRoot 'Resolve-TssRoot.ps1') -Save $dest)   # later lookups find the new copy

    if (-not $NoRebuild) {
        & (Join-Path $PSScriptRoot 'Build-TssIndex.ps1') -TssRoot $dest
        Write-Host "Catalog rebuilt for $newVer."
    }
    Write-Host "Use it with: cd '$dest'; .\TSS.ps1 ...   (expires $((Expiry $newVer).ToString('yyyy-MM-dd')))"
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
