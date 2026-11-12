<#
.SYNOPSIS
Finds the local TSS folder, or remembers one, so the other scripts work on any machine without hardcoded paths.

.DESCRIPTION
Lookup order (first folder that contains TSS.ps1 wins):
  1. $env:TSS_ROOT
  2. The folder saved in %LOCALAPPDATA%\windows-troubleshoot\tss-root.txt (written by -Save and by Update-Tss.ps1)
  3. C:\TSS, the location Microsoft's docs use
Prints nothing when no TSS is found; lookups still work from the bundled catalog.

.EXAMPLE
.\Resolve-TssRoot.ps1
.\Resolve-TssRoot.ps1 -Save D:\Tools\TSS
#>
[CmdletBinding()]
param([string]$Save)
# Windows PowerShell 5.1 started from PowerShell 7 inherits PS7's module folders and then can't load its own cmdlets (Get-FileHash...)
if ($PSVersionTable.PSEdition -ne 'Core') { $env:PSModulePath = (@($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' }) -join ';' }
$pointer = Join-Path $env:LOCALAPPDATA 'windows-troubleshoot\tss-root.txt'

if ($Save) {
    $full = (Resolve-Path $Save -ErrorAction Stop).Path
    if (-not (Test-Path (Join-Path $full 'TSS.ps1'))) { throw "No TSS.ps1 in $full" }
    New-Item -ItemType Directory -Force (Split-Path $pointer) | Out-Null
    Set-Content -Path $pointer -Value $full -Encoding UTF8
    return $full
}

$candidates = @($env:TSS_ROOT)
if (Test-Path $pointer) { $candidates += (Get-Content $pointer -TotalCount 1).Trim() }
$candidates += 'C:\TSS'
$candidates | Where-Object { $_ -and (Test-Path (Join-Path $_ 'TSS.ps1')) } | Select-Object -First 1
