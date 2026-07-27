<#
.SYNOPSIS
    Unit test for the hashing shim ($script:HashShimText) in kit/IR-Collect.ps1.

.DESCRIPTION
    Extracts the shim TEXT from the collector via the AST, defines it, and asserts:
      * Get-IRSha256/Get-IRMd5 return correct, uppercase, well-formed digests
      * the .NET fallback produces the SAME digest as the cmdlet path
      * a BROKEN or MISSING Get-FileHash still yields a correct hash (the whole point)
      * a file open by another writer still hashes (FileShare ReadWrite)

    Regression this locks in: Get-FileHash is not guaranteed present. Measured on a real,
    fully-patched Windows PowerShell 5.1 host in FullLanguage mode - PSModulePath inherited from
    a parent process listed PowerShell 7's module dirs first, 5.1 loaded pwsh 7's
    Microsoft.PowerShell.Utility 7.0.0.0, and Get-FileHash was absent. The collector's manifest
    step caught the error and wrote 'ERR' for every row, sealing an evidence bundle whose manifest
    verified nothing. Also absent on PS < 4.0 (Win7/2008R2). 2026-07-27.

.EXAMPLE  pwsh -File tests/unit/Test-HashShim.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'kit') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
# the shim is a variable assignment holding a here-string, not a function
$asg = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    "$($args[0].Left)" -match 'HashShimText' }, $true)
if ($asg.Count -ne 1) { throw "expected 1 HashShimText assignment, found $($asg.Count)" }
$shimText = $asg[0].Right.Expression.Value
if (-not $shimText) { throw 'could not read the shim here-string value' }
. ([scriptblock]::Create($shimText))

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hashshim_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.bin')
[IO.File]::WriteAllBytes($tmp, [Text.Encoding]::ASCII.GetBytes('IR-Collect hash shim test vector'))

# independent ground truth, computed straight from .NET
$truth = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($tmp)) |
                ForEach-Object { $_.ToString('X2') })

$viaShim = Get-IRSha256 $tmp
Check ($viaShim -eq $truth)                'Get-IRSha256 matches an independently computed SHA-256'
Check ($viaShim -match '^[0-9A-F]{64}$')   'digest is 64 uppercase hex chars (matches Get-FileHash formatting)'
Check ((Get-IRHashNet $tmp 'SHA256') -eq $truth) '.NET fallback path agrees with the cmdlet path'
$md5 = Get-IRMd5 $tmp
Check ($md5 -match '^[0-9A-F]{32}$')       'Get-IRMd5 returns a well-formed MD5'

# --- the regression: make Get-FileHash unusable, shim must still be correct ---
# a function shadows the cmdlet in this scope, exactly as a broken/absent cmdlet behaves
function Get-FileHash { throw 'simulated: Get-FileHash unavailable (pwsh-7 Utility loaded into 5.1)' }
$underFailure = Get-IRSha256 $tmp
Check ($underFailure -eq $truth) 'Get-IRSha256 still correct when Get-FileHash throws  <-- the regression'
$md5UnderFailure = Get-IRMd5 $tmp
Check ($md5UnderFailure -eq $md5) 'Get-IRMd5 still correct when Get-FileHash throws'
Remove-Item function:Get-FileHash -ErrorAction SilentlyContinue

# --- locked-file tolerance: evidence files can still be open when the manifest runs ---
$locked = Join-Path ([IO.Path]::GetTempPath()) ("hashlock_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.bin')
$fsw = [IO.File]::Open($locked, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
try {
    $bytes = [Text.Encoding]::ASCII.GetBytes('still being written')
    $fsw.Write($bytes, 0, $bytes.Length); $fsw.Flush()
    $lockedHash = try { Get-IRHashNet $locked 'SHA256' } catch { "THREW: $($_.Exception.Message)" }
    Check ($lockedHash -match '^[0-9A-F]{64}$') 'fallback hashes a file another process holds open (FileShare ReadWrite)'
} finally { $fsw.Dispose() }

Remove-Item $tmp, $locked -Force -ErrorAction SilentlyContinue
Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
