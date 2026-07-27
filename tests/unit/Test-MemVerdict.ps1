<#
.SYNOPSIS
    Unit test for Resolve-MemVerdict in kit/IR-Collect.ps1 (memory-acquisition classification).

.DESCRIPTION
    Extracts the real shipped function out of the collector via the PowerShell AST (so the test
    exercises production code, not a copy) and asserts every branch of the verdict table.

    Regression this locks in: with no image on disk, $stable is $false, so an "elseif (-not
    $stable)" placed before the no-image check reported "file still growing (imager not
    finished)" and blamed Secure Boot/HVCI - on a host where no imager had ever been staged.
    Observed live on range-SQL01 (2026-07-27).

.EXAMPLE  pwsh -File tests/unit/Test-MemVerdict.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
# $PSScriptRoot is not reliably populated in a param default under -File, so resolve here.
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    # build with Join-Path segments, not a '..\..\' literal - backslash is not a separator on Linux CI
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'kit') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
$fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $args[0].Name -eq 'Resolve-MemVerdict' }, $true)
if ($fn.Count -ne 1) { throw "expected exactly 1 Resolve-MemVerdict definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

$RAM  = 8GB
$NEED = [int64]($RAM * 0.4)   # raw threshold the collector uses

# name, args, expected Code, expected Ok, expected DriverHint
$cases = @(
    @{ n='verified raw image'
       a=@{ Bytes=[int64]($RAM*0.9); Need=$NEED; HaveImage=$true;  Stable=$true;  Locked=$false; ImagerPresent=$true }
       code='verified';          ok=$true;  hint=$false }
    @{ n='verified at exactly the threshold'
       a=@{ Bytes=$NEED;             Need=$NEED; HaveImage=$true;  Stable=$true;  Locked=$false; ImagerPresent=$true }
       code='verified';          ok=$true;  hint=$false }
    @{ n='NO IMAGER STAGED (the SQL01 regression) - must not say "still growing" or blame the driver'
       a=@{ Bytes=[int64]0;          Need=$NEED; HaveImage=$false; Stable=$false; Locked=$false; ImagerPresent=$false }
       code='no-imager-staged';  ok=$false; hint=$false }
    @{ n='imager ran but produced nothing -> driver hint IS appropriate'
       a=@{ Bytes=[int64]0;          Need=$NEED; HaveImage=$false; Stable=$false; Locked=$false; ImagerPresent=$true }
       code='no-image-produced'; ok=$false; hint=$true }
    @{ n='hung imager still holding the file (lock beats instability)'
       a=@{ Bytes=[int64](1GB);      Need=$NEED; HaveImage=$true;  Stable=$false; Locked=$true;  ImagerPresent=$true }
       code='imager-holds-file'; ok=$false; hint=$true }
    @{ n='image still growing'
       a=@{ Bytes=[int64](1GB);      Need=$NEED; HaveImage=$true;  Stable=$false; Locked=$false; ImagerPresent=$true }
       code='image-growing';     ok=$false; hint=$true }
    @{ n='stable but truncated below threshold'
       a=@{ Bytes=[int64](64KB);     Need=$NEED; HaveImage=$true;  Stable=$true;  Locked=$false; ImagerPresent=$true }
       code='image-too-small';   ok=$false; hint=$true }
    @{ n='big + stable but LOCKED must not verify'
       a=@{ Bytes=[int64]($RAM*0.9); Need=$NEED; HaveImage=$true;  Stable=$true;  Locked=$true;  ImagerPresent=$true }
       code='imager-holds-file'; ok=$false; hint=$true }
    @{ n='compressed AFF4 passes its lower threshold'
       a=@{ Bytes=[int64](900MB);    Need=[int64]([math]::Max(200MB,$RAM*0.05)); HaveImage=$true; Stable=$true; Locked=$false; ImagerPresent=$true }
       code='verified';          ok=$true;  hint=$false }
)

$fail = 0
foreach ($c in $cases) {
    $sp = $c.a
    $r = Resolve-MemVerdict @sp
    $errs = @()
    if ($r.Code       -ne $c.code) { $errs += "Code='$($r.Code)' expected '$($c.code)'" }
    if ([bool]$r.Ok   -ne $c.ok)   { $errs += "Ok=$($r.Ok) expected $($c.ok)" }
    if ([bool]$r.DriverHint -ne $c.hint) { $errs += "DriverHint=$($r.DriverHint) expected $($c.hint)" }
    # a failure verdict must always give the operator something to read
    if (-not $r.Ok -and -not $r.Reason) { $errs += 'failure verdict has an empty Reason' }
    if ($r.Ok -and $r.Reason)           { $errs += "success verdict carries a Reason ('$($r.Reason)')" }
    if ($errs) { $fail++; Write-Host "FAIL  $($c.n)`n        $($errs -join "`n        ")" -ForegroundColor Red }
    else       { Write-Host "ok    $($c.n)  [$($r.Code)]" -ForegroundColor Green }
}

# guard the exact wording that misled us, in the case where it is wrong
$sqlish = Resolve-MemVerdict -Bytes 0 -Need $NEED -HaveImage $false -Stable $false -Locked $false -ImagerPresent $false
if ($sqlish.Reason -match 'growing') { $fail++; Write-Host 'FAIL  no-imager reason still mentions "growing"' -ForegroundColor Red }
else { Write-Host 'ok    no-imager reason does not mention "growing"' -ForegroundColor Green }

Write-Host "`n$($cases.Count + 1) assertions, $fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
