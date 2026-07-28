<#
.SYNOPSIS
    Unit test for New-ManifestScript in collectors/IR-Collect.ps1 (evidence-manifest coverage).

.DESCRIPTION
    Extracts the real generator via the PowerShell AST, runs the script it emits against a
    synthetic evidence tree, and asserts the manifest covers every file - including HIDDEN and
    SYSTEM ones.

    Regression this locks in: the manifest enumerated with `Get-ChildItem -Recurse -File` and no
    -Force, so hidden+system files were invisible to it. Copied per-user hives (NTUSER.DAT,
    UsrClass.dat) carry those attributes, so on real range hosts 17/17 (SQL01) and 19/19 (WS02)
    per-user hives were in evidence but had NO manifest entry - nothing to verify them against.
    Measured 2026-07-27.

.EXAMPLE  pwsh -File tests/unit/Test-ManifestScript.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'collectors') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
$fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $args[0].Name -eq 'New-ManifestScript' }, $true)
if ($fn.Count -ne 1) { throw "expected exactly 1 New-ManifestScript definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

# New-ManifestScript prepends the hashing shim, so the test must reproduce the real runtime
# composition - $script:HashShimText has to exist here or every hash silently becomes 'ERR'
# (which is precisely the failure mode this file guards against).
$asg = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    "$($args[0].Left)" -match 'HashShimText' }, $true)
if ($asg.Count -ne 1) { throw "expected 1 HashShimText assignment, found $($asg.Count)" }
$script:HashShimText = $asg[0].Right.Expression.Value

# --- synthetic evidence tree -------------------------------------------------
$dir = Join-Path ([IO.Path]::GetTempPath()) ("manitest_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $dir | Out-Null
New-Item -ItemType Directory -Force (Join-Path $dir '99_logs') | Out-Null
New-Item -ItemType Directory -Force (Join-Path (Join-Path (Join-Path $dir '05_artifacts') 'userhives') 'alice') | Out-Null

$plainRel  = 'SUMMARY.md'
$hiveRel   = Join-Path (Join-Path (Join-Path '05_artifacts' 'userhives') 'alice') 'NTUSER.DAT'
$auditRel  = Join-Path '99_logs' 'audit.log'
$manRel    = Join-Path '99_logs' 'MANIFEST-SHA256.csv'
Set-Content (Join-Path $dir $plainRel) 'summary'   -Encoding UTF8
Set-Content (Join-Path $dir $hiveRel)  'fakehive'  -Encoding UTF8
Set-Content (Join-Path $dir $auditRel) 'audit'     -Encoding UTF8
Set-Content (Join-Path $dir $manRel)   'stale'     -Encoding UTF8

# mark the hive hidden+system exactly as a robocopy'd NTUSER.DAT arrives.
# (Attribute juggling is Windows-only; on Linux CI the coverage assertion still runs, and the
#  -Force flag assertion below is the platform-independent guard.)
$isWindows_ = $true
try { if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { $isWindows_ = $false } } catch {}
if ($isWindows_) {
    $fi = Get-Item (Join-Path $dir $hiveRel) -Force
    $fi.Attributes = $fi.Attributes -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    "hive attributes set to: $((Get-Item (Join-Path $dir $hiveRel) -Force).Attributes)"
} else {
    'non-Windows: skipping hidden/system attribute step (coverage assertion still applies)'
}

# --- run the generated manifest script ---------------------------------------
$scriptText = New-ManifestScript $dir
$rows = & ([scriptblock]::Create($scriptText))
# A backslash is an ordinary filename character on Linux, so building these paths as
# backslash literals created ONE oddly-named directory and every coverage assertion compared
# mismatched separators. The test asserts COVERAGE, not path formatting - normalise both sides.
function Norm([string]$p) { $p.Replace([char]92, [char]47).TrimStart([char]47) }
$covered = @{}
foreach ($r in @($rows)) {
    $p = ($r -split ',', 3)
    if ($p.Count -eq 3) { $covered[(Norm $p[2])] = $p[0] }
}

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green }
    else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

Check ($scriptText -match '-Force') 'generated manifest script passes -Force to Get-ChildItem'
# without the shim prepended, Get-IRSha256 is undefined inside the Start-Job child and every
# row degrades to 'ERR' - assert the dependency explicitly so a refactor cannot drop it silently
Check ($scriptText -match 'function Get-IRSha256') 'generated script carries the hashing shim (Start-Job children inherit no functions)'
Check ($covered.ContainsKey((Norm $plainRel))) "covers a normal file ($plainRel)"
Check ($covered.ContainsKey((Norm $hiveRel)))  "covers a HIDDEN+SYSTEM per-user hive ($hiveRel)  <-- the regression"
Check (-not $covered.ContainsKey((Norm $manRel)))   'excludes MANIFEST-SHA256.csv itself (it is being written)'
# The generator excludes the live audit.log with a regex containing a literal backslash
# ('99_logs\\(audit|errors)\.log$'). That is CORRECT - IR-Collect.ps1 only ever runs on Windows,
# where that is the separator. Asserting the runtime effect on a Linux CI runner tests the
# runner, not the collector, so split it: the pattern's PRESENCE is checked everywhere (a
# refactor that drops the exclusion fails on every platform), and its EFFECT only where the
# separator matches. Weakening it to nothing would have been the easy wrong answer.
Check ($scriptText -match "99_logs.*audit\|errors") 'generated script carries the audit/errors-log exclusion'
if ($isWindows_) {
    Check (-not $covered.ContainsKey((Norm $auditRel))) 'excludes the live audit.log (frozen copy is hashed separately)'
} else {
    # the accounting assertion below already lists $auditRel as deliberately excluded, so it
    # stays honest without adjustment here
    Write-Host 'SKIP  audit.log exclusion effect - backslash separator does not apply on this host' -ForegroundColor Yellow
}
if ($covered.ContainsKey((Norm $hiveRel))) {
    Check ($covered[(Norm $hiveRel)] -match '^[0-9A-Fa-f]{64}$') 'hive entry carries a real SHA-256, not ERR'
}
# every file present must be accounted for as either covered or deliberately excluded
$expectExcluded = @((Norm $manRel), (Norm $auditRel))
$onDisk = Get-ChildItem $dir -Recurse -File -Force | ForEach-Object { Norm $_.FullName.Substring($dir.Length) }
$unaccounted = @($onDisk | Where-Object { -not $covered.ContainsKey($_) -and $_ -notin $expectExcluded })
Check ($unaccounted.Count -eq 0) "no file is silently unaccounted for (found $($unaccounted.Count): $($unaccounted -join ', '))"

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
