<#
.SYNOPSIS
    Audits the self-fix ladders in BOTH collectors: every declared rung must be implemented, and
    the two platforms must agree on which error classes exist.

.DESCRIPTION
    The tool's contract is that every error class has an ORDERED LADDER of real fix attempts, so
    a collection completes rather than merely failing honestly. Two ways that silently rots:

      1. A rung is named in a ladder but never implemented. Invoke-FixRung's `default` arm
         returns $false, which reads as "this fix was tried and did not help" - it terminates the
         ladder early, so every rung BELOW it (including `skip`) is unreachable. Found by this
         test 2026-07-28: `retry-in-place` was declared in the Windows no_space ladder and
         implemented only on Linux, so the Windows ladder quietly stopped one rung short.

      2. The platforms drift. The requirement is that Windows and Linux self-heal equivalently;
         a class handled on one and absent on the other is a parity hole, not a platform quirk.

    This test parses both shipped collectors - it is not a copy of the tables.

.EXAMPLE  pwsh -File tests/unit/Test-FixLadders.ps1
#>
[CmdletBinding()]
param([string]$WinCollector, [string]$ShCollector)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $root)
if (-not $WinCollector) { $WinCollector = Join-Path (Join-Path $repo 'collectors') 'IR-Collect.ps1' }
if (-not $ShCollector)  { $ShCollector  = Join-Path (Join-Path $repo 'collectors') 'ir-collect.sh' }

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

# ---------------- Windows: declared ladders + implemented rungs ----------------
$winText = [IO.File]::ReadAllText($WinCollector)
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $WinCollector), [ref]$null, [ref]$null)

$ladderAsg = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    "$($args[0].Left)" -match 'FixLadders' }, $true)
if ($ladderAsg.Count -ne 1) { throw "expected 1 FixLadders assignment, found $($ladderAsg.Count)" }
$winLadders = [ordered]@{}
foreach ($kv in $ladderAsg[0].Right.Expression.KeyValuePairs) {
    $cls = "$($kv.Item1)".Trim("'", '"')
    $winLadders[$cls] = @([regex]::Matches("$($kv.Item2)", "'([a-z][a-z0-9-]*)'") | ForEach-Object { $_.Groups[1].Value })
}
Check ($winLadders.Count -ge 8) "parsed the Windows ladder table ($($winLadders.Count) classes)"

# the rung names Invoke-FixRung actually handles, taken from its switch arms
$rungFn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                         $args[0].Name -eq 'Invoke-FixRung' }, $true)
if ($rungFn.Count -ne 1) { throw "expected 1 Invoke-FixRung definition, found $($rungFn.Count)" }
$rungBody = $rungFn[0].Extent.Text
$winImpl = @([regex]::Matches($rungBody, "(?m)^\s+'([a-z][a-z0-9-]*)'\s*\{") | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique
Check ($winImpl.Count -ge 8) "parsed the Windows rung implementations ($($winImpl.Count) rungs)"

$winDeclared = @($winLadders.Values | ForEach-Object { $_ }) | Sort-Object -Unique
$winOrphan = @($winDeclared | Where-Object { $_ -notin $winImpl })
Check ($winOrphan.Count -eq 0) "every Windows rung declared in a ladder is implemented$(if($winOrphan){ ' -> ORPHANED: ' + ($winOrphan -join ', ') })   <-- the regression"

# a ladder must END in a terminator, or a class that exhausts its fixes has no defined outcome
foreach ($cls in $winLadders.Keys) {
    Check ($winLadders[$cls][-1] -eq 'skip') "Windows ladder '$cls' terminates in 'skip' (last = '$($winLadders[$cls][-1])')"
}
# an implemented rung nobody can reach is dead weight - flag it rather than let it accumulate
$winUnused = @($winImpl | Where-Object { $_ -notin $winDeclared })
Check ($winUnused.Count -eq 0) "no Windows rung is implemented but unreachable$(if($winUnused){ ' -> ' + ($winUnused -join ', ') })"

# ---------------- Linux: same two questions ----------------
$shText = [IO.File]::ReadAllText($ShCollector)
$shLadderFn = [regex]::Match($shText, "(?ms)^fix_ladder\(\)\s*\{.*?^\}").Value
if (-not $shLadderFn) { throw "could not extract fix_ladder from $ShCollector" }
$shLadders = [ordered]@{}
foreach ($m in [regex]::Matches($shLadderFn, '(?m)^\s*([a-z_|]+)\)\s*echo\s+"([^"]+)"')) {
    foreach ($cls in $m.Groups[1].Value -split '\|') {
        if ($cls -eq '*') { $cls = '(default)' }
        $shLadders[$cls] = @($m.Groups[2].Value -split '\s+' | Where-Object { $_ })
    }
}
Check ($shLadders.Count -ge 6) "parsed the Linux ladder table ($($shLadders.Count) classes)"

$shRungFn = [regex]::Match($shText, "(?ms)^invoke_fix_rung\(\)\s*\{.*?^\}").Value
if (-not $shRungFn) { throw "could not extract invoke_fix_rung from $ShCollector" }
$shImpl = @([regex]::Matches($shRungFn, '(?m)^\s+([a-z][a-z0-9|-]*)\)') | ForEach-Object { $_.Groups[1].Value -split '\|' }) | Sort-Object -Unique
$shDeclared = @($shLadders.Values | ForEach-Object { $_ }) | Sort-Object -Unique
$shOrphan = @($shDeclared | Where-Object { $_ -notin $shImpl })
Check ($shOrphan.Count -eq 0) "every Linux rung declared in a ladder is implemented$(if($shOrphan){ ' -> ORPHANED: ' + ($shOrphan -join ', ') })"
foreach ($cls in $shLadders.Keys) {
    Check ($shLadders[$cls][-1] -eq 'skip') "Linux ladder '$cls' terminates in 'skip' (last = '$($shLadders[$cls][-1])')"
}

# ---------------- cross-platform parity ----------------
# Classes that describe a HOST condition must exist on both. A few are genuinely platform-bound
# (ConstrainedLanguage and the PowerShell job subsystem have no Linux analogue), so they are
# named here deliberately rather than the assertion being weakened to nothing.
$winOnlyOk = @('clm_blocked','job_subsystem','wmi_failure','path_too_long')
$shOnlyOk  = @('(default)')
$winClasses = @($winLadders.Keys)
$shClasses  = @($shLadders.Keys)
$missingOnSh  = @($winClasses | Where-Object { $_ -notin $shClasses -and $_ -notin $winOnlyOk })
$missingOnWin = @($shClasses  | Where-Object { $_ -notin $winClasses -and $_ -notin $shOnlyOk })
Check ($missingOnSh.Count -eq 0)  "no Windows error class is unhandled on Linux$(if($missingOnSh){ ' -> ' + ($missingOnSh -join ', ') })"
Check ($missingOnWin.Count -eq 0) "no Linux error class is unhandled on Windows$(if($missingOnWin){ ' -> ' + ($missingOnWin -join ', ') })"

# ---------------- rungs must DO something ----------------
# A rung whose whole body is an audit line and `return $true` is a marker: it reports a fix that
# never happened, then the retry fails the same way. `skip` is the deliberate exception - its job
# is to stop. `backoff-retry` is also exempt: the wait IS the fix, applied by the caller.
# `native-source` is exempt for a stated reason: its recovery is implemented in the STEP bodies
# (try CIM -> catch -> native tool), which E1 verified live, so there is nothing for the rung
# itself to do beyond permitting the retry. That is a real mechanism, not a marker.
$markerExempt = @('skip','backoff-retry','native-source')
$markers = @()
foreach ($m in [regex]::Matches($rungBody, "(?ms)^\s+'([a-z][a-z0-9-]*)'\s*\{(.*?)^?\s*\}\s*$")) {
    $name = $m.Groups[1].Value
    if ($name -in $markerExempt) { continue }
    $body = $m.Groups[2].Value
    $stripped = ($body -replace 'Write-Audit[^\r\n]*','' -replace 'return\s+\$(true|false)','' -replace '[\s;]','')
    if (-not $stripped) { $markers += $name }
}
Check ($markers.Count -eq 0) "no Windows rung is a bare marker (audit line + return, no action)$(if($markers){ ' -> ' + ($markers -join ', ') })"

# ---------------- a ladder for a class nobody raises is dead code ----------------
# Get-ErrorClass is the only producer of these strings. A ladder keyed to a class the classifier
# can never return is never consulted, however well written it is. Caught 2026-07-28: the
# driver_blocked ladder was added for Linux parity before the Windows classifier could emit it.
$clsFn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                        $args[0].Name -eq 'Get-ErrorClass' }, $true)
if ($clsFn.Count -ne 1) { throw "expected 1 Get-ErrorClass definition, found $($clsFn.Count)" }
$emitted = @([regex]::Matches($clsFn[0].Extent.Text, "return\s+'([a-z_]+)'") | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique
Check ($emitted.Count -ge 8) "parsed the Windows classifier ($($emitted.Count) classes emitted)"
$deadLadders = @($winClasses | Where-Object { $_ -notin $emitted })
Check ($deadLadders.Count -eq 0) "every Windows ladder is keyed to a class the classifier can emit$(if($deadLadders){ ' -> DEAD: ' + ($deadLadders -join ', ') })"
# and the converse: a class that can be raised but has no ladder falls back to nothing
$unladdered = @($emitted | Where-Object { $_ -notin $winClasses -and $_ -ne 'unknown' })
Check ($unladdered.Count -eq 0) "every class the classifier emits has a ladder$(if($unladdered){ ' -> ' + ($unladdered -join ', ') })"

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
