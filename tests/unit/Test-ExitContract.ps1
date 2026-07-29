<#
.SYNOPSIS
    Audits that both collectors implement the SAME exit-code contract.

.DESCRIPTION
    The exit code is the machine-readable answer to "can I trust this bundle?", and it is the only
    part of the tool most automation ever reads. Two collectors that document or implement it
    differently is how a consumer ends up correctly handling one platform and silently
    mis-handling the other.

    Contract (both platforms):
        0   clean
        10  completed with skips, OR the evidence never reached its destination
        15  incomplete - critical evidence missing
        20  RAM not captured on a non-rapid run
        40  fatal / refused before collecting

    Note on the SHIP: on both platforms run_state.json is written and hashed into the manifest
    BEFORE the bundle is shipped, so the ship outcome cannot appear in the completeness verdict
    without either lying or invalidating the seal. It reaches the EXIT CODE instead (Windows via
    an explicit ShipOk rule, Linux via STEPS_FAIL since rsync/scp run through run_step), and the
    detail is written to <bundle>.ship.json beside the bundle. That is deliberate, not a gap -
    recorded here because it looked like a divergence on first inspection and is worth not
    re-litigating.

.EXAMPLE  pwsh -File tests/unit/Test-ExitContract.ps1
#>
[CmdletBinding()]
param([string]$WinCollector, [string]$ShCollector)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $root)
if (-not $WinCollector) { $WinCollector = Join-Path (Join-Path $repo 'collectors') 'IR-Collect.ps1' }
if (-not $ShCollector)  { $ShCollector  = Join-Path (Join-Path $repo 'collectors') 'ir-collect.sh' }
$win = [IO.File]::ReadAllText($WinCollector)
$sh  = [IO.File]::ReadAllText($ShCollector)

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

# --- the documented legend must be identical, character for character ---
$reLegend = '\(0=clean [^)]*40=fatal\)'
$wm = [regex]::Match($win, $reLegend)
$sm = [regex]::Match($sh,  $reLegend)
Check ($wm.Success) "Windows documents an exit legend"
Check ($sm.Success) "Linux documents an exit legend"
if ($wm.Success -and $sm.Success) {
    Check ($wm.Value -eq $sm.Value) "both legends are identical`n        win: $($wm.Value)`n        sh : $($sm.Value)"
    Check ($wm.Value -match 'ship-failed') "the legend mentions a failed ship (10 is not only about skips)"
}

# --- every documented code must actually be assignable in each script ---
foreach ($code in 10, 15, 20, 40) {
    Check ($win -match "exitCode = $code|exit $code") "Windows can return $code"
    Check ($sh  -match "EXIT_CODE=$code|exit $code")  "Linux can return $code"
}

# --- a failed ship must not be able to report clean on either platform ---
Check ($win -match '\$script:ShipOk -eq \$false') 'Windows raises the exit code when the ship failed'
Check ($sh  -match 'run_step ship-(rsync|scp)')    'Linux ships through run_step, so a failure raises STEPS_FAIL'

# --- and the ship detail lands beside the bundle on both, never inside the sealed tree ---
Check ($win -match '\.ship\.json') 'Windows writes a ship-result file'
Check ($sh  -match '\.ship\.json') 'Linux writes a ship-result file'
Check ($win -match 'preflight_ok') 'Windows records the preflight outcome in it'
Check ($sh  -match 'preflight_ok') 'Linux records the preflight outcome in it'

# --- minimum engine version (scenario E5) --------------------------------------------------
# The collector uses [pscustomobject], Get-CimInstance and [ordered] hashtables - none of which
# exist in PowerShell 2.0. Without a #requires it PARSES under v2, starts collecting, and dies
# partway with errors that look like a broken host rather than a wrong interpreter. Verified live
# 2026-07-29 by temporarily requiring v99: exit 1, zero stdout, zero bundles - it refuses before
# doing anything. Guard the directive so a refactor cannot drop it.
$winLines = [IO.File]::ReadAllLines($WinCollector)
$req = @($winLines | Where-Object { $_ -match '^\s*#requires\s+-Version\s+(\d+)' })
Check ($req.Count -ge 1) 'the Windows collector declares a minimum engine version (#requires)'
if ($req.Count) {
    $v = [int]([regex]::Match($req[0], '-Version\s+(\d+)').Groups[1].Value)
    Check ($v -ge 3) "the declared minimum is v3 or higher (got v$v) - v2 lacks [pscustomobject], Get-CimInstance and [ordered]"
    $idx = [array]::FindIndex($winLines, [Predicate[string]]{ param($l) $l -match '^\s*#requires' })
    $codeBefore = @($winLines[0..([Math]::Max(0,$idx-1))] | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*<#' })
    Check ($codeBefore.Count -eq 0) 'nothing executable precedes the #requires directive'
}

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
