<#
.SYNOPSIS
    CI guard: IR-Collect.ps1 must stay free of the signature defect shape.

.DESCRIPTION
    The shape is

        $x = <safe default>            # a value meaning "nothing to worry about"
        try { $x = <probe> } catch {}  # the probe may never run; the failure is discarded
        if ($x) { ...decision... }     # a decision taken on a value that may be the default

    It shipped once, in Show-VolatileGate, and its failure mode is the worst in this project: a
    BitLocker probe that threw left $encRisk at $false, the console printed GREEN, and the
    do-not-power-off banner never appeared. A responder powers the host off and the disk image is
    unreadable for good.

    THE CALIBRATION IS THE POINT, NOT THE ZERO. On the Linux side an earlier detector reported 0
    on the current collector AND 0 on a file that provably contained the bug, and would have
    shipped a false all-clear. So this guard refuses to report clean unless it has first re-found a
    known defect in a vendored fixture.

    Three outcomes, deliberately distinct:
      pass      calibration found the known defect AND the collector is clean
      FAIL (1)  the collector grew a new instance - a product regression
      exit 2    the guard could not calibrate - a TOOL failure, never reported as clean

    The known positive is VENDORED (tests/tools/fixtures/known-positive-bitlocker-gate.ps1) rather
    than fetched with `git show <sha>~1`: CI checks out at depth 1, that revision does not exist
    there, and the calibration would silently pass over an empty file.

.EXAMPLE  pwsh -File tests/unit/Test-SafeDefaultGuard.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $here)
$det       = Join-Path $repo 'tests\tools\Find-SafeDefaultShape.ps1'
$fixture   = Join-Path $repo 'tests\tools\fixtures\known-positive-bitlocker-gate.ps1'
$collector = Join-Path $repo 'collectors\IR-Collect.ps1'

foreach ($f in @($det, $fixture, $collector)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host "FAIL  guard input missing: $f"; exit 2 }
}

$fail = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "ok    $what" } else { Write-Host "FAIL  $what"; $script:fail++ }
}
function Get-Hits([string]$target) {
    $out = & pwsh -NoProfile -File $det $target 2>&1
    $line = $out | Select-String -Pattern 'ranked hits:\s*(\d+)\s+of' | Select-Object -First 1
    if (-not $line) { return @{ ok = $false; text = ($out -join "`n") } }
    return @{ ok = $true; hits = [int]$line.Matches[0].Groups[1].Value; text = ($out -join "`n") }
}

# --- 1. CALIBRATION: the detector must re-find the known defect -------------------------------
$cal = Get-Hits $fixture
if (-not $cal.ok) {
    Write-Host 'FAIL  the detector produced no hit count for the calibration fixture - guard is broken, NOT clean'
    Write-Host ($cal.text -split "`n" | Select-Object -First 6 | ForEach-Object { "      $_" })
    exit 2
}
Check ($cal.hits -eq 1) "calibration: the detector re-finds the known BitLocker defect (got $($cal.hits), need 1)"
if ($cal.hits -ne 1) {
    Write-Host '      A detector that cannot find a defect it is known to contain proves nothing about'
    Write-Host '      the collector. Refusing to report the result below as clean.'
    exit 2
}
Check ($cal.text -match '\$encRisk') 'calibration: the hit is the encryption risk flag, not something incidental'

# --- 2. the actual guard: no instance beyond the JUDGED baseline ------------------------------
# Windows is not at zero, and a blanket "must be 0" would ship a permanently red test - the
# cries-wolf failure this project has a rule about. Three sites carry the shape and were each
# judged individually during the 2026-07-29 audit; they are allowlisted BY VARIABLE NAME (line
# numbers drift) with the reason each is safe. Anything else is a regression.
#
# The allowlist is also checked for staleness: if a listed site disappears, the entry is obsolete
# and should be removed rather than left to silently excuse a future hit with the same name.
$accepted = @{
    'alts'              = 'alternate-imager search; a failed search leaves the list empty so the rung returns false and the ladder ENDS - fails toward giving up, never toward false success'
    'script:GuestTools' = 'guest-tool inventory; $script:Hypervisor beside it is ALREADY three-state (unknown), and an empty tool list is informational, not a decision that costs evidence'
    'n'                 = 'volatile artifact count; the GREEN branch requires $n -ge 10, so a failed count CANNOT produce GREEN - correct by construction'
}

$cur = Get-Hits $collector
if (-not $cur.ok) {
    Write-Host 'FAIL  the detector produced no hit count for the collector - guard is broken, NOT clean'
    exit 2
}
$found = @()
foreach ($m in ([regex]::Matches($cur.text, '(?m)^\s+line\s+\d+\s+\$?([A-Za-z_][A-Za-z0-9_:]*)'))) {
    $found += $m.Groups[1].Value
}
$found = @($found | Select-Object -Unique)
$unexpected = @($found | Where-Object { -not $accepted.ContainsKey($_) })
$missing    = @($accepted.Keys | Where-Object { $found -notcontains $_ })

Check ($found.Count -ge 1) "the detector reported the collector's hit list ($($found.Count) site(s))"
Check ($unexpected.Count -eq 0) "no safe-default site beyond the judged baseline ($($unexpected.Count) new)"
if ($unexpected.Count) {
    Write-Host '      NEW INSTANCE(S) - a probe that fails now answers on the safe side. Judge each before'
    Write-Host '      allowlisting it; the question is whether the DEFAULT is the safe side of a decision'
    Write-Host '      whose wrong answer costs evidence:'
    $unexpected | ForEach-Object { Write-Host "        `$$_" }
}
Check ($missing.Count -eq 0) "the allowlist has no stale entries ($($missing.Count) listed but absent)"
if ($missing.Count) {
    Write-Host '      These are allowlisted but no longer present - remove them, or a future site reusing'
    Write-Host '      the name would be excused without ever being judged:'
    $missing | ForEach-Object { Write-Host "        `$$_" }
}

# --- 3. the volume guard must still be armed --------------------------------------------------
# A zero only means something if the detector still finds the swallowing try/catch blocks at all.
$m = $cur.text | Select-String -Pattern 'SWALLOW and assign a variable:\s*(\d+)' | Select-Object -First 1
$swallow = if ($m) { [int]$m.Matches[0].Groups[1].Value } else { 0 }
Check ($swallow -ge 20) "the detector still finds the collector's swallowing assignments ($swallow, expect >=20)"

Write-Host ''
if ($fail -eq 0) { Write-Host 'all assertions passed'; exit 0 } else { Write-Host "$fail failed"; exit 1 }
