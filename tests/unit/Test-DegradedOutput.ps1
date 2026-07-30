<#
.SYNOPSIS
    Unit test for Test-DegradedOutput in collectors/IR-Collect.ps1 (access-denied stub detection).

.DESCRIPTION
    Extracts the shipped function via the PowerShell AST and drives it against synthetic step
    outputs.

    Regression this locks in: the collector only treated a step as producing nothing when the
    output file was <= 2 bytes. Run as a standard user on range-WS02 (2026-07-28) the privileged
    steps wrote refusals, not data - drivers.txt 115096 B -> 155 B, netstat_anob.txt 8140 B ->
    45 B, sessions.txt 597 B -> 10 B. Every one cleared the 2-byte bar, so empty_outputs was 0,
    nothing was classified, and the bundle sealed verdict=COMPLETE with ok=33 fail=0 skip=0 -
    indistinguishable from a healthy elevated run. An analyst would read "no unusual drivers"
    off a driver list that was never permitted to load.

    The counter-risk is over-triggering: a large healthy artifact may legitimately contain the
    words "Access is denied" (a log excerpt, an ACL dump). Those must NOT be called degraded,
    which is why the density/size gates exist and are asserted here.

.EXAMPLE  pwsh -File tests/unit/Test-DegradedOutput.ps1
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
                     $args[0].Name -eq 'Test-DegradedOutput' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 Test-DegradedOutput definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

# the function reads $script:DenialPattern from the parent scope - take the SHIPPED value, so a
# future edit to the pattern is exercised here rather than against a stale copy
$asg = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    "$($args[0].Left)" -match 'DenialPattern' }, $true)
if ($asg.Count -ne 1) { throw "expected 1 DenialPattern assignment, found $($asg.Count)" }
$script:DenialPattern = $asg[0].Right.Expression.Value

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}
function New-Out([string]$text) {
    $p = Join-Path ([IO.Path]::GetTempPath()) ("degr_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.txt')
    [IO.File]::WriteAllText($p, $text); $p
}
function Probe([string]$text) {
    $p = New-Out $text
    try { Test-DegradedOutput -Path $p -Bytes (Get-Item $p).Length } finally { Remove-Item $p -Force -EA SilentlyContinue }
}

# --- the measured real-world stubs ---
$driversStub = "Get-CimInstance : Access is denied. `r`n    + CategoryInfo : PermissionDenied: (:) [Get-CimInstance], CimException`r`n"
Check ([bool](Probe $driversStub))  'a 155-byte "Access is denied" drivers stub is DEGRADED   <-- the regression'

$netstatStub = "The requested operation requires elevation.`r`n"
Check ([bool](Probe $netstatStub))  'a 45-byte "requires elevation" netstat stub is DEGRADED'

$sessionStub = "Access is denied.`r`n"
Check ([bool](Probe $sessionStub))  'a 10-byte session refusal is DEGRADED'

# the reason must be operator-readable, not a bare $true
$r = Probe $driversStub
Check ($r -is [string] -and $r.Length -gt 5) "returns the offending line as the reason ('$r')"

# --- healthy output must NEVER be called degraded (the over-trigger risk) ---
$healthy = (1..800 | ForEach-Object { "svc$_    Running    Auto    C:\Windows\System32\drivers\d$_.sys" }) -join "`r`n"
Check (-not (Probe $healthy)) 'a large healthy driver table is NOT degraded'

$healthyWithMention = $healthy + "`r`nSecurity log excerpt: 4656 Access is denied for user bob`r`n"
Check (-not (Probe $healthyWithMention)) 'a large healthy artifact that merely MENTIONS "Access is denied" once is NOT degraded'

$noDenial = "no matching processes found`r`n"
Check (-not (Probe $noDenial)) 'a small file with no denial text is NOT degraded (that is emptiness, handled elsewhere)'

# --- size gate: a SMALL output where refusals are a minority of lines but still present.
# Only the $Bytes -lt 4096 arm catches this; without it the case slips through as "healthy".
# A ~200-byte artifact that had to refuse anything did not collect what it claims to have.
$smallMinority = @(
    'Driver Name    State    Start Mode',
    'Get-CimInstance : Access is denied.',
    'sc.exe query : Access is denied.',
    'beep           Running  System',
    'null           Running  System',
    'tcpip          Running  Boot',
    'volmgr         Running  Boot',
    'ntfs           Running  Boot'
) -join "`r`n"
$smallLen = [Text.Encoding]::UTF8.GetByteCount($smallMinority)
Check ($smallLen -lt 4096 -and $smallLen -gt 32) "size-gate fixture really is small ($smallLen B) - the fixture, not the code, would be the bug"
Check ((@($smallMinority -split "`r`n" | Where-Object { $_ -match 'denied' }).Count / 8) -lt 0.5) 'size-gate fixture really has a MINORITY of denial lines (density gate cannot catch it)'
Check ([bool](Probe $smallMinority)) 'a small artifact with a MINORITY of refusals IS degraded (size gate)'

# --- density gate: denials outnumbering content, above the small-file cutoff ---
$dense = ((1..300 | ForEach-Object { "row $_ : Access is denied." }) + (1..50 | ForEach-Object { "ok row $_" })) -join "`r`n"
Check ([bool](Probe $dense)) 'a >4 KB file that is mostly refusals IS degraded (density gate)'

$sparse = ((1..40 | ForEach-Object { "row $_ : Access is denied." }) + (1..600 | ForEach-Object { "real data row $_" })) -join "`r`n"
Check (-not (Probe $sparse)) 'a mostly-data file with a minority of denials is NOT degraded'

# --- the collector must not incriminate ITSELF ---------------------------------
# The fallback banners the collector writes into its own artifacts are prose. If a banner
# happens to contain a denial phrase ("requires elevation"), then on a quiet host a SMALL but
# perfectly healthy artifact trips the size gate on the collector's own words and gets reported
# as degraded. Caught live 2026-07-28: the netstat fallback banner read "netstat -anob requires
# elevation", which the pattern matches.
$banners = [regex]::Matches($ast.Extent.Text, "###[^#
]{4,200}###") | ForEach-Object { $_.Value }
Check ($banners.Count -ge 3) "found the collector's own ### banners to check ($($banners.Count))"
$selfMatch = @($banners | Where-Object { $_ -match $script:DenialPattern })
Check ($selfMatch.Count -eq 0) "no fallback banner matches the denial pattern$(if($selfMatch){ ' -> ' + ($selfMatch -join ' | ') })"

# --- guards ---
Check ($null -eq (Test-DegradedOutput -Path (Join-Path ([IO.Path]::GetTempPath()) 'no_such_file_xyz.txt') -Bytes 100)) 'missing file returns null, does not throw'
Check ($null -eq (Test-DegradedOutput -Path '' -Bytes 0)) 'empty path returns null, does not throw'
$big = New-Out ($driversStub * 4000)
Check ($null -eq (Test-DegradedOutput -Path $big -Bytes (Get-Item $big).Length)) 'a >64 KB file is skipped outright (large artifacts are never stubs)'
Remove-Item $big -Force -EA SilentlyContinue

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
