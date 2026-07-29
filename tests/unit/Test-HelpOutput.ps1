<#
.SYNOPSIS
    CI guard: Get-Help must actually render IR-Collect.ps1's comment-based help.

.DESCRIPTION
    The collector shipped with fifty lines of accurate comment-based help that Get-Help never
    showed anyone. `Get-Help .\IR-Collect.ps1 -Full` returned a 495-character auto-generated syntax
    stub. Nothing errored, nothing warned, the documentation was right there in the file, and it
    was unreachable. Three separate causes, each silent:

      1. NO BLANK LINE between the #requires/comment preamble and the opening <#. PowerShell then
         treats the preamble as contiguous with the help block and discards all of it. This one
         alone killed the whole block.
      2. .NOTES and .EXAMPLE with their text on the SAME LINE as the keyword. Also fatal to the
         entire block, not just to that section.
      3. .PARAMETER with its text on the same line. NOT fatal - and that is worse, because the
         block still renders while every same-line description is quietly dropped.

    So this guard does not check that the help "looks right" in the source. It runs Get-Help and
    asserts the rendered output, which is the only thing an operator ever sees.

    THE CALIBRATION IS THE POINT. "Get-Help returned something" is true of the stub too, and the
    stub is what failure looks like. So the guard first proves it can still DETECT dead help, using
    a vendored fixture whose CBH is broken on purpose
    (tests/tools/fixtures/known-positive-dead-cbh.ps1). If that fixture starts rendering - a newer
    PowerShell tolerating the shape - the guard reports GUARD-BROKEN rather than passing, because
    its own notion of "dead" would no longer be calibrated.

    Three outcomes: 0 pass | 1 the help regressed | 2 the guard could not run.

.EXAMPLE
    pwsh -File tests/unit/Test-HelpOutput.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $here)
$collector = Join-Path $repo 'collectors\IR-Collect.ps1'
$fixture   = Join-Path $repo 'tests\tools\fixtures\known-positive-dead-cbh.ps1'

foreach ($f in @($collector, $fixture)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host "FAIL  guard input missing: $f"; exit 2 }
}

$fail = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "ok    $what" } else { Write-Host "FAIL  $what"; $script:fail++ }
}
function Get-RenderedHelp([string]$path) {
    try { return (Get-Help -Name $path -Full 2>&1 | Out-String) } catch { return '' }
}

# --- 1. CALIBRATION: dead help must still be detectable as dead ------------------------------
$dead = Get-RenderedHelp $fixture
if ([string]::IsNullOrWhiteSpace($dead)) {
    Write-Host 'FAIL  Get-Help produced nothing at all for the calibration fixture - guard broken, NOT clean'
    exit 2
}
if ($dead -match 'CALIBRATIONMARKER') {
    Write-Host 'FAIL  the known-dead fixture RENDERS on this PowerShell - the breakage this guard'
    Write-Host '      detects no longer reproduces, so a pass below would mean nothing. Revisit the'
    Write-Host "      guard rather than trusting it. (PSVersion $($PSVersionTable.PSVersion))"
    exit 2
}
Check ($dead.Length -lt 2000) "calibration: dead help renders as a short stub ($($dead.Length) chars)"

# --- 2. the collector's help must actually render ---------------------------------------------
$help = Get-RenderedHelp $collector
Check ($help.Length -gt 5000) "Get-Help renders real help for the collector ($($help.Length) chars; the stub was 495)"
if ($help.Length -le 5000) {
    Write-Host '      This is the original defect: the help block is present in the file but Get-Help'
    Write-Host '      is falling back to the auto-generated syntax stub. Check for a missing blank'
    Write-Host '      line before <#, or .NOTES/.EXAMPLE text on the same line as the keyword.'
    Write-Host ''
    Write-Host "$fail failed"; exit 1
}

# --- 3. and it must contain what a responder came for -----------------------------------------
# Rendered content, not source text: source can be correct while the renderer drops it, which is
# exactly how the .PARAMETER same-line descriptions went missing.
foreach ($pair in @(
    @('Exit codes',                'the exit contract'),
    @('DO-NOT-POWER-OFF',          'the encryption-risk signal'),
    @('unknown-no-ram',            "encryption_risk's undetermined state"),
    @('by_error_class',            'the failure tally'),
    @('DECRYPTION-KEYS',           'where captured key material lands'),
    @('Case identifier',           'per-parameter descriptions (dropped when .PARAMETER text is inline)')
)) {
    Check ($help -match [regex]::Escape($pair[0])) "help renders $($pair[1])"
}

# --- 4. `unknown` must not be presented as an all-clear ---------------------------------------
Check ($help -match 'NOT a claim that the disk is') "help says 'unknown' is not a claim the disk is clear"

# --- 5. every declared parameter is documented ------------------------------------------------
# The staleness half: -Dest was renamed from -OutputRoot and the help kept documenting the alias,
# while fourteen real parameters had no entry at all. Derive the list from the AST rather than
# maintaining a copy here.
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$null)
$declared = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Check ($declared.Count -ge 15) "AST found the parameter block ($($declared.Count) parameters)"
if ($declared.Count -lt 15) { Write-Host '      cannot judge coverage without the parameter list'; exit 2 }

$src = Get-Content -LiteralPath $collector -Raw
$documented = @([regex]::Matches($src, '(?m)^\.PARAMETER\s+(\w+)') | ForEach-Object { $_.Groups[1].Value })
$undocumented = @($declared | Where-Object { $documented -notcontains $_ })
$phantom      = @($documented | Where-Object { $declared -notcontains $_ })

Check ($undocumented.Count -eq 0) "every declared parameter has a .PARAMETER entry ($($undocumented.Count) missing)"
if ($undocumented.Count) { $undocumented | ForEach-Object { Write-Host "        -$_ is declared but undocumented" } }
Check ($phantom.Count -eq 0) "no .PARAMETER entry names a parameter that does not exist ($($phantom.Count))"
if ($phantom.Count) {
    Write-Host '      A .PARAMETER for a non-existent name renders nothing and hides the real one -'
    Write-Host '      this is how -OutputRoot (an alias) stayed documented while -Dest did not:'
    $phantom | ForEach-Object { Write-Host "        .PARAMETER $_" }
}

# --- 6. the source-level shapes that caused this, so a regression is named not just detected ---
Check (-not ($src -match '(?m)^\.(NOTES|EXAMPLE)[^\S\r\n]+\S')) 'no .NOTES/.EXAMPLE text on the keyword line (fatal to the whole block)'
Check (-not ($src -match '(?m)^\.PARAMETER\s+\w+[^\S\r\n]+\S')) 'no .PARAMETER text on the keyword line (silently dropped)'
$lines = Get-Content -LiteralPath $collector
$open = (0..($lines.Count-1) | Where-Object { $lines[$_].Trim() -eq '<#' } | Select-Object -First 1)
Check ($null -ne $open -and $open -gt 0 -and [string]::IsNullOrWhiteSpace($lines[$open-1])) `
      'a blank line separates the preamble from the opening <#'

Write-Host ''
if ($fail -eq 0) { Write-Host 'all assertions passed'; exit 0 } else { Write-Host "$fail failed"; exit 1 }
