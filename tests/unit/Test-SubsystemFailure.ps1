<#
.SYNOPSIS
    Unit test for Get-SubsystemFailureVerdict - the fix for an error class that could never fire.

.DESCRIPTION
    Found by the 2026-07-29 audit of FAILURE-SCENARIOS.md. `wmi_failure` is assigned only by
    Get-ErrorClass, which matches error TEXT, and Get-ErrorClass is only ever fed by a step that
    threw. When WMI is broken the steps do not throw - they return NOTHING - so `wmi_failure` was
    unreachable, and the ladder declared for it (restart-wmi / native-source / skip) could never be
    handed to a responder. The run still refused to claim COMPLETE, so the evidence was safe; the
    person holding the console was simply never told what to try.

    The correctness risk in fixing it is the mirror image: emptiness is NOT evidence on its own.
    Plenty of queries legitimately return nothing, so a rule that fires on any empty CIM step would
    accuse a healthy host of a broken subsystem. Hence corroboration as the second fact - at least
    two subsystem-backed steps must have run, and none may have produced data.

    The function is extracted from the shipped collector by the AST, not mirrored here, so this
    test cannot pass against a copy that has drifted from what ships.

.EXAMPLE  pwsh -File tests/unit/Test-SubsystemFailure.ps1
#>
[CmdletBinding()]
param([string]$Collector)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $root)
if (-not $Collector) { $Collector = Join-Path (Join-Path $repo 'collectors') 'IR-Collect.ps1' }
if (-not (Test-Path -LiteralPath $Collector)) { Write-Host "collector not found: $Collector"; exit 2 }

# AST, not grep: the file is ~170 KB of nested strings and a text scrape picks up prose.
$tokens = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Collector, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count) { Write-Host "FAIL  collector does not parse: $($errs[0].Message)"; exit 2 }
$fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $n.Name -eq 'Get-SubsystemFailureVerdict' }, $true) | Select-Object -First 1
if (-not $fn) { Write-Host 'FAIL  Get-SubsystemFailureVerdict not found in the shipped collector'; exit 2 }
. ([scriptblock]::Create($fn.Extent.Text))

$fail = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "ok    $what" } else { Write-Host "FAIL  $what"; $script:fail++ }
}

# --- the condition it exists for: every CIM-backed step empty ---
$ran = @('processes','tcp-conns','services','local-users')
$v = Get-SubsystemFailureVerdict -Ran $ran -Empty $ran
Check ($null -ne $v)                       'every subsystem step empty -> a verdict is produced'
Check ($v.class -eq 'wmi_failure')         'the verdict carries the class whose ladder was unreachable'
Check ($v.steps.Count -eq 4)               'the verdict names every step it based the call on'
Check ($v.evidence -match 'processes')     'the evidence string lists the steps, not just a count'

# --- THE POSITIVE CONTROL. This is the assertion that matters most: the E3 fix was caught marking
# a HEALTHY domain INCOMPLETE, and the same mistake here would accuse every healthy host of a
# broken WMI. One step returning data proves the subsystem answers.
$v = Get-SubsystemFailureVerdict -Ran $ran -Empty @('tcp-conns')
Check ($null -eq $v)                       'ONE empty step on a working subsystem -> no verdict (a healthy host stays quiet)'
$v = Get-SubsystemFailureVerdict -Ran $ran -Empty @()
Check ($null -eq $v)                       'nothing empty -> no verdict'
$v = Get-SubsystemFailureVerdict -Ran $ran -Empty @('processes','tcp-conns','services')
Check ($null -eq $v)                       'all but one empty -> still no verdict, because one step answered'

# --- corroboration is required: a single observation is not evidence ---
$v = Get-SubsystemFailureVerdict -Ran @('processes') -Empty @('processes')
Check ($null -eq $v)                       'a single empty step is not enough to blame the subsystem'
$v = Get-SubsystemFailureVerdict -Ran @('processes','tcp-conns') -Empty @('processes','tcp-conns')
Check ($null -ne $v)                       'two empty steps DO corroborate each other'

# --- degenerate input must not produce a confident accusation ---
Check ($null -eq (Get-SubsystemFailureVerdict -Ran @() -Empty @()))            'no steps ran -> no verdict'
Check ($null -eq (Get-SubsystemFailureVerdict -Ran @() -Empty @('processes'))) 'empties with nothing recorded as run -> no verdict'
Check ($null -eq (Get-SubsystemFailureVerdict -Ran @($null,'') -Empty @()))    'blank step names are discarded, not counted'

# --- an empty step NOT belonging to the subsystem must not count toward it ---
$v = Get-SubsystemFailureVerdict -Ran @('processes','tcp-conns') -Empty @('processes','tcp-conns','shadow-copies')
Check ($null -ne $v)                       'an unrelated empty step neither blocks nor is claimed by the verdict'
Check ($v.steps -notcontains 'shadow-copies') 'the verdict only names steps that actually ran for this subsystem'

# --- WIRING. Every assertion above can pass while the feature is dead in production, so assert the
# collector actually calls this and actually populates its inputs.
$src = Get-Content -LiteralPath $Collector -Raw
Check ($src -match 'Get-SubsystemFailureVerdict\s+-Ran\s+\$script:CimStepsRan') `
      'the collector CALLS the verdict with the tracked step list'
Check ((([regex]::Matches($src,'Get-SubsystemFailureVerdict\s+-Ran')).Count) -ge 2) `
      'both the operator report and run_state.json consume it'
Check ($src -match '\$script:CimStepsRan\s*\+=') `
      'Invoke-Step POPULATES the tracked list (otherwise it is always empty and nothing ever fires)'
Check ($src -match "Get-CimInstance\|Get-WmiObject") `
      'membership is derived from the step script text, not a hand-maintained name list'
Check ($src -match 'subsystem_failure=') `
      'run_state.json carries the machine-readable verdict'

# the ladder it points at must exist and be non-empty, or the report offers nothing
$ladder = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true) |
          Where-Object { $_.Extent.Text -match "'wmi_failure'\s*=" } | Select-Object -First 1
Check ($null -ne $ladder) 'the wmi_failure ladder is still declared'
Check ($ladder.Extent.Text -match 'restart-wmi') 'the ladder still starts with restart-wmi'

# --- THREE-STATE census: a bare $null cannot say WHICH situation produced it -------------------
# Caught by the 2026-07-29 live negative control. With Winmgmt STOPPED and Win32_Process returning
# 0 rows, a -RapidOnly run gave verdict=COMPLETE ok=33 empty_outputs=0, identical to a healthy run,
# because the CIM steps fall back to native sources. The verdict correctly returned $null - one
# step DID answer - but "cleared by fallback" and "genuinely healthy" and "too few steps ran to
# say" were all the same null. That is the two-state defect this project keeps fixing elsewhere.
$fn2 = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'Get-SubsystemProbeState' }, $true) | Select-Object -First 1
if (-not $fn2) { Write-Host 'FAIL  Get-SubsystemProbeState not found in the shipped collector'; exit 2 }
. ([scriptblock]::Create($fn2.Extent.Text))

$st = Get-SubsystemProbeState -Ran @('processes','tcp-conns') -Empty @('processes','tcp-conns')
Check ($st.state -eq 'not-answering')       'all steps empty -> state not-answering'
Check ($st.steps_empty -eq 2)               'the census counts the empty steps'

$st = Get-SubsystemProbeState -Ran @('processes','tcp-conns') -Empty @('processes')
Check ($st.state -eq 'answered')            'one step returning data -> state answered (NOT a bare null)'
Check ($st.steps_empty -eq 1)               'answered still reports how many were empty'

$st = Get-SubsystemProbeState -Ran @('processes') -Empty @('processes')
Check ($st.state -eq 'insufficient-evidence') 'too few steps -> insufficient-evidence, distinct from answered'
$st = Get-SubsystemProbeState -Ran @() -Empty @()
Check ($st.state -eq 'insufficient-evidence') 'nothing ran -> insufficient-evidence, never "answered"'
Check ($st.note -match 'says nothing either way')  'the insufficient case says plainly that it proves nothing'

# the three states must be mutually exclusive and total over these inputs
$states = @(
  (Get-SubsystemProbeState -Ran @('a','b') -Empty @('a','b')).state,
  (Get-SubsystemProbeState -Ran @('a','b') -Empty @('a')).state,
  (Get-SubsystemProbeState -Ran @('a')     -Empty @('a')).state
)
Check (($states | Select-Object -Unique).Count -eq 3) 'the three situations produce three DIFFERENT states'

Check ($src -match 'subsystem_probe=') 'run_state.json carries the three-state census, not just the verdict'

Write-Host ''
if ($fail -eq 0) { Write-Host 'all assertions passed'; exit 0 } else { Write-Host "$fail failed"; exit 1 }
