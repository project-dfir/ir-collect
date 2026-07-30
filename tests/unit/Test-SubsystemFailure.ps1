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

# --- CIM EVIDENCE CENSUS (Defect A) ------------------------------------------------------------
# 8 of the 13 CIM-backed steps carry a native fallback, so on a WMI-dead host they still write data
# and every layer above reads that as success. The artifacts DO carry a fallback banner (9 sites),
# but the fact reached nothing: run_state/SUMMARY/report showed COMPLETE with no finding. Measured
# live 2026-07-29 with Winmgmt stopped: COMPLETE ok=33 empty_outputs=0, identical to healthy.
$fn3 = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'Get-CimEvidenceVerdict' }, $true) | Select-Object -First 1
if (-not $fn3) { Write-Host 'FAIL  Get-CimEvidenceVerdict not found in the shipped collector'; exit 2 }
. ([scriptblock]::Create($fn3.Extent.Text))

# POSITIVE CONTROL FIRST: a healthy host must stay silent, or every bundle grows a false finding.
$v = Get-CimEvidenceVerdict -CimAvailable $true -FallbackSteps @() -EmptyCimSteps @()
Check ($v.state -eq 'cim-sourced') 'CIM answered and nothing fell back -> cim-sourced (healthy stays quiet)'

$v = Get-CimEvidenceVerdict -CimAvailable $false -FallbackSteps @('processes.txt','services.txt') -EmptyCimSteps @('vss-list')
Check ($v.state -eq 'cim-unavailable')        'CIM down + fallbacks -> cim-unavailable'
Check (@($v.fallback_steps).Count -eq 2)      'the census names the artifacts that fell back'
Check ($v.note -match 'finding in its own right') 'the note tells the responder a dead WMI is itself a finding'
Check ($v.note -notmatch 'equivalent in content but' -or $v.note -match 'NOT proof') `
      'the note refuses to let native data stand as proof WMI was healthy'

# THREE-STATE: an unrun probe must never read as a healthy one.
$v = Get-CimEvidenceVerdict -CimAvailable $null -FallbackSteps @('processes.txt') -EmptyCimSteps @()
Check ($v.state -eq 'unknown')            'a probe that did not run -> unknown, not healthy'
Check ($v.state -ne 'cim-sourced')        'unknown is never reported as cim-sourced'
Check ($v.note -match 'cannot say')       'the unknown note says plainly that it cannot say'

# CIM answered yet steps still fell back - an intermittent outage, not a clean bill of health
$v = Get-CimEvidenceVerdict -CimAvailable $true -FallbackSteps @('drivers.txt') -EmptyCimSteps @()
Check ($v.state -eq 'degraded')           'CIM up at seal but a step fell back -> degraded, not cim-sourced'
Check ($v.note -match 'intermittent')     'the degraded note offers the intermittent explanation'

# hygiene: blanks discarded, duplicates collapsed
$v = Get-CimEvidenceVerdict -CimAvailable $false -FallbackSteps @('a.txt','a.txt','',$null) -EmptyCimSteps @()
Check (@($v.fallback_steps).Count -eq 1)  'duplicate and blank step names are collapsed, not counted twice'

# --- WIRING: all three operator-facing layers, plus the seal-time inputs ---
Check ($src -match 'Get-CimEvidenceVerdict\s+-CimAvailable') 'the collector CALLS the CIM evidence verdict'
Check ($src -match 'cim_evidence=\$script:CimEvidence')      'run_state.json carries the CIM evidence census'
Check ($src -match '## Evidence source: CIM/WMI was')        'the DIAGNOSTIC REPORT surfaces it'
Check ($src -match '## Evidence source`n- CIM/WMI:')         'SUMMARY.md surfaces it'
# A STRING BEING PRESENT IS NOT A WIRING ASSERTION. The assertion above passed while the SUMMARY
# block sat inside the diagnostics guard - which only fires when something ELSE went wrong - so on
# a WMI-dead host it never executed. The live run caught what the source scan could not. Assert the
# structure: the CIM block must come BEFORE the guard, not inside it.
$iBlock = $src.IndexOf('## Evidence source`n- CIM/WMI:')
$iGuard = $src.IndexOf("if ((`$script:DiagClass.Count -gt 0) -or (-not `$script:JobsOk)")
Check (($iBlock -gt 0) -and ($iGuard -gt 0) -and ($iBlock -lt $iGuard)) `
      'the SUMMARY evidence block is NOT nested inside the "something else went wrong" guard'
Check ($src -match 'Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; \$script:CimProbeOk = \$true') `
      'the seal-time CIM probe actually runs (otherwise the state is always unknown)'
Check ($src -match "unavailable\.\*\(native fallback\|fallback chain\)") `
      'the seal scans artifacts for the fallback banner (the reliable carrier across job runspaces)'

# --- ENCRYPTION RISK: the one where being wrong is IRREVERSIBLE --------------------------------
# Was: $encRisk = $false; try { $encRisk = (Get-BitLockerVolume ...) -and -not $memOk } catch {}
# Initialised to "no risk", catch discards everything. Get-BitLockerVolume throws with no BitLocker
# cmdlets, on editions lacking the feature, with a broken provider, and WHEN NOT ELEVATED - which
# is scenario A3, a case this collector supports. Every one of those printed GREEN, so the operator
# powers off an encrypted host and the disk image is unreadable forever.
$fn4 = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                      $n.Name -eq 'Get-EncryptionRiskVerdict' }, $true) | Select-Object -First 1
if (-not $fn4) { Write-Host 'FAIL  Get-EncryptionRiskVerdict not found in the shipped collector'; exit 2 }
. ([scriptblock]::Create($fn4.Extent.Text))

# THE REGRESSION: probe could not answer, no RAM -> must WARN, not clear the host
$v = Get-EncryptionRiskVerdict -DiskEncrypted $null -MemoryVerified $false
Check ($v.amber -eq $true)                  'probe failed + no RAM -> AMBER (the old code printed GREEN here)'
Check ($v.state -eq 'unknown-no-ram')       'the unknown case has its own state, not the encrypted one'
Check ($v.note -match 'COULD NOT BE DETERMINED') 'the note says the probe failed rather than claiming encryption'
Check ($v.note -match 'not a claim that the disk is encrypted') `
      'it explicitly refuses to assert encryption it never observed'

# genuinely encrypted, no RAM -> the original AMBER case must still fire
$v = Get-EncryptionRiskVerdict -DiskEncrypted $true -MemoryVerified $false
Check ($v.amber -eq $true)                  'encrypted + no RAM -> AMBER'
Check ($v.state -eq 'encrypted-no-ram')     'the encrypted case is distinguishable from the unknown one'

# POSITIVE CONTROLS: neither may raise a false alarm, or the banner becomes noise and gets ignored
$v = Get-EncryptionRiskVerdict -DiskEncrypted $false -MemoryVerified $false
Check ($v.amber -eq $false)                 'not encrypted + no RAM -> no alarm'
$v = Get-EncryptionRiskVerdict -DiskEncrypted $true -MemoryVerified $true
Check ($v.amber -eq $false)                 'encrypted but RAM CAPTURED -> no alarm (the key is in the bundle)'
Check ($v.note -match 'RAM was captured')   'and it says why the host is cleared'
$v = Get-EncryptionRiskVerdict -DiskEncrypted $null -MemoryVerified $true
Check ($v.amber -eq $false)                 'unknown encryption but RAM captured -> no alarm'

# the three situations must be distinguishable, not collapsed
$states = @(
  (Get-EncryptionRiskVerdict -DiskEncrypted $true  -MemoryVerified $false).state,
  (Get-EncryptionRiskVerdict -DiskEncrypted $null  -MemoryVerified $false).state,
  (Get-EncryptionRiskVerdict -DiskEncrypted $false -MemoryVerified $false).state
)
Check (($states | Select-Object -Unique).Count -eq 3) 'encrypted / unknown / clear are three distinct states'

# --- WIRING ---
Check ($src -notmatch '\$encRisk = \$false\s*\r?\n\s*try \{ \$encRisk = \(\[bool\]\(Get-BitLockerVolume') `
      'the old swallowing two-state probe is gone'
Check ($src -match 'Get-EncryptionRiskVerdict -DiskEncrypted \$encState -MemoryVerified \$memOk') `
      'the collector CALLS the encryption verdict with the probed state'
Check ($src -match 'catch \{ \$encState = \$null \}') `
      'a failed probe yields $null (unknown), not $false (safe)'
Check ($src -match 'manage-bde\.exe -status') `
      'a second probe is tried before giving up - capability proven, not inferred'
Check ($src -match 'encryption_risk=\$script:EncVerdict') `
      'run_state.json carries the encryption verdict, not just the console banner'
Check ($src -match 'ENCRYPTION UNKNOWN \+ NO VERIFIED RAM') `
      'the console distinguishes "could not tell" from "encrypted"'

Write-Host ''
if ($fail -eq 0) { Write-Host 'all assertions passed'; exit 0 } else { Write-Host "$fail failed"; exit 1 }
