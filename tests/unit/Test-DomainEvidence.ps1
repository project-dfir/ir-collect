<#
.SYNOPSIS
    Unit test for Get-DomainEvidenceVerdict in collectors/IR-Collect.ps1.

.DESCRIPTION
    Regression this locks in (scenario E3, range-WS02 2026-07-29): with the DC firewalled off,
    FOURTEEN AD steps produced no output, every one was recorded in diagnostics.empty_outputs, and
    the bundle still sealed verdict=COMPLETE, ok=85, failed=0, incomplete EMPTY. An analyst
    receives a COMPLETE bundle from a DOMAIN-JOINED host with no domain data in it and nothing
    saying the domain was never reached. Third instance of this shape after E1/WMI and A3: the
    tool detects the gap, records it in diagnostics, and does not let it reach the verdict.

    The reason this is NOT just "add ad-* to CriticalSteps": an AD query can be legitimately
    empty. A domain with no LAPS, no unconstrained delegation and no AS-REP-roastable accounts
    SHOULD return nothing, and flagging that INCOMPLETE would cry wolf on a healthy collection -
    the same over-trigger A3's degraded-output check had to avoid. Emptiness therefore only counts
    when the domain was UNREACHABLE, which is a separately measured fact.

.EXAMPLE  pwsh -File tests/unit/Test-DomainEvidence.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'collectors') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
$fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $args[0].Name -eq 'Get-DomainEvidenceVerdict' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 Get-DomainEvidenceVerdict definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}
$AD14 = @('ad-domain','ad-users','ad-groups','ad-computers','ad-spn','ad-asrep','ad-uncons',
          'ad-cons','ad-rbcd','ad-admincount','ad-trusts-ldap','ad-laps','ad-this-host')

# --- THE REGRESSION: domain-joined, DC unreachable, AD empty ---
$r = Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $false -EmptyAdSteps $AD14
Check ([bool]$r) 'domain-joined + unreachable + empty AD -> the verdict is told   <-- the regression'
Check ($r -match 'unreachable')  'the note names the CAUSE, not just the symptom'
Check ($r -match '13 AD step')   "the note counts the affected steps ($r)"
Check ($r -match 'ad-users')     'the note names the steps so an analyst can see what is missing'

# --- THE FALSE POSITIVE this must not create ---
$r2 = Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $true -EmptyAdSteps $AD14
Check ($null -eq $r2) 'domain REACHABLE and AD empty -> NOT flagged (a domain with no LAPS/SPNs is legitimately empty)'

# --- everything else that must stay quiet ---
Check ($null -eq (Get-DomainEvidenceVerdict -DomainJoined $false -DomainReachable $false -EmptyAdSteps $AD14)) 'a NON-domain-joined host is never flagged (nothing to enumerate)'
Check ($null -eq (Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $false -EmptyAdSteps @()))    'unreachable but AD returned data -> not flagged'
Check ($null -eq (Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $false -EmptyAdSteps $null))  'a null step list does not throw or invent a finding'

# --- unknown is not the same as unreachable, and must say so ---
$r3 = Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $null -EmptyAdSteps @('ad-users')
Check ([bool]$r3) 'reachability UNKNOWN + empty AD -> still surfaced (silence would imply it was fine)'
Check ($r3 -match 'unknown') "the unknown case is labelled as unknown, not asserted as unreachable ($r3)"
Check ($r3 -notmatch 'controller unreachable') 'the unknown case does not claim a cause the probe never established'

# --- one empty step is enough; the count must be real, not hardcoded ---
$r4 = Get-DomainEvidenceVerdict -DomainJoined $true -DomainReachable $false -EmptyAdSteps @('ad-laps')
Check ($r4 -match '1 AD step') "a single empty step is reported with a real count ($r4)"

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
