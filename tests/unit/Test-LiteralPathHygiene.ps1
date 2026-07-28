<#
.SYNOPSIS
    Audits collectors/IR-Collect.ps1: every cmdlet call on an EVIDENCE path must use -LiteralPath.

.DESCRIPTION
    PowerShell's -Path parameter treats its argument as a WILDCARD PATTERN. A path containing
    [ ] ? or * therefore resolves to nothing (or to the wrong thing), and the call silently does
    nothing - no error, no output. -LiteralPath is the only safe form for a path that came from
    data rather than from a pattern.

    This is not hypothetical for this tool:
      - Measured 2026-07-28 (scenario B6): an extended-length destination begins \?\, the '?' is
        a single-character wildcard, and `Add-Content -Path $AuditLog` wrote NOTHING. The run
        produced an empty bundle while reporting success.
      - -CaseId is operator-supplied and lands in the bundle directory name. A case id like
        "IR-2026-[URGENT]" makes every -Path call on the bundle silently miss. The worst of those
        was `Test-Path $target` / `Get-Item $target` computing a step's byte count: it reads 0, the
        step is recorded EMPTY, and a CORE step doing that drives the verdict to INCOMPLETE - a
        step that wrote perfectly good evidence reported as having collected none.

    The test walks the AST rather than grepping, so a reformatting or a renamed parameter cannot
    make it silently stop checking.

.EXAMPLE  pwsh -File tests/unit/Test-LiteralPathHygiene.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'collectors') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $CollectorPath), [ref]$null, [ref]$null)

# cmdlets whose -Path (or -FilePath) is wildcard-interpreted
$WILDCARD_CMDLETS = @('Get-Content','Set-Content','Add-Content','Out-File','Test-Path','Remove-Item',
                      'Copy-Item','Move-Item','Get-Item','Get-FileHash','Select-String','Export-Csv',
                      'Import-Csv','Rename-Item','Get-ChildItem','Unblock-File')
# variables that hold a path built from EVIDENCE data (case id, host name, user names)
$EVIDENCE_VARS = @('OutDir','AuditLog','ErrLog','StateJsonl','target','ResumeNote')

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

$cmds = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
Check ($cmds.Count -gt 200) "parsed the collector's command calls ($($cmds.Count))"

$offenders = @()
foreach ($c in $cmds) {
    $name = try { $c.GetCommandName() } catch { $null }
    if (-not $name -or $name -notin $WILDCARD_CMDLETS) { continue }
    $txt = $c.Extent.Text
    # does this call reference an evidence-derived path?
    $touchesEvidence = $false
    foreach ($v in $EVIDENCE_VARS) { if ($txt -match ('\$(script:)?' + [regex]::Escape($v) + '\b')) { $touchesEvidence = $true; break } }
    if ($txt -match '\$Dirs\.') { $touchesEvidence = $true }
    if (-not $touchesEvidence) { continue }
    $hasLiteral = @($c.CommandElements | Where-Object {
        $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -match '^LiteralPath$' }).Count -gt 0
    if (-not $hasLiteral) {
        $offenders += "line $($c.Extent.StartLineNumber): $name -> $($txt.Substring(0, [Math]::Min(96, $txt.Length)))"
    }
}
Check ($offenders.Count -eq 0) "every evidence-path call uses -LiteralPath$(if($offenders){ "`n        " + ($offenders -join "`n        ") })"

# the two writes that carry the custody trail are worth naming explicitly - if either regresses,
# the collector loses the file that explains what it did, and does so silently
$src = [IO.File]::ReadAllText($CollectorPath)
Check ($src -match 'Add-Content -LiteralPath \$AuditLog')        'the audit log is written with -LiteralPath  <-- the B6 regression'
Check ($src -match 'Add-Content -LiteralPath \$script:StateJsonl') 'the ledger is written with -LiteralPath'
Check ($src -notmatch 'Add-Content -Path \$AuditLog')            'the audit log is never written with wildcard -Path'

# and the byte-count probe, whose failure mode is a step falsely reported as empty
Check ($src -match 'Test-Path -LiteralPath \$target')  'the step byte-count probe uses -LiteralPath (else a bracketed path reports 0 bytes = falsely EMPTY)'
Check ($src -match 'Get-Item -LiteralPath \$target')   'the step size lookup uses -LiteralPath'

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
