<#
.SYNOPSIS
    Unit test for Repair-LedgerTail in collectors/IR-Collect.ps1 (run_state.jsonl integrity).

.DESCRIPTION
    Extracts the shipped function via the AST and drives it against synthetic ledgers.

    Regression this locks in: when the destination filesystem fills up, the final Add-Content to
    run_state.jsonl is truncated mid-record. The ledger then stops being valid JSONL, so a strict
    parser chokes on the very file that explains why the run failed. Observed on Linux against a
    3 MB loop filesystem (2026-07-27); this is the Windows twin.

    The function must keep every COMPLETE record and drop only the partial tail - silently losing
    good records would be worse than the truncation.

.EXAMPLE  pwsh -File tests/unit/Test-LedgerRepair.ps1
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
                     $args[0].Name -eq 'Repair-LedgerTail' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 Repair-LedgerTail definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

# the function audits through Write-Audit and reads $script:StateJsonl - provide both
$script:AuditLines = @()
function Write-Audit { param([string]$m) $script:AuditLines += $m }

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}
function New-Ledger([string[]]$lines) {
    $p = Join-Path ([IO.Path]::GetTempPath()) ("ledger_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.jsonl')
    [IO.File]::WriteAllLines($p, $lines); $p
}
function ValidJsonl([string]$p) {
    foreach ($l in [IO.File]::ReadAllLines($p)) {
        if (-not $l.Trim()) { continue }
        try { $null = $l | ConvertFrom-Json } catch { return $false }
    }
    return $true
}

$good1 = '{"t":"1","id":"001","name":"a","ev":"ok"}'
$good2 = '{"t":"2","id":"002","name":"b","ev":"ok"}'
$partial = '{"t":"3","id":"003","name":"c","ev":"fail'   # ENOSPC cut it here

# --- the regression: truncated tail ---
$script:StateJsonl = New-Ledger @($good1, $good2, $partial)
$script:AuditLines = @()
Repair-LedgerTail
$after = [IO.File]::ReadAllLines($script:StateJsonl)
Check ($after.Count -eq 2)                  "truncated tail dropped (2 records kept, was 3 lines)"
Check ($after[0] -eq $good1 -and $after[1] -eq $good2) "the COMPLETE records survive untouched"
Check (ValidJsonl $script:StateJsonl)       "result is valid JSONL  <-- the regression"
Check (($script:AuditLines -join ' ') -match 'LEDGER REPAIR') "repair is recorded in the custody trail"
Remove-Item $script:StateJsonl -Force -ErrorAction SilentlyContinue

# --- a clean ledger must be left completely alone ---
$script:StateJsonl = New-Ledger @($good1, $good2)
$before = [IO.File]::ReadAllText($script:StateJsonl)
$script:AuditLines = @()
Repair-LedgerTail
Check ([IO.File]::ReadAllText($script:StateJsonl) -eq $before) "a clean ledger is not rewritten"
Check (($script:AuditLines -join ' ') -notmatch 'LEDGER REPAIR')  "no repair is claimed when nothing was wrong"
Remove-Item $script:StateJsonl -Force -ErrorAction SilentlyContinue

# --- degenerate inputs must not throw or destroy data ---
$script:StateJsonl = New-Ledger @()
Repair-LedgerTail
Check ($true) "empty ledger handled without throwing"
Remove-Item $script:StateJsonl -Force -ErrorAction SilentlyContinue

$script:StateJsonl = New-Ledger @($partial)   # nothing but a partial record
Repair-LedgerTail
Check (([IO.File]::ReadAllLines($script:StateJsonl)).Count -eq 0) "an all-partial ledger reduces to zero records, not garbage"
Remove-Item $script:StateJsonl -Force -ErrorAction SilentlyContinue

$script:StateJsonl = Join-Path ([IO.Path]::GetTempPath()) 'definitely_missing_ledger.jsonl'
Repair-LedgerTail
Check ($true) "missing ledger file handled without throwing"

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
