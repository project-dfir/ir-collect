<#
.SYNOPSIS
    Unit test for Compare-ToolInventory in collectors/IR-Collect.ps1 (toolkit tamper detection).

.DESCRIPTION
    Extracts the shipped function via the AST and drives it against real files on disk.

    Regression this locks in (scenario A5, range-WS02 2026-07-28): Defender quarantined a file
    out of the collector's own toolkit mid-run and the collection sealed verdict=COMPLETE, exit 0,
    with nothing recorded anywhere - no classification, no diagnostic, only a buried audit line
    about RAM. AV quarantine of a carried imager is ORDINARY in the field (winpmem and
    Velociraptor are routinely flagged), so a tool that is not the tool we hashed at the start
    has to reach the verdict.

    The unreadable-file case matters on its own: an AV product that LOCKS a detected file rather
    than deleting it leaves the path in place, and calling an unverifiable tool "verified" is
    exactly the false assurance being guarded against.

.EXAMPLE  pwsh -File tests/unit/Test-ToolInventory.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'collectors') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
foreach ($fname in @('Compare-ToolInventory')) {
    $fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $fname }, $true)
    if ($fn.Count -ne 1) { throw "expected 1 $fname definition, found $($fn.Count)" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}
# the real hashing shim, so the test exercises the same digest path the collector uses
$asg = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                      "$($args[0].Left)" -match 'HashShimText' }, $true)
if ($asg.Count -ne 1) { throw "expected 1 HashShimText assignment, found $($asg.Count)" }
. ([scriptblock]::Create($asg[0].Right.Expression.Value))

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

$dir = Join-Path ([IO.Path]::GetTempPath()) ("toolinv_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $dir | Out-Null
$winpmem = Join-Path $dir 'winpmem_x64.exe'
$velo    = Join-Path $dir 'velociraptor.exe'
$stable  = Join-Path $dir 'autorunsc.exe'
Set-Content $winpmem 'imager-bytes'  -Encoding ASCII
Set-Content $velo    'velo-bytes'    -Encoding ASCII
Set-Content $stable  'stable-bytes'  -Encoding ASCII
$inv = @{}
foreach ($p in @($winpmem,$velo,$stable)) { $inv[$p] = (Get-IRSha256 $p) }
Check ($inv.Count -eq 3 -and @($inv.Values | Where-Object { $_ -match '^[0-9A-Fa-f]{64}$' }).Count -eq 3) 'baseline inventory hashed 3 tools'

# --- nothing touched ---
$r = Compare-ToolInventory $inv
Check ($r.Vanished.Count -eq 0 -and $r.Changed.Count -eq 0) 'an untouched toolkit reports nothing (no false alarm)'

# --- the A5 case: AV deletes the imager ---
Remove-Item $winpmem -Force
$r = Compare-ToolInventory $inv
Check ($r.Vanished -contains 'winpmem_x64.exe') 'a QUARANTINED (deleted) tool is reported vanished   <-- the regression'
Check ($r.Changed.Count -eq 0) 'a deleted tool is not double-counted as changed'
Check ($r.Vanished.Count -eq 1) 'the untouched tools are not implicated'

# --- swapped binary (tampering, or AV replacing with a stub) ---
Set-Content $velo 'DIFFERENT-bytes-entirely' -Encoding ASCII
$r = Compare-ToolInventory $inv
Check ($r.Changed -contains 'velociraptor.exe') 'a tool whose CONTENT changed is reported changed'
Check ($r.Vanished -contains 'winpmem_x64.exe') 'both conditions are reported together, not first-wins'

# --- reported by leaf name, so the audit line is readable ---
Check (($r.Changed + $r.Vanished) -notmatch '[\/]') 'results are leaf names, not full paths'

# --- an empty inventory must not throw or invent findings ---
$r = Compare-ToolInventory @{}
Check ($r.Vanished.Count -eq 0 -and $r.Changed.Count -eq 0) 'an empty inventory yields no findings and does not throw'

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
