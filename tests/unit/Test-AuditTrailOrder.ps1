<#
.SYNOPSIS
    Audits that neither collector writes to the custody trail before the custody trail exists.

.DESCRIPTION
    Write-Audit / audit() both echo to the console AND append to the audit log, and both swallow
    the file error. So a call made before the log file exists LOOKS like it worked - the operator
    sees the line on screen - while the custody record silently never receives it.

    This has bitten twice:
      - Windows: the destination-probe note (PendingDestNote), worked around with a buffer.
      - Linux: the ship-target preflight verdict. Measured 2026-07-28 - ZERO bundles on disk
        contained the line, and its absence was dismissed during review as "it goes to the audit
        log". It did not. That field is what distinguishes scenario B4 from B5, so the scenario
        was untestable until it was found.

    The fix in both cases is to buffer the message and flush it once the trail is open. This test
    makes the rule enforceable instead of remembered.

    Only TOP-LEVEL calls count. A Write-Audit inside a function defined early but invoked later is
    fine, so the Windows side walks the AST and ignores anything inside a function definition.

.EXAMPLE  pwsh -File tests/unit/Test-AuditTrailOrder.ps1
#>
[CmdletBinding()]
param([string]$WinCollector, [string]$ShCollector)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $root)
if (-not $WinCollector) { $WinCollector = Join-Path (Join-Path $repo 'collectors') 'IR-Collect.ps1' }
if (-not $ShCollector)  { $ShCollector  = Join-Path (Join-Path $repo 'collectors') 'ir-collect.sh' }

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

# ---------------- Windows ----------------
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $WinCollector), [ref]$null, [ref]$null)
$asg = $ast.FindAll({
    $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    "$($args[0].Left)" -match '^\$AuditLog$' }, $true)
Check ($asg.Count -ge 1) "found where the Windows audit log is opened"
$openLine = ($asg | ForEach-Object { $_.Extent.StartLineNumber } | Sort-Object)[0]

$funcs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
function InsideFunction($line) {
    foreach ($f in $script:funcs) {
        if ($line -ge $f.Extent.StartLineNumber -and $line -le $f.Extent.EndLineNumber) { return $true }
    }
    return $false
}
$early = @()
foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = try { $c.GetCommandName() } catch { $null }
    if ($n -ne 'Write-Audit') { continue }
    $ln = $c.Extent.StartLineNumber
    if ($ln -lt $openLine -and -not (InsideFunction $ln)) {
        $early += "line ${ln}: $($c.Extent.Text.Substring(0, [Math]::Min(80, $c.Extent.Text.Length)))"
    }
}
Check ($early.Count -eq 0) "no top-level Write-Audit runs before the log is opened (line $openLine)$(if($early){ "`n        " + ($early -join "`n        ") })"

# the buffer-and-flush pattern is how a pre-trail message is meant to reach the record; if the
# Windows collector ever needs one again it should look like the Linux one
$winText = [IO.File]::ReadAllText($WinCollector)

# ---------------- Linux ----------------
$shLines = [IO.File]::ReadAllLines($ShCollector)
$openIdx = [array]::FindIndex($shLines, [Predicate[string]]{ param($l) $l -match '^AUDIT=' })
Check ($openIdx -ge 0) "found where the Linux audit log is opened"
$openLineSh = $openIdx + 1

# Track function bodies by a `name() {` header and a closing `}` at COLUMN 0, which is the style
# used throughout this collector. Counting brace CHARACTERS does not work: every ${var} expansion
# contributes braces, so the depth never returns to zero, the whole file reads as "inside a
# function", and the check silently inspects nothing. That flaw was caught by a mutation that
# reintroduced the real B4 bug and did NOT fail this test.
$inFunc = $false; $earlySh = @()
for ($i = 0; $i -lt $openIdx; $i++) {
    $l = $shLines[$i]
    if (-not $inFunc -and $l -match '^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{') { $inFunc = $true; continue }
    if ($inFunc) { if ($l -match '^\}') { $inFunc = $false }; continue }
    if ($l -match '^\s*audit\s+"' -and $l -notmatch '^\s*#') {
        $earlySh += "line $($i+1): $($l.Trim().Substring(0, [Math]::Min(80, $l.Trim().Length)))"
    }
}
Check ($earlySh.Count -eq 0) "no top-level audit() runs before the log is opened (line $openLineSh)$(if($earlySh){ "`n        " + ($earlySh -join "`n        ") })"

# --- the buffered verdict must actually be flushed, or buffering just loses it more quietly ---
$shText = [IO.File]::ReadAllText($ShCollector)
if ($shText -match 'PENDING_SHIP_AUDIT=') {
    Check ($shText -match 'audit "\$PENDING_SHIP_AUDIT"') 'the buffered ship verdict is flushed into the trail, not just assigned'
    $setLine   = ([array]::FindIndex($shLines, [Predicate[string]]{ param($l) $l -match 'PENDING_SHIP_AUDIT=' })) + 1
    $flushLine = ([array]::FindIndex($shLines, [Predicate[string]]{ param($l) $l -match 'audit "\$PENDING_SHIP_AUDIT"' })) + 1
    Check ($flushLine -gt $openLineSh) "the flush happens AFTER the log is opened (flush line $flushLine > open line $openLineSh)"
    Check ($setLine -lt $flushLine)    "the buffer is set before it is flushed ($setLine < $flushLine)"
}

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
