# Detector for THIS CODEBASE'S SIGNATURE DEFECT, rather than another subject-matter taxonomy.
# (The previous triage grouped by topic and got it wrong - `SYSTEM\b` matched `Win32_ComputerSystem`
# and inflated a bucket with false positives. Grouping by CONSEQUENCE is the useful axis.)
#
# The shape, as found in the BitLocker bug:
#
#     $x = <safe default>          # a value that means "nothing to worry about"
#     try { $x = <probe> } catch {} # the probe may never run, and the failure is discarded
#     if ($x) { ...warn... }        # a DECISION is taken on a value that may be the default
#
# When the probe cannot run, the decision silently takes the safe branch. That is how a failed
# BitLocker query printed GREEN and suppressed the do-not-power-off banner.
#
# A hit is not automatically a bug. It IS a bug when the default is the SAFE side of a decision
# whose wrong answer costs evidence. This ranks them so that judgement is applied to a short list.
param([string]$Collector = 'C:\Users\m808b\ir-collector\collectors\IR-Collect.ps1')

$tok = $null; $errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Collector, [ref]$tok, [ref]$errs)
if ($errs -and $errs.Count) { "PARSE ERRORS: $($errs.Count)"; exit 2 }

function Get-CatchKind($c) {
    $inner = $c.Body.Extent.Text.Trim().Trim('{', '}').Trim()
    if ($inner -eq '') { return 'empty' }
    if ($inner -eq '$null') { return 'null' }
    if ($inner -match '^\s*throw') { return 'rethrow' }
    if ($inner -match 'Write-Audit|Write-Ledger|Add-Content|Write-Host|Write-Warning|\$script:') { return 'recorded' }
    return 'other'
}

# SELF-TEST on a known-present and a known-absent shape before any count is trusted.
$probeSrc = @'
$a = $false
try { $a = Get-Thing } catch {}
if ($a) { 'x' }
$b = $false
try { $b = Get-Thing } catch { Write-Audit "no" }
'@
$pAst = [System.Management.Automation.Language.Parser]::ParseInput($probeSrc, [ref]$null, [ref]$null)
function Find-SafeDefaults($root) {
    $out = @()
    foreach ($t in $root.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)) {
        foreach ($c in $t.CatchClauses) {
            if ((Get-CatchKind $c) -notin @('empty', 'null')) { continue }
            # variables assigned inside the try
            $assigned = $t.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
                        ForEach-Object { $_.Left.Extent.Text } | Where-Object { $_ -match '^\$' } | Select-Object -Unique
            foreach ($v in $assigned) {
                $out += [pscustomobject]@{ Var = $v; Line = $t.Extent.StartLineNumber; Kind = (Get-CatchKind $c) }
            }
        }
    }
    return $out
}
$pHits = @(Find-SafeDefaults $pAst)
if (@($pHits | Where-Object { $_.Var -eq '$a' }).Count -ne 1 -or @($pHits | Where-Object { $_.Var -eq '$b' }).Count -ne 0) {
    "SELF-TEST FAILED: got $($pHits.Count) hits ($(($pHits.Var) -join ',')) - expected only `$a"; exit 2
}
"self-test OK (finds the swallowing shape, ignores the recorded one)"
""

$src = Get-Content -LiteralPath $Collector
$hits = @(Find-SafeDefaults $ast)
"try/catch blocks that SWALLOW and assign a variable: $($hits.Count)"
""

# Rank: is the variable PRE-SET to a safe-looking default before the try, and USED in a decision after?
$ranked = @()
foreach ($h in $hits) {
    $name = [regex]::Escape($h.Var)
    $before = ''
    for ($i = [Math]::Max(0, $h.Line - 6); $i -lt ($h.Line - 1); $i++) { $before += $src[$i] + "`n" }
    $preset = $before -match "$name\s*=\s*(\`$false|\`$true|0|''|`"`"|@\(\))"
    $after = ''
    for ($i = $h.Line; $i -lt [Math]::Min($src.Count, $h.Line + 12); $i++) { $after += $src[$i] + "`n" }
    $decides = $after -match "if\s*\(.*$name" -or $after -match "$name\s*-(eq|ne|gt|lt)" -or $after -match "\`$\(if\s*\(.*$name"
    if ($preset -and $decides) {
        $ranked += [pscustomobject]@{ Line = $h.Line; Var = $h.Var; Kind = $h.Kind
                                      Pre = ($before -split "`n" | Where-Object { $_ -match "$name\s*=" } | Select-Object -Last 1).Trim()
                                      Use = ($after -split "`n" | Where-Object { $_ -match $name } | Select-Object -First 1).Trim() }
    }
}
"=== SIGNATURE SHAPE: safe default + swallowed probe + later decision ==="
if (-not $ranked.Count) { "  none" }
foreach ($r in ($ranked | Sort-Object Line)) {
    "  line {0,-6} {1,-16} [{2}]" -f $r.Line, $r.Var, $r.Kind
    "     default: $($r.Pre.Substring(0,[Math]::Min(96,$r.Pre.Length)))"
    "     used   : $($r.Use.Substring(0,[Math]::Min(96,$r.Use.Length)))"
}
""
"ranked hits: $($ranked.Count) of $($hits.Count) swallowing assignments"
