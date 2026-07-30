<#
.SYNOPSIS
    Unit test for Resolve-UsableOutDir / ConvertTo-ExtendedPath in collectors/IR-Collect.ps1
    (destination usable at the depth the collector actually writes).

.DESCRIPTION
    Extracts both shipped functions via the AST and drives them against real directories.

    Regression this locks in (scenario B6, range-WS02 2026-07-28): with a 229-char -Dest and
    LongPathsEnabled=0, every directory creation failed on MAX_PATH. Not one byte was written,
    audit.log itself was unwritable so the failure could not even be recorded - and the run
    still printed "Collection complete. Output: <path>" naming a directory that did not exist.
    Free space was fine; the preflight only ever asked about space.

    The probe therefore asks the real question: can a path as deep as
    05_artifacts\userhives\<user>\NTUSER.DAT be created and written HERE? If not, the run is
    refused up front with an actionable message rather than started.

    Adopting the extended-length (\\?\) form for the output tree was tried and rejected on
    evidence: the probe passes and directories get created, but drive-qualifier operations
    (free-space checks, Split-Path -Qualifier, DriveInfo) all return null for such a path, so
    free space read 0.0 GB, Stage 1 aborted on a null reference, the seal failed, and the run
    exited 0 with an EMPTY bundle. Hence the assertion below that 'extended' is never returned.

.EXAMPLE  pwsh -File tests/unit/Test-DestPathDepth.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'collectors') 'IR-Collect.ps1'
}
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
foreach ($n in @('ConvertTo-ExtendedPath','Resolve-UsableOutDir')) {
    $fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq $n }, $true)
    if ($fn.Count -ne 1) { throw "expected 1 $n definition, found $($fn.Count)" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}
$isWindows_ = $true
try { if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { $isWindows_ = $false } } catch {}

# --- ORDERING: the helper must be defined before its first call, or the collector dies at
# startup on the very destination check meant to save it. Guard it as a source-order assertion.
$defLine  = ($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                            $args[0].Name -eq 'ConvertTo-ExtendedPath' }, $true))[0].Extent.StartLineNumber
$callLines = @([regex]::Matches([IO.File]::ReadAllText($CollectorPath), "(?m)^(?<pre>.*ConvertTo-ExtendedPath.*)$") |
               ForEach-Object { $_.Groups['pre'].Value }) | Where-Object { $_ -notmatch 'function ConvertTo-ExtendedPath' }
Check ($callLines.Count -ge 2) "found the helper's call sites ($($callLines.Count))"
$srcLines = [IO.File]::ReadAllLines($CollectorPath)
$firstCall = 1 + [array]::FindIndex($srcLines, [Predicate[string]]{ param($l)
    $l -match 'ConvertTo-ExtendedPath' -and $l -notmatch 'function ConvertTo-ExtendedPath' })
Check ($defLine -lt $firstCall) "ConvertTo-ExtendedPath is DEFINED (line $defLine) before its first call (line $firstCall)"

# --- ConvertTo-ExtendedPath shape ---
if ($isWindows_) {
    # Build every backslash from its char code. Literal doubled backslashes do not survive some
    # editing/transport paths intact, and a silently de-doubled expectation would make these
    # assertions compare the wrong strings while still looking correct in the source.
    $B    = [string][char]92
    $EXT  = $B + $B + '?' + $B                      # \\?\
    $UNCX = $EXT + 'UNC' + $B                       # \\?\UNC\
    $local = 'C:' + $B + 'evidence' + $B + 'case1'
    $unc   = $B + $B + 'server' + $B + 'share' + $B + 'case'
    Check ((ConvertTo-ExtendedPath $local) -eq ($EXT + $local))                  "a local absolute path gains the extended prefix ($EXT)"
    Check ((ConvertTo-ExtendedPath ($EXT + 'C:' + $B + 'already')) -eq ($EXT + 'C:' + $B + 'already')) 'an already-extended path is returned untouched'
    Check ((ConvertTo-ExtendedPath $unc) -eq ($UNCX + 'server' + $B + 'share' + $B + 'case')) "a UNC path gains the extended UNC form ($UNCX)"
    # A relative path must be ANCHORED before prefixing - the extended form requires a
    # fully-qualified path, so returning '\\?\relative\path' would produce something the file
    # APIs reject. Assert it resolves to a real absolute extended path.
    $rel = ConvertTo-ExtendedPath ('sub' + $B + 'dir')
    Check ($rel.StartsWith($EXT))       'a relative path is anchored, then given the extended prefix'
    Check ($rel -notmatch '\?\\sub')    'the anchored result is not a bare prefix stuck on the relative fragment'
    Check ($rel.EndsWith('sub' + $B + 'dir')) 'the anchored result still ends with the original fragment'
} else {
    Write-Host 'SKIP  \?\ prefix shape - Windows path semantics only' -ForegroundColor Yellow
}

# --- Resolve-UsableOutDir on a perfectly ordinary destination ---
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("b6_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$r = Resolve-UsableOutDir $tmp
Check ($r.Mode -eq 'plain')  "a short destination resolves as 'plain' (got '$($r.Mode)')"
Check ($r.Path -eq $tmp)     'a short destination is returned unchanged'
Check ($r.ProbeLength -gt $tmp.Length) 'ProbeLength accounts for more than just the base'
# THE POINT OF THE WHOLE FIX: the probe has to be as deep as the deepest thing the collection
# writes. A shallow probe ("does <dest>\x.txt work?") sails under MAX_PATH and reports the
# destination healthy, and then the real run dies on 05_artifacts\userhives\<user>\NTUSER.DAT -
# which is exactly the B6 failure, just moved a few characters later.
$depth = $r.ProbeLength - $tmp.Length
Check ($depth -ge 50) "the probe reaches a realistic artifact depth ($depth chars past the base; a shallow probe would miss B6 entirely)"

# the probe must not leave its scaffolding behind - an operator opening the bundle should not
# find an empty 05_artifacts\userhives\a_reasonably_long_username tree that collected nothing
Check (-not (Test-Path (Join-Path $tmp '05_artifacts'))) 'the probe cleans up after itself (no stray 05_artifacts scaffold)'
Check (@(Get-ChildItem $tmp -Recurse -Force -ErrorAction SilentlyContinue).Count -eq 0) 'the destination is left completely empty by the probe'

# --- a destination that cannot exist at all is 'unusable', not silently 'plain' ---
$bogus = if ($isWindows_) { 'Q:\no_such_volume_here\case' } else { '/proc/definitely/not/writable/case' }
$r2 = Resolve-UsableOutDir $bogus
Check ($r2.Mode -eq 'unusable') "an unwritable destination resolves as 'unusable' (got '$($r2.Mode)')"

# Resolve-UsableOutDir must NEVER hand back an extended-length destination for the output tree.
# It was tried: the probe passes and directories get created, but every drive-qualifier operation
# downstream returns null for a \?\ path, so the run produced an EMPTY bundle and exited 0
# (measured on range-WS02 2026-07-28). A destination that probes healthy and yields no evidence
# is worse than one that is refused, so 'plain' and 'unusable' are the only valid answers.
foreach ($case in @($tmp, $bogus)) {
    $m = (Resolve-UsableOutDir $case).Mode
    Check ($m -in @('plain','unusable')) "Resolve-UsableOutDir returns only plain|unusable, never extended (got '$m')"
}
Check ($r2.Path -eq $bogus)     'an unusable destination returns the original path for the error message'

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
