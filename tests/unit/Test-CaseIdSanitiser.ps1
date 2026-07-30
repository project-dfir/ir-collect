<#
.SYNOPSIS
    Unit test for ConvertTo-SafeToken in collectors/IR-Collect.ps1, and its parity with the
    shell collector's CASE normalisation.

.DESCRIPTION
    -CaseId is typed by a responder under time pressure and lands directly in the bundle
    directory name. Unsanitised it breaks the collection in ways that are hard to read:
      - [ ] ? * make PowerShell's wildcard-interpreting -Path calls silently miss. Measured
        2026-07-28: the byte-count probe then reports 0, so a step that wrote good evidence is
        recorded EMPTY, and a CORE step doing that drives the verdict to INCOMPLETE.
      - an apostrophe breaks the single-quoted command the shell collector generates for its
        manifest.
      - < > : " | / \ are illegal in a Windows filename outright, and a trailing dot or space
        produces a directory Explorer cannot open.

    Both collectors use the SAME whitelist so one case id yields one bundle name on either
    platform; this test asserts that agreement rather than trusting two implementations to drift
    in step. The original string is a custody field and must never be discarded - only the path
    form is normalised.

.EXAMPLE  pwsh -File tests/unit/Test-CaseIdSanitiser.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath, [string]$ShCollector)

$ErrorActionPreference = 'Stop'
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $root)
if (-not $CollectorPath) { $CollectorPath = Join-Path (Join-Path $repo 'collectors') 'IR-Collect.ps1' }
if (-not $ShCollector)   { $ShCollector   = Join-Path (Join-Path $repo 'collectors') 'ir-collect.sh' }

$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $CollectorPath), [ref]$null, [ref]$null)
$fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $args[0].Name -eq 'ConvertTo-SafeToken' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 ConvertTo-SafeToken definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}

# a legitimate case id must survive completely untouched - over-sanitising is its own failure
foreach ($good in @('IR-2026-0042', 'case_01', 'a.b-c_1', 'CASE99')) {
    Check ((ConvertTo-SafeToken $good) -eq $good) "a normal case id is untouched ('$good')"
}

# the measured hostile inputs
$brackets = 'IR-2026-' + [string][char]91 + 'URGENT' + [string][char]93
Check ((ConvertTo-SafeToken $brackets) -eq 'IR-2026-_URGENT_') "bracketed case id is neutralised ('$brackets')  <-- the wildcard trap"
Check ((ConvertTo-SafeToken "O'Brien") -eq 'O_Brien')          "an apostrophe is neutralised (breaks the shell manifest command)"
Check ((ConvertTo-SafeToken 'a/b') -eq 'a_b')                  'a slash cannot nest the bundle somewhere else'
Check ((ConvertTo-SafeToken 'a*b?c') -eq 'a_b_c')              'glob metacharacters are neutralised'
Check ((ConvertTo-SafeToken 'case;rm -rf') -match '^[A-Za-z0-9._-]+$') 'a shell metacharacter cannot survive into a generated command'

# degenerate inputs must produce something an analyst can read, never an empty or junk directory
Check ((ConvertTo-SafeToken '')    -eq 'IR') 'an empty case id falls back rather than making an unnamed bundle'
Check ((ConvertTo-SafeToken '   ') -eq 'IR') 'a whitespace-only case id falls back'
Check ((ConvertTo-SafeToken '///') -eq 'IR') 'a case id with no alphanumerics at all falls back, not "___"'
Check ((ConvertTo-SafeToken ('x' * 200)).Length -le 64) 'an absurdly long case id is bounded (it is part of a path budget)'
Check ((ConvertTo-SafeToken $null) -eq 'IR') 'a null case id does not throw'

# --- PARITY with the shell collector -----------------------------------------------------
# The shell twin uses: tr -c 'A-Za-z0-9._-' '_' | cut -c1-64, with an IR fallback. Assert the
# rule is literally present there, so the two cannot drift into different bundle names.
$sh = [IO.File]::ReadAllText($ShCollector)
Check ($sh -match "tr -c 'A-Za-z0-9\._-' '_'") 'the shell collector uses the same whitelist'
Check ($sh -match 'cut -c1-64')                'the shell collector applies the same length bound'
Check ($sh -match 'CASE_RAW')                  'the shell collector preserves the original case id (custody field)'
$src = [IO.File]::ReadAllText($CollectorPath)
Check ($src -match 'CaseIdRaw')                'the Windows collector preserves the original case id'
Check ($src -match 'case=\$script:CaseIdRaw')  'run_state.json records the ORIGINAL case id, not the normalised token'

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
