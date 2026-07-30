<#
.SYNOPSIS
    Unit test for Test-PathWritable in collectors/IR-Collect.ps1 (destination writability probe).

.DESCRIPTION
    Regression this locks in (range-WS02, 2026-07-28): the probe called
    `New-Item -ItemType Directory -Force` FIRST and treated any failure as "not writable". A DRIVE
    ROOT cannot be created - `New-Item -Force 'X:\'` throws "The path is not of a legal form" -
    so EVERY root-path destination was judged unwritable and silently redirected to
    C:\ir_evidence, on the subject host's own system drive.

    `-Dest E:\` on a USB evidence drive is the most ordinary destination in live response, so this
    misfired on the common case, wrote evidence to the machine under investigation, and reported
    "Collection complete (49 files)" with exit 0.

    The probe must therefore create the directory only when it does not already exist, and answer
    the real question by writing a file and READING IT BACK - an exception-free call is not proof
    that a write landed (same lesson as the UNC probe in B5).

.EXAMPLE  pwsh -File tests/unit/Test-PathWritable.ps1
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
                     $args[0].Name -eq 'Test-PathWritable' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 Test-PathWritable definition, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

$fail = 0
function Check($cond, $msg) {
    if ($cond) { Write-Host "ok    $msg" -ForegroundColor Green } else { Write-Host "FAIL  $msg" -ForegroundColor Red; $script:fail++ }
}
$isWindows_ = $true
try { if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { $isWindows_ = $false } } catch {}

# --- THE REGRESSION: a drive root is writable and must be reported so ---
if ($isWindows_) {
    $sysRoot = $env:SystemDrive + [string][char]92     # "C:\" without a literal backslash
    Check ($sysRoot.Length -eq 3) "built a drive-root path ($sysRoot)"
    Check (Test-PathWritable $sysRoot) "a DRIVE ROOT is reported writable  <-- the regression (New-Item cannot create one)"
} else {
    Check (Test-PathWritable '/tmp') 'a filesystem root-like directory is reported writable'
}

# --- ordinary cases ---
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("tpw_" + [guid]::NewGuid().ToString('N').Substring(0,8))
Check (Test-PathWritable $tmp) 'a destination that does not exist yet is CREATED and reported writable'
Check (Test-Path $tmp)         'the created destination really exists afterwards'
Check (Test-PathWritable $tmp) 'an existing writable destination is reported writable'
Check (@(Get-ChildItem $tmp -Force -ErrorAction SilentlyContinue).Count -eq 0) 'the probe leaves no file behind'

# --- refusals ---
Check (-not (Test-PathWritable '')) 'an empty path is not writable'
Check (-not (Test-PathWritable $null)) 'a null path is not writable, and does not throw'
$bogus = if ($isWindows_) { 'Q:\no_such_volume\case' } else { '/proc/no/such/place' }
Check (-not (Test-PathWritable $bogus)) "a genuinely unusable destination is refused ($bogus)"

# --- a file where a directory should be is not a writable destination ---
$asFile = Join-Path ([IO.Path]::GetTempPath()) ("tpwf_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.txt')
Set-Content -LiteralPath $asFile -Value 'x'
Check (-not (Test-PathWritable $asFile)) 'a path that is a FILE is not a writable destination'
Remove-Item -LiteralPath $asFile -Force -ErrorAction SilentlyContinue
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue

# --- STRUCTURAL assertions, because the behavioural ones cannot discriminate here ----------
# The bug is ENGINE-DEPENDENT: `New-Item -ItemType Directory -Force 'C:'` throws "The path is not
# of a legal form" under Windows PowerShell 5.1 (what the collector runs on a target) but SUCCEEDS
# under PowerShell 7 (what this test and CI run on). Mutations that reintroduced the bug therefore
# did NOT fail the behavioural checks above - they passed for the wrong reason on the wrong engine.
# These assertions read the shipped source instead, so they hold on any engine.
$fnText = $fn[0].Extent.Text
Check ($fnText -match 'Test-Path -LiteralPath \$Path') 'the probe checks existence BEFORE creating (a drive root cannot be created)'
$idxGuard  = $fnText.IndexOf('Test-Path -LiteralPath $Path')
$idxCreate = $fnText.IndexOf('New-Item -ItemType Directory -Force -Path')
Check ($idxGuard -ge 0 -and $idxCreate -ge 0 -and $idxGuard -lt $idxCreate) 'the existence guard comes BEFORE the New-Item call'
Check ($fnText -match "\$back -eq 'x'") 'the probe READS BACK what it wrote (an exception-free call is not proof a write landed)'

# --- the redirect must be recorded in the CUSTODY LOG, not only on the console ---
$src = [IO.File]::ReadAllText($CollectorPath)
Check ($src -match 'PendingRedirectNote') 'a redirect is buffered for the audit trail'
Check ($src -match 'DESTINATION REDIRECTED') 'the buffered note names it as a redirect'
Check ($src -match 'ON THE SUBJECT HOST')    'the note states the contamination consequence'

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if ($fail) { 1 } else { 0 })
