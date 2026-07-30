<#
.SYNOPSIS
    Get-BitLockerKeyVerdict / Get-RecoveryPasswordShape - did the BitLocker capture get real keys?

.DESCRIPTION
    The Linux twin taught this the expensive way. There, `dmsetup table --showkeys` was assumed to
    yield a master key; on modern LUKS2 it yields a KEYRING POINTER, and the collector wrote that
    pointer under a banner promising it decrypts the evidence. Nobody found out until the recovery
    procedure was executed against a real volume (2026-07-29).

    Windows captures the genuine article - a 48-digit recovery password - so this is NOT the same
    defect. What it shared was the SHAPE of the mistake: the CSV row was emitted with no check that
    the password field was populated. A blank one yields a file that exists, has a header, has a row
    per protector, and contains no key. An analyst seeing a MountPoint and a KeyProtectorId has
    every reason to think the volume is recoverable.

    The asymmetry that matters: being wrong toward "captured" tells a responder the evidence can be
    opened when it cannot, and they find out with the host long gone. Being wrong toward "missing"
    costs a needless check. So the tests below lean hard on the first direction.

    The functions are extracted from the collector via the AST rather than copied - a copy drifts,
    and a drifted copy tests nothing. Three outcomes: 0 pass | 1 product failed | 2 guard broken.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repo = Split-Path -Parent (Split-Path -Parent $here)
$collector = Join-Path $repo 'collectors\IR-Collect.ps1'
if (-not (Test-Path -LiteralPath $collector)) { Write-Host "FAIL  collector not found"; exit 2 }

$ast = [System.Management.Automation.Language.Parser]::ParseFile($collector, [ref]$null, [ref]$null)
$wanted = @('Get-RecoveryPasswordShape','Get-BitLockerKeyVerdict')
foreach ($name in $wanted) {
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
    if (-not $fn) { Write-Host "FAIL  could not extract $name from the collector - guard broken, NOT clean"; exit 2 }
    . ([scriptblock]::Create($fn.Extent.Text))
}
foreach ($name in $wanted) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { Write-Host "FAIL  $name did not define - guard broken"; exit 2 }
}

$fail = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "ok    $what" } else { Write-Host "FAIL  $what"; $script:fail++ }
}

$GOOD = '123456-234567-345678-456789-567890-678901-789012-890123'

# --- the shape classifier ---------------------------------------------------------------------
Check ((Get-RecoveryPasswordShape $GOOD) -eq 'recovery-password') 'a real 48-digit recovery password is recognised'
Check ((Get-RecoveryPasswordShape '')    -eq 'absent')  'an empty password is absent'
Check ((Get-RecoveryPasswordShape '   ') -eq 'absent')  'whitespace is absent, not a key'
Check ((Get-RecoveryPasswordShape $null) -eq 'absent')  'a null password is absent'
Check ((Get-RecoveryPasswordShape '123456-234567') -eq 'malformed') 'a truncated password is malformed, not captured'
Check ((Get-RecoveryPasswordShape '12345-234567-345678-456789-567890-678901-789012-890123') -eq 'malformed') 'a 5-digit group is malformed'
Check ((Get-RecoveryPasswordShape '{2b7d1f0a-...}') -eq 'malformed') 'a protector GUID is not mistaken for a password'

# --- the verdict ------------------------------------------------------------------------------
$v = Get-BitLockerKeyVerdict -Rows @("C:,On,{id-1},$GOOD") -ScanOk $true
Check ($v.state -eq 'captured' -and $v.captured -eq 1 -and $v.missing -eq 0) 'a populated row is captured'

$v = Get-BitLockerKeyVerdict -Rows @('C:,On,{id-1},') -ScanOk $true
Check ($v.state -eq 'no-key-captured') 'a row with an EMPTY password is no-key-captured, not captured'
Check ($v.note -match 'UNRECOVERABLE') 'and the note names the consequence'
Check ($v.note -match 'C:') 'and it names which volume'

$v = Get-BitLockerKeyVerdict -Rows @("C:,On,{id-1},$GOOD", 'D:,On,{id-2},') -ScanOk $true
Check ($v.state -eq 'partial' -and $v.captured -eq 1 -and $v.missing -eq 1) 'one good and one blank row is partial'

$v = Get-BitLockerKeyVerdict -Rows @() -ScanOk $true
Check ($v.state -eq 'no-protectors') 'no rows is no-protectors'
Check ($v.note -match 'NO key was captured') 'and it says so plainly for a BitLocker host'

# --- THE THIRD STATE: a check that could not run is not a check that passed --------------------
$v = Get-BitLockerKeyVerdict -Rows $null -ScanOk $null
Check ($v.state -eq 'unknown') 'an unreadable artifact is unknown'
Check ($v.note -match 'NOT a statement that none was') 'and unknown is explicitly not a claim that no key exists'
$v = Get-BitLockerKeyVerdict -Rows @("C:,On,{id},$GOOD") -ScanOk $false
Check ($v.state -eq 'unknown') 'a failed scan is unknown even when rows were passed in'

# --- the expensive direction -------------------------------------------------------------------
# Nothing that is not an exact recovery password may ever produce a 'captured' verdict.
$bogus = @('', '   ', 'null', 'None', '{2b7d1f0a-9c3e-4a1b-8f6d-1e2c3b4a5d6e}', '000000', ('x'*48),
           '123456-234567-345678-456789-567890-678901-789012', '123456-234567-345678-456789-567890-678901-789012-890123-901234')
foreach ($b in $bogus) {
    $r = Get-BitLockerKeyVerdict -Rows @("C:,On,{id},$b") -ScanOk $true
    if ($r.state -eq 'captured') { Write-Host "FAIL  '$b' produced a 'captured' verdict - claims a key that is not there"; $fail++ }
}
Check $true 'no non-password value ever yields a captured verdict'

Write-Host ''
if ($fail -eq 0) { Write-Host 'all assertions passed'; exit 0 } else { Write-Host "$fail failed"; exit 1 }
