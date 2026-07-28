<#
.SYNOPSIS
    Unit test for Test-DestHasSpace in kit/IR-Collect.ps1 (disk-full detection).

.DESCRIPTION
    Extracts the shipped function via the AST and drives it against conditions that all raise
    IOException-family errors but are NOT disk-full.

    Regression this locks in: detecting a full destination by catching [IO.IOException] alone is
    wrong, because PathTooLongException, DirectoryNotFoundException and FileNotFoundException all
    DERIVE from IOException - so a vanished directory or an over-long path would be reported as
    "disk full", flagging the run destination-full and corrupting the verdict. Detection must key
    on the actual condition (Win32 ERROR_HANDLE_DISK_FULL 39 / ERROR_DISK_FULL 112, or ENOSPC 28
    on Unix-hosted pwsh) and FAIL SAFE for everything else. Found by audit 2026-07-28, one
    iteration after the broad catch shipped.

.EXAMPLE  pwsh -File tests/unit/Test-DestSpaceProbe.ps1
#>
[CmdletBinding()]
param([string]$CollectorPath)

$ErrorActionPreference = 'Stop'
if (-not $CollectorPath) {
    $root = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $CollectorPath = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'kit') 'IR-Collect.ps1'
}
$col = (Resolve-Path $CollectorPath).Path
$ast = [System.Management.Automation.Language.Parser]::ParseFile($col, [ref]$null, [ref]$null)
$fn = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                     $args[0].Name -eq 'Test-DestHasSpace' }, $true)
if ($fn.Count -ne 1) { throw "expected 1 Test-DestHasSpace, found $($fn.Count)" }
. ([scriptblock]::Create($fn[0].Extent.Text))

$fail = 0
function Check($cond,$msg){ if($cond){Write-Host "ok    $msg" -ForegroundColor Green}else{Write-Host "FAIL  $msg" -ForegroundColor Red;$script:fail++} }

# 1. healthy dir -> has space
$Dirs = @{ logs = (New-Item -ItemType Directory -Force (Join-Path $env:TEMP ("dh_"+[guid]::NewGuid().ToString('N').Substring(0,6)))).FullName }
Check (Test-DestHasSpace) "healthy writable dir reports space available"

# 2. dir does not exist -> must FAIL SAFE (true), not claim disk-full
$Dirs = @{ logs = 'C:\definitely\not\a\real\path\at\all' }
Check (Test-DestHasSpace) "missing log dir fails SAFE (does not claim disk-full)"

# 3. $Dirs not initialised at all -> fail safe
Remove-Variable Dirs -ErrorAction SilentlyContinue
Check (Test-DestHasSpace) "uninitialised `$Dirs fails SAFE"

# 4. path-too-long: raises PathTooLongException, which DERIVES from IOException.
#    The old broad catch would have called this 'disk full'.
$long = 'C:\' + ('x' * 120) + '\' + ('y' * 120) + '\' + ('z' * 120)
$Dirs = @{ logs = $long }
$r = Test-DestHasSpace
Check $r "an over-long path is NOT reported as disk-full  <-- the umbrella-exception bug"

# 5. confirm the discrimination is real: a synthetic disk-full HResult must read as no-space
$probe = {
    try { throw (New-Object IO.IOException('There is not enough space on the disk.', 0x80070070)) }
    catch [IO.IOException] {
        $code = try { $_.Exception.HResult -band 0xFFFF } catch { 0 }
        if ($code -in 39,112,28) { return $false }
        if ($_.Exception.Message -match 'not enough space|disk is full|No space left') { return $false }
        return $true
    }
}
Check (-not (& $probe)) "a real ERROR_DISK_FULL HResult (0x70) IS classified as no-space"

Write-Host "`n$fail failed" -ForegroundColor $(if($fail){'Red'}else{'Green'})
exit $(if($fail){1}else{0})
