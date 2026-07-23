<#
  Mobile-Collect.ps1 - Windows launcher for mobile-collect.sh.

  Mobile acquisition is POSIX-tool-based (adb + libimobiledevice + MVT); the examiner engine is
  mobile-collect.sh. This launcher runs it under a POSIX shell on Windows.

  It PREFERS Git-Bash (native Windows USB stack -> adb.exe / libimobiledevice-win see the device
  directly), then falls back to WSL. Note: under WSL2 you must attach the USB device with usbipd-win
  first, or acquire natively via Git-Bash. Install tools once:  bash ./fetch-mobile-tools.sh

  Usage (all args pass straight through to mobile-collect.sh):
    .\Mobile-Collect.ps1 -c CASE1 -d E:\evidence --android --analyze
    .\Mobile-Collect.ps1 -c CASE1 -d E:\evidence --ios --analyze --backup-pass CaseIR
#>
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $here 'mobile-collect.sh'
if (-not (Test-Path $script)) { Write-Error "mobile-collect.sh not found next to this launcher"; exit 1 }

# prefer Git-Bash (native USB), then WSL
$gitBash = @("$env:ProgramFiles\Git\bin\bash.exe", "$env:ProgramFiles\Git\usr\bin\bash.exe",
             "${env:ProgramFiles(x86)}\Git\bin\bash.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $gitBash) { $g = Get-Command bash.exe -ErrorAction SilentlyContinue; if ($g -and $g.Source -notmatch 'System32') { $gitBash = $g.Source } }

if ($gitBash) {
    Write-Host "Running mobile-collect.sh under Git-Bash (native USB): $gitBash" -ForegroundColor Cyan
    & $gitBash $script @Rest
    exit $LASTEXITCODE
}
if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    $wslScript = (& wsl.exe wslpath -a ($script -replace '\\','/')).Trim()
    Write-Host "Running mobile-collect.sh under WSL: $wslScript" -ForegroundColor Cyan
    Write-Host "  (WSL2 needs the USB device attached via usbipd-win, or use Git-Bash for native USB.)" -ForegroundColor DarkYellow
    & wsl.exe bash $wslScript @Rest
    exit $LASTEXITCODE
}
Write-Host "No Git-Bash or WSL found. Mobile acquisition needs a POSIX shell + adb/libimobiledevice/MVT." -ForegroundColor Yellow
Write-Host "Install Git for Windows (Git-Bash) or WSL2, then: bash ./fetch-mobile-tools.sh ; and re-run." -ForegroundColor Yellow
exit 2
