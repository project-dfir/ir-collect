<#
.SYNOPSIS
    Put a range VM back to the security policy captured by Export-PolicyBaseline.ps1.

.DESCRIPTION
    Restores AppLocker local policy, AppIDSvc start type, and the __PSLockdownPolicy machine
    variable, then VERIFIES the result and reports pass/fail per item. Verification matters more
    than the restore itself: a revert you did not confirm is not a revert.

    If AppLocker cannot be cleared (rare - usually a domain GPO re-applying it), the script says
    so explicitly rather than reporting success, and points at the heavier fallbacks in README.md.

.EXAMPLE
    .\Restore-PolicyBaseline.ps1                      # uses C:\policy-baseline\LATEST.txt
    .\Restore-PolicyBaseline.ps1 -BaselineDir C:\policy-baseline\20260728_040000Z
#>
[CmdletBinding()]
param(
    [string]$BaselineDir,
    [string]$BaselinePath = 'C:\policy-baseline'
)

$ErrorActionPreference = 'Continue'
function Log($m) { Write-Host "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

if (-not $BaselineDir) {
    $latest = Join-Path $BaselinePath 'LATEST.txt'
    if (-not (Test-Path $latest)) { Write-Host "No baseline pointer at $latest" -ForegroundColor Red; exit 2 }
    $BaselineDir = (Get-Content $latest -Raw).Trim()
}
if (-not (Test-Path $BaselineDir)) { Write-Host "Baseline dir not found: $BaselineDir" -ForegroundColor Red; exit 2 }
Log "Restoring from $BaselineDir"

$state = Get-Content (Join-Path $BaselineDir 'baseline_state.json') -Raw | ConvertFrom-Json
$fail = 0

# --- AppLocker ------------------------------------------------------------------
$localXml = Join-Path $BaselineDir 'applocker_local.xml'
try {
    if (Test-Path $localXml) {
        Set-AppLockerPolicy -XmlPolicy $localXml -ErrorAction Stop
        Log 'AppLocker local policy re-applied from baseline'
    } else {
        # no baseline policy existed -> restore "no policy" by applying an empty rule set
        $empty = Join-Path $env:TEMP 'applocker-empty.xml'
        Set-Content $empty '<AppLockerPolicy Version="1"></AppLockerPolicy>' -Encoding UTF8
        Set-AppLockerPolicy -XmlPolicy $empty -ErrorAction Stop
        Log 'No AppLocker policy in baseline -> cleared to an empty policy'
    }
} catch { Log "AppLocker restore FAILED: $($_.Exception.Message)"; $fail++ }

# --- AppIDSvc -------------------------------------------------------------------
try {
    if ($state.appidsvc_start) {
        Set-Service AppIDSvc -StartupType $state.appidsvc_start -ErrorAction Stop
        Log "AppIDSvc StartupType restored to $($state.appidsvc_start)"
        if ($state.appidsvc_status -ne 'Running') { Stop-Service AppIDSvc -Force -ErrorAction SilentlyContinue }
    }
} catch { Log "AppIDSvc restore FAILED: $($_.Exception.Message)"; $fail++ }

# --- __PSLockdownPolicy ---------------------------------------------------------
try {
    $want = $state.lockdown_env_machine
    if ([string]::IsNullOrEmpty($want)) {
        [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', $null, 'Machine')
        Log '__PSLockdownPolicy machine variable cleared (was unset at baseline)'
    } else {
        [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', $want, 'Machine')
        Log "__PSLockdownPolicy machine variable restored to $want"
    }
} catch { Log "__PSLockdownPolicy restore FAILED: $($_.Exception.Message)"; $fail++ }

# --- VERIFY (the part that actually matters) ------------------------------------
Log '--- verification ---'
$eff = try { (Get-AppLockerPolicy -Effective -Xml) } catch { '' }
$enforcing = $eff -match 'EnforcementMode="Enabled"'
if ($enforcing) { Log 'FAIL: an AppLocker rule collection is still in Enabled (enforce) mode'; $fail++ }
else            { Log 'ok: no AppLocker collection is in enforce mode' }

$envNow = [Environment]::GetEnvironmentVariable('__PSLockdownPolicy','Machine')
if ("$envNow" -ne "$($state.lockdown_env_machine)") { Log "FAIL: __PSLockdownPolicy is '$envNow', baseline was '$($state.lockdown_env_machine)'"; $fail++ }
else { Log 'ok: __PSLockdownPolicy matches baseline' }

# language mode in a FRESH process is the real proof - the current session may be stale
$fresh = & powershell -NoProfile -Command '$ExecutionContext.SessionState.LanguageMode' 2>$null
Log "language mode in a fresh PowerShell: $fresh (baseline was $($state.language_mode))"
if ("$fresh".Trim() -ne "$($state.language_mode)".Trim()) {
    Log 'FAIL: language mode does not match the baseline - a reboot may be needed, re-verify after.'
    $fail++
}

if ($fail -eq 0) { Log 'RESTORE VERIFIED - machine matches its pre-test policy baseline.' }
else {
    Log "RESTORE INCOMPLETE - $fail check(s) failed. Do NOT assume this VM is clean."
    Log 'Fallbacks (README.md): reboot and re-verify; vzdump restore; or rebuild the VM.'
}
exit $(if ($fail) { 1 } else { 0 })
