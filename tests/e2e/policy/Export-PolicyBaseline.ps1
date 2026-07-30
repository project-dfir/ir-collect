<#
.SYNOPSIS
    Capture a machine's CURRENT security-policy state so a test policy can be reverted exactly.

.DESCRIPTION
    Run this on a range VM BEFORE applying any test policy. It writes a self-contained baseline
    folder that Restore-PolicyBaseline.ps1 consumes.

    Why this exists rather than a hypervisor snapshot: the range VM disks are .raw on `dir`
    storage, and Proxmox cannot snapshot that format (qm snapshot -> "snapshot feature is not
    available"). Until those disks are converted to qcow2 there is NO rollback at the hypervisor
    layer, so the revert path has to be in-guest, targeted and verified. See README.md.

    Captured:
      * AppLocker effective + local policy (XML)
      * AppIDSvc start type (AppLocker enforcement depends on it)
      * WDAC / Code Integrity state (deployed policies, HVCI/CI status)
      * PowerShell ExecutionPolicy per scope
      * __PSLockdownPolicy machine environment variable
      * PowerShell script-block/module logging + transcription registry state

.EXAMPLE
    .\Export-PolicyBaseline.ps1 -Path C:\policy-baseline
#>
[CmdletBinding()]
param([string]$Path = 'C:\policy-baseline')

$ErrorActionPreference = 'Continue'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
$dir   = Join-Path $Path $stamp
New-Item -ItemType Directory -Force $dir | Out-Null
function Log($m) { $line = "$((Get-Date).ToUniversalTime().ToString('o')) $m"; Write-Host $line; Add-Content (Join-Path $dir 'export.log') $line }

Log "Exporting security-policy baseline on $env:COMPUTERNAME -> $dir"

# --- AppLocker -----------------------------------------------------------------
try {
    Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop | Set-Content (Join-Path $dir 'applocker_effective.xml') -Encoding UTF8
    Log 'AppLocker effective policy exported'
} catch { Log "AppLocker effective export failed: $($_.Exception.Message)" }
try {
    Get-AppLockerPolicy -Local -Xml -ErrorAction Stop | Set-Content (Join-Path $dir 'applocker_local.xml') -Encoding UTF8
    Log 'AppLocker LOCAL policy exported (this is what Restore re-applies)'
} catch { Log "AppLocker local export failed: $($_.Exception.Message)" }

# --- state that AppLocker enforcement depends on -------------------------------
$state = [ordered]@{
    computer          = $env:COMPUTERNAME
    exported_utc      = (Get-Date).ToUniversalTime().ToString('o')
    ps_version        = "$($PSVersionTable.PSVersion)"
    language_mode     = "$($ExecutionContext.SessionState.LanguageMode)"
    appidsvc_start    = (Get-Service AppIDSvc -ErrorAction SilentlyContinue).StartType.ToString()
    appidsvc_status   = (Get-Service AppIDSvc -ErrorAction SilentlyContinue).Status.ToString()
    lockdown_env_machine = [Environment]::GetEnvironmentVariable('__PSLockdownPolicy','Machine')
    execpolicy        = @{}
}
foreach ($s in 'MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine') {
    $state.execpolicy[$s] = (Get-ExecutionPolicy -Scope $s -ErrorAction SilentlyContinue).ToString()
}
try {
    $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    $state.deviceguard = @{
        codeintegrity_configured = @($ci.SecurityServicesConfigured)
        codeintegrity_running    = @($ci.SecurityServicesRunning)
        ci_policy_enforcement    = "$($ci.CodeIntegrityPolicyEnforcementStatus)"
    }
} catch { $state.deviceguard = "unavailable: $($_.Exception.Message)" }
$state.wdac_policies = @(Get-ChildItem 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active' -Filter *.cip -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })

# --- PowerShell logging policy (we may enable it for diagnostics) --------------
$psLogKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
)
$state.pslogging = @{}
foreach ($k in $psLogKeys) {
    if (Test-Path $k) {
        $props = Get-ItemProperty $k
        $state.pslogging[$k] = ($props.PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
    } else { $state.pslogging[$k] = '(absent)' }
}

$state | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $dir 'baseline_state.json') -Encoding UTF8
Log "language_mode at export : $($state.language_mode)"
Log "AppIDSvc                : $($state.appidsvc_start)/$($state.appidsvc_status)"
Log "__PSLockdownPolicy      : $(if($state.lockdown_env_machine){$state.lockdown_env_machine}else{'(unset)'})"

# a stable pointer so Restore can find the newest baseline without guessing
Set-Content (Join-Path $Path 'LATEST.txt') $dir -Encoding ASCII
Log "Baseline complete. Restore with: .\Restore-PolicyBaseline.ps1 -BaselineDir '$dir'"
