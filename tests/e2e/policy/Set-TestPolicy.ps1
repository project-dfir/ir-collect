<#
.SYNOPSIS
    Apply a named security policy to a RANGE VM so the collector can be tested against it.

.DESCRIPTION
    Test-environment only. Refuses to run unless -IUnderstandThisIsATestVM is passed AND a
    baseline has been exported first, because on this range there is no hypervisor snapshot to
    fall back on (raw-on-dir disks; see README.md).

    Policies:
      clm-applocker  Realistic: an AppLocker script rule set in enforce mode. PowerShell drops
                     scripts outside allow-listed paths into ConstrainedLanguage - the condition
                     a hardened enterprise endpoint actually presents.
      clm-envvar     Quick: sets the machine __PSLockdownPolicy=4 environment variable. Legacy
                     lever, not honoured on every build; use when you want the CLM condition fast
                     and do not care that it is not how real hosts get there.
      audit-only     AppLocker in Audit mode - logs what WOULD be blocked, changes no behaviour.
                     Useful for confirming the rule set targets what you think before enforcing.

.EXAMPLE
    .\Set-TestPolicy.ps1 -Policy clm-applocker -IUnderstandThisIsATestVM
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('clm-applocker','clm-envvar','audit-only')][string]$Policy,
    [string]$BaselinePath = 'C:\policy-baseline',
    [switch]$IUnderstandThisIsATestVM
)

$ErrorActionPreference = 'Stop'
function Log($m) { Write-Host "$((Get-Date).ToUniversalTime().ToString('o')) $m" }

if (-not $IUnderstandThisIsATestVM) {
    Write-Host 'Refusing: this changes machine security policy. Pass -IUnderstandThisIsATestVM on a RANGE VM only.' -ForegroundColor Red
    exit 2
}
# Hard gate: no baseline, no test. The whole point is a guaranteed way back.
$latest = Join-Path $BaselinePath 'LATEST.txt'
if (-not (Test-Path $latest)) {
    Write-Host "Refusing: no baseline at $latest. Run Export-PolicyBaseline.ps1 FIRST - there is no" -ForegroundColor Red
    Write-Host 'hypervisor snapshot on this range, so the exported baseline is the only way back.'   -ForegroundColor Red
    exit 2
}
$baseDir = (Get-Content $latest -Raw).Trim()
Log "Baseline present: $baseDir"
Log "Applying policy: $Policy"

switch ($Policy) {
    'clm-envvar' {
        [Environment]::SetEnvironmentVariable('__PSLockdownPolicy','4','Machine')
        Log 'Set machine __PSLockdownPolicy=4. NEW PowerShell processes should start in ConstrainedLanguage.'
        Log 'Verify:  powershell -NoProfile -Command $ExecutionContext.SessionState.LanguageMode'
    }
    { $_ -in 'clm-applocker','audit-only' } {
        $mode = if ($Policy -eq 'audit-only') { 'AuditOnly' } else { 'Enabled' }
        # Allow-list Windows + Program Files so the VM stays usable and reachable over SSH/WinRM;
        # anything else (including the collector staged in C:\ir) falls outside the allow list,
        # which is exactly what forces ConstrainedLanguage for our scripts.
        $xml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Script" EnforcementMode="$mode">
    <FilePathRule Id="9b7d1e1a-0000-4000-8000-00000000a001" Name="Allow Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9b7d1e1a-0000-4000-8000-00000000a002" Name="Allow Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="9b7d1e1a-0000-4000-8000-00000000a003" Name="Admins full" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
        $f = Join-Path $env:TEMP 'test-applocker.xml'
        Set-Content $f $xml -Encoding UTF8
        Set-AppLockerPolicy -XmlPolicy $f -ErrorAction Stop
        Log "AppLocker script rules applied in $mode mode"
        # enforcement is inert without the Application Identity service
        Set-Service AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service AppIDSvc -ErrorAction SilentlyContinue
        Log "AppIDSvc: $((Get-Service AppIDSvc).Status)"
        Log 'NOTE: a reboot may be required before enforcement fully applies.'
    }
}

Log 'Applied. REVERT WITH:'
Log "  .\Restore-PolicyBaseline.ps1 -BaselineDir '$baseDir'"
