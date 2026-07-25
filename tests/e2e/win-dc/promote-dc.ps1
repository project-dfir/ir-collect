# Idempotent DC promotion. Registered as an at-startup SYSTEM task by ir-setup.ps1 so it survives
# the promotion reboot. The "am I a DC?" guard uses DomainRole (a LOCAL WMI check) - NOT Get-ADDomain,
# which needs ADWS and fails transiently right after the promo reboot (that false-negative caused a
# re-promotion loop). Once DomainRole>=4, wait for ADWS to answer, write DC_READY, self-remove.
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\Windows\Temp\promote-dc.log'
function L($m){ "$(Get-Date -Format o) $m" | Out-File -Append $log }
L "promote-dc invoked"

$role = (Get-CimInstance Win32_ComputerSystem).DomainRole   # 4=backup DC, 5=primary DC
if ($role -ge 4) {
  L "already a DC (DomainRole=$role); waiting for ADWS to answer Get-ADDomain"
  for ($i=0; $i -lt 30; $i++) {
    try { Import-Module ActiveDirectory -ErrorAction Stop; if (Get-ADDomain -ErrorAction Stop) { break } }
    catch { Start-Sleep 10 }
  }
  $dom = (Get-CimInstance Win32_ComputerSystem).Domain
  L "DC up: $dom -> writing DC_READY, removing task"
  "READY $dom $(Get-Date -Format o)" | Out-File 'C:\Windows\Temp\DC_READY'
  Unregister-ScheduledTask -TaskName 'IR-DCPromo' -Confirm:$false
  return
}

# not a DC yet -> install the role + promote (this reboots the machine)
try {
  if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
    L "installing AD-Domain-Services"
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
  }
  Import-Module ADDSDeployment
  $smp = ConvertTo-SecureString 'DsrmP@ss!Lab1' -AsPlainText -Force
  L "Install-ADDSForest lab.local (will reboot)"
  Install-ADDSForest -DomainName 'lab.local' -DomainNetbiosName 'LAB' `
    -ForestMode 'WinThreshold' -DomainMode 'WinThreshold' -InstallDns:$true `
    -SafeModeAdministratorPassword $smp -Force:$true -NoRebootOnCompletion:$false
} catch { L "promo error: $($_.Exception.Message)" }
