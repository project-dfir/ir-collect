# Idempotent DC promotion. Registered as an at-startup SYSTEM task by ir-setup.ps1 so it survives
# the promotion reboot. Once the box is a working DC (Get-ADDomain succeeds, ADWS+NTDS running) it
# writes C:\Windows\Temp\DC_READY and removes its own task.
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\Windows\Temp\promote-dc.log'
function L($m){ "$(Get-Date -Format o) $m" | Out-File -Append $log }
L "promote-dc invoked"

# already a DC? -> mark ready, clean up, exit
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $d = Get-ADDomain -ErrorAction Stop
  if ($d) {
    $svc = Get-Service NTDS,ADWS -ErrorAction SilentlyContinue | Where-Object Status -ne 'Running'
    if (-not $svc) {
      L "DC is up: $($d.DNSRoot)"
      "READY $($d.DNSRoot) $(Get-Date -Format o)" | Out-File 'C:\Windows\Temp\DC_READY'
      Unregister-ScheduledTask -TaskName 'IR-DCPromo' -Confirm:$false
      exit 0
    }
  }
} catch { L "not a DC yet: $($_.Exception.Message)" }

# not a DC yet -> install role + promote (this reboots the machine)
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
