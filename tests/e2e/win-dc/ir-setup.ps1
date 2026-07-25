# Runs at first logon (from autounattend). Enables OpenSSH + key auth, stages the collector +
# DC-promotion script from the seed media, and registers an at-startup SYSTEM task that promotes
# this box to a Domain Controller (survives the promotion reboot; self-removes once the DC is up).
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\Windows\Temp\ir-setup.log'
function L($m){ "$(Get-Date -Format o) $m" | Out-File -Append $log }
L "ir-setup start"

New-Item -ItemType Directory -Force C:\irlab | Out-Null
# stage promote-dc.ps1 + IR-Collect.ps1 from whichever drive is the seed media
foreach ($d in 'D','E','F','G','H') {
  if (Test-Path "${d}:\promote-dc.ps1") { Copy-Item "${d}:\promote-dc.ps1" C:\irlab\ -Force }
  if (Test-Path "${d}:\IR-Collect.ps1") { Copy-Item "${d}:\IR-Collect.ps1" C:\irlab\ -Force }
}
L "staged: $(Get-ChildItem C:\irlab | Select-Object -Expand Name)"

# --- OpenSSH server (scp + remote exec channel from the KVM host) ---
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
# default shell = PowerShell so `ssh host <cmd>` runs under pwsh
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null

# --- authorize the lab key for Administrators (correct restricted ACL) ---
$pub = @'
__PUBKEY__
'@
$ProgramData = $env:ProgramData
$akeys = Join-Path $ProgramData 'ssh\administrators_authorized_keys'
Set-Content -Path $akeys -Value $pub -Encoding ascii
icacls $akeys /inheritance:r | Out-Null
icacls $akeys /grant 'Administrators:F' 'SYSTEM:F' | Out-Null
L "OpenSSH configured"

# --- register the DC-promotion task (SYSTEM, at startup, highest); it self-removes when done ---
$act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\irlab\promote-dc.ps1'
$trig = New-ScheduledTaskTrigger -AtStartup
$prin = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'IR-DCPromo' -Action $act -Trigger $trig -Principal $prin -Force | Out-Null
L "DC-promo task registered; launching promotion now"

# kick the promotion immediately (it will install AD-DS and reboot into a DC)
Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\irlab\promote-dc.ps1' -WindowStyle Hidden
L "ir-setup done"
