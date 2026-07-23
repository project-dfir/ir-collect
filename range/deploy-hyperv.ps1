<#
Deploy IR-Collect into a Hyper-V guest via PowerShell Direct (host <-> guest, NO network needed),
run it, and pull results back. Falls back to Copy-VMFile (Guest Service Interface) for the copy-in
if you only have GSI and not guest creds (but running still needs a session or a scheduled task).

Prereqs: run on the Hyper-V HOST as admin; guest is Windows 10 / Server 2016+; GUEST-OS credentials.
Build the kit first (zip of this repo incl. tools\), then:
  .\deploy-hyperv.ps1 -VMName TRIAGE-WIN01 -KitZip .\kit.zip -Out .\loot
#>
param(
  [Parameter(Mandatory)][string]$VMName,
  [Parameter(Mandatory)][string]$KitZip,
  [string]$Out = '.\loot',
  [pscredential]$Credential
)
$ErrorActionPreference = 'Stop'
if (-not $Credential) { $Credential = Get-Credential -Message "Guest OS credentials for $VMName" }
New-Item -ItemType Directory -Force $Out | Out-Null

# make sure the Guest Service Interface is on (needed if you prefer Copy-VMFile)
try { Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue } catch {}

Write-Host "[*] ${VMName}: opening PowerShell Direct session"
$s = New-PSSession -VMName $VMName -Credential $Credential
try {
    Invoke-Command -Session $s { New-Item -ItemType Directory -Force C:\IR | Out-Null }
    Write-Host "[*] copying kit into guest"
    Copy-Item -ToSession $s $KitZip -Destination 'C:\IR\kit.zip' -Force
    Invoke-Command -Session $s { Expand-Archive -Force C:\IR\kit.zip C:\IR\kit }
    Write-Host "[*] running collector in guest (Lab mode)"
    Invoke-Command -Session $s { & C:\IR\kit\IR-Collect.ps1 -Lab -Auto -Dest C:\IR\out }
    $dst = Join-Path $Out $VMName
    New-Item -ItemType Directory -Force $dst | Out-Null
    Write-Host "[*] pulling results back to $dst"
    Copy-Item -FromSession $s 'C:\IR\out\*' -Destination $dst -Recurse -Force
    Write-Host "[*] done -> $dst"
} finally { Remove-PSSession $s }
