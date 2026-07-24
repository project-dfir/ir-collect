<#
.SYNOPSIS
  End-to-end, headless, autonomous test of IR-Collect against a REAL Windows guest VM on Hyper-V.

.DESCRIPTION
  Runs ON the Hyper-V host (e.g. l3e7). Provisions a Gen2 VM from a ready-to-run eval VHDX,
  boots it HEADLESS, then drives the collector across the full incident-scenario matrix and
  verifies each sealed evidence bundle.

  DESIGN (the binding lesson from the dfir-vm project: do NOT get stuck SSH-ing into the VM
  after boot):
    * Readiness is detected over the HYPERV GUEST CHANNEL, not the network - we poll the
      Heartbeat integration service (PrimaryStatusDescription = 'OK') and the KVP data-exchange
      store for the guest's own signal, each with a BOUNDED timeout. No blind ssh loop.
    * Deploy + drive is over POWERSHELL DIRECT (Invoke-Command -VMName / Copy-Item -ToSession):
      VMBus/HvSocket transport, needs NO guest networking, NO WinRM, NO SSH.
    * The guest admin password is injected OFFLINE (RunOnce in the mounted SOFTWARE hive) so
      PowerShell Direct has a credential it can log on with, regardless of the image default.

  Every phase is logged; the VM is always torn down (unless -KeepVM); results are asserted and
  aggregated into results.json + REPORT.md.

.NOTES
  Requires: Hyper-V (Enabled), elevation, ~40GB free. Idempotent-ish: removes a prior same-name VM.
#>
[CmdletBinding()]
param(
    [string]$VhdxZip      = 'C:\DFIR\e2e\WinDevVM.zip',    # the downloaded eval VHDX zip
    [string]$WorkDir      = 'C:\DFIR\e2e',                  # scratch + results root
    [string]$KitDir       = 'C:\DFIR\e2e\ir-collector',     # ir-collect repo checkout to push into the guest
    [string]$VMName       = 'IRCollect-E2E',
    [string]$GuestUser    = 'User',                         # WinDev eval default local admin
    [string]$GuestPass    = 'IRCollectE2E!42',              # we inject this offline so PSDirect can log on
    [int]   $MemoryGB     = 6,
    [int]   $Cpu          = 4,
    [int]   $BootTimeoutSec  = 900,   # bound for heartbeat OK
    [int]   $PSDirectTimeoutSec = 600, # bound for PowerShell Direct to accept the credential
    [string[]]$Scenarios  = @('1','2','3','4','5','6','7','8','9','10','U'),  # full matrix
    [string[]]$FullRunScenarios = @('5'),  # these get a FULL -Auto run (all heavy jobs); rest are -RapidOnly
    [switch]$Fresh,        # remove any existing VM/vhdx first
    [switch]$KeepVM        # skip teardown (debug)
)

$ErrorActionPreference = 'Stop'
$script:StartUtc = (Get-Date).ToUniversalTime()
$RunId   = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
$RunDir  = Join-Path $WorkDir "run_$RunId"
$ResultsDir = Join-Path $RunDir 'results'
$null = New-Item -ItemType Directory -Force $RunDir, $ResultsDir
$LogFile = Join-Path $RunDir 'e2e.log'
$VhdWork = Join-Path $RunDir 'guest.vhdx'

function Log { param([string]$m,[string]$lvl='INFO')
    $line = "{0} [{1}] {2}" -f ((Get-Date).ToUniversalTime().ToString('HH:mm:ss')), $lvl, $m
    Add-Content -Path $LogFile -Value $line; Write-Host $line -ForegroundColor $(switch($lvl){'ERR'{'Red'}'WARN'{'Yellow'}'OK'{'Green'}default{'Gray'}})
}

# ----- scenario matrix: realistic seed IOCs + the host-role we drive each scenario as -----
# (RFC 5737 TEST-NET IPs, RFC 2606 example.* domains, obviously-fake hashes - safe, realistic shapes.)
$Matrix = @{
  '1'  = @{ role='workstation';      ip='203.0.113.11';   dom='payme.example';        hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
  '2'  = @{ role='cloud-vm';         ip='198.51.100.23';  dom='login.micros0ft.example'; hash='' }
  '3'  = @{ role='workstation';      ip='203.0.113.44';   dom='rclone-sync.example';  hash='' }
  '4'  = @{ role='server';           ip='198.51.100.7';   dom='webshell.example';     hash='da39a3ee5e6b4b0d3255bfef95601890afd80709' }
  '5'  = @{ role='workstation';      ip='203.0.113.66';   dom='beacon.example';       hash='5d41402abc4b2a76b9719d911017c592aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }
  '6'  = @{ role='domain-controller';ip='198.51.100.88';  dom='dc-evil.example';      hash='' }
  '7'  = @{ role='server';           ip='203.0.113.99';   dom='psexec.example';       hash='' }
  '8'  = @{ role='workstation';      ip='198.51.100.111'; dom='lolbin.example';       hash='' }
  '9'  = @{ role='workstation';      ip='203.0.113.121';  dom='phish.example';        hash='' }
  '10' = @{ role='server';           ip='198.51.100.131'; dom='pool.mine.example';    hash='' }
  'U'  = @{ role='workstation';      ip='';               dom='';                     hash='' }
}
# expected plan per scenario (mirrors kit/IR-Collect.ps1 $Scenarios) - the assertion oracle.
$ExpectPlan = @{
  '1'=@('1','9','2','3','4'); '2'=@('6','2','3'); '3'=@('2','4','7','6'); '4'=@('10','1','2','3','4')
  '5'=@('1','2','3','4'); '6'=@('3','5','2','4'); '7'=@('3','2','4','5'); '8'=@('1','3','4','2')
  '9'=@('6','2','3','4'); '10'=@('4','2','3'); 'U'=@('2','3','4','6')   # U -> broad default
}

$secpass = ConvertTo-SecureString $GuestPass -AsPlainText -Force
$GuestCred = New-Object System.Management.Automation.PSCredential("$GuestUser", $secpass)

# ==========================================================================================
function Remove-PriorVM {
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($vm) { Log "Removing prior VM $VMName"; if ($vm.State -ne 'Off'){ Stop-VM $VMName -TurnOff -Force -EA SilentlyContinue }; Remove-VM $VMName -Force -EA SilentlyContinue }
}

function Expand-Guest {
    # locate + extract the VHDX from the eval zip; inject the admin password offline.
    if (-not (Test-Path $VhdxZip)) { throw "VHDX zip not found: $VhdxZip" }
    Log "Extracting VHDX from $VhdxZip ..."
    $ex = Join-Path $RunDir 'vhdx_extract'; $null = New-Item -ItemType Directory -Force $ex
    # tar.exe (bsdtar) is far faster + lower-memory than Expand-Archive on a ~22GB zip
    $tar = (Get-Command tar.exe -EA SilentlyContinue).Source
    if ($tar) { & $tar -xf $VhdxZip -C $ex; if ($LASTEXITCODE -ne 0) { Log "tar extract rc=$LASTEXITCODE, falling back to Expand-Archive" 'WARN'; Expand-Archive -Path $VhdxZip -DestinationPath $ex -Force } }
    else { Expand-Archive -Path $VhdxZip -DestinationPath $ex -Force }
    $src = Get-ChildItem $ex -Recurse -Include *.vhdx,*.vhd | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $src) { throw "no VHDX inside $VhdxZip" }
    Log "Guest disk: $($src.FullName) ($([math]::Round($src.Length/1GB,1)) GB) -> $VhdWork"
    Copy-Item $src.FullName $VhdWork -Force
    Inject-GuestPassword -Vhd $VhdWork
}

function Inject-GuestPassword {
    param([string]$Vhd)
    # Mount the VHDX, load its offline SOFTWARE hive, add a RunOnce that (on the guest's autologon)
    # sets the local admin password + drops a KVP ready marker. This is what lets PowerShell Direct
    # authenticate without ever touching the guest network.
    Log "Injecting admin password + ready-signal via offline RunOnce ..."
    $mount = Mount-VHD -Path $Vhd -Passthru | Get-Disk | Get-Partition | Where-Object { $_.DriveLetter }
    $winPart = $mount | Where-Object { Test-Path ("{0}:\Windows\System32\config\SOFTWARE" -f $_.DriveLetter) } | Select-Object -First 1
    if (-not $winPart) { Dismount-VHD -Path $Vhd; throw "could not find Windows partition in VHDX" }
    $dl = $winPart.DriveLetter
    $hive = "{0}:\Windows\System32\config\SOFTWARE" -f $dl
    $firstboot = "{0}:\Windows\Temp\ir_firstboot.ps1" -f $dl
    @"
net user $GuestUser '$GuestPass'
net user $GuestUser /active:yes
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LimitBlankPasswordUse -Value 0 -EA SilentlyContinue
`$k='HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest'; New-Item `$k -Force | Out-Null
Set-ItemProperty `$k -Name 'IRReady' -Value ('ready ' + (Get-Date -Format o))
"@ | Set-Content $firstboot -Encoding UTF8
    reg load 'HKLM\OFFLINE_SW' $hive | Out-Null
    try {
        $ro = 'HKLM\OFFLINE_SW\Microsoft\Windows\CurrentVersion\RunOnce'
        reg add $ro /v 'IRFirstBoot' /t REG_SZ /d "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\ir_firstboot.ps1" /f | Out-Null
    } finally {
        [gc]::Collect(); Start-Sleep 1; reg unload 'HKLM\OFFLINE_SW' | Out-Null
    }
    Dismount-VHD -Path $Vhd
    Log "Offline injection complete." 'OK'
}

function New-GuestVM {
    Log "Creating Gen2 VM $VMName (${MemoryGB}GB, ${Cpu}vCPU) ..."
    $sw = (Get-VMSwitch | Where-Object { $_.Name -eq 'Default Switch' } | Select-Object -First 1)
    if (-not $sw) { $sw = Get-VMSwitch | Select-Object -First 1 }
    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($MemoryGB*1GB) -VHDPath $VhdWork -SwitchName $sw.Name | Out-Null
    Set-VM -Name $VMName -ProcessorCount $Cpu -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
    Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface','Heartbeat','Key-Value Pair Exchange','Shutdown' -EA SilentlyContinue
    Log "Starting VM headless ..." 'OK'
    Start-VM -Name $VMName
}

function Get-GuestKvp {
    param([string]$Key)
    $vm = Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$VMName'"
    if (-not $vm) { return $null }
    $kvp = Get-WmiObject -Namespace root\virtualization\v2 -Query "Associators of {$($vm.__PATH)} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent"
    if (-not $kvp) { return $null }
    foreach ($item in @($kvp.GuestIntrinsicExchangeItems) + @($kvp.GuestExchangeItems)) {
        if (-not $item) { continue }
        $x = [xml]$item
        $name = ($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Name' }).VALUE
        if ($name -eq $Key) { return ($x.INSTANCE.PROPERTY | Where-Object { $_.NAME -eq 'Data' }).VALUE }
    }
    return $null
}

function Wait-GuestReady {
    # BOUNDED readiness over the guest channel: heartbeat OK, then a working PowerShell Direct session.
    Log "Waiting for guest heartbeat (bound ${BootTimeoutSec}s) ..."
    $deadline = (Get-Date).AddSeconds($BootTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $hb = (Get-VMIntegrationService -VMName $VMName -Name Heartbeat -EA SilentlyContinue).PrimaryStatusDescription
        $os = Get-GuestKvp 'OSName'
        Log ("  heartbeat={0} kvp.OSName={1}" -f (($hb, '-' -ne $null)[0]), (($os, '-' -ne $null)[0]))
        if ($hb -eq 'OK') { break }
        Start-Sleep -Seconds 15
    }
    if ((Get-VMIntegrationService -VMName $VMName -Name Heartbeat -EA SilentlyContinue).PrimaryStatusDescription -ne 'OK') {
        throw "guest never reached heartbeat OK within ${BootTimeoutSec}s"
    }
    Log "Heartbeat OK. Waiting for PowerShell Direct credential (bound ${PSDirectTimeoutSec}s) ..." 'OK'
    $deadline = (Get-Date).AddSeconds($PSDirectTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-Command -VMName $VMName -Credential $GuestCred -ScriptBlock { $env:COMPUTERNAME } -EA Stop
            if ($r) { Log "PowerShell Direct up. Guest=$r" 'OK'; return $true }
        } catch { Log "  PSDirect not ready: $($_.Exception.Message.Split([Environment]::NewLine)[0])" }
        Start-Sleep -Seconds 15
    }
    throw "PowerShell Direct never accepted the credential within ${PSDirectTimeoutSec}s"
}

function Copy-KitToGuest {
    Log "Copying ir-collect kit into guest via PowerShell Direct ..."
    $sess = New-PSSession -VMName $VMName -Credential $GuestCred
    try {
        Invoke-Command -Session $sess -ScriptBlock { param($d) if(Test-Path $d){Remove-Item $d -Recurse -Force -EA SilentlyContinue}; New-Item -ItemType Directory -Force $d | Out-Null } -ArgumentList 'C:\ir-collector'
        Copy-Item -ToSession $sess -Path (Join-Path $KitDir 'kit') -Destination 'C:\ir-collector\kit' -Recurse -Force
        $ok = Invoke-Command -Session $sess -ScriptBlock { Test-Path 'C:\ir-collector\kit\IR-Collect.ps1' }
        if (-not $ok) { throw "kit did not land in guest" }
        Log "Kit staged in guest at C:\ir-collector\kit" 'OK'
    } finally { Remove-PSSession $sess }
}

function Invoke-Scenario {
    param([string]$Sid)
    $m = $Matrix[$Sid]; $full = $Sid -in $FullRunScenarios
    $mode = if ($full) { '-Auto' } else { '-RapidOnly' }
    Log "=== Scenario $Sid  role=$($m.role)  mode=$mode ==="
    $case = "E2E-S$Sid"
    $sess = New-PSSession -VMName $VMName -Credential $GuestCred
    try {
        $guestOut = Invoke-Command -Session $sess -ScriptBlock {
            param($sid,$role,$ip,$dom,$hash,$mode,$case)
            $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\ir-collector\kit\IR-Collect.ps1',
                      $mode,'-Scenario',$sid,'-HostRole',$role,'-CaseId',$case,'-Dest','C:\evidence')
            if ($ip)   { $a += @('-KnownBadIps',$ip) }
            if ($dom)  { $a += @('-KnownBadDomains',$dom) }
            if ($hash) { $a += @('-KnownBadHashes',$hash) }
            $p = Start-Process powershell -ArgumentList $a -Wait -PassThru -WindowStyle Hidden
            $out = Get-ChildItem 'C:\evidence' -Directory | Where-Object { $_.Name -like "${case}_*" } | Sort-Object LastWriteTime -Desc | Select-Object -First 1
            [pscustomobject]@{ exit=$p.ExitCode; outdir=$out.FullName }
        } -ArgumentList $Sid,$m.role,$m.ip,$m.dom,$m.hash,$mode,$case
        Log "  guest exit=$($guestOut.exit) outdir=$($guestOut.outdir)"
        $localOut = Join-Path $ResultsDir "S$Sid"
        Copy-Item -FromSession $sess -Path $guestOut.outdir -Destination $localOut -Recurse -Force
        return (Assert-Scenario -Sid $Sid -LocalOut $localOut -GuestExit $guestOut.exit)
    } finally { Remove-PSSession $sess }
}

function Assert-Scenario {
    param([string]$Sid,[string]$LocalOut,[int]$GuestExit)
    $checks = [ordered]@{}
    $inner = Get-ChildItem $LocalOut -Directory | Select-Object -First 1  # copied dir wraps the case dir
    $base = if (Test-Path (Join-Path $LocalOut '00_metadata')) { $LocalOut } elseif ($inner) { $inner.FullName } else { $LocalOut }
    $intakeF = Join-Path $base '00_metadata\intake.json'
    $rsF     = Join-Path $base '99_logs\run_state.json'
    $sumF    = Join-Path $base 'SUMMARY.md'
    $manF    = Join-Path $base 'MANIFEST-SHA256.csv'
    $checks['intake_exists']    = Test-Path $intakeF
    $checks['runstate_exists']  = Test-Path $rsF
    $checks['summary_exists']   = Test-Path $sumF
    $checks['manifest_exists']  = Test-Path $manF
    $scenarioOk=$false; $planOk=$false; $verdict='?'; $attack=@()
    if (Test-Path $intakeF) {
        $ik = Get-Content $intakeF -Raw | ConvertFrom-Json
        $scenarioOk = ($ik.scenario -eq $Sid)
        $planOk = ((@($ik.plan) -join ',') -eq (@($ExpectPlan[$Sid]) -join ','))
        $attack = @($ik.attack_tags)
    }
    if (Test-Path $rsF) { $verdict = (Get-Content $rsF -Raw | ConvertFrom-Json).completeness.verdict }
    $checks['scenario_matches'] = $scenarioOk
    $checks['plan_matches']     = $planOk
    $checks['attack_tagged']    = ($attack.Count -gt 0 -or $Sid -eq 'U')
    $checks['completeness_verdict_present'] = ($verdict -in 'COMPLETE','INCOMPLETE')
    $pass = -not ($checks.Values -contains $false)
    Log ("  ASSERT S{0}: {1}  (scenario={2} plan={3} verdict={4})" -f $Sid,$(if($pass){'PASS'}else{'FAIL'}),$scenarioOk,$planOk,$verdict) $(if($pass){'OK'}else{'ERR'})
    return [pscustomobject]@{ scenario=$Sid; pass=$pass; verdict=$verdict; attack=$attack; guest_exit=$GuestExit; checks=$checks; outdir=$base }
}

# ==========================================================================================
# MAIN
# ==========================================================================================
$results = @()
try {
    if (-not (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators'))) { throw "must run elevated" }
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State -ne 'Enabled') { throw "Hyper-V not enabled" }
    Log "=== IR-Collect E2E run $RunId ===" 'OK'
    Remove-PriorVM
    Expand-Guest
    New-GuestVM
    Wait-GuestReady
    Copy-KitToGuest
    foreach ($s in $Scenarios) { try { $results += Invoke-Scenario -Sid $s } catch { Log "Scenario $s FAULT: $($_.Exception.Message)" 'ERR'; $results += [pscustomobject]@{ scenario=$s; pass=$false; verdict='FAULT'; error="$($_.Exception.Message)" } } }
}
catch { Log "FATAL: $($_.Exception.Message)" 'ERR' }
finally {
    $passN = @($results | Where-Object pass).Count; $totN = $results.Count
    $summary = [ordered]@{
        run_id=$RunId; started_utc=$script:StartUtc.ToString('o'); ended_utc=(Get-Date).ToUniversalTime().ToString('o')
        host=$env:COMPUTERNAME; vm=$VMName; scenarios_total=$totN; scenarios_passed=$passN
        results=$results
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $RunDir 'results.json') -Encoding UTF8
    $md = @("# IR-Collect E2E Report - $RunId","","- Host: $env:COMPUTERNAME  VM: $VMName","- Scenarios: **$passN / $totN passed**","","| Scenario | Pass | Verdict | Guest exit | ATT&CK |","|---|---|---|---|---|")
    foreach ($r in $results) { $md += ("| {0} | {1} | {2} | {3} | {4} |" -f $r.scenario, $(if($r.pass){'PASS'}else{'FAIL'}), $r.verdict, $r.guest_exit, (@($r.attack) -join ' ')) }
    ($md -join "`n") | Set-Content (Join-Path $RunDir 'REPORT.md') -Encoding UTF8
    Log "RESULT: $passN/$totN scenarios passed. Report: $(Join-Path $RunDir 'REPORT.md')" $(if($passN -eq $totN -and $totN -gt 0){'OK'}else{'ERR'})
    if (-not $KeepVM) { Log "Teardown VM $VMName"; Remove-PriorVM; Remove-Item $VhdWork -Force -EA SilentlyContinue } else { Log "-KeepVM: leaving $VMName" 'WARN' }
    Write-Host ""; Write-Host "E2E_RESULT=$passN/$totN" -ForegroundColor $(if($passN -eq $totN -and $totN -gt 0){'Green'}else{'Red'})
}
