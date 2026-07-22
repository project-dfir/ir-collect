<#
.SYNOPSIS
    IR-Collect - Self-healing incident-response collector for Windows (two-stage: rapid volatile + menu).

.DESCRIPTION
    STAGE 1 (automatic, no prompts): a fast "hasty grab" of all super-important VOLATILE data in
    RFC 3227 order of volatility - processes, network state, sessions, loaded modules, caches.
    This runs first and completes in seconds/minutes so the perishable evidence is secured.

    STAGE 2 (interactive menu): once volatile capture is confirmed, an operator menu offers the
    long-running collections (full RAM image, artifact triage, event-log export, full file hashing,
    Active Directory enumeration, full disk image, browser artifacts). Each is opt-in.

    Uses professional off-OS tools when present (WinPmem, DumpIt, Sysinternals, KAPE, SharpHound,
    FTK Imager) and falls back to native commands otherwise. Drop those .exe files in a 'tools'
    subfolder next to this script, or have them on PATH, and they are auto-detected.

    SELF-HEALING: every action runs in an isolated job with a per-step timeout + retry; any failure,
    hang, or missing tool is logged and skipped - the run never aborts.

.PARAMETER OutputRoot   Case folder location (point at an external drive). Default: script dir.
.PARAMETER CaseId       Case identifier. Default: IR.
.PARAMETER StepTimeoutSec  Default per-step timeout. Default: 120.
.PARAMETER Auto         Run Stage 1 then ALL Stage-2 jobs, no menu (unattended full collection).
.PARAMETER RapidOnly    Run only Stage 1 (volatile) and seal.
.PARAMETER SkipAD       Never run the AD phase.

.EXAMPLE  powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -OutputRoot E:\evidence -CaseId CASE001
.EXAMPLE  powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -Auto   # full unattended

.NOTES  Run elevated. Read-only w.r.t. the evidence disk (writes only to OutputRoot).
#>

[CmdletBinding()]
param(
    [Alias('OutputRoot')]
    [string]$Dest       = $PSScriptRoot,   # external drive path, UNC \\IP\share, or bare IP
    [string]$Share      = 'evidence',      # SMB share name to use when -Dest is a bare IP
    [pscredential]$Cred,                   # optional creds for the network share
    [string]$CaseId     = 'IR',
    [int]   $StepTimeoutSec = 120,
    [switch]$Auto,
    [switch]$RapidOnly,
    [switch]$SkipAD,
    [switch]$DeferMemory,  # capture RAM AFTER the volatile-command battery instead of before it
    [string]$Authorizer = '',   # who authorized this collection (chain of custody)
    [string]$LegalBasis = '',   # authority/legal basis (IR engagement, warrant, consent...)
    [string]$ScopeNote  = ''    # authorized scope of collection
)

$ErrorActionPreference = 'Continue'   # self-heal: never let a single error stop the pipeline
$ProgressPreference    = 'SilentlyContinue'  # speed + keep progress spinners out of captured output
Set-StrictMode -Off
try { [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture } catch {}  # deterministic CSV/number/date

# --- 32-bit-on-64-bit relaunch: a 32-bit pwsh sees SysWOW64/WOW6432Node, silently
#     collecting the WRONG System32/registry. Relaunch the 64-bit host via Sysnative.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $sysnative = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $sysnative) {
        Write-Host "Relaunching under 64-bit PowerShell (avoids WOW64 redirection)..." -ForegroundColor Yellow
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
function Now-Utc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

if ([string]::IsNullOrWhiteSpace($Dest)) { $Dest = (Get-Location).Path }
$hostName = $env:COMPUTERNAME
$stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
$ToolDir  = Join-Path $PSScriptRoot 'tools'

# --- Resolve destination: local drive / UNC share / bare IP -----------------
# Network destinations are slow+fragile to write to live, so we STAGE locally
# (next to the script / thumb drive) then ZIP + ship at seal time.
function Test-IsIP { param([string]$s) $s -match '^(\d{1,3}\.){3}\d{1,3}$' }
$NetworkDest = $null
if (Test-IsIP $Dest)            { $NetworkDest = "\\$Dest\$Share" }
elseif ($Dest -like '\\*')      { $NetworkDest = $Dest }

if ($NetworkDest) {
    $OutputRoot = Join-Path $PSScriptRoot '_staging'   # collect locally first
    try { New-Item -ItemType Directory -Force $OutputRoot | Out-Null } catch { $OutputRoot = $env:TEMP }
} else {
    $OutputRoot = $Dest
}
$OutDir = Join-Path $OutputRoot ("{0}_{1}_{2}" -f $CaseId, $hostName, $stamp)

$Dirs = [ordered]@{
    root        = $OutDir
    metadata    = Join-Path $OutDir '00_metadata'
    volatile    = Join-Path $OutDir '01_volatile'
    network     = Join-Path $OutDir '02_network'
    memory      = Join-Path $OutDir '03_memory'
    persistence = Join-Path $OutDir '04_persistence'
    artifacts   = Join-Path $OutDir '05_artifacts'
    ad          = Join-Path $OutDir '06_activedirectory'
    disk        = Join-Path $OutDir '07_diskimage'
    logs        = Join-Path $OutDir '99_logs'
}
foreach ($d in $Dirs.Values) { try { New-Item -ItemType Directory -Force -Path $d | Out-Null } catch {} }

$AuditLog = Join-Path $Dirs.logs 'audit.log'
$ErrLog   = Join-Path $Dirs.logs 'errors.log'

function Write-Audit {
    param([string]$Message)
    $line = "{0} | {1} | {2}" -f (Now-Utc), $env:USERNAME, $Message
    try { Add-Content -Path $AuditLog -Value $line -Encoding UTF8 } catch {}
    Write-Host $line
}

# ---------------------------------------------------------------------------
# Tool discovery (professional off-OS tools; 'tools' subdir or PATH)
# ---------------------------------------------------------------------------
function Find-Tool {
    param([string[]]$Names)
    foreach ($n in $Names) {
        if (Test-Path $ToolDir) {
            $hit = Get-ChildItem -Path $ToolDir -Filter $n -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    return $null
}
# --- toolkit self-repair: fix common tool problems BEFORE we need them ---------
# (Mark-of-the-Web blocking execution, un-extracted archives). Runs at startup so
# the collector fixes its own kit rather than falling back to the untrusted host.
function Repair-Toolkit {
    if (-not (Test-Path $ToolDir)) {
        Write-Host "Toolkit: no .\tools folder. Build it first with fetch-tools.ps1 on a trusted box." -ForegroundColor Yellow
        Write-Host "         Enumeration will use kernel APIs (CIM/.NET/ADSI); RAM/triage/BloodHound need the carried tools." -ForegroundColor Yellow
        return
    }
    try { Get-ChildItem $ToolDir -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue } catch {}
    Get-ChildItem $ToolDir -Recurse -Filter *.zip -ErrorAction SilentlyContinue | ForEach-Object {
        $ex = Join-Path $_.DirectoryName $_.BaseName
        try { if (-not (Test-Path $ex)) { Expand-Archive $_.FullName $ex -Force; Write-Host "Toolkit: extracted $($_.Name)" } } catch {}
    }
}
Repair-Toolkit

$TOOL = @{
    winpmem   = Find-Tool @('*winpmem*.exe')
    velociraptor = Find-Tool @('*velociraptor*windows*.exe','velociraptor*.exe')
    dumpit    = Find-Tool @('DumpIt.exe')
    magnetram = Find-Tool @('MagnetRAMCapture.exe','MRCv120.exe')
    kape      = Find-Tool @('kape.exe')
    cylr      = Find-Tool @('CyLR.exe')
    autorunsc = Find-Tool @('autorunsc*.exe')
    handle    = Find-Tool @('handle*.exe')
    tcpvcon   = Find-Tool @('tcpvcon*.exe')
    listdlls  = Find-Tool @('Listdlls*.exe')
    sigcheck  = Find-Tool @('sigcheck*.exe')
    psloggedon= Find-Tool @('PsLoggedon*.exe')
    sharphound= Find-Tool @('SharpHound.exe','SharpHound.ps1')
    chainsaw  = Find-Tool @('chainsaw*.exe')
    ftkimager = Find-Tool @('ftkimager.exe')
}

# ---------------------------------------------------------------------------
# Invoke-Step : self-healing collection primitive (timeout + retry + log; never throws)
# ---------------------------------------------------------------------------
$script:StepNum = 0; $script:StepsOk = 0; $script:StepsFail = 0

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        [string]$OutFile,
        [string]$Dir = $Dirs.volatile,
        [int]$TimeoutSec = $StepTimeoutSec,
        [int]$Retries = 1
    )
    $script:StepNum++
    $id = '{0:000}' -f $script:StepNum
    $target = if ($OutFile) { Join-Path $Dir $OutFile } else { $null }
    $attempt = 0; $start = Get-Date
    while ($attempt -le $Retries) {
        $attempt++; $job = $null
        try {
            $job = Start-Job -ScriptBlock $Script
            if (Wait-Job $job -Timeout $TimeoutSec) {
                $out = Receive-Job $job -ErrorAction SilentlyContinue 2>&1
                Remove-Job $job -Force -ErrorAction SilentlyContinue
                if ($target -and $null -ne $out) { try { $out | Out-File -FilePath $target -Encoding UTF8 -Width 4096 } catch {} }
                $dur = [int]((Get-Date) - $start).TotalSeconds
                $lines = if ($out) { @($out).Count } else { 0 }
                Write-Audit ("STEP $id OK   | $Name | ${dur}s | try $attempt | lines=$lines" + $(if($target){" -> $(Split-Path $target -Leaf)"}))
                $script:StepsOk++; return $out
            } else {
                Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
                Write-Audit "STEP $id WARN | $Name | TIMEOUT ${TimeoutSec}s | try $attempt"
                if ($attempt -gt $Retries) { Add-Content $ErrLog "$(Now-Utc) [$id] $Name : timeout ${TimeoutSec}s"; $script:StepsFail++; return $null }
            }
        } catch {
            if ($job) { try { Remove-Job $job -Force -ErrorAction SilentlyContinue } catch {} }
            Write-Audit "STEP $id ERR  | $Name | $($_.Exception.Message) | try $attempt"
            if ($attempt -gt $Retries) { Add-Content $ErrLog "$(Now-Utc) [$id] $Name : $($_.Exception|Out-String)"; $script:StepsFail++; return $null }
            Start-Sleep -Milliseconds 400
        }
    }
    return $null
}
function Collect { param([string]$Name,[scriptblock]$Script,[string]$File,[string]$Dir=$Dirs.volatile,[int]$Timeout=$StepTimeoutSec,[int]$Retries=1)
    Invoke-Step -Name $Name -Script $Script -OutFile $File -Dir $Dir -TimeoutSec $Timeout -Retries $Retries | Out-Null
}

# free-space preflight (bytes) for large evidence files - refuse rather than fill the drive
function Get-FreeBytes { param([string]$Path)
    try { $root=[System.IO.Path]::GetPathRoot((Resolve-Path $Path).Path); return (Get-PSDrive ($root.TrimEnd(':\')) -ErrorAction Stop).Free } catch { return -1 }
}
function Test-Space { param([string]$Path,[double]$NeedBytes,[string]$What)
    $free = Get-FreeBytes $Path
    if ($free -lt 0) { Write-Audit "PREFLIGHT $What : could not determine free space - proceeding cautiously."; return $true }
    if ($free -lt $NeedBytes) {
        Write-Audit ("PREFLIGHT $What : ABORT step - need {0:N1} GB, have {1:N1} GB free on destination." -f ($NeedBytes/1GB),($free/1GB)); return $false }
    Write-Audit ("PREFLIGHT $What : OK - {0:N1} GB free (need ~{1:N1} GB)." -f ($free/1GB),($NeedBytes/1GB)); return $true
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
$domainJoined = $false
try { $domainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch {}

Write-Audit "===== IR-Collect START ====="
Write-Audit "Case=$CaseId Host=$hostName Output=$OutDir Elevated=$isAdmin DomainJoined=$domainJoined PS=$($PSVersionTable.PSVersion)"
if ($NetworkDest) { Write-Audit "Destination is NETWORK: staging locally, shipping to $NetworkDest at seal." } else { Write-Audit "Destination is local/drive: $Dest" }
$detected = ($TOOL.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key }) -join ', '
Write-Audit "Pro tools detected: $(if($detected){$detected}else{'(none - native fallbacks only)'})"
if (-not $isAdmin) { Write-Audit "WARNING: not elevated - some data (process owners, RAM, hives, netstat -b) will be incomplete." }

# DOCTRINE: host is assumed compromised. Prefer carried tools; use kernel-level
# APIs (CIM/.NET/ADSI) over host userland exes; record hashes of any carried tool.
if (Test-Path $ToolDir) {
    Write-Audit "DOCTRINE: carried tools present in .\tools - preferred over host binaries."
    try {
        Get-ChildItem $ToolDir -Recurse -File -Include *.exe,*.ps1 -ErrorAction SilentlyContinue |
          ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.FullName } |
          Out-File (Join-Path $Dirs.metadata 'carried_tools_sha256.txt') -Encoding ASCII
    } catch {}
} else {
    Write-Audit "DOCTRINE NOTE: no .\tools dir - relying on host binaries (may be tampered on a compromised host). Core collection uses CIM/.NET/ADSI (kernel-level) to reduce reliance on host userland exes."
}

# precompute custody fields (try/catch is a statement, not valid inside a hashtable literal)
$fqdn = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $hostName }
$startUtc = Now-Utc
$osCaption = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { '' }
$acqId = try { [guid]::NewGuid().ToString() } catch { "$hostName-$stamp" }
$info = [ordered]@{
    tool='IR-Collect.ps1'; version='2.0'; case=$CaseId; acquisitionId=$acqId; host=$hostName
    fqdn=$fqdn; domain=$env:USERDNSDOMAIN; domainJoined=$domainJoined; collector=$env:USERNAME; elevated=$isAdmin
    startUtc=$startUtc; os=$osCaption; psVersion="$($PSVersionTable.PSVersion)"
    languageMode="$($ExecutionContext.SessionState.LanguageMode)"; is64="$([Environment]::Is64BitProcess)"; toolsDetected=$detected
    authorizer=$Authorizer; legalBasis=$LegalBasis; scope=$ScopeNote
}
if (-not $Authorizer) { Write-Audit "CUSTODY WARNING: no -Authorizer recorded. Pass -Authorizer/-LegalBasis/-ScopeNote for a defensible chain of custody." }
try { $info | ConvertTo-Json | Out-File (Join-Path $Dirs.metadata 'collection_info.json') -Encoding UTF8 } catch {}

# --- destination preflight: write-test + FAT32 4GB cap -----------------------
try {
    $tf = Join-Path $OutputRoot ('.irwrite_' + $stamp); Set-Content $tf 'x' -ErrorAction Stop; Remove-Item $tf -Force -ErrorAction SilentlyContinue
} catch { Write-Audit "PREFLIGHT: destination $OutputRoot NOT writable - $($_.Exception.Message)" }
try {
    $destRoot = [System.IO.Path]::GetPathRoot((Resolve-Path $OutputRoot).Path)
    $vol = Get-Volume -FilePath $OutputRoot -ErrorAction SilentlyContinue
    if ($vol -and $vol.FileSystem -match 'FAT') {
        Write-Audit "PREFLIGHT WARNING: destination is $($vol.FileSystem) - FAT32 caps files at 4GB; a RAM image will TRUNCATE. Reformat destination NTFS/exFAT."
    } elseif ($vol) { Write-Audit "PREFLIGHT: destination filesystem = $($vol.FileSystem)" }
} catch {}
Write-Audit "PREFLIGHT: privilege=$(if($isAdmin){'full'}else{'PARTIAL - not elevated'}) langMode=$($ExecutionContext.SessionState.LanguageMode) 64bit=$([Environment]::Is64BitProcess)"
Write-Audit "FOOTPRINT: tools run from '$PSScriptRoot' (NOT installed on target); evidence written only to destination; live-collection footprint is documented in this log. For non-volatile ground truth follow with a dead-box disk image."

# ===========================================================================
# STAGE 1 - RAPID VOLATILE GRAB (automatic, order of volatility)
# ===========================================================================
function Invoke-RapidVolatile {
    Write-Host ""; Write-Host "================ STAGE 1: RAPID VOLATILE GRAB ================" -ForegroundColor Cyan
    Write-Audit "===== STAGE 1: rapid volatile grab ====="
    $M=$Dirs.metadata; $V=$Dirs.volatile; $N=$Dirs.network

    # --- host identity (fast) ---
    Collect 'systeminfo'     { systeminfo } 'systeminfo.txt' $M
    Collect 'os-cim'         { Get-CimInstance Win32_OperatingSystem | Format-List *; Get-CimInstance Win32_ComputerSystem | Format-List * } 'os_computer.txt' $M
    Collect 'timezone'       { Get-TimeZone | Format-List *; 'UTC now: '+(Now-Utc); 'Local now: '+(Get-Date).ToString('o') } 'timezone.txt' $M
    Collect 'boot-uptime'    { $os=Get-CimInstance Win32_OperatingSystem; 'LastBoot: '+$os.LastBootUpTime; 'Install: '+$os.InstallDate } 'boot.txt' $M
    Collect 'env'            { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize } 'environment.txt' $M
    # CRITICAL while live: BitLocker status + recovery keys. If the disk is encrypted and you go
    # dead-box without these, the image is unreadable. Capture protectors/keys NOW.
    Collect 'bitlocker'      { Get-BitLockerVolume 2>$null | Format-List MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,KeyProtector; '=== Recovery key protectors (manage-bde) ==='; foreach($d in (Get-Volume | Where-Object DriveLetter).DriveLetter){ "--- $d`: ---"; manage-bde -protectors -get "$($d):" 2>$null } } 'bitlocker_keys.txt' $M
    # host clock vs collection clock (timeline provenance / skew)
    Collect 'clock-skew'     { 'Host local time : '+(Get-Date).ToString('o'); 'Host UTC time   : '+(Now-Utc); 'NOTE: compare against a trusted external time source and record offset for timeline defensibility.' } 'clock_provenance.txt' $M

    # --- RAM IMAGE FIRST (RFC 3227: memory is the most volatile capturable artifact) ---
    # Every command below perturbs RAM, so image it before the volatile-command battery.
    if (-not $DeferMemory) {
        Write-Host "Capturing physical memory first (order of volatility)..." -ForegroundColor Cyan
        Job-Memory
    } else { Write-Audit "DeferMemory set - RAM will be captured after volatile commands." }

    # --- processes (most volatile after memory) ---
    Collect 'processes'      { Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | Sort-Object ProcessId | Format-Table -AutoSize -Wrap } 'processes.txt' $V
    Collect 'processes-csv'  { Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation } 'processes.csv' $V
    Collect 'process-owners' { Get-CimInstance Win32_Process | ForEach-Object { $o=try{(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}catch{'?'}; "$($_.ProcessId)`t$($_.Name)`t$o" } } 'process_owners.txt' $V -Timeout 120
    Collect 'tasklist-svc'   { tasklist /svc } 'tasklist_services.txt' $V
    Collect 'drivers'        { Get-CimInstance Win32_SystemDriver | Select-Object Name,State,StartMode,PathName | Sort-Object Name | Format-Table -AutoSize } 'drivers.txt' $V
    if ($TOOL.handle)   { Collect 'sys-handle'  ([scriptblock]::Create("& '$($TOOL.handle)' -accepteula -a -nobanner")) 'handles.txt' $V -Timeout 120 }
    if ($TOOL.listdlls) { Collect 'sys-listdlls' ([scriptblock]::Create("& '$($TOOL.listdlls)' -accepteula")) 'listdlls.txt' $V -Timeout 120 }

    # --- sessions / logged-on ---
    Collect 'whoami-all'     { whoami /all } 'whoami_all.txt' $V
    Collect 'sessions'       { query user; '---'; query session; '---'; net session } 'sessions.txt' $V
    Collect 'klist'          { klist; '=== TGT ==='; klist tgt } 'kerberos_tickets.txt' $V
    Collect 'local-users'    { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=true" | Format-Table Name,SID,Disabled,Lockout -AutoSize } 'local_users.txt' $V
    Collect 'local-admins'   { net localgroup Administrators } 'local_admins.txt' $V
    Collect 'clipboard'      { Get-Clipboard -Raw 2>$null } 'clipboard.txt' $V
    if ($TOOL.psloggedon) { Collect 'sys-psloggedon' ([scriptblock]::Create("& '$($TOOL.psloggedon)' -accepteula")) 'psloggedon.txt' $V }

    # --- network state (routing/arp/dns before disk) ---
    Collect 'netstat'        { netstat -anob } 'netstat_anob.txt' $N
    Collect 'tcp-conns'      { Get-NetTCPConnection 2>$null | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object State,LocalPort | Format-Table -AutoSize } 'tcp_connections.txt' $N
    Collect 'udp-endpoints'  { Get-NetUDPEndpoint 2>$null | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize } 'udp_endpoints.txt' $N
    if ($TOOL.tcpvcon) { Collect 'sys-tcpvcon' ([scriptblock]::Create("& '$($TOOL.tcpvcon)' -accepteula -a")) 'tcpvcon.txt' $N }
    Collect 'ipconfig'       { ipconfig /all } 'ipconfig_all.txt' $N
    Collect 'arp'            { arp -a } 'arp_cache.txt' $N
    Collect 'route'          { route print } 'routing_table.txt' $N
    Collect 'dns-cache'      { ipconfig /displaydns } 'dns_cache.txt' $N
    Collect 'hosts-file'     { Get-Content "$env:WINDIR\System32\drivers\etc\hosts" } 'hosts_file.txt' $N
    Collect 'shares'         { net share; Get-SmbShare 2>$null | Format-Table -AutoSize } 'shares.txt' $N
    Collect 'smb-sessions'   { Get-SmbSession 2>$null | Format-Table -AutoSize; net use } 'smb_sessions.txt' $N
    Collect 'firewall'       { netsh advfirewall show allprofiles } 'firewall_profiles.txt' $N

    if ($DeferMemory) { Write-Host "Capturing physical memory (deferred)..." -ForegroundColor Cyan; Job-Memory }

    Write-Host "STAGE 1 complete: volatile state secured ($script:StepsOk ok / $script:StepsFail failed so far)." -ForegroundColor Green
    Write-Audit "===== STAGE 1 complete: OK=$script:StepsOk FAIL=$script:StepsFail ====="
}

# ===========================================================================
# STAGE 2 - HEAVY / LONG-RUNNING COLLECTIONS (menu-selectable)
# ===========================================================================
$script:Done = @{}
$script:MemOk = $false; $script:MemBytes = 0

function Job-Memory {
    if ($script:Done['memory']) { Write-Audit "RAM already captured - skipping."; return }
    Write-Audit "--- RAM image (volatile #1) ---"; $D=$Dirs.memory
    # free-space preflight: need ~ physical RAM * 1.1
    $ram = try { (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory } catch { 8GB }
    if (-not (Test-Space $D ($ram*1.1) 'RAM-image')) { Collect 'mem-skip-space' { 'RAM image skipped: insufficient destination free space.' } 'RAM_SKIPPED_NO_SPACE.txt' $D; $script:Done['memory']=$true; return }
    $img = Join-Path $D 'memory.raw'
    if     ($TOOL.winpmem) { $wp=$TOOL.winpmem; Invoke-Step 'mem-winpmem' ([scriptblock]::Create("& '$wp' acquire '$img' 2>&1; if(-not (Test-Path '$img')){ & '$wp' '$img' 2>&1 }")) $null $D -TimeoutSec 3600 -Retries 0 | Out-Null }
    elseif ($TOOL.dumpit)  { Invoke-Step 'mem-dumpit'  ([scriptblock]::Create("& '$($TOOL.dumpit)' /OUTPUT '$($D)\memory.dmp' /QUIET")) $null $D -TimeoutSec 3600 -Retries 0 | Out-Null }
    elseif ($TOOL.magnetram){Invoke-Step 'mem-magnet'  ([scriptblock]::Create("& '$($TOOL.magnetram)' /accepteula /go '$D'")) $null $D -TimeoutSec 3600 -Retries 0 | Out-Null }
    else { Write-Audit "RAM: no memory tool found (place winpmem.exe/DumpIt.exe in .\tools). Capturing pagefile-config + hiberfil note only."
           Collect 'mem-fallback' { 'No native full-RAM capture. Recommended: WinPmem or DumpIt.'; Get-CimInstance Win32_PageFileUsage | Format-List * } 'RAM_NOT_CAPTURED.txt' $D }
    # verify a REAL image was produced. Classic silent failure: driver blocked by Secure Boot/HVCI/EDR
    # writes a tiny error file, mem-hash dutifully hashes it, and the collection seals GREEN with no RAM.
    $script:MemBytes = 0
    try { $script:MemBytes = [int64]((Get-ChildItem $D -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.raw','.dmp','.aff4','.lime','.mem' } | Measure-Object Length -Sum).Sum) } catch {}
    $need = try { [int64]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory * 0.4) } catch { 500MB }
    if ($script:MemBytes -ge $need) {
        $script:MemOk = $true
        Write-Audit ("RAM VERIFIED: {0:N1} GB image written (>= 40% of physical RAM)." -f ($script:MemBytes/1GB))
        # post-acquisition verify: re-read + hash (SHA-256 + MD5) so a truncated image can't seal silently
        Invoke-Step 'mem-hash-verify' ([scriptblock]::Create("Get-ChildItem '$D' -File | Where-Object { `$_.Length -gt 1MB } | ForEach-Object { 'SHA256 ' + (Get-FileHash `$_.FullName -Algorithm SHA256).Hash + '  ' + `$_.Name; 'MD5    ' + (Get-FileHash `$_.FullName -Algorithm MD5).Hash + '  ' + `$_.Name }")) 'memory_hashes.txt' $D -TimeoutSec 1800 | Out-Null
    } else {
        $script:MemOk = $false
        Write-Audit ("RAM WARNING: only {0:N1} MB produced - capture likely FAILED (Secure Boot/HVCI/EDR blocked the driver, or no imager). *** Do NOT power off an encrypted host without a recovery key - the FVEK is only in RAM. ***" -f ($script:MemBytes/1MB))
        Collect 'mem-fail-warning' { 'RAM CAPTURE FAILED OR INCOMPLETE. Causes: Secure Boot / HVCI / VBS blocking the kernel driver, EDR quarantine, or no imager present. If the disk is encrypted, DO NOT power off without a recovery key.' } 'RAM_CAPTURE_FAILED.txt' $D
    }
    $script:Done['memory']=$true
}

function Job-Artifacts {
    Write-Audit "--- HEAVY: artifact triage (registry/evtx/prefetch/MFT) ---"; $A=$Dirs.artifacts
    if ($TOOL.velociraptor) {
        # open-source triage: Velociraptor's KapeFiles.Targets (reimplements KAPE !SANS_Triage in VQL)
        Invoke-Step 'velo-triage' ([scriptblock]::Create("& '$($TOOL.velociraptor)' artifacts collect Windows.KapeFiles.Targets --args Device=C: --output '$A\velociraptor_triage.zip' 2>&1")) $null $A -TimeoutSec 3600 -Retries 0 | Out-Null
    } elseif ($TOOL.cylr) {
        Invoke-Step 'cylr-triage' ([scriptblock]::Create("& '$($TOOL.cylr)' -od '$A' -of cylr.zip")) $null $A -TimeoutSec 3600 -Retries 0 | Out-Null
    } elseif ($TOOL.kape) {
        Invoke-Step 'kape-triage' ([scriptblock]::Create("& '$($TOOL.kape)' --tsource C: --target !SANS_Triage --tdest '$A\kape' --tflush")) $null $A -TimeoutSec 3600 -Retries 0 | Out-Null
    } else {
        # native fallback: reg save hives + robocopy of key artifacts
        $hiveDir=Join-Path $A 'registry'; try{New-Item -ItemType Directory -Force $hiveDir|Out-Null}catch{}
        foreach ($h in @(@{n='SYSTEM';p='HKLM\SYSTEM'},@{n='SOFTWARE';p='HKLM\SOFTWARE'},@{n='SAM';p='HKLM\SAM'},@{n='SECURITY';p='HKLM\SECURITY'})) {
            Invoke-Step "reg-$($h.n)" ([scriptblock]::Create("reg save $($h.p) '$hiveDir\$($h.n).hiv' /y")) $null $hiveDir -TimeoutSec 180 | Out-Null
        }
        Invoke-Step 'copy-evtx'     ([scriptblock]::Create("robocopy '$env:WINDIR\System32\winevt\Logs' '$A\evtx' *.evtx /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 900 -Retries 0 | Out-Null
        Invoke-Step 'copy-prefetch' ([scriptblock]::Create("robocopy '$env:WINDIR\Prefetch' '$A\prefetch' *.pf /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 600 -Retries 0 | Out-Null
        Collect 'amcache-copy' { Copy-Item "$env:WINDIR\AppCompat\Programs\Amcache.hve" "$A\Amcache.hve" -Force 2>$null; 'copied if present' } 'amcache_note.txt' $A
        # per-user hives (UserAssist/ShellBags/RunMRU/TypedPaths...) + PowerShell history + USB history
        Invoke-Step 'copy-userhives' ([scriptblock]::Create("robocopy 'C:\Users' '$A\userhives' NTUSER.DAT UsrClass.dat /S /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 600 -Retries 0 | Out-Null
        Invoke-Step 'copy-pshistory' ([scriptblock]::Create("robocopy 'C:\Users' '$A\ps_history' ConsoleHost_history.txt /S /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 300 -Retries 0 | Out-Null
        Collect 'usb-history' { Copy-Item "$env:WINDIR\INF\setupapi.dev.log" "$A\setupapi.dev.log" -Force 2>$null; '=== USBSTOR (also in SYSTEM hive) ==='; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' 2>$null | Select-Object FriendlyName,PSChildName | Format-Table -AutoSize } 'usb_devices.txt' $A
        Collect 'ps-transcript-note' { 'Note: full NTFS metadata ($MFT/$UsnJrnl/$LogFile), SRUM, and locked per-user hives are best captured by the Velociraptor/CyLR triage path (uses VSS/raw). This native fallback is best-effort.' } '_TRIAGE_LIMITATIONS.txt' $A
    }
    $script:Done['artifacts']=$true
}

function Job-EventLogs {
    Write-Audit "--- HEAVY: full event-log export ---"; $A=$Dirs.artifacts
    Collect 'evtx-inventory' { Get-WinEvent -ListLog * 2>$null | Where-Object RecordCount -gt 0 | Select-Object LogName,RecordCount,FileSize,LastWriteTime | Sort-Object RecordCount -Descending | Format-Table -AutoSize } 'event_logs_inventory.txt' $A -Timeout 180
    Invoke-Step 'evtx-copy' ([scriptblock]::Create("robocopy '$env:WINDIR\System32\winevt\Logs' '$A\evtx' *.evtx /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 1200 -Retries 0 | Out-Null
    $script:Done['eventlogs']=$true
}

function Job-Persistence {
    Write-Audit "--- HEAVY: persistence & autoruns ---"; $P=$Dirs.persistence
    Collect 'services'        { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Sort-Object Name | ConvertTo-Csv -NoTypeInformation } 'services.csv' $P
    Collect 'scheduled-tasks' { Get-ScheduledTask 2>$null | ForEach-Object { $t=$_; $a=($t.Actions|ForEach-Object{$_.Execute+' '+$_.Arguments}) -join ' | '; [pscustomobject]@{Path=$t.TaskPath;Name=$t.TaskName;State=$t.State;Action=$a} } | ConvertTo-Csv -NoTypeInformation } 'scheduled_tasks.csv' $P -Timeout 180
    Collect 'installed-sw'    { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object DisplayName | Sort-Object DisplayName | Format-Table -AutoSize } 'installed_software.txt' $P
    Collect 'wmi-persistence' { Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding 2>$null | Format-List *; Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer 2>$null | Format-List * } 'wmi_persistence.txt' $P
    Collect 'defender'        { Get-MpComputerStatus 2>$null | Format-List *; Get-MpThreatDetection 2>$null | Format-List * } 'defender_status.txt' $P
    if ($TOOL.autorunsc) {
        Invoke-Step 'sys-autoruns' ([scriptblock]::Create("& '$($TOOL.autorunsc)' -accepteula -a * -c -h -s -nobanner")) 'autoruns.csv' $P -TimeoutSec 600 -Retries 0 | Out-Null
    } else {
        Collect 'run-keys' {
            $keys=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run')
            foreach($k in $keys){ "== $k =="; try{(Get-ItemProperty $k -ErrorAction Stop).PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{'  '+$_.Name+' = '+$_.Value}}catch{'  (none)'} }
        } 'run_keys.txt' $P
    }
    $script:Done['persistence']=$true
}

function Job-FileHashes {
    Write-Audit "--- HEAVY: full filesystem hash inventory ---"; $A=$Dirs.artifacts
    foreach ($drv in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3').DeviceID) {
        Invoke-Step "hash-$drv" ([scriptblock]::Create(@"
Get-ChildItem '$drv\' -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
  try { `$h=(Get-FileHash `$_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { `$h='ERR' }
  '{0},{1},{2},{3}' -f `$h, `$_.Length, `$_.LastWriteTimeUtc.ToString('o'), `$_.FullName }
"@)) "filehashes_$($drv.TrimEnd(':')).csv" $A -TimeoutSec 7200 -Retries 0 | Out-Null
    }
    $script:Done['filehashes']=$true
}

function Job-Browser {
    Write-Audit "--- HEAVY: browser artifacts ---"; $A=$Dirs.artifacts; $b=Join-Path $A 'browser'; try{New-Item -ItemType Directory -Force $b|Out-Null}catch{}
    $srcs=@("$env:LOCALAPPDATA\Google\Chrome\User Data\Default","$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default")
    foreach($s in $srcs){ if(Test-Path $s){ $name=Split-Path (Split-Path $s -Parent) -Leaf
        foreach($f in 'History','Cookies','Login Data','Web Data','Bookmarks'){ Invoke-Step "browser-$name-$f" ([scriptblock]::Create("Copy-Item '$s\$f' '$b\${name}_$f' -Force 2>`$null; 'ok'")) $null $b -TimeoutSec 120 | Out-Null } } }
    Invoke-Step 'browser-firefox' ([scriptblock]::Create("robocopy '$env:APPDATA\Mozilla\Firefox\Profiles' '$b\firefox' places.sqlite cookies.sqlite /S /R:1 /W:1 /NFL /NDL /NP")) $null $b -TimeoutSec 300 -Retries 0 | Out-Null
    $script:Done['browser']=$true
}

function Job-AD {
    if ($SkipAD) { Write-Audit "AD skipped (-SkipAD)"; return }
    if (-not $domainJoined) { Write-Audit "AD skipped (not domain-joined)"; return }
    Write-Audit "--- HEAVY: Active Directory enumeration ---"; $AD=$Dirs.ad

    Collect 'ad-net-accounts' { net accounts /domain } 'domain_password_policy.txt' $AD
    Collect 'ad-net-da'  { net group "Domain Admins" /domain } 'domain_admins.txt' $AD
    Collect 'ad-net-ea'  { net group "Enterprise Admins" /domain } 'enterprise_admins.txt' $AD
    Collect 'ad-nltest'  { nltest /dclist:$env:USERDNSDOMAIN; '---TRUSTS---'; nltest /domain_trusts /all_trusts /v } 'dc_and_trusts.txt' $AD
    Collect 'ad-gpresult'{ gpresult /z } 'gpresult.txt' $AD -Timeout 180
    Collect 'ad-domain'  { ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())|Format-List *; ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest())|Format-List * } 'domain_forest_info.txt' $AD

    $adsiFn = @'
function Search-AD { param([string]$Filter,[string[]]$Props=@('*'))
  $root=([ADSI]"LDAP://RootDSE").defaultNamingContext
  $s=[adsisearcher]::new(); $s.SearchRoot=[ADSI]"LDAP://$root"; $s.Filter=$Filter; $s.PageSize=1000
  if($Props -ne '*'){ $Props|ForEach-Object{ [void]$s.PropertiesToLoad.Add($_) } }
  $s.FindAll() }
function Dump-AD { param([string]$Filter,[string[]]$Props)
  Search-AD $Filter $Props | ForEach-Object { $p=$_.Properties; $o=[ordered]@{}
    foreach($k in $Props){ $o[$k]=($p[$k.ToLower()] -join ';') }; [pscustomobject]$o } }
'@
    $adSteps=@(
      @{n='ad-users';f='(&(objectCategory=person)(objectClass=user))';p=@('sAMAccountName','userAccountControl','lastLogonTimestamp','pwdLastSet','adminCount','servicePrincipalName','description');file='users.csv'}
      @{n='ad-groups';f='(objectCategory=group)';p=@('sAMAccountName','groupType','description');file='groups.csv'}
      @{n='ad-computers';f='(objectCategory=computer)';p=@('dNSHostName','operatingSystem','operatingSystemVersion','lastLogonTimestamp','userAccountControl');file='computers.csv'}
      @{n='ad-spn';f='(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))';p=@('sAMAccountName','servicePrincipalName','adminCount');file='kerberoastable_spn.csv'}
      @{n='ad-asrep';f='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))';p=@('sAMAccountName');file='asrep_roastable.csv'}
      @{n='ad-uncons';f='(userAccountControl:1.2.840.113556.1.4.803:=524288)';p=@('sAMAccountName','dNSHostName');file='delegation_unconstrained.csv'}
      @{n='ad-cons';f='(msDS-AllowedToDelegateTo=*)';p=@('sAMAccountName','msDS-AllowedToDelegateTo');file='delegation_constrained.csv'}
      @{n='ad-rbcd';f='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)';p=@('sAMAccountName','dNSHostName');file='delegation_rbcd.csv'}
      @{n='ad-admincount';f='(adminCount=1)';p=@('sAMAccountName','objectClass');file='admincount1.csv'}
      @{n='ad-trusts-ldap';f='(objectClass=trustedDomain)';p=@('trustPartner','trustDirection','trustType','trustAttributes');file='trusts_ldap.csv'}
      @{n='ad-laps';f='(ms-Mcs-AdmPwdExpirationTime=*)';p=@('dNSHostName','ms-Mcs-AdmPwdExpirationTime');file='laps_managed.csv'}
    )
    foreach($st in $adSteps){ $sb=[scriptblock]::Create($adsiFn+"`nDump-AD '$($st.f)' @('"+($st.p -join "','")+"') | ConvertTo-Csv -NoTypeInformation"); Invoke-Step $st.n $sb $st.file $AD -TimeoutSec 300 | Out-Null }

    foreach($grp in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','DnsAdmins')){
        $sb=[scriptblock]::Create($adsiFn+@"
`$g=(Search-AD "(&(objectCategory=group)(cn=$grp))" @('distinguishedName'))
if(`$g -and `$g.Count -gt 0){ `$dn=`$g[0].Properties.distinguishedname[0]
  Dump-AD "(memberOf:1.2.840.113556.1.4.1941:=`$dn)" @('sAMAccountName','objectClass','distinguishedName') | ConvertTo-Csv -NoTypeInformation
} else {'group not found: $grp'}
"@)
        $safe=($grp -replace '[^A-Za-z0-9]','_'); Invoke-Step "ad-priv-$safe" $sb "priv_$safe.csv" $AD -TimeoutSec 180 | Out-Null }

    $sbHost=[scriptblock]::Create($adsiFn+"`nDump-AD '(&(objectCategory=computer)(cn=$hostName))' @('dNSHostName','operatingSystem','userAccountControl','servicePrincipalName','msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity','lastLogonTimestamp','whenCreated') | Format-List *")
    Invoke-Step 'ad-this-host' $sbHost 'this_host_object.txt' $AD -TimeoutSec 120 | Out-Null

    if ($TOOL.sharphound) {
        Write-Audit "SharpHound present - collecting BloodHound attack-path data"
        $shDir=Join-Path $AD 'bloodhound'; try{New-Item -ItemType Directory -Force $shDir|Out-Null}catch{}
        if ($TOOL.sharphound -match '\.ps1$') { Invoke-Step 'ad-sharphound' ([scriptblock]::Create(". '$($TOOL.sharphound)'; Invoke-BloodHound -CollectionMethod All -OutputDirectory '$shDir' -ZipFileName bloodhound.zip")) $null $shDir -TimeoutSec 1800 -Retries 0 | Out-Null }
        else { Invoke-Step 'ad-sharphound' ([scriptblock]::Create("& '$($TOOL.sharphound)' -c All --outputdirectory '$shDir' --zipfilename bloodhound.zip")) $null $shDir -TimeoutSec 1800 -Retries 0 | Out-Null }
    }
    $script:Done['ad']=$true
}

function Job-DiskImage {
    Write-Audit "--- HEAVY: full disk image ---"; $D=$Dirs.disk
    if ($TOOL.ftkimager) {
        foreach($pd in (Get-CimInstance Win32_DiskDrive | Select-Object -ExpandProperty DeviceID)) {
            $n=($pd -replace '[\\\.]','_'); Invoke-Step "disk-$n" ([scriptblock]::Create("& '$($TOOL.ftkimager)' '$pd' '$D\$n' --e01 --frag 2G --verify")) $null $D -TimeoutSec 36000 -Retries 0 | Out-Null }
    } else {
        Write-Audit "Full disk image: no FTK Imager found. Place ftkimager.exe in .\tools (or use a hardware imager). Skipping."
        Collect 'disk-note' { 'Full disk imaging requires FTK Imager CLI (ftkimager.exe) or equivalent. Not run.' } 'DISK_NOT_IMAGED.txt' $D
    }
    $script:Done['diskimage']=$true
}

# ---------------------------------------------------------------------------
# STAGE 2 menu
# ---------------------------------------------------------------------------
$MenuItems = [ordered]@{
    '1' = @{ label='Full RAM image (WinPmem/DumpIt)         [~min, LARGE]'; key='memory';      fn={Job-Memory} }
    '2' = @{ label='Artifact triage (KAPE / hives+evtx+pf)  [~min]';        key='artifacts';   fn={Job-Artifacts} }
    '3' = @{ label='Full event-log export (.evtx copies)    [~min]';        key='eventlogs';   fn={Job-EventLogs} }
    '4' = @{ label='Persistence + autoruns (Sysinternals)   [fast]';        key='persistence'; fn={Job-Persistence} }
    '5' = @{ label='Active Directory enumeration (+BloodHound if present)';  key='ad';          fn={Job-AD} }
    '6' = @{ label='Browser artifacts (Chrome/Edge/Firefox) [~min]';        key='browser';     fn={Job-Browser} }
    '7' = @{ label='Full filesystem SHA-256 inventory       [SLOW, hours]'; key='filehashes';  fn={Job-FileHashes} }
    '8' = @{ label='Full disk image (FTK Imager)            [VERY SLOW]';   key='diskimage';   fn={Job-DiskImage} }
}
function Show-Menu {
    Write-Host ""; Write-Host "================ STAGE 2: HEAVY COLLECTION MENU ================" -ForegroundColor Cyan
    Write-Host "Volatile data already secured. Select long-running jobs to run now." -ForegroundColor Gray
    foreach ($k in $MenuItems.Keys) {
        $mk=$MenuItems[$k].key; $mark = if($script:Done[$mk]){'[x]'}else{'[ ]'}
        Write-Host ("  {0} {1} {2}" -f $k, $mark, $MenuItems[$k].label)
    }
    Write-Host "  A  Run ALL remaining"
    Write-Host "  Q  Finish & seal (manifest + report)"
    Write-Host ""
}
function Invoke-Menu {
    # self-heal: if input is redirected (no interactive console) run ALL rather than loop
    if ([Console]::IsInputRedirected) {
        Write-Audit "No interactive console - running ALL heavy jobs."
        foreach ($k in $MenuItems.Keys) { try { & $MenuItems[$k].fn } catch { Write-Audit "Job fault: $($_.Exception.Message)" } }
        return
    }
    while ($true) {
        Show-Menu
        $c = try { (Read-Host "Select (number / A / Q)").Trim().ToUpper() } catch { 'Q' }
        if ($c -eq 'Q') { break }
        elseif ($c -eq 'A') { foreach($k in $MenuItems.Keys){ if(-not $script:Done[$MenuItems[$k].key]){ try { & $MenuItems[$k].fn } catch { Write-Audit "Job fault: $($_.Exception.Message)" } } } }
        elseif ($MenuItems.Contains($c)) { try { & $MenuItems[$c].fn } catch { Write-Audit "Job fault: $($_.Exception.Message)" } }
        else { Write-Host "Invalid selection." -ForegroundColor Yellow }
    }
}

# ===========================================================================
# SEAL - manifest + report
# ===========================================================================
function Invoke-Seal {
    Write-Audit "--- SEAL: manifest + report ---"; $L=$Dirs.logs
    Invoke-Step 'manifest-sha256' ([scriptblock]::Create(@"
Get-ChildItem '$OutDir' -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { `$_.FullName -notmatch 'MANIFEST-SHA256|audit\.log' } |
  ForEach-Object { try { `$h=(Get-FileHash `$_.FullName -Algorithm SHA256).Hash } catch { `$h='ERR' }
    '{0},{1},{2}' -f `$h, `$_.Length, `$_.FullName.Replace('$($OutDir.Replace("\","\\"))','') }
"@)) 'MANIFEST-SHA256.csv' $L -TimeoutSec 1800 | Out-Null

    $endUtc=Now-Utc
    $doneList=($script:Done.GetEnumerator()|Where-Object{$_.Value}|ForEach-Object{$_.Key}) -join ', '
    $summary=@"
# IR-Collect Summary

- **Case:** $CaseId
- **Host:** $hostName ($($info.fqdn))   Domain-joined: $domainJoined
- **Collector:** $env:USERNAME   Elevated: $isAdmin
- **Start (UTC):** $($info.startUtc)     **End (UTC):** $endUtc
- **Steps OK:** $script:StepsOk   **Failed/timed-out:** $script:StepsFail   **Total:** $script:StepNum
- **Pro tools used:** $(if($info.toolsDetected){$info.toolsDetected}else{'native only'})
- **Heavy jobs run:** $(if($doneList){$doneList}else{'(rapid-volatile only)'})
- **Output:** $OutDir

Stage 1 (auto) secured volatile state in order of volatility. Stage 2 heavy jobs were operator-selected.
See 99_logs/audit.log for the full timestamped command trail; 99_logs/errors.log for any recovered failures.
"@
    try { $summary | Out-File (Join-Path $OutDir 'SUMMARY.md') -Encoding UTF8 } catch {}
    try { $info.endUtc=$endUtc; $info.stepsOk=$script:StepsOk; $info.stepsFail=$script:StepsFail; $info.stepsTotal=$script:StepNum; $info.heavyJobs=$doneList
          $info | ConvertTo-Json | Out-File (Join-Path $Dirs.metadata 'collection_info.json') -Encoding UTF8 } catch {}
    # --- ship to network destination if requested ---
    if ($NetworkDest) {
        Write-Audit "Shipping evidence to network destination $NetworkDest"
        $zip = "$OutDir.zip"
        Invoke-Step 'seal-zip' ([scriptblock]::Create("Compress-Archive -Path '$OutDir\*' -DestinationPath '$zip' -Force")) $null $Dirs.logs -TimeoutSec 3600 -Retries 0 | Out-Null
        try { (Get-FileHash $zip -Algorithm SHA256).Hash | Out-File "$zip.sha256" -Encoding ASCII } catch {}
        # map the share (with creds if provided), copy, unmap
        try {
            if ($Cred) { New-PSDrive -Name IRDEST -PSProvider FileSystem -Root $NetworkDest -Credential $Cred -ErrorAction Stop | Out-Null; $tgt='IRDEST:\' }
            else       { $tgt = $NetworkDest }
            Copy-Item "$zip","$zip.sha256" $tgt -Force -ErrorAction Stop
            Write-Audit "Ship OK -> $NetworkDest"
            Write-Host "Shipped $(Split-Path $zip -Leaf) to $NetworkDest" -ForegroundColor Green
        } catch {
            Write-Audit "Ship FAILED: $($_.Exception.Message). Evidence retained locally at $zip"
            Write-Host "Network ship failed - evidence kept locally: $zip" -ForegroundColor Yellow
        } finally { try { Remove-PSDrive IRDEST -ErrorAction SilentlyContinue } catch {} }
    }

    Write-Audit "===== IR-Collect DONE | OK=$script:StepsOk FAIL=$script:StepsFail TOTAL=$script:StepNum ====="
    Write-Host ""; Write-Host "Collection complete. Output: $OutDir" -ForegroundColor Green
    Write-Host "Summary: $(Join-Path $OutDir 'SUMMARY.md')  |  Audit: $AuditLog"
}

# ---------------------------------------------------------------------------
# VOLATILE GREEN gate - confirm perishable data captured before the slow phase
# ---------------------------------------------------------------------------
function Show-VolatileGate {
    $n = 0
    try { $n = (Get-ChildItem $Dirs.volatile,$Dirs.network -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}
    $memOk = [bool]$script:MemOk
    # is the disk encrypted but we have no verified RAM (where the key lives)?
    $encRisk = $false
    try { $encRisk = ([bool](Get-BitLockerVolume 2>$null | Where-Object { $_.ProtectionStatus -eq 'On' })) -and (-not $memOk) } catch {}
    $memNote = if ($memOk) { "RAM: VERIFIED ({0:N1} GB)" -f ($script:MemBytes/1GB) } else { 'RAM: NOT verified - capture failed/absent (see 03_memory)' }
    Write-Host ""
    if ($encRisk) {
        Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Host "  !!  VOLATILE: AMBER - ENCRYPTED DISK + NO VERIFIED RAM   !!" -ForegroundColor Red
        Write-Host "  !!  The BitLocker key lives in RAM you did NOT capture.  !!" -ForegroundColor Red
        Write-Host "  !!  Get a recovery key (00_metadata\bitlocker_keys.txt)  !!" -ForegroundColor Red
        Write-Host "  !!  BEFORE powering off, or the disk image is unreadable.!!" -ForegroundColor Red
        Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        Write-Audit "VOLATILE AMBER | encrypted disk + no verified RAM | files=$n"
    } elseif ($n -ge 10 -and $memOk) {
        Write-Host "  ############################################################" -ForegroundColor Green
        Write-Host "  #   VOLATILE CAPTURE: GREEN  ($n artifacts, OK=$script:StepsOk FAIL=$script:StepsFail)" -ForegroundColor Green
        Write-Host "  #   $memNote"                                                 -ForegroundColor Green
        Write-Host "  #   Perishable data secured in order of volatility."          -ForegroundColor Green
        Write-Host "  #   Safe to proceed to the SLOW non-volatile phase."          -ForegroundColor Green
        Write-Host "  ############################################################" -ForegroundColor Green
        Write-Audit "VOLATILE GREEN | files=$n mem=$memOk OK=$script:StepsOk FAIL=$script:StepsFail"
    } else {
        Write-Host "  !!! VOLATILE: AMBER - $memNote ; $n artifacts. Review 99_logs\errors.log before proceeding." -ForegroundColor Yellow
        Write-Audit "VOLATILE AMBER | files=$n memOk=$memOk"
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# GUIDED INTAKE - answer a few questions about the source/compromised host;
# it configures the volatile->non-volatile collection. Includes a vantage-decision
# preamble (is running-on-the-box even the right move?).
# ---------------------------------------------------------------------------
function Read-Def { param([string]$Prompt,[string]$Default) $r = Read-Host "$Prompt [$Default]"; if ([string]::IsNullOrWhiteSpace($r)) { $Default } else { $r } }

function Invoke-GuidedIntake {
    Write-Host ""; Write-Host "================ GUIDED INTAKE ================" -ForegroundColor Cyan
    Write-Host "-- Vantage check: is running on this box the right move? --" -ForegroundColor Gray
    if ((Read-Def "Is this host a VM or cloud instance? (y/N)" 'N') -match '^[yY]') {
        Write-Host "  -> Prefer a SNAPSHOT: VMware .vmem/.vmdk, or AWS/Azure disk snapshot attached to a clean forensic instance." -ForegroundColor Yellow
        Write-Host "     Zero guest footprint, sidesteps Secure Boot/HVCI. Run this tool only if you can't snapshot." -ForegroundColor Yellow }
    if ((Read-Def "Is C2 / active attacker traffic believed LIVE now? (y/N)" 'N') -match '^[yY]') {
        Write-Host "  -> Capture NETWORK first, OFF-host (PCAP at a TAP/SPAN; firewall/proxy/DNS logs). Running me can tip the attacker." -ForegroundColor Yellow }
    if ((Read-Def "More than a few hosts in scope? (y/N)" 'N') -match '^[yY]') {
        Write-Host "  -> Promote to a fleet HUNT (Velociraptor is in .\tools) instead of USB-per-box." -ForegroundColor Yellow }

    Write-Host ""; Write-Host "-- Source host --" -ForegroundColor Gray
    Write-Host ("  OS: {0} | Host: {1} | Domain-joined: {2} | Elevated: {3}" -f $info.os,$hostName,$domainJoined,$isAdmin)
    $script:Compromised = ((Read-Def "Is this host believed COMPROMISED? (Y/n)" 'Y') -notmatch '^[nN]')
    if ($script:Compromised) { Write-Host "  -> Trusted-tool posture (carried tools + kernel APIs). Remember: RAM + dead-box image are ground truth." -ForegroundColor Yellow }
    $enc = $false; try { $enc = [bool](Get-BitLockerVolume 2>$null | Where-Object { $_.ProtectionStatus -eq 'On' }) } catch {}
    if ($enc) { Write-Host "  -> BitLocker DETECTED. Keys captured in Stage 1 (00_metadata\bitlocker_keys.txt) - REQUIRED before any dead-box image." -ForegroundColor Yellow }

    Write-Host ""; Write-Host "-- Destination --" -ForegroundColor Gray
    Write-Host "  Writing to: $OutDir$(if($NetworkDest){"  (ships to $NetworkDest at seal)"})"

    Write-Host ""; Write-Host "-- Collection scope --" -ForegroundColor Gray
    Write-Host "  [1] Volatile only        (RAM + live state, then seal - fastest)"
    Write-Host "  [2] Volatile + triage    (RECOMMENDED: + artifacts, event logs, persistence, browser$(if($domainJoined){', AD'}))"
    Write-Host "  [3] EVERYTHING           (+ full file-hash inventory + full disk image - hours)"
    switch (Read-Def "Select scope" '2') {
        '1' { $script:VolatileOnly = $true; $script:Plan = @() }
        '3' { $script:Plan = @('2','3','4','6','7','8'); if ($domainJoined) { $script:Plan += '5' } }
        default { $script:Plan = @('2','3','4','6'); if ($domainJoined) { $script:Plan += '5' } }
    }
    $planNames = if ($script:VolatileOnly) { 'seal' } else { ($script:Plan | ForEach-Object { $MenuItems[$_].key }) -join ', ' }
    Write-Host ""; Write-Host "Plan: RAM+volatile -> GREEN gate -> $planNames" -ForegroundColor Green
    [void](Read-Def "Press Enter to begin (Ctrl-C to abort)" '')
}

# ===========================================================================
# MAIN  (self-heal: Seal ALWAYS runs, even if a phase throws)
# ===========================================================================
$script:Sealed = $false; $script:Plan = $null; $script:VolatileOnly = $false
function Complete-Run { if (-not $script:Sealed) { $script:Sealed = $true; try { Invoke-Seal } catch { Write-Audit "Seal error: $($_.Exception.Message)" } } }

# guided intake is the default when interactive and no mode flag was given
if (-not $Auto -and -not $RapidOnly -and -not [Console]::IsInputRedirected) {
    try { Invoke-GuidedIntake } catch { Write-Audit "Guided intake skipped: $($_.Exception.Message)" }
}

try {
    try { Invoke-RapidVolatile } catch { Write-Audit "RapidVolatile fault: $($_.Exception.Message) - continuing." }
    Show-VolatileGate

    if ($RapidOnly -or $script:VolatileOnly) {
        Write-Host "Volatile-only - sealing." -ForegroundColor Yellow
    } elseif ($Auto) {
        Write-Audit "Auto mode: running ALL heavy (non-volatile) jobs."
        foreach ($k in $MenuItems.Keys) { try { & $MenuItems[$k].fn } catch { Write-Audit "Job $($MenuItems[$k].key) fault: $($_.Exception.Message) - continuing." } }
    } elseif ($null -ne $script:Plan) {
        Write-Audit "Guided plan: $($script:Plan -join ',')"
        foreach ($k in $script:Plan) { try { & $MenuItems[$k].fn } catch { Write-Audit "Job fault: $($_.Exception.Message) - continuing." } }
        try { Invoke-Menu } catch { Write-Audit "Menu fault: $($_.Exception.Message)" }   # add more / then seal
    } else {
        try { Invoke-Menu } catch { Write-Audit "Menu fault: $($_.Exception.Message) - sealing." }
    }
}
catch { Write-Audit "FATAL in main: $($_.Exception.Message) - proceeding to seal." }
finally { Complete-Run }
