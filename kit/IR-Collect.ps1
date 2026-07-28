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
.PARAMETER Auto         Run Stage 1 then all Stage-2 jobs EXCEPT the two hours-long ground-truth jobs
                        (full-filesystem SHA-256 + full-disk image); no menu (practical unattended triage).
.PARAMETER IncludeGroundTruth  With -Auto, also run the hours-long ground-truth jobs (7 full-FS hash, 8 disk image).
.PARAMETER RapidOnly    Run only Stage 1 (volatile) and seal.
.PARAMETER SkipAD       Never run the AD phase.
.PARAMETER NoKeyCapture Skip BitLocker recovery-password / key-package capture. By default the
                        collector grabs them while the volume is unlocked, because a dead-box
                        image of an encrypted disk is unreadable without a key. Those outputs
                        ARE the keys to the evidence - see 00_metadata\DECRYPTION-KEYS.md.
                        Use this where extracting key material is outside the engagement's scope.

.NOTES  Exit codes: 0 clean | 10 completed-with-skips | 15 incomplete-critical |
        20 RAM not verified | 40 fatal.

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
    [switch]$NoKeyCapture, # skip BitLocker recovery-password / key-package capture (engagements where extracting key material is out of scope)
    [switch]$IncludeGroundTruth,   # with -Auto: also run the hours-long ground-truth jobs (full-FS hash + disk image)
    [switch]$DeferMemory,  # capture RAM AFTER the volatile-command battery instead of before it
    [switch]$Lab,          # training/exercise mode: read-only-media launch, VM detection, HTTP egress, relaxed contamination
    [string]$Authorizer = '',   # who authorized this collection (chain of custody)
    [string]$LegalBasis = '',   # authority/legal basis (IR engagement, warrant, consent...)
    [string]$ScopeNote  = '',   # authorized scope of collection
    [string]$Resume     = '',   # resume a prior run: point at its output dir; re-runs only unsatisfied steps
    [string]$Scenario   = '',   # non-interactive scenario id (1-10 or U): injects intake+plan, no prompts (automation/lab/E2E)
    [string]$HostRole   = '',   # non-interactive host role: workstation|server|domain-controller|cloud-vm|container|ot-ics|network-device
    [string]$KnownBadIps     = '',  # comma/space-separated seed IOCs (fold into intake.json)
    [string]$KnownBadDomains = '',
    [string]$KnownBadHashes  = ''
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
        $fwd=@(); foreach($kv in $PSBoundParameters.GetEnumerator()){ if($kv.Key -eq 'Cred'){continue}
            if($kv.Value -is [switch]){ if($kv.Value.IsPresent){ $fwd+="-$($kv.Key)" } } else { $fwd+="-$($kv.Key)"; $fwd+="$($kv.Value)" } }
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @fwd
        exit $LASTEXITCODE
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
function Now-Utc { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

# Get-Inv: OS-compat inventory shim. Prefer CIM (PSv3+ / PSv7), fall back to legacy WMI on
# older/older-broken hosts (Win7/2008R2, WinRM-off). Never throws; returns $null on total failure.
# NOTE: only usable in PARENT scope - Start-Job children do not inherit script functions.
function Get-Inv { param([string]$Class,[string]$Filter='',[string]$NS='root\cimv2')
    try { if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-CimInstance -ClassName $Class -Namespace $NS -Filter $Filter -ErrorAction Stop }
            else         { return Get-CimInstance -ClassName $Class -Namespace $NS -ErrorAction Stop } } } catch {}
    try { if (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            if ($Filter) { return Get-WmiObject -Class $Class -Namespace $NS -Filter $Filter -ErrorAction Stop }
            else         { return Get-WmiObject -Class $Class -Namespace $NS -ErrorAction Stop } } } catch {}
    return $null
}

# --- hashing shim: Get-FileHash is NOT guaranteed to exist -------------------
# Observed on a real, fully-patched 5.1 host in FullLanguage mode: PSModulePath inherited from a
# parent process listed PowerShell 7's module directories first, so Windows PowerShell loaded pwsh
# 7's Microsoft.PowerShell.Utility (7.0.0.0) instead of its own - and Get-FileHash was simply gone.
# It is also absent outright on PS < 4.0 (Win7/2008R2, which this collector still supports).
# The previous behaviour was to catch the error and write 'ERR' into every manifest row, then seal:
# an evidence bundle whose manifest verifies NOTHING, with no warning to the operator.
# Everything that hashes goes through this shim. It is kept as TEXT as well as live functions
# because Start-Job children do not inherit script functions - generated job scripts prepend it.
$script:HashShimText = @'
function Get-IRHashNet { param([string]$Path,[string]$Alg)
    # .NET fallback. FileShare ReadWrite so an open/locked evidence file still hashes.
    $a = [Security.Cryptography.HashAlgorithm]::Create($Alg)
    if (-not $a) { throw "no provider for $Alg" }
    try {
        $fs = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try { (($a.ComputeHash($fs)) | ForEach-Object { $_.ToString('X2') }) -join '' } finally { $fs.Dispose() }
    } finally { $a.Dispose() }
}
function Get-IRSha256 { param([string]$Path)
    # try/catch (not a Get-Command probe) so a BROKEN Get-FileHash falls back too, not just a missing one
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    Get-IRHashNet $Path 'SHA256'
}
function Get-IRMd5 { param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm MD5 -ErrorAction Stop).Hash } catch {}
    Get-IRHashNet $Path 'MD5'
}
'@
. ([scriptblock]::Create($script:HashShimText))   # also define them in the parent scope
# Record WHICH backend is live so the operator can see it in diagnostics (parity with the Linux
# collector's hash_backend). 'dotnet-fallback' means Get-FileHash was missing or broken on this
# host - worth knowing, because that is the condition that used to silently produce an all-'ERR'
# manifest. Probe against this script file itself: always present, always readable.
$script:HashBackend = try {
    Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop | Out-Null; 'Get-FileHash'
} catch { 'dotnet-fallback' }

if ([string]::IsNullOrWhiteSpace($Dest)) { $Dest = (Get-Location).Path }
$hostName = $env:COMPUTERNAME
$stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
$ToolDir  = Join-Path $PSScriptRoot 'tools'

# --- Resolve destination: local drive / UNC share / bare IP -----------------
# Network destinations are slow+fragile to write to live, so we STAGE locally
# (next to the script / thumb drive) then ZIP + ship at seal time.
function Test-IsIP { param([string]$s) $s -match '^(\d{1,3}\.){3}\d{1,3}$' }
function Get-WritableRoot {
    # first candidate that we can create + write a probe file into
    param([string[]]$Candidates)
    foreach ($c in $Candidates) {
        try { New-Item -ItemType Directory -Force $c -EA Stop | Out-Null
              $tf = Join-Path $c ('.w_' + $stamp); [IO.File]::WriteAllText($tf,'x'); Remove-Item $tf -Force -EA SilentlyContinue
              return $c } catch {}
    }
    return $null
}
# an instructor-attached, purpose-labeled writable volume (lab evidence disk), if present
$LabVol = $null
try { $lv = Get-Volume 2>$null | Where-Object { $_.FileSystemLabel -match 'IR.?EVID|EVIDENCE' -and $_.DriveLetter } | Select-Object -First 1; if ($lv) { $LabVol = "$($lv.DriveLetter):\" } } catch {}
# is the tool running from read-only media (CD/ISO)?  (can't write next to itself)
$RoMedia = $false
try { $sd = $PSScriptRoot.Substring(0,2); $RoMedia = ((Get-Inv Win32_CDROMDrive | ForEach-Object { $_.Drive }) -contains $sd) } catch {}

$NetworkDest = $null; $HttpDest = $null
if     ($Dest -match '^https?://') { $HttpDest = $Dest }          # lab: POST the sealed bundle to a collector endpoint
elseif (Test-IsIP $Dest)           { $NetworkDest = "\\$Dest\$Share" }
elseif ($Dest -like '\\*')         { $NetworkDest = $Dest }

if ($NetworkDest -or $HttpDest) {
    # stage locally first, ship/POST at seal. Find a WRITABLE staging root (media -> lab disk -> temp).
    $cands = @((Join-Path $PSScriptRoot '_staging'))
    if ($LabVol) { $cands += (Join-Path $LabVol '_ir_staging') }
    $cands += (Join-Path $env:TEMP '_ir_staging')
    $OutputRoot = Get-WritableRoot $cands
    if (-not $OutputRoot) { $OutputRoot = Join-Path $env:TEMP '_ir_staging'; try { New-Item -ItemType Directory -Force $OutputRoot | Out-Null } catch {} }
    if ($OutputRoot -like "$env:TEMP*" -and -not $Lab) {
        Write-Host "!!! CONTAMINATION WARNING: cannot stage on the collection media - staging on the TARGET disk ($OutputRoot)." -ForegroundColor Red
        Write-Host "    This writes evidence onto the subject host. Attach writable removable media and re-run if possible. !!!" -ForegroundColor Red
    } elseif ($Lab) { Write-Host "Lab mode: staging at $OutputRoot; ships/POSTs at seal." -ForegroundColor Cyan }
} else {
    $OutputRoot = $Dest
    # read-only-media / non-writable target: redirect to a writable evidence location so we can run at all.
    # NOTE: create the destination first - a valid local -Dest that does not exist yet must be CREATED,
    # not misjudged as read-only and redirected.
    $probe = $false; try { New-Item -ItemType Directory -Force $OutputRoot -EA Stop | Out-Null; $tf = Join-Path $OutputRoot ('.w_' + $stamp); [IO.File]::WriteAllText($tf,'x'); Remove-Item $tf -Force -EA SilentlyContinue; $probe = $true } catch {}
    if (-not $probe) {
        $redir = if ($LabVol) { Join-Path $LabVol 'ir_evidence' } else { Join-Path $env:SystemDrive 'ir_evidence' }
        Write-Host "Output '$OutputRoot' not writable (read-only media?). Redirecting evidence to $redir." -ForegroundColor Yellow
        $OutputRoot = $redir; try { New-Item -ItemType Directory -Force $OutputRoot | Out-Null } catch {}
    }
}
$OutDir = Join-Path $OutputRoot ("{0}_{1}_{2}" -f $CaseId, $hostName, $stamp)
if ($Resume) { $OutDir = $Resume }

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
$script:StateJsonl = Join-Path $Dirs.logs 'run_state.jsonl'
try { if (-not (Test-Path $script:StateJsonl)) { New-Item -ItemType File -Path $script:StateJsonl -Force | Out-Null } } catch {}

function Write-Audit {
    param([string]$Message)
    $line = "{0} | {1} | {2}" -f (Now-Utc), $env:USERNAME, $Message
    try { Add-Content -Path $AuditLog -Value $line -Encoding UTF8 } catch {}
    Write-Host $line
}

# ===== completion ledger + self-troubleshoot + resume =====
function Get-Phase { param([string]$Dir)
    foreach ($e in $Dirs.GetEnumerator()) { if ($e.Value -eq $Dir) { return $e.Key } }
    return 'other'
}
function Write-Ledger { param([string]$Id,[string]$Name,[string]$Phase,[string]$Ev,[hashtable]$Extra)
    if (-not $script:StateJsonl) { return }
    $o = [ordered]@{ t=(Now-Utc); id=$Id; name=$Name; phase=$Phase; ev=$Ev }
    if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
    try { Add-Content -Path $script:StateJsonl -Value ($o | ConvertTo-Json -Compress -Depth 4) -Encoding UTF8 } catch {}
}
# Test-DestHasSpace: can we still WRITE to the evidence tree? Text matching alone misses a full
# destination whenever the message is localized, wrapped by a provider, or absent entirely - and a
# free-space number can lie (quotas, reserved blocks). An actual write probe cannot.
function Test-DestHasSpace {
    # FAIL SAFE: only report "no space" when we actually attempted a write and it failed. If the
    # log dir is not set up yet (early errors) we must assume space is fine - otherwise every
    # unclassified error would be relabelled no_space and falsely flag the run destination-full.
    $logDir = try { $Dirs.logs } catch { $null }
    if ([string]::IsNullOrWhiteSpace($logDir) -or -not (Test-Path -LiteralPath $logDir)) { return $true }
    $probe = Join-Path $logDir (".spaceprobe." + [Diagnostics.Process]::GetCurrentProcess().Id)
    try {
        [IO.File]::WriteAllText($probe, '0123456789')
        return $true
    } catch [IO.IOException] {
        # IOException covers ERROR_DISK_FULL / ERROR_HANDLE_DISK_FULL; anything else (ACL, locked
        # path) is not a space problem and must not masquerade as one.
        return $false
    } catch { return $true }
    finally { Remove-Item $probe -Force -ErrorAction SilentlyContinue }
}
function Get-ErrorClass { param([string]$Kind,[string]$Text)
    if ($Kind -eq 'timeout') { return 'timeout' }
    # structural check first: a full destination is a fact about the disk, not about the wording
    if (-not (Test-DestHasSpace)) { return 'no_space' }
    switch -Regex ($Text) {
        'Access is denied|UnauthorizedAccess|requires elevation|not elevated|Administrator privilege|SeSecurityPrivilege' { return 'not_elevated' }
        'is not recognized|CommandNotFoundException|cannot find the path|Could not find|No such file' { return 'tool_missing' }
        'not enough space|There is not enough space|disk is full' { return 'no_space' }
        'being used by another process|because it is being used|cannot access the file|volume .* in use' { return 'file_locked' }
        'RPC server is unavailable|network path was not found|is unreachable|actively refused|A connection attempt failed' { return 'net_unreachable' }
        'ConstrainedLanguage|not allowed in ConstrainedLanguage|LanguageMode|blocked by .* policy|AppLocker' { return 'clm_blocked' }
        'Invalid namespace|provider load failure|WMI|CIM|WinRM cannot' { return 'wmi_failure' }
        'Start-Job|background job|Cannot start.*job|maximum number of.*jobs|child process|runspace|PSRemoting' { return 'job_subsystem' }
        'fully qualified file name must be less|PathTooLong|path.*too long|filename or extension is too long' { return 'path_too_long' }
        default { return 'unknown' }
    }
}
function Get-Backoff { param([string]$Cls,[int]$Attempt)
    switch ($Cls) { 'timeout' { return ($Attempt*$Attempt*1000) } 'net_unreachable' { return ($Attempt*$Attempt*1000) } 'file_locked' { return 2000 } default { return 400 } }
}
$script:RemTried = @{}
# Invoke-Remediation: $true => retry now ; $false => give up. Each (id,class) fires once; hard cap 3 attempts.
function Invoke-Remediation { param([string]$Cls,[string]$Name,[string]$Id,[string]$Phase,[int]$Attempt)
    if ($Attempt -ge 3) { return $false }
    $k = "$Id|$Cls"; if ($script:RemTried.ContainsKey($k)) { return $false }; $script:RemTried[$k] = $true
    $action = 'none'; $retry = $false
    switch ($Cls) {
        'timeout'         { $action='backoff-retry';       $retry = ($Attempt -lt 2) }
        'net_unreachable' { $action='backoff-retry';       $retry = ($Attempt -lt 2) }
        'file_locked'     { $action='retry-after-settle';  $retry = $true }
        'no_space'        { $action='insufficient-space';  $retry = $false; $script:DiskFull = $true
                            Write-Audit "DISK FULL during '$Name'. Evidence tree stays at $OutDir (relocating a part-written tree mid-run is unsafe). Free space or re-run with -Dest on larger media." }
        'not_elevated'    { $action='degrade-nonadmin';    $retry = $false }
        'tool_missing'    { $action='fallback-or-skip';    $retry = $false }
        'clm_blocked'     { $action='clm-degrade';         $retry = $false }
        'wmi_failure'     { $action='cim-to-wmi-fallback'; $retry = $false }
        default           { $action='none';                $retry = $false }
    }
    Write-Ledger $Id $Name $Phase 'remediation' @{ class=$Cls; action=$action; result=$(if($retry){'retry'}else{'stop'}) }
    Write-Audit "STEP $Id REMEDIATE | $Name | class=$Cls action=$action -> $(if($retry){'retry'}else{'stop'})"
    return $retry
}
$script:Satisfied = @{}
function Import-PriorState { param([string]$Dir)
    $f = Join-Path $Dir '99_logs\run_state.jsonl'
    if (-not (Test-Path $f)) { return }
    foreach ($line in [IO.File]::ReadAllLines($f)) {
        if ($line -notmatch '"ev":"ok"') { continue }
        try { $o = $line | ConvertFrom-Json; if ($o.name) { $script:Satisfied[$o.name] = $true } } catch {}
    }
    Write-Audit "RESUME: $($script:Satisfied.Count) steps already satisfied - will skip them."
}
function Test-StepSatisfied { param([string]$Name,[string]$Target)
    if (-not $Resume) { return $false }
    if (-not $script:Satisfied.ContainsKey($Name)) { return $false }
    if (-not $Target) { return $true }
    if (-not (Test-Path $Target)) { return $false }
    return ((Get-Item $Target).Length -gt 0)
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
# In-process bounded executor: run a scriptblock with a hard timeout WITHOUT Start-Job.
# Self-heal fallback for hardened hosts where the background-job subsystem is unavailable
# (job quota exhausted, local PSRemoting/WinRM off, some ConstrainedLanguage configs).
# Returns @{ done=<completed?>; out=<merged data + ErrorRecords, matching the job 2>&1 shape> }.
# ---------------------------------------------------------------------------
function Invoke-InProcBounded { param([scriptblock]$Script,[int]$TimeoutSec)
    $ps = [System.Management.Automation.PowerShell]::Create()
    try {
        [void]$ps.AddScript($Script.ToString())
        $async = $ps.BeginInvoke()
        if ($async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds([Math]::Max(1,$TimeoutSec)))) {
            $data = @(); $exErr = $null
            try { $data = @($ps.EndInvoke($async)) } catch { $exErr = $_ }   # a TERMINATING error surfaces here, not in Streams.Error
            $errs = @($ps.Streams.Error)          # non-terminating ErrorRecords (same type Start-Job merges via 2>&1)
            if ($exErr) { $errs = @($errs) + @($exErr) }   # fold terminating error in so Invoke-Step sees error-only (parity with Start-Job)
            return @{ done=$true; out=(@($data)+@($errs)) }
        } else {
            try { $ps.Stop() } catch {}
            return @{ done=$false; out=$null }
        }
    } finally { try { $ps.Dispose() } catch {} }
}
# Probe the background-job subsystem ONCE at startup; if it is unavailable, every Invoke-Step
# transparently switches to the in-process executor instead of failing every single step.
$script:JobsOk = $true
try { $__tj = Start-Job -ScriptBlock { 1 } -ErrorAction Stop; $null = Wait-Job $__tj -Timeout 15; Remove-Job $__tj -Force -ErrorAction SilentlyContinue }
catch { $script:JobsOk = $false }
# operator/test override: set env IRCOLLECT_FORCE_INPROC=1 to force the in-process path (verify the fallback)
if ($env:IRCOLLECT_FORCE_INPROC -eq '1') { $script:JobsOk = $false }
if (-not $script:JobsOk) { try { Write-Audit "SELF-HEAL: background-job subsystem unavailable -> using in-process bounded execution for all steps." } catch { Write-Host "SELF-HEAL: in-process execution mode" -ForegroundColor Yellow } }

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
        [int]$Retries = 1,
        [string[]]$KillOnTimeout = @()
    )
    $script:StepNum++
    $id = '{0:000}' -f $script:StepNum
    $phase = Get-Phase $Dir
    $target = if ($OutFile) { Join-Path $Dir $OutFile } else { $null }
    # resume gate: skip a step already satisfied by a prior run (name known-ok + output present + non-empty)
    if (Test-StepSatisfied $Name $target) {
        Write-Ledger $id $Name $phase 'skipped' @{ reason='already-ok' }
        Write-Audit "STEP $id SKIP | $Name | already satisfied (resume)"; $script:StepsOk++; return $null
    }
    Write-Ledger $id $Name $phase 'planned' @{ timeout_s=$TimeoutSec }
    $attempt = 0; $start = Get-Date; $maxAttempt = 3; $cls = ''
    while ($attempt -lt $maxAttempt) {
        $attempt++; $job = $null
        Write-Ledger $id $Name $phase 'running' @{ attempt=$attempt }
        try {
            $out = $null; $stepTimedOut = $false; $job = $null
            if ($script:JobsOk) { try { $job = Start-Job -ScriptBlock $Script } catch { $script:JobsOk = $false; Write-Audit "STEP $id INFO | $Name | job start failed -> in-process ($($_.Exception.Message.Split([Environment]::NewLine)[0]))" } }
            if ($script:JobsOk -and $job) {
                if (Wait-Job $job -Timeout $TimeoutSec) {
                    $out = Receive-Job $job -ErrorAction SilentlyContinue 2>&1
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                } else {
                    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $stepTimedOut = $true
                }
            } else {
                $r = Invoke-InProcBounded $Script $TimeoutSec
                if ($r.done) { $out = $r.out } else { $stepTimedOut = $true }
            }
            if (-not $stepTimedOut) {
                # separate real data from non-terminating error records (job merges stderr via 2>&1)
                $errRecs  = @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
                $hasData  = @($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).Count -gt 0
                if ($target -and $hasData) { try { [IO.File]::WriteAllText($target, (($out | Out-String -Width 4096)), (New-Object Text.UTF8Encoding($false))) } catch { try { $out | Out-File -FilePath $target -Encoding UTF8 -Width 4096 } catch {} } }
                $dur = [int]((Get-Date) - $start).TotalSeconds
                # soft failure: the job ran but produced ONLY errors and no usable data
                if (-not $hasData -and $errRecs.Count -gt 0) {
                    $errText = ($errRecs | ForEach-Object { $_.ToString() }) -join '; '
                    $cls = Get-ErrorClass 'errorrecord' $errText
                    Write-Audit "STEP $id WARN | $Name | error-only (class=$cls) | try $attempt"
                    if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
                    Write-Ledger $id $Name $phase 'failed' @{ rc='error'; error_class=$cls; error_msg=$errText.Substring(0,[Math]::Min(200,$errText.Length)) }
                    Add-Content $ErrLog "$(Now-Utc) [$id] $Name : $errText"; $script:StepsFail++; return $out
                }
                $bytes = if ($target -and (Test-Path $target)) { (Get-Item $target).Length } else { 0 }
                $lines = if ($out) { @($out).Count } else { 0 }
                Write-Audit ("STEP $id OK   | $Name | ${dur}s | try $attempt | lines=$lines" + $(if($target){" -> $(Split-Path $target -Leaf)"}))
                Write-Ledger $id $Name $phase 'ok' @{ attempt=$attempt; bytes=$bytes; lines=$lines }
                $script:StepsOk++; return $out
            } else {
                # timed out (either transport). The job (if any) is already stopped above. Kill any NATIVE
                # grandchild (e.g. winpmem) by name so a hung imager stops appending before the verify.
                foreach($pn in $KillOnTimeout){ try { Get-Process -Name $pn -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {} }
                $cls = 'timeout'
                Write-Audit "STEP $id WARN | $Name | TIMEOUT ${TimeoutSec}s | try $attempt"
                if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
                Write-Ledger $id $Name $phase 'timeout' @{ rc='timeout'; error_class=$cls; attempts=$attempt; error_msg="exceeded ${TimeoutSec}s timeout" }
                Add-Content $ErrLog "$(Now-Utc) [$id] $Name : timeout ${TimeoutSec}s"; $script:StepsFail++; return $null
            }
        } catch {
            if ($job) { try { Remove-Job $job -Force -ErrorAction SilentlyContinue } catch {} }
            $emsg = $_.Exception.Message; $cls = Get-ErrorClass 'exception' $emsg
            Write-Audit "STEP $id ERR  | $Name | $emsg | try $attempt (class=$cls)"
            if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
            Write-Ledger $id $Name $phase 'failed' @{ rc='exception'; error_class=$cls; error_msg=$emsg.Substring(0,[Math]::Min(200,$emsg.Length)) }
            Add-Content $ErrLog "$(Now-Utc) [$id] $Name : $($_.Exception|Out-String)"; $script:StepsFail++; return $null
        }
    }
    Write-Ledger $id $Name $phase 'failed' @{ rc='exhausted'; error_class=$cls; attempts=$attempt }
    $script:StepsFail++; return $null
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
try { $domainJoined = (Get-Inv Win32_ComputerSystem).PartOfDomain } catch {}

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
          ForEach-Object { "{0}  {1}" -f (Get-IRSha256 $_.FullName), $_.FullName } |
          Out-File (Join-Path $Dirs.metadata 'carried_tools_sha256.txt') -Encoding ASCII
    } catch {}
} else {
    Write-Audit "DOCTRINE NOTE: no .\tools dir - relying on host binaries (may be tampered on a compromised host). Core collection uses CIM/.NET/ADSI (kernel-level) to reduce reliance on host userland exes."
}

# precompute custody fields (try/catch is a statement, not valid inside a hashtable literal)
$fqdn = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $hostName }
$startUtc = Now-Utc
$osCaption = try { (Get-Inv Win32_OperatingSystem).Caption } catch { '' }
$acqId = try { [guid]::NewGuid().ToString() } catch { "$hostName-$stamp" }
$info = [ordered]@{
    tool='IR-Collect.ps1'; version='2.0'; case=$CaseId; acquisitionId=$acqId; host=$hostName
    fqdn=$fqdn; domain=$env:USERDNSDOMAIN; domainJoined=$domainJoined; collector=$env:USERNAME; elevated=$isAdmin
    startUtc=$startUtc; os=$osCaption; psVersion="$($PSVersionTable.PSVersion)"
    languageMode="$($ExecutionContext.SessionState.LanguageMode)"; is64="$([Environment]::Is64BitProcess)"; toolsDetected=$detected
    authorizer=$Authorizer; legalBasis=$LegalBasis; scope=$ScopeNote; exercise=[bool]$Lab; roMedia=$RoMedia
}
if (-not $Authorizer) { Write-Audit "CUSTODY WARNING: no -Authorizer recorded. Pass -Authorizer/-LegalBasis/-ScopeNote for a defensible chain of custody." }
try { [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'collection_info.json'), ($info | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) } catch {}
try { if (-not (Test-Path (Join-Path $Dirs.metadata 'intake.json'))) { $di=[ordered]@{ case_id=$CaseId; scenario='U'; scenario_name='Unknown / broad triage'; host_role='unknown'; scope='single'; connectivity='connected'; exercise=[bool]$Lab; generated_by='IR-Collect.ps1 (non-guided)'; known_bad_ips=@(); known_bad_domains=@(); known_bad_hashes=@(); known_bad_accounts=@(); known_bad_paths=@(); attack_tags=@() }; [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'intake.json'), ($di | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false))) } } catch {}

# --- guest / hypervisor detection: which host-side pull channel is available (training-lab) ---
$script:Hypervisor='unknown'; $script:GuestTools=@()
try {
    $cs = Get-CimInstance Win32_ComputerSystem 2>$null; $bios = Get-CimInstance Win32_BIOS 2>$null
    $sig = "$($cs.Manufacturer) $($cs.Model) $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion) $($bios.SerialNumber)"
    switch -Regex ($sig) {
        'VMware'                       { $script:Hypervisor='vmware'; break }
        'VirtualBox|innotek'           { $script:Hypervisor='virtualbox'; break }
        'QEMU|KVM|BOCHS|SeaBIOS|Red Hat' { $script:Hypervisor='qemu-kvm'; break }
        'Xen'                          { $script:Hypervisor='xen'; break }
        'Amazon|EC2'                   { $script:Hypervisor='aws'; break }
        'Google'                       { $script:Hypervisor='gcp'; break }
        'Microsoft Corporation.*Virtual|Virtual Machine' { $script:Hypervisor='hyper-v'; break }
    }
    foreach($svc in 'vmtools','VBoxService','vmicvss','vmicheartbeat','qemu-ga','GCEAgent','AmazonSSMAgent'){ if (Get-Service $svc -EA SilentlyContinue){ $script:GuestTools += $svc } }
    $envtxt = "Hypervisor: $script:Hypervisor`nGuestTools: $($script:GuestTools -join ', ')`nSMBIOS: $sig`nBootMediaReadOnly: $RoMedia`nLabMode: $([bool]$Lab)`nOutputRoot: $OutputRoot"
    [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'environment_detect.txt'), $envtxt, (New-Object Text.UTF8Encoding($false)))
    Write-Audit "GUEST ENV: hypervisor=$script:Hypervisor tools=$($script:GuestTools -join '+') roMedia=$RoMedia lab=$([bool]$Lab)"
} catch {}
if ($Lab) { Write-Host "=== LAB / TRAINING MODE (hypervisor=$script:Hypervisor) - evidence marked EXERCISE ===" -ForegroundColor Magenta }

# --- destination preflight: write-test + FAT32 4GB cap -----------------------
try {
    $tf = Join-Path $OutputRoot ('.irwrite_' + $stamp); Set-Content $tf 'x' -ErrorAction Stop; Remove-Item $tf -Force -ErrorAction SilentlyContinue
} catch { Write-Audit "PREFLIGHT: destination NOT writable - $($_.Exception.Message)"; Write-Host "!!! DESTINATION NOT WRITABLE: $OutputRoot - fix the drive/path; this collection may capture nothing !!!" -ForegroundColor Red }
try {
    $destRoot = [System.IO.Path]::GetPathRoot((Resolve-Path $OutputRoot).Path)
    $vol = Get-Volume -FilePath $OutputRoot -ErrorAction SilentlyContinue
    if ($vol -and $vol.FileSystem -match 'FAT') {
        Write-Audit "PREFLIGHT WARNING: destination is $($vol.FileSystem) - FAT32 caps files at 4GB; a RAM image will TRUNCATE. Reformat destination NTFS/exFAT."
    } elseif ($vol) { Write-Audit "PREFLIGHT: destination filesystem = $($vol.FileSystem)" }
} catch {}
Write-Audit "PREFLIGHT: privilege=$(if($isAdmin){'full'}else{'PARTIAL - not elevated'}) langMode=$($ExecutionContext.SessionState.LanguageMode) 64bit=$([Environment]::Is64BitProcess)"
Write-Audit "FOOTPRINT: tools run from '$PSScriptRoot' (NOT installed on target); evidence written only to destination; live-collection footprint is documented in this log. For non-volatile ground truth follow with a dead-box disk image."
try {
    $pt = (Get-Inv Win32_OperatingSystem).ProductType  # 1 = workstation
    if ($pt -eq 1 -and $domainJoined -and ((whoami /groups 2>$null) -match 'Domain Admins|Enterprise Admins|Schema Admins')) {
        Write-Host "!!! TIERED-ADMIN RISK: high-privilege domain token (Domain/Enterprise Admin) on a WORKSTATION-class host. Credentials are exposed to a possibly-compromised box. Use a Tier-2 IR account. !!!" -ForegroundColor Red
        Write-Audit "WARNING: high-privilege domain token on workstation-class host (tiered-admin violation / credential-exposure risk)."
    }
} catch {}

# ===========================================================================
# STAGE 1 - RAPID VOLATILE GRAB (automatic, order of volatility)
# ===========================================================================
function Invoke-RapidVolatile {
    Write-Host ""; Write-Host "================ STAGE 1: RAPID VOLATILE GRAB ================" -ForegroundColor Cyan
    Write-Audit "===== STAGE 1: rapid volatile grab ====="
    $M=$Dirs.metadata; $V=$Dirs.volatile; $N=$Dirs.network

    # --- pre-image essentials ONLY: encryption keys + clock. Everything else perturbs RAM, so the
    #     identity battery (systeminfo/os/tz/boot/env) runs AFTER the memory image below (RFC 3227). ---
    # CRITICAL while live: BitLocker status + recovery keys. If the disk is encrypted and you go
    # dead-box without these, the image is unreadable. Capture protectors/keys NOW.
    $env:IRCOLLECT_META = $M   # so job children can write key packages next to the other metadata
    if ($NoKeyCapture) {
        Write-Audit 'KEY CAPTURE SKIPPED (-NoKeyCapture): BitLocker recovery passwords / key packages NOT collected.'
        Collect 'keys-skipped' { 'Volume-encryption key capture was disabled with -NoKeyCapture. A dead-box image of an encrypted volume will NOT be readable without a custodian-supplied key.' } 'ENCRYPTION_KEYS_SKIPPED.txt' $M
    } else {
    Collect 'bitlocker'      { Get-BitLockerVolume 2>$null | Format-List MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,KeyProtector; '=== Recovery key protectors (manage-bde) ==='; foreach($d in (Get-Volume | Where-Object DriveLetter).DriveLetter){ "--- $d`: ---"; manage-bde -protectors -get "$($d):" 2>$null } } 'bitlocker_keys.txt' $M
    # The block above dumps human-readable protector text. Two things it does NOT give you:
    #  1. a MACHINE-READABLE recovery password per volume - the analyst had to eyeball 48 digits
    #     out of prose months later, per volume. Emit an unambiguous <MountPoint>,<ID>,<password> file.
    #  2. the BitLocker KEY PACKAGE - required by repair-bde to recover data from an image whose
    #     metadata/sectors are damaged, which a recovery password alone cannot do.
    Collect 'bitlocker-recovery-keys' {
        'MountPoint,ProtectionStatus,KeyProtectorId,RecoveryPassword'
        foreach ($v in (Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
            foreach ($kp in @($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })) {
                '{0},{1},{2},{3}' -f $v.MountPoint, $v.ProtectionStatus, $kp.KeyProtectorId, $kp.RecoveryPassword
            }
        }
    } 'bitlocker_recovery_keys.csv' $M
    Collect 'bitlocker-keypackage' {
        # -id is required per protector; key packages are what repair-bde consumes
        foreach ($v in (Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.ProtectionStatus -eq 'On' })) {
            foreach ($kp in @($v.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })) {
                # env var, not $using: - Start-Job children inherit the environment, and the
                # in-process fallback executor does not support $using: at all
                $dest = Join-Path $env:IRCOLLECT_META ("keypackage_" + ($v.MountPoint -replace '[:\\]','') )
                New-Item -ItemType Directory -Force $dest | Out-Null
                "--- $($v.MountPoint) protector $($kp.KeyProtectorId) ---"
                manage-bde -KeyPackage $v.MountPoint -id $kp.KeyProtectorId -path $dest 2>&1
            }
        }
        'NOTE: key packages feed repair-bde when an image is damaged; a recovery password alone cannot repair.'
    } 'bitlocker_keypackage.log' $M
    # Other on-host encryption that also gates reading the evidence later
    Collect 'other-crypto' {
        '=== EFS certificates (private keys needed to read EFS files) ==='
        cipher /y 2>&1
        Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
            Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match 'Encrypting File System' } |
            Select-Object Thumbprint, Subject, NotAfter, HasPrivateKey | Format-List
        '=== DPAPI master keys (decrypt browser logins / saved creds later) ==='
        foreach ($p in (Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue)) {
            $mk = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Protect'
            if (Test-Path -LiteralPath $mk) { Get-ChildItem $mk -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName }
        }
        '=== Mounted VeraCrypt/TrueCrypt volumes ==='
        Get-CimInstance Win32_Volume -ErrorAction SilentlyContinue | Where-Object { $_.Label -match 'crypt' } | Format-Table Name,Label,Capacity -AutoSize
        (Get-Process -Name 'VeraCrypt*','TrueCrypt*' -ErrorAction SilentlyContinue | Select-Object Name,Id | Format-Table -AutoSize | Out-String)
    } 'other_encryption_keys.txt' $M
    }
    # Ship the procedure WITH the keys - the analyst who needs this may be months and several
    # handovers away from whoever ran the collection.
    $keyGuide = @'
# Reading this evidence when the volumes are encrypted

(If the run used `-NoKeyCapture`, the key files below were deliberately NOT collected -
only the RAM-recovery route at the end of this document applies.)

**These files are the keys to the evidence.** Anyone holding this bundle can decrypt the imaged
volumes. Store and transfer it at the classification of the data it protects, and record its custody.

## What was captured (00_metadata\)
| File | What it is |
|---|---|
| `bitlocker_recovery_keys.csv` | Machine-readable `MountPoint,ProtectionStatus,KeyProtectorId,RecoveryPassword` - the 48-digit recovery passwords |
| `bitlocker_keys.txt` | Full protector detail per volume (`manage-bde -protectors -get`) |
| `keypackage_*\` | BitLocker key packages - what `repair-bde` needs when the image is DAMAGED |
| `other_encryption_keys.txt` | EFS certs, DPAPI master-key paths, VeraCrypt/TrueCrypt indicators |
| `..\03_memory\` | RAM image - the FVEK itself is only ever here |

## Unlocking an acquired image with a recovery password
Attach the image read-only (Arsenal Image Mounter / FTK Imager / `Mount-DiskImage -Access ReadOnly`),
then against the BitLocker volume:

    manage-bde -unlock X: -RecoveryPassword 123456-...-654321
    manage-bde -status X:

Linux analysis box, using the same recovery password. Prefer dislocker here - note there is NO
space after `-p`, and `-r` keeps it read-only:

    dislocker -r -V /dev/loopNp2 -p563200-557084-...-239976 -- /mnt/bde
    mount -o ro,loop /mnt/bde/dislocker-file /mnt/evidence

`cryptsetup bitlkOpen` also accepts a recovery passphrase, but supply it INTERACTIVELY - passing a
BITLK passphrase via `--key-file` is a known cryptsetup bug (fails with "No key available with
this passphrase"). `--volume-key-file` does work, but it takes the FVEK, not a recovery password.

## When the volume metadata is damaged
A recovery password alone will not repair a corrupt volume - this is what the key package is for:

    repair-bde X: Y: -kp keypackage_C\<file> -rp 123456-...-654321

## If no recovery password was captured
The FVEK lives in RAM while the volume is unlocked, so recover it from the memory image. There is
no first-party Volatility 3 BitLocker plugin - it is a COMMUNITY plugin you must install into
`volatility3/plugins/windows/`, and the invocation is the scanner, not a bare module name:

    vol -f memdump.raw windows.bitlocker.BitlockerFVEKScan --dislocker

That emits a Dislocker-ready `.fvek`, which unlocks the image without any password:

    dislocker -r -V /dev/loopNp2 -k <file>.fvek -- /mnt/bde

Otherwise: Passware/Elcomsoft against the raw image, or the recovery key escrowed in AD
(`msFVE-RecoveryInformation`) or Entra ID / Intune.

## Verify before you rely on it
Unlock, confirm the filesystem mounts read-only, and check the volume GUID against
`bitlocker_keys.txt`. Never write to the original evidence.
'@
    try { [IO.File]::WriteAllText((Join-Path $M 'DECRYPTION-KEYS.md'), $keyGuide, (New-Object Text.UTF8Encoding($false))) } catch {}
    # host clock vs collection clock (timeline provenance / skew)
    Collect 'clock-skew'     { 'Host local time : '+(Get-Date).ToString('o'); 'Host UTC time   : '+((Get-Date).ToUniversalTime().ToString('o')); 'NOTE: compare against a trusted external time source and record offset for timeline defensibility.' } 'clock_provenance.txt' $M

    # --- RAM IMAGE FIRST (RFC 3227: memory is the most volatile capturable artifact) ---
    # Every command below perturbs RAM, so image it before the volatile-command battery.
    if (-not $DeferMemory) {
        Write-Host "Capturing physical memory first (order of volatility)..." -ForegroundColor Cyan
        Job-Memory
    } else { Write-Audit "DeferMemory set - RAM will be captured after volatile commands." }

    # --- host identity (post-image: safe now that the most-volatile artifact is secured) ---
    Collect 'systeminfo'     { systeminfo } 'systeminfo.txt' $M
    Collect 'os-cim'         { Get-CimInstance Win32_OperatingSystem | Format-List *; Get-CimInstance Win32_ComputerSystem | Format-List * } 'os_computer.txt' $M
    Collect 'timezone'       { Get-TimeZone | Format-List *; 'UTC now: '+((Get-Date).ToUniversalTime().ToString('o')); 'Local now: '+(Get-Date).ToString('o') } 'timezone.txt' $M
    Collect 'boot-uptime'    { $os=Get-CimInstance Win32_OperatingSystem; 'LastBoot: '+$os.LastBootUpTime; 'Install: '+$os.InstallDate } 'boot.txt' $M
    Collect 'env'            { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize } 'environment.txt' $M

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
    try { Get-Clipboard -Raw -ErrorAction SilentlyContinue | Set-Content (Join-Path $V 'clipboard.txt') -Encoding UTF8; Write-Audit 'STEP clipboard captured (STA main scope)' } catch { Write-Audit 'clipboard capture failed' }
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
$script:MemOk = $false; $script:MemBytes = 0; $script:MemFailCode = 'not-attempted'

# Classify a memory-acquisition attempt into a verdict + an operator-ACTIONABLE reason.
# Pure (takes observed facts, does no I/O) so it is unit-testable - see tests/unit.
# The reason drives what the analyst does next, so the distinctions matter: "no imager was
# staged" is a kit-provisioning miss fixable in seconds, while "imager produced nothing" is
# a host-hardening problem (Secure Boot/HVCI/EDR). Conflating them sends people the wrong way.
function Resolve-MemVerdict {
    param(
        [int64]$Bytes,           # size of the largest candidate image (0 = none found)
        [int64]$Need,            # format-aware minimum size to accept
        [bool]$HaveImage,        # a candidate image file exists on disk
        [bool]$Stable,           # size did not change across the sample window
        [bool]$Locked,           # another process still holds the file open
        [bool]$ImagerPresent     # an acquisition tool was found and invoked
    )
    if ($HaveImage -and $Bytes -ge $Need -and $Stable -and -not $Locked) {
        return [pscustomobject]@{ Ok=$true; Code='verified'; Reason=''; DriverHint=$false }
    }
    # ORDER MATTERS: absence of a tool, then absence of a file, BEFORE the stability/lock
    # signals - those are only meaningful once a file actually exists. (Getting this order
    # wrong made every no-image run report "file still growing" and blame Secure Boot.)
    $code='image-too-small'; $why=('image too small for its format ({0:N1} MB < {1:N1} MB)' -f ($Bytes/1MB),($Need/1MB)); $hint=$true
    if     (-not $ImagerPresent) { $code='no-imager-staged';  $why='no acquisition tool was staged (place winpmem.exe/DumpIt.exe in .\tools)'; $hint=$false }
    elseif (-not $HaveImage)     { $code='no-image-produced'; $why='the imager ran but produced no image file' }
    elseif ($Locked)             { $code='imager-holds-file'; $why='imager still holds the file (hung/incomplete)' }
    elseif (-not $Stable)        { $code='image-growing';     $why='file still growing (imager not finished)' }
    [pscustomobject]@{ Ok=$false; Code=$code; Reason=$why; DriverHint=$hint }
}

function Job-Memory {
    if ($script:Done['memory']) { Write-Audit "RAM already captured - skipping."; return }
    Write-Audit "--- RAM image (volatile #1) ---"; $D=$Dirs.memory
    # free-space preflight: need ~ physical RAM * 1.1
    $ram = try { (Get-Inv Win32_ComputerSystem).TotalPhysicalMemory } catch { 8GB }
    if (-not (Test-Space $D ($ram*1.1) 'RAM-image')) { Collect 'mem-skip-space' { 'RAM image skipped: insufficient destination free space.' } 'RAM_SKIPPED_NO_SPACE.txt' $D; $script:Done['memory']=$true; return }
    $img = Join-Path $D 'memory.raw'
    $imagerPresent = [bool]($TOOL.winpmem -or $TOOL.dumpit -or $TOOL.magnetram)
    if     ($TOOL.winpmem) { $wp=$TOOL.winpmem; Invoke-Step 'mem-winpmem' ([scriptblock]::Create("& '$wp' acquire '$img' 2>&1; if(-not (Test-Path '$img')){ & '$wp' '$img' 2>&1 }")) $null $D -TimeoutSec 3600 -Retries 0 -KillOnTimeout @([IO.Path]::GetFileNameWithoutExtension($wp)) | Out-Null }
    elseif ($TOOL.dumpit)  { Invoke-Step 'mem-dumpit'  ([scriptblock]::Create("& '$($TOOL.dumpit)' /OUTPUT '$($D)\memory.dmp' /QUIET")) $null $D -TimeoutSec 3600 -Retries 0 -KillOnTimeout @([IO.Path]::GetFileNameWithoutExtension($TOOL.dumpit)) | Out-Null }
    elseif ($TOOL.magnetram){Invoke-Step 'mem-magnet'  ([scriptblock]::Create("& '$($TOOL.magnetram)' /accepteula /go '$D'")) $null $D -TimeoutSec 3600 -Retries 0 -KillOnTimeout @([IO.Path]::GetFileNameWithoutExtension($TOOL.magnetram)) | Out-Null }
    else { Write-Audit "RAM: no memory tool found (place winpmem.exe/DumpIt.exe in .\tools). Capturing pagefile-config + hiberfil note only."
           Collect 'mem-fallback' { 'No native full-RAM capture. Recommended: WinPmem or DumpIt.'; Get-CimInstance Win32_PageFileUsage | Format-List * } 'RAM_NOT_CAPTURED.txt' $D }
    # verify a REAL image was produced. Classic silent failure: driver blocked by Secure Boot/HVCI/EDR
    # writes a tiny error file, mem-hash dutifully hashes it, and the collection seals GREEN with no RAM.
    $imgFile = try { Get-ChildItem $D -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.raw','.dmp','.aff4','.lime','.mem','.zip' } | Sort-Object Length -Descending | Select-Object -First 1 } catch { $null }
    $script:MemBytes = if ($imgFile) { [int64]$imgFile.Length } else { 0 }
    $totalRam = try { [int64](Get-Inv Win32_ComputerSystem).TotalPhysicalMemory } catch { 8GB }
    # stability + lock check: a hung imager (orphaned past the job timeout) leaves a growing/locked partial.
    $stable = $false; $locked = $false
    if ($imgFile) {
        $s1 = $imgFile.Length; Start-Sleep -Seconds 3
        try { $s2 = (Get-Item $imgFile.FullName -ErrorAction Stop).Length } catch { $s2 = $s1 }
        $stable = ($s1 -eq $s2)
        try { $fsx=[IO.File]::Open($imgFile.FullName,'Open','Read','None'); $fsx.Close() } catch { $locked = $true }
    }
    # threshold is FORMAT-AWARE: a compressed AFF4/zip is legitimately far smaller than raw RAM.
    $compressed = $imgFile -and ($imgFile.Extension -in '.aff4','.zip')
    $need = if ($compressed) { [int64][math]::Max(200MB, $totalRam*0.05) } else { [int64]($totalRam*0.4) }
    $verdict = Resolve-MemVerdict -Bytes $script:MemBytes -Need $need -HaveImage ([bool]$imgFile) `
                                  -Stable $stable -Locked $locked -ImagerPresent $imagerPresent
    $script:MemFailCode = $verdict.Code
    if ($verdict.Ok) {
        $script:MemOk = $true
        Write-Audit ("RAM VERIFIED: {0:N1} GB {1} image, stable + not locked (threshold {2:N1} GB)." -f ($script:MemBytes/1GB), $(if($compressed){'compressed'}else{'raw'}), ($need/1GB))
        # post-acquisition verify: re-read + hash (SHA-256 + MD5) so a truncated image can't seal silently
        Invoke-Step 'mem-hash-verify' ([scriptblock]::Create($script:HashShimText + "Get-ChildItem '$D' -File -Force | Where-Object { `$_.Length -gt 1MB } | ForEach-Object { 'SHA256 ' + (Get-IRSha256 `$_.FullName) + '  ' + `$_.Name; 'MD5    ' + (Get-IRMd5 `$_.FullName) + '  ' + `$_.Name }")) 'memory_hashes.txt' $D -TimeoutSec 1800 | Out-Null
    } else {
        $script:MemOk = $false
        $why = $verdict.Reason
        # only blame the driver/host hardening when a tool actually ran - otherwise the fix is to stage one.
        $hint = if ($verdict.DriverHint) { ' Secure Boot/HVCI/EDR may have blocked the driver.' } else { ' Stage an imager in .\tools and re-run.' }
        Write-Audit ("RAM WARNING: {0:N1} MB - capture NOT verified [{1}]: {2}.{3} *** Do NOT power off an encrypted host without a recovery key - the FVEK is only in RAM. ***" -f ($script:MemBytes/1MB), $verdict.Code, $why, $hint)
        $causes = if ($verdict.DriverHint) { 'Causes: Secure Boot/HVCI/VBS blocking the driver, EDR quarantine, or a hung imager.' } else { 'Fix: place winpmem.exe or DumpIt.exe in the kit tools folder and re-run.' }
        $note = ("RAM CAPTURE NOT VERIFIED [{0}]: {1}. {2} If the disk is encrypted, DO NOT power off without a recovery key." -f $verdict.Code, $why, $causes).Replace("'","''")
        Collect 'mem-fail-warning' ([scriptblock]::Create("'$note'")) 'RAM_CAPTURE_FAILED.txt' $D
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
        Collect 'amcache-copy' ([scriptblock]::Create("Copy-Item '$env:WINDIR\AppCompat\Programs\Amcache.hve' '$A\Amcache.hve' -Force -ErrorAction SilentlyContinue; 'copied if present'")) 'amcache_note.txt' $A
        # per-user hives (UserAssist/ShellBags/RunMRU/TypedPaths...) + PowerShell history + USB history
        # TARGETED, not a tree walk. These artifacts live at FIXED paths, but the previous
        # `robocopy 'C:\Users' ... /S` recursed every profile's whole AppData (OneDrive caches,
        # node_modules, browser caches) to find a handful of files: 322s on range-FS01/SQL01 and a
        # repeated 300s timeout on range-WS01 - i.e. the step that hunts per-user evidence was the
        # single most likely one to time out and return NOTHING. Enumerate profiles once, then copy
        # exact directories (robocopy without /S is top-level-only, so each copy is bounded).
        # Profile root comes from ProfileList, not a hardcoded C:\Users - a relocated profile
        # directory previously meant we silently collected nothing at all.
        $profRoot = try { [Environment]::ExpandEnvironmentVariables((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction Stop).ProfilesDirectory) } catch { Join-Path $env:SystemDrive 'Users' }
        $rcOpt = '/B /R:1 /W:1 /NFL /NDL /NP /NJH /NJS'   # /B = backup semantics, needed for in-use hives
        Invoke-Step 'copy-userhives' ([scriptblock]::Create(@"
foreach (`$p in (Get-ChildItem '$profRoot' -Directory -Force -ErrorAction SilentlyContinue)) {
    `$d = Join-Path '$A\userhives' `$p.Name
    robocopy `$p.FullName `$d NTUSER.DAT $rcOpt | Out-Null
    `$uc = Join-Path `$p.FullName 'AppData\Local\Microsoft\Windows'
    if (Test-Path -LiteralPath `$uc) { robocopy `$uc `$d UsrClass.dat $rcOpt | Out-Null }
    "`$(`$p.Name): NTUSER.DAT=`$(Test-Path (Join-Path `$d 'NTUSER.DAT')) UsrClass.dat=`$(Test-Path (Join-Path `$d 'UsrClass.dat'))"
}
"@)) 'userhives_copied.txt' $A -TimeoutSec 600 -Retries 0 | Out-Null
        Invoke-Step 'copy-pshistory' ([scriptblock]::Create(@"
foreach (`$p in (Get-ChildItem '$profRoot' -Directory -Force -ErrorAction SilentlyContinue)) {
    `$src = Join-Path `$p.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
    if (-not (Test-Path -LiteralPath `$src)) { continue }
    `$d = Join-Path '$A\ps_history' `$p.Name
    robocopy `$src `$d ConsoleHost_history.txt $rcOpt | Out-Null
    "`$(`$p.Name): ConsoleHost_history.txt=`$(Test-Path (Join-Path `$d 'ConsoleHost_history.txt'))"
}
"@)) 'pshistory_copied.txt' $A -TimeoutSec 300 -Retries 0 | Out-Null
        Collect 'usb-history' ([scriptblock]::Create("Copy-Item '$env:WINDIR\INF\setupapi.dev.log' '$A\setupapi.dev.log' -Force -ErrorAction SilentlyContinue; '=== USBSTOR (also in SYSTEM hive) ==='; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue | Select-Object FriendlyName,PSChildName | Format-Table -AutoSize")) 'usb_devices.txt' $A
        Collect 'ps-transcript-note' { 'Note: full NTFS metadata ($MFT/$UsnJrnl/$LogFile), SRUM, and locked per-user hives are best captured by the Velociraptor/CyLR triage path (uses VSS/raw). This native fallback is best-effort.' } '_TRIAGE_LIMITATIONS.txt' $A
    }
    $script:Done['artifacts']=$true
}

function Job-EventLogs {
    Write-Audit "--- HEAVY: full event-log export ---"; $A=$Dirs.artifacts
    Collect 'evtx-inventory' { Get-WinEvent -ListLog * 2>$null | Where-Object RecordCount -gt 0 | Select-Object LogName,RecordCount,FileSize,LastWriteTime | Sort-Object RecordCount -Descending | Format-Table -AutoSize } 'event_logs_inventory.txt' $A -Timeout 180
    $src = "$env:WINDIR\System32\winevt\Logs"
    # PASS 1 - secure the compact, high-signal channels FIRST (seconds), so a slow/interrupted bulk
    # copy on a busy DC (multi-GB Security.evtx) can never lose the crown-jewel behavioural logs.
    # (winevt filenames use %4 for '/'; some contain spaces - each is quoted for robocopy.)
    $priority = @('System','Application',
      'Microsoft-Windows-Sysmon%4Operational','Microsoft-Windows-PowerShell%4Operational','Windows PowerShell',
      'Microsoft-Windows-TaskScheduler%4Operational','Microsoft-Windows-Windows Defender%4Operational',
      'Microsoft-Windows-WinRM%4Operational','Microsoft-Windows-WMI-Activity%4Operational',
      'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational','Microsoft-Windows-Bits-Client%4Operational',
      'Directory Service','DNS Server','File Replication Service','Security')
    $pl = ($priority | ForEach-Object { '"{0}.evtx"' -f $_ }) -join ' '
    Invoke-Step 'evtx-priority' ([scriptblock]::Create("robocopy '$src' '$A\evtx' $pl /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 600 -Retries 0 | Out-Null
    # PASS 2 - bulk copy everything else; /XO skips the files already secured in pass 1.
    Invoke-Step 'evtx-bulk' ([scriptblock]::Create("robocopy '$src' '$A\evtx' *.evtx /XO /B /R:1 /W:1 /NFL /NDL /NP")) $null $A -TimeoutSec 1200 -Retries 0 | Out-Null
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
    if ($script:DoNoHarm) { Write-Audit 'filehashes skipped (do-no-harm / OT-ICS mode)'; Collect 'hash-skip-ot' { 'Skipped: do-no-harm (OT/ICS) mode - a full live-filesystem hash walk is too intrusive for control systems.' } 'FILEHASH_SKIPPED_OT.txt' $A; $script:Done['filehashes']=$true; return }
    foreach ($drv in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3').DeviceID) {
        Invoke-Step "hash-$drv" ([scriptblock]::Create($script:HashShimText + @"
Get-ChildItem '$drv\' -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
  try { `$h=Get-IRSha256 `$_.FullName } catch { `$h='ERR' }
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
    if ($script:DoNoHarm) { Write-Audit 'disk image skipped (do-no-harm / OT-ICS mode)'; Collect 'disk-skip-ot' { 'Skipped: do-no-harm (OT/ICS) mode - live disk imaging risks control-system availability.' } 'DISK_SKIPPED_OT.txt' $D; $script:Done['diskimage']=$true; return }
    if ($TOOL.ftkimager) {
        foreach($pd in (Get-CimInstance Win32_DiskDrive | Select-Object -ExpandProperty DeviceID)) {
            $n=($pd -replace '[\\\.]','_'); Invoke-Step "disk-$n" ([scriptblock]::Create("& '$($TOOL.ftkimager)' '$pd' '$D\$n' --e01 --frag 2G --verify")) $null $D -TimeoutSec 36000 -Retries 0 | Out-Null }
    } else {
        Write-Audit "Full disk image: no FTK Imager found. Place ftkimager.exe in .\tools (or use a hardware imager). Skipping."
        Collect 'disk-note' { 'Full disk imaging requires FTK Imager CLI (ftkimager.exe) or equivalent. Not run.' } 'DISK_NOT_IMAGED.txt' $D
    }
    $script:Done['diskimage']=$true
}

function Job-VSS {
    Write-Audit "--- HEAVY: Volume Shadow Copy state (ransomware anti-recovery evidence) ---"; $P=$Dirs.persistence
    Collect 'vss-list' { '=== vssadmin list shadows ==='; vssadmin list shadows 2>&1; '=== Win32_ShadowCopy ==='; Get-CimInstance Win32_ShadowCopy 2>$null | Select-Object ID,InstallDate,VolumeName,DeviceObject | Format-List *; '=== vssadmin list shadowstorage ==='; vssadmin list shadowstorage 2>&1 } 'shadow_copies.txt' $P -Timeout 180
    # T1490 inhibit-recovery: evidence that shadows/backups were (or can be) deleted
    Collect 'vss-recovery-config' { '=== bcdedit (recoveryenabled flags) ==='; bcdedit /enum 2>&1; '=== wbadmin catalog ==='; wbadmin get versions 2>&1 } 'recovery_config.txt' $P -Timeout 120
    $script:Done['vss']=$true
}
function Job-WebLogs {
    Write-Audit "--- HEAVY: web-server logs + webroot timeline (webshell hunt) ---"; $A=$Dirs.artifacts; $w=Join-Path $A 'webserver'; try{New-Item -ItemType Directory -Force $w|Out-Null}catch{}
    Invoke-Step 'web-iis-logs'   ([scriptblock]::Create("robocopy '$env:SystemDrive\inetpub\logs\LogFiles' '$w\iis_logs' /S /R:1 /W:1 /NFL /NDL /NP")) $null $w -TimeoutSec 900 -Retries 0 | Out-Null
    Invoke-Step 'web-iis-config' ([scriptblock]::Create("Copy-Item '$env:WINDIR\System32\inetsrv\config\applicationHost.config' '$w\applicationHost.config' -Force -ErrorAction SilentlyContinue; 'copied applicationHost.config if present'")) 'iis_config_note.txt' $w -TimeoutSec 60 | Out-Null
    # webroot recent-file timeline: dropped .aspx/.asp/.php/.jsp shells sort to the top by mtime
    Collect 'web-root-timeline' {
        $roots=@("$env:SystemDrive\inetpub\wwwroot") + (Get-ChildItem "$env:SystemDrive\inetpub" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName)
        foreach($r in ($roots|Select-Object -Unique)){ if(Test-Path $r){ "=== $r ==="; Get-ChildItem $r -Recurse -File -Include *.asp,*.aspx,*.ashx,*.asmx,*.php,*.jsp,*.jspx,*.war -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 500 LastWriteTimeUtc,Length,FullName | Format-Table -AutoSize } }
    } 'webroot_script_files.txt' $A -Timeout 600
    $script:Done['weblogs']=$true
}

# ---------------------------------------------------------------------------
# STAGE 2 menu
# ---------------------------------------------------------------------------
$MenuItems = [ordered]@{
    '1'  = @{ label='Full RAM image (WinPmem/DumpIt/Magnet - open source)  [~min, LARGE]'; key='memory';      fn={Job-Memory} }
    '2'  = @{ label='Artifact triage (Velociraptor/CyLR - hives+evtx+MFT+SRUM) [~min]';    key='artifacts';   fn={Job-Artifacts} }
    '3'  = @{ label='Full event-log export (.evtx copies)               [~min]';           key='eventlogs';   fn={Job-EventLogs} }
    '4'  = @{ label='Persistence + autoruns (Autorunsc/WMI/tasks/Run)   [fast]';           key='persistence'; fn={Job-Persistence} }
    '5'  = @{ label='Active Directory enumeration (+BloodHound if present)';                key='ad';          fn={Job-AD} }
    '6'  = @{ label='Browser artifacts (Chrome/Edge/Firefox)            [~min]';           key='browser';     fn={Job-Browser} }
    '7'  = @{ label='Full filesystem SHA-256 inventory                  [SLOW, hours]';     key='filehashes';  fn={Job-FileHashes} }
    '8'  = @{ label='Full disk image (raw/E01 imager if present)        [VERY SLOW]';       key='diskimage';   fn={Job-DiskImage} }
    '9'  = @{ label='Volume Shadow Copy state + anti-recovery (ransomware) [fast]';         key='vss';         fn={Job-VSS} }
    '10' = @{ label='Web-server logs + webroot timeline (webshell)      [~min]';            key='weblogs';     fn={Job-WebLogs} }
}
function Show-Menu {
    $rec = @($script:Plan)   # scenario-recommended job numbers (may be empty)
    Write-Host ""; Write-Host "================ STAGE 2: HEAVY COLLECTION MENU ================" -ForegroundColor Cyan
    Write-Host "Volatile data already secured. Choose heavy job(s) to run now." -ForegroundColor Gray
    if ($rec.Count) { Write-Host ("  >> Recommended for this scenario: " + ($rec -join ', ') + "   (press R to run just these)") -ForegroundColor Green }
    foreach ($k in $MenuItems.Keys) {
        $mk=$MenuItems[$k].key
        $mark = if($script:Done[$mk]){'[x]'}else{'[ ]'}
        $star = if($rec -contains $k){'*'}else{' '}
        $color = if($script:Done[$mk]){'DarkGray'}elseif($rec -contains $k){'Green'}else{'Gray'}
        Write-Host ("  {0}{1,2} {2} {3}" -f $star, $k, $mark, $MenuItems[$k].label) -ForegroundColor $color
    }
    Write-Host ""
    Write-Host "  Enter number(s) e.g. 1,3,4   |   R run recommended   A run ALL remaining   ? help   Q finish & seal" -ForegroundColor Cyan
    Write-Host ""
}
function Invoke-Menu {
    # self-heal: if input is redirected (no interactive console) run ALL rather than loop
    if ([Console]::IsInputRedirected) {
        Write-Audit "No interactive console - running ALL heavy jobs."
        foreach ($k in $MenuItems.Keys) { try { & $MenuItems[$k].fn } catch { Write-Audit "Job fault: $($_.Exception.Message)" } }
        return
    }
    $run = { param($k) if($script:Done[$MenuItems[$k].key]){ Write-Host "  $k already collected - skipping." -ForegroundColor DarkGray; return }
             try { & $MenuItems[$k].fn } catch { Write-Audit "Job fault: $($_.Exception.Message)" } }
    while ($true) {
        Show-Menu
        $c = try { (Read-Host "Select").Trim().ToUpper() } catch { 'Q' }
        if ($c -eq '') { continue }
        elseif ($c -eq 'Q') { break }
        elseif ($c -eq '?' -or $c -eq 'H') {
            Write-Host "  Enter one or more job numbers, comma/space separated (e.g. '1,3,4' or '2 5')." -ForegroundColor Gray
            Write-Host "  [x] = already collected this run.   * = recommended for the chosen scenario." -ForegroundColor Gray
            Write-Host "  R = run the recommended set.   A = run everything not yet done.   Q = finish & seal." -ForegroundColor Gray
        }
        elseif ($c -eq 'A') { foreach($k in $MenuItems.Keys){ if(-not $script:Done[$MenuItems[$k].key]){ & $run $k } } }
        elseif ($c -eq 'R') {
            $rec=@($script:Plan)
            if(-not $rec.Count){ Write-Host "  No scenario recommendation set - pick numbers or A." -ForegroundColor Yellow }
            else { foreach($k in $rec){ if($MenuItems.Contains("$k")){ & $run "$k" } } }
        }
        else {
            # multi-select: split on comma/whitespace, run each valid number in order
            $sel = @($c -split '[,\s]+' | Where-Object { $_ })
            $bad = @($sel | Where-Object { -not $MenuItems.Contains($_) })
            if ($bad.Count) { Write-Host "  Not on the menu: $($bad -join ', ')" -ForegroundColor Yellow }
            foreach($k in ($sel | Where-Object { $MenuItems.Contains($_) })) { & $run $k }
        }
    }
}

# ===========================================================================
# SEAL - manifest + report
# ===========================================================================
# Build the evidence-manifest script. Emitted as TEXT (not a scriptblock) because the manifest
# runs in a Start-Job child, which does not inherit script functions - so it must be self-contained.
# Factoring the generator out makes it unit-testable: see tests/unit/Test-ManifestScript.ps1.
#
# -Force is LOAD-BEARING. Without it Get-ChildItem skips hidden+system files, and the copied
# per-user hives (NTUSER.DAT, UsrClass.dat) carry those attributes - so on real range hosts every
# single one of them (17/17 on SQL01, 19/19 on WS02) was collected into evidence but absent from
# MANIFEST-SHA256.csv. An evidence manifest that silently omits the most valuable artifacts cannot
# support a tamper/corruption check on them, which is the whole point of having one.
function New-ManifestScript {
    param([Parameter(Mandatory)][string]$Dir)
    $script:HashShimText + @"
Get-ChildItem '$Dir' -Recurse -File -Force -ErrorAction SilentlyContinue |
  Where-Object { `$_.FullName -notmatch 'MANIFEST-SHA256\.csv$' -and `$_.FullName -notmatch '99_logs\\(audit|errors)\.log$' } |
  ForEach-Object { try { `$h=Get-IRSha256 `$_.FullName } catch { `$h='ERR' }
    '{0},{1},{2}' -f `$h, `$_.Length, `$_.FullName.Replace('$Dir','') }
"@
}

# An ENOSPC mid-append leaves a PARTIAL final record, so run_state.jsonl stops being valid JSONL
# and strict parsers choke on the very file that explains the failure. Keep only whole records.
# Called twice - before the rollup reads the ledger, and again after seal's own steps append.
function Repair-LedgerTail {
    try {
        if (-not (Test-Path $script:StateJsonl)) { return }
        $lines = [IO.File]::ReadAllLines($script:StateJsonl)
        if ($lines.Count -eq 0) { return }
        if ($lines[-1].TrimEnd().EndsWith('}')) { return }
        $keep = @($lines | Where-Object { $_.TrimEnd().EndsWith('}') })
        [IO.File]::WriteAllLines($script:StateJsonl, $keep)
        Write-Audit "LEDGER REPAIR: dropped a truncated final record from run_state.jsonl (kept $($keep.Count) complete records; destination likely filled)."
    } catch {}
}
function Invoke-Seal {
    Write-Audit "--- SEAL: manifest + report ---"; $L=$Dirs.logs
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
$(if($NoKeyCapture){'- **Encryption keys:** NOT captured (-NoKeyCapture). An image of an encrypted volume will not be readable without a custodian key.'}else{@'
> **HANDLING - this bundle contains VOLUME ENCRYPTION KEYS.** 00_metadata holds key material that
> decrypts the imaged volumes. Store and transfer it at the classification of the data it protects
> and record its custody. See 00_metadata\DECRYPTION-KEYS.md.
'@})
"@
    try { $summary | Out-File (Join-Path $OutDir 'SUMMARY.md') -Encoding UTF8 } catch {}
    try { $info.endUtc=$endUtc; $info.stepsOk=$script:StepsOk; $info.stepsFail=$script:StepsFail; $info.stepsTotal=$script:StepNum; $info.heavyJobs=$doneList
          [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'collection_info.json'), ($info | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) } catch {}
    # --- completion rollup + completeness verdict (reduce run_state.jsonl) ---
    $rsj = $script:StateJsonl; $nok=0; $nfail=0; $ntmo=0; $nskip=0; $nplan=0; $failedNames=@()
    $script:DiagClass=[ordered]@{}; $script:DiagRem=[ordered]@{}
    Repair-LedgerTail   # a truncated final record would break the reduction below
    if (Test-Path $rsj) {
        foreach ($ln in [IO.File]::ReadAllLines($rsj)) {
            if     ($ln -match '"ev":"ok"')      { $nok++ }
            elseif ($ln -match '"ev":"failed"')  { $nfail++ }
            elseif ($ln -match '"ev":"timeout"') { $ntmo++ }
            elseif ($ln -match '"ev":"skipped"') { $nskip++ }
            elseif ($ln -match '"ev":"planned"') { $nplan++ }
            if ($ln -match '"ev":"(failed|timeout)"') { try { $o=$ln|ConvertFrom-Json; if($o.name){$failedNames+=$o.name}; $ec=if($o.error_class){[string]$o.error_class}else{'unknown'}; if(-not $script:DiagClass.Contains($ec)){$script:DiagClass[$ec]=[ordered]@{count=0;sample=''}}; $script:DiagClass[$ec].count++; if((-not $script:DiagClass[$ec].sample) -and $o.error_msg){$script:DiagClass[$ec].sample=[string]$o.error_msg} } catch {} }
            elseif ($ln -match '"ev":"remediation"') { try { $o=$ln|ConvertFrom-Json; $ra="$($o.action)/$($o.result)"; if(-not $script:DiagRem.Contains($ra)){$script:DiagRem[$ra]=0}; $script:DiagRem[$ra]++ } catch {} }
        }
    }
    $incomplete = @($failedNames | Sort-Object -Unique)
    # carry the specific reason so the verdict tells the analyst what to fix, not just that RAM is missing
    if (-not $script:MemOk -and -not $RapidOnly) { $incomplete += "memory($($script:MemFailCode))" }
    # a destination that filled up means silent data loss somewhere - never seal that COMPLETE
    if ($script:DiskFull) { $incomplete += 'destination-full' }
    $verdict = if ($incomplete.Count -gt 0) { 'INCOMPLETE' } else { 'COMPLETE' }
    $rs = [ordered]@{
        schema='ir-collect/run-state@1'; tool='IR-Collect.ps1'; case=$CaseId; host=$hostName; output_dir=$OutDir
        ended_utc=$endUtc; status=$(if($verdict -eq 'COMPLETE'){'complete'}else{'partial'}); resumed=[bool]$Resume
        langMode="$($ExecutionContext.SessionState.LanguageMode)"; ps_version="$($PSVersionTable.PSVersion)"; elevated=[bool]$isAdmin
        counts=[ordered]@{ planned=$nplan; ok=$nok; failed=$nfail; timeout=$ntmo; skipped=$nskip }
        memory_verified=[bool]$script:MemOk
        completeness=[ordered]@{ verdict=$verdict; incomplete=@($incomplete) }
        diagnostics=[ordered]@{ exec_mode=$(if($script:JobsOk){'background-job'}else{'in-process(self-heal)'}); hash_backend=$script:HashBackend; by_error_class=$script:DiagClass; remediations=$script:DiagRem }
    }
    $rsPath = Join-Path $Dirs.logs 'run_state.json'
    $rsJson = $rs | ConvertTo-Json -Depth 5
    try { [IO.File]::WriteAllText($rsPath, $rsJson, (New-Object Text.UTF8Encoding($false))) } catch {}
    # If the destination is full that write silently produced nothing (or a 0-byte file) - the one
    # file an analyst opens to learn what went wrong, empty exactly when the run went wrong.
    # Put the rollup somewhere off the failing medium, loudly.
    if (-not (Test-Path $rsPath) -or ((Get-Item $rsPath -ErrorAction SilentlyContinue).Length -eq 0)) {
        foreach ($alt in @($env:TEMP, 'C:\Windows\Temp')) {
            if (-not $alt) { continue }
            try {
                $fb = Join-Path $alt ("ir-collect_run_state_{0}_{1}.json" -f $CaseId, $stamp)
                [IO.File]::WriteAllText($fb, $rsJson, (New-Object Text.UTF8Encoding($false)))
                Write-Audit "ROLLUP FALLBACK: evidence filesystem unwritable - run_state.json written to $fb"
                break
            } catch {}
        }
    }
    $comp = "`n## Completeness - $verdict`n- steps: ok=$nok failed=$nfail timeout=$ntmo skipped=$nskip (planned=$nplan)`n"
    if ($incomplete.Count -gt 0) { $comp += "- incomplete: $($incomplete -join ', ')`n" }
    $comp += "- resume: .\kit\IR-Collect.ps1 -CaseId '$CaseId' -Resume '$OutDir'`n"
    if (($script:DiagClass.Count -gt 0) -or (-not $script:JobsOk) -or ($script:HashBackend -ne 'Get-FileHash')) {
        $comp += "`n## Diagnostics (self-diagnosis)`n- exec mode: $(if($script:JobsOk){'background-job'}else{'in-process fallback (job subsystem unavailable)'})`n"
        $comp += "- hash backend: $script:HashBackend$(if($script:HashBackend -ne 'Get-FileHash'){' (Get-FileHash unavailable on this host - .NET fallback in use)'})`n"
        foreach($k in $script:DiagClass.Keys){ $sm=$script:DiagClass[$k].sample; $comp += "- ${k}: $($script:DiagClass[$k].count) step(s)$(if($sm){" - e.g. $sm"})`n" }
        if ($script:DiagRem.Count -gt 0) { $comp += "- self-heal actions: " + (($script:DiagRem.GetEnumerator()|ForEach-Object{"$($_.Key) x$($_.Value)"}) -join ', ') + "`n" }
    }
    try { Add-Content -Path (Join-Path $OutDir 'SUMMARY.md') -Value $comp -Encoding UTF8 } catch {}
    $script:RunIncomplete = ($verdict -eq 'INCOMPLETE')
    Write-Audit "COMPLETENESS $verdict | ok=$nok fail=$nfail timeout=$ntmo skip=$nskip planned=$nplan"
    # Document the manifest's own gaps INSIDE the bundle. Four files cannot be in
    # MANIFEST-SHA256.csv (it is being written, or they are produced after it), and a verifier
    # who finds unlisted files has no way to tell "deliberately excluded" from "tampered".
    # Written BEFORE the manifest step so this note is itself covered by the manifest.
    $exclNote = @"
MANIFEST-SHA256.csv coverage
============================
Format (headerless): <sha256>,<length>,<path relative to the evidence root>
It covers every file in the evidence tree, INCLUDING hidden/system ones (the per-user
registry hives NTUSER.DAT and UsrClass.dat carry those attributes).

Deliberately NOT listed, and why:
  99_logs/MANIFEST-SHA256.csv   the manifest cannot hash itself
  99_logs/audit.log             still being appended to while the manifest runs
  99_logs/errors.log            same
  99_logs/audit.frozen.log      created after the manifest - a frozen snapshot of audit.log,
                                hashed separately into MANIFEST-audit-log.sha256
  MANIFEST-audit-log.sha256     created after the manifest; holds the hash above

Anything else absent from the manifest was NOT excluded by design - treat it as unexplained.
"@
    try { [IO.File]::WriteAllText((Join-Path $L 'MANIFEST-README.txt'), $exclNote, (New-Object Text.UTF8Encoding($false))) } catch {}
    # manifest LAST so it covers SUMMARY.md + final collection_info.json (fixed literal path strip)
    Invoke-Step 'manifest-sha256' ([scriptblock]::Create((New-ManifestScript $OutDir))) 'MANIFEST-SHA256.csv' $L -TimeoutSec 1800 | Out-Null

    # freeze + hash the custody trail itself. audit.log is excluded from the manifest above because it
    # is still being written when the manifest runs; snapshot a frozen copy and hash THAT so the
    # timeline record has an integrity seal too.
    try {
        Copy-Item $AuditLog (Join-Path $L 'audit.frozen.log') -Force -ErrorAction SilentlyContinue
        Repair-LedgerTail   # seal's own steps append after pass 1; re-check before freezing custody
        $ah = Get-IRSha256 (Join-Path $L 'audit.frozen.log')
        [IO.File]::WriteAllText((Join-Path $OutDir 'MANIFEST-audit-log.sha256'), "$ah  99_logs/audit.frozen.log`n", (New-Object Text.UTF8Encoding($false)))
        Write-Audit "Custody trail frozen + hashed: $ah"
    } catch { Write-Audit "Could not freeze/hash audit.log: $($_.Exception.Message)" }

    # --- ship the sealed bundle: SMB/UNC share and/or HTTP(S) POST to a lab collector ---
    if ($NetworkDest -or $HttpDest) {
        Write-Audit "Sealing + shipping evidence ($(if($HttpDest){"HTTP $HttpDest"}else{$NetworkDest}))"
        $zip = "$OutDir.zip"
        if ("$($ExecutionContext.SessionState.LanguageMode)" -eq 'FullLanguage') {
            $zipSb = "Add-Type -AssemblyName System.IO.Compression.FileSystem; if(Test-Path '$zip'){Remove-Item '$zip' -Force}; [System.IO.Compression.ZipFile]::CreateFromDirectory('$OutDir','$zip')"
        } else {
            $zipSb = "Compress-Archive -Path '$OutDir\*' -DestinationPath '$zip' -Force"   # CLM-safe (cmdlet); may fail >2GB
        }
        Invoke-Step 'seal-zip' ([scriptblock]::Create($zipSb)) $null $Dirs.logs -TimeoutSec 3600 -Retries 0 | Out-Null
        if (-not (Test-Path $zip) -and $NetworkDest -and -not $Cred) {
            Write-Audit "seal-zip produced no archive - shipping raw folder via robocopy instead."
            Invoke-Step 'ship-folder' ([scriptblock]::Create("robocopy '$OutDir' '$NetworkDest\$(Split-Path $OutDir -Leaf)' /E /Z /R:1 /W:1 /NFL /NDL /NP")) $null $Dirs.logs -TimeoutSec 7200 -Retries 0 | Out-Null
        }
        try { (Get-IRSha256 $zip) | Out-File "$zip.sha256" -Encoding ASCII } catch {}
        if ($NetworkDest) {
            try {
                if ($Cred) { New-PSDrive -Name IRDEST -PSProvider FileSystem -Root $NetworkDest -Credential $Cred -ErrorAction Stop | Out-Null; $tgt='IRDEST:\' }
                else       { $tgt = $NetworkDest }
                Copy-Item "$zip","$zip.sha256" $tgt -Force -ErrorAction Stop
                Write-Audit "Ship OK -> $NetworkDest"; Write-Host "Shipped $(Split-Path $zip -Leaf) to $NetworkDest" -ForegroundColor Green
            } catch {
                Write-Audit "Ship FAILED: $($_.Exception.Message). Evidence retained locally at $zip"
                Write-Host "Network ship failed - evidence kept locally: $zip" -ForegroundColor Yellow
            } finally { try { Remove-PSDrive IRDEST -ErrorAction SilentlyContinue } catch {} }
        }
        if ($HttpDest -and (Test-Path $zip)) {
            # POST/PUT the bundle to a lab collector (e.g. an uploadserver / range results endpoint)
            try {
                $u = if ($HttpDest.EndsWith('/')) { $HttpDest + (Split-Path $zip -Leaf) } else { $HttpDest }
                try   { Invoke-RestMethod -Uri $u -Method Put -InFile $zip -TimeoutSec 3600 -ErrorAction Stop | Out-Null }
                catch { Invoke-WebRequest -Uri $HttpDest -Method Post -InFile $zip -ContentType 'application/zip' -TimeoutSec 3600 -UseBasicParsing -ErrorAction Stop | Out-Null }
                Write-Audit "HTTP upload OK -> $HttpDest"; Write-Host "Uploaded $(Split-Path $zip -Leaf) to $HttpDest" -ForegroundColor Green
            } catch {
                Write-Audit "HTTP upload FAILED: $($_.Exception.Message). Evidence retained locally at $zip"
                Write-Host "HTTP upload failed - evidence kept locally: $zip" -ForegroundColor Yellow
            }
        }
    }

    if ($Lab -and -not $NetworkDest -and -not $HttpDest) {
        $leaf = Split-Path $OutDir -Leaf
        $hint = switch ($script:Hypervisor) {
            'vmware'     { "govc guest.download -vm <VM> -l <user>:<pass> '$OutDir' ./$leaf  (VMware Tools guest ops)" }
            'virtualbox' { "VBoxManage guestcontrol <VM> copyfrom --username <u> --password <p> --recursive '$OutDir' './$leaf'" }
            'hyper-v'    { "PowerShell Direct: Copy-Item -FromSession (New-PSSession -VMName <VM> -Credential (Get-Credential)) '$OutDir' -Destination ./$leaf -Recurse" }
            'qemu-kvm'   { "Proxmox/QEMU: qm guest exec <vmid> -- tar czf - '$OutDir' > $leaf.tgz , or mount the guest disk / shared folder" }
            default      { "Pull '$OutDir' via your hypervisor's guest file-copy or a shared folder, or re-run with -Dest <IP|\\share|http://collector>." }
        }
        Write-Host "LAB: evidence left in-guest at $OutDir. Host-side pull:" -ForegroundColor Cyan
        Write-Host "  $hint" -ForegroundColor Gray
        Write-Audit "LAB host-pull hint ($script:Hypervisor): $hint"
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

# Incident SCENARIOS: each is a profile overlay on the constant RFC 3227 base collection -
# it reprioritises which heavy jobs auto-run (plan), tags ATT&CK, and records the uniquely
# perishable "grab first" item + a SOC-handoff caveat. 'U' = today's broad default (no change).
$Scenarios = [ordered]@{
  '1'  = @{ name='Ransomware / destructive';                        plan=@('1','9','2','3','4'); attack=@('T1486','T1490','T1489','T1562.001'); first='RAM FIRST (encryption keys/beacon may be resident), then PRESERVE Volume Shadow Copies (job 9) before malware or an admin deletes them, then $MFT/$UsnJrnl timeline via triage (job 2). DO NOT reboot.'; note='Also grab a ransom note + a sample encrypted file for family ID.' }
  '2'  = @{ name='BEC / cloud (M365/Entra) account compromise';     plan=@('6','2','3');         attack=@('T1078.004','T1114.003','T1098.002','T1528','T1556.006'); first='Mostly an OFF-HOST / cloud investigation: pull the M365 Unified Audit Log + Entra sign-in/audit logs, inbox-forwarding rules, mailbox delegates, OAuth grants (see docs/SCENARIOS.md). On this host only browser tokens/cookies matter, if it was the theft origin.'; note='Endpoint collection is secondary here; detection content is cloud-log-based, not Suricata/Zeek.' }
  '3'  = @{ name='Insider threat / data exfiltration';              plan=@('2','4','7','6');     attack=@('T1567.002','T1052.001','T1560','T1048'); first='Live process/handles + current network (rclone/scp/upload in flight) + mounted removable volumes while the session is live. Then USB history + SRUM (bytes-sent) via triage (job 2).'; note='Behaviour over IOCs (insiders use legit tools). Hash the sensitive share (job 7) to prove what left.' }
  '4'  = @{ name='Web-server / public-app compromise (webshell)';   plan=@('10','1','2','3','4');attack=@('T1190','T1505.003','T1059','T1105'); first='Live netstat + process tree of the web service FIRST (in-memory-only shells leave nothing on disk), then web logs + webroot timeline (job 10).'; note='The tell is w3wp/httpd/php-fpm spawning cmd/powershell/sh. Web logs are outside default triage - job 10 adds them.' }
  '5'  = @{ name='Commodity malware / C2 beacon';                   plan=@('1','2','3','4');     attack=@('T1071.001','T1071.004','T1573','T1055','T1569.002'); first='RAM FIRST (beacon config / injected shellcode is memory-only), then live net-conn->PID->binary-hash, DNS cache, named pipes.'; note='Add JA3 + beacon-interval hunts to the handoff.' }
  '6'  = @{ name='Active Directory / Domain-Controller compromise'; plan=@('3','5','2','4');     attack=@('T1003.006','T1558.001','T1207','T1003.003'); first='EXPORT THE DC SECURITY EVENT LOG IMMEDIATELY (busy DCs roll logs in hours - the most perishable evidence here), plus current Kerberos tickets + sessions.'; note='On a DC prefer a snapshot/dead-box over live tools. AD compromise is inherently MULTI-HOST - collect from ALL DCs (fan-out).' }
  '7'  = @{ name='Lateral movement / credential theft';             plan=@('3','2','4','5');     attack=@('T1021.001','T1021.002','T1003.001','T1550.002','T1569.002'); first='Logon telemetry (4624/4625 type 3/10, 4648, 4672), RDP artifacts, LSASS-access (Sysmon 10), cached tickets + live sessions.'; note='Correlate logon type across the host pair. Strongest single-vs-fleet trigger - promote to a Velociraptor hunt (fan-out).' }
  '8'  = @{ name='Living-off-the-land / fileless';                  plan=@('1','3','4','2');     attack=@('T1059','T1218','T1047','T1546.003'); first='RAM + live process command lines (fileless = memory-only). Capture PowerShell scriptblock/transcript (4104/4103) and the WMI repository (OBJECTS.DATA).'; note='Emit a LOLBin execution report from 4688/Sysmon1 vs a LOLBAS list.' }
  '9'  = @{ name='Phishing initial access (workstation)';           plan=@('6','2','3','4');     attack=@('T1566.001','T1204.002','T1059.005','T1218'); first='Browser session/cookies (AiTM token theft), running first-stage process, %TEMP% before cleanup.'; note='Hunt Office (WINWORD/EXCEL/OUTLOOK)->cmd/powershell/mshta. Often chains to C2/lateral - add those as secondary.' }
  '10' = @{ name='Cryptomining';                                    plan=@('4','2','3');         attack=@('T1496','T1543.003','T1053.005'); first='Live high-CPU/GPU process + cmdline + pool connections, then persistence (cron/service/task).'; note='Usually a symptom of a broader compromise - consider C2-beacon as secondary. Check for rootkit-hidden PIDs.' }
  'A'  = @{ name='FULL forensic sweep (no scenario yet) - order-of-volatility + all analysis artifacts'; plan=@('1','2','3','9','4','5','6','10'); attack=@(); first='No specific lead: capture EVERYTHING our tools analyse, in RFC 3227 order of volatility - RAM -> artifact triage (hives/EVTX/$MFT/SRUM) -> event logs -> Volume Shadow state -> persistence -> AD -> browser -> web logs.'; note='Do-everything default when you have no scenario. The two hours-long GROUND-TRUTH steps stay opt-in: add job 7 (full-FS SHA-256) / job 8 (full-disk image) from the Stage-2 menu (or -Auto) for a dead-box baseline.' }
  'U'  = @{ name='Unknown / broad triage';                          plan=@();                    attack=@(); first='Standard RFC 3227 order-of-volatility triage (RAM -> processes -> network -> artifacts).'; note='Default behaviour - no reprioritisation.' }
}

function Invoke-GuidedIntake {
    $script:Intake = [ordered]@{ case_id=$CaseId; exercise=[bool]$Lab; generated_by='IR-Collect.ps1' }
    Write-Host ""; Write-Host "================ GUIDED INTAKE ================" -ForegroundColor Cyan

    Write-Host "-- Vantage check: is running on THIS box the right move? --" -ForegroundColor Gray
    $isVmCloud = (Read-Def "Is this host a VM or cloud instance? (y/N)" 'N') -match '^[yY]'
    if ($isVmCloud) { Write-Host "  -> Prefer a SNAPSHOT (VMware .vmem/.vmdk or cloud disk snapshot to a clean forensic instance). Run this only if you can't snapshot." -ForegroundColor Yellow }
    $c2live = (Read-Def "Is C2 / active attacker traffic believed LIVE now? (y/N)" 'N') -match '^[yY]'
    if ($c2live) { Write-Host "  -> Capture NETWORK first, OFF-host (PCAP at a TAP/SPAN; firewall/proxy/DNS logs). Running me can tip the attacker; keep enrichment PASSIVE." -ForegroundColor Yellow }

    Write-Host ""; Write-Host "-- Incident scenario (drives collection order + detection handoff) --" -ForegroundColor Gray
    Write-Host "   (No scenario yet? Choose A = full order-of-volatility sweep + everything our tools analyse.)" -ForegroundColor DarkGray
    foreach($k in $Scenarios.Keys){ Write-Host ("  {0,-3} {1}" -f $k, $Scenarios[$k].name) }
    $sc = (Read-Def "Select scenario" 'A').ToUpper(); if (-not $Scenarios.Contains($sc)) { $sc='A' }
    $scen = $Scenarios[$sc]
    Write-Host ("  -> FIRST: {0}" -f $scen.first) -ForegroundColor Yellow
    if ($scen.note) { Write-Host ("     NOTE:  {0}" -f $scen.note) -ForegroundColor DarkYellow }
    $script:Intake.scenario = $sc; $script:Intake.scenario_name = $scen.name; $script:Intake.attack_tags = @($scen.attack)

    # -- mobile device trigger: a phone is often the real endpoint (BEC token / smishing / exfil target) --
    $mobMap = @{ '2'='bec'; '3'='exfil'; '9'='smish'; '5'='beacon'; '10'='spyware'; '6'='token'; '7'='token'; '1'='ransom' }
    $mobProf = if ($mobMap.ContainsKey($sc)) { $mobMap[$sc] } else { 'U' }
    if ((Read-Def "Was a MOBILE device involved (victim / exfil target / MFA-auth / lateral)? (y/N)" 'N') -match '^[yY]') {
        $script:Intake.mobile_involved = $true; $script:Intake.mobile_profile = $mobProf
        Write-Host "  -> Acquire the phone from an EXAMINER box (see docs/MOBILE.md). Suggested command:" -ForegroundColor Yellow
        Write-Host ("     ./mobile-collect.sh -c {0} -d <dest> --android|--ios --scenario {1} --analyze --faraday --authorizer '{2}'" -f $CaseId,$mobProf,$Authorizer) -ForegroundColor Gray
    } else { $script:Intake.mobile_involved = $false }

    Write-Host ""; Write-Host "-- Host role / environment --" -ForegroundColor Gray
    Write-Host "  [1] Workstation  [2] Server  [3] Domain Controller  [4] Cloud VM  [5] Container/k8s node  [6] OT/ICS  [7] Network device"
    $roleDef = if ($info.os -match 'Server') { '2' } else { '1' }
    $role = Read-Def "Select role" $roleDef
    $roleName = @{'1'='workstation';'2'='server';'3'='domain-controller';'4'='cloud-vm';'5'='container';'6'='ot-ics';'7'='network-device'}[$role]; if(-not $roleName){$roleName='workstation'}
    $script:Intake.host_role = $roleName
    switch ($roleName) {
        'server'            { Write-Host "  -> Server: prioritising services/tasks + app/IIS logs; de-prioritising browser. Avoid live full-disk image on prod." -ForegroundColor Yellow }
        'domain-controller' { Write-Host "  -> DC: strongly prefer a SNAPSHOT/dead-box. NTDS.dit+SYSTEM via VSS, huge Security log; never disrupt replication. Collect from ALL DCs." -ForegroundColor Yellow }
        'cloud-vm'          { Write-Host "  -> Cloud VM: prefer a disk SNAPSHOT to a clean forensic instance; also pull cloud control-plane logs (CloudTrail/Activity/Audit)." -ForegroundColor Yellow }
        'container'         { Write-Host "  -> Container/k8s: capture running-container state FAST (docker/crictl ps, image digests, diffs, SA tokens, kube audit) - pods are ephemeral. This tool captures the NODE." -ForegroundColor Yellow }
        'ot-ics'            { $script:DoNoHarm=$true; Write-Host "  -> OT/ICS DO-NO-HARM mode: no filesystem-hash walk / disk image / active enum. Host-only + passive. Availability > evidence." -ForegroundColor Red }
        'network-device'    { Write-Host "  -> Network device: collect OFF-box (config, ARP/CAM, routing, syslog, NetFlow) via console - this host tool does not apply." -ForegroundColor Yellow }
    }

    $scope = Read-Def "Scope: single host or fleet? (s/F)" 's'
    if ($scope -match '^[fF]') { Write-Host "  -> Fleet: promote to a Velociraptor HUNT (in .\tools) - collection becomes a targeted VQL artifact set, not USB-per-box." -ForegroundColor Yellow }
    $script:Intake.scope = $(if($scope -match '^[fF]'){'fleet'}else{'single'})
    $conn = Read-Def "Connectivity: connected or airgapped/quarantined? (c/A)" 'c'
    $script:Intake.connectivity = $(if($conn -match '^[aA]'){'airgapped'}else{'connected'})

    Write-Host ""; Write-Host "-- Known-bad indicators you already hold (comma-separated, Enter to skip) --" -ForegroundColor Gray
    $script:Intake.known_bad_ips      = @((Read-Def "  Malicious IPs" '')       -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_domains  = @((Read-Def "  Malicious domains" '')   -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_hashes   = @((Read-Def "  Malicious hashes" '')    -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_accounts = @((Read-Def "  Suspect accounts" '')    -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_paths    = @((Read-Def "  Suspect files/paths" '') -split ','      | Where-Object { $_ })

    Write-Host ""; Write-Host "-- Scope-out (Enter to skip) --" -ForegroundColor Gray
    $script:Intake.first_activity_utc = Read-Def "Earliest suspected activity (UTC)" ''
    $script:Intake.detection_utc      = Read-Def "When detected (UTC)" ''
    $script:Intake.crown_jewels       = Read-Def "Crown jewels in scope (DC/finance/PII/source?)" ''
    $script:Intake.data_at_risk       = Read-Def "Data at risk (PII/PHI/PCI/IP/creds/none)" 'unknown'
    $script:Intake.severity           = Read-Def "Severity 1-4 (1=critical)" '3'
    $script:Intake.is_vm_cloud = [bool]$isVmCloud; $script:Intake.attacker_c2_live = [bool]$c2live

    $script:Compromised = ((Read-Def "Is this host believed COMPROMISED? (Y/n)" 'Y') -notmatch '^[nN]')
    if ($script:Compromised) { Write-Host "  -> Trusted-tool posture (carried tools + kernel APIs). RAM + dead-box image are ground truth." -ForegroundColor Yellow }
    $enc = $false; try { $enc = [bool](Get-BitLockerVolume 2>$null | Where-Object { $_.ProtectionStatus -eq 'On' }) } catch {}
    if ($enc) { Write-Host "  -> BitLocker DETECTED. Keys captured in Stage 1 (00_metadata\bitlocker_keys.txt) - REQUIRED before any dead-box image." -ForegroundColor Yellow }

    # build the collection plan from scenario + role
    $plan = @($scen.plan)
    if (-not $plan.Count) { $plan = @('2','3','4','6'); if ($domainJoined) { $plan += '5' } }        # broad default
    if ($roleName -in 'server','domain-controller') { $plan = @($plan | Where-Object { $_ -ne '6' }) } # drop browser on servers
    if ($roleName -eq 'domain-controller' -and $domainJoined -and $plan -notcontains '5') { $plan += '5' }
    if ($script:DoNoHarm) { $plan = @($plan | Where-Object { $_ -notin '7','8' }) }                    # OT: no hash-walk / disk image
    if ($SkipAD) { $plan = @($plan | Where-Object { $_ -ne '5' }) }
    $script:Plan = @($plan | Select-Object -Unique)
    $script:Intake.plan = $script:Plan

    $planNames = ($script:Plan | ForEach-Object { $MenuItems[$_].key }) -join ', '
    Write-Host ""; Write-Host ("Plan: RAM+volatile -> GREEN gate -> {0}" -f $(if($planNames){$planNames}else{'seal (volatile only)'})) -ForegroundColor Green
    Write-Host ("Scenario: {0}  |  Role: {1}  |  Scope: {2}  |  ATT&CK: {3}" -f $scen.name,$roleName,$script:Intake.scope,($scen.attack -join ',')) -ForegroundColor DarkGray
    try { [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'intake.json'), ($script:Intake | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false))) } catch {}
    Write-Audit "INTAKE scenario=$sc role=$roleName scope=$($script:Intake.scope) plan=$($script:Plan -join ',') seedIOCs=$(($script:Intake.known_bad_ips.Count + $script:Intake.known_bad_domains.Count + $script:Intake.known_bad_hashes.Count))"
    [void](Read-Def "Press Enter to begin (Ctrl-C to abort)" '')
}

function Set-IntakeAuto {
    # non-interactive twin of Invoke-GuidedIntake: same catalog, same plan logic, zero prompts.
    $sc = if ($Scenarios.Contains($Scenario)) { $Scenario } else { 'U' }
    $scen = $Scenarios[$sc]
    $roleName = if ($HostRole) { $HostRole.ToLower() } elseif ($info.os -match 'Server') { 'server' } else { 'workstation' }
    if ($roleName -notin 'workstation','server','domain-controller','cloud-vm','container','ot-ics','network-device') { $roleName='workstation' }
    $script:Intake = [ordered]@{ case_id=$CaseId; exercise=[bool]$Lab; generated_by='IR-Collect.ps1'; noninteractive=$true }
    $script:Intake.scenario = $sc; $script:Intake.scenario_name = $scen.name; $script:Intake.attack_tags = @($scen.attack)
    $mobMap = @{ '2'='bec'; '3'='exfil'; '9'='smish'; '5'='beacon'; '10'='spyware'; '6'='token'; '7'='token'; '1'='ransom' }
    $script:Intake.mobile_involved = $false
    if ($mobMap.ContainsKey($sc)) { $script:Intake.mobile_profile = $mobMap[$sc] }
    $script:Intake.host_role = $roleName
    if ($roleName -eq 'ot-ics') { $script:DoNoHarm = $true }
    $script:Intake.scope = 'single'; $script:Intake.connectivity = 'connected'
    $script:Intake.known_bad_ips     = @(($KnownBadIps)     -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_domains = @(($KnownBadDomains) -split '[, ]+' | Where-Object { $_ })
    $script:Intake.known_bad_hashes  = @(($KnownBadHashes)  -split '[, ]+' | Where-Object { $_ })
    # collection plan: identical rules to the guided path
    $plan = @($scen.plan)
    if (-not $plan.Count) { $plan = @('2','3','4','6'); if ($domainJoined) { $plan += '5' } }
    if ($roleName -in 'server','domain-controller') { $plan = @($plan | Where-Object { $_ -ne '6' }) }
    if ($roleName -eq 'domain-controller' -and $domainJoined -and $plan -notcontains '5') { $plan += '5' }
    if ($script:DoNoHarm) { $plan = @($plan | Where-Object { $_ -notin '7','8' }) }
    if ($SkipAD) { $plan = @($plan | Where-Object { $_ -ne '5' }) }
    $script:Plan = @($plan | Select-Object -Unique)
    $script:Intake.plan = $script:Plan
    try { [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'intake.json'), ($script:Intake | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false))) } catch {}
    Write-Audit "INTAKE(auto) scenario=$sc ($($scen.name)) role=$roleName plan=$($script:Plan -join ',') attack=$($scen.attack -join ',') seedIOCs=$(($script:Intake.known_bad_ips.Count + $script:Intake.known_bad_domains.Count + $script:Intake.known_bad_hashes.Count))"
}

# ===========================================================================
# MAIN  (self-heal: Seal ALWAYS runs, even if a phase throws)
# ===========================================================================
$script:Sealed = $false; $script:Plan = $null; $script:VolatileOnly = $false; $script:DoNoHarm = $false; $script:RunIncomplete = $false
function Complete-Run { if (-not $script:Sealed) { $script:Sealed = $true; try { Invoke-Seal } catch { Write-Audit "Seal error: $($_.Exception.Message)" } } }
# interrupt-safety: a hard Ctrl-C / console-close during the long Stage-2 phase must still seal.
try { [Console]::add_CancelKeyPress({ param($s,$e) $e.Cancel=$true; Write-Host "`nInterrupt - sealing evidence before exit..." -ForegroundColor Yellow; try { Complete-Run } catch {} }) } catch {}
try { Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action { try { Complete-Run } catch {} } | Out-Null } catch {}

# guided intake is the default when interactive and no mode flag was given
if ($Resume) { Import-PriorState $OutDir }
if ($Scenario) {
    try { Set-IntakeAuto } catch { Write-Audit "Auto-intake failed: $($_.Exception.Message)" }
} elseif (-not $Auto -and -not $RapidOnly -and -not [Console]::IsInputRedirected) {
    try { Invoke-GuidedIntake } catch { Write-Audit "Guided intake skipped: $($_.Exception.Message)" }
}

try {
    try { Invoke-RapidVolatile } catch { Write-Audit "RapidVolatile fault: $($_.Exception.Message) - continuing." }
    Show-VolatileGate

    if ($RapidOnly -or $script:VolatileOnly) {
        Write-Host "Volatile-only - sealing." -ForegroundColor Yellow
    } elseif ($Auto) {
        # -Auto is unattended triage: skip the two hours-long GROUND-TRUTH jobs (7 full-FS hash, 8 disk image)
        # unless -IncludeGroundTruth is given, so an automated run actually finishes in minutes not hours.
        # run scenario-relevant jobs FIRST (so the important evidence is secured before unrelated
        # jobs), then everything else in menu order; ground-truth 7/8 excluded unless requested.
        $order = @(); if ($script:Plan) { $order += @($script:Plan) }; $order += @($MenuItems.Keys)
        $autoJobs = @($order | Where-Object { $MenuItems.Contains("$_") -and ($IncludeGroundTruth -or ("$_" -notin '7','8')) } | Select-Object -Unique)
        Write-Audit ("Auto mode: order=$($autoJobs -join ',') " + $(if($IncludeGroundTruth){'INCLUDING ground-truth 7/8'}else{'EXCEPT hours-long ground-truth 7(full-FS hash)/8(disk image); pass -IncludeGroundTruth to add them'}) + ".")
        foreach ($k in $autoJobs) { try { & $MenuItems[$k].fn } catch { Write-Audit "Job $($MenuItems[$k].key) fault: $($_.Exception.Message) - continuing." } }
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

# --- exit-code contract: 0 clean | 10 completed-with-skips | 15 incomplete-critical | 20 RAM not verified | 40 fatal ---
$exitCode = 0
# ascending severity - the LAST condition that holds wins, so 20 (no RAM) is not masked by 15.
# (It was: no-verified-RAM also sets RunIncomplete, so exit 20 could never be observed.)
if ($script:StepsFail -gt 0) { $exitCode = 10 }
if ($script:RunIncomplete) { $exitCode = 15 }
if (-not $script:MemOk -and -not $RapidOnly) { $exitCode = 20 }
Write-Audit "EXIT $exitCode (0=clean 10=skips 15=incomplete-critical 20=no-RAM 40=fatal)"
exit $exitCode
