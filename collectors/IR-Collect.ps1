#requires -Version 3
# ^ Refuse to START on PowerShell 2.0 rather than half-run on it. The script uses
# [pscustomobject] (12x), Get-CimInstance (25x) and [ordered] hashtables (21x), none of which
# exist in v2 - so without this it parses, begins collecting, and dies partway through with
# errors that look like a broken host rather than a wrong interpreter.
#
# Scenario E5, measured on range-WS02 2026-07-29: the PS 2.0 FEATURE is Enabled there, but
# .NET 2.0 is absent, so `powershell -Version 2` refuses on its own ("Version v2.0.50727 of the
# .NET Framework is not installed"). That refusal is host-specific - on a legacy host that does
# have .NET 2.0 (Server 2008 R2, Win7 - exactly the machines a live-response collector still
# meets) nothing would have stopped it. #requires makes the refusal universal and immediate,
# which is what the A6 precedent asks for: let the host refuse, but only if it actually will.

<#
.SYNOPSIS
    IR-Collect - self-healing incident-response collector for Windows (two-stage: rapid volatile + menu).

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

    READING THE VERDICT. 99_logs\run_state.json carries machine-readable findings that the console
    summary states only in passing. Four are worth knowing before you act on a bundle:

    encryption_risk - THE DO-NOT-POWER-OFF SIGNAL, and it has three states because the third one
    is the whole point:
      ok                a shutdown costs nothing (RAM was captured, or no encrypted volume found).
      encrypted-no-ram  an unlocked encrypted volume IS present and RAM was NOT captured. Power the
                        host off and the disk image is unreadable. Capture keys or RAM first.
      unknown-no-ram    the probe COULD NOT DETERMINE whether a volume is encrypted - the BitLocker
                        cmdlets and manage-bde both failed. This is NOT a claim that the disk is
                        clear, and not a claim that it is encrypted. Treat it as encrypted-no-ram
                        until a human establishes otherwise.

    cim_evidence - the PROVENANCE of the collected content, not its contents. A dead WMI is itself
    a finding: it can mean a broken host, and it can mean an intruder disabled it.

    subsystem_probe - whether a subsystem answered at all. 'insufficient-evidence' means the probe
    could not reach a conclusion; it is not a clean bill of health.

    by_error_class - a tally of failures by kind. AN EMPTY MAP DOES NOT MEAN NOTHING WENT WRONG:
    conditions such as a preflight refusal, or a destination that cannot be written, are handled
    before any class could be assigned. Read completeness.verdict and the counts, not the absence
    of classes. Ship results, when shipping was requested, are in <bundle>.ship.json.

.PARAMETER Dest
    Case folder location - an external drive path, a UNC \\IP\share, or a bare IP. Aliased as
    -OutputRoot. Default: the script's own directory.
.PARAMETER Share
    SMB share name to use when -Dest is given as a bare IP. Default: evidence.
.PARAMETER Cred
    Optional credentials for the network share.
.PARAMETER CaseId
    Case identifier. Default: IR.
.PARAMETER StepTimeoutSec
    Default per-step timeout in seconds. Default: 120.
.PARAMETER Auto
    Run Stage 1 then all Stage-2 jobs EXCEPT the two hours-long ground-truth jobs (full-filesystem
    SHA-256 and full-disk image); no menu. Practical unattended triage.
.PARAMETER IncludeGroundTruth
    With -Auto, also run the hours-long ground-truth jobs (7 full-FS hash, 8 disk image).
.PARAMETER RapidOnly
    Run only Stage 1 (volatile) and seal.
.PARAMETER SkipAD
    Never run the Active Directory phase.
.PARAMETER DeferMemory
    Capture RAM AFTER the volatile-command battery instead of before it.
.PARAMETER NoKeyCapture
    Skip BitLocker recovery-password / key-package capture. By default the collector grabs them
    while the volume is unlocked, because a dead-box image of an encrypted disk is unreadable
    without a key. Those outputs ARE the keys to the evidence - see 00_metadata\DECRYPTION-KEYS.md.
    Use this where extracting key material is outside the engagement's scope.
.PARAMETER AllowConstrainedLanguage
    Proceed even though PowerShell is in ConstrainedLanguage mode. By default the collector REFUSES
    (exit 40): in that mode step construction and all hashing are blocked, so it cannot produce a
    manifest or custody digests, and the writable probe fails in a way that can redirect evidence
    onto the target's system drive. Prefer the native triage binaries in .\tools, or off-host
    acquisition. This switch collects partial, UNVERIFIABLE volatile data.
.PARAMETER Lab
    Training/exercise mode: read-only-media launch, VM detection, HTTP egress, relaxed
    contamination rules. Not for real evidence.
.PARAMETER Authorizer
    Who authorized this collection. Recorded for chain of custody.
.PARAMETER LegalBasis
    Authority or legal basis for the collection (IR engagement, warrant, consent, ...).
.PARAMETER ScopeNote
    The authorized scope of collection.
.PARAMETER Resume
    Resume a prior run: point at its output directory. Only unsatisfied steps are re-run.
.PARAMETER Scenario
    Non-interactive scenario id (1-10 or U). Injects intake and plan with no prompts, for
    automation, lab and end-to-end use.
.PARAMETER HostRole
    Non-interactive host role: workstation, server, domain-controller, cloud-vm, container,
    ot-ics or network-device.
.PARAMETER KnownBadIps
    Comma- or space-separated seed IOCs, folded into intake.json.
.PARAMETER KnownBadDomains
    Comma- or space-separated seed domain IOCs, folded into intake.json.
.PARAMETER KnownBadHashes
    Comma- or space-separated seed file-hash IOCs, folded into intake.json.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -Dest E:\evidence -CaseId CASE001

    Interactive: Stage 1 runs immediately, then the Stage-2 menu is offered.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -Auto

    Full unattended triage, skipping only the two hours-long ground-truth jobs.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -RapidOnly -Dest \\10.0.0.5\evidence

    Volatile capture only, written straight to a network share.

.NOTES
    Exit codes: 0 clean | 10 completed-with-skips | 15 incomplete-critical | 20 RAM not verified
    | 40 fatal.

    Run elevated. Read-only with respect to the evidence disk - the collector writes only under
    -Dest.

    KEYWORD PLACEMENT MATTERS HERE. .NOTES and .EXAMPLE text MUST start on the line after the
    keyword: with it on the same line, PowerShell silently discards the ENTIRE comment-based help
    block and Get-Help falls back to an auto-generated syntax stub. .PARAMETER is worse, because it
    fails quietly in a different way - the block still renders, but every same-line description is
    dropped. That is how this help sat dead in the repo: 50 lines of accurate documentation that
    Get-Help never showed anyone. tests/unit/Test-HelpOutput.ps1 guards it.
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
    [switch]$AllowConstrainedLanguage, # proceed under ConstrainedLanguage; output is NOT verifiable evidence (no hashes/manifest)
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

# --- ConstrainedLanguage preflight: refuse to produce untrustworthy evidence -----------------
# Measured on a real 5.1 host (2026-07-28): under ConstrainedLanguage the collector APPEARS to run
# but is structurally broken - [scriptblock]::Create is blocked, which is how nearly every step is
# built; the hashing shim never gets defined and Get-FileHash is unavailable, so NOTHING is hashed
# (no manifest, no custody digests); Start-Job is refused; and the writable-probe throws, which the
# destination logic reads as "read-only media" and silently REDIRECTS EVIDENCE ONTO THE SYSTEM
# DRIVE of the machine under investigation - the inverse of what a collector must do.
# A half-collection with no hashes, written to the target's C:, is worse than a clean refusal, so
# stop here and say exactly why. -AllowConstrainedLanguage overrides for operators who want the
# partial volatile data anyway and accept that it is NOT verifiable evidence.
# Everything in this block must itself be CLM-safe: property reads, string compares, Write-Host only.
$script:LangMode = "$($ExecutionContext.SessionState.LanguageMode)"
if ($script:LangMode -ne 'FullLanguage') {
    Write-Host ''
    Write-Host "  !! PowerShell language mode is $($script:LangMode), not FullLanguage." -ForegroundColor Red
    Write-Host '  !! IR-Collect cannot produce verifiable evidence in this mode:' -ForegroundColor Red
    Write-Host '  !!   - step construction ([scriptblock]::Create) is blocked' -ForegroundColor Red
    Write-Host '  !!   - no hashing is available, so there is no manifest and no custody digests' -ForegroundColor Red
    Write-Host '  !!   - the writable probe fails, so evidence can be redirected onto the target C:' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Usual cause: WDAC/AppLocker policy on a hardened endpoint.' -ForegroundColor Yellow
    Write-Host '  Do instead: run from a signed/allow-listed path, use the Velociraptor or CyLR' -ForegroundColor Yellow
    Write-Host '  triage binaries in .\tools (native executables, unaffected by language mode),' -ForegroundColor Yellow
    Write-Host '  or acquire off-host (VM snapshot / disk image).' -ForegroundColor Yellow
    Write-Host ''
    if (-not $AllowConstrainedLanguage) {
        Write-Host '  Refusing to run. Pass -AllowConstrainedLanguage to collect UNVERIFIABLE partial data anyway.' -ForegroundColor Red
        exit 40
    }
    Write-Host '  -AllowConstrainedLanguage set: continuing. Output will NOT be verifiable evidence.' -ForegroundColor Yellow
}
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
    # Bounded retry on a SHARING VIOLATION: antivirus/EDR real-time scanning routinely holds a
    # just-written file open for a moment, and on a live IR host that is the normal case, not an
    # edge case. Without this a transient lock turns into a permanent 'ERR' row in the manifest.
    $a = [Security.Cryptography.HashAlgorithm]::Create($Alg)
    if (-not $a) { throw "no provider for $Alg" }
    try {
        for ($try = 1; $try -le 3; $try++) {
            try {
                $fs = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                try { return (($a.ComputeHash($fs)) | ForEach-Object { $_.ToString('X2') }) -join '' }
                finally { $fs.Dispose() }
            } catch [IO.IOException] {
                if ($try -eq 3) { throw }
                Start-Sleep -Milliseconds (150 * $try)
            }
        }
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

function Test-PathWritable {
    <#  Can evidence actually be written here?

        The previous inline probe called `New-Item -ItemType Directory -Force` FIRST and treated
        any failure as "not writable". A DRIVE ROOT cannot be created - `New-Item -Force 'X:'`
        throws "The path is not of a legal form" - so every root-path destination was judged
        unwritable and silently redirected onto the subject host's system drive. Measured on
        range-WS02 2026-07-28: `-Dest X:\` on a proven-writable 300 MB volume produced its bundle
        at C:\ir_evidence and reported success. `-Dest E:\` on a USB evidence drive - the most
        ordinary destination there is - had the same fault.

        So: create the directory only if it does not already exist, then answer the real question
        by WRITING a probe file and READING IT BACK. An exit status alone does not prove a write
        landed (the same lesson as the UNC probe in B5). #>
    param([string]$Path)
    if (-not $Path) { return $false }
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop | Out-Null
        }
        $tf = Join-Path $Path ('.w_' + [guid]::NewGuid().ToString('N').Substring(0,8))
        [IO.File]::WriteAllText($tf, 'x')
        $back = try { [IO.File]::ReadAllText($tf) } catch { '' }
        Remove-Item -LiteralPath $tf -Force -ErrorAction SilentlyContinue
        return ($back -eq 'x')
    } catch { return $false }
}

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
    $probe = Test-PathWritable $OutputRoot
    if (-not $probe) {
        $redir = if ($LabVol) { Join-Path $LabVol 'ir_evidence' } else { Join-Path $env:SystemDrive 'ir_evidence' }
        # Redirecting evidence onto the SUBJECT HOST is a contamination event and a custody fact.
        # It used to be announced with Write-Host only, so the audit log - the record an analyst
        # actually reads - said "Destination is local/drive: X:\" while the bundle sat on C:.
        # Buffer it here (the trail is not open yet) and flush once it is.
        $script:PendingRedirectNote = "DESTINATION REDIRECTED: '$OutputRoot' was not writable, so evidence was written to $redir instead. This is ON THE SUBJECT HOST - treat the collection as having modified the target, and prefer removable media on any re-run."
        Write-Host ''
        Write-Host "  !! '$OutputRoot' is not writable. Redirecting evidence to $redir" -ForegroundColor Red
        Write-Host '  !! That location is ON THE SUBJECT HOST - this collection now writes to the machine under investigation.' -ForegroundColor Red
        Write-Host '  !! Attach writable removable media and re-run if the destination was meant to be external.' -ForegroundColor Yellow
        Write-Host ''
        $OutputRoot = $redir; try { New-Item -ItemType Directory -Force $OutputRoot | Out-Null } catch {}
    }
}
function ConvertTo-SafeToken {
    <#  Reduce an operator-supplied identifier to something safe to put in a path.

        -CaseId is typed by a responder under time pressure and lands directly in the bundle
        directory name. Unsanitised it breaks the collection in ways that are hard to read:
        [ ] ? and * make PowerShell's wildcard-interpreting -Path calls silently miss (see
        tests/unit/Test-LiteralPathHygiene.ps1), an apostrophe breaks the single-quoted command
        the Linux twin generates for its manifest, < > : " | / \ are outright illegal in a
        Windows filename, and a trailing dot or space produces a directory Explorer cannot open.

        The ORIGINAL string is never discarded - it is recorded in the metadata and the audit log,
        because the case id is a custody field and the operator's own wording is what ties this
        bundle to their paperwork. Only the PATH form is normalised. #>
    param([string]$Value, [string]$Fallback = 'IR')
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Fallback }
    # WHITELIST, not a blacklist of illegal characters. A whitelist is identical on both
    # platforms, so the same -CaseId yields the same bundle name whether the responder ran the
    # PowerShell or the shell collector - and it cannot be outflanked by a character that is
    # merely awkward rather than illegal (spaces, quotes, semicolons, glob metacharacters).
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        if (($ch -ge 'a' -and $ch -le 'z') -or ($ch -ge 'A' -and $ch -le 'Z') -or
            ($ch -ge '0' -and $ch -le '9') -or $ch -eq '.' -or $ch -eq '_' -or $ch -eq '-') {
            [void]$sb.Append($ch)
        } else { [void]$sb.Append('_') }
    }
    $t = $sb.ToString()
    if ($t.Length -gt 64) { $t = $t.Substring(0, 64) }
    if ([string]::IsNullOrWhiteSpace($t.Replace('_',''))) {
        # nothing but separators left - a directory named "___" tells the analyst nothing
        if ($t -notmatch '[A-Za-z0-9]') { return $Fallback }
    }
    return $t
}
$script:CaseIdRaw  = $CaseId
$script:CaseIdSafe = ConvertTo-SafeToken $CaseId
$OutDir = Join-Path $OutputRoot ("{0}_{1}_{2}" -f $script:CaseIdSafe, $hostName, $stamp)
if ($Resume) { $OutDir = $Resume }

function ConvertTo-ExtendedPath {
    <#  Rewrite a path into its extended-length form so the Win32 file APIs stop enforcing
        MAX_PATH (260). Local paths take \\?\, UNC paths take \\?\UNC\, and an already-extended
        path is returned untouched.

        A RELATIVE path is first resolved against the current directory by GetFullPath and then
        prefixed - the extended form requires a fully-qualified path, so anchoring it is the only
        way to produce a usable one, and it matches how every other PowerShell path operation
        treats a relative input. Anything GetFullPath cannot anchor comes back unchanged. #>
    param([string]$Path)
    if (-not $Path -or $Path.StartsWith('\\?\')) { return $Path }
    $full = try { [IO.Path]::GetFullPath($Path) } catch { return $Path }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    if ($full -match '^[A-Za-z]:\\')  { return '\\?\' + $full }
    return $Path
}

function Resolve-UsableOutDir {
    <#  Prove the destination can hold the paths this collector actually writes, BEFORE anything
        depends on it - and repair it if it cannot.

        Free space is not the only way a destination can be unusable. Measured on range-WS02
        2026-07-28 (scenario B6) with a 229-char -Dest and LongPathsEnabled=0: every directory
        creation failed on MAX_PATH, not one byte was written, audit.log itself was unwritable so
        even the failure could not be recorded - and the collector still printed
        "Collection complete. Output: <path>" naming a directory that did not exist.

        The deepest thing the tree holds is a per-user hive
        (05_artifacts\userhives\<user>\NTUSER.DAT), so that is what gets probed. If the plain
        path is refused, the extended-length (\\?\) form is tried, which genuinely lifts the
        260-char limit for the Win32 file APIs. Only if BOTH fail is the destination unusable.

        Returns .Path (what to use), .Mode (plain | extended | unusable) and .ProbeLength. #>
    param([string]$Base)
    $rel   = Join-Path (Join-Path (Join-Path '05_artifacts' 'userhives') 'a_reasonably_long_username') 'NTUSER.DAT'
    $probeLen = ($Base.Length + 1 + $rel.Length)
    # ONLY the plain form is offered as a working destination. Adopting the extended-length
    # (\\?\) form for the whole output tree was tried and MEASURED on range-WS02 2026-07-28: the
    # probe passes and the directories get created, but the drive-qualifier logic downstream
    # (free-space checks, Split-Path -Qualifier, DriveInfo) all return null for a \\?\ path, so
    # free space read 0.0 GB, Stage 1 aborted on a null reference, the seal failed, and the run
    # exited 0 having written an EMPTY bundle. A destination that "works" in the probe but
    # produces no evidence is worse than one that is refused. Full extended-length support means
    # auditing every path-derived operation in this script; until that is done, refuse honestly.
    foreach ($mode in @('plain')) {
        # [IO.Path]::Combine, not Join-Path: Join-Path validates the PSDrive and THROWS for a
        # destination on a drive that does not exist ("Cannot find drive 'Q'"). A probe whose job
        # is to decide whether a destination is usable must never itself die on an unusable one.
        $b = try { if ($mode -eq 'plain') { $Base } else { ConvertTo-ExtendedPath $Base } } catch { $null }
        if (-not $b) { continue }
        if ($mode -eq 'extended' -and $b -eq $Base) { continue }   # nothing new to try
        $probe = [IO.Path]::Combine($b, $rel)
        try {
            $null = New-Item -ItemType Directory -Force (Split-Path $probe -Parent) -ErrorAction Stop
            [IO.File]::WriteAllText($probe, 'probe')
            if (-not (Test-Path -LiteralPath $probe)) { throw 'probe file did not materialise' }
            # leave nothing behind: remove the probe file and the scaffold it needed
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            try { Remove-Item -LiteralPath ([IO.Path]::Combine($b,'05_artifacts')) -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            return [pscustomobject]@{ Path = $b; Mode = $mode; ProbeLength = $probeLen }
        } catch {
            try { Remove-Item -LiteralPath ([IO.Path]::Combine($b,'05_artifacts')) -Recurse -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    return [pscustomobject]@{ Path = $Base; Mode = 'unusable'; ProbeLength = $probeLen }
}

# Resume paths are the operator's own and already exist - do not rewrite them out from under a
# partially collected tree.
if (-not $Resume) {
    $script:DestProbe = Resolve-UsableOutDir $OutDir
    if ($script:DestProbe.Mode -eq 'unusable') {
        Write-Host ''
        Write-Host "  !! Destination cannot hold this collection's paths." -ForegroundColor Red
        Write-Host ("  !! The deepest artifact path would be ~{0} characters and the filesystem refused it," -f $script:DestProbe.ProbeLength) -ForegroundColor Red
        Write-Host ("  !! MAX_PATH here is 260 characters and this destination is {0}." -f $Dest.Length) -ForegroundColor Red
        Write-Host '  !! Refusing to start: a run that cannot create its own tree cannot record why it failed.' -ForegroundColor Red
        Write-Host '  !! Use a shorter -Dest (a drive root or a short folder is ideal).' -ForegroundColor Yellow
        Write-Host ''
        exit 40
    }
}

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
try { if (-not (Test-Path -LiteralPath $script:StateJsonl)) { New-Item -ItemType File -Path $script:StateJsonl -Force | Out-Null } } catch {}

function Write-Audit {
    param([string]$Message)
    $line = "{0} | {1} | {2}" -f (Now-Utc), $env:USERNAME, $Message
    # -LiteralPath, never -Path: -Path treats its argument as a WILDCARD pattern. An
    # extended-length destination begins \?\ and the '?' is a single-character wildcard, so the
    # audit log silently resolved to nothing and every custody line was lost - the run wrote no
    # files at all while reporting success (scenario B6, 2026-07-28). The same trap applies to any
    # evidence path containing [ ] ? or *, which a username or filename legitimately can.
    try { Add-Content -LiteralPath $AuditLog -Value $line -Encoding UTF8 } catch {}
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
    try { Add-Content -LiteralPath $script:StateJsonl -Value ($o | ConvertTo-Json -Compress -Depth 4) -Encoding UTF8 } catch {}
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
        # IOException is an UMBRELLA: PathTooLongException, DirectoryNotFoundException and
        # FileNotFoundException all derive from it, so catching the type alone would report
        # "disk full" for a vanished directory or an over-long path. Match the actual condition:
        #   Win32 ERROR_HANDLE_DISK_FULL = 39 (0x27), ERROR_DISK_FULL = 112 (0x70); .NET packs the
        #   Win32 code into the low word of HResult (0x8007xxxx). On Unix-hosted pwsh the errno
        #   ENOSPC (28) can appear instead. Fall back to the message only if HResult is unhelpful.
        $code = try { $_.Exception.HResult -band 0xFFFF } catch { 0 }
        if ($code -in 39, 112, 28) { return $false }
        if ($_.Exception.Message -match 'not enough space|disk is full|No space left') { return $false }
        return $true   # some other I/O problem - not a space problem, do not masquerade as one
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
        # a refused kernel driver is NOT the same failure as a refused file: retrying the same
        # imager cannot succeed, so it gets its own class and its own ladder (try an imager that
        # uses a different mechanism). Kept ahead of the generic matches because these messages
        # often also contain "Access is denied", which would otherwise mis-file it as not_elevated.
        'Secure Boot|Code Integrity|HVCI|not digitally signed|driver .*(load|signature)|(load|start).* driver|0xC0000428|CreateService failed|OpenSCManager' { return 'driver_blocked' }
        'not enough space|There is not enough space|disk is full' { return 'no_space' }
        'being used by another process|because it is being used|cannot access the file|volume .* in use' { return 'file_locked' }
        # name resolution failing is a DIFFERENT fix from the route being down: waiting helps a
        # flaky resolver, whereas an unreachable host needs the operator. Both ladders existed;
        # neither class could be produced until now (found 2026-07-28 by Test-FixLadders).
        'DNS name does not exist|No such host is known|DNS_ERROR|server failed to resolve|Temporary failure in name resolution|Resolve-DnsName' { return 'dns_blocked' }
        'too many requests|rate limit|HTTP 429|throttl|server is too busy|The request was throttled' { return 'rate_limit' }
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
$script:EmptySteps = @()
# Names of steps that queried CIM/WMI and had somewhere to write. Populated in Invoke-Step from the
# step's own script text. Exists to give emptiness a SECOND FACT: one empty CIM step proves
# nothing, but every CIM step on the host coming back empty is a broken subsystem.
$script:CimStepsRan = @()

# Get-SubsystemFailureVerdict <ran> <empty> -> $null, or the class + ladder to hand the operator.
#
# THE GAP THIS CLOSES. Error classes are assigned by matching error TEXT (Get-ErrorClass), and are
# only ever fed from a step that threw. When WMI is broken the steps do not throw - they return
# NOTHING - so `wmi_failure` could never be produced, and the fix ladder declared for it
# (restart-wmi / native-source / skip) could never be offered to a responder. The run correctly
# refused to claim COMPLETE, but the person holding the console was never told what to try. Same
# shape as E1/A3/E3 and the clock work: the tool sees the condition and stops short of the verdict.
#
# EMPTINESS ALONE IS NOT EVIDENCE, so this needs a second fact rather than a longer critical list.
# A single empty CIM step is ordinary - plenty of queries legitimately return nothing. What is not
# ordinary is EVERY CIM-backed step on the host returning nothing at once. So the rule is
# corroboration: at least two such steps must have run, and none of them may have produced data.
# That is also what keeps a healthy host quiet - one empty query can never trip it.
function Get-SubsystemFailureVerdict {
    param(
        [string[]]$Ran,
        [string[]]$Empty,
        [string]$Subsystem = 'CIM/WMI',
        [string]$Class     = 'wmi_failure'
    )
    $ran = @($Ran | Where-Object { $_ })
    # Fewer than two steps is not corroboration, it is a single observation.
    if ($ran.Count -lt 2) { return $null }
    $empties = @($Empty | Where-Object { $_ })
    $worked  = @($ran | Where-Object { $empties -notcontains $_ })
    # ANY step that produced data proves the subsystem answers, so emptiness elsewhere is a
    # property of those queries, not of the subsystem.
    if ($worked.Count -gt 0) { return $null }
    [pscustomobject]@{
        subsystem = $Subsystem
        class     = $Class
        steps     = @($ran | Sort-Object)
        evidence  = ("all {0} {1}-backed step(s) produced no output: {2}" -f $ran.Count, $Subsystem, (($ran | Sort-Object) -join ', '))
    }
}

# Get-EncryptionRiskVerdict - may this host be powered off without destroying the evidence?
#
# THE DEFECT THIS CLOSES, and it is the most consequential in this file because the loss is
# PHYSICAL AND IRREVERSIBLE. The risk flag was computed as:
#
#     $encRisk = $false
#     try { $encRisk = ([bool](Get-BitLockerVolume ...)) -and (-not $memOk) } catch {}
#
# initialised to "no risk" and with the catch discarding everything. Get-BitLockerVolume throws on
# hosts without the BitLocker cmdlets, on editions that lack the feature, when the provider is
# broken, and WHEN NOT ELEVATED - which is scenario A3, a case this collector explicitly supports.
# In every one of those the flag stayed $false, the console printed GREEN, and the responder was
# told nothing. The AMBER banner exists to say "the BitLocker key lives in RAM you did NOT capture,
# get a recovery key BEFORE powering off, or the disk image is unreadable". A failed probe read as
# "not encrypted", so the operator powers the host off and the evidence is gone for good.
#
# TWO-STATE WHERE IT MUST BE THREE. "not encrypted" and "could not determine" are different facts
# and only one of them is safe. An unrun probe must never resolve to the safe side when the cost of
# being wrong is an unreadable disk image.
function Get-EncryptionRiskVerdict {
    param(
        [System.Nullable[bool]]$DiskEncrypted,   # $null = the probe could not answer
        [bool]$MemoryVerified
    )
    # Verified RAM means the key was captured, so encryption stops being a power-off risk. This is
    # the only branch that clears the host, and it turns on a fact we measured rather than assumed.
    if ($MemoryVerified) {
        return [ordered]@{ state='ok'; amber=$false
                           note='RAM was captured, so any volume key resident in memory is preserved in this bundle' }
    }
    if ($DiskEncrypted -eq $true) {
        return [ordered]@{ state='encrypted-no-ram'; amber=$true
                           note='this disk is encrypted and RAM was NOT captured - the volume key exists only in memory that is about to be lost' }
    }
    if ($null -eq $DiskEncrypted) {
        # Warn, and say WHY it is a warning rather than a finding. Claiming encryption we did not
        # observe would be its own false statement; staying silent risks the disk.
        return [ordered]@{ state='unknown-no-ram'; amber=$true
                           note='encryption status COULD NOT BE DETERMINED (the probe failed - commonly no BitLocker cmdlets, or not elevated) and RAM was NOT captured. This is not a claim that the disk is encrypted; it is a refusal to assume it is not, because that assumption is unrecoverable if wrong' }
    }
    [ordered]@{ state='ok'; amber=$false; note='no encrypted volume detected' }
}

# Get-CimEvidenceVerdict - did CIM actually produce this bundle's evidence, or did fallbacks?
#
# THE DEFECT THIS CLOSES. Eight of the thirteen CIM-backed steps carry a native fallback, so on a
# host with WMI stopped they still write data - and every layer above them reads that as success.
# The artifacts DO say so (nine sites emit a "CIM/WMI unavailable ... native fallback" banner) but
# that fact reaches nothing: run_state.json, SUMMARY.md and the diagnostic report all present a
# WMI-dead host as COMPLETE with no finding. Measured live 2026-07-29 with Winmgmt stopped:
# COMPLETE ok=33 failed=0 empty_outputs=0, indistinguishable from a healthy run. Adversaries
# disable WMI, so "six core steps switched to native sources" is itself a finding.
#
# It also fixes Get-SubsystemFailureVerdict, which could never fire on a CIM outage: it treats any
# step that produced data as proof the subsystem answered, and a fallback step ALWAYS produces
# data - from a native source. Output existing is not evidence that CIM produced it.
#
# THREE-STATE on the probe, per the E3 lesson: an unrun probe must not read as a healthy one.
# Get-BitLockerKeyVerdict - did bitlocker_recovery_keys.csv actually capture usable keys?
#
# The Linux twin taught this the expensive way. There, `dmsetup table --showkeys` was assumed to
# yield a master key and on modern LUKS2 it yields a KEYRING POINTER instead; the collector wrote
# the pointer under a banner promising it decrypts the evidence, and nobody found out until the
# procedure was executed against a real volume (2026-07-29). The Windows side captures the genuine
# article - a 48-digit recovery password - so it is NOT the same defect. But it shares the shape of
# the mistake: the CSV row is emitted with no check that the password field is populated, so a
# blank one produces a file that exists, has headers, has a row per protector, and contains no key.
# An analyst reading a CSV with a MountPoint and a KeyProtectorId has every reason to believe the
# volume is recoverable.
#
# A recovery password is 8 hyphen-separated groups of exactly 6 digits. Anything else is not one.
# Being wrong toward "captured" is the expensive direction - it tells a responder the evidence can
# be opened when it cannot - so only the exact form counts.
#
# Pure (no I/O) so it is unit-testable - see tests/unit/Test-BitLockerKeyVerdict.ps1.
function Get-RecoveryPasswordShape {
    param([string]$Password)
    if ([string]::IsNullOrWhiteSpace($Password)) { return 'absent' }
    if ($Password -match '^\d{6}(-\d{6}){7}$') { return 'recovery-password' }
    'malformed'
}

function Get-BitLockerKeyVerdict {
    param(
        [string[]]$Rows = @(),          # CSV data rows, header already removed
        [System.Nullable[bool]]$ScanOk  # $null = the CSV could not be read at all
    )
    if ($null -eq $ScanOk -or $ScanOk -eq $false) {
        return [ordered]@{ state='unknown'; captured=0; missing=0
            note='the recovery-key artifact could not be read at seal, so this bundle cannot say whether any key was captured. This is NOT a statement that none was.' }
    }
    $rows = @($Rows | Where-Object { $_ -and $_.Trim() })
    if ($rows.Count -eq 0) {
        return [ordered]@{ state='no-protectors'; captured=0; missing=0
            note='no BitLocker recovery-password protectors were reported. On a host with no encrypted volume that is expected; on one with BitLocker enabled it means the protectors were not readable and NO key was captured.' }
    }
    $ok = 0; $bad = @()
    foreach ($r in $rows) {
        $f = $r -split ','
        $pw = if ($f.Count -ge 4) { $f[3] } else { '' }
        if ((Get-RecoveryPasswordShape $pw) -eq 'recovery-password') { $ok++ }
        else { $bad += $(if ($f.Count -ge 1 -and $f[0]) { $f[0] } else { '?' }) }
    }
    if ($bad.Count -eq 0) {
        return [ordered]@{ state='captured'; captured=$ok; missing=0
            note="$ok recovery password(s) captured in full. These ARE the keys to the evidence - handle at the classification of the data they protect." }
    }
    $state = if ($ok -gt 0) { 'partial' } else { 'no-key-captured' }
    [ordered]@{ state=$state; captured=$ok; missing=$bad.Count
        note="$($bad.Count) protector row(s) carry NO usable recovery password (volume(s): $($bad -join ', ')). A row without a 48-digit password does not open anything - the volume may be UNRECOVERABLE from a dead-box image unless RAM was captured. Commonly the collector was not elevated enough to read the protector." }
}

function Get-CimEvidenceVerdict {
    param(
        [System.Nullable[bool]]$CimAvailable,   # $null = the probe did not run
        [string[]]$FallbackSteps = @(),
        [string[]]$EmptyCimSteps = @()
    )
    $fb = @($FallbackSteps | Where-Object { $_ } | Sort-Object -Unique)
    $mt = @($EmptyCimSteps  | Where-Object { $_ } | Sort-Object -Unique)
    if ($fb.Count -eq 0 -and $mt.Count -eq 0 -and $CimAvailable -eq $true) {
        return [ordered]@{ state='cim-sourced'; fallback_steps=@(); empty_steps=@()
                           note='CIM answered and no step needed a fallback' }
    }
    $state = 'degraded'
    if ($null -eq $CimAvailable)      { $state = 'unknown' }
    elseif ($CimAvailable -eq $false) { $state = 'cim-unavailable' }
    $note = switch ($state) {
        'cim-unavailable' { "CIM did not answer at seal; $($fb.Count) step(s) fell back to native sources and $($mt.Count) produced nothing. Native data is equivalent in content but NOT proof the host's WMI was healthy - treat a dead WMI as a finding in its own right." }
        'unknown'         { "the CIM probe did not run, so this bundle cannot say whether WMI was healthy; $($fb.Count) step(s) fell back and $($mt.Count) produced nothing." }
        default           { "CIM answered at seal, but $($fb.Count) step(s) still fell back to native sources and $($mt.Count) produced nothing - the outage may have been intermittent." }
    }
    [ordered]@{ state=$state; fallback_steps=$fb; empty_steps=$mt; note=$note }
}

# THREE-STATE census of the same probe. Get-SubsystemFailureVerdict returns $null for THREE
# different situations - the subsystem answered, it was cleared because one step returned data, or
# too few subsystem-backed steps ran to say anything - and a bare null in run_state.json cannot be
# told apart. That is the exact two-state defect this project keeps fixing in other people's code
# (E3's domain probe, the clock sync flag), introduced here by me and caught by the 2026-07-29
# negative control, where null meant "cleared by native fallbacks" and read as "healthy".
#
# Live evidence for why it matters: with Winmgmt STOPPED and Win32_Process returning 0 rows, a
# -RapidOnly run produced verdict=COMPLETE ok=33 empty_outputs=0 - identical to a healthy run -
# because the CIM steps fall back to native sources. Nothing in the bundle said WMI was dead.
function Get-SubsystemProbeState {
    param([string[]]$Ran, [string[]]$Empty, [int]$MinSteps = 2)
    $ran = @($Ran | Where-Object { $_ })
    if ($ran.Count -lt $MinSteps) {
        return [ordered]@{ state='insufficient-evidence'; steps_ran=$ran.Count; steps_empty=0
                           note="fewer than $MinSteps subsystem-backed steps ran, so this bundle says nothing either way about the subsystem" }
    }
    $empties = @($Empty | Where-Object { $_ })
    $e = @($ran | Where-Object { $empties -contains $_ }).Count
    if ($e -eq $ran.Count) {
        return [ordered]@{ state='not-answering'; steps_ran=$ran.Count; steps_empty=$e
                           note='every subsystem-backed step returned nothing' }
    }
    [ordered]@{ state='answered'; steps_ran=$ran.Count; steps_empty=$e
                note='at least one subsystem-backed step returned data' }
}
# path -> SHA-256 of every carried tool, taken before collection and re-verified at seal.
# Initialised here (not only inside the "tools dir exists" branch) so the seal-time check has a
# defined value on a host with no toolkit at all.
$script:ToolInventory = @{}
$script:ShipOk = $null
$script:ShipError = $null
$script:NetProbe = $null
$script:ToolVanished  = @()
$script:ToolChanged   = @()
function Compare-ToolInventory {
    <#  Re-verify a toolkit snapshot (path -> SHA-256) against what is on disk NOW.
        Returns .Vanished and .Changed as leaf names, for the verdict and the audit log.

        A tool that is present but UNREADABLE counts as Changed, never as fine: an
        AV product that locks a detected file rather than deleting it leaves the path in place,
        and treating an unverifiable tool as verified is the whole failure mode this guards. #>
    param([hashtable]$Inventory)
    $vanished = @(); $changed = @()
    foreach ($p in @($Inventory.Keys)) {
        if (-not (Test-Path -LiteralPath $p)) { $vanished += (Split-Path $p -Leaf); continue }
        $now = try { Get-IRSha256 $p } catch { $null }
        if ($now -ne $Inventory[$p]) { $changed += (Split-Path $p -Leaf) }
    }
    [pscustomobject]@{ Vanished = @($vanished); Changed = @($changed) }
}
# A step can also "succeed" while writing nothing but a refusal. Measured on range-WS02 as a
# standard user (2026-07-28): drivers.txt 115096 B -> 155 B, netstat_anob.txt 8140 B -> 45 B,
# sessions.txt 597 B -> 10 B - each an "Access is denied" stub. Every byte count was above the
# `-le 2` empty threshold, so empty_outputs was 0 and the bundle sealed COMPLETE. An analyst
# would read "no unusual drivers" off a driver list that was never obtainable. Degraded output
# is therefore tracked separately from empty output, and both bear on the verdict.
$script:DegradedSteps = @()
$script:DenialPattern = 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation'
function Get-DomainEvidenceVerdict {
    <#  Decide whether empty AD enumeration belongs in the completeness verdict.

        Measured on range-WS02 2026-07-29 (scenario E3): with the DC firewalled off, FOURTEEN AD
        steps produced no output, every one was recorded in diagnostics.empty_outputs, and the
        bundle still sealed verdict=COMPLETE with an empty incomplete list. An analyst receives a
        COMPLETE bundle from a DOMAIN-JOINED host containing no domain data and nothing saying the
        domain was never reached.

        The distinction that matters, and the reason this is not simply "add ad-* to
        CriticalSteps": an AD query can be legitimately empty. A domain with no LAPS deployment,
        no unconstrained delegation and no AS-REP-roastable accounts SHOULD return nothing, and
        calling that INCOMPLETE would cry wolf on a healthy collection - the same over-trigger
        A3's degraded-output check had to avoid.

        So emptiness only counts against the verdict when the domain was UNREACHABLE. Pure, so it
        is unit-testable without a domain. #>
    param([bool]$DomainJoined, [System.Nullable[bool]]$DomainReachable, [string[]]$EmptyAdSteps)
    if (-not $DomainJoined)            { return $null }   # nothing to enumerate
    if (-not $EmptyAdSteps -or $EmptyAdSteps.Count -eq 0) { return $null }   # AD answered
    if ($DomainReachable -eq $true)    { return $null }   # reachable and empty = genuinely empty
    $why = if ($null -eq $DomainReachable) { 'reachability unknown' } else { 'domain controller unreachable' }
    return ("domain-evidence-missing({0}; {1} AD step(s) empty: {2})" -f $why, $EmptyAdSteps.Count, (($EmptyAdSteps | Sort-Object) -join '/'))
}

function Test-DegradedOutput {
    <#  True when a step's output is dominated by an access refusal rather than by data.
        Two independent signals, either sufficient - a tiny file that mentions a denial, or a
        file where denials outnumber real content lines. Reads at most 8 KB so a large healthy
        artifact that merely quotes the word "denied" once is never misjudged. #>
    param([string]$Path, [long]$Bytes)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
    if ($Bytes -gt 65536) { return $null }
    $txt = try {
        $fs = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try { $buf = New-Object byte[] ([Math]::Min(8192, $fs.Length)); [void]$fs.Read($buf,0,$buf.Length); [Text.Encoding]::UTF8.GetString($buf) } finally { $fs.Dispose() }
    } catch { return $null }
    if ($txt -notmatch $script:DenialPattern) { return $null }
    $lines   = @($txt -split "`r?`n" | Where-Object { $_.Trim() })
    $denials = @($lines | Where-Object { $_ -match $script:DenialPattern }).Count
    if ($denials -eq 0) { return $null }
    if ($Bytes -lt 4096 -or ($denials / [Math]::Max(1,$lines.Count)) -ge 0.5) {
        return (@($lines | Where-Object { $_ -match $script:DenialPattern })[0]).Trim()
    }
    return $null
}
# Steps whose emptiness means the collection FAILED at its core purpose, not merely that a query
# had no results. A host genuinely has processes, network endpoints, services, and local users -
# if these come back empty the data was not collected, whatever the exit code says. Everything
# else that comes back empty is reported but not treated as fatal (some queries legitimately
# return nothing, e.g. no shadow copies).
# NAMES MUST MATCH THE Collect CALLS EXACTLY - an invented name silently never matches, which
# would make this whole check a no-op. Verified against a real run's ledger, 2026-07-28.
$script:CriticalSteps = @('processes','processes-csv','process-owners','tasklist-svc','drivers',
                          'local-users','systeminfo','os-cim','netstat','tcp-conns',
                          'udp-endpoints','services')
# Invoke-Remediation: $true => retry now ; $false => give up. Each (id,class) fires once; hard cap 3 attempts.
# --- SELF-FIX LADDERS --------------------------------------------------------------------
# Every error class gets an ORDERED list of fix attempts, tried one per retry until one works or
# the ladder is exhausted. The previous design allowed exactly one "remediation" per (step,class)
# and every entry was a LABEL, not an action - 'cim-to-wmi-fallback', 'degrade-nonadmin',
# 'fallback-or-skip' were strings that got logged while the step gave up. The point is to COMPLETE
# the collection, so each rung below either does something real or is named honestly as a marker.
# REACHABILITY, MEASURED 2026-07-29 - which of these can actually be OFFERED to a responder.
#
# A class only reaches a responder if Get-ErrorClass assigns it, and that happens solely when a
# step fails INSIDE its own execution and surfaces error TEXT - or via the one direct assignment
# further down (tool_missing, on toolkit tampering). Five conditions were induced live and read
# back from diagnostics.by_error_class and the ledger:
#
#   carried tool removed mid-run -> tool_missing FIRED (this is the proof the channel works)
#   healthy host                 -> nothing        (correct)
#   unreachable UNC destination  -> nothing
#   IRCOLLECT_FORCE_INPROC=1     -> nothing
#   over-long -Dest              -> nothing, and NO BUNDLE at all
#
# The empty results are not gaps. Each of those conditions is handled EARLIER and BETTER than a
# ladder could, so the matching ladder below is VESTIGIAL - kept because the class is still a valid
# label if a step ever does fail that way, but it will not be reached by the obvious trigger:
#
#   path_too_long   - refused before the tree exists ("a run that cannot create its own tree cannot
#                     record why it failed"). There is no ledger to carry a class, and no retry
#                     helps: the operator must pass a shorter -Dest, which the refusal already says.
#   job_subsystem   - the in-process fallback IS this ladder's first rung (force-inproc), applied
#                     automatically and reported via diagnostics.exec_mode. The remediation happens
#                     before anything could offer it.
#   wmi_failure     - a broken CIM subsystem returns EMPTY rather than throwing, so no text reaches
#                     the classifier. Covered instead by diagnostics.cim_evidence.
#   net_unreachable - the destination probe returns a STRUCTURED RESULT rather than throwing, and a
#                     failed ship is recorded in <bundle>.ship.json + ship.preflight_reason + an
#                     exit code >= 10. DELIBERATELY NOT WIRED to this ladder: the bundle is already
#                     sealed and safe locally, so an automatic backoff-retry would only delay the
#                     operator's return for a destination that may be down for hours. A retry
#                     policy belongs to whatever orchestrates the collection, which already has
#                     everything it needs to make that choice.
#
# DO NOT "fix" this by having those detections write error_class. That would manufacture ERRORS for
# conditions the collector handled correctly - a transparent fallback is not a job_subsystem error -
# and would degrade the diagnostics it appears to improve.
$script:FixLadders = @{
    'wmi_failure'     = @('restart-wmi','native-source','skip')
    'no_space'        = @('purge-scratch','relocate-dest','retry-in-place','skip')
    'tool_missing'    = @('rescan-tools','native-source','skip')
    'file_locked'     = @('settle-retry','copy-via-shadow','skip')
    'timeout'         = @('backoff-retry','extend-timeout','skip')
    'net_unreachable' = @('backoff-retry','skip')
    'dns_blocked'     = @('backoff-retry','skip')
    'rate_limit'      = @('backoff-retry','extend-timeout','skip')
    'not_elevated'    = @('native-source','skip')
    'job_subsystem'   = @('force-inproc','skip')
    'path_too_long'   = @('shortpath-retry','skip')
    'driver_blocked'  = @('try-alt-imager','native-source','skip')
    'clm_blocked'     = @('skip')
}
$script:RemRung   = @{}   # (id|class) -> how many rungs already tried
$script:TmoBoost  = @{}   # step id -> timeout multiplier granted by extend-timeout
$script:LongPathIds = @{} # step id -> use an extended-length (\\?\) destination, granted by shortpath-retry

# Invoke-FixRung: perform one rung. Returns $true if the run should retry the step afterwards.
# Each rung reports what it ACTUALLY achieved; a rung that could not act says so rather than
# claiming a fix, because a self-heal that lies is worse than one that does nothing.
function Invoke-FixRung { param([string]$Rung,[string]$Name,[string]$Id)
    switch ($Rung) {
        'restart-wmi' {
            # a genuine repair: WMI is a service, and a stopped/disabled Winmgmt is fixable
            try {
                $svc = Get-Service Winmgmt -ErrorAction Stop
                if ($svc.StartType -eq 'Disabled') { Set-Service Winmgmt -StartupType Manual -ErrorAction SilentlyContinue }
                if ($svc.Status -ne 'Running')     { Start-Service Winmgmt -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
                $ok = $false
                try { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop | Out-Null; $ok = $true } catch {}
                Write-Audit "  FIX restart-wmi: Winmgmt now $((Get-Service Winmgmt).Status); CIM usable = $ok"
                return $ok
            } catch { Write-Audit "  FIX restart-wmi: could not touch the service - $($_.Exception.Message)"; return $false }
        }
        'purge-scratch' {
            # reclaim space we are responsible for before blaming the operator's disk
            $freed = 0
            foreach ($d in @($env:TEMP, (Join-Path $env:WINDIR 'Temp'))) {
                if (-not $d -or -not (Test-Path $d)) { continue }
                Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
                    ForEach-Object { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
            }
            $ok = (Test-DestHasSpace)
            Write-Audit ("  FIX purge-scratch: reclaimed {0:N1} MB from temp; destination writable = {1}" -f ($freed/1MB), $ok)
            return $ok
        }
        'relocate-dest' {
            # only ever ADDITIVE: never move a part-written tree, but give later steps somewhere to land
            $alt = $null
            foreach ($c in @((Join-Path $env:SystemDrive 'ir_evidence_overflow'), (Join-Path $env:TEMP 'ir_evidence_overflow'))) {
                try { New-Item -ItemType Directory -Force $c -ErrorAction Stop | Out-Null
                      [IO.File]::WriteAllText((Join-Path $c '.probe'),'x'); Remove-Item (Join-Path $c '.probe') -Force
                      $alt = $c; break } catch {}
            }
            if ($alt) { $script:OverflowDir = $alt; Write-Audit "  FIX relocate-dest: overflow area available at $alt (existing tree left in place)"; return $false }
            Write-Audit '  FIX relocate-dest: no writable overflow location found'; return $false
        }
        'extend-timeout' {
            $script:TmoBoost[$Id] = 3
            Write-Audit "  FIX extend-timeout: step $Id gets 3x its bound on the next attempt"
            return $true
        }
        'settle-retry'   { Start-Sleep -Seconds 3; Write-Audit '  FIX settle-retry: waited for the holder to release'; return $true }
        'copy-via-shadow' {
            $ok = $false
            try { $r = (Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop | Measure-Object).Count
                  $ok = $r -gt 0; Write-Audit "  FIX copy-via-shadow: $r existing shadow copies available for offline read" } catch {
                  Write-Audit '  FIX copy-via-shadow: no usable shadow copy (not created - creating one alters the subject host)' }
            return $false
        }
        'rescan-tools'   {
            $n = 0; try { $n = @(Get-ChildItem $ToolDir -Recurse -File -Include *.exe -ErrorAction SilentlyContinue).Count } catch {}
            Write-Audit "  FIX rescan-tools: $n carried executables visible under $ToolDir"
            return ($n -gt 0)
        }
        'force-inproc'   { $script:JobsOk = $false; Write-Audit '  FIX force-inproc: switching to in-process execution for the remainder'; return $true }
        'shortpath-retry'{
            # grant THIS step an extended-length destination on the retry, and prove the prefix
            # actually resolves before claiming the fix - a rung that only logs is worse than none,
            # because the ledger then records a remediation that never occurred
            $probe = ConvertTo-ExtendedPath $script:OutDir
            $ok = ($probe -ne $script:OutDir) -and (Test-Path -LiteralPath $probe)
            if ($ok) { $script:LongPathIds[$Id] = $true }
            Write-Audit "  FIX shortpath-retry: extended-length destination $(if($ok){"enabled for step $Id ($probe)"}else{'unavailable - path is relative or unresolvable'})"
            return $ok
        }
        'retry-in-place' {
            # last resort before giving up on space: the earlier rungs may have freed enough, or
            # another process may have released its hold. Re-probe for real rather than assuming.
            # Was DECLARED in the no_space ladder but never implemented, so it fell through to
            # `default { return $false }` - which reads as "tried, did not help" and terminated the
            # ladder one rung early, making `skip` unreachable. Found 2026-07-28 by Test-FixLadders.
            Start-Sleep -Seconds 2
            $ok = (Test-DestHasSpace)
            Write-Audit "  FIX retry-in-place: re-probed the original destination; writable = $ok"
            return $ok
        }
        'try-alt-imager' {
            # the memory driver was refused (Secure Boot / HVCI / EDR). A different imager may use
            # a different mechanism, so look for one we actually carry rather than retrying the
            # same binary. Parity with the Linux ladder, which has had this rung since LiME->AVML.
            $alts = @()
            foreach ($n in @('winpmem','DumpIt','magnet_ram_capture','ramcapture','velociraptor')) {
                try { $alts += @(Get-ChildItem $ToolDir -Recurse -File -Filter "*$n*.exe" -ErrorAction SilentlyContinue) } catch {}
            }
            $alts = @($alts | Sort-Object FullName -Unique)
            Write-Audit "  FIX try-alt-imager: $($alts.Count) candidate imager(s) carried$(if($alts){': ' + (($alts | ForEach-Object { $_.Name }) -join ', ')})"
            return ($alts.Count -gt 1)
        }
        'backoff-retry'  { return $true }
        'native-source'  { Write-Audit '  FIX native-source: step-level non-WMI fallback will be used on retry'; return $true }
        'skip'           { return $false }
        default          { return $false }
    }
}

# Invoke-Remediation: climb the ladder for this class, one rung per attempt.
function Invoke-Remediation { param([string]$Cls,[string]$Name,[string]$Id,[string]$Phase,[int]$Attempt)
    if ($Attempt -ge 4) { return $false }
    $ladder = $script:FixLadders[$Cls]
    if (-not $ladder) { $ladder = @('backoff-retry','skip') }
    $k = "$Id|$Cls"
    $rungIx = if ($script:RemRung.ContainsKey($k)) { $script:RemRung[$k] } else { 0 }
    if ($rungIx -ge $ladder.Count) { return $false }
    $rung = $ladder[$rungIx]
    $script:RemRung[$k] = $rungIx + 1

    if ($Cls -eq 'no_space') { $script:DiskFull = $true }
    $retry = Invoke-FixRung -Rung $rung -Name $Name -Id $Id
    $remaining = $ladder.Count - ($rungIx + 1)
    Write-Ledger $Id $Name $Phase 'remediation' @{ class=$Cls; action=$rung; rung="$($rungIx+1)/$($ladder.Count)"; result=$(if($retry){'retry'}else{'next-or-stop'}) }
    Write-Audit "STEP $Id REMEDIATE | $Name | class=$Cls rung $($rungIx+1)/$($ladder.Count)=$rung -> $(if($retry){'retry'}else{"advance ($remaining left)"})"
    # a rung that could not fix things still lets the ladder advance on the next attempt, as long
    # as rungs remain - that is the difference between a ladder and a single shot.
    if (-not $retry -and $remaining -gt 0 -and $rung -ne 'skip') { return $true }
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
    if (-not (Test-Path -LiteralPath $Target)) { return $false }
    return ((Get-Item -LiteralPath $Target).Length -gt 0)
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
    # shortpath-retry granted this step an extended-length path. The \\?\ prefix lifts the 260-char
    # MAX_PATH limit for the Win32 file APIs, which is the ONLY thing that actually makes a
    # too-long destination writable - the rung used to just log that it had retried "with the
    # shortened destination path" while changing nothing, so the retry failed identically and the
    # custody log carried a false statement. Found by tests/unit/Test-FixLadders.ps1, 2026-07-28.
    if ($target -and $script:LongPathIds.ContainsKey($id)) { $target = ConvertTo-ExtendedPath $target }
    # resume gate: skip a step already satisfied by a prior run (name known-ok + output present + non-empty)
    if (Test-StepSatisfied $Name $target) {
        Write-Ledger $id $Name $phase 'skipped' @{ reason='already-ok' }
        Write-Audit "STEP $id SKIP | $Name | already satisfied (resume)"; $script:StepsOk++; return $null
    }
    Write-Ledger $id $Name $phase 'planned' @{ timeout_s=$TimeoutSec }
    # maxAttempt covers the longest fix ladder (4 rungs) so a late rung is actually reachable;
    # a ladder whose last rung can never be tried is the same unreachable-capability bug again.
    $attempt = 0; $start = Get-Date; $maxAttempt = 4; $cls = ''
    while ($attempt -lt $maxAttempt) {
        $attempt++; $job = $null
        # the extend-timeout rung grants this step a larger bound for its remaining attempts
        $effTimeout = if ($script:TmoBoost.ContainsKey($id)) { $TimeoutSec * $script:TmoBoost[$id] } else { $TimeoutSec }
        Write-Ledger $id $Name $phase 'running' @{ attempt=$attempt }
        try {
            $out = $null; $stepTimedOut = $false; $job = $null
            if ($script:JobsOk) { try { $job = Start-Job -ScriptBlock $Script } catch { $script:JobsOk = $false; Write-Audit "STEP $id INFO | $Name | job start failed -> in-process ($($_.Exception.Message.Split([Environment]::NewLine)[0]))" } }
            if ($script:JobsOk -and $job) {
                if (Wait-Job $job -Timeout $effTimeout) {
                    $out = Receive-Job $job -ErrorAction SilentlyContinue 2>&1
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                } else {
                    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
                    $stepTimedOut = $true
                }
            } else {
                $r = Invoke-InProcBounded $Script $effTimeout
                if ($r.done) { $out = $r.out } else { $stepTimedOut = $true }
            }
            if (-not $stepTimedOut) {
                # separate real data from non-terminating error records (job merges stderr via 2>&1)
                $errRecs  = @($out | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
                $hasData  = @($out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).Count -gt 0
                if ($target -and $hasData) { try { [IO.File]::WriteAllText($target, (($out | Out-String -Width 4096)), (New-Object Text.UTF8Encoding($false))) } catch { try { $out | Out-File -LiteralPath $target -Encoding UTF8 -Width 4096 } catch {} } }
                $dur = [int]((Get-Date) - $start).TotalSeconds
                # soft failure: the job ran but produced ONLY errors and no usable data
                if (-not $hasData -and $errRecs.Count -gt 0) {
                    $errText = ($errRecs | ForEach-Object { $_.ToString() }) -join '; '
                    $cls = Get-ErrorClass 'errorrecord' $errText
                    Write-Audit "STEP $id WARN | $Name | error-only (class=$cls) | try $attempt"
                    if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
                    Write-Ledger $id $Name $phase 'failed' @{ rc='error'; error_class=$cls; error_msg=$errText.Substring(0,[Math]::Min(200,$errText.Length)) }
                    Add-Content -LiteralPath $ErrLog -Value "$(Now-Utc) [$id] $Name : $errText"; $script:StepsFail++; return $out
                }
                # -LiteralPath: with -Path, a bundle path containing [ ] ? or * (a -CaseId like
                # "IR-2026-[URGENT]" is enough) resolves to nothing, so bytes reads 0 and a step
                # that wrote perfectly good evidence gets recorded as EMPTY - and a CORE step
                # doing that drives the verdict to INCOMPLETE. Found in the B6 follow-up sweep.
                $bytes = if ($target -and (Test-Path -LiteralPath $target)) { (Get-Item -LiteralPath $target).Length } else { 0 }
                $lines = if ($out) { @($out).Count } else { 0 }
                Write-Audit ("STEP $id OK   | $Name | ${dur}s | try $attempt | lines=$lines" + $(if($target){" -> $(Split-Path $target -Leaf)"}))
                # A step that ran without error but produced NOTHING is not a success worth
                # reporting as one. Measured on a range VM with WMI stopped: 10 core volatile
                # artifacts (processes, process owners, TCP/UDP connections, services-by-task,
                # drivers, local users, systeminfo, os/computer) silently vanished while the run
                # reported verdict=COMPLETE, ok=33, failed=0 - identical to a healthy run. An
                # analyst would read "no suspicious processes" from evidence that captured no
                # processes at all. Record emptiness so the verdict can tell the truth.
                # Which subsystem did this step depend on? Derived from the step's OWN SOURCE TEXT
                # rather than a hand-maintained name list, because this file already carries a
                # warning that such a list silently no-ops when a name stops matching (see
                # $script:CriticalSteps). A scriptblock cannot drift from itself.
                if ($OutFile -and $Script.ToString() -match 'Get-CimInstance|Get-WmiObject') {
                    $script:CimStepsRan += $Name
                }
                if ($OutFile -and $bytes -le 2) {
                    $script:EmptySteps += [pscustomobject]@{ id=$id; name=$Name; phase=$phase; file=$OutFile }
                    Write-Ledger $id $Name $phase 'ok' @{ attempt=$attempt; bytes=$bytes; lines=$lines; empty=$true }
                    Write-Audit "STEP $id OK-EMPTY | $Name | produced no output -> $OutFile"
                } elseif ($OutFile -and ($why = Test-DegradedOutput -Path $target -Bytes $bytes)) {
                    # wrote something, but that something is a refusal - not evidence
                    $script:DegradedSteps += [pscustomobject]@{ id=$id; name=$Name; phase=$phase; file=$OutFile; reason=$why; bytes=$bytes }
                    Write-Ledger $id $Name $phase 'ok' @{ attempt=$attempt; bytes=$bytes; lines=$lines; degraded=$true; error_class='not_elevated'; error_msg=$why }
                    Write-Audit "STEP $id OK-DEGRADED | $Name | output is an access refusal, not data ($bytes B): $why"
                } else {
                    Write-Ledger $id $Name $phase 'ok' @{ attempt=$attempt; bytes=$bytes; lines=$lines }
                }
                $script:StepsOk++; return $out
            } else {
                # timed out (either transport). The job (if any) is already stopped above. Kill any NATIVE
                # grandchild (e.g. winpmem) by name so a hung imager stops appending before the verify.
                foreach($pn in $KillOnTimeout){ try { Get-Process -Name $pn -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {} }
                $cls = 'timeout'
                Write-Audit "STEP $id WARN | $Name | TIMEOUT ${TimeoutSec}s | try $attempt"
                if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
                Write-Ledger $id $Name $phase 'timeout' @{ rc='timeout'; error_class=$cls; attempts=$attempt; error_msg="exceeded ${TimeoutSec}s timeout" }
                Add-Content -LiteralPath $ErrLog -Value "$(Now-Utc) [$id] $Name : timeout ${TimeoutSec}s"; $script:StepsFail++; return $null
            }
        } catch {
            if ($job) { try { Remove-Job $job -Force -ErrorAction SilentlyContinue } catch {} }
            $emsg = $_.Exception.Message; $cls = Get-ErrorClass 'exception' $emsg
            Write-Audit "STEP $id ERR  | $Name | $emsg | try $attempt (class=$cls)"
            if (Invoke-Remediation $cls $Name $id $phase $attempt) { Start-Sleep -Milliseconds (Get-Backoff $cls $attempt); continue }
            Write-Ledger $id $Name $phase 'failed' @{ rc='exception'; error_class=$cls; error_msg=$emsg.Substring(0,[Math]::Min(200,$emsg.Length)) }
            Add-Content -LiteralPath $ErrLog -Value "$(Now-Utc) [$id] $Name : $($_.Exception|Out-String)"; $script:StepsFail++; return $null
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

# Breadcrumb for an INTERRUPTED run. Measured on range WS02 (2026-07-28): a hard kill 90s into a
# collection - what an EDR live-response harness does at its ~30 minute cap - skips PowerShell
# finally blocks entirely, so the always-seal wrapper never runs. No SUMMARY.md, no run_state.json,
# no manifest: the tree looks abandoned. It is not - the append-only ledger survives intact and
# -Resume finishes the job (verified: ok=38 skipped=32 failed=0). Nothing told the operator that,
# so leave a note that only exists while the run is unfinished. Invoke-Seal removes it.
# DESTINATION PREFLIGHT. Measured on WS01 against a genuinely full 40 MB volume (0 KB free,
# a 512 KB write refused): the collector starts, writes a handful of files, then dies before it
# ever reaches Invoke-Seal - so run_state.json is never written AND the ENOSPC rollup fallback
# added earlier never fires, because that fallback lives inside seal. The operator is left with a
# few files and no diagnosis whatsoever. A self-heal that only works if the run survives to the
# end is no use when the destination is full from the first write, so refuse up front instead.
$minFree = 64MB
$freeNow = Get-FreeBytes $OutDir
if ($freeNow -ge 0 -and $freeNow -lt $minFree) {
    $msg = "Destination has only {0:N1} MB free; a collection needs at least {1:N0} MB." -f ($freeNow/1MB), ($minFree/1MB)
    Write-Host ''
    Write-Host "  !! $msg" -ForegroundColor Red
    Write-Host '  !! Refusing to start: on a full destination this tool cannot even record WHY it failed' -ForegroundColor Red
    Write-Host '  !! (the run dies before the seal step that writes the diagnostics).' -ForegroundColor Red
    Write-Host '  !! Point -Dest at larger media, or free space and re-run.' -ForegroundColor Yellow
    Write-Host ''
    try { Write-Audit "PREFLIGHT REFUSED: $msg" } catch {}
    # Do not leave the empty output tree behind. Refusing while a case folder sits on the target
    # reads as "it collected something" - remove it so the refusal is unambiguous. Only ever
    # removes a directory this run just created and never wrote evidence into.
    try {
        $leftovers = @(Get-ChildItem -LiteralPath $OutDir -Recurse -File -Force -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -notin 'audit.log','errors.log' })
        if ($leftovers.Count -eq 0) { Remove-Item -LiteralPath $OutDir -Recurse -Force -ErrorAction SilentlyContinue }
    } catch {}
    exit 40
}
Write-Audit ("PREFLIGHT destination: {0:N1} GB free" -f ($freeNow/1GB))

$script:ResumeNote = Join-Path $OutDir 'RUN-INTERRUPTED-READ-ME.txt'
# WRITE-THROUGH, deliberately. Measured on range WS02 under a hard power event (qm reset):
# run_state.jsonl and audit.log survived because they are appended to continuously, which keeps
# forcing metadata flushes - but this file, written once at t=0 and never touched again, sat in
# the NTFS cache and was LOST. A breadcrumb that only exists to explain an interrupted run is
# useless if it cannot survive the interruption. Flush it to disk immediately.
try { $script:ResumeNoteText = @"
THIS COLLECTION DID NOT FINISH.

If this file is still here, the collector was interrupted - killed by an EDR/live-response
timeout, a reboot, or the console being closed. A hard kill cannot run the seal step, so this
tree has no SUMMARY.md, no run_state.json and no manifest. That does NOT mean the evidence is
lost: every completed step is recorded in 99_logs
un_state.jsonl, and resuming re-runs only
what is missing.

Resume with:

    .\collectors\IR-Collect.ps1 -CaseId '$CaseId' -Resume '$OutDir'

Resuming also performs the seal, after which this file is deleted automatically.
Do not treat an unsealed tree as a failed collection until you have tried the above.
"@, (New-Object Text.UTF8Encoding($false))
      $fsn = New-Object IO.FileStream($script:ResumeNote,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
      try { $bytes = [Text.Encoding]::UTF8.GetBytes($script:ResumeNoteText); $fsn.Write($bytes,0,$bytes.Length); $fsn.Flush($true) } finally { $fsn.Dispose() }
    } catch {}
Write-Audit "===== IR-Collect START ====="
Write-Audit "Case=$CaseId Host=$hostName Output=$OutDir Elevated=$isAdmin DomainJoined=$domainJoined PS=$($PSVersionTable.PSVersion)"
function Test-NetworkDestination {
    <#  Prove the network destination is writable NOW, not at seal time.

        Network destinations are staged locally and shipped at the end, which is the right design
        - writing evidence across SMB during live response is slow and fragile. But nothing
        validated the share up front, so an operator pointed at a share they cannot write to ran
        the ENTIRE collection before finding out. Measured on range-WS02 2026-07-28 against
        \<dc>\C$: 175 s for a RapidOnly run, and a full -Auto run is 20+ minutes.

        This is a WARNING, never a refusal: the evidence is staged locally and is not at risk, so
        stopping the collection would destroy volatile data over a credential problem. Telling the
        operator at second 5 lets them fix it while the run proceeds.

        An unreachable host is slow to fail (31 s measured), so the probe is bounded - waiting
        longer than the operator would tolerate defeats the point of probing early. #>
    param([string]$Unc, [int]$TimeoutSec = 20)
    $res = [ordered]@{ target = $Unc; ok = $false; reason = ''; seconds = 0 }
    $t0 = Get-Date
    $probeDir = $null
    try {
        $probeDir = [IO.Path]::Combine($Unc, ".irprobe_$([guid]::NewGuid().ToString('N').Substring(0,8))")
        $job = Start-Job -ScriptBlock {
            param($d)
            try {
                [void][IO.Directory]::CreateDirectory($d)
                $f = [IO.Path]::Combine($d, 'p.txt')
                [IO.File]::WriteAllText($f, 'x')
                $back = [IO.File]::ReadAllText($f)
                [IO.File]::Delete($f); [IO.Directory]::Delete($d)
                if ($back -ne 'x') { return 'probe file did not read back' }
                return 'OK'
            } catch { return ($_.Exception.Message -split "`r?`n")[0] }
        } -ArgumentList $probeDir
        if (Wait-Job $job -Timeout $TimeoutSec) {
            $r = Receive-Job $job
            if ("$r" -eq 'OK') { $res.ok = $true } else { $res.reason = "$r" }
        } else {
            $res.reason = "no response within ${TimeoutSec}s (host unreachable or SMB hung)"
        }
        Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    } catch {
        # Start-Job can be unavailable (job subsystem blocked); fall back to a direct probe rather
        # than reporting a healthy destination we never actually tested
        try {
            [void][IO.Directory]::CreateDirectory($probeDir)
            $f = [IO.Path]::Combine($probeDir, 'p.txt'); [IO.File]::WriteAllText($f, 'x')
            $res.ok = ([IO.File]::ReadAllText($f) -eq 'x')
            [IO.File]::Delete($f); [IO.Directory]::Delete($probeDir)
        } catch { $res.reason = ($_.Exception.Message -split "`r?`n")[0] }
    }
    $res.seconds = [int]((Get-Date) - $t0).TotalSeconds
    [pscustomobject]$res
}
if ($NetworkDest) {
    Write-Audit "Destination is NETWORK: staging locally, shipping to $NetworkDest at seal."
    $script:NetProbe = Test-NetworkDestination $NetworkDest
    if ($script:NetProbe.ok) {
        Write-Audit "PREFLIGHT ship target: $NetworkDest is writable ($($script:NetProbe.seconds)s)."
    } else {
        Write-Audit "PREFLIGHT SHIP TARGET UNWRITABLE: $NetworkDest - $($script:NetProbe.reason). Collection CONTINUES and the bundle will be retained locally; fix credentials/share now if you want it shipped."
        Write-Host ''
        Write-Host "  !! Ship target $NetworkDest is NOT writable: $($script:NetProbe.reason)" -ForegroundColor Yellow
        Write-Host '  !! Collecting anyway - evidence is staged locally and will be retained there.' -ForegroundColor Yellow
        Write-Host '  !! Fix the share or credentials now and the seal-time ship will succeed.' -ForegroundColor Yellow
        Write-Host ''
    }
} else { Write-Audit "Destination is local/drive: $Dest" }
$detected = ($TOOL.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key }) -join ', '
Write-Audit "Pro tools detected: $(if($detected){$detected}else{'(none - native fallbacks only)'})"
if (-not $isAdmin) { Write-Audit "WARNING: not elevated - some data (process owners, RAM, hives, netstat -b) will be incomplete." }

# DOCTRINE: host is assumed compromised. Prefer carried tools; use kernel-level
# APIs (CIM/.NET/ADSI) over host userland exes; record hashes of any carried tool.
if (Test-Path $ToolDir) {
    # Snapshot the toolkit: path -> SHA-256. Kept in memory so the seal can re-verify it, because
    # a carried tool can VANISH mid-run - AV quarantine is the ordinary cause (winpmem and
    # Velociraptor are routinely flagged), and a compromised host tampering with the responder's
    # own binaries is the alarming one. Either way the analyst must be told.
    $script:ToolInventory = @{}
    try {
        foreach ($t in @(Get-ChildItem $ToolDir -Recurse -File -Include *.exe,*.ps1 -ErrorAction SilentlyContinue)) {
            $script:ToolInventory[$t.FullName] = (Get-IRSha256 $t.FullName)
        }
    } catch {}
    # The old line claimed "carried tools present" whenever the DIRECTORY existed - it said so on
    # a host whose tools folder was empty, which is a false statement in a custody log.
    if ($script:ToolInventory.Count -gt 0) {
        Write-Audit "DOCTRINE: $($script:ToolInventory.Count) carried tool(s) present in .\tools - preferred over host binaries."
    } else {
        Write-Audit "DOCTRINE NOTE: .\tools exists but is EMPTY - no carried tools. Relying on host binaries and kernel-level APIs (CIM/.NET/ADSI). RAM capture is not possible without a staged imager."
    }
    try {
        $lines = @("# carried tool inventory taken at $(Now-Utc)",
                   "# count: $($script:ToolInventory.Count)")
        if ($script:ToolInventory.Count -eq 0) {
            # an EMPTY file cannot be told apart from an inventory that failed to run; say it
            $lines += 'NONE - no carried tools were present in the toolkit at collection start.'
        } else {
            $lines += @($script:ToolInventory.Keys | Sort-Object | ForEach-Object { "{0}  {1}" -f $script:ToolInventory[$_], $_ })
        }
        $lines | Out-File -LiteralPath (Join-Path $Dirs.metadata 'carried_tools_sha256.txt') -Encoding ASCII
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
try { if (-not (Test-Path -LiteralPath (Join-Path $Dirs.metadata 'intake.json'))) { $di=[ordered]@{ case_id=$CaseId; scenario='U'; scenario_name='Unknown / broad triage'; host_role='unknown'; scope='single'; connectivity='connected'; exercise=[bool]$Lab; generated_by='IR-Collect.ps1 (non-guided)'; known_bad_ips=@(); known_bad_domains=@(); known_bad_hashes=@(); known_bad_accounts=@(); known_bad_paths=@(); attack_tags=@() }; [IO.File]::WriteAllText((Join-Path $Dirs.metadata 'intake.json'), ($di | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false))) } } catch {}

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
    $tf = Join-Path $OutputRoot ('.irwrite_' + $stamp); Set-Content -LiteralPath $tf -Value 'x' -ErrorAction Stop; Remove-Item -LiteralPath $tf -Force -ErrorAction SilentlyContinue
} catch { Write-Audit "PREFLIGHT: destination NOT writable - $($_.Exception.Message)"; Write-Host "!!! DESTINATION NOT WRITABLE: $OutputRoot - fix the drive/path; this collection may capture nothing !!!" -ForegroundColor Red }
try {
    $destRoot = [System.IO.Path]::GetPathRoot((Resolve-Path $OutputRoot).Path)
    $vol = Get-Volume -FilePath $OutputRoot -ErrorAction SilentlyContinue
    if ($vol -and $vol.FileSystem -match 'FAT') {
        Write-Audit "PREFLIGHT WARNING: destination is $($vol.FileSystem) - FAT32 caps files at 4GB; a RAM image will TRUNCATE. Reformat destination NTFS/exFAT."
    } elseif ($vol) { Write-Audit "PREFLIGHT: destination filesystem = $($vol.FileSystem)" }
} catch {}
Write-Audit "PREFLIGHT: privilege=$(if($isAdmin){'full'}else{'PARTIAL - not elevated'}) langMode=$($ExecutionContext.SessionState.LanguageMode) 64bit=$([Environment]::Is64BitProcess)"
# Probe the domain ONCE so the verdict can distinguish "AD returned nothing" from "AD was never
# reachable". $null (not $false) when there is no domain to probe or the probe itself cannot run -
# unknown is not the same as unreachable, and the verdict text says which.
$script:DomainReachable = $null
if ($domainJoined) {
    # Win32_ComputerSystem.Domain FIRST. LOGONSERVER and USERDNSDOMAIN are empty for SYSTEM and,
    # measured on range-WS02 2026-07-29, empty for an interactive admin over SSH too - so a probe
    # keyed on them silently never ran and the verdict could only ever say "reachability unknown".
    # The CIM value is populated in both contexts. Env vars remain as a fallback for hosts where
    # CIM is broken (scenario E1).
    $dcHost = $null
    try { $cs = Get-Inv Win32_ComputerSystem; if ($cs -and $cs.Domain -and $cs.Domain -ne $cs.Workgroup) { $dcHost = "$($cs.Domain)".Trim() } } catch {}
    if (-not $dcHost) { $dcHost = "$env:LOGONSERVER".TrimStart([char]92) }
    if (-not $dcHost) { $dcHost = "$env:USERDNSDOMAIN" }
    if ($dcHost) {
        $script:DomainReachable = try {
            $c = New-Object Net.Sockets.TcpClient
            $ok = $c.BeginConnect($dcHost, 389, $null, $null).AsyncWaitHandle.WaitOne(3000, $false)
            if ($ok -and $c.Connected) { $c.Close(); $true } else { $c.Close(); $false }
        } catch { $false }
    }
    Write-Audit "PREFLIGHT domain: joined=True host=$dcHost ldap389Reachable=$(if($null -eq $script:DomainReachable){'unknown'}else{$script:DomainReachable})"
}
# The redirect decision happens before the audit log exists, so it is buffered and flushed here -
# same pattern the ship preflight needed, enforced by tests/unit/Test-AuditTrailOrder.ps1.
if ($script:PendingRedirectNote) { Write-Audit $script:PendingRedirectNote }
# The case id is a CUSTODY field: if the path form had to be normalised, the operator's original
# wording must still appear in the record that ties this bundle to their paperwork.
if ($script:CaseIdRaw -ne $script:CaseIdSafe) {
    Write-Audit "CASE ID normalised for the filesystem: '$($script:CaseIdRaw)' -> '$($script:CaseIdSafe)'. The original is preserved here and in the run metadata; only the directory name was changed."
}
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
    # Record the host clock AND measure it against a reference. The previous version wrote the
    # host's own time plus a note telling the analyst to "compare against a trusted external time
    # source" - which records nothing about whether the clock is WRONG, and leaves the one
    # measurement that makes a timeline defensible as homework. Measured on range-WS02 2026-07-29
    # with the clock deliberately advanced: the artifact changed (it holds the skewed time) but
    # nothing in it let a reader tell the clock was off.
    Collect 'clock-skew'     {
        'Host local time : ' + (Get-Date).ToString('o')
        'Host UTC time   : ' + ((Get-Date).ToUniversalTime().ToString('o'))
        $src = try { (w32tm /query /source 2>$null | Select-Object -First 1) } catch { $null }
        'Time source     : ' + $(if ($src) { "$src".Trim() } else { 'unknown' })
        $off = $null; $peerUsed = $null
        # the configured source first, then the logon server - a domain member always has one
        foreach ($peer in @("$src".Trim(), ($env:LOGONSERVER -replace '^\\',''))) {
            if (-not $peer) { continue }
            if ($peer -match 'Local CMOS|Free-running|unknown') { continue }
            $sc = try { w32tm /stripchart /computer:$peer /samples:1 /dataonly 2>&1 | Select-Object -Last 1 } catch { $null }
            $m = [regex]::Match("$sc", '([+-]\d+[.,]\d+)s')
            if ($m.Success) { $off = [double]($m.Groups[1].Value -replace ',', '.'); $peerUsed = $peer; break }
        }
        if ($null -ne $off) {
            'Reference peer  : ' + $peerUsed
            $dir = if ($off -lt 0) { 'this host is AHEAD of the reference by {0:0.000}s' -f [Math]::Abs($off) }
                   elseif ($off -gt 0) { 'this host is BEHIND the reference by {0:0.000}s' -f [Math]::Abs($off) }
                   else { 'this host agrees with the reference' }
            'Measured offset : ' + ('{0:+0.000;-0.000;0.000}' -f $off) + 's  (w32tm convention: reference MINUS host)'
            'Interpretation  : ' + $dir
            if ([Math]::Abs($off) -gt 60) {
                'WARNING: this host is more than 60s from its own time source. Timestamps in this bundle are NOT directly comparable with other hosts until the offset above is applied.'
            }
        } else {
            'Reference peer  : NONE REACHABLE'
            'Measured offset : UNAVAILABLE - no time source answered, so this bundle carries no independent evidence that the host clock is correct. Compare these timestamps against a trusted source before building a timeline.'
        }
    } 'clock_provenance.txt' $M

    # --- RAM IMAGE FIRST (RFC 3227: memory is the most volatile capturable artifact) ---
    # Every command below perturbs RAM, so image it before the volatile-command battery.
    if (-not $DeferMemory) {
        Write-Host "Capturing physical memory first (order of volatility)..." -ForegroundColor Cyan
        Job-Memory
    } else { Write-Audit "DeferMemory set - RAM will be captured after volatile commands." }

    # --- host identity (post-image: safe now that the most-volatile artifact is secured) ---
    Collect 'systeminfo'     { $r = try { systeminfo 2>$null } catch { $null }
                               if ($r) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'
                                 $k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                                 "Host          : $env:COMPUTERNAME"; "User          : $env:USERNAME"
                                 "OS            : $((Get-ItemProperty $k -EA SilentlyContinue).ProductName)"
                                 "Build         : $((Get-ItemProperty $k -EA SilentlyContinue).CurrentBuildNumber).$((Get-ItemProperty $k -EA SilentlyContinue).UBR)"
                                 "InstallDate   : $((Get-ItemProperty $k -EA SilentlyContinue).InstallDate)"
                                 "Version       : $([Environment]::OSVersion.VersionString)"
                                 "Architecture  : $env:PROCESSOR_ARCHITECTURE"; "Domain        : $env:USERDOMAIN"
                                 "Boot(approx)  : $((Get-Date).AddMilliseconds(-[Environment]::TickCount64))"
                                 'NICs:'; ipconfig /all } } 'systeminfo.txt' $M
    Collect 'os-cim'         { $r = try { (Get-CimInstance Win32_OperatingSystem -EA Stop | Format-List * | Out-String) + (Get-CimInstance Win32_ComputerSystem -EA Stop | Format-List * | Out-String) } catch { $null }
                               if ($r -and $r.Trim()) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'
                                 Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue | Format-List *
                                 "OSVersion  : $([Environment]::OSVersion.VersionString)"; "Is64BitOS  : $([Environment]::Is64BitOperatingSystem)"
                                 "Machine    : $([Environment]::MachineName)"; "Processors : $([Environment]::ProcessorCount)" } } 'os_computer.txt' $M
    Collect 'timezone'       { Get-TimeZone | Format-List *; 'UTC now: '+((Get-Date).ToUniversalTime().ToString('o')); 'Local now: '+(Get-Date).ToString('o') } 'timezone.txt' $M
    Collect 'boot-uptime'    { $os=Get-CimInstance Win32_OperatingSystem; 'LastBoot: '+$os.LastBootUpTime; 'Install: '+$os.InstallDate } 'boot.txt' $M
    Collect 'env'            { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize } 'environment.txt' $M

    # --- processes (most volatile after memory) ---
    Collect 'processes'      { $r = try { Get-CimInstance Win32_Process -EA Stop | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | Sort-Object ProcessId | Format-Table -AutoSize -Wrap | Out-String -Width 500 } catch { $null }
                               if ($r -and $r.Trim()) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'
                                 Get-Process -EA SilentlyContinue | Select-Object Id,ProcessName,@{n='Path';e={$_.Path}},StartTime,@{n='WS_MB';e={[int]($_.WorkingSet64/1MB)}} | Sort-Object Id | Format-Table -AutoSize | Out-String -Width 500
                                 '--- tasklist /v ---'; tasklist /v 2>$null } } 'processes.txt' $V
    Collect 'processes-csv'  { $r = try { Get-CimInstance Win32_Process -EA Stop | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation } catch { $null }
                               if ($r) { $r } else { Get-Process -EA SilentlyContinue | Select-Object @{n='ProcessId';e={$_.Id}},@{n='Name';e={$_.ProcessName}},@{n='ExecutablePath';e={$_.Path}},@{n='CreationDate';e={$_.StartTime}} | ConvertTo-Csv -NoTypeInformation } } 'processes.csv' $V
    Collect 'process-owners' { $r = try { Get-CimInstance Win32_Process -EA Stop | ForEach-Object { $o=try{(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}catch{'?'}; "$($_.ProcessId)`t$($_.Name)`t$o" } } catch { $null }
                               if ($r) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'; '--- tasklist /v (USER column) ---'; tasklist /v /fo table 2>$null } } 'process_owners.txt' $V -Timeout 120
    Collect 'tasklist-svc'   { $r = try { tasklist /svc 2>$null } catch { $null }
                               if ($r) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'; '--- sc query (service->state) ---'; sc.exe query type= service state= all 2>$null } } 'tasklist_services.txt' $V
    Collect 'drivers'        { $r = try { Get-CimInstance Win32_SystemDriver -EA Stop | Select-Object Name,State,StartMode,PathName | Sort-Object Name | Format-Table -AutoSize | Out-String -Width 300 } catch { $null }
                               # a refusal is not data: sc.exe query needs privilege, driverquery does not
                               if ($r -and $r.Trim() -and $r -notmatch 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation' -and $r.Trim().Length -gt 400) { $r } else {
                                 '### Win32_SystemDriver unavailable or refused - collected via fallback chain ###'
                                 $q = try { $t = sc.exe query type= driver state= all 2>&1 | Out-String; if ($t -and $t -notmatch 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation' -and $t.Trim().Length -gt 400) { $t } else { $null } } catch { $null }
                                 if ($q) { '--- sc.exe query type= driver ---'; $q } else {
                                   $dq = try { $t = driverquery.exe /v /fo table 2>&1 | Out-String; if ($t -and $t -notmatch 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation' -and $t.Trim().Length -gt 200) { $t } else { $null } } catch { $null }
                                   if ($dq) { '--- driverquery /v (unprivileged; loaded drivers + start mode) ---'; $dq } else {
                                     '--- on-disk driver inventory only (no loaded-driver state available) ---'
                                     Get-ChildItem "$env:WINDIR\System32\drivers\*.sys" -EA SilentlyContinue | Select-Object Name,Length,LastWriteTimeUtc | Format-Table -AutoSize | Out-String -Width 300 } } } } 'drivers.txt' $V
    if ($TOOL.handle)   { Collect 'sys-handle'  ([scriptblock]::Create("& '$($TOOL.handle)' -accepteula -a -nobanner")) 'handles.txt' $V -Timeout 120 }
    if ($TOOL.listdlls) { Collect 'sys-listdlls' ([scriptblock]::Create("& '$($TOOL.listdlls)' -accepteula")) 'listdlls.txt' $V -Timeout 120 }

    # --- sessions / logged-on ---
    Collect 'whoami-all'     { whoami /all } 'whoami_all.txt' $V
    # `net session` and `query session` need privilege; Win32_LogonSession + explorer.exe owners
    # still establish who is logged on, so the session picture degrades rather than disappearing.
    Collect 'sessions'       { $r = try { @(query user 2>&1; '---'; query session 2>&1; '---'; net session 2>&1) | Out-String } catch { '' }
                               if ($r -and $r -notmatch 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation' -and $r.Trim().Length -gt 120) { $r } else {
                                 '### session enumeration partly refused - unprivileged fallback ###'
                                 '--- query user (best effort) ---'; try { query user 2>&1 } catch {}
                                 '--- Win32_LogonSession (interactive) ---'
                                 try { Get-CimInstance Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10 OR LogonType=11' -EA Stop | Select-Object LogonId,LogonType,StartTime | Format-Table -AutoSize | Out-String } catch { '(unavailable)' }
                                 '--- shell owners (who has a desktop) ---'
                                 try { Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -EA Stop | ForEach-Object { $o=try{(Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User}catch{'?'}; "$($_.ProcessId)`t$o" } } catch { '(unavailable)' } } } 'sessions.txt' $V
    Collect 'klist'          { klist; '=== TGT ==='; klist tgt } 'kerberos_tickets.txt' $V
    Collect 'local-users'    { $r = try { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=true" -EA Stop | Format-Table Name,SID,Disabled,Lockout -AutoSize | Out-String } catch { $null }
                               if ($r -and $r.Trim()) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'
                                 $lu = try { Get-LocalUser -EA Stop | Format-Table Name,SID,Enabled,LastLogon -AutoSize | Out-String } catch { $null }
                                 if ($lu -and $lu.Trim()) { $lu } else { '--- net user ---'; net user 2>$null } } } 'local_users.txt' $V
    Collect 'local-admins'   { net localgroup Administrators } 'local_admins.txt' $V
    try { Get-Clipboard -Raw -ErrorAction SilentlyContinue | Set-Content (Join-Path $V 'clipboard.txt') -Encoding UTF8; Write-Audit 'STEP clipboard captured (STA main scope)' } catch { Write-Audit 'clipboard capture failed' }
    if ($TOOL.psloggedon) { Collect 'sys-psloggedon' ([scriptblock]::Create("& '$($TOOL.psloggedon)' -accepteula")) 'psloggedon.txt' $V }

    # --- network state (routing/arp/dns before disk) ---
    # -b (owning executable) needs an Administrator token; unelevated it returns a 45-byte refusal.
    # -ano needs no privilege and still yields every endpoint + owning PID, so the connection map
    # survives; only the EXE-name column is lost, and Get-Process recovers most of that.
    Collect 'netstat'        { $r = try { netstat -anob 2>&1 | Out-String } catch { '' }
                               if ($r -and $r -notmatch 'Access is denied|Requested registry access is not allowed|UnauthorizedAccess|requires elevation|Administrator privilege|SeSecurityPrivilege|PermissionDenied|perform an unauthorized operation' -and $r.Trim().Length -gt 200) { $r } else {
                                 '### netstat -anob needs an Administrator token - collected via unprivileged fallback ###'
                                 '### -ano gives every endpoint and owning PID; the owning EXE-NAME column is unobtainable ###'
                                 netstat -ano 2>$null
                                 '--- owning process names resolved via Get-Process (best effort) ---'
                                 try { Get-NetTCPConnection -EA Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}} | Sort-Object State,LocalPort | Format-Table -AutoSize | Out-String -Width 300 } catch { '(Get-NetTCPConnection unavailable)' } } } 'netstat_anob.txt' $N
    Collect 'tcp-conns'      { $r = try { Get-NetTCPConnection -EA Stop | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object State,LocalPort | Format-Table -AutoSize | Out-String -Width 300 } catch { $null }
                               if ($r -and $r.Trim()) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'; '--- netstat -ano (TCP) ---'; netstat -ano -p TCP 2>$null } } 'tcp_connections.txt' $N
    Collect 'udp-endpoints'  { $r = try { Get-NetUDPEndpoint -EA Stop | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize | Out-String -Width 300 } catch { $null }
                               if ($r -and $r.Trim()) { $r } else { '### CIM/WMI unavailable - collected via native fallback (data is equivalent, formatting differs) ###'; '--- netstat -ano (UDP) ---'; netstat -ano -p UDP 2>$null } } 'udp_endpoints.txt' $N
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
    Collect 'services'        { $r = try { Get-CimInstance Win32_Service -EA Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Sort-Object Name | ConvertTo-Csv -NoTypeInformation } catch { $null }
                                if ($r) { $r } else { Get-Service -EA SilentlyContinue | Select-Object Name,DisplayName,@{n='State';e={$_.Status}},@{n='StartMode';e={$_.StartType}},@{n='StartName';e={'(needs WMI)'}},@{n='PathName';e={(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -EA SilentlyContinue).ImagePath}} | Sort-Object Name | ConvertTo-Csv -NoTypeInformation } } 'services.csv' $P
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
  Where-Object { `$_.FullName -notmatch 'MANIFEST-SHA256\.csv$' -and `$_.FullName -notmatch '99_logs\\(audit|errors)\.log$' -and `$_.FullName -notmatch '99_logs\\run_state\.jsonl$' } |
  ForEach-Object { try { `$h=Get-IRSha256 `$_.FullName } catch { `$h='ERR' }
    '{0},{1},{2}' -f `$h, `$_.Length, `$_.FullName.Replace('$Dir','') }
"@
}

# An ENOSPC mid-append leaves a PARTIAL final record, so run_state.jsonl stops being valid JSONL
# and strict parsers choke on the very file that explains the failure. Keep only whole records.
# Called twice - before the rollup reads the ledger, and again after seal's own steps append.
function Repair-LedgerTail {
    try {
        if (-not (Test-Path -LiteralPath $script:StateJsonl)) { return }
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
    try { $summary | Out-File -LiteralPath (Join-Path $OutDir 'SUMMARY.md') -Encoding UTF8 } catch {}
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
    # --- toolkit re-verification: did a carried tool change or vanish during the run? ---
    # AV quarantine is the ordinary cause and is EXPECTED in the field (winpmem and Velociraptor
    # are routinely flagged); host tampering with the responder's binaries is the alarming one.
    # Either way, a tool that is not the tool we hashed at the start invalidates any conclusion
    # drawn from its output, so it belongs in the verdict and not in a buried audit line.
    # Measured on range-WS02 2026-07-28 (scenario A5): Defender quarantined a file out of the
    # toolkit mid-scenario and the run sealed COMPLETE, exit 0, with nothing recorded anywhere.
    if ($script:ToolInventory -and $script:ToolInventory.Count -gt 0) {
        $tv = Compare-ToolInventory $script:ToolInventory
        $script:ToolVanished = @($tv.Vanished); $script:ToolChanged = @($tv.Changed)
        if ($script:ToolVanished.Count -or $script:ToolChanged.Count) {
            $msg = "TOOLKIT TAMPERED DURING RUN: $($script:ToolVanished.Count) vanished$(if($script:ToolVanished){" ($($script:ToolVanished -join ', '))"}), $($script:ToolChanged.Count) hash-changed$(if($script:ToolChanged){" ($($script:ToolChanged -join ', '))"}). Most likely AV quarantine; on a compromised host, consider tampering. Any output from these tools is suspect."
            Write-Audit $msg
            $ec = 'tool_missing'
            if (-not $script:DiagClass.Contains($ec)) { $script:DiagClass[$ec] = [ordered]@{ count=0; sample='' } }
            $script:DiagClass[$ec].count += ($script:ToolVanished.Count + $script:ToolChanged.Count)
            if (-not $script:DiagClass[$ec].sample) { $script:DiagClass[$ec].sample = $msg.Substring(0, [Math]::Min(200, $msg.Length)) }
        } else {
            Write-Audit "TOOLKIT VERIFIED: all $($script:ToolInventory.Count) carried tool(s) unchanged since collection start."
        }
        try {
            @("# toolkit re-verification at $(Now-Utc)",
              "# tools at start: $($script:ToolInventory.Count)",
              "# vanished during run: $($script:ToolVanished.Count) $($script:ToolVanished -join ', ')",
              "# hash-changed during run: $($script:ToolChanged.Count) $($script:ToolChanged -join ', ')") |
              Out-File -LiteralPath (Join-Path $Dirs.metadata 'carried_tools_verify.txt') -Encoding ASCII
        } catch {}
    }
    if ($script:ToolVanished.Count -or $script:ToolChanged.Count) {
        $incomplete += "toolkit-tampered($((@($script:ToolVanished) + @($script:ToolChanged)) -join '/'))"
    }
    # AD enumeration that came back empty because the domain was unreachable is missing evidence,
    # not an empty result set. See Get-DomainEvidenceVerdict for why this is not just more entries
    # in CriticalSteps.
    $emptyAd = @($script:EmptySteps | Where-Object { $_.name -like 'ad-*' } | ForEach-Object { $_.name } | Sort-Object -Unique)
    $domNote = Get-DomainEvidenceVerdict -DomainJoined ([bool]$domainJoined) -DomainReachable $script:DomainReachable -EmptyAdSteps $emptyAd
    if ($domNote) { $incomplete += $domNote; Write-Audit "VERDICT: $domNote" }
    $criticalEmpty = @($script:EmptySteps | Where-Object { $script:CriticalSteps -contains $_.name } | ForEach-Object { $_.name } | Sort-Object -Unique)
    if ($criticalEmpty.Count) { $incomplete += "core-volatile-empty($($criticalEmpty -join '/'))" }
    # output that is an access refusal rather than data is missing evidence, whatever its byte count
    $degradedNames = @($script:DegradedSteps | ForEach-Object { $_.name } | Sort-Object -Unique)
    if ($degradedNames.Count) { $incomplete += "access-denied($($degradedNames -join '/'))" }
    # An unelevated live-response triage CANNOT be complete: RAM, registry hives, the Security
    # event log, the full driver list and per-connection process ownership all require an
    # Administrator token. Saying COMPLETE here would tell an analyst the absence of a finding
    # is meaningful when the query was never permitted to run. Verified on range-WS02 as a
    # standard user, 2026-07-28: ok=33 fail=0 skip=0, verdict COMPLETE, with drivers.txt at 155 B.
    if (-not $isAdmin) { $incomplete += 'unelevated(privileged artifacts unobtainable without Administrator)' }
    $verdict = if ($incomplete.Count -gt 0) { 'INCOMPLETE' } else { 'COMPLETE' }
    # --- CIM evidence census -------------------------------------------------------------------
    # Done HERE, at seal, not inside the steps: a step scriptblock may run in a background-job
    # runspace, where $script: writes never come back to this scope. The artifacts are the reliable
    # carrier, and the banner is already written by the fallback branches themselves.
    $script:CimProbeOk = $null
    try { $null = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; $script:CimProbeOk = $true }
    catch { $script:CimProbeOk = $false }
    # Three-state on the SCAN itself, not just on its result. If this throws, an empty
    # $script:FallbackSteps is indistinguishable from "no step fell back" - the same collapse this
    # census exists to fix, one level up. Found by the safe-default sweep 2026-07-29, in my own code.
    $script:FallbackScanOk = $true
    $script:FallbackSteps = @()
    try {
        foreach ($d in @($Dirs.volatile, $Dirs.system, $Dirs.network) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }) {
            foreach ($f in Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue) {
                if ($f.Length -gt 2MB) { continue }   # banners are written at the top of small text artifacts
                $head = ''
                try { $head = (Get-Content -LiteralPath $f.FullName -TotalCount 40 -ErrorAction Stop) -join "`n" } catch { continue }
                if ($head -match 'unavailable.*(native fallback|fallback chain)') { $script:FallbackSteps += $f.Name }
            }
        }
    } catch { $script:FallbackScanOk = $false }
    $cimEmpty = @($script:EmptySteps | Where-Object { $script:CimStepsRan -contains $_.name } | ForEach-Object { $_.name })
    $script:CimEvidence = Get-CimEvidenceVerdict -CimAvailable $script:CimProbeOk -FallbackSteps $script:FallbackSteps -EmptyCimSteps $cimEmpty
    if (-not $script:FallbackScanOk -and $script:CimEvidence) {
        $script:CimEvidence.note = $script:CimEvidence.note + ' NOTE: the fallback scan itself failed, so the list of native-sourced artifacts below is INCOMPLETE - absence from it is not evidence a step used CIM.'
    }

    # Did the BitLocker capture actually get keys? Read the shipped artifact rather than trusting
    # that the step exited 0 - the step succeeds whether or not the password field came back empty.
    # Three outcomes, and a read failure is 'unknown', never a clean bill of health.
    $blRows = $null; $blScanOk = $null
    try {
        $blCsv = Join-Path $M 'bitlocker_recovery_keys.csv'
        if (Test-Path -LiteralPath $blCsv) {
            $all = @(Get-Content -LiteralPath $blCsv -ErrorAction Stop)
            $blRows = @($all | Select-Object -Skip 1)
            $blScanOk = $true
        } elseif ($NoKeyCapture) {
            $blScanOk = $true; $blRows = @()      # deliberately not collected; not a failure
        }
    } catch { $blScanOk = $false }
    $script:BitLockerKeys = Get-BitLockerKeyVerdict -Rows $blRows -ScanOk $blScanOk
    if ($script:BitLockerKeys.state -in @('no-key-captured','partial')) {
        Write-Audit "KEY CAPTURE INCOMPLETE: $($script:BitLockerKeys.note)"
    }

    $rs = [ordered]@{
        schema='ir-collect/run-state@1'; tool='IR-Collect.ps1'; case=$script:CaseIdRaw; case_path_token=$script:CaseIdSafe; host=$hostName; output_dir=$OutDir
        ended_utc=$endUtc; status=$(if($verdict -eq 'COMPLETE'){'complete'}else{'partial'}); resumed=[bool]$Resume
        langMode="$($ExecutionContext.SessionState.LanguageMode)"; ps_version="$($PSVersionTable.PSVersion)"; elevated=[bool]$isAdmin
        counts=[ordered]@{ planned=$nplan; ok=$nok; failed=$nfail; timeout=$ntmo; skipped=$nskip }
        memory_verified=[bool]$script:MemOk
        completeness=[ordered]@{ verdict=$verdict; incomplete=@($incomplete) }
        # The ship happens AFTER this file is written and hashed into the manifest - recording the
        # outcome here would either be a null claiming nothing, or a post-seal rewrite that
        # invalidates the custody digest. So state what IS known at seal time, and point at the
        # file written beside the bundle once the transfer has actually been attempted.
        ship=[ordered]@{ target=$NetworkDest; attempted=[bool]$NetworkDest; preflight_ok=$(if($script:NetProbe){[bool]$script:NetProbe.ok}else{$null}); preflight_reason=$(if($script:NetProbe){$script:NetProbe.reason}else{$null}); result_file=$(if($NetworkDest){'<bundle>.ship.json (written after the seal)'}else{$null}) }
        diagnostics=[ordered]@{ exec_mode=$(if($script:JobsOk){'background-job'}else{'in-process(self-heal)'}); language_mode=$script:LangMode; hash_backend=$script:HashBackend; empty_outputs=@($script:EmptySteps | ForEach-Object { $_.name }); degraded_outputs=@($script:DegradedSteps | ForEach-Object { [ordered]@{ name=$_.name; bytes=$_.bytes; reason=$_.reason } }); by_error_class=$script:DiagClass; remediations=$script:DiagRem; subsystem_failure=$(
            # Machine-readable twin of the report section. Null on a healthy host, and on any host
            # where at least one CIM step returned data - emptiness alone never sets it.
            $sf = Get-SubsystemFailureVerdict -Ran $script:CimStepsRan -Empty @($script:EmptySteps | ForEach-Object { $_.name })
            if ($sf) { [ordered]@{ subsystem=$sf.subsystem; error_class=$sf.class; steps=$sf.steps; ladder=@($script:FixLadders[$sf.class]); inferred_from='every subsystem-backed step empty (no error was raised)' } } else { $null }
        ); encryption_risk=$script:EncVerdict; cim_evidence=$script:CimEvidence; bitlocker_keys=$script:BitLockerKeys; subsystem_probe=$(
            # Never a bare null: says WHICH of the three situations produced it.
            Get-SubsystemProbeState -Ran $script:CimStepsRan -Empty @($script:EmptySteps | ForEach-Object { $_.name })
        ) }
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
    $comp += "- resume: .\collectors\IR-Collect.ps1 -CaseId '$CaseId' -Resume '$OutDir'`n"
    if (-not $isAdmin) {
        $comp += "`n## UNELEVATED COLLECTION - READ BEFORE DRAWING CONCLUSIONS`n"
        $comp += "This ran as ``$env:USERNAME`` WITHOUT an Administrator token. The absence of a finding in`n"
        $comp += "the artifacts below is NOT evidence of absence - the query was never permitted to run.`n"
        $comp += "- physical memory: not acquirable (no driver load right)`n- registry hives (SAM/SYSTEM/SECURITY) and the Security event log: not readable`n"
        $comp += "- full driver list, per-connection process ownership (netstat -b), other users' sessions and handles: refused`n"
        if ($script:DegradedSteps.Count) {
            $comp += "`nSteps whose output was an access refusal rather than data:`n"
            foreach ($d in $script:DegradedSteps) { $comp += "- ``$($d.name)`` -> $($d.file) ($($d.bytes) B): $($d.reason)`n" }
        }
        $comp += "`nRe-run elevated to obtain these.`n"
    } elseif ($script:DegradedSteps.Count) {
        $comp += "`n## Access-denied artifacts`n"
        foreach ($d in $script:DegradedSteps) { $comp += "- ``$($d.name)`` -> $($d.file) ($($d.bytes) B): $($d.reason)`n" }
    }
    # NOT inside the diagnostics guard below. That guard fires only when something ELSE already
    # went wrong (an error was classified, jobs failed, or the hash backend fell back). On a host
    # whose WMI is simply dead none of those is true - the fallbacks absorb it - so the finding was
    # suppressed by exactly the condition it exists to report. Caught live 2026-07-29: the report
    # named the outage and SUMMARY.md stayed silent.
    if ($script:CimEvidence -and $script:CimEvidence.state -ne 'cim-sourced') {
        $comp += "`n## Evidence source`n- CIM/WMI: **$($script:CimEvidence.state)** - $($script:CimEvidence.note)"
        if (@($script:CimEvidence.fallback_steps).Count) { $comp += "`n- artifacts collected via native fallback: $(@($script:CimEvidence.fallback_steps) -join ', ')" }
    }
    if (($script:DiagClass.Count -gt 0) -or (-not $script:JobsOk) -or ($script:HashBackend -ne 'Get-FileHash')) {
        $comp += "`n## Diagnostics (self-diagnosis)`n- exec mode: $(if($script:JobsOk){'background-job'}else{'in-process fallback (job subsystem unavailable)'})`n"
        $comp += "- hash backend: $script:HashBackend$(if($script:HashBackend -ne 'Get-FileHash'){' (Get-FileHash unavailable on this host - .NET fallback in use)'})`n"
        foreach($k in $script:DiagClass.Keys){ $sm=$script:DiagClass[$k].sample; $comp += "- ${k}: $($script:DiagClass[$k].count) step(s)$(if($sm){" - e.g. $sm"})`n" }
        if ($script:DiagRem.Count -gt 0) { $comp += "- self-heal actions: " + (($script:DiagRem.GetEnumerator()|ForEach-Object{"$($_.Key) x$($_.Value)"}) -join ', ') + "`n" }
    }
    try { Add-Content -LiteralPath (Join-Path $OutDir 'SUMMARY.md') -Value $comp -Encoding UTF8 } catch {}
    $script:RunIncomplete = ($verdict -eq 'INCOMPLETE')
    Write-Audit "COMPLETENESS $verdict | ok=$nok fail=$nfail timeout=$ntmo skip=$nskip planned=$nplan"

    # --- DIAGNOSTIC-REPORT.md: the one file to hand to whoever fixes the tool -------------------
    # run_state.json is machine-readable and SUMMARY.md is about the EVIDENCE; neither is a
    # troubleshooting artifact. This is: what the host looked like, which execution paths were
    # taken, exactly what failed and how the self-heal responded, and how to reproduce it.
    #
    # SAFE TO SHARE BY CONSTRUCTION: metadata only. No collected evidence, no file contents, no
    # key material, no IOC values - so it can be sent to a tool maintainer without a data-handling
    # review. Anything that could carry case data is deliberately reduced to a count or a path.
    try {
        $failRows = @()
        if (Test-Path $rsj) {
            foreach ($ln in [IO.File]::ReadAllLines($rsj)) {
                if ($ln -match '"ev":"(failed|timeout)"') {
                    try { $o = $ln | ConvertFrom-Json
                          $failRows += [pscustomobject]@{ id=$o.id; name=$o.name; phase=$o.phase; ev=$o.ev
                                                          cls=$o.error_class; att=$o.attempts; msg=$o.error_msg } } catch {}
                }
            }
        }
        $remRows = @()
        if (Test-Path $rsj) {
            foreach ($ln in [IO.File]::ReadAllLines($rsj)) {
                if ($ln -match '"ev":"remediation"') {
                    try { $o = $ln | ConvertFrom-Json
                          $remRows += [pscustomobject]@{ id=$o.id; name=$o.name; cls=$o.class; action=$o.action; result=$o.result } } catch {}
                }
            }
        }
        $destInfo = try {
            $d = Get-Item -LiteralPath $OutDir -ErrorAction Stop
            $drv = Get-PSDrive -Name ($d.PSDrive.Name) -ErrorAction SilentlyContinue
            "$OutDir  (free: $([math]::Round(($drv.Free/1GB),1)) GB)"
        } catch { "$OutDir  (could not stat)" }

        $rep = New-Object Text.StringBuilder
        [void]$rep.AppendLine("# IR-Collect diagnostic report")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("Hand this file to whoever maintains the tool. It is **metadata only** - no collected")
        [void]$rep.AppendLine("evidence, no file contents, no key material - so it is safe to send as-is.")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## Verdict")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("| | |")
        [void]$rep.AppendLine("|---|---|")
        [void]$rep.AppendLine("| verdict | ``$verdict`` |")
        [void]$rep.AppendLine("| steps | ok=$nok failed=$nfail timeout=$ntmo skipped=$nskip planned=$nplan |")
        [void]$rep.AppendLine("| incomplete | $(if($incomplete.Count){($incomplete -join ', ')}else{'(nothing)'}) |")
        [void]$rep.AppendLine("| memory verified | $([bool]$script:MemOk) ($($script:MemFailCode)) |")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## Host and execution environment")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("| | |")
        [void]$rep.AppendLine("|---|---|")
        [void]$rep.AppendLine("| host / role | $hostName / $(if($HostRole){$HostRole}else{'(unset)'}) |")
        [void]$rep.AppendLine("| OS | $((Get-Inv Win32_OperatingSystem).Caption) build $([Environment]::OSVersion.Version) |")
        [void]$rep.AppendLine("| PowerShell | $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), 64-bit process: $([Environment]::Is64BitProcess) |")
        [void]$rep.AppendLine("| language mode | ``$script:LangMode`` |")
        [void]$rep.AppendLine("| elevated | $isAdmin |")
        [void]$rep.AppendLine("| exec mode | $(if($script:JobsOk){'background-job'}else{'in-process (self-heal fallback)'}) |")
        [void]$rep.AppendLine("| hash backend | ``$script:HashBackend`` |")
        [void]$rep.AppendLine("| destination | $destInfo |")
        [void]$rep.AppendLine("| tools detected | $(if($info.toolsDetected){$info.toolsDetected}else{'native only'}) |")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## What failed")
        [void]$rep.AppendLine("")
        if ($failRows.Count -eq 0) {
            [void]$rep.AppendLine("No step failed or timed out.")
        } else {
            [void]$rep.AppendLine("| step | name | phase | outcome | class | message |")
            [void]$rep.AppendLine("|---|---|---|---|---|---|")
            foreach ($f in $failRows) {
                $m = "$($f.msg)" -replace '\|','\|'
                if ($m.Length -gt 120) { $m = $m.Substring(0,120) + '...' }
                [void]$rep.AppendLine("| $($f.id) | $($f.name) | $($f.phase) | $($f.ev) | ``$($f.cls)`` | $m |")
            }
        }
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## Steps that ran but produced NOTHING")
        [void]$rep.AppendLine("")
        if ($script:EmptySteps.Count -eq 0) { [void]$rep.AppendLine("None - every step that ran wrote output.") }
        else {
            [void]$rep.AppendLine("These exited without error but wrote an empty file. Ones marked CORE mean the")
            [void]$rep.AppendLine("collection missed its primary purpose - a host always has processes, connections,")
            [void]$rep.AppendLine("services and users, so empty here means the data was not captured.")
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine("| step | name | phase | file | |")
            [void]$rep.AppendLine("|---|---|---|---|---|")
            foreach ($e in $script:EmptySteps) {
                $crit = if ($script:CriticalSteps -contains $e.name) { '**CORE**' } else { '' }
                [void]$rep.AppendLine("| $($e.id) | $($e.name) | $($e.phase) | $($e.file) | $crit |")
            }
        }
        # A whole subsystem being down is a different finding from a list of empty steps, and it is
        # the one with an actionable fix. Without this the responder gets the symptom table above
        # and no name for the cause - the ladder for it existed but nothing could ever select it.
        # A WMI outage that the fallbacks papered over is invisible in the counts above - the run
        # looks COMPLETE because every step wrote something. Say so plainly, because a host whose
        # WMI was dead during collection is a finding, not a formatting note.
        if ($script:CimEvidence -and $script:CimEvidence.state -ne 'cim-sourced') {
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine("## Evidence source: CIM/WMI was $($script:CimEvidence.state)")
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine($script:CimEvidence.note)
            $fbs = @($script:CimEvidence.fallback_steps)
            if ($fbs.Count) {
                [void]$rep.AppendLine("")
                [void]$rep.AppendLine("Collected via a native fallback rather than CIM ($($fbs.Count)):")
                [void]$rep.AppendLine("")
                foreach ($f in $fbs) { [void]$rep.AppendLine("- ``$f``") }
                [void]$rep.AppendLine("")
                [void]$rep.AppendLine("The content is equivalent; the provenance is not. Do not read these as evidence that")
                [void]$rep.AppendLine("the host's WMI was healthy, and consider a disabled Winmgmt an indicator in its own right.")
            }
        }
        $subFail = Get-SubsystemFailureVerdict -Ran $script:CimStepsRan -Empty @($script:EmptySteps | ForEach-Object { $_.name })
        if ($subFail) {
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine("### Likely cause: the $($subFail.subsystem) subsystem is not answering")
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine("$($subFail.evidence).")
            [void]$rep.AppendLine("")
            [void]$rep.AppendLine("Classified as ``$($subFail.class)``. This is inferred from every one of those steps")
            [void]$rep.AppendLine("coming back empty at once, not from an error message - a broken $($subFail.subsystem)")
            [void]$rep.AppendLine("returns nothing rather than failing, which is why the run did not mark them failed.")
            [void]$rep.AppendLine("")
            $ladder = @($script:FixLadders[$subFail.class])
            if ($ladder.Count) {
                [void]$rep.AppendLine("Try, in order: " + (($ladder | ForEach-Object { "``$_``" }) -join ' -> ') + ".")
                [void]$rep.AppendLine("")
                [void]$rep.AppendLine("On Windows that means: ``Restart-Service Winmgmt -Force`` (or ``net stop winmgmt``")
                [void]$rep.AppendLine("then start it), re-run this collector, and if CIM still returns nothing use the")
                [void]$rep.AppendLine("native equivalents (``tasklist``, ``netstat -ano``, ``sc query``) which do not go")
                [void]$rep.AppendLine("through WMI. Re-collect before treating any of the empty artifacts as findings.")
            }
        }
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## What the self-heal did about it")
        [void]$rep.AppendLine("")
        if ($remRows.Count -eq 0) { [void]$rep.AppendLine("No remediation fired.") }
        else {
            [void]$rep.AppendLine("| step | name | class | action | result |")
            [void]$rep.AppendLine("|---|---|---|---|---|")
            foreach ($r in $remRows) { [void]$rep.AppendLine("| $($r.id) | $($r.name) | ``$($r.cls)`` | $($r.action) | $($r.result) |") }
        }
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## Reproducing this")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine('```powershell')
        [void]$rep.AppendLine(".\collectors\IR-Collect.ps1 -CaseId '$CaseId'$(if($Scenario){" -Scenario $Scenario"})$(if($HostRole){" -HostRole $HostRole"})$(if($RapidOnly){' -RapidOnly'})$(if($Auto){' -Auto'})")
        [void]$rep.AppendLine('```')
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("Resume just the unsatisfied steps of THIS run:")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine('```powershell')
        [void]$rep.AppendLine(".\collectors\IR-Collect.ps1 -CaseId '$CaseId' -Resume '$OutDir'")
        [void]$rep.AppendLine('```')
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("## Also send, if you can")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("- ``99_logs/run_state.json`` - machine-readable rollup (metadata only, safe)")
        [void]$rep.AppendLine("- ``99_logs/run_state.jsonl`` - per-step ledger (metadata only, safe)")
        [void]$rep.AppendLine("- ``99_logs/audit.log`` - full command trail. **Review before sending**: it records")
        [void]$rep.AppendLine("  the commands run and the paths touched on the subject host.")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("Do NOT send ``00_metadata/`` (contains volume encryption keys) or any collected artifact.")
        [void]$rep.AppendLine("")
        [void]$rep.AppendLine("_Generated $endUtc by IR-Collect._")
        [IO.File]::WriteAllText((Join-Path $L 'DIAGNOSTIC-REPORT.md'), $rep.ToString(), (New-Object Text.UTF8Encoding($false)))
        Write-Audit "Diagnostic report written: 99_logs\DIAGNOSTIC-REPORT.md (metadata only, safe to share)"
        # the run reached seal, so the interrupted-run breadcrumb no longer applies
        try { if ($script:ResumeNote -and (Test-Path -LiteralPath $script:ResumeNote)) { Remove-Item -LiteralPath $script:ResumeNote -Force -ErrorAction SilentlyContinue } } catch {}
    } catch { Write-Audit "Diagnostic report generation failed: $($_.Exception.Message)" }
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
  99_logs/run_state.jsonl       the completion ledger, appended to by seal's own steps, so any
                                digest taken during the manifest is stale before the bundle closes
  99_logs/run_state.frozen.jsonl  created after the manifest - a frozen snapshot of the ledger,
                                hashed into MANIFEST-audit-log.sha256 alongside the audit trail
  MANIFEST-audit-log.sha256     created after the manifest; holds the hashes above (one per line)

Anything else absent from the manifest was NOT excluded by design - treat it as unexplained.
"@
    try { [IO.File]::WriteAllText((Join-Path $L 'MANIFEST-README.txt'), $exclNote, (New-Object Text.UTF8Encoding($false))) } catch {}
    # manifest LAST so it covers SUMMARY.md + final collection_info.json (fixed literal path strip)
    Invoke-Step 'manifest-sha256' ([scriptblock]::Create((New-ManifestScript $OutDir))) 'MANIFEST-SHA256.csv' $L -TimeoutSec 1800 | Out-Null

    # freeze + hash the custody trail itself. audit.log is excluded from the manifest above because it
    # is still being written when the manifest runs; snapshot a frozen copy and hash THAT so the
    # timeline record has an integrity seal too.
    try {
        Copy-Item -LiteralPath $AuditLog -Destination (Join-Path $L 'audit.frozen.log') -Force -ErrorAction SilentlyContinue
        Repair-LedgerTail   # seal's own steps append after pass 1; re-check before freezing custody
        $ah = Get-IRSha256 (Join-Path $L 'audit.frozen.log')
        [IO.File]::WriteAllText((Join-Path $OutDir 'MANIFEST-audit-log.sha256'), "$ah  99_logs/audit.frozen.log`n", (New-Object Text.UTF8Encoding($false)))
        Write-Audit "Custody trail frozen + hashed: $ah"
    } catch { Write-Audit "Could not freeze/hash audit.log: $($_.Exception.Message)" }

    # Same treatment for the COMPLETION LEDGER, and for the same reason.
    #
    # run_state.jsonl is excluded from the manifest above because seal's own steps append to it, so
    # any digest taken during the manifest is stale before the bundle closes. Excluding it was only
    # half the fix: it left the record of what the collector actually did with NO integrity seal at
    # all, so an analyst could not detect modification of it. Linux had already been given both
    # halves; this side had only the exclusion, and the asymmetry was found by verifying a real
    # Windows bundle rather than by reading either script.
    #
    # Appended as a second line - MANIFEST-audit-log.sha256 is one entry per line, and the verifier
    # reads it that way.
    try {
        $rsLive = Join-Path $L 'run_state.jsonl'
        if (Test-Path -LiteralPath $rsLive) {
            $rsFrozen = Join-Path $L 'run_state.frozen.jsonl'
            Copy-Item -LiteralPath $rsLive -Destination $rsFrozen -Force -ErrorAction Stop
            $rh = Get-IRSha256 $rsFrozen
            [IO.File]::AppendAllText((Join-Path $OutDir 'MANIFEST-audit-log.sha256'), "$rh  99_logs/run_state.frozen.jsonl`n", (New-Object Text.UTF8Encoding($false)))
            Write-Audit "Completion ledger frozen + hashed: $rh"
        } else { Write-Audit 'Completion ledger absent at seal - nothing to freeze.' }
    } catch { Write-Audit "Could not freeze/hash run_state.jsonl: $($_.Exception.Message)" }

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
                $script:ShipOk = $true
                Write-Audit "Ship OK -> $NetworkDest"; Write-Host "Shipped $(Split-Path $zip -Leaf) to $NetworkDest" -ForegroundColor Green
            } catch {
                # A run whose evidence never reached the destination exited 0, so nothing
                # automating this could tell. The bundle is intact locally, so this is not a
                # failed COLLECTION - but it is not a clean run either.
                $script:ShipOk = $false
                $script:ShipError = ($_.Exception.Message -split "`r?`n")[0]
                Write-Audit "Ship FAILED: $($_.Exception.Message). Evidence retained locally at $zip"
                Write-Host "Network ship failed - evidence kept locally: $zip" -ForegroundColor Yellow
                Write-Host "  The COLLECTION is intact; only the transfer failed. Copy the bundle by hand or re-run the ship." -ForegroundColor Yellow
            } finally { try { Remove-PSDrive IRDEST -ErrorAction SilentlyContinue } catch {} }
            # Written BESIDE the bundle, never inside it: the bundle is already sealed and hashed,
            # and an evidence container that changes after its manifest is worthless. This file is
            # the machine-readable answer to "did the evidence actually reach the destination?"
            try {
                $shipRec = [ordered]@{
                    schema='ir-collect/ship-result@1'; case=$script:CaseIdRaw; bundle=(Split-Path $zip -Leaf)
                    target=$NetworkDest; ok=[bool]$script:ShipOk; error=$script:ShipError
                    preflight_ok=$(if($script:NetProbe){[bool]$script:NetProbe.ok}else{$null})
                    local_copy=$zip; utc=(Now-Utc)
                }
                [IO.File]::WriteAllText("$zip.ship.json", ($shipRec | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
                Write-Audit "Ship result recorded: $zip.ship.json (ok=$([bool]$script:ShipOk))"
            } catch {}
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
    # Never announce a completed collection without confirming the evidence is actually THERE.
    # With a 229-char -Dest (scenario B6) every write failed on MAX_PATH and the run still printed
    # "Collection complete. Output: <path>" for a directory that did not exist - the single most
    # misleading thing this tool has done, because the operator walks away believing they have a
    # bundle. The closing line is now a statement about the tree on disk, not about reaching the
    # end of the script.
    $bundleFiles = @(Get-ChildItem -LiteralPath $OutDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count
    Write-Host ""
    if ($bundleFiles -eq 0) {
        Write-Host "COLLECTION PRODUCED NO EVIDENCE. Nothing was written to: $OutDir" -ForegroundColor Red
        # Name the cause that actually applies. "Use a shorter -Dest" is B6's advice (MAX_PATH) and
        # is wrong - actively misleading - when the destination was unmounted or removed mid-run,
        # which is the far more common way this branch is reached. Same misdiagnosis the Linux twin
        # made by calling a vanished destination "full" (scenario B3).
        $destGone = -not (Test-Path -LiteralPath (Split-Path $OutDir -Qualifier) -ErrorAction SilentlyContinue)
        if ($destGone) {
            Write-Host "The destination volume is NO LONGER PRESENT - it was removed or unmounted during the run." -ForegroundColor Yellow
            Write-Host "Anything collected before that point went with it. Re-run against media that stays attached." -ForegroundColor Yellow
        } else {
            Write-Host "The destination could not be written to. Check free space, permissions, and that -Dest is not too long a path." -ForegroundColor Yellow
        }
        try { Write-Audit "FINAL: no files present under $OutDir - reporting failure, not completion." } catch {}
    } else {
        $verdictWord = if ($script:RunIncomplete) { 'Collection INCOMPLETE' } else { 'Collection complete' }
        $colour      = if ($script:RunIncomplete) { 'Yellow' } else { 'Green' }
        Write-Host "$verdictWord ($bundleFiles files). Output: $OutDir" -ForegroundColor $colour
        Write-Host "Summary: $(Join-Path $OutDir 'SUMMARY.md')  |  Audit: $AuditLog"
    }
}

# ---------------------------------------------------------------------------
# VOLATILE GREEN gate - confirm perishable data captured before the slow phase
# ---------------------------------------------------------------------------
function Show-VolatileGate {
    $n = 0
    try { $n = (Get-ChildItem -LiteralPath $Dirs.volatile,$Dirs.network -File -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count } catch {}
    $memOk = [bool]$script:MemOk
    # is the disk encrypted but we have no verified RAM (where the key lives)?
    # THREE-STATE: $null means the probe could not answer, and must not collapse into "no risk".
    $encState = $null
    try { $encState = [bool](Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.ProtectionStatus -eq 'On' }) } catch { $encState = $null }
    if ($null -eq $encState) {
        # manage-bde ships on editions where the PowerShell module does not, so a cmdlet-less host
        # is not automatically an unknown one. Prove the capability rather than inferring it.
        try {
            $bde = (& manage-bde.exe -status 2>&1 | Out-String)
            if ($bde -match 'Protection\s+On')       { $encState = $true }
            elseif ($bde -match 'Protection\s+Off')  { $encState = $false }
        } catch { $encState = $null }
    }
    $script:EncVerdict = Get-EncryptionRiskVerdict -DiskEncrypted $encState -MemoryVerified $memOk
    $encRisk = [bool]$script:EncVerdict.amber
    $memNote = if ($memOk) { "RAM: VERIFIED ({0:N1} GB)" -f ($script:MemBytes/1GB) } else { 'RAM: NOT verified - capture failed/absent (see 03_memory)' }
    Write-Host ""
    if ($encRisk) {
        Write-Host "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
        if ($script:EncVerdict.state -eq 'unknown-no-ram') {
            Write-Host "  !!  VOLATILE: AMBER - ENCRYPTION UNKNOWN + NO VERIFIED RAM !!" -ForegroundColor Red
            Write-Host "  !!  The encryption probe could NOT answer (no cmdlets, or !!" -ForegroundColor Red
            Write-Host "  !!  not elevated). If this disk IS encrypted, its key is  !!" -ForegroundColor Red
            Write-Host "  !!  in RAM you did not capture. Do not assume it is not.  !!" -ForegroundColor Red
        } else {
        Write-Host "  !!  VOLATILE: AMBER - ENCRYPTED DISK + NO VERIFIED RAM   !!" -ForegroundColor Red
        Write-Host "  !!  The BitLocker key lives in RAM you did NOT capture.  !!" -ForegroundColor Red
        }
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
# The evidence never reached the destination the operator named. The COLLECTION is intact (the
# bundle is retained locally and says so), so this is not exit 15 - but a run that could not
# deliver its output must not report clean either, or automation shipping to a share nobody can
# write to reports success forever. Measured 2026-07-28: exit was 0.
if ($script:ShipOk -eq $false) { if ($exitCode -lt 10) { $exitCode = 10 } }
if ($script:RunIncomplete) { $exitCode = 15 }
if (-not $script:MemOk -and -not $RapidOnly) { $exitCode = 20 }
Write-Audit "EXIT $exitCode (0=clean 10=skips/ship-failed 15=incomplete-critical 20=no-RAM 40=fatal)"
exit $exitCode
