<#
.SYNOPSIS
    fetch-tools.ps1 - Assemble the IR-Collect thumb-drive payload (OPEN-SOURCE tools only).

.DESCRIPTION
    Downloads the open-source, license-free, professionally-proven responder tools into .\tools\
    (Windows binaries) so IR-Collect.ps1 uses them by default. Pulls each from its OFFICIAL GitHub
    releases via the GitHub API (latest version, robust to version bumps), records SHA-256 +
    source URL in tools\PROVENANCE.txt, and self-heals: a failed download is logged and skipped.

    Run this ONCE on your own trusted workstation to build the kit, then carry the drive.

    NOT fetched (free but NOT open-source - add manually if your engagement allows):
      Sysinternals suite, KAPE, FTK Imager, Magnet RAM Capture.
    Python tools (install with pipx on your analysis box, not the victim):
      bloodhound-python, netexec, impacket.

.EXAMPLE  powershell -ExecutionPolicy Bypass -File .\fetch-tools.ps1
#>
[CmdletBinding()] param([string]$ToolDir)

$ErrorActionPreference = 'Continue'
if ([string]::IsNullOrWhiteSpace($ToolDir)) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { (Get-Location).Path }
    $ToolDir = Join-Path $base 'tools'
}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
New-Item -ItemType Directory -Force $ToolDir | Out-Null
$prov = Join-Path $ToolDir 'PROVENANCE-windows.txt'
"IR-Collect Windows payload - fetched $((Get-Date).ToUniversalTime().ToString('o'))" | Out-File $prov -Encoding UTF8

function Log($m){ Write-Host $m; Add-Content $prov $m }

# Get the download URL of the latest-release asset matching $Pattern from a GitHub repo
function Get-LatestAsset {
    param([string]$Repo,[string]$Pattern)
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $r = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent'='ir-collect'; 'Accept'='application/vnd.github+json' } -TimeoutSec 30
    $asset = $r.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "no asset matching /$Pattern/ in $Repo@$($r.tag_name)" }
    [pscustomobject]@{ Url=$asset.browser_download_url; Name=$asset.name; Tag=$r.tag_name }
}

# Download one tool (self-healing). Handles .zip (extract) and raw .exe. Records provenance.
function Get-Tool {
    param([string]$Label,[string]$Repo,[string]$Pattern,[switch]$Unzip)
    Write-Host ("--- {0} ({1}) ---" -f $Label,$Repo) -ForegroundColor Cyan
    try {
        $dest = $null
        $a = Get-LatestAsset -Repo $Repo -Pattern $Pattern
        $dest = Join-Path $ToolDir $a.Name
        Invoke-WebRequest -Uri $a.Url -OutFile $dest -Headers @{ 'User-Agent'='ir-collect' } -TimeoutSec 300
        $h = (Get-FileHash $dest -Algorithm SHA256).Hash
        Log ("OK  {0,-14} {1,-40} {2}  {3}" -f $Label,$a.Name,$h.Substring(0,16),$a.Url)
        if ($Unzip -and $dest -match '\.zip$') {
            $ex = Join-Path $ToolDir ($Label)
            try { Expand-Archive -Path $dest -DestinationPath $ex -Force; Remove-Item $dest -Force; Log ("    extracted -> $Label\") } catch { Log "    unzip failed: $($_.Exception.Message)" }
        }
    } catch {
        if ($dest -and (Test-Path $dest)) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }  # drop partial download
        Log ("ERR {0,-14} {1} : {2}" -f $Label,$Repo,$_.Exception.Message)
        Write-Host "  skipped (continuing)" -ForegroundColor Yellow
    }
}

Write-Host "Assembling IR-Collect open-source payload into $ToolDir" -ForegroundColor Green

# --- memory acquisition ---
Get-Tool -Label 'winpmem'     -Repo 'Velocidex/WinPmem'        -Pattern 'winpmem.*(x64|amd64).*\.exe$|winpmem_mini_x64.*\.exe$'
# --- triage collectors (open source; replace proprietary KAPE) ---
Get-Tool -Label 'velociraptor' -Repo 'Velocidex/velociraptor'  -Pattern 'windows-amd64\.exe$'
Get-Tool -Label 'CyLR'        -Repo 'orlikoski/CyLR'           -Pattern 'win.*(x64|amd64).*\.zip$' -Unzip
# --- Active Directory attack paths ---
Get-Tool -Label 'SharpHound'  -Repo 'SpecterOps/SharpHound'    -Pattern 'SharpHound.*\.zip$' -Unzip
# --- event-log / evtx hunting (open source) ---
Get-Tool -Label 'chainsaw'    -Repo 'WithSecureLabs/chainsaw'  -Pattern 'chainsaw.*x86_64.*windows.*\.zip$' -Unzip
Get-Tool -Label 'hayabusa'    -Repo 'Yamato-Security/hayabusa' -Pattern 'win-x64.*\.zip$' -Unzip

# Eric Zimmerman tools (MIT, open source) - use the official downloader
try {
    Write-Host "--- Eric Zimmerman tools (MFTECmd/PECmd/EvtxECmd/AmcacheParser...) ---" -ForegroundColor Cyan
    $ezDir = Join-Path $ToolDir 'EZTools'
    Invoke-WebRequest 'https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1' -OutFile (Join-Path $ToolDir 'Get-ZimmermanTools.ps1') -Headers @{ 'User-Agent'='ir-collect' } -TimeoutSec 120
    Log "OK  EZTools        Get-ZimmermanTools.ps1 fetched - run it to populate EZTools\ (net6)"
    Write-Host "  Run: .\tools\Get-ZimmermanTools.ps1 -Dest .\tools\EZTools   (populates the parsers)" -ForegroundColor Gray
} catch { Log "ERR EZTools : $($_.Exception.Message)" }

Write-Host ""
Write-Host "Done. See $prov for what was fetched + hashes." -ForegroundColor Green
Write-Host "NOT fetched (free but proprietary, add manually if allowed): Sysinternals, KAPE, FTK Imager, Magnet RAM." -ForegroundColor Yellow
Write-Host "Python (install on analysis box via pipx): bloodhound-python, netexec, impacket." -ForegroundColor Yellow
