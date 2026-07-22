<#
.SYNOPSIS
    Build-DetectionContent.ps1 - Turn an IR-Collect capture into detection content for the
    follow-on team's suite (Splunk Enterprise Security + Security Onion).

.DESCRIPTION
    The SOC forward party captures perishable evidence from compromised hosts with IR-Collect.
    This tool (run on the ANALYST box, NOT the victim) mines that collection folder for observables
    and emits a handoff package the main team ingests directly:

      ioc/indicators.csv        - deduped IOCs (type,value,source,host)
      ioc/indicators.stix.json  - STIX 2.1 bundle
      splunk/hunt_searches.spl  - ready-to-run SPL for Splunk ES
      splunk/savedsearches.conf - Splunk ES correlation-search stubs
      sigma/*.yml               - Sigma rules (vendor-neutral -> convert to SPL or Sec Onion)
      suricata/local.rules      - Suricata alerts for Security Onion (C2 IP/domain)
      zeek/ircollect.intel      - Zeek Intelligence Framework feed for Security Onion
      HANDOFF.md                - what's here and how the follow-on team loads it

    Self-healing: missing/parse-failed sources are skipped and logged, never fatal.

.PARAMETER CollectionDir  An IR-Collect output folder (<CASE>_<HOST>_<UTC>), or a parent of several.
.PARAMETER OutDir         Where to write the package. Default: <CollectionDir>\_detection.
.PARAMETER SidBase        Starting Suricata SID (local range). Default 9100000.

.EXAMPLE  pwsh ./Build-DetectionContent.ps1 -CollectionDir E:\evidence\CASE001_HOST_20260722
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CollectionDir,
    [string]$OutDir,
    [int]$SidBase = 9100000
)
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $CollectionDir)) { Write-Error "CollectionDir not found: $CollectionDir"; exit 1 }
if (-not $OutDir) { $OutDir = Join-Path $CollectionDir '_detection' }
foreach ($d in 'ioc','splunk','sigma','suricata','zeek') { New-Item -ItemType Directory -Force (Join-Path $OutDir $d) | Out-Null }

# Collect the set of collection folders (support a parent dir with several hosts)
$folders = @()
if (Test-Path (Join-Path $CollectionDir '00_metadata')) { $folders = @($CollectionDir) }
else { $folders = Get-ChildItem $CollectionDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName '00_metadata') } | Select-Object -ExpandProperty FullName }
if (-not $folders) { $folders = @($CollectionDir) }   # try anyway

# ---------------------------------------------------------------------------
# IOC accumulation
# ---------------------------------------------------------------------------
$IOC = @{}   # key "type|value" -> object
function Add-IOC {
    param([string]$Type,[string]$Value,[string]$Source,[string]$Hn)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $Value = $Value.Trim()
    $k = "$Type|$Value"
    if (-not $IOC.ContainsKey($k)) { $IOC[$k] = [ordered]@{ type=$Type; value=$Value; source=$Source; host=$Hn } }
}

# public-IP test (exclude RFC1918 / loopback / link-local / multicast / broadcast)
function Test-PublicIP {
    param([string]$ip)
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $o = $ip.Split('.') | ForEach-Object { [int]$_ }
    if ($o[0] -eq 10) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 127 -or $o[0] -eq 0 -or $o[0] -ge 224) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    if ($ip -eq '255.255.255.255') { return $false }
    return $true
}

$ipRe   = '((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)'
$domRe  = '(?i)\b([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}\b'
$hashRe = '\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b'
$suspDirRe = '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\|/tmp/|/dev/shm/|/var/tmp/)'

foreach ($f in $folders) {
    $hostn = 'unknown'
    try { $ci = Get-Content (Join-Path $f '00_metadata\collection_info.json') -Raw -ErrorAction Stop | ConvertFrom-Json; if ($ci.host) { $hostn = $ci.host } } catch {}
    Write-Host "Mining $f (host=$hostn)" -ForegroundColor Cyan

    function Read-Src { param([string]$rel) $p = Join-Path $f $rel; if (Test-Path $p) { try { Get-Content $p -Raw -ErrorAction Stop } catch { '' } } else { '' } }

    # --- network: external (public) remote IPs = candidate C2 ---
    foreach ($rel in '02_network\tcp_connections.txt','02_network\netstat_anob.txt','02_network\udp_endpoints.txt','02_network\connections.txt','02_network\arp_cache.txt') {
        $txt = Read-Src $rel
        foreach ($m in [regex]::Matches($txt, $ipRe)) { if (Test-PublicIP $m.Value) { Add-IOC 'ipv4-c2' $m.Value $rel $hostn } }
    }
    # --- DNS cache + hosts file = candidate C2 domains ---
    foreach ($rel in '02_network\dns_cache.txt','02_network\hosts_file.txt','02_network\dns.txt') {
        $txt = Read-Src $rel
        foreach ($m in [regex]::Matches($txt, $domRe)) {
            $d = $m.Value.ToLower()
            # allowlist common benign infra to cut false positives (research: FP-control is priority #1).
            # Coarse first pass - the follow-on team enriches (VT/GreyNoise/prevalence) before arming.
            if ($d -match '\.(local|arpa|lan|internal|corp|home)$') { continue }
            if ($d -match '(^|\.)(microsoft|windows|windowsupdate|msftconnecttest|msftncsi|office365|office|live|azure|azureedge|msedge|bing|skype|xboxlive|apple|icloud|mzstatic|google|googleapis|gstatic|gvt1|gvt2|youtube|akamai|akamaiedge|akamaized|cloudflare|cloudfront|fastly|amazonaws|digicert|verisign|globalsign|sectigo|ocsp|mozilla|ubuntu|debian|canonical|entrust)\.[a-z.]+$') { continue }
            Add-IOC 'domain' $d $rel $hostn
        }
    }
    # --- suspicious process image paths + hashes ---
    foreach ($rel in '01_volatile\processes.csv','01_volatile\processes.txt','04_persistence\services.csv','04_persistence\autoruns.csv','04_persistence\scheduled_tasks.csv') {
        $txt = Read-Src $rel
        foreach ($line in ($txt -split "`n")) {
            if ($line -match $suspDirRe) {
                foreach ($pm in [regex]::Matches($line, '(?i)[a-z]:\\[^,"\r\n]+\.(exe|dll|ps1|bat|scr|vbs)')) { Add-IOC 'file-path' $pm.Value $rel $hostn }
                foreach ($pm in [regex]::Matches($line, '(?i)/(tmp|dev/shm|var/tmp)/[^\s,"]+')) { Add-IOC 'file-path' $pm.Value $rel $hostn }
            }
            foreach ($hm in [regex]::Matches($line, $hashRe)) { Add-IOC 'hash' $hm.Value $rel $hostn }
        }
    }
    # --- autoruns hashes (Sysinternals -h output) ---
    $ar = Read-Src '04_persistence\autoruns.csv'
    foreach ($hm in [regex]::Matches($ar, $hashRe)) { Add-IOC 'hash' $hm.Value '04_persistence\autoruns.csv' $hostn }
}

$all = @($IOC.Values | ForEach-Object { [pscustomobject]$_ })
$ips     = @($all | Where-Object { $_.type -eq 'ipv4-c2'  } | Select-Object -Expand value -Unique)
$domains = @($all | Where-Object { $_.type -eq 'domain'   } | Select-Object -Expand value -Unique)
$hashes  = @($all | Where-Object { $_.type -eq 'hash'     } | Select-Object -Expand value -Unique)
$paths   = @($all | Where-Object { $_.type -eq 'file-path'} | Select-Object -Expand value -Unique)
Write-Host ("Extracted: {0} external IPs, {1} domains, {2} hashes, {3} suspicious paths" -f $ips.Count,$domains.Count,$hashes.Count,$paths.Count) -ForegroundColor Green

# ---------------------------------------------------------------------------
# 1. IOC CSV + STIX
# ---------------------------------------------------------------------------
$all | Export-Csv (Join-Path $OutDir 'ioc\indicators.csv') -NoTypeInformation
$stixObjs = @()
foreach ($i in $all) {
    $pat = switch ($i.type) {
        'ipv4-c2'  { "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '$($i.value)']" }
        'domain'   { "[domain-name:value = '$($i.value)']" }
        'hash'     { "[file:hashes.'SHA-256' = '$($i.value)']" }
        'file-path'{ "[file:name = '$(( $i.value -split '[\\/]')[-1])']" }
        default    { $null }
    }
    if ($pat) { $stixObjs += [ordered]@{ type='indicator'; spec_version='2.1'; pattern=$pat; pattern_type='stix'; description="IR-Collect $($i.type) from host $($i.host)" } }
}
[ordered]@{ type='bundle'; objects=$stixObjs } | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutDir 'ioc\indicators.stix.json') -Encoding UTF8

# ---------------------------------------------------------------------------
# 2. Splunk SPL hunt searches (for Splunk Enterprise Security)
# ---------------------------------------------------------------------------
$Q = [char]34   # double-quote char, to avoid nested-escape parser issues
$spl = New-Object System.Text.StringBuilder
[void]$spl.AppendLine('# Splunk hunt searches generated by IR-Collect Build-DetectionContent')
[void]$spl.AppendLine('# Point at your indexes / CIM data models. Adjust field names to your sourcetypes.')
[void]$spl.AppendLine('')
if ($ips.Count) {
    $ipList = ($ips | ForEach-Object { $Q + $_ + $Q }) -join ','
    $ipOr   = ($ips | ForEach-Object { 'dest_ip=' + $Q + $_ + $Q }) -join ' OR '
    [void]$spl.AppendLine('### Beaconing / C2 to captured external IPs')
    [void]$spl.AppendLine('| tstats count min(_time) as first max(_time) as last from datamodel=Network_Traffic where All_Traffic.dest_ip IN (' + $ipList + ') by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port')
    [void]$spl.AppendLine('### Fallback (raw):')
    [void]$spl.AppendLine('index=* (' + $ipOr + ') | stats count values(src_ip) by dest_ip dest_port sourcetype')
    [void]$spl.AppendLine('')
}
if ($domains.Count) {
    $dList = ($domains | ForEach-Object { $Q + $_ + $Q }) -join ','
    $dOr   = ($domains | ForEach-Object { 'query=' + $Q + $_ + $Q + ' OR url=' + $Q + '*' + $_ + '*' + $Q }) -join ' OR '
    [void]$spl.AppendLine('### DNS resolution / web requests to captured domains')
    [void]$spl.AppendLine('| tstats count from datamodel=Network_Resolution where DNS.query IN (' + $dList + ') by DNS.src DNS.query')
    [void]$spl.AppendLine('index=* sourcetype IN (stream:dns,*dns*,*proxy*,zeek*) (' + $dOr + ') | stats count by query src')
    [void]$spl.AppendLine('')
}
if ($hashes.Count) {
    $hList = ($hashes | ForEach-Object { $Q + $_ + $Q }) -join ','
    [void]$spl.AppendLine('### Process/file execution of captured hashes (Sysmon/EDR)')
    [void]$spl.AppendLine('index=* sourcetype IN (*Sysmon*,*EDR*,*CrowdStrike*) (Hashes IN (' + $hList + ') OR SHA256 IN (' + $hList + ')) | stats count values(Image) values(ComputerName) by _time')
    [void]$spl.AppendLine('')
}
if ($paths.Count) {
    $imgs = ($paths | ForEach-Object { 'Image=' + $Q + '*' + (($_ -split '[\\/]')[-1]) + $Q }) -join ' OR '
    [void]$spl.AppendLine('### Execution from suspicious paths (captured)')
    [void]$spl.AppendLine('index=* sourcetype IN (*Sysmon*,WinEventLog:*) EventCode IN (1,4688) (' + $imgs + ') | stats count values(CommandLine) by Image ComputerName')
    [void]$spl.AppendLine('')
}
$spl.ToString() | Out-File (Join-Path $OutDir 'splunk\hunt_searches.spl') -Encoding UTF8

# Splunk ES correlation-search stub
$ipListCsv = ($ips | ForEach-Object { $Q + $_ + $Q }) -join ','
$corr = @"
# Splunk ES correlation-search stubs (savedsearches.conf). Tune thresholds/throttle before enabling.
[IR-Collect - C2 IP contact ($($folders.Count) host(s))]
search = | tstats count from datamodel=Network_Traffic where All_Traffic.dest_ip IN ($ipListCsv) by All_Traffic.src_ip All_Traffic.dest_ip
action.notable = 1
action.notable.param.severity = high
cron_schedule = */10 * * * *
description = Endpoint contacted an IP captured from a compromised host during IR triage.
"@
$corr | Out-File (Join-Path $OutDir 'splunk\savedsearches.conf') -Encoding UTF8

# ---------------------------------------------------------------------------
# 3. Sigma rules (vendor-neutral -> convert to Splunk or Sec Onion with pySigma)
# ---------------------------------------------------------------------------
if ($ips.Count -or $domains.Count) {
@"
title: IR-Collect C2 network indicators
id: $([guid]::NewGuid())
status: experimental
description: Network indicators captured from compromised host(s) during IR triage.
references:
  - IR-Collect triage collection
logsource:
  category: network_connection
detection:
  selection_ip:
    DestinationIp:
$(($ips | ForEach-Object { "      - $_" }) -join "`n")
  selection_dns:
    query:
$(($domains | ForEach-Object { "      - $_" }) -join "`n")
  condition: selection_ip or selection_dns
level: high
tags:
  - attack.command_and_control
"@ | Out-File (Join-Path $OutDir 'sigma\c2_network_indicators.yml') -Encoding UTF8
}
if ($hashes.Count -or $paths.Count) {
@"
title: IR-Collect malicious process indicators
id: $([guid]::NewGuid())
status: experimental
description: Process/file indicators captured from compromised host(s) during IR triage.
logsource:
  category: process_creation
detection:
  selection_hash:
    Hashes|contains:
$(($hashes | ForEach-Object { "      - $_" }) -join "`n")
  selection_image:
    Image|endswith:
$(($paths | ForEach-Object { "      - $(($_ -split '[\\/]')[-1])" } | Select-Object -Unique) -join "`n")
  condition: selection_hash or selection_image
level: high
tags:
  - attack.execution
"@ | Out-File (Join-Path $OutDir 'sigma\malicious_process_indicators.yml') -Encoding UTF8
}

# ---------------------------------------------------------------------------
# 4. Suricata rules (Security Onion) - local SID range
# ---------------------------------------------------------------------------
$sid = $SidBase
$sur = New-Object System.Text.StringBuilder
[void]$sur.AppendLine("# Suricata local.rules generated by IR-Collect. Load into Security Onion (/nsm/rules/local.rules or SecurityOnion 'idstools' local rules).")
foreach ($ip in $ips) {
    [void]$sur.AppendLine("alert ip `$HOME_NET any -> $ip any (msg:`"IR-Collect C2 IP contact $ip`"; classtype:trojan-activity; sid:$sid; rev:1; metadata:source ir-collect;)")
    $sid++
}
foreach ($d in $domains) {
    [void]$sur.AppendLine("alert dns `$HOME_NET any -> any any (msg:`"IR-Collect C2 domain $d`"; dns.query; content:`"$d`"; nocase; classtype:trojan-activity; sid:$sid; rev:1; metadata:source ir-collect;)")
    $sid++
}
$sur.ToString() | Out-File (Join-Path $OutDir 'suricata\local.rules') -Encoding UTF8

# ---------------------------------------------------------------------------
# 5. Zeek Intelligence Framework feed (Security Onion)
# ---------------------------------------------------------------------------
$zeek = New-Object System.Text.StringBuilder
[void]$zeek.AppendLine("#fields`tindicator`tindicator_type`tmeta.source`tmeta.desc")
foreach ($ip in $ips)     { [void]$zeek.AppendLine("$ip`tIntel::ADDR`tIR-Collect`tC2 IP from IR triage") }
foreach ($d in $domains)  { [void]$zeek.AppendLine("$d`tIntel::DOMAIN`tIR-Collect`tC2 domain from IR triage") }
foreach ($h in $hashes)   { [void]$zeek.AppendLine("$h`tIntel::FILE_HASH`tIR-Collect`tfile hash from IR triage") }
$zeek.ToString() | Out-File (Join-Path $OutDir 'zeek\ircollect.intel') -Encoding UTF8

# ---------------------------------------------------------------------------
# HANDOFF.md for the follow-on team
# ---------------------------------------------------------------------------
@"
# IR-Collect -> Detection Content Handoff

Generated from forward-party triage of $($folders.Count) compromised host(s).
Observables extracted: **$($ips.Count) external IPs, $($domains.Count) domains, $($hashes.Count) hashes, $($paths.Count) suspicious paths.**

## For the Splunk Enterprise Security team
- ``splunk/hunt_searches.spl`` - paste into Search; hunts these IOCs across your indexes / CIM data models
  (Network_Traffic, Network_Resolution). Adjust index/sourcetype/field names to your environment.
- ``splunk/savedsearches.conf`` - correlation-search stubs; tune thresholds + throttle, then enable in ES.
- ``ioc/indicators.csv`` - load as a KV-store/lookup for ``| lookup`` enrichment, or into Threat Intel Framework.
- ``ioc/indicators.stix.json`` - STIX 2.1; ingest via ES Threat Intelligence Management.

## For the Security Onion team
- ``suricata/local.rules`` - copy to the SO idstools local rules, ``so-rule-update``. Alerts on C2 IP/domain.
- ``zeek/ircollect.intel`` - add to the Zeek Intel framework (``@load frameworks/intel/seed`` / Intel::read_files)
  so Zeek tags any traffic matching these indicators in conn/dns/http/ssl logs.
- ``sigma/*.yml`` - convert with pySigma to your backend (``sigma convert -t splunk`` or ``-t elasticsearch``
  for the SO Elastic stack).

## Hunt hypotheses to seed the baseline
- Any internal host contacting the captured C2 IPs/domains = additional compromise (scope expansion).
- Execution of the captured hashes / filenames anywhere in the fleet = same tooling reused.
- Beaconing patterns (regular interval, small payloads) to these IPs during the baseline window.

Convert Sigma once, deploy to both stacks. IOCs are candidates - validate before alerting broadly
(some external IPs may be legitimate CDNs/telemetry; the CSV notes the source artifact for triage).
"@ | Out-File (Join-Path $OutDir 'HANDOFF.md') -Encoding UTF8

Write-Host ""
Write-Host "Detection content written to: $OutDir" -ForegroundColor Green
Write-Host "  ioc/  splunk/  sigma/  suricata/  zeek/  + HANDOFF.md"
