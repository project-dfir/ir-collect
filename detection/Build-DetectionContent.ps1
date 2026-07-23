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
.PARAMETER SidBase        Starting Suricata SID (local range). Default 1000000.

.EXAMPLE  pwsh ./Build-DetectionContent.ps1 -CollectionDir E:\evidence\CASE001_HOST_20260722
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CollectionDir,
    [string]$OutDir,
    [int]$SidBase = 1000000
)
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $CollectionDir)) { Write-Error "CollectionDir not found: $CollectionDir"; exit 1 }
if (-not $OutDir) { $OutDir = Join-Path $CollectionDir '_detection' }
foreach ($d in 'ioc','splunk','sigma','suricata','zeek') { New-Item -ItemType Directory -Force (Join-Path $OutDir $d) | Out-Null }

# Collect the set of collection folders (support a parent dir with several hosts)
function Test-IsCapture($d) { (Test-Path (Join-Path $d '00_metadata')) -or (Test-Path (Join-Path $d 'meta\collection_info.json')) }
$folders = @()
if (Test-IsCapture $CollectionDir) { $folders = @($CollectionDir) }
else { $folders = Get-ChildItem $CollectionDir -Directory -ErrorAction SilentlyContinue | Where-Object { Test-IsCapture $_.FullName } | Select-Object -ExpandProperty FullName }
if (-not $folders) { $folders = @($CollectionDir) }   # try anyway

# ---------------------------------------------------------------------------
# IOC accumulation
# ---------------------------------------------------------------------------
function Save-Text($path,$text){ [IO.File]::WriteAllText($path, ($text -replace "`r`n","`n"), (New-Object Text.UTF8Encoding($false))) }
function New-DetUuid($seed){ $md5=[Security.Cryptography.MD5]::Create(); ([guid]::new($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($seed)))).ToString() }
function New-DetId($prefix,$seed){ "$prefix--" + (New-DetUuid $seed) }
function Esc-Stix($v){ "$v" -replace '\\','\\\\' -replace "'","\'" }   # STIX string: backslash + single-quote
function Yaml-Q($v){ '"' + ("$v" -replace '\\','\\\\' -replace '"','\"') + '"' }   # safe double-quoted YAML scalar
$stixTs = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
$IOC = @{}   # key "type|value" -> object
function Add-IOC {
    param([string]$Type,[string]$Value,[string]$Source,[string]$Hn,[int]$Confidence=50,[bool]$ToIds=$false)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $Value = $Value.Trim()
    $k = "$Type|$Value"
    if (-not $IOC.ContainsKey($k)) { $IOC[$k] = [ordered]@{ type=$Type; value=$Value; source=$Source; host=$Hn; confidence=$Confidence; to_ids=$ToIds } }
    else {
        if (($IOC[$k].host -split ';') -notcontains $Hn) { $IOC[$k].host = "$($IOC[$k].host);$Hn" }
        if ($Confidence -gt $IOC[$k].confidence) { $IOC[$k].confidence = $Confidence }
        if ($ToIds) { $IOC[$k].to_ids = $true }
    }
}
# intake accumulators (scenario context steers tagging + the ATT&CK Navigator layer)
$IntakeCase = $null; $IntakeScenarios = @(); $AttackTags = @(); $SeedCount = 0

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
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }
    if ($ip -eq '255.255.255.255') { return $false }
    return $true
}

$ipRe   = '(?<![\d.])((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'
$domRe  = '(?i)\b([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}\b'
$hashRe = '\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b'
$hashReStrong = '\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40})\b'   # SHA1/SHA256 only - 32-hex MD5 collides with GUIDs/CLSIDs
$benignRe = '(^|\.)(microsoft|windows|windowsupdate|msftconnecttest|msftncsi|office365|office|live|azure|azureedge|msedge|bing|skype|xboxlive|apple|icloud|mzstatic|google|googleapis|gstatic|gvt1|gvt2|youtube|akamai|akamaiedge|akamaized|cloudflare|cloudfront|fastly|amazonaws|digicert|verisign|globalsign|sectigo|ocsp|mozilla|ubuntu|debian|canonical|entrust)\.[a-z.]+$'
$suspDirRe = '(?i)(\\Temp\\|\\AppData\\|\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\|/tmp/|/dev/shm/|/var/tmp/)'

foreach ($f in $folders) {
    $hostn = 'unknown'
    try { $ci = Get-Content (Join-Path $f '00_metadata\collection_info.json') -Raw -ErrorAction Stop | ConvertFrom-Json; if ($ci.host) { $hostn = $ci.host } } catch {}

    # --- MOBILE capture (mobile-collect.sh): meta/ tree + pre-extracted detection/mobile_iocs.csv ---
    if (Test-Path (Join-Path $f 'meta\collection_info.json')) {
        try { $mci = Get-Content (Join-Path $f 'meta\collection_info.json') -Raw | ConvertFrom-Json
              $hostn = "$($mci.platform)-$($mci.serial)"
              if ($mci.case) { $IntakeCase = $mci.case }
              if ($mci.scenario_name) { $IntakeScenarios += $mci.scenario_name }
              if ($mci.attack_tags) { $AttackTags += @(("$($mci.attack_tags)") -split '[, ]+' | Where-Object { $_ }) } } catch {}
        $micsv = Join-Path $f 'detection\mobile_iocs.csv'
        if (Test-Path $micsv) {
            Write-Host "Mining MOBILE capture $f (host=$hostn)" -ForegroundColor Cyan
            foreach ($row in (Import-Csv $micsv -ErrorAction SilentlyContinue)) {
                switch ($row.type) {
                    'domain'          { Add-IOC 'domain'    ("$($row.value)").ToLower() 'mobile-mvt' $hostn 75 $true }
                    'ipv4'            { Add-IOC 'ipv4-c2'   "$($row.value)" 'mobile-mvt' $hostn 75 $true }
                    'sha256'          { Add-IOC 'hash'      "$($row.value)" 'mobile-mvt' $hostn 75 $true }
                    'apk-hash'        { Add-IOC 'hash'      "$($row.value)" 'mobile-apk'  $hostn 60 $false }
                    'process'         { Add-IOC 'file-path' "$($row.value)" 'mobile-mvt' $hostn 75 $true }
                    'android-package' { Add-IOC 'file-path' "$($row.value)" 'mobile-pkg' $hostn 60 $false }
                }
            }
        }
        continue   # mobile folder has no host 01_volatile/02_network tree to mine
    }
    Write-Host "Mining $f (host=$hostn)" -ForegroundColor Cyan
    # intake.json: scenario context + operator's already-known indicators (seeded confidence=75, to_ids)
    $intake = $null
    try { $intake = Get-Content (Join-Path $f '00_metadata\intake.json') -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
    if ($intake) {
        if ($intake.case_id)       { $IntakeCase = $intake.case_id }
        if ($intake.scenario_name) { $IntakeScenarios += $intake.scenario_name }
        if ($intake.attack_tags)   { $AttackTags += @($intake.attack_tags) }
        foreach ($x in @($intake.known_bad_ips))     { if ($x) { Add-IOC 'ipv4-c2'   "$x" 'operator-intake' $hostn 75 $true; $SeedCount++ } }
        foreach ($x in @($intake.known_bad_domains)) { if ($x) { Add-IOC 'domain'    ("$x").ToLower() 'operator-intake' $hostn 75 $true; $SeedCount++ } }
        foreach ($x in @($intake.known_bad_hashes))  { if ($x) { Add-IOC 'hash'      "$x" 'operator-intake' $hostn 75 $true; $SeedCount++ } }
        foreach ($x in @($intake.known_bad_paths))   { if ($x) { Add-IOC 'file-path' "$x" 'operator-intake' $hostn 75 $true; $SeedCount++ } }
    }

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
            if ($d -match '\.(exe|dll|dat|ini|log|tmp|sys|bat|ps1|txt|csv|xml|json|lnk|pf|evtx)$') { continue }
            Add-IOC 'domain' $d $rel $hostn
        }
    }
    # --- suspicious process image paths + hashes ---
    foreach ($rel in '01_volatile\processes.csv','01_volatile\processes.txt','04_persistence\services.csv','04_persistence\autoruns.csv','04_persistence\scheduled_tasks.csv') {
        $txt = Read-Src $rel
        foreach ($line in ($txt -split "`n")) {
            if ($line -match $suspDirRe) {
                foreach ($pm in [regex]::Matches($line, '(?i)[a-z]:\\[^,"\r\n ]+\.(exe|dll|ps1|bat|scr|vbs)')) { Add-IOC 'file-path' $pm.Value $rel $hostn }
                foreach ($pm in [regex]::Matches($line, '(?i)/(tmp|dev/shm|var/tmp)/[^\s,"]+')) { Add-IOC 'file-path' $pm.Value $rel $hostn }
            }
            foreach ($hm in [regex]::Matches($line, $hashReStrong)) { Add-IOC 'hash' $hm.Value $rel $hostn }
            # C2 in a command line (e.g. powershell -enc / DownloadString('http://1.2.3.4/a'))
            foreach ($ipm in [regex]::Matches($line, $ipRe)) { if (Test-PublicIP $ipm.Value) { Add-IOC 'ipv4-c2' $ipm.Value "$rel(cmd)" $hostn } }
            foreach ($dm in [regex]::Matches($line, $domRe)) { $d=$dm.Value.ToLower(); if ($d -notmatch '\.(local|arpa|lan|internal|corp|home)$' -and $d -notmatch $benignRe -and $d -notmatch '\.(exe|dll|dat|ini|log|tmp|sys|bat|ps1|txt|csv|xml|json|lnk|pf|evtx)$') { Add-IOC 'domain' $d "$rel(cmd)" $hostn } }
        }
    }
    # --- autoruns hashes (Sysinternals -h output) ---
    $ar = Read-Src '04_persistence\autoruns.csv'
    foreach ($hm in [regex]::Matches($ar, $hashRe)) { Add-IOC 'hash' $hm.Value '04_persistence\autoruns.csv' $hostn }
}

$AttackTags = @($AttackTags | Where-Object { $_ } | Select-Object -Unique)
$sigTags = ($AttackTags | ForEach-Object { "  - attack.$($_.ToLower())" }) -join "`n"
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
        'domain'   { "[domain-name:value = '$(Esc-Stix $i.value)']" }
        'hash'     { $alg = if($i.value.Length -eq 40){'SHA-1'}elseif($i.value.Length -eq 32){'MD5'}else{'SHA-256'}; "[file:hashes.'$alg' = '$($i.value)']" }
        'file-path'{ "[file:name = '$(Esc-Stix (( $i.value -split '[\\/]')[-1]))']" }
        default    { $null }
    }
    if ($pat) { $stixObjs += [ordered]@{ type='indicator'; spec_version='2.1'; id=(New-DetId 'indicator' $pat); created=$stixTs; modified=$stixTs; valid_from=$stixTs; name="IR-Collect $($i.type)"; pattern=$pat; pattern_type='stix'; description="IR-Collect $($i.type) from host $($i.host)"; confidence=50; indicator_types=@('malicious-activity') } }
}
$bundle = [ordered]@{ type='bundle'; id=(New-DetId 'bundle' (($stixObjs | ForEach-Object { $_.pattern }) -join '|')); objects=$stixObjs }
Save-Text (Join-Path $OutDir 'ioc\indicators.stix.json') ($bundle | ConvertTo-Json -Depth 6)

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
    [void]$spl.AppendLine('index=* (sourcetype=stream:dns OR sourcetype=*dns* OR sourcetype=*proxy* OR sourcetype=zeek*) (' + $dOr + ') | stats count by query src')
    [void]$spl.AppendLine('')
}
if ($hashes.Count) {
    $hList = ($hashes | ForEach-Object { $Q + $_ + $Q }) -join ','
    [void]$spl.AppendLine('### Process/file execution of captured hashes (Sysmon/EDR)')
    [void]$spl.AppendLine('index=* (sourcetype=*Sysmon* OR sourcetype=*EDR* OR sourcetype=*CrowdStrike*) (Hashes IN (' + $hList + ') OR SHA256 IN (' + $hList + ')) | stats count values(Image) values(ComputerName) by _time')
    [void]$spl.AppendLine('')
}
if ($paths.Count) {
    $imgs = ($paths | ForEach-Object { 'Image=' + $Q + '*' + (($_ -split '[\\/]')[-1]) + $Q }) -join ' OR '
    [void]$spl.AppendLine('### Execution from suspicious paths (captured)')
    [void]$spl.AppendLine('index=* (sourcetype=*Sysmon* OR sourcetype=WinEventLog:*) EventCode IN (1,4688) (' + $imgs + ') | stats count values(CommandLine) by Image ComputerName')
    [void]$spl.AppendLine('')
}
Save-Text (Join-Path $OutDir 'splunk\hunt_searches.spl') $spl.ToString()

# Splunk ES correlation-search stub
$ipListCsv = ($ips | ForEach-Object { $Q + $_ + $Q }) -join ','
$corr = @"
# Splunk ES correlation search (savedsearches.conf). Review + enable in ES. Tune throttle/thresholds.
[IR-Collect - C2 IP contact]
search = | tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip IN ($ipListCsv) by All_Traffic.src_ip All_Traffic.dest_ip
disabled = 1
enableSched = 1
cron_schedule = */10 * * * *
dispatch.earliest_time = -24h
dispatch.latest_time = now
counttype = number of events
quantity = 0
relation = greater than
alert.track = 1
action.correlationsearch.enabled = 1
action.correlationsearch.label = IR-Collect - C2 IP contact
action.notable = 1
action.notable.param.rule_title = IR-Collect - C2 IP contact
action.notable.param.rule_description = Endpoint contacted an external IP captured from a compromised host during IR triage.
action.notable.param.security_domain = network
action.notable.param.severity = high
action.notable.param.nes_fields = src,dest
description = Endpoint contacted an IP captured from a compromised host during IR triage.
"@
if ($ips.Count) { Save-Text (Join-Path $OutDir 'splunk\savedsearches.conf') $corr } else { Save-Text (Join-Path $OutDir 'splunk\savedsearches.conf') '# no external IPs captured - no correlation search generated' }

# ---------------------------------------------------------------------------
# 3. Sigma rules (vendor-neutral -> convert to Splunk or Sec Onion with pySigma)
# ---------------------------------------------------------------------------
if ($ips.Count) {
    $det=@('  selection:','    DestinationIp:'); $ips | ForEach-Object { $det += "      - $_" }
    $y = @"
title: IR-Collect C2 destination IPs
id: $(New-DetUuid ("ipnet|" + ($ips -join ',')))
status: experimental
description: External destination IPs captured from compromised host(s) during IR triage.
logsource:
  category: network_connection
detection:
$($det -join "`n")
  condition: selection
level: high
tags:
  - attack.command_and_control
$sigTags
"@
    Save-Text (Join-Path $OutDir 'sigma\c2_ip_indicators.yml') $y
}
if ($domains.Count) {
    $det=@('  selection:','    QueryName:'); $domains | ForEach-Object { $det += "      - $_" }
    $y = @"
title: IR-Collect C2 DNS queries
id: $(New-DetUuid ("dns|" + ($domains -join ',')))
status: experimental
description: DNS queries to domains captured from compromised host(s) during IR triage.
logsource:
  category: dns_query
detection:
$($det -join "`n")
  condition: selection
level: high
tags:
  - attack.command_and_control
$sigTags
"@
    Save-Text (Join-Path $OutDir 'sigma\c2_dns_indicators.yml') $y
}
if ($hashes.Count -or $paths.Count) {
    $det=@(); $cond=@()
    if ($hashes.Count) { $det += '  selection_hash:'; $det += '    Hashes|contains:'; $hashes | ForEach-Object { $det += "      - $_" }; $cond += 'selection_hash' }
    if ($paths.Count) { $det += '  selection_image:'; $det += '    Image|endswith:'; ($paths | ForEach-Object { ($_ -split '[\\/]')[-1] } | Select-Object -Unique) | ForEach-Object { $det += ('      - ' + (Yaml-Q $_)) }; $cond += 'selection_image' }
    $y = @"
title: IR-Collect malicious process indicators
id: $(New-DetUuid ("proc|" + (($hashes + $paths) -join ',')))
status: experimental
description: Process/file indicators captured from compromised host(s) during IR triage.
logsource:
  category: process_creation
detection:
$($det -join "`n")
  condition: $($cond -join ' or ')
level: high
tags:
  - attack.execution
$sigTags
"@
    Save-Text (Join-Path $OutDir 'sigma\malicious_process_indicators.yml') $y
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
    [void]$sur.AppendLine("alert dns `$HOME_NET any -> any any (msg:`"IR-Collect C2 domain $d`"; dns.query; content:`"$d`"; nocase; endswith; classtype:trojan-activity; sid:$sid; rev:1; metadata:source ir-collect;)")
    $sid++
}
Save-Text (Join-Path $OutDir 'suricata\local.rules') $sur.ToString()

# ---------------------------------------------------------------------------
# 5. Zeek Intelligence Framework feed (Security Onion)
# ---------------------------------------------------------------------------
$zeek = New-Object System.Text.StringBuilder
[void]$zeek.AppendLine("#fields`tindicator`tindicator_type`tmeta.source`tmeta.desc")
foreach ($ip in $ips)     { [void]$zeek.AppendLine("$ip`tIntel::ADDR`tIR-Collect`tC2 IP from IR triage") }
foreach ($d in $domains)  { [void]$zeek.AppendLine("$d`tIntel::DOMAIN`tIR-Collect`tC2 domain from IR triage") }
foreach ($h in $hashes)   { $alg = if($h.Length -eq 40){'sha1'}elseif($h.Length -eq 32){'md5'}else{'sha256'}; [void]$zeek.AppendLine("$h`tIntel::FILE_HASH`tIR-Collect`t$alg hash from IR triage (Zeek matches its computed algo)") }
Save-Text (Join-Path $OutDir 'zeek\ircollect.intel') $zeek.ToString()

# ---------------------------------------------------------------------------
# 6. ATT&CK Navigator layer (union of scenario techniques) - one-page campaign view
# ---------------------------------------------------------------------------
if ($AttackTags.Count) {
    $layer = [ordered]@{
        name        = "IR-Collect $IntakeCase"
        versions    = [ordered]@{ attack='14'; navigator='4.9.0'; layer='4.5' }
        domain      = 'enterprise-attack'
        description = "Techniques from IR-Collect forward-triage scenario(s): $($IntakeScenarios -join '; ')"
        gradient    = [ordered]@{ colors=@('#ffffff','#fd8d3c'); minValue=0; maxValue=100 }
        techniques  = @($AttackTags | ForEach-Object { [ordered]@{ techniqueID=$_; score=100; color='#fd8d3c'; comment='IR-Collect scenario'; enabled=$true } })
    }
    Save-Text (Join-Path $OutDir 'ioc\attack_layer.json') ($layer | ConvertTo-Json -Depth 6)
}

# ---------------------------------------------------------------------------
# HANDOFF.md for the follow-on team
# ---------------------------------------------------------------------------
@"
# IR-Collect -> Detection Content Handoff

Generated from forward-party triage of $($folders.Count) compromised host(s).
**Case:** $IntakeCase   **Scenario(s):** $($IntakeScenarios -join '; ')
**ATT&CK:** $($AttackTags -join ', ')
Observables: **$($ips.Count) external IPs, $($domains.Count) domains, $($hashes.Count) hashes, $($paths.Count) suspicious paths** ($SeedCount operator-seeded from intake, confidence=75).
- ``ioc/attack_layer.json`` - MITRE ATT&CK Navigator layer for the scenario; load at https://mitre-attack.github.io/attack-navigator/ for a one-page campaign view.

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
