# Incident Scenarios & Environment Variations

IR-Collect runs one constant **RFC 3227 order-of-volatility base collection** on every host. A
**scenario** is a profile overlay on top of that: it (a) **reprioritises** which heavy jobs auto-run,
(b) adds **scenario-specific collection**, (c) records the uniquely-perishable *grab-first* item, and
(d) tags the detection handoff with **MITRE ATT&CK** so `Build-DetectionContent.ps1` can seed from your
known-bad indicators and emit an ATT&CK Navigator layer.

Pick the scenario + host role in the **guided intake** (`IR-Collect.ps1` with no `-Auto`/`-RapidOnly`,
or `ir-collect.sh` interactively). The choices are written to `00_metadata/intake.json`, which the
detection generator reads. `Unknown / broad triage` reproduces the original scenario-agnostic behaviour,
so nothing regresses if you skip the choice.

This mirrors how the bundled tools already model triage: **UAC `profiles/`** on Linux and
**KAPE compound targets / Velociraptor `Windows.KapeFiles.Targets`** on Windows — a base set plus a
scenario overlay.

---

## How the menu adapts

| Menu job (Win / Linux) | What it is |
|---|---|
| 1 memory | Full RAM image (WinPmem/DumpIt/Magnet · AVML/LiME) |
| 2 artifacts | Triage pack (Velociraptor/CyLR · UAC) — hives/evtx/$MFT/SRUM · logs/config/histories |
| 3 eventlogs *(Win)* | Full `.evtx` export |
| 4 persistence | Services, tasks, autoruns, WMI subs · cron/systemd/suid |
| 5 ad | Active Directory / domain enumeration (+BloodHound) |
| 6 browser *(Win)* | Chrome/Edge/Firefox artifacts |
| 7 filehashes | Full-filesystem SHA-256 inventory |
| 8 diskimage | Full disk image |
| 9 vss *(Win)* | Volume Shadow Copy state + anti-recovery evidence (ransomware) |
| 10 weblogs / 7 weblogs *(Linux)* | Web-server logs + webroot mtime timeline (webshell) |

The scenario sets the auto-run **plan** (reprioritised); you can still add any job from the Stage-2 menu
afterwards. The **host role** further tunes the plan (e.g. drops browser on servers; OT/ICS drops the
hash-walk and disk image entirely).

---

## Scenario catalog

Each entry: the **grab-first** perishable item, the auto **plan**, ATT&CK, and what generic triage would
otherwise miss. Event IDs are Windows Security unless a channel is named.

### 1 · Ransomware / destructive — `T1486, T1490, T1489, T1562.001`
- **First:** RAM (keys/beacon may be resident) → **preserve Volume Shadow Copies (job 9)** before malware
  or an admin deletes them → `$MFT`/`$UsnJrnl` timeline via triage. **Do not reboot.**
- **Misses otherwise:** USN journal (time-boxes the whole encryption run), live VSS state, `vssadmin/wbadmin/bcdedit`
  recovery-inhibit evidence (4688/Sysmon 1). Grab a ransom note + one encrypted sample for family ID.
- **Linux:** check LVM/`.snapshot`/borg/restic for deleted backups; new `.locked/.ecc` extensions.

### 2 · BEC / cloud (M365/Entra) account compromise — `T1078.004, T1114.003, T1098.002, T1528`
- **This is an OFF-HOST investigation** — the endpoint tool is secondary. See **Cloud / off-host
  collection** below for the exact log pulls (Unified Audit Log, sign-in logs, inbox rules, OAuth grants).
- On the endpoint, only browser session cookies/tokens matter, and only if that device was the theft origin.

### 3 · Insider threat / data exfiltration — `T1567.002, T1052.001, T1560`
- **First:** live process/handles + current network (rclone/scp/rsync in flight) + mounted removable
  volumes while the session is live.
- **Misses otherwise:** USBSTOR↔MountedDevices↔volume-serial correlation, **SRUM bytes-sent**, cloud-sync
  client DBs + `~/.config/rclone/rclone.conf` (remote + often creds). Hash the sensitive share (job 7) to
  prove what left. Behaviour > IOCs (insiders use legitimate tools).

### 4 · Web-server / public-app compromise (webshell) — `T1190, T1505.003, T1059`
- **First:** live `netstat`/`ss` + process tree of the web service (in-memory-only shells leave nothing on
  disk) → **web logs + webroot timeline (job 10 / Linux job 7)**.
- **Tell:** `w3wp`/`httpd`/`nginx`/`php-fpm`/`java` spawning `cmd`/`powershell`/`sh`. Web logs are outside a
  default triage — the weblogs job adds IIS/Apache/Nginx/Tomcat logs, server config, and a mtime-sorted
  `.aspx/.asp/.php/.jsp` webroot listing (dropped shells sort to the top).

### 5 · Commodity malware / C2 beacon — `T1071.001, T1071.004, T1573, T1055`
- **First:** RAM (beacon config / injected shellcode is memory-only) → live conn→PID→binary-hash, DNS cache,
  named pipes (Sysmon 17/18).
- **Handoff:** add JA3/JA4 fingerprints + beacon-interval hunts. The generator mines download-cradle IPs/domains
  straight out of process command lines.

### 6 · Active Directory / Domain-Controller compromise — `T1003.006, T1558.001, T1207`
- **First:** **export the DC Security event log immediately** (busy DCs roll logs in hours — the most
  perishable evidence in the catalog) + current Kerberos tickets + sessions.
- **Notes:** 4662 with replication GUIDs from a non-DC = DCSync; 4769 RC4 = kerberoast/Golden Ticket. On a DC
  **prefer a snapshot/dead-box** over live tools; never disrupt replication. AD compromise is inherently
  **multi-host — collect from ALL DCs** (set scope=fleet → Velociraptor hunt). NTDS.dit + SYSTEM via VSS.

### 7 · Lateral movement / credential theft — `T1021.x, T1003.001, T1550.x`
- **First:** logon telemetry (4624/4625 type 3/10, 4648, 4672), RDP artifacts, **LSASS-access (Sysmon 10)**,
  cached tickets + live sessions.
- **Misses otherwise:** logon-type correlation across the host pair, RDP-client (outbound) MRU,
  `authorized_keys`/`known_hosts` (Linux spread map). Strongest single-vs-fleet trigger → promote to a hunt.

### 8 · Living-off-the-land / fileless — `T1059, T1218, T1047`
- **First:** RAM + live process command lines (fileless = memory-only); PowerShell scriptblock/transcript
  (4104/4103); the **WMI repository** (`OBJECTS.DATA`).
- **Handoff:** a LOLBin execution report from 4688/Sysmon 1 vs a LOLBAS list.

### 9 · Phishing initial access — `T1566, T1204, T1218`
- **First:** browser session/cookies (AiTM token theft), the running first-stage process, `%TEMP%` before
  cleanup.
- **Tell:** Office (`WINWORD/EXCEL/OUTLOOK`) → `cmd/powershell/mshta`; Zone.Identifier/MOTW ADS; Office
  TrustRecords. Usually chains to C2/lateral — add those as secondary.

### 10 · Cryptomining — `T1496, T1543.003, T1053.005`
- **First:** live high-CPU/GPU process + cmdline + pool connections → persistence (cron/service/task).
- **Notes:** usually a symptom of a broader compromise — consider C2-beacon as secondary. Check for
  rootkit-hidden PIDs. On a container/k8s node most crypto lives in pods (see below).

### Also cataloged (see the research notes): supply-chain, OT/ICS, container/k8s, macOS
Selectable via the closest scenario + the **host role** overlay (Container/k8s, OT/ICS). macOS uses UAC's
native macOS artifacts (LaunchAgents/Daemons, TCC/quarantine, `log collect`).

---

## Environment / host-role variations

The **host role** (asked at intake) overlays the scenario plan — it changes *what* each job targets and
*whether* intrusive jobs run at all.

| Role | What changes |
|---|---|
| **Workstation** | Default. User-artifact-heavy (browser, Office MRU, LNK, USB). RAM cheap and worth it. |
| **Server** | Prioritise service/task persistence + app/IIS logs; **browser dropped**. Avoid live full-disk image on prod — prefer VSS + targeted triage. |
| **Domain Controller** | NTDS.dit + SYSTEM via VSS, SYSVOL/GPO, huge Security log. **Strongly prefer snapshot/dead-box.** Never disrupt replication. Collect from all DCs. |
| **Cloud VM** | Prefer a **disk snapshot** attached to a clean forensic instance over in-guest run; also pull cloud control-plane logs. |
| **Container / k8s node** | Capture running-container state FAST (`docker/crictl ps`, image digests, `docker diff`, SA tokens, kube audit) — pods are ephemeral. The host tool captures the **node**. |
| **OT / ICS** | **Do-no-harm mode** (auto): no filesystem-hash walk, no disk image, no active enum. Host-only + passive. Availability > evidence — never risk process disruption. |
| **Network device** | Collect **off-box** (config, ARP/CAM, routing, syslog, NetFlow) via console — the host agent does not apply. |

**Cross-cutting flags** (also at intake):
- **Scope = fleet** → promote to a **Velociraptor hunt** (bundled): collection becomes a targeted VQL
  artifact set, not USB-per-box. AD-compromise and lateral-movement are inherently fleet scenarios.
- **Connectivity = airgapped/quarantined** → collect to local removable media only; no ship-at-seal; skip
  live network enrichment (defer to the analyst box). Detection content is still generated for when the
  host's historical logs reach the SOC.
- **C2 believed live** → capture network **off-host first** (TAP/SPAN pcap, firewall/proxy/DNS logs); keep
  enrichment passive so you don't tip the adversary.

---

## Cloud / off-host collection (scenario 2 BEC, container nodes, cloud VMs)

These are not endpoint jobs — run them from the analyst/PAW box against the cloud tenant, then drop the
exports next to the host collection so `Build-DetectionContent.ps1` folds them into the handoff.

**Microsoft 365 / Entra (BEC):**
- **Unified Audit Log** — `Search-UnifiedAuditLog` (Exchange Online PowerShell). Age-limited (E3 ~180 d);
  pull immediately and wide. Focus operations: `New-InboxRule`/`Set-InboxRule`/`UpdateInboxRules`
  (ForwardTo/DeleteMessage), `Set-Mailbox` (ForwardingSMTPAddress), `MailItemsAccessed`,
  `Add-MailboxPermission`, `Consent to application`/`Add service principal`, `UserLoggedIn`.
- **Entra sign-in logs** (IP/ASN/device, MFA satisfied?, session-token reuse) and **audit logs** (MFA method
  changes, SSPR). Sign-ins age out at 30 days by default.
- Open-source pullers: **Microsoft-Extractor-Suite**, **DFIR-O365RC**, **Hawk**, **CRT** (CrowdStrike
  Reporting Tool for Azure).

**AWS / Azure / GCP:** CloudTrail / Azure Activity / GCP Audit — `RunInstances`, new access keys, unusual
regions, IMDS access, attached-role usage.

**Container / k8s:** `docker ps` / `crictl ps`, image list + digests, `docker diff`, kube audit log,
ServiceAccount tokens (`/var/run/secrets/kubernetes.io/...`), `kubelet` logs. Snapshot the running container
before it reschedules.

Put the operator's already-known indicators into the intake (Malicious IPs/domains/hashes/accounts/paths)
— the generator seeds them at **confidence 75 / to_ids** so the fleet sweep starts from known-bad, then adds
the mined candidates around them.

---

## Mobile scenarios (Android / iPhone)

A phone is a **device column** in the incident, not a separate tool. The host guided intake asks *"was a
mobile device involved?"* and, based on the host scenario, prints the matching `mobile-collect.sh
--scenario <id>` command. `mobile-collect.sh` carries the same scenario doctrine (grab-first order,
ATT&CK-**Mobile** tags, forced analysis) and its findings fold into the **same** detection handoff +
ATT&CK Navigator layer as the host (via `detection/mobile_iocs.csv` → `Build-DetectionContent.ps1`).
Grounded in **NIST SP 800-101r1** (mobile), MVT methodology, and ATT&CK Mobile (T14xx/T15xx/T16xx).

| id | Scenario | ATT&CK-Mobile | Grab-first / emphasis |
|---|---|---|---|
| `smish` | Smishing / mobile phishing | T1660,T1456,T1204,T1417 | SMS/MMS + notifications + browser URL + install-source of an app sideloaded right after the lure |
| `spyware` | Mobile spyware / stalkerware (Pegasus-class) | T1636,T1430,T1429,T1512,T1417,T1521 | **Do not reboot**; Faraday; live syslog/logcat + crash reports FIRST → MVT over shutdown.log/DataUsage/WebKit/tcc.db + accessibility/appops/device_policy |
| `mdm` | Malicious MDM / config-profile compromise | T1626.001,T1629,T1478,T1474 | Snapshot installed profiles / trusted CAs / VPN payloads / MDM enrollment → **diff vs corporate baseline** |
| `bec`/`token` | Mobile BEC / on-device token theft | T1635,T1409,T1417.001,T1636.004 | iOS encrypted backup = Keychain (OAuth/refresh tokens); Android `dumpsys account` + mail-app data; pair with host BEC cloud pull |
| `exfil` | Mobile as exfil destination | T1533,T1544,T1567 | Hash `/sdcard` (Android) / Files+camera-roll (iOS); cloud-sync app inventory; correlate phone serial ↔ workstation USBSTOR |
| `beacon` | Mobile C2 beacon | T1437.001,T1521,T1481 | Live connectivity/netstats + full logcat before isolation → MVT IOC check |
| `ransom` | Mobile extortion channel | T1471,T1516 | Extortion/leak-site contact evidence (SMS/notifications, messaging DBs, dropped locker APK/profile). Do **not** wipe |
| `lost` | Lost / stolen device | T1461,T1626 | **Off-device**: Find My / MDM console / iCloud-Google activity / carrier; only tether if recovered + unlocked (writes an off-device checklist) |

**How host scenarios map to a mobile profile** (what the intake suggests): BEC→`bec`, insider-exfil→`exfil`,
phishing→`smish`, C2→`beacon`, cryptomining→`spyware`, AD/lateral→`token`, ransomware→`ransom`.

### Scenario × device coverage (summary)

`P`=primary · `✓`=in scope · `S`=secondary · `R`=off-box/control-plane · `—`=n/a. Phones are covered by
`mobile-collect.sh`; Windows/Linux/DC/cloud-VM/container/OT/netdev by the host collectors' role overlay.

| Scenario | Win/Linux host | Cloud VM | Container | OT/ICS | Net dev | Android | iPhone |
|---|---|---|---|---|---|---|---|
| Ransomware | P | ✓(snap) | S | S(do-no-harm) | R | S(`ransom`) | S(`ransom`) |
| BEC / cloud acct | S | S | — | — | R | **P(`bec`)** | **P(`bec`)** |
| Insider / exfil | P | ✓ | S | — | R | **P(`exfil`)** | **P(`exfil`)** |
| Webshell | P | P | P | — | R | — | — |
| C2 beacon | P | ✓ | P | S | R | S(`beacon`) | S(`beacon`) |
| AD / DC | P | S | — | — | R | S(`token`) | S(`token`) |
| Lateral / cred | P | ✓ | S | S | R | S(`token`) | S(`token`) |
| LOLBin / fileless | P | ✓ | ✓ | S | R | — | — |
| Phishing | P | S | — | — | R | **P(`smish`)** | **P(`smish`)** |
| Cryptomining | P | P | P | S | R | S(`spyware`) | S(`spyware`) |
| Mobile spyware | — | — | — | — | R | **P(`spyware`)** | **P(`spyware`)** |
| Malicious MDM | S | S | — | — | R | **P(`mdm`)** | **P(`mdm`)** |
| Lost / stolen | S | — | — | — | — | **P(`lost`)** | **P(`lost`)** |

See **[MOBILE.md](MOBILE.md)** for acquisition doctrine, the open-source tool stack, and per-platform steps.
