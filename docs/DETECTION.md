# From triage capture → detection content (SOC forward-party workflow)

## The workflow this fits

A SOC/IR **forward party** deploys early to compromised hosts to grab perishable evidence (RAM, live
connections, processes, persistence) **before it's lost** — RFC 3227 order of volatility, NIST SP 800-86.
The **follow-on team** arrives with the full suite (network TAP/sensors, log forwarding, **Security Onion**
= Suricata+Zeek+Elastic, **Splunk Enterprise Security**) and baselines/hunts for weeks. The forward
party's deliverable isn't the raw capture — it's **detection content the follow-on team loads directly**.

This maps to established doctrine: DoD **Cyber Protection Teams** (hunt/clear phases), Mandiant/CrowdStrike
**"live-response triage → enterprise sweep"**, **F3EAD** (Find-Fix-Finish-Exploit-Analyze-Disseminate),
SANS **FOR508** (IR/hunt) → **FOR572** (network) → **SEC555** (SIEM content) → **FOR578** (CTI). Treat the
handoff as a **living, versioned feed**, not a one-shot list.

## What `Build-DetectionContent.ps1` produces today

Run it on the **analyst box** (not the victim) against a collection folder:

```
pwsh detection/Build-DetectionContent.ps1 -CollectionDir E:\evidence\CASE001_HOST_20260722_141530Z
#   (also accepts a mobile-collect.sh capture folder - folds its MVT IOCs into the same handoff)
```

| Output | Consumer | Notes |
|---|---|---|
| `ioc/indicators.csv` + `.stix.json` | Splunk ES threat-intel, MISP, humans | deduped IOCs w/ source + host |
| `splunk/hunt_searches.spl` | Splunk ES | uses CIM data models (Network_Traffic/Resolution) |
| `splunk/savedsearches.conf` | Splunk ES | correlation-search stubs (tune + enable) |
| `sigma/*.yml` | **both** stacks | vendor-neutral → `sigma convert` to SPL or Elastic/EQL |
| `suricata/local.rules` | Security Onion | SID range from `-SidBase`; C2 IP/domain |
| `zeek/ircollect.intel` | Security Onion | Zeek Intel Framework TSV feed |
| `HANDOFF.md` | follow-on team | what's here + how to load it |

## Roadmap (from a detection-engineering review — prioritized)

The current generator lives in the **bottom of the Pyramid of Pain** (hashes/IPs/domains — brittle,
short-lived). The upgrades that make it SOC-grade, in order:

1. **FP control first (highest ROI).** Enrich/allowlist before arming anything: prevalence lists
   (Cisco Umbrella/Tranco/Majestic), cloud/CDN ASN suppression, **NSRL** for hashes, **VirusTotal /
   GreyNoise / abuse.ch / passive-DNS** enrichment, and a **0–100 confidence score + `to_ids` gate** so
   CDN/telemetry noise ships as *context*, not alerts. (A coarse benign-domain allowlist is already in.)
2. **Sigma + MISP/STIX as canonical source**, derive the four native artifacts from them; hit exact
   schemas — Splunk **CIM** field names + **ES threat-intel KV-store** collections (`ip_intel`,
   `domain_intel`, `file_intel`…), **Zeek `Intel::` enums** (SHA1 for `FILE_HASH`), **Suricata SID
   1,000,000–1,999,999** local range + `iprep` datasets for bulk IOCs.
3. **Climb to behavioral/TTP detections.** For each captured artifact emit a **technique-level Sigma
   rule** (e.g. "scheduled task running encoded PowerShell from %TEMP%" = T1053.005+T1059.001+T1027), not
   just the atomic value; **tag every rule with MITRE ATT&CK IDs**; cross-reference **SigmaHQ / Splunk
   ESCU / Elastic detection-rules** rather than reinventing.
4. **Hunt-enablement outputs:** an **ATT&CK Navigator layer** (one-page campaign view), a **timeline**
   (Plaso/log2timeline → Timesketch), and a **baselining playbook** — beacon seeds for **RITA** (Zeek),
   Elastic **`new_terms`** rules, Splunk **ESCU first-seen / URL-Toolbox entropy** — plus the host
   **logging-posture** (Sysmon/PS-logging/audit state) so the team knows which rules will even fire.
5. **Detection-as-code + guardrails:** Git + CI (Sigma lint, `suricata -T`, `zeek -C`), deterministic
   rule IDs/versions, **Atomic Red Team** validation ("fires ✔/untested"); **provenance/chain-of-custody**
   on every indicator; and **OPSEC/deconfliction** — default enrichment of *attacker* infra to
   **passive-only** so you don't tip off a live adversary.

## Higher-value observables to extract next

Beyond IPs/domains/hashes: **named pipes**, **mutexes**, **service names + binary paths**, **scheduled-task
actions** (the command, not just the name), **WMI EventConsumer** script/query, **parent→child process
lineage**, **encoded/LOLBin command lines** (cross-ref LOLBAS/GTFOBins), **JA3/JA4 + TLS cert fields +
User-Agents + HTTP URIs**, and Windows Event IDs (4688+cmdline, 4104, 7045, 4698, Sysmon 1/3/7/11/17-21).
These climb the pyramid and survive attacker infrastructure rotation.
