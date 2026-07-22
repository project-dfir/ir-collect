# What a run-on-the-box collector is blind to — and where to reach instead

IR-Collect answers one question well: *"what can I learn by executing on this one running box?"*
That question has three structural limits — **trust** (a kernel/hypervisor rootkit can fake what any
in-OS tool sees), **footprint** (running code perturbs the box and can tip off an active attacker),
and **scope** (real intrusions are many hosts + an identity plane, not one machine). Below is what
sits *outside* this tool's boundary, from a three-angle review. Use it to decide when NOT to just run
this tool, and what to pair it with.

---

## A. Other places to collect from (vantage points this tool can't reach)

| Vantage | Why it beats/backstops on-box | Reach for |
|---|---|---|
| **Network (off-host)** | Evidence a host rootkit *cannot forge* — collected off the wire. #1 architectural blind spot. | Full PCAP at a **TAP/SPAN** (`tcpdump`/`dumpcap`, index with **Arkime**); **Zeek** conn/dns/http/ssl logs; **Suricata**; **NetFlow/IPFIX** (`nfdump`/SiLK); firewall + **proxy** + **DNS server** logs. SANS FOR572. |
| **Identity / central** | Modern attacks are identity attacks; the evidence is on the DC/IdP, not the workstation. | **DC security logs via WEF/WEC**; **Entra ID / M365 Unified Audit Log** (Microsoft-Extractor-Suite, DFIR-O365RC); the **SIEM**; **EDR** telemetry (retroactive, sees what malware unhooked locally). |
| **VM / cloud snapshot** | Zero-guest-footprint acquisition — beats live triage for virtual workloads, sidesteps Secure Boot/HVCI. | **VMware** snapshot-with-memory → `.vmem` (RAM, Volatility-ready) + `.vmdk`; **AWS EBS snapshot** → attach to clean forensic EC2; **Azure/GCP** managed-disk snapshot. `aws ec2 create-snapshot`, `az snapshot create`. |
| **Out-of-band hardware** | See below the OS when it's locked/hung, or boot a forensic ISO remotely. | **iDRAC / iLO / IPMI / Redfish / XCC**: SEL logs, virtual media (mount WinFE/CAINE), serial-over-LAN/KVM. |
| **Fleet / at scale** | This tool is one-box-one-USB; it can't answer "which of my 5,000 endpoints talked to this C2." | **Velociraptor hunts** (you already carry it — same VQL artifacts fleet-wide); **EDR live-query/RTR**; **osquery/Fleet**; KAPE via GPO/PsExec. |
| **Cloud-native / ephemeral** | Containers/serverless are gone before a USB arrives; there's no disk. | Container runtime (`docker/crictl inspect`, `/var/lib/docker/overlay2`, Falco/Tracee); **kube-apiserver audit log**; snapshot the node (it's a VM); **CloudTrail / Azure Activity / GCP Audit**, CloudWatch, VPC Flow Logs; Lambda = provider logs only. FOR509. |

**Rule of thumb:** VM/cloud → prefer a **snapshot** over running this tool. Active C2 → grab **network**
first, off-host. >3 hosts → promote to a **Velociraptor hunt**. Physical/remote/locked → **iDRAC virtual media**.
(The guided intake now asks these up front.)

---

## B. High-value artifacts to add to on-box collection

The **Velociraptor `Windows.KapeFiles.Targets`** / **CyLR** / **UAC** triage path (all staged in `tools/`)
already grabs most of the Windows gaps below via VSS/raw — prefer it over the native fallback. Priority adds:

1. **NTFS metadata (timelining backbone):** `$MFT`, `$UsnJrnl:$J`, `$LogFile`, `$Boot`, `$Recycle.Bin` `$I/$R`. `reg save` does **not** get these — the triage tools do (raw/VSS). Parse with **MFTECmd**.
2. **Per-user hives:** `NTUSER.DAT` + `UsrClass.dat` → UserAssist, ShellBags, RunMRU, TypedPaths, RecentApps, MUICache, WordWheelQuery. (Native fallback now copies these best-effort.)
3. **Execution/ESE DBs:** **Amcache.hve** (copy, not note), **SRUM** (`SRUDB.dat` — per-process network bytes = exfil volume), **Windows.edb** (Search index).
4. **Full `winevt\Logs` folder** (200+ logs, not just 3): **Sysmon**, PowerShell/Operational (4104), TaskScheduler, TerminalServices (RDP 21/22/25/1149), WMI-Activity, BITS, Defender/Operational. Chainsaw/Hayabusa (staged) hunt these.
5. **Credential/token stores:** **DPAPI master keys** (or copied browser logins are undecryptable), Credential Manager/Vault, cloud CLI creds (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube/config`), Windows `~/.ssh`, PuTTY/WinSCP saved sessions, `.git-credentials`.
6. **USB history:** `USBSTOR`+`MountedDevices` (in SYSTEM hive), `setupapi.dev.log`. (Native fallback now copies.)
7. **Memory-adjacent:** `pagefile.sys`, `swapfile.sys`, `hiberfil.sys` (a *second* memory image), WER/crash dumps (`MEMORY.DMP`, `%LocalAppData%\CrashDumps`).
8. **Persistence ASEPs not in SCM/Run:** IFEO Debugger, AppInit/AppCert DLLs, Winlogon, LSA SSP, COM hijack (UsrClass), netsh helpers, print monitors, Office add-ins/templates, browser extensions, raw WMI `OBJECTS.DATA`.
9. **Linux (UAC covers these — staged):** `auditd` raw, **binary journald** files, `/proc/<pid>/{maps,environ,fd,exe}` incl. **recover deleted-but-running binaries** (`cp /proc/<pid>/exe`), `/etc/ld.so.preload`, package integrity (`rpm -Va`/`debsums`), **eBPF** (`bpftool prog show`), containers, `/proc/sys/kernel/tainted`.
10. **macOS:** currently **out of scope** — if Macs exist, use `log collect` (.logarchive), LaunchAgents/Daemons plists, FSEvents, TCC.db, quarantine; tools: macOS-UAC, AutoMacTC, aftermath.

**Triage-time analysis (turn collection into detection):** YARA scan (**Loki**/THOR-Lite/Fenrir) over disk + process memory; **autoruns `-vt -h`** + **sigcheck** of running images; per-process memory dumps of suspicious PIDs (`Windows.Memory.ProcessDump`); hash the full-FS inventory against NSRL/known-bad; run **Plaso/log2timeline** → **Timesketch** for a super-timeline.

---

## C. Strategy / procedure — the non-code things that make or break it

- **Encryption keys while live (now captured):** BitLocker/LUKS status + recovery keys go in `00_metadata`. If the disk is encrypted and you power off without the key, the dead-box image is unreadable. The gate now goes **AMBER** on *encrypted disk + no verified RAM*.
- **RAM-capture verification (now enforced):** the classic silent failure is WinPmem blocked by Secure Boot/HVCI writing a tiny file while the run seals GREEN. The gate now **asserts a real image (≥40% of RAM)** and re-hashes it (SHA-256 + MD5).
- **Pre-touch decision + authorization (see `RUNBOOK.md`):** isolate-vs-collect (don't yank the cable — EDR-contain), scene/screen photo, who authorized it, scope, escalation criteria. Pass `-Authorizer/-LegalBasis/-ScopeNote`.
- **Verify, don't just hash:** re-read + re-hash + compare after acquisition; emit a second algorithm (now MD5 alongside SHA-256 for the memory image).
- **Anti-forensics awareness:** live SharpHound/AD enumeration is **noisy** — if the adversary may be active, prefer offline/dead-box AD analysis (keep it out of `-Auto` on hot boxes). Detect cleared logs (Security 1102 / System 104) and timestomping ($SI vs $FN) at analysis time.
- **Analysis handoff:** memory image → **Volatility 3** (Linux needs the ISF built from the captured `kallsyms`/`System.map` via `dwarf2json`); triage → **Plaso → Timesketch**; keep output machine-readable (CSV/JSON), not `Format-Table`.

Standards: RFC 3227, NIST SP 800-61r2 / 800-86, ISO/IEC 27037 (collection) & 27042 (analysis/verification), SWGDE, ACPO.
