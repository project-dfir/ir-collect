# IR-Collect — Lightweight Self-Healing Incident-Response Collector

A grab-and-go **first-responder triage kit**: one script per OS, run from a thumb drive on a
machine you *assume is compromised*. It captures everything about the box in **RFC 3227 order of
volatility**, secures the perishable data first behind a **VOLATILE GREEN** checkpoint, then lets
you pick the slow non-volatile jobs from a menu. Every step **self-heals** — a hang, error, or
missing tool is logged and skipped; the run never halts.

- **Windows:** `IR-Collect.ps1` (PowerShell 5.1+, native CIM/.NET/ADSI)
- **Linux:** `ir-collect.sh` (POSIX/bash, native `/proc`, `ss`, `ip`, `systemctl`…)

**Start here:** the collectors default to a **guided intake** — pick the **incident scenario** (ransomware,
BEC/cloud, insider-exfil, webshell, C2 beacon, AD/DC, lateral, LOLBin, phishing, cryptomining…) and the
**host role** (workstation/server/DC/cloud-VM/container/OT), plus any indicators you already hold. That
reprioritises the menu, adds scenario-specific collection, and tags the detection handoff with ATT&CK. Read
**[docs/RANGE.md](docs/RANGE.md)** for TRAINING / cyber-range use (loading the kit into guest VMs and
extracting evidence across VMware/Hyper-V/VirtualBox/KVM), **[docs/MOBILE.md](docs/MOBILE.md)** for
ANDROID + iPHONE acquisition (open-source logical acquisition + MVT spyware triage from an examiner box), **[docs/SCENARIOS.md](docs/SCENARIOS.md)** for the scenario catalog + environment matrix + cloud/off-host
collection, **[docs/RUNBOOK.md](docs/RUNBOOK.md)** before a real collection (pre-touch decisions, encryption,
authorization), **[docs/GAPS.md](docs/GAPS.md)** for what a single-box tool can't see (network/identity/cloud
vantage points), **[docs/DETECTION.md](docs/DETECTION.md)** for turning a capture into Splunk ES / Security
Onion content, and **[docs/ENTERPRISE.md](docs/ENTERPRISE.md)** for deployment at scale (signing/CLM, EDR
deconfliction, fleet bridge). Build the tool payload once with `collectors/fetch-tools.*`.

### Repository layout
```
collectors/                                the shippable, path-coupled collector kit (archive its CONTENTS)
  IR-Collect.ps1 / ir-collect.sh      collectors (Windows / Linux)    -- run on the compromised host
  fetch-tools.ps1 / fetch-tools.sh    one-time kit builder            -- run on a trusted box
  loader.ps1 / loader.sh              in-guest bootstrap (read-only ISO / share launch)
  tools/                              open-source payload (fetched, not committed)
tools/verify-bundle.py              verify a RECEIVED bundle against its manifest  -- analyst box
                                    (note: distinct from collectors/tools/, which is the payload)
detection/Build-DetectionContent.ps1  capture -> Splunk/Sigma/Suricata/Zeek + Navigator  -- analyst box
mobile/                             mobile forensics                  -- run on the examiner box
  mobile-collect.sh / Mobile-Collect.ps1   Android + iOS logical acquisition + MVT triage
  fetch-mobile-tools.sh               one-time mobile examiner-box setup (adb/libimobiledevice/MVT/iLEAPP)
range/                              training-lab deploy helpers (per-hypervisor), collector server, detect
docs/SCENARIOS.md                   incident-scenario catalog + host-role matrix + cloud/off-host steps
docs/RANGE.md                       training-lab use: load into / extract out of guest VMs (any hypervisor)
docs/MOBILE.md                      Android + iPhone forensics: doctrine, usage, open-source tool stack
range/                              lab helpers: per-hypervisor deploy scripts, in-guest detect, loader, collector server
docs/RUNBOOK.md                     pre-touch field procedure + checklist
docs/GAPS.md                        off-host vantage points (network/identity/cloud) + artifact gaps
docs/DETECTION.md                   forward-triage -> detection-handoff doctrine + roadmap
docs/ENTERPRISE.md                  deployment at scale (signing/CLM, EDR deconfliction, fleet bridge)
```

### The SOC forward-party workflow
1. **Build the kit** once on a trusted box (`fetch-tools.*`) and carry the drive.
2. **Forward party** runs the collector on compromised hosts — guided intake (**scenario + host role +
   known indicators**) → volatile (RAM-first) → GREEN gate → scenario-prioritised non-volatile. The
   intake is written to `00_metadata/intake.json`. Perishable evidence secured before the main team arrives.
3. **Generate detection content** (`Build-DetectionContent.ps1`) from the capture — it reads `intake.json`,
   **seeds your known-bad IOCs**, and emits IOCs, Splunk SPL, Sigma (ATT&CK-tagged), Suricata, Zeek intel,
   and an **ATT&CK Navigator layer**.
4. **Hand off** to the follow-on team's suite (Splunk Enterprise Security + Security Onion) so they hunt
   those indicators across the enterprise and the weeks-long network baseline.

---

## Doctrine (why it works the way it does)

| Principle | Implementation |
|---|---|
| **Order of volatility** (RFC 3227) | Identity → **RAM image** → processes → sessions/tickets → network → *(GREEN gate)* → disk artifacts → persistence → AD → file-hashing → disk image |
| **Memory first** | Full RAM is imaged at the **top of Stage 1**, before any command perturbs it. `-DeferMemory`/`--defer-memory` moves it after the volatile-command battery if you prefer. |
| **Don't trust the host** | Carried binaries in `tools/bin` **shadow** host binaries (rootkit may have trojaned `ps`/`ss`/`ls`); kernel-level APIs (CIM/.NET/ADSI, raw `/proc`, `/proc/net`) preferred over host userland; `LD_PRELOAD`/`ld.so.preload` neutralized; SHA-256 of every invoked/carried tool recorded. |
| **Self-heal through any step** | Per-step **timeout + retry + catch + log**; always-seal wrapper; signal traps; no-TTY fallback to "run all"; a hung command is killed and skipped. |
| **Two-stage: fast then slow** | Stage 1 (automatic) secures volatile data quickly → **VOLATILE GREEN** confirmation → Stage 2 menu for the hours-long non-volatile jobs. |
| **Chain of custody** | UTC audit log of every command (exit code, duration, retries), SHA-256 manifest of all output, acquisition GUID, collector identity, host-clock provenance, tool hashes, sealed zip hash on ship. |
| **Ground-truth caveat** | Live results from a compromised host can be faked by a kernel/eBPF/LD_PRELOAD rootkit. **The RAM image + a dead-box disk image are ground truth**; live enumeration is corroboration. |
| **Keys are volatile too** | Order of volatility applies to **encryption keys**, not just data: power the box off and the volume master key is gone from kernel memory, leaving the image unreadable unless a custodian supplies a passphrase. While volumes are unlocked the collector captures them — see below. |

Standards followed: **RFC 3227**, **NIST SP 800-86**, **SWGDE**, **ISO/IEC 27037**.

### Volume encryption keys — captured by default

| | Windows | Linux |
|---|---|---|
| Key material | BitLocker recovery passwords (`bitlocker_recovery_keys.csv`, machine-readable) + **key packages** for `repair-bde` | live dm-crypt **volume master keys** (`dmsetup table --showkeys`) — decrypt the image with no passphrase at all |
| Container metadata | protector detail per volume | **LUKS header backups** — without the header even a *correct* passphrase fails, and header destruction is a known ransomware move |
| Also | EFS certs, DPAPI master-key paths, VeraCrypt/TrueCrypt indicators | `/etc/crypttab` + keyfile inventory, kernel keyring (fscrypt/eCryptfs) |

Everything lands in `00_metadata/`, alongside **`DECRYPTION-KEYS.md`** — what was captured plus the
actual verified commands to apply it months later (`--volume-key-file`, `dmsetup` mapping with the
sector offset, `luksHeaderRestore`, `manage-bde`/`dislocker`, `repair-bde`), and the
RAM-recovery route if no key was captured.

> **These outputs are the keys to the evidence.** Anyone holding the bundle can decrypt the imaged
> volumes, so store and transfer it at the classification of the data it protects and record its
> custody. The SUMMARY carries a handling banner to that effect. Where extracting key material is
> outside the engagement's authority, pass **`-NoKeyCapture`** / **`--no-keys`**.

---

## Footprint & safety — is it safe to run on the target?

**Nothing is installed on the target.** Tools run from the USB (`tools/`); evidence is written **only**
to your destination — never to the source disk. But **live collection is never zero-footprint**:
running any executable on a live box loads it into the target's RAM, shifts the page cache, and may
leave Prefetch/event-log traces; WinPmem loads a kernel driver. This is unavoidable when capturing
volatile data — doctrine's answer is to **run from removable media, write to a separate drive, and
document every action** (the audit log does this, UTC-timestamped + hashed).

**You cannot "containerize" your tools on the target** — the point is to touch its live kernel/RAM.
The forensic equivalent of an isolated environment is **dead-box acquisition**:

| Mode | What | When |
|---|---|---|
| **Live triage** (this tool) | run from USB on the *running* box, pull volatile + triage | need RAM / live connections / running malware, or can't take the box down |
| **Dead-box** | power off; image the disk via a **hardware write-blocker**, or boot the target from a **trusted forensic USB** (WinFE / CAINE / Tsurugi / SIFT) so the suspect OS never runs | non-volatile ground truth, after volatile is captured |

**Professional sequence:** live-collect volatile (RAM + triage) with this kit → **then go dead-box**
for the disk image. On a confirmed-compromised host a rootkit can fake what *any* live tool sees, so
the **RAM image + a dead-box disk image are ground truth**; live enumeration corroborates.

## Usage

### Windows
```powershell
# to an external drive, interactive menu for the slow jobs
powershell -ExecutionPolicy Bypass -File .\kit\IR-Collect.ps1 -Dest E:\evidence -CaseId CASE001

# fully unattended - rapid volatile + ALL heavy jobs, no prompts
powershell -ExecutionPolicy Bypass -File .\kit\IR-Collect.ps1 -Dest E:\evidence -Auto

# volatile only (fastest), then seal
powershell -ExecutionPolicy Bypass -File .\kit\IR-Collect.ps1 -Dest E:\evidence -RapidOnly

# ship to a network collector at an IP (stages locally, zips+hashes, SMB copy)
powershell -ExecutionPolicy Bypass -File .\kit\IR-Collect.ps1 -Dest 10.0.0.5 -Share evidence -CaseId C1

# TRAINING / range mode: mark EXERCISE, VM-aware, POST the bundle to a lab collector (see docs/RANGE.md)
powershell -ExecutionPolicy Bypass -File .\kit\IR-Collect.ps1 -Lab -Auto -Dest http://collector:8000/
```
Run **as Administrator**. Key switches: `-Auto`, `-RapidOnly`, `-SkipAD`, `-DeferMemory`, `-Lab`, `-StepTimeoutSec N`, `-Share <name>`, `-Cred`. `-Dest` accepts a drive path, `\\host\share`, a bare IP, or `http(s)://collector/`.

### Linux
```bash
sudo ./collectors/ir-collect.sh -d /mnt/evidence -c CASE001          # external drive + menu
sudo ./collectors/ir-collect.sh -d /mnt/usb --auto                   # unattended, all jobs
sudo ./collectors/ir-collect.sh -d /mnt/usb --rapid-only             # volatile only
sudo ./collectors/ir-collect.sh -d user@10.0.0.5:/evidence -c C1     # ship over ssh (rsync/scp)
sudo ./collectors/ir-collect.sh --lab --auto -d http://collector:8000/  # TRAINING/range: mark EXERCISE, HTTP POST (docs/RANGE.md)
```

### Mobile (Android / iPhone) - runs on the EXAMINER box with the device on USB
```bash
bash ./mobile/fetch-mobile-tools.sh                              # one-time: adb + libimobiledevice + MVT + iLEAPP/ALEAPP
# Android (USB debugging on, RSA trusted): acquire + MVT/ALEAPP triage
./mobile/mobile-collect.sh -c CASE1 -d /evidence --android --analyze --faraday --authorizer "J. Doe"
# iPhone (unlocked, 'Trust'): encrypted backup + mvt-ios spyware check
./mobile/mobile-collect.sh -c CASE1 -d /evidence --ios --analyze --backup-pass CaseIR
# Windows examiner: .\mobile\Mobile-Collect.ps1 -c CASE1 -d E:\evidence --android --analyze   (runs under Git-Bash/WSL)
```
Mobile flags: `--android`/`--ios`, `--scenario <smish|spyware|mdm|bec|token|exfil|beacon|ransom|lost>`, `--analyze`, `--faraday`/`--isolate`, `--backup-pass`, `--allow-root`, `--authorizer/--legal/--scope`. Runs on the examiner box (not the phone) - see [docs/MOBILE.md](docs/MOBILE.md).

The **destination** may be a local path, a UNC share (`\\IP\share`), or a bare IP/`user@host:path`.
Network destinations stage locally first, then zip + hash + ship (SMB on Windows; rsync/scp on Linux).

---

## The tool payload — open-source, pre-staged on the drive

The kit **carries its own tools**; the collector **never downloads anything during an incident** — it
only detects what's already in `tools/`. Build the kit **once on a trusted workstation** with the
included one-time builder, then carry the drive:

```
powershell -ExecutionPolicy Bypass -File .\kit\fetch-tools.ps1     # Windows payload -> tools\
bash ./collectors/fetch-tools.sh                                          # Linux payload  -> tools/bin\
```

These pull **open-source, license-free, professionally-proven** tools from their **official GitHub
releases**, record SHA-256 + source URL in `tools/PROVENANCE-*.txt`, and self-heal (a failed
download is logged and skipped).

| Need | Open-source tool (auto-staged) |
|---|---|
| **RAM image** | **WinPmem** (Velocidex, signed) · **AVML** (Microsoft, static) · LiME (build per-kernel) |
| **Artifact triage** | **Velociraptor** offline (`Windows.KapeFiles.Targets`) · **CyLR** · **UAC** (Linux) |
| **Event-log hunting** | **Chainsaw** · **Hayabusa** · **EZ-Tools** (MFTECmd/PECmd/EvtxECmd…) |
| **Active Directory** | **SharpHound** (BloodHound) · bloodhound-python/netexec (analysis box) |
| **Linux trusted core** | **static busybox** (coarse fallback) — trusted enumeration reads raw `/proc` |

**Not auto-staged** (free but **not** open-source — add manually only if allowed): Sysinternals,
KAPE, FTK Imager, Magnet RAM. **Python** tools install on your *analysis* box via `pipx`, not the victim.

> **Format the collection drive NTFS or exFAT, not FAT32** — a RAM image > 4 GB truncates on FAT32.

## Trust model — rely on our tools, self-repair, never trust host userland

- **Carried tools do the acquisition** (WinPmem/AVML, Velociraptor/CyLR/UAC, SharpHound), invoked by
  absolute path from `tools/`.
- **Enumeration uses kernel-level sources, not host userland exes** — Windows via **CIM/WMI/ETW/ADSI**
  (.NET kernel interface, not the trojanable `tasklist.exe`/`netstat.exe`); Linux via **raw `/proc`
  and `/proc/net`** (kernel truth a userland rootkit can't fake). Host utilities (`klist`, `nltest`,
  `reg`) are used only where no API exists, and logged as such.
- **Self-repair, not host-fallback:** at startup each script **fixes its own kit** — unblocks
  Mark-of-the-Web (Windows), `chmod +x` + extracts archives (Linux), reports what's missing — then
  retries a failed step after repair. Host-native commands are an explicitly-logged *last resort*.
- **Ground truth** is the **RAM image + a dead-box disk image**; live enumeration corroborates.

---

## Output layout

```
<CASE>_<HOST>_<UTC>/
  00_metadata/     identity, clock provenance, collection_info.json, tool + used-binary hashes
  01_volatile/     processes, cmdlines, dlls/handles, sessions, tickets, users, modules
  02_network/      connections+PIDs, listening ports, arp, routes, dns cache, firewall, shares
  03_memory/       RAM image (+ Linux kernel symbols for Volatility 3) + sha256
  04_persistence/  services, scheduled tasks/cron/systemd, autoruns, WMI, startup, suid/caps, packages
  05_artifacts/    registry hives / evtx / prefetch / MFT (Win); /var/log, configs, histories (Linux); file hashes
  06_activedirectory/ domain/forest/trusts, users/groups/computers, priv groups, delegation, roastable, host object
  07_diskimage/    full disk image (opt-in)
  99_logs/         audit.log (every command, UTC, exit code, duration), errors.log, MANIFEST-SHA256
  SUMMARY.md
```

### Reading the verdict — `99_logs/run_state.json`

The bundle's machine-readable answer to *"can I trust this collection, and what do I do next?"*
Beyond `completeness.verdict` and the step counts, `diagnostics` carries findings that a responder
should read **before acting on the evidence or on the host**:

| field | says |
|---|---|
| `encryption_risk` | **`encrypted-no-ram`** — the disk is encrypted and RAM was not captured: the volume key exists only in memory that is about to be lost. **`unknown-no-ram`** — the encryption probe could not answer *and* RAM was not captured; this is **not** a claim the disk is encrypted, it is a refusal to assume it is not. **`ok`** — either nothing encrypted, or RAM was captured so the key is in the bundle. Anything but `ok` means **do not power the host off** until a recovery key is in hand. |
| `cim_evidence` | whether CIM/WMI actually produced this evidence. `cim-unavailable` with `fallback_steps` listed means those artifacts came from **native sources**, not WMI — the content is equivalent, the provenance is not, and a host whose WMI was dead during collection is itself a finding. |
| `subsystem_probe` | three-state census behind `subsystem_failure`: `not-answering` / `answered` / `insufficient-evidence`. The last one means the bundle says nothing either way — it is not a clean bill of health. |
| `by_error_class` | which failure classes were assigned, with a sample. Empty on a healthy run. Note that several conditions are handled *before* a class could be assigned (a refused destination, a transparent in-process fallback), so an empty map does not mean nothing went wrong — read `ship`, `exec_mode` and the verdict too. |
| `ship` | `preflight_ok`, `preflight_reason`, and whether the transfer succeeded. A failed ship leaves the **collection intact locally** and exits ≥ 10; `<bundle>.ship.json` beside the archive is the machine-readable record, written outside the sealed container so the manifest stays valid. |

`SUMMARY.md` carries the same findings in prose, and `99_logs/DIAGNOSTIC-REPORT.md` explains what
failed, what self-heal attempted, and how to reproduce it.


---

### Verifying a bundle you received

Do this **before** you analyse anything. A manifest nobody checks is a claim, not evidence.

```
python tools/verify-bundle.py /path/to/CASE001_HOST_20260730_051500Z
```

It needs only Python 3 — no dependencies, and deliberately **not** the collector's own hashing
code. A verifier built from the code that produced the digests can only show that code is
self-consistent, which is not the question you are asking.

Exit `0` verified · `1` verification FAILED · `2` could not verify (say so; do not record a pass).

| Result | What it means | What to do |
|---|---|---|
| `MISMATCH` | a listed file's content changed since sealing | Stop. Note it in the custody record before anything else. |
| `MISSING` | the manifest lists a file that is not present | Usually an incomplete transfer — re-copy from source and re-verify. |
| `UNLISTED` | a file is present that the manifest does not list **and** the bundle does not declare as excluded | The one a hash check alone never catches: every listed file still matches while something was *added*. |
| `custody trail` | `99_logs/audit.frozen.log` and `99_logs/run_state.frozen.jsonl`, hashed separately | These are the record of what the collector did. Treat a mismatch here as seriously as one in the evidence. |

Legitimately-unlisted files (the live `audit.log`, the manifest itself, and a few others) are read
from the bundle's own `99_logs/MANIFEST-README.txt` — the tool never carries its own copy of that
list, so the two cannot drift apart. If that note is missing or unreadable the tool exits `2`
rather than guessing, because an unlisted file whose status cannot be established is exactly what
tampering looks like.

**The limit, stated plainly.** The manifest cannot cover itself — nothing can hash itself — so
anyone able to alter a file can recompute the manifest to match. This detects damage, truncation,
partial transfer and casual tampering. It does **not** prove authenticity. For that you need a
signature over the manifest, or its digest recorded out-of-band at collection time and carried
separately from the bundle. Record that digest when you take custody; it costs one line and it is
the only thing that closes this gap.

---

## What makes it bulletproof (anti-halt hardening)

Built in from the DFIR failure-mode catalog:

- **Per-step watchdog** kills any hung command (Windows `Start-Job`+`Wait-Job`; Linux `timeout -k`
  with a manual `sleep&kill` fallback when `timeout` is absent). **stdin closed** so nothing blocks
  on a prompt; Sysinternals get `-accepteula`.
- **Numeric / no-resolve flags** everywhere (`netstat -ano`, `ss -n`, `lsof -bnP`) so a hostile/dead
  DNS can't hang collection.
- **Bounded traversal**: `find -xdev` + prune of `/proc /sys /dev /run` and network mounts; reparse
  points skipped on Windows — no symlink-loop or stale-NFS hangs.
- **Free-space preflight** before RAM/disk imaging (needs ≈ RAM×1.1); refuses rather than filling the
  drive. **FAT32 4 GB** and **write-only/read-only** destination checks up front.
- **32-bit→64-bit relaunch** on Windows via `Sysnative` (a 32-bit host silently sees the wrong
  `System32`/registry). Language-Mode / ExecutionPolicy recorded; `-Bypass` at launch.
- **Feature-detect + graceful fallback**: CIM→WMI, `ss`→`netstat`→raw `/proc/net`, `journalctl`→
  `/var/log`, AD module→ADSI, locked file → `reg save`/`robocopy /B` backup mode.
- **Deterministic output**: UTF-8, `InvariantCulture`/`LC_ALL=C`, progress spinners silenced.
- **Retry classification**: read-only enumeration retries; RAM/disk imaging is **run-once** (no
  overwrite/loop); host-modifying steps run once.
- **Always seals**: manifest + report are written even on Ctrl-C or an unexpected fault.

---

## Limitations / operator notes

- Live triage on a compromised host is **corroboration, not ground truth** — always follow with the
  RAM image analysis and, where possible, a **dead-box** disk image (boot WinFE/CAINE/Tsurugi).
- Full RAM capture needs a carried imager (kernel driver on Windows may be blocked by Secure Boot/
  HVCI; AVML on Linux avoids kernel-module pain). Without one, the script records what it can and
  flags `RAM_NOT_CAPTURED`.
- For a Linux memory image to be usable in **Volatility 3**, the kernel symbol material is captured
  alongside it (`kallsyms`, `System.map`, version) — build the ISF later with `dwarf2json`.
- EDR/AV may quarantine responder tools — allow-list the kit's hashes with the SOC beforehand.
- Record the **host-clock offset** vs a trusted source (the script captures host local+UTC time; you
  supply the trusted delta) so the timeline is defensible.
