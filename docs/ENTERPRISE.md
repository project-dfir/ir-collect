# Enterprise Deployment

IR-Collect is a **single-host forward-triage** instrument. It is best-in-class for the boxes a
responder can physically reach — offline/air-gapped, unmanaged, EDR-less, OT/ICS, or the one
high-value host you grab RAM from before anyone else arrives. Everything below is about running it
*well* in a managed enterprise, and being honest about where you must bridge to a fleet platform.

## Hard truths (read first)

1. **`-ExecutionPolicy Bypass` is a lie on a managed host.** A GPO-pushed machine ExecutionPolicy
   (AllSigned) outranks the command-line flag — an unsigned `.ps1` is refused before line 1. **You
   must Authenticode-sign the scripts** (and allowlist the carried tools).
2. **Per-host USB does not scale past a handful of hosts.** For "collect from the 200 endpoints that
   beaconed to this C2," that's a **hunt**, not a collection — use a fleet platform.
3. **Your kit is an attack toolkit to the EDR** (WinPmem loads a driver; SharpHound is textbook
   recon). Coexistence is an **allowlisting + deconfliction process with the SOC**, never "disable the EDR."
4. **The real enterprise future of this logic is a Velociraptor artifact set** (you already carry
   Velociraptor). Same doctrine, delivered by the managed server. The USB is the offline/unmanaged fallback.

## Will it even run? (locked-down Windows)

| Control | Effect | What to do |
|---|---|---|
| **GPO ExecutionPolicy = AllSigned** | Unsigned `.ps1` refused; `-Bypass` ignored | **Authenticode-sign** the scripts (internal PKI or trusted CA), `-TimestampServer` so it survives cert expiry |
| **WDAC / AppLocker (enforce)** | Blocks unsigned scripts + binaries; forces Constrained Language Mode | Sign scripts; **catalog-sign `tools/`** (`New-FileCatalog` → sign the `.cat`) and allowlist by publisher/hash |
| **Constrained Language Mode (CLM)** | `.NET` static calls, `Add-Type`, `New-Object` (non-allowed types) blocked; cmdlets + native exes survive | The collector **detects `LanguageMode`** and uses CLM-safe paths (Compress-Archive instead of `[ZipFile]`, `Out-File` fallback for the BOM writer). ~70% of enumeration survives; sealing degrades gracefully |
| **AMSI** | Scans script text + dynamic scriptblocks; a hit blocks the buffer | Keep scripts clean/unobfuscated; get the hash allowlisted; prefer native exes |
| **HVCI / Secure Boot** | WinPmem kernel driver won't load | Already flagged `RAM_NOT_CAPTURED`; **pivot to hypervisor/cloud snapshot** (see GAPS.md) |
| **Script-block logging (4104)** | Every command lands in the SIEM | Not a blocker — a **deconfliction** item (tell the SOC it's you) |

**Verdict for WDAC-enforced / Tier-0 hosts:** don't try to whitelist a per-incident USB script — run
collection through a tool the org has **already** signed and allowlisted: **EDR live-response** or a
**Velociraptor agent deployed as an approved service**.

## Deploying at scale

| Mechanism | Fit | Notes |
|---|---|---|
| **Velociraptor hunt** (best) | ★★★ | You carry it. Re-express the collection as **VQL artifacts** → same doctrine, server fan-out, central store, throttling, RBAC — all free |
| **EDR live-response / RTR** | ★★★ | Already privileged + allowlisted. Use `-Auto -RapidOnly` (bounded runtime); heavy jobs don't fit RTR's exec model |
| **WinRM / `Invoke-Command`** | ★★ | **Non-interactive only**; honor `MaxMemoryPerShellMB` (stream to disk, never hold RAM/image blobs in the pipeline); solve the **double-hop** (ship back through the session, or Kerberos RBCD — avoid CredSSP) |
| **SCCM/MECM, Intune** | ★★ | Silent, SYSTEM context, **meaningful exit codes**, finish in the time budget; output to a reachable collector |
| **Ansible / SSH (Linux)** | ★★ | `--auto`, exit codes, `fetch` to controller; the `.sh` is close to ready |
| **GPO startup / PsExec `-s`** | ★ | Blunt/noisy; fine for a handful |

**The collector already supports unattended runs:** `-Auto`/`--auto` skips the guided intake **and**
the menu (runs all jobs); the menu also falls back to run-all when there's no TTY, so a remote push
can't hang on a prompt. **Exit-code contract:** `0` clean · `10` completed-with-skips · `20` RAM not
verified · `40` fatal — key SCCM/Intune/Ansible off these.

## SOC deconfliction (do this BEFORE a fleet run)

Notify the SOC with the **batch ID, host list, tool hashes/certs, operator, window, and expected
alerts** ("you will see WinPmem driver loads + SharpHound LDAP from these 40 hosts 0200–0400 UTC —
that's us"). Create **temporary EDR allow/suppress rules keyed to the tool hash+path, expiring with
the window.** Never disable the EDR — it blinds you during an active intrusion and is itself a
detection. Expect quarantine anyway; the collector skips-and-logs and continues.

## Least privilege & tiered admin

- Prefer **SYSTEM** (PsExec `-s`/Intune/scheduled task) for *local* collection — no domain creds on a
  suspect box. Minimum privileges per stage: **SeBackupPrivilege/SeRestorePrivilege** (locked
  hives/`$MFT`/evtx via `robocopy /B`), **SeDebugPrivilege** (process memory/handles),
  **SeSecurityPrivilege** (Security log). Build a constrained IR account with just these — not Domain Admin.
- **Cardinal rule: never authenticate a Tier-0 (DA/EA) credential onto a Tier-2 workstation.** The
  collector **warns loudly** if it detects a Domain/Enterprise-Admin token on a workstation-class host.
- Drive fleet collection from a **PAW**; run the AD-touching parts (SharpHound) **from the analysis
  box against the DC** (bloodhound-python/netexec), not as noisy on-host SharpHound on a hot box.

## Network realities

- **Air-gapped/segmented:** `fetch-tools.*` can't reach GitHub inside a segment. Run it **once in a
  connected staging enclave**, produce a versioned, hashed (`PROVENANCE-*.txt`), signed kit bundle,
  and move that frozen bundle across the gap on approved media. Point `fetch-tools` at an **internal
  mirror** (Artifactory/Nexus) where possible.
- **Bandwidth:** a 64 GB RAM/disk image across a WAN will saturate a branch circuit. **Default to
  local-stage + triage-ship** (the kit already stages locally); ship only the KB–MB triage bundle
  across the WAN, and move big images physically or off-hours. Ship to a collector **inside the
  segment**, then cross the boundary via the approved path.
- **Egress/proxy:** the network-ship (SMB/rsync/scp) may be blocked or need proxy auth — prefer an
  in-segment evidence node.

## Scale & safety

- **Never blind-full-image RAM on a hot Tier-0 DB server** — I/O contention/latency, driver risk on
  HVCI. Prefer a **hypervisor snapshot-with-memory (`.vmem`)** (zero guest footprint).
- **Canary ring:** run on 1–5 representative hosts, verify, then expand.
- **Throttle/stagger** fan-out (Velociraptor/EDR do this natively; rate-limit WinRM/Ansible batches),
  and set a **per-host wall-clock cap** so one hung host can't hold the batch.
- Heavy Linux jobs run under **`ionice -c3 nice -n 19`**; Windows heavy jobs should run
  below-normal priority.
- **Test in a lab that mirrors prod hardening** (WDAC policy, EDR, GPO ExecutionPolicy) — the #1
  reason IR tooling fails in prod is it was only tested on an unhardened box.

## Central case management

- **Mandate `-CaseId` in fleet mode** (the default collides across many hosts). Capture
  `CaseId / BatchId / HostId / AcquisitionGUID` + **collection method** (USB/WinRM/Velociraptor/EDR).
- **Trusted time:** record host-local + host-UTC **plus a delta against a trusted source** (`w32tm
  /query /status`, `chronyc tracking`) so the cross-host timeline is defensible.
- **Roll-up:** each host writes `MANIFEST-SHA256` + `collection_info.json`; concatenate them into one
  **case-level index** on the evidence server, and append each sealed-zip SHA-256 to an
  **append-only/WORM case ledger** (S3 Object-Lock/MinIO). Inherit `-Authorizer/-LegalBasis/-ScopeNote`
  from the batch so every host carries identical authorization metadata.

## The bridge: Velociraptor artifacts

The single move that makes this enterprise-real is re-expressing the collection logic as **Velociraptor
VQL artifacts**, so the *same* RFC-3227 doctrine runs either as one-box-USB **or** server fan-out —
with central storage, throttling, RBAC, and allowlisting handled by the platform you already deploy.
That's the roadmap; the USB remains the offline/unmanaged-host fallback.
