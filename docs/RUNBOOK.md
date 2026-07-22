# IR-Collect Field Runbook — do this BEFORE you touch the keyboard

Collection starts the moment you run the tool. Five minutes of these decisions first is the difference
between evidence that holds up and a collection that's quietly worthless. (NIST SP 800-61r2 / 800-86,
ISO/IEC 27037.)

## 0. Vantage decision — is running-on-the-box even right?
- [ ] **Is it a VM / cloud instance?** → prefer a **snapshot** (VMware `.vmem`/`.vmdk`; `aws ec2 create-snapshot`; `az snapshot create`) attached to a clean forensic instance. Zero guest footprint. Run this tool only if you can't snapshot.
- [ ] **Is C2 / attacker traffic live now?** → capture **network off-host first** (PCAP at a TAP/SPAN, firewall/proxy/DNS logs). Running code can tip the attacker.
- [ ] **More than ~3 hosts in scope?** → promote to a **Velociraptor hunt** (in `tools/`), don't go USB-per-box.
- [ ] **Physical / remote / locked?** → **iDRAC/iLO virtual media** to boot a forensic ISO.

## 1. Authorization & scope (record it)
- [ ] Confirm you are **authorized** to collect from this system. Note **who authorized it** and the **legal basis**.
- [ ] Confirm the **scope** (this host only? disk? user data? privacy/GDPR/monitoring-law constraints?).
- [ ] Pass it to the tool: `-Authorizer "<name/role>" -LegalBasis "<engagement/warrant/consent>" -ScopeNote "<scope>"` (Windows) — it's written into the custody record.

## 2. Document the scene (before touching anything)
- [ ] **Photograph the screen** (open windows, logged-in user, ransom note) and the physical setup (cables, drive serials, asset tag).
- [ ] Note **running state**: powered on? logged in as whom? on the network?
- [ ] Record the **host clock vs a trusted time source** (offset) — the tool captures host time; you supply the trusted delta.

## 3. Encryption check (case-ending if skipped)
- [ ] Is the disk **BitLocker / LUKS / FileVault / VeraCrypt** encrypted? (The tool detects and warns.)
- [ ] If yes: the tool captures status + recovery keys to `00_metadata`. **Confirm a key or a verified RAM image is in hand.**
- [ ] **DO NOT power off an encrypted host** until you have a recovery key OR a verified RAM image (the key lives in RAM). The gate goes **AMBER** if this isn't satisfied.

## 4. Isolate vs. collect (a decision, not a default)
- [ ] **Don't yank the network cable** — it destroys live C2 evidence and can trigger malware dead-man switches (wipers/ransomware keyed to isolation).
- [ ] Prefer **session-preserving isolation**: EDR network-contain, or a switch-port ACL.
- [ ] Record who made the call and when.

## 5. Destination & kit readiness
- [ ] Collection drive is **NTFS or exFAT** (not FAT32 — RAM image > 4 GB truncates), and **≥ RAM×1.1 + triage + margin** free.
- [ ] Destination pre-wiped/verified; credentials for any network share / AD ready.
- [ ] Tools staged in `tools/` (run `fetch-tools.*` on a trusted box beforehand). **Test-fire the whole kit on a known-good VM before the incident** — confirm RAM opens in Volatility 3, artifacts are non-empty, nothing is EDR-quarantined. (The #1 field regret is discovering WinPmem is HVCI-blocked at 2 a.m.)

## 6. Run
```
# guided (recommended): answers a few questions, drives volatile -> non-volatile
powershell -ExecutionPolicy Bypass -File .\IR-Collect.ps1 -Dest E:\evidence -CaseId CASE001 -Authorizer "J.Doe, IR Lead" -LegalBasis "IR engagement" -ScopeNote "host only"
sudo ./ir-collect.sh -d /mnt/evidence -c CASE001
```

## 7. Before you leave
- [ ] Gate is **GREEN** (verified RAM + volatile secured) — not AMBER.
- [ ] `MANIFEST-SHA256` written; `SUMMARY.md` reviewed; `errors.log` checked for silent gaps.
- [ ] For non-volatile **ground truth**: follow with a **dead-box disk image** (write-blocker, or boot WinFE/CAINE/Tsurugi). On a compromised host, RAM + dead-box are ground truth; live enumeration corroborates.
- [ ] Escalate (stop and call for help) on: nation-state indicators, active ransomware, legal hold, anything headed for litigation.

## 8. Handoff to analysis
- Memory → **Volatility 3** (Linux: build the ISF from captured `kallsyms`/`System.map` with `dwarf2json`).
- Triage → **Plaso/log2timeline** → **Timesketch**; evtx → **Chainsaw/Hayabusa** (in `tools/`); registry/execution → **EZ-Tools**.
- See `GAPS.md` for off-host vantage points (network, identity, cloud) this box-level collection can't reach.
