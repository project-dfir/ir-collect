# Failure-scenario catalogue

Conditions a live-response collector actually meets in the field, each with how to reproduce it on
a **range VM** and what correct behaviour looks like. This is the backlog the hardening loop works
through; it is not aspirational — every row is either already exercised or queued.

The bar for "correct" is the same everywhere: **either do the job, or fail loudly and honestly.**
Every defect found so far has been the same shape — a capability reporting success it never
achieved — so a scenario only passes if the run's own artifacts (`run_state.json`, `SUMMARY.md`,
`DIAGNOSTIC-REPORT.md`) tell the truth about what happened.

Status: ✅ tested & handled · ⚠️ tested, gap remains · ⬜ queued · 🔬 needs a policy/VM change

---

## A. Host lockdown (the hardened-endpoint family)

| # | Scenario | Reproduce on a range VM | Correct behaviour | Status |
|---|---|---|---|---|
| A1 | **ConstrainedLanguage** (AppLocker/WDAC) | `tests/e2e/policy/Set-TestPolicy.ps1 -Policy clm-applocker` | Refuse with exit 40 before writing anything; never redirect evidence to the target's `C:` | ✅ gate added; 🔬 still to run under a *real* AppLocker policy, not a session switch |
| A2 | **Job subsystem blocked** | `IRCOLLECT_FORCE_INPROC=1` | Transparent in-process fallback, `exec_mode` reports it | ✅ |
| A3 | **Not elevated** | run as a standard user | Degrade, log what is unobtainable, do not claim completeness | ✅ CLOSED 2026-07-28 - found + fixed a false-COMPLETE, see below |
| A4 | **`Get-FileHash` unavailable** | inherit a `PSModulePath` that loads pwsh 7's Utility into 5.1 | .NET fallback, `hash_backend` says which | ✅ |
| A5 | **AV/EDR quarantines a carried tool** | drop EICAR beside `winpmem.exe`, or let Defender flag it | Tool marked missing, run continues, `tool_missing` classified — never a silent skip | ⬜ (winpmem is *routinely* flagged in the field) |
| A6 | **Execution policy / unsigned script blocked** | `Set-ExecutionPolicy AllSigned` (machine) | Clear failure at launch, not a half-run | ⬜ |

## B. Destination

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| B1 | **Read-only media** | mount a loop image `-o ro` | Detect, redirect, log the redirect | ✅ |
| B2 | **Destination full** | Linux: 3 MB loop fs. Windows: 40 MB VHD filled to <96 KB free — **assert a 512 KB write is refused before judging** | Refuse up front rather than dying mid-run with no diagnosis | ✅ **BOTH VERIFIED**. Linux field-tested. Windows: 4th attempt induced the condition (76 KB free, 512 KB write refused) and found the seal-time ENOSPC fallback cannot help — a destination full from the first write kills the run before `Invoke-Seal`, so no `run_state.json` and the fallback never fires. Fixed with a 64 MB destination preflight: **verified exit 40 with the refusal message**. The case folder does remain, containing only `audit.log` with the `PREFLIGHT REFUSED` line — that is deliberate, it is the custody record that a collection was attempted and declined |
| B3 | **USB yanked mid-run** | `qm set <vmid> -delete <disk>` or unmount the loop device mid-collection | Do not hang; seal what exists somewhere writable; say the destination vanished | ⬜ **high value, untested** |
| B4 | **Network destination dies mid-ship** | drop the route / stop sshd on the collector server | Retain evidence locally, never delete the local copy on a failed ship | ⬜ |
| B5 | **UNC auth failure** | wrong credentials to an SMB share | Fail at preflight, not after an hour of collecting | ⬜ |
| B6 | **MAX_PATH exceeded** | deep nested profile paths | `path_too_long` classified (branch exists, never fired) | ⬜ |

## C. Process lifetime

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| C1 | **Killed mid-run** — EDR live-response harnesses commonly cap child tools at ~30 min | `-Auto` (Stage 2 runs 13–20 min), kill the collector's process tree at ~90s | Ledger survives; `-Resume` recovers the collection; operator is told the tree is resumable | ✅ **VALIDATED 2026-07-28 on WS02** (3rd attempt — the first two were invalid because RapidOnly finishes in <60s). Hard `Stop-Process -Force` skips `finally`, so the always-seal wrapper **cannot** run: no SUMMARY.md, no run_state.json, no manifest. But `run_state.jsonl` survived intact (113 records, 0 invalid) and `-Resume` finished it: **ok=38 skipped=32 failed=0 COMPLETE**, 139→147 files. Gap found and fixed: an interrupted tree looked abandoned, so the collector now drops `RUN-INTERRUPTED-READ-ME.txt` at start and deletes it at seal |
| C2 | **Host reboots mid-run** | `qm reset <vmid>` during an `-Auto` run — assert evidence BYTES are growing first (file count is static during a RAM capture) | Ledger stays parseable; `-Resume` finishes it; operator is told the tree is resumable | ✅ **VALIDATED 2026-07-28 on WS02.** Reset fired with 6.44 GB written and growing. Survived: `run_state.jsonl` **20 records / 0 invalid** and `audit.log` — a hard power event leaves the ledger parseable. Absent as expected: SUMMARY.md, run_state.json (seal never ran). `-Resume` completed it: **ok=34 skipped=5 failed=0 COMPLETE**, 13→49 files. **Defect found:** `RUN-INTERRUPTED-READ-ME.txt` did NOT survive — a write-once file never touched again sits in the NTFS cache, while the ledger survives precisely because continuous appends force flushes. Fixed with a WriteThrough FileStream + `Flush($true)`. **Fix VERIFIED under the original condition** (2nd reset, 2026-07-28): `RUN-INTERRUPTED-READ-ME.txt` **714 B PRESENT** after a hard `qm reset` where it was previously ABSENT; ledger 17 records / 0 invalid; `-Resume` then completed it (**ok=33 skipped=5 failed=0 COMPLETE**, 14→49 files). Root cause of the earlier launch failures: stale collector processes holding the redirect targets — fixed by killing leftovers, using unique per-run redirect filenames, and gating on the child being alive at 15s |
| C3 | **Step hangs forever** | carried tool that `sleep`s past its bound | Watchdog kills the whole process group, `timeout` classified | ✅ |
| C4 | **Console closed / no TTY** | run detached | Non-interactive fallback runs everything, no prompt deadlock | ⬜ |

## D. Data-shape surprises

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| D1 | **Enormous profile count** | GHOSTS users (WS01: 251,747 dirs under `C:\Users`) | Targeted copies, no tree walk | ✅ |
| D2 | **Junction loops** | legacy `Application Data` reparse points | No duplicate artifacts, no infinite recursion | ✅ |
| D3 | **Multi-GB Security.evtx on a DC** | the range DC | Priority channels secured before the bulk copy | ✅ |
| D4 | **Hidden/system evidence files** | copied `NTUSER.DAT` | Present in the manifest with real hashes | ✅ |
| D5 | **Encrypted volume** | BitLocker on, or LUKS | Keys captured while unlocked; AMBER if no verified RAM | ⚠️ code paths never run against a *real* encrypted volume |
| D6 | **Filenames with spaces / `%4` / Unicode** | winevt channel names | Quoted correctly | ✅ |

## E. Platform / environment

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| E1 | **WMI/CIM broken** | `sc config Winmgmt start= disabled` + stop, on a range VM | Run must not claim COMPLETE when core volatile evidence is missing | ✅ tested on WS02 — found the worst defect of the session (see below); `wmi_failure` still never fires because the steps do not error, they return nothing — emptiness detection is what catches it |
| E2 | **No `sha256sum`** (stock macOS/BSD/busybox) | `HASH_BACKEND` forced per backend | shasum/sha256/openssl/digest/python3 fallback | ✅ unit-tested across 4 backends |
| E3 | **Domain unreachable** for AD enumeration | block LDAP to the DC | Skip cleanly, mark incomplete, do not hang | ⬜ |
| E4 | **Clock skew** | shift VM clock | Recorded in `clock_provenance.txt` for timeline defensibility | ✅ captured, never validated under skew |
| E5 | **PS 2.0 / Server 2008R2** | old guest | `Get-Inv` WMI path; graceful degradation | ⬜ |

---

## Verify the condition is actually in flight before acting

Four scenario attempts in one session produced clean-looking results that tested **nothing**,
all for the same reason: a `-RapidOnly` collection on these VMs finishes in **under 60 seconds**
and writes only ~100 KB. So:

- C1 (kill mid-run) x2 — the run had already sealed when the kill landed; a "perfect" bundle with
  a full manifest is evidence of a *normal run*, not of surviving termination.
- B2 (ENOSPC) x2 — 5 MB of free space is ample for a 100 KB bundle, so the disk never filled.

**Rule: assert the condition is live before triggering it.** Confirm the process is still running,
the image is still growing, or the disk is genuinely full — and if the assertion fails, mark the
attempt INVALID rather than recording a pass. Use `-Auto` (Stage 2 runs 13–20 min) when a scenario
needs the collector to still be working, and squeeze free space below ~256 KB when it needs the
destination to fail.

## Testing hygiene — do not run this on your own workstation

`-RapidOnly` still captures RAM (memory is the most volatile artifact, so it is Stage 1). With a
memory imager staged in `collectors/tools`, **every** local test run writes a full memory image of the
machine you are sitting at. Six such runs during one session consumed 187 GB and left six complete
RAM images — containing that host's credentials, keys and session data — sitting in a temp folder.

So: run scenarios on a **range VM**. When a quick logic check on the workstation is genuinely the
fastest path, copy only the script to a scratch directory so no `tools/` payload is discovered
(no imager found → the fast `mem-fallback` path, a few KB instead of 32 GB), and delete the output
afterwards:

```powershell
mkdir $env:TEMP\irtest; copy kit\IR-Collect.ps1 $env:TEMP\irtest\   # no tools\ alongside it
& $env:TEMP\irtest\IR-Collect.ps1 -RapidOnly -Scenario A -CaseId LOCAL -Dest $env:TEMP\irtest\out
Remove-Item $env:TEMP\irtest -Recurse -Force
```

## How to run one

```powershell
# 1. baseline the VM (mandatory - there is no hypervisor snapshot on this range)
.\tests\e2e\policy\Export-PolicyBaseline.ps1

# 2. induce the condition (see the table)

# 3. collect
powershell -File C:\ir\IR-Collect.ps1 -RapidOnly -Scenario A -CaseId SCN_<id> -Dest C:\evidence

# 4. judge it by the artifacts, not by whether it "seemed to work"
#    99_logs\DIAGNOSTIC-REPORT.md   <- what failed, what self-heal did, how to reproduce
#    99_logs\run_state.json         <- verdict, diagnostics{exec_mode, language_mode, hash_backend}
#    SUMMARY.md                     <- completeness + handling banner

# 5. revert and CONFIRM the revert
.\tests\e2e\policy\Restore-PolicyBaseline.ps1
```

A scenario is only "handled" when the artifacts state the truth. A run that quietly produced less
evidence than it claimed is a **failure**, even if it exited 0.

## A3 - not elevated (CLOSED 2026-07-28)

**Setup.** Local standard user `iruser` on range-WS02 (10.20.50.239), explicitly removed from
Administrators and asserted at 0 members. Run via `schtasks /RL LIMITED`, which yields a genuine
non-elevated token; `Start-Process -Credential` was abandoned because the child cannot open
redirect files it does not own, so it died in <20 s with empty logs and proved nothing.
Validity gate: the bundle's own `elevated` field must read `False`, otherwise the attempt is
discarded rather than scored.

Two environment defects surfaced first and were fixed before the scenario could run at all:
`winmgmt` was left **disabled** by an earlier WMI-broken scenario, and the GPO baseline denies
`SeBatchLogonRight`, so the task registered but never executed.

**What the collector did (the defect).** It sealed the bundle **COMPLETE**, `ok=33 fail=0
skip=0 timeout=0`, `empty_outputs=0`, exit 0 - byte-for-byte the shape of a healthy elevated
run. Diffed against an elevated bundle from the same host:

| artifact | elevated | unelevated |
|---|---|---|
| `01_volatile/drivers.txt` | 115 096 B | **155 B** ("Access is denied") |
| `02_network/netstat_anob.txt` | 8 140 B | **45 B** |
| `01_volatile/sessions.txt` | 597 B | **10 B** |
| `03_memory/memory.raw` | 6.3 GB | absent |

Every stub cleared the `-le 2` emptiness threshold, so nothing was recorded. An analyst would
read "no unusual drivers" off a driver list that was never permitted to load - the failure mode
this whole test suite exists to prevent.

**Fixes.**
1. `Test-DegradedOutput` / `test_degraded_output` - output dominated by an access refusal is
   tracked separately from empty output, via a size gate and a density gate (both mutation-
   tested; a large healthy artifact that merely mentions "Access is denied" must not trip).
2. An unelevated run can no longer be COMPLETE. RAM, hives, the Security log and per-connection
   ownership all require a privileged token, so absence of a finding is not evidence of absence.
   SUMMARY.md gains an explicit "READ BEFORE DRAWING CONCLUSIONS" block listing what was
   unobtainable.
3. Real `not_elevated` recovery rungs, not markers: `netstat -anob` -> `-ano` +
   `Get-NetTCPConnection` (keeps every endpoint and owning PID, loses only the EXE-name column);
   `Win32_SystemDriver` -> `sc.exe query` -> `driverquery /v` -> on-disk inventory;
   `net session` -> `Win32_LogonSession` + shell owners.

**Result after the fix.** verdict `INCOMPLETE`, exit 15, unelevated block present, and the
ladder recovered real data: `drivers.txt` 155 B -> **29 870 B**, with `netstat_anob.txt` and
`sessions.txt` both leaving the loss list entirely.

**Linux parity.** Non-root run on rick-pve: exit 15, `INCOMPLETE`,
`unprivileged(privileged-artifacts-unobtainable-without-root)`. Linux already fails these steps
loudly rather than writing stubs, so its four refusals were classified as failures.

**A trap this created.** The fallback banner first read `### netstat -anob requires elevation
###` - the collector's own prose matched the denial pattern, so on a quiet host a small but
perfectly healthy artifact would incriminate itself. `Test-DegradedOutput.ps1` now extracts
every `###` banner from the shipped script and asserts none match the pattern.
