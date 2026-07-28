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
| A3 | **Not elevated** | run as a standard user | Degrade, log what is unobtainable, do not claim completeness | ⬜ Linux done (29/29, graceful); Windows untested |
| A4 | **`Get-FileHash` unavailable** | inherit a `PSModulePath` that loads pwsh 7's Utility into 5.1 | .NET fallback, `hash_backend` says which | ✅ |
| A5 | **AV/EDR quarantines a carried tool** | drop EICAR beside `winpmem.exe`, or let Defender flag it | Tool marked missing, run continues, `tool_missing` classified — never a silent skip | ⬜ (winpmem is *routinely* flagged in the field) |
| A6 | **Execution policy / unsigned script blocked** | `Set-ExecutionPolicy AllSigned` (machine) | Clear failure at launch, not a half-run | ⬜ |

## B. Destination

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| B1 | **Read-only media** | mount a loop image `-o ro` | Detect, redirect, log the redirect | ✅ |
| B2 | **Destination full** | 3 MB loop filesystem | Classify `no_space` structurally, honest `retry-in-place-DISK-FULL`, rollup survives off-medium, ledger stays valid JSONL, verdict `destination-full` | ✅ Linux; ⚠️ Windows logic unit-tested but never field-run (needs an admin-created small volume) |
| B3 | **USB yanked mid-run** | `qm set <vmid> -delete <disk>` or unmount the loop device mid-collection | Do not hang; seal what exists somewhere writable; say the destination vanished | ⬜ **high value, untested** |
| B4 | **Network destination dies mid-ship** | drop the route / stop sshd on the collector server | Retain evidence locally, never delete the local copy on a failed ship | ⬜ |
| B5 | **UNC auth failure** | wrong credentials to an SMB share | Fail at preflight, not after an hour of collecting | ⬜ |
| B6 | **MAX_PATH exceeded** | deep nested profile paths | `path_too_long` classified (branch exists, never fired) | ⬜ |

## C. Process lifetime

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| C1 | **Killed mid-run** — EDR live-response harnesses commonly cap child tools at ~30 min | `Stop-Process -Force` / `kill -9` **during Stage 2** — must be a job that actually runs long enough | Always-seal wrapper produces a usable partial bundle; `-Resume` picks up the rest | ⬜ **attempted 2026-07-28, TEST INVALID** — RapidOnly with no imager staged completes in <25s, so the kill landed after the run had already sealed. Re-run against `-Auto` (or with an imager staged) and kill during a heavy Stage-2 job. NOTE: a hard `Stop-Process -Force` does not run PowerShell `finally`, so the seal wrapper is expected NOT to fire — the real question is whether the append-only ledger lets `-Resume` recover |
| C2 | **Host reboots mid-run** | `qm reset <vmid>` | Partial bundle is still parseable; resume works | ⬜ |
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

## Testing hygiene — do not run this on your own workstation

`-RapidOnly` still captures RAM (memory is the most volatile artifact, so it is Stage 1). With a
memory imager staged in `kit/tools`, **every** local test run writes a full memory image of the
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
