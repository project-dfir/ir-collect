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
| A5 | **AV/EDR quarantines a carried tool** | drop EICAR beside `winpmem.exe`, or let Defender flag it | Tool marked missing, run continues, `tool_missing` classified — never a silent skip | ✅ CLOSED 2026-07-28 - found + fixed a false-COMPLETE, see below |
| A6 | **Execution policy / unsigned script blocked** | `Set-ExecutionPolicy AllSigned` (machine) | Clear failure at launch, not a half-run | ✅ CLOSED 2026-07-29 - see below (enforced by the host, not by collector code) |

## B. Destination

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| B1 | **Read-only media** | mount a loop image `-o ro` | Detect, redirect, log the redirect | ✅ |
| B2 | **Destination full** | Linux: 3 MB loop fs. Windows: 40 MB VHD filled to <96 KB free — **assert a 512 KB write is refused before judging** | Refuse up front rather than dying mid-run with no diagnosis | ✅ **BOTH VERIFIED**. Linux field-tested. Windows: 4th attempt induced the condition (76 KB free, 512 KB write refused) and found the seal-time ENOSPC fallback cannot help — a destination full from the first write kills the run before `Invoke-Seal`, so no `run_state.json` and the fallback never fires. Fixed with a 64 MB destination preflight: **verified exit 40 with the refusal message**. The case folder does remain, containing only `audit.log` with the `PREFLIGHT REFUSED` line — that is deliberate, it is the custody record that a collection was attempted and declined |
| B3 | **USB yanked mid-run** | `qm set <vmid> -delete <disk>` or unmount the loop device mid-collection | Do not hang; say the destination vanished; never claim a bundle that is not there | ✅ CLOSED 2026-07-28 (Linux) + 2026-07-29 (Windows) - see below; salvage of a part-written tree DECLINED with reasoning (see below) |
| B4 | **Network destination dies mid-ship** | drop the route / stop sshd on the collector server | Retain evidence locally, never delete the local copy on a failed ship | ✅ CLOSED 2026-07-28 - see below |
| B5 | **UNC auth failure** | wrong credentials to an SMB share | Warn at preflight, keep collecting (evidence is staged locally), never report a clean run when the evidence never arrived | ✅ CLOSED 2026-07-28 - see below |
| B6 | **MAX_PATH exceeded** | long `-Dest`, or deep nested profile paths | Refuse up front with an actionable message; never report success for a tree that was never written | ✅ CLOSED 2026-07-28 - found the worst false-success yet, see below |

## C. Process lifetime

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| C1 | **Killed mid-run** — EDR live-response harnesses commonly cap child tools at ~30 min | `-Auto` (Stage 2 runs 13–20 min), kill the collector's process tree at ~90s | Ledger survives; `-Resume` recovers the collection; operator is told the tree is resumable | ✅ **VALIDATED 2026-07-28 on WS02** (3rd attempt — the first two were invalid because RapidOnly finishes in <60s). Hard `Stop-Process -Force` skips `finally`, so the always-seal wrapper **cannot** run: no SUMMARY.md, no run_state.json, no manifest. But `run_state.jsonl` survived intact (113 records, 0 invalid) and `-Resume` finished it: **ok=38 skipped=32 failed=0 COMPLETE**, 139→147 files. Gap found and fixed: an interrupted tree looked abandoned, so the collector now drops `RUN-INTERRUPTED-READ-ME.txt` at start and deletes it at seal |
| C2 | **Host reboots mid-run** | `qm reset <vmid>` during an `-Auto` run — assert evidence BYTES are growing first (file count is static during a RAM capture) | Ledger stays parseable; `-Resume` finishes it; operator is told the tree is resumable | ✅ **VALIDATED 2026-07-28 on WS02.** Reset fired with 6.44 GB written and growing. Survived: `run_state.jsonl` **20 records / 0 invalid** and `audit.log` — a hard power event leaves the ledger parseable. Absent as expected: SUMMARY.md, run_state.json (seal never ran). `-Resume` completed it: **ok=34 skipped=5 failed=0 COMPLETE**, 13→49 files. **Defect found:** `RUN-INTERRUPTED-READ-ME.txt` did NOT survive — a write-once file never touched again sits in the NTFS cache, while the ledger survives precisely because continuous appends force flushes. Fixed with a WriteThrough FileStream + `Flush($true)`. **Fix VERIFIED under the original condition** (2nd reset, 2026-07-28): `RUN-INTERRUPTED-READ-ME.txt` **714 B PRESENT** after a hard `qm reset` where it was previously ABSENT; ledger 17 records / 0 invalid; `-Resume` then completed it (**ok=33 skipped=5 failed=0 COMPLETE**, 14→49 files). Root cause of the earlier launch failures: stale collector processes holding the redirect targets — fixed by killing leftovers, using unique per-run redirect filenames, and gating on the child being alive at 15s |
| C3 | **Step hangs forever** | carried tool that `sleep`s past its bound | Watchdog kills the whole process group, `timeout` classified | ✅ |
| C4 | **Console closed / no TTY** | run detached as SYSTEM with stdin bound to NUL | Non-interactive fallback runs everything, no prompt deadlock | ✅ CLOSED 2026-07-29 - see below |

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
| E1 | **WMI/CIM broken** | `sc config Winmgmt start= disabled` + stop, on a range VM | Run must not claim COMPLETE when core volatile evidence is missing | ⚠️ tested on WS02 — found the worst defect of the session (see below). The scenario's requirement IS met: emptiness detection stops the run claiming COMPLETE. But `wmi_failure` is unreachable - the steps return nothing rather than erroring, and the classifier only matches error TEXT - so a genuinely broken WMI never reaches the operator with its `restart-wmi`/`native-source` fix ladder. Marked ⚠️ per this page's own legend: tested, gap remains |
| E2 | **No `sha256sum`** (stock macOS/BSD/busybox) | `HASH_BACKEND` forced per backend | shasum/sha256/openssl/digest/python3 fallback | ✅ unit-tested across 4 backends |
| E3 | **Domain unreachable** for AD enumeration | block LDAP/SMB/Kerberos/NTP to the DC | Skip cleanly, mark incomplete, do not hang | ✅ CLOSED 2026-07-29 - defect found AND fixed; both controls pass (see below) |
| E4 | **Clock skew** | shift VM clock | Recorded in `clock_provenance.txt` for timeline defensibility | ✅ CLOSED 2026-07-29 - validated under a live skew; the artifact now MEASURES the offset instead of asking the analyst to; Linux second pass 2026-07-29 found 3 more defects (empty Reference ID, a fabricated "no reachable peer" cause, and NTPSynchronized=no reported as a working source) - all fixed, both controls live |
| E5 | **PowerShell 2.0** | `powershell -Version 2` | Refuse; v2 lacks the language features | ✅ CLOSED 2026-07-29 - `#requires -Version 3` added and live-verified; original repro INVALID on this host (see below) |

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
mkdir $env:TEMP\irtest; copy collectors\IR-Collect.ps1 $env:TEMP\irtest\   # no tools\ alongside it
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

## A5 - AV quarantines a carried tool (CLOSED 2026-07-28)

**Setup.** Real-time protection is **off** on this range by design (it would eat the GHOSTS and
Caldera agents that generate the traffic), so the quarantine was driven by an on-demand
`Start-MpScan` scoped to `C:\ir\tools` — a genuine Defender quarantine with no global RTP toggle
and no risk to the range. EICAR is assembled from fragments at runtime; a literal in the script
would get the *script* quarantined in transit, which tests nothing.

Validity gate: the bait must be removed **while the collector is still running**. The run is
logged INVALID if the collector exits first — the point is a tool disappearing mid-collection,
not a tool that was already absent.

**What the collector did (the defect).** With a tool quarantined out from under it, the run
sealed **COMPLETE, exit 0**, `failed=0`, no error class, no diagnostic. Three separate problems:

1. `carried_tools_sha256.txt` — the record of *which binaries touched the evidence*, a
   chain-of-custody artifact — was written **0 bytes**. "No tools were carried" was
   indistinguishable from "the inventory failed to run".
2. The audit log asserted `DOCTRINE: carried tools present in .\tools` whenever the **directory**
   existed. It said this on a host whose toolkit was empty — a false statement in a custody log.
3. Nothing ever re-checked. The inventory was a snapshot at startup, so a tool vanishing later
   was invisible. Only a buried RAM line hinted at it.

**Fix.** The toolkit is hashed at start (path → SHA-256) and re-verified at seal by
`Compare-ToolInventory`. Anything vanished or hash-changed is classified `tool_missing`, written
to `carried_tools_verify.txt`, named in the verdict, and stated plainly in the audit log:
*"Most likely AV quarantine; on a compromised host, consider tampering. Any output from these
tools is suspect."* A tool that is present but **unreadable** counts as changed, never as fine —
an AV that locks rather than deletes leaves the path in place, and calling an unverifiable tool
verified is the exact false assurance being guarded against. The inventory file now states
`NONE` explicitly rather than being empty.

**Result.** Bait quarantined at t+15s with the collector still running → verdict `INCOMPLETE`,
exit 15, `toolkit-tampered(winpmem_x64.exe)`, `tool_missing` classified with a readable sample.
The benign tool staged alongside it was **not** implicated. An intact toolkit still seals
`COMPLETE`, exit 0, `TOOLKIT VERIFIED` — the check does not cry wolf.

**Range note.** WS02's real `winpmem.exe` was present through 16:15Z and gone by 18:06Z, with
**no** Defender quarantine event for it (the log shows only the EICAR baits and Caldera's
`splunkd.exe`). The cause was not established — and `Remove-MpThreat` was run during cleanup,
destroying the quarantine history that might have shown it. The imager has been restored from
the rick-pve staging copy and re-verified. Lesson: do not clear AV state before reading it.

## B6 - MAX_PATH exceeded (CLOSED 2026-07-28)

**Setup.** `LongPathsEnabled=0` (the Windows default) on range-WS02, PS 5.1, and a 229-character
`-Dest`. Condition gated: a plain write at collector-like depth (287 chars) must be **refused**
before the scenario is scored, otherwise long paths are permitted here and B6 cannot be provoked.

**What the collector did (the defect).** Every directory creation failed on MAX_PATH. Not one
byte was written. `audit.log` itself was unwritable, so the run could not even record why it
failed. And it printed:

```
Collection complete. Output: C:\b6\deep_case_folder_segment_abcdef\...\B6_WS02_20260728_184400Z
```

naming a directory that did not exist. This is the most misleading thing the tool has done: the
operator walks away believing they have a bundle. Free space was fine — the preflight only ever
asked about **space**, never about whether the destination could hold the collector's own paths.

**Fixes.**
1. `Resolve-UsableOutDir` probes the destination at the depth actually used
   (`05_artifacts\userhives\<user>\NTUSER.DAT`) before anything depends on it. A shallow probe
   would sail under MAX_PATH and hand back a "healthy" destination that dies mid-run, so the
   probe depth is itself asserted in the unit test.
2. An unusable destination is **refused with exit 40** and an actionable message naming the
   limit and the actual length, instead of starting a run that cannot record its own failure.
3. The closing line is now a statement about the tree on disk, not about reaching the end of the
   script: zero files prints `COLLECTION PRODUCED NO EVIDENCE`, and a partial run says
   `Collection INCOMPLETE (n files)`.
4. Evidence writes use `-LiteralPath`, never `-Path`. `-Path` treats its argument as a **wildcard
   pattern**, so any evidence path containing `[ ] ? *` — which a username or filename
   legitimately can — silently resolves to nothing and the write is lost.

**Rejected on evidence: adopting `\?\` for the output tree.** It was implemented and measured.
The probe passes and directories get created, but every drive-qualifier operation downstream
(free-space checks, `Split-Path -Qualifier`, `DriveInfo`) returns null for such a path — free
space read `0.0 GB`, Stage 1 aborted on a null reference, the seal failed, and the run exited
**0** having produced an **empty bundle**. A destination that probes healthy and yields no
evidence is strictly worse than one that is refused. Full extended-length support means auditing
every path-derived operation in the script; until that is done, the collector refuses honestly.
`Resolve-UsableOutDir` therefore returns only `plain` or `unusable`, and the unit test asserts
`extended` is never handed back.

**Result.** 229-char dest → exit 40, refusal naming the limit and the length, nothing left
behind. Normal dest → exit 0, COMPLETE, 49 files. Three mutations of the new probe caught in
both directions.

## B5 - UNC auth failure (CLOSED 2026-07-28)

**Setup.** `-Dest \<dc>\C$` from range-WS02, where the write is genuinely denied. Establishing
that condition took three attempts, all of them harness bugs worth recording: `New-Item` on a
nonexistent share reported success (the probe trusted the absence of an exception instead of
reading the file back), and the UNC literal lost a backslash in transit **twice**, so the paths
were relative and resolved to local directories - which is why five impossible destinations,
including a host that does not exist, all "passed". The final probe builds the prefix from
`[char]92` and asserts `([uri]$p).IsUnc` before testing anything.

**What the collector did.** Network destinations are staged locally and shipped at seal - the
right design, since writing evidence across SMB during live response is slow and fragile. But
nothing validated the share up front. `PREFLIGHT destination: 45.3 GB free` refers to the *local
staging root*, not the target. So the operator ran the **entire collection** before learning the
share was denied: 175 s for RapidOnly, 20+ minutes for `-Auto`. The end-state handling was
already good - the bundle is retained locally and says so - but the run **exited 0**, so nothing
automating it could tell the evidence never arrived.

**Fixes.**
1. `Test-NetworkDestination` probes the share at startup by creating, writing, reading back and
   deleting a probe file. Bounded at 20 s in a background job, because an unreachable host takes
   ~31 s to fail and waiting longer defeats the point of probing early. Falls back to a direct
   probe if the job subsystem is blocked, rather than reporting a destination it never tested.
2. It **warns, never refuses**. The evidence is staged locally and is not at risk, so aborting
   would destroy volatile data over a credential problem. The operator is told at second 5 and
   can fix the share while the run proceeds - the seal-time ship then succeeds.
3. A failed ship sets exit **10**, not 0. The collection is intact, so this is not exit 15, but a
   run that could not deliver its output must not report clean.
4. The outcome is written to `<bundle>.zip.ship.json` **beside** the bundle, never inside it: the
   bundle is already sealed and hashed, and an evidence container that changes after its manifest
   is worthless. `run_state.json` records only what is knowable at seal time (target, whether the
   preflight passed, and why not) plus a pointer to that file.

**Result.** Warned at **0.3 s** instead of 197 s; exit **10**; `ship.json` carries
`ok=false, error="Access is denied"`; manifest still 45 rows / 0 ERR, so the seal is untouched.
A local destination still exits 0 with `attempted=false`.


## Linux ship parity (2026-07-28)

B5 gave the Windows collector three things the shell twin lacked: a preflight probe of the ship
target, a machine-readable ship result, and a non-zero exit when the evidence never arrived.
Parity across the two collectors is a standing requirement, so the shell side now has all three.

- `test_network_dest` probes over ssh: `mkdir -p`, write a byte, **read it back**, remove it.
  Bounded with `timeout 20`, because an unreachable host is slow to fail. It warns and continues
  - the bundle is staged locally and is not at risk, so aborting would destroy volatile data over
  a routing or credential problem.
- `<bundle>.tar.gz.ship.json` is written beside the bundle (never inside it - the archive is
  already hashed) with `ok`, `preflight_ok`, `preflight_reason` and the local copy's path.
- Exit signalling already worked by accident: rsync/scp run through `run_step`, so a failure
  raises `STEPS_FAIL` and the run exits 10.

**A false negative found by the positive control.** The first probe merged stderr into stdout, so
ssh's "Warning: Permanently added ... to the list of known hosts" made the readback `!= "x"` and a
destination that was **perfectly writable** was reported unwritable - while the ship then
succeeded and the bundle arrived. stderr now goes to its own file and is used only for the reason
string. Both controls are asserted every time: a working target must produce **zero** warnings and
`preflight_ok: true`; an unreachable one exactly one warning and the real reason.

## Exit-contract audit (2026-07-28)

The exit code is the machine-readable answer to "can I trust this bundle?" and the only part of
the tool most automation reads. `tests/unit/Test-ExitContract.ps1` now asserts both collectors
implement and document the *same* contract, parsed from the shipped scripts.

**Resolved a non-issue.** A failed ship not appearing in the completeness verdict looked like a
Linux/Windows divergence. It is neither, and it is not a gap: on both platforms `run_state.json`
is written and hashed into the manifest **before** the bundle ships, so the ship outcome cannot
enter the verdict without either lying or invalidating the seal. It reaches the **exit code**
instead - Windows through an explicit `ShipOk` rule, Linux through `STEPS_FAIL` because rsync/scp
run via `run_step` - and the detail goes to `<bundle>.ship.json`. Recorded so it is not
re-litigated.

**Found a real one.** The shell collector could never return **40**. It had *no refusal path at
all* - its only non-zero early exit was for an unknown argument - so it would start a collection
onto a destination too small to hold one and die partway with nothing able to record why. The
Windows twin has refused since B2. Linux now performs the same preflight (creatable, writable,
≥64 MB free) and refuses with exit 40.

Verified with both controls: a normal destination still collects (exit 15, bundle created); a
3 MB loop filesystem is refused with exit 40, names the actual free space, and leaves **zero**
files behind.

## B4 - network destination dies mid-ship (CLOSED 2026-07-28)

**Setup.** Ship to `root@127.0.0.1`, then `iptables -I OUTPUT -o lo -p tcp --dport 22 -j DROP`
once the preflight has passed. Dropping loopback SSH only - the controlling session runs over the
ethernet interface and is untouched - and the rule is removed by an `EXIT` trap that loops until
`iptables -C` reports it gone.

**The distinguishing signature.** B5 (destination bad from the start) and B4 (destination dies
after validation) must not look alike in the record. B5 leaves `preflight_ok: false, ok: false`;
B4 leaves **`preflight_ok: true, ok: false`** - the destination was verified, then died. That
pair is the assertion.

**Three attempts were refused before one counted**, and the refusals are the point:
1. The run finished in 7 s before the route could be dropped - and the harness *scored it anyway*
   because a fallback read the audit log without checking the process was still alive. A
   **successful** ship was nearly recorded as B4. Gate fixed to require preflight-passed **and**
   the collector still running.
2. Grepping the console for the preflight verdict found nothing - it goes to the audit log.
3. Polling the audit log found nothing either, which exposed a **real bug in the shell collector
   shipped the previous iteration**: the ship preflight runs long before `$OUTDIR/99_logs` exists,
   so its `audit` call wrote the verdict **nowhere**. Zero bundles on disk contained the line. The
   console echo had made it look present. The verdict is now buffered and flushed as soon as the
   custody trail opens.

**Result.** Route dropped with the collector confirmed running and SSH confirmed dead: exit 15;
local copy **retained** at 3,954,380 bytes; `ship.json` `preflight_ok: true, ok: false`; **0**
files at the destination; the `net_unreachable` ladder ran backoff-retry -> extend-timeout ->
skip; firewall rule removed.

## B3 - destination yanked mid-run (CLOSED 2026-07-28, Linux)

**Setup.** A 200 MB ext4 loop filesystem as `-d`, `umount -l` once the destination genuinely holds
evidence (gated on >20 KB written **and** the collector still alive, not on a timer - a rapid run
here finishes in ~6 s). An `EXIT` trap unmounts and removes the image whatever happens.

**What the collector did (the defect).** All 32 steps failed, exit was correctly 15 and it did not
hang - but it printed:

```
Collection complete. Output: /tmp/b3mnt/B3_rick-pve_20260728_153140Z
Summary: .../SUMMARY.md  |  Audit: .../99_logs/audit.log
```

for a directory that no longer existed, then sent the operator to read two files that were never
written. This is the **same false-success shape as B6**, which the Windows twin was fixed for -
the shell collector never got that guard. It also misdiagnosed the cause: `FIX purge-scratch:
reclaimed 0 KB but destination is still full`. The destination was not full, it was **gone**, and
telling a responder to free space sends them the wrong way.

**Fixes (parity with the Windows B6 work).**
1. The closing line describes the tree on disk, not reaching the end of the script: zero files
   prints `COLLECTION PRODUCED NO EVIDENCE` and names the likely cause; otherwise it reports the
   real file count and whether the run was incomplete.
2. The `Summary:`/`Audit:` paths are printed only when the bundle actually has files.
3. `purge-scratch` distinguishes a destination that has **disappeared** from one that is full, and
   says so.

**Result.** Negative control: `COLLECTION PRODUCED NO EVIDENCE`, correct diagnosis
(`NO LONGER EXISTS (unmounted or removed mid-run) - this is not a space problem`), exit 15, no
hang (14 s), no phantom paths. Positive control: a normal destination still reports
`Collection INCOMPLETE (48 files)` with the true count.

**Still open, honestly.** The scenario's stated bar also asks the collector to *seal what it has
somewhere writable* when the destination vanishes. It does not do that - the evidence written
before the yank is lost with the mount. The run now reports that truthfully instead of claiming
success, which is the more important half, but relocation of a part-written tree remains
unimplemented on both platforms.

## Audit-trail-order sweep (2026-07-28)

`Write-Audit` / `audit()` both echo to the console **and** append to the audit log, and both
swallow the file error. A call made before the log exists therefore *looks* like it worked - the
operator sees the line on screen - while the custody record never receives it.

This had already bitten twice: the Windows destination-probe note, and the Linux ship-target
preflight verdict. The second was the worse one - **zero** bundles on disk contained the line, its
absence was dismissed during review as "it goes to the audit log", and the missing field is
exactly what distinguishes B4 from B5, so that scenario was untestable until it surfaced.

`tests/unit/Test-AuditTrailOrder.ps1` now enforces the rule on both collectors: no top-level
audit call before the log is opened, and where a message must be buffered, the buffer is set
before the open and flushed after it. Only top-level calls count - a call inside a function
defined early but invoked later is fine, so the Windows side walks the AST.

**The first version of this test was blind and a mutation proved it.** The Linux half tracked
function bodies by counting brace characters; every `${var}` expansion contributes braces, so the
depth never returned to zero, the whole file read as "inside a function", and the check inspected
nothing. Reintroducing the real B4 bug did **not** fail the test. It now anchors on a closing
brace at column 0, and that same mutation fails as it should.

## B3 half (a) - Windows yanked destination: NOT SCORED, but it found something worse

**The scenario was not run.** A 300 MB VHD was attached as `X:` and proven writable, the collector
was launched with `-Dest X:\`, and the harness gated on the destination accumulating bytes before
detaching the disk. That gate never tripped, so nothing was yanked and nothing is claimed.

**Why it never tripped is the finding.** The collector silently abandoned `X:\` and wrote the
bundle to **`C:\ir_evidence\`** - the subject host's own system drive - then reported
`Collection complete (49 files)` and `EXIT 0`. The redirect was never announced. Three separate
statements in the custody record are false as a result:

| audit line | reality |
|---|---|
| `Destination is local/drive: X:\` | evidence went to `C:\ir_evidence\` |
| `PREFLIGHT destination: 45.3 GB free` | that is **C:**'s free space; `X:` had 284 MB |
| `FOOTPRINT: ... evidence written only to destination` | it was written to the subject's system disk |

This is the contamination case the tool explicitly warns about elsewhere (`!!! CONTAMINATION
WARNING` exists for the network-staging path, and scenario A1 exists because ConstrainedLanguage
once redirected evidence to the target's `C:`). Here it happened for an ordinary local `-Dest`
that was **writable**, with no warning at all, and the run reported success.

Not investigated yet: whether `-Dest 'X:\'` (trailing separator) fails a check in
`Resolve-UsableOutDir` or `Get-WritableRoot`, or whether a removable/virtual volume is rejected
by some other test. The redirect target `C:\ir_evidence` is hardcoded fallback behaviour.

**Priority for the next iteration**, ahead of finishing B3(a) itself: a writable destination must
never be silently replaced, the free-space figure must describe the destination actually used, and
any redirect must be stated loudly in both the console and the custody log.

### Silent evidence redirect - FIXED 2026-07-29

**Root cause.** The destination writability probe called `New-Item -ItemType Directory -Force`
*first* and treated any failure as "not writable". **A drive root cannot be created** -
`New-Item -Force 'X:\'` throws *"The path is not of a legal form"* - so every root-path
destination was judged unwritable and silently redirected to `C:\ir_evidence` on the subject
host. `-Dest E:\` on a USB evidence drive, the most ordinary destination in live response, hit
this every time.

**Fix.** `Test-PathWritable` creates the directory only when it does not already exist, then
answers the real question by writing a probe file and **reading it back** - the same lesson as
the UNC probe in B5, where an exception-free call proved nothing. The redirect, when it does
happen, is now buffered and flushed into the **custody log** (it was `Write-Host` only) and names
the consequence: the evidence is on the subject host and the collection has modified the target.

**Verified on PS 5.1**, where the bug lives: `-Dest Y:\` on a 300 MB VHD put its bundle on `Y:`
(48 files) with **zero** leaked to `C:\ir_evidence`, and the audit log now reads
`PREFLIGHT destination: 0.3 GB free` / `Destination is local/drive: Y:\` - both previously false.

**The unit test could not catch this on its own, and that is worth recording.** The bug is
engine-dependent: `New-Item -Force 'C:\'` throws under Windows PowerShell 5.1 (what runs on a
target) but **succeeds** under PowerShell 7 (what the tests and CI run on). Mutations that put
the bug back therefore passed the behavioural assertions. `Test-PathWritable.ps1` adds structural
assertions that read the shipped source - existence guard present, guard *before* the `New-Item`
statement, readback present - which hold on any engine. A first attempt at the ordering assertion
matched the `New-Item` mentioned in the function's own docstring rather than the statement, and
failed on correct code until it was anchored properly.

### B3 half (a) - Windows destination yanked mid-run: CLOSED 2026-07-29

**Setup.** A 300 MB VHD attached as `Z:`, gated on the destination genuinely holding evidence
(21,661 bytes) **and** the collector still running, then `detach vdisk` out from under it. This
scenario was blocked on the previous attempt because evidence was being silently redirected to
`C:\ir_evidence` - fixing that made the gate reachable.

**Result.** The B6-era guard holds on Windows: no hang (12 s to exit), `EXIT 15`, **no** false
"Collection complete", `COLLECTION PRODUCED NO EVIDENCE` printed, `FINAL: no files present ... -
reporting failure, not completion` in the audit log, and **zero** bundles leaked to
`C:\ir_evidence` - so the redirect fix holds under this condition too.

**One defect found and fixed.** The advice attached to that message was B6's: *"Re-run with a
shorter -Dest on writable media"*. Path length has nothing to do with a volume being unplugged,
and sending a responder to shorten their path while their evidence drive is missing is the same
misdiagnosis the Linux twin made when it called a vanished destination "full". The message now
distinguishes the two: a missing volume is named as removed or unmounted, with the honest note
that anything collected before that point went with it; other causes still point at space,
permissions and path length.

**Re-verified after the fix** under the same live yank: `names the VANISHED volume: True`,
`wrongly advises shorter dest: False`.

### B3 half (b) - salvaging a part-written tree: DECLINED, 2026-07-29

The scenario's original bar asked the collector to "seal what it has somewhere writable" when the
destination vanishes. After measuring what is actually possible, that is **deliberately not
implemented**. The reasoning, so it is not re-opened by instinct:

**1. Salvage after the fact is impossible.** Once the volume is unmounted the already-written
files are unreachable - you cannot copy what you can no longer read. Nothing at seal time can
recover them.

**2. The only mechanism that would work costs more than it saves.** Preserving artifacts requires
duplicating every one to local scratch *as it is collected*, i.e. writing the full evidence set to
the subject host on **every** run. That inverts the tool's own doctrine - it prints a
`FOOTPRINT:` line asserting evidence goes only to the destination, and a `CONTAMINATION WARNING`
when it is forced to stage on the target - and it doubles I/O and space on every collection, to
insure against an uncommon event. A responder who unplugs the evidence drive mid-collection has a
procedural problem; permanently contaminating every future engagement is not the fix.

**3. The forensically important part already survives, and it was verified.** The account of what
happened does not live on the destination alone. Measured on range-WS02 during a live yank:
`run_state.json` was written to `%TEMP%\ir-collect_run_state_<case>_<stamp>.json` (3,197 bytes) by
the existing rollup fallback, and the operator is told on the console. So an analyst still learns
which steps ran, what the verdict was, and that the destination disappeared - they simply do not
get the artifacts, which are gone with the mount either way.

**What was fixed instead** (both platforms): the run no longer claims success for a bundle that is
not there, and it names the real cause rather than guessing - see the B3 and B6 entries above.

**Residual, stated plainly:** the fallback rollup lands in `%TEMP%` on the subject host and is not
cleaned up. That is a small, deliberate footprint - kilobytes of metadata, no evidence content -
and the console names the path when it happens.

## A6 - execution policy AllSigned (CLOSED 2026-07-29)

**Setup.** The collector is unsigned (`Get-AuthenticodeSignature` -> `NotSigned`, asserted first -
a signed collector would make the scenario meaningless). Launched via a child with
`-ExecutionPolicy AllSigned`.

**Attempt 1 was INVALID and the reason is instructive.** It set `AllSigned` at *LocalMachine*
scope and asserted `Get-ExecutionPolicy -Scope LocalMachine` - which was true and irrelevant. The
child inherited **Process-scope Bypass** from the harness, so the *effective* policy was Bypass
and the collector ran normally, producing 49 files under a policy that was supposedly blocking it.
Checking the scope you set instead of the value that governs is the same mistake as reading a
return code instead of the result. The gate now asserts the **effective** policy inside a child
launched the same way as the one under test.

**Result.** Exit **1**, nothing on stdout, and PowerShell's own refusal on stderr: *"File
C:\ir\IR-Collect.ps1 cannot be loaded. The file ... is not digitally signed."* **0 bundles**
created, nothing leaked to `C:\ir_evidence`, machine policy left at `RemoteSigned`. Positive
control with `-ExecutionPolicy Bypass`: exit 0, 1 bundle, 49 files.

**Stated plainly:** this is enforced by the PowerShell host, not by collector code - the script
never starts, so there is no half-run tree to clean up and nothing for the tool to detect. The
scenario's bar ("clear failure at launch, not a half-run") is met, but no collector logic is
responsible for it, and none should be added: refusing to run an unsigned script is the host's job.

## C4 - no TTY / fully detached (CLOSED 2026-07-29)

**Setup.** Scheduled task running as `NT AUTHORITY\SYSTEM`, no interactive session, action wrapped
in `cmd /c ... < NUL` so stdin is bound to NUL. Bounded wait of 300 s, because a prompt deadlock
is precisely what this scenario hunts and an unbounded wait would hide one.

**Attempt 1 was not scored.** It launched the same task without the `< NUL` binding, and the
in-task probe reported `console : True` - a SYSTEM scheduled task still gets a conhost, so the
condition the scenario names was not live. More usefully, it was the *wrong* condition to chase:
console presence is not what deadlocks a collector. A **readable stdin that blocks** is. The
governing value is `[Console]::IsInputRedirected`, and the gate now asserts that instead.

**Result** with stdin genuinely unreadable (`IsInputRedirected: True`, running as `WS02$`): the
collection finished with **49 files**, verdict `COMPLETE`, `ok=33 failed=0`, manifest 45 rows /
**0 ERR**, exit 0, no deadlock. Identical output to an interactive administrator run.

**Observation worth keeping, not a defect.** The detached SYSTEM run took **270 s** against
roughly 25 s for the same `-RapidOnly` collection interactively. Correctness is unaffected - every
count matches - but a 10x slowdown under SYSTEM is unexplained and worth understanding before
anyone builds timeouts around detached execution.

## E4 - clock skew (CLOSED 2026-07-29)

**Setup.** WS02's clock advanced by 4 minutes - deliberately inside Kerberos' 5-minute tolerance so
the domain keeps working, while still being a skew any real measurement must catch. Restored with
`w32tm /resync` and verified **by measurement** against the DC afterwards, not by the resync
command's own say-so.

**The gap.** The artifact was previously the host's own local and UTC time plus a note:
*"compare against a trusted external time source and record offset for timeline defensibility."*
Under a live skew the file changed - it faithfully recorded the wrong time - but nothing in it let
a reader tell the clock was wrong. The one measurement that makes a timeline defensible was left
as homework for the analyst, on a host they may never touch again.

**Fix.** The step now measures the offset against the host's configured time source (falling back
to the logon server), names the peer it used, and warns above 60 s. With no source reachable it
says so explicitly rather than implying the clock is fine - the E3 case gets an honest
`UNAVAILABLE` instead of silence.

**A sign error caught before it shipped.** The first version labelled the value *"host clock
relative to that reference"*. `w32tm /stripchart` reports **reference minus host**, so a host
running fast yields a NEGATIVE number - the label inverted it, and an analyst correcting a
timeline by that sign would have shifted every timestamp the wrong way. The artifact now states
the convention and spells out the direction in words: *"this host is AHEAD of the reference by
239.989s"*.

**Verified live.** Correct clock: `+0.001s`, no warning. Advanced 4 minutes: `-239.989s`,
`Interpretation: this host is AHEAD of the reference by 239.989s`, WARNING present, reference peer
named `IR-DC01.lab.local`. Clock restored and confirmed at `+0.01s` vs the DC.

**Harness note.** My own assertion expected a positive number and failed on correct output - which
is how the inverted label was found. A failing assertion on working code is worth reading before
"fixing" the assertion.

## E3 - domain unreachable (CLOSED 2026-07-29)

**Setup.** Outbound firewall rules on WS02 blocking TCP 389/636/445/88/3268 and UDP 88/123/389 to
`10.20.50.233`. Baseline asserted reachable first, the block asserted effective
(`445=False 389=False`) before judging, and both rules removed by a teardown that **verifies**
removal and re-tests reachability.

**Proven.**
- **No hang.** The run completed in 95 s against ~25 s baseline - slower, but bounded and
  self-terminating. No step waited on the dead DC indefinitely.
- **The clock step's UNAVAILABLE path works**, which is what E4 built it for. It still names the
  configured source and reports the peer honestly:
  `Time source: IR-DC01.lab.local` / `Reference peer: NONE REACHABLE` /
  `Measured offset: UNAVAILABLE - ... this bundle carries no independent evidence that the host
  clock is correct.` That is the right answer: absent a reference, say so rather than imply the
  clock is fine.

**NOT proven, and the reason.** The run reported `verdict: COMPLETE, ok=33, failed=0` - because
`-RapidOnly` seals after Stage 1 and never reaches the AD section. The AD steps
(`ad-net-accounts`, `ad-net-da`, `ad-net-ea`, `ad-nltest`, `ad-gpresult`, `ad-domain`) were never
planned, so **nothing was skipped, nothing could be marked incomplete, and the scenario's central
claim is untested.** A COMPLETE verdict here is correct for the steps that ran and says nothing
about AD.

**To finish this**, the same block must be applied to a run that actually plans the AD section
(`-Auto`, 13-20 min), asserting those six steps fail or skip cleanly, land in the verdict, and do
not hang. Queued rather than claimed.

**Found while checking:** the diagnostic report's resume hint still pointed at `.\kit\IR-Collect.ps1`
in **three** places - a path that has not existed since the repo reorganised to `collectors/`. An
analyst following the bundle's own instructions would have run nothing. Fixed.

### E3 attempt 2 - VOID (2026-07-29)

An `-Auto` run was launched under the same DC block so the AD section would actually be planned.
It is **not scored**, for a reason that is entirely a harness error:

`e3b.ps1` blocked the DC, launched the collector, and waited - but had **no teardown**. The
orchestrating call timed out at ~10 minutes while the guest run continued (bounded at 25 min
there), leaving firewall rules on a range VM with nothing scheduled to remove them. Removing them
immediately was the right call for the range, but it un-did the test condition mid-run: by the
time the collector reaches the AD section the DC is reachable again, so those steps will succeed
normally and prove nothing.

State at teardown: 279 files collected, `run_state.json` not yet written, **0 AD ledger records** -
the AD section had not been reached. Firewall rules removed and verified (0 remaining, 445 and 389
both reachable again).

**The lesson is the one already on the board, applied to the harness rather than the collector:**
every scenario script must tear down in a `finally`/trap that runs whether the orchestrator is
still watching or not. A long-running scenario cannot depend on the caller staying alive to clean
up after it. The Linux harnesses already do this with `trap ... EXIT`; the PowerShell ones must
too, and a bounded wait inside the guest is not a substitute.

**Still required to close E3:** the AD steps must run *while* the DC is unreachable. Either the
teardown moves inside the guest script (block, run, evaluate, unblock, all in one process), or a
watchdog scheduled task removes the rules at a fixed deadline regardless of what the orchestrator
does.

### E3 attempt 3 - the AD steps finally ran, and found a defect (2026-07-29)

**What made it runnable.** The whole scenario in ONE guest script, launched detached as a
scheduled task, writing progress to a status file this session polls; teardown in `finally`; a
watchdog task removing the firewall rules at a hard deadline regardless. The orchestrator's
~10-minute cap stopped mattering. Attempts 1 and 2 failed purely on orchestration.

**Condition genuinely live throughout:** `after block: 445=False 389=False`, and the status log
records `dcBlocked=True` at every checkpoint across the whole `-Auto` run.

**Two halves of the bar are met.** Nothing hung - the run completed on its own - and every AD step
finished rather than blocking on the dead DC. The clock step reported
`Reference peer: NONE REACHABLE` / `Measured offset: UNAVAILABLE`, which is the E4 path behaving
exactly as designed under a real outage.

**The third half is not.** With the DC unreachable, **fourteen** AD steps produced no output at
all - `ad-domain, ad-users, ad-groups, ad-computers, ad-spn, ad-asrep, ad-uncons, ad-cons,
ad-rbcd, ad-admincount, ad-trusts-ldap, ad-laps, ad-this-host` (plus `copy-pshistory`,
`web-root-timeline`). The collector **noticed** - they are all listed in
`diagnostics.empty_outputs` - and then sealed the bundle anyway:

```
verdict    : COMPLETE
counts     : ok=85 failed=0 timeout=0 skipped=0
incomplete : (empty)
errclass   : {}
```

An analyst receives a bundle stamped COMPLETE, from a **domain-joined** host, containing no domain
data whatsoever, with nothing in the verdict to say the domain was never reached.

**Root cause.** `$script:CriticalSteps` - the list whose emptiness drives the verdict - covers
core volatile artifacts (processes, netstat, services, local users) and was never extended to the
AD section. Emptiness detection works; it just does not apply here. This is the same shape as the
E1/WMI defect, one section further along, and the same shape as A3: the tool sees the gap and does
not let it reach the verdict.

**Fix required (not yet implemented):** on a domain-joined host, empty AD enumeration must reach
the verdict - ideally naming the cause, since "the DC was unreachable" is knowable at the time
(the same probe the clock step already makes). Deliberately not rushed in at the end of an
iteration: a verdict change needs its own live `-Auto` run to verify, and that is 20 minutes.

**Range restored:** E3B bundle removed, `IRTEST-BlockDC*` rules 0, DC 445 reachable, E3Run and
IRWatchdog tasks deleted, C:\evidence back to 3 directories.

### E3 fix - verdict mechanism PROVEN, cause attribution was not (2026-07-29)

**Negative control, live under a blocked DC:**

```
E3NEG verdict=INCOMPLETE ok=85 failed=0  emptyAD=13
E3NEG incomplete=domain-evidence-missing(reachability unknown; 13 AD step(s) empty:
  ad-admincount/ad-asrep/ad-computers/ad-cons/ad-domain/ad-groups/ad-laps/
  ad-rbcd/ad-spn/ad-this-host/ad-trusts-ldap/ad-uncons/ad-users)
```

The defect is fixed: the same run that previously sealed COMPLETE now seals **INCOMPLETE** and
names all thirteen missing AD steps. An analyst can no longer be handed a COMPLETE bundle from a
domain-joined host with no domain data in it.

**But it fired through the wrong branch.** The note says *"reachability unknown"*, not *"domain
controller unreachable"* - `$script:DomainReachable` was `$null`, so the LDAP probe never ran. The
probe keyed on `$env:LOGONSERVER` / `$env:USERDNSDOMAIN`, and measurement showed both are empty
**for SYSTEM and for an interactive administrator over SSH**. In this environment that probe could
essentially never run, so the verdict could only ever reach the "unknown" wording.

**The three-state design is the reason this was safe.** Had `DomainReachable` been a plain boolean,
an unrun probe would have defaulted to `$false` and the bundle would have asserted a cause nobody
established - "domain controller unreachable" on evidence that only showed AD returned nothing.
Instead it surfaced the gap and labelled its own uncertainty honestly. That is the
"never state a cause the code has not established" rule doing real work rather than sitting in a
comment.

**Fix.** The probe now derives the domain from `Win32_ComputerSystem.Domain` (populated in both
contexts, `lab.local` on this host), keeping the environment variables as a fallback for hosts
where CIM is broken (scenario E1).

**Outstanding:** the positive control (DC reachable - the same steps must NOT force INCOMPLETE) was
still running when this was recorded, and the negative control must be re-run with the corrected
probe to confirm the note reads *"domain controller unreachable"*. Neither is claimed.

### E3 - CLOSED 2026-07-29, both controls passing

| control | DC | verdict | empty AD steps | `domain-evidence-missing` |
|---|---|---|---|---|
| **E3NEG** | blocked | **INCOMPLETE** | 13 | present, `(domain controller unreachable; 13 AD step(s) empty: ad-admincount/ad-asrep/ad-computers/ad-cons/ad-domain/ad-groups/ad-laps/ad-rbcd/ad-spn/ad-this-host/ad-trusts-ldap/ad-uncons/ad-users)` |
| **E3POS** | reachable | **COMPLETE** | 4 | **absent** |

E3POS is the one that matters. The same collector, on the same host, with four AD steps returning
nothing - `ad-cons`, `ad-laps`, `ad-rbcd`, `ad-trusts-ldap`, because this domain genuinely has no
constrained delegation, no LAPS and no extra trusts - seals **COMPLETE**. Empty is not treated as
missing when the domain answered.

**It took three attempts and the middle one nearly shipped a worse bug than the original.**

1. Fix written, unit-tested 18/18, three mutations caught. Looked done.
2. Live negative control: INCOMPLETE with all 13 steps named - but the note said *"reachability
   unknown"* instead of naming the cause. The LDAP probe had never run: it keyed on
   `$env:LOGONSERVER` / `$env:USERDNSDOMAIN`, and both are **empty under SYSTEM and for an
   interactive administrator over SSH**. Measured, not assumed.
3. Live **positive** control with the DC reachable: `domain-evidence-missing` **fired anyway**,
   flagging four legitimately-empty steps. The fix, as written, would have marked healthy domain
   collections INCOMPLETE - the exact cry-wolf failure it was designed to avoid. The negative
   control passed at every stage and could never have revealed this.

The probe now reads `Win32_ComputerSystem.Domain` (populated in both contexts), keeping the
environment variables as a fallback for CIM-broken hosts (E1).

**Why the wrong version was survivable:** `DomainReachable` is three-state (`$true`/`$false`/
`$null`). An unrun probe therefore produced *"reachability unknown"* - visibly wrong - rather than
defaulting to `$false` and asserting *"domain controller unreachable"* on evidence nobody had. A
boolean would have shipped a confident false cause into an evidence bundle.

Range restored to baseline: 0 firewall rules, DC reachable, 0 E3 bundles, 3 evidence dirs, tasks
deleted.

## E5 - PowerShell 2.0 (CLOSED 2026-07-29)

**The original repro is INVALID on this host, and that was measured rather than assumed.** The
PS 2.0 *feature* is `Enabled` on range-WS02, but .NET 2.0 is not installed, so
`powershell -Version 2` refuses on its own: *"Version v2.0.50727 of the .NET Framework is not
installed and it is required to run version 2 of Windows PowerShell."* The collector never starts,
so nothing about its behaviour under v2 could be observed here.

**That refusal is host-specific, and the gap behind the scenario was real.** The collector had no
`#requires` and no version check, while using `[pscustomobject]` (12x), `Get-CimInstance` (25x) and
`[ordered]` hashtables (21x) - none of which exist in v2. On a legacy host that *does* have .NET
2.0 - Server 2008 R2, Windows 7, exactly the machines a live-response collector still meets -
nothing would have stopped it. It would parse, begin collecting, and die partway through with
errors that read like a broken host rather than a wrong interpreter.

This is where E5 differs from A6. In A6 the host refuses on *every* machine with AllSigned, so
adding collector logic would have duplicated the host's job. Here the host only refuses on machines
that happen to lack .NET 2.0, so `#requires -Version 3` makes the refusal universal and immediate.

**Verified live without needing a v2 host**, by temporarily requiring an impossible version:

| control | directive | exit | stdout lines | bundles |
|---|---|---|---|---|
| negative | `#requires -Version 99` | 1 | **0** | **0** |
| positive | `#requires -Version 3` | 0 | normal | 1 (49 files) |

Zero stdout lines is the part that matters: it refuses *before* collecting anything, which is the
scenario's actual bar. Two mutations - dropping the directive, and weakening it to `-Version 2` -
each fail the suite.


## Linux parity for E4 - clock offset measurement (2026-07-29)

`ir-collect.sh` had the identical gap the Windows collector had: `clock_provenance.txt` recorded
the host's own local and UTC time plus *"NOTE: compare to trusted time source; record offset for
timeline defensibility."* It measured nothing.

`clock_verdict` is now a pure function (unit-tested without a time daemon) fed by chronyc, ntpq or
timedatectl, whichever is present. **Three-state**, per the E3 lesson: *measured* / *UNAVAILABLE*
(a daemon exists but reported no offset) / *UNKNOWN* (no time tooling at all). An unmeasured clock
never reads as a correct one.

**Every source is normalised to host-minus-reference before it reaches the formatter**, so the
sign convention lives in one place per tool: chronyc reports fast/slow in words, ntpq reports
reference-minus-host in milliseconds and is negated. E4 shipped an inverted label for exactly this
reason, so the artifact also spells the direction out in words.

**Live on rick-pve.** Positive control: `Measured offset : 0.000242663s`,
*"this host agrees with the reference"*, **no** false warning. **The negative control is INVALID** -
`date -s "+200 seconds"` was corrected by `chronyd` before the collector measured, so the clock was
never actually skewed at measurement time and nothing about detection was proven. Recorded rather
than claimed; a real skew test needs chronyd stopped first.

**A defect the invalid run still exposed:** chrony reported `-0.000000000`, and the string-shaped
`case` matched `-*` first, printing *"BEHIND the reference by 0.000000000s"* - a direction asserted
on a measurement showing agreement. Agreement is now decided numerically with a sub-millisecond
band, and a mutation that checks the sign first fails the suite.

**E5 parity needs nothing:** `ir-collect.sh` already requires bash 4+ and, better than refusing,
re-execs a carried static bash from `tools/bin` when the host's is too old.


### Linux clock: closing the gap the invalid negative control left (2026-07-29)

The live negative control could not be redone. No Linux VM on the range answers ssh, and the only
other host is the Proxmox hypervisor - skewing a production hypervisor's clock to exercise a string
parse is not a trade worth making. So the gap was closed by narrowing it instead of by re-running:

| what | how it is now covered |
|---|---|
| end-to-end extraction from real chronyc | the live POSITIVE control (`0.000242663s`, agreement, no false warning) |
| direction and the 60s warning | `clock_verdict` unit tests, both mutations caught |
| **parsing chronyc's LARGE-offset output** | **new**: the parse driven with real chronyc output shapes |

The last row was the genuine unknown - the positive control only ever exercised a ~0s offset, so
nothing proved the awk handled `200.123456789 seconds fast of NTP time`. It now parses fast (+),
slow (-), sub-microsecond, and the unsynchronised `-0.000000000` seen live; and it asserts the
parse reads only the `System time` line, not `Last offset` or `RMS offset` - which sit above it in
real `chronyc tracking` output and would have been a live bug had the regex been looser.

**The test mirrors a copy of the parse**, because the original lives inside a long single-quoted
`bash -c` string and cannot be sourced. A copy can drift from the original and keep passing, so the
test also asserts the shipped file still contains the same awk program. Two mutations - renaming
the captured field, and flipping `slow` to `fast` - each fail it.

Anchoring that guard took three attempts: `grep` patterns for the shipped text kept failing against
*correct* code because the awk program is embedded with backslash-escaped `$`. Fixed by reading the
exact bytes out of the file and matching fragments confirmed to exist, rather than guessing the
escaping - the same trap that has now cost time in five separate iterations.

## E4 Linux, second pass - the clock evidence a synchronised-looking host actually carries (CLOSED 2026-07-29)

The first Linux pass measured the offset and got the sign convention right. This pass asked a
different question - what the step reports on hosts where no offset exists - and found three
defects, two of them the tool's recurring failure mode: **the collector already held the fact and
did not let it reach the verdict** (same class as E1/WMI, A3, E3).

**How the premise that blocked this was wrong.** The carried state said the Linux clock work could
not be verified live because "no Linux VM on the range answers ssh". That was false: it came from
probing with `qm guest cmd` (no guest agent is installed anywhere) and as `root` rather than the
real accounts. `range-linux-web` (10.20.50.60) answers ssh with passwordless sudo. It has no chrony
- only `systemd-timesyncd`, the Ubuntu default - which is precisely why it exposed these defects.

### Defect 1 - the Reference ID was never extracted (asserted nothing, every run)

`awk -F"= *" "/Reference ID/{print $2; exit}"`, but `chronyc tracking` separates with `:`. `$2` was
always empty, so every Linux bundle from a chrony host recorded:

```
Time source     : chronyc ()
```

An empty parenthetical claiming a reference the code never read. Confirmed against real bytes from
rick-pve - `Reference ID    : 4540E102 (cambria.bitsrc.net)` - and by mutation: the old separator
extracts nothing from that exact line.

### Defect 2 - "(no reachable peer)", a cause the code never established

Whenever no numeric offset was available the step printed `is present but reported no offset (no
reachable peer)`. Nothing in the probe determines peer reachability. It is stated unconditionally,
so a perfectly synchronised host that simply exposes no number through this probe was reported as
having an unreachable peer. **`systemd-timesyncd` never exposes an offset through this probe at
all**, so on the default Ubuntu configuration this false cause was the normal output.

### Defect 3 - `NTPSynchronized=no` was reported as a working time source

The worst of the three for a forensic bundle. The step read the sync flag, used it only to build a
display string, and then discarded it. A host whose clock has **never been anchored to anything**
produced:

```
Time source     : timedatectl (NTPSynchronized=no)
Measured offset : UNAVAILABLE - ... is present but reported no offset (no reachable peer).
```

No warning. That reads as a quiet daemon on an otherwise fine host. The truth is stronger and worse:
every timestamp in the bundle is unanchored and the error is *unbounded*, not merely unmeasured -
which is the difference between a timeline that can be corrected later and one that cannot.

### Fix

`clock_verdict` takes the sync state as a third, defaulted argument and stays pure/unit-testable.
Three-state per the E3 lesson - `no` / `yes` / unread - and the unread case invents no cause:

| sync | verdict |
|---|---|
| `no` | `NOT SYNCHRONISED` + timestamps `UNVERIFIED` + `WARNING` (error unbounded) |
| `yes` | synchronised but no numeric offset; residual error bounded by the daemon, not by this measurement |
| unread | offset unavailable and sync state `could not be read` - no cause asserted |

A real measured offset still outranks the flag. The step now reads `NTPSynchronized` regardless of
which daemon won, so the fact survives to the verdict.

### Verification - both controls, live, condition asserted at measurement time

Driven by extracting the **shipped** step text and the **shipped** `clock_verdict` from
`collectors/ir-collect.sh` and running them verbatim, so this tests the artifact, not a copy.

**Positive control - rick-pve, chrony, synchronised.** Live condition confirmed at measurement time
(`Reference ID : 4540E102 (cambria.bitsrc.net)`, `System time : 0.000049317 seconds fast`):

```
Time source     : chronyc (4540E102 (cambria.bitsrc.net))
Measured offset : 0.000049315s  (host minus reference; positive = this host is AHEAD)
Interpretation  : this host agrees with the reference
```

Reference ID present, offset measured, agreement, and critically **no spurious warning** - the E3
lesson that a fix must not degrade a healthy host.

**True negative - range-linux-web, timesyncd, never synchronised.** Live condition confirmed at
measurement time (`NTPSynchronized=no`, `Server: n/a`, `Packet count: 0`):

```
Time source     : timedatectl (NTPSynchronized=no)
Measured offset : NOT SYNCHRONISED - ... has never been synchronised against a time source ...
Interpretation  : this host's timestamps are UNVERIFIED - the clock could be off by any amount ...
WARNING: this clock is not synchronised. Timestamps in this bundle are NOT safely comparable ...
```

Previously this host produced the fabricated-cause line and **no warning at all**.

### Mutation testing

Each mutation attacks the mechanism, not a threshold; the unmutated file fails nothing.

| mutation | result |
|---|---|
| `sync=no` branch made unmatchable | 3 failures |
| Reference ID separator reverted to `=` | 2 failures |
| step stops passing `sync` through to `clock_verdict` | 1 failure |

That last one matters most: without it the whole feature could be dead in production while every
in-function assertion still passed.

### Still not done, and why

The chrony **large-offset** path is still not proven live. `range-linux-web` has no chrony, and the
only host on the range that runs it is the Proxmox hypervisor - skewing a production hypervisor's
clock to exercise a string parse remains a bad trade. It stays covered by real chronyc output
shapes plus a drift guard asserting the shipped parse still matches the mirrored copy.

## Audit pass over this page (2026-07-29)

First end-to-end review of the catalogue as a whole. It had grown to ~1010 lines across many
sessions, and status was being written in three places - the section tables, the per-scenario
headings, and the prose - with nothing keeping them agreeing. Four defects, all of them the
documentation form of the bug this project keeps finding in the collector: **a status claiming
more, or less, than the evidence underneath it.**

**1. E3's heading contradicted its own body.** `## E3 - domain unreachable (PARTIAL 2026-07-29)`,
while the table row said CLOSED and the section itself ended with `### E3 - CLOSED 2026-07-29, both
controls passing`. A reader skimming headings would have concluded the scenario was unfinished.
The heading was written mid-investigation and never updated when the fix landed.

**2. A live instruction pointed at a directory that no longer exists.** The testing-hygiene recipe
said `copy kit\IR-Collect.ps1 ...` - `kit/` was renamed to `collectors/` and the block two lines
above it already said `collectors/tools`. Anyone following it copies nothing and then runs a
collector that is not there. Note the irony recorded at line 663: this page documents finding and
fixing *exactly this class of bug* in the collector's own resume hint, while carrying it here.

**3. E5 was the only closed row with no status glyph**, against the legend at the top of the page.

**4. E1 was marked ✅ while its own text described an open gap.** The row read "`wmi_failure` still
never fires because the steps do not error, they return nothing". Verified still true: the
classifier only matches error TEXT (`collectors/IR-Collect.ps1:510`), so when WMI is broken and the
steps return empty rather than throwing, nothing ever classifies as `wmi_failure`.

The scenario's stated requirement *is* met - emptiness detection stops the run claiming COMPLETE -
so the ✅ was not baseless. But the consequence is real and worth its own harden pass:
`collectors/IR-Collect.ps1:618` defines a fix ladder for `wmi_failure` (`restart-wmi`,
`native-source`, `skip`) that **can never be offered to an operator**, because the only path that
would select it is unreachable in the one scenario it exists for. The tool detects the condition and
still fails to hand the responder the remediation - the same shape as E1/A3/E3 and the clock work.
Re-marked ⚠️ per this page's own legend, with the gap stated rather than trailing off.

### Mechanical checks now run over this page

Worth keeping because all four defects above were found by cross-checking, not by reading prose:

- every `tests/`, `collectors/`, `docs/` path the page mentions must exist in the repo
- no section heading may carry a status its table row contradicts
- every closed row carries a glyph from the legend

The path check was itself wrong on the first attempt - the character class `[/\]` escapes the
bracket, so the pattern matched garbage and reported three nonexistent "missing" files while
missing the real one. Re-run with a self-test asserting the pattern finds a known-present and a
known-absent path before its output was trusted. **A checking script needs a positive control as
much as a scenario does.**
