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
| A6 | **Execution policy / unsigned script blocked** | `Set-ExecutionPolicy AllSigned` (machine) | Clear failure at launch, not a half-run | ⬜ |

## B. Destination

| # | Scenario | Reproduce | Correct behaviour | Status |
|---|---|---|---|---|
| B1 | **Read-only media** | mount a loop image `-o ro` | Detect, redirect, log the redirect | ✅ |
| B2 | **Destination full** | Linux: 3 MB loop fs. Windows: 40 MB VHD filled to <96 KB free — **assert a 512 KB write is refused before judging** | Refuse up front rather than dying mid-run with no diagnosis | ✅ **BOTH VERIFIED**. Linux field-tested. Windows: 4th attempt induced the condition (76 KB free, 512 KB write refused) and found the seal-time ENOSPC fallback cannot help — a destination full from the first write kills the run before `Invoke-Seal`, so no `run_state.json` and the fallback never fires. Fixed with a 64 MB destination preflight: **verified exit 40 with the refusal message**. The case folder does remain, containing only `audit.log` with the `PREFLIGHT REFUSED` line — that is deliberate, it is the custody record that a collection was attempted and declined |
| B3 | **USB yanked mid-run** | `qm set <vmid> -delete <disk>` or unmount the loop device mid-collection | Do not hang; seal what exists somewhere writable; say the destination vanished | ⬜ **high value, untested** |
| B4 | **Network destination dies mid-ship** | drop the route / stop sshd on the collector server | Retain evidence locally, never delete the local copy on a failed ship | ✅ CLOSED 2026-07-28 - see below |
| B5 | **UNC auth failure** | wrong credentials to an SMB share | Warn at preflight, keep collecting (evidence is staged locally), never report a clean run when the evidence never arrived | ✅ CLOSED 2026-07-28 - see below |
| B6 | **MAX_PATH exceeded** | long `-Dest`, or deep nested profile paths | Refuse up front with an actionable message; never report success for a tree that was never written | ✅ CLOSED 2026-07-28 - found the worst false-success yet, see below |

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
