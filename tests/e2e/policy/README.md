# Security-policy testing on the range — and the guaranteed way back

The collector has to behave correctly on **hardened** endpoints (AppLocker/WDAC, ConstrainedLanguage,
locked-down execution policy). Those conditions cannot be simulated safely on a working laptop, so
they get tested on range VMs. This directory is the harness for doing that reversibly.

> **Test environment only.** Every script here refuses to run without
> `-IUnderstandThisIsATestVM`, and `Set-TestPolicy.ps1` additionally refuses unless a baseline
> already exists.

---

## Read this first: there is currently NO hypervisor rollback

The obvious safety net would be a Proxmox snapshot before each test. It is **not available**:

```
# qm snapshot 154 baseline-clean
snapshot feature is not available
```

Because the range VM disks are **`.raw` files on `dir` storage** (`local:154/vm-154-disk-1.raw`),
and Proxmox can only snapshot `qcow2`, LVM-thin or ZFS. So the in-guest baseline in this directory
is not a convenience — **it is the only rollback that exists today.**

Three ways to change that, in increasing cost:

| Option | Cost | Gives you |
|---|---|---|
| Convert disks `raw` → `qcow2` | VM downtime + temporary 2× disk space (~560 GB free, 60 GB disks → fine) | Real `qm snapshot` / `qm rollback` |
| `vzdump` before a test session | Slow, full-VM sized | Whole-VM restore, works on any storage |
| In-guest baseline (this directory) | Seconds | Reverts exactly the policy knobs we touch |

Recommended: keep using the in-guest baseline for routine policy tests, and convert to qcow2 if we
start doing destructive tests where a partial revert is not good enough.

Convert (VM shut down):

```bash
qm shutdown 154 && qm stop 154
qemu-img convert -p -f raw -O qcow2 /var/lib/vz/images/154/vm-154-disk-1.raw \
                                    /var/lib/vz/images/154/vm-154-disk-1.qcow2
qm set 154 --scsi0 local:154/vm-154-disk-1.qcow2
qm start 154 && qm snapshot 154 baseline-clean
```

---

## The procedure

Always all four steps, in order. Skipping step 1 means there is no way back.

```powershell
# 1. BASELINE — capture the machine's current policy state
.\Export-PolicyBaseline.ps1                       # -> C:\policy-baseline\<stamp>\ + LATEST.txt

# 2. APPLY — a named test policy (refuses if step 1 was skipped)
.\Set-TestPolicy.ps1 -Policy clm-applocker -IUnderstandThisIsATestVM

# 3. TEST — run the collector against the hardened condition
powershell -File C:\ir\IR-Collect.ps1 -RapidOnly -Scenario A -CaseId CLMRANGE -Dest C:\evidence

# 4. REVERT — and confirm it actually reverted
.\Restore-PolicyBaseline.ps1                      # exits non-zero if verification fails
```

### Policies

| Name | What it does | Realism |
|---|---|---|
| `clm-applocker` | AppLocker **Script** rules in enforce mode, allow-listing `%WINDIR%` and `%PROGRAMFILES%` only. Scripts outside those paths run in ConstrainedLanguage. | How real hardened endpoints get there |
| `audit-only` | Same rules in Audit mode — logs what *would* be blocked, changes nothing | Use to confirm the rule set targets what you expect before enforcing |
| `clm-envvar` | Machine `__PSLockdownPolicy=4` | Quick lever; legacy, not honoured on every build |

### What the baseline captures

AppLocker effective + local policy (XML) · AppIDSvc start type and status (enforcement is inert
without it) · WDAC/Device Guard state and deployed `.cip` policies · ExecutionPolicy for every
scope · `__PSLockdownPolicy` machine variable · PowerShell script-block/module-logging and
transcription registry state.

### Restore verifies, it does not assume

`Restore-PolicyBaseline.ps1` re-applies the baseline and then **checks the result**: no rule
collection left in enforce mode, `__PSLockdownPolicy` back to its baseline value, and the language
mode **in a freshly spawned PowerShell** matching the baseline. It exits non-zero and says
`RESTORE INCOMPLETE` rather than reporting a success it did not verify. A reboot is sometimes
needed before AppLocker enforcement fully drops — re-run the restore afterwards to confirm.

---

## Why we test this at all

Running the collector under ConstrainedLanguage (2026-07-28) showed it does not degrade — it
breaks while *appearing* to work: `[scriptblock]::Create` is blocked (that is how nearly every
step is built), nothing gets hashed (no manifest, no custody digests), and the writable probe
throws in a way that redirected evidence onto the target's own `C:\`. The collector now refuses
with exit 40 unless `-AllowConstrainedLanguage` is passed. This harness is how that stays true.
