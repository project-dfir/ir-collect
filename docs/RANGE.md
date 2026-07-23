# Training / Cyber-Range Use (virtual environments)

A very common use of this toolkit is a **training exercise** where the "compromised" hosts are VMs in a
range. Two problems that don't exist on a physical thumb-drive engagement have to be solved: **loading the
tool into each guest**, and **extracting the evidence back out** — across whatever hypervisor the range
runs on. This is what **Lab mode** and the `range/` helpers are for.

## Lab mode (`-Lab` / `--lab`)

```powershell
.\IR-Collect.ps1 -Lab -Auto -Dest http://collector:8000/     # POST the bundle to a lab collector
```
```bash
sudo ./ir-collect.sh --lab --auto -d 10.0.0.5                 # or a plain path / user@host:path
```

Lab mode changes four things vs a real engagement:
1. **Marks the evidence `EXERCISE`** (`00_metadata/intake.json` + `collection_info.json`) so training data is never mistaken for a real case.
2. **Read-only-media friendly.** Launched from a mounted ISO/CD it can't write next to itself; instead of the real-engagement "contamination" alarm it quietly resolves a **writable** output (see precedence below) and carries on.
3. **Detects the hypervisor + guest agent** (`00_metadata/environment_detect.txt`) and, if the evidence stays in-guest, prints the exact **host-side pull command** for that hypervisor.
4. **HTTP(S) egress** is enabled: `-Dest http://host:port/` PUTs/POSTs the sealed bundle to a collector.

**Writable-output precedence** (both OSes, so a read-only delivery never blocks collection):
`-Dest` you pass  →  a volume **labeled `EVIDENCE`/`IR-EVIDENCE`** (an attached evidence disk)  →
`$IR_OUT`/`%IR_OUT%`  →  `C:\ir_evidence` / `/var/tmp/ir_evidence` (leave-in-guest for a host-side pull).

## Getting the tool IN and evidence OUT — pick a channel

| Hypervisor | Load in + run + pull out | Guest prereq |
|---|---|---|
| **VMware** (ESXi/vCenter/Workstation) | `range/deploy-vmware.sh` (govc guest ops) | VMware Tools + guest creds |
| **Hyper-V** | `range/deploy-hyperv.ps1` (PowerShell Direct; Copy-VMFile) | Win 10/2016+ guest + creds; GSI |
| **VirtualBox** | `range/deploy-vbox.sh` (VBoxManage guestcontrol) | Guest Additions + guest creds |
| **QEMU/KVM / Proxmox** | `range/deploy-kvm.sh` (`qm guest exec` / `virsh` QGA) | qemu-guest-agent |
| **Any (network)** | `-Dest <IP|user@host:path|http://collector>` from inside the guest | guest network |
| **Read-only ISO** | attach the kit ISO; run `range/loader.*`; write to an `EVIDENCE`-labeled disk | — |
| **Snapshot / offline** | leave output on disk; instructor `snapshot` + `guestmount --ro` | — |

All four `deploy-*` helpers do the same four steps: **detect/target → upload kit → run collector in Lab mode
→ pull results to `./loot/<vm>/`**. They travel over the hypervisor channel, so **no guest network is
required** (except the generic network option). Build a `kit` archive of this repo (including `tools/`) first,
e.g. `zip -r kit.zip .` (Windows guest) or `tar czf kit.tgz .` (Linux guest), and pass it with `-k`.

### Examples
```bash
# VMware, whole set of Windows guests
export GOVC_URL=https://vcenter/sdk GOVC_USERNAME='lab\svc' GOVC_PASSWORD=*** GOVC_INSECURE=1
for vm in WIN01 WIN02 DC01; do
  range/deploy-vmware.sh -vm "$vm" -u 'LAB\Administrator' -p 'P@ss' -k kit.zip -o ./loot
done
```
```powershell
# Hyper-V, PowerShell Direct (no network in the guest at all)
range\deploy-hyperv.ps1 -VMName TRIAGE-WIN01 -KitZip .\kit.zip -Out .\loot
```
```bash
# Proxmox / KVM
range/deploy-kvm.sh -id 101 -o ./loot            # Linux guest, qemu-guest-agent
```

## The collector server (network egress)

`-Dest http://…` ships the sealed bundle with a raw HTTP body. Stand up the bundled receiver on the
analyst/collector box (isolated range network only — it has **no auth**):

```bash
python3 range/collector-server.py 8000 ./loot     # accepts PUT, raw POST, and multipart -> ./loot/
```
It matches what the collectors send (`Invoke-RestMethod -Put -InFile` / `curl -T`). Prefer an **attached
evidence disk** or a **shared folder** for large full-RAM/disk images; HTTP is best for the KB–MB triage
bundle. `nginx` with `dav_methods PUT` or `python3 -m uploadserver` (multipart) also work.

## In-guest detection (orchestration)

Run `range/ir-detect.ps1` / `range/ir-detect.sh` first to print `"<hypervisor> <agent flags>"`, so an
orchestrator can choose the matching `deploy-*` helper. The collector records the same info to
`00_metadata/environment_detect.txt` every run.

## Loader (ISO / share auto-launch)

When the kit is on a read-only ISO or a share and you just want to launch it from inside the guest:
```
D:\range\loader.ps1 -Auto -CaseId EXERCISE1        # Windows
/mnt/cdrom/range/loader.sh --auto -c EXERCISE1     # Linux
```
It finds the collector next to itself, resolves a writable output (evidence disk → `$IR_OUT` → default),
and runs Lab mode. Extra args pass straight through.

## Range conventions matched
Predictable naming (`<case>_<host>_<UTC>` + `SUMMARY.md` + `MANIFEST-SHA256` + `collection_info.json`),
a single results share/collector with per-host subdirs, idempotent exit-coded deploy helpers, and
read-only delivery decoupled from a writable evidence target — the same patterns used by
DetectionLab / GOAD / Ludus / Splunk Attack Range. **Everything here is for authorized training ranges.**
