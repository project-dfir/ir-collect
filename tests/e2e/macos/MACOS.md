# macOS VM testing — status & honest verdict

## What works
- **macOS collector (Darwin branch) is validated on REAL Apple hardware** via the GitHub Actions
  CI smoke matrix (.github/workflows/smoke.yml): macos-latest (Apple Silicon) + macos-15-intel,
  both green. License-clean, better coverage than a Hackintosh VM.
- **macOS OpenCore boots on our AMD Threadripper (rick)** via kholia/OSX-KVM + AMD_Vanilla:
  the OpenCore picker renders and the installer kernel+kexts load through to EXITBS:START
  (UEFI->XNU handoff). rick setup: ~/irvmlab/macos/OSX-KVM (Sonoma BaseSystem + target disk),
  AMD_Vanilla patches merged into config.plist via merge_amd.py (core-count byte=2),
  -cpu Haswell-noTSX,...,vendor=GenuineIntel, QEMU monitor socket for headless screendump.

## What does NOT work (and why it is not pursued further)
- **XNU kernel panics at the very start of init** on the AMD host (frozen at EXITBS:START, no
  kernel console output) - the notoriously fiddly AMD-Hackintosh step; uncertain, deep tuning.
- **Even if XNU booted, the installer is a GUI** (Recovery -> Disk Utility -> Install -> Setup
  Assistant). No unattended macOS install exists; only a VNC-assisted install -> golden-image ->
  qcow2-overlay clones. Cannot be fully headless-automated like the Windows-DC/Linux/FreeBSD E2Es.

## Verdict
For a forensic collector, CI on real Apple hardware IS the correct macOS coverage (license-clean,
genuine Macs, already green). A bootable macOS VM on our AMD hardware is a separate, uncertain
Hackintosh project whose end state (a GUI install) still is not automatable. Recommendation: rely
on the CI macOS validation; treat the OSX-KVM boot here as a proven-to-picker lab a human could
finish via VNC if a local macOS VM is ever needed.
