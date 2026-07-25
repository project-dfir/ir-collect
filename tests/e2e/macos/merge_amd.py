#!/usr/bin/env python3
# Merge AMD_Vanilla kernel patches into the OSX-KVM OpenCore config.plist for a Zen2 Threadripper.
# Run with the VM OFF, after mounting the EFI at /mnt/oc.
import plistlib

CORES = 2  # == CPU_CORES in boot-macOS-headless.sh (physical cores, NOT threads)
AMD = "/tmp/amd.plist"
CFG = "/mnt/oc/EFI/OC/config.plist"

amd = plistlib.load(open(AMD, "rb"))
amd_patches = amd["Kernel"]["Patch"]

# set the core-count byte (index 1 of Replace) on every cpuid_cores_per_package row
for p in amd_patches:
    if "cpuid_cores_per_package" in p.get("Comment", ""):
        r = bytearray(p["Replace"]); r[1] = CORES; p["Replace"] = bytes(r)

cfg = plistlib.load(open(CFG, "rb"))
cfg.setdefault("Kernel", {}).setdefault("Patch", [])
have = {p.get("Comment") for p in cfg["Kernel"]["Patch"]}
added = 0
for p in amd_patches:
    if p.get("Comment") not in have:
        cfg["Kernel"]["Patch"].append(p); added += 1

# verbose boot so a panic renders as text on the framebuffer (screenshot-visible)
nv = cfg.setdefault("NVRAM", {}).setdefault("Add", {}).setdefault(
    "7C436110-AB2A-4BBB-A880-FE41995C9F82", {})
ba = nv.get("boot-args", "")
ba = (ba if isinstance(ba, str) else "")
for tok in ("-v", "keepsyms=1", "debug=0x100"):
    if tok not in ba:
        ba = (ba + " " + tok).strip()
nv["boot-args"] = ba

plistlib.dump(cfg, open(CFG, "wb"))
print(f"added {added} AMD patches, core byte=0x{CORES:02x}, boot-args='{ba}'")
