#!/usr/bin/env bash
# ir-vm-lab.sh - headless multi-OS VM E2E for IR-Collect on rick/KVM (libvirt).
#
# Runs ON rick. For each target OS: builds a DISPOSABLE guest from a prepared cloud image
# (qcow2 overlay), boots it HEADLESS, waits on a BOUNDED readiness signal (the guest's DHCP
# lease from libvirt dnsmasq - a real boot+network signal, NOT a blind ssh loop), then uses
# SSH-after-ready as the UNIVERSAL channel: scp the collector in, run it, scp the sealed
# bundle out. (scp works on every guest OS - no 9p/guest-agent kernel dependency; this is the
# same channel the macOS and FreeBSD guests use.) Asserts intake/run_state/manifest, tears down.
#
# Usage: ir-vm-lab.sh [--distro ubuntu] [--scenario A] [--mem 3072] [--vcpus 2] [--keep]
set -u
LAB="$HOME/irvmlab"; IMG="$LAB/images"; RUNS="$LAB/runs"; mkdir -p "$IMG" "$RUNS"
KEY="$LAB/lab_key"; [ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -f "$KEY" -q 2>/dev/null
PUBKEY="$(cat "$KEY.pub" 2>/dev/null)"
URI="qemu:///system"
DISTRO=ubuntu; SCEN=A; MEM=3072; VCPUS=2; KEEP=0
while [ $# -gt 0 ]; do case "$1" in
  --distro) DISTRO="$2"; shift 2;; --scenario) SCEN="$2"; shift 2;;
  --mem) MEM="$2"; shift 2;; --vcpus) VCPUS="$2"; shift 2;; --keep) KEEP=1; shift;;
  *) echo "unknown arg $1"; exit 2;; esac; done

case "$DISTRO" in
  ubuntu) BASE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
          BASE="$IMG/noble-server-cloudimg-amd64.img"; OSVARIANT="ubuntu24.04";;
  debian) BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
          BASE="$IMG/debian-12-genericcloud-amd64.qcow2"; OSVARIANT="debian12";;
  alma)   BASE_URL="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"
          BASE="$IMG/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"; OSVARIANT="almalinux9";;
  fedora) BASE_URL="https://dl.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2"
          BASE="$IMG/Fedora-Cloud-Base-42.qcow2"; OSVARIANT="fedora42";;
  freebsd) BASE_URL="https://download.freebsd.org/releases/VM-IMAGES/14.3-RELEASE/amd64/Latest/FreeBSD-14.3-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz"
          BASE="$IMG/FreeBSD-14.3-BASIC-CLOUDINIT-ufs.qcow2"; OSVARIANT="freebsd14.0";;
  *) echo "unknown distro $DISTRO"; exit 2;; esac

RUNID="${DISTRO}_$(date -u +%Y%m%d_%H%M%S)"
RUN="$RUNS/$RUNID"; SHARE_OUT="$RUN/out"; mkdir -p "$SHARE_OUT"
DOM="irvm-$RUNID"
log(){ echo "$(date -u +%H:%M:%S) | $*"; }
cleanup(){
  [ "$KEEP" = 1 ] && { log "--keep: leaving $DOM"; return; }
  sudo virsh -c "$URI" destroy "$DOM" >/dev/null 2>&1
  sudo virsh -c "$URI" undefine "$DOM" --nvram >/dev/null 2>&1
  rm -f "$RUN/overlay.qcow2" "$RUN/seed.img" 2>/dev/null
}
trap cleanup EXIT

# ---- 0) base image ----------------------------------------------------------------
if [ ! -f "$BASE" ]; then
  log "downloading base $DISTRO ..."
  case "$BASE_URL" in
    *.xz) curl -fL --retry 3 -o "$BASE.xz" "$BASE_URL" && unxz -f "$BASE.xz" || { log "download/decompress failed"; exit 1; };;
    *)    curl -fL --retry 3 -o "$BASE" "$BASE_URL" || { log "download failed"; exit 1; };;
  esac
fi

# ---- 1) disposable overlay + cloud-init seed (user + ssh only) ---------------------
log "run $RUNID : overlay + seed"
chmod o+x "$HOME" "$LAB" "$RUNS" "$RUN" 2>/dev/null || true
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$RUN/overlay.qcow2" >/dev/null
qemu-img resize "$RUN/overlay.qcow2" 12G >/dev/null 2>&1
chmod o+r "$RUN/overlay.qcow2" 2>/dev/null || true
cat > "$RUN/user-data" <<CI
#cloud-config
hostname: irvm
users:
  - name: irlab
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    ssh_authorized_keys:
      - $PUBKEY
ssh_pwauth: true
CI
printf 'instance-id: %s\nlocal-hostname: irvm\n' "$RUNID" > "$RUN/meta-data"
# FreeBSD base ships no bash (the collector is bash) and no sudo -> install them at first boot
if [ "$DISTRO" = freebsd ]; then printf 'packages:\n  - bash\n  - sudo\n' >> "$RUN/user-data"; fi
cloud-localds "$RUN/seed.img" "$RUN/user-data" "$RUN/meta-data"
chmod o+r "$RUN/seed.img" 2>/dev/null || true

# ---- 2) boot headless (virtio net for DHCP lease + ssh; no 9p, no guest-agent) -----
log "creating + booting headless domain $DOM"
sudo virt-install --connect "$URI" --name "$DOM" \
  --memory "$MEM" --vcpus "$VCPUS" --cpu host-passthrough --os-variant "$OSVARIANT" \
  --import \
  --disk "path=$RUN/overlay.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$RUN/seed.img,device=cdrom" \
  --network network=default,model=virtio \
  --graphics none --noautoconsole --boot uefi 2>"$RUN/virtinstall.err" \
  || { log "virt-install failed:"; cat "$RUN/virtinstall.err"; exit 1; }

# ---- 3) BOUNDED readiness: the guest's DHCP lease/IP (real boot+network signal) ----
SSHO="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"
log "waiting for guest IP (bound 420s) ..."
G=""; deadline=$(( $(date +%s) + 420 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  G="$(sudo virsh -c "$URI" domifaddr "$DOM" 2>/dev/null | grep -oE '192\.168\.122\.[0-9]+' | head -1)"
  [ -n "$G" ] && break; sleep 5
done
[ -n "$G" ] || { log "FAIL: guest never got an IP within timeout"; exit 1; }
log "guest IP $G ; waiting for sshd (bound 150s) ..."
deadline=$(( $(date +%s) + 150 )); sok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  ssh -i "$KEY" $SSHO irlab@"$G" true 2>/dev/null && { sok=1; break; }; sleep 4
done
[ "$sok" = 1 ] || { log "FAIL: sshd not ready"; exit 1; }

# ---- 4) UNIVERSAL channel: scp kit in, run, scp bundle out -------------------------
log "pushing collector + running (scenario $SCEN) ..."
scp -i "$KEY" $SSHO "$LAB/kit/ir-collect.sh" irlab@"$G":/tmp/ir-collect.sh >/dev/null 2>&1 \
  || { log "FAIL: scp kit in"; exit 1; }
EXITCODE="$(ssh -i "$KEY" $SSHO irlab@"$G" \
  "sudo bash /tmp/ir-collect.sh --rapid-only --scenario $SCEN --host-role server -c VME2E -d /tmp/vmout </dev/null >/tmp/collector.log 2>&1; rc=\$?; sudo chmod -R a+rX /tmp/vmout /tmp/collector.log 2>/dev/null; echo \$rc" \
  2>/dev/null | tail -1)"
log "collector exit=$EXITCODE ; pulling bundle ..."
scp -i "$KEY" $SSHO -r irlab@"$G":/tmp/vmout "$SHARE_OUT/" >/dev/null 2>&1
scp -i "$KEY" $SSHO irlab@"$G":/tmp/collector.log "$SHARE_OUT/" >/dev/null 2>&1

# ---- 5) assert the sealed bundle (now redzeplin-owned via scp) ---------------------
BASE_D="$(find "$SHARE_OUT" -type d -name 'VME2E_*' | head -1)"
[ -n "$BASE_D" ] || { log "FAIL: no evidence dir pulled"; ls -laR "$SHARE_OUT" | head -20; exit 1; }
fail(){ log "ASSERT FAIL: $1"; exit 1; }
[ -f "$BASE_D/00_metadata/intake.json" ] || fail "no intake.json"
[ -f "$BASE_D/99_logs/run_state.json" ] || fail "no run_state.json"
[ -f "$BASE_D/SUMMARY.md" ] || fail "no SUMMARY.md"
find "$BASE_D" -iname 'MANIFEST-SHA256.*' 2>/dev/null | grep -q . || fail "no manifest"
grep -q "\"scenario\":\"$SCEN\"" "$BASE_D/00_metadata/intake.json" || fail "scenario!=$SCEN"
VERDICT="$(grep -o '"verdict":"[^"]*"' "$BASE_D/99_logs/run_state.json" | head -1)"
PLAN="$(grep -o '"plan":"[^"]*"' "$BASE_D/00_metadata/intake.json" | head -1)"
NFILES="$(find "$BASE_D" -type f | wc -l)"
log "PASS: $DISTRO VM E2E | scenario=$SCEN $PLAN $VERDICT exit=$EXITCODE files=$NFILES"
echo "IR_VM_LAB_RESULT distro=$DISTRO result=PASS scenario=$SCEN verdict=$VERDICT exit=$EXITCODE files=$NFILES"
