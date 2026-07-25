#!/usr/bin/env bash
# ir-vm-lab.sh - headless multi-OS VM E2E for IR-Collect on rick/KVM (libvirt).
#
# Runs ON rick. For each target OS: builds a DISPOSABLE guest from a prepared cloud image
# (qcow2 overlay), boots it HEADLESS, waits on the qemu-guest-agent (BOUNDED - the readiness
# signal, NOT a blind ssh loop), runs the collector inside via `virsh guest-exec`, and pulls the
# sealed bundle back over a 9p shared dir (no ssh, no guest network needed for transport).
# Asserts intake.json + run_state.json + manifest, then tears the guest down.
#
# Channels (per the research):
#   Linux/BSD/illumos : qemu-guest-agent  -> guest-ping (ready) + guest-exec (run) ; 9p (files)
#   macOS             : no guest agent    -> SSH-after-ready (handled by a separate variant)
#
# Usage: ir-vm-lab.sh [--distro ubuntu] [--scenario A] [--mem 2048] [--vcpus 2] [--keep]
set -u
LAB="$HOME/irvmlab"; IMG="$LAB/images"; RUNS="$LAB/runs"; mkdir -p "$IMG" "$RUNS"
URI="qemu:///system"
DISTRO=ubuntu; SCEN=A; MEM=3072; VCPUS=2; KEEP=0
while [ $# -gt 0 ]; do case "$1" in
  --distro) DISTRO="$2"; shift 2;; --scenario) SCEN="$2"; shift 2;;
  --mem) MEM="$2"; shift 2;; --vcpus) VCPUS="$2"; shift 2;; --keep) KEEP=1; shift;;
  *) echo "unknown arg $1"; exit 2;; esac; done

# ---- per-distro base image config -------------------------------------------------
case "$DISTRO" in
  ubuntu) BASE_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
          BASE="$IMG/noble-server-cloudimg-amd64.img"; OSVARIANT="ubuntu24.04";;
  debian) BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
          BASE="$IMG/debian-12-genericcloud-amd64.qcow2"; OSVARIANT="debian12";;
  alma)   BASE_URL="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"
          BASE="$IMG/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2"; OSVARIANT="almalinux9";;
  fedora) BASE_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2"
          BASE="$IMG/Fedora-Cloud-Base-41.qcow2"; OSVARIANT="fedora41";;
  *) echo "unknown distro $DISTRO"; exit 2;; esac

RUNID="$(printf '%s' "${DISTRO}_$(date -u +%Y%m%d_%H%M%S)")"
RUN="$RUNS/$RUNID"; SHARE_IN="$RUN/share_in"; SHARE_OUT="$RUN/share_out"
mkdir -p "$SHARE_IN" "$SHARE_OUT"
# system libvirt runs guests as libvirt-qemu (uid 64055): it must be able to traverse to
# the disk images and WRITE the 9p output share. Open the path just enough for that.
chmod o+x "$HOME" "$LAB" "$RUNS" "$RUN" 2>/dev/null || true
chmod 0777 "$SHARE_OUT" 2>/dev/null || true
DOM="irvm-$RUNID"
log(){ echo "$(date -u +%H:%M:%S) | $*"; }

cleanup(){
  [ "$KEEP" = 1 ] && { log "--keep: leaving $DOM"; return; }
  virsh -c "$URI" destroy "$DOM" >/dev/null 2>&1
  virsh -c "$URI" undefine "$DOM" --nvram >/dev/null 2>&1
  rm -f "$RUN/overlay.qcow2" "$RUN/seed.img" 2>/dev/null
}
trap cleanup EXIT

# ---- 0) ensure the base cloud image is present (qemu-guest-agent is installed at
#         first boot via cloud-init packages: - the guest has working NAT internet) ----
[ -f "$BASE" ] || { log "downloading base $DISTRO ..."; curl -fL --retry 3 -o "$BASE" "$BASE_URL"; }

# ---- 1) disposable overlay + cloud-init seed ---------------------------------------
log "run $RUNID : overlay + seed"
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$RUN/overlay.qcow2" >/dev/null
qemu-img resize "$RUN/overlay.qcow2" 12G >/dev/null 2>&1
# stage the collector kit into the read-only share
cp "$LAB/kit/ir-collect.sh" "$SHARE_IN/" 2>/dev/null || { log "kit not staged at $LAB/kit"; exit 1; }

cat > "$RUN/user-data" <<CI
#cloud-config
hostname: irvm
package_update: true
packages:
  - qemu-guest-agent
users:
  - name: irlab
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: false
    plain_text_passwd: irlab
    shell: /bin/bash
ssh_pwauth: true
bootcmd:
  - [ mkdir, -p, /mnt/irkit, /mnt/irout ]
mounts:
  - [ irkit, /mnt/irkit, 9p, "trans=virtio,version=9p2000.L,ro,_netdev", "0", "0" ]
  - [ irout, /mnt/irout, 9p, "trans=virtio,version=9p2000.L,_netdev", "0", "0" ]
runcmd:
  - [ systemctl, enable, --now, qemu-guest-agent ]
  - [ sh, -c, "mount -a 2>/dev/null; touch /mnt/irout/CLOUDINIT_DONE" ]
CI
printf 'instance-id: %s\nlocal-hostname: irvm\n' "$RUNID" > "$RUN/meta-data"
cloud-localds "$RUN/seed.img" "$RUN/user-data" "$RUN/meta-data"

# ---- 2) define + boot headless with guest-agent channel + two 9p shares ------------
log "creating + booting headless domain $DOM"
chmod o+rx "$RUN" 2>/dev/null; chmod o+r "$RUN/overlay.qcow2" "$RUN/seed.img" 2>/dev/null || true
sudo virt-install --connect "$URI" --name "$DOM" \
  --memory "$MEM" --vcpus "$VCPUS" --cpu host-passthrough \
  --os-variant "$OSVARIANT" \
  --import \
  --disk "path=$RUN/overlay.qcow2,format=qcow2,bus=virtio" \
  --disk "path=$RUN/seed.img,device=cdrom" \
  --network network=default,model=virtio \
  --channel "unix,target_type=virtio,name=org.qemu.guest_agent.0" \
  --filesystem "source=$SHARE_IN,target=irkit,accessmode=mapped,readonly=on" \
  --filesystem "source=$SHARE_OUT,target=irout,accessmode=mapped" \
  --graphics none --noautoconsole --boot uefi 2>"$RUN/virtinstall.err" \
  || { log "virt-install failed:"; cat "$RUN/virtinstall.err"; exit 1; }

# ---- 3) BOUNDED readiness: qemu-guest-agent ping (NOT an ssh loop) -----------------
log "waiting for guest-agent (bound 300s) ..."
deadline=$(( $(date +%s) + 300 )); ready=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  if sudo virsh -c "$URI" qemu-agent-command "$DOM" '{"execute":"guest-ping"}' >/dev/null 2>&1; then
    ready=1; break; fi
  sleep 5
done
[ "$ready" = 1 ] || { log "FAIL: guest-agent never responded"; exit 1; }
log "guest-agent UP"

# ---- 4) run the collector via SSH (readiness already confirmed by guest-agent above).
#         Transport stays on the 9p share; SSH is only the synchronous RUN channel (blocks
#         until the collector finishes, closes stdin). This is the SAME ssh-after-ready
#         pattern used for the macOS guest (which has no guest agent). NOT a blind loop -
#         we only connect AFTER a real readiness signal. ----------------------------------
command -v sshpass >/dev/null 2>&1 || sudo -n apt-get install -y sshpass >/dev/null 2>&1
G="$(sudo virsh -c "$URI" domifaddr "$DOM" 2>/dev/null | grep -oE '192\.168\.122\.[0-9]+' | head -1)"
[ -n "$G" ] || { log "FAIL: no guest IP from domifaddr"; exit 1; }
SSHO="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"
log "guest IP $G ; waiting for sshd (bound 120s) ..."
deadline=$(( $(date +%s) + 120 )); sok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  sshpass -p irlab ssh $SSHO irlab@"$G" true 2>/dev/null && { sok=1; break; }; sleep 4
done
[ "$sok" = 1 ] || { log "FAIL: sshd not ready"; exit 1; }
log "running collector in guest (scenario $SCEN) ..."
EXITCODE="$(sshpass -p irlab ssh $SSHO irlab@"$G" \
  "sudo bash /mnt/irkit/ir-collect.sh --rapid-only --scenario $SCEN --host-role server -c VME2E -d /mnt/irout </dev/null >/mnt/irout/collector.log 2>&1; rc=\$?; sudo chmod -R a+rX /mnt/irout 2>/dev/null; echo \$rc" \
  2>/dev/null | tail -1)"
log "collector exit=$EXITCODE  (bundle written to 9p share)"

# ---- 5) assert the sealed bundle. It is on the host via 9p but owned by libvirt-qemu
#         with 700/600 modes (9p accessmode=mapped virtualises perms in xattrs, so an
#         in-guest chmod does not change the real host mode) -> read it as root. ---------
S(){ sudo "$@"; }   # bundle files are root/libvirt-qemu owned; read via sudo
BASE="$(S find "$SHARE_OUT" -maxdepth 1 -type d -name 'VME2E_*' | head -1)"
[ -n "$BASE" ] || { log "FAIL: no evidence dir on share"; sudo ls -la "$SHARE_OUT"; exit 1; }
fail(){ log "ASSERT FAIL: $1"; exit 1; }
S test -f "$BASE/00_metadata/intake.json" || fail "no intake.json"
S test -f "$BASE/99_logs/run_state.json" || fail "no run_state.json"
S test -f "$BASE/SUMMARY.md" || fail "no SUMMARY.md"
S test -f "$BASE/99_logs/MANIFEST-SHA256.csv" || S test -f "$BASE/99_logs/MANIFEST-SHA256.txt" || S test -f "$BASE/MANIFEST-SHA256.txt" || fail "no manifest"
S grep -q "\"scenario\":\"$SCEN\"" "$BASE/00_metadata/intake.json" || fail "scenario!=$SCEN"
VERDICT="$(S grep -o '"verdict":"[^"]*"' "$BASE/99_logs/run_state.json" | head -1)"
PLAN="$(S grep -o '"plan":"[^"]*"' "$BASE/00_metadata/intake.json" | head -1)"
NFILES="$(S find "$BASE" -type f | wc -l)"
log "PASS: $DISTRO VM E2E | scenario=$SCEN $PLAN $VERDICT exit=$EXITCODE files=$NFILES"
echo "IR_VM_LAB_RESULT distro=$DISTRO result=PASS scenario=$SCEN verdict=$VERDICT exit=$EXITCODE files=$NFILES"
