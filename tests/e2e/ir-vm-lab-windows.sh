#!/usr/bin/env bash
# ir-vm-lab-windows.sh - headless Windows Server 2022 DOMAIN CONTROLLER E2E on rick/KVM.
#
# The ENTERPRISE test: unattended-install Windows Server 2022 (virtio), auto-promote it to a
# Domain Controller (lab.local), then drive IR-Collect.ps1 with -HostRole domain-controller so
# the collector's Active Directory enumeration branch (Job-AD) actually runs on a real DC.
# Readiness is gated on the DC being up (DC_READY marker, written only after Get-ADDomain/ADWS),
# not just a port. Drive channel = Windows OpenSSH (scp + ssh powershell). Golden-image friendly.
#
# Usage: ir-vm-lab-windows.sh [--scenario 6] [--mem 4096] [--vcpus 4] [--keep] [--build-only]
set -u
LAB="$HOME/irvmlab"; ISO="$LAB/iso"; RUNS="$LAB/runs"; DC="$LAB/win-dc"
mkdir -p "$RUNS" "$DC"
URI="qemu:///system"
KEY="$LAB/lab_key"; [ -f "$KEY" ] || ssh-keygen -t ed25519 -N '' -f "$KEY" -q 2>/dev/null
PUBKEY="$(cat "$KEY.pub")"
SERVER_ISO="$ISO/winsrv2022-eval.iso"; VIRTIO_ISO="$ISO/virtio-win.iso"
SCEN=6; MEM=4096; VCPUS=4; KEEP=0; BUILD_ONLY=0
while [ $# -gt 0 ]; do case "$1" in
  --scenario) SCEN="$2"; shift 2;; --mem) MEM="$2"; shift 2;; --vcpus) VCPUS="$2"; shift 2;;
  --keep) KEEP=1; shift;; --build-only) BUILD_ONLY=1; shift;; *) echo "unknown $1"; exit 2;; esac; done

RUNID="windc_$(date -u +%Y%m%d_%H%M%S)"; RUN="$RUNS/$RUNID"; OUT="$RUN/out"
mkdir -p "$OUT"; DOM="irvm-$RUNID"
log(){ echo "$(date -u +%H:%M:%S) | $*"; }
SSHO="-i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8"
cleanup(){ [ "$KEEP" = 1 ] && { log "--keep: leaving $DOM"; return; }
  sudo virsh -c "$URI" destroy "$DOM" >/dev/null 2>&1; sudo virsh -c "$URI" undefine "$DOM" --nvram >/dev/null 2>&1
  rm -f "$RUN/install.qcow2" 2>/dev/null; }
trap cleanup EXIT

[ -f "$SERVER_ISO" ] || { log "FAIL: server ISO missing $SERVER_ISO"; exit 1; }
[ -f "$VIRTIO_ISO" ] || { log "FAIL: virtio ISO missing"; exit 1; }
[ -f "$DC/IR-Collect.ps1" ] || { log "FAIL: stage IR-Collect.ps1 into $DC first"; exit 1; }

# ---- 1) build the seed ISO (autounattend + setup scripts + collector) --------------
log "building seed ISO (autounattend + ir-setup + promote-dc + collector) ..."
SEED="$RUN/seed"; mkdir -p "$SEED"
cp "$DC/autounattend.xml" "$DC/promote-dc.ps1" "$DC/IR-Collect.ps1" "$SEED/"
# inject the lab pubkey into ir-setup.ps1
sed "s#__PUBKEY__#$PUBKEY#" "$DC/ir-setup.ps1" > "$SEED/ir-setup.ps1"
genisoimage -o "$RUN/seed.iso" -V IRSEED -J -r -quiet "$SEED"/* || { log "FAIL: seed iso"; exit 1; }
chmod o+r "$RUN/seed.iso" 2>/dev/null

# ---- 2) install disk + headless unattended install --------------------------------
qemu-img create -f qcow2 "$RUN/install.qcow2" 60G >/dev/null
chmod o+x "$HOME" "$LAB" "$RUNS" "$RUN" 2>/dev/null; chmod o+r "$RUN/install.qcow2" 2>/dev/null
log "creating VM $DOM + starting unattended Server 2022 install (headless) ..."
sudo virt-install --connect "$URI" --name "$DOM" \
  --memory "$MEM" --vcpus "$VCPUS" --cpu host-passthrough --os-variant win2k22 \
  --disk "path=$RUN/install.qcow2,format=qcow2,bus=virtio" \
  --cdrom "$SERVER_ISO" \
  --disk "path=$VIRTIO_ISO,device=cdrom" \
  --disk "path=$RUN/seed.iso,device=cdrom" \
  --network network=default,model=virtio \
  --graphics vnc --noautoconsole --boot uefi \
  --events on_poweroff=destroy,on_reboot=restart,on_crash=destroy \
  --wait 0 2>"$RUN/virtinstall.err" || true
sudo virsh -c "$URI" list --all --name | grep -q "$DOM" || { log "FAIL: domain not created:"; cat "$RUN/virtinstall.err"; exit 1; }
# Windows UEFI install ISO prints "Press any key to boot from CD or DVD" and waits for a keypress;
# headless nobody presses it, so it falls through to "No bootable device". Send ENTER repeatedly
# for the first ~30s to boot the installer.
( for _k in $(seq 1 30); do sudo virsh -c "$URI" send-key "$DOM" KEY_ENTER >/dev/null 2>&1; sleep 1; done ) &
log "install running (Server install ~20-30m + DC promo ~5-8m; reboots several times) ..."
[ "$BUILD_ONLY" = 1 ] && { log "--build-only: leaving install running"; KEEP=1; exit 0; }

# ---- 3) BOUNDED readiness: wait for DC_READY (written only after Get-ADDomain/ADWS up) ----
log "waiting for guest IP + sshd + DC promotion (bound 60m) ..."
deadline=$(( $(date +%s) + 3600 )); G=""; DCUP=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  [ -z "$G" ] && G="$(sudo virsh -c "$URI" domifaddr "$DOM" 2>/dev/null | grep -oE '192\.168\.122\.[0-9]+' | head -1)"
  if [ -n "$G" ]; then
    if ssh $SSHO Administrator@"$G" "if (Test-Path C:\\Windows\\Temp\\DC_READY){exit 0}else{exit 1}" 2>/dev/null; then DCUP=1; break; fi
  fi
  sleep 20
done
[ "$DCUP" = 1 ] || { log "FAIL: DC not ready within 60m (IP=${G:-none})"; exit 1; }
log "DC UP at $G ; driving collector (scenario $SCEN, host-role domain-controller) ..."

# ---- 4) drive IR-Collect.ps1 on the DC (Auto -> exercises Job-AD enumeration) -------
ssh $SSHO Administrator@"$G" "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\irlab\\IR-Collect.ps1 -Auto -Scenario $SCEN -HostRole domain-controller -CaseId VMDC -Dest C:\\vmout" 2>/dev/null
log "collector done ; pulling bundle ..."
scp $SSHO -r Administrator@"$G":C:/vmout "$OUT/" >/dev/null 2>&1

# ---- 5) assert the sealed bundle incl. the AD-enumeration output --------------------
BASE_D="$(find "$OUT" -type d -name 'VMDC_*' | head -1)"
[ -n "$BASE_D" ] || { log "FAIL: no evidence dir pulled"; ls -laR "$OUT" | head; exit 1; }
fail(){ log "ASSERT FAIL: $1"; exit 1; }
[ -f "$BASE_D/00_metadata/intake.json" ] || fail "no intake.json"
[ -f "$BASE_D/99_logs/run_state.json" ] || fail "no run_state.json"
grep -qE '"host_role": *"domain-controller"' "$BASE_D/00_metadata/intake.json" || fail "host_role != domain-controller"
grep -qE '"scenario": *"6"' "$BASE_D/00_metadata/intake.json" || fail "scenario != 6"
ADFILES="$(find "$BASE_D/06_activedirectory" -type f 2>/dev/null | wc -l)"
[ "$ADFILES" -gt 0 ] || fail "AD enumeration produced no files (Job-AD did not run on the DC)"
VERDICT="$(grep -o '"verdict":"[^"]*"' "$BASE_D/99_logs/run_state.json" | head -1)"
NFILES="$(find "$BASE_D" -type f | wc -l)"
log "PASS: Windows Server 2022 DC E2E | host-role=domain-controller scenario=$SCEN AD_files=$ADFILES $VERDICT total_files=$NFILES"
echo "IR_VM_LAB_RESULT distro=winsrv2022-dc result=PASS host_role=domain-controller ad_files=$ADFILES verdict=$VERDICT files=$NFILES"
