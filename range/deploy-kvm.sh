#!/usr/bin/env bash
# Deploy IR-Collect into a QEMU/KVM guest via the qemu-guest-agent (Proxmox `qm` or libvirt `virsh`).
# NO guest network required, but QGA file transfer is base64/chunked (~48 MB/round) - for a large
# kit prefer delivering it on a SHARED FOLDER (virtiofs/9p) or an attached ISO, then just RUN it here.
#
# Prereqs: qemu-guest-agent installed+running in the guest; run on the KVM/Proxmox host.
# Usage (Proxmox):  ./deploy-kvm.sh -id 101 -o ./loot [--win]     # kit already staged in guest
#         (libvirt): ./deploy-kvm.sh -dom triage01 -o ./loot [--win]
set -eu
OUT="./loot"; WIN=0; ID=""; DOM=""
while [ $# -gt 0 ]; do case "$1" in
  -id) ID="$2"; shift 2;; -dom) DOM="$2"; shift 2;; -o) OUT="$2"; shift 2;; --win) WIN=1; shift;;
  *) echo "unknown arg: $1"; exit 1;; esac; done
mkdir -p "$OUT/${ID:-$DOM}"

run_win='powershell -NoProfile -ExecutionPolicy Bypass -File C:\IR\kit\IR-Collect.ps1 -Lab -Auto -Dest C:\IR\out'
run_lnx='cd /opt/ir && ./ir-collect.sh --lab --auto -d /opt/ir/out'

if command -v qm >/dev/null 2>&1 && [ -n "$ID" ]; then
  echo "[*] Proxmox: qm guest exec on VMID $ID"
  qm guest cmd "$ID" get-osinfo >/dev/null || { echo "guest agent not responding on $ID"; exit 1; }
  if [ "$WIN" = 1 ]; then
    qm guest exec "$ID" -- cmd.exe /c "$run_win"
    echo "[!] Windows: pull C:\\IR\\out via a shared folder or 'guestmount' on the disk image."
  else
    qm guest exec "$ID" -- /bin/sh -c "$run_lnx"
    # pull the newest bundle by streaming base64 back through the agent
    b64=$(qm guest exec "$ID" -- /bin/sh -c 'f=$(ls -t /opt/ir/out/*.tar.gz 2>/dev/null | head -1); [ -n "$f" ] && base64 -w0 "$f"' 2>/dev/null | sed -n 's/.*"out-data":[ ]*"\([^"]*\)".*/\1/p')
    if [ -n "$b64" ]; then echo "$b64" | base64 -d > "$OUT/$ID/bundle.tar.gz" && echo "[*] pulled -> $OUT/$ID/bundle.tar.gz"
    else echo "[!] auto-pull failed (bundle >48MB?). Retrieve /opt/ir/out via shared folder or: guestmount -a disk.qcow2 --ro /mnt"; fi
  fi
elif command -v virsh >/dev/null 2>&1 && [ -n "$DOM" ]; then
  echo "[*] libvirt: qemu-agent-command on domain $DOM"
  path=$([ "$WIN" = 1 ] && echo 'cmd.exe' || echo '/bin/sh')
  arg=$([ "$WIN" = 1 ] && echo "\"/c\",\"$run_win\"" || echo "\"-c\",\"$run_lnx\"")
  virsh qemu-agent-command "$DOM" "{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"$path\",\"arg\":[$arg],\"capture-output\":true}}"
  echo "[!] poll with guest-exec-status; then pull the bundle via shared folder or: guestmount -a <disk> --ro /mnt"
else
  echo "need 'qm -id <vmid>' (Proxmox) or 'virsh -dom <domain>' (libvirt) with qemu-guest-agent"; exit 1
fi
echo "[*] done -> $OUT/${ID:-$DOM}/"
