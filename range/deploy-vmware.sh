#!/usr/bin/env bash
# Deploy IR-Collect into a VMware guest over VMware Tools guest operations (govc), run it, pull results.
# Travels over the hypervisor channel - NO guest network required.
#
# Prereqs: govc installed; VMware Tools running in the guest; valid GUEST-OS credentials;
#          GOVC_URL / GOVC_USERNAME / GOVC_PASSWORD exported (GOVC_INSECURE=1 for self-signed).
# Build the kit first (a zip/tgz of this repo incl. tools/), then:
#   export GOVC_URL=https://vcenter/sdk GOVC_USERNAME=... GOVC_PASSWORD=...
#   ./deploy-vmware.sh -vm TRIAGE-WIN01 -u 'LAB\Administrator' -p 'P@ss' -k kit.zip -o ./loot
#   ./deploy-vmware.sh -vm TRIAGE-LNX01 -u root -p 'P@ss' -k kit.tgz --linux
set -eu
KIT=""; OUT="./loot"; OS=win; VM=""; GU=""; GP=""
while [ $# -gt 0 ]; do case "$1" in
  -vm) VM="$2"; shift 2;; -u) GU="$2"; shift 2;; -p) GP="$2"; shift 2;;
  -k) KIT="$2"; shift 2;; -o) OUT="$2"; shift 2;; --linux) OS=linux; shift;;
  *) echo "unknown arg: $1"; exit 1;; esac; done
[ -n "$VM" ] && [ -n "$KIT" ] || { echo "usage: -vm VM -u USER -p PASS -k KIT [-o OUT] [--linux]"; exit 1; }
GA="-vm $VM -l $GU:$GP"
mkdir -p "$OUT/$VM"

echo "[*] $VM: uploading kit + launching collector (VMware Tools guest ops)"
if [ "$OS" = win ]; then
  govc guest.mkdir  $GA -p 'C:\IR' || true
  govc guest.upload $GA -f "$KIT" 'C:\IR\kit.zip'
  govc guest.start  $GA 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -Command "Expand-Archive -Force C:\IR\kit.zip C:\IR\kit" >/dev/null
  pid=$(govc guest.start $GA 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File 'C:\IR\kit\IR-Collect.ps1' -Lab -Auto -Dest 'C:\IR\out')
  echo "[*] guest PID $pid - waiting for exit"
  while govc guest.ps $GA -p "$pid" -X -e 2>/dev/null | grep -q .; do sleep 5; done
  govc guest.download $GA -f 'C:\IR\out' "$OUT/$VM/collected" 2>/dev/null || \
    echo "[!] download: the collector zips to C:\\IR\\out - pull the produced .zip with 'govc guest.download'"
else
  govc guest.mkdir  $GA -p /opt/ir || true
  govc guest.upload $GA -f "$KIT" /opt/ir/kit.tgz
  pid=$(govc guest.start $GA /bin/sh -c 'cd /opt/ir && tar xzf kit.tgz && bash ./ir-collect.sh --lab --auto -d /opt/ir/out')
  while govc guest.ps $GA -p "$pid" -X -e 2>/dev/null | grep -q .; do sleep 5; done
  govc guest.download $GA -f /opt/ir/out "$OUT/$VM/collected" 2>/dev/null || \
    echo "[!] pull the produced .tar.gz from /opt/ir/out with 'govc guest.download'"
fi
echo "[*] done -> $OUT/$VM/"
