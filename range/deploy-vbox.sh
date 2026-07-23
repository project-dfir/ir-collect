#!/usr/bin/env bash
# Deploy IR-Collect into a VirtualBox guest via Guest Additions (VBoxManage guestcontrol),
# run it, pull results. NO guest network required.
#
# Prereqs: VBoxManage on the host; Guest Additions running in the guest; GUEST-OS credentials.
# Build the kit first (zip/tgz of this repo incl. tools/), then:
#   ./deploy-vbox.sh -vm TRIAGE-WIN01 -u Administrator -p 'P@ss' -k kit.zip -o ./loot
#   ./deploy-vbox.sh -vm TRIAGE-LNX01 -u root -p 'P@ss' -k kit.tgz --linux
set -eu
OUT="./loot"; OS=win; VM=""; U=""; P=""; KIT=""
while [ $# -gt 0 ]; do case "$1" in
  -vm) VM="$2"; shift 2;; -u) U="$2"; shift 2;; -p) P="$2"; shift 2;;
  -k) KIT="$2"; shift 2;; -o) OUT="$2"; shift 2;; --linux) OS=linux; shift;;
  *) echo "unknown arg: $1"; exit 1;; esac; done
[ -n "$VM" ] && [ -n "$KIT" ] || { echo "usage: -vm VM -u USER -p PASS -k KIT [-o OUT] [--linux]"; exit 1; }
GC() { VBoxManage guestcontrol "$VM" --username "$U" --password "$P" "$@"; }
mkdir -p "$OUT/$VM"

echo "[*] $VM: uploading kit + launching collector (VBoxManage guestcontrol)"
if [ "$OS" = win ]; then
  GC mkdir --parents 'C:\IR'
  GC copyto "$KIT" 'C:\IR\kit.zip'
  GC run --exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' --wait-stdout -- \
     powershell -NoProfile -Command "Expand-Archive -Force C:\IR\kit.zip C:\IR\kit"
  GC run --exe 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' --wait-stdout -- \
     powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\IR\kit\IR-Collect.ps1' -Lab -Auto -Dest 'C:\IR\out'
  GC copyfrom --recursive 'C:\IR\out' "$OUT/$VM/collected"
else
  GC mkdir --parents /opt/ir
  GC copyto "$KIT" /opt/ir/kit.tgz
  GC run --exe /bin/sh --wait-stdout -- sh -c 'cd /opt/ir && tar xzf kit.tgz && bash ./ir-collect.sh --lab --auto -d /opt/ir/out'
  GC copyfrom --recursive /opt/ir/out "$OUT/$VM/collected"
fi
echo "[*] done -> $OUT/$VM/"
