#!/usr/bin/env bash
# Mobile unit tests: stub adb + libimobiledevice binaries on PATH (record argv, return canned
# output) and drive mobile-collect.sh to validate command CONSTRUCTION + intake/ledger WITHOUT
# any real device. This is how we cover the iOS ACQUISITION branch (hardware-gated for real) and
# the off-device/lost path. No emulator, no phone.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # repo root
COLLECTOR="$ROOT/mobile/mobile-collect.sh"
FAKE="$(mktemp -d)"; LOG="$FAKE/calls.log"; : > "$LOG"

# mkbin NAME BODY...  -> a fake exe that logs its argv then runs BODY
mkbin() {
  local n="$1"; shift
  { printf '#!/usr/bin/env bash\n'
    printf 'echo "%s $*" >> %q\n' "$n" "$LOG"
    printf '%s\n' "$@"
  } > "$FAKE/$n"
  chmod +x "$FAKE/$n"
}

# --- fake libimobiledevice (iOS) ---
mkbin idevice_id 'case "$*" in *-l*) echo 00008030-FAKEUDID0001;; *) echo "idevice_id 1.3.0";; esac'
mkbin idevicepair 'echo "SUCCESS: Paired with device"'
mkbin ideviceinfo 'echo "ProductType: iPhone12,1"; echo "ProductVersion: 16.5"'
mkbin ideviceinstaller 'echo "com.apple.mobilesafari - Safari"'
mkbin ideviceprovision 'echo "(no provisioning profiles)"'
mkbin idevicediagnostics 'echo "diagnostics: ok"'
mkbin idevicecrashreport 'exit 0'
mkbin idevicesyslog 'sleep 0.2; exit 0'
mkbin idevicebackup2 'for a in "$@"; do case "$a" in backup) d="${@: -1}"; mkdir -p "$d/00008030-FAKEUDID0001"; echo "Backup Successful";; esac; done; echo ok'
mkbin mvt-ios 'echo "mvt-ios ok"'
mkbin ileapp 'echo "ileapp ok"'
# --- fake adb (Android) ---
mkbin adb 'case "$*" in
  *"start-server"*) : ;;
  *devices*) printf "List of devices attached\nemulator-5554\tdevice\n";;
  *get-state*) echo device;;
  *"version"*) echo "Android Debug Bridge version 1.0.41";;
  *"ro.build.version.sdk"*) echo 33;;
  *) echo "";;
esac'
mkbin mvt-android 'echo "mvt-android ok"'

export PATH="$FAKE:$PATH"
fail() { echo "FAIL: $1"; echo "--- call log ---"; cat "$LOG"; exit 1; }

echo "===== TEST 1: iOS acquisition command construction (scenario spyware) ====="
O1="$(mktemp -d)"
"$COLLECTOR" --ios --serial 00008030-FAKEUDID0001 --auto --scenario spyware -c UTIOS -d "$O1" >/dev/null 2>&1
B1="$(find "$O1" -maxdepth 1 -type d -name 'UTIOS_*' | head -1)"
[ -n "$B1" ] || fail "no iOS bundle dir"
[ -f "$B1/meta/collection_info.json" ] || fail "no collection_info.json"
[ -f "$B1/logs/run_state.json" ] || fail "no run_state.json (ledger reducer)"
grep -q '"scenario":"spyware"' "$B1/meta/collection_info.json" || fail "scenario not spyware in intake"
grep -q 'idevicebackup2.*encryption on' "$LOG" || fail "encrypted-backup enable not invoked"
grep -q 'idevicebackup2 .*backup' "$LOG" || fail "idevicebackup2 backup not invoked"
grep -q 'idevicepair' "$LOG" || fail "pairing not invoked"
grep -q 'ideviceinfo' "$LOG" || fail "device identity not queried"
echo "  OK: encrypted idevicebackup2 backup + pair + identity constructed; scenario=spyware sealed"

echo "===== TEST 2: off-device (lost/stolen) checklist path ====="
O2="$(mktemp -d)"
"$COLLECTOR" --ios --serial X --auto --scenario lost -c UTLOST -d "$O2" >/dev/null 2>&1
B2="$(find "$O2" -maxdepth 1 -type d -name 'UTLOST_*' | head -1)"
[ -n "$B2" ] || fail "no lost bundle dir"
[ -f "$B2/artifacts/OFF_DEVICE_CHECKLIST.md" ] || fail "off-device checklist not written"
grep -q 'Find My' "$B2/artifacts/OFF_DEVICE_CHECKLIST.md" || fail "checklist content missing"
echo "  OK: off-device workflow wrote the lost/stolen checklist (no tethered acquisition attempted)"

echo "MOBILE UNIT TESTS PASS (iOS acquisition-branch + off-device; Android is covered by the emulator E2E)"
