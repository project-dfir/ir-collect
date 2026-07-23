#!/usr/bin/env bash
# mobile-collect.sh - open-source mobile-device triage collector (Android + iOS).
#
# Runs on the EXAMINER WORKSTATION (Linux / macOS / WSL / Git-Bash) with the device tethered over
# USB - NOT on the phone. Doctrine: acquire logically with adb / idevicebackup2, then analyze
# OFFLINE with MVT / iLEAPP / ALEAPP (MVT no longer touches live devices). Open-source only; the
# honest ceiling is LOGICAL / non-root acquisition (physical/full-FS = jailbreak or proprietary).
#
# Tools it drives (install via fetch-mobile-tools.sh):
#   Android : adb (platform-tools), androidqf (2nd acquirer), mvt-android, aleapp
#   iOS     : libimobiledevice (idevice*), mvt-ios, ileapp
#
# Usage:
#   ./mobile-collect.sh -c CASE001 -d /evidence [--android|--ios] [--serial ID] [--auto]
#                       [--mvt] [--analyze] [--backup-pass PW] [--faraday] [--isolate]
#                       [--allow-root] [--authorizer NAME] [--legal TEXT] [--scope TEXT]
#   Defaults: auto-detect platform + device; interactive doctrine gate; acquire only (add --analyze
#             to run MVT/iLEAPP/ALEAPP). Encrypted iOS backup password defaults to the case id.
set -u

# ---------------------------------------------------------------------------
# args
# ---------------------------------------------------------------------------
DEST="."; CASE="MOB"; PLATFORM=""; SERIAL=""; AUTO=0; DO_MVT=0; ANALYZE=0
BACKUP_PASS=""; FARADAY=0; ISOLATE=0; ALLOW_ROOT=0
AUTHORIZER=""; LEGAL=""; SCOPE=""
while [ $# -gt 0 ]; do case "$1" in
  -d|--dest)       DEST="$2"; shift 2;;
  -c|--case)       CASE="$2"; shift 2;;
  --android)       PLATFORM=android; shift;;
  --ios)           PLATFORM=ios; shift;;
  --serial|--udid) SERIAL="$2"; shift 2;;
  --auto)          AUTO=1; shift;;
  --mvt|--analyze) DO_MVT=1; ANALYZE=1; shift;;
  --backup-pass)   BACKUP_PASS="$2"; shift 2;;
  --faraday)       FARADAY=1; shift;;
  --isolate)       ISOLATE=1; shift;;
  --allow-root)    ALLOW_ROOT=1; shift;;
  --authorizer)    AUTHORIZER="$2"; shift 2;;
  --legal)         LEGAL="$2"; shift 2;;
  --scope)         SCOPE="$2"; shift 2;;
  -h|--help)       grep '^# ' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done
[ -z "$BACKUP_PASS" ] && BACKUP_PASS="$CASE"

now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; }
STAMP="$(date -u +%Y%m%d_%H%M%SZ)"
EXAMINER="$(id -un 2>/dev/null || echo examiner)"
OS="$(uname -s 2>/dev/null || echo unknown)"
STEP=0

# ---------------------------------------------------------------------------
# device detection (auto platform + serial)
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
detect() {
  if [ -z "$PLATFORM" ] || [ "$PLATFORM" = android ]; then
    if have adb; then adb start-server >/dev/null 2>&1
      AND_LIST="$(adb devices | awk 'NR>1 && $2=="device"{print $1}')"
      [ -n "$AND_LIST" ] && [ -z "$PLATFORM" ] && PLATFORM=android
    fi
  fi
  if [ -z "$PLATFORM" ] || [ "$PLATFORM" = ios ]; then
    if have idevice_id; then IOS_LIST="$(idevice_id -l 2>/dev/null)"
      [ -n "$IOS_LIST" ] && [ -z "$PLATFORM" ] && PLATFORM=ios
    fi
  fi
}
detect

if [ -z "$PLATFORM" ]; then
  echo "No device detected. Connect an UNLOCKED device over USB and enable USB debugging (Android)"
  echo "or tap 'Trust' (iOS). Prereqs: run ./fetch-mobile-tools.sh. Force with --android / --ios."
  exit 2
fi

# ---------------------------------------------------------------------------
# output layout + logs
# ---------------------------------------------------------------------------
if [ -z "$SERIAL" ]; then
  [ "$PLATFORM" = android ] && SERIAL="$(echo "${AND_LIST:-}" | head -1)"
  [ "$PLATFORM" = ios ]     && SERIAL="$(echo "${IOS_LIST:-}" | head -1)"
fi
[ -z "$SERIAL" ] && { echo "No $PLATFORM device serial/UDID found."; exit 2; }

SAFE_SERIAL="$(echo "$SERIAL" | tr -c 'A-Za-z0-9._-' '_')"
OUT="$DEST/${CASE}_${PLATFORM}_${SAFE_SERIAL}_${STAMP}"
mkdir -p "$OUT"/{meta,logs,artifacts,apks,dumpsys,reports,detection} 2>/dev/null || { echo "cannot create $OUT"; exit 1; }
AUDIT="$OUT/logs/audit.log"; CMDLOG="$OUT/logs/command.log"; HASHES="$OUT/meta/hashes.csv"
: > "$AUDIT"; : > "$CMDLOG"; echo "sha256,size,path" > "$HASHES"
log()  { echo "$(now_utc) | $*" | tee -a "$AUDIT"; }
hashf() { [ -s "$1" ] || return 0; local h s; h="$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)"; s="$(stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null)"; echo "${h:-ERR},${s:-?},${1#$OUT/}" >> "$HASHES"; }
hashtree() { find "$1" -type f 2>/dev/null | while IFS= read -r f; do hashf "$f"; done; }

# per-step wrapper: self-heal (timeout + never abort), tee to command.log, hash the output file
_to() { local t="$1"; shift; if have timeout; then timeout -k 5 "$t" "$@"; else "$@"; fi; }
run() {  # run <name> <timeout_s> <outfile|-> cmd...
  local name="$1" tmo="$2" out="$3"; shift 3
  STEP=$((STEP+1)); local id; id="$(printf '%03d' "$STEP")"
  echo "== [$id] $name :: $* ==" >> "$CMDLOG"
  local rc=0
  if [ "$out" = "-" ]; then _to "$tmo" "$@" >>"$CMDLOG" 2>&1; rc=$?
  else _to "$tmo" "$@" >"$OUT/$out" 2>>"$CMDLOG"; rc=$?; hashf "$OUT/$out"; fi
  case $rc in 0) log "STEP $id OK   | $name";;
    124|137|143) log "STEP $id WARN | $name | TIMEOUT ${tmo}s";;
    *) log "STEP $id WARN | $name | rc=$rc";; esac
  return 0
}

# ---------------------------------------------------------------------------
# doctrine gate (authorization + network isolation vs remote wipe)
# ---------------------------------------------------------------------------
echo
echo "================ MOBILE ACQUISITION - $PLATFORM ($SERIAL) ================"
echo " Examiner: $EXAMINER   Case: $CASE   Out: $OUT"
echo " DOCTRINE: open-source LOGICAL acquisition only (non-root Android / encrypted iOS backup)."
echo "           physical / full-filesystem needs jailbreak or proprietary tools - NOT attempted."
log "START platform=$PLATFORM serial=$SERIAL examiner=$EXAMINER os=$OS authorizer=${AUTHORIZER:-none}"
[ -z "$AUTHORIZER" ] && log "CUSTODY WARNING: no --authorizer recorded (pass --authorizer/--legal/--scope)."
if [ "$AUTO" != 1 ] && [ -e /dev/tty ]; then
  echo
  read -rp " Do you have AUTHORIZATION to acquire this device + data? (y/N) " a </dev/tty
  case "$a" in [yY]*) :;; *) echo "Abort: authorization required."; exit 3;; esac
  echo " REMOTE-WIPE RISK: Find My / MDM can wipe or lock this device over the network."
  echo "  Best practice = Faraday bag/box. We capture LIVE network/process state FIRST, then isolate."
  if [ "$FARADAY" = 1 ]; then echo "  (--faraday asserted: device already RF-isolated.)"; fi
  read -rp " Proceed with acquisition? (y/N) " a </dev/tty
  case "$a" in [yY]*) :;; *) echo "Aborted."; exit 3;; esac
fi

# ===========================================================================
# ANDROID
# ===========================================================================
android_isolate() {
  [ "$FARADAY" = 1 ] && { log "ISOLATION: --faraday (hardware) - no software toggle."; return; }
  if [ "$ISOLATE" = 1 ]; then
    log "ISOLATION: enabling airplane mode + Wi-Fi off (device-state change, documented)."
    run iso-airplane 15 - "${ADB[@]}" shell cmd connectivity airplane-mode enable
    run iso-wifi     15 - "${ADB[@]}" shell svc wifi disable
    run iso-data     15 - "${ADB[@]}" shell svc data disable
  elif [ "$AUTO" != 1 ] && [ -e /dev/tty ]; then
    read -rp " Enable airplane mode now (software isolation)? (y/N) " a </dev/tty
    case "$a" in [yY]*) run iso-airplane 15 - "${ADB[@]}" shell cmd connectivity airplane-mode enable; run iso-wifi 15 - "${ADB[@]}" shell svc wifi disable;; esac
  fi
}

collect_android() {
  ADB=(adb -s "$SERIAL")
  run adb-version 10 meta/adb_version.txt adb version
  # Phase A - detect + gate on 'device'
  run devices     10 artifacts/00_devices.txt adb devices -l
  local state; state="$("${ADB[@]}" get-state 2>/dev/null)"
  log "adb state = ${state:-none}"
  if [ "$state" != device ]; then
    log "Device not authorized/online (state=$state). Accept the USB-debugging RSA prompt on the phone."
    if [ "$AUTO" != 1 ] && [ -e /dev/tty ]; then read -rp " Press Enter after accepting on-device, or Ctrl-C to abort " _ </dev/tty
      adb kill-server >/dev/null 2>&1; adb start-server >/dev/null 2>&1; "${ADB[@]}" reconnect >/dev/null 2>&1; sleep 2; fi
  fi
  run getprop     15 artifacts/01_getprop.txt "${ADB[@]}" shell getprop
  # root check (leverage pre-existing root only; never root the subject)
  ROOTED=0; "${ADB[@]}" shell su -c id >/dev/null 2>&1 && ROOTED=1
  log "root available = $ROOTED (allow_root=$ALLOW_ROOT)"

  # Phase B - VOLATILE FIRST (before isolation): processes, live net, notifications, logcat, packages
  run ps          15 artifacts/02_ps.txt          "${ADB[@]}" shell ps -A
  run connectivity 30 dumpsys/connectivity.txt     "${ADB[@]}" shell dumpsys connectivity
  run netstats    30 dumpsys/netstats.txt          "${ADB[@]}" shell dumpsys netstats
  run notification 15 dumpsys/notification.txt      "${ADB[@]}" shell dumpsys notification
  run logcat_all  60 artifacts/03_logcat_all.txt   "${ADB[@]}" logcat -d -b all -v threadtime
  run packages_f  20 artifacts/04_packages.txt     "${ADB[@]}" shell cmd package list packages -f
  run package_full 60 dumpsys/package_full.txt      "${ADB[@]}" shell dumpsys package

  # ISOLATE now that live state is captured
  android_isolate

  # Phase C - subsystem state (compromise-triage gold: accessibility, device_policy, appops, account)
  for S in battery wifi usagestats device_policy accessibility appops account activity input_method netpolicy mount user backup; do
    run "dumpsys_$S" 60 "dumpsys/$S.txt" "${ADB[@]}" shell dumpsys "$S"
  done
  # Phase D - settings + stores
  for T in global secure system; do run "settings_$T" 15 "artifacts/05_settings_$T.txt" "${ADB[@]}" shell settings list "$T"; done
  run users       10 artifacts/05b_users.txt "${ADB[@]}" shell pm list users   # work-profile detection
  run bugreport   600 - "${ADB[@]}" bugreport "$OUT/artifacts/bugreport.zip"; hashf "$OUT/artifacts/bugreport.zip"
  run calllog     30 artifacts/06_calllog.txt "${ADB[@]}" shell content query --uri content://call_log/calls
  run sms         30 artifacts/07_sms.txt     "${ADB[@]}" shell content query --uri content://sms
  run sdcard_pull 900 - "${ADB[@]}" pull /sdcard "$OUT/artifacts/sdcard"; hashtree "$OUT/artifacts/sdcard"
  # adb backup: deprecated/empty on Android 12+, best-effort only
  run adb_backup  180 - "${ADB[@]}" backup -all -shared -apk -f "$OUT/artifacts/backup.ab"; hashf "$OUT/artifacts/backup.ab"

  # Phase E - APKs (MVT-native handles splits + hashing; else manual)
  if have mvt-android; then
    run mvt_apks 1800 - mvt-android download-apks --serial "$SERIAL" --output "$OUT/apks"
  else
    log "mvt-android absent - pulling base APKs manually from package paths."
    "${ADB[@]}" shell cmd package list packages -f 2>/dev/null | sed -n 's/^package:\(.*\)=\(.*\)$/\1|\2/p' | while IFS='|' read -r apk pkg; do
      [ -n "$apk" ] && "${ADB[@]}" pull "$apk" "$OUT/apks/${pkg}.apk" >/dev/null 2>&1 && hashf "$OUT/apks/${pkg}.apk"
    done
  fi

  # Phase F - root-only escalation (only if device ALREADY rooted and --allow-root)
  if [ "$ROOTED" = 1 ] && [ "$ALLOW_ROOT" = 1 ]; then
    log "ROOT escalation (pre-existing root): /data/data tar + sockets + fs listing."
    "${ADB[@]}" shell 'su -c "tar -cf - /data/data"' > "$OUT/artifacts/data_data.tar" 2>>"$CMDLOG"; hashf "$OUT/artifacts/data_data.tar"
    run root_sockets 30 artifacts/net_sockets.txt "${ADB[@]}" shell su -c 'cat /proc/net/tcp /proc/net/tcp6'
    run root_fslist  120 artifacts/fs_listing.txt "${ADB[@]}" shell su -c 'ls -laR /data/app /data/data'
  fi

  # Phase G - androidqf as an independent 2nd acquirer (best-effort; it is interactive)
  if have androidqf; then log "androidqf present - run it separately for a corroborating package (interactive)."; fi

  ACQ_TIER="logical/non-root"; [ "$ROOTED" = 1 ] && [ "$ALLOW_ROOT" = 1 ] && ACQ_TIER="logical + root-fs (pre-existing root)"
}

analyze_android() {
  [ "$ANALYZE" = 1 ] || return 0
  if have mvt-android; then
    log "MVT: download-iocs + check-bugreport"
    run mvt_iocs 120 - mvt-android download-iocs
    [ -f "$OUT/artifacts/bugreport.zip" ] && run mvt_bugreport 600 - mvt-android check-bugreport --output "$OUT/reports/mvt_bugreport" "$OUT/artifacts/bugreport.zip"
    [ -f "$OUT/artifacts/backup.ab" ]     && run mvt_backup    300 - mvt-android check-backup    --output "$OUT/reports/mvt_backup"    "$OUT/artifacts/backup.ab"
  fi
  if have aleapp || have aleapp.py; then
    local AL; AL="$(command -v aleapp || command -v aleapp.py)"
    [ -f "$OUT/artifacts/bugreport.zip" ] && run aleapp 900 - "$AL" -t zip -i "$OUT/artifacts/bugreport.zip" -o "$OUT/reports/aleapp"
  fi
}

# ===========================================================================
# iOS
# ===========================================================================
collect_ios() {
  run idevice-ver 10 meta/idevice_version.txt idevice_id -v
  run udid_list   10 artifacts/00_udids.txt idevice_id -l
  # Step 1 - pairing / trust
  run pair        60 - idevicepair -u "$SERIAL" pair
  run pair_valid  15 meta/pairing.txt idevicepair -u "$SERIAL" validate
  # Step 2 - identity
  run ideviceinfo 20 meta/ideviceinfo.txt ideviceinfo -u "$SERIAL"
  # Step 3 - VOLATILE first: syslog window, crash reports, diagnostics, profiles, apps
  log "Capturing live syslog window (background) + volatile logs."
  ( idevicesyslog -u "$SERIAL" > "$OUT/logs/idevicesyslog_${STAMP}.log" 2>>"$CMDLOG" ) &
  SYSLOG_PID=$!
  run crashreports 300 - idevicecrashreport -u "$SERIAL" -e -k "$OUT/logs/crashreports"; hashtree "$OUT/logs/crashreports"
  run diagnostics 60 logs/diagnostics.txt idevicediagnostics -u "$SERIAL" diagnostics All
  run provisioning 30 artifacts/provisioning_profiles.txt ideviceprovision -u "$SERIAL" list
  # ideviceinstaller: 'list' on new builds, '-l' on older
  if ideviceinstaller -u "$SERIAL" list >/dev/null 2>&1; then run apps 60 artifacts/installed_apps.txt ideviceinstaller -u "$SERIAL" list
  else run apps 60 artifacts/installed_apps.txt ideviceinstaller -u "$SERIAL" -l; fi
  # Step 5 - ENCRYPTED backup (encrypted >> unencrypted: unlocks Keychain/Health/Safari/call history)
  export BACKUP_PASSWORD="$BACKUP_PASS"
  log "Enabling backup ENCRYPTION (password documented in collection_info; encrypted backup = full triage surface)."
  run enc_on 30 - idevicebackup2 -u "$SERIAL" -i encryption on
  run bkp_info0 20 meta/backup_encryption.txt idevicebackup2 -u "$SERIAL" info
  # Step 6 - FULL backup (hours; do not short-timeout)
  log "Full logical backup starting - may take HOURS; keep device UNLOCKED + connected."
  run backup 14400 - idevicebackup2 -u "$SERIAL" backup --full "$OUT/artifacts/backup"; hashtree "$OUT/artifacts/backup"
  run bkp_info 30 meta/backup_summary.txt idevicebackup2 -s "$OUT/artifacts/backup" info
  # Step 7 - stop volatile capture
  kill "${SYSLOG_PID:-0}" 2>/dev/null; hashf "$OUT/logs/idevicesyslog_${STAMP}.log"
  ACQ_TIER="logical (encrypted iTunes backup)"
}

analyze_ios() {
  [ "$ANALYZE" = 1 ] || return 0
  local BKDIR="$OUT/artifacts/backup/$SERIAL"
  [ -d "$BKDIR" ] || BKDIR="$(find "$OUT/artifacts/backup" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1)"
  if have mvt-ios; then
    export MVT_IOS_BACKUP_PASSWORD="$BACKUP_PASS"
    run mvt_decrypt 1800 - mvt-ios decrypt-backup -d "$OUT/artifacts/backup_decrypted" "$BKDIR"
    run mvt_iocs 120 - mvt-ios download-iocs
    run mvt_check 900 - mvt-ios check-backup --output "$OUT/reports/mvt_backup" "$OUT/artifacts/backup_decrypted"
  fi
  if have ileapp || have ileapp.py; then
    local IL; IL="$(command -v ileapp || command -v ileapp.py)"
    local DEC; DEC="$(find "$OUT/artifacts/backup_decrypted" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1)"
    [ -n "$DEC" ] && run ileapp 1800 - "$IL" -t itunes -i "$DEC" -o "$OUT/reports/ileapp"
  fi
}

# ---------------------------------------------------------------------------
# IOC extraction from MVT detections -> detection/mobile_iocs.csv (detection handoff)
# ---------------------------------------------------------------------------
extract_iocs() {
  local ic="$OUT/detection/mobile_iocs.csv"; echo "type,value,source" > "$ic"
  local PY; PY="$(command -v python3 || command -v python)"
  if [ -n "$PY" ]; then
    "$PY" - "$OUT/reports" "$ic" <<'PY' 2>/dev/null || true
import sys, os, json, re
reports, out = sys.argv[1], sys.argv[2]
ipre=re.compile(r'\b((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)\b')
rows=set()
def walk(o):
    if isinstance(o,dict):
        for k,v in o.items():
            if isinstance(v,str):
                lk=k.lower()
                if 'domain' in lk or 'host' in lk or 'url' in lk:
                    for d in re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', v, re.I): rows.add(('domain',d.lower()))
                if 'ip' in lk:
                    for m in ipre.finditer(v): rows.add(('ipv4',m.group(0)))
                if 'sha256' in lk or ('hash' in lk and len(v)==64): rows.add(('sha256',v))
                if 'process' in lk or 'proc' in lk: rows.add(('process',v))
                if 'package' in lk or lk=='name': rows.add(('android-package',v))
            walk(v)
    elif isinstance(o,list):
        for i in o: walk(i)
for root,_,files in os.walk(reports):
    for f in files:
        if f.endswith('detected.json'):
            try: walk(json.load(open(os.path.join(root,f),encoding='utf-8')))
            except Exception: pass
with open(out,'a',encoding='utf-8') as fh:
    for t,v in sorted(rows):
        if v and v not in ('localhost',): fh.write("%s,%s,mvt-detected\n" % (t,v))
PY
  fi
  awk -F, 'NR>1 && $3 ~ /\.apk$/ {print "sha256,"$1",apk-hash"}' "$HASHES" >> "$ic" 2>/dev/null || true
  local n; n=$(($(wc -l < "$ic") - 1)); log "IOC extraction -> $n indicators in detection/mobile_iocs.csv"
  hashf "$ic"
}

# ---------------------------------------------------------------------------
# seal: chain of custody + manifest
# ---------------------------------------------------------------------------
seal() {
  local end; end="$(now_utc)"
  local tv; tv="$( { adb version 2>/dev/null | head -1; idevice_id -v 2>/dev/null; mvt-ios version 2>/dev/null || mvt-android version 2>/dev/null; } | tr '\n' ';' )"
  local bkpw="n/a"; [ "$PLATFORM" = ios ] && bkpw="$BACKUP_PASS"
  cat > "$OUT/meta/collection_info.json" <<EOF
{ "tool":"mobile-collect.sh","platform":"$PLATFORM","serial":"$SERIAL","case":"$CASE",
  "examiner":"$EXAMINER","examiner_os":"$OS","startUtc":"$STARTUTC","endUtc":"$end",
  "acquisition_tier":"${ACQ_TIER:-logical}","faraday":$FARADAY,"analyzed":$ANALYZE,
  "backup_password":"$bkpw",
  "authorizer":"$AUTHORIZER","legal_basis":"$LEGAL","scope":"$SCOPE","toolVersions":"$tv" }
EOF
  hashf "$OUT/meta/collection_info.json"
  cat > "$OUT/SUMMARY.md" <<EOF
# mobile-collect Summary
- **Platform:** $PLATFORM   **Device:** $SERIAL
- **Case:** $CASE   **Examiner:** $EXAMINER ($OS)
- **Start:** $STARTUTC   **End:** $end
- **Acquisition tier:** ${ACQ_TIER:-logical}   (open-source ceiling; physical/full-FS not attempted)
- **Analyzed (MVT/iLEAPP/ALEAPP):** $( [ "$ANALYZE" = 1 ] && echo yes || echo "no (add --analyze)" )
- **Output:** $OUT
- Compromise findings: reports/*/*detected.json ; IOCs: detection/mobile_iocs.csv
- Integrity: meta/hashes.csv ; full manifest: meta/MANIFEST-SHA256.txt
EOF
  hashf "$OUT/SUMMARY.md"
  ( cd "$OUT" && find . -type f ! -path './meta/MANIFEST-SHA256.txt' ! -path './logs/audit.log' ! -path './logs/command.log' -print0 | xargs -0 sha256sum 2>/dev/null ) > "$OUT/meta/MANIFEST-SHA256.txt"
  cp -a "$AUDIT" "$OUT/logs/audit.frozen.log" 2>/dev/null && ( cd "$OUT" && sha256sum logs/audit.frozen.log ) > "$OUT/meta/MANIFEST-audit.sha256" 2>/dev/null
  log "===== mobile-collect DONE | platform=$PLATFORM tier=${ACQ_TIER:-logical} ====="
  echo; echo "Collection complete: $OUT"
  echo "  Summary: $OUT/SUMMARY.md | IOCs: $OUT/detection/mobile_iocs.csv"
}

# always seal, even on error / Ctrl-C
SEALED=0; STARTUTC="$(now_utc)"; ACQ_TIER=""
finish() { [ "$SEALED" = 0 ] && { SEALED=1; seal; }; }
trap 'log "signal caught - sealing"; finish; exit 0' INT TERM
trap finish EXIT

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
if [ "$PLATFORM" = android ]; then collect_android; analyze_android
else collect_ios; analyze_ios; fi
extract_iocs
finish
