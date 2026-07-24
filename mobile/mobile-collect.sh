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
AUTHORIZER=""; LEGAL=""; SCOPE=""; SCENARIO="U"; RESUME_DIR=""
while [ $# -gt 0 ]; do case "$1" in
  -d|--dest)       DEST="$2"; shift 2;;
  -c|--case)       CASE="$2"; shift 2;;
  --android)       PLATFORM=android; shift;;
  --ios)           PLATFORM=ios; shift;;
  --serial|--udid) SERIAL="$2"; shift 2;;
  --auto)          AUTO=1; shift;;
  --scenario)      SCENARIO="$2"; shift 2;;
  --mvt|--analyze) DO_MVT=1; ANALYZE=1; shift;;
  --backup-pass)   BACKUP_PASS="$2"; shift 2;;
  --faraday)       FARADAY=1; shift;;
  --isolate)       ISOLATE=1; shift;;
  --allow-root)    ALLOW_ROOT=1; shift;;
  --authorizer)    AUTHORIZER="$2"; shift 2;;
  --legal)         LEGAL="$2"; shift 2;;
  --scope)         SCOPE="$2"; shift 2;;
  --resume)        RESUME_DIR="$2"; shift 2;;
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
if [ -n "${RESUME_DIR:-}" ]; then OUT="$RESUME_DIR"; else OUT="$DEST/${CASE}_${PLATFORM}_${SAFE_SERIAL}_${STAMP}"; fi
mkdir -p "$OUT"/{meta,logs,artifacts,apks,dumpsys,reports,detection} 2>/dev/null || { echo "cannot create $OUT"; exit 1; }
AUDIT="$OUT/logs/audit.log"; CMDLOG="$OUT/logs/command.log"; HASHES="$OUT/meta/hashes.csv"
: > "$AUDIT"; : > "$CMDLOG"; echo "sha256,size,path" > "$HASHES"
STATE_JSONL="$OUT/logs/run_state.jsonl"; touch "$STATE_JSONL" 2>/dev/null
log()  { echo "$(now_utc) | $*" | tee -a "$AUDIT"; }
hashf() { [ -s "$1" ] || return 0; local h s; h="$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)"; s="$(stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null)"; echo "${h:-ERR},${s:-?},${1#$OUT/}" >> "$HASHES"; }
hashtree() { find "$1" -type f 2>/dev/null | while IFS= read -r f; do hashf "$f"; done; }

# ===== completion ledger + self-troubleshoot + resume (mobile) =====
fsize() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null; }
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }
ledger() { # ledger id name phase ev [k=v ...]
  [ -n "${STATE_JSONL:-}" ] || return 0
  local id="$1" name="$2" phase="$3" ev="$4"; shift 4
  local extra=""; for kv in "$@"; do extra="$extra,\"${kv%%=*}\":\"$(jesc "${kv#*=}")\""; done
  printf '{"t":"%s","id":"%s","name":"%s","phase":"%s","ev":"%s"%s}\n' "$(now_utc)" "$id" "$(jesc "$name")" "$phase" "$ev" "$extra" >> "$STATE_JSONL" 2>/dev/null
}
phase_of() { case "$1" in mvt_*|ileapp|aleapp|*decrypt*) echo analyze;; iso-*) echo isolation;; pair*|enc_*|bkp_*|backup|ideviceinfo|udid_*|idevice-ver|provisioning|apps|diagnostics|crashreports) echo ios-acq;; *) echo acquire;; esac; }
classify_error() { # name rc errfile -> class
  local name="$1" rc="$2" e="$3"; local S=""; [ -f "$e" ] && S="$(tr -d '\0' <"$e" 2>/dev/null)"
  case "$rc" in 124|137|143) echo timeout; return;; 127) echo tool_missing; return;; esac
  case "$S" in
    *unauthorized*|*"user denied"*) echo adb_unauthorized;;
    *"device offline"*) echo device_offline;;
    *"no devices/emulators"*|*"device '"*|*"waiting for device"*|*"no devices"*) echo device_not_found;;
    *"Could not connect to lockdownd"*|*trust*|*Trust*|*pairing*|*Pairing*|*InvalidHostID*) echo ios_not_trusted;;
    *SessionInactive*|*"Please unlock"*|*passcode*|*locked*) echo device_locked;;
    *password*|*"Enter a password"*) echo backup_password;;
    *"No space left"*) echo no_space;;
    *"No route to host"*|*"Network is unreachable"*|*"Connection refused"*|*"could not resolve"*|*"Temporary failure in name resolution"*) echo net_unreachable;;
    *"command not found"*|*"No such file or directory"*) echo tool_missing;;
    *) echo unknown;;
  esac
}
declare -A REM_TRIED 2>/dev/null || true
redirect_dest() { for c in /var/tmp/ir_mobile_evidence "$HOME/ir_mobile_evidence"; do if mkdir -p "$c" 2>/dev/null && ( : > "$c/.w" ) 2>/dev/null; then rm -f "$c/.w"; echo "redirect:$c"; return; fi; done; echo none; }
backoff() { case "$1" in timeout|net_unreachable) echo $(( $2 * $2 ));; device_offline|device_not_found) echo 3;; *) echo 0;; esac; }
# remediate: 0 => retry now ; 1 => give up. Each (id,class) fires once; hard cap 3 attempts/step.
remediate() {
  local cls="$1" name="$2" id="$3" attempt="$4"
  [ "$attempt" -ge 3 ] && return 1
  local k="$id|$cls"; [ -n "${REM_TRIED[$k]:-}" ] && return 1; REM_TRIED[$k]=1
  local action=none retry=1
  case "$cls" in
    adb_unauthorized) adb kill-server >/dev/null 2>&1; adb start-server >/dev/null 2>&1; adb -s "$SERIAL" reconnect >/dev/null 2>&1; sleep 2; action="adb-reauth"; retry=0;;
    device_offline)   adb -s "$SERIAL" reconnect offline >/dev/null 2>&1; sleep 2; action="adb-reconnect"; retry=0;;
    device_not_found) adb reconnect >/dev/null 2>&1; sleep 3; action="wait-redetect"; retry=0;;
    ios_not_trusted)  idevicepair -u "$SERIAL" pair >/dev/null 2>&1; sleep 2; action="ios-repair"; retry=0;;
    device_locked)    action="needs-unlock"; retry=1;;
    backup_password)  action="password-required"; retry=1;;
    no_space)         action="$(redirect_dest)"; [ "$action" != none ] && retry=0;;
    timeout|net_unreachable) action="backoff-retry"; [ "$attempt" -lt 2 ] && retry=0;;
    tool_missing)     action="skip-missing-tool"; retry=1;;
    *) action=none; retry=1;;
  esac
  ledger "$id" "$name" "$(phase_of "$name")" remediation "class=$cls" "action=$action" "result=$( [ $retry = 0 ] && echo retry || echo stop )"
  log "STEP $id REMEDIATE | $name | class=$cls action=$action -> $( [ $retry = 0 ] && echo retry || echo stop )"
  return $retry
}
declare -A SATISFIED 2>/dev/null || true
load_prior_state() { local d="$1"; [ -f "$d/logs/run_state.jsonl" ] || return 1
  while IFS= read -r line; do case "$line" in *'"ev":"ok"'*) local nm; nm="$(printf '%s' "$line" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')"; [ -n "$nm" ] && SATISFIED[$nm]=1;; esac; done < "$d/logs/run_state.jsonl"
  log "RESUME: ${#SATISFIED[@]} steps already satisfied - will skip them."; }
step_satisfied() {
  [ -n "${RESUME_DIR:-}" ] || return 1
  [ -n "${SATISFIED[$1]:-}" ] || return 1
  [ "$2" = "/dev/null" ] && return 0
  [ -f "$2" ] || return 1
  local b; b="$(fsize "$2")"; [ "${b:-0}" -gt 0 ] 2>/dev/null || return 1
  return 0; }

# per-step wrapper: self-heal (timeout + never abort), tee to command.log, hash the output file
_to() { local t="$1"; shift; if have timeout; then timeout -k 5 "$t" "$@"; else "$@"; fi; }
run() {  # run <name> <timeout_s> <outfile|-> cmd...  (instrumented: ledger + resume + self-heal)
  local name="$1" tmo="$2" out="$3"; shift 3
  STEP=$((STEP+1)); local id; id="$(printf '%03d' "$STEP")"
  local phase; phase="$(phase_of "$name")"
  local target="/dev/null"; [ "$out" != "-" ] && target="$OUT/$out"
  if step_satisfied "$name" "$target"; then ledger "$id" "$name" "$phase" skipped reason=already-ok; log "STEP $id SKIP | $name (resume: already satisfied)"; return 0; fi
  echo "== [$id] $name :: $* ==" >> "$CMDLOG"
  ledger "$id" "$name" "$phase" planned "timeout_s=$tmo"
  local etmp="$OUT/logs/.err.$id"; : > "$etmp" 2>/dev/null
  local attempt=0 rc=0 cls="" maxr=3
  while [ "$attempt" -lt "$maxr" ]; do
    attempt=$((attempt+1))
    ledger "$id" "$name" "$phase" running "attempt=$attempt"
    if [ "$out" = "-" ]; then _to "$tmo" "$@" >>"$CMDLOG" 2>"$etmp"; rc=$?
    else _to "$tmo" "$@" >"$OUT/$out" 2>"$etmp"; rc=$?; fi
    cat "$etmp" >> "$CMDLOG" 2>/dev/null
    [ "$out" != "-" ] && hashf "$OUT/$out"
    if [ "$rc" = 0 ]; then
      local bytes=0; [ "$out" != "-" ] && [ -f "$OUT/$out" ] && bytes="$(fsize "$OUT/$out")"
      ledger "$id" "$name" "$phase" ok "attempt=$attempt" "bytes=${bytes:-0}"
      log "STEP $id OK   | $name"; return 0
    fi
    cls="$(classify_error "$name" "$rc" "$etmp")"
    local ev=failed; case "$rc" in 124|137|143) ev=timeout;; esac
    if remediate "$cls" "$name" "$id" "$attempt"; then
      local w; w="$(backoff "$cls" "$attempt")"; [ "${w:-0}" -gt 0 ] 2>/dev/null && sleep "$w"; continue
    else
      local emsg; emsg="$(head -c 200 "$etmp" 2>/dev/null | tr -d '\0')"
      ledger "$id" "$name" "$phase" "$ev" "rc=$rc" "error_class=$cls" "error_msg=$emsg"
      case "$ev" in timeout) log "STEP $id WARN | $name | TIMEOUT ${tmo}s (class=$cls)";; *) log "STEP $id WARN | $name | rc=$rc class=$cls";; esac
      return 0
    fi
  done
  local emsg2; emsg2="$(head -c 200 "$etmp" 2>/dev/null | tr -d '\0')"
  ledger "$id" "$name" "$phase" failed "rc=$rc" "error_class=$cls" "error_msg=$emsg2" "attempts=$attempt"
  log "STEP $id WARN | $name | exhausted retries (class=$cls)"
  return 0
}

# ---------------------------------------------------------------------------
# incident scenario (mirrors the host collectors) -> ATT&CK-Mobile tags + emphasis + forced analysis
# ---------------------------------------------------------------------------
OFF_DEVICE=0; SCEN_NAME="Unknown / broad triage"; ATTACK=""; FIRST="Standard logical acquisition."
case "$(echo "$SCENARIO" | tr A-Z a-z)" in
  smish)   SCEN_NAME="Smishing / mobile phishing"; ATTACK="T1660,T1456,T1204,T1417"; ANALYZE=1;
           FIRST="Grab SMS/MMS + notification history + browser URL + the install-source of any app sideloaded right after the lure (before the user deletes the message).";;
  spyware) SCEN_NAME="Mobile spyware / stalkerware"; ATTACK="T1636,T1430,T1429,T1512,T1417,T1521,T1631"; ANALYZE=1; FARADAY=${FARADAY};
           FIRST="DO NOT REBOOT (zero-click implants are memory-resident). Faraday-isolate. Capture live syslog/logcat + crash reports FIRST, then MVT check-backup/bugreport over shutdown.log/DataUsage/WebKit/tcc.db + accessibility/appops/device_policy.";;
  mdm)     SCEN_NAME="Malicious MDM / configuration-profile compromise"; ATTACK="T1626.001,T1629,T1478,T1474"; ANALYZE=1;
           FIRST="Enumerate + snapshot installed configuration/provisioning profiles, trusted CA certs, VPN/proxy payloads, MDM enrollment BEFORE anyone revokes them; DIFF against the corporate baseline (rogue CA/proxy/silent-install = red flag).";;
  bec|token) SCEN_NAME="Mobile BEC / on-device token theft"; ATTACK="T1635,T1409,T1417.001,T1521,T1636.004"; ANALYZE=1;
           FIRST="iOS encrypted backup = Keychain (OAuth/refresh tokens); Android dumpsys account + mail-app data. Pair with host scenario 2 cloud UAL/Entra pull - the phone is the token origin.";;
  exfil)   SCEN_NAME="Mobile as exfil destination"; ATTACK="T1533,T1544,T1567";
           FIRST="Pull + hash /sdcard (Android) / Files+camera-roll (iOS) to find copied corporate files; inventory cloud-sync apps + DataUsage; correlate the phone serial to the workstation USBSTOR mount.";;
  beacon)  SCEN_NAME="Mobile C2 beacon"; ATTACK="T1437.001,T1521,T1481"; ANALYZE=1;
           FIRST="Capture live dumpsys connectivity/netstats + full logcat (Android) / DataUsage+syslog (iOS) BEFORE isolation, then MVT IOC check for beaconing domains.";;
  ransom)  SCEN_NAME="Mobile extortion channel"; ATTACK="T1471,T1516";
           FIRST="Grab the extortion/leak-site contact evidence: SMS/notification, messaging-app DBs, any dropped locker APK / config profile. Do NOT wipe or reset.";;
  lost)    SCEN_NAME="Lost / stolen device (off-device)"; ATTACK="T1461,T1626"; OFF_DEVICE=1;
           FIRST="Device usually absent/locked -> OFF-DEVICE workflow: Find My / MDM console (last check-in, location, remote-lock/wipe issued?), iCloud/Google account activity, carrier records. If recovered + unlocked: Faraday, then normal acquisition.";;
  *)       SCENARIO="U";;
esac

# ---------------------------------------------------------------------------
# doctrine gate (authorization + network isolation vs remote wipe)
# ---------------------------------------------------------------------------
echo
echo "================ MOBILE ACQUISITION - $PLATFORM ($SERIAL) ================"
echo " Examiner: $EXAMINER   Case: $CASE   Out: $OUT"
echo " Scenario: $SCEN_NAME  (ATT&CK-Mobile: ${ATTACK:-none})"
[ -n "$ATTACK" ] && echo "  -> FIRST: $FIRST"
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
  SDK="$("${ADB[@]}" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"; case "$SDK" in ''|*[!0-9]*) SDK=0;; esac
  log "Android API level (SDK) = $SDK"
  PKGCMD="cmd package"; [ "$SDK" -lt 24 ] 2>/dev/null && PKGCMD="pm"

  # Phase B - VOLATILE FIRST (before isolation): processes, live net, notifications, logcat, packages
  run ps          15 artifacts/02_ps.txt          "${ADB[@]}" shell ps -A
  run connectivity 30 dumpsys/connectivity.txt     "${ADB[@]}" shell dumpsys connectivity
  run netstats    30 dumpsys/netstats.txt          "${ADB[@]}" shell dumpsys netstats
  run notification 15 dumpsys/notification.txt      "${ADB[@]}" shell dumpsys notification
  run logcat_all  60 artifacts/03_logcat_all.txt   "${ADB[@]}" logcat -d -b all -v threadtime
  run packages_f  20 artifacts/04_packages.txt     "${ADB[@]}" shell $PKGCMD list packages -f
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
  if [ "$SDK" -ge 31 ] 2>/dev/null; then
    log "adb backup deprecated/neutered on Android 12+ (API $SDK) - skipped (bugreport+sdcard+APKs cover it)."
  else
    run adb_backup  180 - "${ADB[@]}" backup -all -shared -apk -f "$OUT/artifacts/backup.ab"; hashf "$OUT/artifacts/backup.ab"
  fi

  # Phase E - APKs (MVT-native handles splits + hashing; else manual)
  if have mvt-android; then
    run mvt_apks 1800 - mvt-android download-apks --serial "$SERIAL" --output "$OUT/apks"
  else
    log "mvt-android absent - pulling base APKs manually from package paths."
    "${ADB[@]}" shell $PKGCMD list packages -f 2>/dev/null | sed -n 's/^package:\(.*\)=\(.*\)$/\1|\2/p' | while IFS='|' read -r apk pkg; do
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
  "scenario":"$SCENARIO","scenario_name":"$SCEN_NAME","attack_tags":"$ATTACK",
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
  # --- completion rollup + completeness verdict (reduce run_state.jsonl; no jq) ---
  local nok nfail ntmo nskip nplan
  nok=$(grep -c '"ev":"ok"' "$STATE_JSONL" 2>/dev/null); nfail=$(grep -c '"ev":"failed"' "$STATE_JSONL" 2>/dev/null)
  ntmo=$(grep -c '"ev":"timeout"' "$STATE_JSONL" 2>/dev/null); nskip=$(grep -c '"ev":"skipped"' "$STATE_JSONL" 2>/dev/null)
  nplan=$(grep -c '"ev":"planned"' "$STATE_JSONL" 2>/dev/null)
  : "${nok:=0}" "${nfail:=0}" "${ntmo:=0}" "${nskip:=0}" "${nplan:=0}"
  local incomplete=""; local failed_names
  failed_names=$(grep -E '"ev":"(failed|timeout)"' "$STATE_JSONL" 2>/dev/null | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
  [ -n "$failed_names" ] && incomplete="$failed_names"
  incomplete="$(printf %s "$incomplete" | tr -cd '[:alnum:] ._():/-' | sed 's/  */ /g; s/^ //; s/ $//')"
  local verdict=COMPLETE; [ -n "$incomplete" ] && verdict=INCOMPLETE
  # JSON-escape string fields (examiner box may be Windows git-bash -> backslash paths)
  local j_out j_ser j_case j_tier j_inc; j_out="$(jesc "$OUT")"; j_ser="$(jesc "$SERIAL")"; j_case="$(jesc "$CASE")"; j_tier="$(jesc "${ACQ_TIER:-logical}")"; j_inc="$(jesc "$incomplete")"
  cat > "$OUT/logs/run_state.json" 2>/dev/null <<RSEOF
{ "schema":"ir-collect/run-state@1","tool":"mobile-collect.sh","case":"$j_case","platform":"$PLATFORM","serial":"$j_ser","output_dir":"$j_out",
  "ended_utc":"$end","status":"$( [ "$verdict" = COMPLETE ] && echo complete || echo partial )","resumed":$( [ -n "${RESUME_DIR:-}" ] && echo true || echo false ),
  "counts":{"planned":$nplan,"ok":$nok,"failed":$nfail,"timeout":$ntmo,"skipped":$nskip},
  "acquisition_tier":"$j_tier",
  "completeness":{"verdict":"$verdict","incomplete":"$j_inc"} }
RSEOF
  { echo; echo "## Completeness - $verdict"; echo "- steps: ok=$nok failed=$nfail timeout=$ntmo skipped=$nskip (planned=$nplan)"; [ -n "$incomplete" ] && echo "- incomplete: $incomplete"; echo "- resume: ./mobile-collect.sh -c '$CASE' -d '$DEST' --resume '$OUT'"; } >> "$OUT/SUMMARY.md" 2>/dev/null
  RUN_INCOMPLETE=$( [ "$verdict" = COMPLETE ] && echo 0 || echo 1 )
  hashf "$OUT/logs/run_state.json"
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
[ -n "${RESUME_DIR:-}" ] && load_prior_state "$OUT"
if [ "$OFF_DEVICE" = 1 ]; then
  log "OFF-DEVICE scenario (lost/stolen) - writing an off-device investigation checklist instead of a tethered acquisition."
  cat > "$OUT/artifacts/OFF_DEVICE_CHECKLIST.md" <<'CL'
# Lost / Stolen Device - Off-Device Investigation Checklist
The device is not in hand (or is locked with no passcode). Collect from the platforms it touches:
- [ ] Find My iPhone / Google Find My Device: status, last check-in, last known location, is a remote lock/WIPE pending or issued?
- [ ] MDM/EMM console (Intune / Workspace ONE / Jamf / MobileIron): last sync, compliance, issued lost-mode/wipe commands, installed profiles/apps.
- [ ] iCloud (appleid.apple.com) / Google account activity: recent sign-ins, new devices, security events, data access.
- [ ] Carrier: call/SMS records, IMEI status, SIM swap history.
- [ ] Corporate SSO/IdP (Entra/Okta) sign-in logs for the user + this device id; revoke tokens/sessions.
- [ ] If RECOVERED and UNLOCKED: Faraday-isolate immediately, then re-run this tool tethered.
- [ ] If passcode-locked with no passcode: open-source acquisition ends here -> escalate to Cellebrite/GrayKey/XRY.
CL
  hashf "$OUT/artifacts/OFF_DEVICE_CHECKLIST.md"
  ACQ_TIER="off-device (lost/stolen checklist)"
else
  if [ "$PLATFORM" = android ]; then collect_android; analyze_android
  else collect_ios; analyze_ios; fi
  extract_iocs
fi
finish
[ "${RUN_INCOMPLETE:-0}" = "1" ] && exit 15
exit 0
