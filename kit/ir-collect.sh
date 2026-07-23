#!/usr/bin/env bash
# =============================================================================
# ir-collect.sh - Self-healing IR collector for Linux (two-stage: rapid + menu)
#
# STAGE 1 (automatic): fast "hasty grab" of super-important VOLATILE data in
#   RFC 3227 order of volatility - processes, network state, sessions, modules.
# STAGE 2 (menu): operator selects long-running jobs - RAM image, artifact
#   collection, full file hashing, Active Directory enumeration, disk image.
#
# Lightweight thumb-drive kit: runs with only native tools; uses pro tools
# (AVML/LiME for RAM, UAC, ldapsearch, bloodhound-python) if found in ./tools
# or on PATH. Point it at an external drive OR a network IP.
#
# SELF-HEALING: every action runs via run_step() with a per-step timeout +
# retry + audit log; any hang/failure/missing tool is logged and skipped -
# the run never aborts.
#
# Usage:
#   sudo ./ir-collect.sh -d /mnt/evidence -c CASE001        # to external drive
#   sudo ./ir-collect.sh -d user@10.0.0.5:/evidence -c C1   # ship to IP (rsync/ssh)
#   sudo ./ir-collect.sh -d /mnt/usb --auto                 # unattended, all jobs
#   sudo ./ir-collect.sh -d /mnt/usb --rapid-only           # volatile only
# =============================================================================

set +e                      # self-heal: never abort on a single command failure
set -o pipefail 2>/dev/null || true

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
DEST="$(cd "$(dirname "$0")" && pwd)"
CASE="IR"
STEP_TIMEOUT=120
AUTO=0
RAPID_ONLY=0
SKIP_AD=0
DEFER_MEM=0
AUTHORIZER=""; LEGAL_BASIS=""; SCOPE_NOTE=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_DIR="$SCRIPT_DIR/tools"
BIN="$TOOL_DIR/bin"

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--dest)        DEST="$2"; shift 2 ;;
    -c|--case)        CASE="$2"; shift 2 ;;
    -t|--timeout)     STEP_TIMEOUT="$2"; shift 2 ;;
    --auto)           AUTO=1; shift ;;
    --rapid-only)     RAPID_ONLY=1; shift ;;
    --resume)         RESUME_DIR="$2"; shift 2 ;;
    --skip-ad)        SKIP_AD=1; shift ;;
    --defer-memory)   DEFER_MEM=1; shift ;;
    --lab|--training) LAB=1; shift ;;
    --authorizer)     AUTHORIZER="$2"; shift 2 ;;
    --legal)          LEGAL_BASIS="$2"; shift 2 ;;
    --scope)          SCOPE_NOTE="$2"; shift 2 ;;
    -h|--help)        grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; }
# --- portability preamble: OS family + coreutils flavor (drives stat/find branching) ---
OS_FAMILY=linux; case "$(uname -s 2>/dev/null)" in Darwin) OS_FAMILY=macos;; *BSD|DragonFly) OS_FAMILY=bsd;; SunOS) OS_FAMILY=solaris;; AIX) OS_FAMILY=aix;; esac
STAT_FLAVOR=gnu; stat -c %s /dev/null >/dev/null 2>&1 || { stat -f %z /dev/null >/dev/null 2>&1 && STAT_FLAVOR=bsd; }
FIND_FLAVOR=gnu; find --version >/dev/null 2>&1 || FIND_FLAVOR=bsd
ARCH="$(uname -m 2>/dev/null)"
fsize()  { case "$STAT_FLAVOR" in bsd) stat -f %z "$1" 2>/dev/null;; *) stat -c %s "$1" 2>/dev/null;; esac; }
HOSTN="$(hostname 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y%m%d_%H%M%SZ)"

# --- DOCTRINE: don't trust the compromised host's binaries --------------------
# Carried trusted static binaries in ./tools/bin SHADOW the host's (rootkit may
# have replaced ps/ss/ls/netstat). We prepend them and keep a sane baseline PATH.
BASE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [ -d "$TOOL_DIR/bin" ]; then export PATH="$TOOL_DIR/bin:$BASE_PATH"; TRUSTED_BIN=1
else export PATH="$BASE_PATH"; TRUSTED_BIN=0; fi
# Require bash 4+ (associative arrays). Re-exec a carried bash if the host bash is too old/absent.
if { [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO:-0}" -lt 4 ]; } && [ -z "${_IRC_REEXEC:-}" ]; then
  if [ -x "$BIN/bash" ]; then export _IRC_REEXEC=1; exec "$BIN/bash" "$0" "$@"; fi
  echo "WARNING: bash 4+ recommended (associative arrays). Carry a static bash in tools/bin." >&2
fi
# Neutralize userland-rootkit hooks + non-deterministic locale for our own process.
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT 2>/dev/null
export LC_ALL=C LANG=C          # deterministic tool output / sorting / decimal separators
umask 077                       # evidence files not world-readable

# ---------------------------------------------------------------------------
# Resolve destination: local path vs network (IP or user@host:path)
# Network dest -> stage locally, then rsync/scp at seal.
# ---------------------------------------------------------------------------
# an instructor-attached, purpose-labeled writable volume (lab evidence disk), if present + mountable
LAB_VOL=""
if command -v blkid >/dev/null 2>&1; then
  _ev="$(blkid -L EVIDENCE 2>/dev/null || blkid -L IR-EVIDENCE 2>/dev/null)"
  if [ -n "$_ev" ]; then
    _mp="$(lsblk -no MOUNTPOINT "$_ev" 2>/dev/null | head -1)"
    [ -z "$_mp" ] && { mkdir -p /mnt/ir_evidence 2>/dev/null && mount "$_ev" /mnt/ir_evidence 2>/dev/null && _mp=/mnt/ir_evidence; }
    [ -n "$_mp" ] && LAB_VOL="$_mp"
  fi
fi
# is the tool running from read-only media (ISO/CD/squashfs)?  (can't write next to itself)
RO_MEDIA=0
_srcfs="$(df -P "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2{print $1}')"
mount 2>/dev/null | grep -q "^$_srcfs .*[(,]ro[,)]" && RO_MEDIA=1
case "$_srcfs" in /dev/sr*|/dev/loop*) RO_MEDIA=1;; esac

NETWORK_DEST=""; HTTP_DEST=""
if echo "$DEST" | grep -qE '^https?://'; then
  HTTP_DEST="$DEST"                                  # lab: POST the sealed bundle to a collector endpoint
elif echo "$DEST" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(:.*)?$' || echo "$DEST" | grep -q '@'; then
  NETWORK_DEST="$DEST"
  echo "$DEST" | grep -q ':' || NETWORK_DEST="${DEST}:/tmp/evidence"
fi

# choose a WRITABLE output/staging root: script dir -> lab evidence disk -> /tmp
pick_writable() { for c in "$@"; do if mkdir -p "$c" 2>/dev/null && ( : > "$c/.w_$STAMP" ) 2>/dev/null; then rm -f "$c/.w_$STAMP" 2>/dev/null; echo "$c"; return; fi; done; }
if [ -n "$NETWORK_DEST" ] || [ -n "$HTTP_DEST" ]; then
  OUT_ROOT="$(pick_writable "$SCRIPT_DIR/_staging" ${LAB_VOL:+"$LAB_VOL/_ir_staging"} "/tmp/_ir_staging")"
  [ -z "$OUT_ROOT" ] && OUT_ROOT="/tmp/_ir_staging" && mkdir -p "$OUT_ROOT" 2>/dev/null
  if echo "$OUT_ROOT" | grep -q '^/tmp' && [ "${LAB:-0}" != "1" ]; then
    echo "!!! CONTAMINATION WARNING: cannot stage on the collection media - staging on the TARGET disk ($OUT_ROOT)."
    echo "    Attach writable removable media and re-run if at all possible. !!!"
  elif [ "${LAB:-0}" = "1" ]; then echo "Lab mode: staging at $OUT_ROOT; ships/POSTs at seal."; fi
else
  OUT_ROOT="$DEST"
  # read-only-media / non-writable target: redirect to a writable evidence location so we can run at all
  if ! ( mkdir -p "$OUT_ROOT" 2>/dev/null && ( : > "$OUT_ROOT/.w_$STAMP" ) 2>/dev/null ); then
    REDIR="${LAB_VOL:+$LAB_VOL/ir_evidence}"; [ -z "$REDIR" ] && REDIR="/var/tmp/ir_evidence"
    echo "Output '$OUT_ROOT' not writable (read-only media?). Redirecting evidence to $REDIR."
    OUT_ROOT="$REDIR"; mkdir -p "$OUT_ROOT" 2>/dev/null
  else rm -f "$OUT_ROOT/.w_$STAMP" 2>/dev/null; fi
fi
OUTDIR="$OUT_ROOT/${CASE}_${HOSTN}_${STAMP}"
[ -n "${RESUME_DIR:-}" ] && OUTDIR="$RESUME_DIR"   # --resume: finish an existing capture

# Output subfolders (per phase)
D_META="$OUTDIR/00_metadata"
D_VOL="$OUTDIR/01_volatile"
D_NET="$OUTDIR/02_network"
D_MEM="$OUTDIR/03_memory"
D_PERS="$OUTDIR/04_persistence"
D_ART="$OUTDIR/05_artifacts"
D_AD="$OUTDIR/06_activedirectory"
D_DISK="$OUTDIR/07_diskimage"
D_LOG="$OUTDIR/99_logs"
for d in "$D_META" "$D_VOL" "$D_NET" "$D_MEM" "$D_PERS" "$D_ART" "$D_AD" "$D_DISK" "$D_LOG"; do mkdir -p "$d" 2>/dev/null; done

AUDIT="$D_LOG/audit.log"
ERRLOG="$D_LOG/errors.log"

audit() { echo "$(now_utc) | $(id -un 2>/dev/null) | $*" | tee -a "$AUDIT"; }
STATE_JSONL="$D_LOG/run_state.jsonl"; touch "$STATE_JSONL" 2>/dev/null
INIT=unknown; [ -d /run/systemd/system ] && INIT=systemd || { command -v rc-service >/dev/null 2>&1 && INIT=openrc; }; command -v launchctl >/dev/null 2>&1 && INIT=launchd
cat > "$D_META/platform_profile.json" 2>/dev/null <<PPEOF
{ "os_family":"$OS_FAMILY","arch":"$ARCH","stat_flavor":"$STAT_FLAVOR","find_flavor":"$FIND_FLAVOR","init":"$INIT",
  "shell":"${BASH_VERSION:-sh}","has_proc":$( [ -r /proc/self/status ] && echo true || echo false ),
  "is_root":$( [ "$(id -u 2>/dev/null)" = 0 ] && echo 1 || echo 0 ),"resume":$( [ -n "${RESUME_DIR:-}" ] && echo true || echo false ) }
PPEOF
[ -n "${RESUME_DIR:-}" ] && audit "RESUME: continuing capture at $OUTDIR"

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------
find_tool() {  # find_tool name1 name2 ...
  for n in "$@"; do
    if [ -d "$TOOL_DIR" ]; then
      f="$(find "$TOOL_DIR" -maxdepth 3 -name "$n" -type f 2>/dev/null | head -n1)"
      [ -n "$f" ] && { echo "$f"; return 0; }
    fi
    p="$(command -v "$n" 2>/dev/null)"
    [ -n "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}
# --- toolkit self-repair: fix common tool problems BEFORE we need them ---------
# (missing exec bit, un-extracted archives, busybox applets not installed). Runs
# so the collector fixes its own kit rather than trusting host binaries.
repair_toolkit() {
  [ -d "$TOOL_DIR" ] || { echo "Toolkit: no tools/ dir - build it with fetch-tools.sh on a trusted box."; return; }
  [ -d "$BIN" ] && chmod +x "$BIN"/* 2>/dev/null
  find "$TOOL_DIR" -maxdepth 3 -type f \( -name 'avml' -o -name 'velociraptor*' -o -name 'busybox' -o -name 'CyLR' -o -name 'uac' -o -name 'chainsaw' -o -name 'hayabusa*' \) -exec chmod +x {} \; 2>/dev/null
  for z in "$BIN"/*.zip; do [ -f "$z" ] && { unzip -oq "$z" -d "${z%.zip}" 2>/dev/null && rm -f "$z" && echo "Toolkit: extracted $(basename "$z")"; }; done
  for t in "$BIN"/*.tar.gz; do [ -f "$t" ] && { tar xzf "$t" -C "$BIN" 2>/dev/null && rm -f "$t" && echo "Toolkit: extracted $(basename "$t")"; }; done
  # Trusted enumeration reads raw /proc + /proc/net (resists USERLAND rootkits; a kernel/DKOM
  # rootkit can still hook these, so RAM + dead-box remain ground truth). busybox stays a coarse
  # fallback, NOT applet-shadowed (its ps/ss lack flags).
}
repair_toolkit

T_AVML="$(find_tool avml)";                 T_LIME="$(find_tool lime.ko)"
T_UAC="$(find_tool uac uac.sh)";            T_LDAP="$(find_tool ldapsearch)"
T_BHPY="$(find_tool bloodhound-python)";    T_NXC="$(find_tool nxc netexec crackmapexec)"
T_BB="$(find_tool busybox)"

# ---------------------------------------------------------------------------
# run_step : self-healing collection primitive
#   run_step <name> <outfile|-> <dir> <timeout> <retries> <command...>
#   command is run with `timeout`; stdout -> outfile; outcome -> audit log.
#   NEVER aborts the script.
# ---------------------------------------------------------------------------
STEP_NUM=0; STEPS_OK=0; STEPS_FAIL=0
# detect `timeout` and whether it supports -k (BusyBox builds may not)
have_timeout=0; TMO_K=""
if command -v timeout >/dev/null 2>&1; then
  have_timeout=1
  timeout -k 1 1 true >/dev/null 2>&1 && TMO_K="-k 5"
fi
SETSID=""; command -v setsid >/dev/null 2>&1 && SETSID="setsid"
NICE=""; command -v nice >/dev/null 2>&1 && NICE="nice -n 19"; command -v ionice >/dev/null 2>&1 && NICE="ionice -c3 $NICE"

# ===== completion ledger + self-troubleshoot + resume =====
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }
ledger() { # ledger id name phase ev [k=v ...]
  [ -n "${STATE_JSONL:-}" ] || return 0
  local id="$1" name="$2" phase="$3" ev="$4"; shift 4
  local extra=""; for kv in "$@"; do extra="$extra,\"${kv%%=*}\":\"$(jesc "${kv#*=}")\""; done
  printf '{"t":"%s","id":"%s","name":"%s","phase":"%s","ev":"%s"%s}\n' "$(now_utc)" "$id" "$(jesc "$name")" "$phase" "$ev" "$extra" >> "$STATE_JSONL" 2>/dev/null
}
phase_of() { case "$1" in *00_metadata) echo metadata;; *01_volatile) echo volatile;; *02_network) echo network;; *03_memory) echo memory;; *04_persistence) echo persistence;; *05_artifacts) echo artifacts;; *06_activedirectory) echo ad;; *07_diskimage) echo diskimage;; *) echo other;; esac; }
classify_error() { # name rc errfile -> class
  local name="$1" rc="$2" e="$3"; local S=""; [ -f "$e" ] && S="$(tr -d '\0' <"$e" 2>/dev/null)"
  case "$rc" in 124|137|143) echo timeout; return;; 127) echo tool_missing; return;; 126) echo not_elevated; return;; 255) echo net_unreachable; return;; esac
  case "$S" in
    *"Permission denied"*|*"Operation not permitted"*|*"must be root"*) echo not_elevated;;
    *"command not found"*|*"No such file or directory"*) echo tool_missing;;
    *"No space left on device"*) echo no_space;;
    *"Text file busy"*|*"resource busy"*|*"Device or resource busy"*) echo file_locked;;
    *"insmod"*|*"Key was rejected"*|*"Lockdown"*|*"Required key not available"*) echo driver_blocked;;
    *"No route to host"*|*"Connection refused"*|*"Connection timed out"*|*"Network is unreachable"*) echo net_unreachable;;
    *"could not resolve"*|*"Name or service not known"*|*"Temporary failure in name resolution"*) echo dns_blocked;;
    *"Sizelimit"*|*"Administrative Limit"*) echo rate_limit;;
    *) echo unknown;;
  esac
}
declare -A REM_TRIED 2>/dev/null || true
redirect_dest() { for c in ${LAB_VOL:+"$LAB_VOL/ir_evidence"} /var/tmp/ir_evidence; do if mkdir -p "$c" 2>/dev/null && ( : > "$c/.w" ) 2>/dev/null; then rm -f "$c/.w"; echo "redirect:$c"; return; fi; done; echo none; }
backoff() { case "$1" in timeout|net_unreachable|rate_limit) echo $(( $2 * $2 ));; file_locked) echo 2;; *) echo 0;; esac; }
# remediate: 0 => retry now ; 1 => give up. Each (id,class) once; hard cap 3 attempts.
remediate() {
  local cls="$1" name="$2" id="$3" attempt="$4"
  [ "$attempt" -ge 3 ] && return 1
  local k="$id|$cls"; [ -n "${REM_TRIED[$k]:-}" ] && return 1; REM_TRIED[$k]=1
  local action=none retry=1
  case "$cls" in
    timeout|net_unreachable|dns_blocked|rate_limit) action="backoff-retry"; [ "$attempt" -lt 2 ] && retry=0;;
    file_locked) action="retry-after-settle"; retry=0;;
    no_space)    action="$(redirect_dest)"; [ "$action" != none ] && retry=0;;
    not_elevated) action="degraded-nonroot"; retry=1;;
    tool_missing) action="fallback-or-skip"; retry=1;;
    driver_blocked) action="pivot-flag"; retry=1;;
    *) action=none; retry=1;;
  esac
  ledger "$id" "$name" other remediation "class=$cls" "action=$action" "result=$( [ $retry = 0 ] && echo retry || echo stop )"
  audit "STEP $id REMEDIATE | $name | class=$cls action=$action -> $( [ $retry = 0 ] && echo retry || echo stop )"
  return $retry
}
declare -A SATISFIED 2>/dev/null || true
load_prior_state() { # dir
  local d="$1"; [ -f "$d/99_logs/run_state.jsonl" ] || return 1
  while IFS= read -r line; do case "$line" in *'"ev":"ok"'*) local nm; nm="$(printf '%s' "$line" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p')"; [ -n "$nm" ] && SATISFIED[$nm]=1;; esac; done < "$d/99_logs/run_state.jsonl"
  audit "RESUME: ${#SATISFIED[@]} steps already satisfied - will skip them."
}
step_satisfied() { # name target
  [ -n "${RESUME_DIR:-}" ] || return 1
  [ -n "${SATISFIED[$1]:-}" ] || return 1
  [ "$2" = "/dev/null" ] && return 0
  [ -f "$2" ] || return 1
  local b; b="$(fsize "$2")"; [ "${b:-0}" -gt 0 ] 2>/dev/null || return 1
  return 0
}

run_step() {
  local name="$1" outfile="$2" dir="$3" tmo="$4" retries="$5"; shift 5
  STEP_NUM=$((STEP_NUM+1)); local id; id="$(printf '%03d' "$STEP_NUM")"
  local phase; phase="$(phase_of "$dir")"
  local target="/dev/null"; [ "$outfile" != "-" ] && target="$dir/$outfile"
  if step_satisfied "$name" "$target"; then ledger "$id" "$name" "$phase" skipped reason=already-ok; audit "STEP $id SKIP | $name | already satisfied (resume)"; STEPS_OK=$((STEPS_OK+1)); return 0; fi
  ledger "$id" "$name" "$phase" planned "timeout_s=$tmo"
  local attempt=0 rc=0 start cls=""; start="$(date +%s)"
  local etmp="$D_LOG/.err.$id"; : > "$etmp" 2>/dev/null
  while [ "$attempt" -le "$retries" ]; do
    attempt=$((attempt+1))
    ledger "$id" "$name" "$phase" running "attempt=$attempt"
    # stdin closed (</dev/null) so no tool can block on an interactive prompt
    if [ -n "$SETSID" ]; then
      # PREFERRED: run in a NEW process group so the watchdog kills the WHOLE pipeline
      # (dd|gzip), not just the parent shell. GNU `timeout` only signals its direct child,
      # so pipeline grandchildren would be orphaned and keep writing - hence setsid first.
      if [ "$target" = "/dev/null" ]; then $SETSID "$@" </dev/null >>"$AUDIT" 2>"$etmp" &
      else $SETSID "$@" </dev/null >"$target" 2>"$etmp" & fi
      local pid=$!; local kt="-$pid"
      ( sleep "$tmo"; kill -TERM "$kt" 2>/dev/null; sleep 5; kill -KILL "$kt" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!
      wait "$pid" 2>/dev/null; rc=$?
      kill "$wd" 2>/dev/null; pkill -P "$wd" 2>/dev/null
    elif [ "$have_timeout" = "1" ]; then
      if [ "$target" = "/dev/null" ]; then timeout $TMO_K "$tmo" "$@" </dev/null >>"$AUDIT" 2>"$etmp"; rc=$?
      else timeout $TMO_K "$tmo" "$@" </dev/null >"$target" 2>"$etmp"; rc=$?; fi
    else
      # neither setsid nor timeout: best-effort single-pid watchdog
      if [ "$target" = "/dev/null" ]; then "$@" </dev/null >>"$AUDIT" 2>"$etmp" &
      else "$@" </dev/null >"$target" 2>"$etmp" & fi
      local pid=$!
      ( sleep "$tmo"; kill -TERM "$pid" 2>/dev/null; sleep 5; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!; wait "$pid" 2>/dev/null; rc=$?; kill "$wd" 2>/dev/null
    fi
    cat "$etmp" >> "$ERRLOG" 2>/dev/null
    local dur=$(( $(date +%s) - start ))
    if [ "$rc" = "0" ]; then
      local bytes=0; [ "$target" != "/dev/null" ] && [ -f "$target" ] && bytes="$(fsize "$target")"
      ledger "$id" "$name" "$phase" ok "attempt=$attempt" "duration_s=$dur" "out_file=$outfile" "out_bytes=${bytes:-0}"
      audit "STEP $id OK   | $name | ${dur}s | try $attempt${outfile:+ -> $outfile}"
      STEPS_OK=$((STEPS_OK+1)); rm -f "$etmp"; return 0
    fi
    # classify + bounded self-troubleshoot (each fix logged as a custody action)
    cls="$(classify_error "$name" "$rc" "$etmp")"
    if remediate "$cls" "$name" "$id" "$attempt"; then retries=$attempt; sleep "$(backoff "$cls" "$attempt")"; continue; fi
    if [ "$rc" = "124" ] || [ "$rc" = "137" ] || [ "$rc" = "143" ]; then audit "STEP $id WARN | $name | TIMEOUT ${tmo}s cls=$cls | try $attempt"
    else audit "STEP $id ERR  | $name | rc=$rc cls=$cls | try $attempt"; fi
    [ "$attempt" -le "$retries" ] && sleep 0.4
  done
  case "$rc" in 124|137|143) term=timeout;; *) term=failed;; esac
  ledger "$id" "$name" "$phase" "${term:-failed}" "attempt=$attempt" "exit_code=$rc" "error_class=${cls:-unknown}" "error_msg=$(head -c 200 "$etmp" 2>/dev/null | tr -d '\n\r')"
  echo "$(now_utc) [$id] $name : ${term:-failed} rc=$rc cls=${cls:-?}" >> "$ERRLOG"
  STEPS_FAIL=$((STEPS_FAIL+1)); rm -f "$etmp"; return 0     # swallow: never abort
}
# shell-snippet variant (for pipes/redirs): run_sh <name> <outfile> <dir> <tmo> <retries> '<shell>'
run_sh() {
  local name="$1" outfile="$2" dir="$3" tmo="$4" retries="$5" snippet="$6"
  run_step "$name" "$outfile" "$dir" "$tmo" "$retries" bash -c "$snippet"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
audit "===== ir-collect START ====="
audit "Case=$CASE Host=$HOSTN Output=$OUTDIR root=$IS_ROOT timeout=${STEP_TIMEOUT}s"
DET=""; for kv in "avml:$T_AVML" "lime:$T_LIME" "uac:$T_UAC" "ldapsearch:$T_LDAP" "bloodhound-python:$T_BHPY" "netexec:$T_NXC"; do
  [ -n "${kv#*:}" ] && DET="$DET ${kv%%:*}"; done
audit "Pro tools detected:${DET:- (none - native only)}"
[ "$TRUSTED_BIN" = "1" ] && audit "DOCTRINE: using CARRIED trusted static binaries from tools/bin (host binaries shadowed)." \
  || audit "DOCTRINE WARNING: no tools/bin - relying on host binaries which may be rootkit-tampered. Carry static busybox/sleuthkit for a compromised host."
[ -n "$NETWORK_DEST" ] && audit "Destination is NETWORK: staging locally, shipping to $NETWORK_DEST at seal." || audit "Destination local: $DEST"
[ "$IS_ROOT" = "0" ] && audit "WARNING: not root - RAM capture, some /proc, shadow, logs will be incomplete."

# Record hashes of the binaries we are about to trust/use (integrity baseline)
integrity_baseline() {
  { for b in bash ps ss ip ls cat find sha256sum lsof ldapsearch dd tar; do
      p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] && printf '%s  %s\n' "$(sha256sum "$p" 2>/dev/null | cut -d' ' -f1)" "$p"
    done; } > "$D_META/used_binaries_sha256.txt" 2>/dev/null
}

# --- destination preflight: write-test, filesystem 4GB cap, containerization ----
if ! ( : > "$OUT_ROOT/.irwrite_test" ) 2>/dev/null; then
  audit "PREFLIGHT: destination $OUT_ROOT is NOT writable - fix before collecting evidence."
else rm -f "$OUT_ROOT/.irwrite_test" 2>/dev/null; fi
DEST_FS="$(stat -f -c %T "$OUT_ROOT" 2>/dev/null || findmnt -no FSTYPE "$OUT_ROOT" 2>/dev/null)"
case "$DEST_FS" in
  *msdos*|*vfat*|*fat*) audit "PREFLIGHT WARNING: destination is $DEST_FS (FAT/exFAT family). FAT32 caps files at 4GB - a RAM image will TRUNCATE. Reformat destination NTFS/exFAT/ext4." ;;
  *) [ -n "$DEST_FS" ] && audit "PREFLIGHT: destination filesystem = $DEST_FS" ;;
esac
CONTAINER=""
[ -f /.dockerenv ] && CONTAINER="docker"
grep -qaE '(docker|lxc|kubepods|containerd)' /proc/1/cgroup 2>/dev/null && CONTAINER="${CONTAINER:-container}"
[ -n "$CONTAINER" ] && audit "PREFLIGHT: running INSIDE a $CONTAINER - PIDs/mounts/network are namespaced; host view differs. Consider collecting from the host namespace."
AUACHK="$([ "$IS_ROOT" = "0" ] && echo 'PARTIAL - not root' || echo full)"
audit "PREFLIGHT: privilege=$AUACHK  timeout=$( [ "$have_timeout" = 1 ] && echo yes || echo 'no(manual watchdog)')  trusted_bin=$TRUSTED_BIN"
audit "FOOTPRINT: tools run from '$SCRIPT_DIR' (NOT installed on target); evidence written only to destination; live footprint documented in this log. For non-volatile ground truth follow with a dead-box disk image."

# collection_info.json
cat > "$D_META/collection_info.json" 2>/dev/null <<EOF
{ "tool":"ir-collect.sh","version":"2.0","case":"$CASE","host":"$HOSTN",
  "collector":"$(id -un 2>/dev/null)","root":$IS_ROOT,"startUtc":"$(now_utc)",
  "kernel":"$(uname -a 2>/dev/null | sed 's/"/ /g')","toolsDetected":"${DET# }",
  "exercise":${LAB:-0},"authorizer":"$AUTHORIZER","legalBasis":"$LEGAL_BASIS","scope":"$SCOPE_NOTE" }
EOF
[ -z "$AUTHORIZER" ] && audit "CUSTODY WARNING: no --authorizer recorded (pass --authorizer/--legal/--scope for a defensible chain of custody)."
# --- guest / hypervisor detection: which host-side pull channel is available (training-lab) ---
HYPERVISOR="unknown"; GUEST_AGENT=""
if command -v systemd-detect-virt >/dev/null 2>&1; then HYPERVISOR="$(systemd-detect-virt 2>/dev/null || echo unknown)"; fi
if [ "$HYPERVISOR" = "unknown" ] || [ "$HYPERVISOR" = "none" ]; then
  _pn="$(cat /sys/class/dmi/id/product_name 2>/dev/null) $(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
  case "$_pn" in
    *VMware*)                 HYPERVISOR="vmware";;
    *VirtualBox*|*innotek*)   HYPERVISOR="virtualbox";;
    *Microsoft*|*Hyper-V*)    HYPERVISOR="hyper-v";;
    *QEMU*|*KVM*|*"Red Hat"*) HYPERVISOR="qemu-kvm";;
  esac
fi
case "$HYPERVISOR" in oracle) HYPERVISOR="virtualbox";; microsoft) HYPERVISOR="hyper-v";; qemu) HYPERVISOR="qemu-kvm";; esac
pgrep -x vmtoolsd    >/dev/null 2>&1 && GUEST_AGENT="$GUEST_AGENT vmtoolsd"
pgrep -x qemu-ga     >/dev/null 2>&1 && GUEST_AGENT="$GUEST_AGENT qemu-ga"
pgrep -x VBoxService >/dev/null 2>&1 && GUEST_AGENT="$GUEST_AGENT VBoxService"
[ -e /dev/virtio-ports/org.qemu.guest_agent.0 ] && GUEST_AGENT="$GUEST_AGENT qga-channel"
lsmod 2>/dev/null | grep -q hv_utils && GUEST_AGENT="$GUEST_AGENT hyperv-lis"
{ echo "Hypervisor: $HYPERVISOR"; echo "GuestAgent:$GUEST_AGENT"; echo "BootMediaReadOnly: $RO_MEDIA"; echo "LabMode: ${LAB:-0}"; echo "OutputRoot: $OUT_ROOT"; } > "$D_META/environment_detect.txt" 2>/dev/null
audit "GUEST ENV: hypervisor=$HYPERVISOR agent=$GUEST_AGENT roMedia=$RO_MEDIA lab=${LAB:-0}"
[ "${LAB:-0}" = "1" ] && echo "=== LAB / TRAINING MODE (hypervisor=$HYPERVISOR) - evidence marked EXERCISE ==="

# default intake.json (overwritten by guided intake); the detection generator always finds one
cat > "$D_META/intake.json" 2>/dev/null <<EOF
{ "case_id":"$CASE","scenario":"U","scenario_name":"Unknown / broad triage","host_role":"unknown","scope":"single","connectivity":"connected","exercise":${LAB:-0},"generated_by":"ir-collect.sh (non-guided)","known_bad_ips":[],"known_bad_domains":[],"known_bad_hashes":[],"known_bad_accounts":[],"known_bad_paths":[],"attack_tags":[] }
EOF

# ===========================================================================
# STAGE 1 - RAPID VOLATILE GRAB
# ===========================================================================
rapid_volatile() {
  echo; echo "================ STAGE 1: RAPID VOLATILE GRAB ================"
  audit "===== STAGE 1: rapid volatile grab ====="

  # host identity
  run_step meta-uname       uname.txt        "$D_META" 30 1 uname -a
  run_sh   meta-release     os_release.txt   "$D_META" 30 1 'cat /etc/*release 2>/dev/null; echo; hostnamectl 2>/dev/null'
  run_sh   meta-date        time.txt         "$D_META" 30 1 'echo "UTC: $(date -u)"; echo "Local: $(date)"; echo "Uptime: $(uptime)"; timedatectl 2>/dev/null'
  run_step meta-env         environment.txt  "$D_META" 30 1 printenv
  run_sh   meta-mounts      mounts.txt       "$D_META" 30 1 'mount; echo "---FSTAB---"; cat /etc/fstab; echo "---DF---"; df -h; echo "---LSBLK---"; lsblk -f 2>/dev/null'
  run_sh   meta-clock       clock_provenance.txt "$D_META" 20 1 'echo "Host local: $(date +%FT%T%z 2>/dev/null || date)"; echo "Host UTC:   $(date -u +%FT%T.%3NZ 2>/dev/null || date -u)"; echo "NOTE: compare to trusted time source; record offset for timeline defensibility."'
  # CRITICAL while live: LUKS/dm-crypt status. A dead-box image of an encrypted disk is unreadable
  # without the key - capture encryption state (and note master keys live in RAM we are imaging).
  run_sh   meta-crypto      encryption.txt   "$D_META" 30 1 'echo "=== encrypted volumes ==="; lsblk -o NAME,FSTYPE,MOUNTPOINT,TYPE 2>/dev/null | grep -iE "crypt|luks"; echo "=== dm-crypt maps ==="; dmsetup ls --target crypt 2>/dev/null; for d in $(lsblk -pno NAME,FSTYPE 2>/dev/null | awk "\$2==\"crypto_LUKS\"{print \$1}"); do echo "== $d =="; cryptsetup luksDump "$d" 2>/dev/null; done; if lsblk -o FSTYPE,TYPE 2>/dev/null | grep -qiE "crypto_LUKS|(^|[[:space:]])crypt([[:space:]]|$)"; then echo "ENCRYPTED=yes"; else echo "ENCRYPTED=no"; fi; echo "NOTE: if encrypted, the master key is in the RAM image; extract before shutdown."'

  # --- RAM IMAGE FIRST (RFC 3227: memory is the most volatile capturable artifact) ---
  if [ "$DEFER_MEM" = "0" ]; then
    echo "Capturing physical memory first (order of volatility)..."
    job_memory
  else
    audit "defer-memory set - RAM captured after volatile commands."
  fi

  # processes (most volatile after memory)
  run_step proc-full        processes.txt    "$D_VOL" 60 1 ps -eww -o pid,ppid,user,stime,etime,nlwp,stat,cmd
  run_step proc-aux         ps_aux.txt       "$D_VOL" 60 1 ps auxww
  run_sh   proc-tree        pstree.txt       "$D_VOL" 30 1 'pstree -pal 2>/dev/null || ps -ejH'
  run_sh   proc-exe         proc_exe.txt     "$D_VOL" 60 1 'ls -l /proc/*/exe 2>/dev/null | grep -a deleted; echo "=== all exe links ==="; ls -l /proc/*/exe 2>/dev/null'
  run_sh   proc-cmdline     proc_cmdline.txt "$D_VOL" 60 1 'for p in /proc/[0-9]*; do printf "%s\t" "${p#/proc/}"; tr "\0" " " < "$p/cmdline" 2>/dev/null; echo; done'
  run_sh   open-files       lsof.txt         "$D_VOL" 90 1 'lsof -bnPw 2>/dev/null || ls -l /proc/*/fd 2>/dev/null'

  # sessions
  run_sh   sessions         sessions.txt     "$D_VOL" 30 1 'echo "=== who -a ==="; who -a; echo "=== w ==="; w; echo "=== last -20 ==="; last -Faiwx 2>/dev/null | head -40; echo "=== lastb ==="; lastb 2>/dev/null | head -20; echo "=== loginctl ==="; loginctl list-sessions 2>/dev/null'
  run_sh   users            users.txt        "$D_VOL" 30 1 'echo "=== passwd ==="; cat /etc/passwd; echo "=== groups ==="; cat /etc/group; echo "=== sudoers ==="; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null'
  run_sh   shadow           shadow.txt       "$D_VOL" 30 1 'cat /etc/shadow 2>/dev/null || echo "no access (need root)"'
  run_sh   sudo-groups      sudo_members.txt "$D_VOL" 30 1 'getent group sudo wheel root 2>/dev/null; true'

  # kernel modules
  run_sh   modules          kernel_modules.txt "$D_VOL" 30 1 'lsmod; echo "=== /proc/modules ==="; cat /proc/modules'
  run_sh   kernel-cfg       kernel_cfg.txt   "$D_VOL" 30 1 'echo "=== cmdline ==="; cat /proc/cmdline; echo "=== sysctl (net/kernel) ==="; sysctl -a 2>/dev/null | grep -E "^(kernel|net)\." | head -200'

  # network state
  run_sh   net-conns        connections.txt  "$D_NET" 60 1 'echo "=== ss -tulpanW ==="; ss -tulpanW 2>/dev/null || netstat -anp 2>/dev/null || { echo "(ss/netstat absent - raw /proc/net)"; cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null; }; true'
  run_sh   net-if           interfaces.txt   "$D_NET" 30 1 'ip -s addr 2>/dev/null || ifconfig -a 2>/dev/null; echo "=== promisc check ==="; ip link 2>/dev/null | grep -i promisc; true'
  run_step net-route        routes.txt       "$D_NET" 30 1 ip route
  run_step net-arp          arp_neigh.txt    "$D_NET" 30 1 ip neigh
  run_sh   net-dns          dns.txt          "$D_NET" 30 1 'cat /etc/resolv.conf; echo "=== hosts ==="; cat /etc/hosts; echo "=== nsswitch ==="; cat /etc/nsswitch.conf; resolvectl status 2>/dev/null'
  run_sh   net-fw           firewall.txt     "$D_NET" 45 1 'echo "=== iptables ==="; iptables -L -n -v 2>/dev/null; echo "=== nft ==="; nft list ruleset 2>/dev/null; echo "=== ufw ==="; ufw status verbose 2>/dev/null; true'
  run_sh   net-sockets      unix_sockets.txt "$D_NET" 30 1 'ss -xp 2>/dev/null | head -300'

  [ "$DEFER_MEM" = "1" ] && { echo "Capturing physical memory (deferred)..."; job_memory; }

  echo "STAGE 1 complete: volatile state secured (OK=$STEPS_OK FAIL=$STEPS_FAIL so far)."
  audit "===== STAGE 1 complete: OK=$STEPS_OK FAIL=$STEPS_FAIL ====="
}

# ===========================================================================
# STAGE 2 - HEAVY JOBS
# ===========================================================================
declare -A DONE
# free-space preflight: refuse a dump rather than fill the destination
enough_space() {  # enough_space <need_kib> <what>
  local need="$1" what="$2"
  local avail; avail="$(df -Pk "$OUT_ROOT" 2>/dev/null | awk 'NR==2{print $4}')"
  [ -z "$avail" ] && { audit "PREFLIGHT $what: unknown free space - proceeding"; return 0; }
  if [ "$avail" -lt "$need" ]; then
    audit "PREFLIGHT $what: ABORT - need $((need/1024)) MB, have $((avail/1024)) MB free"; return 1; fi
  audit "PREFLIGHT $what: OK - $((avail/1024)) MB free (need ~$((need/1024)) MB)"; return 0
}
job_memory() {
  [ -n "${DONE[memory]}" ] && { audit "RAM already captured - skipping."; return; }
  audit "--- RAM image (volatile #1) ---"
  # capture kernel symbol material FIRST - without it a Linux RAM dump is unparseable in Volatility 3
  run_sh mem-symbols kernel_symbols.txt "$D_MEM" 60 0 'echo "=== uname -r ==="; uname -r; echo "=== version ==="; cat /proc/version; echo "=== kallsyms head ==="; head -50 /proc/kallsyms 2>/dev/null; for m in /boot/System.map-$(uname -r) /usr/lib/debug/boot/vmlinux-$(uname -r); do [ -f "$m" ] && cp -a "$m" "'"$D_MEM"'/" 2>/dev/null && echo "copied $m"; done; cp -a /proc/kallsyms "'"$D_MEM"'/kallsyms" 2>/dev/null'
  # preflight: need ~ MemTotal * 1.1
  local memkb; memkb="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)"; [ -z "$memkb" ] && memkb=8388608
  if ! enough_space $(( memkb * 11 / 10 )) RAM-image; then
    run_sh mem-skip-space RAM_SKIPPED_NO_SPACE.txt "$D_MEM" 10 0 'echo "RAM image skipped: insufficient destination free space."'; DONE[memory]=1; return
  fi
  if [ -n "$T_AVML" ]; then
    run_step mem-avml - "$D_MEM" 3600 0 "$T_AVML" "$D_MEM/memory.lime"
  elif [ -n "$T_LIME" ]; then
    run_sh mem-lime - "$D_MEM" 3600 0 "insmod '$T_LIME' 'path=$D_MEM/memory.lime format=lime'"
  else
    audit "RAM: no AVML/LiME found (place 'avml' in ./tools/bin). Capturing /proc/kcore note only."
    run_sh mem-fallback RAM_NOT_CAPTURED.txt "$D_MEM" 30 0 'echo "No AVML/LiME. Recommended: microsoft/avml (single static binary, no kernel module needed)."; ls -l /proc/kcore 2>/dev/null; free -h'
  fi
  # verify a REAL image exists (silent-fail: no AVML/LiME or blocked -> tiny/no file, seals GREEN)
  MEM_BYTES=0
  for f in "$D_MEM"/memory.lime "$D_MEM"/memory.raw; do [ -f "$f" ] && MEM_BYTES=$(( MEM_BYTES + $(stat -c %s "$f" 2>/dev/null || echo 0) )); done
  local need=$(( ${memkb:-8388608} * 1024 * 4 / 10 ))   # 40% of physical RAM in bytes
  if [ "$MEM_BYTES" -ge "$need" ]; then
    MEM_OK=1; audit "RAM VERIFIED: $((MEM_BYTES/1024/1024)) MB image (>= 40% of RAM)"
    run_sh mem-hash memory_hashes.txt "$D_MEM" 1800 0 'cd "'"$D_MEM"'" && for f in memory.lime memory.raw; do [ -f "$f" ] && { echo "SHA256 $(sha256sum "$f")"; echo "MD5    $(md5sum "$f")"; }; done; true'
  else
    MEM_OK=0; audit "RAM WARNING: only $((MEM_BYTES/1024/1024)) MB - capture likely FAILED (no AVML/LiME, or blocked). *** Do NOT power off an encrypted host without the LUKS key - the master key is only in RAM. ***"
    run_sh mem-fail RAM_CAPTURE_FAILED.txt "$D_MEM" 10 0 'echo "RAM capture failed/incomplete. If the disk is LUKS-encrypted, do NOT power off without the key."'
  fi
  DONE[memory]=1
}
job_artifacts() {
  audit "--- HEAVY: artifact collection (logs/config/histories) ---"
  if [ -n "$T_UAC" ]; then
    run_step uac-collect - "$D_ART" 3600 0 "$T_UAC" -p full "$D_ART"
  else
    run_sh art-logs      - "$D_ART" 1200 0 "mkdir -p '$D_ART/varlog'; cp -a --parents /var/log '$D_ART/varlog' 2>/dev/null; echo done"
    run_sh art-journal   journal.txt "$D_ART" 300 0 'journalctl --no-pager 2>/dev/null | tail -50000'
    run_sh art-etc       - "$D_ART" 300 0 "mkdir -p '$D_ART/etc'; for f in /etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/resolv.conf /etc/ssh/sshd_config /etc/fstab; do cp -a --parents \$f '$D_ART/etc' 2>/dev/null; done; cp -a --parents /etc/cron* '$D_ART/etc' 2>/dev/null; echo done"
    run_sh art-histories history.txt "$D_ART" 120 0 'for h in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do [ -f "$h" ] && { echo "=== $h ==="; cat "$h"; }; done 2>/dev/null'
    run_sh art-ssh       ssh_keys.txt "$D_ART" 120 0 'for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$k" ] && { echo "=== $k ==="; cat "$k"; }; done 2>/dev/null'
    run_sh art-tmp       tmp_listing.txt "$D_ART" 60 0 'ls -laR /tmp /var/tmp /dev/shm 2>/dev/null'
  fi
  DONE[artifacts]=1
}
job_persistence() {
  audit "--- HEAVY: persistence ---"
  run_sh pers-cron     cron.txt     "$D_PERS" 60 1 'for u in $(cut -f1 -d: /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null); [ -n "$c" ] && { echo "== $u =="; echo "$c"; }; done; echo "=== /etc/cron* ==="; ls -laR /etc/cron* /var/spool/cron 2>/dev/null; cat /etc/crontab 2>/dev/null'
  run_sh pers-systemd  systemd.txt  "$D_PERS" 60 1 'systemctl list-units --type=service --all --no-pager 2>/dev/null; echo "=== unit files ==="; systemctl list-unit-files --no-pager 2>/dev/null; echo "=== timers ==="; systemctl list-timers --all --no-pager 2>/dev/null'
  run_sh pers-startup  startup.txt  "$D_PERS" 60 1 'echo "=== rc.local ==="; cat /etc/rc.local 2>/dev/null; echo "=== init.d ==="; ls -la /etc/init.d 2>/dev/null; echo "=== ld.so.preload ==="; cat /etc/ld.so.preload 2>/dev/null; echo "=== autostart ==="; ls -la /home/*/.config/autostart ~/.config/autostart 2>/dev/null'
  run_sh pers-packages packages.txt "$D_PERS" 120 1 'dpkg -l 2>/dev/null || rpm -qa 2>/dev/null'
  run_sh pers-suid     suid_sgid.txt "$D_PERS" 300 0 "$NICE "'find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null'
  run_sh pers-caps     capabilities.txt "$D_PERS" 300 0 'getcap -r / 2>/dev/null'
  DONE[persistence]=1
}
job_filehashes() {
  audit "--- HEAVY: full filesystem SHA-256 inventory ---"
  [ "${DO_NO_HARM:-0}" = "1" ] && { audit "filehashes skipped (do-no-harm/OT-ICS)"; run_sh hash-skip-ot FILEHASH_SKIPPED_OT.txt "$D_ART" 10 0 'echo "Skipped: do-no-harm (OT/ICS) mode - a full live-filesystem hash walk is too intrusive for control systems."'; DONE[filehashes]=1; return; }
  run_sh hash-all filehashes.csv "$D_ART" 7200 0 "$NICE "'find / -xdev -type f -print0 2>/dev/null | while IFS= read -r -d "" f; do h=$(sha256sum "$f" 2>/dev/null | cut -d" " -f1); s=$(stat -c "%s|%Y" "$f" 2>/dev/null); echo "${h:-ERR},$s,\"$f\""; done'
  DONE[filehashes]=1
}
job_ad() {
  [ "$SKIP_AD" = "1" ] && { audit "AD skipped (--skip-ad)"; return; }
  audit "--- HEAVY: Active Directory / domain enumeration ---"
  # local join state
  run_sh ad-join realm_join.txt "$D_AD" 60 1 'echo "=== realm list ==="; realm list 2>/dev/null; echo "=== sssctl domains ==="; sssctl domain-list 2>/dev/null; echo "=== wbinfo ==="; wbinfo --all-domains 2>/dev/null; wbinfo -t 2>/dev/null; echo "=== net ads info ==="; net ads info 2>/dev/null'
  run_sh ad-config domain_config.txt "$D_AD" 60 1 'echo "=== krb5.conf ==="; cat /etc/krb5.conf 2>/dev/null; echo "=== sssd.conf ==="; cat /etc/sssd/sssd.conf 2>/dev/null | sed "s/\(ldap_default_authtok *=\).*/\1 <redacted>/"; echo "=== nsswitch ==="; cat /etc/nsswitch.conf 2>/dev/null'
  run_sh ad-getent getent_ad.txt "$D_AD" 120 1 'echo "=== passwd ==="; getent passwd 2>/dev/null | tail -200; echo "=== group domain admins ==="; getent group "domain admins" 2>/dev/null'
  run_sh ad-klist  kerberos.txt "$D_AD" 30 1 'klist 2>/dev/null; echo "=== keytab ==="; klist -k /etc/krb5.keytab 2>/dev/null'
  # over-the-network LDAP if a DC + ticket are available
  if [ -n "$T_LDAP" ]; then
    DC="$(realm list 2>/dev/null | awk "/server-software/{print}" ; grep -i '^\s*ldap_uri' /etc/sssd/sssd.conf 2>/dev/null)"
    audit "ldapsearch present. Run manually with a DC + kerberos ticket for full LDAP dump (see README). Attempting RootDSE."
    run_sh ad-rootdse rootdse.txt "$D_AD" 60 0 'ldapsearch -x -H "ldap://$(awk -F= "/^ *server *=/{print \$2; exit}" /etc/krb5.conf 2>/dev/null | tr -d " ")" -s base -b "" defaultNamingContext namingContexts 2>/dev/null || echo "RootDSE query needs a reachable DC; see README for authenticated ldapsearch."'
  fi
  # BloodHound.py if present + creds provided via env (BH_USER/BH_PASS/BH_DOMAIN/BH_DC)
  if [ -n "$T_BHPY" ] && [ -n "$BH_USER" ]; then
    run_step ad-bloodhound - "$D_AD" 1800 0 "$T_BHPY" -d "$BH_DOMAIN" -u "$BH_USER" -p "$BH_PASS" -ns "$BH_DC" -c All --zip
  fi
  DONE[ad]=1
}
job_diskimage() {
  audit "--- HEAVY: disk image ---"
  [ "${DO_NO_HARM:-0}" = "1" ] && { audit "disk image skipped (do-no-harm/OT-ICS)"; run_sh disk-skip-ot DISK_SKIPPED_OT.txt "$D_DISK" 10 0 'echo "Skipped: do-no-harm (OT/ICS) mode - live disk imaging risks control-system availability."'; DONE[diskimage]=1; return; }
  if command -v dd >/dev/null 2>&1; then
    for disk in $(lsblk -dnp -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
      n="$(basename "$disk")"
      run_sh disk-$n - "$D_DISK" 36000 0 "set -o pipefail; $NICE dd if=$disk conv=noerror,sync bs=4M status=progress 2>>'$AUDIT' | gzip > '$D_DISK/${n}.raw.gz' && sha256sum '$D_DISK/${n}.raw.gz' > '$D_DISK/${n}.sha256'"
    done
  else
    run_sh disk-note DISK_NOT_IMAGED.txt "$D_DISK" 30 0 'echo "dd not found - cannot image."'
  fi
  DONE[diskimage]=1
}

job_weblogs() {
  audit "--- HEAVY: web-server logs + webroot timeline (webshell hunt) ---"
  local W="$D_ART/webserver"; mkdir -p "$W" 2>/dev/null
  run_sh web-logs   - "$W" 900 0 'for d in /var/log/apache2 /var/log/httpd /var/log/nginx /var/log/lighttpd; do [ -d "$d" ] && cp -a --parents "$d" "'"$W"'" 2>/dev/null; done; for f in /var/log/tomcat*/catalina.out /opt/tomcat*/logs/catalina.out; do [ -f "$f" ] && cp -a --parents "$f" "'"$W"'" 2>/dev/null; done; echo done'
  run_sh web-config - "$W" 120 0 'for f in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/nginx/nginx.conf; do [ -f "$f" ] && cp -a --parents "$f" "'"$W"'" 2>/dev/null; done; echo done'
  # webroot recent-file timeline: dropped .php/.jsp/.aspx shells sort to the top by mtime
  run_sh web-root-timeline webroot_script_files.txt "$W" 600 0 'for r in /var/www /srv/www /usr/share/nginx/html /var/lib/tomcat*/webapps /opt/*/webapps; do [ -d "$r" ] && { echo "=== $r ==="; find "$r" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.jsp" -o -name "*.jspx" -o -name "*.asp" -o -name "*.aspx" -o -name "*.war" \) -printf "%TY-%Tm-%Td %TH:%TM %10s %p\n" 2>/dev/null | sort -r | head -500; }; done'
  DONE[weblogs]=1
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
mark() { [ -n "${DONE[$1]}" ] && echo "[x]" || echo "[ ]"; }
show_menu() {
  echo; echo "================ STAGE 2: HEAVY COLLECTION MENU ================"
  echo "Volatile data already secured. Select long-running jobs to run now."
  echo "  1 $(mark memory)      Full RAM image (AVML/LiME)          [LARGE]"
  echo "  2 $(mark artifacts)   Artifact collection (UAC / logs+cfg) [~min]"
  echo "  3 $(mark persistence) Persistence (cron/systemd/suid/pkgs) [fast]"
  echo "  4 $(mark ad)          Active Directory / domain enum"
  echo "  5 $(mark filehashes)  Full filesystem SHA-256 inventory    [SLOW]"
  echo "  6 $(mark diskimage)   Full disk image (dd)                 [VERY SLOW]"
  echo "  7 $(mark weblogs)    Web-server logs + webroot timeline (webshell) [~min]"
  echo "  A  Run ALL remaining"
  echo "  Q  Finish & seal"
  echo
}
run_menu() {
  # self-heal: if there is no interactive terminal, we cannot show a menu -
  # fall back to running ALL jobs rather than looping forever on a failed read.
  if [ ! -t 0 ] && [ ! -e /dev/tty ]; then
    audit "No TTY for menu - falling back to ALL heavy jobs."
    job_memory; job_artifacts; job_persistence; job_ad; job_filehashes; job_diskimage; job_weblogs
    return
  fi
  local badreads=0
  while true; do
    show_menu
    printf "Select (number / A / Q): "
    if ! read -r c </dev/tty 2>/dev/null; then
      badreads=$((badreads+1)); audit "menu read failed ($badreads)"
      [ "$badreads" -ge 3 ] && { audit "repeated read failure - sealing."; break; }
      continue
    fi
    case "$(echo "$c" | tr a-z A-Z)" in
      1) job_memory ;;
      2) job_artifacts ;;
      3) job_persistence ;;
      4) job_ad ;;
      5) job_filehashes ;;
      6) job_diskimage ;;
      7) job_weblogs ;;
      A) [ -z "${DONE[memory]}" ] && job_memory; [ -z "${DONE[artifacts]}" ] && job_artifacts; [ -z "${DONE[persistence]}" ] && job_persistence; [ -z "${DONE[ad]}" ] && job_ad; [ -z "${DONE[filehashes]}" ] && job_filehashes; [ -z "${DONE[diskimage]}" ] && job_diskimage; [ -z "${DONE[weblogs]}" ] && job_weblogs ;;
      Q) break ;;
      *) echo "Invalid selection." ;;
    esac
  done
}

# ===========================================================================
# SEAL
# ===========================================================================
seal() {
  audit "--- SEAL: manifest + report ---"
  local end; end="$(now_utc)"
  local donelist=""; for k in "${!DONE[@]}"; do donelist="$donelist $k"; done
  cat > "$OUTDIR/SUMMARY.md" 2>/dev/null <<EOF
# ir-collect Summary

- **Case:** $CASE
- **Host:** $HOSTN   root: $IS_ROOT
- **Collector:** $(id -un 2>/dev/null)
- **Start (UTC):** (see collection_info.json)   **End (UTC):** $end
- **Steps OK:** $STEPS_OK   **Failed/timed-out:** $STEPS_FAIL   **Total:** $STEP_NUM
- **Pro tools:** ${DET:- native only}
- **Heavy jobs run:**${donelist:- (rapid-volatile only)}
- **Output:** $OUTDIR

Stage 1 (auto) secured volatile state in order of volatility. Stage 2 heavy jobs were operator-selected.
See 99_logs/audit.log for the full timestamped trail; 99_logs/errors.log for recovered failures.
EOF

  # --- completion rollup + completeness verdict (reduce run_state.jsonl; no jq dependency) ---
  local nok nfail ntmo nskip nplan
  # grep -c prints "0" and exits 1 on no-match; capture then default (never use || echo which doubles)
  nok=$(grep -c '"ev":"ok"' "$STATE_JSONL" 2>/dev/null); nfail=$(grep -c '"ev":"failed"' "$STATE_JSONL" 2>/dev/null)
  ntmo=$(grep -c '"ev":"timeout"' "$STATE_JSONL" 2>/dev/null); nskip=$(grep -c '"ev":"skipped"' "$STATE_JSONL" 2>/dev/null)
  nplan=$(grep -c '"ev":"planned"' "$STATE_JSONL" 2>/dev/null)
  : "${nok:=0}" "${nfail:=0}" "${ntmo:=0}" "${nskip:=0}" "${nplan:=0}"
  local incomplete=""
  [ "${MEM_OK:-0}" != 1 ] && [ "$RAPID_ONLY" != 1 ] && incomplete="memory(no-verified-RAM)"
  local failed_names; failed_names=$(grep -E '"ev":"(failed|timeout)"' "$STATE_JSONL" 2>/dev/null | sed -n 's/.*"name":"\([^"]*\)".*//p' | sort -u | tr '
' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
  [ -n "$failed_names" ] && incomplete="$(echo "$incomplete $failed_names" | sed 's/^ //; s/ $//')"
  local verdict=COMPLETE; [ -n "$incomplete" ] && verdict=INCOMPLETE
  cat > "$D_LOG/run_state.json" 2>/dev/null <<RSEOF
{ "schema":"ir-collect/run-state@1","tool":"ir-collect.sh","case":"$CASE","host":"$HOSTN","output_dir":"$OUTDIR",
  "ended_utc":"$end","status":"$( [ "$verdict" = COMPLETE ] && echo complete || echo partial )","resumed":$( [ -n "${RESUME_DIR:-}" ] && echo true || echo false ),
  "counts":{"planned":$nplan,"ok":$nok,"failed":$nfail,"timeout":$ntmo,"skipped":$nskip},
  "memory_verified":$( [ "${MEM_OK:-0}" = 1 ] && echo true || echo false ),
  "completeness":{"verdict":"$verdict","incomplete":"$(printf '%s' "$incomplete" | tr -d '\"' )"} }
RSEOF
  { echo; echo "## Completeness - $verdict"; echo "- steps: ok=$nok failed=$nfail timeout=$ntmo skipped=$nskip (planned=$nplan)"; [ -n "$incomplete" ] && echo "- incomplete:$incomplete"; echo "- resume: ./kit/ir-collect.sh --resume '$OUTDIR'"; } >> "$OUTDIR/SUMMARY.md" 2>/dev/null
  RUN_INCOMPLETE=$( [ "$verdict" = COMPLETE ] && echo 0 || echo 1 )

  # manifest LAST so it covers SUMMARY.md
  run_sh manifest MANIFEST-SHA256.txt "$D_LOG" 1800 0 "cd '$OUTDIR' && find . -type f ! -name 'MANIFEST-SHA256.txt' ! -path './99_logs/audit.log' ! -path './99_logs/errors.log' -print0 | xargs -0 sha256sum 2>/dev/null"
  # freeze + hash the custody trail itself (excluded above because it is still being written)
  cp -a "$AUDIT" "$D_LOG/audit.frozen.log" 2>/dev/null && ( cd "$OUTDIR" && sha256sum 99_logs/audit.frozen.log ) > "$OUTDIR/MANIFEST-audit-log.sha256" 2>/dev/null && audit "Custody trail frozen + hashed."

  # ship the sealed bundle: scp/rsync to a collection server, and/or HTTP(S) POST to a lab collector
  if [ -n "$NETWORK_DEST" ] || [ -n "$HTTP_DEST" ]; then
    audit "Sealing + shipping evidence (${HTTP_DEST:-$NETWORK_DEST})"
    local zip="$OUTDIR.tar.gz"
    run_sh seal-tar - "$D_LOG" 3600 0 "tar czf '$zip' -C '$OUT_ROOT' '$(basename "$OUTDIR")' && sha256sum '$zip' > '$zip.sha256'"
    if [ -n "$NETWORK_DEST" ]; then
      local SSHOPT="-o StrictHostKeyChecking=accept-new"
      [ -n "$IR_SSH_KNOWN_HOSTS" ] && SSHOPT="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$IR_SSH_KNOWN_HOSTS"
      if command -v rsync >/dev/null 2>&1; then
        run_step ship-rsync - "$D_LOG" 3600 0 rsync -avz -e "ssh $SSHOPT" "$zip" "$zip.sha256" "$NETWORK_DEST/"
      elif command -v scp >/dev/null 2>&1; then
        run_step ship-scp - "$D_LOG" 3600 0 scp $SSHOPT "$zip" "$zip.sha256" "$NETWORK_DEST/"
      else audit "No rsync/scp - evidence kept locally at $zip"; fi
    fi
    if [ -n "$HTTP_DEST" ] && [ -f "$zip" ]; then
      local url="$HTTP_DEST"; case "$HTTP_DEST" in */) url="$HTTP_DEST$(basename "$zip")";; esac
      if command -v curl >/dev/null 2>&1; then
        run_step ship-http - "$D_LOG" 3600 0 curl -fsS --max-time 3600 -T "$zip" "$url"
      elif command -v wget >/dev/null 2>&1; then
        run_step ship-http - "$D_LOG" 3600 0 wget -q --method=PUT --body-file="$zip" -O /dev/null "$url"
      else audit "No curl/wget - HTTP upload skipped; evidence kept locally at $zip"; fi
    fi
  fi

  if [ "${LAB:-0}" = "1" ] && [ -z "$NETWORK_DEST" ] && [ -z "$HTTP_DEST" ]; then
    local leaf; leaf="$(basename "$OUTDIR")"
    case "$HYPERVISOR" in
      vmware)     hint="govc guest.download -vm <VM> -l <u>:<p> '$OUTDIR' ./$leaf  (VMware Tools guest ops)";;
      virtualbox) hint="VBoxManage guestcontrol <VM> copyfrom --username <u> --password <p> --recursive '$OUTDIR' './$leaf'";;
      hyper-v)    hint="Hyper-V LIS: copy '$OUTDIR' out via a mounted share, or snapshot+offline-mount the guest disk";;
      qemu-kvm)   hint="Proxmox/QEMU: qm guest exec <vmid> -- tar czf - '$OUTDIR' > $leaf.tgz , or 'guestmount -a disk.qcow2 --ro'";;
      *)          hint="Pull '$OUTDIR' via your hypervisor guest file-copy / shared folder, or re-run with -d <IP|user@host:path|http://collector>";;
    esac
    echo "LAB: evidence left in-guest at $OUTDIR. Host-side pull:"
    echo "  $hint"
    audit "LAB host-pull hint ($HYPERVISOR): $hint"
  fi
  audit "===== ir-collect DONE | OK=$STEPS_OK FAIL=$STEPS_FAIL TOTAL=$STEP_NUM ====="
  echo; echo "Collection complete. Output: $OUTDIR"
  echo "Summary: $OUTDIR/SUMMARY.md  |  Audit: $AUDIT"
}

# ---------------------------------------------------------------------------
# VOLATILE GREEN gate - confirm the perishable data is captured before the
# slow non-volatile phase. This is the checkpoint the operator waits for.
# ---------------------------------------------------------------------------
SEALED=0
volatile_green_gate() {
  local vol_files; vol_files=$(find "$D_VOL" "$D_NET" -type f 2>/dev/null | wc -l | tr -d ' ')
  local enc=0; grep -q '^ENCRYPTED=yes' "$D_META/encryption.txt" 2>/dev/null && enc=1
  local memnote; [ "${MEM_OK:-0}" = "1" ] && memnote="RAM: VERIFIED ($((MEM_BYTES/1024/1024)) MB)" || memnote="RAM: NOT verified - capture failed/absent"
  echo
  if [ "$enc" = "1" ] && [ "${MEM_OK:-0}" != "1" ]; then
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "  !!  VOLATILE: AMBER - ENCRYPTED DISK + NO VERIFIED RAM   !!"
    echo "  !!  The LUKS master key is in RAM you did NOT capture.   !!"
    echo "  !!  Do NOT power off without the key or the disk image   !!"
    echo "  !!  is unreadable. See 00_metadata/encryption.txt.       !!"
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    audit "VOLATILE AMBER | encrypted disk + no verified RAM | files=$vol_files"
  elif [ "$vol_files" -ge 10 ] && [ "${MEM_OK:-0}" = "1" ]; then
    echo "  ############################################################"
    echo "  #   VOLATILE CAPTURE: GREEN  ($vol_files artifacts, OK=$STEPS_OK FAIL=$STEPS_FAIL)"
    echo "  #   $memnote"
    echo "  #   Perishable data secured in order of volatility."
    echo "  #   Safe to proceed to the SLOW non-volatile phase."
    echo "  ############################################################"
    audit "VOLATILE GREEN | files=$vol_files memOk=${MEM_OK:-0} OK=$STEPS_OK FAIL=$STEPS_FAIL"
  else
    echo "  !!! VOLATILE: AMBER - $memnote ; $vol_files artifacts. Review 99_logs/errors.log."
    audit "VOLATILE AMBER | files=$vol_files memOk=${MEM_OK:-0}"
  fi
  echo
}

# self-heal: guarantee we always seal, even on Ctrl-C / unexpected exit
finish() { [ "$SEALED" = "0" ] && { SEALED=1; seal; }; }
trap 'audit "signal caught - sealing what we have"; finish; exit 0' INT TERM
trap 'finish' EXIT

# ---------------------------------------------------------------------------
# GUIDED INTAKE - a few questions about the source/compromised host that drive
# the volatile->non-volatile collection. Includes a vantage-decision preamble.
# ---------------------------------------------------------------------------
GUIDED=0; VOL_ONLY=0; PLAN=""; DO_NO_HARM=0
sani() { printf '%s' "$1" | tr -d '\\"'; }
json_arr() {  # split on comma/space -> ["a","b"]
  local out="" x; local IFS=', '; set -f; local a=($1); set +f
  for x in "${a[@]}"; do x="$(sani "$x")"; [ -n "$x" ] && out="$out\"$x\","; done; printf '[%s]' "${out%,}"; }
json_arr_c() {  # split on comma only (paths may contain spaces) -> ["a b","c"]
  local out="" x; local OLD="$IFS"; IFS=','; set -f; local a=($1); set +f; IFS="$OLD"
  for x in "${a[@]}"; do x="$(sani "$(echo "$x" | sed 's/^ *//; s/ *$//')")"; [ -n "$x" ] && out="$out\"$x\","; done; printf '[%s]' "${out%,}"; }
guided_intake() {
  [ -e /dev/tty ] || return
  echo; echo "================ GUIDED INTAKE ================"
  echo "-- Vantage check: is running on THIS box the right move? --"
  read -rp "Is this host a VM or cloud instance? (y/N) " VMC </dev/tty
  case "$VMC" in [yY]*) echo "  -> Prefer a SNAPSHOT (VMware .vmem/.vmdk, or cloud disk snapshot to a clean forensic instance). Run me only if you can't snapshot.";; esac
  read -rp "Is C2 / attacker traffic believed LIVE now? (y/N) " C2L </dev/tty
  case "$C2L" in [yY]*) echo "  -> Capture NETWORK off-host FIRST (PCAP at a TAP/SPAN; firewall/proxy/DNS logs). Running me can tip the attacker; keep enrichment PASSIVE.";; esac

  echo; echo "-- Incident scenario (drives collection order + detection handoff) --"
  echo "  1  Ransomware / destructive"
  echo "  2  BEC / cloud (M365/Entra) account compromise"
  echo "  3  Insider threat / data exfiltration"
  echo "  4  Web-server / public-app compromise (webshell)"
  echo "  5  Commodity malware / C2 beacon"
  echo "  6  Active Directory / Domain-Controller compromise"
  echo "  7  Lateral movement / credential theft"
  echo "  8  Living-off-the-land / fileless"
  echo "  9  Phishing initial access"
  echo "  10 Cryptomining"
  echo "  U  Unknown / broad triage"
  read -rp "Select scenario [U] " SCEN </dev/tty; SCEN="$(echo "${SCEN:-U}" | tr a-z A-Z)"
  case "$SCEN" in
    1)  SCEN_NAME="Ransomware / destructive"; PLAN="artifacts persistence"; ATTACK="T1486,T1490,T1489,T1562.001"; FIRST="RAM FIRST (keys/beacon may be resident); check for deleted backups/snapshots (LVM/.snapshot/borg/restic); filesystem timeline via artifacts. DO NOT reboot.";;
    2)  SCEN_NAME="BEC / cloud account compromise"; PLAN="artifacts"; ATTACK="T1078.004,T1114.003,T1098.002"; FIRST="Mostly OFF-HOST: pull M365 Unified Audit Log / Entra or cloud-IdP logs, forwarding rules, OAuth grants (docs/SCENARIOS.md). On-host is secondary.";;
    3)  SCEN_NAME="Insider threat / data exfiltration"; PLAN="artifacts persistence filehashes"; ATTACK="T1567.002,T1052.001,T1560"; FIRST="Live process/handles + current network (rclone/scp/rsync in flight) + mounted media while live; then shell histories + ~/.config/rclone.";;
    4)  SCEN_NAME="Web-server / public-app compromise (webshell)"; PLAN="weblogs artifacts persistence"; ATTACK="T1190,T1505.003,T1059"; FIRST="Live ss + process tree of the web service FIRST (memory-only shells), then web logs + webroot mtime timeline (job 7).";;
    5)  SCEN_NAME="Commodity malware / C2 beacon"; PLAN="artifacts persistence"; ATTACK="T1071.001,T1071.004,T1573,T1055"; FIRST="RAM FIRST (beacon/injected code is memory-only), then live conn->PID->exe hash (/proc/<pid>/exe), DNS.";;
    6)  SCEN_NAME="AD / Domain-Controller compromise"; PLAN="artifacts ad persistence"; ATTACK="T1003.006,T1558.001,T1207,T1003.003"; FIRST="Kerberos tickets (klist) + sssd/realm state + krb5.keytab; the Windows DCs are the primary target - this Linux host is a supporting angle.";;
    7)  SCEN_NAME="Lateral movement / credential theft"; PLAN="artifacts persistence ad"; ATTACK="T1021.004,T1078,T1552.004"; FIRST="auth.log/secure (SSH lateral), ~/.ssh (authorized_keys/known_hosts/id_*), lastlog/wtmp/btmp, live sessions.";;
    8)  SCEN_NAME="Living-off-the-land / fileless"; PLAN="artifacts persistence"; ATTACK="T1059.004,T1071,T1546"; FIRST="RAM + live process cmdlines (/proc/<pid>/cmdline), shell histories, /dev/shm + /tmp payloads, cron/systemd transient units.";;
    9)  SCEN_NAME="Phishing initial access"; PLAN="artifacts persistence"; ATTACK="T1566,T1204,T1059"; FIRST="Downloads + /tmp payloads, mail spools, browser history; on Linux usually a server pivot - chain to C2/lateral.";;
    10) SCEN_NAME="Cryptomining"; PLAN="persistence artifacts"; ATTACK="T1496,T1543.002,T1053.003"; FIRST="Live high-CPU process + cmdline + pool connections, cron/systemd/rc.local persistence, /tmp+/dev/shm miners; check for rootkit-hidden PIDs.";;
    *)  SCEN="U"; SCEN_NAME="Unknown / broad triage"; PLAN="artifacts persistence ad"; ATTACK=""; FIRST="Standard RFC 3227 order-of-volatility triage.";;
  esac
  echo "  -> FIRST: $FIRST"

  # mobile device trigger: a phone is often the real endpoint (BEC token / smishing / exfil target)
  case "$SCEN" in 2) MOBPROF=bec;; 3) MOBPROF=exfil;; 9) MOBPROF=smish;; 5) MOBPROF=beacon;; 10) MOBPROF=spyware;; 6|7) MOBPROF=token;; 1) MOBPROF=ransom;; *) MOBPROF=U;; esac
  read -rp "Was a MOBILE device involved (victim / exfil target / MFA-auth / lateral)? (y/N) " mi </dev/tty
  case "$mi" in [yY]*) MOBILE_INVOLVED=1; echo "  -> Acquire the phone from an EXAMINER box (docs/MOBILE.md). Suggested:";
    echo "     ./mobile-collect.sh -c $CASE -d <dest> --android|--ios --scenario $MOBPROF --analyze --faraday --authorizer '$AUTHORIZER'";; *) MOBILE_INVOLVED=0;; esac

  echo; echo "-- Host role / environment --"
  echo "  [1] Workstation  [2] Server  [3] Cloud VM  [4] Container/k8s node  [5] OT/ICS  [6] Network device"
  read -rp "Select role [2] " ROLE </dev/tty; ROLE="${ROLE:-2}"
  case "$ROLE" in
    1) HOST_ROLE="workstation";;
    3) HOST_ROLE="cloud-vm"; echo "  -> Cloud VM: prefer a disk SNAPSHOT to a clean forensic instance; also pull cloud control-plane logs (CloudTrail/Activity/Audit).";;
    4) HOST_ROLE="container"; echo "  -> Container/k8s: capture running-container state FAST (docker/crictl ps, image digests, diffs, SA tokens, kube audit) - pods are ephemeral. This captures the NODE.";;
    5) HOST_ROLE="ot-ics"; DO_NO_HARM=1; echo "  -> OT/ICS DO-NO-HARM mode: no filesystem-hash walk / disk image / active enum. Host-only + passive. Availability > evidence.";;
    6) HOST_ROLE="network-device"; echo "  -> Network device: collect OFF-box (config, ARP/CAM, routing, syslog, NetFlow) via console - this host tool does not apply.";;
    *) HOST_ROLE="server";;
  esac

  read -rp "Scope: single host or fleet? (s/F) " SCOPE_IN </dev/tty
  case "$SCOPE_IN" in [fF]*) SCOPE="fleet"; echo "  -> Fleet: promote to a Velociraptor HUNT (in tools/) - a targeted artifact set, not USB-per-box.";; *) SCOPE="single";; esac
  read -rp "Connectivity: connected or airgapped/quarantined? (c/A) " CONN_IN </dev/tty
  case "$CONN_IN" in [aA]*) CONNECTIVITY="airgapped";; *) CONNECTIVITY="connected";; esac

  echo; echo "-- Known-bad indicators you already hold (comma-separated, Enter to skip) --"
  read -rp "  Malicious IPs: " KB_IPS </dev/tty
  read -rp "  Malicious domains: " KB_DOMAINS </dev/tty
  read -rp "  Malicious hashes: " KB_HASHES </dev/tty
  read -rp "  Suspect accounts: " KB_ACCOUNTS </dev/tty
  read -rp "  Suspect files/paths: " KB_PATHS </dev/tty

  echo; echo "-- Scope-out (Enter to skip) --"
  read -rp "Earliest suspected activity (UTC): " FIRST_UTC </dev/tty
  read -rp "When detected (UTC): " DETECT_UTC </dev/tty
  read -rp "Crown jewels in scope: " CROWN </dev/tty
  read -rp "Data at risk (PII/PHI/PCI/IP/creds/none) [unknown]: " DATARISK </dev/tty; DATARISK="${DATARISK:-unknown}"
  read -rp "Severity 1-4 (1=critical) [3]: " SEVERITY </dev/tty; SEVERITY="${SEVERITY:-3}"

  read -rp "Is this host believed COMPROMISED? (Y/n) " a </dev/tty
  case "$a" in [nN]*) COMPROMISED=0;; *) COMPROMISED=1; echo "  -> Trusted-tool posture (carried tools + raw /proc). RAM + dead-box are ground truth.";; esac
  if lsblk -o TYPE,FSTYPE 2>/dev/null | grep -qiE 'crypt|luks'; then
    echo "  -> LUKS/dm-crypt DETECTED. The master key is in the RAM image - do NOT power off without it (or a recovery key)."; fi

  # role overlays on the plan
  [ "$HOST_ROLE" = "ot-ics" ] && PLAN="$(echo "$PLAN" | sed -E 's/(^| )filehashes( |$)/ /g; s/(^| )diskimage( |$)/ /g')"
  [ "$SKIP_AD" = "1" ] && PLAN="$(echo "$PLAN" | sed -E 's/(^| )ad( |$)/ /g')"
  PLAN="$(echo "$PLAN" | tr -s ' ' | sed 's/^ //; s/ $//')"

  # write intake.json - seeds the detection generator with operator-supplied known-bad IOCs
  cat > "$D_META/intake.json" 2>/dev/null <<EOF
{ "case_id":"$(sani "$CASE")","exercise":${LAB:-0},"mobile_involved":${MOBILE_INVOLVED:-0},"mobile_profile":"${MOBPROF:-U}","scenario":"$SCEN","scenario_name":"$(sani "$SCEN_NAME")",
  "attack_tags":$(json_arr "$ATTACK"),
  "host_role":"$HOST_ROLE","scope":"$SCOPE","connectivity":"$CONNECTIVITY",
  "known_bad_ips":$(json_arr "$KB_IPS"),"known_bad_domains":$(json_arr "$KB_DOMAINS"),
  "known_bad_hashes":$(json_arr "$KB_HASHES"),"known_bad_accounts":$(json_arr "$KB_ACCOUNTS"),
  "known_bad_paths":$(json_arr_c "$KB_PATHS"),
  "first_activity_utc":"$(sani "$FIRST_UTC")","detection_utc":"$(sani "$DETECT_UTC")",
  "crown_jewels":"$(sani "$CROWN")","data_at_risk":"$(sani "$DATARISK")","severity":"$(sani "$SEVERITY")",
  "plan":"$PLAN","generated_by":"ir-collect.sh" }
EOF
  GUIDED=1
  echo; echo "Plan: RAM+volatile -> GREEN gate -> ${PLAN:-seal}"
  echo "Scenario: $SCEN_NAME  |  Role: $HOST_ROLE  |  Scope: $SCOPE  |  ATT&CK: $ATTACK"
  audit "INTAKE scenario=$SCEN role=$HOST_ROLE scope=$SCOPE plan=$PLAN"
  read -rp "Press Enter to begin (Ctrl-C to abort) " _ </dev/tty
}

# ===========================================================================
# MAIN
# ===========================================================================
# guided intake is the default when interactive and no mode flag was given
if [ -n "${RESUME_DIR:-}" ]; then load_prior_state "$OUTDIR"
elif [ "$AUTO" != "1" ] && [ "$RAPID_ONLY" != "1" ] && [ -e /dev/tty ]; then guided_intake; fi

integrity_baseline
rapid_volatile
volatile_green_gate

if [ "$RAPID_ONLY" = "1" ] || [ "$VOL_ONLY" = "1" ]; then
  echo "volatile-only - sealing."
elif [ "$AUTO" = "1" ]; then
  audit "Auto mode: running ALL heavy (non-volatile) jobs."
  job_memory; job_artifacts; job_persistence; job_ad; job_filehashes; job_diskimage; job_weblogs
elif [ "$GUIDED" = "1" ]; then
  audit "Guided plan: $PLAN"
  for j in $PLAN; do "job_$j" || audit "job_$j fault - continuing"; done
  run_menu   # add more / then seal
else
  run_menu
fi
finish   # seal (trap also guards this)

# --- exit-code contract (parity with IR-Collect.ps1): 0 clean | 10 skips | 20 no-RAM | 40 fatal ---
EXIT_CODE=0
[ "${STEPS_FAIL:-0}" -gt 0 ] && EXIT_CODE=10
[ "${RUN_INCOMPLETE:-0}" = "1" ] && EXIT_CODE=15
[ "${MEM_OK:-0}" != "1" ] && [ "$RAPID_ONLY" != "1" ] && EXIT_CODE=20
audit "EXIT $EXIT_CODE (0=clean 10=skips 20=no-RAM 40=fatal)"
exit $EXIT_CODE
