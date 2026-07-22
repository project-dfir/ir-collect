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
    --skip-ad)        SKIP_AD=1; shift ;;
    --defer-memory)   DEFER_MEM=1; shift ;;
    -h|--help)        grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

now_utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ; }
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
NETWORK_DEST=""
if echo "$DEST" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(:.*)?$' || echo "$DEST" | grep -q '@'; then
  NETWORK_DEST="$DEST"
  # bare IP -> default remote path
  echo "$DEST" | grep -q ':' || NETWORK_DEST="${DEST}:/tmp/evidence"
  OUT_ROOT="$SCRIPT_DIR/_staging"
  if ! mkdir -p "$OUT_ROOT" 2>/dev/null; then
    OUT_ROOT="/tmp/_ir_staging"; mkdir -p "$OUT_ROOT" 2>/dev/null
    echo "!!! CONTAMINATION WARNING: cannot stage on the collection media - falling back to the TARGET disk ($OUT_ROOT)."
    echo "    This writes evidence onto the subject host. Attach writable removable media and re-run if at all possible. !!!"
  fi
else
  OUT_ROOT="$DEST"
fi
OUTDIR="$OUT_ROOT/${CASE}_${HOSTN}_${STAMP}"

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

run_step() {
  local name="$1" outfile="$2" dir="$3" tmo="$4" retries="$5"; shift 5
  STEP_NUM=$((STEP_NUM+1)); local id; id="$(printf '%03d' "$STEP_NUM")"
  local target="/dev/null"; [ "$outfile" != "-" ] && target="$dir/$outfile"
  local attempt=0 rc=0 start; start="$(date +%s)"
  while [ "$attempt" -le "$retries" ]; do
    attempt=$((attempt+1))
    # stdin closed (</dev/null) so no tool can block on an interactive prompt
    if [ -n "$SETSID" ]; then
      # PREFERRED: run in a NEW process group so the watchdog kills the WHOLE pipeline
      # (dd|gzip), not just the parent shell. GNU `timeout` only signals its direct child,
      # so pipeline grandchildren would be orphaned and keep writing - hence setsid first.
      if [ "$target" = "/dev/null" ]; then $SETSID "$@" </dev/null >>"$AUDIT" 2>>"$ERRLOG" &
      else $SETSID "$@" </dev/null >"$target" 2>>"$ERRLOG" & fi
      local pid=$!; local kt="-$pid"
      ( sleep "$tmo"; kill -TERM "$kt" 2>/dev/null; sleep 5; kill -KILL "$kt" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!
      wait "$pid" 2>/dev/null; rc=$?
      kill "$wd" 2>/dev/null; pkill -P "$wd" 2>/dev/null
    elif [ "$have_timeout" = "1" ]; then
      if [ "$target" = "/dev/null" ]; then timeout $TMO_K "$tmo" "$@" </dev/null >>"$AUDIT" 2>>"$ERRLOG"; rc=$?
      else timeout $TMO_K "$tmo" "$@" </dev/null >"$target" 2>>"$ERRLOG"; rc=$?; fi
    else
      # neither setsid nor timeout: best-effort single-pid watchdog
      if [ "$target" = "/dev/null" ]; then "$@" </dev/null >>"$AUDIT" 2>>"$ERRLOG" &
      else "$@" </dev/null >"$target" 2>>"$ERRLOG" & fi
      local pid=$!
      ( sleep "$tmo"; kill -TERM "$pid" 2>/dev/null; sleep 5; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!; wait "$pid" 2>/dev/null; rc=$?; kill "$wd" 2>/dev/null
    fi
    local dur=$(( $(date +%s) - start ))
    if [ "$rc" = "0" ]; then
      audit "STEP $id OK   | $name | ${dur}s | try $attempt${outfile:+ -> $outfile}"
      STEPS_OK=$((STEPS_OK+1)); return 0
    elif [ "$rc" = "124" ] || [ "$rc" = "137" ] || [ "$rc" = "143" ]; then
      audit "STEP $id WARN | $name | TIMEOUT ${tmo}s | try $attempt"
    else
      audit "STEP $id ERR  | $name | rc=$rc | try $attempt"
    fi
    [ "$attempt" -le "$retries" ] && sleep 0.4
  done
  echo "$(now_utc) [$id] $name : failed rc=$rc" >> "$ERRLOG"
  STEPS_FAIL=$((STEPS_FAIL+1)); return 0     # swallow: never abort
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
  "kernel":"$(uname -a 2>/dev/null | sed 's/"/ /g')","toolsDetected":"${DET# }" }
EOF
# default intake.json (overwritten by guided intake); the detection generator always finds one
cat > "$D_META/intake.json" 2>/dev/null <<EOF
{ "case_id":"$CASE","scenario":"U","scenario_name":"Unknown / broad triage","host_role":"unknown","scope":"single","connectivity":"connected","generated_by":"ir-collect.sh (non-guided)","known_bad_ips":[],"known_bad_domains":[],"known_bad_hashes":[],"known_bad_accounts":[],"known_bad_paths":[],"attack_tags":[] }
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

  # manifest LAST so it covers SUMMARY.md
  run_sh manifest MANIFEST-SHA256.txt "$D_LOG" 1800 0 "cd '$OUTDIR' && find . -type f ! -name 'MANIFEST-SHA256.txt' ! -path './99_logs/audit.log' ! -path './99_logs/errors.log' -print0 | xargs -0 sha256sum 2>/dev/null"
  # freeze + hash the custody trail itself (excluded above because it is still being written)
  cp -a "$AUDIT" "$D_LOG/audit.frozen.log" 2>/dev/null && ( cd "$OUTDIR" && sha256sum 99_logs/audit.frozen.log ) > "$OUTDIR/MANIFEST-audit-log.sha256" 2>/dev/null && audit "Custody trail frozen + hashed."

  # ship to network destination
  if [ -n "$NETWORK_DEST" ]; then
    audit "Shipping evidence to $NETWORK_DEST"
    local zip="$OUTDIR.tar.gz"
    # host-key pinning: set IR_SSH_KNOWN_HOSTS to a pre-provisioned known_hosts to defeat first-contact
    # MITM on evidence in transit (aligns with the most-secure-route rule); else fall back to TOFU.
    local SSHOPT="-o StrictHostKeyChecking=accept-new"
    [ -n "$IR_SSH_KNOWN_HOSTS" ] && SSHOPT="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$IR_SSH_KNOWN_HOSTS"
    run_sh seal-tar - "$D_LOG" 3600 0 "tar czf '$zip' -C '$OUT_ROOT' '$(basename "$OUTDIR")' && sha256sum '$zip' > '$zip.sha256'"
    if command -v rsync >/dev/null 2>&1; then
      run_step ship-rsync - "$D_LOG" 3600 0 rsync -avz -e "ssh $SSHOPT" "$zip" "$zip.sha256" "$NETWORK_DEST/"
    elif command -v scp >/dev/null 2>&1; then
      run_step ship-scp - "$D_LOG" 3600 0 scp $SSHOPT "$zip" "$zip.sha256" "$NETWORK_DEST/"
    else
      audit "No rsync/scp - evidence kept locally at $zip"
    fi
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
    1)  SCEN_NAME="Ransomware / destructive"; PLAN="artifacts persistence"; ATTACK="T1486,T1490,T1489,T1496"; FIRST="RAM FIRST (keys/beacon may be resident); check for deleted backups/snapshots (LVM/.snapshot/borg/restic); filesystem timeline via artifacts. DO NOT reboot.";;
    2)  SCEN_NAME="BEC / cloud account compromise"; PLAN="artifacts"; ATTACK="T1078.004,T1114.003,T1098.002"; FIRST="Mostly OFF-HOST: pull M365 Unified Audit Log / Entra or cloud-IdP logs, forwarding rules, OAuth grants (docs/SCENARIOS.md). On-host is secondary.";;
    3)  SCEN_NAME="Insider threat / data exfiltration"; PLAN="artifacts persistence filehashes"; ATTACK="T1567.002,T1052.001,T1560"; FIRST="Live process/handles + current network (rclone/scp/rsync in flight) + mounted media while live; then shell histories + ~/.config/rclone.";;
    4)  SCEN_NAME="Web-server / public-app compromise (webshell)"; PLAN="weblogs artifacts persistence"; ATTACK="T1190,T1505.003,T1059"; FIRST="Live ss + process tree of the web service FIRST (memory-only shells), then web logs + webroot mtime timeline (job 7).";;
    5)  SCEN_NAME="Commodity malware / C2 beacon"; PLAN="artifacts persistence"; ATTACK="T1071.001,T1071.004,T1573,T1055"; FIRST="RAM FIRST (beacon/injected code is memory-only), then live conn->PID->exe hash (/proc/<pid>/exe), DNS.";;
    6)  SCEN_NAME="AD / Domain-Controller compromise"; PLAN="artifacts ad persistence"; ATTACK="T1003.006,T1558,T1207"; FIRST="Kerberos tickets (klist) + sssd/realm state + krb5.keytab; the Windows DCs are the primary target - this Linux host is a supporting angle.";;
    7)  SCEN_NAME="Lateral movement / credential theft"; PLAN="artifacts persistence ad"; ATTACK="T1021.004,T1078,T1552.004"; FIRST="auth.log/secure (SSH lateral), ~/.ssh (authorized_keys/known_hosts/id_*), lastlog/wtmp/btmp, live sessions.";;
    8)  SCEN_NAME="Living-off-the-land / fileless"; PLAN="artifacts persistence"; ATTACK="T1059.004,T1071,T1546"; FIRST="RAM + live process cmdlines (/proc/<pid>/cmdline), shell histories, /dev/shm + /tmp payloads, cron/systemd transient units.";;
    9)  SCEN_NAME="Phishing initial access"; PLAN="artifacts persistence"; ATTACK="T1566,T1204,T1059"; FIRST="Downloads + /tmp payloads, mail spools, browser history; on Linux usually a server pivot - chain to C2/lateral.";;
    10) SCEN_NAME="Cryptomining"; PLAN="persistence artifacts"; ATTACK="T1496,T1543.002,T1053.003"; FIRST="Live high-CPU process + cmdline + pool connections, cron/systemd/rc.local persistence, /tmp+/dev/shm miners; check for rootkit-hidden PIDs.";;
    *)  SCEN="U"; SCEN_NAME="Unknown / broad triage"; PLAN="artifacts persistence ad"; ATTACK=""; FIRST="Standard RFC 3227 order-of-volatility triage.";;
  esac
  echo "  -> FIRST: $FIRST"

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
{ "case_id":"$(sani "$CASE")","scenario":"$SCEN","scenario_name":"$(sani "$SCEN_NAME")",
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
if [ "$AUTO" != "1" ] && [ "$RAPID_ONLY" != "1" ] && [ -e /dev/tty ]; then guided_intake; fi

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
