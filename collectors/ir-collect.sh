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
#   sudo ./ir-collect.sh -d /mnt/usb --no-keys              # do NOT extract volume keys
#
# ENCRYPTION KEYS: while volumes are unlocked the collector captures the live dm-crypt
#   master keys (dmsetup --showkeys) and LUKS header backups into 00_metadata, because
#   after shutdown an image of an encrypted volume is unreadable without them. Those
#   outputs ARE the keys to the evidence - see 00_metadata/DECRYPTION-KEYS.md for handling
#   and for how to apply them later. Use --no-keys where that is out of scope.
#
# EXIT CODES: 0 clean | 10 completed-with-skips | 15 incomplete-critical | 20 RAM not
#   verified | 40 fatal.
#
# READING THE VERDICT - 99_logs/run_state.json holds machine-readable findings that the
#   console summary states only in passing. The three worth knowing before you act:
#
#   encryption_risk  THE DO-NOT-POWER-OFF SIGNAL. Three states, and the third is the point:
#       ok                 nothing to lose by shutting down (RAM captured, or no encrypted
#                          volume found).
#       encrypted-no-ram   an unlocked encrypted volume IS present and RAM was NOT captured.
#                          Power off and the disk image is unreadable. Capture keys first.
#       unknown-no-ram     the probe COULD NOT DETERMINE whether a volume is encrypted -
#                          lsblk missing or failed. This is NOT a claim that the disk is
#                          clear, and it is not a claim that it is encrypted. Treat it as
#                          encrypted-no-ram until a human establishes otherwise.
#
#   clock_provenance  whether the recorded timestamps can be anchored to real time, and by
#       what source. Timestamps from an unsynchronised clock still correlate internally, but
#       will not line up with any other host's log until the offset is known.
#
#   by_error_class  a tally of failures by kind. AN EMPTY MAP DOES NOT MEAN NOTHING WENT
#       WRONG: several conditions - a preflight refusal, a destination that cannot be
#       written - are handled before any class could be assigned. Read completeness.verdict
#       and the counts, not the absence of classes.
#
#   Ship results, when shipping was requested, are in <bundle>.ship.json beside the bundle.
# =============================================================================

set +e                      # self-heal: never abort on a single command failure
set -o pipefail 2>/dev/null || true

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
DEST="$(cd "$(dirname "$0")" && pwd)"
CASE="IR"
STEP_TIMEOUT=120
NO_KEYS=0            # --no-keys: skip volume-master-key / LUKS-header capture
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
    --no-keys)        NO_KEYS=1; shift ;;
    --auto)           AUTO=1; shift ;;
    --rapid-only)     RAPID_ONLY=1; shift ;;
    --resume)         RESUME_DIR="$2"; shift 2 ;;
    --skip-ad)        SKIP_AD=1; shift ;;
    --scenario)       SCENARIO_ARG="$2"; shift 2 ;;
    --host-role)      HOST_ROLE_ARG="$2"; shift 2 ;;
    --known-bad-ips)  KB_IPS_ARG="$2"; shift 2 ;;
    --known-bad-domains) KB_DOMAINS_ARG="$2"; shift 2 ;;
    --known-bad-hashes)  KB_HASHES_ARG="$2"; shift 2 ;;
    --defer-memory)   DEFER_MEM=1; shift ;;
    --lab|--training) LAB=1; shift ;;
    --authorizer)     AUTHORIZER="$2"; shift 2 ;;
    --legal)          LEGAL_BASIS="$2"; shift 2 ;;
    --scope)          SCOPE_NOTE="$2"; shift 2 ;;
    # Print ONLY the operator header - the block between the two banner lines. A plain
    # `grep '^#' "$0"` printed all 233 comment lines in the file, of which 197 were
    # implementation commentary written for whoever edits this script ("Pure (no I/O) so it
    # is unit-testable", repair_ledger_tail's rationale). A responder looking for what a
    # verdict means had to find it inside that. Documentation nobody can locate is not
    # documentation - see tests/unit/test-help-output.sh, which keeps the noise out.
    -h|--help)        awk 'NR==1{next} /^# ={10,}$/{if(s){exit} s=1; next} /^#/{sub(/^# ?/,""); print}' "$0"; exit 0 ;;
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

# --- hashing shim: sha256sum is NOT universal --------------------------------
# GNU coreutils has sha256sum; stock macOS has `shasum -a 256` (and `md5`, not md5sum);
# FreeBSD has `sha256`/`md5`; illumos has `digest`; some busybox builds have neither.
# This script explicitly supports macos/bsd/solaris (see OS_FAMILY above), and every hash
# site previously called sha256sum directly - so on those platforms the evidence manifest
# comes out EMPTY and the per-file hash walk writes 'ERR', silently, while the run seals.
# The Windows collector hit the same class of bug (Get-FileHash absent); keep both honest.
# Resolve ONCE at startup, and record it so the operator can see which backend was used.
HASH_BACKEND=none; MD5_BACKEND=none
if   command -v sha256sum >/dev/null 2>&1;                    then HASH_BACKEND=sha256sum
elif command -v shasum    >/dev/null 2>&1;                    then HASH_BACKEND=shasum
elif command -v sha256    >/dev/null 2>&1;                    then HASH_BACKEND=sha256
elif command -v openssl   >/dev/null 2>&1;                    then HASH_BACKEND=openssl
elif command -v digest    >/dev/null 2>&1;                    then HASH_BACKEND=digest
elif command -v python3   >/dev/null 2>&1;                    then HASH_BACKEND=python3
fi
if   command -v md5sum >/dev/null 2>&1;  then MD5_BACKEND=md5sum
elif command -v md5    >/dev/null 2>&1;  then MD5_BACKEND=md5
elif command -v openssl >/dev/null 2>&1; then MD5_BACKEND=openssl
elif command -v python3 >/dev/null 2>&1; then MD5_BACKEND=python3
fi
# irhash <file> -> bare lowercase hex digest on stdout (empty + rc1 if nothing works)
# Every backend is funnelled through a shape check. A backend that is present but non-functional
# (a Windows Store python3 stub, a truncated pipe, an SELinux-denied helper) can exit 0 having
# printed nothing or printed a warning. Returning that as a digest would put a bogus value in
# MANIFEST-SHA256.csv, which is worse than no digest at all - a manifest is a custody claim.
# Fail loudly instead so the caller records ERR. Measured 2026-07-28: python3 present but
# emitting nothing on a Windows test host.
irhash() {
  local d; d="$(_irhash_raw "$1")" || return 1
  case "$d" in
    *[!0-9a-fA-F]*|'') return 1 ;;
  esac
  [ "${#d}" = 64 ] || return 1
  printf '%s' "$d"
}
_irhash_raw() {
  local f="$1"
  case "$HASH_BACKEND" in
    sha256sum) sha256sum    -- "$f" 2>/dev/null | cut -d' ' -f1 ;;
    shasum)    shasum -a 256 -- "$f" 2>/dev/null | cut -d' ' -f1 ;;
    sha256)    sha256 -q     "$f" 2>/dev/null ;;
    openssl)   openssl dgst -sha256 "$f" 2>/dev/null | sed 's/.*= *//' ;;
    digest)    digest -a sha256 "$f" 2>/dev/null ;;
    python3)   python3 -c 'import hashlib,sys;h=hashlib.sha256()
f=open(sys.argv[1],"rb")
[h.update(c) for c in iter(lambda:f.read(1<<20),b"")]
print(h.hexdigest())' "$f" 2>/dev/null ;;
    *) return 1 ;;
  esac
}
irmd5() {
  local f="$1"
  case "$MD5_BACKEND" in
    md5sum)  md5sum -- "$f" 2>/dev/null | cut -d' ' -f1 ;;
    md5)     md5 -q "$f" 2>/dev/null ;;
    openssl) openssl dgst -md5 "$f" 2>/dev/null | sed 's/.*= *//' ;;
    python3) python3 -c 'import hashlib,sys;h=hashlib.md5()
f=open(sys.argv[1],"rb")
[h.update(c) for c in iter(lambda:f.read(1<<20),b"")]
print(h.hexdigest())' "$f" 2>/dev/null ;;
    *) return 1 ;;
  esac
}
# hash a whole tree the way the manifest needs it: "<digest>  <path>" per line
irhash_tree() { local base="$1"; shift
  ( cd "$base" 2>/dev/null || return 1
    find . -type f "$@" -print | while IFS= read -r f; do
      printf '%s  %s\n' "$(irhash "$f" 2>/dev/null || echo ERR)" "$f"
    done )
}
# run_sh executes snippets in `bash -c` children, so the shim must cross that boundary:
# export the functions AND the resolved backends they switch on.
export HASH_BACKEND MD5_BACKEND
# _irhash_raw MUST be exported alongside irhash: the manifest step runs via `bash -c`, which
# inherits only EXPORTED functions. When irhash was split into a validating wrapper plus this
# raw backend, exporting only the wrapper left it calling an undefined helper in the child, so
# every digest came back ERR - 43 of 48 rows in a measured run (2026-07-28) - while the local
# unit test passed because it evaluates both halves in one shell.
export -f irhash _irhash_raw irmd5 2>/dev/null || true
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

# Prove the ship target is reachable and writable NOW, not at seal time. Parity with the Windows
# twin's Test-NetworkDestination: measured there, an operator pointed at a destination they could
# not write to ran the ENTIRE collection before finding out.
#
# WARN, never refuse: the bundle is staged locally and is not at risk, so aborting would destroy
# volatile data over a credential or routing problem. Bounded, because an unreachable host is slow
# to fail and waiting longer than the operator would tolerate defeats the point of probing early.
NET_PROBE_OK=""; NET_PROBE_REASON=""
test_network_dest() {
  local dest="$1" host="${1%%:*}" path="${1#*:}" out=""
  [ -n "$dest" ] || return 0
  command -v ssh >/dev/null 2>&1 || { NET_PROBE_REASON="no ssh client to probe with"; return 1; }
  # stderr goes to its OWN file, never merged into the value being compared: ssh emits
  # "Warning: Permanently added ... to the list of known hosts" on first contact, and folding that
  # into stdout made the readback != "x" for a destination that was perfectly writable. Measured
  # 2026-07-28: a ship that SUCCEEDED was reported unwritable at preflight.
  local errf; errf="$(mktemp 2>/dev/null || echo /tmp/.irprobe.err.$$)"
  out="$(timeout 20 ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new          "$host" "mkdir -p '$path' && t=\"$path/.irprobe.\$\$\" && printf x > \"\$t\" && cat \"\$t\" && rm -f \"\$t\"" 2>"$errf")"
  local rc=$?
  if [ $rc -eq 124 ]; then rm -f "$errf"; NET_PROBE_REASON="no response within 20s (host unreachable or ssh hung)"; return 1; fi
  # verify the byte came BACK - an exit status alone does not prove the write landed
  if [ "$out" = "x" ]; then rm -f "$errf"; return 0; fi
  NET_PROBE_REASON="$(head -1 "$errf" 2>/dev/null | cut -c1-160)"
  rm -f "$errf"
  [ -n "$NET_PROBE_REASON" ] || NET_PROBE_REASON="probe wrote no readable byte back (rc=$rc)"
  return 1
}
if [ -n "$NETWORK_DEST" ]; then
  if test_network_dest "$NETWORK_DEST"; then
    NET_PROBE_OK=1
    # The audit log does not exist yet - this probe runs long before $OUTDIR/99_logs is created.
    # Calling audit() here wrote the verdict NOWHERE: measured 2026-07-28, zero bundles contained
    # the line. Buffer it and flush once the custody trail is open. (The console echo below is
    # immediate either way, so the operator is never left waiting for it.)
    PENDING_SHIP_AUDIT="PREFLIGHT ship target: $NETWORK_DEST is writable."
  else
    NET_PROBE_OK=0
    PENDING_SHIP_AUDIT="PREFLIGHT SHIP TARGET UNWRITABLE: $NETWORK_DEST - $NET_PROBE_REASON. Collection CONTINUES and the bundle will be retained locally; fix access now if you want it shipped."
    echo ""
    echo "  !! Ship target $NETWORK_DEST is NOT writable: $NET_PROBE_REASON"
    echo "  !! Collecting anyway - evidence is staged locally and will be retained there."
    echo "  !! Fix access now and the seal-time ship will succeed."
    echo ""
  fi
fi

else
  OUT_ROOT="$DEST"
  # read-only-media / non-writable target: redirect to a writable evidence location so we can run at all
  if ! ( mkdir -p "$OUT_ROOT" 2>/dev/null && ( : > "$OUT_ROOT/.w_$STAMP" ) 2>/dev/null ); then
    REDIR="${LAB_VOL:+$LAB_VOL/ir_evidence}"; [ -z "$REDIR" ] && REDIR="/var/tmp/ir_evidence"
    echo "Output '$OUT_ROOT' not writable (read-only media?). Redirecting evidence to $REDIR."
    OUT_ROOT="$REDIR"; mkdir -p "$OUT_ROOT" 2>/dev/null
  else rm -f "$OUT_ROOT/.w_$STAMP" 2>/dev/null; fi
fi
# Reduce the operator-supplied case id to something safe to put in a path. -c/--case is typed
# by a responder under time pressure and lands directly in the bundle directory name; an
# apostrophe breaks the single-quoted command this script generates for its manifest, a slash
# silently nests the bundle somewhere else, and glob characters break the Windows twin's
# path resolution. The ORIGINAL is preserved (CASE_RAW) and recorded, because the case id is a
# custody field that ties this bundle to the operator's paperwork - only the PATH form changes.
CASE_RAW="$CASE"
CASE="$(printf '%s' "$CASE" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)"
# run_state.json is hand-built, so the RAW case id has to be JSON-escaped before it goes in - an
# operator writing a quote in -c would otherwise emit invalid JSON in the one file a tool reads
# to learn what happened. (The Windows twin builds its rollup with ConvertTo-Json, which escapes.)
# Built with bash parameter expansion rather than sed: the escape sequences a sed script needs
# here are exactly the ones that get mangled in transit, and a silently broken sed produced an
# EMPTY value (measured 2026-07-28) - which would have written "case":"" into the rollup.
CASE_RAW_J="${CASE_RAW//\\/\\\\}"
CASE_RAW_J="${CASE_RAW_J//\"/\\\"}"
[ -n "$CASE" ] || CASE="IR"
# Refuse a destination that cannot hold a collection, BEFORE anything depends on it. Parity with
# the Windows twin, which has refused with exit 40 since scenario B2; this collector had no
# refusal path at all - its only non-zero early exit was for an unknown argument - so it would
# happily start a collection onto a full disk and die partway with nothing able to record why.
# Found 2026-07-28 by tests/unit/Test-ExitContract.ps1, which asserts both collectors implement
# the same exit contract.
#
# 64 MB is the same floor the Windows collector uses: below that a run cannot even write its own
# diagnostics, so starting one produces a bundle that explains nothing.
_preflight_dest() {
  local root="$1" need_kb=65536 free_kb=''
  mkdir -p "$root" 2>/dev/null || { echo "$root: cannot be created"; return 1; }
  ( : > "$root/.w_$STAMP" ) 2>/dev/null || { echo "$root: not writable"; return 1; }
  rm -f "$root/.w_$STAMP" 2>/dev/null
  free_kb="$(df -Pk "$root" 2>/dev/null | awk 'NR==2{print $4}')"
  case "$free_kb" in ''|*[!0-9]*) return 0 ;; esac   # unknown free space is not proof of failure
  [ "$free_kb" -ge "$need_kb" ] && return 0
  echo "$root: only $(( free_kb / 1024 )) MB free; a collection needs at least $(( need_kb / 1024 )) MB"
  return 1
}
_pf_msg="$(_preflight_dest "$OUT_ROOT")" || {
  echo "" >&2
  echo "  !! $_pf_msg" >&2
  echo "  !! Refusing to start: on a destination this small the run dies before it can record WHY." >&2
  echo "  !! Point -d at larger writable media, or free space and re-run." >&2
  echo "" >&2
  exit 40
}
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
# EXEC MODE - the Linux twin of the Windows collector's background-job vs in-process report.
# Which watchdog we get materially changes what a hung step does, so the operator must see it:
#   setsid-pgroup  - preferred: kills the WHOLE process group, so `dd | gzip` dies as a unit
#   timeout-cmd    - GNU timeout: signals only its direct child; pipeline grandchildren can orphan
#   bare-watchdog  - neither available (busybox/minimal): single-PID best-effort only
if   [ -n "$SETSID" ];        then EXEC_MODE="setsid-pgroup"
elif [ "$have_timeout" = 1 ]; then EXEC_MODE="timeout-cmd"
else                               EXEC_MODE="bare-watchdog"; fi
# operator/test override, mirrors IRCOLLECT_FORCE_INPROC on the Windows side
case "${IRCOLLECT_FORCE_EXEC:-}" in
  timeout)  SETSID=""; EXEC_MODE="timeout-cmd" ;;
  bare)     SETSID=""; have_timeout=0; EXEC_MODE="bare-watchdog" ;;
esac
NICE=""; command -v nice >/dev/null 2>&1 && NICE="nice -n 19"; command -v ionice >/dev/null 2>&1 && NICE="ionice -c3 $NICE"

# ===== completion ledger + self-troubleshoot + resume =====
NL=$'
'   # real newline, for building multi-line diagnostics strings
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r\t'; }
ledger() { # ledger id name phase ev [k=v ...]
  [ -n "${STATE_JSONL:-}" ] || return 0
  local id="$1" name="$2" phase="$3" ev="$4"; shift 4
  local extra=""; for kv in "$@"; do extra="$extra,\"${kv%%=*}\":\"$(jesc "${kv#*=}")\""; done
  printf '{"t":"%s","id":"%s","name":"%s","phase":"%s","ev":"%s"%s}\n' "$(now_utc)" "$id" "$(jesc "$name")" "$phase" "$ev" "$extra" >> "$STATE_JSONL" 2>/dev/null
}
# repair_ledger_tail: an ENOSPC mid-append leaves a PARTIAL final record, so run_state.jsonl stops
# being valid JSONL and strict parsers choke on the very file that explains the failure. Keep only
# complete records. Must run BOTH before the rollup reads the ledger and again at the very end,
# because seal's own steps (manifest, ship) append after the first pass and can truncate too.
repair_ledger_tail() {
  [ -s "${STATE_JSONL:-}" ] || return 0
  tail -1 "$STATE_JSONL" 2>/dev/null | grep -q "}$" && return 0
  local keep; keep="$(grep -c "}$" "$STATE_JSONL" 2>/dev/null)"
  if grep "}$" "$STATE_JSONL" > "$ERRTMP/ledger.fixed" 2>/dev/null && [ -s "$ERRTMP/ledger.fixed" ]; then
    cat "$ERRTMP/ledger.fixed" > "$STATE_JSONL" 2>/dev/null
    audit "LEDGER REPAIR: dropped a truncated final record from run_state.jsonl (kept ${keep:-0} complete records; destination likely filled)."
  fi
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
# Scratch for per-step stderr, deliberately NOT on the evidence filesystem (see run_step).
ERRTMP="$(mktemp -d 2>/dev/null || echo /tmp)"
# dest_has_space: can we still write to the evidence tree? Returns 1 when the destination is full.
# A write probe is authoritative where `df` can lie (quotas, reserved blocks, full inode table).
dest_has_space() {
  local probe="${D_LOG:-$OUTDIR}/.spaceprobe.$$"
  if ( : > "$probe" ) 2>/dev/null && printf '0123456789' >> "$probe" 2>/dev/null; then
    rm -f "$probe" 2>/dev/null; return 0
  fi
  rm -f "$probe" 2>/dev/null; return 1
}

declare -A REM_TRIED 2>/dev/null || true
redirect_dest() { for c in ${LAB_VOL:+"$LAB_VOL/ir_evidence"} /var/tmp/ir_evidence; do if mkdir -p "$c" 2>/dev/null && ( : > "$c/.w" ) 2>/dev/null; then rm -f "$c/.w"; echo "redirect:$c"; return; fi; done; echo none; }
backoff() { case "$1" in timeout|net_unreachable|rate_limit) echo $(( $2 * $2 ));; file_locked) echo 2;; *) echo 0;; esac; }
# remediate: 0 => retry now ; 1 => give up. Each (id,class) once; hard cap 3 attempts.
# --- SELF-FIX LADDERS ---------------------------------------------------------------------
# Parity with IR-Collect.ps1: every error class gets an ORDERED list of fix attempts, tried one
# per retry until one works or the rungs run out. The old design allowed exactly one remediation
# per (step,class) and most entries were LABELS, not actions - 'fallback-or-skip', 'pivot-flag',
# 'degraded-nonroot' were logged while the step gave up. The goal is to COMPLETE the collection,
# so each rung below either does something real or is named honestly as a marker.
fix_ladder() {  # fix_ladder <class> -> space-separated rungs, in order
  case "$1" in
    timeout)        echo "backoff-retry extend-timeout skip" ;;
    no_space)       echo "purge-scratch relocate-dest retry-in-place skip" ;;
    tool_missing)   echo "repair-toolkit native-source skip" ;;
    file_locked)    echo "settle-retry copy-nolock skip" ;;
    driver_blocked) echo "try-alt-imager native-source skip" ;;
    not_elevated)   echo "native-source skip" ;;
    net_unreachable|dns_blocked|rate_limit) echo "backoff-retry extend-timeout skip" ;;
    *)              echo "backoff-retry skip" ;;
  esac
}
declare -A REM_RUNG 2>/dev/null || true
declare -A TMO_BOOST 2>/dev/null || true

# invoke_fix_rung <rung> <name> <id> -> rc 0 means "retry the step now"
# A rung that cannot act says so rather than claiming a fix; a self-heal that lies is worse than
# one that does nothing.
invoke_fix_rung() {
  local rung="$1" name="$2" id="$3"
  case "$rung" in
    backoff-retry) return 0 ;;
    extend-timeout)
      TMO_BOOST[$id]=3
      audit "  FIX extend-timeout: step $id gets 3x its bound on the next attempt"
      return 0 ;;
    purge-scratch)
      # reclaim space we are responsible for before blaming the operator's disk
      local before after freed
      before=$(df -Pk "$OUTDIR" 2>/dev/null | awk 'NR==2{print $4}')
      find /tmp /var/tmp -maxdepth 1 -type f -mtime +1 -delete 2>/dev/null
      [ -n "${ERRTMP:-}" ] && find "$ERRTMP" -type f -mmin +5 -delete 2>/dev/null
      after=$(df -Pk "$OUTDIR" 2>/dev/null | awk 'NR==2{print $4}')
      freed=$(( ${after:-0} - ${before:-0} ))
      if dest_has_space; then
        audit "  FIX purge-scratch: reclaimed ${freed} KB; destination writable again"; return 0
      fi
      # "still full" is a claim about space. A destination that has been UNMOUNTED or removed is
      # not full, it is GONE, and telling the operator to free space sends them the wrong way.
      if [ ! -d "$OUTDIR" ]; then
        audit "  FIX purge-scratch: destination $OUTDIR NO LONGER EXISTS (unmounted or removed mid-run) - this is not a space problem"
      else
        audit "  FIX purge-scratch: reclaimed ${freed} KB but destination is still full"
      fi
      return 1 ;;
    relocate-dest)
      # ADDITIVE only: never move a part-written tree, but give later steps somewhere to land
      local alt; alt="$(redirect_dest)"
      if [ "$alt" != none ]; then
        OVERFLOW_DIR="${alt#redirect:}"
        audit "  FIX relocate-dest: overflow area available at $OVERFLOW_DIR (existing tree left in place)"
      else
        audit "  FIX relocate-dest: no writable overflow location found"
      fi
      return 1 ;;
    retry-in-place)
      audit "  FIX retry-in-place: destination still full; retrying once in case space was freed externally"
      return 0 ;;
    settle-retry) sleep 3; audit "  FIX settle-retry: waited for the holder to release"; return 0 ;;
    copy-nolock)
      audit "  FIX copy-nolock: will retry with a plain read (no flock); a live-mmap'd file may still refuse"
      return 0 ;;
    repair-toolkit)
      # a genuine repair: chmod +x, extract archives, re-discover carried binaries
      repair_toolkit >/dev/null 2>&1
      local n; n=$(find "${TOOL_DIR:-/nonexistent}" -maxdepth 3 -type f -perm -u+x 2>/dev/null | wc -l)
      audit "  FIX repair-toolkit: $n executable carried tools present after repair"
      [ "${n:-0}" -gt 0 ] && return 0 || return 1 ;;
    try-alt-imager)
      # LiME insmod refused (Secure Boot / lockdown / unsigned module) -> AVML needs no module
      if [ -n "${T_AVML:-}" ]; then
        audit "  FIX try-alt-imager: kernel module blocked, AVML present and needs no module - retrying with it"
        MEM_IMAGER=avml; return 0
      fi
      audit "  FIX try-alt-imager: kernel module blocked and no AVML staged - cannot acquire RAM"
      return 1 ;;
    native-source)
      audit "  FIX native-source: step-level fallback (procfs/native binaries) will be used on retry"
      return 0 ;;
    skip) return 1 ;;
    *) return 1 ;;
  esac
}

# remediate: climb the ladder for this class, one rung per attempt.
# rc 0 => retry now ; rc 1 => give up on this step
remediate() {
  local cls="$1" name="$2" id="$3" attempt="$4" rphase="${5:-other}"
  [ "$attempt" -ge 4 ] && return 1
  local ladder rungs n ix rung
  ladder="$(fix_ladder "$cls")"
  # shellcheck disable=SC2206
  rungs=($ladder); n=${#rungs[@]}
  local k="$id|$cls"
  ix=${REM_RUNG[$k]:-0}
  [ "$ix" -ge "$n" ] && return 1
  rung="${rungs[$ix]}"
  REM_RUNG[$k]=$((ix+1))

  [ "$cls" = no_space ] && DISK_FULL=1
  local retry=1
  if invoke_fix_rung "$rung" "$name" "$id"; then retry=0; fi
  local remaining=$(( n - ix - 1 ))
  ledger "$id" "$name" "$rphase" remediation "class=$cls" "action=$rung" "rung=$((ix+1))/$n" \
         "result=$( [ $retry = 0 ] && echo retry || echo next-or-stop )"
  audit "STEP $id REMEDIATE | $name | class=$cls rung $((ix+1))/$n=$rung -> $( [ $retry = 0 ] && echo retry || echo "advance ($remaining left)" )"
  # a rung that could not fix things still lets the ladder advance next attempt, while rungs
  # remain - that is the difference between a ladder and a single shot
  if [ $retry != 0 ] && [ "$remaining" -gt 0 ] && [ "$rung" != skip ]; then return 0; fi
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

# A step can exit 0 while writing nothing but a refusal. Measured on the Windows twin as a
# standard user (range-WS02, 2026-07-28): drivers 115096 B -> 155 B, netstat 8140 B -> 45 B -
# each an "Access is denied" stub that cleared every emptiness check and sealed as COMPLETE.
# The same shape occurs on Linux without root: /proc/*/exe, ss -p, dmesg, and the audit log all
# refuse rather than fail. Detect refusal-as-output so the verdict can tell the truth.
# Two independent signals, either sufficient: a small file mentioning a denial, or a file where
# denials outnumber content. Files over 64 KB are never stubs, so they are skipped outright -
# that also keeps a large healthy artifact quoting "Permission denied" from being misjudged.
DENIAL_RE='Permission denied|Operation not permitted|Access is denied|must be root|are you root|requires root|Insufficient privileges|not permitted'
DEGRADED_STEPS=""
test_degraded_output() {
  local path="$1" bytes="$2"
  [ -n "$path" ] && [ "$path" != "/dev/null" ] && [ -f "$path" ] || return 0
  [ "${bytes:-0}" -gt 0 ] 2>/dev/null || return 0
  [ "${bytes:-0}" -le 65536 ] 2>/dev/null || return 0
  local head_txt; head_txt="$(head -c 8192 "$path" 2>/dev/null)" || return 0
  printf '%s' "$head_txt" | grep -Eq "$DENIAL_RE" || return 0
  local total denials
  total="$(printf '%s\n' "$head_txt" | grep -c '[^[:space:]]' 2>/dev/null)"; [ -n "$total" ] || total=1
  [ "$total" -gt 0 ] 2>/dev/null || total=1
  denials="$(printf '%s\n' "$head_txt" | grep -Ec "$DENIAL_RE" 2>/dev/null)"; [ -n "$denials" ] || denials=0
  if [ "$bytes" -lt 4096 ] || [ $(( denials * 2 )) -ge "$total" ]; then
    printf '%s' "$(printf '%s\n' "$head_txt" | grep -Em1 "$DENIAL_RE" | cut -c1-160)"
  fi
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
  # the longest ladder is 4 rungs, so allow that many attempts - a rung that can never be tried is
  # the same unreachable-capability bug this project keeps finding
  [ "$retries" -lt 3 ] && retries=3
  # stderr scratch lives OFF the evidence filesystem on purpose: when the destination fills up,
  # a scratch file stored there captures nothing, classify_error sees empty stderr, and every
  # failure degrades to "unknown" - which is exactly when accurate classification matters most.
  local etmp="$ERRTMP/.err.$id"; : > "$etmp" 2>/dev/null
  while [ "$attempt" -le "$retries" ]; do
    attempt=$((attempt+1))
    # extend-timeout rung grants this step a larger bound for its remaining attempts
    local tmo_eff=$(( tmo * ${TMO_BOOST[$id]:-1} ))
    ledger "$id" "$name" "$phase" running "attempt=$attempt"
    # stdin closed (</dev/null) so no tool can block on an interactive prompt
    if [ -n "$SETSID" ]; then
      # PREFERRED: run in a NEW process group so the watchdog kills the WHOLE pipeline
      # (dd|gzip), not just the parent shell. GNU `timeout` only signals its direct child,
      # so pipeline grandchildren would be orphaned and keep writing - hence setsid first.
      if [ "$target" = "/dev/null" ]; then $SETSID "$@" </dev/null >>"$AUDIT" 2>"$etmp" &
      else $SETSID "$@" </dev/null >"$target" 2>"$etmp" & fi
      local pid=$!; local kt="-$pid"
      ( sleep "$tmo_eff"; kill -TERM "$kt" 2>/dev/null; sleep 5; kill -KILL "$kt" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!
      wait "$pid" 2>/dev/null; rc=$?
      kill "$wd" 2>/dev/null; pkill -P "$wd" 2>/dev/null
    elif [ "$have_timeout" = "1" ]; then
      if [ "$target" = "/dev/null" ]; then timeout $TMO_K "$tmo_eff" "$@" </dev/null >>"$AUDIT" 2>"$etmp"; rc=$?
      else timeout $TMO_K "$tmo_eff" "$@" </dev/null >"$target" 2>"$etmp"; rc=$?; fi
    else
      # neither setsid nor timeout: best-effort single-pid watchdog
      if [ "$target" = "/dev/null" ]; then "$@" </dev/null >>"$AUDIT" 2>"$etmp" &
      else "$@" </dev/null >"$target" 2>"$etmp" & fi
      local pid=$!
      ( sleep "$tmo_eff"; kill -TERM "$pid" 2>/dev/null; sleep 5; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
      local wd=$!; wait "$pid" 2>/dev/null; rc=$?; kill "$wd" 2>/dev/null
    fi
    cat "$etmp" >> "$ERRLOG" 2>/dev/null
    local dur=$(( $(date +%s) - start ))
    if [ "$rc" = "0" ]; then
      local bytes=0; [ "$target" != "/dev/null" ] && [ -f "$target" ] && bytes="$(fsize "$target")"
      local degr=""; degr="$(test_degraded_output "$target" "${bytes:-0}")"
      if [ -n "$degr" ]; then
        # exited 0 but wrote a refusal rather than data - not a success worth reporting as one
        DEGRADED_STEPS="$DEGRADED_STEPS $name"
        ledger "$id" "$name" "$phase" ok "attempt=$attempt" "duration_s=$dur" "out_file=$outfile" "out_bytes=${bytes:-0}" "degraded=true" "error_class=not_elevated"
        audit "STEP $id OK-DEGRADED | $name | output is an access refusal, not data (${bytes}B): $degr"
      else
        ledger "$id" "$name" "$phase" ok "attempt=$attempt" "duration_s=$dur" "out_file=$outfile" "out_bytes=${bytes:-0}"
        audit "STEP $id OK   | $name | ${dur}s | try $attempt${outfile:+ -> $outfile}"
      fi
      STEPS_OK=$((STEPS_OK+1)); rm -f "$etmp"; return 0
    fi
    # classify + bounded self-troubleshoot (each fix logged as a custody action)
    cls="$(classify_error "$name" "$rc" "$etmp")"
    # Structural fallback: a full destination often produces a bare non-zero rc with NO stderr
    # (the shell could not even write the redirect), so the text-matching classifier returns
    # "unknown" and the no_space remediation - the one built for this - can never fire.
    # Probe the destination directly instead of trusting the message.
    if [ "$cls" = unknown ] && ! dest_has_space; then cls=no_space; fi
    if remediate "$cls" "$name" "$id" "$attempt" "$phase"; then retries=$attempt; sleep "$(backoff "$cls" "$attempt")"; continue; fi
    if [ "$rc" = "124" ] || [ "$rc" = "137" ] || [ "$rc" = "143" ]; then audit "STEP $id WARN | $name | TIMEOUT ${tmo}s cls=$cls | try $attempt"
    else audit "STEP $id ERR  | $name | rc=$rc cls=$cls | try $attempt"; fi
    [ "$attempt" -le "$retries" ] && sleep 0.4
  done
  case "$rc" in 124|137|143) term=timeout;; *) term=failed;; esac
  # a killed step usually leaves EMPTY stderr, which left the diagnostics rollup showing a blank
  # sample for the timeout class (the Windows collector had the same gap) - synthesise a message
  local emsg; emsg="$(head -c 200 "$etmp" 2>/dev/null | tr -d '\n\r')"
  [ -z "$emsg" ] && [ "${term:-failed}" = timeout ] && emsg="exceeded ${tmo}s timeout"
  [ -z "$emsg" ] && emsg="exit code $rc, no stderr"
  ledger "$id" "$name" "$phase" "${term:-failed}" "attempt=$attempt" "exit_code=$rc" "error_class=${cls:-unknown}" "error_msg=$emsg"
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
[ -n "${PENDING_SHIP_AUDIT:-}" ] && audit "$PENDING_SHIP_AUDIT"
[ "$CASE_RAW" != "$CASE" ] && audit "CASE ID normalised for the filesystem: '$CASE_RAW' -> '$CASE'. The original is preserved here and in the run metadata; only the directory name was changed."
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
      p="$(command -v "$b" 2>/dev/null)"; [ -n "$p" ] && printf '%s  %s\n' "$(irhash "$p" 2>/dev/null || echo ERR)" "$p"
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
{ "tool":"ir-collect.sh","version":"2.0","case":"$CASE_RAW_J","case_path_token":"$CASE","host":"$HOSTN",
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
  # Each source is normalised to HOST MINUS REFERENCE (positive = host ahead) before it reaches
  # clock_verdict, so the sign convention lives in exactly one place per tool rather than being
  # re-derived by the reader. chronyc says "fast/slow" in words; ntpq reports reference-minus-host
  # in milliseconds, so it is negated.
  run_sh   meta-clock       clock_provenance.txt "$D_META" 30 1 'echo "Host local: $(date +%FT%T%z 2>/dev/null || date)"; echo "Host UTC:   $(date -u +%FT%T.%3NZ 2>/dev/null || date -u)"; src=""; ahead=""; if command -v chronyc >/dev/null 2>&1; then t="$(chronyc tracking 2>/dev/null)"; if [ -n "$t" ]; then src="chronyc ($(printf "%s" "$t" | awk -F": *" "/Reference ID/{print \$2; exit}"))"; ahead="$(printf "%s" "$t" | awk "/System time/{v=\$4; if (\$0 ~ /slow/) v=\"-\" v; print v; exit}")"; fi; fi; if [ -z "$src" ] && command -v ntpq >/dev/null 2>&1; then o="$(ntpq -pn 2>/dev/null | awk "/^\*/{print \$9; exit}")"; if [ -n "$o" ]; then src="ntpq"; ahead="$(awk -v m="$o" "BEGIN{printf \"%.6f\", -m/1000}")"; fi; fi; sync=""; if command -v timedatectl >/dev/null 2>&1; then sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"; fi; if [ -z "$src" ] && [ -n "$sync" ]; then src="timedatectl (NTPSynchronized=$sync)"; fi; clock_verdict "$src" "$ahead" "$sync"'
  # CRITICAL while live: LUKS/dm-crypt status. A dead-box image of an encrypted disk is unreadable
  # without the key - capture encryption state (and note master keys live in RAM we are imaging).
  run_sh   meta-crypto      encryption.txt   "$D_META" 30 1 'echo "=== encrypted volumes ==="; lsblk -o NAME,FSTYPE,MOUNTPOINT,TYPE 2>/dev/null | grep -iE "crypt|luks"; echo "=== dm-crypt maps ==="; dmsetup ls --target crypt 2>/dev/null; for d in $(lsblk -pno NAME,FSTYPE 2>/dev/null | awk "\$2==\"crypto_LUKS\"{print \$1}"); do echo "== $d =="; cryptsetup luksDump "$d" 2>/dev/null; done; if lsblk -o FSTYPE,TYPE 2>/dev/null | grep -qiE "crypto_LUKS|(^|[[:space:]])crypt([[:space:]]|$)"; then echo "ENCRYPTED=yes"; elif ! command -v lsblk >/dev/null 2>&1; then echo "ENCRYPTED=unknown"; echo "REASON=lsblk absent - encryption state was never determined on this host"; elif ! lsblk -o FSTYPE,TYPE >/dev/null 2>&1; then echo "ENCRYPTED=unknown"; echo "REASON=lsblk present but failed - encryption state was never determined"; else echo "ENCRYPTED=no"; fi; echo "NOTE: if encrypted, the master key is in the RAM image; extract before shutdown."'

  # --- VOLUME ENCRYPTION KEYS, while the volumes are still unlocked --------------------------
  # The step above records that a disk is encrypted; that alone does not make a dead-box image
  # readable. These do. Order of volatility applies to KEYS too: once the box is powered off the
  # dm-crypt master key is gone from kernel memory and the image is unreadable without the user's
  # passphrase, which an uncooperative or unavailable custodian may never provide.
  #   * dmsetup table --showkeys : the live VOLUME MASTER KEY of every unlocked dm-crypt target,
  #     in hex. This is the decisive artifact - it decrypts the image directly, no passphrase
  #     needed (cryptsetup open --master-key-file / dmsetup create against the acquired image).
  #   * luksHeaderBackup : without the LUKS header even a CORRECT passphrase cannot open the
  #     image, and header destruction is a known ransomware / anti-forensic move. Cheap insurance.
  #   * crypttab + keyfile inventory : how the volume is unlocked at boot, and whether a keyfile
  #     on another (unencrypted) volume would do it.
  # SENSITIVITY: these outputs ARE the keys to the evidence. Handle the bundle accordingly - see
  # the generated 00_metadata/DECRYPTION-KEYS.md. Pass --no-keys to skip if the engagement's
  # authority does not extend to extracting key material.
  # volume_key_shape <key-field-from-dmsetup-table> -> hex | keyring-reference | absent
  #
  # `dmsetup table --showkeys` does NOT always show a key. Since cryptsetup 2.x the volume key for
  # a LUKS2 device normally lives in the KERNEL KEYRING, and the table then carries a REFERENCE of
  # the form ":64:logon:cryptsetup:<uuid>-d0" in place of the hex. MEASURED on range-linux-web with
  # cryptsetup 2.7.0 (2026-07-29): a normal open yields the reference, and only `--disable-keyring`
  # yields the 128-hex-char key - and how the volume was opened is the custodian's business, not
  # ours. So on an ordinarily-booted host this step CANNOT capture the master key.
  #
  # That matters more than anything else in this file. The banner below says "these are VOLUME
  # MASTER KEYS - they decrypt the evidence" and DECRYPTION-KEYS.md tells the analyst to hex-decode
  # the field. Writing a keyring pointer under that banner is precisely the failure this project
  # exists to prevent: a file that exists, is non-empty, and does not contain what it claims. The
  # responder discovers it months later with the host long gone. So say it, in the artifact, at the
  # moment it is true.
  #
  # Defined HERE rather than beside the other verdict helpers because bash runs top-down and this
  # step executes long before those definitions; exported because run_sh bodies get a fresh `bash -c`.
  # Pure (no I/O) so it is unit-testable - see tests/unit/test-volume-key-shape.sh.
  volume_key_shape() {
    local k="${1:-}"
    case "$k" in
      '')             echo "absent" ;;
      *:*)            echo "keyring-reference" ;;   # ":64:logon:cryptsetup:<uuid>-d0"
      *[!0-9a-fA-F]*) echo "absent" ;;              # neither hex nor a reference - nothing usable
      ??*)            echo "hex" ;;
      *)              echo "absent" ;;
    esac
  }
  export -f volume_key_shape

  if [ "${NO_KEYS:-0}" = "1" ]; then
    audit "KEY CAPTURE SKIPPED (--no-keys): volume master keys / LUKS headers NOT collected."
    run_sh meta-keys-skipped ENCRYPTION_KEYS_SKIPPED.txt "$D_META" 10 0 'echo "Volume-encryption key capture was disabled with --no-keys. A dead-box image of an encrypted volume will NOT be readable without the custodian passphrase."'
  else
    run_sh meta-volkeys volume_master_keys.txt "$D_META" 60 1 '
      echo "*** SENSITIVE: this file may contain VOLUME MASTER KEYS - they decrypt the evidence. ***"
      echo "=== dm-crypt targets (table --showkeys) ==="
      if command -v dmsetup >/dev/null 2>&1; then
        dmsetup ls --target crypt 2>/dev/null | grep -v "No devices found" | while read -r nm _; do
          [ -z "$nm" ] && continue
          echo "--- $nm ---"
          t=$(dmsetup table --showkeys "$nm" 2>/dev/null)
          echo "$t"
          echo "    (fields: start len crypt <cipher> <KEY-OR-KEYRING-REF> <iv-offset> <device> <offset> ...)"
          # Say what was actually obtained. A reader must never have to infer this by eye.
          case "$(volume_key_shape "$(echo "$t" | awk "{print \$5}")")" in
            hex)
              echo "    KEY SHAPE: hex - this IS the master key. Handle accordingly." ;;
            keyring-reference)
              echo "    KEY SHAPE: KEYRING REFERENCE - *** NO MASTER KEY WAS CAPTURED FOR $nm ***"
              echo "    The volume key is held in the kernel keyring (cryptsetup 2.x default for"
              echo "    LUKS2), so the table shows a pointer, not the key. That pointer is useless"
              echo "    once this host is powered off. DO NOT treat this file as a decryption key"
              echo "    for $nm. Recover the key from the RAM image instead - see"
              echo "    DECRYPTION-KEYS.md, 'If no master key was captured'. If RAM was not"
              echo "    captured either, this evidence may be UNREADABLE after shutdown." ;;
            *)
              echo "    KEY SHAPE: absent/unrecognised - no usable key material in this line." ;;
          esac
        done
      else echo "dmsetup not present - cannot read live master keys"; fi
      echo "=== cipher/keysize per active LUKS mapping ==="
      if command -v cryptsetup >/dev/null 2>&1; then
        dmsetup ls --target crypt 2>/dev/null | grep -v "No devices found" | while read -r nm _; do
          [ -n "$nm" ] && { echo "--- $nm ---"; cryptsetup status "$nm" 2>/dev/null; }
        done
      fi
      echo "=== /etc/crypttab ==="; cat /etc/crypttab 2>/dev/null || echo "(none)"
      echo "=== keyfiles referenced by crypttab ==="
      awk "!/^#/ && NF>=3 {print \$3}" /etc/crypttab 2>/dev/null | while read -r kf; do
        case "$kf" in none|-|"") continue;; esac
        if [ -f "$kf" ]; then echo "$kf : PRESENT ($(wc -c <"$kf" 2>/dev/null) bytes)"; else echo "$kf : missing"; fi
      done
      echo "=== kernel keyring (fscrypt/eCryptfs material) ==="
      command -v keyctl >/dev/null 2>&1 && { keyctl show @u 2>/dev/null; keyctl show @s 2>/dev/null; } || echo "keyctl not present"
      command -v fscryptctl >/dev/null 2>&1 && fscryptctl get_policy / 2>/dev/null
      true'
    # LUKS header backups - binary, one file per device, needed to use a passphrase against the image
    run_sh meta-luksheaders luks_header_backup.log "$D_META" 120 0 '
      command -v cryptsetup >/dev/null 2>&1 || { echo "cryptsetup absent - no header backups taken"; exit 0; }
      lsblk -pno NAME,FSTYPE 2>/dev/null | awk "\$2==\"crypto_LUKS\"{print \$1}" | while read -r d; do
        out="'"$D_META"'/luks_header_$(echo "$d" | tr "/" "_").img"
        if cryptsetup luksHeaderBackup "$d" --header-backup-file "$out" 2>&1; then
          echo "$d -> $(basename "$out") ($(wc -c <"$out" 2>/dev/null) bytes)"
        else echo "$d -> header backup FAILED"; fi
      done
      true'
  fi

  # Captured key material is only useful if the next analyst knows how to apply it months later,
  # so ship the procedure WITH the keys rather than assuming institutional knowledge.
  cat > "$D_META/DECRYPTION-KEYS.md" 2>/dev/null <<'DKEOF'
# Reading this evidence when the volumes are encrypted

(If the run used `--no-keys`, the key files below were deliberately NOT collected -
only the RAM-recovery route at the end of this document applies.)

**These files are the keys to the evidence.** Anyone holding this bundle can decrypt the imaged
volumes. Store and transfer it at the classification of the data it protects, and record its
custody. If your authority did not extend to key extraction, the collector supports `--no-keys`.

## What was captured (00_metadata/)
| File | What it is |
|---|---|
| `volume_master_keys.txt` | Live dm-crypt **master keys** (hex) from `dmsetup table --showkeys`, plus cipher/keysize, `/etc/crypttab`, keyfile inventory, kernel keyring |
| `luks_header_*.img` | Per-device LUKS header backups (`cryptsetup luksHeaderBackup`) |
| `encryption.txt` | Which volumes are encrypted, `luksDump` metadata |
| `../03_memory/` | RAM image - the master key is also recoverable from here if the above failed |

## FIRST: check whether a master key was actually captured
`dmsetup table --showkeys` does not always show a key. Since cryptsetup 2.x, a LUKS2 volume opened
normally keeps its key in the **kernel keyring**, and the table carries a reference instead:

    0 163840 crypt aes-xts-plain64 :64:logon:cryptsetup:b8875a97-...-d0 0 7:0 32768

If the fifth field contains colons, **no master key was captured** - that pointer died with the
host. Only a volume opened with `--disable-keyring` shows the 128-hex-character key. Which of the
two you get depends on how the custodian's system opened the volume, not on anything the collector
can choose, so this is not a collection error and retrying will not change it. Go straight to
"If no master key was captured" below. `volume_master_keys.txt` labels each mapping with its KEY
SHAPE so you do not have to judge this by eye.

(Measured on cryptsetup 2.7.0: normal open -> keyring reference; `--disable-keyring` -> hex.)

## Using a master key against an acquired image (no passphrase needed)
Only applies when the fifth field is hex. The `dmsetup table` line then looks like:

    0 1953125 crypt aes-xts-plain64 <MASTER-KEY-HEX> 0 8:2 32768

Take `<MASTER-KEY-HEX>`, the cipher, and the final number (the **data offset in 512-byte
sectors**, here 32768 = 16 MiB), then on the analysis box:

    printf '%s' '<MASTER-KEY-HEX>' | xxd -r -p > /tmp/mk.bin      # hex -> raw key
    losetup --find --show --read-only /evidence/disk.raw          # -> /dev/loopN
    cryptsetup open --type luks --volume-key-file /tmp/mk.bin \
        --readonly /dev/loopN decrypted                            # LUKS w/ header intact
    mount -o ro,noload /dev/mapper/decrypted /mnt/evidence

`--volume-key-file` is the current spelling; on cryptsetup older than 2.7 use its obsolete alias
`--master-key-file`. Both open a LUKS device with no passphrase at all.

If the LUKS header is missing or damaged, map the raw payload directly instead. **Reuse the table
line captured in `volume_master_keys.txt` verbatim and change only the device field** - do not
retype it from the parts:

    # captured:  0 163840 crypt aes-xts-plain64 <KEY> 0 7:0 32768 1 sector_size:4096
    # substitute field 7 (the device) with your loop device, leave everything else alone:
    echo "0 163840 crypt aes-xts-plain64 <KEY> 0 /dev/loopN 32768 1 sector_size:4096" \
      | dmsetup create decrypted --readonly

The trailing `1 sector_size:4096` is why. LUKS2 commonly formats with 4096-byte sectors, and a
table rebuilt without that option silently maps at 512 - `dmsetup create` SUCCEEDS and the mount
then fails with "bad superblock", which reads like a corrupt image rather than a wrong mapping.
Both routes were exercised on cryptsetup 2.7.0 (2026-07-29): copying the captured table reached the
plaintext; reconstructing the line by hand created a mapping that would not mount.

Restore a header first if you have one and prefer the normal path:

    cryptsetup luksHeaderRestore /dev/loopN --header-backup-file luks_header__dev_sda3.img

(The doubled underscore is not a typo: the backup filename is the device path with every `/`
turned into `_`, and `/dev/sda3` begins with one. Use the name as it appears in `00_metadata/`.)

## If no master key was captured
Recover it from the RAM image instead - the key is resident in kernel memory while the volume is
unlocked. Note there is **no first-party Volatility 3 plugin for LUKS**; the working routes are:

- `bulk_extractor -e aes memory.lime` or `findaes` - carve AES key schedules from the image
- the `luks2-master-key-extract` project (community) against a LUKS2 host
- Volatility 2's `dm_dump` plugin, which reconstructs the `dmsetup` arguments for the mapping
- failing all of that, a custodian-supplied passphrase plus the header backup:
  `cryptsetup open --header luks_header_dev_sda3.img /dev/loopN decrypted`

This is precisely why the collector grabs `dmsetup table --showkeys` live - carving a key out of
a memory image is markedly less reliable than reading it from the kernel while the box is up.

## Verify before you rely on it
Decrypt, then confirm the filesystem mounts read-only and its UUID matches `encryption.txt`.
Never mount the original evidence read-write; always work from a copy or a read-only loop device.
DKEOF

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
# resolve_mem_verdict <bytes> <need> <have_image 0|1> <stable 0|1> <imager_present 0|1>
#   -> "<code>|<reason>|<hint>"  on stdout
# Pure (no I/O) so it is unit-testable - see tests/unit/test-mem-verdict.sh. Mirrors the Windows
# collector's Resolve-MemVerdict, including the ORDERING RULE: absence of a tool, then absence of
# a file, BEFORE the stability signal - stability is only meaningful once a file exists. Getting
# that order wrong is what made the Windows side report "file still growing" and blame Secure Boot
# on hosts where no imager had ever been staged.
# clock_verdict <source> <host_ahead_seconds|empty> -> the clock_provenance lines.
# Pure (no I/O) so it is unit-testable without a time daemon - see tests/unit/test-clock-verdict.sh.
#
# Parity with the Windows twin (scenario E4), which had the identical gap: the artifact recorded
# the host's own local and UTC time plus a note telling the analyst to "compare to a trusted time
# source", which records nothing about whether the clock is WRONG and leaves the one measurement
# that makes a timeline defensible as homework.
#
# THREE-STATE, per the E3 lesson: measured / unavailable (a daemon exists but reported no offset)
# / unknown (no time tooling at all). An unmeasured clock must never read as a correct one.
#
# SIGN CONVENTION IS STATED, NOT ASSUMED. E4 shipped an inverted label because w32tm reports
# reference-minus-host; here the caller normalises to HOST-MINUS-REFERENCE, so positive means this
# host is ahead, and the direction is also spelled out in words.
clock_verdict() {
  # ${3:-}: defaulted, not required. The collector does not run under `set -u`, so an absent third
  # argument would silently become empty here anyway - but the unit suite DOES, and a bare "$3"
  # aborts the function mid-output there, which reads as a logic failure rather than a call-shape
  # one. An omitted sync state is a legitimate input meaning "unknown"; it must behave like one.
  local src="$1" ahead="$2" sync="${3:-}"
  if [ -z "$src" ]; then
    echo "Time source     : NONE FOUND (no chrony, ntpd or timedatectl)"
    echo "Measured offset : UNKNOWN - no time daemon on this host, so this bundle carries no independent evidence that the clock is correct. Compare these timestamps against a trusted source before building a timeline."
    return 0
  fi
  echo "Time source     : $src"
  if [ -z "$ahead" ]; then
    # THE CAUSE MUST BE ESTABLISHED, NOT ASSUMED. This branch used to state "(no reachable peer)"
    # unconditionally, which is a diagnosis the code never made: an absent offset only means the
    # daemon did not expose a number. systemd-timesyncd - the DEFAULT on Ubuntu, so the common
    # case for Linux targets - never exposes one through the probe above even when it is happily
    # synchronised. So report the sync flag we actually read, and nothing more.
    case "$sync" in
      no|NO|No)
        # Same class as E3/A3: the tool already SAW this fact and let it die before the verdict.
        # A host that has never synchronised is the strongest clock finding this step can make -
        # every timestamp in the bundle is unanchored - so it must not read as a quiet daemon.
        echo "Measured offset : NOT SYNCHRONISED - $src reports this clock has never been synchronised against a time source, so no offset exists to report."
        echo "Interpretation  : this host's timestamps are UNVERIFIED - the clock could be off by any amount in either direction."
        echo "WARNING: this clock is not synchronised. Timestamps in this bundle are NOT safely comparable with other hosts, and the error is unbounded rather than merely unmeasured."
        ;;
      yes|YES|Yes)
        echo "Measured offset : UNAVAILABLE - $src reports the clock IS synchronised but does not expose a numeric offset, so the size of any residual error is unknown (it is bounded by the daemon's own discipline, not by this measurement)."
        ;;
      *)
        echo "Measured offset : UNAVAILABLE - $src is present but reported no offset, and its synchronisation state could not be read. This bundle carries no independent evidence that the clock is correct."
        ;;
    esac
    return 0
  fi
  echo "Measured offset : ${ahead}s  (host minus reference; positive = this host is AHEAD)"
  # numeric, not string-shaped: "-0.000000000" is a negative ZERO and previously fell into the
  # BEHIND branch, printing "BEHIND the reference by 0.000000000s" - a direction asserted on a
  # measurement that shows agreement. Sub-millisecond differences are agreement, not drift.
  if awk -v a="$ahead" 'BEGIN{ if (a<0) a=-a; exit !(a<0.001) }' 2>/dev/null; then
    echo "Interpretation  : this host agrees with the reference"
  elif case "$ahead" in -*) true;; *) false;; esac; then
    echo "Interpretation  : this host is BEHIND the reference by ${ahead#-}s"
  else
    echo "Interpretation  : this host is AHEAD of the reference by ${ahead}s"
  fi
  # awk, not bash arithmetic: the offset is fractional and bash cannot compare floats
  if awk -v a="$ahead" 'BEGIN{ if (a<0) a=-a; exit !(a>60) }' 2>/dev/null; then
    echo "WARNING: this host is more than 60s from its time source. Timestamps in this bundle are NOT directly comparable with other hosts until the offset above is applied."
  fi
}
export -f clock_verdict 2>/dev/null || true   # exported HERE, not with the hashing helpers: run_sh runs steps through `bash -c`, which inherits only exported functions, and `export -f` on a not-yet-defined function silently does nothing.

resolve_mem_verdict() {
  local bytes="$1" need="$2" have="$3" stable="$4" imager="$5"
  local blocked="Secure Boot / kernel lockdown / module signing may have blocked it."
  if [ "$have" = 1 ] && [ "${bytes:-0}" -ge "${need:-0}" ] && [ "$stable" = 1 ]; then
    printf 'verified||'; return 0
  fi
  if   [ "$imager" != 1 ]; then printf 'no-imager-staged|%s|%s' \
        "no acquisition tool was staged (place 'avml' in ./tools/bin, or provide a LiME .ko)" \
        "Stage an imager and re-run."
  elif [ "$have" != 1 ];   then printf 'no-image-produced|%s|%s' "the imager ran but produced no image file" "$blocked"
  elif [ "$stable" != 1 ]; then printf 'image-growing|%s|%s'     "file still growing (imager not finished)" "$blocked"
  else printf 'image-too-small|image too small for its format (%s MB < %s MB)|%s' \
        "$(( ${bytes:-0} / 1024 / 1024 ))" "$(( ${need:-0} / 1024 / 1024 ))" "$blocked"
  fi
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
  MEM_IMAGER=""   # which acquisition tool actually ran (drives the verdict reason below)
  if [ -n "$T_AVML" ]; then
    MEM_IMAGER=avml
    run_step mem-avml - "$D_MEM" 3600 0 "$T_AVML" "$D_MEM/memory.lime"
  elif [ -n "$T_LIME" ]; then
    MEM_IMAGER=lime
    run_sh mem-lime - "$D_MEM" 3600 0 "insmod '$T_LIME' 'path=$D_MEM/memory.lime format=lime'"
  else
    audit "RAM: no AVML/LiME found (place 'avml' in ./tools/bin). Capturing /proc/kcore note only."
    run_sh mem-fallback RAM_NOT_CAPTURED.txt "$D_MEM" 30 0 'echo "No AVML/LiME. Recommended: microsoft/avml (single static binary, no kernel module needed)."; ls -l /proc/kcore 2>/dev/null; free -h'
  fi
  # verify a REAL image exists (silent-fail: no AVML/LiME or blocked -> tiny/no file, seals GREEN).
  # Parity with the Windows collector's Resolve-MemVerdict: the REASON drives what the analyst
  # does next, so "no imager was staged" (fix in seconds) must not be reported as "blocked by the
  # kernel" (a host-hardening problem). Same ordering rule: absence of a tool, then absence of a
  # file, BEFORE stability - stability is only meaningful once a file exists.
  MEM_BYTES=0; local img=""
  for f in "$D_MEM"/memory.lime "$D_MEM"/memory.raw; do
    if [ -f "$f" ]; then local b; b="$(fsize "$f")"; b="${b:-0}"
       [ "$b" -gt "${MEM_BYTES:-0}" ] 2>/dev/null && { MEM_BYTES="$b"; img="$f"; }
    fi
  done
  local need=$(( ${memkb:-8388608} * 1024 * 4 / 10 ))   # 40% of physical RAM in bytes
  # stability check: a killed/hung imager leaves a partial that is still growing
  local stable=0
  if [ -n "$img" ]; then
    local s1 s2; s1="$(fsize "$img")"; sleep 3; s2="$(fsize "$img")"
    [ "${s1:-0}" = "${s2:-1}" ] && stable=1
    MEM_BYTES="${s2:-$MEM_BYTES}"
  fi
  MEM_FAIL_CODE=verified
  if [ -n "$img" ] && [ "${MEM_BYTES:-0}" -ge "$need" ] && [ "$stable" = 1 ]; then
    MEM_OK=1
    audit "RAM VERIFIED: $((MEM_BYTES/1024/1024)) MB image, stable (threshold $((need/1024/1024)) MB)"
    run_sh mem-hash memory_hashes.txt "$D_MEM" 1800 0 'cd "'"$D_MEM"'" && for f in memory.lime memory.raw; do [ -f "$f" ] && { echo "SHA256 $(irhash "$f")  $f"; echo "MD5    $(irmd5 "$f")  $f"; }; done; true'
  else
    MEM_OK=0
    local v why hint
    v="$(resolve_mem_verdict "$MEM_BYTES" "$need" "$( [ -n "$img" ] && echo 1 || echo 0 )" "$stable" "$( [ -n "$MEM_IMAGER" ] && echo 1 || echo 0 )")"
    MEM_FAIL_CODE="${v%%|*}"; v="${v#*|}"; why="${v%%|*}"; hint="${v#*|}"
    audit "RAM WARNING: $((MEM_BYTES/1024/1024)) MB - capture NOT verified [$MEM_FAIL_CODE]: $why. $hint *** Do NOT power off an encrypted host without the LUKS key - the master key is only in RAM. ***"
    run_sh mem-fail RAM_CAPTURE_FAILED.txt "$D_MEM" 10 0 "echo \"RAM CAPTURE NOT VERIFIED [$MEM_FAIL_CODE]: $why. $hint If the disk is LUKS-encrypted, do NOT power off without the key.\""
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
  run_sh hash-all filehashes.csv "$D_ART" 7200 0 "$NICE "'find / -xdev -type f -print0 2>/dev/null | while IFS= read -r -d "" f; do h=$(irhash "$f" 2>/dev/null); s=$(stat -c "%s|%Y" "$f" 2>/dev/null); echo "${h:-ERR},$s,\"$f\""; done'
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
      run_sh disk-$n - "$D_DISK" 36000 0 "set -o pipefail; $NICE dd if=$disk conv=noerror,sync bs=4M status=progress 2>>'$AUDIT' | gzip > '$D_DISK/${n}.raw.gz' && irhash '$D_DISK/${n}.raw.gz' > '$D_DISK/${n}.sha256'"
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
$( [ "${NO_KEYS:-0}" = "1" ] && printf '%s' "- **Encryption keys:** NOT captured (--no-keys). An image of an encrypted volume will not be readable without a custodian key." || printf '%s' "> **HANDLING - this bundle contains VOLUME ENCRYPTION KEYS.** 00_metadata holds key material that
> decrypts the imaged volumes. Store and transfer it at the classification of the data it protects
> and record its custody. See 00_metadata/DECRYPTION-KEYS.md." )
EOF

  # (D) An ENOSPC mid-append leaves a PARTIAL final record, so run_state.jsonl stops being valid
  # JSONL and strict parsers choke on the very file that explains the failure. Drop the partial
  # line and say so in the audit trail - a truncated record is not evidence we can stand behind.
  repair_ledger_tail

  # --- completion rollup + completeness verdict (reduce run_state.jsonl; no jq dependency) ---
  local nok nfail ntmo nskip nplan
  # grep -c prints "0" and exits 1 on no-match; capture then default (never use || echo which doubles)
  nok=$(grep -c '"ev":"ok"' "$STATE_JSONL" 2>/dev/null); nfail=$(grep -c '"ev":"failed"' "$STATE_JSONL" 2>/dev/null)
  ntmo=$(grep -c '"ev":"timeout"' "$STATE_JSONL" 2>/dev/null); nskip=$(grep -c '"ev":"skipped"' "$STATE_JSONL" 2>/dev/null)
  nplan=$(grep -c '"ev":"planned"' "$STATE_JSONL" 2>/dev/null)
  : "${nok:=0}" "${nfail:=0}" "${ntmo:=0}" "${nskip:=0}" "${nplan:=0}"
  local incomplete=""
  # carry the specific reason so the verdict says what to fix, not just that RAM is missing
  [ "${MEM_OK:-0}" != 1 ] && [ "$RAPID_ONLY" != 1 ] && incomplete="memory(${MEM_FAIL_CODE:-not-attempted})"
  # a destination that filled up means silent data loss somewhere - never seal that COMPLETE
  [ "${DISK_FULL:-0}" = 1 ] && incomplete="$(printf '%s destination-full' "$incomplete" | sed 's/^ //')"
  local failed_names; failed_names=$(grep -E '"ev":"(failed|timeout)"' "$STATE_JSONL" 2>/dev/null | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
  [ -n "$failed_names" ] && incomplete="$(echo "$incomplete $failed_names" | sed 's/^ //; s/ $//')"
  incomplete="$(printf %s "$incomplete" | tr -cd '[:alnum:] ._():/-' | sed 's/  */ /g; s/^ //; s/ $//')"
  # output that is an access refusal rather than data is missing evidence, whatever its byte count
  if [ -n "${DEGRADED_STEPS// /}" ]; then
    local degr_u; degr_u="$(printf '%s\n' $DEGRADED_STEPS | sort -u | tr '\n' '/' | sed 's|/$||')"
    incomplete="$(printf '%s access-denied(%s)' "$incomplete" "$degr_u" | sed 's/^ //')"
  fi
  # An unprivileged live-response triage CANNOT be complete: RAM, other users' /proc entries,
  # the audit log, shadow, and socket-to-process mapping all require root. Saying COMPLETE here
  # would tell an analyst that the absence of a finding is meaningful when the query was never
  # permitted to run. Parity with the Windows twin, which was measured sealing COMPLETE as a
  # standard user with a 155-byte driver list (2026-07-28).
  [ "$IS_ROOT" != 1 ] && incomplete="$(printf '%s unprivileged(privileged-artifacts-unobtainable-without-root)' "$incomplete" | sed 's/^ //')"
  local verdict=COMPLETE; [ -n "$incomplete" ] && verdict=INCOMPLETE

  # --- self-diagnosis rollup (parity with the Windows collector's diagnostics{}) -------------
  # Reduce run_state.jsonl into something an analyst reads at a glance: HOW steps executed, WHY
  # they failed (grouped, with a sample message), and what the self-heal engine actually did.
  # Pure sed/sort/awk - no jq, which is not present on a stock host.
  local diag_cls_json="" diag_rem_json="" diag_cls_md="" diag_rem_md=""
  if [ -f "$STATE_JSONL" ]; then
    local cls_line first=1
    while IFS='|' read -r cnt cls; do
      [ -z "$cls" ] && continue
      # first message seen for this class, as the human-readable sample
      local sample; sample="$(grep -E '"ev":"(failed|timeout)"' "$STATE_JSONL" 2>/dev/null \
        | grep "\"error_class\":\"$cls\"" | head -1 | sed -n 's/.*"error_msg":"\([^"]*\)".*/\1/p')"
      [ "$first" = 1 ] || diag_cls_json="$diag_cls_json,"
      diag_cls_json="$diag_cls_json\"$(jesc "$cls")\":{\"count\":$cnt,\"sample\":\"$(jesc "$sample")\"}"
      diag_cls_md="${diag_cls_md}${diag_cls_md:+$NL}- ${cls}: ${cnt} step(s)$( [ -n "$sample" ] && printf ' - e.g. %s' "$sample" )"
      first=0
    done <<EOF
$(grep -E '"ev":"(failed|timeout)"' "$STATE_JSONL" 2>/dev/null | sed -n 's/.*"error_class":"\([^"]*\)".*/\1/p' | sort | uniq -c | awk '{print $1"|"$2}')
EOF
    first=1
    while IFS='|' read -r cnt act; do
      [ -z "$act" ] && continue
      [ "$first" = 1 ] || diag_rem_json="$diag_rem_json,"
      diag_rem_json="$diag_rem_json\"$(jesc "$act")\":$cnt"
      diag_rem_md="$diag_rem_md ${act} x${cnt}"
      first=0
    done <<EOF
$(grep '"ev":"remediation"' "$STATE_JSONL" 2>/dev/null | sed -n 's/.*"action":"\([^"]*\)".*"result":"\([^"]*\)".*/\1\/\2/p' | sort | uniq -c | awk '{print $1"|"$2}')
EOF
  fi
  cat > "$D_LOG/run_state.json" 2>/dev/null <<RSEOF
{ "schema":"ir-collect/run-state@1","tool":"ir-collect.sh","case":"$CASE_RAW_J","case_path_token":"$CASE","host":"$HOSTN","output_dir":"$OUTDIR",
  "ended_utc":"$end","status":"$( [ "$verdict" = COMPLETE ] && echo complete || echo partial )","resumed":$( [ -n "${RESUME_DIR:-}" ] && echo true || echo false ),
  "counts":{"planned":$nplan,"ok":$nok,"failed":$nfail,"timeout":$ntmo,"skipped":$nskip},
  "memory_verified":$( [ "${MEM_OK:-0}" = 1 ] && echo true || echo false ),
  "encryption_risk":"$(encryption_risk_verdict "$(if [ -r "$D_META/encryption.txt" ]; then grep -m1 -oE '^ENCRYPTED=(yes|no|unknown)' "$D_META/encryption.txt" 2>/dev/null | cut -d= -f2; fi)" "${MEM_OK:-0}")",
  "completeness":{"verdict":"$verdict","incomplete":"$incomplete"},
  "diagnostics":{"exec_mode":"$EXEC_MODE","hash_backend":"$HASH_BACKEND","by_error_class":{$diag_cls_json},"remediations":{$diag_rem_json}} }
RSEOF
  { echo; echo "## Completeness - $verdict"; echo "- steps: ok=$nok failed=$nfail timeout=$ntmo skipped=$nskip (planned=$nplan)"; [ -n "$incomplete" ] && echo "- incomplete:$incomplete"; echo "- resume: ./collectors/ir-collect.sh --resume '$OUTDIR'"; } >> "$OUTDIR/SUMMARY.md" 2>/dev/null
  # Diagnostics section - printed whenever something failed OR the exec path is degraded
  if [ -n "$diag_cls_md" ] || [ "$EXEC_MODE" != "setsid-pgroup" ] || [ "$HASH_BACKEND" != "sha256sum" ]; then
    { echo; echo "## Diagnostics (self-diagnosis)"
      case "$EXEC_MODE" in
        setsid-pgroup) echo "- exec mode: setsid process-group watchdog (preferred - a hung pipeline is killed as a unit)";;
        timeout-cmd)   echo "- exec mode: \`timeout\` only (no setsid) - it signals just the direct child, so a hung pipeline can orphan grandchildren";;
        bare-watchdog) echo "- exec mode: bare single-PID watchdog (no setsid, no timeout) - hang containment is best-effort only";;
      esac
      echo "- hash backend: $HASH_BACKEND$( [ "$HASH_BACKEND" = none ] && printf ' (NO hashing available - manifest entries will read ERR)' )"
      [ -n "$diag_cls_md" ] && printf '%s\n' "$diag_cls_md"
      [ -n "$diag_rem_md" ] && echo "- self-heal actions:$diag_rem_md"
    } >> "$OUTDIR/SUMMARY.md" 2>/dev/null
  fi
  # (C) If the destination is full the heredoc above yields a ZERO-BYTE run_state.json - the one
  # file an analyst opens to learn what went wrong is empty exactly when the run went wrong.
  # Detect that and put the rollup somewhere off the failing medium, loudly.
  if [ ! -s "$D_LOG/run_state.json" ]; then
    _fb="${ERRTMP}/run_state.${CASE}.json"
    cat > "$_fb" 2>/dev/null <<RSFB
{ "schema":"ir-collect/run-state@1","tool":"ir-collect.sh","case":"$CASE_RAW_J","case_path_token":"$CASE","host":"$HOSTN","output_dir":"$OUTDIR",
  "ended_utc":"$end","status":"partial","rollup_location":"fallback - evidence filesystem was not writable",
  "counts":{"planned":$nplan,"ok":$nok,"failed":$nfail,"timeout":$ntmo,"skipped":$nskip},
  "memory_verified":$( [ "${MEM_OK:-0}" = 1 ] && echo true || echo false ),
  "encryption_risk":"$(encryption_risk_verdict "$(if [ -r "$D_META/encryption.txt" ]; then grep -m1 -oE '^ENCRYPTED=(yes|no|unknown)' "$D_META/encryption.txt" 2>/dev/null | cut -d= -f2; fi)" "${MEM_OK:-0}")",
  "completeness":{"verdict":"$verdict","incomplete":"$incomplete"},
  "diagnostics":{"exec_mode":"$EXEC_MODE","hash_backend":"$HASH_BACKEND","by_error_class":{$diag_cls_json},"remediations":{$diag_rem_json}} }
RSFB
    for _alt in /var/tmp /tmp; do
      if cp -a "$_fb" "$_alt/ir-collect_run_state_${CASE}_${STAMP}.json" 2>/dev/null; then
        audit "ROLLUP FALLBACK: evidence filesystem unwritable - run_state.json written to $_alt/ir-collect_run_state_${CASE}_${STAMP}.json"
        break
      fi
    done
  fi
  RUN_INCOMPLETE=$( [ "$verdict" = COMPLETE ] && echo 0 || echo 1 )

  # Document the manifest's own gaps inside the bundle (parity with the Windows collector).
  # Written BEFORE the manifest step so the note is itself covered by the manifest.
  cat > "$D_LOG/MANIFEST-README.txt" 2>/dev/null <<MREOF
MANIFEST-SHA256.txt coverage
============================
Format: <sha256>  <path relative to the evidence root>
Hashes were produced with the '$HASH_BACKEND' backend (sha256sum is not present on every
platform this collector supports - stock macOS uses shasum, FreeBSD sha256, illumos digest).
A digest of 'ERR' means hashing failed for that file specifically.

Deliberately NOT listed, and why:
  99_logs/MANIFEST-SHA256.txt   the manifest cannot hash itself
  99_logs/audit.log             still being appended to while the manifest runs
  99_logs/errors.log            same
  99_logs/audit.frozen.log      created after the manifest - a frozen snapshot of audit.log,
                                hashed separately into MANIFEST-audit-log.sha256
  MANIFEST-audit-log.sha256     created after the manifest; holds the hash above

Anything else absent from the manifest was NOT excluded by design - treat it as unexplained.
MREOF
  # manifest LAST so it covers SUMMARY.md
  run_sh manifest MANIFEST-SHA256.txt "$D_LOG" 1800 0 "cd '$OUTDIR' && find . -type f ! -name 'MANIFEST-SHA256.txt' ! -path './99_logs/audit.log' ! -path './99_logs/errors.log' ! -path './99_logs/audit.frozen.log' -print | while IFS= read -r f; do printf '%s  %s\n' \"\$(irhash \"\$f\" 2>/dev/null || echo ERR)\" \"\$f\"; done"
  # freeze + hash the custody trail itself (excluded above because it is still being written)
  repair_ledger_tail   # seal's own steps append after the first pass; re-check before freezing custody
  cp -a "$AUDIT" "$D_LOG/audit.frozen.log" 2>/dev/null && ( cd "$OUTDIR" && printf '%s  %s\n' "$(irhash 99_logs/audit.frozen.log)" 99_logs/audit.frozen.log ) > "$OUTDIR/MANIFEST-audit-log.sha256" 2>/dev/null && audit "Custody trail frozen + hashed."

  # ship the sealed bundle: scp/rsync to a collection server, and/or HTTP(S) POST to a lab collector
  if [ -n "$NETWORK_DEST" ] || [ -n "$HTTP_DEST" ]; then
    audit "Sealing + shipping evidence (${HTTP_DEST:-$NETWORK_DEST})"
    local zip="$OUTDIR.tar.gz"
    run_sh seal-tar - "$D_LOG" 3600 0 "tar czf '$zip' -C '$OUT_ROOT' '$(basename "$OUTDIR")' && irhash '$zip' > '$zip.sha256'"
    if [ -n "$NETWORK_DEST" ]; then
      local _fail_before_ship="${STEPS_FAIL:-0}"
      local SSHOPT="-o StrictHostKeyChecking=accept-new"
      [ -n "$IR_SSH_KNOWN_HOSTS" ] && SSHOPT="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=$IR_SSH_KNOWN_HOSTS"
      if command -v rsync >/dev/null 2>&1; then
        run_step ship-rsync - "$D_LOG" 3600 0 rsync -avz -e "ssh $SSHOPT" "$zip" "$zip.sha256" "$NETWORK_DEST/"
      elif command -v scp >/dev/null 2>&1; then
        run_step ship-scp - "$D_LOG" 3600 0 scp $SSHOPT "$zip" "$zip.sha256" "$NETWORK_DEST/"
      else audit "No rsync/scp - evidence kept locally at $zip"; fi
      # Record whether the evidence actually ARRIVED, beside the bundle and never inside it: the
      # bundle is already sealed and hashed, and an evidence container that changes after its
      # manifest is worthless. Parity with the Windows twin's <bundle>.ship.json.
      # STEPS_FAIL rising across the ship step is the signal - a run_step failure is how rsync/scp
      # report here, and it is what drives the exit code.
      _ship_ok=0
      [ "${STEPS_FAIL:-0}" = "${_fail_before_ship:-0}" ] && _ship_ok=1
      {
        printf '{
'
        printf '  "schema": "ir-collect/ship-result@1",
'
        printf '  "case": "%s",
' "$CASE_RAW_J"
        printf '  "bundle": "%s",
' "$(basename "$zip")"
        printf '  "target": "%s",
' "$NETWORK_DEST"
        printf '  "ok": %s,
' "$( [ "$_ship_ok" = 1 ] && echo true || echo false )"
        printf '  "preflight_ok": %s,
' "$( [ "${NET_PROBE_OK:-}" = 1 ] && echo true || [ "${NET_PROBE_OK:-}" = 0 ] && echo false || echo null )"
        printf '  "preflight_reason": "%s",
' "$NET_PROBE_REASON"
        printf '  "local_copy": "%s",
' "$zip"
        printf '  "utc": "%s"
' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '}
'
      } > "$zip.ship.json" 2>/dev/null
      audit "Ship result recorded: $zip.ship.json (ok=$_ship_ok)"
      [ "$_ship_ok" = 1 ] || echo "  Network ship failed - evidence kept locally: $zip (the COLLECTION is intact; only the transfer failed)"
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
  # Never announce a completed collection without confirming the evidence is actually THERE.
  # Measured 2026-07-28 (scenario B3): the destination was unmounted mid-run, all 32 steps failed,
  # and this still printed "Collection complete. Output: <path>" for a directory that no longer
  # existed - the operator walks away believing they have a bundle. The Windows twin gained this
  # guard during B6; this is the parity fix.
  _bundle_files=$(find "$OUTDIR" -type f 2>/dev/null | wc -l)
  echo
  if [ "${_bundle_files:-0}" -eq 0 ]; then
    echo "COLLECTION PRODUCED NO EVIDENCE. Nothing was written to: $OUTDIR"
    echo "The destination became unwritable or disappeared during the run. Re-run against writable media."
  elif [ "${RUN_INCOMPLETE:-0}" = "1" ]; then
    echo "Collection INCOMPLETE (${_bundle_files} files). Output: $OUTDIR"
  else
    echo "Collection complete (${_bundle_files} files). Output: $OUTDIR"
  fi
  # Only point at the summary and audit log when they exist. Printing paths into a destination
  # that vanished sends the operator to look for files that were never written.
  [ "${_bundle_files:-0}" -gt 0 ] && echo "Summary: $OUTDIR/SUMMARY.md  |  Audit: $AUDIT"
}

# ---------------------------------------------------------------------------
# VOLATILE GREEN gate - confirm the perishable data is captured before the
# slow non-volatile phase. This is the checkpoint the operator waits for.
# ---------------------------------------------------------------------------
SEALED=0

# encryption_risk_verdict <enc_state:yes|no|unknown> <mem_ok:0|1> -> one of
#   encrypted-no-ram | unknown-no-ram | ok
#
# PARITY with the Windows twin's Get-EncryptionRiskVerdict, which closed the same defect there.
# The gate used to compute this inline as
#
#     local enc=0; grep -q '^ENCRYPTED=yes' "$D_META/encryption.txt" 2>/dev/null && enc=1
#
# so THREE different situations collapsed into "not encrypted": the disk really is unencrypted; the
# meta-crypto step never ran, timed out (30s bound) or its file is missing; and the probe ran on a
# host with no lsblk, where the old code printed a flat ENCRYPTED=no from a tool that never
# executed. Only the first is safe. The step now emits ENCRYPTED=unknown for the last case.
#
# Why this matters more than a wrong label: the specific banner tells the responder NOT TO POWER
# OFF because the LUKS master key is only in RAM. Lose that and the disk image is unreadable
# forever - the one failure mode in this tool that no later analysis can undo. An unrun probe must
# never resolve to the safe side here.
encryption_risk_verdict() {
  local enc="${1:-unknown}" mem="${2:-0}"
  # Captured RAM holds the master key, so encryption stops being a power-off risk. This is the only
  # branch that clears the host, and it turns on a fact that was measured.
  if [ "$mem" = "1" ]; then echo "ok"; return 0; fi
  case "$enc" in
    yes)     echo "encrypted-no-ram" ;;
    no)      echo "ok" ;;
    *)       echo "unknown-no-ram" ;;   # unknown, empty, or any unrecognised value
  esac
}

volatile_green_gate() {
  local vol_files; vol_files=$(find "$D_VOL" "$D_NET" -type f 2>/dev/null | wc -l | tr -d ' ')
  # THREE-STATE, read from the artifact the step actually wrote. A missing file is "unknown", not
  # "no" - the distinction the old two-state grep destroyed.
  local encstate='unknown'
  if [ -r "$D_META/encryption.txt" ]; then
    if grep -q '^ENCRYPTED=yes' "$D_META/encryption.txt" 2>/dev/null; then encstate='yes'
    elif grep -q '^ENCRYPTED=no' "$D_META/encryption.txt" 2>/dev/null; then encstate='no'
    fi
  fi
  local encverdict; encverdict=$(encryption_risk_verdict "$encstate" "${MEM_OK:-0}")
  local enc=0; [ "$encverdict" = 'encrypted-no-ram' ] && enc=1
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
  elif [ "$encverdict" = "unknown-no-ram" ]; then
    # Deliberately does NOT claim the disk is encrypted - nothing observed that. It refuses to
    # assume the opposite, because that assumption is the unrecoverable one. Without this branch a
    # host whose encryption probe failed fell through to the generic amber below, which talks about
    # artifact counts and never mentions power-off.
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "  !!  VOLATILE: AMBER - ENCRYPTION UNKNOWN + NO VERIFIED RAM !!"
    echo "  !!  The encryption probe could NOT determine this disk's   !!"
    echo "  !!  state. If it IS encrypted the master key is in RAM you !!"
    echo "  !!  did not capture. Do NOT assume it is unencrypted.      !!"
    echo "  !!  Check 00_metadata/encryption.txt before powering off.  !!"
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    audit "VOLATILE AMBER | encryption UNDETERMINED + no verified RAM | files=$vol_files"
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
# resolve_scenario: SCEN -> SCEN_NAME/PLAN/ATTACK/FIRST/MOBPROF (shared: guided + non-interactive)
resolve_scenario() {
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
    A)  SCEN_NAME="FULL forensic sweep (no scenario yet) - order-of-volatility + all analysis artifacts"; PLAN="memory artifacts weblogs persistence ad"; ATTACK=""; FIRST="No specific lead: capture EVERYTHING our tools analyse in RFC 3227 order - RAM -> artifact triage (logs/journals/histories/configs) -> web logs -> persistence -> AD. Full-FS hash + disk image stay opt-in via the menu.";;
    *)  SCEN="U"; SCEN_NAME="Unknown / broad triage"; PLAN="artifacts persistence ad"; ATTACK=""; FIRST="Standard RFC 3227 order-of-volatility triage.";;
  esac
  case "$SCEN" in 2) MOBPROF=bec;; 3) MOBPROF=exfil;; 9) MOBPROF=smish;; 5) MOBPROF=beacon;; 10) MOBPROF=spyware;; 6|7) MOBPROF=token;; 1) MOBPROF=ransom;; *) MOBPROF=U;; esac
}

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
  echo "  A  FULL sweep (no scenario yet) - order-of-volatility + everything our tools analyse"
  echo "  U  Unknown / broad triage"
  read -rp "Select scenario [A] " SCEN </dev/tty; SCEN="$(echo "${SCEN:-A}" | tr a-z A-Z)"
  resolve_scenario
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

noninteractive_intake() {  # --scenario/--host-role/--known-bad-* : prompt-free intake (automation/lab/E2E)
  SCEN="$(echo "${SCENARIO_ARG:-A}" | tr a-z A-Z)"
  resolve_scenario
  HOST_ROLE="${HOST_ROLE_ARG:-workstation}"
  case "$HOST_ROLE" in ot-ics) DO_NO_HARM=1;; esac
  [ "$DO_NO_HARM" = "1" ] && PLAN="$(echo "$PLAN" | sed -E 's/(^| )filehashes( |$)/ /g; s/(^| )diskimage( |$)/ /g')"
  [ "$SKIP_AD" = "1" ] && PLAN="$(echo "$PLAN" | sed -E 's/(^| )ad( |$)/ /g')"
  PLAN="$(echo "$PLAN" | tr -s ' ' | sed 's/^ //; s/ $//')"
  cat > "$D_META/intake.json" 2>/dev/null <<EOF
{ "case_id":"$(sani "$CASE")","exercise":${LAB:-0},"mobile_involved":0,"mobile_profile":"${MOBPROF:-U}","scenario":"$SCEN","scenario_name":"$(sani "$SCEN_NAME")",
  "attack_tags":$(json_arr "$ATTACK"),
  "host_role":"$HOST_ROLE","scope":"single","connectivity":"connected",
  "known_bad_ips":$(json_arr "${KB_IPS_ARG:-}"),"known_bad_domains":$(json_arr "${KB_DOMAINS_ARG:-}"),
  "known_bad_hashes":$(json_arr "${KB_HASHES_ARG:-}"),"known_bad_accounts":[],"known_bad_paths":[],
  "noninteractive":1,"plan":"$PLAN","generated_by":"ir-collect.sh" }
EOF
  GUIDED=1
  audit "INTAKE(auto) scenario=$SCEN role=$HOST_ROLE plan=$PLAN attack=$ATTACK"
  echo "Scenario: $SCEN_NAME | Role: $HOST_ROLE | Plan: ${PLAN:-(volatile only)}"
}

# ===========================================================================
# MAIN
# ===========================================================================
# guided intake is the default when interactive and no mode flag was given
if [ -n "${RESUME_DIR:-}" ]; then load_prior_state "$OUTDIR"
elif [ -n "${SCENARIO_ARG:-}" ]; then noninteractive_intake
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
# Legend kept identical to the Windows twin: the exit code is the machine-readable contract and
# two collectors documenting it differently is how consumers end up handling only one of them.
# A failed ship reaches 10 here via STEPS_FAIL (rsync/scp run through run_step), which is the same
# outcome the Windows collector reaches with an explicit ShipOk rule.
audit "EXIT $EXIT_CODE (0=clean 10=skips/ship-failed 15=incomplete-critical 20=no-RAM 40=fatal)"
exit $EXIT_CODE
