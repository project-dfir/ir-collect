#!/usr/bin/env bash
# Unit test for the hashing shim in collectors/ir-collect.sh (Linux/macOS/BSD twin of
# tests/unit/Test-HashShim.ps1).
#
# Extracts the shim straight out of the shipped collector (so the test cannot drift from
# production code), then asserts EVERY available backend produces the same digest.
#
# Regression this locks in: sha256sum is NOT universal. Stock macOS has `shasum -a 256` and
# `md5` (no sha256sum/md5sum), FreeBSD has `sha256`/`md5`, illumos has `digest`, and some
# busybox builds have none. ir-collect.sh explicitly supports macos/bsd/solaris, yet every
# hash site called sha256sum directly - so on those platforms the evidence manifest came out
# empty and the per-file hash walk wrote 'ERR', silently, while the run sealed.
#
# Usage: bash tests/unit/test-hash-shim.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../../collectors/ir-collect.sh}"
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }

# pull out the shim block: from the backend resolution to the export line
SHIM="$(sed -n '/^# --- hashing shim/,/^export -f irhash irmd5/p' "$COLLECTOR")"
[ -n "$SHIM" ] || { echo "could not extract the hashing shim from $COLLECTOR"; exit 2; }
eval "$SHIM"

FAIL=0
ok()   { printf 'ok    %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$1" = 0 ]; then ok "$2"; else bad "$2"; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
F="$TMP/vector.bin"
printf 'ir-collect hash shim test vector' > "$F"
# ground truth for that exact content (sha256 of the 31-byte string above)
TRUTH="$(printf 'ir-collect hash shim test vector' | { sha256sum 2>/dev/null || shasum -a 256 2>/dev/null || openssl dgst -sha256 2>/dev/null | sed 's/.*= *//'; } | cut -d' ' -f1)"
[ -n "$TRUTH" ] || { echo "no hasher at all on this box - cannot establish ground truth"; exit 2; }

echo "resolved backends: HASH_BACKEND=$HASH_BACKEND MD5_BACKEND=$MD5_BACKEND"

got="$(irhash "$F")"
[ "$got" = "$TRUTH" ]; check $? "irhash matches an independently computed SHA-256"
printf '%s' "$got" | grep -Eq '^[0-9a-f]{64}$'; check $? "digest is 64 lowercase hex chars"
m="$(irmd5 "$F")"
printf '%s' "$m" | grep -Eq '^[0-9a-f]{32}$'; check $? "irmd5 returns a well-formed MD5"

# --- the regression: every AVAILABLE backend must agree -----------------------
# simulates the macOS/BSD/busybox hosts we cannot boot here, by driving the same code path
# the shim would take there.
tested=0
for b in sha256sum shasum sha256 openssl digest python3; do
    case "$b" in
        sha256sum) command -v sha256sum >/dev/null 2>&1 || continue ;;
        shasum)    command -v shasum    >/dev/null 2>&1 || continue ;;
        sha256)    command -v sha256    >/dev/null 2>&1 || continue ;;
        openssl)   command -v openssl   >/dev/null 2>&1 || continue ;;
        digest)    command -v digest    >/dev/null 2>&1 || continue ;;
        python3)   command -v python3   >/dev/null 2>&1 || continue ;;
    esac
    HASH_BACKEND="$b"
    g="$(irhash "$F")"
    if [ "$g" = "$TRUTH" ]; then ok "backend '$b' agrees with ground truth"
    else bad "backend '$b' returned '$g' (expected '$TRUTH')"; fi
    tested=$((tested+1))
done
[ "$tested" -ge 2 ]; check $? "at least two independent backends were exercised (tested $tested)"

# --- no backend at all must be loud, not silently wrong -----------------------
HASH_BACKEND=none
g="$(irhash "$F" 2>/dev/null)"; rc=$?
[ "$rc" != 0 ] && [ -z "$g" ]; check $? "with no backend, irhash fails loudly (rc!=0, empty) so callers write ERR"

# --- a path with spaces must still hash --------------------------------------
HASH_BACKEND="$(command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum)"
SP="$TMP/a file with spaces.bin"
printf 'ir-collect hash shim test vector' > "$SP"
[ "$(irhash "$SP")" = "$TRUTH" ]; check $? "hashes a path containing spaces"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
