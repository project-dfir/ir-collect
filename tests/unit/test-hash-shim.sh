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
# End the range on the export STATEMENT, not on one exact argument list: adding a function to
# `export -f` used to break this anchor, the range then ran to EOF and swallowed the whole
# collector, and the test died on an unrelated unbound variable (2026-07-28).
SHIM="$(sed -n '/^# --- hashing shim/,/^export -f /p' "$COLLECTOR")"
[ -n "$SHIM" ] || { echo "could not extract the hashing shim from $COLLECTOR"; exit 2; }
# A silently unbounded range is how this test previously ingested the entire collector. Assert
# the extracted shim is a plausible SIZE before evaluating it.
SHIM_LINES=$(printf '%s
' "$SHIM" | wc -l)
if [ "$SHIM_LINES" -lt 5 ] || [ "$SHIM_LINES" -gt 200 ]; then
    printf 'FAIL  hashing-shim extraction looks wrong (%s lines) - the sed range is not bounded
' "$SHIM_LINES"
    exit 2
fi
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
        # `command -v python3` succeeds for a non-functional stub (the Windows Store alias
        # prints nothing and exits nonzero). Presence is not capability - probe it for real,
        # and SKIP rather than FAIL when the interpreter cannot actually hash. Measured
        # 2026-07-28 on a Windows test host, where this produced a false failure.
        python3)   command -v python3   >/dev/null 2>&1 || continue
                   if ! python3 -c 'import hashlib' >/dev/null 2>&1; then
                       printf 'SKIP  backend %s present but non-functional here (not a collector defect)
' "$b"; continue
                   fi ;;
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


# --- the digest SHAPE check -------------------------------------------------------------
# irhash funnels every backend through a shape check so a present-but-broken helper cannot put
# a bogus value into MANIFEST-SHA256.csv. A manifest is a custody claim: a wrong digest is worse
# than a recorded ERR, because it looks verified. Drive the check by stubbing the raw layer.
_ir_saved_raw="$(declare -f _irhash_raw)"
shape_case() {  # shape_case <what-the-backend-prints> <expect ok|reject> <label>
    eval "_irhash_raw() { printf '%s' \"$1\"; }"
    local got rc
    got="$(irhash /dev/null 2>/dev/null)"; rc=$?
    if [ "$2" = ok ]; then
        if [ "$rc" = 0 ] && [ -n "$got" ]; then printf 'ok    %s
' "$3"; else printf 'FAIL  %s (rc=%s got=%s)
' "$3" "$rc" "$got"; FAIL=$((FAIL+1)); fi
    else
        if [ "$rc" != 0 ] && [ -z "$got" ]; then printf 'ok    %s
' "$3"; else printf 'FAIL  %s (rc=%s got=%s)
' "$3" "$rc" "$got"; FAIL=$((FAIL+1)); fi
    fi
}
VALID64='9fce5e72d5371e842fbc8804567f94a323c07f468b0e3fa547819cc51ff9e304'
shape_case "$VALID64"              ok     'a well-formed 64-hex digest is accepted'
shape_case ""                      reject 'a backend that prints NOTHING is rejected  <-- the python3-stub case'
shape_case "deadbeef"              reject 'a too-SHORT digest is rejected (truncated pipe)'
shape_case "${VALID64}extra"       reject 'a too-LONG digest is rejected'
shape_case "python3: command not found" reject 'a backend that prints an ERROR MESSAGE is rejected'
shape_case "9fce5e72d5371e842fbc8804567f94a323c07f468b0e3fa547819cc51ff9e3zz" reject 'a 64-char NON-HEX value is rejected'
eval "$_ir_saved_raw"




# --- EXPORT COVERAGE ----------------------------------------------------------------------
# The manifest step hashes every file through `bash -c`, and a bash -c child inherits ONLY
# exported functions. When irhash was split into a validating wrapper plus a raw backend, the
# collector exported the wrapper alone, so in the child it called an undefined helper and every
# digest came back ERR - 43 of 48 manifest rows in a measured run (2026-07-28). This test file
# evaluates the whole shim in ONE shell, so it can never reproduce that by execution; the export
# list has to be asserted directly.
#
# Derived, not hardcoded: take every function the collector defines, see which ones irhash's body
# actually calls, and require each to be exported. A future split under any name is covered.
EXPORT_LINE="$(grep -E '^export -f ' "$COLLECTOR" | head -1)"
if [ -z "$EXPORT_LINE" ]; then
    printf 'FAIL  the collector has no `export -f` line - the manifest child gets no hashing functions
'
    FAIL=$((FAIL+1))
else
    IRHASH_BODY="$(sed -n '/^irhash() {/,/^}/p' "$COLLECTOR")"
    ALL_FUNCS="$(grep -oE '^[A-Za-z_][A-Za-z0-9_]*\(\)' "$COLLECTOR" | tr -d '()' | sort -u)"
    DEPS=''
    for f in $ALL_FUNCS; do
        [ "$f" = irhash ] && continue
        case "$IRHASH_BODY" in *"$f"*) DEPS="$DEPS $f";; esac
    done
    printf 'ok    irhash dependencies discovered from source:%s
' "${DEPS:- (none)}"
    for dep in irhash $DEPS; do
        case " $EXPORT_LINE " in
            *" $dep "*) printf 'ok    %s is exported to bash -c children
' "$dep";;
            *) printf 'FAIL  %s is called by the manifest but NOT in `export -f` - every digest becomes ERR
' "$dep"
               FAIL=$((FAIL+1));;
        esac
    done
fi

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
