#!/usr/bin/env bash
# tools/verify-bundle.py must FAIL on a tampered bundle. That is the whole test.
#
# A verifier that always says VERIFIED is worse than none - it converts "nobody checked" into
# "checked and fine", which is the exact failure this project keeps finding in other guises. So
# every assertion below is built the same way: construct a bundle, prove it verifies, then break
# ONE thing and require the tool to notice, naming the right category.
#
# Both manifest dialects are exercised, because the two collectors do not agree on format:
#   Windows  99_logs/MANIFEST-SHA256.csv   <sha256>,<length>,<path>
#   Linux    99_logs/MANIFEST-SHA256.txt   <sha256>  <path>
# A verifier that silently understood only one would report a clean bundle for half the product.
#
# Exit: 0 pass | 1 the verifier regressed | 2 the test could not run
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
V="$REPO/tools/verify-bundle.py"
[ -f "$V" ] || { echo "FAIL  verifier not found: $V"; exit 2; }

PY=""
for c in python python3; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "FAIL  no python on PATH - cannot run the verifier, NOT reporting clean"; exit 2; }

WORK="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/vb$$")"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }
# grep reports success as 0 and check wants 1. Passing $? straight into check inverted every
# output assertion on the first run - ten of them "failed" against a verifier that was correct.
# Hence a separate helper rather than a mental conversion at each call site.
checkg() { # checkg <extended-regex> <description>
    if grep -qE "$1" "$WORK/out.txt"; then printf 'ok    %s\n' "$2"
    else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); echo "      report said:"; sed -n '1,12p' "$WORK/out.txt" | sed 's/^/        /'; fi
}

# sha256 via python so the FIXTURE does not depend on sha256sum being present either
hash_of() { "$PY" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"; }

# build_bundle <dir> <csv|txt>
build_bundle() {
    local B="$1" KIND="$2"
    rm -rf "$B"; mkdir -p "$B/00_metadata" "$B/01_volatile" "$B/99_logs"
    printf 'case data\n'      > "$B/00_metadata/collection_info.json"
    printf 'process list\n'   > "$B/01_volatile/processes.txt"
    printf 'summary\n'        > "$B/SUMMARY.md"
    cat > "$B/99_logs/MANIFEST-README.txt" <<'MRE'
MANIFEST-SHA256 coverage
========================
Format: see below

Deliberately NOT listed, and why:
  99_logs/MANIFEST-SHA256.csv   the manifest cannot hash itself
  99_logs/MANIFEST-SHA256.txt   the manifest cannot hash itself
  99_logs/audit.log             still being appended to while the manifest runs
  99_logs/errors.log            same
  99_logs/audit.frozen.log      created after the manifest
  MANIFEST-audit-log.sha256     created after the manifest; holds the hash above

Anything else absent from the manifest was NOT excluded by design - treat it as unexplained.
MRE
    printf 'audit line\n'  > "$B/99_logs/audit.log"
    printf 'no errors\n'   > "$B/99_logs/errors.log"

    local MF
    if [ "$KIND" = csv ]; then MF="$B/99_logs/MANIFEST-SHA256.csv"; else MF="$B/99_logs/MANIFEST-SHA256.txt"; fi
    : > "$MF"
    # every file except the documented exclusions
    ( cd "$B" && find . -type f \
        ! -name 'MANIFEST-SHA256.csv' ! -name 'MANIFEST-SHA256.txt' \
        ! -path './99_logs/audit.log' ! -path './99_logs/errors.log' \
        ! -path './99_logs/audit.frozen.log' ! -name 'MANIFEST-audit-log.sha256' -print ) |
    while IFS= read -r f; do
        local rel="${f#./}"
        local d; d="$(hash_of "$B/$rel")"
        if [ "$KIND" = csv ]; then
            printf '%s,%s,%s\n' "$d" "$(wc -c <"$B/$rel" | tr -d ' ')" "$rel" >> "$MF"
        else
            printf '%s  %s\n' "$d" "$rel" >> "$MF"
        fi
    done
    # frozen custody trail, hashed separately - exactly as the collectors do it
    cp "$B/99_logs/audit.log" "$B/99_logs/audit.frozen.log"
    printf '%s  %s\n' "$(hash_of "$B/99_logs/audit.frozen.log")" '99_logs/audit.frozen.log' \
        > "$B/MANIFEST-audit-log.sha256"
}

run_verify() { "$PY" "$V" "$1" >"$WORK/out.txt" 2>&1; echo $?; }

for KIND in csv txt; do
    B="$WORK/bundle-$KIND"

    # --- 0. a clean bundle must VERIFY, or every failure below proves nothing ----------------
    build_bundle "$B" "$KIND"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 0 ] && echo 1 || echo 0)" "[$KIND] an untampered bundle VERIFIES (exit $rc)"
    if [ "$rc" != 0 ]; then
        echo "      the baseline does not verify, so the tamper controls below are meaningless:"
        sed -n '1,15p' "$WORK/out.txt" | sed 's/^/      /'
        exit 2
    fi
    checkg 'cannot cover itself' "[$KIND] the report states the manifest cannot cover itself"

    # --- 1. one flipped byte ------------------------------------------------------------------
    build_bundle "$B" "$KIND"
    printf 'process listX\n' > "$B/01_volatile/processes.txt"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 1 ] && echo 1 || echo 0)" "[$KIND] a MODIFIED file fails verification (exit $rc)"
    checkg 'MISMATCH *: *[1-9]' "[$KIND] and it is reported as MISMATCH"

    # --- 2. truncation ------------------------------------------------------------------------
    build_bundle "$B" "$KIND"
    : > "$B/01_volatile/processes.txt"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 1 ] && echo 1 || echo 0)" "[$KIND] a TRUNCATED file fails verification"

    # --- 3. a listed file removed -------------------------------------------------------------
    build_bundle "$B" "$KIND"
    rm -f "$B/01_volatile/processes.txt"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 1 ] && echo 1 || echo 0)" "[$KIND] a DELETED file fails verification"
    checkg 'MISSING *: *[1-9]' "[$KIND] and it is reported as MISSING, not as a mismatch"

    # --- 4. a file ADDED after sealing --------------------------------------------------------
    # The one a hash comparison alone would never catch: every listed file still matches.
    build_bundle "$B" "$KIND"
    printf 'planted\n' > "$B/01_volatile/planted.txt"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 1 ] && echo 1 || echo 0)" "[$KIND] an ADDED file fails verification"
    checkg 'UNLISTED *: *[1-9]' "[$KIND] and it is reported as UNLISTED"

    # --- 5. the custody trail itself tampered -------------------------------------------------
    build_bundle "$B" "$KIND"
    printf 'audit line TAMPERED\n' > "$B/99_logs/audit.frozen.log"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 1 ] && echo 1 || echo 0)" "[$KIND] a tampered CUSTODY TRAIL fails verification"
    checkg 'custody trail : MISMATCH' "[$KIND] and the custody trail is named specifically"

    # --- 6. a declared-excluded file is NOT treated as tampering ------------------------------
    # The cries-wolf direction. audit.log is legitimately unlisted; flagging it would train an
    # analyst to ignore UNLISTED, and then the planted file above goes unnoticed too.
    build_bundle "$B" "$KIND"
    printf 'audit line\nmore audit\n' >> "$B/99_logs/audit.log"
    rc=$(run_verify "$B")
    check "$([ "$rc" = 0 ] && echo 1 || echo 0)" "[$KIND] a DECLARED-EXCLUDED file does not raise a false alarm"
done

# --- 7. the exclusion list must come from the bundle, and its absence must stop the tool -----
B="$WORK/bundle-csv"
build_bundle "$B" csv
rm -f "$B/99_logs/MANIFEST-README.txt"
rc=$(run_verify "$B")
check "$([ "$rc" = 2 ] && echo 1 || echo 0)" "a bundle with NO MANIFEST-README.txt is CANNOT-VERIFY (exit 2), not clean"

build_bundle "$B" csv
printf 'MANIFEST coverage\n=====\nnothing here\n' > "$B/99_logs/MANIFEST-README.txt"
rc=$(run_verify "$B")
check "$([ "$rc" = 2 ] && echo 1 || echo 0)" "an unparseable exclusion block is CANNOT-VERIFY, not clean"

# --- 8. no manifest at all --------------------------------------------------------------------
build_bundle "$B" csv
rm -f "$B/99_logs/MANIFEST-SHA256.csv"
rc=$(run_verify "$B")
check "$([ "$rc" = 2 ] && echo 1 || echo 0)" "a bundle with no manifest is CANNOT-VERIFY, not VERIFIED"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
