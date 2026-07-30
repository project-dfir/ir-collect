#!/usr/bin/env bash
# Every repo path the operator docs point at must exist.
#
# On 2026-07-30 the README told Windows operators to run `.\kit\IR-Collect.ps1` six times. kit/ was
# renamed to collectors/ long ago; the Linux command lines were updated and the Windows ones were
# not, so a reader following the README verbatim got a file-not-found. The same stale path sat in
# docs/RUNBOOK.md and docs/RANGE.md. The scenario catalogue already had a path check; the docs an
# operator actually starts from did not.
#
# Three outcomes: 0 pass | 1 a doc points at something that is not there | 2 the guard could not run.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CHK="$REPO/tests/tools/check-doc-paths.py"
[ -f "$CHK" ] || { echo "FAIL  checker not found: $CHK"; exit 2; }

PY=""
for c in python python3; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "FAIL  no python on PATH - NOT reporting clean"; exit 2; }

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }

OUT="$("$PY" "$CHK" "$REPO" 2>&1)" || { echo "FAIL  checker errored:"; printf '%s\n' "$OUT" | sed 's/^/      /'; exit 2; }
TOTAL=$(printf '%s\n' "$OUT" | awk '/^TOTAL /{print $2}')
MISS=$(printf '%s\n' "$OUT" | awk '/^TOTAL /{print $4}')

# --- calibration: the extractor must actually find paths ---------------------------------------
# A zero here would make the result below vacuously clean, which is the failure this file exists
# to prevent. The docs reference dozens of repo paths; if the count collapses, the extractor broke.
check "$([ "${TOTAL:-0}" -ge 30 ] && echo 1 || echo 0)" \
      "extractor finds repo paths in the docs (${TOTAL:-0}, expect >=30)"
if [ "${TOTAL:-0}" -lt 30 ]; then
    echo "      Too few paths to trust a clean result - the extractor or the docs changed shape."
    exit 2
fi

# --- the guard itself ---------------------------------------------------------------------------
check "$([ "${MISS:-1}" -eq 0 ] && echo 1 || echo 0)" \
      "every repo path referenced by README/docs exists (${MISS:-?} missing)"
if [ "${MISS:-0}" -ne 0 ]; then
    printf '%s\n' "$OUT" | grep '^  MISSING' | head -10
    echo "      A doc telling an operator to run something that is not there is a defect in the"
    echo "      instructions, not a cosmetic issue - it is how the kit/ rename went unnoticed."
fi

# --- calibration: it must CATCH a path that is not there -----------------------------------------
# Proving the checker can fail is the whole basis for trusting the zero above. Done on a COPY of the
# repo layout rather than by editing README, so a crash cannot leave the tree dirty.
TMP="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/dp$$")"
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/docs"
cp "$REPO/README.md" "$TMP/README.md" 2>/dev/null || true
printf '\nSee `collectors/DEFINITELY-NOT-HERE.ps1` for details.\n' >> "$TMP/README.md"
CAL="$("$PY" "$CHK" "$TMP" 2>&1)"
# Assert THE PLANTED PATH specifically, not just a non-zero count. The temp tree has no collectors/
# at all, so every path in the copied README is missing there - a count-based assertion would pass
# on that alone and would never notice the planted one being skipped. Name the thing being caught.
if printf '%s\n' "$CAL" | grep -qF 'DEFINITELY-NOT-HERE.ps1'; then r=1; else r=0; fi
check "$r" "calibration: the PLANTED non-existent path is the one reported"
if [ "$r" != 1 ]; then
    echo "      The checker did not name the path that was deliberately added, so the clean result"
    echo "      above proves nothing about its ability to catch a real one."
    exit 2
fi

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
