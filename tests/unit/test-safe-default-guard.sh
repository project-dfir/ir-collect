#!/usr/bin/env bash
# CI guard: the Linux collector must stay free of the signature defect shape
#
#     VAR=<safe default> ; <probe whose failure is discarded> ; <decision on VAR>
#
# which is how a failed probe silently answers on the safe side. It produced the BitLocker risk flag
# on Windows and the LUKS gate here - the latter meaning a responder could power off an encrypted
# host and lose the disk image permanently.
#
# THE CALIBRATION IS THE POINT, not the zero. An earlier version of this detector implemented only
# `VAR=$(probe 2>/dev/null)`, reported 0 on the current collector AND 0 on a file that provably
# contained the bug, and would have shipped a false all-clear. So this guard refuses to report
# "clean" unless it has first re-found a KNOWN defect in a vendored fixture.
#
# Three outcomes, deliberately distinct:
#   pass      - calibration found the known defect AND the collector is clean
#   FAIL      - the collector has grown a new instance (a product regression)
#   exit 2    - the guard itself could not calibrate (a TOOL failure, never reported as clean)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DET="$REPO/tests/tools/find-safe-default-shape.py"
FIXTURE="$REPO/tests/tools/fixtures/known-positive-luks-gate.sh"
COLLECTOR="$REPO/collectors/ir-collect.sh"

PY=""
for c in python python3; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "SKIP  no python interpreter available"; exit 0; }

for f in "$DET" "$FIXTURE" "$COLLECTOR"; do
    [ -f "$f" ] || { echo "FAIL  guard input missing: $f"; exit 2; }
done

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }

# --- 1. CALIBRATION: the detector must re-find the known defect ------------------------------
CAL="$("$PY" "$DET" "$FIXTURE" 1 2>&1)"
CAL_RC=$?
if [ "$CAL_RC" -ne 0 ]; then
    echo "FAIL  the detector errored on the calibration fixture (rc=$CAL_RC) - guard is broken, NOT clean"
    printf '%s\n' "$CAL" | sed 's/^/      /'
    exit 2
fi
CAL_HITS="$(printf '%s\n' "$CAL" | sed -n 's/.*decision : \([0-9]*\)$/\1/p')"
[ -n "$CAL_HITS" ] || CAL_HITS="$(printf '%s\n' "$CAL" | grep -oE 'decision : [0-9]+' | grep -oE '[0-9]+$')"
check "$([ "${CAL_HITS:-0}" = "1" ] && echo 1 || echo 0)" \
      "calibration: the detector re-finds the known LUKS defect in the fixture (got ${CAL_HITS:-none}, need 1)"
if [ "${CAL_HITS:-0}" != "1" ]; then
    echo "      A detector that cannot find a defect it is known to contain proves nothing about"
    echo "      the collector. Refusing to report the result below as clean."
    exit 2
fi
check "$(printf '%s\n' "$CAL" | grep -q 'shape 2' && echo 1 || echo 0)" \
      "calibration: it is found as shape 2 (conditional assignment), the form this codebase uses"

# --- 2. the actual guard --------------------------------------------------------------------
OUT="$("$PY" "$DET" "$COLLECTOR" 2>&1)"
OUT_RC=$?
if [ "$OUT_RC" -ne 0 ]; then
    echo "FAIL  the detector errored on the collector (rc=$OUT_RC) - guard is broken, NOT clean"
    printf '%s\n' "$OUT" | sed 's/^/      /'
    exit 2
fi
HITS="$(printf '%s\n' "$OUT" | grep -oE 'decision : [0-9]+' | grep -oE '[0-9]+$')"
check "$([ -n "$HITS" ] && echo 1 || echo 0)" "the detector reported a hit count for the collector"
check "$([ "${HITS:-1}" = "0" ] && echo 1 || echo 0)" \
      "collectors/ir-collect.sh has no safe-default+swallowed-probe+decision (got ${HITS:-unknown})"
if [ "${HITS:-0}" != "0" ]; then
    echo "      NEW INSTANCE(S) - a probe that fails now answers on the safe side:"
    printf '%s\n' "$OUT" | sed -n '/line /,$p' | sed 's/^/      /'
fi

# --- 3. the volume guard must still be armed -------------------------------------------------
# A zero is only meaningful if the pattern still matches the swallowing constructs at all.
SWALLOW="$(printf '%s\n' "$OUT" | grep -oE 'swallowing construct : [0-9]+' | grep -oE '[0-9]+$')"
check "$([ "${SWALLOW:-0}" -ge 100 ] && echo 1 || echo 0)" \
      "the pattern still matches the collector's swallowing constructs (${SWALLOW:-0}, expect >=100)"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
