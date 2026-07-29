#!/usr/bin/env bash
# `ir-collect.sh --help` must print the OPERATOR header, and only that.
#
# WHY. --help was `grep '^#' "$0"`, which prints every comment line in the file. That was 233
# lines, of which 197 were implementation commentary addressed to whoever edits the script -
# repair_ledger_tail's ENOSPC rationale, "Pure (no I/O) so it is unit-testable", why the stderr
# scratch dir is off the evidence filesystem. The operator header was 15% of its own help output.
#
# That matters here more than it would elsewhere, because the header is where encryption_risk is
# explained, and encryption_risk is the do-not-power-off signal. A responder deciding whether it is
# safe to shut a host down should not have to read past unit-test notes to find it.
#
# THE POSITIVE CONTROL IS THE POINT. "The help output contains no implementation commentary" is
# trivially true of an empty string, of a broken awk, and of a file that never had commentary. So
# every exclusion below is paired with proof that the excluded text IS STILL PRESENT IN THE FILE.
# If the noise disappears from the source, this guard reports GUARD-BROKEN (exit 2) rather than
# passing - a check that could not run must never look like a check that passed.
#
# Three outcomes: 0 pass | 1 the help output regressed | 2 the guard could not run.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SH="$REPO/collectors/ir-collect.sh"
[ -f "$SH" ] || { echo "FAIL  collector not found: $SH"; exit 2; }

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }

HELP="$(bash "$SH" --help 2>/dev/null)"
HLINES=$(printf '%s\n' "$HELP" | wc -l | tr -d ' ')
RAW=$(grep -c '^#' "$SH")

# --- 0. GUARD CALIBRATION -----------------------------------------------------------------
# The whole test is about a filter, so prove there is something to filter and that --help ran.
[ -n "$HELP" ] || { echo "FAIL  --help produced no output at all - guard broken, NOT clean"; exit 2; }
if [ "$RAW" -lt 100 ]; then
    echo "FAIL  only $RAW '#' lines in the collector - the file this guard was written against had"
    echo "      233. Either the file changed shape or the count is wrong; refusing to judge."
    exit 2
fi

# The noise this filter exists to remove must still be IN THE FILE, or its absence from the help
# output proves nothing. These are implementation comments; if a refactor deletes them, update the
# list - do not let the guard quietly pass on a file with nothing left to exclude.
NOISE_OK=1
for n in 'unit-testable' 'repair_ledger_tail' 'ENOSPC'; do
    if ! grep -qF -- "$n" "$SH"; then
        echo "      calibration: '$n' is no longer in the collector, so excluding it from --help"
        echo "      proves nothing. Pick a replacement marker from the current implementation comments."
        NOISE_OK=0
    fi
done
[ "$NOISE_OK" = 1 ] || { echo "FAIL  guard cannot calibrate - NOT reporting the result below as clean"; exit 2; }
check 1 "calibration: implementation commentary is present in the file to be excluded"

# --- 1. the header is bounded -------------------------------------------------------------
check "$([ "$HLINES" -lt 80 ] && echo 1 || echo 0)" \
      "--help is bounded to the operator header ($HLINES lines; the file has $RAW comment lines)"

# --- 2. and it excludes the implementation commentary that IS in the file ------------------
for n in 'unit-testable' 'repair_ledger_tail' 'ENOSPC'; do
    printf '%s' "$HELP" | grep -qF -- "$n" && r=0 || r=1
    check "$r" "--help omits implementation commentary ('$n')"
done

# --- 3. it still contains what an operator came for ----------------------------------------
# Bounding the output is only an improvement if nothing operational was cut with the noise.
while IFS='|' read -r pat what; do
    printf '%s' "$HELP" | grep -qF -- "$pat" && r=1 || r=0
    check "$r" "--help still documents $what"
done <<'EOF'
sudo ./ir-collect.sh|the usage lines
--no-keys|the switch that suppresses key extraction
DECRYPTION-KEYS|where captured keys land
EXIT CODES|the exit contract
encryption_risk|the do-not-power-off signal
unknown-no-ram|encryption_risk's third state
by_error_class|the failure tally
EOF

# --- 4. the third state must be described as UNDETERMINED, not as safe ---------------------
# The defect this project keeps finding is a two-state answer to a three-state question. The
# header must not present `unknown` as an all-clear; assert the wording that says so survives.
printf '%s' "$HELP" | grep -qF -- 'NOT a claim that the disk is' && r=1 || r=0
check "$r" "--help says 'unknown' is not a claim the disk is clear"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
