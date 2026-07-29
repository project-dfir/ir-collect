#!/usr/bin/env bash
# Unit test for clock_verdict in collectors/ir-collect.sh - the Linux twin of the Windows E4 work.
#
# Regression this locks in: the artifact recorded the host's own local and UTC time plus a note
# telling the analyst to "compare to trusted time source; record offset for timeline
# defensibility". It measured nothing. The Windows collector had the identical gap and it was
# fixed there first (scenario E4); this is the parity fix.
#
# Two things the Windows version taught, both asserted here:
#   1. THREE-STATE. measured / unavailable (daemon present, no peer) / unknown (no tooling). An
#      unmeasured clock must never read as a correct one.
#   2. THE SIGN CONVENTION MUST BE STATED. E4 shipped an inverted label because w32tm reports
#      reference-minus-host; an analyst correcting a timeline by that sign shifts every timestamp
#      the wrong way. Callers normalise to host-minus-reference and the direction is also in words.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../../collectors/ir-collect.sh}"
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }
FN="$(sed -n '/^clock_verdict() {/,/^}/p' "$COLLECTOR")"
[ -n "$FN" ] || { echo "could not extract clock_verdict"; exit 2; }
LINES=$(printf '%s\n' "$FN" | wc -l)
if [ "$LINES" -lt 8 ] || [ "$LINES" -gt 60 ]; then
    echo "FAIL  clock_verdict extraction looks wrong ($LINES lines) - the sed range is not bounded"; exit 2
fi
eval "$FN"

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }
has() { case "$1" in *"$2"*) echo 1;; *) echo 0;; esac; }

# --- no time tooling at all ---
o="$(clock_verdict "" "")"
check "$(has "$o" 'NONE FOUND')" 'no time daemon -> source reported as NONE FOUND'
check "$(has "$o" 'UNKNOWN')"    'no time daemon -> offset UNKNOWN, not silence'
check "$(has "$o" 'no independent evidence')" 'no time daemon -> says the bundle cannot vouch for the clock'

# --- daemon present but no peer ---
o="$(clock_verdict "chronyc (10.0.0.1)" "")"
check "$(has "$o" 'UNAVAILABLE')" 'daemon present, no offset -> UNAVAILABLE (distinct from UNKNOWN)'
check "$(has "$o" 'chronyc')"     'the source is still named when the offset is unavailable'

# --- measured, host AHEAD (the E4 sign case) ---
o="$(clock_verdict "chronyc (dc01)" "239.989")"
check "$(has "$o" 'is AHEAD of the reference by 239.989s')" 'a positive offset is described as AHEAD, in words'
check "$(has "$o" 'WARNING')"                               'an offset over 60s warns that timestamps are not comparable'
check "$(has "$o" 'host minus reference')"                  'the sign convention is stated, not left to the reader'

# --- measured, host BEHIND ---
o="$(clock_verdict "ntpq" "-12.5")"
check "$(has "$o" 'is BEHIND the reference by 12.5s')" 'a negative offset is described as BEHIND'
o2="$(clock_verdict "ntpq" "-12.5")"
check "$([ "$(has "$o2" 'WARNING')" = 0 ] && echo 1 || echo 0)" 'a small offset does NOT warn (12.5s is under the 60s bar)'

# --- large NEGATIVE offset must warn too (absolute value, not signed comparison) ---
o="$(clock_verdict "ntpq" "-300.0")"
check "$(has "$o" 'WARNING')" 'a large NEGATIVE offset warns as well (magnitude, not sign)'

# --- NEGATIVE ZERO is agreement, not drift. chrony can report "-0.000000000"; the first version
# matched on string shape and printed "BEHIND the reference by 0.000000000s" - a direction claimed
# on a measurement that shows none. Found live on rick-pve 2026-07-29.
o="$(clock_verdict "chronyc (dc)" "-0.000000000")"
check "$(has "$o" 'agrees with the reference')" 'a NEGATIVE ZERO offset reads as agreement, not BEHIND'
check "$([ "$(has "$o" 'BEHIND')" = 0 ] && echo 1 || echo 0)" 'a negative zero never prints a direction'

# --- agreement ---
o="$(clock_verdict "chronyc (dc01)" "0.000001")"
check "$([ "$(has "$o" 'WARNING')" = 0 ] && echo 1 || echo 0)" 'a healthy clock does not warn'

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
