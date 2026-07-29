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

# --- the chronyc PARSE, against real output shapes -------------------------------------------
# The live positive control proved end-to-end extraction works for a ~0s offset, and clock_verdict
# is unit-tested above for direction and the 60s warning. What neither covers is whether the awk
# parse handles chronyc's LARGE-offset output, and that could not be proven live: no Linux VM on
# the range is ssh-reachable, and the only other host is the Proxmox hypervisor - skewing a
# production hypervisor's clock to test a string parse is not a trade worth making.
#
# So the parse is extracted from the shipped collector and driven with real chronyc output shapes.
# The convention: chronyc says "fast" (host ahead -> positive) or "slow" (host behind -> negated).
chrony_parse() { awk '/System time/{v=$4; if ($0 ~ /slow/) v="-" v; print v; exit}'; }
# The function above is a COPY of the parse embedded in the collector's meta-clock step (it lives
# inside a long single-quoted bash -c string and cannot be sourced). A copy can drift from the
# original and keep passing, so assert the shipped file still contains the same awk program.
# grep -F, not a pattern: the shipped text contains backslash-escaped $ and a BRE pattern for it
# failed to match correct code on the first attempt.
if grep -qF 'System time/{v=' "$COLLECTOR" && grep -qF 'slow/) v=' "$COLLECTOR"; then
    printf 'ok    the collector still ships the parse this test mirrors
'
else
    printf 'FAIL  the collector parse has drifted from the copy under test
'; FAIL=$((FAIL+1))
fi

o="$(printf 'Reference ID    : 0A140AE9 (dc01.lab.local)
System time     : 200.123456789 seconds fast of NTP time
Last offset     : +0.000001 seconds
' | chrony_parse)"
check "$([ "$o" = "200.123456789" ] && echo 1 || echo 0)" "a LARGE 'fast' offset parses to a positive number (got '$o')"

o="$(printf 'Reference ID    : 0A140AE9 (dc01)
System time     : 200.123456789 seconds slow of NTP time
' | chrony_parse)"
check "$([ "$o" = "-200.123456789" ] && echo 1 || echo 0)" "a LARGE 'slow' offset parses to a NEGATIVE number (got '$o')"

o="$(printf 'System time     : 0.000000242 seconds fast of NTP time
' | chrony_parse)"
check "$([ "$o" = "0.000000242" ] && echo 1 || echo 0)" "a sub-microsecond offset parses (matches the live positive control)"

o="$(printf 'Reference ID    : 00000000 ()
Stratum         : 0
System time     : 0.000000000 seconds slow of NTP time
' | chrony_parse)"
check "$([ "$o" = "-0.000000000" ] && echo 1 || echo 0)" "an unsynchronised chrony yields the negative zero seen live (feeds the agreement case above)"

# the parse must not pick up a DIFFERENT line that happens to contain a number
o="$(printf 'Last offset     : +0.000001 seconds
RMS offset      : 0.000002 seconds
System time     : 5.5 seconds fast of NTP time
' | chrony_parse)"
check "$([ "$o" = "5.5" ] && echo 1 || echo 0)" "only the 'System time' line is read, not 'Last offset' or 'RMS offset' (got '$o')"

# end-to-end: parse feeding the formatter must produce a correct large-offset verdict
v="$(clock_verdict "chronyc (dc01)" "$(printf 'System time     : 200.5 seconds fast of NTP time
' | chrony_parse)")"
check "$(has "$v" 'is AHEAD of the reference by 200.5s')" 'parse + verdict together describe a large fast clock as AHEAD'
check "$(has "$v" 'WARNING')" 'parse + verdict together warn on a large offset'

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
