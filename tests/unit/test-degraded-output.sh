#!/usr/bin/env bash
# Unit test for test_degraded_output in collectors/ir-collect.sh - the Linux twin of
# tests/unit/Test-DegradedOutput.ps1. Extracts the shipped function so the test exercises
# production code.
#
# Regression this locks in (measured first on the Windows side, range-WS02 2026-07-28): a step
# can exit 0 having written nothing but "Access is denied". drivers.txt went 115096 B -> 155 B
# and netstat_anob.txt 8140 B -> 45 B, both above the emptiness threshold, so the bundle sealed
# verdict=COMPLETE with zero failures - indistinguishable from a healthy privileged run.
#
# The counter-risk is over-triggering: a large healthy artifact may legitimately contain
# "Permission denied" (a log excerpt, a find(1) stderr capture). Those must NOT be flagged,
# which is what the size and density gates are for - both are asserted here.
#
# Usage: bash tests/unit/test-degraded-output.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../../collectors/ir-collect.sh}"
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }

# take the SHIPPED pattern too, so editing it re-tests rather than drifting from a stale copy
DENIAL_RE="$(sed -n "s/^DENIAL_RE='\(.*\)'$/\1/p" "$COLLECTOR")"
[ -n "$DENIAL_RE" ] || { echo "could not extract DENIAL_RE from $COLLECTOR"; exit 2; }
FN="$(sed -n '/^test_degraded_output() {/,/^}/p' "$COLLECTOR")"
[ -n "$FN" ] || { echo "could not extract test_degraded_output from $COLLECTOR"; exit 2; }
eval "$FN"

FAIL=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }
probe() {  # probe <text> -> echoes the reason (empty when healthy)
    local f="$TMP/p.$$.txt"; printf '%s' "$1" > "$f"
    test_degraded_output "$f" "$(wc -c <"$f" | tr -d ' ')"
    rm -f "$f"
}
nonempty() { [ -n "$1" ] && echo 1 || echo 0; }
empty()    { [ -z "$1" ] && echo 1 || echo 0; }

# --- real-world stubs ---
check "$(nonempty "$(probe 'cat: /proc/1/environ: Permission denied
')")" 'a small "Permission denied" stub is DEGRADED   <-- the regression'
check "$(nonempty "$(probe 'ss: no permission to open socket diag; Operation not permitted
')")" 'an "Operation not permitted" stub is DEGRADED'
check "$(nonempty "$(probe 'dmesg: read kernel buffer failed: Operation not permitted
')")" 'a dmesg refusal is DEGRADED'

r="$(probe 'cat: /proc/1/environ: Permission denied
')"
check "$([ ${#r} -gt 5 ] && echo 1 || echo 0)" "returns the offending line as the reason ('$r')"

# --- healthy output must NEVER be flagged ---
big="$(for i in $(seq 1 800); do echo "systemd-$i  running  /usr/lib/systemd/system/u$i.service"; done)"
check "$(empty "$(probe "$big")")" 'a large healthy unit table is NOT degraded'
check "$(empty "$(probe "$big
find: /run/user/1000/gvfs: Permission denied")")" 'a large healthy artifact that merely MENTIONS a denial once is NOT degraded'
check "$(empty "$(probe 'no matching processes
')")" 'a small file with no denial text is NOT degraded (that is emptiness, handled elsewhere)'

# --- size gate: small file, denials a MINORITY of lines (density gate cannot catch this) ---
small="$(printf 'PID  CMD\ncat: /proc/1/environ: Permission denied\n1 systemd\n2 kthreadd\n3 rcu_gp\n4 kworker\n5 migration\n')"
smalllen=$(printf '%s' "$small" | wc -c | tr -d ' ')
check "$([ "$smalllen" -lt 4096 ] && [ "$smalllen" -gt 32 ] && echo 1 || echo 0)" "size-gate fixture really is small (${smalllen} B)"
check "$(nonempty "$(probe "$small")")" 'a small artifact with a MINORITY of refusals IS degraded (size gate)'

# --- density gate: >4 KB but mostly refusals ---
dense="$(for i in $(seq 1 300); do echo "row $i: Permission denied"; done; for i in $(seq 1 50); do echo "ok row $i"; done)"
check "$(nonempty "$(probe "$dense")")" 'a >4 KB file that is mostly refusals IS degraded (density gate)'
sparse="$(for i in $(seq 1 40); do echo "row $i: Permission denied"; done; for i in $(seq 1 600); do echo "real data row $i"; done)"
check "$(empty "$(probe "$sparse")")" 'a mostly-data file with a minority of denials is NOT degraded'

# --- guards: must never throw or emit noise ---
check "$(empty "$(test_degraded_output "$TMP/definitely_missing.txt" 100)")" 'missing file returns empty, does not error'
check "$(empty "$(test_degraded_output '/dev/null' 0)")"                     '/dev/null target returns empty'
check "$(empty "$(test_degraded_output '' 0)")"                              'empty path returns empty'
huge="$TMP/huge.txt"; for i in $(seq 1 4000); do echo "line $i: Permission denied"; done > "$huge"
check "$(empty "$(test_degraded_output "$huge" "$(wc -c <"$huge" | tr -d ' ')")")" 'a >64 KB file is skipped outright (large artifacts are never stubs)'

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
