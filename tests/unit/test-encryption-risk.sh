#!/usr/bin/env bash
# Unit test for encryption_risk_verdict in collectors/ir-collect.sh - the Linux twin of the Windows
# Get-EncryptionRiskVerdict fix.
#
# The defect on this side was the same two-state collapse, in one line of the volatile gate:
#
#     local enc=0; grep -q '^ENCRYPTED=yes' "$D_META/encryption.txt" 2>/dev/null && enc=1
#
# THREE situations became "not encrypted": the disk really is unencrypted; the meta-crypto step
# never ran / timed out / its file is missing; and the probe ran on a host with no lsblk, where the
# step printed a flat ENCRYPTED=no from a tool that never executed. Only the first is safe.
#
# Consequence, and why this outranks a cosmetic mislabel: with encryption unknown and no RAM, the
# gate fell through to a generic amber about artifact counts and NEVER MENTIONED POWER-OFF. The
# specific banner exists to stop a responder powering off a host whose LUKS master key lives only
# in RAM - the one failure in this tool that no later analysis can undo.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../../collectors/ir-collect.sh}"
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }

FN="$(sed -n '/^encryption_risk_verdict() {/,/^}/p' "$COLLECTOR")"
[ -n "$FN" ] || { echo "FAIL  could not extract encryption_risk_verdict"; exit 2; }
LINES=$(printf '%s\n' "$FN" | wc -l)
if [ "$LINES" -lt 6 ] || [ "$LINES" -gt 40 ]; then
    echo "FAIL  extraction looks wrong ($LINES lines) - the sed range is not bounded"; exit 2
fi
eval "$FN"

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }
eq() { [ "$1" = "$2" ] && echo 1 || echo 0; }

# --- THE REGRESSION: an undetermined probe with no RAM must NOT read as safe ---
check "$(eq "$(encryption_risk_verdict unknown 0)" 'unknown-no-ram')" \
      'encryption UNKNOWN + no RAM -> unknown-no-ram (the old code said "not encrypted")'
check "$(eq "$(encryption_risk_verdict '' 0)" 'unknown-no-ram')" \
      'an EMPTY state is unknown, not safe - a missing artifact file lands here'
check "$(eq "$(encryption_risk_verdict garbage 0)" 'unknown-no-ram')" \
      'an unrecognised state is unknown, not safe'
check "$(eq "$(encryption_risk_verdict)" 'unknown-no-ram')" \
      'called with NO arguments at all -> unknown, never ok'

# --- the original encrypted case must still fire ---
check "$(eq "$(encryption_risk_verdict yes 0)" 'encrypted-no-ram')" \
      'encrypted + no RAM -> encrypted-no-ram'
check "$([ "$(encryption_risk_verdict yes 0)" != "$(encryption_risk_verdict unknown 0)" ] && echo 1 || echo 0)" \
      'encrypted and unknown are DISTINCT states, not merged into one warning'

# --- POSITIVE CONTROLS: a banner that fires on healthy hosts becomes noise and gets ignored ---
check "$(eq "$(encryption_risk_verdict no 0)" 'ok')"      'not encrypted + no RAM -> ok (no alarm)'
check "$(eq "$(encryption_risk_verdict yes 1)" 'ok')"     'encrypted but RAM CAPTURED -> ok (the key is in the bundle)'
check "$(eq "$(encryption_risk_verdict unknown 1)" 'ok')" 'unknown but RAM captured -> ok'
check "$(eq "$(encryption_risk_verdict no 1)" 'ok')"      'clean host -> ok'

# --- the three no-RAM situations must be distinguishable ---
A="$(encryption_risk_verdict yes 0)"; B="$(encryption_risk_verdict unknown 0)"; C="$(encryption_risk_verdict no 0)"
check "$([ "$A" != "$B" ] && [ "$B" != "$C" ] && [ "$A" != "$C" ] && echo 1 || echo 0)" \
      'encrypted / unknown / clear are three different verdicts'

# --- WIRING. Every assertion above can pass while the gate ignores the function entirely. ---
check "$(grep -qF 'encverdict=$(encryption_risk_verdict "$encstate"' "$COLLECTOR" && echo 1 || echo 0)" \
      'the volatile gate CALLS the verdict'
check "$(grep -qF 'ENCRYPTION UNKNOWN + NO VERIFIED RAM' "$COLLECTOR" && echo 1 || echo 0)" \
      'the gate has a distinct banner for the unknown case'
check "$(grep -qF 'encverdict" = "unknown-no-ram"' "$COLLECTOR" && echo 1 || echo 0)" \
      'that banner is selected by the verdict, not recomputed inline'
check "$([ "$(grep -c '"encryption_risk":' "$COLLECTOR")" = 2 ] && echo 1 || echo 0)" \
      'both run_state emitters carry encryption_risk (main and the ENOSPC fallback rollup)'
# A bare grep for ENCRYPTED=unknown is too weak: there are TWO branches that must emit it, and
# mutating either one back to "no" left every assertion green. Assert each branch by its reason
# string, so a host that cannot run the probe can never be reported as unencrypted.
check "$(grep -qF 'echo "ENCRYPTED=unknown"; echo "REASON=lsblk absent' "$COLLECTOR" && echo 1 || echo 0)" \
      'a host with NO lsblk emits unknown, not "no" (the probe never ran)'
check "$(grep -qF 'echo "ENCRYPTED=unknown"; echo "REASON=lsblk present but failed' "$COLLECTOR" && echo 1 || echo 0)" \
      'an lsblk that FAILS emits unknown, not "no"'
check "$([ "$(grep -c 'ENCRYPTED=unknown' "$COLLECTOR")" -ge 2 ] && echo 1 || echo 0)" \
      'both undetermined branches survive - neither may quietly revert to "no"'
check "$(grep -qF "grep -q '^ENCRYPTED=no'" "$COLLECTOR" && echo 1 || echo 0)" \
      'the gate reads ENCRYPTED=no explicitly rather than treating "not yes" as no'

# The old two-state line must be gone from EXECUTABLE code, or the fix is decorative. Scoped to
# non-comment lines: the doc block above the new function quotes the old line to explain what it
# got wrong, and a flat grep matched that comment - a test failing on correct code. Same trap as
# the "no reachable peer" assertion in the clock work.
check "$(grep -vE '^\s*#' "$COLLECTOR" | grep -qF "local enc=0; grep -q '^ENCRYPTED=yes'" && echo 0 || echo 1)" \
      'no executable line still uses the old two-state grep'

# --- PARITY with the Windows twin: the same three state names, or the collectors disagree ---
WIN="$HERE/../../collectors/IR-Collect.ps1"
if [ -f "$WIN" ]; then
    for st in encrypted-no-ram unknown-no-ram; do
        check "$(grep -qF "$st" "$WIN" && echo 1 || echo 0)" "Windows uses the same state name '$st'"
    done
fi

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
