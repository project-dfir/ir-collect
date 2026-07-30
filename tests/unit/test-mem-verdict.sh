#!/usr/bin/env bash
# Unit test for resolve_mem_verdict in collectors/ir-collect.sh - the Linux twin of
# tests/unit/Test-MemVerdict.ps1. Extracts the shipped function out of the collector so the
# test exercises production code, then asserts every branch of the verdict table.
#
# Regression this locks in (found first on the Windows side, 2026-07-27): if the reason chain
# checks the stability signal BEFORE checking whether an image exists at all, then a host where
# no imager was ever staged gets told "file still growing (imager not finished)" and blamed on
# Secure Boot - sending the analyst to debug kernel lockdown when the actual fix is to drop
# avml into ./tools/bin.
#
# Usage: bash tests/unit/test-mem-verdict.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$HERE/../../collectors/ir-collect.sh}"
[ -f "$COLLECTOR" ] || { echo "collector not found: $COLLECTOR"; exit 2; }

FN="$(sed -n '/^resolve_mem_verdict() {/,/^}/p' "$COLLECTOR")"
[ -n "$FN" ] || { echo "could not extract resolve_mem_verdict from $COLLECTOR"; exit 2; }
eval "$FN"

RAM=$(( 8 * 1024 * 1024 * 1024 ))
NEED=$(( RAM * 4 / 10 ))
FAIL=0

# case: name | bytes need have stable imager | expected_code | expect_blocked_hint(1|0)
run_case() {
    local name="$1" bytes="$2" need="$3" have="$4" stable="$5" imager="$6" want="$7" wanthint="$8"
    local out code reason hint
    out="$(resolve_mem_verdict "$bytes" "$need" "$have" "$stable" "$imager")"
    code="${out%%|*}"; out="${out#*|}"; reason="${out%%|*}"; hint="${out#*|}"
    local errs=""
    [ "$code" = "$want" ] || errs="$errs code='$code' expected '$want';"
    case "$hint" in *"Secure Boot"*) got_hint=1;; *) got_hint=0;; esac
    [ "$got_hint" = "$wanthint" ] || errs="$errs blocked-hint=$got_hint expected $wanthint;"
    if [ "$want" = verified ]; then
        [ -z "$reason" ] || errs="$errs success verdict carries a reason ('$reason');"
    else
        [ -n "$reason" ] || errs="$errs failure verdict has an empty reason;"
    fi
    if [ -n "$errs" ]; then printf 'FAIL  %s\n        %s\n' "$name" "$errs"; FAIL=$((FAIL+1))
    else printf 'ok    %s  [%s]\n' "$name" "$code"; fi
}

run_case "verified image"                       $(( RAM * 9 / 10 )) $NEED 1 1 1 verified          0
run_case "verified exactly at threshold"        $NEED               $NEED 1 1 1 verified          0
run_case "NO IMAGER STAGED (the regression)"    0                   $NEED 0 0 0 no-imager-staged  0
run_case "imager ran, produced nothing"         0                   $NEED 0 0 1 no-image-produced 1
run_case "image still growing"                  $(( 1024*1024*1024 )) $NEED 1 0 1 image-growing   1
run_case "stable but truncated"                 65536               $NEED 1 1 1 image-too-small   1
run_case "big+stable but no imager recorded"    $(( RAM * 9 / 10 )) $NEED 1 1 0 verified          0

# the exact wording that misled us must NOT appear for the no-imager case
out="$(resolve_mem_verdict 0 "$NEED" 0 0 0)"
case "$out" in
    *growing*) printf 'FAIL  no-imager reason still mentions "growing"\n'; FAIL=$((FAIL+1));;
    *) printf 'ok    no-imager reason does not mention "growing"\n';;
esac
case "$out" in
    *"Secure Boot"*) printf 'FAIL  no-imager case still blames Secure Boot\n'; FAIL=$((FAIL+1));;
    *) printf 'ok    no-imager case does not blame Secure Boot\n';;
esac

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
