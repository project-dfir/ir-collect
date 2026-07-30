#!/usr/bin/env bash
# Every shell snippet ir-collect.sh hands to `bash -c` must be valid shell.
#
# `bash -n collectors/ir-collect.sh` PASSES on a file whose snippets are broken - a snippet is only
# a string until run_sh evaluates it. On 2026-07-30 an apostrophe inside one of those single-quoted
# strings terminated it early, and meta-volkeys - the VOLUME MASTER KEY capture - failed rc=2 on
# every run for two iterations. The artifact still appeared: correct filename, correct banner, and
# then nothing, because the step died mid-way. Unit tests passed, the manifest verified, and the
# summary still announced that the bundle contained encryption keys.
#
# The failure was found by reading a rendered SUMMARY.md, which is not a thing CI can do. This is
# the cheap mechanical half of that lesson: syntax-check every snippet on every commit.
#
# Exit: 0 pass | 1 a snippet is broken | 2 the guard could not run.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SH="$REPO/collectors/ir-collect.sh"
EX="$REPO/tests/tools/extract-snippets.py"
[ -f "$SH" ] || { echo "FAIL  collector not found"; exit 2; }
[ -f "$EX" ] || { echo "FAIL  extractor not found"; exit 2; }

PY=""
for c in python python3; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
[ -n "$PY" ] || { echo "FAIL  no python on PATH - NOT reporting clean"; exit 2; }

WORK="$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/sn$$")"
trap 'rm -rf "$WORK"' EXIT INT TERM

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }

# --- calibration: the extractor must actually find snippets -----------------------------------
# A zero here would make every assertion below vacuously true, which is the failure mode this
# whole file exists to prevent.
"$PY" "$EX" "$SH" "$WORK/snips" > "$WORK/list.txt" 2>&1 || { echo "FAIL  extractor errored:"; sed 's/^/      /' "$WORK/list.txt"; exit 2; }
N=$(awk '/^TOTAL /{print $2}' "$WORK/list.txt")
[ -n "$N" ] || { echo "FAIL  extractor printed no TOTAL - guard broken"; exit 2; }
check "$([ "$N" -ge 10 ] && echo 1 || echo 0)" "extractor finds the run_sh snippets ($N found, expect >=10)"
if [ "$N" -lt 10 ]; then
    echo "      Too few snippets to trust a clean result. Either run_sh changed shape or the"
    echo "      extractor no longer understands it; refusing to certify."
    exit 2
fi

# --- calibration: it must CATCH a deliberately broken snippet ----------------------------------
# Reproduce the exact 2026-07-30 defect - an apostrophe inside a single-quoted snippet.
mkdir -p "$WORK/cal"
printf 'echo "see DECRYPTION-KEYS.md, %s"\n' "'If no master key was captured'" > "$WORK/cal/broken.sh"
if bash -n "$WORK/cal/broken.sh" 2>/dev/null; then
    # The fixture as written is valid shell on its own; what breaks is the EMBEDDING. Simulate the
    # embedding the way run_sh does, so the calibration tests the real failure mode.
    printf "bash -c 'echo %s'\n" "'x'" > "$WORK/cal/embed.sh"
fi
BROKEN="$WORK/cal/embed2.sh"
printf "echo 'unterminated\n" > "$BROKEN"
bash -n "$BROKEN" 2>/dev/null && r=0 || r=1
check "$r" "calibration: bash -n does detect an unterminated single quote"
if [ "$r" != 1 ]; then
    echo "      bash -n cannot detect the defect class this guard checks for - refusing to certify."
    exit 2
fi

# --- the guard itself --------------------------------------------------------------------------
BAD=0
while IFS= read -r line; do
    case "$line" in TOTAL*|'') continue;; esac
    f=$(printf '%s' "$line" | awk '{print $4}')
    nm=$(printf '%s' "$line" | awk '{print $2}')
    ln=$(printf '%s' "$line" | awk '{print $3}')
    [ -f "$f" ] || continue
    if ! err=$(bash -n "$f" 2>&1); then
        echo "      BROKEN SNIPPET: step '$nm' (collector line $ln)"
        printf '        %s\n' "$err" | head -3
        BAD=$((BAD+1))
    fi
done < "$WORK/list.txt"
check "$([ "$BAD" -eq 0 ] && echo 1 || echo 0)" "every run_sh snippet is valid shell ($BAD broken)"

# --- and the specific hazard, named so a regression is understood not just detected ------------
# An apostrophe inside a single-quoted snippet terminates it. bash -n on the extracted body may
# still pass depending on where the quote lands, so check for the pattern directly too.
APOS=0
for f in "$WORK"/snips/*.sh; do
    [ -f "$f" ] || continue
    # a lone apostrophe inside a double-quoted echo is the shape that bit us
    if grep -qE "echo \"[^\"]*'[^\"]*\"" "$f"; then
        echo "      APOSTROPHE inside a snippet: $(basename "$f")"
        grep -nE "echo \"[^\"]*'[^\"]*\"" "$f" | head -2 | sed 's/^/        /'
        APOS=$((APOS+1))
    fi
done
check "$([ "$APOS" -eq 0 ] && echo 1 || echo 0)" "no snippet contains an apostrophe inside a double-quoted string ($APOS)"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
