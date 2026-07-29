#!/usr/bin/env bash
# Mechanical consistency checks for tests/e2e/scenarios/FAILURE-SCENARIOS.md.
#
# WHY THIS IS A TEST AND NOT ANOTHER AUDIT. Status for a scenario is written in THREE places - the
# summary table row, the per-scenario section heading, and the prose - and they drift. It has now
# happened four times: E3's heading said PARTIAL while its row said CLOSED and its own body said
# "both controls passing"; E5 shipped without a legend glyph; E1 was marked handled while its text
# described an open gap; D5's row still said "never run against a real encrypted volume" while the
# section below recorded both controls passing. Every one was found by cross-checking, never by
# reading. So the cross-check belongs in CI, where it runs whether or not anyone is auditing.
#
# The checks are deliberately narrow: they compare the document against ITSELF and against the
# filesystem. They cannot tell whether a claim is true - only whether the page contradicts itself
# or points at something that does not exist.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DOC="${1:-$REPO/tests/e2e/scenarios/FAILURE-SCENARIOS.md}"
[ -f "$DOC" ] || { echo "FAIL  catalogue not found: $DOC"; exit 2; }

FAIL=0
check() { if [ "$1" = 1 ]; then printf 'ok    %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; FAIL=$((FAIL+1)); fi; }

# --- SELF-TEST the extractors against known-present and known-absent shapes -------------------
# An extractor that silently matches nothing reports a clean document, which is the failure mode
# this whole page is about. Prove it finds something real before trusting a zero.
ROWS=$(grep -cE '^\| [A-E][0-9]+ \|' "$DOC")
check "$([ "$ROWS" -ge 20 ] && echo 1 || echo 0)" "row extractor finds the scenario table ($ROWS rows, expect >=20)"
SECS=$(grep -cE '^## ' "$DOC")
check "$([ "$SECS" -ge 15 ] && echo 1 || echo 0)" "section extractor finds headings ($SECS, expect >=15)"
if [ "$ROWS" -lt 20 ] || [ "$SECS" -lt 15 ]; then
    echo "FAIL  extractors are broken - every result below would be meaningless"; exit 2
fi

# --- 1. no scenario heading may claim a status its table row contradicts ----------------------
# Only headings that begin with a scenario ID are scenario status; "## Audit: ..." and the INVALID
# control write-ups are notes about attempts, not row status.
DRIFT=0
while IFS= read -r h; do
    id=$(printf '%s' "$h" | sed -E 's/^## ([A-E][0-9]+).*/\1/')
    hstat=$(printf '%s' "$h" | grep -oE '\((CLOSED|PARTIAL|OPEN|INVALID)[^)]*\)' | head -1)
    [ -n "$hstat" ] || continue
    row=$(grep -E "^\| $id \|" "$DOC" | head -1)
    [ -n "$row" ] || continue
    case "$hstat" in
        *PARTIAL*|*OPEN*)
            if printf '%s' "$row" | grep -q 'CLOSED'; then
                echo "      DRIFT: heading '$id' says ${hstat} but its table row says CLOSED"
                DRIFT=$((DRIFT+1))
            fi ;;
    esac
done < <(grep -E '^## [A-E][0-9]+' "$DOC")
check "$([ "$DRIFT" -eq 0 ] && echo 1 || echo 0)" "no scenario heading contradicts its own table row"

# --- 2. every closed row carries a glyph from the legend at the top of the page ---------------
NOGLYPH=$(grep -E '^\| [A-E][0-9]+ \|' "$DOC" | grep 'CLOSED' | grep -cv -e '✅' -e '⚠️' || true)
check "$([ "$NOGLYPH" -eq 0 ] && echo 1 || echo 0)" "every CLOSED row carries a legend glyph ($NOGLYPH without)"

# --- 3. repo paths the page tells an operator to run must exist -------------------------------
# Historical quotations are legitimate: line 663 and the audit section quote `kit\IR-Collect.ps1`
# precisely to describe that stale path being fixed. Only flag paths on lines that are not
# describing a past defect.
MISSING=0
while IFS= read -r line; do
    case "$line" in *"kit"*"IR-Collect.ps1"*) continue;; esac   # the documented historical example
    # sed, not `tr -d '.'`: tr removes EVERY dot, so Set-TestPolicy.ps1 became Set-TestPolicyps1
    # and the checker reported seven missing files that all exist. Strip only TRAILING punctuation.
    for p in $(printf '%s' "$line" | grep -oE '(tests|collectors|docs)/[A-Za-z0-9_./-]+' | sed -E 's/[`,.]+$//'); do
        [ -e "$REPO/$p" ] || { echo "      MISSING: $p"; MISSING=$((MISSING+1)); }
    done
done < <(grep -E '(tests|collectors|docs)/' "$DOC")
check "$([ "$MISSING" -eq 0 ] && echo 1 || echo 0)" "every repo path the page references exists ($MISSING missing)"

# --- 4. a "live-verified" claim must have evidence on the page --------------------------------
# Not proof the claim is true - only that the section shows a run rather than asserting one. Every
# section making such a claim must contain a fenced block (the captured output) somewhere after it.
CLAIMS=$(grep -cE 'live.verified|verified live|LIVE VERIFIED' "$DOC" || true)
FENCES=$(grep -c '^```' "$DOC" || true)
check "$([ "$CLAIMS" -ge 1 ] && echo 1 || echo 0)" "the page does claim live verification ($CLAIMS times)"
check "$([ "$FENCES" -ge "$CLAIMS" ] && echo 1 || echo 0)" \
      "there are at least as many captured-output blocks as live-verified claims ($FENCES fences vs $CLAIMS claims)"

# --- 5. INVALID controls must stay marked INVALID, never quietly upgraded ---------------------
# A control recorded INVALID is evidence about the HARNESS, not the product. If one is later
# described as passing without a new run, that is exactly the false-success this project exists to
# prevent - so assert the word survives wherever a control was recorded invalid.
INV=$(grep -cE 'INVALID' "$DOC" || true)
check "$([ "$INV" -ge 3 ] && echo 1 || echo 0)" "invalid-control records are still present and marked ($INV mentions)"

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
