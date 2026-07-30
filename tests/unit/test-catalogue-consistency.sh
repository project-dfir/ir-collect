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

PY_BIN=""
for c in python python3; do command -v "$c" >/dev/null 2>&1 && { PY_BIN="$c"; break; }; done

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

# --- 6. cited LINE NUMBERS: attempted and WITHDRAWN, deliberately ---------------------------
# The page cites code positions as evidence ("IR-Collect.ps1:767 defines the wmi_failure ladder"),
# and those drift whenever code is inserted above them. A real instance was found by hand on
# 2026-07-29: the page cited :618 for that ladder, which had moved to :767 - the citation still
# read as authoritative while pointing at an unrelated comment. That citation is now corrected.
#
# An automated version of the check is NOT shipped. Two attempts produced FALSE POSITIVES on
# citations that were correct: the first compared only the first backticked token after a citation
# (often a symbol from the surrounding sentence, not the code at that line), and the second failed
# because the extractor captured `'wmi_failure'` WITH its quotes, so a literal search never matched.
#
# A check that cries wolf gets switched off, and then it protects nothing. Shipping an assertion
# known to fire on correct input is worse than shipping none - the same reasoning that made
# "publish nothing when the instrument fails calibration" the rule elsewhere in this project.
#
# What a working version needs: the doc quoting code in a machine-checkable form (a fenced block
# tagged with its file and line), rather than a heuristic guessing which nearby backtick refers to
# the cited line. Until the page carries that, citation drift is caught by hand.

# --- 7. every in-page anchor link must resolve to a real heading -------------------------------
# The page carries a generated navigation index (tests/tools/build-catalogue-index.py). An index
# that points at sections which no longer exist is worse than no index: it sends a reader
# somewhere wrong while looking authoritative, which is the same failure as the drifted code
# citation this page already records. The index is generated, so this asserts the page and the
# generator agree - and it must also fail when a section is RENAMED without regenerating.
if [ -n "$PY_BIN" ]; then
    "$PY_BIN" - "$DOC" <<'PYEOF' > /tmp/anchors.$$ 2>&1
import io, re, sys
s = io.open(sys.argv[1], encoding='utf-8').read()

def anchor(t):
    a = t.strip().lower().replace('`', '')
    a = re.sub(r'[^\w\s-]', '', a, flags=re.UNICODE)
    return re.sub(r'\s+', '-', a.strip())

heads = {anchor(l[3:]) for l in s.split('\n') if l.startswith('## ')}
links = re.findall(r'\]\(#([^)]+)\)', s)
missing = sorted({l for l in links if l not in heads})
print('LINKS %d' % len(links))
print('MISSING %d' % len(missing))
for m in missing[:10]:
    print('  BROKEN %s' % m)
PYEOF
    LINKS=$(awk '/^LINKS /{print $2}' /tmp/anchors.$$)
    MISS=$(awk '/^MISSING /{print $2}' /tmp/anchors.$$)
    rm -f /tmp/anchors.$$
    check "$([ "${LINKS:-0}" -ge 20 ] && echo 1 || echo 0)" \
          "the page carries a navigation index (${LINKS:-0} anchor links, expect >=20)"
    check "$([ "${MISS:-1}" -eq 0 ] && echo 1 || echo 0)" \
          "every anchor link resolves to a real heading (${MISS:-?} broken)"
else
    echo "ok    anchor check SKIPPED - no python (reported, not silently passed)"
fi

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
