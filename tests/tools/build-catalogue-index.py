"""Generate the navigation index for FAILURE-SCENARIOS.md from its own headings.

WHY GENERATED, NOT WRITTEN BY HAND. The page is 2600+ lines and 56 sections, appended one
investigation at a time. A hand-written index drifts the moment a section is added or retitled,
and a stale index is worse than none - it sends a reader to the wrong place while looking
authoritative. This project already retired one checker for crying wolf and fixed one drifted
citation; an index is the same hazard in a friendlier costume.

So: the index is derived from the headings, the anchors are computed with GitHub's own rule, and
tests/unit/test-catalogue-consistency.sh asserts every anchor in the page resolves to a real
heading. Regenerate with:

    python tests/tools/build-catalogue-index.py tests/e2e/scenarios/FAILURE-SCENARIOS.md <out.md>

WRITES THE FILE ITSELF, in explicit UTF-8, rather than printing for a shell redirect. The first
version printed to stdout; on Windows that encodes to the console codepage, so an em-dash in a
heading came back as cp1252 byte 0x97 and the captured file was not valid UTF-8. Splicing that
into the page would have corrupted it. It does not edit the page - splicing stays a human decision.
"""
import io
import re
import sys

# Ordered theme rules: the FIRST pattern that matches a heading claims it. Anything unmatched
# falls into "Other investigations" rather than being dropped - a silently missing entry is the
# failure mode this whole file exists to avoid.
THEMES = [
    ('Start here', [
        r'^Verify the condition', r'^Testing hygiene', r'^How to run one',
    ]),
    ('Scenario families', [
        r'^[A-E]\. ',
    ]),
    ('Closed scenarios', [
        r'^[A-E]\d+\b', r'^B3 half',
    ]),
    ('The signature defect: two-state where it must be three', [
        r'signature', r'safe-default', r'swallowed failures', r'Encryption risk was two-state',
        r'LUKS gate had the same',
    ]),
    ('Encryption, keys and the evidence they unlock', [
        r'[Ee]ncryption', r'master-key', r'LUKS', r'recovery procedure',
    ]),
    ('Error-class reachability and the fix ladders', [
        r'[Ee]rror-class', r'fix ladder', r'reachability',
    ]),
    ('Bundle verification, custody and sealing', [
        r'Verifying a bundle', r'chain-of-custody', r'cannot check',
    ]),
    ('Open questions and named gaps', [
        r'NOT solved', r'a GAP', r'A1 preparation',
    ]),
    ('When the instrument was the broken part', [
        r'INVALID', r'crying wolf', r'was lying', r'does not work', r'told nobody',
        r'^Audit', r'NOT SCORED',
    ]),
]


def anchor(title):
    """GitHub's heading-anchor rule: lowercase, drop punctuation, spaces to hyphens."""
    a = title.strip().lower()
    a = a.replace('`', '')
    a = re.sub(r'[^\w\s-]', '', a, flags=re.UNICODE)   # strip punctuation incl. em dashes
    a = re.sub(r'\s+', '-', a.strip())
    return a


def main(argv):
    if len(argv) != 3:
        print("usage: build-catalogue-index.py <FAILURE-SCENARIOS.md> <out.md>")
        return 2
    try:
        lines = io.open(argv[1], encoding='utf-8').read().split('\n')
    except OSError as e:
        print("CANNOT READ: %s" % e)
        return 2

    heads = [l[3:].strip() for l in lines if l.startswith('## ')]
    if len(heads) < 15:
        print("ONLY %d headings found - refusing to build an index from that" % len(heads))
        return 2

    claimed = set()
    buckets = []
    for name, pats in THEMES:
        hits = []
        for h in heads:
            if h in claimed:
                continue
            if any(re.search(p, h) for p in pats):
                hits.append(h)
                claimed.add(h)
        if hits:
            buckets.append((name, hits))
    leftover = [h for h in heads if h not in claimed]
    if leftover:
        buckets.append(('Other investigations', leftover))

    out = []
    out.append('## Finding your way around this page')
    out.append('')
    out.append('%d sections, appended one investigation at a time. This index is GENERATED from the'
               % len(heads))
    out.append('headings (`tests/tools/build-catalogue-index.py`) and its anchors are checked in CI, because a')
    out.append('hand-maintained index drifts and a stale index is worse than none - it sends a reader')
    out.append('somewhere wrong while looking authoritative.')
    out.append('')
    for name, hits in buckets:
        out.append('**%s**' % name)
        out.append('')
        for h in hits:
            out.append('- [%s](#%s)' % (h, anchor(h)))
        out.append('')
    io.open(argv[2], 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
    print("wrote %s: %d entries in %d themes" % (argv[2], len(heads), len(buckets)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
