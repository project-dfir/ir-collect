"""Extract the single-quoted shell snippets that ir-collect.sh hands to `bash -c`, AS BASH SEES THEM.

WHY THIS EXISTS. `bash -n collectors/ir-collect.sh` PASSES on a file whose snippets are broken,
because a snippet is only a string until run_sh evaluates it. On 2026-07-30 an apostrophe inside
one of those single-quoted strings terminated it early, and meta-volkeys - the VOLUME MASTER KEY
capture - failed rc=2 on every run for two iterations, writing a file that had the right name, the
right banner, and nothing after it.

THE BOUNDARY RULE IS THE WHOLE POINT. Inside a bash single-quoted string, the ONLY thing that ends
it is the next apostrophe - not a newline, not an escape, nothing else. A first version of this
extractor scanned for the next LINE ENDING in a quote instead, reported 22 of 24 snippets broken
against a collector whose steps demonstrably run, and would have been a cries-wolf check that got
switched off. Scanning to the next apostrophe is both correct and exactly the semantics that
produced the defect: if an apostrophe appears in the middle, what bash executes is the truncated
head, and the remainder becomes stray tokens.

Usage:  extract-snippets.py <collector.sh> <outdir>
Prints "<index> <step-name> <line-number> <outfile>" per snippet, then "TOTAL <n>".
Exit 2 if the file cannot be read or a snippet never closes.
"""
import io
import os
import re
import sys

# run_sh <name> <outfile> <dir> <timeout> <retries> '<snippet>
OPEN = re.compile(r"^\s*run_sh\s+(\S+)\s")


def main(argv):
    if len(argv) != 3:
        print("usage: extract-snippets.py <collector.sh> <outdir>")
        return 2
    src, outdir = argv[1], argv[2]
    try:
        text = io.open(src, encoding='utf-8', errors='replace').read()
    except OSError as e:
        print("CANNOT READ %s: %s" % (src, e))
        return 2
    if not os.path.isdir(outdir):
        os.makedirs(outdir)

    lines = text.split('\n')
    # character offset of the start of each line, so a line number can be reported
    offsets = []
    pos = 0
    for l in lines:
        offsets.append(pos)
        pos += len(l) + 1

    def line_of(off):
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    n = 0
    for idx, line in enumerate(lines):
        m = OPEN.match(line)
        if not m:
            continue
        name = m.group(1)
        # the opening quote is the first apostrophe on the run_sh line
        q = line.find("'")
        if q < 0:
            continue
        start = offsets[idx] + q + 1
        # Bash ends a single-quoted string at the next apostrophe - but this file deliberately
        # SPLICES, using the idiom "'"$VAR"'" to close the quote, let the OUTER shell expand a
        # variable, and reopen. That is correct and common here, so an apostrophe immediately
        # followed by a double quote is a splice, not the end. Skip over the spliced segment and
        # keep scanning. Without this the extractor flagged five working steps and would have been
        # a check that cries wolf.
        cur = start
        parts = []
        end = -1
        while True:
            e = text.find("'", cur)
            if e < 0:
                break
            if e + 1 < len(text) and text[e + 1] == '"':
                reopen = text.find("'", e + 1)      # the closing quote of the spliced segment
                if reopen < 0:
                    break
                parts.append(text[cur:e])
                parts.append('SPLICED_VAR')          # a placeholder that is valid shell
                cur = reopen + 1
                continue
            parts.append(text[cur:e])
            end = e
            break
        if end < 0:
            print("UNCLOSED snippet for %s starting at line %d" % (name, idx + 1))
            return 2
        body = ''.join(parts)
        n += 1
        out = os.path.join(outdir, "%02d_%s.sh" % (n, re.sub(r'[^A-Za-z0-9_-]', '_', name)))
        io.open(out, 'w', encoding='utf-8', newline='\n').write(body + '\n')
        print("%d %s %d %s" % (n, name, idx + 1, out))
    print("TOTAL %d" % n)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
