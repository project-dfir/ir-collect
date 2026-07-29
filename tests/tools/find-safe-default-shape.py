# Linux twin of the consequence-shape detector: find where ir-collect.sh sets a SAFE DEFAULT,
# overwrites it from a probe whose failure is DISCARDED, then makes a DECISION on the result.
#
# Shell hides this differently from PowerShell - there is no `catch {}`; the swallowing is
# `2>/dev/null`, `|| true`, `|| :` or `|| echo <default>`.
#
# TWO shapes, and the second one matters more here:
#   1. VAR=default ; VAR=$(probe 2>/dev/null)          ; if [ "$VAR" ... ]
#   2. VAR=default ; probe 2>/dev/null && VAR=other    ; if [ "$VAR" ... ]
# Shape 2 is what the pre-fix LUKS gate used. A first version of this detector implemented only
# shape 1, reported ZERO on a collector that provably contained the bug, and would have published
# "no hits, risk bounded". CALIBRATE AGAINST A KNOWN POSITIVE FROM THE REAL CODEBASE - a synthetic
# self-test only proves the detector finds the shape you imagined.
import io, re, sys, os

SRC = sys.argv[1] if len(sys.argv) > 1 else 'collectors/ir-collect.sh'

SWALLOW = re.compile(r'2>\s*/dev/null|\|\|\s*true\b|\|\|\s*:\s*$|\|\|\s*echo\b')
ASSIGN  = re.compile(r'^\s*(?:local\s+|export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
SAFEDEF = re.compile(r'^(?:0|1|""|\'\'|no|false|none|unknown|)$', re.I)
COND    = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=([^\s;]+)\s*;?.*?&&\s*([A-Za-z_][A-Za-z0-9_]*)=')

def used_in_decision(lines, start, var):
    window = '\n'.join(lines[start:start + 25])
    pat = (r'\[\[?[^\]]*\$\{?' + re.escape(var) + r'\b'
           r'|if\s+[^\n]*\$\{?' + re.escape(var) + r'\b'
           r'|case\s+"?\$\{?' + re.escape(var) + r'\b')
    return re.search(pat, window)

def analyse(lines):
    hits, prior = [], {}
    for i, ln in enumerate(lines):
        code = ln.split('#')[0]
        # --- shape 1: assignment from a swallowed probe, over an earlier safe default ---
        m = ASSIGN.match(code)
        if m:
            var, rhs = m.group(1), m.group(2).strip()
            swallows = bool(SWALLOW.search(rhs))
            looks_probe = '$(' in rhs or '`' in rhs
            if swallows and looks_probe and var in prior:
                dline, dval = prior[var]
                if i - dline <= 12 and SAFEDEF.match(dval.strip().strip('"').strip("'")):
                    u = used_in_decision(lines, i + 1, var)
                    if u:
                        hits.append((i + 1, var, dval.strip(), rhs[:70], u.group(0).strip()[:60], 1))
            if not (swallows and looks_probe):
                prior[var] = (i, rhs)
        # --- shape 2: safe default then a conditional assignment gated on a swallowed probe ---
        if SWALLOW.search(code):
            c = COND.search(code)
            if c and c.group(1) == c.group(3):
                dvar, dval = c.group(1), c.group(2)
                if SAFEDEF.match(dval.strip().strip('"').strip("'")):
                    u = used_in_decision(lines, i + 1, dvar)
                    if u:
                        hits.append((i + 1, dvar, dval, code.strip()[:70], u.group(0).strip()[:60], 2))
    return hits

# ---- SELF-TEST: find both shapes, reject the two non-shapes ----
probe_src = [
    'FOO=0',
    'FOO=$(some_probe 2>/dev/null)',
    'if [ "$FOO" -ge 1 ]; then echo hi; fi',
    'BAR=0',
    'BAR=$(other_probe)',
    'if [ "$BAR" -ge 1 ]; then echo hi; fi',
    'BAZ=0',
    'BAZ=$(p 2>/dev/null)',
    'echo done',
    'QUX=0; grep -q x /f 2>/dev/null && QUX=1',
    'if [ "$QUX" = 1 ]; then echo hi; fi',
]
names = sorted(h[1] for h in analyse(probe_src))
if names != ['FOO', 'QUX']:
    print('SELF-TEST FAILED: expected FOO+QUX, got %r - output below would be meaningless' % (names,))
    sys.exit(2)
print('self-test OK (finds both shapes; rejects unswallowed and undecided)')
print()

if not os.path.exists(SRC):
    print('collector not found: %s' % SRC); sys.exit(2)
lines = io.open(SRC, encoding='utf-8').read().split('\n')

total = sum(1 for l in lines if SWALLOW.search(l.split('#')[0]))
print('%s' % SRC)
print('  lines with a swallowing construct : %d' % total)
if total < 20:
    print('  SUSPICIOUSLY FEW - pattern may be wrong'); sys.exit(2)

hits = analyse(lines)
print('  safe-default + swallowed probe + decision : %d' % len(hits))
print()
for ln, var, dflt, probe, use, shape in hits:
    print('  line %-6d %-14s [shape %d]' % (ln, var, shape))
    print('     default : %s=%s' % (var, dflt))
    print('     probe   : %s' % probe)
    print('     decision: %s' % use)
