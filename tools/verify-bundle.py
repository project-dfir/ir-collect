#!/usr/bin/env python3
"""Verify a sealed ir-collect evidence bundle. For the analyst who RECEIVES one.

The collector writes a SHA-256 manifest and the README calls that the chain-of-custody
feature. Until now nothing on the receiving end ever used it: there was no verifier, and no
documented procedure for checking a bundle that arrived. A manifest nobody validates is a
claim, not evidence.

INDEPENDENCE IS THE POINT. This uses Python's hashlib, deliberately NOT the collector's own
hashing (`irhash` on Linux, Get-FileHash on Windows). A verifier built from the code that
produced the digests can only prove that code is self-consistent, which is not the question.

WHAT IT CANNOT DO, stated plainly rather than implied:
  * The manifest CANNOT COVER ITSELF - nothing can hash itself. Anyone able to alter a file
    can recompute the manifest to match. This detects damage, truncation, partial transfer
    and casual tampering; it does NOT prove authenticity. That needs a signature or an
    out-of-band digest of the manifest, recorded when the bundle was sealed.
  * It says nothing about whether the collection was complete or correct - only that what
    was sealed is what is here now.

The set of legitimately-unlisted files is READ FROM THE BUNDLE'S OWN MANIFEST-README.txt,
not hardcoded here. If it were hardcoded, this tool and that document would drift, and the
first sign would be a verifier quietly excusing a file nobody meant to exclude. If the note
is missing or unparseable this exits 2 (cannot verify) rather than guessing - an unlisted
file whose status cannot be established is exactly what tampering looks like.

Exit codes:  0 verified | 1 verification FAILED | 2 could not verify (tool/input problem)
"""
import hashlib
import os
import sys

BUF = 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(BUF)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def norm(p):
    """Compare paths the same way regardless of which collector wrote them."""
    p = p.replace('\\', '/').lstrip('./').lstrip('/')
    return p.lower()


def to_fs(rel):
    """Manifest path -> a path that can be joined onto the bundle root.

    The two collectors disagree about the leading separator: Linux writes './00_metadata/x' and
    Windows writes '\\00_metadata\\x'. Translating the Windows form naively gives '/00_metadata/x',
    which os.path.join treats as ABSOLUTE and silently discards the bundle root - so every lookup
    landed at the filesystem root and every file in a real Windows bundle was reported MISSING.
    A verifier that cries tampering over a path-separator convention is worse than useless, so
    strip the leading separators before joining rather than trusting the manifest's spelling.
    """
    r = rel.replace('\\', '/').lstrip('/')
    while r.startswith('./'):
        r = r[2:]
    return r.replace('/', os.sep)


def parse_exclusions(root):
    """Read the bundle's own statement of what it deliberately left out."""
    note = os.path.join(root, '99_logs', 'MANIFEST-README.txt')
    if not os.path.isfile(note):
        return None, "99_logs/MANIFEST-README.txt is absent, so there is no way to tell a deliberately excluded file from an added one"
    try:
        with open(note, 'r', encoding='utf-8', errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        return None, "could not read MANIFEST-README.txt: %s" % e

    excl, collecting = set(), False
    for ln in lines:
        if ln.strip().startswith('Deliberately NOT listed'):
            collecting = True
            continue
        if collecting:
            if not ln.strip():
                continue
            if ln.strip().startswith('Anything else absent'):
                break
            if ln.startswith('  ') and not ln.startswith('      '):
                tok = ln.strip().split()[0]
                if '/' in tok or tok.endswith(('.log', '.csv', '.txt', '.sha256')):
                    excl.add(norm(tok))
    if not excl:
        return None, "the 'Deliberately NOT listed' block in MANIFEST-README.txt yielded no entries - the format changed and this parser no longer understands it"
    return excl, None


def parse_manifest(root):
    """Windows ships a CSV (<sha>,<len>,<path>); Linux a text file (<sha>  <path>)."""
    csv = os.path.join(root, '99_logs', 'MANIFEST-SHA256.csv')
    txt = os.path.join(root, '99_logs', 'MANIFEST-SHA256.txt')
    if os.path.isfile(csv):
        path, kind = csv, 'csv'
    elif os.path.isfile(txt):
        path, kind = txt, 'txt'
    else:
        return None, None, None, "no MANIFEST-SHA256.csv or .txt under 99_logs/"

    entries, bad = {}, 0
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            ln = ln.rstrip('\r\n')
            if not ln.strip():
                continue
            if kind == 'csv':
                parts = ln.split(',', 2)
                if len(parts) != 3:
                    bad += 1
                    continue
                digest, rel = parts[0].strip(), parts[2].strip()
            else:
                parts = ln.split('  ', 1)
                if len(parts) != 2:
                    bad += 1
                    continue
                digest, rel = parts[0].strip(), parts[1].strip()
            if not rel:
                bad += 1
                continue
            entries[norm(rel)] = (digest, rel)
    return entries, kind, bad, None


def main(argv):
    if len(argv) != 2:
        print("usage: verify-bundle.py <bundle-directory>")
        return 2
    root = argv[1]
    if not os.path.isdir(root):
        print("FAIL  not a directory: %s" % root)
        return 2

    entries, kind, bad_lines, err = parse_manifest(root)
    if err:
        print("CANNOT VERIFY  %s" % err)
        return 2
    excl, eerr = parse_exclusions(root)
    if eerr:
        print("CANNOT VERIFY  %s" % eerr)
        return 2

    # the manifest itself is never listed in itself; treat it as excluded for the sweep
    manifest_rel = norm('99_logs/MANIFEST-SHA256.%s' % kind)
    excl.add(manifest_rel)

    on_disk = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            on_disk.add(norm(rel))

    ok, mismatch, missing, unreadable = 0, [], [], []
    for key, (digest, rel) in sorted(entries.items()):
        full = os.path.join(root, to_fs(rel))
        if not os.path.isfile(full):
            missing.append(rel)
            continue
        if digest.upper() == 'ERR':
            unreadable.append(rel)
            continue
        try:
            actual = sha256(full)
        except OSError as e:
            unreadable.append("%s (%s)" % (rel, e))
            continue
        if actual.lower() == digest.lower():
            ok += 1
        else:
            mismatch.append(rel)

    unlisted = sorted(p for p in on_disk if p not in entries and p not in excl)

    print("bundle        : %s" % os.path.abspath(root))
    print("manifest      : MANIFEST-SHA256.%s  (%d entries, %d unparseable line(s))"
          % (kind, len(entries), bad_lines))
    print("verified      : %d file(s) hash-match" % ok)
    print("MISMATCH      : %d" % len(mismatch))
    for m in mismatch[:20]:
        print("                %s" % m)
    print("MISSING       : %d  (listed in the manifest, not present)" % len(missing))
    for m in missing[:20]:
        print("                %s" % m)
    print("UNLISTED      : %d  (present, not in the manifest, not declared as excluded)" % len(unlisted))
    for m in unlisted[:20]:
        print("                %s" % m)
    if unreadable:
        print("NOT CHECKED   : %d  (manifest recorded ERR, or unreadable now)" % len(unreadable))
        for m in unreadable[:10]:
            print("                %s" % m)

    # the separately-hashed custody trail
    aud = os.path.join(root, 'MANIFEST-audit-log.sha256')
    audit_bad = False
    # One entry per line: the audit trail, and the completion ledger beside it. Both are frozen
    # after the manifest runs, because both are still being appended to while it runs.
    if os.path.isfile(aud):
        try:
            with open(aud, 'r', encoding='utf-8', errors='replace') as fh:
                lines = [l.strip() for l in fh if l.strip()]
            if not lines:
                print("custody trail : UNCHECKED - MANIFEST-audit-log.sha256 is empty")
                audit_bad = True
            for line in lines:
                want, rel = line.split(None, 1)
                rel = rel.strip()
                target = os.path.join(root, to_fs(rel))
                if not os.path.isfile(target):
                    print("custody trail : MISSING - %s is named by MANIFEST-audit-log.sha256 but absent" % rel)
                    audit_bad = True
                    continue
                good = sha256(target).lower() == want.lower()
                print("custody trail : %s (%s)" % ("VERIFIED" if good else "MISMATCH", rel))
                if not good:
                    audit_bad = True
        except (OSError, ValueError) as e:
            print("custody trail : UNCHECKED - MANIFEST-audit-log.sha256 is unreadable or malformed (%s)" % e)
            audit_bad = True
    else:
        print("custody trail : absent (no MANIFEST-audit-log.sha256)")

    print("")
    print("NOTE: the manifest cannot cover itself. A passing result shows the listed files are")
    print("      unchanged since sealing; it does NOT prove the manifest is the original one.")
    print("      Authenticity requires a signature or a digest of the manifest recorded")
    print("      out-of-band at collection time.")

    failed = mismatch or missing or unlisted or audit_bad or bad_lines
    print("")
    print("RESULT: %s" % ("FAILED" if failed else "VERIFIED"))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
