#!/usr/bin/env bash
# volume_key_shape: does `dmsetup table --showkeys` actually contain a key?
#
# WHY THIS EXISTS. On 2026-07-29 the DECRYPTION-KEYS.md recovery procedure was executed end to end
# for the first time, against a LUKS2 loopback on range-linux-web (cryptsetup 2.7.0). It failed at
# the first step, and the reason was not the command - it was that no key had been captured:
#
#   0 163840 crypt aes-xts-plain64 :64:logon:cryptsetup:b8875a97-...-d0 0 7:0 32768 1 sector_size:4096
#
# Since cryptsetup 2.x a LUKS2 volume opened normally keeps its key in the KERNEL KEYRING, so the
# table carries a reference. Only `--disable-keyring` yields hex (measured: 128 chars), and how the
# volume was opened belongs to whoever booted the host. The collector was writing that pointer into
# volume_master_keys.txt under a banner reading "these are VOLUME MASTER KEYS - they decrypt the
# evidence". A file that exists, is non-empty, and does not contain what it claims - discovered
# months later with the host gone.
#
# So the shape is now classified explicitly and stated in the artifact. This test pins the
# classifier, because everything downstream of it is a claim about whether evidence is recoverable.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SH="$REPO/collectors/ir-collect.sh"
[ -f "$SH" ] || { echo "FAIL  collector not found"; exit 2; }

# Pull the function out of the collector rather than copying it - a copy drifts, and a drifted copy
# would test nothing. Extract the definition and eval it here.
FN=$(awk '/^  volume_key_shape\(\) \{/,/^  \}/' "$SH")
if [ -z "$FN" ]; then
    echo "FAIL  could not extract volume_key_shape from the collector - guard broken, NOT clean"
    exit 2
fi
eval "$(printf '%s\n' "$FN" | sed 's/^  //')"
if ! command -v volume_key_shape >/dev/null 2>&1 && ! type volume_key_shape >/dev/null 2>&1; then
    echo "FAIL  extracted text did not define the function - guard broken"; exit 2
fi

FAIL=0
t() { # t <input> <expected> <why>
    got=$(volume_key_shape "$1")
    if [ "$got" = "$2" ]; then printf 'ok    %s\n' "$3"
    else printf 'FAIL  %s (got %s, want %s)\n' "$3" "$got" "$2"; FAIL=$((FAIL+1)); fi
}

# --- the real observed reference, verbatim from range-linux-web -------------------------------
t ':64:logon:cryptsetup:b8875a97-cfd1-4c30-a78e-5b0d916e8355-d0' 'keyring-reference' \
  'the exact keyring reference observed live is NOT mistaken for a key'
t ':32:user:foo' 'keyring-reference' 'any colon-bearing field is a reference'

# --- real hex keys ----------------------------------------------------------------------------
t 'df7c775d8a2a51712aa19fd6c3b40e1af8f2b6d1c0a4e7938b5c6d7e8f90a1b2' 'hex' \
  'a 64-char hex key is recognised'
t "$(printf '0%.0s' $(seq 1 128))" 'hex' 'a 128-char hex key (aes-xts 512-bit) is recognised'
t 'ABCDEF0123456789' 'hex' 'uppercase hex is recognised'

# --- nothing usable ---------------------------------------------------------------------------
t '' 'absent' 'an empty field is absent, not a key'
t 'none' 'absent' 'a non-hex word is absent'
t 'zzzz' 'absent' 'non-hex letters are absent'
t 'a' 'absent' 'a single character is not a usable key'

# --- THE DIRECTION THAT COSTS EVIDENCE --------------------------------------------------------
# Being wrong toward "hex" is the expensive error: it tells a responder a key was captured when it
# was not, and they learn otherwise only once the host is gone. Assert that nothing ambiguous
# lands on 'hex'.
for probe in ':64:logon:cryptsetup:x' '' 'none' 'not-a-key' '::' 'deadbeef:0'; do
    got=$(volume_key_shape "$probe")
    if [ "$got" = 'hex' ]; then
        printf 'FAIL  %s classified as hex - claims a key that is not there\n' "${probe:-<empty>}"
        FAIL=$((FAIL+1))
    fi
done
printf 'ok    %s\n' 'no ambiguous field is ever classified as hex'

echo
if [ "$FAIL" = 0 ]; then echo "all assertions passed"; else echo "$FAIL failed"; fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
