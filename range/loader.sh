#!/bin/sh
# In-guest LOADER (Linux). Use when the kit is delivered on a read-only ISO / share and you just
# want to launch it: finds ir-collect.sh next to itself, resolves a WRITABLE output, runs --lab.
# Extra args pass through (e.g. --auto -c EXERCISE1).
#
#   /mnt/cdrom/range/loader.sh --auto -c EXERCISE1
#
# Output precedence: a volume LABELED EVIDENCE/IR-EVIDENCE (attached evidence disk) ->
# $IR_OUT -> /var/tmp/ir_evidence. (Never writes onto the read-only delivery media.)
here="$(cd "$(dirname "$0")" && pwd)"
col="$(find "$here" -name ir-collect.sh -type f 2>/dev/null | head -1)"
[ -z "$col" ] && { echo "ir-collect.sh not found under $here" >&2; exit 1; }

out=""
if command -v blkid >/dev/null 2>&1; then
  ev="$(blkid -L EVIDENCE 2>/dev/null || blkid -L IR-EVIDENCE 2>/dev/null)"
  if [ -n "$ev" ]; then
    mkdir -p /mnt/ir_evidence 2>/dev/null
    mount "$ev" /mnt/ir_evidence 2>/dev/null && out=/mnt/ir_evidence
  fi
fi
[ -z "$out" ] && out="${IR_OUT:-/var/tmp/ir_evidence}"
mkdir -p "$out" 2>/dev/null

echo "Loader: $col  ->  $out  (lab mode)"
if command -v bash >/dev/null 2>&1; then exec bash "$col" --lab -d "$out" "$@"
else exec sh "$col" --lab -d "$out" "$@"; fi
