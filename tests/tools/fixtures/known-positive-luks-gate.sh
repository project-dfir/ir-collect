#!/usr/bin/env bash
# KNOWN-POSITIVE FIXTURE - do not "fix" this file. It is the volatile gate exactly as it stood
# before commit 09ccfe4, and it contains the two-state collapse that shipped:
#
#     local enc=0; grep -q '^ENCRYPTED=yes' ... 2>/dev/null && enc=1
#
# A safe default, a probe whose failure is discarded, and a decision taken on the result. The
# safe-default detector MUST find exactly one hit here. Vendored rather than fetched with
# `git show <sha>~1` because CI checkouts are shallow and that would silently yield nothing -
# a calibration that cannot run is indistinguishable from a calibration that passed.

# VOLATILE GREEN gate - confirm the perishable data is captured before the
# slow non-volatile phase. This is the checkpoint the operator waits for.
# ---------------------------------------------------------------------------
SEALED=0
volatile_green_gate() {
  local vol_files; vol_files=$(find "$D_VOL" "$D_NET" -type f 2>/dev/null | wc -l | tr -d ' ')
  local enc=0; grep -q '^ENCRYPTED=yes' "$D_META/encryption.txt" 2>/dev/null && enc=1
  local memnote; [ "${MEM_OK:-0}" = "1" ] && memnote="RAM: VERIFIED ($((MEM_BYTES/1024/1024)) MB)" || memnote="RAM: NOT verified - capture failed/absent"
  echo
  if [ "$enc" = "1" ] && [ "${MEM_OK:-0}" != "1" ]; then
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "  !!  VOLATILE: AMBER - ENCRYPTED DISK + NO VERIFIED RAM   !!"
    echo "  !!  The LUKS master key is in RAM you did NOT capture.   !!"
    echo "  !!  Do NOT power off without the key or the disk image   !!"
    echo "  !!  is unreadable. See 00_metadata/encryption.txt.       !!"
    echo "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    audit "VOLATILE AMBER | encrypted disk + no verified RAM | files=$vol_files"
  elif [ "$vol_files" -ge 10 ] && [ "${MEM_OK:-0}" = "1" ]; then
    echo "  ############################################################"
    echo "  #   VOLATILE CAPTURE: GREEN  ($vol_files artifacts, OK=$STEPS_OK FAIL=$STEPS_FAIL)"
