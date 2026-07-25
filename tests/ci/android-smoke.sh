#!/usr/bin/env bash
# CI Android smoke: drive mobile-collect.sh against a booted emulator, assert the sealed bundle.
# Invoked by .github/workflows/mobile.yml inside reactivecircus/android-emulator-runner (device already booted).
set -x
adb root >/dev/null 2>&1 && adb wait-for-device || true
# best-effort seed so content-provider queries have a row (single line - no continuations)
adb shell content insert --uri content://sms --bind address:s:+15550000001 --bind body:s:e2e_msg --bind type:i:1 >/dev/null 2>&1 || true

chmod +x mobile/mobile-collect.sh
./mobile/mobile-collect.sh --android --auto --scenario beacon -c CIMOB -d ./mobout || echo "collector exit=$? (asserting artifacts next)"

echo "=== assert sealed mobile bundle ==="
base=$(find ./mobout -maxdepth 1 -type d -name 'CIMOB_*' | head -1)
echo "bundle: $base"
[ -n "$base" ] || { echo "FAIL: no bundle dir"; exit 1; }
for f in meta/collection_info.json logs/run_state.json SUMMARY.md; do
  [ -f "$base/$f" ] || { echo "FAIL: missing $f"; exit 1; }
done
echo "--- scenario + acquisition tier ---"
grep -o '"scenario":"[^"]*"'         "$base/meta/collection_info.json" || true
grep -o '"acquisition_tier":"[^"]*"' "$base/meta/collection_info.json" || true
echo "--- run_state verdict ---"
grep -o '"verdict":"[^"]*"' "$base/logs/run_state.json" || true
grep -q '"scenario":"beacon"' "$base/meta/collection_info.json" || { echo "FAIL: scenario not beacon"; exit 1; }
[ -s "$base/logs/run_state.jsonl" ] || { echo "FAIL: empty ledger"; exit 1; }
echo "captured dirs:"; ls "$base/dumpsys" "$base/artifacts" 2>/dev/null | head
echo "MOBILE ANDROID SMOKE PASS"
