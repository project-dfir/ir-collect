# Mobile Device Forensics (Android + iOS)

Mobile support works differently from the host collectors: **you do not run a script on the phone.**
Acquisition runs from an **examiner workstation** with the device tethered over USB, using open-source
tooling — mirroring how `Build-DetectionContent.ps1` runs on the analyst box, not the victim.

- **Engine:** `mobile/mobile-collect.sh` (Linux / macOS / WSL / Git-Bash examiner box).
- **Windows launcher:** `mobile/Mobile-Collect.ps1` (runs the engine under Git-Bash for native USB, else WSL).
- **Set up the box once:** `bash ./mobile/fetch-mobile-tools.sh`.

Standards: **NIST SP 800-101r1** (mobile acquisition tiers + isolation), **SWGDE** mobile best practices,
MVT methodology (acquire-then-analyze-offline), ATT&CK Mobile. Scenario-aware: pass `--scenario
<smish|spyware|mdm|bec|token|exfil|beacon|ransom|lost>` to reprioritise + auto-run the MVT analysis and
tag `collection_info.json` with ATT&CK-Mobile IDs (see [SCENARIOS.md](SCENARIOS.md) for the catalog +
scenario×device matrix). The host guided intake prompts for a mobile device and prints the matching command.

## Doctrine (enforced by the tool)

1. **Authorization first.** Mobile data (messages, Health, Keychain, location) is highly sensitive — the
   tool refuses to start interactively without confirmed authorization; pass `--authorizer/--legal/--scope`.
2. **Network isolation vs remote wipe.** Find My / MDM can wipe or lock the device remotely. Best practice
   is a **Faraday bag/box**. The tool captures **live network/process/notification state FIRST**, *then*
   isolates (`--isolate` toggles airplane mode on Android after volatile capture; `--faraday` asserts the
   device is already RF-isolated so no software toggle is made).
3. **Don't reboot.** A reboot can evict non-persistent (zero-click) spyware — exactly the evidence you want.
4. **Acquire, then analyze offline.** Modern MVT no longer touches a live device; the tool **acquires**
   (adb / `idevicebackup2`) and then **analyzes** the collected artifacts with MVT / iLEAPP / ALEAPP.
5. **Honest acquisition ceiling (open-source):**
   - **Logical** — the realistic ceiling. Android non-root: getprop/dumpsys/logcat/bugreport/packages/APKs/`/sdcard`. iOS: **encrypted** `idevicebackup2` backup.
   - **Filesystem** — Android needs pre-existing root (`--allow-root`, never roots the subject); iOS needs a checkm8/checkra1n jailbreak (not automated). ⚠️
   - **Physical** (full flash) — **not** achievable open-source on modern devices. Stated plainly, not faked.
6. **Integrity/chain of custody.** Every artifact SHA-256'd at write (`meta/hashes.csv`), full
   `MANIFEST-SHA256.txt`, frozen+hashed audit trail, examiner/case/UTC/tool-versions/device-id recorded.

## Android

Uses **adb** (Google platform-tools) for logical acquisition; **MVT** (`mvt-android`) + **ALEAPP** for
analysis; **androidqf** as an optional independent second acquirer. Requires **USB debugging ON** and the
on-device **RSA authorization** accepted (the tool self-heals `unauthorized`/`offline`).

```bash
# acquire only (interactive doctrine gate)
./mobile/mobile-collect.sh -c CASE1 -d /evidence --android
# acquire + analyze (MVT IOC check + ALEAPP), assert Faraday isolation, record custody
./mobile/mobile-collect.sh -c CASE1 -d /evidence --android --analyze --faraday \
    --authorizer "J. Doe" --legal "IR engagement 2026-07" --scope "phishing triage"
```
Key artifacts (order-of-volatility): `ps`, `dumpsys connectivity/netstats/notification`, full `logcat`,
then **`dumpsys accessibility / device_policy / appops / account`** (the stalkerware/banker tells),
settings, `bugreport.zip`, call log / SMS (best-effort — often restricted), `/sdcard`, and hashed APKs
(`mvt-android download-apks`). `adb backup` is attempted but is **effectively dead on Android 12+** —
don't rely on it. Root-only escalation (`--allow-root`) tars `/data/data` and reads `/proc/net` **only if
the device is already rooted**.

> Linux prereqs: `android-udev-rules` + your user in `plugdev` (else `no permissions`). Windows: the Google
> USB driver bound to the ADB interface. See `mobile/fetch-mobile-tools.sh`.

## iOS / iPhone

Uses **libimobiledevice** (`idevice*`) for a logical **encrypted backup**; **MVT** (`mvt-ios`) + **iLEAPP**
for analysis. Requires the device **unlocked with passcode** and **"Trust This Computer"** accepted.

```bash
./mobile/mobile-collect.sh -c CASE1 -d /evidence --ios --analyze --backup-pass CaseIR2026 \
    --authorizer "J. Doe" --legal "consent" --scope "spyware check"
```
Flow: `idevicepair pair` (preserve the pairing record) → `ideviceinfo` → volatile (`idevicesyslog`,
`idevicecrashreport`, `ideviceprovision list`, `ideviceinstaller`) → **`idevicebackup2 encryption on`**
→ **`idevicebackup2 backup --full`** (hours; ~= used capacity — budget ≥1.5× free space) → hash + manifest.

**Encrypted backups are essential** — they unlock Keychain, Health, Safari history, call history, and the
richer app data MVT needs. If a backup password is *already* set and unknown, you must obtain it (the tool
can't decrypt without it). The default backup password is the case id; it's recorded in `collection_info.json`.

Analysis: `mvt-ios decrypt-backup` → `download-iocs` → `check-backup` (flags Pegasus/Predator/stalkerware
via Amnesty's STIX2 feeds — `shutdown.log`, `DataUsage.sqlite`, Safari/WebKit, `tcc.db`, malicious
**configuration profiles**), plus iLEAPP for a broad artifact timeline.

## Compromise triage → detection handoff

MVT writes `reports/*/*detected.json` for every IOC match. The tool harvests those into
**`detection/mobile_iocs.csv`** (malicious domains/IPs, spyware process names like `bh`, file hashes,
package names) plus APK SHA-256s — a normalized indicator set the SOC feeds into DNS/proxy blocks,
EDR/YARA/Sigma, and MDM compliance rules, or back into MVT as a custom `--iocs` STIX2 bundle to sweep the
rest of the fleet. **Corporate angle:** on MDM/supervised devices, diff the installed **configuration
profiles / trusted CAs / VPN payloads** (`ideviceprovision` / `dumpsys device_policy`) against the expected
baseline — rogue profile/CA push is a primary mobile attack + insider vector.

## What this is / isn't
A **triage** capability: fast, open-source, logical acquisition + spyware/compromise checking that fits the
IR/SOC workflow. It is **not** a court-grade full-physical extraction suite (Cellebrite/GrayKey/XRY) — for
locked devices with no passcode, or full-flash imaging, escalate to those. Everything here assumes lawful
authority over the device.
