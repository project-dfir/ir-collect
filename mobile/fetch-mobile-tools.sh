#!/usr/bin/env bash
# fetch-mobile-tools.sh - set up the EXAMINER workstation for mobile acquisition.
# Run ONCE on a TRUSTED analyst box (not the victim). Installs / points to the open-source stack:
#   adb (Android platform-tools), androidqf, MVT (mvt-android + mvt-ios), iLEAPP, ALEAPP,
#   and checks for libimobiledevice (iOS). Idempotent; prints what it did + what you must finish.
set -u
OS="$(uname -s 2>/dev/null || echo unknown)"
d="$(cd "$(dirname "$0")" && pwd)"   # script dir (mobile/) - tools land in mobile/tools
mkdir -p $d/tools/bin
echo "== examiner OS: $OS =="

dl() { if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi; }

# --- Android: platform-tools (adb) ---
if command -v adb >/dev/null 2>&1; then echo "[ok] adb present: $(adb version 2>/dev/null | head -1)"
else
  case "$OS" in
    Linux)  url=https://dl.google.com/android/repository/platform-tools-latest-linux.zip;;
    Darwin) url=https://dl.google.com/android/repository/platform-tools-latest-darwin.zip;;
    *)      url=https://dl.google.com/android/repository/platform-tools-latest-windows.zip;;
  esac
  echo "[*] fetching platform-tools: $url"
  if dl "$url" $d/tools/platform-tools.zip && command -v unzip >/dev/null 2>&1; then
    (cd $d/tools && unzip -oq platform-tools.zip)
    echo "[ok] adb -> $d/tools/platform-tools/  (add to PATH:  export PATH=\$d/tools/platform-tools:\$PATH )"
  else echo "[!] download/unzip failed - install adb via your package manager (android-tools-adb / brew install android-platform-tools)"; fi
fi

# --- iOS: libimobiledevice ---
if command -v idevice_id >/dev/null 2>&1; then echo "[ok] libimobiledevice present: $(idevice_id -v 2>/dev/null | head -1)"
else
  case "$OS" in
    Linux)  echo "[!] iOS: sudo apt install libimobiledevice-utils libimobiledevice6 ideviceinstaller usbmuxd";
            echo "        (if pairing/backup fails on a NEW iPhone, build libplist/libusbmuxd/libimobiledevice/usbmuxd from git master)";;
    Darwin) echo "[!] iOS: brew install libimobiledevice ideviceinstaller   (macOS runs Apple's own usbmuxd - do not start a second one)";;
    *)      echo "[!] iOS on Windows: install Apple Mobile Device Support (iTunes from apple.com, NOT the Microsoft Store),";
            echo "        then put libimobiledevice-win binaries on PATH. Verify with: idevice_id -l";;
  esac
fi

# --- MVT (mvt-android + mvt-ios) ---
if command -v mvt-ios >/dev/null 2>&1 || command -v mvt-android >/dev/null 2>&1; then echo "[ok] MVT present"
elif command -v pipx >/dev/null 2>&1; then pipx install mvt && echo "[ok] MVT installed via pipx"
else echo "[!] MVT: install pipx (python3 -m pip install --user pipx) then: pipx install mvt   (Python 3.10+)"; fi

# --- iLEAPP + ALEAPP (parsers) ---
if command -v git >/dev/null 2>&1; then
  [ -d $d/tools/iLEAPP ] || { git clone --depth 1 https://github.com/abrignoni/iLEAPP $d/tools/iLEAPP 2>/dev/null && echo "[ok] iLEAPP cloned - pip install -r $d/tools/iLEAPP/requirements.txt"; }
  [ -d $d/tools/ALEAPP ] || { git clone --depth 1 https://github.com/abrignoni/ALEAPP $d/tools/ALEAPP 2>/dev/null && echo "[ok] ALEAPP cloned - pip install -r $d/tools/ALEAPP/requirements.txt"; }
else echo "[!] git not found - clone iLEAPP + ALEAPP from github.com/abrignoni manually into $d/tools/"; fi

# --- androidqf (independent 2nd Android acquirer) ---
echo "[!] androidqf: download the release binary for your OS from"
echo "        https://github.com/mvt-project/androidqf/releases  -> $d/tools/bin/androidqf (chmod +x)"

echo
echo "Verify the box is ready:"
echo "  adb version ; idevice_id -v ; mvt-ios version ; python $d/tools/iLEAPP/ileapp.py -h"
echo "Linux Android: sudo apt install android-udev-rules ; sudo usermod -aG plugdev \$USER ; udevadm control --reload"
echo "Linux iOS:     systemctl status usbmuxd   (must be running)"
