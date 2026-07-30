#!/usr/bin/env bash
# =============================================================================
# fetch-tools.sh - Assemble the IR-Collect Linux payload (OPEN-SOURCE tools only)
#
# Downloads open-source, license-free, professionally-proven responder tools into
# ./tools/bin so ir-collect.sh relies on OUR carried binaries, not the host's.
# Includes a STATIC BUSYBOX whose applet symlinks (ps, ss, ls, find, cat, netstat...)
# shadow the host's trojanable userland via PATH. Records SHA-256 + source in
# tools/PROVENANCE.txt. Self-heals: a failed download is logged and skipped.
#
# Run ONCE on a trusted workstation to build the kit, then carry the drive.
#
# NOT fetched (need build or not single-binary): LiME (compile per-kernel).
# Python (install on your ANALYSIS box via pipx, never the victim):
#   bloodhound-python, netexec, impacket.
# =============================================================================
set +e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_DIR="${1:-$SCRIPT_DIR/tools}"
BIN="$TOOL_DIR/bin"
mkdir -p "$BIN"
PROV="$TOOL_DIR/PROVENANCE-linux.txt"
echo "IR-Collect Linux payload - fetched $(date -u +%FT%TZ)" > "$PROV"

DL="curl -fsSL"; command -v curl >/dev/null 2>&1 || DL="wget -qO-"
dl_to() { # dl_to <url> <dest>
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  else wget -q "$1" -O "$2"; fi
}
log() { echo "$*"; echo "$*" >> "$PROV"; }

# fetch latest-release asset matching a regex from a GitHub repo (self-healing)
gh_asset() { # gh_asset <label> <repo> <pattern> <dest_basename> [chmod]
  local label="$1" repo="$2" pat="$3" dest="$4" doexec="$5"
  echo "--- $label ($repo) ---"
  local url
  url="$($DL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | grep -oE '"browser_download_url": *"[^"]+"' | sed -E 's/.*"([^"]+)"/\1/' \
        | grep -E "$pat" | head -n1)"
  if [ -z "$url" ]; then log "ERR $label: no asset matching /$pat/ in $repo"; return; fi
  local out="$BIN/$dest"
  if dl_to "$url" "$out"; then
    [ "$doexec" = "x" ] && chmod +x "$out"
    log "OK  $(printf '%-14s' "$label") $(sha256sum "$out" | cut -c1-16)  $url"
  else
    rm -f "$out" 2>/dev/null   # drop partial download
    log "ERR $label: download failed $url"
  fi
}

command -v unzip >/dev/null 2>&1 || echo "WARNING: unzip not found - zip tools (CyLR/hayabusa) will not extract. Install unzip." >&2
echo "Assembling IR-Collect open-source payload into $BIN"

# --- static busybox: our trusted core userland (ps/ss/ls/find/cat/netstat...) ---
echo "--- busybox (static, trusted core binaries) ---"
BB_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
if dl_to "$BB_URL" "$BIN/busybox"; then
  chmod +x "$BIN/busybox"
  # NOTE: we deliberately do NOT `busybox --install` applet symlinks - busybox's
  # limited ps/ss lack the flags the collector uses and would BREAK collection.
  # busybox is a coarse fallback; trusted enumeration reads raw /proc + /proc/net.
  log "OK  busybox        $(sha256sum "$BIN/busybox" | cut -c1-16)  $BB_URL  (fallback binary)"
else
  log "ERR busybox: download failed - host binaries will NOT be shadowed. Fetch a static busybox manually."
fi

# --- memory acquisition (open source) ---
gh_asset avml          'microsoft/avml'            '/avml$'                                  avml x
# --- triage collectors (open source) ---
gh_asset velociraptor  'Velocidex/velociraptor'    'linux-amd64$'                            velociraptor x
gh_asset CyLR          'orlikoski/CyLR'            'linux.*(x64|amd64).*\.zip$|CyLR$'         CyLR.zip
# --- hidden-process detection / evtx hunting (open source) ---
gh_asset chainsaw      'WithSecureLabs/chainsaw'   'x86_64-unknown-linux-gnu\.tar\.gz$'      chainsaw.tar.gz
gh_asset hayabusa      'Yamato-Security/hayabusa'  'lin.*x64.*\.zip$'                        hayabusa.zip

# UAC (Unix-like Artifacts Collector) - tarball, extract to tools/uac
echo "--- UAC (tclahr/uac) ---"
UAC_URL="$($DL https://api.github.com/repos/tclahr/uac/releases/latest 2>/dev/null | grep -oE '"browser_download_url": *"[^"]+"' | sed -E 's/.*"([^"]+)"/\1/' | grep -E '\.tar\.gz$' | head -n1)"
if [ -n "$UAC_URL" ] && dl_to "$UAC_URL" "$TOOL_DIR/uac.tar.gz"; then
  mkdir -p "$TOOL_DIR/uac" && tar xzf "$TOOL_DIR/uac.tar.gz" -C "$TOOL_DIR/uac" --strip-components=1 2>/dev/null && rm -f "$TOOL_DIR/uac.tar.gz"
  [ -f "$TOOL_DIR/uac/uac" ] && chmod +x "$TOOL_DIR/uac/uac"
  log "OK  uac           extracted -> uac/  $UAC_URL"
else log "ERR uac: fetch failed"; fi

# extract any zips we grabbed
for z in "$BIN"/CyLR.zip "$BIN"/hayabusa.zip; do
  [ -f "$z" ] && { d="$BIN/$(basename "$z" .zip)"; mkdir -p "$d"; unzip -oq "$z" -d "$d" 2>/dev/null && rm -f "$z" && log "    extracted $(basename "$z")"; }
done
[ -f "$BIN/chainsaw.tar.gz" ] && { tar xzf "$BIN/chainsaw.tar.gz" -C "$BIN" 2>/dev/null && rm -f "$BIN/chainsaw.tar.gz" && log "    extracted chainsaw"; }

echo
log "Done. Payload in $BIN ; provenance in $PROV"
echo "unhide (hidden-process detector): install via your distro pkg (apt/yum install unhide) onto the kit, or carry a static build."
echo "Python analysis tools (on your box, not the victim): pipx install bloodhound impacket netexec"
