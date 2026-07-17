#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Install Torando Control on macOS from this staged directory. Run with sudo.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo" >&2; exit 1; fi
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# 1) Python package + CLI shims.
install -d /usr/local/lib/torando-gui
cp -R "$HERE/lib/torando_gui" /usr/local/lib/torando-gui/torando_gui
install -m 0755 "$HERE/bin/torando-guid" /usr/local/bin/torando-guid
install -m 0755 "$HERE/bin/torando-gui" /usr/local/bin/torando-gui

# 2) The .app bundle into /Applications.
rm -rf "/Applications/Torando Control.app"
cp -R "$HERE/Torando Control.app" "/Applications/Torando Control.app"

# 3) Seed config: on macOS Tor comes from Homebrew and manages its own torrc,
#    so leave manage_torrc on but point at the brew torrc; pin DNS via
#    networksetup (handled by the daemon).
CFG=/etc/torando-gui/config.json
install -d /etc/torando-gui
if [ ! -f "$CFG" ]; then
    cat > "$CFG" <<'JSON'
{
  "host": "127.0.0.1",
  "port": 8088,
  "socks_port": 9050,
  "dns_port": 53,
  "manage_torrc": false,
  "lock_resolv": true,
  "ipv6_killswitch": true
}
JSON
    echo "seeded $CFG"
fi

# 4) LaunchDaemon for the root daemon.
install -m 0644 "$HERE/co.securityops.torando-gui.plist" \
    /Library/LaunchDaemons/co.securityops.torando-gui.plist
launchctl unload /Library/LaunchDaemons/co.securityops.torando-gui.plist 2>/dev/null || true
launchctl load /Library/LaunchDaemons/co.securityops.torando-gui.plist

echo ""
echo "Installed. Make sure Tor is running (brew install tor && brew services start tor)."
echo "Open 'Torando Control' from /Applications."
echo "If Gatekeeper blocks it (unsigned), right-click > Open, or:"
echo "  xattr -dr com.apple.quarantine '/Applications/Torando Control.app'"
