#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Remove Torando Control from macOS. Run with sudo.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run with sudo" >&2; exit 1; fi

# Restore DNS/proxy first (best effort) before tearing the daemon down.
/usr/local/bin/torando-guid --restore-dns 2>/dev/null || true

launchctl unload /Library/LaunchDaemons/co.securityops.torando-gui.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/co.securityops.torando-gui.plist
rm -rf /usr/local/lib/torando-gui \
       /usr/local/bin/torando-guid /usr/local/bin/torando-gui \
       "/Applications/Torando Control.app"
echo "removed. Config under /etc/torando-gui left in place."
