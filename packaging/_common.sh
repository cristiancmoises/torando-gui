#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Shared helpers for the per-format build scripts. Source this file.
set -eu

VERSION="1.3.4"
PKGNAME="torando-gui"

# Resolve repo root regardless of where the script is invoked from.
PKG_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$PKG_DIR/.." && pwd)
DIST="$ROOT/dist"

# stage_tree DESTDIR — populate a DESTDIR with the full install layout.
stage_tree() {
    dest="$1"
    rm -rf "$dest"
    install -d "$dest/usr/lib/$PKGNAME"
    cp -r "$ROOT/backend/torando_gui" "$dest/usr/lib/$PKGNAME/torando_gui"
    # strip caches that may have been created during testing
    find "$dest/usr/lib/$PKGNAME" -name '__pycache__' -type d -prune -exec rm -rf {} +

    install -d "$dest/usr/bin"
    install -m 0755 "$PKG_DIR/bin/torando-gui" "$dest/usr/bin/torando-gui"
    install -m 0755 "$PKG_DIR/bin/torando-guid" "$dest/usr/bin/torando-guid"

    install -d "$dest/usr/lib/systemd/system"
    install -m 0644 "$PKG_DIR/systemd/torando-gui.service" \
        "$dest/usr/lib/systemd/system/torando-gui.service"

    install -d "$dest/usr/share/polkit-1/actions"
    install -m 0644 "$PKG_DIR/polkit/co.securityops.torando-gui.policy" \
        "$dest/usr/share/polkit-1/actions/co.securityops.torando-gui.policy"
    install -d "$dest/usr/share/polkit-1/rules.d"
    install -m 0644 "$PKG_DIR/polkit/49-torando-gui.rules" \
        "$dest/usr/share/polkit-1/rules.d/49-torando-gui.rules"

    install -d "$dest/usr/share/applications"
    install -m 0644 "$PKG_DIR/desktop/torando-gui.desktop" \
        "$dest/usr/share/applications/torando-gui.desktop"

    # icons at a few hicolor sizes
    for sz in 256 128 64; do
        install -d "$dest/usr/share/icons/hicolor/${sz}x${sz}/apps"
        python3 "$PKG_DIR/icons/make_icon.py" \
            "$dest/usr/share/icons/hicolor/${sz}x${sz}/apps/torando-gui.png" "$sz" >/dev/null
    done

    install -d "$dest/usr/share/doc/$PKGNAME"
    install -m 0644 "$ROOT/README.md" "$dest/usr/share/doc/$PKGNAME/README.md"
    install -m 0644 "$ROOT/THREAT_MODEL.md" "$dest/usr/share/doc/$PKGNAME/THREAT_MODEL.md"
}

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: '$1' not found — $2" >&2
        return 1
    }
}
