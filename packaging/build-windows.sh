#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Stage the Windows release: the pure-Python package + .cmd launchers +
# install/uninstall PowerShell scripts, zipped into dist/. Buildable on Linux
# (no Windows toolchain needed; the payload is stdlib Python).
set -eu
. "$(dirname -- "$0")/_common.sh"

require zip "install the 'zip' package" || exit 1

TOP="$ROOT/build/windows/${PKGNAME}-${VERSION}"
rm -rf "$TOP"
install -d "$TOP/lib"
cp -r "$ROOT/backend/torando_gui" "$TOP/lib/torando_gui"
find "$TOP/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +

install -m 0755 "$PKG_DIR/windows/torando-guid.cmd" "$TOP/torando-guid.cmd"
install -m 0755 "$PKG_DIR/windows/torando-gui.cmd" "$TOP/torando-gui.cmd"
install -m 0644 "$PKG_DIR/windows/install.ps1" "$TOP/install.ps1"
install -m 0644 "$PKG_DIR/windows/uninstall.ps1" "$TOP/uninstall.ps1"
install -m 0644 "$ROOT/README.md" "$TOP/README.md"
install -m 0644 "$ROOT/THREAT_MODEL.md" "$TOP/THREAT_MODEL.md"
install -m 0644 "$ROOT/LICENSE" "$TOP/LICENSE.txt"

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}-${VERSION}-windows.zip"
rm -f "$OUT"
( cd "$ROOT/build/windows" && zip -qr "$OUT" "${PKGNAME}-${VERSION}" )
echo "built: $OUT"
