#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Build Torando_Control-x86_64.AppImage
set -eu
. "$(dirname -- "$0")/_common.sh"

APPDIR="$ROOT/build/AppDir"
stage_tree "$APPDIR"   # puts the package under $APPDIR/usr/lib/torando-gui

# AppImage top-level requirements
install -m 0755 "$PKG_DIR/AppRun" "$APPDIR/AppRun"
install -m 0644 "$PKG_DIR/desktop/torando-gui.desktop" "$APPDIR/torando-gui.desktop"
python3 "$PKG_DIR/icons/make_icon.py" "$APPDIR/torando-gui.png" 256 >/dev/null
# top-level icon also expected as .DirIcon
cp "$APPDIR/torando-gui.png" "$APPDIR/.DirIcon"

# Locate or fetch appimagetool.
TOOL="${APPIMAGETOOL:-}"
if [ -z "$TOOL" ]; then
    if command -v appimagetool >/dev/null 2>&1; then
        TOOL=$(command -v appimagetool)
    else
        CACHE="$ROOT/build/appimagetool-x86_64.AppImage"
        if [ ! -x "$CACHE" ]; then
            echo "fetching appimagetool…" >&2
            url="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
            curl -fsSL "$url" -o "$CACHE" || {
                echo "error: could not download appimagetool; set APPIMAGETOOL=/path" >&2
                exit 1
            }
            chmod +x "$CACHE"
        fi
        TOOL="$CACHE"
    fi
fi

mkdir -p "$DIST"
OUT="$DIST/Torando_Control-x86_64.AppImage"

# Many CI/container hosts lack FUSE; --appimage-extract-and-run avoids it, and
# ARCH must be exported for appimagetool's runtime selection.
export ARCH="x86_64"
if ! "$TOOL" --appimage-extract-and-run "$APPDIR" "$OUT" 2>/dev/null; then
    "$TOOL" "$APPDIR" "$OUT"
fi
echo "built: $OUT"
