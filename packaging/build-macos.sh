#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Stage the macOS release: the Python package, CLI shims, a "Torando Control.app"
# bundle (unsigned; shell-script executable), the LaunchDaemon plist and the
# install scripts, zipped into dist/. Buildable on Linux — the .app is just a
# directory tree; only the optional .icns needs png2icns.
set -eu
. "$(dirname -- "$0")/_common.sh"

require zip "install the 'zip' package" || exit 1

TOP="$ROOT/build/macos/${PKGNAME}-${VERSION}"
rm -rf "$TOP"
install -d "$TOP/lib" "$TOP/bin"
cp -r "$ROOT/backend/torando_gui" "$TOP/lib/torando_gui"
find "$TOP/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +

# CLI shims (installed to /usr/local/bin), lib under /usr/local/lib/torando-gui.
for tool in torando-gui torando-guid; do
    case "$tool" in
        torando-gui)  mod="torando_gui.launcher" ;;
        torando-guid) mod="torando_gui" ;;
    esac
    cat > "$TOP/bin/$tool" <<EOF
#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
export PYTHONPATH="/usr/local/lib/torando-gui\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\$(command -v python3 || echo /usr/bin/python3)" -m $mod "\$@"
EOF
    chmod 0755 "$TOP/bin/$tool"
done

# The .app bundle.
APP="$TOP/Torando Control.app"
install -d "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m 0644 "$PKG_DIR/macos/Info.plist" "$APP/Contents/Info.plist"
install -m 0755 "$PKG_DIR/macos/app-launcher.sh" "$APP/Contents/MacOS/torando-gui"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# Optional icon: render PNGs, compose an .icns if png2icns is present.
if command -v png2icns >/dev/null 2>&1; then
    tmpd=$(mktemp -d)
    for sz in 16 32 128 256 512; do
        python3 "$PKG_DIR/icons/make_icon.py" "$tmpd/icon_${sz}.png" "$sz" >/dev/null 2>&1 || true
    done
    # shellcheck disable=SC2046
    png2icns "$APP/Contents/Resources/torando-gui.icns" $(ls "$tmpd"/icon_*.png 2>/dev/null) \
        >/dev/null 2>&1 || echo "note: png2icns failed; app ships without a custom icon"
    rm -rf "$tmpd"
else
    echo "note: png2icns not found; app ships without a custom icon"
fi

install -m 0644 "$PKG_DIR/macos/co.securityops.torando-gui.plist" \
    "$TOP/co.securityops.torando-gui.plist"
install -m 0755 "$PKG_DIR/macos/install.sh" "$TOP/install.sh"
install -m 0755 "$PKG_DIR/macos/uninstall.sh" "$TOP/uninstall.sh"
install -m 0644 "$ROOT/README.md" "$TOP/README.md"
install -m 0644 "$ROOT/THREAT_MODEL.md" "$TOP/THREAT_MODEL.md"
install -m 0644 "$ROOT/LICENSE" "$TOP/LICENSE"

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}-${VERSION}-macos.zip"
rm -f "$OUT"
( cd "$ROOT/build/macos" && zip -qry "$OUT" "${PKGNAME}-${VERSION}" )
echo "built: $OUT"
