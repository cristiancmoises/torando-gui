#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Stage the Windows ALL-IN-ONE release: the pure-Python package plus a bundled
# embeddable CPython and the Tor Expert Bundle, so the user needs neither Python
# nor Tor pre-installed — just unzip and run install.ps1. Buildable on Linux
# (downloads the Windows binaries and assembles the tree; no Windows toolchain).
set -eu
. "$(dirname -- "$0")/_common.sh"

require zip "install the 'zip' package" || exit 1
require curl "install 'curl'" || exit 1

# Pinned components. Bump deliberately (Tor especially — security updates).
PYVER="${TORANDO_PYVER:-3.12.7}"
TORVER="${TORANDO_TORVER:-15.0.18}"
PY_URL="https://www.python.org/ftp/python/${PYVER}/python-${PYVER}-embed-amd64.zip"
TOR_URL="https://archive.torproject.org/tor-package-archive/torbrowser/${TORVER}/tor-expert-bundle-windows-x86_64-${TORVER}.tar.gz"

CACHE="$ROOT/build/windows-cache"
mkdir -p "$CACHE"
PY_ZIP="$CACHE/python-${PYVER}-embed-amd64.zip"
TOR_TGZ="$CACHE/tor-expert-bundle-${TORVER}.tar.gz"
[ -f "$PY_ZIP" ]  || { echo "fetching embeddable Python ${PYVER}…" >&2; curl -fsSL "$PY_URL"  -o "$PY_ZIP"; }
[ -f "$TOR_TGZ" ] || { echo "fetching Tor Expert Bundle ${TORVER}…" >&2; curl -fsSL "$TOR_URL" -o "$TOR_TGZ"; }

TOP="$ROOT/build/windows/${PKGNAME}-${VERSION}"
rm -rf "$TOP"
install -d "$TOP/lib" "$TOP/python" "$TOP/tor"

# 1) The application package.
cp -r "$ROOT/backend/torando_gui" "$TOP/lib/torando_gui"
find "$TOP/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +

# 2) Embeddable CPython. Extract, then point its isolated path file at ..\lib so
#    `python -m torando_gui` resolves the bundled package (an embeddable Python
#    with a ._pth uses ONLY those paths and ignores PYTHONPATH).
python3 -m zipfile -e "$PY_ZIP" "$TOP/python"
PTH=$(ls "$TOP/python"/python*._pth)
printf '..\\lib\n' >> "$PTH"

# 3) Tor: tor.exe + DLLs under tor\, geoip data under tor\data\.
TT=$(mktemp -d)
tar -C "$TT" -xzf "$TOR_TGZ"
cp -r "$TT/tor/." "$TOP/tor/"
install -d "$TOP/tor/data"
cp "$TT/data/geoip" "$TT/data/geoip6" "$TOP/tor/data/" 2>/dev/null || true
rm -rf "$TT"

# 4) Bootstrap scripts (explicit sys.path + logging), launchers, installer.
install -d "$TOP/boot"
install -m 0644 "$PKG_DIR/windows/boot/daemon.py" "$TOP/boot/daemon.py"
install -m 0644 "$PKG_DIR/windows/boot/gui.py"    "$TOP/boot/gui.py"
install -m 0644 "$PKG_DIR/windows/torando-guid.cmd" "$TOP/torando-guid.cmd"
install -m 0644 "$PKG_DIR/windows/torando-gui.cmd"  "$TOP/torando-gui.cmd"
install -m 0644 "$PKG_DIR/windows/install.ps1"      "$TOP/install.ps1"
install -m 0644 "$PKG_DIR/windows/uninstall.ps1"    "$TOP/uninstall.ps1"
install -m 0644 "$PKG_DIR/windows/torrc.template"   "$TOP/torrc.template"
install -m 0644 "$ROOT/README.md"       "$TOP/README.md"
install -m 0644 "$ROOT/THREAT_MODEL.md" "$TOP/THREAT_MODEL.md"
install -m 0644 "$ROOT/LICENSE"         "$TOP/LICENSE.txt"

# Record what was bundled (for provenance / updates).
cat > "$TOP/BUNDLED.txt" <<EOF
torando-gui $VERSION — Windows all-in-one
Bundled CPython:  $PYVER  ($PY_URL)
Bundled Tor:      $TORVER ($TOR_URL)

Tor ships security updates often; to refresh it, replace tor\\tor.exe and the
tor\\*.dll / tor\\data files from a newer Tor Expert Bundle, or reinstall a newer
torando-gui release.
EOF

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}-${VERSION}-windows.zip"
rm -f "$OUT"
( cd "$ROOT/build/windows" && zip -qry "$OUT" "${PKGNAME}-${VERSION}" )
echo "built: $OUT  (all-in-one: Python ${PYVER} + Tor ${TORVER})"
