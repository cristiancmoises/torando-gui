#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Build torando-gui-<ver>.tar.zst (DESTDIR-style tree + install.sh)
set -eu
. "$(dirname -- "$0")/_common.sh"

require zstd "install the 'zstd' package" || exit 1
require tar "install 'tar'" || exit 1

TOP="$ROOT/build/tarball/${PKGNAME}-${VERSION}"
stage_tree "$TOP/root"

install -d "$TOP/root/usr/share/licenses/$PKGNAME"
install -m 0644 "$ROOT/LICENSE" "$TOP/root/usr/share/licenses/$PKGNAME/LICENSE"

cat > "$TOP/install.sh" <<'EOF'
#!/bin/sh
# Install Torando Control from this portable tarball. Run as root.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp -a "$HERE/root/." /
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
echo "installed. enable with: systemctl enable --now torando-gui.service"
echo "then run: torando-gui"
EOF
chmod 0755 "$TOP/install.sh"

cat > "$TOP/uninstall.sh" <<'EOF'
#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
systemctl disable --now torando-gui.service 2>/dev/null || true
rm -rf /usr/lib/torando-gui \
       /usr/bin/torando-gui /usr/bin/torando-guid \
       /usr/lib/systemd/system/torando-gui.service \
       /usr/share/polkit-1/actions/co.securityops.torando-gui.policy \
       /usr/share/polkit-1/rules.d/49-torando-gui.rules \
       /usr/share/applications/torando-gui.desktop \
       /usr/share/icons/hicolor/*/apps/torando-gui.png \
       /usr/share/doc/torando-gui /usr/share/licenses/torando-gui
systemctl daemon-reload 2>/dev/null || true
echo "removed."
EOF
chmod 0755 "$TOP/uninstall.sh"

install -m 0644 "$ROOT/README.md" "$TOP/README.md"
install -m 0644 "$ROOT/THREAT_MODEL.md" "$TOP/THREAT_MODEL.md"
install -m 0644 "$ROOT/LICENSE" "$TOP/LICENSE"

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}-${VERSION}.tar.zst"
tar -C "$ROOT/build/tarball" --numeric-owner --owner=0 --group=0 \
    --use-compress-program "zstd -19" -cf "$OUT" "${PKGNAME}-${VERSION}"
echo "built: $OUT"
