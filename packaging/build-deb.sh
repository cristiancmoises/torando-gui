#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Build torando-gui_<ver>_all.deb
set -eu
. "$(dirname -- "$0")/_common.sh"

require dpkg-deb "install the 'dpkg-dev' package" || exit 1

STAGE="$ROOT/build/deb"
stage_tree "$STAGE"

ARCH="all"
INSTALLED_KB=$(du -sk "$STAGE/usr" | cut -f1)

install -d "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKGNAME
Version: $VERSION
Architecture: $ARCH
Maintainer: Cristian Cezar Moisés <cristian@securityops.co>
Installed-Size: $INSTALLED_KB
Depends: python3 (>= 3.11), tor, iptables, e2fsprogs, polkit | policykit-1
Recommends: python3-gi, gir1.2-gtk-4.0, gir1.2-webkit-6.0
Suggests: python3-pil
Section: net
Priority: optional
Homepage: https://github.com/cristiancmoises/torando-gui
Description: Route a user's egress through Tor (transparent proxy + killswitch)
 Loopback web GUI that forces one local user's traffic through Tor's
 TransPort/DNSPort and drops everything else from that user. Automates the
 upstream torando iptables rules plus torrc and resolv.conf management.
EOF

# resolv.conf/torrc are touched at runtime, not shipped, so the only conffiles
# are the polkit rule and the desktop entry administrators may wish to edit.
cat > "$STAGE/DEBIAN/conffiles" <<EOF
/usr/share/polkit-1/rules.d/49-torando-gui.rules
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor || true
fi
echo "torando-gui installed. Enable with: systemctl enable --now torando-gui.service"
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop torando-gui.service 2>/dev/null || true
    systemctl disable torando-gui.service 2>/dev/null || true
fi
EOF
chmod 0755 "$STAGE/DEBIAN/prerm"

# Debian copyright location
install -d "$STAGE/usr/share/doc/$PKGNAME"
install -m 0644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/$PKGNAME/copyright"

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group -Zzstd -b "$STAGE" "$OUT"
echo "built: $OUT"
