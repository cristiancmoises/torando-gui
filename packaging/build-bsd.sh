#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Stage a FreeBSD or OpenBSD release tarball: the Python package, CLI shims, the
# rc.d service and an install script. Usage:
#   sh packaging/build-bsd.sh freebsd
#   sh packaging/build-bsd.sh openbsd
set -eu
. "$(dirname -- "$0")/_common.sh"

OS="${1:-freebsd}"
case "$OS" in
    freebsd) RC_SRC="$PKG_DIR/freebsd/torando-gui.rc"; RC_DEST="/usr/local/etc/rc.d/torando-gui";
             RC_NAME="torando-gui"; ENABLE="sysrc torando_gui_enable=YES"; SVC="service torando-gui start" ;;
    openbsd) RC_SRC="$PKG_DIR/openbsd/torando-gui.rc"; RC_DEST="/etc/rc.d/torando_gui";
             RC_NAME="torando_gui"; ENABLE="rcctl enable torando_gui"; SVC="rcctl start torando_gui" ;;
    *) echo "usage: $0 freebsd|openbsd" >&2; exit 2 ;;
esac

require tar "install 'tar'" || exit 1

TOP="$ROOT/build/$OS/${PKGNAME}-${VERSION}"
rm -rf "$TOP"
install -d "$TOP/lib" "$TOP/bin" "$TOP/rc"
cp -r "$ROOT/backend/torando_gui" "$TOP/lib/torando_gui"
find "$TOP/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +

for tool in torando-gui torando-guid; do
    case "$tool" in
        torando-gui)  mod="torando_gui.launcher" ;;
        torando-guid) mod="torando_gui" ;;
    esac
    cat > "$TOP/bin/$tool" <<EOF
#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
export PYTHONPATH="/usr/local/lib/torando-gui\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\$(command -v python3 || echo /usr/local/bin/python3)" -m $mod "\$@"
EOF
    chmod 0755 "$TOP/bin/$tool"
done

install -m 0755 "$RC_SRC" "$TOP/rc/$RC_NAME"

cat > "$TOP/install.sh" <<EOF
#!/bin/sh
# Install Torando Control on $OS. Run as root.
set -eu
if [ "\$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
HERE=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
install -d /usr/local/lib/torando-gui
cp -R "\$HERE/lib/torando_gui" /usr/local/lib/torando-gui/torando_gui
install -m 0755 "\$HERE/bin/torando-guid" /usr/local/bin/torando-guid
install -m 0755 "\$HERE/bin/torando-gui" /usr/local/bin/torando-gui
install -m 0755 "\$HERE/rc/$RC_NAME" "$RC_DEST"
install -d /usr/local/etc/torando-gui /etc/torando-gui 2>/dev/null || true
CFG=$( [ "$OS" = freebsd ] && echo /usr/local/etc/torando-gui/config.json || echo /etc/torando-gui/config.json )
if [ ! -f "\$CFG" ]; then
    cat > "\$CFG" <<'JSON'
{
  "host": "127.0.0.1",
  "port": 8088,
  "socks_port": 9050,
  "dns_port": 53,
  "manage_torrc": true,
  "lock_resolv": true,
  "ipv6_killswitch": true,
  "tor_user": "_tor"
}
JSON
    echo "seeded \$CFG"
fi
echo ""
echo "Installed. Enable and start:"
echo "  $ENABLE"
echo "  $SVC"
echo "Ensure Tor is installed and /dev/pf is readable by _tor if you use pf redirect."
EOF
chmod 0755 "$TOP/install.sh"

cat > "$TOP/uninstall.sh" <<EOF
#!/bin/sh
set -eu
if [ "\$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
/usr/local/bin/torando-guid --restore-dns 2>/dev/null || true
rm -rf /usr/local/lib/torando-gui /usr/local/bin/torando-guid /usr/local/bin/torando-gui "$RC_DEST"
echo "removed."
EOF
chmod 0755 "$TOP/uninstall.sh"

install -m 0644 "$ROOT/README.md" "$TOP/README.md"
install -m 0644 "$ROOT/THREAT_MODEL.md" "$TOP/THREAT_MODEL.md"
install -m 0644 "$ROOT/LICENSE" "$TOP/LICENSE"

mkdir -p "$DIST"
OUT="$DIST/${PKGNAME}-${VERSION}-${OS}.tar.gz"
tar -C "$ROOT/build/$OS" --numeric-owner --owner=0 --group=0 -czf "$OUT" "${PKGNAME}-${VERSION}"
echo "built: $OUT"
