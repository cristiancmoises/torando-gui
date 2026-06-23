#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Build torando-gui-<ver>-1.noarch.rpm
set -eu
. "$(dirname -- "$0")/_common.sh"

require rpmbuild "install the 'rpm-build' (Fedora) or 'rpm' (Debian) package" || exit 1

TOPDIR="$ROOT/build/rpm"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR/BUILD" "$TOPDIR/RPMS" "$TOPDIR/SOURCES" "$TOPDIR/SPECS" "$TOPDIR/SRPMS"

# Stage the install tree the spec will copy from.
stage_tree "$TOPDIR/SOURCES/stage"
cp "$ROOT/LICENSE" "$TOPDIR/SOURCES/LICENSE"
cp "$PKG_DIR/torando-gui.spec" "$TOPDIR/SPECS/torando-gui.spec"

rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/torando-gui.spec"

mkdir -p "$DIST"
found=$(find "$TOPDIR/RPMS" -name '*.rpm' | head -n1)
cp "$found" "$DIST/"
echo "built: $DIST/$(basename "$found")"
