#!/usr/bin/env bash
# Build livenx-si-findings-export_<version>_all.deb into ./dist.
# Requires dpkg-deb (Debian/Ubuntu: preinstalled; macOS: brew install dpkg).
set -euo pipefail

cd "$(dirname "$0")"
NAME=livenx-si-findings-export
VERSION=$(awk '/^Version:/ {print $2}' packaging/DEBIAN/control)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
export COPYFILE_DISABLE=1  # keep macOS ._ resource files out of the archive

ROOT="$STAGE/$NAME"
# Only /var, /etc and /data persist across a LiveNX reboot, so nothing is
# installed under /usr, /opt or /lib.
install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/var/lib/$NAME" "$ROOT/etc/$NAME" "$ROOT/etc/systemd/system"
install -m 0644 packaging/DEBIAN/control packaging/DEBIAN/conffiles "$ROOT/DEBIAN/"
install -m 0755 packaging/DEBIAN/postinst packaging/DEBIAN/prerm packaging/DEBIAN/postrm "$ROOT/DEBIAN/"
install -m 0755 si_findings_export.py "$ROOT/var/lib/$NAME/"
# 0600: the file holds the LiveNX API token; systemd reads it as root.
install -m 0600 packaging/si-findings-export.env "$ROOT/etc/$NAME/"
install -m 0644 packaging/$NAME.service "$ROOT/etc/systemd/system/"

mkdir -p dist
# gzip keeps the package readable by every dpkg version LiveNX has shipped.
dpkg-deb --root-owner-group -Zgzip --build "$ROOT" "dist/${NAME}_${VERSION}_all.deb"
