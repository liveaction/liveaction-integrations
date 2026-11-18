#!/usr/bin/env bash
# Build livenx-si-findings-export-<version>-1.noarch.rpm into ./dist for RHEL 8.
# Uses a local rpmbuild when present, otherwise an AlmaLinux 8 container
# (needs docker).
set -euo pipefail

cd "$(dirname "$0")"
NAME=livenx-si-findings-export
VERSION=$(awk '/^Version:/ {print $2}' packaging/DEBIAN/control)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/SOURCES" dist
cp si_findings_export.py packaging/si-findings-export.env packaging/$NAME.service "$STAGE/SOURCES/"
cp packaging/$NAME.spec "$STAGE/"

if command -v rpmbuild >/dev/null 2>&1; then
    rpmbuild -bb --define "_topdir $STAGE" --define "_sourcedir $STAGE/SOURCES" \
        --define "pkg_version $VERSION" --define "dist %{nil}" "$STAGE/$NAME.spec"
    cp "$STAGE"/RPMS/noarch/*.rpm dist/
else
    docker run --rm --platform linux/amd64 -v "$STAGE":/build almalinux:8 bash -c '
        dnf -q -y install rpm-build >/dev/null &&
        rpmbuild -bb --define "_topdir /build" --define "_sourcedir /build/SOURCES" \
            --define "pkg_version '"$VERSION"'" --define "dist %{nil}" /build/'"$NAME"'.spec'
    cp "$STAGE"/RPMS/noarch/*.rpm dist/
fi
ls -1 dist/*.rpm
