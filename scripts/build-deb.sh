#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
VERSION=${VERSION:-0.1.0}
case "$VERSION" in *[!0-9A-Za-z.+~:-]*|'') echo 'Invalid Debian version' >&2; exit 2;; esac
ARCH=$(dpkg --print-architecture)
mkdir -p dist
make -f modern.mk dnsp-modern
make -f modern.mk modern-check
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"; rm -f debian/control; rmdir debian 2>/dev/null || true' EXIT HUP INT TERM
if [ -e debian/control ]; then echo "Existing debian/control detected; refusing to overwrite" >&2; exit 1; fi
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/lib/systemd/system" "$STAGE/usr/share/doc/dnsp-modern"
install -m 0755 dnsp-modern "$STAGE/usr/bin/dnsp-modern"
install -m 0644 packaging/systemd/dnsp-modern.service "$STAGE/lib/systemd/system/dnsp-modern.service"
install -m 0644 packaging/README-packaging.md "$STAGE/usr/share/doc/dnsp-modern/README.packaging"
# Generate runtime dependencies from the actual binary, rather than guessing
# between libcurl4 and libcurl4t64 across Debian/Ubuntu releases.
mkdir -p debian
printf 'Source: dnsp-modern\nSection: net\nPriority: optional\nMaintainer: DNSProxy contributors <noreply@github.com>\nStandards-Version: 4.6.2\n\nPackage: dnsp-modern\nArchitecture: any\nDescription: DNS-over-HTTPS forwarding resolver\n' > debian/control
DEPS=$(dpkg-shlibdeps -O -l"/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" -e"$STAGE/usr/bin/dnsp-modern" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
rm -f debian/control
[ -n "$DEPS" ] || { echo 'Could not determine runtime dependencies' >&2; exit 1; }
cat > "$STAGE/DEBIAN/control" <<END
Package: dnsp-modern
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: DNSProxy contributors <noreply@github.com>
Depends: $DEPS
Description: Experimental DNS-over-HTTPS forwarding resolver
 Opt-in DNS proxy with libcurl multi and bounded concurrency.
END
OUT="dist/dnsp-modern_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "Built $OUT"
