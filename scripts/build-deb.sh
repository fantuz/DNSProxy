#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
VERSION=${VERSION:-0.2.3}
case "$VERSION" in *[!0-9A-Za-z.+~:-]*|'') echo 'Invalid Debian version' >&2; exit 2;; esac
ARCH=$(dpkg --print-architecture)
mkdir -p dist
make -B -f modern.mk dnsp-modern
make -f modern.mk modern-check

# Keep dpkg-shlibdeps scratch files isolated; never write to the real debian/
# directory in a developer's checkout.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
STAGE="$WORK/stage"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin" "$STAGE/lib/systemd/system" \
         "$STAGE/usr/share/doc/dnsp-modern" "$WORK/deps/debian"
install -m 0755 dnsp-modern "$STAGE/usr/bin/dnsp-modern"
install -m 0644 packaging/systemd/dnsp-modern.service "$STAGE/lib/systemd/system/dnsp-modern.service"
install -m 0644 packaging/README-packaging.md "$STAGE/usr/share/doc/dnsp-modern/README.packaging"
cat > "$WORK/deps/debian/control" <<END
Source: dnsp-modern
Section: net
Priority: optional
Maintainer: DNSProxy contributors <noreply@github.com>
Standards-Version: 4.6.2

Package: dnsp-modern
Architecture: any
Description: DNS-over-HTTPS forwarding resolver
END
DEPS=$(cd "$WORK/deps" && dpkg-shlibdeps -O -l"/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" -e"$STAGE/usr/bin/dnsp-modern" | sed -n 's/^shlibs:Depends=//p')
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
 Event-driven DoH forwarder with EDNS validation and Prometheus metrics.
END
OUT="dist/dnsp-modern_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "Built $OUT"
