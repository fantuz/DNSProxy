#!/bin/sh
# Optional, architecture-independent companion; no GTK dependency on the daemon.
set -eu
cd "$(dirname "$0")/.."
version=${1:-$(cat VERSION)}
dpkg --validate-version "$version"
case "$version" in *[!0-9A-Za-z.+~:-]*|'') echo 'Invalid GUI Debian version' >&2; exit 2;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' 0
mkdir -p "$work/DEBIAN" "$work/usr/bin" "$work/usr/share/dnsp-modern-gui" \
    "$work/usr/share/applications" "$work/usr/share/icons/hicolor/scalable/apps" \
    "$work/usr/share/doc/dnsp-modern-gui/images" dist
install -m 0755 packaging/gui/dnsp-gui "$work/usr/bin/dnsp-gui"
install -m 0644 tools/linux-gui/*.py "$work/usr/share/dnsp-modern-gui/"
install -m 0644 packaging/gui/*.desktop "$work/usr/share/applications/"
install -m 0644 packaging/gui/dnsp-modern.svg "$work/usr/share/icons/hicolor/scalable/apps/"
install -m 0644 docs/LINUX-GUI.md "$work/usr/share/doc/dnsp-modern-gui/README.md"
install -m 0644 docs/images/linux-gui-poc-*.png "$work/usr/share/doc/dnsp-modern-gui/images/"
install -m 0644 LICENSE "$work/usr/share/doc/dnsp-modern-gui/copyright"
cat > "$work/DEBIAN/control" <<END
Package: dnsp-modern-gui
Version: $version
Section: net
Priority: optional
Architecture: all
Maintainer: DNSProxy contributors <noreply@github.com>
Depends: python3 (>= 3.9), python3-gi, python3-gi-cairo, gir1.2-gtk-4.0, hicolor-icon-theme
Recommends: dnsp-modern
Description: GTK 4 desktop monitor and user resolver launcher for DNSProxy
 View resolver instances, service state, traffic, latency and startup options.
 The monitor runs as an ordinary user and does not modify system DNS configuration.
END
dpkg-deb --build --root-owner-group "$work" "dist/dnsp-modern-gui_${version}_all.deb"
