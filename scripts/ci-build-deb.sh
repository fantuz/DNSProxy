#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

distro=$1
version="${BUILD_VERSION:?}+$distro"
pkg="dist/dnsp-modern_${version}_$(dpkg --print-architecture).deb"

VERSION="$version" sh scripts/build-deb.sh
test -s "$pkg"
dpkg-deb --info "$pkg"
dpkg-deb --contents "$pkg"
test "$(dpkg-deb --field "$pkg" Package)" = dnsp-modern
test "$(dpkg-deb --field "$pkg" Version)" = "$version"
dpkg-deb --field "$pkg" Depends | grep -Eq '(^|, )ca-certificates(,|$)'

inspection=$(mktemp -d)
trap 'rm -rf "$inspection"' EXIT
dpkg-deb -R "$pkg" "$inspection"
tail -n +3 "$inspection/usr/share/doc/dnsp-modern/copyright" | cmp LICENSE -
for script in postinst prerm postrm; do
    test -x "$inspection/DEBIAN/$script"
done
printf 'package=%s\n' "$pkg" >> "${GITHUB_OUTPUT:?}"
gui="dist/dnsp-modern-gui_${version}_all.deb"
test "$(dpkg-deb --field "$gui" Package)" = dnsp-modern-gui
test "$(dpkg-deb --field "$gui" Version)" = "$version"
test "$(dpkg-deb --field "$gui" Architecture)" = all
dpkg-deb -x "$gui" "$inspection/gui"
test -x "$inspection/gui/usr/bin/dnsp-gui"
test -f "$inspection/gui/usr/share/applications/org.dnsproxy.LinuxMonitor.desktop"
printf 'gui_package=%s\n' "$gui" >> "$GITHUB_OUTPUT"
# The same pure-Python package is tested on both CPUs and published once.
if [ "$(dpkg --print-architecture)" = amd64 ]; then
    printf 'gui_upload=%s\n' "$gui" >> "$GITHUB_OUTPUT"
fi
