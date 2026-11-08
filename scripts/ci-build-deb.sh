#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

distro=$1
base=$(cat VERSION)
if ! printf '%s\n' "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "VERSION must contain MAJOR.MINOR.PATCH" >&2
    exit 1
fi
case "${GITHUB_REF:-}" in
    refs/tags/*)
        if [ "${GITHUB_REF_NAME:-}" != "v$base-modern" ]; then
            echo "Release tag must match VERSION (v$base-modern)" >&2
            exit 1
        fi
        version=$base
        ;;
    *) version="$base~pre${GITHUB_RUN_NUMBER:?}.ci" ;;
esac
version="$version+$distro"
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
