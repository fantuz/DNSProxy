#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

version=${VERSION:-$(cat VERSION)}
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(~[a-zA-Z0-9.]+)?$'; then
    echo "Invalid RPM version" >&2
    exit 2
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' 0
mkdir "$work/SOURCES"
git archive --format=tar.gz --prefix="dnsp-modern-$version/" HEAD -- \
    dnsp-modern.c dnsp-platform.h modern.mk VERSION LICENSE tests/test_modern.py tests/test_curl_callbacks.c \
    tests/test_platform.c \
    packaging/README-packaging.md packaging/systemd/dnsp-modern.service \
    > "$work/SOURCES/dnsp-modern-$version.tar.gz"

rpmbuild -bb --define "_topdir $work" --define "dnsp_version $version" packaging/rpm/dnsp-modern.spec
set -- "$work"/RPMS/*/dnsp-modern-"$version"-*.rpm
test "$#" -eq 1
test -f "$1"
test "$(rpm -qp --qf '%{NAME}' "$1")" = dnsp-modern
test "$(rpm -qp --qf '%{VERSION}' "$1")" = "$version"
test "$(rpm -qp --qf '%{ARCH}' "$1")" = "$(rpm --eval '%{_arch}')"

mkdir -p dist
package="dist/${1##*/}"
cp "$1" "$package"
rpm -qpl "$package"
rpm -qpR "$package" | grep -Fx ca-certificates
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'package=%s\n' "$package" >> "$GITHUB_OUTPUT"
fi
printf 'Built %s\n' "$package"
