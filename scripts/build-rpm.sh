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
    dnsp-modern.c dnsp-platform.h dnsp-service.h dnsp-policy.h modern.mk VERSION LICENSE tests/test_modern.py tests/test_curl_callbacks.c \
    tests/test_platform.c tests/test_ipv6.py tests/test_linux_dns.py tests/test_policy.py tests/test_policy_updater.py \
    tests/host_capabilities.py tests/test_host_capabilities.py tests/test_hedging.py \
    scripts/update-blocklist.py docs/BLOCKLISTS.md \
    packaging/README-packaging.md packaging/systemd/ packaging/linux/dnsp-configure-dns \
    tools/desktop-gui/ packaging/gui/ docs/LINUX-GUI.md docs/images/linux-gui-poc-*.png \
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
set -- "$work"/RPMS/noarch/dnsp-modern-gui-"$version"-*.rpm
test "$#" -eq 1 && test -s "$1"
gui_package="dist/${1##*/}"
cp "$1" "$gui_package"
test "$(rpm -qp --qf '%{ARCH}' "$gui_package")" = noarch
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf 'package=%s\n' "$package" >> "$GITHUB_OUTPUT"
    printf 'gui_package=%s\n' "$gui_package" >> "$GITHUB_OUTPUT"
    if [ "$(rpm --eval '%{_arch}')" = x86_64 ]; then
        printf 'gui_upload=%s\n' "$gui_package" >> "$GITHUB_OUTPUT"
    fi
fi
printf 'Built %s\n' "$package"
