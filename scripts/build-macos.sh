#!/usr/bin/env bash
# Native macOS build against Apple's SDK and system libcurl, without Homebrew.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Darwin ]] || { echo 'Run this script on macOS' >&2; exit 2; }
arch=$(uname -m)
case "$arch" in x86_64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 2 ;; esac
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
sdk=$(xcrun --sdk macosx --show-sdk-path)
compiler=$(xcrun --sdk macosx --find clang)
flags=(-isysroot "$sdk" -mmacosx-version-min=15.0 -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror)
bundle="dist/macos-$arch"
rm -rf -- "$bundle"
mkdir -p "$bundle"
"$compiler" "${flags[@]}" -DDNSP_VERSION="\"$version\"" -o "$bundle/dnsp-modern" dnsp-modern.c -L"$sdk/usr/lib" -lcurl
for probe in platform curl_callbacks; do
    "$compiler" "${flags[@]}" -o "dist/macos-$probe" "tests/test_$probe.c" -L"$sdk/usr/lib" -lcurl
done
# Reject accidental dependencies on the builder's Homebrew or workspace paths.
otool -L "$bundle/dnsp-modern"
otool -L "$bundle/dnsp-modern" | tail -n +2 | awk '{print $1}' | while read -r dependency; do
    case "$dependency" in /usr/lib/*|/System/Library/*) ;; *) echo "Non-system dependency: $dependency" >&2; exit 1 ;; esac
done
cp LICENSE "$bundle/"
cp docs/MACOS.md "$bundle/"
cp packaging/macos/Start-DNSProxy.command "$bundle/"
chmod 755 "$bundle/Start-DNSProxy.command"
{
    printf 'DNSProxy %s\nSource commit: %s\nArchitecture: %s\nMinimum macOS: 15.0\n' "$version" "$(git rev-parse HEAD)" "$arch"
    "$bundle/dnsp-modern" --version
    sw_vers
    "$compiler" --version
    otool -L "$bundle/dnsp-modern"
} > "$bundle/BUILD-INFO.txt"
(cd "$bundle" && shasum -a 256 dnsp-modern Start-DNSProxy.command LICENSE MACOS.md BUILD-INFO.txt > SHA256SUMS)
archive="dist/dnsp-modern-$version-macos-$arch.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$archive" -C "$bundle" .
(cd dist && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
