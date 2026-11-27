#!/usr/bin/env bash
# Native macOS build against Apple's SDK and system libcurl, without Homebrew.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Darwin ]] || { echo 'Run this script on macOS' >&2; exit 2; }
[[ $(sysctl -in sysctl.proc_translated 2>/dev/null || true) != 1 ]] || {
    echo 'Run the native Apple Silicon shell, not a Rosetta-translated shell' >&2; exit 2;
}
arch=$(uname -m)
case "$arch" in x86_64|arm64) ;; *) echo "Unsupported architecture: $arch" >&2; exit 2 ;; esac
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
sdk=$(xcrun --sdk macosx --show-sdk-path)
compiler=$(xcrun --sdk macosx --find clang)
profile=release
workers=2
case "${1:-}" in
    '') ;;
    --benchmark-baseline) profile=baseline; workers=1 ;;
    *) echo 'Usage: build-macos.sh [--benchmark-baseline]' >&2; exit 2 ;;
esac
# Keep a portable ISA baseline. In particular, do not optimize for the builder's
# CPU: an ARM runner can be newer than the oldest supported Apple Silicon Mac.
release_flags=(-arch "$arch" -isysroot "$sdk" -mmacosx-version-min=15.0 -O2)
if [[ $profile == release ]]; then release_flags+=(-Wl,-dead_strip); fi
flags=("${release_flags[@]}" -std=c11 -Wall -Wextra -Wpedantic -Werror)
bundle="dist/macos-$arch"
rm -rf -- "$bundle"
app="$bundle/DNSProxy.app"
contents="$app/Contents"
mkdir -p "$contents/MacOS" "$contents/Helpers" "$contents/Resources"
build_pids=()
wait_builds() {
    local failed=0 pid
    for pid in ${build_pids[@]+"${build_pids[@]}"}; do wait "$pid" || failed=1; done
    build_pids=()
    return "$failed"
}
compile() {
    local name=$1; shift
    # BSD time on the supported macOS versions accepts -o; compiler diagnostics
    # remain on stderr rather than being mixed into the timing record.
    /usr/bin/time -p -o "dist/macos-build-$arch-$name.time" "$compiler" "$@" &
    build_pids+=("$!")
    # Bounded batches also work with macOS's system Bash 3.2 (no wait -n).
    if [[ ${#build_pids[@]} == "$workers" ]]; then wait_builds; fi
}
compile resolver "${flags[@]}" -DDNSP_VERSION="\"$version\"" -o "$bundle/dnsp-modern" dnsp-modern.c -L"$sdk/usr/lib" -lcurl
compile helper "${release_flags[@]}" -fobjc-arc -fblocks -Wall -Wextra -Werror \
    -o "$bundle/dnsp-macos" packaging/macos/dnsp-macos.m -framework Foundation -framework SystemConfiguration
compile desktop "${release_flags[@]}" -fobjc-arc -Wall -Wextra -Werror \
    -o "$contents/MacOS/DNSProxy" packaging/macos/desktop-main.m -framework AppKit
compile dns-tests "${release_flags[@]}" -fobjc-arc -fblocks -Wall -Wextra -Werror -Wno-unused-function \
    -o dist/macos-dns-tests tests/test_macos_dns.m -framework Foundation -framework SystemConfiguration
for probe in platform curl_callbacks; do
    compile "$probe" "${flags[@]}" -o "dist/macos-$probe" "tests/test_$probe.c" -L"$sdk/usr/lib" -lcurl
done
wait_builds
# Reject accidental dependencies on the builder's Homebrew or workspace paths.
for executable in dnsp-modern dnsp-macos DNSProxy.app/Contents/MacOS/DNSProxy; do
    [[ $(lipo -archs "$bundle/$executable") == "$arch" ]] || {
        echo "Unexpected executable architecture: $executable" >&2; exit 1;
    }
    otool -L "$bundle/$executable"
    otool -L "$bundle/$executable" | tail -n +2 | awk '{print $1}' | while read -r dependency; do
        case "$dependency" in /usr/lib/*|/System/Library/*) ;; *) echo "Non-system dependency: $dependency" >&2; exit 1 ;; esac
    done
done
# Ad-hoc signatures provide integrity without a developer identity or Apple ticket.
for executable in dnsp-modern dnsp-macos; do
    codesign --force --sign - --identifier "io.github.fantuz.DNSProxy.$executable" "$bundle/$executable"
    codesign --verify --strict "$bundle/$executable"
done
cp LICENSE packaging/macos/START-HERE.txt "$bundle/"
cp docs/MACOS.md "$bundle/"
cp docs/MACOS-GUI.md "$bundle/"
cp docs/BLOCKLISTS.md scripts/update-blocklist.py "$bundle/"
cp packaging/macos/Start-DNSProxy.command "$bundle/"
cp packaging/macos/Start-DNSProxy-GUI.command "$bundle/"
mkdir -p "$bundle/gui"
# Include source modules and the optional launcher, never developer bytecode or
# a Homebrew-linked runtime. Keep the native CLI dependency check above intact.
for module in tools/desktop-gui/*.py tools/desktop-gui/dnsp-gui-macos; do
    cp "$module" "$bundle/gui/"
done
cp "$bundle/dnsp-modern" "$contents/Helpers/"
cp -R "$bundle/gui" "$contents/Resources/"
cp packaging/macos/Desktop-Info.plist "$contents/Info.plist"
/usr/bin/plutil -insert CFBundleShortVersionString -string "$version" "$contents/Info.plist"
/usr/bin/plutil -insert CFBundleVersion -string "$version" "$contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
chmod 755 "$bundle/Start-DNSProxy.command" "$bundle/Start-DNSProxy-GUI.command" "$bundle/gui/dnsp-gui-macos"
{
    printf 'DNSProxy %s\nSource commit: %s\nArchitecture: %s\nMinimum macOS: 15.0\n' "$version" "$(git rev-parse HEAD)" "$arch"
    printf 'Release compiler flags:'; printf ' %q' "${release_flags[@]}"; printf '\n'
    printf 'CPU target: compiler portable baseline; no builder-specific CPU features\n'
    printf 'Compilation profile: %s\nCompilation workers: %s\n' "$profile" "$workers"
    printf 'Signing: ad-hoc integrity signatures; no Developer ID or Apple notarization\n'
    printf 'Optional GUI: GTK 4/PyGObject/Cairo from Homebrew; source included under gui/\n'
    "$bundle/dnsp-modern" --version
    sw_vers
    "$compiler" --version
    otool -L "$bundle/dnsp-modern"
} > "$bundle/BUILD-INFO.txt"
(cd "$bundle" && find . -type f ! -name SHA256SUMS -exec shasum -a 256 {} \; | LC_ALL=C sort -k2 > SHA256SUMS)
archive="dist/dnsp-modern-$version-macos-$arch.tar.gz"
COPYFILE_DISABLE=1 tar -czf "$archive" -C "$bundle" .
(cd dist && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")
