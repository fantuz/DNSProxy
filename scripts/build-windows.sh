#!/usr/bin/env bash
# Run in MSYS2 UCRT64 (amd64) or CLANGARM64. No MSYS runtime is shipped.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${MSYSTEM:-}" in
    UCRT64) arch=amd64; compiler=gcc ;;
    CLANGARM64) arch=arm64; compiler=clang ;;
    *) echo 'Use an MSYS2 UCRT64 or CLANGARM64 shell' >&2; exit 2 ;;
esac
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
# Never carry stale DLLs or development executables into the portable ZIP.
rm -rf -- dist/windows
mkdir -p dist/windows
windres -I packaging/windows packaging/windows/dnsp-modern.rc -o dist/windows-manifest.o
"$compiler" -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror \
    -DDNSP_VERSION="\"$version\"" -o dist/windows/dnsp-modern.exe \
    dnsp-modern.c dist/windows-manifest.o $(pkg-config --cflags --libs libcurl) -lws2_32 -ladvapi32 -municode
python scripts/bundle-windows.py --prefix "$MINGW_PREFIX" --directory dist/windows --arch "$arch"
"$compiler" -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -o dist/platform-probe.exe \
    tests/test_platform.c $(pkg-config --cflags --libs libcurl) -lws2_32
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'openssl=%s\n' "$(cygpath -w "$MINGW_PREFIX/bin/openssl.exe")" >> "$GITHUB_OUTPUT"
fi
# Test-only executable: the real service adapter reporting a nonzero exit.
"$compiler" -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -o dist/service-fixture.exe \
    tests/test_windows_service_fixture.c -ladvapi32
