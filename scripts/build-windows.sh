#!/usr/bin/env bash
# Run in MSYS2 UCRT64. The output is native Windows, with no MSYS runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${MSYSTEM:-}" == UCRT64 ]] || { echo 'Use an MSYS2 UCRT64 shell' >&2; exit 2; }
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
# Never carry stale DLLs or development executables into the portable ZIP.
rm -rf -- dist/windows
mkdir -p dist/windows
windres -I packaging/windows packaging/windows/dnsp-modern.rc -o dist/windows-manifest.o
gcc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror \
    -DDNSP_VERSION="\"$version\"" -o dist/windows/dnsp-modern.exe \
    dnsp-modern.c dist/windows-manifest.o $(pkg-config --cflags --libs libcurl) -lws2_32 -ladvapi32 -municode
python scripts/bundle-windows.py --prefix "$MINGW_PREFIX" --directory dist/windows
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -o dist/platform-probe.exe \
    tests/test_platform.c $(pkg-config --cflags --libs libcurl) -lws2_32
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'openssl=%s\n' "$(cygpath -w "$MINGW_PREFIX/bin/openssl.exe")" >> "$GITHUB_OUTPUT"
fi
# Test-only executable: the real service adapter reporting a nonzero exit.
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -o dist/service-fixture.exe \
    tests/test_windows_service_fixture.c -ladvapi32
