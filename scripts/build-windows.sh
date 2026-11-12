#!/usr/bin/env bash
# Run in MSYS2 UCRT64. The output is native Windows, with no MSYS runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "${MSYSTEM:-}" == UCRT64 ]] || { echo 'Use an MSYS2 UCRT64 shell' >&2; exit 2; }
version=$(cat VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
mkdir -p dist/windows
windres -I packaging/windows packaging/windows/dnsp-modern.rc -o dist/windows-manifest.o
gcc -std=c11 -O2 -g -Wall -Wextra -Wpedantic -Werror \
    -DDNSP_VERSION="\"$version\"" -o dist/windows/dnsp-modern.exe \
    dnsp-modern.c dist/windows-manifest.o $(pkg-config --cflags --libs libcurl) -lws2_32
python scripts/bundle-windows.py --prefix "$MINGW_PREFIX" --directory dist/windows
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'openssl=%s\n' "$(cygpath -w "$MINGW_PREFIX/bin/openssl.exe")" >> "$GITHUB_OUTPUT"
fi
