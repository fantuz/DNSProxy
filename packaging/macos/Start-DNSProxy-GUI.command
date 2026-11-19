#!/bin/sh
# Optional Homebrew GUI. The native resolver itself needs no Homebrew runtime.
set -eu
root=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
exec "$root/gui/dnsp-gui-macos" --binary "$root/dnsp-modern" "$@"
