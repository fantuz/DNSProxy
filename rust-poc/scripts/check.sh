#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python=${PYTHON:-python3}
mode=${1:-all}
case "$mode" in
    all|core) ;;
    *) printf 'Usage: %s [all|core]\n' "$0" >&2; exit 2 ;;
esac

cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked --release

# Keep the upstream test and fixture files identical to the C revision.
# Their original executable path resolves to a symlink in a temporary tree.
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cp -R tests bench "$stage/"
ln -s "$root/target/release/dnsp-modern-rust" "$stage/dnsp-modern"
export PYTHONDONTWRITEBYTECODE=1
unset DNSP_TEST_BINARY
if [ "$mode" = core ]; then
    "$python" -m unittest discover -s "$stage/tests" -p 'test_modern.py' -v
else
    "$python" -m unittest discover -s "$stage/tests" -p 'test_*.py' -v
fi
