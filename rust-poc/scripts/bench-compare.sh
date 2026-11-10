#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf 'Usage: %s PATH_TO_C_BINARY NEW_RESULTS_DIRECTORY\n' "$0" >&2
    exit 2
fi

baseline=$(realpath -- "$1")
[ -x "$baseline" ] || { printf 'C binary is missing or not executable\n' >&2; exit 2; }
mkdir -p -- "$2"
out=$(realpath -- "$2")
[ -z "$(ls -A -- "$out")" ] || { printf 'Results directory must be empty\n' >&2; exit 2; }
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
python=${PYTHON:-python3}

cargo build --release --locked
export PYTHONDONTWRITEBYTECODE=1
for run in 1 2 3; do
    if [ "$run" = 2 ]; then order='rust c'; else order='c rust'; fi
    for implementation in $order; do
        if [ "$implementation" = c ]; then
            binary=$baseline
        else
            binary=$root/target/release/dnsp-modern-rust
        fi
        printf '\n--- %s / run %s ---\n' "$implementation" "$run"
        "$python" bench/bench_modern.py --binary "$binary" --protocol h2-h3 \
            --concurrency 1,8,32 --upstream-delay-ms 1 --warmup 0.5 --duration 2 \
            --max-host-connections 8 --assert-h2-multiplex --output "$out/${implementation}-${run}.json"
    done
done
