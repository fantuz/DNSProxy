#!/bin/sh
# Run the local DoH benchmark with impairment scoped to the upstream TCP port.
set -eu
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 ONE_WAY_DELAY LOSS_PERCENT PYTHON [benchmark options]" >&2
    exit 2
fi
delay=$1 loss=$2
shift 2
python=$1
shift
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

# A fresh network namespace has no routes to host interfaces or public servers.
exec unshare --net sh -eu -c '
    delay=$1 loss=$2 python=$3 benchmark=$4
    shift 4
    port=9443
    ip link set lo up
    tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    tc qdisc add dev lo parent 1:3 handle 30: netem delay "$delay" loss "$loss"
    tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff \
        match ip dport "$port" 0xffff flowid 1:3
    tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip protocol 6 0xff \
        match ip sport "$port" 0xffff flowid 1:3
    trap "tc -s qdisc show dev lo" 0
    echo "Synthetic upstream TCP impairment $delay one-way and $loss random loss"
    set -- "$python" "$benchmark" "$@" --mock-upstream-port "$port"
    if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
        set -- setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups "$@"
    fi
    "$@"
' sh "$delay" "$loss" "$python" "$here/bench_modern.py" "$@"
