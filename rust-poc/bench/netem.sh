#!/bin/sh
# Run the local DoH benchmark with impairment scoped to the upstream port.
set -eu
# CI can supply an already isolated container with only loopback networking.
isolated=false
if [ "${1:-}" = '--isolated' ]; then
    shift
    isolated=true
fi
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 ONE_WAY_DELAY LOSS_PERCENT PYTHON [benchmark options]" >&2
    exit 2
fi
if [ "$isolated" = false ]; then
    # A fresh namespace has no routes to host interfaces or public servers.
    exec unshare --net sh "$0" --isolated "$@"
fi
if [ "$(ip -o link show | awk '{print $2}')" != 'lo:' ]; then
    echo '--isolated requires a network namespace containing only loopback' >&2
    exit 2
fi
delay=$1 loss=$2
shift 2
python=$1
shift
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

port=9443
ip link set lo up
tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
trap 'tc -s qdisc show dev lo; tc qdisc del dev lo root' 0
tc qdisc add dev lo parent 1:3 handle 30: netem delay "$delay" loss "$loss"
for proto in 6 17; do  # TCP and UDP
    for direction in dport sport; do
        tc filter add dev lo parent 1: protocol ip prio "$proto" u32 match ip protocol "$proto" 0xff \
            match ip "$direction" "$port" 0xffff flowid 1:3
    done
done
echo "Synthetic upstream TCP and UDP impairment $delay one-way and $loss random loss"
set -- "$python" "$here/bench_modern.py" "$@" --mock-upstream-port "$port"
if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
    set -- setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups "$@"
fi
setpriv --bounding-set=-net_admin --no-new-privs "$@"
