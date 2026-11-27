#!/bin/sh
# Run the OS daemon only inside fresh Linux mount and network namespaces.
set -eu
if [ "${1:-}" != --isolated ]; then
    [ "$#" -gt 0 ] || { echo "Usage: sudo $0 /path/to/python bench/compare_resolvers.py [options]" >&2; exit 2; }
    export DNSP_PARENT_MNTNS="$(readlink /proc/self/ns/mnt)"
    export DNSP_PARENT_NETNS="$(readlink /proc/self/ns/net)"
    exec unshare --mount --net --propagation private -- "$0" --isolated "$@"
fi
shift
[ -n "${DNSP_PARENT_MNTNS:-}" ] && [ -n "${DNSP_PARENT_NETNS:-}" ] || exit 2
[ "$DNSP_PARENT_MNTNS" != "$(readlink /proc/self/ns/mnt)" ] || exit 2
[ "$DNSP_PARENT_NETNS" != "$(readlink /proc/self/ns/net)" ] || exit 2
# Both the daemon configuration and its runtime sockets live on private tmpfs.
mount -t tmpfs -o mode=755 tmpfs /etc/systemd
mount -t tmpfs -o mode=755 tmpfs /run
if [ -d /var/lib/systemd ]; then mount -t tmpfs -o mode=755 tmpfs /var/lib/systemd; fi
mkdir -p /run/systemd/resolve
chown systemd-resolve:systemd-resolve /run/systemd/resolve
ip link set lo up
# resolved considers its global DNS scope offline with only a loopback link.
# Both ends of this pair stay inside the namespace. There is no default route.
ip link add dnsp-test0 type veth peer name dnsp-test1
ip addr add 192.0.2.254/32 dev dnsp-test0
ip link set dnsp-test1 up
ip link set dnsp-test0 up
export DNSP_RESOLVED_BENCH_NS="$(readlink /proc/self/ns/mnt) $(readlink /proc/self/ns/net)"
exec "$@"
