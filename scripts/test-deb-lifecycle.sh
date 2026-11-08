#!/bin/sh
# Run on a disposable systemd CI runner with no existing dnsp-modern package.
set -eu
cd "$(dirname "$0")/.."
pkg=$(realpath "$1")
unit=dnsp-modern.service
dropin="/etc/systemd/system/$unit.d"
if [ "$(id -u)" -ne 0 ] || [ ! -d /run/systemd/system ] ||
   dpkg-query -W dnsp-modern >/dev/null 2>&1 || [ -e "$dropin" ]; then
    echo "A clean, disposable systemd runner is required" >&2
    exit 1
fi
work=$(mktemp -d)
fixture=
cleanup() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        journalctl -u "$unit" --no-pager -n 80 >&2 || :
    fi
    systemctl stop "$unit" >/dev/null 2>&1 || :
    dpkg --purge dnsp-modern >/dev/null 2>&1 || :
    if [ -n "$fixture" ]; then kill "$fixture" 2>/dev/null || :; fi
    if [ -f "$dropin/ci-lifecycle.conf" ]; then
        rm "$dropin/ci-lifecycle.conf"
        rmdir "$dropin" || :
    fi
    systemctl daemon-reload || :
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT

apt-get install -y --no-install-recommends "$pkg"
test "$(systemctl is-enabled "$unit" || :)" = disabled
if systemctl is-active --quiet "$unit"; then exit 1; fi
apt-get purge -y dnsp-modern

# Model a pre-lifecycle release using the same payload and no maintainer scripts.
dpkg-deb -R "$pkg" "$work/old"
sed -i 's/^Version:.*/Version: 0~lifecycle-test/' "$work/old/DEBIAN/control"
rm "$work/old/DEBIAN/postinst" "$work/old/DEBIAN/prerm" "$work/old/DEBIAN/postrm"
dpkg-deb --build --root-owner-group "$work/old" "$work/previous.deb"
chmod 0755 "$work"
apt-get install -y --no-install-recommends "$work/previous.deb"

PYTHONPATH=tests python3 -u -c '
from test_modern import HTTP, DoH, unused_ports
with HTTP(("127.0.0.1", 0), DoH) as server:
    print(server.server_port, unused_ports()[0], flush=True)
    server.serve_forever()
' > "$work/ports" &
fixture=$!
for i in $(seq 1 50); do
    if [ -s "$work/ports" ]; then break; fi
    sleep 0.1
done
read -r doh_port dns_port < "$work/ports"

mkdir -p "$dropin"
cat > "$work/ci-lifecycle.conf" <<END
[Service]
ExecStart=
ExecStart=/usr/bin/dnsp-modern -l 127.0.0.1 -p $dns_port -s http://127.0.0.1:$doh_port/dns-query
END
install -m 0644 "$work/ci-lifecycle.conf" "$dropin/"
systemctl daemon-reload
systemctl enable --now "$unit"

probe() {
    PYTHONPATH=tests python3 - "$dns_port" <<'PY'
import socket
import sys
import time
from test_modern import Tests, query

addr = ("127.0.0.1", int(sys.argv[1]))
packet = query()
deadline = time.monotonic() + 5
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.settimeout(.25)
    while True:
        udp.sendto(packet, addr)
        try:
            answer = udp.recv(4096)
            break
        except TimeoutError:
            if time.monotonic() >= deadline:
                raise
    assert answer[:2] == packet[:2] and answer[2:4] == b"\x81\x80"

with socket.create_connection(addr, timeout=2) as tcp:
    tcp.sendall(Tests.frame(packet))
    answer = Tests.tcp_frame(tcp)
    assert answer[:2] == packet[:2] and answer[2:4] == b"\x81\x80"
PY
}

probe
old_pid=$(systemctl show "$unit" -p MainPID --value)
test "$old_pid" -gt 0
apt-get install -y --no-install-recommends "$pkg"
new_pid=$(systemctl show "$unit" -p MainPID --value)
test "$new_pid" -gt 0
test "$new_pid" != "$old_pid"
systemctl is-enabled --quiet "$unit"
cmp "$dropin/ci-lifecycle.conf" "$work/ci-lifecycle.conf"
probe

apt-get remove -y dnsp-modern
if systemctl is-active --quiet "$unit"; then exit 1; fi
test ! -e /usr/bin/dnsp-modern
apt-get purge -y dnsp-modern
test ! -L "/etc/systemd/system/multi-user.target.wants/$unit"
cmp "$dropin/ci-lifecycle.conf" "$work/ci-lifecycle.conf"
