"""Exercise the shared DNS core over native IPv4 and IPv6 sockets."""
from contextlib import contextmanager, ExitStack
import os
import socket
import random
import struct
import tempfile
import threading
import time
import unittest

import test_modern as fixtures
from test_modern import (BINARY, HTTP, CacheDoH, DoH, query,
                         spawn_proxy, terminate_proxy, sized_query)


class CountingDoH(CacheDoH):
    def do_POST(self):
        self.server.requests += 1
        self.server.started.set()
        self.server.gate.wait(5)
        super().do_POST()


def listener_ports():
    # Stay below the host ephemeral range: readiness/upstream connections must
    # not steal the port between reservation and the child binding its listeners.
    with ExitStack() as held:
        ports = []
        for port in random.sample(range(18000, 28000), 100):
            try:
                reservations = []
                for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                        sock = held.enter_context(socket.socket(family, kind))
                        if family == socket.AF_INET6:
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        sock.bind((host, port))
                        reservations.append(sock)
                ports.append(port)
                if len(ports) == 2:
                    return ports
            except OSError:
                for sock in reservations:
                    sock.close()
        raise RuntimeError('Cannot reserve dual-family test ports')


class IPv6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.bind(('::1', 0))
        except OSError:
            if os.environ.get('DNSP_REQUIRE_IPV6') == '1':
                raise
            raise unittest.SkipTest('IPv6 loopback is disabled on this host')

    @contextmanager
    def proxy(self, *args, addresses=('127.0.0.1', '::1'), handler=CountingDoH):
        port, metrics = listener_ports()
        with HTTP(('127.0.0.1', 0), handler) as server, tempfile.TemporaryFile() as log:
            server.requests = 0
            server.started = threading.Event()
            server.gate = threading.Event()
            server.gate.set()
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            command = [str(BINARY), '-p', str(port), '-m', str(metrics), '-s',
                       f'http://127.0.0.1:{server.server_port}/dns-query']
            for address in addresses:
                command += ['-l', address]
            process = spawn_proxy(command + list(args), stderr=log)
            try:
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        self.udp('::1', port, timeout=.2)
                        break
                    except OSError:
                        time.sleep(.03)
                else:
                    log.seek(0)
                    self.fail(f'IPv6 startup failed: {log.read()!r}')
                server.requests = 0
                server.started.clear()
                yield port, metrics, server
            finally:
                server.gate.set()
                terminate_proxy(process)
                process.wait(timeout=5)
                server.shutdown()
                worker.join(timeout=3)

    @staticmethod
    def udp(address, port, packet=None, timeout=3):
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
            sock.settimeout(timeout)
            sock.connect((address, port))
            sock.send(packet or query())
            data, source = sock.recvfrom(65535)
            return data, source

    def test_udp_tcp_both_families_and_record_types(self):
        with self.proxy(handler=DoH) as (port, _, server):
            for host in ('127.0.0.1', '::1'):
                for typ in (1, 28, 16, 65, 65400):
                    with self.subTest(host=host, rrtype=typ):
                        packet = query(typ, edns=1232)
                        reply, source = self.udp(host, port, packet)
                        self.assertEqual(source[:2], (host, port))
                        self.assertEqual(reply[:2], packet[:2])
                        self.assertEqual(reply[3] & 15, 0)
                        with socket.create_connection((host, port), timeout=3) as sock:
                            sock.sendall(struct.pack('!H', len(packet)) + packet)
                            self.assertEqual(fixtures.Tests.tcp_frame(sock), reply)

    def test_ipv6_udp_maximum_and_tcp_truncation_retry(self):
        with self.proxy(handler=DoH) as (port, _, server):
            for size in (65507, 65527):
                packet = sized_query(size)
                reply, _ = self.udp('::1', port, packet)
                self.assertEqual(reply[3] & 15, 0)
                self.assertTrue(reply[2] & 2)
                with socket.create_connection(('::1', port), timeout=3) as sock:
                    sock.sendall(struct.pack('!H', len(packet)) + packet)
                    full = fixtures.Tests.tcp_frame(sock)
                    self.assertEqual(len(full), size)
                    self.assertFalse(full[2] & 2)

    def test_cache_shared_across_families(self):
        with self.proxy('--cache-entries', '32') as (port, metrics, server):
            packet = query(28, ident=42)
            first, _ = self.udp('::1', port, packet)
            second, _ = self.udp('127.0.0.1', port, query(28, ident=43))
            self.assertEqual(first[3] & 15, 0)
            self.assertEqual(second[:2], b'\0+')
            self.assertEqual(server.requests, 1)
            self.assertGreaterEqual(fixtures.Tests.metric(fixtures.Tests.metrics(self, metrics), 'dnsp_cache_hits_total'), 1)

    def test_ipv6_wildcard_sources_and_local_errors(self):
        with self.proxy('--cache-entries', '32', addresses=('::',)) as (port, _, server):
            for packet, code in ((query(28), 0), (query(28, ident=42), 0),
                                 (query()[:3] + b'\x01' + query()[4:], 1)):
                reply, source = self.udp('::1', port, packet)
                self.assertEqual(source[:2], ('::1', port))
                self.assertEqual(reply[:2], packet[:2])
                self.assertEqual(reply[3] & 15, code)
            with self.assertRaises(OSError):
                socket.create_connection(('127.0.0.1', port), timeout=.2)

    def test_ipv6_coalescing_keeps_waiter_ids(self):
        with self.proxy(addresses=('::',)) as (port, metrics, server), \
             socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as first, \
             socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as second:
            for sock in (first, second):
                sock.settimeout(3)
                sock.connect(('::1', port))
            server.gate.clear()
            first.send(query(ident=41))
            self.assertTrue(server.started.wait(2))
            second.send(query(ident=42))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                joined = fixtures.Tests.metric(fixtures.Tests.metrics(self, metrics), 'dnsp_udp_queries_coalesced_total')
                if joined == 1:
                    break
                time.sleep(.02)
            self.assertEqual(joined, 1)
            server.gate.set()
            for sock, ident in ((first, 41), (second, 42)):
                self.assertEqual(sock.recv(4096)[:2], struct.pack('!H', ident))
            self.assertEqual(server.requests, 1)

    def test_tcp_limits_distinguish_address_families(self):
        with self.proxy('--tcp-max-per-source', '1') as (port, metrics, _), \
             socket.create_connection(('127.0.0.1', port), timeout=3) as v4, \
             socket.create_connection(('::1', port), timeout=3) as v6:
            packet = query()
            for sock in (v4, v6):
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                self.assertEqual(fixtures.Tests.tcp_frame(sock)[3] & 15, 0)
            with socket.create_connection(('::1', port), timeout=3) as extra:
                try:
                    self.assertEqual(extra.recv(1), b'')
                except ConnectionResetError:
                    pass
            self.assertEqual(fixtures.Tests.metric(fixtures.Tests.metrics(self, metrics),
                             'dnsp_tcp_connections_rejected_total{reason="source_limit"}'), 1)

    def test_explicit_failed_listener_releases_all_ports(self):
        for address in ('not-an-ip', '2001:db8::dead', 'fe80::1%invalid-interface'):
            with self.subTest(address=address):
                port, _ = listener_ports()
                with tempfile.TemporaryFile() as log:
                    process = spawn_proxy([str(BINARY), '-l', '127.0.0.1', '-l', address,
                                           '-p', str(port)], stderr=log)
                    self.assertNotEqual(process.wait(timeout=5), 0)
                    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                        with socket.socket(socket.AF_INET, kind) as sock:
                            sock.bind(('127.0.0.1', port))


if __name__ == '__main__':
    unittest.main()
