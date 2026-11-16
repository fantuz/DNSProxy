"""Test the actual runtime image. Run explicitly on native Linux Docker runners."""
import asyncio
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE/'bench'))
from bench_modern import await_ready, free_port, make_certificate, one_load  # noqa: E402
from mock_doh import MockServer  # noqa: E402
from test_http3 import quic_upstream  # noqa: E402
from test_policy import exchange, question  # noqa: E402
import test_modern as dns  # noqa: E402

IMAGE = os.environ.get('DNSP_CONTAINER_IMAGE', 'dnsp-modern:ci')


def docker(*args, check=True):
    return subprocess.run(['docker', *args], text=True, capture_output=True, check=check, timeout=45)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_POST(self):
        packet = self.rfile.read(int(self.headers['Content-Length']))
        self.server.received.append(packet)
        end = dns.question_end(packet)
        typ = struct.unpack('!H', packet[end-4:end-2])[0]
        data = {1: socket.inet_aton('192.0.2.1'), 28: socket.inet_pton(socket.AF_INET6, '2001:db8::1'),
                16: b'\x05hello', 65280: b'opaque'}[typ]
        count = 100 if b'\x05large\x07example\x00' in packet else 1
        rr = b'\xc0\x0c' + struct.pack('!HHIH', typ, 1, 60, len(data)) + data
        reply = packet[:2] + struct.pack('!5H', 0x8180, 1, count, 0, 0) + packet[12:end] + rr * count
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_args):
        pass


class ContainerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dnsp-container-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        self.cert, self.key = make_certificate(self.root)
        self.cert.chmod(0o644)

    @contextmanager
    def proxy(self, upstream, *extra, network='host', address='127.0.0.1', rules=None):
        dns_port, metrics_port = free_port(), free_port()
        while metrics_port == dns_port:
            metrics_port = free_port()
        args = ['run', '-d', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--network', network, '--health-interval=1s', '--health-start-period=1s',
                '-e', f'DNSP_HEALTH_PORT={metrics_port}',
                '--mount', f'type=bind,src={self.cert},dst=/etc/dnsp/ca.pem,readonly']
        if network != 'host':
            args += ['-p', f'127.0.0.1:{dns_port}:5300/udp', '-p', f'127.0.0.1:{dns_port}:5300/tcp']
        if rules:
            args += ['--mount', f'type=bind,src={rules},dst=/etc/dnsp/rules,readonly']
        args += [IMAGE, '-l', '127.0.0.1' if network == 'host' else '0.0.0.0',
                 '-p', str(dns_port if network == 'host' else 5300), '-m', str(metrics_port),
                 '-s', f'https://localhost:{upstream}/dns-query', '--bootstrap-address', address,
                 '--ca-file', '/etc/dnsp/ca.pem', *extra]
        container = docker(*args).stdout.strip()
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                state = json.loads(docker('inspect', container).stdout)[0]['State']
                if not state['Running']:
                    self.fail(f'Container exited: {state}')
                if state.get('Health', {}).get('Status') == 'healthy':
                    break
                time.sleep(.1)
            else:
                self.fail('Container health check did not become healthy')
            yield container, dns_port, metrics_port
            docker('stop', '--time', '5', container)
            state = json.loads(docker('inspect', container).stdout)[0]['State']
            self.assertEqual(state['ExitCode'], 0, state)
            self.assertFalse(state['OOMKilled'], state)
        finally:
            if sys.exc_info()[0]:
                print(docker('logs', container, check=False).stdout, file=sys.stderr)
                print(docker('logs', container, check=False).stderr, file=sys.stderr)
                print(docker('inspect', container, check=False).stdout, file=sys.stderr)
            docker('rm', '-f', container, check=False)

    def metrics(self, container, port):
        text = docker('exec', container, 'curl', '-fsS', '--noproxy', '*',
                      f'http://127.0.0.1:{port}/metrics').stdout
        return {line.rsplit(None, 1)[0]: float(line.rsplit(None, 1)[1])
                for line in text.splitlines() if line and not line.startswith('#')}

    def test_bridge_udp_tcp_cache_edns_and_readonly_blocklist_reload(self):
        network = 'dnsp-ci-' + uuid.uuid4().hex[:12]
        docker('network', 'create', network)
        self.addCleanup(lambda: docker('network', 'rm', network, check=False))
        gateway = json.loads(docker('network', 'inspect', network).stdout)[0]['IPAM']['Config'][0]['Gateway']
        server = http.server.ThreadingHTTPServer(('0.0.0.0', free_port()), Handler)
        server.daemon_threads = True
        server.received = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rules = self.root/'rules'
        rules.mkdir(mode=0o755)
        (rules/'deny.txt').write_text('ads.example\n')
        with self.proxy(server.server_port, '--cache-entries', '64', '--blocklist', '/etc/dnsp/rules/deny.txt',
                        network=network, address=gateway, rules=rules) as (container, port, metric):
            info = json.loads(docker('inspect', container).stdout)[0]
            self.assertEqual(info['Config']['User'], '10001:10001')
            self.assertTrue(info['HostConfig']['ReadonlyRootfs'])
            self.assertIn('ALL', info['HostConfig']['CapDrop'])
            self.assertEqual(docker('exec', container, 'id', '-u').stdout.strip(), '10001')
            self.assertNotEqual(docker('exec', container, 'touch', '/forbidden', check=False).returncode, 0)
            self.assertNotIn('9153/tcp', info['NetworkSettings']['Ports'])
            self.assertIn('VERSION_ID="13"', docker('exec', container, 'cat', '/etc/os-release').stdout)
            features = docker('exec', container, 'curl', '--version').stdout
            self.assertIn('HTTP2', features)
            self.assertIn('HTTP3', features)
            for typ, suffix in ((1, socket.inet_aton('192.0.2.1')), (28, socket.inet_pton(socket.AF_INET6, '2001:db8::1')),
                                (16, b'\x05hello'), (65280, b'opaque')):
                for tcp in (False, True):
                    with self.subTest(typ=typ, tcp=tcp):
                        packet = question(f'type-{typ}.example', typ, ident=0x1234 + tcp)
                        reply = exchange(port, packet, tcp=tcp)
                        self.assertEqual(reply[:2], packet[:2])
                        self.assertEqual(reply[3] & 15, 0)
                        self.assertEqual(reply[6:8], b'\x00\x01')
                        self.assertTrue(reply.endswith(suffix))
            for edns, limit in ((False, 512), (True, 1232)):
                packet = question('large.example', edns=edns)
                reply = exchange(port, packet)
                self.assertLessEqual(len(reply), limit)
                self.assertTrue(reply[2] & 2)
                full = exchange(port, packet, tcp=True)
                self.assertGreater(len(full), 1232)
                self.assertFalse(full[2] & 2)
                self.assertEqual(struct.unpack('!H', full[6:8])[0], 100)
            self.assertGreater(self.metrics(container, metric)['dnsp_cache_hits_total'], 0)
            before = len(server.received)
            self.assertEqual(exchange(port, question('ads.example'))[3] & 15, 3)
            self.assertEqual(len(server.received), before)
            temporary = rules/'deny.new'
            temporary.write_text('ads.example\nnew.example\n')
            temporary.replace(rules/'deny.txt')
            docker('kill', '--signal=HUP', container)
            deadline = time.monotonic() + 5
            while self.metrics(container, metric)['dnsp_blocklist_generation'] < 2:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.05)
            self.assertEqual(exchange(port, question('new.example'))[3] & 15, 3)

    def test_packaged_http2_multiplex_and_reuse(self):
        upstream = MockServer(free_port(), self.cert, self.key, delay_ms=20)
        upstream.start()
        try:
            await_ready(upstream.port, None, 'HTTP/2 fixture')
            with self.proxy(upstream.port) as (container, port, metric):
                self.assertEqual(one_load(port, 1, 0)['successful_queries'], 1)
                result = one_load(port, 8, .25)
                self.assertGreaterEqual(result['successful_queries'], 8, result)
                self.assertEqual(result['failed_responses'] + result['timeouts'], 0, result)
                observed = upstream.app.snapshot()
                self.assertEqual(observed['upstream_connections_used'], 1, observed)
                self.assertGreaterEqual(observed['upstream_max_simultaneous_per_connection'], 2, observed)
                self.assertGreater(self.metrics(container, metric)['dnsp_upstream_http_responses_total{version="2"}'], 1)
        finally:
            upstream.close()

    async def test_packaged_http3_multiplex_and_reuse(self):
        upstream = MockServer(free_port(), self.cert, self.key, delay_ms=20)
        async with quic_upstream(upstream, self.cert, self.key):
            with self.proxy(upstream.port, '--upstream-http=prefer-h3') as (container, port, metric):
                warm = await asyncio.to_thread(one_load, port, 1, 0)
                self.assertEqual(warm['successful_queries'], 1, warm)
                result = await asyncio.to_thread(one_load, port, 8, .25)
                self.assertGreaterEqual(result['successful_queries'], 8, result)
                self.assertEqual(result['failed_responses'] + result['timeouts'], 0, result)
                observed = upstream.app.snapshot()
                self.assertEqual(observed['upstream_connections_used'], 1, observed)
                self.assertGreaterEqual(observed['upstream_max_simultaneous_per_connection'], 2, observed)
                stats = self.metrics(container, metric)
                self.assertGreater(stats['dnsp_upstream_http_responses_total{version="3"}'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
