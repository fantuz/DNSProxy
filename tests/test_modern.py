#!/usr/bin/env python3
"""Loopback integration: RFC 8484 framing, EDNS, DNS validation, libcurl loop."""
import http.client
import http.server
import os
import socket
import socketserver
import struct
import subprocess
import threading
import time
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
QUERY = bytes.fromhex('1234010000010000000000000377777706676f6f676c6503636f6d0000010001')
ANSWER = bytes.fromhex('c00c000100010000003c0004c0000201')


def query(qtype=1, edns=None, ident=0x1234):
    q = bytearray(QUERY)
    q[:2] = struct.pack('!H', ident)
    q[-4:-2] = struct.pack('!H', qtype)
    if edns is not None:
        q[10:12] = b'\0\1'
        q += b'\0\x00\x29' + struct.pack('!H', edns) + b'\0' * 6
    return bytes(q)


def make_response(data):
    typ = struct.unpack('!H', data[len(QUERY)-4:len(QUERY)-2])[0]
    r = bytearray(data[:len(QUERY)])
    r[2:4] = b'\x81\x80'
    if typ in (65001, 65006, 65007):
        answers = {65001:65, 65006:140, 65007:350}[typ]
        r[6:8] = struct.pack('!H', answers)
        r += ANSWER * answers
    elif typ == 65002:  # wrong ID
        r[0] ^= 1
    elif typ == 65003:  # mismatched question
        r[13] ^= 1
    elif typ == 65004:  # malformed answer RDATA bounds
        r[6:8] = b'\0\1'
        r += ANSWER[:-1]
    elif typ == 65005:  # invalid compression pointer
        r[6:8] = b'\0\1'
        r += b'\xc0\xff' + ANSWER[2:]
    # Copy any EDNS OPT after the ANSWER section, not before it.
    if len(data) > len(QUERY):
        r.extend(data[len(QUERY):])
    return bytes(r)


class DoH(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_POST(self):
        n = int(self.headers['Content-Length'])
        data = self.rfile.read(n)
        if self.path != '/dns-query' or self.headers.get('Content-Type') != 'application/dns-message':
            self.send_error(400)
            return
        r = make_response(data)
        typ = struct.unpack('!H', data[len(QUERY)-4:len(QUERY)-2])[0]
        self.send_response(502 if typ == 65009 else 200)
        self.send_header('Content-Type', 'text/plain' if typ == 65008 else 'application/dns-message')
        self.send_header('Content-Length', str(len(r)))
        self.end_headers()
        try:
            self.wfile.write(r)
        except (BrokenPipeError, ConnectionResetError):
            pass
    def log_message(self, *args):
        pass


class HTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def unused_ports():
    with socket.socket() as a, socket.socket() as b:
        a.bind(('127.0.0.1', 0))
        b.bind(('127.0.0.1', 0))
        return a.getsockname()[1], b.getsockname()[1]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTP(('127.0.0.1', 0), DoH)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.server.server_close)
        cls.addClassCleanup(cls.server.shutdown)

        cls.port, cls.metrics_port = unused_ports()
        # A regular file prevents unconsumed PIPE output from blocking the proxy
        # and allows diagnostics even when a sanitizer-instrumented process hangs.
        cls.proxy_log = tempfile.TemporaryFile(mode='w+b')
        cls.addClassCleanup(cls.proxy_log.close)
        cls.process = subprocess.Popen([
            str(BASE/'dnsp-modern'), '-p', str(cls.port), '-m', str(cls.metrics_port),
            '-s', f'http://127.0.0.1:{cls.server.server_port}/dns-query'
        ], stdout=subprocess.DEVNULL, stderr=cls.proxy_log)
        cls.addClassCleanup(cls.stop_proxy)

        # A 200 ms sleep is not an adequate readiness check with ASan/UBSan.
        # Require a complete, successful DNS round-trip before testing malformed
        # requests; otherwise the first test can time out on a slow CI runner.
        deadline = time.monotonic() + float(os.environ.get('DNSP_TEST_STARTUP_TIMEOUT', '12'))
        last = 'no response received'
        while time.monotonic() < deadline:
            code = cls.process.poll()
            if code is not None:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(0.75)
                    sock.sendto(query(), ('127.0.0.1', cls.port))
                    answer = sock.recvfrom(4096)[0]
                if (answer[:2] == QUERY[:2] and answer[2:4] == b'\x81\x80'
                        and answer[12:] == QUERY[12:]):
                    return
                last = f'invalid readiness answer: {answer[:40].hex()}'
            except (socket.timeout, OSError) as exc:
                last = repr(exc)
            time.sleep(0.1)

        cls.proxy_log.flush()
        cls.proxy_log.seek(0)
        diagnostic = cls.proxy_log.read(8192).decode('utf-8', errors='replace')
        raise RuntimeError(f'proxy not ready (exit={cls.process.poll()}, '
                           f'last={last}); stderr:\n{diagnostic}')

    @classmethod
    def stop_proxy(cls):
        if cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=5)

    def udp(self, payload):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(4)
            s.sendto(payload, ('127.0.0.1', self.port))
            try:
                return s.recvfrom(4096)[0]
            except socket.timeout as exc:
                self.proxy_log.flush()
                self.proxy_log.seek(0)
                diagnostic = self.proxy_log.read(8192).decode('utf-8', errors='replace')
                raise AssertionError(
                    f'UDP response timed out (proxy exit={self.process.poll()}); '
                    f'proxy stderr:\n{diagnostic}'
                ) from exc

    def tcp(self, payload):
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as s:
            s.settimeout(4)
            s.sendall(struct.pack('!H', len(payload)) + payload)
            def readall(size):
                b = b''
                while len(b) < size:
                    part = s.recv(size-len(b))
                    if not part:
                        raise AssertionError('unexpected TCP EOF')
                    b += part
                return b
            n = struct.unpack('!H', readall(2))[0]
            return readall(n)

    def metrics(self):
        c = http.client.HTTPConnection('127.0.0.1', self.metrics_port, timeout=4)
        try:
            c.request('GET', '/metrics')
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            return r.read().decode()
        finally:
            c.close()

    @staticmethod
    def metric(data, name):
        for line in data.splitlines():
            if line.startswith(name + ' '):
                return float(line.split()[1])
        raise AssertionError(f'missing metric {name}')

    def test_udp(self):
        out = self.udp(query())
        self.assertEqual(out[:2], QUERY[:2])
        self.assertTrue(out[2] & 0x80)
        self.assertEqual(out[12:], QUERY[12:])

    def test_tcp(self):
        out = self.tcp(query())
        self.assertEqual(out[:2], QUERY[:2])
        self.assertEqual(out[12:], QUERY[12:])

    def test_parallel_udp(self):
        errors = []
        def worker(i):
            try:
                q = query(ident=i + 500)
                out = self.udp(q)
                assert out[:2] == q[:2], (out, q)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors, errors)

    def test_invalid_udp_does_not_kill(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'\0\1', ('127.0.0.1', self.port))
        out = self.udp(query())
        self.assertEqual(out[:2], QUERY[:2])
        self.assertEqual(out[2:4], b'\x81\x80')
        self.assertEqual(out[12:], QUERY[12:])

    def test_udp_without_edns_truncates_to_512(self):
        out = self.udp(query(65001))
        self.assertLessEqual(len(out), 512)
        self.assertTrue(out[2] & 0x02)  # TC
        self.assertEqual(out[6:12], b'\0' * 6)
        self.assertEqual(out[4:6], b'\0\1')

    def test_udp_edns_sufficient_size_full_response(self):
        out = self.udp(query(65001, edns=1232))
        self.assertEqual(len(out), len(QUERY) + 65 * len(ANSWER) + 11)
        self.assertEqual(out[2] & 0x02, 0)
        self.assertEqual(out[6:8], b'\0A')

    def test_udp_edns_small_size_truncates(self):
        out = self.udp(query(65001, edns=600))
        self.assertLessEqual(len(out), 600)
        self.assertTrue(out[2] & 0x02)

    def test_udp_edns_large_advertisement_capped(self):
        out = self.udp(query(65006, edns=65535))
        self.assertEqual(len(out), len(QUERY) + 140*len(ANSWER) + 11)
        self.assertLessEqual(len(out), 4096)

    def test_udp_edns_over_max_truncates(self):
        out = self.udp(query(65007, edns=65535))
        self.assertTrue(out[2] & 0x02)
        self.assertLessEqual(len(out), 4096)

    def test_reject_bad_content_type_or_http_status(self):
        for typ in (65008, 65009):
            with self.subTest(typ=typ):
                out = self.udp(query(typ))
                self.assertEqual(out[3] & 15, 2)

    def test_tcp_no_udp_limit(self):
        out = self.tcp(query(65001))
        self.assertEqual(len(out), len(QUERY) + 65*len(ANSWER))
        self.assertEqual(out[2] & 0x02, 0)

    def test_strict_upstream_validation(self):
        for typ in (65002, 65003, 65004, 65005):
            with self.subTest(typ=typ):
                out = self.udp(query(typ))
                self.assertEqual(out[3] & 15, 2)  # SERVFAIL
                self.assertEqual(out[6:12], b'\0' * 6)

    def test_malformed_edns(self):
        q = bytearray(query(edns=1232))
        q[10:12] = b'\0\2'  # lies about the number of additional RRs
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(.25)
            s.sendto(q, ('127.0.0.1', self.port))
            with self.assertRaises(socket.timeout):
                s.recvfrom(4096)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(.25)
            q = bytearray(query(edns=1232))
            q[10:12] = b'\0\2'
            q.extend(q[-11:])  # duplicate EDNS OPT
            s.sendto(q, ('127.0.0.1', self.port))
            with self.assertRaises(socket.timeout):
                s.recvfrom(4096)
        self.assertTrue(self.udp(query())[2] & 0x80)

    def test_metrics(self):
        before = self.metrics()
        self.assertIn('dnsp_upstream_http_responses_total{version="1"}', before)
        self.assertIn('dnsp_queries_total{transport="udp"}', before)
        self.udp(query())
        after = self.metrics()
        self.assertGreater(self.metric(after, 'dnsp_upstream_requests_total'),
                           self.metric(before, 'dnsp_upstream_requests_total'))
        self.assertGreater(self.metric(after, 'dnsp_curl_socket_callbacks_total'), 0)
        self.assertGreater(self.metric(after, 'dnsp_curl_timer_callbacks_total'), 0)
        self.assertEqual(self.metric(after, 'dnsp_queries_inflight'), 0)
        self.assertGreater(self.metric(after, 'dnsp_upstream_http_responses_total{version="1"}'), 0)
        self.assertGreater(self.metric(after, 'dnsp_upstream_duration_seconds_count'), 0)

    def test_reject_insecure_remote_url_and_bad_port(self):
        for args in (['-s', 'http://127.0.0.1:80@not-local.example/dns-query'],
                     ['-p', '99999999999999999999999999']):
            with self.subTest(args=args):
                r = subprocess.run([str(BASE/'dnsp-modern')] + args,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=2)
                self.assertEqual(r.returncode, 2, r.stderr)

    def test_sequential_curl_reuse(self):
        before = self.metrics()
        for _ in range(5):
            self.udp(query())
        after = self.metrics()
        self.assertGreater(self.metric(after, 'dnsp_upstream_reused_requests_total'),
                           self.metric(before, 'dnsp_upstream_reused_requests_total'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
