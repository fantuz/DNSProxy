#!/usr/bin/env python3
"""Loopback integration: RFC 8484 framing, EDNS, DNS validation, libcurl loop."""
from contextlib import ExitStack, contextmanager
import http.client
import http.server
import os
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import tempfile
import unittest
from pathlib import Path
from select import select

BASE = Path(__file__).resolve().parent.parent
BINARY = Path(os.environ.get('DNSP_TEST_BINARY', BASE/'dnsp-modern'))
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


def edns_options(packet, options):
    return packet[:-2] + struct.pack('!H', len(options)) + options


def rr(typ, data, owner=b'\xc0\x0c', *, ttl=60):
    return owner + struct.pack('!HHIH', typ, 1, ttl, len(data)) + data


def question_end(data):
    pos = 12
    if data[4:6] == b'\0\0':
        return pos
    while data[pos]:
        pos += 1 + data[pos]
    return pos + 5


def padding_option(size):
    return struct.pack('!HH', 12, size - 4) + bytes(size - 4)


def sized_query(size):
    base = query(edns=4096)
    return edns_options(base, padding_option(size - len(base)))


ALT = b'\x03alt\x07example\0'
SOA = ALT + ALT + struct.pack('!IIIII', 1, 3600, 600, 86400, 60)
ADDRESS = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
RR_FIXTURES = {
    2: ALT,                               # NS
    5: b'\xc0\x10',                      # CNAME to google.com
    6: SOA,                               # SOA
    12: ALT,                              # PTR
    15: b'\0\x0a' + ALT,                 # MX
    16: b'\x03txt',                       # TXT
    28: ADDRESS,                          # AAAA
    33: struct.pack('!HHH', 1, 2, 443) + ALT,  # SRV
    35: b'\0\x01\0\x01\x01S\x03SIP\0' + ALT,  # NAPTR
    39: ALT,                              # DNAME
    43: b'\x12\x34\x0d\x02' + bytes(32),   # DS
    44: b'\x04\x02' + bytes(32),          # SSHFP
    46: struct.pack('!HBBIIIH', 1, 13, 3, 60, 1800000000, 1700000000, 0x1234)
        + ALT + bytes(64),                # RRSIG
    47: ALT + b'\0\x01\x40',              # NSEC
    48: b'\x01\x01\x03\x0d' + bytes(64),  # DNSKEY
    50: b'\x01\0\0\0\0\x14' + bytes(20) + b'\0\x01\x40',  # NSEC3
    52: b'\x03\x01\x01' + bytes(32),      # TLSA
    53: b'\x03\x01\x01' + bytes(32),      # SMIMEA
    64: b'\0\x01' + ALT + b'\0\x03\0\x02\x01\xbb',  # SVCB port
    65: b'\0\x01' + ALT + b'\0\x01\0\x03\x02h2',  # HTTPS ALPN
    256: b'\0\x01\0\x01https://example.com/',  # URI
    257: b'\0\x05issueletsencrypt.org',    # CAA
    65400: b'\xc0\x04\xff',               # unknown/private-use type
}


def make_response(data):
    end = question_end(data)
    typ = struct.unpack('!H', data[end-4:end-2])[0] if end > 12 else 0
    r = bytearray(data[:end])
    r[2:4] = bytes([0x81, 0x80 | (data[3] & 0x10)])
    if typ in (65001, 65006, 65007, 65016):
        answers = {65001:65, 65006:140, 65007:350, 65016:65}[typ]
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
    elif typ in (65011, 65012, 65013, 65014):
        r[6:8] = b'\0\1'
        r += {
            65011: rr(5, b'\xff'),                  # incomplete CNAME pointer
            65012: rr(1, b'\xc0\x00\x02\x01', owner=b'\xc0\x04'),
            65013: rr(5, b'\xc0\x0c'),             # valid compressed CNAME
            65014: rr(65400, b'\xc0\x04\xff'),     # opaque unknown RDATA
        }[typ]
    elif typ in (65018, 65019, 65023):  # FORMERR, TC, and bare NOERROR
        flags = {65018: 0x8181, 65019: 0x8380, 65023: 0x8180}[typ]
        return data[:2] + struct.pack('!HHHHH', flags, 0, 0, 0, 0)
    elif typ == 65024:  # NXDOMAIN
        r[3] |= 3
    elif typ in (65025, 65026, 65027):
        r[6:8] = b'\0\2'
        # These TTL bytes look like an encoded name. The second owner
        # either starts there or spans it from the last CLASS octet.
        offset = 5 if typ == 65026 else 6
        pointer = struct.pack('!H', 0xc000 | (end + offset))
        ttl = 0x61000000 if typ == 65026 else 0x01610000
        r += rr(1, b'\xc0\x00\x02\x01', ttl=ttl)
        if typ == 65027:
            r += rr(17, pointer + b'\xc0\x0c')  # Legacy RP RDATA.
        else:
            r += rr(1, b'\xc0\x00\x02\x02', owner=pointer)
    elif typ == 65028:  # A legal compressed legacy name still ages.
        r[6:8] = b'\0\1'
        r += rr(17, b'\xc0\x0c' * 2)
    elif typ in RR_FIXTURES or typ == 255:
        r[6:8] = b'\0\1'
        r += rr(typ, RR_FIXTURES[typ]) if typ != 255 else rr(13, b'\x07RFC8482\0')
        if typ == 48:
            r[3] |= 0x20  # upstream AD bit
    # Copy any EDNS OPT after the ANSWER section, not before it.
    if len(data) > end:
        r.extend(data[end:])
        if typ == 65015:
            r = edns_options(r, struct.pack('!HH', 65000, 2) + b'x')
        if typ == 65016:
            r[-6] = 1  # upstream extended RCODE, kept on local truncation
        if typ == 65020:
            r = edns_options(r, padding_option(65536 - len(r)))
        if typ == 65022:
            r[-6:-4] = b'\x01\0'  # BADVERS, supported version 0
        if typ == 0:
            cookie = data[end+15:end+23] + bytes(16)
            r = edns_options(r[:end+11], struct.pack('!HH', 10, len(cookie)) + cookie)
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
        end = question_end(data)
        typ = struct.unpack('!H', data[end-4:end-2])[0] if end > 12 else 0
        if typ == 65010:  # test intentional upstream delay and cancellation
            time.sleep(0.7)
        label = data[13:13+data[12]] if end>12 else b''
        if label in (b'coalesce', b'coalesce-fail', b'coalesce-nostore'):
            self.server.coalesce_gate.wait(5)
        status = 502 if label == b'coalesce-fail' else {65009: 502, 65017: 201}.get(typ, 200)
        self.send_response(status)
        if label == b'coalesce-nostore':
            self.send_header('Cache-Control', 'no-store')
        media = {65008: 'text/plain', 65021: 'Application/DNS-Message ; fixture=ok'}
        self.send_header('Content-Type', media.get(typ, 'application/dns-message'))
        if 65025 <= typ <= 65028:
            self.send_header('Age', '1')
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


class CacheDoH(DoH):
    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        end = question_end(data)
        label = data[13:13+data[12]].lower()
        qtype = struct.unpack('!H', data[end-4:end-2])[0]
        address = ADDRESS if qtype == 28 else bytes([192, 0, 2, 1])
        ttl = 0 if label == b'zero' else 30
        answer = struct.pack('!2sHHIH', b'\xc0\x0c', qtype, 1, ttl, len(address)) + address
        count, flags = 1, 0x8180
        if label == b'short-dns':
            answer = (struct.pack('!2sHHIH', b'\xc0\x0c', 5, 1, 1, len(ALT)) + ALT
                      + rr(qtype, address, owner=ALT))
            count = 2
        elif label in (b'negative', b'nodata'):
            count, answer = 0, b''
            flags |= 3 if label == b'negative' else 0
        elif label == b'tc':
            flags |= 0x0200
        response = (data[:2] + struct.pack('!H', flags) + data[4:6] + struct.pack('!H', count)
                    + data[8:end] + answer + data[end:])
        # Keep short lifetimes independent of whole-second Date rounding.
        self.send_response_only(200)
        if label == b'old-date':
            self.send_header('Date', self.date_time_string(time.time()-60))
        self.send_header('Content-Type', 'application/dns-message')
        if label in (b'aged', b'short-http', b'already-stale'):
            self.send_header('Age', '31' if label == b'already-stale' else '7')
        controls = {b'short-http': 'public, max-age=8', b'nostore': 'public, no-store, max-age=30',
                    b'nocache': 'no-cache', b'private': 'private, max-age=30'}
        if label in controls:
            self.send_header('Cache-Control', controls[label])
        if label == b'vary':
            self.send_header('Vary', 'Cookie')
        elif label == b'vary-accept':
            self.send_header('Vary', 'Accept')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


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
            str(BINARY), '-p', str(cls.port), '-m', str(cls.metrics_port),
            '-s', f'http://user:fixture-log-secret@127.0.0.1:{cls.server.server_port}/dns-query'
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

    @staticmethod
    def tcp_frame(sock):
        def exact(n):
            result = bytearray()
            while len(result) < n:
                chunk = sock.recv(n - len(result))
                if not chunk:
                    raise AssertionError(f'unexpected TCP EOF: {len(result)}/{n}')
                result.extend(chunk)
            return bytes(result)
        length = struct.unpack('!H', exact(2))[0]
        return exact(length)

    @staticmethod
    def frame(payload):
        return struct.pack('!H', len(payload)) + payload

    def test_tcp_reuses_connection(self):
        before = self.metrics()
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.settimeout(4)
            for i in range(4):
                packet = query(ident=2000 + i)
                sock.sendall(self.frame(packet))
                answer = self.tcp_frame(sock)
                self.assertEqual(answer[:2], packet[:2])
                self.assertEqual(answer[2:4], b'\x81\x80')
        after = self.metrics()
        self.assertGreaterEqual(self.metric(after, 'dnsp_tcp_keepalive_queries_total') -
                                self.metric(before, 'dnsp_tcp_keepalive_queries_total'), 3)

    def test_tcp_source_limit_and_idle_pressure(self):
        rejected = 'dnsp_tcp_connections_rejected_total{reason="source_limit"}'
        capacity = 'dnsp_tcp_connections_rejected_total{reason="capacity"}'
        idle_timeouts = 'dnsp_tcp_idle_timeouts_total'
        before = self.metrics()
        with ExitStack() as sockets:
            def connect(source):
                return sockets.enter_context(socket.create_connection(
                    ('127.0.0.1', self.port), timeout=3, source_address=(source, 0)))

            first = connect('127.0.0.2')
            for _ in range(31):
                connect('127.0.0.2')
            self.assertEqual(connect('127.0.0.2').recv(1), b'')
            self.assertEqual(self.metric(self.metrics(), rejected), self.metric(before, rejected) + 1)
            control = connect('127.0.0.1')
            control.sendall(self.frame(QUERY))
            self.assertEqual(self.tcp_frame(control), make_response(QUERY))

            for source, count in (('127.0.0.3', 32), ('127.0.0.4', 32), ('127.0.0.5', 31)):
                for _ in range(count):
                    connect(source)
            self.assertEqual(connect('127.0.0.6').recv(1), b'')
            self.assertEqual(self.metric(self.metrics(), capacity), self.metric(before, capacity) + 1)
            # Under pressure the first idle socket expires before the 15s default.
            first.settimeout(6)
            self.assertEqual(first.recv(1), b'')
            self.assertGreater(self.metric(self.metrics(), idle_timeouts), self.metric(before, idle_timeouts))
            client = connect('127.0.0.6')
            client.sendall(self.frame(QUERY))
            self.assertEqual(self.tcp_frame(client), make_response(QUERY))

    def test_tcp_pipelined_frames_ordered(self):
        count = 8
        packets = [query(ident=3000+i) for i in range(count)]
        before = self.metrics()
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.settimeout(6)
            sock.sendall(b''.join(map(self.frame, packets)))
            for packet in packets:
                answer = self.tcp_frame(sock)
                self.assertEqual(answer[:2], packet[:2])
                self.assertEqual(answer[2:4], b'\x81\x80')
        after = self.metrics()
        self.assertGreaterEqual(self.metric(after, 'dnsp_tcp_pipeline_buffered_total') -
                                self.metric(before, 'dnsp_tcp_pipeline_buffered_total'), 1)

    def test_tcp_parallel_reused_sessions(self):
        errors = []
        def worker(index):
            try:
                packets = [query(ident=5000 + index * 10 + j) for j in range(5)]
                with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
                    sock.settimeout(6)
                    sock.sendall(b''.join(map(self.frame, packets)))
                    for packet in packets:
                        answer = self.tcp_frame(sock)
                        if answer[:2] != packet[:2]:
                            raise AssertionError((answer[:2], packet[:2]))
            except Exception as exc:
                errors.append((index, repr(exc)))
        jobs = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for job in jobs:
            job.start()
        for job in jobs:
            job.join(timeout=8)
        self.assertFalse(any(job.is_alive() for job in jobs), 'TCP clients hung')
        self.assertFalse(errors, errors)

    def test_tcp_half_close_preserves_last_reply(self):
        packets = [query(65010, ident=4000), query(ident=4001), query(ident=4002)]
        before = self.metrics()
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.settimeout(5)
            sock.sendall(b''.join(map(self.frame, packets)))
            sock.shutdown(socket.SHUT_WR)
            for packet in packets:
                answer = self.tcp_frame(sock)
                self.assertEqual(answer[:2], packet[:2])
            self.assertEqual(sock.recv(1), b'')
        after = self.metrics()
        self.assertGreater(self.metric(after, 'dnsp_tcp_half_closes_total'),
                           self.metric(before, 'dnsp_tcp_half_closes_total'))

    def test_tcp_rst_cancels_orphaned_upstream(self):
        for buffered in (False, True):
            with self.subTest(buffered=buffered):
                self.assert_rst_cancels_orphaned_upstream(buffered)

    def test_tcp_half_close_after_successor_length_cancels_request(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.sendall(self.frame(query(65010)) + self.frame(query())[:2])
            sock.shutdown(socket.SHUT_WR)
            self.assertEqual(sock.recv(1), b'')

    def assert_rst_cancels_orphaned_upstream(self, buffered):
        before = self.metrics()
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=4)
        try:
            frames = self.frame(query(qtype=65010, ident=4500))
            if buffered:
                frames += self.frame(query(ident=4501))
            sock.sendall(frames)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                stats = self.metrics()
                has_inflight = self.metric(stats, 'dnsp_queries_inflight') >= 1
                has_successor = self.metric(stats, 'dnsp_tcp_pipeline_buffered_total') > self.metric(
                    before, 'dnsp_tcp_pipeline_buffered_total')
                if has_inflight and (not buffered or has_successor):
                    break
                time.sleep(.01)
            else:
                self.fail('delayed TCP query never entered the upstream queue')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack('ii', 1, 0))  # abortive close / RST
        finally:
            sock.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            after = self.metrics()
            if self.metric(after, 'dnsp_tcp_cancelled_upstream_total') > self.metric(
                    before, 'dnsp_tcp_cancelled_upstream_total'):
                self.assertEqual(self.metric(after, 'dnsp_queries_inflight'), 0)
                break
            time.sleep(.02)
        else:
            self.fail('RST did not cancel the abandoned upstream request')

    def test_tcp_partial_framing(self):
        packet = query(ident=4230)
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.settimeout(4)
            framed = self.frame(packet)
            for piece in (framed[:1], framed[1:2], framed[2:5], framed[5:]):
                sock.sendall(piece)
                time.sleep(0.005)
            self.assertEqual(self.tcp_frame(sock)[:2], packet[:2])

    def test_tcp_closes_invalid_frames_before_forwarding(self):
        response = make_response(QUERY)
        upstream = 'dnsp_upstream_requests_total'
        for frame in (struct.pack('!H', 11), self.frame(response)):
            with self.subTest(frame=frame), socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
                before = self.metric(self.metrics(), upstream)
                client.sendall(frame)
                self.assertEqual(client.recv(1), b'')
                self.assertEqual(self.metric(self.metrics(), upstream), before)
        self.assertEqual(self.tcp(QUERY), response)

    def test_tcp_deadlines(self):
        # A dedicated instance allows shorter client deadlines.
        port, metrics_port = unused_ports()
        with tempfile.TemporaryFile(mode='w+b') as logfile:
            proc = subprocess.Popen([
                str(BINARY), '-p', str(port), '-m', str(metrics_port),
                '--tcp-idle-ms', '250', '--tcp-io-ms', '250',
                '-s', f'http://127.0.0.1:{self.server.server_port}/dns-query'
            ], stdout=subprocess.DEVNULL, stderr=logfile)
            try:
                deadline = time.monotonic() + 5
                sock = None
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        break
                    try:
                        sock = socket.create_connection(('127.0.0.1', port), timeout=.2)
                        break
                    except OSError:
                        time.sleep(.05)
                self.assertIsNotNone(sock, 'proxy did not open the TCP listener')
                with sock:
                    sock.settimeout(3)
                    self.assertEqual(sock.recv(1), b'')  # idle connection closed
                with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                    delayed = query(qtype=65010, ident=4231)
                    sock.sendall(self.frame(delayed))
                    self.assertEqual(self.tcp_frame(sock)[:2], delayed[:2])
                    self.assertEqual(sock.recv(1), b'')  # idle only after response
                with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
                    sock.settimeout(.04)
                    for byte in self.frame(query())[:20]:
                        try:
                            sock.sendall(bytes([byte]))
                            self.assertEqual(sock.recv(1), b'')
                            break
                        except socket.timeout:
                            continue
                        except ConnectionResetError:
                            break
                    else:
                        self.fail('partial reads kept the frame assembly deadline alive')
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait(timeout=3)

    def test_reject_invalid_tcp_deadlines(self):
        for option in ('--tcp-idle-ms', '--tcp-io-ms'):
            for raw in ('0', '99', '600001', '-1', 'anything'):
                with self.subTest(option=option, raw=raw):
                    proc = subprocess.run([str(BINARY), option, raw],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                          timeout=2)
                    self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_reject_invalid_connection_limits(self):
        for option, too_large in (('--tcp-max-per-source', '129'), ('--max-host-connections', '17')):
            for raw in ('0', too_large, 'invalid'):
                with self.subTest(option=option, raw=raw):
                    result = subprocess.run([str(BINARY), option, raw], capture_output=True, timeout=3)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(f'invalid {option}'.encode(), result.stderr)

    def metrics(self, port=None):
        c = http.client.HTTPConnection('127.0.0.1', port or self.metrics_port, timeout=4)
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

    def test_coalesces_udp_queries_with_bounded_waiters(self):
        for label, expected_rcode in ((b'coalesce', 0), (b'coalesce-fail', 2)):
            with self.subTest(label=label):
                gate = threading.Event()
                self.server.coalesce_gate = gate
                before = self.metrics()
                upstream = 'dnsp_upstream_requests_total'
                joined = 'dnsp_udp_queries_coalesced_total'

                def packet(qtype, ident):
                    data = query(qtype, ident=ident)
                    return data[:12] + bytes([len(label)]) + label + data[16:]

                def send(sock, qtype, ident):
                    sock.sendto(packet(qtype, ident), ('127.0.0.1', self.port))

                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
                        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
                    first.settimeout(4)
                    second.settimeout(4)
                    send(first, 1, 100)
                    ids = range(101, 111) if expected_rcode == 0 else (101,)
                    for ident in ids:
                        send(second, 1, ident)
                    if expected_rcode == 0:
                        send(second, 1, 101)  # Same peer and ID is a retransmit.
                        send(first, 28, 200)  # A distinct QTYPE needs its own transfer.
                    want_upstream, want_joined = (3, 10) if expected_rcode == 0 else (1, 1)
                    try:
                        deadline = time.monotonic()+2
                        while time.monotonic()<deadline:
                            after = self.metrics()
                            if (self.metric(after, joined)-self.metric(before, joined) == want_joined and
                                self.metric(after, upstream)-self.metric(before, upstream) == want_upstream):
                                break
                            time.sleep(.01)
                        else:
                            self.fail('expected UDP queries to join before the upstream replied')
                    finally:
                        gate.set()
                    for sock, expected_ids in ((first, (100, 200) if expected_rcode == 0 else (100,)),
                                               (second, ids)):
                        actual_ids = []
                        for _ in expected_ids:
                            reply = sock.recv(4096)
                            actual_ids.append(struct.unpack_from('!H', reply)[0])
                            self.assertEqual(reply[3]&15, expected_rcode)
                        self.assertCountEqual(actual_ids, expected_ids)
                        sock.settimeout(.1)
                        with self.assertRaises(socket.timeout):
                            sock.recv(4096)

    def test_coalesced_no_store_response_retries_waiter(self):
        gate = threading.Event()
        self.server.coalesce_gate = gate
        before = self.metrics()
        label = b'coalesce-nostore'
        upstream = 'dnsp_upstream_requests_total'
        joined = 'dnsp_udp_queries_coalesced_total'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            try:
                for sock, ident in ((first, 1), (second, 2)):
                    sock.settimeout(4)
                    q = query(ident=ident)
                    sock.sendto(q[:12]+bytes([len(label)])+label+q[16:], ('127.0.0.1', self.port))
                deadline = time.monotonic()+2
                while time.monotonic()<deadline:
                    after = self.metrics()
                    if self.metric(after, joined)-self.metric(before, joined) == 1:
                        break
                    time.sleep(.01)
                else:
                    self.fail('second query did not join')
                self.assertEqual(self.metric(after, upstream)-self.metric(before, upstream), 1)
            finally:
                gate.set()
            for sock, ident in ((first, 1), (second, 2)):
                reply = sock.recv(4096)
                self.assertEqual(struct.unpack_from('!H', reply)[0], ident)
                self.assertEqual(reply[3]&15, 0)
        self.assertEqual(self.metric(self.metrics(), upstream)-self.metric(before, upstream), 2)

    def test_invalid_udp_does_not_kill(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'\0\1', ('127.0.0.1', self.port))
        out = self.udp(query())
        self.assertEqual(out[:2], QUERY[:2])
        self.assertEqual(out[2:4], b'\x81\x80')
        self.assertEqual(out[12:], QUERY[12:])

    def test_udp_overload_rejects_new_work_and_recovers(self):
        gate = threading.Event()
        self.server.coalesce_gate = gate
        # EDNS keeps each request independent while the fixture holds its reply.
        template = query(edns=1232)
        packet = template[:12] + b'\x08coalesce' + template[16:]
        target = ('127.0.0.1', self.port)
        inflight = 'dnsp_queries_inflight'
        requests = 'dnsp_upstream_requests_total'
        overload = 'dnsp_overload_total'
        capacity = 128
        before = self.metrics()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as held:
            held.settimeout(4)
            held.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
            try:
                deadline = time.monotonic() + 2
                # Confirm each batch before sending more so the socket queue has room.
                for start in range(0, capacity, 16):
                    end = min(start + 16, capacity)
                    for ident in range(start, end):
                        held.sendto(struct.pack('!H', ident) + packet[2:], target)
                    while self.metric(self.metrics(), inflight) != end:
                        self.assertLess(time.monotonic(), deadline, 'upstream request slots did not fill')
                        time.sleep(.01)
                extra_id = struct.pack('!H', capacity)
                rejected = self.udp(extra_id + packet[2:])
                self.assertEqual(rejected[:2], extra_id)
                self.assertEqual(rejected[3] & 15, 2)
                after = self.metrics()
                self.assertEqual(self.metric(after, overload), self.metric(before, overload) + 1)
                self.assertEqual(self.metric(after, requests), self.metric(before, requests) + capacity)
            finally:
                gate.set()
            completed = {struct.unpack_from('!H', held.recv(4096))[0] for _ in range(capacity)}
            self.assertEqual(completed, set(range(capacity)))
        self.assertEqual(self.metric(self.metrics(), inflight), 0)
        self.assertEqual(self.udp(QUERY), make_response(QUERY))

    def test_udp_input_bounds_and_valid_prefix(self):
        self.assertEqual(len(self.udp(sized_query(1232))), 1232)
        for size in (1233, 4096, 4097, 65507):
            with self.subTest(size=size):
                before = self.metrics()
                packet = sized_query(size)
                self.assertEqual(len(packet), size)
                out = self.udp(packet)
                self.assertTrue(out[2] & 2)
                self.assertEqual(out[3] & 15, 0)
                self.assertEqual(out[10:12], b'\0\1')
                after = self.metrics()
                self.assertEqual(self.metric(after, 'dnsp_upstream_requests_total'),
                                 self.metric(before, 'dnsp_upstream_requests_total') + 1)
        before = self.metrics()
        out = self.udp(sized_query(4096) + b'x')
        self.assertEqual(out[3] & 15, 1)
        after = self.metrics()
        self.assertEqual(self.metric(after, 'dnsp_upstream_requests_total'),
                         self.metric(before, 'dnsp_upstream_requests_total'))

    def test_tcp_and_doh_wire_limit(self):
        packet = sized_query(65535)
        self.assertEqual(len(packet), 65535)
        self.assertEqual(self.tcp(packet), make_response(packet))
        too_large = self.tcp(query(65020, edns=4096))
        self.assertEqual(too_large[3] & 15, 2)

    def test_question_name_wire_limit(self):
        prefix = b'\x3f' + b'a'*63
        max_name = prefix*3 + b'\x3d' + b'b'*61 + b'\0'
        question = QUERY[:12] + max_name + QUERY[-4:]
        self.assertEqual(len(max_name), 255)
        self.assertEqual(self.udp(question), make_response(question))
        too_long = QUERY[:12] + prefix*3 + b'\x3e' + b'b'*62 + b'\0' + QUERY[-4:]
        out = self.udp(too_long)
        self.assertEqual(out[3] & 15, 1)
        self.assertEqual(len(out), 12)

    def test_max_length_name_with_compressed_answer(self):
        base = query(28)
        name = b'\x01a'*127 + b'\0'
        packet = base[:12] + name + base[-4:]
        expected = make_response(packet)
        owner = question_end(packet)
        self.assertEqual(expected[owner:owner+2], b'\xc0\x0c')
        self.assertEqual(self.udp(packet), expected)
        self.assertEqual(self.tcp(packet), expected)

    def test_message_wide_compression_budget(self):
        upstream = 'dnsp_upstream_requests_total'
        for chained in (False, True):
            with self.subTest(chained=chained):
                packet = bytearray(query())
                packet[10:12] = struct.pack('!H', 32)
                target = 12
                for _ in range(32):
                    owner = struct.pack('!H', 0xc000 | target)
                    if chained:
                        target = len(packet)
                    packet += rr(65280, b'', owner)
                before = self.metric(self.metrics(), upstream)
                answer = self.udp(packet)
                if chained:
                    self.assertEqual(answer[3] & 15, 1)
                    self.assertEqual(self.metric(self.metrics(), upstream), before)
                else:
                    self.assertEqual(answer, make_response(packet))
                    self.assertEqual(self.metric(self.metrics(), upstream), before + 1)

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
        packet = bytearray(query(65016, edns=600))
        packet[len(QUERY)+7] = 0x80  # DO
        out = self.udp(packet)
        self.assertTrue(out[2] & 0x02)
        self.assertEqual(out[6:12], b'\0\0\0\0\0\1')
        self.assertEqual(out[len(QUERY):], bytes.fromhex('0000291000010080000000'))

    def test_local_servfail_keeps_edns(self):
        for transport in (self.udp, self.tcp):
            with self.subTest(transport=transport.__name__):
                out = transport(query(65009, edns=1232))
                self.assertEqual(out[3] & 15, 2)
                self.assertEqual(out[10:12], b'\0\1')
                self.assertEqual(out[len(QUERY):], bytes.fromhex('0000291000000000000000'))

    def test_udp_edns_large_advertisement_capped(self):
        packet = query(65006, edns=65535)
        out = self.udp(packet)
        self.assertTrue(out[2] & 0x02)
        self.assertLessEqual(len(out), 1232)
        upstream = f'http://127.0.0.1:{self.server.server_port}/dns-query'
        full = self.isolated_udp(upstream, '--udp-reply-max', '4096', env=os.environ, packet=packet)
        self.assertEqual(full, make_response(packet))
        self.assertEqual(self.tcp(packet), full)

    def test_udp_edns_over_max_truncates(self):
        out = self.udp(query(65007, edns=65535))
        self.assertTrue(out[2] & 0x02)
        self.assertLessEqual(len(out), 1232)

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
        for typ in (65002, 65003, 65004, 65005, 65011, 65012):
            with self.subTest(typ=typ):
                out = self.udp(query(typ))
                self.assertEqual(out[3] & 15, 2)  # SERVFAIL
                self.assertEqual(out[6:12], b'\0' * 6)

    def test_known_and_unknown_rr_rdata(self):
        for typ, rdata in ((65013, b'\xc0\x0c'), (65014, b'\xc0\x04\xff')):
            with self.subTest(typ=typ):
                out = self.udp(query(typ))
                self.assertEqual(out[3] & 15, 0)
                self.assertEqual(out[6:8], b'\0\1')
                self.assertTrue(out.endswith(rdata))

    def test_malformed_edns_options(self):
        for options in (b'\x00', struct.pack('!HH', 65000, 2) + b'x'):
            with self.subTest(options=options):
                packet = edns_options(query(edns=1232), options)
                for transport in (self.udp, self.tcp):
                    out = transport(packet)
                    self.assertEqual(out[3] & 15, 1)
                    self.assertEqual(out[10:12], b'\0\1')
                    self.assertEqual(len(out), len(QUERY)+11)
        opaque = edns_options(query(edns=1232), struct.pack('!HH', 65000, 1) + b'x')
        self.assertEqual(self.udp(opaque)[len(QUERY):], opaque[len(QUERY):])
        out = self.udp(query(65015, edns=1232))
        self.assertEqual(out[3] & 15, 2)
        self.assertEqual(out[10:12], b'\0\1')

    def test_malformed_edns(self):
        q = bytearray(query(edns=1232))
        q[10:12] = b'\0\2'  # lies about the number of additional RRs
        for packet in (q, q + q[-11:]):
            out = self.udp(packet)
            self.assertEqual(out[3] & 15, 1)
            self.assertEqual(out[10:12], b'\0\1')
        self.assertTrue(self.udp(query())[2] & 0x80)

    def test_questionless_cookie_query_and_upstream_errors(self):
        cookie = bytearray(query(edns=1232))
        cookie[4:6] = b'\0\0'
        cookie = edns_options(cookie[:12] + cookie[len(QUERY):],
                              struct.pack('!HH', 10, 8) + b'12345678')
        self.assertEqual(self.udp(cookie), make_response(cookie))
        self.assertEqual(self.tcp(cookie), make_response(cookie))
        header = cookie[:10] + b'\0\0'
        self.assertEqual(self.tcp(header), make_response(header))
        for typ in (65018, 65019):
            packet = query(typ, edns=1232)
            self.assertEqual(self.udp(packet), make_response(packet))
        self.assertEqual(self.udp(query(65023))[3] & 15, 2)

    def test_multiple_questions_and_unsupported_operations(self):
        multi = bytearray(QUERY + QUERY[12:])
        multi[4:6] = b'\0\2'
        out = self.udp(multi)
        self.assertEqual(out[3] & 15, 1)
        self.assertEqual(len(out), 12)
        self.assertEqual(out[4:6], b'\0\0')

        update = bytearray(QUERY)
        update[2] = 5 << 3
        out = self.tcp(update)
        self.assertEqual(out[2] & 0x78, 5 << 3)
        self.assertEqual(out[3] & 15, 4)
        ixfr = bytearray(query(251))
        ixfr[8:10] = b'\0\1'
        ixfr += rr(6, SOA)
        for packet in (query(252), ixfr):
            self.assertEqual(self.tcp(packet)[3] & 15, 4)

    def test_local_format_error_preserves_tcp_pipeline(self):
        bad = edns_options(query(edns=1232, ident=0x4444), b'\0')
        good = query(28, ident=0x4445)
        with socket.create_connection(('127.0.0.1', self.port), timeout=4) as sock:
            sock.sendall(self.frame(bad) + self.frame(good))
            sock.shutdown(socket.SHUT_WR)
            out = self.tcp_frame(sock)
            self.assertEqual(out[:2], bad[:2])
            self.assertEqual(out[3] & 15, 1)
            self.assertEqual(self.tcp_frame(sock), make_response(good))
            self.assertEqual(sock.recv(1), b'')

    def test_edns_version_and_udp_minimum(self):
        packet = bytearray(query(65022, edns=1232))
        packet[len(QUERY)+6] = 1  # ask upstream for EDNS version 1
        self.assertEqual(self.udp(packet), make_response(packet))
        out = self.udp(query(65001, edns=128))
        self.assertTrue(out[2] & 2)
        self.assertLessEqual(len(out), 512)

    def test_supported_record_and_question_formats(self):
        for typ in (*RR_FIXTURES, 255):
            with self.subTest(typ=typ):
                packet = query(typ)
                expected = make_response(packet)
                self.assertEqual(self.udp(packet), expected)
                self.assertEqual(self.tcp(packet), expected)
        chaos = bytearray(query(16))
        chaos[-2:] = b'\0\x03'  # CHAOS class
        self.assertEqual(self.udp(chaos), make_response(chaos))
        dnssec = bytearray(query(48, edns=1232))
        dnssec[3] |= 0x10  # CD
        dnssec[len(QUERY)+7] |= 0x80  # DO
        out = self.udp(dnssec)
        self.assertEqual(out, make_response(dnssec))
        self.assertEqual(out[3] & 0x30, 0x30)  # upstream AD plus CD

    def test_doh_media_type_accepts_parameter_whitespace(self):
        packet = query(65021)
        self.assertEqual(self.udp(packet), make_response(packet))

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

    def test_metrics_handles_partial_and_invalid_requests(self):
        target = ('127.0.0.1', self.metrics_port)
        with socket.create_connection(target, timeout=3) as pending:
            pending.sendall(b'GET /metrics HTTP/1.1\r\n')
            for request in (b'GET /other HTTP/1.1\r\n\r\n', b'x' * 512):
                with self.subTest(size=len(request)), socket.create_connection(target, timeout=3) as client:
                    client.sendall(request)
                    self.assertEqual(client.recv(1), b'')
            self.assertIn('dnsp_queries_inflight', self.metrics())
            self.assertFalse(select([pending], [], [], 0)[0])

            pending.sendall(b'\r\n')
            with http.client.HTTPResponse(pending) as response:
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertIn(b'dnsp_queries_inflight', response.read())

    def test_sigusr1_report(self):
        before = self.metrics()
        for exchange, packet in ((self.udp, query()), (self.tcp, query(65024))):
            self.assertEqual(exchange(packet), make_response(packet))
        self.assertEqual(self.udp(query(65002))[3] & 15, 2)  # Local SERVFAIL.
        self.assertEqual(self.udp(query(65018))[3] & 15, 1)  # Upstream FORMERR.
        self.assertTrue(self.udp(query(65019))[2] & 2)       # Upstream TC.
        self.assertTrue(self.udp(query(65001))[2] & 2)       # Local TC.
        self.assertEqual(self.udp(query(65022, edns=1232))[-6], 1)  # BADVERS.

        after = self.metrics()
        satisfied = 'dnsp_queries_satisfied_total'
        self.assertEqual(self.metric(after, satisfied) - self.metric(before, satisfied), 2)

        fd = self.proxy_log.fileno()
        start = os.fstat(fd).st_size
        self.process.send_signal(signal.SIGUSR1)
        deadline = time.monotonic() + 3
        log = ''
        while time.monotonic() < deadline and self.process.poll() is None:
            log = os.pread(fd, os.fstat(fd).st_size - start, start).decode()
            if log.endswith('\n') and 'event=stats ' in log:
                break
            time.sleep(.02)
        else:
            self.fail(f'SIGUSR1 report missing (exit={self.process.poll()}): {log!r}')

        line = next(line for line in log.splitlines() if 'event=stats ' in line)
        report = dict(field.split('=', 1) for field in line.split())
        self.assertEqual(int(report['queries_satisfied']), self.metric(after, satisfied))
        self.assertEqual(int(report['upstream_failed']), self.metric(after, 'dnsp_upstream_failures_total'))
        self.assertEqual(int(report['udp_truncated']), self.metric(after, 'dnsp_truncated_responses_total'))
        self.assertEqual(int(report['port']), self.port)
        self.assertEqual(int(report['metrics_port']), self.metrics_port)
        self.assertEqual(int(report['inflight']), 0)
        self.assertGreater(int(report['uptime_ms']), 0)
        self.assertNotIn('fixture-log-secret', log)
        self.assertNotIn('google.com', log)
        self.assertEqual(self.udp(query()), make_response(query()))

    def test_accepts_successful_http_status_with_dns_body(self):
        out = self.udp(query(65017))
        self.assertEqual(out[2:4], b'\x81\x80')

    def test_failure_logs_are_redacted_and_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.udp(query(65009))[3] & 15, 2)
        self.assertEqual(self.udp(query(65008))[3] & 15, 2)
        self.proxy_log.seek(0)
        log = self.proxy_log.read().decode()
        self.assertNotIn('fixture-log-secret', log)
        self.assertNotIn('google.com', log)
        self.assertEqual(log.count('event=upstream_http_status'), 1)
        self.assertIn('event=upstream_http_status transport=udp curl_code=0 http_status=502', log)
        self.assertIn('upstream=primary proxy_connect_status=0', log)
        self.assertIn('event=upstream_content_type', log)

    def test_version_reports_libcurl_build_and_runtime(self):
        result = subprocess.run([str(BINARY), '--version'], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'^dnsp-modern (?:[0-9]+\.[0-9]+\.[0-9]+|dev)\n')
        for field in ('libcurl_build', 'libcurl_runtime', 'tls_backend'):
            self.assertRegex(result.stdout, rf'(?m)^{field}=\S')
        for field in ('http2', 'http3', 'prefer_h3'):
            self.assertRegex(result.stdout, rf'(?m)^{field}=(?:yes|no)$')

    def test_listener_failure_reports_role(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            result = subprocess.run([str(BINARY), '-p', str(port)],
                                    capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f'event=listener_failed role=dns_tcp port={port}'.encode(), result.stderr)

    def test_reject_insecure_remote_url_and_bad_port(self):
        for args in (['-s', 'http://127.0.0.1:80@not-local.example/dns-query'],
                     ['-p', '99999999999999999999999999']):
            with self.subTest(args=args):
                r = subprocess.run([str(BINARY)] + args,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=2)
                self.assertEqual(r.returncode, 2, r.stderr)

    def isolated_udp(self, upstream, *args, env, packet=QUERY):
        port, _ = unused_ports()
        with tempfile.TemporaryFile() as logfile:
            proc = subprocess.Popen([str(BINARY), '-p', str(port), '-s', upstream, *args],
                                    env=env, stderr=logfile)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and proc.poll() is None:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    logfile.seek(0)
                    self.fail(f'isolated proxy failed to start: {logfile.read()!r}')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(4)
                    sock.sendto(packet, ('127.0.0.1', port))
                    return sock.recv(4096)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                logfile.seek(0)
                self.assertEqual(proc.returncode, 0, logfile.read())

    def test_doh_deadlines(self):
        upstream = f'http://127.0.0.1:{self.server.server_port}/dns-query'
        packet = query(65010)  # The upstream waits 700 ms before responding.
        for timeout in (200, 3000):
            with self.subTest(timeout=timeout):
                answer = self.isolated_udp(upstream, '--doh-connect-ms', '100',
                                           '--doh-timeout-ms', str(timeout),
                                           env=os.environ, packet=packet)
                self.assertEqual(answer[:2], packet[:2])
                self.assertEqual(answer[3] & 15, 2 if timeout == 200 else 0)

    def test_help_and_invalid_doh_deadlines(self):
        for option in ('-h', '--help'):
            result = subprocess.run([str(BINARY), option], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            for flag in (b'--bootstrap-address', b'--tcp-io-ms', b'--doh-connect-ms', b'--doh-timeout-ms'):
                self.assertIn(flag, result.stdout)
        for args in (('--doh-connect-ms',), ('--doh-connect-ms', '99'),
                     ('--doh-timeout-ms', '60001'), ('--doh-timeout-ms', '-1'),
                     ('--doh-timeout-ms', '1000')):
            with self.subTest(args=args):
                result = subprocess.run([str(BINARY), *args], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(args[0].encode(), result.stderr)

    def test_compression_cannot_read_ttl_bytes(self):
        for typ in (65025, 65026, 65027):
            with self.subTest(typ=typ):
                q = query(typ)
                reply = self.udp(q)
                self.assertEqual(reply[3] & 15, 2)
                self.assertEqual(reply[12:], q[12:])

        q = query(65028)
        reply = self.udp(q)
        self.assertEqual(reply[3] & 15, 0)
        self.assertEqual(reply[len(q):], rr(17, b'\xc0\x0c' * 2, ttl=59))

    def test_forwarded_age_without_cache_hit(self):
        upstream = HTTP(('127.0.0.1', 0), CacheDoH)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        url = f'http://127.0.0.1:{upstream.server_port}/dns-query'
        q = query(28, edns=1232)
        packet = q[:12] + b'\x04aged' + q[16:]
        with_option = edns_options(packet, padding_option(4))
        for args, data in (((), packet), (('--cache-entries', '1'), with_option)):
            with self.subTest(args=args):
                reply = self.isolated_udp(url, *args, env=os.environ, packet=data)
                self.assertEqual(struct.unpack_from('!I', reply, question_end(reply)+6)[0], 23)
                self.assertTrue(reply.endswith(data[question_end(data):]))

    def test_answer_cache(self):
        upstream = HTTP(('127.0.0.1', 0), CacheDoH)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        port, metrics_port = unused_ports()

        def packet(name, ident=0x1234, qtype=1, edns=None):
            base = query(qtype, edns, ident)
            return base[:12] + bytes([len(name)]) + name + base[16:]

        def exchange(data, tcp=False):
            if tcp:
                with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                    sock.sendall(self.frame(data))
                    return self.tcp_frame(sock)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(data, ('127.0.0.1', port))
                return sock.recv(4096)

        def counter(name):
            return self.metric(self.metrics(metrics_port), f'dnsp_{name}_total')

        def ttl(reply):
            return struct.unpack_from('!I', reply, question_end(reply)+6)[0]

        with tempfile.TemporaryFile() as log, subprocess.Popen([
            str(BINARY), '-p', str(port), '-m', str(metrics_port), '--cache-entries', '1',
            '-s', f'http://127.0.0.1:{upstream.server_port}/dns-query'
        ], stderr=log) as proc:
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and proc.poll() is None:
                    try:
                        self.metrics(metrics_port)
                        break
                    except OSError:
                        time.sleep(.02)
                else:
                    log.seek(0)
                    self.fail(f'cache proxy failed to start: {log.read()!r}')

                first = exchange(packet(b'aged', qtype=28, edns=1232))
                self.assertEqual(ttl(first), 23)
                time.sleep(1.05)
                hit = exchange(packet(b'aged', ident=0x2222, qtype=28, edns=1232), tcp=True)
                self.assertEqual(hit[:2], b'\x22\x22')
                self.assertEqual(hit[-11:], first[-11:])  # OPT contents survive replay.
                self.assertGreater(ttl(hit), 0)
                self.assertLess(ttl(hit), 23)
                self.assertEqual(counter('cache_hits'), 1)
                self.assertEqual(counter('cache_misses'), 1)
                self.assertEqual(counter('upstream_requests'), 1)

                data = packet(b'vary-accept')
                exchange(data)
                exchange(data)
                self.assertEqual(counter('upstream_requests'), 2)
                self.assertEqual(counter('cache_hits'), 2)

                # Exact-key match protects case, flags and EDNS parameters.
                exchange(packet(b'Aged', qtype=28, edns=1232))
                exchange(packet(b'Aged', qtype=28, edns=1400))
                exchange(packet(b'aged', qtype=28, edns=1232))
                self.assertEqual(counter('upstream_requests'), 5)  # One-slot eviction.

                for label in (b'short-dns', b'short-http'):
                    with self.subTest(expiration=label):
                        data = packet(label)
                        exchange(data)
                        hits = counter('cache_hits')
                        exchange(data)
                        self.assertEqual(counter('cache_hits'), hits+1)
                        before = counter('upstream_requests')
                        time.sleep(1.1)
                        exchange(data)
                        self.assertEqual(counter('upstream_requests'), before+1)

                option = edns_options(packet(b'opts', edns=1232), padding_option(4))
                do = bytearray(packet(b'dnssec', edns=1232))
                do[-4] |= 0x80
                cd = bytearray(packet(b'checking'))
                cd[3] |= 0x10
                bypass = (b'zero', b'negative', b'nodata', b'tc', b'already-stale', b'old-date',
                          b'nostore', b'nocache', b'private', b'vary')
                for data in (*map(packet, bypass), option, do, cd):
                    before = counter('upstream_requests')
                    exchange(data)
                    exchange(data)
                    self.assertEqual(counter('upstream_requests'), before+2, data)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                log.seek(0)
                self.assertEqual(proc.returncode, 0, log.read())

    def test_loopback_http_bypasses_ambient_proxy(self):
        # Hold an unused port so the inherited proxy cannot complete a connection.
        with socket.socket() as dead_proxy:
            dead_proxy.bind(('127.0.0.1', 0))
            proxy = f'http://127.0.0.1:{dead_proxy.getsockname()[1]}'
            env = dict(os.environ, http_proxy=proxy, no_proxy='', NO_PROXY='')
            answer = self.isolated_udp(f'http://127.0.0.1:{self.server.server_port}/dns-query', env=env)
        self.assertEqual(answer[2:4], b'\x81\x80')

    def test_invalid_upstream_http_preference(self):
        for args in (['--upstream-http'], ['--upstream-http='], ['--upstream-http', 'h3-only']):
            with self.subTest(args=args):
                proc = subprocess.run([str(BINARY), *args], timeout=3,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn(b'--upstream-http requires auto or prefer-h3', proc.stderr)

    @unittest.skipUnless(shutil.which('openssl'), 'openssl required to generate a local TLS certificate')
    def test_bootstrap_address_connects_directly_and_verifies_hostname(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = str(Path(tmp)/'cert.pem'), str(Path(tmp)/'key.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=dnsp-bootstrap.invalid',
                            '-addext', 'subjectAltName=DNS:dnsp-bootstrap.invalid',
                            '-out', cert, '-keyout', key], check=True, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            class TLSDoH(DoH):
                protocol_version = 'HTTP/1.0'  # close the fixture after each reply

                def handle(self):
                    try:
                        super().handle()
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # A rejected certificate can close before HTTP starts.

                def do_POST(self):
                    data = self.rfile.read(int(self.headers['Content-Length']))
                    self.server.received.append(data)
                    reply = make_response(data)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/dns-message')
                    self.send_header('Content-Length', str(len(reply)))
                    self.end_headers()
                    self.wfile.write(reply)

            with HTTP(('127.0.0.1', 0), TLSDoH) as server:
                server.received = []
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    env = dict(os.environ, https_proxy='http://127.0.0.1:1', no_proxy='', NO_PROXY='')
                    for host, rcode in (('dnsp-bootstrap.invalid', 0), ('wrong.invalid', 2)):
                        with self.subTest(host=host):
                            url = f'https://{host}:{server.server_port}/dns-query'
                            answer = self.isolated_udp(url, '--ca-file', cert,
                                                       '--bootstrap-address', '127.0.0.1', env=env)
                            self.assertEqual(answer[3] & 15, rcode)
                    url = f'https://dnsp-bootstrap.invalid:{server.server_port}/dns-query'
                    option = struct.pack('!HH', 65000, 2) + b'ok'
                    unpadded = edns_options(query(edns=1232), option)
                    padded = edns_options(unpadded[:-len(option)], option + padding_option(9))
                    expected = edns_options(unpadded[:-len(option)],
                                            option + padding_option(128 - len(unpadded)))
                    for packet, enabled, upstream in ((unpadded, False, unpadded),
                                                       (unpadded, True, expected),
                                                       (padded, True, padded),
                                                       (QUERY, True, QUERY)):
                        with self.subTest(enabled=enabled, size=len(packet)):
                            args = ['--edns-padding'] if enabled else []
                            answer = self.isolated_udp(url, '--ca-file', cert,
                                                       '--bootstrap-address', '127.0.0.1',
                                                       *args, env=env, packet=packet)
                            self.assertEqual(server.received[-1], upstream)
                            self.assertEqual(answer, make_response(packet))
                finally:
                    server.shutdown()
                    thread.join(timeout=3)

    def test_reject_invalid_bootstrap_options(self):
        for args in (['--bootstrap-address'],
                     ['--bootstrap-address', 'resolver.invalid'],
                     ['--bootstrap-address', '127.0.0.1', '-s', 'http://127.0.0.1/dns-query']):
            with self.subTest(args=args):
                proc = subprocess.run([str(BINARY), *args], timeout=3,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_sequential_curl_reuse(self):
        before = self.metrics()
        for _ in range(5):
            self.udp(query())
        after = self.metrics()
        self.assertGreater(self.metric(after, 'dnsp_upstream_reused_requests_total'),
                           self.metric(before, 'dnsp_upstream_reused_requests_total'))
        self.assertEqual(self.metric(after, 'dnsp_upstream_easy_handles_reused_total')
                         - self.metric(before, 'dnsp_upstream_easy_handles_reused_total'), 5)


class FailoverDoH(DoH):
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass  # A timed-out or rejected connection can close mid-request.

    def do_CONNECT(self):
        self.server.tunnels.append(self.path)
        self.send_error(403)

    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        mode = self.server.mode
        self.server.received.append(data)
        self.server.started.set()
        if mode == 'stall':
            self.server.release.wait(5)
            return
        if mode == 'http503':
            self.send_error(503)
            return
        end = question_end(data)
        rcode = {'nxdomain': 3, 'refused': 5, 'servfail': 2}.get(mode, 0)
        record = rr(1, self.server.address) if not rcode else b''
        response = (data[:2] + struct.pack('!HHH', 0x8180 | rcode, 1, int(bool(record))) +
                    data[8:end] + record + data[end:])
        if mode == 'invalid':
            response = b'invalid'
        self.send_response_only(403 if mode == 'partial403' else 200)
        self.send_header('Content-Type', 'application/dns-message')
        if mode == 'nostore':
            self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        if mode in ('partial', 'partial403'):
            self.wfile.write(response[:7])
            self.close_connection = True
        else:
            self.wfile.write(response)


class FailoverHTTP(HTTP):
    def get_request(self):
        if self.accept_delay:
            time.sleep(self.accept_delay)
        return super().get_request()


class FailoverTests(unittest.TestCase):
    @contextmanager
    def endpoint(self, mode='answer', address=b'\xc0\x00\x02\x01', tls=None, accept_delay=0):
        with FailoverHTTP(('127.0.0.1', 0), FailoverDoH) as server:
            server.mode = mode
            server.address = address
            server.accept_delay = accept_delay
            server.received = []
            server.tunnels = []
            server.started = threading.Event()
            server.release = threading.Event()
            if tls:
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={'poll_interval': .02}, daemon=True)
            thread.start()
            try:
                yield server
            finally:
                server.release.set()
                server.shutdown()
                thread.join(timeout=3)

    @staticmethod
    def url(server):
        return f'http://127.0.0.1:{server.server_port}/dns-query'

    @contextmanager
    def proxy(self, primary, backup, *args, env=None, connect_ms=200, total_ms=1600):
        port, metrics = unused_ports()
        command = [str(BINARY), '-p', str(port), '-m', str(metrics), '-s', primary,
                   '--backup-upstream', backup, '--doh-connect-ms', str(connect_ms),
                   '--doh-timeout-ms', str(total_ms), *args]
        with tempfile.TemporaryFile() as log, subprocess.Popen(command, stderr=log, env=env) as proc:
            try:
                deadline = time.monotonic() + float(os.environ.get('DNSP_TEST_STARTUP_TIMEOUT', '12'))
                while time.monotonic() < deadline and proc.poll() is None:
                    try:
                        with socket.create_connection(('127.0.0.1', metrics), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    log.seek(0)
                    self.fail(f'proxy did not start: {log.read()!r}')
                yield port, metrics
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
                log.seek(0)
                diagnostic = log.read(8192).decode('utf-8', errors='replace')
                if sys.exc_info()[0] and diagnostic:
                    print(f'{BINARY} stderr:\n{diagnostic}', file=sys.stderr, end='')
                self.assertEqual(proc.returncode, 0, diagnostic)

    @staticmethod
    def udp(port, packet=QUERY):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.sendto(packet, ('127.0.0.1', port))
            return sock.recv(4096)

    def test_partial_transfer_retries_and_keeps_backup_out_of_cache(self):
        with self.endpoint('partial') as primary, self.endpoint(address=b'\xc0\x00\x02\x02') as backup:
            with self.proxy(self.url(primary), self.url(backup), '--cache-entries', '16') as (port, metrics):
                self.assertTrue(self.udp(port).endswith(backup.address))
                primary.mode = 'answer'
                self.assertTrue(self.udp(port, query(ident=42)).endswith(primary.address))
                stats = Tests.metrics(self, metrics)
                for metric, expected in (
                    ('dnsp_upstream_endpoint_requests_total{role="primary"}', 2),
                    ('dnsp_upstream_endpoint_failures_total{role="primary"}', 1),
                    ('dnsp_upstream_endpoint_replies_total{role="backup"}', 1),
                    ('dnsp_queries_satisfied_total', 2),
                    ('dnsp_cache_hits_total', 0),
                ):
                    self.assertEqual(Tests.metric(stats, metric), expected)
                self.assertEqual(backup.received, [QUERY])

    def test_timeout_leaves_one_budget_for_both_attempts(self):
        for mode in ('answer', 'stall'):
            with self.subTest(backup=mode), self.endpoint('stall') as primary, self.endpoint(mode) as backup:
                with self.proxy(self.url(primary), self.url(backup)) as (port, _):
                    packet = query(edns=1232)
                    start = time.monotonic()
                    response = self.udp(port, packet)
                    elapsed = time.monotonic() - start
                    self.assertEqual(response[:2], packet[:2])
                    self.assertEqual(response[3] & 15, 2 if mode == 'stall' else 0)
                    self.assertEqual(primary.received, [packet])
                    self.assertEqual(backup.received, [packet])
                    self.assertLess(elapsed, 2.1)  # Two independent timeouts would take 2.4 s.

    def test_dns_results_and_http_errors_do_not_fail_over(self):
        with self.endpoint() as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, _):
                for mode, rcode in (('nxdomain', 3), ('refused', 5), ('servfail', 2),
                                    ('http503', 2), ('partial403', 2), ('invalid', 2)):
                    with self.subTest(mode=mode):
                        before = len(backup.received)
                        primary.mode = mode
                        self.assertEqual(self.udp(port)[3] & 15, rcode)
                        self.assertEqual(len(backup.received), before)

    def test_https_proxy_denial_does_not_fail_over(self):
        # A delayed CONNECT response must arrive before the connection deadline.
        with self.endpoint(accept_delay=.35) as tunnel, self.endpoint() as backup:
            proxy = self.url(tunnel)
            env = dict(os.environ, https_proxy=proxy, HTTPS_PROXY=proxy, no_proxy='', NO_PROXY='')
            with self.proxy('https://blocked.invalid/dns-query', self.url(backup), env=env,
                            connect_ms=1500, total_ms=3000) as (port, _):
                self.assertEqual(self.udp(port)[3] & 15, 2)
                self.assertEqual(tunnel.tunnels, ['blocked.invalid:443'])
                self.assertEqual(backup.received, [])

    def test_ineligible_queries_stay_on_primary(self):
        cookie = edns_options(query(edns=1232), struct.pack('!HH', 10, 8) + bytes(8))
        # The fixture treats the synthetic MAC as opaque, as does the proxy.
        mac = bytes(16)
        tsig = (b'\x0bhmac-sha256\0' + bytes(6) + struct.pack('!HH', 300, len(mac)) + mac +
                struct.pack('!HHH', 0x1234, 0, 0))
        signed = (QUERY[:10] + b'\0\1' + QUERY[12:] + b'\x03key\0' +
                  struct.pack('!HHIH', 250, 255, 0, len(tsig)) + tsig)
        cases = (
            ('cookie', cookie), ('signed', signed), ('TKEY', query(249)), ('TSIG', query(250)),
            ('CHAOS class', QUERY[:-2] + b'\0\3'), ('questionless', QUERY[:4] + bytes(8)),
        )
        with self.endpoint('partial') as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, _):
                for name, packet in cases:
                    with self.subTest(query=name):
                        response = self.udp(port, packet)
                        self.assertEqual(response[:2], packet[:2])
                        self.assertEqual(response[3] & 15, 2)
                self.assertEqual(primary.received, [packet for _, packet in cases])
                self.assertEqual(backup.received, [])

    def test_coalesced_udp_waiters_keep_ids_on_backup(self):
        for mode, requests in (('answer', 1), ('nostore', 2)):
            with self.subTest(backup=mode), self.endpoint('stall') as primary, self.endpoint(mode) as backup:
                with self.proxy(self.url(primary), self.url(backup)) as (port, metrics), \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as leader, \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as waiter:
                    leader.settimeout(4)
                    waiter.settimeout(4)
                    leader.sendto(query(ident=41), ('127.0.0.1', port))
                    self.assertTrue(primary.started.wait(3))
                    waiter.sendto(query(ident=42), ('127.0.0.1', port))
                    for sock, ident in ((leader, 41), (waiter, 42)):
                        reply = sock.recv(4096)
                        self.assertEqual(reply[:2], struct.pack('!H', ident))
                        self.assertTrue(reply.endswith(backup.address))
                    self.assertEqual(len(backup.received), requests)
                    self.assertEqual(len(primary.received), 1)
                    self.assertEqual(Tests.metric(Tests.metrics(self, metrics), 'dnsp_udp_queries_coalesced_total'), 1)

    def test_wildcard_udp_source_on_upstream_cache_and_local_replies(self):
        with self.endpoint() as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup), '-l', '0.0.0.0',
                            '--cache-entries', '16') as (port, metrics), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('127.0.0.1', 0))
                sock.settimeout(3)
                target = ('127.0.0.2', port)
                sock.connect(target)
                malformed = QUERY[:3] + b'\x01' + QUERY[4:]
                for packet, rcode in ((QUERY, 0), (query(ident=42), 0), (malformed, 1)):
                    sock.send(packet)
                    reply, peer = sock.recvfrom(4096)
                    self.assertEqual(peer, target)
                    self.assertEqual(reply[:2], packet[:2])
                    self.assertEqual(reply[3] & 15, rcode)
                self.assertEqual(primary.received, [QUERY])
                self.assertEqual(backup.received, [])
                self.assertEqual(Tests.metric(Tests.metrics(self, metrics), 'dnsp_cache_hits_total'), 1)

    def test_wildcard_udp_coalesces_across_destinations_and_keeps_reply_sources(self):
        for mode, requests in (('answer', 1), ('nostore', 2)):
            with self.subTest(backup=mode), self.endpoint('stall') as primary, self.endpoint(mode) as backup:
                with self.proxy(self.url(primary), self.url(backup), '-l', '0.0.0.0',
                                connect_ms=1500, total_ms=3000) as (port, metrics), \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.bind(('127.0.0.1', 0))
                    sock.settimeout(4)
                    first, second = ('127.0.0.1', port), ('127.0.0.2', port)
                    sock.sendto(QUERY, first)
                    self.assertTrue(primary.started.wait(3))
                    sock.sendto(QUERY, second)
                    sock.sendto(QUERY, second)  # Retransmission to the same local IP.
                    sources = []
                    for _ in range(2):
                        reply, peer = sock.recvfrom(4096)
                        self.assertEqual(reply[:2], QUERY[:2])
                        self.assertEqual(reply[3] & 15, 0)
                        sources.append(peer)
                    self.assertCountEqual(sources, [first, second])
                    sock.settimeout(.1)
                    with self.assertRaises(socket.timeout):
                        sock.recv(4096)
                    self.assertEqual(primary.received, [QUERY])
                    self.assertEqual(backup.received, [QUERY] * requests)
                    self.assertEqual(Tests.metric(Tests.metrics(self, metrics), 'dnsp_udp_queries_coalesced_total'), 2)

    def test_tcp_disconnect_cancels_backup_transfer(self):
        with self.endpoint('partial') as primary, self.endpoint('stall') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metrics):
                with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                    sock.sendall(Tests.frame(QUERY))
                    self.assertTrue(backup.started.wait(3))
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    stats = Tests.metrics(self, metrics)
                    if Tests.metric(stats, 'dnsp_tcp_cancelled_upstream_total') == 1:
                        self.assertEqual(Tests.metric(stats, 'dnsp_queries_inflight'), 0)
                        break
                    time.sleep(.02)
                else:
                    self.fail('the TCP disconnect did not cancel the backup transfer')
                primary.mode = 'answer'
                with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                    sock.sendall(Tests.frame(QUERY))
                    self.assertTrue(Tests.tcp_frame(sock).endswith(primary.address))

    @unittest.skipUnless(shutil.which('openssl'), 'openssl required to generate a local TLS certificate')
    def test_bootstrapped_backup_uses_hostname_and_primary_cert_failure_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = str(Path(tmp)/'cert.pem'), str(Path(tmp)/'key.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=resolver.invalid',
                            '-addext', 'subjectAltName=DNS:resolver.invalid',
                            '-out', cert, '-keyout', key], check=True, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            # Delay accept before the server-side TLS handshake.
            with self.endpoint('partial') as plain, self.endpoint(tls=tls, accept_delay=.35) as secure:
                secure_url = f'https://resolver.invalid:{secure.server_port}/dns-query'
                with self.proxy(self.url(plain), secure_url, '--ca-file', cert,
                                '--backup-bootstrap-address', '127.0.0.1', '--edns-padding',
                                connect_ms=1500, total_ms=3000) as (port, _):
                    response = self.udp(port)
                    self.assertTrue(response.endswith(secure.address), response.hex())
                    packet = query(edns=1232)
                    response = self.udp(port, packet)
                    padded = edns_options(packet, padding_option(128 - len(packet)))
                    self.assertEqual(plain.received[-1], packet)
                    self.assertEqual(secure.received[-1], padded)
                    self.assertEqual(response[:2], packet[:2])
                    end = question_end(packet)
                    self.assertEqual(response[end:], rr(1, secure.address) + packet[end:])
                plain.received.clear()
                plain.mode = 'answer'
                wrong_url = f'https://wrong.invalid:{secure.server_port}/dns-query'
                with self.proxy(wrong_url, self.url(plain), '--ca-file', cert,
                                '--bootstrap-address', '127.0.0.1',
                                connect_ms=1500, total_ms=3000) as (port, _):
                    self.assertEqual(self.udp(port)[3] & 15, 2)
                    self.assertEqual(plain.received, [])

    def test_invalid_backup_options(self):
        for args in (('--backup-bootstrap-address', '127.0.0.1'),
                     ('--backup-upstream', 'http://resolver.invalid/dns-query'),
                     ('--backup-upstream', 'https://CLOUDFLARE-DNS.COM.:443/another-path'),
                     ('--backup-upstream', 'https://backup.invalid/dns-query',
                      '--backup-bootstrap-address', 'invalid')):
            with self.subTest(args=args):
                proc = subprocess.run([str(BINARY), *args], capture_output=True, timeout=3)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn(b'--backup-', proc.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
