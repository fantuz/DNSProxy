#!/usr/bin/env python3
"""Loopback integration: RFC 8484 framing, EDNS, DNS validation, libcurl loop."""
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
import threading
import time
import tempfile
import unittest
from pathlib import Path

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


def rr(typ, data, owner=b'\xc0\x0c'):
    return owner + struct.pack('!HHIH', typ, 1, 60, len(data)) + data


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
        if label in (b'coalesce', b'coalesce-fail'):
            self.server.coalesce_gate.wait(5)
        status = 502 if label == b'coalesce-fail' else {65009: 502, 65017: 201}.get(typ, 200)
        self.send_response(status)
        media = {65008: 'text/plain', 65021: 'Application/DNS-Message ; fixture=ok'}
        self.send_header('Content-Type', media.get(typ, 'application/dns-message'))
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

    def test_invalid_udp_does_not_kill(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'\0\1', ('127.0.0.1', self.port))
        out = self.udp(query())
        self.assertEqual(out[:2], QUERY[:2])
        self.assertEqual(out[2:4], b'\x81\x80')
        self.assertEqual(out[12:], QUERY[12:])

    def test_udp_input_bounds_and_valid_prefix(self):
        self.assertEqual(len(self.udp(sized_query(4096))), 4096)
        for size in (4097, 65507):
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
        self.assertIn('event=upstream_content_type', log)

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

            with HTTP(('127.0.0.1', 0), TLSDoH) as server:
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
