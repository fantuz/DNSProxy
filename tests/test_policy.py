"""Domain policy on the real shared resolver; no public DNS or live adapter writes."""
from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import random
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import test_modern as dns


def wire_name(name):
    labels = name.rstrip('.').split('.') if name else []
    return b''.join(bytes([len(part)]) + part.encode('ascii') for part in labels) + b'\0'


def question(name='ads.example', typ=1, *, edns=True, ident=0x1234, flags=0x0100, klass=1):
    opt = bytes.fromhex('00002904d0000000000000') if edns else b''
    return struct.pack('!6H', ident, flags, 1, 0, 0, bool(opt)) + wire_name(name) + struct.pack('!HH', typ, klass) + opt


def response(packet, records=None, authority=b''):
    end = dns.question_end(packet)
    if records is None:
        return dns.make_response(packet)
    return packet[:2] + struct.pack('!5H', 0x81a0, 1, len(records), bool(authority), 0) + packet[12:end] + b''.join(records) + authority


def record(owner, typ, value):
    return wire_name(owner) + struct.pack('!HHIH', typ, 1, 60, len(value)) + value


def exchange(port, packet, host='127.0.0.1', tcp=False):
    if tcp:
        with socket.create_connection((host, port), timeout=5) as client:
            client.sendall(struct.pack('!H', len(packet)) + packet)
            return dns.Tests.tcp_frame(client)
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(packet, (host, port))
        return client.recv(65535)


def ports():
    # Keep fixtures out of ephemeral connection ranges and check both protocols.
    found = []
    held = []
    try:
        for port in random.sample(range(18000, 28000), 100):
            trial = []
            try:
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    sock = socket.socket(socket.AF_INET, kind)
                    trial.append(sock)
                    sock.bind(('127.0.0.1', port))
                held.extend(trial)
                found.append(port)
                if len(found) == 2:
                    return found
            except OSError:
                for sock in trial:
                    sock.close()
        raise RuntimeError('No TCP/UDP fixture ports available')
    finally:
        for sock in held:
            sock.close()


class PolicyDoH(dns.DoH):
    def do_POST(self):
        packet = self.rfile.read(int(self.headers['Content-Length']))
        self.server.received.append(packet)
        self.server.started.set()
        self.server.gate.wait(8)
        answer = self.server.answer(packet)
        self.send_response(self.server.status)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(answer)))
        self.end_headers()
        try:
            self.wfile.write(answer)
        except OSError:
            pass


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='dnsp-policy-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.deny, self.allow = self.root/'deny.txt', self.root/'allow.txt'
        self.deny.write_text('ads.example\n.blocked.example\n*.children.example\n')
        self.allow.write_text('safe.blocked.example\n')

    def replace(self, path, text):
        temporary = path.with_suffix('.new')
        temporary.write_text(text)
        os.replace(temporary, path)

    @contextmanager
    def proxy(self, *extra, ipv6=False, filtering=True):
        port, metric = ports()
        with dns.HTTP(('127.0.0.1', 0), PolicyDoH) as upstream:
            upstream.received = []
            upstream.started, upstream.gate = threading.Event(), threading.Event()
            upstream.gate.set()
            upstream.answer, upstream.status = response, 200
            worker = threading.Thread(target=upstream.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
            worker.start()
            command = [str(dns.BINARY), '-p', str(port), '-m', str(metric),
                       '-s', f'http://127.0.0.1:{upstream.server_port}/dns-query']
            if filtering:
                command += ['--blocklist', str(self.deny), '--allowlist', str(self.allow), '--blocklist-reload-ms', '100']
            command += extra
            if ipv6:
                command += ['-l', '127.0.0.1', '-l', '::1']
            with tempfile.TemporaryFile() as log:
                process = dns.spawn_proxy(command, stderr=log)
                try:
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            log.seek(0)
                            self.fail(f'Policy proxy exited: {log.read().decode(errors="replace")}')
                        try:
                            self.stats(metric)
                            break
                        except OSError:
                            time.sleep(0.02)
                    else:
                        self.fail('Policy proxy did not start')
                    yield port, metric, upstream, process
                finally:
                    upstream.gate.set()
                    dns.terminate_proxy(process)
                    process.wait(timeout=8)
                    if sys.exc_info()[0]:
                        log.seek(0)
                        print(log.read().decode(errors='replace'), file=sys.stderr)
                    upstream.shutdown()
                    worker.join(timeout=3)

    @staticmethod
    def stats(port):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            connection.request('GET', '/metrics')
            reply = connection.getresponse()
            if reply.status != 200:
                raise AssertionError(reply.status)
            return {line.split()[0]: float(line.split()[1]) for line in reply.read().decode().splitlines()
                    if line and not line.startswith('#')}
        finally:
            connection.close()

    def wait_stat(self, port, key, minimum):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = self.stats(port)[key]
            if value >= minimum:
                return value
            time.sleep(0.025)
        self.fail(f'{key} did not reach {minimum}: {value}')

    def assert_blocked(self, reply, packet, rcode=5):
        self.assertEqual(reply[:2], packet[:2])
        self.assertTrue(reply[2] & 0x80)
        self.assertEqual(reply[3] & 15, rcode)
        self.assertEqual(reply[3] & 0x20, 0)  # No fabricated DNSSEC authentication.
        self.assertEqual(reply[6:10], bytes(4))
        self.assertEqual(reply[12:dns.question_end(reply)], packet[12:dns.question_end(packet)])
        if packet[10:12] != b'\0\0':
            self.assertEqual(reply[-6:], bytes.fromhex('000f0002000f'))
            self.assertEqual(reply[10:12], b'\0\1')
        else:
            self.assertEqual(reply[10:12], bytes(2))

    def test_all_types_both_transports_and_address_families(self):
        with self.proxy(ipv6=True) as (port, metric, upstream, _):
            count = 0
            for host in ('127.0.0.1', '::1'):
                for tcp in (False, True):
                    for typ in (1, 28, 2, 5, 15, 16, 33, 48, 64, 65, 255, 65400):
                        packet = question('AdS.ExAmPlE.', typ, ident=count, flags=0x0130)
                        self.assert_blocked(exchange(port, packet, host, tcp), packet)
                        count += 1
            self.assertEqual(upstream.received, [])
            self.assertEqual(self.stats(metric)['dnsp_blocked_queries_total'], count)
            self.assertEqual(self.stats(metric)['dnsp_upstream_requests_total'], 0)

    def test_formats_allowlist_and_label_boundaries(self):
        self.deny.write_bytes(b'\xef\xbb\xbf# list\r\n0.0.0.0 AdS.ExAmPlE. extra.example # aliases\r\n'
                              b':: zero.example\n.blocked.example\n*.children.example\nxn--bcher-kva.example\n')
        with self.proxy() as (port, _, upstream, _):
            for name in ('ads.example', 'extra.example', 'zero.example', 'blocked.example',
                         'a.blocked.example', 'x.children.example', 'xn--bcher-kva.example'):
                packet = question(name)
                self.assert_blocked(exchange(port, packet), packet)
            for name in ('safe.blocked.example', 'notblocked.example', 'children.example',
                         'ads.example.other', 'x.ads.example'):
                self.assertEqual(exchange(port, question(name))[3] & 15, 0, name)
            self.assertEqual(len(upstream.received), 5)

    def test_edns_flags_version_and_signed_queries(self):
        with self.proxy() as (port, _, upstream, _):
            for edns in (False, True):
                packet = question(edns=edns, flags=0x0030)
                answer = exchange(port, packet)
                self.assert_blocked(answer, packet)
                self.assertEqual(answer[2] & 1, 0)
                self.assertEqual(answer[3] & 0x10, 0x10)
            packet = bytearray(question())
            packet[-5] = 1  # Unsupported EDNS version.
            answer = exchange(port, packet)
            self.assertEqual(answer[3] & 15, 0)
            self.assertEqual(answer[-6:-4], b'\x01\0')  # BADVERS, server EDNS(0).
            signed = bytearray(question())
            signed[10:12] = b'\0\2'
            signed += record('key.example', 250, b'opaque-authentication')
            self.assert_blocked(exchange(port, signed), signed)
            self.assertEqual(upstream.received, [])
            self.assertEqual(exchange(port, question(klass=3))[3] & 15, 0)

    def test_reply_modes_zero_ttl_and_no_fake_soa(self):
        for mode, rcode in (('refused', 5), ('nxdomain', 3), ('nodata', 0), ('null', 0)):
            with self.subTest(mode=mode), self.proxy('--block-response', mode) as (port, _, upstream, _):
                for typ in (1, 28, 65):
                    packet = question(typ=typ)
                    answer = exchange(port, packet)
                    if mode == 'null' and typ in (1, 28):
                        start = dns.question_end(answer)
                        self.assertEqual(answer[6:10], b'\0\1\0\0')
                        self.assertEqual(answer[start+6:start+10], bytes(4))
                        size = 4 if typ == 1 else 16
                        self.assertEqual(answer[start+12:start+12+size], bytes(size))
                        self.assertEqual(answer[-6:], bytes.fromhex('000f0002000f'))
                    else:
                        self.assert_blocked(answer, packet, rcode)
                self.assertEqual(upstream.received, [])

    def test_binary_labels_do_not_become_dotted_or_nul_terminated_strings(self):
        with self.proxy() as (port, _, upstream, _):
            for label in (b'ads.example', b'ads\0example', b'ads\xffexample'):
                packet = struct.pack('!6H', 42, 0x100, 1, 0, 0, 0) + bytes([len(label)]) + label + b'\0\0\1\0\1'
                self.assertEqual(exchange(port, packet)[3] & 15, 0)
            self.assertEqual(len(upstream.received), 3)

    def test_reachable_cname_dname_and_svcb_targets(self):
        with self.proxy() as (port, metric, upstream, _):
            cases = [
                [record('ok.example', 5, wire_name('ads.example'))],
                [record('next.example', 5, wire_name('ads.example')),
                 record('ok.example', 5, wire_name('next.example'))],
                [record('example', 39, wire_name('blocked.example'))],
                [record('ok.example', 64, b'\0\0' + wire_name('ads.example'))],
                [record('ok.example', 65, b'\0\1' + wire_name('ads.example') + bytes.fromhex('00040004c0000201'))],
                [record('ok.example', 5, wire_name('next.example')),
                 record('next.example', 65, b'\0\0' + wire_name('ads.example'))],
            ]
            for records in cases:
                upstream.answer = lambda packet, rows=records: response(packet, rows)
                packet = question('ok.example', 65)
                self.assert_blocked(exchange(port, packet), packet)
            self.assertEqual(self.stats(metric)['dnsp_blocked_aliases_total'], len(cases))
            # Unrelated answer/authority aliases must not block the question.
            upstream.answer = lambda packet: response(packet, [record('unrelated.example', 5, wire_name('ads.example'))],
                                                       record('ok.example', 5, wire_name('ads.example')))
            self.assertEqual(exchange(port, question('ok.example'))[3] & 15, 0)
            # An allowlisted target wins over its own deny rule.
            self.replace(self.allow, 'ads.example\n')
            self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
            upstream.answer = lambda packet: response(packet, [record('ok.example', 5, wire_name('ads.example'))])
            self.assertEqual(exchange(port, question('ok.example'))[3] & 15, 0)

    def test_alias_cycles_and_invalid_targets_are_bounded(self):
        with self.proxy() as (port, _, upstream, _):
            upstream.answer = lambda packet: response(packet, [record('ok.example', 5, wire_name('next.example')),
                                                              record('next.example', 5, wire_name('ok.example'))])
            self.assertEqual(exchange(port, question('ok.example'))[3] & 15, 0)
            # RFC 9460 forbids compressed TargetName in HTTPS/SVCB.
            upstream.answer = lambda packet: response(packet, [record('ok.example', 65, b'\0\0\xc0\x0c')])
            self.assertEqual(exchange(port, question('ok.example', 65))[3] & 15, 2)
            upstream.answer = response
            self.assertEqual(exchange(port, question('ok.example'))[3] & 15, 0)

    def test_reload_invalidates_cached_aliases_and_positive_answers(self):
        self.deny.write_text('initial.example\n')
        with self.proxy('--cache-entries', '16') as (port, metric, upstream, _):
            upstream.answer = lambda packet: response(packet, [record('ok.example', 5, wire_name('ads.example')),
                                                              record('ads.example', 1, bytes([192, 0, 2, 1]))])
            packet = question('ok.example', edns=False)
            self.assertEqual(exchange(port, packet)[3] & 15, 0)
            self.assertEqual(exchange(port, packet)[3] & 15, 0)
            self.assertEqual(len(upstream.received), 1)
            self.replace(self.deny, 'ads.example\n')
            self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
            self.assert_blocked(exchange(port, packet), packet)
            self.assertEqual(len(upstream.received), 2)
            self.replace(self.deny, 'ok.example\n')
            self.wait_stat(metric, 'dnsp_blocklist_generation', 3)
            self.assert_blocked(exchange(port, packet), packet)
            self.assertEqual(len(upstream.received), 2)

    def test_reload_rechecks_inflight_tcp_and_coalesced_udp(self):
        for alias in (False, True):
            with self.subTest(alias=alias):
                self.deny.write_text("initial.example\n")
                with self.proxy('--cache-entries', '16') as (port, metric, upstream, _):
                    upstream.gate.clear()
                    if alias:
                        upstream.answer = lambda packet: response(packet, [record('pending.example', 5, wire_name('ads.example')),
                                                                          record('ads.example', 1, bytes([192, 0, 2, 1]))])
                    packets = [question('pending.example', edns=False, ident=i) for i in (41, 42, 43)]
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
                         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
                         socket.create_connection(('127.0.0.1', port), timeout=5) as tcp:
                        first.settimeout(5);second.settimeout(5)
                        first.sendto(packets[0], ('127.0.0.1', port))
                        self.assertTrue(upstream.started.wait(3))
                        second.sendto(packets[1], ('127.0.0.1', port))
                        tcp.sendall(dns.Tests.frame(packets[2]))
                        self.wait_stat(metric, 'dnsp_udp_queries_coalesced_total', 1)
                        self.wait_stat(metric, 'dnsp_upstream_requests_total', 2)
                        self.replace(self.deny, 'ads.example\n' if alias else 'pending.example\n')
                        self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
                        upstream.gate.set()
                        for answer, packet in zip((first.recv(4096), second.recv(4096), dns.Tests.tcp_frame(tcp)), packets):
                            self.assert_blocked(answer, packet)
                    self.assertEqual(self.stats(metric)['dnsp_queries_inflight'], 0)
                    self.assertEqual(self.stats(metric)['dnsp_blocked_queries_total'], 3)
                    self.replace(self.deny, 'different.example\n')
                    self.wait_stat(metric, 'dnsp_blocklist_generation', 3)
                    self.assertEqual(exchange(port, packets[0])[3] & 15, 0)
                    self.assertEqual(len(upstream.received), 3)

    def test_failed_reload_retains_rules_and_recovers_after_missing_file(self):
        with self.proxy() as (port, metric, upstream, _):
            packet = question()
            self.replace(self.deny, '<html>broken feed</html>\n')
            self.wait_stat(metric, 'dnsp_blocklist_reload_failures_total', 1)
            self.assertEqual(self.stats(metric)['dnsp_blocklist_generation'], 1)
            self.assert_blocked(exchange(port, packet), packet)
            self.deny.unlink()
            self.wait_stat(metric, 'dnsp_blocklist_reload_failures_total', 2)
            self.assert_blocked(exchange(port, packet), packet)
            self.replace(self.deny, 'different.example\n')
            self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
            self.assertEqual(exchange(port, packet)[3] & 15, 0)
            self.assertEqual(len(upstream.received), 1)

    def test_newly_denied_inflight_failure_does_not_use_backup(self):
        backup, _ = ports()
        with self.proxy('--backup-upstream', f'http://127.0.0.1:{backup}/dns-query',
                        '--doh-timeout-ms', '10000') as (port, metric, upstream, _):
            upstream.gate.clear()
            upstream.status = 503
            packet = question('pending.example', edns=False)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                client.sendto(packet, ('127.0.0.1', port))
                self.assertTrue(upstream.started.wait(3))
                self.replace(self.deny, 'pending.example\n')
                self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
                upstream.gate.set()
                self.assert_blocked(client.recv(4096), packet)
            self.assertEqual(self.stats(metric)['dnsp_upstream_endpoint_requests_total{role="backup"}'], 0)

    @unittest.skipIf(os.name == 'nt', 'Windows uses SCM PARAMCHANGE')
    def test_reload_without_filtering_is_harmless(self):
        with self.proxy(filtering=False) as (port, _, _, process):
            os.kill(process.pid, signal.SIGHUP)
            self.assertEqual(exchange(port, question())[3] & 15, 0)
            self.assertIsNone(process.poll())

    def test_repeated_reload_retires_snapshots(self):
        with self.proxy() as (port, metric, _, _):
            memory = []
            for index in range(8):
                self.replace(self.deny, f'entry{index}.example\n')
                self.wait_stat(metric, 'dnsp_blocklist_generation', index + 2)
                memory.append(self.stats(metric)['dnsp_blocklist_memory_bytes'])
                self.assertEqual(exchange(port, question('allowed.example'))[3] & 15, 0)
            self.assertEqual(len(set(memory)), 1)

    @unittest.skipIf(os.name == 'nt', 'Windows uses automatic reload or SCM PARAMCHANGE')
    def test_sighup_with_automatic_reload_disabled(self):
        with self.proxy('--blocklist-reload-ms', '0') as (port, metric, _, process):
            self.replace(self.deny, 'different.example\n')
            os.kill(process.pid, signal.SIGHUP)
            self.wait_stat(metric, 'dnsp_blocklist_generation', 2)
            self.assertEqual(exchange(port, question())[3] & 15, 0)

    def test_tcp_pipeline_mixes_local_and_forwarded_replies(self):
        with self.proxy() as (port, _, upstream, _):
            packets = [question(name, ident=i) for i, name in enumerate(('ads.example', 'ok.example', 'ads.example'))]
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                client.sendall(b''.join(map(dns.Tests.frame, packets)))
                for packet in packets:
                    answer = dns.Tests.tcp_frame(client)
                    self.assertEqual(answer[:2], packet[:2])
                    self.assertEqual(answer[3] & 15, 0 if packet == packets[1] else 5)
            self.assertEqual(len(upstream.received), 1)

    def test_check_only_rejects_bad_or_missing_inputs(self):
        command = [str(dns.BINARY), '--blocklist', str(self.deny), '--check-blocklists']
        valid = subprocess.run(command, capture_output=True, timeout=8)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn(b'blocklist_entries=3', valid.stdout)
        for content in (b'bad..example\n', b'a'*64 + b'.example\n', b'ads.example\0\n',
                        b'||ads.example^\n', b'ads.example extra\n', b'127.0.0.1\n',
                        b'\xff.example\n', b'#' + b'x'*4097):
            self.deny.write_bytes(content)
            invalid = subprocess.run(command, capture_output=True, timeout=8)
            self.assertEqual(invalid.returncode, 2, (content[:30], invalid.stderr))
        self.deny.unlink()
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=8).returncode, 2)
        with self.deny.open('wb') as output:
            output.truncate(64*1024*1024 + 1)
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=8).returncode, 2)
        self.deny.unlink()
        if os.name != 'nt':
            os.mkfifo(self.deny)
            self.assertEqual(subprocess.run(command, capture_output=True, timeout=8).returncode, 2)
            self.deny.unlink()
        for flags in (['--allowlist', str(self.allow)], ['--block-response', 'typo'], ['--check-blocklists']):
            self.assertEqual(subprocess.run([str(dns.BINARY), *flags], capture_output=True, timeout=8).returncode, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
