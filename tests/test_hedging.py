"""Real dual-upstream races, reply ownership, deadlines and bounded telemetry."""
from contextlib import contextmanager
import socket
import ssl
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest

import test_modern as dns


class HedgingTests(unittest.TestCase):
    endpoint = dns.FailoverTests.endpoint
    url = staticmethod(dns.FailoverTests.url)
    udp = staticmethod(dns.FailoverTests.udp)

    @contextmanager
    def proxy(self, primary, backup, *args, hedge_ms=50, **kwargs):
        with dns.FailoverTests.proxy(self, primary, backup, *args,
                                    '--upstream-hedge-ms', str(hedge_ms), **kwargs) as ports:
            yield ports

    def metric(self, port, name):
        return dns.Tests.metric(dns.Tests.metrics(self, port), name)

    def wait_metric(self, port, name, value):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.metric(port, name) == value:
                return
            time.sleep(.01)
        self.fail(f'{name} did not become {value}')

    def test_fast_primary_does_not_contact_backup(self):
        with self.endpoint() as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup), hedge_ms=150) as (port, metric):
                self.assertTrue(self.udp(port).endswith(primary.address))
                self.assertEqual(backup.received, [])
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_started_total'), 0)

    def test_backup_wins_once_and_late_primary_cannot_reply(self):
        with self.endpoint('wait_answer') as primary, \
             self.endpoint(address=b'\xc0\x00\x02\x02') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metric), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(dns.QUERY, ('127.0.0.1', port))
                self.assertTrue(client.recv(4096).endswith(backup.address))
                primary.release.set()
                client.settimeout(.15)
                with self.assertRaises(socket.timeout):
                    client.recv(4096)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedge_wins_total{role="backup"}'), 1)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_cancelled_total'), 1)
                self.assertEqual(self.metric(metric, 'dnsp_queries_inflight'), 0)

    def test_tcp_winner_preserves_the_persistent_session(self):
        with self.endpoint('wait_answer') as primary, \
             self.endpoint(address=b'\xc0\x00\x02\x02') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metric), \
                 socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(struct.pack('!H', len(dns.QUERY)) + dns.QUERY)
                self.assertTrue(dns.Tests.tcp_frame(client).endswith(backup.address))
                primary.mode = 'answer'
                packet = dns.query(ident=42)
                client.sendall(struct.pack('!H', len(packet)) + packet)
                reply = dns.Tests.tcp_frame(client)
                self.assertEqual(reply[:2], packet[:2])
                self.assertTrue(reply.endswith(primary.address))
                primary.release.set()
                client.settimeout(.15)
                with self.assertRaises(socket.timeout):
                    client.recv(1)
                self.assertEqual(self.metric(metric, 'dnsp_client_duration_seconds_count{transport="tcp"}'), 2)

    def test_primary_can_win_after_the_backup_starts(self):
        with self.endpoint('wait_answer') as primary, self.endpoint('stall') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metric), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(dns.QUERY, ('127.0.0.1', port))
                self.assertTrue(backup.started.wait(2))
                primary.release.set()
                self.assertTrue(client.recv(4096).endswith(primary.address))
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedge_wins_total{role="primary"}'), 1)

    def test_invalid_backup_does_not_displace_a_valid_primary(self):
        with self.endpoint('wait_answer') as primary, self.endpoint('invalid') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metric), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(dns.QUERY, ('127.0.0.1', port))
                self.wait_metric(metric, 'dnsp_upstream_failures_total', 1)
                primary.release.set()
                self.assertTrue(client.recv(4096).endswith(primary.address))

    def test_both_attempts_share_one_deadline(self):
        with self.endpoint('stall') as primary, self.endpoint('stall') as backup:
            with self.proxy(self.url(primary), self.url(backup), total_ms=400) as (port, metric):
                started = time.monotonic()
                self.assertEqual(self.udp(port)[3] & 15, 2)
                self.assertLess(time.monotonic() - started, .95)
                self.assertEqual(len(primary.received), 1)
                self.assertEqual(len(backup.received), 1)
                self.assertEqual(self.metric(metric, 'dnsp_queries_inflight'), 0)

    @unittest.skipUnless(dns.OPENSSL, 'TLS fixture requires openssl')
    def test_extended_tls_primary_still_obeys_the_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / 'cert.pem', Path(directory) / 'key.pem'
            subprocess.run([dns.OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-out', str(cert), '-keyout', str(key)], check=True, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            with self.endpoint('stall', tls=tls) as primary, self.endpoint('stall') as backup:
                with self.proxy(f'https://localhost:{primary.server_port}/dns-query', self.url(backup),
                                '--ca-file', str(cert), '--bootstrap-address', '127.0.0.1',
                                total_ms=800, hedge_ms=80) as (port, metric), \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    start = time.monotonic()
                    client.sendto(dns.QUERY, ('127.0.0.1', port))
                    self.assertEqual(client.recv(4096)[3] & 15, 2)
                    self.assertLess(time.monotonic() - start, 1.6)
                    self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_started_total'), 1)
                    self.assertEqual(self.metric(metric, 'dnsp_queries_inflight'), 0)
                    self.assertEqual(len(primary.received), 1)
                    self.assertEqual(len(backup.received), 1)

    def test_late_coalesced_waiters_keep_ids_and_obey_no_store(self):
        for mode, requests in (('wait_answer', 1), ('wait_nostore', 2)):
            with self.subTest(mode=mode), self.endpoint('stall') as primary, \
                 self.endpoint(mode, address=b'\xc0\x00\x02\x02') as backup:
                with self.proxy(self.url(primary), self.url(backup)) as (port, metric), \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as leader, \
                     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as waiter:
                    for client in (leader, waiter):
                        client.settimeout(3)
                    leader.sendto(dns.query(ident=41), ('127.0.0.1', port))
                    self.assertTrue(backup.started.wait(2))
                    waiter.sendto(dns.query(ident=42), ('127.0.0.1', port))
                    self.wait_metric(metric, 'dnsp_udp_queries_coalesced_total', 1)
                    backup.release.set()
                    for client, ident in ((leader, 41), (waiter, 42)):
                        reply = client.recv(4096)
                        self.assertEqual(reply[:2], struct.pack('!H', ident))
                        self.assertTrue(reply.endswith(backup.address))
                    self.assertEqual(len(backup.received), requests)
                    self.assertEqual(self.metric(metric, 'dnsp_client_duration_seconds_count{transport="udp"}'), 2)

    def test_server_specific_requests_never_start_a_parallel_backup(self):
        cookie = dns.edns_options(dns.query(edns=1232), struct.pack('!HH', 10, 8) + bytes(8))
        with self.endpoint('stall') as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup), total_ms=250) as (port, _):
                for packet in (cookie, dns.query(249), dns.QUERY[:-2] + b'\0\3'):
                    self.assertEqual(self.udp(port, packet)[3] & 15, 2)
                self.assertEqual(backup.received, [])

    def test_tcp_disconnect_cancels_both_attempts(self):
        with self.endpoint('stall') as primary, self.endpoint('stall') as backup:
            with self.proxy(self.url(primary), self.url(backup)) as (port, metric):
                client = socket.create_connection(('127.0.0.1', port), timeout=3)
                client.sendall(struct.pack('!H', len(dns.QUERY)) + dns.QUERY)
                self.assertTrue(backup.started.wait(2))
                client.shutdown(socket.SHUT_RDWR)
                client.close()
                self.wait_metric(metric, 'dnsp_queries_inflight', 0)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_inflight'), 0)

    def test_parallel_backups_have_a_separate_capacity_bound(self):
        with self.endpoint('stall') as primary, self.endpoint('stall') as backup:
            with self.proxy(self.url(primary), self.url(backup), total_ms=2000) as (port, metric), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                for i in range(30):
                    client.sendto(dns.query(62000 + i, ident=i), ('127.0.0.1', port))
                self.wait_metric(metric, 'dnsp_upstream_hedges_started_total', 16)
                self.wait_metric(metric, 'dnsp_upstream_hedges_suppressed_total', 14)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_suppressed_total'), 14)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_hedges_inflight'), 16)
                self.assertEqual(self.metric(metric, 'dnsp_queries_inflight'), 30)

    def test_policy_reload_is_applied_before_starting_a_backup(self):
        with tempfile.TemporaryDirectory() as directory, self.endpoint('wait_answer') as primary, \
             self.endpoint() as backup:
            rules = Path(directory) / 'deny.txt'
            rules.write_text('initial.example\n')
            with self.proxy(self.url(primary), self.url(backup), '--blocklist', str(rules),
                            '--blocklist-reload-ms', '100', hedge_ms=500) as (port, metric), \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(dns.QUERY, ('127.0.0.1', port))
                self.assertTrue(primary.started.wait(2))
                rules.write_text('www.google.com\n')
                self.wait_metric(metric, 'dnsp_blocklist_generation', 2)
                time.sleep(.55)
                primary.release.set()
                self.assertEqual(client.recv(4096)[3] & 15, 5)
                self.assertEqual(backup.received, [])

    def test_primary_certificate_failure_stays_fail_closed(self):
        dns.FailoverTests.test_bootstrapped_backup_uses_hostname_and_primary_cert_failure_stops(self)

    def test_histograms_and_build_information_are_bounded_and_consistent(self):
        with self.endpoint() as primary, self.endpoint() as backup:
            with self.proxy(self.url(primary), self.url(backup), '--cache-entries', '16') as (port, metric):
                self.udp(port)
                self.udp(port, dns.query(ident=42))
                body = dns.Tests.metrics(self, metric)
                self.assertIn('dnsp_build_info{version=', body)
                count = self.metric(metric, 'dnsp_client_duration_seconds_count{transport="udp"}')
                self.assertEqual(count, 2)
                self.assertEqual(self.metric(metric, 'dnsp_client_duration_seconds_bucket{transport="udp",le="+Inf"}'), count)
                self.assertEqual(self.metric(metric, 'dnsp_upstream_duration_seconds_bucket{le="+Inf"}'), 1)
                self.assertLess(len(body), 15360)

    def test_invalid_hedging_options_are_rejected(self):
        for arguments in (('--upstream-hedge-ms', '1'), ('--upstream-hedge-ms', '-1'),
                          ('--backup-upstream', 'https://dns.google/dns-query',
                           '--upstream-hedge-ms', '3000')):
            with self.subTest(arguments=arguments):
                result = subprocess.run([str(dns.BINARY), *arguments], capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
