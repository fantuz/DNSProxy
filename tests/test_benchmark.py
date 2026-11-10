#!/usr/bin/env python3
"""Tests for benchmark report logic and actual loopback TLS/HTTP2 multiplexing."""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE/'bench'))
from bench_modern import (DNS_QUESTION, EDNS_OPT, await_quiescent, await_ready,  # noqa: E402
                          free_port, make_certificate, metric_snapshot, percentile, proxy_cpu_rss)
from mock_doh import MockServer, make_response  # noqa: E402


class BenchmarkUnitTests(unittest.TestCase):
    def test_percentiles_interpolated(self):
        self.assertEqual(percentile([1., 2., 3., 4., 5.], 50), 3)
        self.assertEqual(percentile([1., 2., 3., 4., 5.], 95), 4.8)
        self.assertIsNone(percentile([], 99))

    def test_mock_dns_response_counts_and_question(self):
        request = bytes.fromhex('123401000001000000000001') + bytes.fromhex(
            '076578616d706c6503636f6d0000010001') + bytes.fromhex('0000291000000000000000')
        response = make_response(request, 240)
        self.assertEqual(response[:2], request[:2])
        self.assertEqual(response[6:8], b'\x00\xf0')
        self.assertEqual(response[12:29], request[12:29])
        self.assertLessEqual(len(response), 4096)
        self.assertIsNone(make_response(b'\x00', 1))

    def test_cpu_snapshot_optional_procfs(self):
        cpu, rss, peak = proxy_cpu_rss(-999999)
        self.assertEqual((cpu, rss, peak), (None, None, None))


class BenchmarkIntegrationTests(unittest.TestCase):
    def test_large_udp_replies_distinguish_truncation_from_success(self):
        with tempfile.TemporaryDirectory(prefix='dnsp-large-bench-') as td:
            for cap in (None, 4096):
                with self.subTest(cap=cap):
                    dest = Path(td)/f'results-{cap}.json'
                    cmd = [sys.executable, str(BASE/'bench/bench_modern.py'),
                           '--protocol', 'h2', '--concurrency', '1', '--answers', '240',
                           '--warmup', '0.1', '--duration', '0.2', '--output', str(dest)]
                    if cap is not None:
                        cmd.extend(['--udp-reply-max', str(cap)])
                    out = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
                    self.assertEqual(out.returncode, 0, f'{out.stdout}\n{out.stderr}')
                    row, = json.loads(dest.read_text())['results']
                    self.assertEqual(row['failed_responses'] + row['timeouts'], 0, row)
                    if cap is None:
                        self.assertGreater(row['truncated_responses'], 0)
                        self.assertEqual(row['truncated_responses'], row['total_queries'])
                        self.assertEqual(row['successful_queries'], 0)
                        self.assertEqual(row['dns_response_bytes'], 0)
                        self.assertIsNone(row['p99_ms'])
                    else:
                        self.assertEqual(row['truncated_responses'], 0)
                        self.assertGreater(row['successful_queries'], 0)
                        self.assertEqual(row['dns_response_bytes'], 3869 * row['successful_queries'])

    def test_cold_h2_burst_uses_one_connection_at_default_cap(self):
        with tempfile.TemporaryDirectory(prefix='dnsp-cold-h2-') as td:
            cert, key = make_certificate(Path(td))
            upstream_port, proxy_port, metrics_port = (free_port() for _ in range(3))
            upstream = MockServer(upstream_port, cert, key, protocol='h2', delay_ms=100)
            upstream.start()
            try:
                await_ready(upstream_port, None, 'DoH mock')
                with tempfile.TemporaryFile() as log, subprocess.Popen([
                    str(BASE/'dnsp-modern'), '-p', str(proxy_port), '-m', str(metrics_port),
                    '-s', f'https://localhost:{upstream_port}/dns-query', '--ca-file', str(cert),
                    '--bootstrap-address', '127.0.0.1',
                ], stderr=log) as proxy:
                    try:
                        await_ready(metrics_port, proxy, 'DNSProxy metrics')
                        self.assertEqual(metric_snapshot(metrics_port)['dnsp_upstream_requests_total'], 0)
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                            client.settimeout(4)
                            for ident in range(12):
                                packet = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 1) + DNS_QUESTION + EDNS_OPT
                                client.sendto(packet, ('127.0.0.1', proxy_port))
                            replies = [client.recv(4096) for _ in range(12)]
                        self.assertCountEqual([struct.unpack_from('!H', r)[0] for r in replies], range(12))
                        self.assertTrue(all((r[2]&0x80) and (r[3]&15)==0 for r in replies))
                        await_quiescent(metrics_port, upstream)
                        timing = metric_snapshot(metrics_port)
                        self.assertEqual(timing['dnsp_upstream_phase_duration_seconds_count{phase="tls"}'], 1)
                        self.assertGreater(timing['dnsp_upstream_phase_duration_seconds_sum{phase="tls"}'], 0)
                        self.assertEqual(timing['dnsp_upstream_phase_duration_seconds_count{phase="first_byte"}'], 12)
                        observed = upstream.app.snapshot()
                        self.assertEqual(observed['upstream_http_versions'].get('2'), 12)
                        self.assertEqual(observed['upstream_connections_used'], 1, observed)
                        self.assertGreaterEqual(observed['upstream_max_simultaneous_per_connection'], 2)
                    finally:
                        proxy.terminate()
                        try:
                            proxy.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            proxy.kill()
                            proxy.wait(timeout=3)
            finally:
                upstream.close()

    def test_h2_multiplex_and_h1_control(self):
        # Requires hypercorn/h2/openssl; intentionally separate from modern-check.
        with tempfile.TemporaryDirectory(prefix='dnsp-bench-ci-') as td:
            dest = Path(td)/'results.json'
            cmd = [sys.executable, str(BASE/'bench/bench_modern.py'),
                   '--binary', str(BASE/'dnsp-modern'),
                   '--protocol', 'both', '--concurrency', '1,8',
                   '--duration', '0.7', '--warmup', '0.2',
                   '--max-host-connections', '1', '--assert-h2-multiplex',
                   '--h2-max-streams', '4', '--h2-idle-timeout', '0.25',
                   '--output', str(dest)]
            out = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(out.returncode, 0, f'{out.stdout}\n{out.stderr}')
            results = json.loads(dest.read_text())['results']
            self.assertEqual(len(results), 4)
            h2 = next(r for r in results if r['protocol_requested']=='h2' and r['concurrency']==8)
            h1 = next(r for r in results if r['protocol_requested']=='h1' and r['concurrency']==8)
            self.assertGreaterEqual(h2['upstream_observed']['upstream_max_simultaneous_per_connection'], 2)
            self.assertLessEqual(h2['upstream_observed']['upstream_max_simultaneous_per_connection'], 4)
            self.assertEqual(h1['upstream_observed']['upstream_max_simultaneous_per_connection'], 1)
            self.assertGreater(h2['curl_metric_delta']['dnsp_upstream_http_responses_total{version="2"}'], 0)
            self.assertEqual(h1['curl_metric_delta']['dnsp_upstream_http_responses_total{version="2"}'], 0)
            self.assertGreater(h2['successful_queries'], 0)
            self.assertGreater(h1['successful_queries'], 0)
            self.assertGreater(h2['proxy_rss_peak_bytes'], 0)
            phases = h2['upstream_phases']
            self.assertEqual(phases['first_byte']['samples'], h2['successful_queries'])
            self.assertGreater(phases['first_byte']['mean_ms'], 0)
            self.assertEqual(phases['tls'], {'samples': 0, 'mean_ms': None})
            idle = h2['h2_idle_probe']
            self.assertEqual(idle['successful_queries'], 1)
            self.assertEqual(idle['curl_metric_delta']['dnsp_upstream_new_connections_total'], 1)
            self.assertEqual(idle['upstream_phases']['tls']['samples'], 1)
            self.assertIsNone(h1['h2_idle_probe'])
            self.assertTrue(dest.with_suffix('.csv').is_file())

    def test_h2_recovers_after_goaway(self):
        with tempfile.TemporaryDirectory(prefix='dnsp-goaway-') as td:
            dest = Path(td)/'results.json'
            out = subprocess.run([
                sys.executable, str(BASE/'bench/bench_modern.py'),
                '--protocol', 'h2', '--concurrency', '1', '--h2-max-requests', '2',
                '--warmup', '0.001', '--duration', '4.5', '--output', str(dest),
            ], text=True, capture_output=True, timeout=30)
            self.assertEqual(out.returncode, 0, f'{out.stdout}\n{out.stderr}')
            result, = json.loads(dest.read_text())['results']
            # One request used the original connection during warmup. Successful
            # replies on two peer sockets prove recovery beyond the GOAWAY boundary.
            self.assertGreaterEqual(result['successful_queries'], 2, result)
            self.assertGreaterEqual(result['upstream_observed']['upstream_connections_used'], 2, result)
            self.assertGreaterEqual(result['curl_metric_delta']['dnsp_upstream_new_connections_total'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
