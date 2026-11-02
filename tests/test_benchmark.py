#!/usr/bin/env python3
"""Tests for benchmark report logic and actual loopback TLS/HTTP2 multiplexing."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE/'bench'))
from bench_modern import percentile, proxy_cpu_rss  # noqa: E402
from mock_doh import make_response  # noqa: E402


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
    def test_h2_multiplex_and_h1_control(self):
        # Requires hypercorn/h2/openssl; intentionally separate from modern-check.
        with tempfile.TemporaryDirectory(prefix='dnsp-bench-ci-') as td:
            dest = Path(td)/'results.json'
            cmd = [sys.executable, str(BASE/'bench/bench_modern.py'),
                   '--binary', str(BASE/'dnsp-modern'),
                   '--protocol', 'both', '--concurrency', '1,8',
                   '--duration', '0.7', '--warmup', '0.2',
                   '--max-host-connections', '1', '--assert-h2-multiplex',
                   '--output', str(dest)]
            out = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(out.returncode, 0, f'{out.stdout}\n{out.stderr}')
            results = json.loads(dest.read_text())['results']
            self.assertEqual(len(results), 4)
            h2 = next(r for r in results if r['protocol_requested']=='h2' and r['concurrency']==8)
            h1 = next(r for r in results if r['protocol_requested']=='h1' and r['concurrency']==8)
            self.assertGreaterEqual(h2['upstream_observed']['upstream_max_simultaneous_per_connection'], 2)
            self.assertEqual(h1['upstream_observed']['upstream_max_simultaneous_per_connection'], 1)
            self.assertGreater(h2['curl_metric_delta']['dnsp_upstream_http_responses_total{version="2"}'], 0)
            self.assertEqual(h1['curl_metric_delta']['dnsp_upstream_http_responses_total{version="2"}'], 0)
            self.assertGreater(h2['successful_queries'], 0)
            self.assertGreater(h1['successful_queries'], 0)
            self.assertGreater(h2['proxy_rss_peak_bytes'], 0)
            self.assertTrue(dest.with_suffix('.csv').is_file())


if __name__ == '__main__':
    unittest.main(verbosity=2)
