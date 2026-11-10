"""Loopback HTTP/3 tests. Requires a QUIC-capable libcurl and aioquic."""
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE/'bench'))
from bench_modern import await_ready, free_port, make_certificate, metric_snapshot, one_load  # noqa: E402
from mock_doh import MockServer  # noqa: E402


@asynccontextmanager
async def quic_upstream(upstream, cert, key):
    from mock_h3 import start_http3

    server = await start_http3('127.0.0.1', upstream.port, cert, key, upstream.app)
    try:
        yield
    finally:
        server.close()


class Http3Tests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def upstream(self, *, http2=True):
        with tempfile.TemporaryDirectory(prefix='dnsp-h3-') as tmp:
            cert, key = await asyncio.to_thread(make_certificate, Path(tmp))
            upstream = MockServer(free_port(), cert, key, delay_ms=15)
            if not http2:
                yield upstream, cert, key
                return
            upstream.start()
            try:
                await asyncio.to_thread(await_ready, upstream.port, None, 'DoH mock')
                self.assertIsNone(upstream.failure)
                yield upstream, cert, key
            finally:
                await asyncio.to_thread(upstream.close)

    @contextmanager
    def proxy(self, upstream_port, cert, mode='prefer-h3', hostname='localhost', env=None, backup_port=None):
        dns_port, metrics_port = free_port(), free_port()
        command = [str(BASE/'dnsp-modern'), '-p', str(dns_port), '-m', str(metrics_port),
                   '-s', f'https://{hostname}:{upstream_port}/dns-query', '--ca-file', str(cert)]
        if mode is not None:
            command.append(f'--upstream-http={mode}')
        if env is None:
            command.extend(['--bootstrap-address', '127.0.0.1'])
        if backup_port is not None:
            command.extend(['--backup-upstream', f'https://localhost:{backup_port}/dns-query',
                            '--backup-bootstrap-address', '127.0.0.1',
                            '--doh-connect-ms', '400', '--doh-timeout-ms', '1600'])
        with tempfile.TemporaryFile() as log, subprocess.Popen(command, stderr=log, env=env) as proxy:
            try:
                await_ready(metrics_port, proxy, 'DNSProxy metrics')
                yield dns_port, metrics_port
            finally:
                proxy.terminate()
                try:
                    proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=3)
                if sys.exc_info()[0]:
                    log.seek(0)
                    print(log.read().decode(errors='replace'), file=sys.stderr)

    async def test_h3_opt_in_and_multiplex(self):
        async with self.upstream() as (upstream, cert, key):
            async with quic_upstream(upstream, cert, key):
                with self.proxy(upstream.port, cert, mode=None) as (dns, metrics):
                    initial = await asyncio.to_thread(one_load, dns, 1, 0)
                    self.assertEqual(initial['successful_queries'], 1)
                    self.assertEqual(metric_snapshot(metrics)['dnsp_upstream_http_responses_total{version="2"}'], 1)

        # Exercise QUIC multiplexing without racing a working HTTP/2 listener.
        async with self.upstream(http2=False) as (upstream, cert, key):
            async with quic_upstream(upstream, cert, key):
                with self.proxy(upstream.port, cert) as (dns, metrics):
                    initial = await asyncio.to_thread(one_load, dns, 1, 0)
                    self.assertEqual(initial['successful_queries'], 1)
                    load = await asyncio.to_thread(one_load, dns, 8, 0.25)
                    self.assertGreaterEqual(load['successful_queries'], 8, load)
                    self.assertEqual(load['failed_responses'] + load['timeouts'], 0, load)
                    observed = upstream.app.snapshot()
                    responses = load['successful_queries'] + 1
                    self.assertEqual(observed['upstream_http_versions'], {'3': responses}, observed)
                    self.assertEqual(observed['upstream_connections_used'], 1, observed)
                    self.assertGreaterEqual(observed['upstream_max_simultaneous_per_connection'], 2, observed)
                    stats = metric_snapshot(metrics)
                    self.assertEqual(stats['dnsp_upstream_http_responses_total{version="3"}'], responses)

    def test_matched_benchmark_records_both_negotiated_protocols(self):
        with tempfile.TemporaryDirectory(prefix='dnsp-h3-bench-') as tmp:
            dest = Path(tmp)/'results.json'
            out = subprocess.run([
                sys.executable, str(BASE/'bench/bench_modern.py'), '--protocol', 'h2-h3',
                '--concurrency', '8', '--warmup', '0.3', '--duration', '0.3',
                '--assert-h2-multiplex', '--assert-h3-multiplex', '--output', str(dest),
            ], text=True, capture_output=True, timeout=30)
            self.assertEqual(out.returncode, 0, f'{out.stdout}\n{out.stderr}')
            rows = json.loads(dest.read_text())['results']
            self.assertEqual([row['protocol_requested'] for row in rows], ['h2', 'h3'])
            for version, row in zip((2, 3), rows):
                self.assertGreater(row['successful_queries'], 0, row)
                self.assertEqual(row['failed_responses'] + row['timeouts'], 0, row)
                self.assertGreater(row['curl_metric_delta'][f'dnsp_upstream_http_responses_total{{version="{version}"}}'], 0)

    async def test_fallback_when_udp_gets_no_response(self):
        async with self.upstream() as (upstream, cert, _):
            # Bind UDP without replying so QUIC sees a blackhole instead of ICMP.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as drop:
                drop.bind(('127.0.0.1', upstream.port))
                with self.proxy(upstream.port, cert) as (dns, metrics):
                    result = await asyncio.to_thread(one_load, dns, 1, 0)
                    self.assertEqual(result['successful_queries'], 1, result)
                    stats = metric_snapshot(metrics)
                    self.assertEqual(stats['dnsp_upstream_http_responses_total{version="2"}'], 1)
                    self.assertEqual(stats['dnsp_upstream_http_responses_total{version="3"}'], 0)
                drop.settimeout(1)
                self.assertGreaterEqual(len(drop.recv(4096)), 1200)

    async def test_h3_connection_failure_uses_backup(self):
        async with self.upstream() as (backup, cert, _):
            for blackhole in (False, True):
                with self.subTest(blackhole=blackhole), \
                     socket.socket() as closed, socket.socket(type=socket.SOCK_DGRAM) as udp:
                    # Reserve the port without listening so TCP refuses the connection.
                    closed.bind(('127.0.0.1', 0))
                    port = closed.getsockname()[1]
                    if blackhole:
                        udp.bind(('127.0.0.1', port))
                    with self.proxy(port, cert, backup_port=backup.port) as (dns, metrics):
                        result = await asyncio.to_thread(one_load, dns, 1, 0)
                        self.assertEqual(result['successful_queries'], 1, result)
                        stats = metric_snapshot(metrics)
                        self.assertEqual(stats['dnsp_upstream_endpoint_requests_total{role="primary"}'], 1)
                        self.assertEqual(stats['dnsp_upstream_endpoint_replies_total{role="backup"}'], 1)
                        self.assertEqual(stats['dnsp_upstream_http_responses_total{version="2"}'], 1)

    async def test_oversized_doh_reply_is_terminal_and_proxy_recovers(self):
        async with self.upstream() as (backup, cert, key):
            for version, mode in ((2, 'auto'), (3, 'prefer-h3')):
                with self.subTest(version=version):
                    # 4,096 A records alone exceed the maximum DNS message length.
                    primary = MockServer(free_port(), cert, key, answers=4096)
                    async with AsyncExitStack() as stack:
                        if version == 2:
                            primary.start()
                            stack.push_async_callback(asyncio.to_thread, primary.close)
                            await asyncio.to_thread(await_ready, primary.port, None, 'HTTP/2 mock')
                            self.assertIsNone(primary.failure)
                        else:
                            await stack.enter_async_context(quic_upstream(primary, cert, key))
                        with self.proxy(primary.port, cert, mode=mode, backup_port=backup.port) as (dns, metrics):
                            rejected = await asyncio.to_thread(one_load, dns, 1, 0)
                            self.assertEqual(rejected['failed_responses'], 1, rejected)
                            self.assertEqual(rejected['truncated_responses'] + rejected['timeouts'], 0, rejected)

                            primary.app.answers = 1
                            answer = await asyncio.to_thread(one_load, dns, 1, 0)
                            self.assertEqual(answer['successful_queries'], 1, answer)
                            stats = metric_snapshot(metrics)
                            self.assertEqual(stats['dnsp_upstream_endpoint_requests_total{role="backup"}'], 0)
                            self.assertEqual(stats[f'dnsp_upstream_http_responses_total{{version="{version}"}}'], 2)

    def test_rejects_plaintext_upstream(self):
        proc = subprocess.run([str(BASE/'dnsp-modern'), '--upstream-http', 'prefer-h3',
                               '-s', 'http://127.0.0.1:9443/dns-query'],
                              capture_output=True, timeout=3)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn(b'prefer-h3 requires an HTTPS upstream', proc.stderr)

    async def test_rejects_wrong_certificate_hostname(self):
        async with self.upstream() as (upstream, cert, key):
            async def assert_terminal_failure():
                with self.proxy(upstream.port, cert, hostname='wrong.invalid',
                                backup_port=upstream.port) as (dns, metrics):
                    result = await asyncio.to_thread(one_load, dns, 1, 0)
                    self.assertEqual(result['failed_responses'], 1, result)
                    stats = metric_snapshot(metrics)
                    self.assertEqual(stats['dnsp_upstream_failures_total'], 1)
                    self.assertEqual(stats['dnsp_upstream_endpoint_requests_total{role="backup"}'], 0)
                    self.assertEqual(upstream.app.snapshot()['upstream_http_versions'], {})
            # Check the TCP fallback alone and with a QUIC listener available.
            await assert_terminal_failure()
            async with quic_upstream(upstream, cert, key):
                await assert_terminal_failure()

    async def test_untrusted_h3_certificate_does_not_use_backup(self):
        async with self.upstream() as (primary, cert, key), self.upstream() as (backup, trusted_ca, _):
            async with quic_upstream(primary, cert, key):
                with self.proxy(primary.port, trusted_ca, backup_port=backup.port) as (dns, metrics):
                    result = await asyncio.to_thread(one_load, dns, 1, 0)
                    self.assertEqual(result['failed_responses'], 1, result)
                    stats = metric_snapshot(metrics)
                    self.assertEqual(stats['dnsp_upstream_endpoint_requests_total{role="backup"}'], 0)

    async def test_respects_configured_https_proxy(self):
        class RejectConnect(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                self.server.targets.append(self.path)
                self.send_error(403)

            def log_message(self, *_args):
                pass

        async with self.upstream() as (upstream, cert, key):
            with HTTPServer(('127.0.0.1', 0), RejectConnect) as tunnel:
                tunnel.targets = []
                thread = threading.Thread(target=tunnel.serve_forever, daemon=True)
                thread.start()
                try:
                    url = f'http://127.0.0.1:{tunnel.server_port}'
                    env = dict(os.environ, https_proxy=url, HTTPS_PROXY=url, no_proxy='', NO_PROXY='')
                    async with quic_upstream(upstream, cert, key):
                        with self.proxy(upstream.port, cert, env=env) as (dns, _):
                            result = await asyncio.to_thread(one_load, dns, 1, 0)
                            self.assertEqual(result['failed_responses'], 1, result)
                    self.assertEqual(tunnel.targets, [f'localhost:{upstream.port}'])
                    self.assertEqual(upstream.app.snapshot()['upstream_http_versions'], {})
                finally:
                    await asyncio.to_thread(tunnel.shutdown)
                    thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
