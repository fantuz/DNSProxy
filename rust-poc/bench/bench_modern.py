#!/usr/bin/env python3
"""Closed-loop DNSProxy UDP benchmark with TLS/ALPN DoH upstream.

No root, external traffic or metrics-server modification needed by default.
The synthetic upstream supports real HTTP/2 and optional HTTP/3 and tracks
simultaneous streams per connection.
"""
import argparse
from array import array
import csv
import http.client
import json
import math
import os
from pathlib import Path
import socket
import selectors
import subprocess
import sys
import tempfile
import time

from mock_doh import MockServer

ROOT = Path(__file__).resolve().parent.parent
DNS_QUESTION = bytes.fromhex('076578616d706c6503636f6d0000010001')
EDNS_OPT = b'\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00'  # UDP 4096 bytes
HTTP3_COUNTER = 'dnsp_upstream_http_responses_total{version="3"}'
COUNTERS = [
    'dnsp_upstream_requests_total', 'dnsp_upstream_success_total',
    'dnsp_upstream_failures_total', 'dnsp_upstream_timeouts_total',
    'dnsp_upstream_new_connections_total', 'dnsp_upstream_reused_requests_total',
    'dnsp_upstream_http_responses_total{version="1"}',
    'dnsp_upstream_http_responses_total{version="2"}',
    'dnsp_upstream_duration_seconds_sum', 'dnsp_upstream_duration_seconds_count',
    'dnsp_overload_total', 'dnsp_truncated_responses_total',
]
PHASES = ('queue', 'tls', 'first_byte')


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def make_certificate(directory):
    cert = directory/'localhost.pem'
    key = directory/'localhost.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-keyout', str(key), '-out', str(cert),
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def metric_snapshot(port):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        conn.request('GET', '/metrics')
        response = conn.getresponse()
        if response.status != 200:
            raise RuntimeError(f'metrics HTTP status {response.status}')
        raw = response.read().decode('ascii')
    finally:
        conn.close()
    values = {}
    for line in raw.splitlines():
        if not line or line.startswith('#'):
            continue
        name, value = line.rsplit(None, 1)
        values[name] = float(value)
    missing = [key for key in COUNTERS if key not in values]
    if missing:
        raise RuntimeError(f'missing expected metrics: {missing}')
    return values


def metrics_delta(before, after):
    delta = {k: after[k]-before[k] for k in COUNTERS}
    if HTTP3_COUNTER in before and HTTP3_COUNTER in after:
        delta[HTTP3_COUNTER] = after[HTTP3_COUNTER] - before[HTTP3_COUNTER]
    return delta


def phase_timings(before, after):
    phases = {}
    for phase in PHASES:
        count_key = f'dnsp_upstream_phase_duration_seconds_count{{phase="{phase}"}}'
        sum_key = f'dnsp_upstream_phase_duration_seconds_sum{{phase="{phase}"}}'
        count = int(after.get(count_key, 0) - before.get(count_key, 0))
        total = after.get(sum_key, 0) - before.get(sum_key, 0)
        phases[phase] = {'samples': count, 'mean_ms': round(total * 1000 / count, 3) if count else None}
    return phases


def proxy_cpu_rss(pid):
    """Process CPU seconds and resident memory bytes, Linux /proc only."""
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        fields = raw[raw.rfind(')')+2:].split()  # starts at field 3
        ticks = os.sysconf('SC_CLK_TCK')
        cpu = (int(fields[11])+int(fields[12]))/ticks
        rss = int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
        hwm = rss
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmHWM:'):
                hwm = int(line.split()[1]) * 1024
                break
        return cpu, rss, hwm
    except (OSError, ValueError, IndexError):
        return None, None, None


def percentile(sorted_values, percentile_value):
    if not sorted_values:
        return None
    pos = (len(sorted_values)-1) * percentile_value / 100.0
    low = int(pos)
    frac = pos-low
    if low+1 < len(sorted_values):
        return round(float(sorted_values[low]*(1-frac) + sorted_values[low+1]*frac), 3)
    return round(float(sorted_values[low]), 3)


def one_load(port, concurrency, seconds):
    """Closed-loop N-client UDP load using selectors, not N OS threads.

    One outstanding request per connected socket. All clients start together;
    no thread-start/GIL scheduling delay in the concurrency ramp.
    """
    selector = selectors.DefaultSelector()
    states = {}
    samples = array('f')  # microseconds, 4 bytes/observation
    errors = timeouts = truncated = received_bytes = 0
    idle_timeout_s = 3.5  # proxy upstream deadline is 3.0 s

    def submit(s, state):
        state['id'] = (state['id']+1) & 0xffff
        packet = (state['id'].to_bytes(2, 'big') + b'\x01\x00\x00\x01' +
                  b'\x00\x00'*2 + b'\x00\x01' + DNS_QUESTION + EDNS_OPT)
        state['sent_ns'] = time.perf_counter_ns()
        try:
            n = s.send(packet)
            return n == len(packet)
        except OSError:
            return False

    def forget(s):
        selector.unregister(s)
        states.pop(s, None)
        s.close()

    try:
        for i in range(concurrency):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            s.connect(('127.0.0.1', port))
            selector.register(s, selectors.EVENT_READ)
            states[s] = {'id': (i*521+1)&0xffff, 'sent_ns': 0}
        start = time.perf_counter()
        stop_at = start+seconds
        for s, state in states.items():
            if not submit(s, state):
                errors += 1
        while states:
            now = time.perf_counter()
            next_deadline = min(st['sent_ns']/1e9+idle_timeout_s for st in states.values())
            wait = max(0.0, next_deadline-now)
            # Wake up at the requested end time to avoid over-sending queries.
            if now < stop_at:
                wait = min(wait, stop_at-now)
            for key, _ in selector.select(wait):
                s = key.fileobj
                state = states.get(s)
                if state is None:
                    continue
                try:
                    answer = s.recv(4096)
                    elapsed_us = (time.perf_counter_ns()-state['sent_ns'])/1000.0
                    if (len(answer)<12 or answer[:2] != state['id'].to_bytes(2, 'big')
                            or not answer[2]&0x80):
                        errors += 1
                    elif answer[2]&0x02:
                        truncated += 1
                    elif answer[3]&15:
                        errors += 1
                    else:
                        samples.append(elapsed_us)
                        received_bytes += len(answer)
                except BlockingIOError:
                    continue
                except OSError:
                    errors += 1
                if time.perf_counter() < stop_at:
                    if not submit(s, state):
                        errors += 1
                else:
                    forget(s)
            now = time.perf_counter()
            for s, state in list(states.items()):
                if now-state['sent_ns']/1e9 >= idle_timeout_s:
                    timeouts += 1
                    if now < stop_at:
                        if not submit(s, state):
                            errors += 1
                    else:
                        forget(s)
        elapsed = time.perf_counter()-start
    finally:
        for s in list(states):
            try:
                selector.unregister(s)
            except Exception:
                pass
            s.close()
        selector.close()
    samples = sorted(samples)
    n = len(samples)
    return {
        'elapsed_s': round(elapsed, 3), 'successful_queries': n,
        'failed_responses': errors, 'timeouts': timeouts, 'truncated_responses': truncated,
        'total_queries': n+errors+timeouts+truncated, 'qps': round(n/elapsed, 2),
        'dns_response_bytes': received_bytes,
        'dns_response_mib_s': round(received_bytes/elapsed/1048576, 4),
        'p50_ms': round(percentile(samples, 50)/1000, 3) if n else None,
        'p95_ms': round(percentile(samples, 95)/1000, 3) if n else None,
        'p99_ms': round(percentile(samples, 99)/1000, 3) if n else None,
        'max_ms': round(float(samples[-1])/1000, 3) if n else None,
        'latency_samples': n,
    }


def await_ready(port, process, name, timeout=12):
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f'{name} exited prematurely with code {process.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f'{name} did not start on port {port}')


def await_quiescent(metrics_port, upstream, timeout=10.0):
    """Prevent cross-scenario contamination after client timeouts or curl backlog."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proxy_idle = metric_snapshot(metrics_port).get('dnsp_queries_inflight', 0) == 0
        upstream_idle = upstream is None or upstream.app.snapshot()['upstream_inflight'] == 0
        if proxy_idle and upstream_idle:
            return
        time.sleep(0.05)
    raise RuntimeError('proxy/upstream failed to drain inflight requests between scenarios')


def run_suite(args, protocol, tmpdir):
    upstream_server = None
    proxy = None
    proxy_log = tmpdir / f'proxy-{protocol}.log'
    f = None
    try:
        upstream_port = args.mock_upstream_port or free_port()
        proxy_port = free_port()
        metrics_port = free_port()
        if args.upstream_url:
            url = args.upstream_url
            cert = None
        else:
            cert, key = make_certificate(tmpdir)
            upstream_server = MockServer(upstream_port, cert, key, protocol=protocol,
                                         delay_ms=args.upstream_delay_ms, answers=args.answers,
                                         h2_max_streams=args.h2_max_streams,
                                         h2_idle_timeout=args.h2_idle_timeout or 30,
                                         h2_max_requests=args.h2_max_requests)
            upstream_server.start()
            await_ready(upstream_port, None, 'DoH mock')
            if upstream_server.failure:
                raise RuntimeError(f'upstream start failed: {upstream_server.failure}')
            url = f'https://localhost:{upstream_port}/dns-query'
        cmd = [str(args.binary), '-p', str(proxy_port), '-m', str(metrics_port),
               '-s', url, '--max-host-connections', str(args.max_host_connections)]
        if args.udp_reply_max is not None:
            cmd += ['--udp-reply-max', str(args.udp_reply_max)]
        if cert:
            cmd += ['--ca-file', str(cert), '--bootstrap-address', '127.0.0.1']
        if protocol == 'h3':
            cmd.append('--upstream-http=prefer-h3')
        f = proxy_log.open('wb')
        proxy = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=f)
        await_ready(metrics_port, proxy, 'DNSProxy metrics')
        rows = []
        for concurrency in args.concurrency:
            # Prewarm both TLS session and libcurl's HTTP/2 multiplexing knowledge.
            await_quiescent(metrics_port, upstream_server)
            if upstream_server:
                upstream_server.app.reset()
            # Let curl learn the advertised stream limit before ramping up a
            # constrained fixture. This keeps SETTINGS discovery out of the run.
            warm_clients = min(concurrency, 8)
            if protocol == 'h2' and args.h2_max_streams < concurrency:
                warm_clients = 1
            one_load(proxy_port, warm_clients, args.warmup)
            await_quiescent(metrics_port, upstream_server)
            idle_probe = None
            if protocol == 'h2' and args.h2_idle_timeout:
                before_idle = metric_snapshot(metrics_port)
                time.sleep(args.h2_idle_timeout + 0.2)
                # Zero seconds still issues the initial single query.
                idle_probe = one_load(proxy_port, 1, 0)
                await_quiescent(metrics_port, upstream_server)
                after_idle = metric_snapshot(metrics_port)
                idle_probe['curl_metric_delta'] = metrics_delta(before_idle, after_idle)
                idle_probe['upstream_phases'] = phase_timings(before_idle, after_idle)
            if upstream_server:
                upstream_server.app.reset()
            before = metric_snapshot(metrics_port)
            cpu_before, rss_before, _ = proxy_cpu_rss(proxy.pid)
            result = one_load(proxy_port, concurrency, args.duration)
            cpu_after, rss_after, rss_peak = proxy_cpu_rss(proxy.pid)
            await_quiescent(metrics_port, upstream_server)
            after = metric_snapshot(metrics_port)
            result.update({
                'protocol_requested': protocol if upstream_server else 'external',
                'concurrency': concurrency, 'max_host_connections': args.max_host_connections,
                'upstream_delay_ms': args.upstream_delay_ms if upstream_server else None,
                'proxy_cpu_seconds': round(cpu_after-cpu_before, 4) if cpu_after is not None and cpu_before is not None else None,
                'proxy_cpu_percent_of_one_core': round(100*(cpu_after-cpu_before)/result['elapsed_s'], 2)
                    if cpu_after is not None and cpu_before is not None else None,
                'proxy_rss_start_bytes': rss_before, 'proxy_rss_end_bytes': rss_after,
                'proxy_rss_peak_bytes': rss_peak,
                'proxy_rss_delta_bytes': rss_after-rss_before if rss_before is not None and rss_after is not None else None,
                'curl_metric_delta': metrics_delta(before, after),
                'upstream_phases': phase_timings(before, after),
                'h2_idle_probe': idle_probe,
                'upstream_observed': upstream_server.app.snapshot() if upstream_server else None,
            })
            if args.assert_h2_multiplex and upstream_server and protocol=='h2' and concurrency>=8:
                obs = result['upstream_observed']
                if (obs['upstream_max_simultaneous_per_connection']<2 or
                    not obs['upstream_http_versions'].get('2') or
                    result['curl_metric_delta']['dnsp_upstream_http_responses_total{version="2"}']<1):
                    raise AssertionError(f'HTTP/2 multiplexing not confirmed at concurrency={concurrency}: {result}')
            if args.assert_h3_multiplex and protocol == 'h3':
                observed = result['upstream_observed']
                if (set(observed['upstream_http_versions']) != {'3'} or
                        not result['curl_metric_delta'].get(HTTP3_COUNTER, 0) or
                        (concurrency >= 8 and observed['upstream_max_simultaneous_per_connection'] < 2)):
                    raise AssertionError(f'HTTP/3 negotiation or multiplexing not confirmed: {result}')
            rows.append(result)
            # Retain completed scenarios even if a later level cannot finish.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.with_suffix('.partial.jsonl').open('a') as partial:
                partial.write(json.dumps(result, sort_keys=True) + '\n')
            obs = result['upstream_observed'] or {}
            print(f"{protocol:4s}  c={concurrency:3d}  qps={result['qps']:9.1f}  "
                  f"p95={result['p95_ms']!s:>8} ms  p99={result['p99_ms']!s:>8} ms  "
                  f"truncated={result['truncated_responses']}  "
                  f"cpu={result['proxy_cpu_percent_of_one_core']}%  "
                  f"dnsMiB/s={result['dns_response_mib_s']:.3f}  "
                  f"new={result['curl_metric_delta']['dnsp_upstream_new_connections_total']:.0f}  "
                  f"reuse={result['curl_metric_delta']['dnsp_upstream_reused_requests_total']:.0f}  "
                  f"streams/conn_peak={obs.get('upstream_max_simultaneous_per_connection', 'n/a')}", flush=True)
        return rows
    finally:
        if proxy:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill();proxy.wait()
        if upstream_server:
            upstream_server.close()
        if f:
            f.close()
        if args.verbose and proxy_log.exists():
            print(f'[proxy {protocol} stderr]\n{proxy_log.read_text()[-15000:]}', file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=lambda s: Path(s).resolve(), default=ROOT/'dnsp-modern')
    parser.add_argument('--protocol', choices=('h2', 'h1', 'both', 'h3', 'h2-h3'), default='both',
                        help='Use both for HTTP/2 and HTTP/1.1, or h2-h3 for a matched QUIC comparison')
    parser.add_argument('--concurrency', default='1,8,32,64',
                        help='Comma-separated numbers of concurrent closed-loop UDP clients')
    parser.add_argument('--duration', type=float, default=10.0, help='Measurement seconds per level')
    parser.add_argument('--warmup', type=float, default=1.0, help='Warmup seconds per level')
    parser.add_argument('--upstream-delay-ms', type=float, default=5.0)
    parser.add_argument('--answers', type=int, default=1, help='A records per reply (1..240); tests response payload size')
    parser.add_argument('--udp-reply-max', type=int, help='Proxy UDP reply cap in bytes (512..4096)')
    parser.add_argument('--max-host-connections', type=int, default=1)
    parser.add_argument('--h2-max-streams', type=int, default=100,
                        help='Advertised HTTP/2 stream limit on the synthetic upstream')
    parser.add_argument('--h2-idle-timeout', type=float,
                        help='Set the mock HTTP/2 idle timeout and measure the first query after it expires')
    parser.add_argument('--h2-max-requests', type=int, default=10_000_000,
                        help='Synthetic HTTP/2 connection request ceiling for exercising GOAWAY')
    parser.add_argument('--mock-upstream-port', type=int, help='Fixed loopback port for traffic shaping')
    parser.add_argument('--upstream-url', help='Optional real HTTPS DoH endpoint; requires public trusted CA; no synthetic upstream statistics')
    parser.add_argument('--assert-h2-multiplex', action='store_true', help='Fail if synthetic HTTP/2 concurrent streams are not observed at c>=8')
    parser.add_argument('--assert-h3-multiplex', action='store_true',
                        help='Require only HTTP/3 responses and concurrent streams at c>=8')
    parser.add_argument('--output', type=Path, default=Path('dist/bench-modern.json'))
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    try:
        args.concurrency = [int(s) for s in args.concurrency.split(',')]
    except ValueError:
        parser.error('concurrency must be integers separated by commas')
    if (not args.concurrency or any(c<1 or c>128 for c in args.concurrency) or
        args.duration<=0 or args.warmup<=0 or args.answers<1 or args.answers>240 or
        args.max_host_connections<1 or args.max_host_connections>16 or
        args.upstream_delay_ms<0):
        parser.error('invalid benchmark argument (concurrency 1..128, connections 1..16)')
    if args.upstream_url and (not args.upstream_url.startswith('https://') or args.protocol in ('both', 'h2-h3')):
        parser.error('external upstream requires HTTPS and one requested protocol')
    if args.assert_h3_multiplex and (args.upstream_url or args.protocol not in ('h3', 'h2-h3')):
        parser.error('--assert-h3-multiplex requires a synthetic HTTP/3 scenario')
    if not 1 <= args.h2_max_streams <= 2**31 - 1 or args.h2_max_requests < 1:
        parser.error('HTTP/2 stream and request limits must be positive (streams <= 2147483647)')
    if args.h2_idle_timeout is not None and not (math.isfinite(args.h2_idle_timeout) and args.h2_idle_timeout > 0):
        parser.error('--h2-idle-timeout must be a positive finite number')
    if args.mock_upstream_port is not None and not 1 <= args.mock_upstream_port <= 65535:
        parser.error('--mock-upstream-port must be in 1..65535')
    if args.udp_reply_max is not None and not 512 <= args.udp_reply_max <= 4096:
        parser.error('--udp-reply-max must be in 512..4096')
    h2_controls = (args.h2_idle_timeout is not None or
                   args.h2_max_streams != 100 or args.h2_max_requests != 10_000_000)
    if args.upstream_url and (h2_controls or args.mock_upstream_port is not None):
        parser.error('HTTP/2 fixture controls and --mock-upstream-port require the synthetic upstream')
    if args.protocol in ('h1', 'h3') and h2_controls:
        parser.error('HTTP/2 fixture controls require an HTTP/2 scenario')
    return args


def main():
    args = parse_args()
    if not args.binary.is_file():
        raise SystemExit(f'proxy binary missing: {args.binary}; run make -f modern.mk')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix('.partial.jsonl').unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='dnsp-bench-') as name:
        temp = Path(name)
        rows = []
        comparisons = {'both': ('h2', 'h1'), 'h2-h3': ('h2', 'h3')}
        for protocol in comparisons.get(args.protocol, (args.protocol,)):
            rows.extend(run_suite(args, protocol, temp))
    output = args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    document = {
        'schema': 1, 'description': 'DNSProxy modern controlled TLS DoH benchmark',
        'disclaimer': 'Closed-loop selector-driven UDP queries; synthetic upstream in Python shares host CPU with load generator; do not treat as Internet DoH performance.',
        'config': {k: str(v) if isinstance(v, Path) else v for k,v in vars(args).items()},
        'host': {'os': os.uname().sysname if hasattr(os, 'uname') else sys.platform,
                 'cpu_count': os.cpu_count()},
        'results': rows,
    }
    output.write_text(json.dumps(document, indent=2)+'\n')
    with output.with_suffix('.csv').open('w', newline='') as f:
        fields = ['protocol_requested', 'concurrency', 'successful_queries',
                  'failed_responses', 'timeouts', 'truncated_responses', 'qps', 'dns_response_mib_s', 'p50_ms', 'p95_ms',
                  'p99_ms', 'max_ms', 'proxy_cpu_percent_of_one_core',
                  'proxy_rss_end_bytes', 'proxy_rss_peak_bytes', 'proxy_rss_delta_bytes']
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    print(f'Results: {output} and {output.with_suffix(".csv")}')


if __name__ == '__main__':
    main()
