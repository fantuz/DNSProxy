#!/usr/bin/env python3
"""Compare local DNS forwarding paths and warm answer caches on Linux."""
import argparse
import base64
import csv
import hashlib
import itertools
import json
import multiprocessing
import os
import platform
import selectors
import socket
import struct
import subprocess
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from statistics import median
from urllib.parse import parse_qs

from bench_modern import await_ready, free_ports, make_certificate, percentile, proxy_cpu_rss
from mock_doh import DohApp, MockServer
from plain_dns import udp_worker

SEQUENCE = itertools.count()
HOT_NAMES = 16
SUFFIX = b'\x07example\x00\x00\x01\x00\x01'
EDNS = bytes.fromhex('00002904d0000000000000')  # 1232-byte UDP payload
ANSWER_ADDRESS = socket.inet_aton('192.0.2.1')


class ComparisonApp(DohApp):
    """Serve A records in .example and NXDOMAIN for resolver startup probes."""

    def _clear(self):
        super()._clear()
        self.methods = Counter()

    def snapshot(self):
        result = super().snapshot()
        with self.lock:
            result['methods'] = dict(self.methods)
        return result

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http' and scope['path'] == '/dns-query':
            method = scope['method']
            with self.lock:
                self.methods[method] += 1
            if method == 'GET':
                value, = parse_qs(scope['query_string'])[b'dns']
                body = base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))

                async def receive_get():
                    return {'type': 'http.request', 'body': body}

                receive = receive_get
                scope = {**scope, 'method': 'POST'}
        await super().__call__(scope, receive, send)


def fixture_worker(channel, port, cert, key, delay_ms):
    server = MockServer(port, cert, key, protocol='h2')
    server.app = ComparisonApp(delay_ms=delay_ms, answers=1, question_suffix=SUFFIX)
    server.start()
    try:
        await_ready(port, None, 'HTTP/2 fixture')
        channel.send('ready')
        while True:
            operation = channel.recv()
            if operation == 'stop':
                break
            # The client can receive the last packet just before ASGI records completion.
            deadline = time.monotonic() + 3
            while server.app.snapshot()['upstream_inflight']:
                if time.monotonic() >= deadline:
                    raise RuntimeError('fixture did not drain')
                time.sleep(0.001)
            if operation == 'reset':
                server.app.reset()
            channel.send(server.app.snapshot())
    finally:
        server.close()
        channel.close()


@contextmanager
def fixture(worker, *worker_args):
    ctx = multiprocessing.get_context('spawn')
    parent, child = ctx.Pipe()
    process = ctx.Process(target=worker, args=(child, *worker_args))
    process.start()
    child.close()
    try:
        if not parent.poll(15) or parent.recv() != 'ready':
            raise RuntimeError('fixture failed to start')

        def metrics(operation):
            parent.send(operation)
            if not parent.poll(5):
                raise RuntimeError('fixture failed to return metrics')
            return parent.recv()

        yield metrics
    finally:
        try:
            if process.is_alive():
                parent.send('stop')
        finally:
            parent.close()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()


def valid_reply(packet, query_id, question):
    if len(packet) < 12:
        return False
    txid, flags, questions, answers = struct.unpack_from('!4H', packet)
    offset = 12 + len(question)
    if (txid != query_id or flags & 0x820f != 0x8000 or questions != 1 or answers != 1
            or packet[12:offset] != question):
        return False
    owner = question[:-4]
    if packet[offset:offset+2] == b'\xc0\x0c':
        offset += 2
    elif packet[offset:offset+len(owner)] == owner:
        offset += len(owner)
    else:
        return False
    return (packet[offset:offset+4] == b'\x00\x01\x00\x01'
            and packet[offset+8:offset+14] == b'\x00\x04' + ANSWER_ADDRESS)


def await_forwarding(port, process):
    # dnscrypt-proxy opens its listener before it finishes upstream discovery.
    question = b'\x05ready' + SUFFIX
    packet = struct.pack('!6H', 1, 0x0100, 1, 0, 0, 0) + question
    last_reply = b''
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.25)
            sock.connect(('127.0.0.1', port))
            try:
                sock.send(packet)
                last_reply = sock.recv(65535)
                if valid_reply(last_reply, 1, question):
                    return
            except (TimeoutError, ConnectionRefusedError):
                pass
        time.sleep(0.05)
    raise RuntimeError(f'forwarder failed its readiness query, last reply {last_reply.hex() or "timeout"}')


def question_for(number):
    label = f'q{number:016x}'.encode()
    return bytes([len(label)]) + label + SUFFIX


def prime_cache(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect(('127.0.0.1', port))
        for number in range(HOT_NAMES):
            question = question_for(number)
            txid = next(SEQUENCE) & 0xffff
            sock.send(struct.pack('!6H', txid, 0x0100, 1, 0, 0, 1) + question + EDNS)
            if not valid_reply(sock.recv(65535), txid, question):
                raise RuntimeError('cache priming returned an invalid DNS answer')


def load(port, clients, seconds, workload='miss'):
    pending = {}
    samples = []

    def submit(sock):
        number = next(SEQUENCE)
        question = question_for(number % HOT_NAMES if workload == 'hit' else number)
        query_id = number & 0xffff
        header = struct.pack('!6H', query_id, 0x0100, 1, 0, 0, 1)
        pending[sock] = (query_id, question, time.perf_counter())
        sock.send(header + question + EDNS)

    with selectors.DefaultSelector() as poll:
        sockets = []
        try:
            for _ in range(clients):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                sock.connect(('127.0.0.1', port))
                poll.register(sock, selectors.EVENT_READ)
            start = time.perf_counter()
            for sock in sockets:
                submit(sock)
            while pending:
                deadline = min(item[2] for item in pending.values()) + 4
                for key, _ in poll.select(max(0, deadline - time.perf_counter())):
                    sock = key.fileobj
                    packet = sock.recv(65535)
                    query_id, question, sent = pending.pop(sock)
                    now = time.perf_counter()
                    if now - sent >= 4 or not valid_reply(packet, query_id, question):
                        raise RuntimeError(f'late or invalid DNS reply for {question!r}: {packet.hex()}')
                    samples.append((now - sent) * 1000)
                    if now < start + seconds:
                        submit(sock)
                    else:
                        poll.unregister(sock)
                if any(time.perf_counter() - item[2] >= 4 for item in pending.values()):
                    raise TimeoutError('DNS client timed out')
            elapsed = time.perf_counter() - start
        finally:
            for sock in sockets:
                sock.close()
    samples.sort()
    return dict(queries=len(samples), elapsed_s=round(elapsed, 6),
                qps=round(len(samples) / elapsed, 2),
                p50_ms=percentile(samples, 50), p95_ms=percentile(samples, 95),
                p99_ms=percentile(samples, 99))


def proxy_command(name, binary, port, upstream, cert, directory, workload):
    endpoint = f'127.0.0.1:{upstream}'
    url = f'https://{endpoint}/dns-query'
    if name == 'systemd-resolved':
        # The wrapper mounts a private tmpfs at /etc/systemd and at /run.
        private_ns = ' '.join(os.readlink(f'/proc/self/ns/{kind}') for kind in ('mnt', 'net'))
        if os.environ.get('DNSP_RESOLVED_BENCH_NS') != private_ns or not Path('/etc/systemd').is_mount():
            raise RuntimeError('systemd-resolved requires bench/compare-system-resolver.sh')
        Path('/etc/systemd/resolved.conf').write_text(f"""[Resolve]
DNS={endpoint}
FallbackDNS=
Domains=~.
DNSSEC=no
DNSOverTLS=no
LLMNR=no
MulticastDNS=no
ReadEtcHosts=no
DNSStubListener=no
DNSStubListenerExtra=127.0.0.1:{port}
Cache={'yes' if workload == 'hit' else 'no'}
CacheFromLocalhost=yes
""")
        return [binary]
    if name in ('DNSProxy', 'DNSProxy candidate'):
        return [binary, '-l', '127.0.0.1', '-p', str(port), '-s', url,
                '--ca-file', str(cert), '--cache-entries', '256' if workload == 'hit' else '0']
    if name == 'AdGuard':
        return [binary, '-l', '127.0.0.1', '-p', str(port), '-u', url,
                '--cache=true' if workload == 'hit' else '--cache=false',
                '--dnssec=false', '--hosts-file-enabled=false', '--timeout=3s']
    # DNS stamp fields: DoH, properties, address, empty hash list, TLS host, path.
    def field(value):
        data = value.encode('ascii')
        return bytes([len(data)]) + data

    stamp = b'\x02' + bytes(8) + field('127.0.0.1') + b'\x00' + field(endpoint) + field('/dns-query')
    encoded = base64.urlsafe_b64encode(stamp).rstrip(b'=').decode('ascii')
    config = directory / 'dnscrypt-proxy.toml'
    config.write_text(f"""listen_addresses = ['127.0.0.1:{port}']
server_names = ['fixture']
bootstrap_resolvers = ['{endpoint}']
ignore_system_dns = true
netprobe_timeout = 0
netprobe_address = '{endpoint}'
cache = {'true' if workload == 'hit' else 'false'}
cache_size = 256
cache_min_ttl = 0
block_unqualified = false
block_undelegated = false
http3 = false
timeout = 3000
[static.fixture]
stamp = 'sdns://{encoded}'
""")
    return [binary, '-config', str(config)]


def check_upstream(observed, protocol, expected):
    if (observed['upstream_completed'] != expected or observed['upstream_invalid']
            or observed['upstream_inflight']):
        raise RuntimeError(f'expected {expected} valid upstream completions: {observed}')
    if protocol == 'h2':
        versions = {'2': expected} if expected else {}
        if observed['upstream_http_versions'] != versions or sum(observed['methods'].values()) != expected:
            raise RuntimeError(f'HTTP/2 or method counts differ: {observed}')
    return dict(upstream_h2=expected if protocol == 'h2' else 0,
                upstream_udp=expected if protocol == 'udp' else 0,
                upstream_get=observed.get('methods', {}).get('GET', 0),
                upstream_post=observed.get('methods', {}).get('POST', 0),
                tls_connections=observed.get('upstream_connections_used', 0))


def direct_upstream(args, run, port, metrics):
    for clients in args.clients:
        load(port, clients, args.warmup)
        metrics('reset')
        row = load(port, clients, args.duration)
        upstream = check_upstream(metrics('snapshot'), 'udp', row['queries'])
        yield dict(resolver='Direct UDP', run=run, clients=clients, workload='miss', **row,
                   proxy_cpu_s=None, rss_mib=None, **upstream)


def scenario(name, binary, args, run, directory, cert, upstream, metrics, workload):
    protocol = 'udp' if name == 'systemd-resolved' else 'h2'
    port, = free_ports(1, exclude=[upstream])
    command = proxy_command(name, str(binary), port, upstream, cert, directory, workload)
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}}
    env.update(SSL_CERT_FILE=str(cert), GOMAXPROCS='1')
    # Give the forwarder exclusive use of one allowed CPU among benchmark processes.
    log = directory / 'proxy.log'
    with log.open('wb') as stream:
        process = subprocess.Popen(['taskset', '-c', str(args.cpu), *command], env=env,
                                   stdout=stream, stderr=subprocess.STDOUT, cwd=directory)
        try:
            await_ready(port, process, name)
            await_forwarding(port, process)
            if workload == 'hit':
                metrics('reset')
                prime_cache(port)
                check_upstream(metrics('snapshot'), protocol, HOT_NAMES)
            for clients in args.clients:
                load(port, clients, args.warmup, workload)
                metrics('reset')
                cpu_before, _, _ = proxy_cpu_rss(process.pid)
                row = load(port, clients, args.duration, workload)
                cpu_after, rss, _ = proxy_cpu_rss(process.pid)
                observed = metrics('snapshot')
                n = row['queries'] if workload == 'miss' else 0
                counts = check_upstream(observed, protocol, n)
                row.update(proxy_cpu_s=round(cpu_after - cpu_before, 3), rss_mib=round(rss / 1048576, 2), **counts)
                yield dict(resolver=name, run=run, clients=clients, workload=workload, **row)
        except Exception:
            print(log.read_text(errors='replace')[-3000:], flush=True)
            raise
        finally:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def write_summary(directory, rows):
    lines = ['# Local DoH forwarder comparison', '',
             'Medians across repetitions. The QPS range is the smallest and largest run.',
             'Latency columns are medians of the per-run percentiles. CPU time and RSS',
             'cover the proxy process only. RSS is sampled at the end of each window.', '',
             '| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |',
             '| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |']
    for workload in dict.fromkeys(r['workload'] for r in rows):
        for clients in sorted({r['clients'] for r in rows}):
            for name in dict.fromkeys(r['resolver'] for r in rows):
                group = [r for r in rows if r['clients'] == clients and r['resolver'] == name and r['workload'] == workload]
                if not group:
                    continue
                rates = [r['qps'] for r in group]
                timings = [median(r[key] for r in group) for key in ('p50_ms', 'p95_ms', 'p99_ms')]
                cpu = rss = '—'
                if group[0]['proxy_cpu_s'] is not None:
                    cpu = f"{median(r['proxy_cpu_s'] * 1e6 / r['queries'] for r in group):.0f}"
                    rss = f"{median(r['rss_mib'] for r in group):.1f}"
                lines.append(f'| {workload} | {clients} | {name} | {median(rates):,.0f} | {min(rates):,.0f}–{max(rates):,.0f} | '
                             + ' | '.join(f'{ms:.2f}' for ms in timings) + f' | {cpu} | {rss} |')
    temporary = directory / 'summary.partial.md'
    temporary.write_text('\n'.join(lines) + '\n')
    temporary.replace(directory / 'summary.md')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dnsp', type=Path, default=Path('./dnsp-modern'))
    parser.add_argument('--adguard', type=Path)
    parser.add_argument('--dnscrypt', type=Path)
    parser.add_argument('--candidate', type=Path, help='test a second DNSProxy binary with identical settings')
    parser.add_argument('--systemd-resolved', type=Path, help='also run the private OS stub and its direct UDP upstream')
    parser.add_argument('--direct-udp', action='store_true', help='also measure the plain UDP upstream directly')
    parser.add_argument('--output', type=Path, required=True, help='new results directory')
    parser.add_argument('--clients', type=int, nargs='+', default=[1, 8, 32])
    parser.add_argument('--workloads', nargs='+', choices=('miss', 'hit'), default=['miss'])
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--duration', type=float, default=3)
    parser.add_argument('--warmup', type=float, default=0.75)
    parser.add_argument('--delay-ms', type=float, default=1)
    args = parser.parse_args()
    allowed = sorted(os.sched_getaffinity(0))
    if (len(allowed) < 2 or not all(1 <= n <= 128 for n in args.clients)
            or len(set(args.clients)) != len(args.clients) or len(set(args.workloads)) != len(args.workloads) or args.runs < 1
            or min(args.duration, args.warmup) <= 0 or args.delay_ms < 0):
        parser.error('requires two CPUs, distinct client counts in 1..128 and positive run lengths')
    args.cpu = allowed[0]
    binaries = {name: path.resolve(strict=True) for name, path in
                [('DNSProxy', args.dnsp), ('DNSProxy candidate', args.candidate),
                 ('AdGuard', args.adguard), ('dnscrypt-proxy', args.dnscrypt)] if path is not None}
    if args.systemd_resolved:
        binaries['systemd-resolved'] = args.systemd_resolved.resolve(strict=True)
    software = {}
    for name, binary in binaries.items():
        flag = '-version' if name == 'dnscrypt-proxy' else '--version'
        software[name] = {'version': subprocess.check_output([binary, flag], text=True).strip(),
                          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    model = next((line.partition(':')[2].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                  if line.startswith('model name')), platform.machine())
    metadata = dict(started_utc=datetime.now(timezone.utc).isoformat(), cpu_model=model, system=platform.platform(), python=platform.python_version(),
                    distribution=platform.freedesktop_os_release()['PRETTY_NAME'],
                    dependencies={p: version(p) for p in ['hypercorn', 'h2']}, binaries=software,
                    proxy_cpu=args.cpu, fixture_client_cpus=allowed[1:], runs=args.runs,
                    clients=args.clients, workloads=args.workloads, direct_udp=bool(args.direct_udp or args.systemd_resolved), hot_names=HOT_NAMES, duration_s=args.duration, warmup_s=args.warmup,
                    fixture_delay_ms=args.delay_ms, clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    os.sched_setaffinity(0, allowed[1:])
    partial = args.output / 'measurements.partial.csv'
    with tempfile.TemporaryDirectory() as tmp, partial.open('w', newline='') as output:
        directory = Path(tmp)
        cert, key = make_certificate(directory, san='IP:127.0.0.1,DNS:localhost')
        writer = None
        rows = []
        names = list(binaries)
        if args.systemd_resolved:
            names.remove('systemd-resolved')
            names = ['systemd-resolved', 'Direct UDP', *names]
        elif args.direct_udp:
            names.append('Direct UDP')
        for i in range(args.runs):
            for name in names[i % len(names):] + names[:i % len(names)]:
                for workload in (args.workloads if i % 2 == 0 else reversed(args.workloads)):
                    if name == 'Direct UDP' and workload == 'hit':
                        continue  # An authoritative fixture has no forwarding cache.
                    upstream, = free_ports(1)
                    plain = name in ('Direct UDP', 'systemd-resolved')
                    worker = (udp_worker, upstream, args.delay_ms) if plain else (fixture_worker, upstream, cert, key, args.delay_ms)
                    with fixture(*worker) as metrics:
                        if name == 'Direct UDP':
                            samples = direct_upstream(args, i+1, upstream, metrics)
                        else:
                            samples = scenario(name, binaries[name], args, i+1, directory, cert, upstream, metrics, workload)
                        for row in samples:
                            if writer is None:
                                writer = csv.DictWriter(output, fieldnames=row, lineterminator='\n')
                                writer.writeheader()
                            writer.writerow(row)
                            rows.append(row)
                            output.flush()
                            print(name, workload, 'run', i+1, 'clients', row['clients'], 'QPS', row['qps'], flush=True)

    partial.replace(args.output / 'measurements.csv')
    write_summary(args.output, rows)


if __name__ == '__main__':
    main()
