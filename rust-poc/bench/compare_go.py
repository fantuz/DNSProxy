#!/usr/bin/env python3
"""Linux application baseline: current C/Rust and pinned AdGuard dnsproxy (Go).

The proxy alone is restricted to one CPU. Clients and the synthetic TLS DoH
server share the host. Unique question names prevent cache/coalescing hits.
This compares complete applications, not language runtimes in isolation.
"""
import argparse
from array import array
import base64
from collections import Counter
import csv
import itertools
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import statistics
import subprocess
import sys
import time
from urllib.parse import parse_qs

from bench_modern import await_ready, free_port, percentile, proxy_cpu_rss
from mock_doh import DohApp, MockServer

GO_VERSION = 'v0.86.0'
SEQUENCE = itertools.count()


class GetPostDohApp(DohApp):
    """Accept RFC 8484 GET as used by Go, alongside the C/Rust POST path."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.methods = Counter()

    def reset(self):
        super().reset()
        with self.lock:
            self.methods.clear()

    def snapshot(self):
        result = super().snapshot()
        with self.lock:
            result['upstream_http_methods'] = dict(self.methods)
        return result

    def record_method(self, method):
        with self.lock:
            self.methods[method] += 1

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            self.record_method(scope['method'])
        if scope['type'] == 'http' and scope['method'] == 'GET' and scope['path'] == '/dns-query':
            query = parse_qs(scope.get('query_string', b'').decode('ascii'))
            value, = query['dns']
            body = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

            async def receive_body():
                return {'type': 'http.request', 'body': body, 'more_body': False}

            scope = {**scope, 'method': 'POST'}
            receive = receive_body
        await super().__call__(scope, receive, send)


def load(port, transport, clients, seconds, answers):
    """One outstanding query per socket; TCP connections persist for the level."""
    selector = selectors.DefaultSelector()
    states = {}
    samples = array('f')
    received_bytes = 0

    def submit(sock, state):
        number = next(SEQUENCE)
        label = f'q{number:016x}'.encode('ascii')
        question = bytes([len(label)]) + label + b'\x07example\x00\x00\x01\x00\x01'
        packet = ((number & 65535).to_bytes(2, 'big') +
                  b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01' + question +
                  b'\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00')
        state.update(id=packet[:2], question=question, started=time.perf_counter(),
                     incoming=bytearray(), outgoing=memoryview(
                         len(packet).to_bytes(2, 'big') + packet
                         if transport == 'tcp' else packet))
        selector.modify(sock, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def close(sock):
        selector.unregister(sock)
        states.pop(sock)
        sock.close()

    try:
        for _ in range(clients):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM
                                 if transport == 'tcp' else socket.SOCK_DGRAM)
            try:
                sock.settimeout(3.5)
                sock.connect(('127.0.0.1', port))
                if transport == 'tcp':
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ)
                states[sock] = {}
            except BaseException:
                sock.close()
                raise
        started = time.perf_counter()
        stop_at = started + seconds
        for sock, state in states.items():
            submit(sock, state)
        while states:
            deadline = min(state['started'] + 3.5 for state in states.values())
            for key, mask in selector.select(max(0, deadline-time.perf_counter())):
                sock = key.fileobj
                state = states[sock]
                if mask & selectors.EVENT_WRITE:
                    try:
                        sent = sock.send(state['outgoing'])
                    except BlockingIOError:
                        continue
                    if sent == 0 or (transport == 'udp' and sent != len(state['outgoing'])):
                        raise RuntimeError('short/closed DNS write')
                    state['outgoing'] = state['outgoing'][sent:]
                    if not state['outgoing']:
                        selector.modify(sock, selectors.EVENT_READ)
                if not mask & selectors.EVENT_READ:
                    continue
                try:
                    chunk = sock.recv(65535)
                except BlockingIOError:
                    continue
                if not chunk:
                    raise RuntimeError('DNS connection closed before response')
                state['incoming'].extend(chunk)
                packet = state['incoming']
                if transport == 'tcp':
                    if len(packet) < 2:
                        continue
                    length = int.from_bytes(packet[:2], 'big')
                    if len(packet) < length + 2:
                        continue
                    if len(packet) != length + 2:
                        raise RuntimeError('unexpected extra TCP response data')
                    packet = packet[2:]
                question = state['question']
                if (len(packet) < 12 or packet[:2] != state['id'] or
                        not packet[2] & 0x80 or packet[2] & 2 or packet[3] & 15 or
                        packet[4:6] != b'\x00\x01' or
                        int.from_bytes(packet[6:8], 'big') != answers or
                        packet[12:12+len(question)] != question):
                    raise RuntimeError(f'invalid/truncated DNS response: {bytes(packet).hex()}')
                samples.append((time.perf_counter()-state['started'])*1000)
                received_bytes += len(packet)
                if time.perf_counter() < stop_at:
                    submit(sock, state)
                else:
                    close(sock)
            if any(time.perf_counter()-state['started'] >= 3.5 for state in states.values()):
                raise RuntimeError('DNS query exceeded the 3.5 second client deadline')
        elapsed = time.perf_counter()-started
    finally:
        for sock in list(states):
            close(sock)
        selector.close()
    ordered = sorted(samples)
    return dict(successful_queries=len(samples), qps=round(len(samples)/elapsed, 2),
                elapsed_s=elapsed, p50_ms=percentile(ordered, 50),
                p95_ms=percentile(ordered, 95), p99_ms=percentile(ordered, 99),
                dns_response_bytes=received_bytes, failed_responses=0, timeouts=0)


def drain(server):
    deadline = time.monotonic()+5
    while server.app.snapshot()['upstream_inflight']:
        if time.monotonic() >= deadline:
            raise RuntimeError('upstream did not drain')
        time.sleep(0.01)


def scenario(args, name, binary, protocol, transport, answers, run, cert, key):
    proxy_port, upstream_port = free_port(), free_port()
    while upstream_port == proxy_port:
        upstream_port = free_port()
    server = MockServer(upstream_port, cert, key, protocol=protocol,
                        delay_ms=args.delay_ms, answers=answers)
    server.app = GetPostDohApp(delay_ms=args.delay_ms, answers=answers)
    log = args.output / f'{name}-{protocol}-{transport}-{answers}-{run}.log'
    proxy = None
    server.start()
    try:
        await_ready(upstream_port, None, 'DoH fixture')
        if server.failure:
            raise RuntimeError(server.failure)
        url = f'https://localhost:{upstream_port}/dns-query'
        env = os.environ.copy()
        # All benchmark traffic stays on loopback. Ignore ambient proxy settings.
        for variable in list(env):
            if variable.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
                env.pop(variable)
        if name == 'go':
            if protocol == 'h3':
                url = url.replace('https://', 'h3://', 1)
            command = [str(binary), '-l', '127.0.0.1', '-p', str(proxy_port),
                       '-u', url, '--cache=false', '--dnssec=false',
                       '--hosts-file-enabled=false', '--timeout=3s']
            env.update(SSL_CERT_FILE=str(cert), GOMAXPROCS='1')
        else:
            command = [str(binary), '-l', '127.0.0.1', '-p', str(proxy_port),
                       '-s', url, '--ca-file', str(cert),
                       '--bootstrap-address', '127.0.0.1', '--cache-entries', '0',
                       '--max-host-connections', '8', '--tcp-max-per-source', '128']
            if protocol == 'h3':
                command.append('--upstream-http=prefer-h3')
        command = ['taskset', '-c', str(args.cpu)] + command
        with log.open('wb') as output:
            proxy = subprocess.Popen(command, stdout=output, stderr=output, env=env)
            await_ready(proxy_port, proxy, name)
            for clients in args.clients:
                load(proxy_port, transport, clients, args.warmup, answers)
                drain(server)
                server.app.reset()
                cpu_before, _, _ = proxy_cpu_rss(proxy.pid)
                row = load(proxy_port, transport, clients, args.duration, answers)
                cpu_after, rss, peak = proxy_cpu_rss(proxy.pid)
                drain(server)
                observed = server.app.snapshot()
                expected = '2' if protocol == 'h2' else '3'
                if (set(observed['upstream_http_versions']) != {expected} or
                        observed['upstream_completed'] != row['successful_queries'] or
                        observed['upstream_invalid']):
                    raise RuntimeError(f'forwarding/protocol mismatch: {row}, {observed}')
                if cpu_before is None or cpu_after is None:
                    raise RuntimeError('Linux process CPU accounting unavailable')
                cpu_seconds = cpu_after-cpu_before
                row.update(implementation=name, protocol=protocol, transport=transport,
                           answers=answers, clients=clients, run=run,
                           proxy_cpu_seconds=cpu_seconds,
                           proxy_cpu_percent=100*cpu_seconds/row['elapsed_s'],
                           proxy_rss_bytes=rss, proxy_peak_rss_bytes=peak,
                           upstream=observed, command=command)
                with (args.output/'measurements.jsonl').open('a') as results:
                    results.write(json.dumps(row, sort_keys=True)+'\n')
                print(f'{name:4} {protocol} {transport} answers={answers:2} '
                      f'clients={clients:2} run={run} qps={row["qps"]:.0f} '
                      f'p99={row["p99_ms"]:.3f}ms peak={peak/1048576:.1f}MiB', flush=True)
    except BaseException:
        print(f'Failed scenario: {name}, {protocol}, {transport}, answers={answers}, run={run}', flush=True)
        print(f'Upstream state: {server.app.snapshot()}, failure={server.failure}', flush=True)
        if log.exists():
            print(log.read_text(errors='replace')[-8000:], flush=True)
        raise
    finally:
        if proxy:
            proxy.terminate()
            try:
                proxy.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait()
        server.close()


def summarize(output):
    rows = [json.loads(line) for line in (output/'measurements.jsonl').read_text().splitlines()]
    fields = ['implementation', 'protocol', 'transport', 'answers', 'clients', 'run',
              'successful_queries', 'qps', 'p50_ms', 'p95_ms', 'p99_ms',
              'proxy_cpu_seconds', 'proxy_cpu_percent', 'proxy_peak_rss_bytes']
    with (output/'measurements.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    groups = {}
    for row in rows:
        group = tuple(row[key] for key in fields[:5])
        groups.setdefault(group, []).append(row)
    text = ['# Linux C / Rust / Go application baseline', '',
            'Medians of three runs. Each proxy uses one CPU; the client and local TLS',
            'upstream share the host. Cache is disabled and every question is unique.',
            'Connection pooling and protocol engines differ between applications.', '',
            'C and Rust use RFC 8484 POST; AdGuard dnsproxy uses GET.', '',
            '| Application | DoH | Client | A records | Clients | QPS | p95 ms | p99 ms | CPU % | Peak MiB |',
            '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for group, values in sorted(groups.items()):
        if len(values) != 3:
            raise RuntimeError(f'incomplete benchmark group: {group}')
        med = lambda key: statistics.median(row[key] for row in values)
        text.append('| '+' | '.join(map(str, group))+
                    f' | {med("qps"):.0f} | {med("p95_ms"):.3f} | {med("p99_ms"):.3f}'
                    f' | {med("proxy_cpu_percent"):.1f} | {med("proxy_peak_rss_bytes")/1048576:.1f} |')
    (output/'summary.md').write_text('\n'.join(text)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-binary', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--go-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=2)
    parser.add_argument('--warmup', type=float, default=0.5)
    parser.add_argument('--delay-ms', type=float, default=1)
    parser.add_argument('--clients', default='1,8,32')
    parser.add_argument('--worker', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.clients = [int(value) for value in args.clients.split(',')]
    if (not args.clients or min(args.clients) < 1 or max(args.clients) > 128 or
            args.duration <= 0 or args.warmup < 0 or args.delay_ms < 0):
        parser.error('invalid duration, warmup, delay or client count')
    args.output = args.output.resolve()
    args.cpu = min(os.sched_getaffinity(0))
    binaries = dict(c=args.c_binary.resolve(), rust=args.rust_binary.resolve(),
                    go=args.go_binary.resolve())
    if args.worker:
        fields = args.worker.split(',')
        if (len(fields) != 5 or fields[0] not in binaries or
                fields[1] not in ('h2', 'h3') or fields[2] not in ('udp', 'tcp') or
                fields[3] not in ('1', '64') or fields[4] not in ('1', '2', '3')):
            parser.error('invalid internal worker selector')
        name, protocol, transport, answers, run = fields
        scenario(args, name, binaries[name], protocol, transport, int(answers), int(run),
                 args.output/'localhost.pem', args.output/'localhost.key')
        return
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('output directory must be empty')
    args.output.mkdir(parents=True, exist_ok=True)
    versions = {name: subprocess.check_output([str(binary), '--version'],
                text=True, stderr=subprocess.STDOUT).strip() for name, binary in binaries.items()}
    if GO_VERSION not in versions['go']:
        parser.error(f'expected AdGuard dnsproxy {GO_VERSION}: {versions["go"]}')
    metadata = dict(platform=platform.platform(), python=platform.python_version(),
                    machine=platform.machine(), proxy_cpu=args.cpu,
                    available_cpus=sorted(os.sched_getaffinity(0)), versions=versions,
                    rust_revision=os.environ.get('GITHUB_SHA'),
                    c_revision=(Path(__file__).resolve().parent.parent/'SOURCE_REVISION').read_text().strip(),
                    upstream_delay_ms=args.delay_ms, measurement_seconds=args.duration,
                    warmup_seconds=args.warmup, go_source=f'AdguardTeam/dnsproxy@{GO_VERSION}')
    (args.output/'environment.json').write_text(json.dumps(metadata, indent=2)+'\n')
    cert, key = args.output/'localhost.pem', args.output/'localhost.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-days', '1', '-keyout', str(key), '-out', str(cert),
                    '-subj', '/CN=localhost', '-addext',
                    'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        order = list(binaries)
        for run in range(1, 4):
            for protocol, transport, answers in itertools.product(('h2', 'h3'), ('udp', 'tcp'), (1, 64)):
                for name in order:
                    # Isolate the QUIC fixture's native TLS/QPACK objects and
                    # event-loop lifetime from preceding application scenarios.
                    subprocess.run([
                        sys.executable, str(Path(__file__).resolve()),
                        '--c-binary', str(binaries['c']),
                        '--rust-binary', str(binaries['rust']),
                        '--go-binary', str(binaries['go']),
                        '--output', str(args.output), '--duration', str(args.duration),
                        '--warmup', str(args.warmup), '--delay-ms', str(args.delay_ms),
                        '--clients', ','.join(map(str, args.clients)),
                        '--worker', f'{name},{protocol},{transport},{answers},{run}',
                    ], check=True)
            order = order[1:]+order[:1]
        summarize(args.output)
    finally:
        # The fixture's private key is ephemeral and is not part of the artifact.
        key.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
