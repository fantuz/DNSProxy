#!/usr/bin/env python3
"""Compare PR/base binaries and large policies on one GitHub runner.

Interleaved repeated samples limit runner drift. Broad relative gates catch
large regressions; retained JSON contains QPS, p95/p99, CPU and RSS for review.
All upstream traffic is loopback TLS/HTTP2; generated domains are reserved .invalid.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import threading
import time

from bench_modern import (await_quiescent, await_ready, free_port, make_certificate,
                          metric_snapshot, one_load, proxy_cpu_rss)
from mock_doh import MockServer


def generate(path, count, *, first='sentinel.invalid'):
    with path.open('w') as output:
        output.write(first + '\n')
        for index in range(count - 1):
            output.write(f'd{index}.denied.invalid\n')


def sample(binary, upstream, cert, rules, duration, *, blocked=False, reload=False):
    dns, metrics = free_port(), free_port()
    command = [str(binary), '-p', str(dns), '-m', str(metrics),
               '-s', f'https://localhost:{upstream.port}/dns-query', '--ca-file', str(cert),
               '--bootstrap-address', '127.0.0.1']
    if rules:
        command += ['--blocklist', str(rules), '--blocklist-reload-ms', '100' if reload else '0']
    mutator = None
    with tempfile.TemporaryFile() as log, subprocess.Popen(command, stderr=log) as proxy:
        try:
            await_ready(metrics, proxy, 'Policy benchmark', timeout=30)
            expected = 5 if blocked else 0
            one_load(dns, 32, 0.3, expected_rcode=expected)
            await_quiescent(metrics, upstream)
            before = metric_snapshot(metrics)
            cpu_before, rss_before, _ = proxy_cpu_rss(proxy.pid)
            if reload:
                def replace():
                    time.sleep(0.2)
                    staged = rules.with_suffix('.new')
                    with rules.open() as source, staged.open('w') as target:
                        next(source)
                        target.write('reloaded.invalid\n')
                        shutil.copyfileobj(source, target)
                    os.replace(staged, rules)
                mutator = threading.Thread(target=replace)
                mutator.start()
            row = one_load(dns, 32, duration, expected_rcode=expected)
            if mutator:
                mutator.join(timeout=10)
                if mutator.is_alive():
                    raise AssertionError('List replacement did not finish')
                deadline = time.monotonic() + 20
                while metric_snapshot(metrics)['dnsp_blocklist_generation'] < 2:
                    if time.monotonic() > deadline:
                        raise AssertionError('Large policy did not reload')
                    time.sleep(0.05)
            await_quiescent(metrics, upstream)
            cpu_after, rss_after, rss_peak = proxy_cpu_rss(proxy.pid)
            after = metric_snapshot(metrics)
            row.update({'binary': str(binary), 'rules_file': rules.name if rules else None,
                        'expected_rcode': expected, 'reload': reload,
                        'policy_memory_bytes': after.get('dnsp_blocklist_memory_bytes', 0),
                        'policy_generation': after.get('dnsp_blocklist_generation', 0),
                        'rss_start_bytes': rss_before, 'rss_end_bytes': rss_after, 'rss_peak_bytes': rss_peak,
                        'cpu_seconds': cpu_after - cpu_before if cpu_after is not None and cpu_before is not None else None,
                        'upstream_requests': after['dnsp_upstream_requests_total'] - before['dnsp_upstream_requests_total'],
                        'blocked_queries': after.get('dnsp_blocked_queries_total', 0) - before.get('dnsp_blocked_queries_total', 0)})
            if row['failed_responses'] or row['timeouts'] or row['truncated_responses'] or not row['successful_queries']:
                raise AssertionError(f'Incorrect benchmark replies: {row}')
            if blocked and (row['upstream_requests'] or row['blocked_queries'] != row['successful_queries']):
                raise AssertionError(f'Blocked traffic escaped the local policy: {row}')
            if row['policy_memory_bytes'] > 96 * 1024 * 1024:
                raise AssertionError(f'Policy allocation bound exceeded: {row}')
            if rss_peak is not None and rss_peak > 256 * 1024 * 1024:
                raise AssertionError(f'Unexpected resolver RSS: {row}')
            return row
        except Exception:
            log.seek(0)
            print(log.read().decode(errors='replace'))
            raise
        finally:
            proxy.terminate()
            proxy.wait(timeout=8)
            if mutator:
                mutator.join(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--baseline-binary', type=Path, required=True)
    parser.add_argument('--baseline-commit', default='unknown')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--duration', type=float, default=1.5)
    args = parser.parse_args()
    if args.samples < 3 or args.duration < 1:
        parser.error('Use at least three samples of at least one second')
    report = {'baseline_commit': args.baseline_commit, 'candidate_commit': os.environ.get('GITHUB_SHA'),
              'concurrency': 32, 'samples': [], 'summary': {}, 'gates': {}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='dnsp-policy-bench-') as directory:
            root = Path(directory)
            cert, key = make_certificate(root)
            hundred, million, blocked = root/'100k.txt', root/'1m.txt', root/'1m-blocked.txt'
            generate(hundred, 100000)
            generate(million, 1000000)
            generate(blocked, 1000000, first='example.com')
            upstream = MockServer(free_port(), cert, key, delay_ms=1)
            upstream.start()
            try:
                await_ready(upstream.port, None, 'HTTP2 mock')
                cases = [('base', args.baseline_binary, None), ('disabled', args.binary, None),
                         ('100k', args.binary, hundred), ('1m', args.binary, million)]
                for index in range(args.samples):
                    # Reverse every other round so the candidate is not always
                    # measured after the reference on a warming or busy runner.
                    for name, binary, rules in (cases if index % 2 == 0 else list(reversed(cases))):
                        row = sample(binary.resolve(), upstream, cert, rules, args.duration)
                        row.update(case=name, sample=index)
                        report['samples'].append(row)
                for name, options in [('blocked', {'blocked': True}), ('reload', {'reload': True})]:
                    row = sample(args.binary.resolve(), upstream, cert, blocked if name == 'blocked' else million,
                                 max(3, args.duration), **options)
                    row.update(case=name)
                    report['samples'].append(row)
            finally:
                upstream.close()
        for name in ('base', 'disabled', '100k', '1m'):
            rows = [row for row in report['samples'] if row['case'] == name]
            report['summary'][name] = {key: statistics.median(row[key] for row in rows)
                                       for key in ('qps', 'p95_ms', 'p99_ms')}
        base = report['summary']['base']
        for name in ('disabled', '100k', '1m'):
            row = report['summary'][name]
            qps_ratio = row['qps'] / base['qps']
            p99_ratio = row['p99_ms'] / max(0.001, base['p99_ms'])
            report['gates'][name] = {'qps_ratio': qps_ratio, 'p99_ratio': p99_ratio,
                                     'pass': qps_ratio >= 0.65 and p99_ratio <= 2.5}
        if not all(row['pass'] for row in report['gates'].values()):
            raise AssertionError(f'Large relative performance regression: {report["gates"]}')
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report['summary'], indent=2))
    print(json.dumps(report['gates'], indent=2))


if __name__ == '__main__':
    main()
