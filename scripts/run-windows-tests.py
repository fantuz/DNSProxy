#!/usr/bin/env python3
"""Run independent portable suites concurrently; system DNS/SCM tests stay serial."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
# Distinct non-ephemeral listener ranges avoid cross-process probe/bind races.
GROUPS = {
    'core': (10000, 16000, [('tests/test_modern.py', '-v'), ('tests/test_ipv6.py', '-v')]),
    'policy': (18000, 24000, [('tests/test_hedging.py', '-v'), ('tests/test_policy.py', '-v'),
                            ('tests/test_policy_updater.py', '-v')]),
    'protocol': (26000, 32000, [('-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_benchmark.py', '-v'),
                              ('tests/test_http3.py', '--isolated', '-v')]),
}


def run_group(name, config, directory, timeout=300):
    start, stop, suites = config
    environment = dict(os.environ, DNSP_TEST_PORT_START=str(start), DNSP_TEST_PORT_STOP=str(stop))
    results = []
    began = time.monotonic()
    with (directory / f'{name}.log').open('w', encoding='utf-8') as log:
        for arguments in suites:
            command = [sys.executable, *arguments]
            log.write(f'\n>>> {command!r}\n')
            log.flush()
            suite_start = time.monotonic()
            try:
                with subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log,
                                      stderr=subprocess.STDOUT,
                                      start_new_session=os.name != 'nt') as process:
                    try:
                        code = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        # Kill the suite's proxies/fixtures as well as its Python driver.
                        if os.name == 'nt':
                            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                           stdout=log, stderr=subprocess.STDOUT, check=False, timeout=30)
                        else:
                            os.killpg(process.pid, signal.SIGKILL)
                        process.kill()
                        process.wait(timeout=10)
                        code = 124
                        log.write(f'\nTIMEOUT after {timeout}s\n')
            except OSError as error:
                log.write(f'\nCannot launch suite: {error}\n')
                code = 127
            results.append({'command': arguments, 'exit_code': code,
                            'seconds': round(time.monotonic() - suite_start, 3)})
    return {'name': name, 'port_start': start, 'port_stop': stop,
            'seconds': round(time.monotonic() - began, 3), 'suites': results}


def run_groups(groups, directory, workers=2, timeout=300):
    directory.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run_group, name, config, directory, timeout)
                   for name, config in groups.items()]
        # Await every group and every suite, including after another suite fails.
        return [future.result() for future in futures]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, choices=(1, 2, 3), default=2)
    parser.add_argument('--logs', type=Path, default=ROOT / 'dist/windows-test-logs')
    arguments = parser.parse_args()
    began = time.monotonic()
    results = run_groups(GROUPS, arguments.logs, arguments.workers)
    report = {'workers': arguments.workers, 'seconds': round(time.monotonic() - began, 3),
              'groups': results}
    (arguments.logs / 'timings.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for group in results:
        print(f'::group::{group["name"]}: {group["seconds"]}s', flush=True)
        print((arguments.logs / f'{group["name"]}.log').read_text(encoding='utf-8', errors='replace'))
        print('::endgroup::', flush=True)
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a', encoding='utf-8') as output:
            output.write('\n### Portable Windows test groups\n\n| Group | Seconds | Failed suites |\n| --- | ---: | ---: |\n')
            for group in results:
                failed = sum(suite['exit_code'] != 0 for suite in group['suites'])
                output.write(f'| {group["name"]} | {group["seconds"]} | {failed} |\n')
            output.write(f'\nElapsed: {report["seconds"]}s with {arguments.workers} workers.\n')
    return int(any(suite['exit_code'] != 0 for group in results for suite in group['suites']))


if __name__ == '__main__':
    raise SystemExit(main())
