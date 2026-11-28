#!/usr/bin/env python3
"""Compare CPU cost per unchanged, full diagnostic snapshot in the desktop GUI."""

import argparse
from pathlib import Path
import runpy
from statistics import median
from time import process_time
from timeit import Timer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('module', type=Path, help='path to the candidate owned_process.py')
    parser.add_argument('--baseline', type=Path, help='path to the baseline owned_process.py')
    args = parser.parse_args()
    sources = ([('Baseline', args.baseline)] if args.baseline else []) + [('Candidate', args.module)]
    record = b'event=upstream http_status=200 https://resolver.example/dns-query?key=private\n'
    log = (record * (65536 // len(record) + 1))[:65536]
    timers = []
    expected = None
    for name, source in sources:
        owner = runpy.run_path(str(source))['OwnedResolver']([])
        owner._append(log)
        formatted = owner.snapshot()['logs']
        if 'key=private' in formatted or '[redacted]' not in formatted:
            raise ValueError('Snapshot did not redact the fixture URL')
        if expected is not None and formatted != expected:
            raise ValueError('Snapshots differ between builds')
        expected = formatted
        timer = Timer(owner.snapshot, timer=process_time)
        loops, _ = timer.autorange()
        timers.append((name, timer, loops, []))

    for repetition in range(7):
        for _, timer, loops, samples in (timers if repetition % 2 == 0 else reversed(timers)):
            samples.append(timer.timeit(loops) * 1e6 / loops)
    print('### Desktop CPU per unchanged 64 KiB log snapshot')
    print('\n| Build | Median CPU (us/snapshot) | Snapshots per repetition |')
    print('| --- | ---: | ---: |')
    for name, _, loops, samples in timers:
        print(f'| {name} | {median(samples):.3f} | {loops} |')


if __name__ == '__main__':
    main()
