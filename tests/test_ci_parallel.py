"""Exercise real subprocess scheduling, error propagation and fixture isolation."""
import importlib.util
import os
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('windows_runner', ROOT / 'scripts/run-windows-tests.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SchedulingTests(unittest.TestCase):
    def test_groups_overlap_and_receive_separate_port_ranges(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            groups = {}
            for name, peer, start in [('first', 'second', 10000), ('second', 'first', 18000)]:
                code = (
                    'import os,time; from pathlib import Path; '
                    f'root=Path({str(root)!r}); (root/{name!r}).touch(); '
                    f'peer=root/{peer!r}; deadline=time.monotonic()+5; '
                    '\nwhile not peer.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                    'assert peer.exists(), "groups did not overlap"\n'
                    f'assert os.environ["DNSP_TEST_PORT_START"] == {str(start)!r}\n'
                    'print(os.environ["DNSP_TEST_PORT_STOP"])'
                )
                groups[name] = (start, start+6000, [('-c', code)])
            results = runner.run_groups(groups, root/'logs', workers=2, timeout=10)
            self.assertTrue(all(s['exit_code'] == 0 for g in results for s in g['suites']), results)
            self.assertIn('16000', (root/'logs/first.log').read_text())
            self.assertIn('24000', (root/'logs/second.log').read_text())

    def test_failure_does_not_drop_later_suites_or_other_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            groups = {
                'bad': (10000, 16000, [('-c', 'raise SystemExit(7)'), ('-c', 'print("still ran")')]),
                'good': (18000, 24000, [('-c', 'print("other group ran")')]),
            }
            results = runner.run_groups(groups, root)
            self.assertEqual([s['exit_code'] for g in results for s in g['suites']], [7, 0, 0])
            self.assertIn('still ran', (root/'bad.log').read_text())
            self.assertIn('other group ran', (root/'good.log').read_text())

    def test_timeout_kills_the_fixture_tree_and_continues(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root/'escaped-fixture'
            child = f'import time; from pathlib import Path; time.sleep(2); Path({str(marker)!r}).touch()'
            code = f'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",{child!r}]); time.sleep(10)'
            result = runner.run_group('timeout', (10000, 16000,
                                      [('-c', code), ('-c', 'print("after timeout")')]), root, timeout=1)
            self.assertEqual([s['exit_code'] for s in result['suites']], [124, 0])
            time.sleep(2.1)
            self.assertFalse(marker.exists(), 'fixture child escaped timeout cleanup')

    def test_real_port_allocators_obey_the_group_range(self):
        sys.path.insert(0, str(ROOT/'tests'))
        sys.path.insert(0, str(ROOT/'bench'))
        import test_modern
        import test_ipv6
        import bench_modern

        with patch.dict(os.environ, DNSP_TEST_PORT_START='26000', DNSP_TEST_PORT_STOP='27000'), \
                patch('socket.socket') as sockets:
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sockets.return_value = sock
            ports = [*test_modern.unused_ports(), bench_modern.free_port()]
            ports.extend(test_ipv6.listener_ports())
        self.assertTrue(all(26000 <= port < 27000 for port in ports), ports)
        with patch.dict(os.environ, DNSP_TEST_PORT_START='100', DNSP_TEST_PORT_STOP='110'):
            for allocator in (test_modern.unused_ports, test_ipv6.listener_ports, bench_modern.free_port):
                with self.assertRaises(ValueError):
                    allocator()

    def test_production_groups_never_share_listener_ranges(self):
        ranges = [set(range(start, stop)) for start, stop, _ in runner.GROUPS.values()]
        for index, ports in enumerate(ranges):
            self.assertTrue(all(ports.isdisjoint(other) for other in ranges[index+1:]))
        commands = [arguments[0] for _, _, suites in runner.GROUPS.values() for arguments in suites]
        self.assertNotIn('tests/test_windows_service.py', commands)
        self.assertNotIn('tests/test_windows.py', commands)


if __name__ == '__main__':
    unittest.main()
