"""DNS configuration recovery with real state files and synthetic OS boundaries."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'packaging/linux/dnsp-configure-dns'
loader = importlib.machinery.SourceFileLoader('dnsp_integration', str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
dns = importlib.util.module_from_spec(spec)
loader.exec_module(dns)


class FakeNetwork:
    name = 'nm'

    def __init__(self, path):
        self.file = path
        self.original = {'ipv4.dns': '', 'ipv4.ignore-auto-dns': 'no',
                         'ipv6.dns': '2001:db8::2,2001:db8::1', 'ipv6.ignore-auto-dns': 'yes'}
        self.file.write_text(json.dumps(self.original))
        self.writes = 0
        self.fail_refresh = False
        self.crash = False

    def prepare(self, interfaces):
        return [dict(identity='test-profile-uuid', interface=interfaces[0],
                     before=self.read(None), after=dns.AFTER.copy())]

    def read(self, entry):
        return json.loads(self.file.read_text())

    def write(self, entry, value):
        self.writes += 1
        self.file.write_text(json.dumps(value))
        if self.crash:
            os._exit(77)

    def refresh(self, entry):
        if self.fail_refresh:
            self.fail_refresh = False
            raise RuntimeError('Injected reapply failure')
        return ['test0']

    verify_active = refresh


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root/'state.json'
        self.backend = FakeNetwork(self.root/'profile.json')
        self.armed = False

    def arm(self):
        self.assertEqual(dns.load(self.state)['phase'], 'pending')
        self.assertEqual(self.backend.writes, 0)
        self.armed = True

    def disarm(self):
        self.armed = False

    def enable(self, **kwargs):
        return dns.enable(self.state, self.backend, ['test0'], check=lambda: None,
                          start_timer=self.arm, stop_timer=self.disarm, check_system=lambda: None, **kwargs)

    def restore(self):
        dns.restore(self.state, self.backend, self.disarm)

    def test_apply_restore_preserves_dhcp_and_static_order(self):
        self.enable()
        self.assertEqual(self.backend.read(None), dns.AFTER)
        self.assertEqual(dns.load(self.state)['phase'], 'active')
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.armed)
        self.restore()
        self.assertEqual(self.backend.read(None), self.backend.original)
        self.assertFalse(self.state.exists())
        self.restore()  # idempotent

    def test_repeat_enable_cannot_replace_original_snapshot(self):
        self.enable()
        before = self.state.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            self.enable()
        self.assertEqual(self.state.read_bytes(), before)

    def test_preview_has_no_side_effects(self):
        plan = self.enable(preview=True)
        self.assertEqual(plan['entries'][0]['before'], self.backend.original)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.armed)
        self.assertEqual(self.backend.writes, 0)

    def test_reapply_failure_restores_persistent_and_runtime_settings(self):
        self.backend.fail_refresh = True
        with self.assertRaisesRegex(RuntimeError, 'reapply failure'):
            self.enable()
        self.assertEqual(self.backend.read(None), self.backend.original)
        self.assertFalse(self.state.exists())

    def test_failed_watchdog_never_changes_dns(self):
        with self.assertRaisesRegex(RuntimeError, 'timer failed'):
            dns.enable(self.state, self.backend, ['test0'], check=lambda: None,
                       start_timer=lambda: self.fail_timer(), stop_timer=self.disarm)
        self.assertEqual(self.backend.writes, 0)
        self.assertFalse(self.state.exists())

    @staticmethod
    def fail_timer():
        raise RuntimeError('timer failed')

    def test_failed_health_rolls_back(self):
        calls = []
        def health():
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('health failed')
        with self.assertRaisesRegex(RuntimeError, 'health failed'):
            dns.enable(self.state, self.backend, ['test0'], check=health,
                       start_timer=self.arm, stop_timer=self.disarm, check_system=lambda: None)
        self.assertEqual(self.backend.read(None), self.backend.original)
        self.assertFalse(self.state.exists())

    def test_restore_refuses_external_edits_and_retains_state(self):
        self.enable()
        changed = dns.AFTER.copy()
        changed['ipv4.dns'] = '192.0.2.9'
        self.backend.write(None, changed)
        with self.assertRaisesRegex(RuntimeError, 'changed externally'):
            self.restore()
        self.assertTrue(self.state.exists())
        self.assertEqual(self.backend.read(None), changed)
        self.backend.write(None, dns.AFTER)
        self.restore()
        self.assertEqual(self.backend.read(None), self.backend.original)

    def test_restore_retries_refresh_after_persistent_write(self):
        self.enable()
        self.backend.fail_refresh = True
        with self.assertRaisesRegex(RuntimeError, 'reapply failure'):
            self.restore()
        self.assertEqual(self.backend.read(None), self.backend.original)
        self.assertTrue(self.state.exists())
        self.restore()
        self.assertFalse(self.state.exists())

    def test_killed_process_recovers_from_durable_pending_state(self):
        child = os.fork()
        if child == 0:
            self.backend.crash = True
            self.enable()
            os._exit(1)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 77)
        self.assertEqual(dns.load(self.state)['phase'], 'pending')
        self.assertEqual(self.backend.read(None), dns.AFTER)
        self.restore()
        self.assertEqual(self.backend.read(None), self.backend.original)

    def test_expired_transaction_cannot_commit(self):
        with patch.object(dns.time, 'time', side_effect=[0, 121]):
            with self.assertRaisesRegex(RuntimeError, 'deadline expired'):
                self.enable()
        self.assertEqual(self.backend.read(None), self.backend.original)
        self.assertFalse(self.state.exists())


class BackendTests(unittest.TestCase):
    def test_nm_changes_only_owned_properties_in_one_update(self):
        backend = dns.NetworkManager()
        with patch.object(dns, 'run', return_value='') as run:
            backend.write({'identity': 'uuid-1'}, dns.AFTER)
        self.assertEqual(run.call_args.args, (
            'nmcli', 'connection', 'modify', 'uuid', 'uuid-1',
            'ipv4.dns', '127.0.0.1', 'ipv4.ignore-auto-dns', 'yes',
            'ipv6.dns', '::1', 'ipv6.ignore-auto-dns', 'yes'))

    def test_nm_restore_uses_current_device_or_inactive_profile(self):
        backend = dns.NetworkManager()
        with patch.object(dns, 'run', side_effect=['renamed0', 'uuid-1', '']) as run:
            self.assertEqual(backend.refresh({'identity': 'uuid-1', 'interface': 'old0'}), ['renamed0'])
        self.assertEqual(run.call_args.args, ('nmcli', 'device', 'reapply', 'renamed0'))
        with patch.object(dns, 'run', return_value='--') as run:
            self.assertEqual(backend.refresh({'identity': 'uuid-1'}), [])
            self.assertEqual(run.call_count, 1)

    def test_nm_will_not_reapply_another_profile(self):
        with patch.object(dns, 'run', side_effect=['eth0', 'different-uuid']):
            with self.assertRaisesRegex(RuntimeError, 'Connection changed'):
                dns.NetworkManager().refresh({'identity': 'uuid-1'})

    def test_networkd_owns_only_one_dropin(self):
        backend = dns.Networkd()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root/'host.network'
            original.write_text('[Match]\nName=test0\n[Network]\nDHCP=yes\n')
            entry = {'path': str(root/'host.network.d/90-dnsproxy.conf')}
            self.assertIsNone(backend.read(entry))
            backend.write(entry, dns.DROPIN)
            self.assertEqual(backend.read(entry), dns.DROPIN)
            self.assertEqual(Path(entry['path']).stat().st_mode & 0o777, 0o644)
            backend.write(entry, None)
            self.assertIsNone(backend.read(entry))
            self.assertEqual(original.read_text(), '[Match]\nName=test0\n[Network]\nDHCP=yes\n')

    def test_networkd_refuses_broad_match(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)/'host.network'
            profile.write_text('[Match]\nName=en*\n[Network]\nDHCP=yes\n')
            with patch.object(dns.Networkd, 'profile', return_value=profile):
                with self.assertRaisesRegex(RuntimeError, 'exact Match Name'):
                    dns.Networkd().prepare(['enp1s0'])

    def test_atomic_replace_refuses_symlink_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'state.json'
            victim = Path(directory)/'victim'
            victim.write_text('keep')
            target.with_name('state.json.new').symlink_to(victim)
            with self.assertRaises(OSError):
                dns.atomic_write(target, 'overwrite')
            self.assertEqual(victim.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
