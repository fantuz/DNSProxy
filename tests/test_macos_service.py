"""Native launchd acceptance; never change the runner's actual adapter DNS."""
import os
from pathlib import Path
import plistlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import test_modern as fixtures

ROOT = Path('/Library/Application Support/DNSProxy')
LABEL = 'net.fantuz.dnsproxy'


@unittest.skipUnless(sys.platform == 'darwin', 'Native macOS launchd acceptance')
class MacServiceTests(unittest.TestCase):
    def helper(self, *args, check=True):
        result = subprocess.run(['sudo', str(fixtures.BINARY.parent/'dnsp-macos'), *args],
                                text=True, capture_output=True, timeout=60)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def pid(self):
        result = subprocess.run(['sudo', 'launchctl', 'print', 'system/' + LABEL],
                                text=True, capture_output=True, timeout=10)
        match = re.search(r'^\s*pid = (\d+)', result.stdout, re.M)
        return int(match[1]) if match else 0

    def assert_dns(self):
        packet = fixtures.query(28)
        for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                client.sendto(packet, (address, 53))
                answer = client.recv(4096)
            self.assertEqual(answer[:2], packet[:2])
            self.assertEqual(answer[3] & 15, 0)
            with socket.create_connection((address, 53), timeout=5) as client:
                client.sendall(struct.pack('!H', len(packet)) + packet)
                self.assertEqual(fixtures.Tests.tcp_frame(client)[3] & 15, 0)

    def test_launchd_lifecycle_unprivileged_dns_recovery_and_uninstall(self):
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory)/'localhost.crt', Path(directory)/'localhost.key'
            subprocess.run([fixtures.OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-out', str(cert), '-keyout', str(key)], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with fixtures.HTTP(('127.0.0.1', 0), fixtures.DoH) as server:
                server.socket = context.wrap_socket(server.socket, server_side=True)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                installed = False
                try:
                    self.helper('install', f'https://localhost:{server.server_port}/dns-query', '127.0.0.1', str(cert))
                    installed = True
                    self.assert_dns()
                    pid = self.pid()
                    self.assertGreater(pid, 0)
                    identity = subprocess.check_output(['ps', '-o', 'user=', '-p', str(pid)], text=True).strip()
                    self.assertEqual(identity, 'nobody')
                    self.assertNotEqual(self.helper('install', check=False).returncode, 0)
                    self.helper('services')
                    self.assertIn('original DNS settings', self.helper('status').stdout)
                    invalid = self.helper('enable-dns', 'invalid-uuid', check=False)
                    self.assertNotEqual(invalid.returncode, 0)
                    self.assertIn('invalid service UUID', invalid.stderr)
                    self.assertFalse((ROOT/'dns-state.plist').exists())
                    job = Path('/Library/LaunchDaemons', LABEL + '.plist')
                    original = subprocess.check_output(['sudo', 'cat', str(job)])
                    changed = plistlib.loads(original)
                    changed['ProgramArguments'] = ['/usr/bin/false']
                    staged_job = Path(directory)/'changed-job.plist'
                    staged_job.write_bytes(plistlib.dumps(changed))
                    try:
                        subprocess.run(['sudo', 'cp', str(staged_job), str(job)], check=True)
                        refusal = self.helper('stop', check=False)
                        self.assertNotEqual(refusal.returncode, 0)
                        self.assertIn('ownership record', refusal.stderr)
                        self.assert_dns()
                    finally:
                        staged_job.write_bytes(original)
                        subprocess.run(['sudo', 'cp', str(staged_job), str(job)], check=True)
                    # External termination is recovered by launchd, retaining bound sockets.
                    subprocess.run(['sudo', 'kill', '-KILL', str(pid)], check=True)
                    deadline = time.monotonic() + 25
                    while time.monotonic() < deadline:
                        if self.pid() not in (0, pid):
                            self.assert_dns()
                            break
                        time.sleep(.25)
                    else:
                        self.fail('launchd did not recover the resolver')
                    self.helper('stop')
                    time.sleep(2)
                    self.assertEqual(self.pid(), 0)
                    self.assertNotEqual(self.helper('enable-dns', '11111111-1111-1111-1111-111111111111', check=False).returncode, 0)
                    self.assertFalse((ROOT/'dns-state.plist').exists())
                    for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                            with socket.socket(family, kind) as sock:
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                sock.bind((address, 53))
                    self.helper('start')
                    self.assert_dns()
                    self.helper('restore-dns')  # Idempotent, no snapshot means no network changes.
                    # A synthetic, unavailable service exercises stop/uninstall guards.
                    state = {'Version': 1, 'Phase': 'Active', 'Deadline': __import__('datetime').datetime.now(),
                             'Entries': {'11111111-1111-1111-1111-111111111111': {
                                 'Before': {'Present': False, 'Configuration': {}},
                                 'After': {'Present': True, 'Configuration': {'ServerAddresses': ['127.0.0.1', '::1']}}}}}
                    staged = Path(directory)/'dns-state.plist'
                    staged.write_bytes(plistlib.dumps(state))
                    subprocess.run(['sudo', 'install', '-m', '600', str(staged), str(ROOT/'dns-state.plist')], check=True)
                    try:
                        for command in ('stop', 'uninstall', 'restore-dns'):
                            self.assertNotEqual(self.helper(command, check=False).returncode, 0)
                        self.assertTrue((ROOT/'dns-state.plist').exists())
                        self.assert_dns()
                    finally:
                        # This is test-created synthetic state, not a real DNS snapshot.
                        subprocess.run(['sudo', 'rm', str(ROOT/'dns-state.plist')], check=True)
                    with Path('/var/log/dnsp-modern.log').open('ab') as log:
                        log.write(b'x' * (5 * 1024 * 1024))
                    self.helper('recover')
                    self.assertLessEqual(Path('/var/log/dnsp-modern.log.1').stat().st_size, 4 * 1024 * 1024)
                    self.assertLess(Path('/var/log/dnsp-modern.log').stat().st_size, 4 * 1024 * 1024)
                    self.assert_dns()
                finally:
                    if installed:
                        self.helper('uninstall')
                    server.shutdown()
                    worker.join(timeout=3)
        self.assertFalse(ROOT.exists())
        self.assertEqual(self.pid(), 0)

    def test_port_conflict_rolls_back_installation(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 53))
            result = self.helper('install', check=False)
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse(ROOT.exists())
        for label in (LABEL, LABEL + '.recovery'):
            self.assertFalse(Path('/Library/LaunchDaemons', label + '.plist').exists())


if __name__ == '__main__':
    unittest.main()
