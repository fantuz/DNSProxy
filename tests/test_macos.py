"""Acceptance checks for the extracted native macOS launcher."""
import os
from pathlib import Path
import platform
import plistlib
import re
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'Native macOS package acceptance')
class MacOSTests(unittest.TestCase):
    def test_packaged_architecture_and_deployment_target(self):
        binary = Path(os.environ['DNSP_TEST_BINARY']).resolve()
        for name in ('dnsp-modern', 'dnsp-macos', 'DNSProxy.app/Contents/MacOS/DNSProxy'):
            with self.subTest(executable=name):
                executable = binary.parent / name
                architectures = subprocess.check_output(
                    ['lipo', '-archs', str(executable)], text=True).strip()
                self.assertEqual(architectures, platform.machine())
                load_commands = subprocess.check_output(
                    ['otool', '-l', str(executable)], text=True)
                minimums = re.findall(r'^\s*minos\s+(\S+)', load_commands, re.M)
                self.assertEqual(len(minimums), 1, load_commands)
                self.assertEqual(tuple(int(part) for part in minimums[0].split('.'))[:2], (15, 0))

    def test_moved_finder_app_starts_through_launch_services(self):
        root = Path(os.environ['DNSP_TEST_BINARY']).resolve().parent
        with tempfile.TemporaryDirectory(prefix='DNSProxy moved app ') as temp:
            app = Path(temp) / 'DNSProxy.app'
            shutil.copytree(root / app.name, app)
            info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
            self.assertEqual(info['CFBundleShortVersionString'], (Path(__file__).resolve().parents[1] / 'VERSION').read_text().strip())
            for item in (root / 'dnsp-modern', root / 'dnsp-macos', app / 'Contents/Helpers/dnsp-modern'):
                subprocess.run(['codesign', '--verify', '--strict', str(item)], check=True)
            verify_app = ['codesign', '--verify', '--deep', '--strict', str(app)]
            subprocess.run(verify_app, check=True)
            # LaunchServices opens the same moved bundle as Finder. The GTK application
            # prints its own help after the native launcher locates the bundled code.
            out, err = Path(temp) / 'stdout', Path(temp) / 'stderr'
            subprocess.run(['/usr/bin/open', '-n', '-W', '--stdout', str(out), '--stderr', str(err),
                            str(app), '--args', '--help'], check=True, timeout=45)
            self.assertIn('--metrics-port', out.read_text(), err.read_text() if err.exists() else '')
            subprocess.run(verify_app, check=True)
            # A substituted resource must invalidate the bundle seal.
            resource = app / 'Contents/Resources/gui/dnsp-gui.py'
            with resource.open('a') as stream:
                stream.write('\n# modified copy\n')
            self.assertNotEqual(subprocess.run(verify_app, capture_output=True).returncode, 0)

    def test_launcher_from_another_directory_and_clean_shutdown(self):
        binary = Path(os.environ['DNSP_TEST_BINARY']).resolve()
        # A missing question with QDCOUNT=1 produces FORMERR without an upstream request.
        packet = b'\x12\x34\x01\x00\x00\x01' + b'\0' * 6
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryFile() as log:
            process = subprocess.Popen([str(binary.parent / 'Start-DNSProxy.command')],
                                       cwd=cwd, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        for address, port in (('127.0.0.1', 5053), ('::1', 5053), ('127.0.0.1', 9090)):
                            with socket.create_connection((address, port), timeout=.2):
                                pass
                        break
                    except OSError:
                        time.sleep(.05)
                else:
                    log.seek(0)
                    self.fail(f'Packaged launcher failed to start: {log.read()!r}')

                for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    with self.subTest(address=address):
                        with socket.socket(family, socket.SOCK_DGRAM) as client:
                            client.settimeout(3)
                            client.sendto(packet, (address, 5053))
                            answer = client.recv(4096)
                        self.assertEqual(answer[:2], packet[:2])
                        self.assertEqual(answer[3] & 15, 1)
                        with socket.create_connection((address, 5053), timeout=3) as client:
                            client.sendall(struct.pack('!H', len(packet)) + packet)
                            client.shutdown(socket.SHUT_WR)
                            framed = b''
                            while chunk := client.recv(4096):
                                framed += chunk
                        self.assertEqual(framed, struct.pack('!H', len(answer)) + answer)
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
