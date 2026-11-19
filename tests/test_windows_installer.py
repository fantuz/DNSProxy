"""Exercise the production setup EXE, actual SCM and installed DNS listeners."""
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest

import test_modern as fixtures
from test_windows_bundle import check_machine


@unittest.skipUnless(os.name == 'nt' and os.environ.get('DNSP_TEST_INSTALLER'),
                     'Requires the native Windows setup EXE')
class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = Path(os.environ['DNSP_TEST_INSTALLER']).resolve()
        cls.app = Path(os.environ['ProgramFiles']) / 'DNSProxy'
        cls.state = Path(os.environ['ProgramData']) / 'DNSProxy'
        cls.evidence = Path('dist/windows-installer-evidence').resolve()
        cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.environment = {k: v for k, v in os.environ.items() if k.lower() != 'psmodulepath'}
        # These tests own only a clean disposable hosted runner installation.
        if cls.app.exists() or cls.state.exists():
            raise RuntimeError('Installer acceptance requires no existing DNSProxy installation')
        cls.invocation = 0

    def ps(self, command, check=True):
        shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command',
                                 "$ErrorActionPreference='Stop'; " + command],
                                text=True, capture_output=True, timeout=60, env=self.environment)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    @staticmethod
    def quoted(path):
        return "'" + str(path).replace("'", "''") + "'"

    def invoke(self, executable, *arguments, succeeds=True):
        type(self).invocation += 1
        log = self.evidence / f'{self._testMethodName}-{self.invocation}.log'
        result = subprocess.run([str(executable), '/VERYSILENT', '/SUPPRESSMSGBOXES',
                                 '/NORESTART', '/SP-', f'/LOG={log}', *arguments],
                                capture_output=True, timeout=150, env=self.environment)
        details = log.read_text(encoding='utf-8-sig', errors='replace') if log.exists() else repr(result)
        self.assertEqual(result.returncode == 0, succeeds, details)

    def service(self):
        text = self.ps("Get-CimInstance Win32_Service -Filter \"Name='DNSProxy'\" | "
                       'Select-Object State,StartName,StartMode,PathName,ProcessId | ConvertTo-Json').stdout.strip()
        return json.loads(text) if text else None

    def uninstall(self, succeeds=True):
        self.invoke(self.app / 'unins000.exe', succeeds=succeeds)
        if succeeds:
            self.assertIsNone(self.service())
            self.assertFalse((self.app / 'bin/dnsp-modern.exe').exists())
            self.assertFalse(self.state.exists())

    @contextmanager
    def installation(self, *arguments):
        self.invoke(self.installer, *arguments)
        try:
            yield
        finally:
            # Pending-DNS cases remove their synthetic marker in their own finally.
            self.uninstall()
            # Inno deliberately retains files it did not install.
            for path in (self.app / 'bin/keep-user-file.txt',):
                path.unlink(missing_ok=True)
            for path in (self.app / 'bin', self.app):
                if path.exists() and not any(path.iterdir()):
                    path.rmdir()

    def assert_installed_payload(self):
        binary = self.app / 'bin/dnsp-modern.exe'
        arch = os.environ['DNSP_TEST_WINDOWS_ARCH']
        check_machine(binary, arch)
        result = subprocess.run([str(binary), '--version'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (binary.parent / 'SHA256SUMS').read_text().splitlines()
        for line in manifest:
            digest, name = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((binary.parent / name).read_bytes()).hexdigest(), digest, name)
        registered = self.ps("Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{439B9015-B446-4C7E-95F1-923143B86B53}_is1' | Select-Object DisplayName,DisplayVersion | ConvertTo-Json")
        self.assertEqual(json.loads(registered.stdout)['DisplayName'], 'DNSProxy')
        start_menu = self.ps("[Environment]::GetFolderPath('CommonPrograms')").stdout.strip()
        self.assertTrue((Path(start_menu) / 'DNSProxy/Start DNSProxy in a console.lnk').is_file())

    def assert_dns(self, port):
        # FORMERR is generated locally and requires no Internet or test trust edit.
        packet = b'\x12\x34\x01\x00\x00\x01' + b'\0' * 6
        for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                client.settimeout(4)
                client.sendto(packet, (address, port))
                answer = client.recv(4096)
            self.assertEqual(answer[:2], packet[:2])
            self.assertEqual(answer[3] & 15, 1)
            with socket.create_connection((address, port), timeout=4) as client:
                client.sendall(struct.pack('!H', len(packet)) + packet)
                self.assertEqual(fixtures.Tests.tcp_frame(client), answer)

    def test_a_interactive_wizard_can_be_cancelled_before_changes(self):
        # Exercise native controls without a Python UI runtime in the product.
        from ctypes import wintypes

        user = ctypes.WinDLL('user32', use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user.IsWindowVisible.argtypes = [wintypes.HWND]
        user.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
        user.EnumChildWindows.argtypes = [wintypes.HWND, callback_type, wintypes.LPARAM]
        user.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user.SendMessageW.restype = wintypes.LPARAM

        def windows(parent=None):
            found = []

            @callback_type
            def collect(handle, _):
                if user.IsWindowVisible(handle):
                    caption, kind = ctypes.create_unicode_buffer(2048), ctypes.create_unicode_buffer(128)
                    user.GetWindowTextW(handle, caption, len(caption))
                    user.GetClassNameW(handle, kind, len(kind))
                    found.append((handle, caption.value, kind.value))
                return True

            if parent:
                user.EnumChildWindows(parent, collect, 0)
            else:
                user.EnumWindows(collect, 0)
            return found

        def wait_for(predicate, parent=None):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                found = [entry for entry in windows(parent) if predicate(entry)]
                if found:
                    return found[0][0]
                time.sleep(.1)
            self.fail(f'Wizard control not found. Windows: {windows(parent)}')

        def click(caption, parent):
            handle = wait_for(lambda entry: entry[1].replace('&', '').startswith(caption), parent)
            user.SendMessageW(handle, 0x00F5, 0, 0)  # BM_CLICK

        def screenshot(name):
            path = self.quoted(self.evidence / name)
            self.ps("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
                    '$bounds=[Windows.Forms.Screen]::PrimaryScreen.Bounds; '
                    '$bitmap=New-Object Drawing.Bitmap($bounds.Width,$bounds.Height); '
                    '$graphics=[Drawing.Graphics]::FromImage($bitmap); '
                    '$graphics.CopyFromScreen($bounds.Location,[Drawing.Point]::Empty,$bounds.Size); '
                    f'$bitmap.Save({path},[Drawing.Imaging.ImageFormat]::Png); '
                    '$graphics.Dispose(); $bitmap.Dispose()')

        process = subprocess.Popen([str(self.installer), '/SP-'], env=self.environment)
        try:
            wizard = wait_for(lambda entry: entry[2] == 'TWizardForm' and 'DNSProxy' in entry[1])
            click('I accept the agreement', wizard)
            click('Next', wizard)
            wait_for(lambda entry: entry[1] == 'Windows service', wizard)
            screenshot('01-service-choice.png')
            selector = wait_for(lambda entry: 'CheckListBox' in entry[2], wizard)
            user.SendMessageW(selector, 0x0186, 0, 0)  # LB_SETCURSEL
            user.SendMessageW(selector, 0x0100, 0x20, 0)  # WM_KEYDOWN / Space
            user.SendMessageW(selector, 0x0101, 0x20, 0)
            click('Next', wizard)
            wait_for(lambda entry: entry[1].replace('&', '').startswith('Numeric bootstrap IP'), wizard)
            screenshot('02-service-options.png')
            click('Cancel', wizard)
            confirmation = wait_for(lambda entry: entry[0] != wizard and 'Setup' in entry[1])
            click('Yes', confirmation)
            process.wait(timeout=20)
            self.assertIsNone(self.service())
            self.assertFalse(self.app.exists())
        finally:
            if process.poll() is None:
                subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], capture_output=True)

    def test_default_install_is_optional_service_and_can_be_removed(self):
        before = self.ps('Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4').stdout
        with self.installation():
            self.assertIsNone(self.service())
            self.assert_installed_payload()
            after = self.ps('Get-DnsClientServerAddress | Select-Object InterfaceIndex,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 4').stdout
            self.assertEqual(json.loads(before), json.loads(after))

    def test_service_configuration_https_upgrade_and_dns_uninstall_guard(self):
        port = fixtures.unused_ports()[0]
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / 'localhost.crt', Path(directory) / 'localhost.key'
            subprocess.run([fixtures.OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-out', str(cert), '-keyout', str(key)], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with fixtures.HTTP(('127.0.0.1', 0), fixtures.DoH) as server:
                server.socket = context.wrap_socket(server.socket, server_side=True)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                upstream = f'https://localhost:{server.server_port}/dns-query'
                try:
                    with self.installation('/SERVICE=1', f'/PORT={port}', f'/UPSTREAM={upstream}',
                                           '/BOOTSTRAP=127.0.0.1', '/AUTOSTART=0'):
                        self.assert_installed_payload()
                        service = self.service()
                        self.assertEqual(service['State'], 'Running')
                        self.assertEqual(service['StartMode'], 'Manual')
                        self.assertEqual(service['StartName'].lower(), 'nt authority\\localservice')
                        self.assert_dns(port)
                        record = json.loads((self.state / 'installation.json').read_text(encoding='utf-8-sig'))
                        self.assertEqual(record['Port'], port)
                        self.assertEqual(record['Upstream'], upstream)
                        self.assertEqual(record['ListenAddress'], ['127.0.0.1', '::1'])
                        self.assertEqual(record['ManagedBy'], 'InnoSetup')
                        # Trust only the controlled TLS fixture, after checking the production payload.
                        ca = self.app / 'bin/ca-bundle.crt'
                        ca.write_bytes(ca.read_bytes() + b'\n' + cert.read_bytes())
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                            client.settimeout(5)
                            client.sendto(fixtures.query(28), ('127.0.0.1', port))
                            self.assertEqual(client.recv(4096)[3] & 15, 0)
                        # A guard must fail before stopping or deleting an owned resolver.
                        pending = self.state / 'dns-state.json'
                        pending.write_text('{"synthetic_pending_test":true}')
                        try:
                            self.invoke(self.installer, '/SERVICE=1', succeeds=False)
                            self.uninstall(succeeds=False)
                            self.assertEqual(self.service()['ProcessId'], service['ProcessId'])
                            self.assert_dns(port)
                        finally:
                            pending.unlink()
                        log_marker = self.state / 'logs/keep-upgrade.txt'
                        log_marker.write_text('keep logs')
                        user_file = self.app / 'bin/keep-user-file.txt'
                        user_file.write_text('keep unowned data')
                        obsolete = self.app / 'bin/obsolete-ci-file.txt'
                        obsolete.write_bytes(b'old installer-owned file')
                        with (self.app / 'bin/SHA256SUMS').open('a') as manifest:
                            manifest.write(hashlib.sha256(obsolete.read_bytes()).hexdigest() + '  ' + obsolete.name + '\n')
                        # Upgrade retains the existing configuration rather than adopting defaults.
                        self.invoke(self.installer, '/SERVICE=1')
                        self.assertEqual(self.service()['StartMode'], 'Manual')
                        self.assertNotEqual(self.service()['ProcessId'], service['ProcessId'])
                        self.assertEqual(json.loads((self.state / 'installation.json').read_text(encoding='utf-8-sig')), record)
                        self.assert_dns(port)
                        self.assertFalse(obsolete.exists())
                        self.assertEqual(log_marker.read_text(), 'keep logs')
                        self.assertEqual(user_file.read_text(), 'keep unowned data')
                        self.ps('Stop-Service DNSProxy')
                        self.invoke(self.installer, '/SERVICE=1')
                        self.assertEqual(self.service()['State'], 'Stopped')
                finally:
                    server.shutdown()
                    worker.join(timeout=3)

    def test_automatic_service_can_be_installed_stopped_without_ipv6(self):
        with self.installation('/SERVICE=1', '/IPV6=0', '/STARTNOW=0'):
            service = self.service()
            self.assertEqual(service['State'], 'Stopped')
            self.assertEqual(service['StartMode'], 'Auto')
            record = json.loads((self.state / 'installation.json').read_text(encoding='utf-8-sig'))
            self.assertEqual(record['ListenAddress'], ['127.0.0.1'])

    def test_invalid_configuration_port_conflicts_and_foreign_service_do_not_install(self):
        for argument in ('/PORT=0', '/UPSTREAM=http://localhost/dns-query',
                         '/UPSTREAM=https://user:secret@localhost/dns-query', '/BOOTSTRAP=localhost'):
            with self.subTest(argument=argument):
                self.invoke(self.installer, '/SERVICE=1', argument, succeeds=False)
                self.assertIsNone(self.service())
                self.assertFalse(self.app.exists())
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(('127.0.0.1', 0))
            self.invoke(self.installer, '/SERVICE=1', f'/PORT={listener.getsockname()[1]}', succeeds=False)
            self.assertFalse(self.app.exists())
        binary = fixtures.BINARY.resolve()
        self.ps(f'New-Service -Name DNSProxy -BinaryPathName {self.quoted(binary)} -StartupType Manual | Out-Null')
        try:
            before = self.service()
            self.invoke(self.installer, '/SERVICE=1', succeeds=False)
            self.assertEqual(self.service(), before)
            self.assertFalse(self.app.exists())
        finally:
            self.ps('sc.exe delete DNSProxy; if ($LASTEXITCODE) { throw "SCM delete failed" }')


if __name__ == '__main__':
    unittest.main(verbosity=2)
