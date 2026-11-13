"""SCM acceptance using a real LocalService process and local HTTPS fixture."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

import test_modern as fixtures


@unittest.skipUnless(os.name == 'nt', 'Native Windows SCM acceptance')
class ServiceTests(unittest.TestCase):
    def ps(self, text, check=True):
        executable = Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        # The workflow runs in PowerShell 7. Its module path points at incompatible
        # assemblies for Windows PowerShell 5.1; let the child select its own.
        environment = {k: v for k, v in os.environ.items() if k.lower() != 'psmodulepath'}
        result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-Command',
                                 "$ErrorActionPreference='Stop'; " + text],
                                text=True, capture_output=True, timeout=45, env=environment)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    @staticmethod
    def quoted(path):
        return "'" + str(path).replace("'", "''") + "'"

    @contextmanager
    def installed(self):
        name = 'DNSProxy-CI-' + uuid.uuid4().hex[:10]
        source = Path(tempfile.mkdtemp())/'portable bundle'
        shutil.copytree(fixtures.BINARY.parent, source)
        try:
            cert, key = source/'ca-bundle.crt', source.parent/'localhost.key'
            subprocess.run([fixtures.OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                            '-out', str(cert), '-keyout', str(key)], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            with fixtures.HTTP(('127.0.0.1', 0), fixtures.DoH) as server:
                server.socket = context.wrap_socket(server.socket, server_side=True)
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    script = self.quoted(source/'Install-DNSProxyService.ps1')
                    args = f"-ServiceName {name} -Upstream https://localhost:{server.server_port}/dns-query -BootstrapAddress 127.0.0.1"
                    self.ps(f'& {script} {args}')
                    yield name, source
                finally:
                    state = Path(os.environ['ProgramData'])/name/'installation.json'
                    if state.exists():
                        self.ps(f"& {self.quoted(source/'Uninstall-DNSProxyService.ps1')} -ServiceName {name}")
                    server.shutdown()
                    worker.join(timeout=3)
        finally:
            shutil.rmtree(source.parent)

    def assert_dns(self):
        packet = fixtures.query(28)
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(packet, (host, 53))
                self.assertEqual(sock.recv(4096)[3] & 15, 0)
            with socket.create_connection((host, 53), timeout=3) as sock:
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                self.assertEqual(fixtures.Tests.tcp_frame(sock)[3] & 15, 0)

    def test_service_lifecycle_account_recovery_and_uninstall(self):
        with self.installed() as (name, source):
            service = json.loads(self.ps(f"Get-CimInstance Win32_Service -Filter \"Name='{name}'\" | Select-Object State,StartName,StartMode,ProcessId | ConvertTo-Json").stdout)
            self.assertEqual(service['State'], 'Running')
            self.assertEqual(service['StartName'].lower(), 'nt authority\\localservice')
            self.assertEqual(service['StartMode'], 'Auto')
            self.assert_dns()
            integration = Path(os.environ['ProgramFiles'])/name/'Set-DNSProxyDns.ps1'
            self.assertIn('No DNSProxy adapter configuration', self.ps(
                f"& {self.quoted(integration)} -ServiceName {name} -Action Status").stdout)
            self.ps(f"& {self.quoted(integration)} -ServiceName {name} -Action Enable -WhatIf")
            self.assertFalse((Path(os.environ['ProgramData'])/name/'dns-state.json').exists())
            # Duplicate install cannot replace an existing service or delete its files.
            duplicate = self.ps(f"& {self.quoted(source/'Install-DNSProxyService.ps1')} -ServiceName {name}", check=False)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assert_dns()
            self.ps(f"Stop-Service {name}; (Get-Service {name}).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(10))")
            for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                    with socket.socket(family, kind) as sock:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        sock.bind((host, 53))
            self.ps(f"Start-Service {name}; (Get-Service {name}).WaitForStatus('Running',[TimeSpan]::FromSeconds(10))")
            self.assert_dns()
            pid = int(self.ps(f"(Get-CimInstance Win32_Service -Filter \"Name='{name}'\").ProcessId").stdout)
            self.ps(f'Stop-Process -Id {pid} -Force')
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = self.ps(f"(Get-CimInstance Win32_Service -Filter \"Name='{name}'\").ProcessId").stdout.strip()
                if current not in ('0', str(pid)):
                    try:
                        self.assert_dns()
                        break
                    except OSError:
                        pass
                time.sleep(.2)
            else:
                self.fail('SCM did not recover the terminated service')
            log = Path(os.environ['ProgramData'])/name/'logs/service.log'
            self.assertIn('event=listening', log.read_text())
        self.assertFalse((Path(os.environ['ProgramFiles'])/name).exists())
        self.assertFalse((Path(os.environ['ProgramData'])/name).exists())
        self.assertEqual(self.ps(f"@(Get-Service {name} -ErrorAction SilentlyContinue).Count").stdout.strip(), '0')

    def test_startup_conflict_rolls_back_installation(self):
        name = 'DNSProxy-CI-' + uuid.uuid4().hex[:10]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(('127.0.0.1', 53))
            result = self.ps(f"& {self.quoted(fixtures.BINARY.parent/'Install-DNSProxyService.ps1')} -ServiceName {name}", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Start-Service', result.stderr)
        self.assertFalse((Path(os.environ['ProgramFiles'])/name).exists())
        self.assertFalse((Path(os.environ['ProgramData'])/name).exists())


if __name__ == '__main__':
    unittest.main()
