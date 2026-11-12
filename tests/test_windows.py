"""Native Windows acceptance: system DNS port, native client and console shutdown."""
from contextlib import contextmanager
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

import test_modern as fixtures
from test_modern import BINARY, DoH, HTTP, QUERY, make_response, question_end, rr


class WindowsDoH(DoH):
    def do_POST(self):
        packet = self.rfile.read(int(self.headers['Content-Length']))
        response = make_response(packet)
        end = question_end(response)
        if response[end-4:end-2] == b'\0\1':
            response = (response[:6] + b'\0\1' + response[8:end] +
                        rr(1, b'\xc0\0\x02\x01') + response[end:])
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)


@unittest.skipUnless(os.name == 'nt', 'Native Windows acceptance tests')
class WindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A headless CI shell may have no console to deliver control events.
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        if not kernel.GetConsoleCP():
            if not kernel.AllocConsole():
                raise ctypes.WinError(ctypes.get_last_error())
            cls.addClassCleanup(kernel.FreeConsole)

    @contextmanager
    def proxy(self):
        with HTTP(('127.0.0.1', 0), WindowsDoH) as server, tempfile.TemporaryFile() as log:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            process = subprocess.Popen([
                str(BINARY), '-l', '127.0.0.1', '-p', '53',
                '-s', f'http://127.0.0.1:{server.server_port}/dns-query',
            ], stderr=log, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        with socket.create_connection(('127.0.0.1', 53), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.05)
                else:
                    log.seek(0)
                    self.fail(f'Port 53 startup failed: {log.read()!r}')
                yield process
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                    process.wait(timeout=5)
                server.shutdown()
                worker.join(timeout=3)

    def test_port_53_udp_tcp_and_native_resolver(self):
        with self.proxy():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(QUERY, ('127.0.0.1', 53))
                answer = client.recv(4096)
                self.assertEqual(answer[:2], QUERY[:2])
                self.assertTrue(answer.endswith(b'\xc0\0\x02\x01'))
            with socket.create_connection(('127.0.0.1', 53), timeout=3) as client:
                client.sendall(struct.pack('!H', len(QUERY)) + QUERY)
                self.assertEqual(fixtures.Tests.tcp_frame(client), answer)
            resolved = subprocess.run([
                'powershell.exe', '-NoProfile', '-Command',
                'Resolve-DnsName www.google.com -Type A -Server 127.0.0.1 -DnsOnly '
                '| Select-Object -ExpandProperty IPAddress',
            ], capture_output=True, text=True, timeout=15)
            self.assertEqual(resolved.returncode, 0, resolved.stderr)
            self.assertIn('192.0.2.1', resolved.stdout)

    def test_listener_is_exclusive_and_console_stop_is_clean(self):
        with self.proxy() as process:
            other = subprocess.run([str(BINARY), '-l', '127.0.0.1', '-p', '53'],
                                   capture_output=True, timeout=5)
            self.assertNotEqual(other.returncode, 0)
            self.assertIn(b'role=dns_udp', other.stderr)
            process.send_signal(signal.CTRL_BREAK_EVENT)
            self.assertEqual(process.wait(timeout=5), 0)


if __name__ == '__main__':
    unittest.main()
