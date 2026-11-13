"""Acceptance checks for the extracted native macOS launcher."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'Native macOS package acceptance')
class MacOSTests(unittest.TestCase):
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
