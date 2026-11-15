"""Real loopback HTTPS downloads; failed updates leave the installed file intact."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

from test_modern import BINARY, OPENSSL

BASE = Path(__file__).resolve().parents[1]


class Feed(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', self.server.redirect)
        else:
            self.send_response(200)
            self.send_header('Content-Type', self.server.media)
            self.send_header('Content-Length', str(len(self.server.body)))
        self.end_headers()
        if self.path != '/redirect':
            try:
                self.wfile.write(self.server.body)
            except OSError:
                pass

    def log_message(self, *_args):
        pass


class UpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='dnsp-feed-')
        cls.root = Path(cls.directory.name)
        cls.cert, key = cls.root/'ca.pem', cls.root/'ca.key'
        subprocess.run([OPENSSL, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(cls.cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        cls.server = HTTPServer(('127.0.0.1', 0), Feed)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.worker = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        cls.worker.start()
        cls.url = f'https://localhost:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=3)
        cls.directory.cleanup()

    def setUp(self):
        self.target = self.root/'installed.txt'
        self.target.write_text('original.example\n')
        self.server.body, self.server.media = b'0.0.0.0 ads.example\n', 'text/plain'
        self.server.redirect = self.url + '/list'

    def run_update(self, *flags, url=None, output=None):
        return subprocess.run([sys.executable, str(BASE/'scripts/update-blocklist.py'),
                               url or self.url + '/list', str(output or self.target),
                               '--binary', str(BINARY), '--ca-file', str(self.cert), *flags],
                              text=True, capture_output=True, timeout=15)

    def assert_unchanged(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.target.read_text(), 'original.example\n')
        self.assertEqual(list(self.root.glob('.installed.txt.*')), [])

    def test_valid_download_preserves_permissions_and_replaces_after_validation(self):
        if os.name != 'nt':
            self.target.chmod(0o640)
        digest = hashlib.sha256(self.server.body).hexdigest()
        result = self.run_update('--sha256', digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), self.server.body)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.assertEqual(list(self.root.glob('.installed.txt.*')), [])

    def test_invalid_downloads_never_replace_the_current_file(self):
        for body, media in ((b'<html>error</html>', 'text/html'), (b'', 'text/plain'),
                            (b'# no domains\n', 'text/plain'), (b'bad..example\n', 'text/plain'),
                            (b'||ad.example^\n', 'text/plain'), (b'ad.example\0\n', 'text/plain')):
            with self.subTest(body=body):
                self.server.body, self.server.media = body, media
                self.assert_unchanged(self.run_update())
        self.server.body, self.server.media = b'ads.example\n', 'text/plain'
        self.assert_unchanged(self.run_update('--sha256', '0'*64))
        self.assert_unchanged(self.run_update('--max-bytes', '3'))

    def test_https_redirects_and_certificate_verification(self):
        result = self.run_update(url=self.url + '/redirect')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.target.write_text('original.example\n')
        self.server.redirect = f'http://localhost:{self.server.server_port}/list'
        self.assert_unchanged(self.run_update(url=self.url + '/redirect'))
        self.assert_unchanged(self.run_update(url='http://localhost/list'))
        self.assert_unchanged(self.run_update(url=f'https://127.0.0.1:{self.server.server_port}/list'))
        self.assert_unchanged(self.run_update('--ca-file', str(self.root/'absent.pem')))

    @unittest.skipIf(os.name == 'nt', 'Unprivileged Windows symlinks depend on host policy')
    def test_symlink_output_cannot_replace_another_file(self):
        alias = self.root/'link.txt'
        alias.symlink_to(self.target)
        try:
            self.assert_unchanged(self.run_update(output=alias))
            self.assertTrue(alias.is_symlink())
        finally:
            alias.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
