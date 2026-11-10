"""Exercise both IPv6 bootstrap options with real TLS and an IPv4 DNS client."""
import errno
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

import test_modern as fixtures


class Ipv6BootstrapTests(unittest.TestCase):
    isolated_udp = fixtures.Tests.isolated_udp

    @unittest.skipUnless(shutil.which('openssl'), 'openssl required for local TLS')
    def test_primary_and_backup_ipv6_bootstrap(self):
        class IPv6HTTP(fixtures.HTTP):
            address_family = socket.AF_INET6

        with tempfile.TemporaryDirectory(prefix='dnsp-v6-') as tmp:
            cert, key = str(Path(tmp)/'cert.pem'), str(Path(tmp)/'key.pem')
            hostname = 'dnsp-bootstrap-v6.invalid'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '1', '-subj', f'/CN={hostname}',
                            '-addext', f'subjectAltName=DNS:{hostname}',
                            '-out', cert, '-keyout', key], check=True, timeout=10,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            try:
                upstream = IPv6HTTP(('::1', 0), fixtures.DoH)
            except OSError as exc:
                if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                    self.skipTest('IPv6 loopback unavailable')
                raise
            with upstream:
                upstream.socket = ctx.wrap_socket(upstream.socket, server_side=True)
                thread = threading.Thread(target=upstream.serve_forever, daemon=True)
                thread.start()
                try:
                    url = f'https://{hostname}:{upstream.server_port}/dns-query'
                    env = dict(os.environ, https_proxy='http://127.0.0.1:1',
                               no_proxy='', NO_PROXY='')
                    expected = fixtures.make_response(fixtures.QUERY)
                    self.assertEqual(self.isolated_udp(
                        url, '--ca-file', cert, '--bootstrap-address', '::1', env=env), expected)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed:
                        closed.bind(('127.0.0.1', 0))
                        primary = f'http://127.0.0.1:{closed.getsockname()[1]}/dns-query'
                        self.assertEqual(self.isolated_udp(
                            primary, '--backup-upstream', url, '--backup-bootstrap-address', '::1',
                            '--ca-file', cert, env=env), expected)
                finally:
                    upstream.shutdown()
                    thread.join(timeout=3)
