"""Regression coverage for IPv6-disabled hosts and strict CI requirements."""
import errno
import socket
import unittest
from unittest import mock

import host_capabilities as host


class HostCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(host.os.environ, {'DNSP_REQUIRE_IPV6': '0'})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @staticmethod
    def fake_socket():
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        return sock

    def test_probes_udp_and_tcp_and_closes_both_sockets(self):
        sockets = [self.fake_socket(), self.fake_socket()]
        with mock.patch.object(host.socket, 'socket', side_effect=sockets) as factory:
            host.require_ipv6_loopback()
        self.assertEqual(factory.call_args_list, [
            mock.call(socket.AF_INET6, socket.SOCK_DGRAM),
            mock.call(socket.AF_INET6, socket.SOCK_STREAM),
        ])
        for sock in sockets:
            sock.setsockopt.assert_called_once_with(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind.assert_called_once_with(('::1', 0))
            sock.__exit__.assert_called_once()

    def test_unavailable_address_families_skip_locally(self):
        for code in host._IPV6_UNAVAILABLE:
            with self.subTest(code=code):
                error = OSError(code, 'IPv6 disabled')
                with mock.patch.object(host.socket, 'socket', side_effect=error):
                    with self.assertRaisesRegex(unittest.SkipTest, 'IPv6 loopback is unavailable') as result:
                        host.require_ipv6_loopback()
                self.assertIs(result.exception.__cause__, error)

    def test_missing_loopback_address_skips_and_closes_socket(self):
        sock = self.fake_socket()
        sock.bind.side_effect = OSError(errno.EADDRNOTAVAIL, 'No IPv6 loopback address')
        with mock.patch.object(host.socket, 'socket', return_value=sock):
            with self.assertRaises(unittest.SkipTest):
                host.require_ipv6_loopback()
        sock.__exit__.assert_called_once()

    def test_udp_support_alone_does_not_enable_tcp_tests(self):
        sock = self.fake_socket()
        error = OSError(errno.EPROTONOSUPPORT, 'IPv6 TCP unavailable')
        with mock.patch.object(host.socket, 'socket', side_effect=[sock, error]):
            with self.assertRaises(unittest.SkipTest):
                host.require_ipv6_loopback()
        sock.__exit__.assert_called_once()

    def test_required_ipv6_fails_instead_of_skipping(self):
        for kind in ('udp', 'tcp'):
            with self.subTest(kind=kind):
                error = OSError(errno.EAFNOSUPPORT, 'IPv6 disabled')
                sockets = [error] if kind == 'udp' else [self.fake_socket(), error]
                with mock.patch.dict(host.os.environ, {'DNSP_REQUIRE_IPV6': '1'}), \
                     mock.patch.object(host.socket, 'socket', side_effect=sockets):
                    with self.assertRaisesRegex(RuntimeError, 'required by DNSP_REQUIRE_IPV6=1') as result:
                        host.require_ipv6_loopback()
                self.assertIs(result.exception.__cause__, error)

    def test_resource_permission_and_other_errors_are_not_skipped(self):
        for code in (errno.EMFILE, errno.EACCES, errno.EADDRINUSE):
            with self.subTest(code=code):
                error = OSError(code, 'Unexpected host error')
                with mock.patch.object(host.socket, 'socket', side_effect=error):
                    with self.assertRaises(OSError) as result:
                        host.require_ipv6_loopback()
                self.assertIs(result.exception, error)


if __name__ == '__main__':
    unittest.main(verbosity=2)
