"""Runtime requirements shared by the loopback integration tests."""
import errno
import os
import socket
import unittest


_IPV6_UNAVAILABLE = {
    getattr(errno, name)
    for name in (
        'EAFNOSUPPORT', 'EPROTONOSUPPORT', 'ENOPROTOOPT', 'EADDRNOTAVAIL', 'ENODEV',
        'WSAEAFNOSUPPORT', 'WSAEPROTONOSUPPORT', 'WSAENOPROTOOPT', 'WSAEADDRNOTAVAIL',
    )
    if hasattr(errno, name)
}


def require_ipv6_loopback():
    """Probe both transports; skip unavailable IPv6 locally and require it in CI."""
    try:
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            with socket.socket(socket.AF_INET6, kind) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(('::1', 0))
    except OSError as error:
        if (error.errno not in _IPV6_UNAVAILABLE and
                getattr(error, 'winerror', None) not in _IPV6_UNAVAILABLE):
            raise
        if os.environ.get('DNSP_REQUIRE_IPV6') == '1':
            raise RuntimeError(
                f'IPv6 loopback is required by DNSP_REQUIRE_IPV6=1: {error}'
            ) from error
        raise unittest.SkipTest(f'IPv6 loopback is unavailable on this host: {error}') from error
