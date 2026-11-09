"""Local TLS/ALPN HTTP/2 or HTTP/1.1 DoH upstream for repeatable benchmarks.

Uses Hypercorn (ASGI); tracks concurrent requests per TLS connection by peer
IP/port as observed on the server, rather than inferring multiplexing from
curl's aggregate counters. This is a test server, not a general resolver.
"""
import asyncio
import http.server
import socketserver
import socket
import ssl
import time
from collections import Counter, defaultdict
import threading


class DohApp:
    def __init__(self, delay_ms=5, answers=1):
        self.delay = delay_ms / 1000.0
        self.answers = answers
        self.lock = threading.Lock()
        self._clear()

    def _clear(self):
        self.connections = set()
        self.http_versions = Counter()
        self.active = defaultdict(int)
        self.max_per_connection = 0
        self.max_total = 0
        self.inflight = 0
        self.completed = 0
        self.invalid = 0

    def reset(self):
        with self.lock:
            if self.inflight:
                raise RuntimeError("Cannot reset upstream metrics while requests remain active")
            self._clear()

    def snapshot(self):
        with self.lock:
            return {
                'upstream_connections_used': len(self.connections),
                'upstream_http_versions': dict(self.http_versions),
                'upstream_max_simultaneous_per_connection': self.max_per_connection,
                'upstream_max_simultaneous_total': self.max_total,
                'upstream_completed': self.completed,
                'upstream_invalid': self.invalid,
                'upstream_inflight': self.inflight,
            }

    def begin(self, peer, version):
        with self.lock:
            self.connections.add(peer)
            self.http_versions[version] += 1
            self.active[peer] += 1
            self.inflight += 1
            self.max_total = max(self.max_total, self.inflight)
            self.max_per_connection = max(self.max_per_connection, self.active[peer])

    def finish(self, peer, valid):
        with self.lock:
            if valid:
                self.completed += 1
            else:
                self.invalid += 1
            self.inflight -= 1
            self.active[peer] -= 1
            if not self.active[peer]:
                del self.active[peer]

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return
        if scope['method'] != 'POST' or scope['path'] != '/dns-query':
            await send({'type': 'http.response.start', 'status': 404, 'headers': []})
            await send({'type': 'http.response.body', 'body': b''})
            return
        body = bytearray()
        while True:
            event = await receive()
            if event['type'] == 'http.disconnect':
                return
            if event['type'] != 'http.request':
                continue
            body.extend(event.get('body', b''))
            if event.get('more_body', False) is False:
                break
        peer = tuple(scope['client'])  # stable per TCP/TLS connection
        self.begin(peer, scope['http_version'])
        valid = False
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            response = make_response(bytes(body), self.answers)
            if response is None:
                await send({'type': 'http.response.start', 'status': 400, 'headers': []})
                await send({'type': 'http.response.body', 'body': b''})
            else:
                await send({'type': 'http.response.start', 'status': 200,
                            'headers': [(b'content-type', b'application/dns-message'),
                                        (b'content-length', str(len(response)).encode())]})
                await send({'type': 'http.response.body', 'body': response})
                valid = True
        finally:
            self.finish(peer, valid)


def make_response(data, answers):
    if len(data) < 17 or data[2] & 0x80 or data[4:6] != b'\x00\x01':
        return None
    i = 12
    while True:
        if i >= len(data):
            return None
        n = data[i]
        i += 1
        if n > 63 or i+n > len(data):
            return None
        i += n
        if n == 0:
            break
    if i + 4 > len(data):
        return None
    question = data[12:i+4]
    rr = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01'
    return (data[:2] + b'\x81\x80\x00\x01' + answers.to_bytes(2, 'big') +
            b'\x00\x00\x00\x00' + question + rr*answers)


class Http1Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http1(host, port, cert, key, app):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass  # normal when the client retires a keepalive connection

        def do_POST(self):
            if self.path != '/dns-query':
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if length < 12 or length > 65535:
                    self.send_error(400)
                    return
                data = self.rfile.read(length)
            except (ValueError, OSError):
                return
            peer = tuple(self.client_address)
            app.begin(peer, '1.1')
            valid = False
            try:
                if app.delay:
                    time.sleep(app.delay)
                response = make_response(data, app.answers)
                valid = response is not None
                self.send_response(200 if valid else 400)
                self.send_header('Content-Type', 'application/dns-message')
                self.send_header('Content-Length', str(len(response) if valid else 0))
                self.end_headers()
                if valid:
                    self.wfile.write(response)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            finally:
                app.finish(peer, valid)

        def log_message(self, *_args):
            pass

    server = Http1Server((host, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(['http/1.1'])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name='doh-http1')
    thread.start()
    return server, thread


class MockServer:
    def __init__(self, port, cert, key, protocol='h2', delay_ms=5, answers=1,
                 h2_max_streams=100, h2_idle_timeout=30.0, h2_max_requests=10_000_000):
        self.port = port
        self.cert = cert
        self.key = key
        self.protocol = protocol
        self.h2_max_streams = h2_max_streams
        self.h2_idle_timeout = h2_idle_timeout
        self.h2_max_requests = h2_max_requests
        self.app = DohApp(delay_ms=delay_ms, answers=answers)
        self.loop = None
        self.stop = None
        self.thread = None
        self.failure = None
        self.http1_server = None

    def start(self):
        if self.protocol == 'h1':
            self.http1_server, self.thread = start_http1('127.0.0.1', self.port, self.cert, self.key, self.app)
            return
        from hypercorn.asyncio import serve
        from hypercorn.config import Config
        config = Config()
        config.bind = [f'127.0.0.1:{self.port}']
        config.certfile = str(self.cert)
        config.keyfile = str(self.key)
        config.alpn_protocols = ['h2'] if self.protocol == 'h2' else ['http/1.1']
        config.accesslog = None
        config.errorlog = None
        config.loglevel = 'ERROR'
        config.h2_max_concurrent_streams = self.h2_max_streams
        # Keep synthetic tests focused on multiplexing, not a framework's
        # default 1000-requests-per-connection GOAWAY policy.
        config.keep_alive_max_requests = self.h2_max_requests
        config.keep_alive_timeout = self.h2_idle_timeout

        def entry():
            async def run():
                self.loop = asyncio.get_running_loop()
                self.stop = asyncio.Event()
                await serve(self.app, config, shutdown_trigger=self.stop.wait)
            try:
                asyncio.run(run())
            except Exception as exc:
                self.failure = exc
        self.thread = threading.Thread(target=entry, name='doh-mock', daemon=True)
        self.thread.start()

    def close(self):
        if self.http1_server is not None:
            self.http1_server.shutdown()
            self.http1_server.server_close()
            self.thread.join(timeout=5)
            return
        if self.loop is not None and self.stop is not None:
            try:
                self.loop.call_soon_threadsafe(self.stop.set)
            except RuntimeError:
                pass
        if self.thread:
            self.thread.join(timeout=5)
