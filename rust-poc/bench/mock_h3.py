"""Small QUIC DoH fixture for loopback tests and benchmarks."""
import asyncio
import base64
from urllib.parse import parse_qs

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

from mock_doh import make_response


async def start_http3(host, port, cert, key, app):
    class DohProtocol(QuicConnectionProtocol):
        def __init__(self, quic, **kwargs):
            super().__init__(quic, **kwargs)
            self.http = H3Connection(quic)
            self.requests = {}

        def quic_event_received(self, event):
            for message in self.http.handle_event(event):
                ready = False
                if isinstance(message, HeadersReceived):
                    headers = dict(message.headers)
                    method = headers.get(b':method')
                    path, _, query = headers.get(b':path', b'').partition(b'?')
                    if method == b'POST' and path == b'/dns-query':
                        self.requests[message.stream_id] = bytearray()
                    elif method == b'GET' and path == b'/dns-query':
                        value, = parse_qs(query.decode('ascii'))['dns']
                        body = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
                        self.requests[message.stream_id] = bytearray(body)
                    if message.stream_id in self.requests:
                        record_method = getattr(app, 'record_method', None)
                        if record_method:
                            record_method(method.decode('ascii'))
                        ready = message.stream_ended
                elif isinstance(message, DataReceived) and message.stream_id in self.requests:
                    self.requests[message.stream_id].extend(message.data)
                    ready = message.stream_ended
                if ready:
                    stream = message.stream_id
                    app.begin(self, '3')
                    asyncio.get_running_loop().call_later(
                        app.delay, self.reply, stream, self.requests.pop(stream))

        def reply(self, stream, body):
            response = make_response(bytes(body), app.answers)
            try:
                self.http.send_headers(stream, [(b':status', b'200' if response else b'400'),
                                                (b'content-type', b'application/dns-message')])
                self.http.send_data(stream, response or b'', end_stream=True)
                self.transmit()
            finally:
                app.finish(self, response is not None)

    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(str(cert), str(key))
    return await serve(host, port, configuration=config, create_protocol=DohProtocol)
