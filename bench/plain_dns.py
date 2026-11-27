"""Plain UDP version of the loopback benchmark fixture, using the same DNS answers."""
import asyncio

from mock_doh import make_response


def udp_worker(channel, port, delay_ms):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    completed = invalid = inflight = 0

    class Upstream(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, peer):
            nonlocal invalid, inflight
            response = make_response(data, 1)
            if response is None:
                invalid += 1
                return
            inflight += 1

            def finish():
                nonlocal completed, inflight
                self.transport.sendto(response, peer)
                completed += 1
                inflight -= 1

            loop.call_later(delay_ms / 1000, finish)

    transport, _ = loop.run_until_complete(loop.create_datagram_endpoint(
        Upstream, local_addr=('127.0.0.1', port)))

    def control():
        nonlocal completed, invalid
        operation = channel.recv()
        if operation == 'stop':
            loop.stop()
            return
        if operation == 'reset':
            if inflight:
                raise RuntimeError('UDP fixture still has pending replies')
            completed = invalid = 0
        channel.send(dict(upstream_completed=completed, upstream_invalid=invalid, upstream_inflight=inflight))

    try:
        loop.add_reader(channel.fileno(), control)
        channel.send('ready')
        loop.run_forever()
    finally:
        transport.close()
        channel.close()
        loop.run_until_complete(asyncio.sleep(0))
        loop.close()
