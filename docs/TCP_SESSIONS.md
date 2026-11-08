# `dnsp-modern`: persistent DNS-over-TCP sessions

`dnsp-modern` accepts conventional DNS-over-TCP messages, each prefixed by a
2-byte network-order length. Starting with the TCP session patch (proposed for
`v0.2.3-modern`), it **keeps the client TCP connection open after a response**.
This is independent of the persistent upstream libcurl/DoH connection pool.

## Protocol behavior

- Multiple complete requests can be sent sequentially over a single TCP connection.
- Coalesced / pipelined requests are accepted and responses are sent **in request
  order**. The current implementation allows **one upstream request in flight per
  TCP client** and buffers **one additional complete DNS frame**. Remaining
  pipelined bytes stay in the kernel receive buffer, providing backpressure.
- This is **not parallel, out-of-order processing of pipelined TCP queries**.
  It improves client-side TCP reuse, not the maximum throughput of one TCP
  session with high upstream latency. Multiple TCP clients and UDP queries still
  use the existing bounded, asynchronous HTTP/2 upstream pool.
- Client write-half-closes (`shutdown(SHUT_WR)`) are supported: a client may send
  its final query and continue reading the corresponding response(s).
- Abrupt disconnects (including TCP resets) cancel any outstanding upstream
  request associated with that client, freeing the in-flight slot.
- Empty or malformed TCP frames and incomplete frames at EOF close the client
  connection. DNS error responses (e.g. SERVFAIL on upstream errors) do not
  automatically close an otherwise healthy TCP session.

## Configuration

```sh
./dnsp-modern -l 127.0.0.1 -p 5300 -m 9153 \
  --tcp-idle-ms 15000 \
  -s https://cloudflare-dns.com/dns-query
```

Both TCP settings accept **100–600000 milliseconds** and default to **15000**.

- `--tcp-idle-ms` limits the wait for the next query after accepting the
  connection or writing a response. libcurl's 3-second upstream timeout applies
  while a complete query is in flight.
- `--tcp-io-ms` sets the maximum time to assemble a DNS frame from its first
  byte and, independently, to send a queued response. Partial reads and writes
  do not extend these deadlines.

An expired connection may be closed without notice. Clients must be able to
reconnect.

The current implementation is intended for trusted/local networks. It is not
hardened for use as a public DNS resolver: no per-client request rate limits,
no DNSSEC validation, and no fully parallel TCP query dispatch. The existing
limits of 128 TCP clients and 128 active upstream queries remain in effect.

## Metrics

With `-m 9153`, inspect `http://127.0.0.1:9153/metrics`:

| Metric | Meaning |
| --- | --- |
| `dnsp_tcp_connections_accepted_total` | TCP client connections accepted |
| `dnsp_tcp_connections_closed_total` | TCP client connections closed |
| `dnsp_tcp_keepalive_queries_total` | Queries after the first on a reused TCP client connection |
| `dnsp_tcp_pipeline_buffered_total` | Complete successor frames buffered while prior work is outstanding |
| `dnsp_tcp_half_closes_total` | Client write-side EOFs observed |
| `dnsp_tcp_idle_timeouts_total` | Client connections closed by the idle timer |
| `dnsp_tcp_io_timeouts_total` | Client connections closed by a frame assembly or response write deadline |
| `dnsp_tcp_cancelled_upstream_total` | In-flight upstream queries cancelled when their TCP client is closed |
| `dnsp_tcp_clients` | Currently open TCP client connections (existing gauge) |
| `dnsp_queries_inflight` | Currently active upstream requests (existing gauge) |

All counters are process-local and reset when the process restarts. An HTTP/2
upstream connection-reuse counter is **not** evidence of TCP client reuse;
measure the two concepts separately.

## Local regression tests

```sh
make -f modern.mk modern-check

# Optional sanitizer run:
make -B -f modern.mk dnsp-modern \
  CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'
make -f modern.mk modern-check
```

The integration suite covers sequential TCP requests, pipelined/coalesced
requests, response ordering, client write-half-close, fragmented framing,
idle expiry, invalid idle settings, abortive disconnect cancellation, and
concurrent persistent sessions, alongside the existing UDP/EDNS/DoH tests.
