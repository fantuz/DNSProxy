# Verify a `dnsp-modern` deployment

## Check the local listener

The packaged service listens on `127.0.0.1:5300` and serves Prometheus metrics
on `127.0.0.1:9153`. For a manual run, enable the metrics listener with
`-m 9153`.

```sh
dig @127.0.0.1 -p 5300 example.com A
dig @127.0.0.1 -p 5300 +tcp example.com A
curl -fsS http://127.0.0.1:9153/metrics
```

The `+tcp` query checks the client-facing DNS/TCP listener. Both commands can
use the same HTTPS connection to the upstream resolver. To inspect the first
UDP response when testing a large answer, use `dig +notcp +ignore` so `dig`
displays `TC` without automatically retrying over TCP. The proxy limits each
UDP response by the client's EDNS buffer size and the server reply cap. With
no EDNS the client limit is 512 bytes.

## Confirm the upstream protocol

Run a query and compare the HTTP version counters before and after it.

```sh
curl -fsS http://127.0.0.1:9153/metrics |
  grep '^dnsp_upstream_http_responses_total'
```

| Observation | What to check |
| --- | --- |
| `http_preference=h3` in a startup or status log | The process requested HTTP/3. Look for an increase in the response counter with `version="3"` to confirm negotiation. |
| HTTP/2 responses with `prefer-h3` | The TCP fallback may have won or an existing HTTP/2 connection may be reused. Check UDP reachability to the upstream HTTPS port and whether libcurl is using a forward proxy. |
| Startup rejects `prefer-h3` | The running binary needs a linked libcurl with HTTP/3 and TCP fallback support. Check the binary's `--help` and startup error. |
| Queries time out with many active transfers | Compare the upstream timeout and overload counters. On libcurl 8.6 or newer, the queue phase shows how much time transfers spent waiting inside libcurl. |
| UDP responses show `TC` and TCP replies work | The client advertised a small EDNS buffer or the proxy applied its UDP reply cap. Check the client buffer and `--udp-reply-max`. |

For the packaged service, inspect the launch arguments and request a status
snapshot without restarting the service.

```sh
systemctl cat dnsp-modern
sudo systemctl kill --kill-who=main -s SIGUSR1 dnsp-modern
journalctl -u dnsp-modern -n 20 --no-pager
```

## Choose a test suite

| Test | Coverage |
| --- | --- |
| `make modern-check` | DNS wire validation, EDNS, UDP/TCP framing and deadlines, caching, and local DoH error handling. The upstream fixtures exercise HTTP/1.1 and include HTTPS certificate checks. |
| `test_benchmark.py` | TLS HTTP/1.1 and HTTP/2, simultaneous streams, idle reconnect, and recovery after GOAWAY. The benchmark workflow also runs a TCP loss scenario on an isolated loopback link. |
| `test_http3.py` | HTTP/3 negotiation and concurrent streams, HTTP/2 fallback with the QUIC path blackholed, certificate hostname checks, and proxy routing. Requires a QUIC-capable libcurl and the optional Python test dependencies. |
| `make modern-fuzz` | Coverage-guided DNS wire, EDNS, TTL, and HTTP cache-header parsing under sanitizers. |

Use the [benchmark guide](../bench/README.md) to install the optional test
dependencies and compare latency, failures, and negotiated protocol. Loopback
results reflect the local fixture and selected libcurl build.
