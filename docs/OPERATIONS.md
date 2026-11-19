# Verify a `dnsp-modern` deployment

## Check the local listener

The packaged Linux systemd service listens on `127.0.0.1:5300` and serves
Prometheus metrics on `127.0.0.1:9153`. For a manual run, enable the metrics
listener with `-m 9153`.

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

Run `dnsp-modern --version` on the executable you deploy. It shows the
libcurl headers used to build it, the library version loaded at runtime,
the TLS backend, and HTTP/2 and HTTP/3 capabilities. Compare the two libcurl
versions if a local installation under `/usr/local` may be taking precedence.

Run a query and compare the HTTP version counters before and after it.

```sh
curl -fsS http://127.0.0.1:9153/metrics |
  grep '^dnsp_upstream_http_responses_total'
```

| Observation | What to check |
| --- | --- |
| `http_preference=h3` in a startup or status log | The process requested HTTP/3. Look for an increase in the response counter with `version="3"` to confirm negotiation. |
| HTTP/2 responses with `prefer-h3` | The TCP fallback may have won or an existing HTTP/2 connection may be reused. Check UDP reachability to the upstream HTTPS port and whether libcurl is using a forward proxy. |
| Startup rejects `prefer-h3` | Check for `prefer_h3=yes` in `--version` and read the startup error. |
| Queries time out with many active transfers | Compare the upstream timeout and overload counters. On libcurl 8.6 or newer, the queue phase shows how much time transfers spent waiting inside libcurl. |
| UDP responses show `TC` and TCP replies work | The client advertised a small EDNS buffer or the proxy applied its UDP reply cap. Check the client buffer and `--udp-reply-max`. |

For the packaged Linux service, inspect the launch arguments and request a
status snapshot without restarting the service.

```sh
systemctl cat dnsp-modern
sudo systemctl kill --kill-who=main -s SIGUSR1 dnsp-modern
journalctl -u dnsp-modern -n 20 --no-pager
```

## Inspect latency and parallel requests

`dnsp_build_info` reports the running daemon version, numeric runtime libcurl
version and built HTTP/2/3 capabilities. Query names, endpoint URLs and client
addresses are never metric labels.

`dnsp_client_duration_seconds` is a histogram labelled by UDP/TCP transport.
Timing starts when a complete request is received (a full frame for TCP) and
ends when the full reply is written. Cache hits, policy blocks, DNS errors and
truncations count; abandoned requests and failed writes do not. Coalesced UDP
clients have individual arrival times. TCP timings include pipeline queueing.

`dnsp_upstream_duration_seconds` measures each completed DoH attempt, including
failures. Cancelled losing races and client-disconnect cancellations are
excluded. Its existing `_sum` and `_count` remain available. Both histograms
use fixed upper bounds in seconds: .001, .0025, .005, .01, .025, .05, .1, .25,
.5, 1, 2.5, 5, 10, 60 and +Inf. Memory use and label cardinality are bounded.
For example, in Prometheus:

```promql
histogram_quantile(0.95, sum by (le) (rate(dnsp_client_duration_seconds_bucket[5m])))
```

The [desktop GUI](DESKTOP-GUI.md) estimates p50/p95/p99 from histogram deltas over
at most 60 sampling intervals (roughly 30 seconds at the default refresh). Bucket
interpolation makes these estimates; they are not per-query logs. The window
resets on process/instance changes, counter resets and collection gaps.

For `--upstream-hedge-ms`, inspect launches, suppressed launches, cancellations,
role-labelled wins and `dnsp_upstream_hedges_inflight`. Compare percentiles and
upstream request volume with the default sequential mode before enabling it
permanently. See [the upstream policy](UPSTREAM_FAILOVER.md).

## Inspect live capacity

| Gauge | Meaning |
| --- | --- |
| `dnsp_uptime_seconds` | Monotonic resolver uptime since the listeners were initialized |
| `dnsp_cache_entries` | Occupied cache slots whose expiry is later than the scrape time |
| `dnsp_cache_capacity` | Configured cache slot count; zero means disabled |
| `dnsp_queries_inflight` | Active logical queries, excluding parallel backup attempts |
| `dnsp_upstream_attempts_inflight` | All active attempts, including parallel backups |
| `dnsp_queries_capacity` | Maximum shared slots for logical queries and parallel backups |
| `dnsp_tcp_clients` / `dnsp_tcp_clients_capacity` | Current and maximum accepted TCP client connections |

Compare active attempts with the shared slot capacity when diagnosing overload;
parallel backups use slots independently of their primary attempt. Cache
occupancy is a read-only view: scraping does not refresh TTLs or remove expired
data. The [desktop monitoring tab](DESKTOP-GUI.md#interval-monitoring-and-diagnostics)
combines these gauges with interval outcomes, policy freshness and TCP errors.

## Choose a test suite

| Test | Coverage |
| --- | --- |
| `python3 tests/test_hedging.py` | Parallel wins, deadlines, capacity, coalescing, TLS rejection, policy reload and TCP cancellation |
| `make modern-check` | DNS wire validation, EDNS, UDP/TCP framing and deadlines, caching, and local DoH error handling. The upstream fixtures exercise HTTP/1.1 and include HTTPS certificate checks. |
| `test_benchmark.py` | TLS HTTP/1.1 and HTTP/2, simultaneous streams, idle reconnect, and recovery after GOAWAY. The benchmark workflow also runs a TCP loss scenario on an isolated loopback link. |
| `test_http3.py` | HTTP/3 negotiation and concurrent streams, HTTP/2 fallback with the QUIC path blackholed, certificate hostname checks, and proxy routing. Requires a QUIC-capable libcurl and the optional Python test dependencies. |
| `make modern-fuzz` | Coverage-guided DNS wire, EDNS, TTL, and HTTP cache-header parsing under sanitizers. |

Use the [benchmark guide](../bench/README.md) to install the optional test
dependencies and compare latency, failures, and negotiated protocol. Loopback
results reflect the local fixture and selected libcurl build.

HTTP/3 integration scenarios use separate Python processes with `--isolated`
to avoid state leaking between native QUIC fixtures and event loops. Each
scenario retains its persistent connections and multiplexing checks. The race
scenario also verifies an eight-client burst after cancelling a losing stream.
