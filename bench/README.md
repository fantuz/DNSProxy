# DNSProxy Modern — repeatable DoH/HTTP2 performance measurements

This is a **separate, opt-in** benchmark for `dnsp-modern`. It does not change
or run the legacy DNSProxy. Default workloads use **loopback only**; no public
resolver receives benchmark traffic. Local TLS/ALPN negotiates actual HTTP/2
or HTTP/1.1, and libcurl's certificate and hostname verification remain active.

## Install / build (Debian or Ubuntu)

```bash
sudo apt install build-essential pkg-config libcurl4-openssl-dev python3 python3-venv openssl
python3 -m venv .bench-venv
.bench-venv/bin/python -m pip install 'hypercorn==0.18.0' 'h2==4.3.0'
make -f modern.mk dnsp-modern
make -f modern.mk modern-check    # existing DNS correctness tests
.bench-venv/bin/python -m unittest discover -s tests -p test_benchmark.py -v
```

The two optional Python dependencies are used only by the synthetic server.
`dnsp-modern` and its Debian package do **not** depend on Python, Hypercorn or h2.

## Baseline: HTTP/2 vs HTTP/1.1 under identical conditions

```bash
.bench-venv/bin/python bench/bench_modern.py \
  --protocol both --concurrency 1,8,32,64 \
  --warmup 2 --duration 15 --upstream-delay-ms 5 \
  --max-host-connections 1 --assert-h2-multiplex \
  --output dist/bench-modern.json
```

The script prints per-scenario summaries and writes `dist/bench-modern.json`
and `dist/bench-modern.csv`. Scenario durations are separate; both protocols
use the same artificially delayed upstream and **one allowed upstream TCP
connection**, highlighting the multiplexing difference. This is a *closed-loop*
load: each UDP client submits the next query only after receiving a reply or
timing out. To explore connection parallelism, repeat with
`--max-host-connections 8` (the default for the proxy outside benchmarks).

For larger DNS payloads, use `--answers 240` (about 3.9 KB/reply). The synthetic
client advertises EDNS UDP size 4096. The reported `dns_response_mib_s` counts
DNS response payload bytes received over UDP; it is **not** HTTP/2 framing or
wire-level network throughput. The mock does no recursion or caching.

## Interpreting results

* `qps` = successfully answered queries divided by elapsed wall-clock time.
  Failed responses, timeouts, and upstream error counters are kept separately.
* `p50_ms`, `p95_ms`, `p99_ms` = end-to-end UDP request/response latency,
  measured using `perf_counter_ns()`; failures are not included in percentiles.
* `proxy_cpu_percent_of_one_core` = delta process user+system CPU time divided
  by elapsed wall time × 100. `200%` means two CPU cores worth of CPU time.
* `proxy_rss_*` = Linux `/proc/PID` resident bytes; `proxy_rss_peak_bytes` is
  the **process lifetime** high-water mark, not a window-specific maximum.
* `curl_metric_delta` = before/after differences from `127.0.0.1:<port>/metrics`,
  including new/reused upstream connections, response versions, successes,
  failures, timeouts and upstream cumulative request time.
* `upstream_phases` reports a sample count and mean in milliseconds for libcurl
  queue wait, TCP-to-TLS handshake time on new connections, and the time from
  transfer-ready to first byte. First-byte time includes sending the query,
  network transit and the upstream's response preparation. Queue timing
  requires libcurl 8.6 or newer. A phase with zero samples has a `null` mean.
  These observations have different sample sets. Use `p99_ms` for end-to-end
  tail latency.
* `upstream_observed.upstream_connections_used` = distinct TCP peer address/port
  tuples observed by the synthetic ASGI upstream **within this scenario**.
  For HTTP/2, one tuple can carry many simultaneous streams.
* `upstream_observed.upstream_max_simultaneous_per_connection` is the direct
  evidence for multiplexing: **>1** on HTTP/2; **1** on HTTP/1.1.
  `--assert-h2-multiplex` fails if stream overlap is not observed at ≥8 clients.

The synthetic HTTP/2 upstream uses Hypercorn/h2; the HTTP/1.1 control uses a
minimal TLS `http.server` with TCP_NODELAY. Both share the same DNS reply
builder and configurable service delay, but they are **not the same HTTP server
implementation**; do not attribute every throughput difference solely to ALPN.
The client uses a single nonblocking UDP selector loop, not one OS thread per
client. The synthetic upstream runs in Python **on the same machine** as the
load generator, so Python scheduling, TLS implementations and host CPU load can cap
throughput or increase p99. No hard-coded QPS/latency threshold is asserted in
CI. Compare *differences under matched conditions*, repeat runs, and benchmark
on the real deployment hardware before inferring production capacity. The
HTTP/2 server's keepalive request ceiling is raised from Hypercorn's default
of 1000 to avoid spurious HTTP/2 GOAWAY/framing errors during prolonged tests.

### Constrained streams and idle reconnects

```bash
.bench-venv/bin/python bench/bench_modern.py \
  --protocol h2 --concurrency 16,64 --h2-max-streams 8 \
  --h2-idle-timeout 0.5 --max-host-connections 2 --duration 5 \
  --output dist/bench-h2-limits.json
```

Repeat with caps `1`, `2`, and `8` to see how queueing and p99 change when the
peer advertises a smaller stream limit. With `--h2-idle-timeout`, the harness
waits for the mock's idle timeout after warmup and records a separate one-query
`h2_idle_probe` with its latency, connection count and timing phases.
Use `--h2-max-requests N` in a separate run to force connection retirement
with GOAWAY. Check successes and failures as well as new connections because
the mock can interrupt a query at the retirement boundary.

### Upstream packet loss and delay on Linux

Install `iproute2` and use a host with the kernel `netem` queue discipline.
The wrapper creates a temporary network namespace and shapes only IPv4 TCP and
UDP traffic to or from the mock DoH port. The DNS and metrics links stay on
unshaped loopback. The first two arguments are one-way delay and packet loss.

```bash
sudo sh bench/netem.sh 10ms 0.5% .bench-venv/bin/python \
  --protocol h2 --concurrency 16,64 --h2-max-streams 8 \
  --max-host-connections 8 --duration 5 --output dist/bench-h2-loss.json
```

Compare against the same command with `0ms 0%`. The wrapper prints queue
statistics so the run records whether packets were dropped. The namespace and
its traffic rules disappear when the benchmark exits.

### HTTP/2 versus HTTP/3

Use a binary linked to an HTTP/3-capable libcurl and install `aioquic` into the
benchmark environment. The H2 and H3 scenarios use the same DNS fixture data,
upstream service delay, and client concurrency. The H3 scenario uses aioquic
for QUIC and offers the same local HTTP/2 server as TCP fallback.

```sh
.bench-venv/bin/python -m pip install 'aioquic==1.3.0'
sudo sh bench/netem.sh 10ms 0.5% .bench-venv/bin/python \
  --protocol h2-h3 --concurrency 8,32,64 --duration 5 \
  --output dist/bench-h2-h3-loss.json
```

Run the same workload without `netem` for a baseline. Compare p99 alongside
failure counts, timeouts, and CPU. Check the negotiated versions in
`curl_metric_delta` and `upstream_observed.upstream_http_versions` before
comparing protocols. HTTP/3 preference can yield TCP fallback on a slow or
lossy link. Use `--assert-h3-multiplex` when a run must negotiate HTTP/3 and
show concurrent streams at eight or more clients. The default `--protocol both`
still compares HTTP/2 with HTTP/1.1.

### Longer stability check

Run 30–60 seconds per level and compare success rate, p99, failure counters,
CPU and RSS. `--duration 60 --concurrency 8,32,64` executes three successive
60-second scenarios, **not** a single 180-second concurrency level. Keep the
output and check RSS high-water marks for upward trends. For leak hunting use
external profiling/sanitizers, since this is only a black-box measurement.

### Real HTTPS DoH endpoint (optional)

```bash
.bench-venv/bin/python bench/bench_modern.py \
  --protocol h2 --upstream-url https://YOUR-DNS-OVER-HTTPS-SERVER/dns-query \
  --concurrency 1,4 --warmup 1 --duration 3 \
  --output dist/live-brief.json
```

Only benchmark a server you own or are authorized to load-test. This mode
still verifies HTTPS, but **cannot measure simultaneous HTTP/2 streams on the
remote server**: `upstream_observed` is `null`; use curl HTTP version and reuse
metrics as indirect clues, not proof. Network/WAN latency and DNS provider
rate limiting affect results, and aggressive load against public resolvers is
not appropriate. The TLS mock is the preferred reproducible baseline.

## Automated smoke tests

```bash
make -f modern.mk benchmark-smoke   # optional hypercorn/h2 dependencies
```

A separate `.github/workflows/dnsp-modern-benchmark.yml` runs a short
loopback smoke on pull requests touching the benchmark and on manual dispatch.
The existing `dnsp-modern.yml` release/DEB workflow is untouched.

The same workflow runs HTTP/3 integration tests on Debian 13. With a
QUIC-capable libcurl and the benchmark environment installed, run them locally.

```bash
.bench-venv/bin/python -m pip install 'aioquic==1.3.0'
.bench-venv/bin/python tests/test_http3.py
```

The test upstream uses real QUIC and records concurrent HTTP/3 streams. The
tests also exercise TCP fallback with UDP blackholed, certificate validation,
and respect for a configured HTTPS proxy.

## Security and design notes

The benchmark uses a short-lived self-signed localhost certificate generated
with OpenSSL. The proxy `--ca-file` option makes this certificate trusted **for
that upstream only**, without turning off peer or hostname verification.
`--max-host-connections` is a bounded 1..16 libcurl setting; the default
remains 8 in `dnsp-modern` and in packaged services. The CLI options preserve
backward compatibility. The benchmark uses ephemeral loopback ports and
terminates its child proxy and mock server after completion; Ctrl-C should
also stop the child when the harness exits.
