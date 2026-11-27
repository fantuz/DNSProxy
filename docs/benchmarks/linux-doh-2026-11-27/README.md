# DNSProxy, AdGuard dnsproxy and dnscrypt-proxy on Linux

This run compares the released DNSProxy 4.11.1 C forwarder with AdGuard
dnsproxy v0.86.0 and dnscrypt-proxy 2.1.21 in DoH mode on 2026-11-27.
All three forwarded uncached UDP questions to the same local HTTP/2 fixture.
[DNSProxy source](https://github.com/fantuz/DNSProxy/tree/v4.11.1-modern) ·
[AdGuard release](https://github.com/AdguardTeam/dnsproxy/releases/tag/v0.86.0) ·
[dnscrypt-proxy release](https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.21)

## Results

All 386,752 measured replies matched the expected DNS answer and the upstream
HTTP/2 count across 54 windows. Each forwarder used one upstream TLS connection
per measured window.

| Concurrent UDP clients | DNSProxy QPS | AdGuard QPS | dnscrypt-proxy QPS |
| ---: | ---: | ---: | ---: |
| 1 | 520 | 480 | 494 |
| 8 | 1,981 | 2,141 | 2,026 |
| 32 | 2,752 | 3,049 | 2,772 |

DNSProxy had the highest median throughput with one client and the lowest RSS
at all three loads. At 32 clients its median throughput was 9.8% below AdGuard
and within 1% of dnscrypt-proxy. Median p99s at that load were 22.68, 18.99
and 24.50 ms respectively. QPS ranges overlapped across all three at 32 clients.
A follow-up with fixed arrival rates and a separately hosted upstream would
help identify where queueing starts before changing the resolver.

The [full table](summary.md) includes QPS ranges, p50, p95 and p99 latency,
process CPU time per query and resident memory. The [measurements](measurements.csv)
give every repetition, the HTTP method counts and the number of TLS connections
that carried measured traffic. The [environment](environment.json) identifies
the hardware, kernel, proxy binaries, TLS library and fixture versions.

## Comparing a desktop or shared resolver

One benchmark client sends its next query only after the previous reply.
A desktop doing serial lookups fits that case. A browser loading several hostnames
or multiple applications can have queries outstanding at the same time on one PC.
For a shared resolver, compare both throughput and p95/p99 at the observed load.

If the loopback metrics endpoint is enabled on port 9090, sample it during
normal use. Compare changes in cache hits and misses over the same interval.
The in-flight gauge is an instantaneous sample and can miss short bursts.

```sh
curl -fsS http://127.0.0.1:9090/metrics |
  grep -E '^dnsp_(queries_inflight|cache_(hits|misses)_total) '
```

Keep the cache configured as you normally use it. The benchmark disabled it
to measure forwarding cost. [Metrics and observability](../../../README.md#metrics-and-observability)

## Workload

- The Linux x86-64 client kept one UDP query outstanding per socket, with 1, 8
  or 32 sockets. Each query used a distinct name under `.example.`, requested a
  single A record and advertised a 1,232-byte EDNS UDP payload. Each proxy's
  answer cache was disabled.
- The TLS upstream waited 1 ms per request and served `192.0.2.1`. Each proxy
  trusted a temporary test certificate for the loopback IP. The client checked
  transaction ID, question, response and truncation flags, RCODE, answer type,
  class and address. The fixture independently counted requests and negotiated
  HTTP versions. AdGuard used GET. DNSProxy and dnscrypt-proxy used POST.
- Each forwarder ran on one logical CPU. Both Go programs used `GOMAXPROCS=1`.
  The load generator and the fixture ran in separate processes on the remaining
  CPUs. Each repetition started fresh proxy and fixture processes and rotated
  the order of the three programs. Each client level had a 0.75 s warm-up and
  a 4 s measurement window. Outstanding queries were drained and included in
  elapsed time.
- Rates are completed queries divided by measured wall time. Each table cell
  is the median of six windows. For latency this is the median of six per-run
  percentiles. CPU is user plus system time from Linux `/proc`. RSS is a
  sample at the end of the window.

The shared virtual host, Python fixture and closed-loop client can all affect
throughput. These measurements cover warm HTTP/2 connections and small cache
misses. Internet RTT and loss, cache hits, persistent DNS-over-TCP clients,
HTTP/3, larger responses and multicore scaling need separate measurements.
An earlier comparison includes persistent TCP, HTTP/3 and larger responses
for older revisions. [November 12 baseline](../linux-c-rust-go-2026-11-12/README.md)

## Reproduce

Build with `make -f modern.mk dnsp-modern` (the recorded daemon uses the default
`-O2 -g` flags). Follow the comparison instructions to fetch checksum-pinned
peer releases and produce a fresh result directory. The timed traffic uses
loopback only. [Commands and prerequisites](../../../bench/README.md#compare-local-doh-forwarders)
