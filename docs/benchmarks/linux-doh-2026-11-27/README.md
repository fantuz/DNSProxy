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

## Warm-cache comparison

A second session rotated all three forwarders through uncached and fully cached
workloads on the same Linux host. All 381,934 measured misses reached the HTTP/2
fixture. The proxies returned 11,461,805 validated cache hits with zero upstream
requests in the timed hit windows. Each process primed 16 positive A records
with a 60 s TTL before its warm measurements. Query IDs kept changing.

| Concurrent UDP clients | DNSProxy hit QPS | AdGuard hit QPS | dnscrypt-proxy hit QPS |
| ---: | ---: | ---: | ---: |
| 1 | 26,396 | 15,202 | 15,695 |
| 8 | 105,979 | 41,664 | 55,707 |
| 32 | 123,410 | 41,233 | 66,433 |

At 32 clients DNSProxy’s warm p99 was 0.68 ms. AdGuard measured 2.39 ms and
dnscrypt-proxy 1.24 ms. These short runs on a shared virtual host use a small
hot set. Real cache hit rates, TTL expiry, available CPU, working-set size and
cache collisions affect production results. The uncached controls in this same
session measured 2,731, 3,013 and 2,791 QPS respectively at 32 clients.
[Full paired workload table](cache/summary.md) · [108 measurement windows](cache/measurements.csv) ·
[Environment](cache/environment.json)

## Linux system resolver and direct upstream

A separate Ubuntu 24.04.5 run compared five paths on one four-vCPU AMD EPYC
runner. A UDP client queried each local forwarder directly. The three DoH
forwarders used HTTP/2 with validated TLS. Ubuntu’s `systemd-resolved` 255
used a plain UDP upstream, and the direct row sent the same questions straight
to that upstream. Both fixtures served the same A answer after a 1 ms delay.
All traffic stayed on loopback in an isolated network namespace.

| Resolver or path | Miss QPS, 1 client | Miss QPS, 8 | Miss QPS, 32 | Hit QPS, 1 client | Hit QPS, 8 | Hit QPS, 32 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| DNSProxy | 586 | 1,918 | 2,681 | 25,571 | 101,413 | 107,748 |
| AdGuard dnsproxy | 562 | 2,194 | 2,772 | 11,564 | 36,239 | 22,343 |
| dnscrypt-proxy | 550 | 2,055 | 2,424 | 12,718 | 41,382 | 41,896 |
| systemd-resolved | 776 | 4,239 | 10,439 | 13,715 | 32,588 | 31,296 |
| Direct UDP upstream | 853 | 5,692 | 19,362 | — | — | — |

All 483,156 measured misses produced exactly one upstream answer each, and all
4,357,212 measured warm answers produced zero upstream requests. Direct UDP
has no forwarding cache. At 32 clients DNSProxy’s cached p99 was 0.34 ms and
the OS stub’s was 1.81 ms. On misses their p99s were 16.19 and 4.08 ms,
respectively. These paths include different transports and fixture software.
The OS row measures UDP to the Linux stub socket. Application caches and
libc/NSS lookups are outside this measurement.

The table gives medians across three rotated repetitions of 3 s per window,
after a 0.5 s warm-up. This host and its libcurl differ from the Debian run
above. Compare rows within the same session.
[Full table with latency, CPU and RSS](system-resolver/summary.md) ·
[81 measurement windows](system-resolver/measurements.csv) · [Environment](system-resolver/environment.json) ·
[GitHub Actions run](https://github.com/fantuz/DNSProxy/actions/runs/46042370733/job/140653420291) ·
[Reproduction](../../../bench/README.md#warm-answers-and-the-operating-system-resolver)

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

Keep the cache configured as you normally use it. The miss workload disables
the answer cache to measure forwarding cost. [Metrics and observability](../../../README.md#metrics-and-observability)

## Event-loop experiment

The release scans its TCP client slots when it computes the next poll deadline
and when it expires idle clients. A candidate reused the active TCP entries
already in the poll list for those two operations. Both builds used the same
compiler flags and ran with 1 and 32 UDP clients, alternating the order over
eight paired repetitions. All 64 windows completed with verified DNS answers.

At 32 clients with warm answers, the candidate delivered less throughput in
seven of eight pairs. Its median paired change was −6.5% in queries/s, +10.5%
in CPU time per query and +17.5% in p99 latency. On misses at the same load,
the median paired throughput change was +0.4%. The release keeps its current
TCP slot handling. To repeat the test, apply the candidate patch to
`v4.11.1-modern` in a separate checkout and pass both binaries to the runner.
[Candidate patch](tcp-scan/candidate.patch) · [Per-build medians](tcp-scan/summary.md) ·
[64 measurement windows](tcp-scan/measurements.csv) · [Environment](tcp-scan/environment.json) ·
[Build comparison command](../../../bench/README.md#comparing-a-resolver-patch)

## Per-query storage experiment

A second candidate reserved the eight coalesced UDP client slots only in active
heap queries. An immediate cache hit could skip initializing those slots.
The same eight-pair experiment completed 64 windows and 7,209,210 verified
replies. With one cached client, process CPU time per query fell in all eight
pairs (median −2.5%) and throughput rose in six (median +2.0%). At 32 cached
clients throughput improved in five of eight pairs (median +1.3%). With one
uncached client the median paired p99 increased 13.7%. The production resolver
keeps its current allocation. A longer run on dedicated hardware would help
establish whether the single-client CPU saving holds without a latency cost.
[Candidate patch](query-storage/candidate.patch) · [Per-build medians](query-storage/summary.md) ·
[64 measurement windows](query-storage/measurements.csv) · [Environment](query-storage/environment.json)

## Uncached workload

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
misses. Internet RTT and loss, mixed hit rates, persistent DNS-over-TCP clients,
HTTP/3, larger responses and multicore scaling need separate measurements.
An earlier comparison includes persistent TCP, HTTP/3 and larger responses
for older revisions. [November 12 baseline](../linux-c-rust-go-2026-11-12/README.md)

## Reproduce

Build with `make -f modern.mk dnsp-modern` (the recorded daemon uses the default
`-O2 -g` flags). Follow the comparison instructions to fetch checksum-pinned
peer releases and produce a fresh result directory. The timed traffic uses
loopback only. [Commands and prerequisites](../../../bench/README.md#compare-local-doh-forwarders)
