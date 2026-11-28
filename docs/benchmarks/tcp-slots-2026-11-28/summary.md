# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| miss | 1 | DNSProxy | 583 | 566–621 | 1.65 | 1.95 | 2.67 | 104 | 8.5 |
| miss | 1 | DNSProxy candidate | 586 | 551–620 | 1.65 | 1.97 | 2.78 | 98 | 8.5 |
| miss | 32 | DNSProxy | 3,407 | 2,937–3,778 | 9.17 | 11.20 | 15.39 | 104 | 10.8 |
| miss | 32 | DNSProxy candidate | 3,453 | 3,382–3,778 | 8.98 | 11.08 | 15.91 | 102 | 10.8 |
| hit | 1 | DNSProxy | 33,718 | 24,423–34,918 | 0.02 | 0.04 | 0.09 | 10 | 8.5 |
| hit | 1 | DNSProxy candidate | 33,419 | 31,279–35,897 | 0.02 | 0.04 | 0.09 | 10 | 8.5 |
| hit | 32 | DNSProxy | 149,682 | 127,431–158,182 | 0.19 | 0.31 | 0.51 | 3 | 8.5 |
| hit | 32 | DNSProxy candidate | 146,730 | 142,613–158,435 | 0.20 | 0.31 | 0.48 | 3 | 8.5 |

## Paired CPU comparison

The candidate bounds TCP polling, deadline checks and expiry scans at the
highest occupied TCP slot. An empty TCP table costs zero slot inspections
for each of those scans. Holes below an active client keep their slot numbers.

Both binaries used the same GCC flags (`-O2 -g`) and libcurl 8.14.1. The
Linux runner rotated build order over eight repetitions with one dedicated
logical CPU for the resolver. All 11,827,727 measured replies validated.
The table gives the median of the eight within-pair percentage changes.
A negative CPU or latency change means less CPU time or lower latency.

| Workload | UDP clients | CPU time per query | Throughput | p99 latency |
| --- | ---: | ---: | ---: | ---: |
| Warm cache | 1 | −4.0% | −0.4% | −3.2% |
| Warm cache | 32 | −4.3% | −0.3% | −4.8% |
| Uncached HTTP/2 | 1 | −4.2% | −0.2% | −6.0% |
| Uncached HTTP/2 | 32 | −3.6% | +1.7% | +7.7% |

The 32-client warm case used less CPU in all eight pairs. The uncached
32-client case had higher p99 latency in five pairs. These shared-host
measurements do not establish a latency improvement under upstream load.
Native Windows runs are recorded separately in the PR’s Actions artifacts.

[Raw windows](measurements.csv) · [Build and host details](environment.json) ·
[Reproduction command](../../../bench/README.md#comparing-a-resolver-patch)
