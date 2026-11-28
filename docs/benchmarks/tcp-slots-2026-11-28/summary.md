# TCP slot scan experiment

The production resolver keeps its existing TCP loop. The patch saved a small
amount of CPU on Linux, but consistently reduced warm-cache throughput on
Windows AMD64 at 32 clients. The first table reports the initial Linux run.

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

The 32-client warm case used less CPU in all eight Linux pairs. For the
32-client uncached case, the first run had higher p99 latency in five
pairs. Eight additional pairs with 10-second windows validated another
517,122 replies. Their median paired CPU cost changed by −2.6%, throughput
by +1.7% and p99 by −1.3%.

## Native Windows results

Both executables on each architecture used the same toolchain, bundled libcurl
8.23.0 and default Windows process scheduling. Four alternating pairs per
workload validated 1,617,494 replies on AMD64 and 478,500 on ARM64. Each
measurement window was two seconds. The table uses within-pair changes.
The ARM64 resolver ran natively. Its Python load driver ran under x64 emulation.

| Architecture | Workload | UDP clients | CPU time per query | Throughput | p99 latency |
| --- | --- | ---: | ---: | ---: | ---: |
| AMD64 | Warm cache | 1 | −6.1% | +0.9% | +3.8% |
| AMD64 | Warm cache | 32 | +2.0% | −9.5% | +15.4% |
| AMD64 | Uncached HTTP/2 | 1 | Below timer resolution | <0.1% | <0.1% |
| AMD64 | Uncached HTTP/2 | 32 | +14.7% | +1.6% | +0.9% |
| ARM64 | Warm cache | 1 | −2.4% | −0.8% | +8.7% |
| ARM64 | Warm cache | 32 | −0.1% | −0.6% | −0.9% |
| ARM64 | Uncached HTTP/2 | 1 | Coarse timer | −0.3% | <0.1% |
| ARM64 | Uncached HTTP/2 | 32 | +9.6% | +1.7% | −0.2% |

On AMD64 with 32 warm-cache clients the candidate was slower and had higher
p99 in every pair. Median throughput fell from 84,885 to 76,824 queries/s.
CPU estimates for lightly loaded, single-client misses have too few Windows
process timer ticks for a reliable percentage. The native tests use isolated
loopback fixtures and do not predict CPU usage on a particular desktop.

| Raw measurements | Build and host details |
| --- | --- |
| [Initial Linux run](measurements.csv) | [Linux environment](environment.json) |
| [Linux repeat](linux-repeat/measurements.csv) | [Repeat environment](linux-repeat/environment.json) |
| [Windows AMD64](windows-amd64/measurements.csv) | [AMD64 environment](windows-amd64/environment.json) |
| [Windows ARM64](windows-arm64/measurements.csv) | [ARM64 environment](windows-arm64/environment.json) |

[Candidate patch](candidate.patch) · [Reproduction command](../../../bench/README.md#comparing-a-resolver-patch) ·
[Native workflow run](https://github.com/fantuz/DNSProxy/actions/runs/46095651536)
