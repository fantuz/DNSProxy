# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| miss | 1 | DNSProxy | 511 | 470–557 | 1.81 | 2.65 | 4.05 | 170 | 8.5 |
| miss | 1 | DNSProxy candidate | 516 | 402–541 | 1.82 | 2.46 | 3.92 | 201 | 8.5 |
| miss | 32 | DNSProxy | 2,811 | 2,649–2,910 | 11.00 | 14.93 | 20.08 | 134 | 11.0 |
| miss | 32 | DNSProxy candidate | 2,820 | 2,648–2,933 | 11.06 | 14.51 | 20.23 | 141 | 11.0 |
| hit | 1 | DNSProxy | 26,087 | 17,395–27,244 | 0.03 | 0.06 | 0.15 | 14 | 8.5 |
| hit | 1 | DNSProxy candidate | 20,146 | 17,009–27,110 | 0.03 | 0.06 | 0.39 | 17 | 8.5 |
| hit | 32 | DNSProxy | 109,086 | 71,485–130,225 | 0.22 | 0.75 | 1.62 | 5 | 8.5 |
| hit | 32 | DNSProxy candidate | 94,946 | 84,636–122,454 | 0.22 | 1.05 | 2.29 | 6 | 8.5 |
