# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| miss | 1 | DNSProxy | 512 | 425–545 | 1.83 | 2.60 | 3.69 | 156 | 8.5 |
| miss | 1 | DNSProxy candidate | 510 | 476–525 | 1.82 | 2.62 | 4.29 | 169 | 8.5 |
| miss | 32 | DNSProxy | 2,449 | 1,750–3,018 | 11.34 | 19.87 | 31.48 | 136 | 10.9 |
| miss | 32 | DNSProxy candidate | 2,666 | 2,285–2,859 | 11.33 | 16.04 | 23.95 | 132 | 10.9 |
| hit | 1 | DNSProxy | 25,405 | 18,027–26,465 | 0.03 | 0.07 | 0.17 | 14 | 8.5 |
| hit | 1 | DNSProxy candidate | 25,915 | 23,917–27,308 | 0.03 | 0.07 | 0.16 | 13 | 8.5 |
| hit | 32 | DNSProxy | 126,298 | 101,404–132,905 | 0.22 | 0.41 | 0.67 | 4 | 8.5 |
| hit | 32 | DNSProxy candidate | 120,448 | 109,364–136,866 | 0.22 | 0.43 | 0.89 | 4 | 8.5 |
