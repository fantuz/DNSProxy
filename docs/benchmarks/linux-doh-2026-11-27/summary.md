# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | DNSProxy | 520 | 512–554 | 1.75 | 2.39 | 3.70 | 154 | 8.5 |
| 1 | AdGuard | 480 | 451–520 | 1.91 | 2.94 | 4.47 | 272 | 17.6 |
| 1 | dnscrypt-proxy | 494 | 484–517 | 1.90 | 2.56 | 3.83 | 243 | 17.5 |
| 8 | DNSProxy | 1,981 | 1,767–2,105 | 3.76 | 5.28 | 7.06 | 99 | 9.0 |
| 8 | AdGuard | 2,141 | 1,935–2,242 | 3.54 | 5.09 | 7.59 | 134 | 18.2 |
| 8 | dnscrypt-proxy | 2,026 | 1,896–2,136 | 3.82 | 5.18 | 7.37 | 121 | 17.9 |
| 32 | DNSProxy | 2,752 | 2,334–3,037 | 10.97 | 15.18 | 22.68 | 133 | 10.9 |
| 32 | AdGuard | 3,049 | 2,801–3,248 | 10.09 | 13.52 | 18.99 | 118 | 18.7 |
| 32 | dnscrypt-proxy | 2,772 | 2,550–2,856 | 10.83 | 14.80 | 24.50 | 109 | 18.0 |
