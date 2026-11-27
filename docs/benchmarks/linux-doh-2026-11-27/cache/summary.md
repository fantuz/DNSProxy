# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| miss | 1 | DNSProxy | 514 | 359–540 | 1.80 | 2.66 | 4.18 | 160 | 8.5 |
| miss | 1 | AdGuard | 504 | 473–514 | 1.85 | 2.51 | 4.00 | 219 | 17.6 |
| miss | 1 | dnscrypt-proxy | 497 | 430–502 | 1.91 | 2.54 | 3.83 | 226 | 17.6 |
| miss | 8 | DNSProxy | 1,935 | 1,845–2,037 | 3.85 | 5.49 | 8.10 | 97 | 9.0 |
| miss | 8 | AdGuard | 2,085 | 1,942–2,145 | 3.62 | 5.93 | 8.36 | 124 | 18.3 |
| miss | 8 | dnscrypt-proxy | 1,955 | 1,862–2,015 | 3.93 | 5.65 | 8.03 | 120 | 17.9 |
| miss | 32 | DNSProxy | 2,731 | 2,447–2,775 | 11.18 | 15.10 | 22.18 | 131 | 11.0 |
| miss | 32 | AdGuard | 3,013 | 2,916–3,067 | 10.10 | 14.49 | 20.52 | 111 | 18.7 |
| miss | 32 | dnscrypt-proxy | 2,791 | 2,654–2,933 | 10.83 | 14.64 | 21.50 | 101 | 18.1 |
| hit | 1 | DNSProxy | 26,396 | 24,558–28,378 | 0.03 | 0.06 | 0.15 | 13 | 8.5 |
| hit | 1 | AdGuard | 15,202 | 11,309–16,000 | 0.04 | 0.12 | 0.27 | 42 | 18.1 |
| hit | 1 | dnscrypt-proxy | 15,695 | 15,064–16,429 | 0.04 | 0.11 | 0.25 | 38 | 18.0 |
| hit | 8 | DNSProxy | 105,979 | 98,559–108,737 | 0.06 | 0.14 | 0.27 | 4 | 8.5 |
| hit | 8 | AdGuard | 41,664 | 31,782–45,928 | 0.15 | 0.39 | 0.69 | 23 | 18.1 |
| hit | 8 | dnscrypt-proxy | 55,707 | 36,063–57,542 | 0.12 | 0.29 | 0.51 | 17 | 18.1 |
| hit | 32 | DNSProxy | 123,410 | 118,966–130,042 | 0.22 | 0.40 | 0.68 | 4 | 8.5 |
| hit | 32 | AdGuard | 41,233 | 26,686–44,323 | 0.67 | 1.62 | 2.39 | 23 | 18.3 |
| hit | 32 | dnscrypt-proxy | 66,433 | 46,716–67,714 | 0.40 | 0.86 | 1.24 | 15 | 18.0 |
