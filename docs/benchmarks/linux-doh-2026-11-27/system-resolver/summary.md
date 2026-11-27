# Local DoH forwarder comparison

Medians across repetitions. The QPS range is the smallest and largest run.
Latency columns are medians of the per-run percentiles. CPU time and RSS
cover the proxy process only. RSS is sampled at the end of each window.

| Workload | Clients | Forwarder | QPS | QPS range | p50 ms | p95 ms | p99 ms | CPU µs/query | RSS MiB |
| --- | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| miss | 1 | systemd-resolved | 776 | 766–777 | 1.28 | 1.32 | 1.33 | 120 | 12.0 |
| miss | 1 | Direct UDP | 853 | 849–858 | 1.16 | 1.19 | 1.21 | — | — |
| miss | 1 | DNSProxy | 586 | 581–587 | 1.70 | 1.72 | 1.76 | 159 | 11.7 |
| miss | 1 | AdGuard | 562 | 545–565 | 1.75 | 1.88 | 1.92 | 237 | 17.6 |
| miss | 1 | dnscrypt-proxy | 550 | 528–553 | 1.80 | 1.87 | 1.94 | 236 | 17.5 |
| miss | 8 | systemd-resolved | 4,239 | 4,156–4,345 | 1.94 | 2.08 | 2.18 | 87 | 12.0 |
| miss | 8 | Direct UDP | 5,692 | 5,623–5,715 | 1.40 | 1.45 | 1.51 | — | — |
| miss | 8 | DNSProxy | 1,918 | 1,640–1,960 | 4.09 | 4.44 | 4.53 | 134 | 11.9 |
| miss | 8 | AdGuard | 2,194 | 1,713–2,274 | 3.52 | 4.32 | 4.54 | 190 | 18.0 |
| miss | 8 | dnscrypt-proxy | 2,055 | 1,567–2,057 | 3.88 | 4.41 | 4.88 | 188 | 17.7 |
| miss | 32 | systemd-resolved | 10,439 | 9,230–10,667 | 3.08 | 3.95 | 4.08 | 93 | 12.4 |
| miss | 32 | Direct UDP | 19,362 | 12,450–19,814 | 1.65 | 1.71 | 1.77 | — | — |
| miss | 32 | DNSProxy | 2,681 | 2,139–2,714 | 11.31 | 13.04 | 16.19 | 162 | 12.4 |
| miss | 32 | AdGuard | 2,772 | 1,979–2,807 | 11.27 | 12.61 | 15.12 | 156 | 18.6 |
| miss | 32 | dnscrypt-proxy | 2,424 | 1,886–2,437 | 13.45 | 13.94 | 14.89 | 156 | 18.1 |
| hit | 1 | systemd-resolved | 13,715 | 13,637–14,449 | 0.06 | 0.09 | 0.10 | 47 | 12.0 |
| hit | 1 | DNSProxy | 25,571 | 24,859–25,915 | 0.03 | 0.05 | 0.05 | 16 | 11.8 |
| hit | 1 | AdGuard | 11,564 | 10,825–12,614 | 0.07 | 0.11 | 0.14 | 65 | 17.9 |
| hit | 1 | dnscrypt-proxy | 12,718 | 12,133–13,447 | 0.07 | 0.10 | 0.11 | 56 | 17.7 |
| hit | 8 | systemd-resolved | 32,588 | 30,544–35,355 | 0.22 | 0.48 | 0.49 | 31 | 12.0 |
| hit | 8 | DNSProxy | 101,413 | 99,231–101,665 | 0.07 | 0.09 | 0.14 | 8 | 11.8 |
| hit | 8 | AdGuard | 36,239 | 28,193–39,284 | 0.18 | 0.42 | 0.57 | 28 | 18.1 |
| hit | 8 | dnscrypt-proxy | 41,382 | 33,449–53,737 | 0.15 | 0.31 | 0.48 | 24 | 17.7 |
| hit | 32 | systemd-resolved | 31,296 | 29,581–36,987 | 0.86 | 1.79 | 1.81 | 32 | 12.0 |
| hit | 32 | DNSProxy | 107,748 | 107,526–108,123 | 0.29 | 0.31 | 0.34 | 8 | 11.8 |
| hit | 32 | AdGuard | 22,343 | 20,734–37,990 | 1.65 | 2.18 | 2.52 | 45 | 18.3 |
| hit | 32 | dnscrypt-proxy | 41,896 | 34,259–49,231 | 0.80 | 1.10 | 1.61 | 24 | 17.8 |
