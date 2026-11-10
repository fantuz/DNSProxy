# Upstream failover

Configure a backup when both resolvers can serve the same DNS view and
enforce the same filtering and DNSSEC policies. A query that fails over is
disclosed to both resolvers. For example, if you operate these two endpoints:

```sh
./dnsp-modern -s https://primary.example.net/dns-query \
  --backup-upstream https://backup.example.net/dns-query -m 9153
```

The endpoints must have different hostnames or ports. Each hostname retains
its own TLS identity. If DNSProxy is the system resolver, pin the addresses
for both endpoints with `--bootstrap-address` and `--backup-bootstrap-address`.
Each pin bypasses ambient proxy settings for its own endpoint. The same
`--ca-file` and `--upstream-http` settings apply to both endpoints.

## Query handling

An eligible request starts at the primary. The proxy gives that attempt half
of the available `--doh-timeout-ms` budget. If it encounters a retryable
transport failure, the backup gets the remaining time. A quick primary failure
leaves more time for the backup. If the primary succeeds, the backup receives
no query. If the backup fails, the client receives `SERVFAIL`.

Retryable failures include inability to resolve or connect to the primary,
timeouts, connection resets, incomplete transfers, and HTTP/2 stream or HTTP/3
transport errors. A completed DNS reply ends the query, including `NXDOMAIN`,
`REFUSED`, or DNS `SERVFAIL`. TLS certificate failures, HTTP status errors, and
invalid DoH replies also end the query and are logged.

Failover applies to a single Internet-class question with either no additional
records or an option-free EDNS(0) OPT record. Queries carrying DNS Cookies or
other EDNS options, signed messages, and key negotiation stay on the primary.
Backup replies bypass the answer cache, so a backup result cannot replace a
primary answer after recovery.

## Verify the behavior

```sh
curl -fsS http://127.0.0.1:9153/metrics |
  grep '^dnsp_upstream_endpoint_'
```

`dnsp_upstream_endpoint_requests_total`, `dnsp_upstream_endpoint_replies_total`,
and `dnsp_upstream_endpoint_failures_total` use the `role="primary"` and
`role="backup"` labels. A valid DNS reply counts in the endpoint's reply total
regardless of its DNS result code. These metrics count attempts. Use
`dnsp_queries_satisfied_total` for complete answers sent to clients.
