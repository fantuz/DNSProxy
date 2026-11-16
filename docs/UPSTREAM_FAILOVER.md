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

## Sequential failover (default)

An eligible request starts at the primary. The proxy gives that attempt half
of the available `--doh-timeout-ms` budget. If it encounters a retryable
transport failure, the backup gets the remaining time. A quick primary failure
leaves more time for the backup. If the primary succeeds, the backup receives
no query. If the backup fails, the client receives `SERVFAIL`.

Retryable failures include inability to resolve or connect to the primary,
timeouts, connection resets, incomplete transfers, and HTTP/2 stream or HTTP/3
transport errors. A completed DNS reply ends the query, including `NXDOMAIN`,
`REFUSED`, or DNS `SERVFAIL`. TLS certificate failures, HTTP status errors,
proxy CONNECT denials, and invalid DoH replies also end the query and are
logged.

Failover applies to a single Internet-class question with either no additional
records or an option-free EDNS(0) OPT record. Queries carrying DNS Cookies or
other EDNS options, signed messages, and key negotiation stay on the primary.
Backup replies bypass the answer cache, so a backup result cannot replace a
primary answer after recovery.

## Optional delayed parallel requests

Add `--upstream-hedge-ms 150` to the example above to start a backup when an
eligible primary request remains pending after 150 ms. The default is `0`
(disabled). A positive delay requires a backup and must be smaller than
`--doh-timeout-ms`; the accepted range is 0–60000 ms.

Both attempts use the same original deadline, enforced independently by the
event loop even when a libcurl timeout is extended. After the primary authenticates,
it keeps the remaining total budget while the backup races it. Before HTTPS
certificate verification completes, the original half-budget failover policy
remains in effect; the hedge waits for authentication. A primary certificate or
proxy rejection cannot be hidden by a faster backup. HTTP/2 and optional HTTP/3
use the same race logic and existing connection pools.

The first validated DNS reply wins, including `NXDOMAIN`, `REFUSED` or DNS
`SERVFAIL`. An invalid DNS response or transport failure does not displace the
other pending attempt. The losing transfer is removed from libcurl and its
query buffers are released. Disconnecting a TCP client cancels both attempts.
The feature uses the same replay eligibility as sequential failover, and
preserves client IDs, UDP limits, DNS/HTTP cache rules, EDNS padding and
blocklist checks. Backup replies continue to bypass the answer cache.

Parallel attempts consume the existing global limit of 128 active transfers,
with a separate ceiling of 16 extra backups. Capacity pressure suppresses a
new hedge; the primary continues. Coalesced clients still share one logical
query. No extra thread or per-query timer object is created.

This option trades additional provider traffic and disclosure for the chance
of reducing slow replies. Use primary and backup resolvers with equivalent
DNS views, DNSSEC and filtering policies. A fast primary avoids the extra
request. Measure your actual workload before choosing a delay.

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

The `dnsp_upstream_hedges_*` counters show launches, capacity/setup suppression,
cancelled losers and currently active extra attempts. Wins are counted by
`dnsp_upstream_hedge_wins_total{role="primary"|"backup"}`. A win means a validated
DNS reply won a launched race; failure-driven fallback alone is not a hedge.
`dnsp_queries_inflight` counts logical queries, rather than both race attempts.
