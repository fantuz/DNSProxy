# Linux C / Rust / Go application baseline

This additional comparison measures DNSProxy's C implementation and Rust
feasibility port against **AdGuard dnsproxy v0.86.0**, an external Go
application. DNSProxy does not maintain a Go port. The measurements describe
these applications and their transport engines, rather than the intrinsic
performance of C, Rust or Go.

The [complete GitHub Actions run](https://github.com/fantuz/DNSProxy/actions/runs/43254052353)
passed all five Rust jobs, including formatting, Clippy, Rust unit tests,
amd64/arm64 integration tests, the full HTTP/2 and HTTP/3 fixtures, and the
wire comparison. C revision: `343323e411488cfa3e608dfbf8496de8d91959b8`.
Rust revision: `7c844c19d4e40a306a6381dbdaa010f0053fb758`.
The Go release archive was verified against its pinned SHA-256.

## Method

- Linux amd64 GitHub runner, Debian 13 container; C and Rust use libcurl 8.14.1
  and OpenSSL 3.5.7. [Recorded environment and versions](environment.json).
- Each proxy is restricted to CPU 0; Go also uses `GOMAXPROCS=1`. The load
  generator and local TLS fixture share the host and can use its four CPUs.
- Local, certificate-verified `localhost` DoH origin, with a 1 ms synthetic
  upstream delay. C and Rust use an explicit loopback bootstrap address.
- HTTP/2 and HTTP/3 upstreams; UDP and persistent TCP downstream clients.
- Replies contain 1 or 64 synthetic A records. Each level uses 1, 8 or 32
  clients, 0.5 seconds of warmup and 2 seconds of measurement.
- Every query name within a scenario is unique, and answer caching is disabled.
  This exercises forwarding without cache hits or duplicate-query sharing.
- Three repetitions rotate application order. Each application scenario runs
  in a fresh Python worker to isolate the QUIC fixture and its event loop.
- C and Rust use RFC 8484 POST. AdGuard dnsproxy uses GET. Its DNS, HTTP and
  QUIC implementations and pooling policies differ from native libcurl.

Client successes are checked for transaction ID, question, answer count,
response code and truncation. Measured upstream completions must equal client
successes, and the observed HTTP version must match the requested protocol.
CPU time and RSS come from Linux `/proc`; peak RSS is `VmHWM` by the end of
each level. TCP connections persist within each level, and their connection
setup is outside the measurement interval.

## Results

All **216 measurements** completed: 72 configuration/application groups, each
repeated three times. The measured successes were **190,458 for C**,
**193,104 for Rust**, and **257,160 for Go**, with zero failed responses,
timeouts or truncations. Every measurement used the requested upstream HTTP
version and forwarded every successful query to the synthetic upstream.

The following subset shows medians for 32 UDP clients and one A record per
reply. The p99 column is the median of three per-run p99 values.

| Application | Upstream | QPS | p99 ms | Peak RSS, MiB |
| --- | --- | ---: | ---: | ---: |
| DNSProxy C | HTTP/2 | 2,206 | 17.410 | 16.29 |
| DNSProxy Rust | HTTP/2 | 2,014 | 18.857 | 16.71 |
| AdGuard Go | HTTP/2 | 2,329 | 16.924 | 19.02 |
| DNSProxy C | HTTP/3 | 1,541 | 29.321 | 20.00 |
| DNSProxy Rust | HTTP/3 | 1,318 | 29.336 | 20.08 |
| AdGuard Go | HTTP/3 | 2,516 | 16.493 | 19.48 |

See the [full median table](summary.md) for both client transports, reply sizes
and all concurrency levels. Go's HTTP/3 implementation performed better in
this CPU-constrained fixture. This points to transport-engine and application
differences worth profiling; it does not isolate a language effect. These
short shared-runner figures should not be treated as Internet resolver
capacity, or directly compared with the unrestricted-CPU
[C/Rust feasibility run](../rust-poc-2026-11-12/README.md).

The project's decision remains to maintain the C codebase and retain Rust as
a feasibility branch. The existing C release, packaging and deployment path
continues to be useful, while the port has not demonstrated a consistent
operational advantage that justifies replacing that maintained path.

## Data and reproduction

- [Original per-measurement JSON Lines](measurements.jsonl), including observed
  connection counts, protocol/method counters and launch arguments.
- [CSV measurements](measurements.csv), with line endings normalized to LF.
- [Versions and CPU affinity](environment.json).
- [Source revisions, totals and file checksums](manifest.json).
- [Pinned benchmark script](https://github.com/fantuz/DNSProxy/blob/7c844c19d4e40a306a6381dbdaa010f0053fb758/rust-poc/bench/compare_go.py)
  and [build/reproduction instructions](https://github.com/fantuz/DNSProxy/blob/7c844c19d4e40a306a6381dbdaa010f0053fb758/rust-poc/README.md#github-validation).

Early benchmark attempts repeatedly restarted the QUIC fixture within one
Python process and timed out with both C and Rust. Isolated worker checks
passed, and the complete run reported here passed after applying that
isolation. The incomplete attempts are excluded from this baseline.
