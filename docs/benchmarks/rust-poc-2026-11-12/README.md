# Rust port: Linux feasibility and performance

DNSProxy's maintained implementation remains C. The Rust feasibility port
implements the same DNS forwarding role and uses the same native libcurl
HTTP/TLS/QUIC engine. This study checks the port's behavior and operating costs;
it does not establish a general C-versus-Rust language ranking.

## Revisions and checks

- C reference: [`343323e4`](https://github.com/fantuz/DNSProxy/commit/343323e411488cfa3e608dfbf8496de8d91959b8).
- Tested Rust revision: [`93b3a1ec`](https://github.com/fantuz/DNSProxy/tree/93b3a1ec077d5c3d8ee7eec985f32d3d96f1ca07/rust-poc).
- [GitHub Actions run](https://github.com/fantuz/DNSProxy/actions/runs/43245557198), 12 November 2026.
- Formatting, Clippy with warnings treated as errors, and 9 Rust unit tests passed.
- The 71 core integration tests passed on Ubuntu 22.04/24.04 amd64 and Ubuntu 24.04 arm64.
- The full Debian protocol suite passed 88 tests, including HTTP/2, HTTP/3 and IPv6 upstream bootstrap.
- All 24,226 seeded wire cases matched the C oracle. Corpus seed: `8484`.
  SHA-256: `608768d6bd8bb415efb74aa5e8f5293aca663e5cdf20670662b0975795b17865`.

The refresh includes TTL-safe DNS compression checks, legacy name-bearing
record validation, destination-aware UDP replies on wildcard listeners,
version/capability reporting, and per-upstream failure diagnostics. The port
also retains TCP framing and deadlines, UDP reply caps, cache expiration,
coalescing, failover, EDNS padding, metrics and SIGUSR1 reporting. The
[port checklist](https://github.com/fantuz/DNSProxy/blob/93b3a1ec077d5c3d8ee7eec985f32d3d96f1ca07/rust-poc/PORT_CHECKLIST.md)
maps the implementation and tests. Agreement with a C oracle is evidence of
compatibility for this corpus, rather than independent proof that either
implementation is free from protocol or security bugs.

## Benchmark method

The job used an amd64 GitHub-hosted Linux runner with four reported CPUs and
the `rust:1.90.0-trixie` Debian 13 container. Both binaries used system libcurl
8.14.1 (`8.14.1-2+deb13u7`) with OpenSSL 3.5.7. C was built with `-O2 -g` and
warnings treated as errors; Rust used the locked dependencies and Cargo release
profile with thin LTO.

Each run used the same local certificate-verified DoH fixture and UDP load
generator, a 1 ms upstream delay, one A record per response, a per-host
connection cap of 8, and the answer cache disabled. The levels were 1, 8 and
32 concurrent UDP clients, each with 0.5 seconds of warmup and 2 seconds of
measurement. Three runs alternated application order. The fixture recorded the
negotiated HTTP version and simultaneous streams; both HTTP/2 and HTTP/3 were
observed as requested, with multiplexing at higher concurrency.

The proxy, Python fixture and load generator shared the host. CPU affinity was
not restricted in this C/Rust run. Peak RSS is the proxy's Linux `VmHWM` by the
end of each level; it includes the native transport libraries. Each table
entry is the median of the corresponding per-run measurement, so percentile
columns are medians of run percentiles rather than pooled latency percentiles.

## Results

| Application | Upstream | Clients | QPS | p99 ms | CPU, % of one core | Peak RSS, MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| C | HTTP/2 | 1 | 683 | 1.712 | 7.5 | 14.03 |
| Rust | HTTP/2 | 1 | 693 | 1.731 | 6.5 | 14.54 |
| C | HTTP/2 | 8 | 2,755 | 3.911 | 26.0 | 14.48 |
| Rust | HTTP/2 | 8 | 2,871 | 5.279 | 26.5 | 15.02 |
| C | HTTP/2 | 32 | 4,285 | 13.023 | 49.9 | 16.14 |
| Rust | HTTP/2 | 32 | 4,412 | 10.660 | 50.9 | 16.61 |
| C | HTTP/3 | 1 | 659 | 2.327 | 13.5 | 14.81 |
| Rust | HTTP/3 | 1 | 673 | 1.629 | 13.0 | 15.41 |
| C | HTTP/3 | 8 | 3,570 | 3.160 | 89.9 | 18.12 |
| Rust | HTTP/3 | 8 | 3,450 | 3.177 | 90.4 | 18.73 |
| C | HTTP/3 | 32 | 3,451 | 16.306 | 98.6 | 22.62 |
| Rust | HTTP/3 | 32 | 3,387 | 15.973 | 99.2 | 23.30 |

Across the measured levels, C completed **92,674** queries and Rust completed
**93,326**. Both recorded zero failed responses, timeouts and truncations.
At 32 clients, Rust QPS was about 3.0% higher for HTTP/2 and 1.8% lower for
HTTP/3. Its median peak RSS was about 0.47 MiB higher for HTTP/2 and 0.67 MiB
higher for HTTP/3. HTTP/3 approached one proxy CPU core in both implementations.

These short shared-runner measurements do not establish a consistent
performance winner. They measure a synthetic local workload, and repeated
questions can also benefit from in-flight coalescing. The separate
[C/Rust/Go application baseline](../linux-c-rust-go-2026-11-12/README.md) adds
unique questions, persistent TCP clients, larger replies and one CPU per proxy.
Dedicated-host tests, longer durations, cache workloads and network delay/loss
profiles remain useful before estimating production capacity.

## Why the maintained implementation remains C

The port demonstrates that the design can be expressed in Rust and can pass
the existing behavior checks. Rust's ownership and borrowing rules reduce
classes of memory-management risk in the code that Rust owns. Native libcurl,
FFI calls and their buffer lifetimes still require care and review.

C already has the project's maintained package builds, releases, systemd
integration and operational documentation. Supporting a second implementation
would require continuing protocol parity, security review and deployment
maintenance. The current measurements show similar throughput with slightly
higher memory use in Rust, without a demonstrated operational benefit large
enough to justify replacing that supported path now. This is a project
maintenance decision; it does not rule out future Rust work.

## Raw results and reproduction

The six original JSON files are preserved alongside this report:

- C: [run 1](c-1.json), [run 2](c-2.json), [run 3](c-3.json).
- Rust: [run 1](rust-1.json), [run 2](rust-2.json), [run 3](rust-3.json).
- [Verified medians, revisions and raw-file SHA-256 values](summary.json).

The [tested workflow](https://github.com/fantuz/DNSProxy/blob/93b3a1ec077d5c3d8ee7eec985f32d3d96f1ca07/.github/workflows/dnsp-rust-poc.yml)
records dependency setup and the exact commands. See the
[Rust build and benchmark instructions](https://github.com/fantuz/DNSProxy/blob/93b3a1ec077d5c3d8ee7eec985f32d3d96f1ca07/rust-poc/README.md#repeat-the-checks)
to repeat the comparison. The Rust branch also has a separate C/Rust/Go
application benchmark using unique question names and one CPU per proxy;
its protocol engines and pooling policies differ, so its figures should be
interpreted separately from this matched C/Rust feasibility run.
