# DNSProxy — DNS over HTTPS (DoH)

[![golangci-lint](https://img.shields.io/badge/golangci--lint-enabled-brightgreen?logo=go)](https://golangci-lint.run/)
[![build](https://github.com/fantuz/DNSProxy/actions/workflows/dnsp-modern.yml/badge.svg)](https://github.com/fantuz/DNSProxye/actions/workflows/dnsp-modern.yml)
![Latest GitHub release](https://img.shields.io/github/release/fantuz/DNSProxy.svg)
[![GitHub license](https://img.shields.io/github/license/fantuz/DNSProxy)](LICENSE)
![GitHub all releases](https://img.shields.io/github/downloads/fantuz/DNSProxy/total)

DNSProxy bridges conventional **DNS clients (UDP/TCP)** to upstream
**DNS-over-HTTPS (DoH)** resolvers. The experimental `dnsp-modern` implementation
uses RFC 8484 `application/dns-message` POST requests, libcurl's event-driven
multi interface, TLS verification, and opportunistic HTTP/2 multiplexing.

This project grew out of DNS transport and privacy experiments dating to roughly
2009–2010 and work surrounding [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).
Historical project notes, experiments, and original CLI examples are preserved
in [docs/README-legacy.md](docs/README-legacy.md). **Those legacy instructions
do not describe `dnsp-modern`.**

> **Experimental software.** This is a forwarding proxy, not a full recursive
> resolver, DNSSEC validator, or production-hardened public resolver. It does
> not guarantee anonymity or prevent all DNS leaks; client routing and the
> chosen DoH provider still matter.

## Which executable?

| Executable | Role | Build | Status |
| --- | --- | --- | --- |
| `dnsp-modern` | Event-driven RFC 8484 DoH forwarder | `make -f modern.mk` | Experimental, independent modern implementation |
| `dnsp-h2` | Historical DoH prototype with different features/CLI | Original `Makefile` | Legacy |
| `dnsp` | Pre-standardization HTTP/DNS experiment | Original `Makefile` | Deprecated |

The modern build does **not** replace the legacy binaries. Historical features
such as disk caching, custom TTL rewriting, HTTP proxy-chain options, and raw
message dumps have **not** been migrated. Do not interchange CLI flags between
these executables.

`dnsp-modern` now supports **persistent DNS-over-TCP client sessions**, ordered
sequential/pipelined messages, and an adjustable `--tcp-idle-ms` timeout. See
[the TCP session documentation](docs/TCP_SESSIONS.md) for behavior, limits,
metrics and tests.

## Build, test and run

On Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libcurl4-openssl-dev python3 dnsutils
make -f modern.mk
make -f modern.mk modern-check
```

Run as an unprivileged process; UDP and TCP DNS both listen on port 5300:

```bash
./dnsp-modern -l 127.0.0.1 -p 5300 \
  -s https://cloudflare-dns.com/dns-query -m 9153

dig @127.0.0.1 -p 5300 example.com A
dig +tcp @127.0.0.1 -p 5300 example.com AAAA
curl -fsS http://127.0.0.1:9153/metrics
```

Do not replace your system resolver or bind port 53 until the proxy is tested.
The DNS listeners are IPv4; `-l` expects an IPv4 bind address. Metrics always
bind **127.0.0.1** regardless of `-l`.

### Options available in baseline `dnsp-modern` v0.2.0

| Flag | Meaning | Default |
| --- | --- | --- |
| `-l IPv4` | DNS UDP/TCP bind address | `127.0.0.1` |
| `-p PORT` | DNS listener port, 1–65535 | `5300` |
| `-s URL` | Upstream DoH endpoint | `https://cloudflare-dns.com/dns-query` |
| `-m PORT` | Loopback-only metrics listener port; must differ from `-p` | Disabled for manual runs |

Unknown options or invalid ports exit with status 2. Remote upstreams must use
HTTPS; plaintext HTTP is permitted **only for a 127.0.0.1 local testing host**.
The loopback HTTP test endpoint is contacted directly. HTTPS upstreams use TLS
certificate and hostname verification, and redirects are disabled.

If the host uses DNSProxy as its system resolver, configure an upstream IP to
bootstrap the HTTPS connection without consulting the system resolver:

```sh
./dnsp-modern -s https://cloudflare-dns.com/dns-query --bootstrap-address 1.1.1.1
```

`--bootstrap-address IP` accepts one numeric IPv4 or unbracketed IPv6 address
for an HTTPS upstream hostname. It connects directly to that address, bypassing
proxy environment settings, while keeping the URL hostname for TLS and HTTP.
Choose an address served by your DoH provider and update it if the provider
changes addresses.

**Optional benchmark add-on (separate patch):** The HTTP/2 benchmarking patch
adds `--max-host-connections N` and `--ca-file PATH`, a `bench/` directory,
and an independent benchmark workflow. **Those flags are not supported by the
baseline source**: use them only after applying that follow-up patch. The
benchmark measures actual streams, QPS, latency percentiles, CPU and RSS on
local test servers. Refer to `bench/README.md` once installed.

## Architecture and protocol scope

- Binary DNS wire packets arrive over UDP or framed DNS-over-TCP.
- DoH requests use a persistent libcurl multi manager; libcurl socket and timer
  callbacks are integrated into the main `poll()` event loop.
- HTTP/2 is requested over TLS if negotiated; HTTP/1.1 can be used as fallback.
  **RFC 8484 does not require HTTP/2.** Connection reuse counters do not prove
  HTTP/2 multiplexing; benchmark actual simultaneous streams.
- Outstanding upstream requests, TCP client slots, and response sizes are
  bounded; upstream requests have connection and overall timeouts.
- Incoming DNS packets and upstream HTTP status, `Content-Type`, transaction ID,
  question and DNS record boundaries are validated before replies are sent.
- UDP replies are limited to 512 bytes for non-EDNS clients; EDNS(0) clients
  advertise a size clamped to 512–4096. Oversized replies use `TC=1`; clients
  can retry over TCP.
- There is **no DNSSEC cryptographic validation, local DNS caching, recursion,
  TTL manipulation, or EDNS option negotiation**.
- A persistent TCP session accepts pipelined queries and sends replies in
  order, with one upstream request in flight per session.

The client-to-proxy DNS leg is not encrypted merely because the upstream DoH
connection is encrypted. Do not bind the proxy to an untrusted interface.

## Metrics and observability

The proxy writes startup and failure diagnostics to stderr. For a systemd
installation, read them with `journalctl -u dnsp-modern`. Warnings include an
event name, client transport, and numeric libcurl and HTTP codes when
available. Each warning category emits at most once per ten seconds. The next
warning in that category reports how many messages it suppressed. The log
omits the upstream URL, DNS questions, payloads, and client addresses.

When all upstream slots are in use, a valid query receives `SERVFAIL`.
`dnsp_overload_total` includes these replies and local request setup failures.

The packaged systemd unit enables HTTP metrics at
`http://127.0.0.1:9153/metrics`; manual runs enable metrics only with `-m`.
Useful Prometheus-compatible series:

| Metric | Meaning |
| --- | --- |
| `dnsp_queries_total{transport="udp"}` / `{transport="tcp"}` | Submitted queries by protocol |
| `dnsp_queries_inflight` | Active upstream requests |
| `dnsp_upstream_requests_total` | Submitted upstream DoH requests |
| `dnsp_upstream_success_total`, `dnsp_upstream_failures_total`, `dnsp_upstream_timeouts_total` | Completion and errors |
| `dnsp_invalid_queries_total`, `dnsp_invalid_responses_total`, `dnsp_overload_total` | Validation/capacity events |
| `dnsp_truncated_responses_total` | Truncated UDP answers |
| `dnsp_upstream_http_responses_total{version="2"}` | Responses negotiated over HTTP/2 |
| `dnsp_upstream_new_connections_total`, `dnsp_upstream_reused_requests_total` | libcurl connection activity |
| `dnsp_upstream_duration_seconds_sum`, `dnsp_upstream_duration_seconds_count` | Aggregate upstream time |
| `dnsp_curl_socket_callbacks_total`, `dnsp_curl_timer_callbacks_total` | Event-loop activity |

Metrics reset when the process restarts. They do not expose query names or
client addresses. The HTTP version and connection reuse counters **do not
measure simultaneous HTTP/2 streams**; use the optional benchmark add-on for
that measurement.

## Debian packaging and systemd

```bash
sudo apt-get install -y dpkg-dev
sh scripts/build-deb.sh
# Default VERSION=0.2.0; the package stays under dist/.
sudo apt install ./dist/dnsp-modern_0.2.0_$(dpkg --print-architecture).deb
```

A different version can be supplied for packaging:

```bash
VERSION=0.2.1 sh scripts/build-deb.sh
sudo apt install ./dist/dnsp-modern_0.2.1_$(dpkg --print-architecture).deb
```

The package installs `/usr/bin/dnsp-modern` and a systemd service, **disabled
and stopped** by default. It does not edit `/etc/resolv.conf` or take port 53.
The packaged service runs under a restricted dynamic user and forwards to the
Cloudflare DoH endpoint on `127.0.0.1:5300` with metrics on `127.0.0.1:9153`.

```bash
sudo systemctl enable --now dnsp-modern
systemctl status dnsp-modern
journalctl -u dnsp-modern -f
```

Change settings with `sudo systemctl edit dnsp-modern`, clearing `ExecStart=`
before supplying a replacement. See
[packaging/README-packaging.md](packaging/README-packaging.md) for details.

## Linux packages and releases

GitHub Actions builds DEBs for Debian 13 and Ubuntu 22.04/24.04, and RPMs for
Rocky Linux 9. Each distribution has native x86-64 and ARM64 builds. Download
the matching package and `SHA256SUMS` from
[GitHub Releases](https://github.com/fantuz/DNSProxy/releases).

Set the next version in `VERSION` and merge to `master` to publish once the
package matrix and sanitizer job pass. See the
[packaging guide](packaging/README-packaging.md) for installation, local
builds, and manual release recovery.
