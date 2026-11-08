# Packaging dnsp-modern

`dnsp-modern` is an **opt-in** DNS-over-HTTPS forwarder. It does not replace the
legacy `dnsp`/`dnsp-h2` binaries, modify `/etc/resolv.conf`, or take over port 53.
Persistent TCP clients can pipeline requests. The proxy sends replies in order
and handles one upstream request at a time per connection.

## Manual build and integration tests

On supported Debian/Ubuntu systems:

```sh
sudo apt install build-essential pkg-config libcurl4-openssl-dev dpkg-dev python3
version=0.2.4~local1
VERSION="$version" sh scripts/build-deb.sh
sudo apt install "./dist/dnsp-modern_${version}_$(dpkg --print-architecture).deb"
```

The build script runs the integration tests before packaging. Build on your
target distribution so `dpkg-shlibdeps` can read its installed libc and libcurl
package metadata. Choose a version that sorts after any build you are upgrading.

A fresh installation leaves the service **disabled and stopped**. Start it
explicitly:

```sh
sudo systemctl enable --now dnsp-modern
journalctl -u dnsp-modern -f
```

On a live systemd host, upgrading restarts an already-running instance and
leaves a stopped instance stopped. Removal stops the service. These actions
honor `policy-rc.d`. Purge clears the service enable links and preserves
operator-owned drop-ins. Fresh installation leaves first start to the operator.

The packaged service listens on `127.0.0.1:5300` (UDP and TCP), forwards to
`https://cloudflare-dns.com/dns-query`, and exposes metrics on the loopback
interface at `http://127.0.0.1:9153/metrics`. It never binds metrics to a public
interface. If port 9153 is already in use, override `ExecStart` with
`sudo systemctl edit dnsp-modern` (first clear it with a blank `ExecStart=`).
Manual launch can disable metrics by omitting `-m PORT`. The package installs
the system CA bundle as a dependency for TLS verification. If the host will
resolve its own DoH upstream through DNSProxy, configure `--bootstrap-address`
with an address for that provider before switching the system resolver.

```sh
dig @127.0.0.1 -p 5300 example.com A
dig +tcp @127.0.0.1 -p 5300 example.com A
curl -fsS http://127.0.0.1:9153/metrics
```

Observe `dnsp_upstream_http_responses_total{version="2"}` and
`dnsp_upstream_reused_requests_total` while generating traffic to evaluate
HTTP/2 negotiation and connection reuse. Loopback integration tests exercise
HTTP/1.1 only and do not prove remote HTTP/2 throughput. Metrics are process-
local and reset on restart; they do not include DNS question names, client
addresses, or other high-cardinality labels.

## GitHub Actions releases

`.github/workflows/dnsp-modern.yml` builds packages for Debian 13, Ubuntu 22.04,
and Ubuntu 24.04. Ubuntu runners exercise the service lifecycle with systemd.
The Debian container checks installation and purge with APT.

The top-level `VERSION` file supplies the base version for local builds and CI.
A branch build uses a version such as `0.2.4~pre17.ci+debian13`. A release tag must
match the file, for example `v0.2.4-modern` for `VERSION` containing `0.2.4`.
The tag build publishes an experimental pre-release with all three packages
and `SHA256SUMS` after the checks pass.

Generated packages belong in workflow artifacts and GitHub Releases.

Install the artifact built for your own distribution/version; binary
packages are not guaranteed to be portable across Debian and Ubuntu releases.
These packages are **not signed** or published to an APT repository. Verify
checksums and the GitHub release source before installing.

## Protocol and performance limitations

The proxy forwards DNS wire messages without caching or DNSSEC validation.
UDP reply limits are 512 bytes without EDNS and the client's advertised EDNS
buffer size (clamped to 512–4096) otherwise. Oversized UDP replies are returned
with `TC=1` and can be retried over TCP. The upstream DoH response must pass
HTTP status, Content-Type, DNS header/ID/question, and record-boundary checks.
Use the default loopback bind for local forwarding. The project also includes
local TLS/ALPN benchmarks for HTTP/2 and HTTP/1.1. See
[bench/README.md](../bench/README.md) for setup and measurements.
