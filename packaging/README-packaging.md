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

On a system with QUIC-capable libcurl, such as Debian 13, you can append
`--upstream-http=prefer-h3` to an `ExecStart` override. Check negotiated versions
in the loopback metrics. [Upstream HTTP/3 configuration](../README.md#optional-upstream-http3)

```sh
dig @127.0.0.1 -p 5300 example.com A
dig +tcp @127.0.0.1 -p 5300 example.com A
curl -fsS http://127.0.0.1:9153/metrics
```

Observe `dnsp_upstream_http_responses_total` by version and
`dnsp_upstream_reused_requests_total` while generating traffic to check
protocol negotiation and connection reuse. The benchmark and QUIC suites
verify concurrent HTTP/2 and HTTP/3 streams with local upstreams. Metrics
reset when the process restarts and omit query names and client addresses.
See [deployment checks and test coverage](../docs/OPERATIONS.md).

## Packages and architectures

| Distribution | Format | x86-64 | ARM64 |
| --- | --- | --- | --- |
| Ubuntu 22.04 | DEB | amd64 | arm64 |
| Ubuntu 24.04 | DEB | amd64 | arm64 |
| Debian 13 | DEB | amd64 | arm64 |
| Rocky Linux 9 | RPM | x86_64 | aarch64 |

Build RPMs from a committed checkout on Rocky Linux 9:

```sh
sudo dnf install gcc make git rpm-build redhat-rpm-config libcurl-devel openssl python3 systemd-rpm-macros
sh scripts/build-rpm.sh
sudo dnf install "./dist/dnsp-modern-$(cat VERSION)-1.el9.$(rpm --eval '%{_arch}').rpm"
```

Install a downloaded DEB with `sudo apt install ./package.deb` or a downloaded
RPM with `sudo dnf install ./package.rpm`. Use your distribution's package and
its architecture. First start is opt-in for both formats. On a live systemd
host, the RPM uses the distribution's restart-on-upgrade and stop-on-removal
helpers.

## Automatic and manual releases

1. Set the next release number in the top-level `VERSION` file and merge to
   `master`.
2. The first successful build for the new version creates the matching
   `vVERSION-modern` tag at the tested commit and publishes a regular GitHub release
   with eight Linux packages, the Windows x86-64 PoC ZIP, and `SHA256SUMS`.
   Publication waits for the native Windows build and portable bundle tests
   as well as Linux packaging and sanitizers. Other commits at the published version
   produce CI artifacts. A failed check prevents publication.
3. To release from the Actions page, open **DNSProxy modern - test and package
   → Run workflow**, choose `master`, and enable **publish**. Enter a
   `release_version` higher than both the selected commit's `VERSION` and the
   highest release tag. The workflow stages a commit that changes only
   `VERSION`. All eight Linux package builds, the Windows build/tests, and the
   sanitizer job check out that commit before the workflow tags it and publishes
   the complete set. A blank
   field uses the `VERSION` from `master`. Pushing an explicit tag also works
   when it matches the tagged commit's `VERSION`.

Manual releases with a version input stage the commit on `ci/release-<run-id>`.
Publication removes that branch after creating the release. Failed runs keep
it so **Re-run failed jobs** can use the same commit. To abandon a failed run,
remove its staging branch once the run has finished.

The prepared release commit does not update `master`, so its `VERSION` can lag
behind the latest release. To synchronize it, merge a change setting `VERSION`
to the published version. CI builds snapshot artifacts for that merge and
leaves the existing release tag and packages untouched. For a new release,
choose a version higher than the latest release tag.

If publication fails after creating the tag, rerun the failed workflow for the
tagged commit. If an incomplete GitHub release draft exists, inspect it and
clear it before retrying. Package assets for a published version are immutable
from the workflow. To change them, increment `VERSION`.

Ubuntu runners test install, upgrade and purge with live systemd. Debian
containers exercise APT install and purge. Rocky containers exercise DNF
install and removal and run UDP and TCP queries against the installed binary.

Release assets are direct downloads with SHA-256 checksums. Download the
matching package and `SHA256SUMS` to the same directory and run
`sha256sum --ignore-missing -c SHA256SUMS`. Use the GitHub release page as the
source for both files.

Windows downloads are available from v4.0.3 onward as
`dnsp-modern-VERSION-windows-amd64-poc.zip`, also covered by `SHA256SUMS`.
See the [Windows guide](../docs/WINDOWS.md) for PowerShell verification and setup.
The publisher rejects missing, empty, extra, or wrong-version packages, including
the Windows ZIP, before creating a release tag. Earlier releases remain unchanged.

## Protocol and performance limitations

The proxy forwards standard DNS QUERY messages and carries arbitrary DNS
record types and EDNS options to the upstream resolver. IPv4 UDP requests
can be up to 65,507 bytes and DNS/TCP and DoH bodies up to 65,535 bytes.
UDP reply limits are 512 bytes without EDNS and the client's advertised EDNS
buffer size (clamped to 512–1232 by default) otherwise. Set `--udp-reply-max`
to override the upper bound, up to 4096 bytes. Oversized UDP replies are returned
with `TC=1` and can be retried over TCP. The upstream DoH response must pass
HTTP status, Content-Type, DNS header/ID/question, and record-boundary checks.
Use the default loopback bind for local forwarding. The project also includes
local TLS/ALPN benchmarks for HTTP/2 and HTTP/1.1. See
[bench/README.md](../bench/README.md) for setup and measurements.
