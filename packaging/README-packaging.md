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

## Optional direct port 53 service

The package includes an example `port-53.conf` systemd drop-in. It keeps
`DynamicUser=yes`, adds only `CAP_NET_BIND_SERVICE`, explicitly enables IPv4
and IPv6 loopback, and pins the upstream bootstrap address to prevent recursive
system DNS lookup. Copy it into `dnsp-modern.service.d` only when direct port 53
is wanted, review the addresses/provider, then reload systemd and restart.
On IPv6-disabled hosts remove `-l ::1`. Check for existing port 53 listeners
before enabling it. Ordinary installations keep port 5300 without capabilities.
When systemd-resolved fronts DNSProxy it can instead forward to port 5300;
do not replace its stub listener or symlink as part of service setup.

## Packages and architectures

| Distribution | Format | x86-64 | ARM64 |
| --- | --- | --- | --- |
| Ubuntu 22.04 | DEB | amd64 | arm64 |
| Ubuntu 24.04 | DEB | amd64 | arm64 |
| Debian 13 | DEB | amd64 | arm64 |
| Rocky Linux 9 | RPM | x86_64 | aarch64 |
| Windows PoC | Portable ZIP | amd64 | — |
| macOS 15+ | Portable tar.gz | x86_64 (Intel) | arm64 (Apple Silicon) |

The [macOS archives](../docs/MACOS.md) use Apple's system libcurl and include a
foreground launcher on local port 5053. They require neither Homebrew nor
Rosetta. Developer ID signing/notarization and launchd installation are deferred.

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
   with eight Linux packages, the Windows x86-64 PoC ZIP, two native macOS
   archives, and `SHA256SUMS`. Publication waits for the native Windows and both
   macOS builds and extracted-package tests, as well as Linux packaging and
   sanitizers. Other commits at the published version
   produce CI artifacts. A failed check prevents publication.
3. To release from the Actions page, open **DNSProxy modern - test and package
   → Run workflow**, choose `master`, and enable **publish**. Enter a
   `release_version` higher than both the selected commit's `VERSION` and the
   highest release tag. The workflow stages a commit that changes only
   `VERSION`. All eight Linux package builds, Windows and both macOS builds/tests,
   and the sanitizer job check out that commit before the workflow tags it and publishes
   the complete set. A blank
   field uses the `VERSION` from `master`. Pushing an explicit tag also works
   when it matches the tagged commit's `VERSION`.

Release notes begin with a download table for Windows, macOS Intel/Apple Silicon
and each Linux package target, followed by the generated changelog. README
download buttons point to the latest release's table, so they do not need
version-specific URLs.
The **Refresh release download table** workflow updates the latest release's
table when its renderer changes on `master`, or when run manually from `master`.
It verifies that every linked asset exists and preserves the existing changelog;
it does not change release tags, versions or package assets. When refreshing
older releases without macOS archives, it preserves their original package set
instead of adding unavailable downloads.

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
macOS downloads are available from v4.2.0 onward as
`dnsp-modern-VERSION-macos-x86_64.tar.gz` and
`dnsp-modern-VERSION-macos-arm64.tar.gz`, also covered by `SHA256SUMS`.
The publisher rejects missing, empty, extra, or wrong-version packages, including
the Windows ZIP and either macOS archive, before creating a release tag.
Existing package assets remain unchanged.

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

## Reversible Linux resolver integration

The package includes `dnsp-configure-dns` (Python 3 standard library) and an
inactive systemd recovery service/timer. Installation and upgrade do not change
DNS settings or enable this timer. Supported backends are **NetworkManager**
(`nmcli`) and **systemd-networkd + systemd-resolved**; choose one explicitly.
Other managers, resolvconf, static resolv.conf, macOS/BSD and VPN split-DNS need
manual integration. The helper never replaces `/etc/resolv.conf`.

First configure the existing service using the packaged `port-53.conf` example:

```sh
sudo mkdir -p /etc/systemd/system/dnsp-modern.service.d
sudo install -m 0644 /usr/share/doc/dnsp-modern/port-53.conf \
  /etc/systemd/system/dnsp-modern.service.d/port-53.conf
# Review the upstream and numeric bootstrap address in the drop-in first.
sudo systemctl daemon-reload
sudo systemctl enable --now dnsp-modern
sudo systemctl restart dnsp-modern
```

On RPM systems, find the documentation directory with `rpm -ql dnsp-modern`.
The drop-in retains DynamicUser and adds only CAP_NET_BIND_SERVICE for port 53.
It binds IPv4/IPv6 loopback. Do not enable a second resolver on those addresses;
resolved's usual `127.0.0.53` stub can coexist. A custom backup upstream must have
its own numeric bootstrap address to avoid a resolver dependency loop.

Review and apply an explicit selection (replace `enp1s0`; repeat `--interface`
for multiple interfaces):

```sh
sudo dnsp-configure-dns enable --backend nm --interface enp1s0 --dry-run
sudo dnsp-configure-dns enable --backend nm --interface enp1s0
sudo dnsp-configure-dns status
sudo dnsp-configure-dns restore
```

For networkd, use `--backend networkd` instead. Both paths require the owned
service enabled at boot, dual loopback port 53, numeric bootstrap and working
UDP/TCP DNS. Setup checks the persisted and effective adapter settings and then
checks system name resolution; a failed check restores the original settings.
A dry run performs reads and health probes and prints the exact snapshot/changes.

**NetworkManager:** only active Ethernet/Wi-Fi profiles with IPv4 and IPv6 using
`auto` or `manual` are accepted. The helper saves the connection UUID and changes
only `ipv4.dns`, `ipv6.dns` and their `ignore-auto-dns` properties. It uses `device
reapply`, without disconnecting the link. Original ordered static addresses and
automatic-DNS flags are restored exactly; DHCP/RA address leases are not pinned.
Search-domain properties are preserved, but NetworkManager's ignore-auto-dns
also suppresses DHCP-provided search domains while enabled. Other profiles,
routes, DNS priorities and global manager settings are untouched. Restoration
finds the currently active device by UUID; an inactive profile is restored on
disk without being activated. A NetworkManager-owned resolv.conf or the
systemd-resolved stub symlink is required.

**networkd/resolved:** requires the resolved stub resolv.conf symlink and an
active `.network` profile with a single exact `[Match] Name=enp1s0`. Broad matches,
MAC-only matches and existing drop-ins require manual setup. This conservative
restriction prevents applying changes to unselected interfaces. The helper owns
one `90-dnsproxy.conf` drop-in, sets dual loopback DNS and `~.` routing, and disables
DNS learned by DHCPv4, DHCPv6 and RA. It preserves the base profile and existing
search domains. Restore removes only an unchanged DNSProxy-owned drop-in, reloads
networkd and reconfigures the same profile/link if still present. A link that is
absent is restored persistently for its next appearance. Profile changes require
manual inspection. This works with suitable `/run/systemd/network` generated
profiles without editing the generated base file.

Neither backend promises exclusive DNS routing across all interfaces, VPNs or
application-level DoH. Per-link split-DNS, enterprise policy and custom local
DNSSEC/DoT requirements need dedicated validation. Do not use this helper to
replace corporate DNS policy. The common implementation targets the versions in
Ubuntu 22.04/24.04, Debian 13 and Rocky 9; CI covers transaction logic and package
lifecycle on the existing package matrix, not all live network-manager combinations.

### Recovery and removal

A root-only `state.json` in `/var/lib/dnsp-modern-integration` records the original
settings before any DNS write. A persistent systemd timer is armed before writes;
failed setup rolls back immediately. Pending transactions expire after two minutes.
The watchdog retries every minute and after boot, using the same process lock.
Commands have bounded execution time. If setup is killed after a persisted write,
the next recovery attempt restores from disk. A successful commit disables the
watchdog and keeps the original snapshot for explicit restoration.

Always run `sudo dnsp-configure-dns restore` **before** stopping or removing the
service. DEB/RPM removal refuses while the recovery record exists. Upgrades retain
the snapshot. Restore refuses external edits, keeps the record and reports the
conflicting profile/drop-in. Resolve the conflict and retry; never delete the
record merely to bypass package removal. Committed integration relies on the
resolver service's restart policy; it does not silently fall back to plaintext
DNS when the service remains unavailable.

Tests cover durable writes, process death after a write, automatic/static restore,
partial reapply/health failures, watchdog failure, administrator drift, preview,
profile identity changes, and owned drop-in removal. Before broad deployment,
use disposable VMs for each backend: apply and resolve over both transports;
restore mixed DHCP/static settings; kill setup and reboot while pending; unplug
and rename an adapter; reboot a committed setup; test package upgrade/removal;
and attach/detach the actual VPN used on the host. Real networkd/NM reload and
roaming acceptance remains separate from the synthetic boundary tests.
