# Native macOS builds

DNSProxy uses the same C resolver on macOS, Linux and Windows. Native packages
are built separately for **Intel (x86-64)** and **Apple Silicon (arm64)**, with
**macOS 15 or newer** as the minimum. Intel and Apple Silicon are both tested on
macOS 15 in CI. Older macOS versions are not covered by these packages.

## Download and start

Open the [latest release's download table](https://github.com/fantuz/DNSProxy/releases/latest#downloads)
and choose your Mac's architecture. **About This Mac** shows either an Intel
processor or an Apple chip. Download the corresponding
`dnsp-modern-VERSION-macos-x86_64.tar.gz` or
`dnsp-modern-VERSION-macos-arm64.tar.gz` and `SHA256SUMS` from the same release.
Before extracting, verify the archive against its entry in `SHA256SUMS`:

```sh
shasum -a 256 dnsp-modern-*-macos-*.tar.gz
```

Extract the archive into its own folder. Double-click **Start-DNSProxy.command**,
or run it in Terminal. It listens on **127.0.0.1:5053** and **[::1]:5053**, using
UDP and TCP, and forwards to Cloudflare over HTTPS. It enables 256 cache slots
and loopback metrics on port 9090. Ctrl+C stops the foreground process.

Test it from another terminal:

```sh
dig @127.0.0.1 -p 5053 example.com A
dig @::1 -p 5053 example.com AAAA
dig @::1 -p 5053 example.com AAAA +tcp
```

The package needs no Homebrew installation, Rosetta or third-party library
downloads: it links to Apple's system libcurl. TLS and HTTP capabilities depend
on the installed macOS libcurl; `./dnsp-modern --version` reports them. HTTP/2 is
tested on both architectures. HTTP/3 is not guaranteed by these packages.
`BUILD-INFO.txt` records the source commit, architecture and build environment.

## Port 53 and system DNS

The launcher uses port 5053 so it can be tested without changing the Mac's DNS
settings or taking over a system service. To use standard DNS port 53, first
check for a listener with `sudo lsof -nP -iUDP:53 -iTCP:53`. Then run explicitly:

```sh
sudo ./dnsp-modern -l 127.0.0.1 -l ::1 -p 53 --bootstrap-address 1.1.1.1 --cache-entries 256
```

## Persistent launchd service

From the extracted bundle, install the service explicitly:

```sh
sudo ./dnsp-macos install
sudo ./dnsp-macos status
```

Installation copies the two executables into `/Library/Application Support/DNSProxy`,
protects them against unprivileged writes, and registers system LaunchDaemons.
launchd owns port **53** on **127.0.0.1** and **::1**, for UDP and TCP, and passes
those sockets to the shared C resolver running as **nobody**. No user login is
required. The resolver uses HTTPS with a numeric upstream bootstrap address,
so it can start without using the Mac's DNS resolver. Installation does not
change any network service's DNS settings.

An optional upstream, numeric bootstrap address and CA bundle can be provided:

```sh
sudo ./dnsp-macos install https://cloudflare-dns.com/dns-query 1.1.1.1
# For private enterprise trust, add the path to your PEM CA bundle as a third argument.
```

Existing installations, jobs or reserved log paths are refused. Failed startup
rolls back files and jobs created by that installation attempt. Upgrade by
restoring DNS, uninstalling and installing the new bundle. This helper does not
perform unattended upgrades.

launchd restarts failed processes with a minimum 10-second throttle. Logs go to
`/var/log/dnsp-modern.log`; a root recovery job checks them every minute and
keeps a previous log of up to 4 MiB. The current log can exceed 4 MiB between
checks. Copy/truncate rotation can lose concurrent log lines at the boundary.

```sh
sudo ./dnsp-macos stop
sudo ./dnsp-macos start
sudo ./dnsp-macos uninstall
```

Stop and uninstall refuse while a DNS snapshot exists. Both require restoring
DNS first. Commands are serialized with a root-owned lock, and destructive
commands verify the saved job ownership record.

## Reversible DNS configuration

List the network services and select explicit UUIDs (names can change):

```sh
sudo ./dnsp-macos services
sudo ./dnsp-macos enable-dns YOUR-NETWORK-SERVICE-UUID
# Multiple Ethernet/Wi-Fi UUIDs can be supplied in the same transaction.
sudo ./dnsp-macos status
sudo ./dnsp-macos restore-dns
```

Enable tests real upstream DNS through both loopback families over UDP and TCP,
then arms recovery **before** changing DNS. It saves the configured DNS dictionary
for every selected service, including search domains and the absence of static
settings. Restoration returns an automatic/DHCP service to automatic mode; it
does not save DHCP's current DNS addresses as a new static configuration.

The snapshot is stored as root-only `dns-state.plist` under the installation
directory. A Pending transaction has a two-minute deadline. The recovery job
runs at boot and every minute, restoring expired Pending or unfinished Restoring
transactions. Failed post-change health checks attempt immediate rollback. An
Active transaction persists across reboots with the resolver service; a runtime
upstream outage does not silently switch to an unencrypted DNS provider.

Restore compares current settings to the saved Before/After values. Administrator
edits, removed services or write failures retain the snapshot and produce an
error instead of overwriting unrelated settings. Resolve the conflict/reconnect
the service, then retry `restore-dns`. Repeated Enable refuses to replace the
original snapshot. Do not delete the snapshot to bypass stop/uninstall guards.

Only enabled Ethernet and Wi-Fi services are supported. VPN, scoped/split DNS,
configuration-profile managed DNS and applications with their own DNS/DoH path
are outside this helper's support scope. macOS may retain supplemental resolvers;
inspect `scutil --dns` and verify the intended traffic path on your Mac. A profile
may reject or override changes; use the organization's management tools in that
case. The helper does not remove profiles or disable VPNs.

## Download approval and signing

These packages are not Developer ID signed or notarized. macOS may request
approval before running a downloaded executable or command file. Follow
[Apple's guidance for opening downloaded apps](https://support.apple.com/102445)
after verifying the release and checksum. Developer ID signing, notarization
and an installer are deferred; no global Gatekeeper changes are needed.

## Build and validation

Install Apple's Command Line Tools (`xcode-select --install`), then run:

```sh
bash scripts/build-macos.sh
```

CI extracts and tests the exact archive on each native architecture. It checks
system-only dynamic dependencies, IPv4/IPv6 UDP/TCP, wildcard reply addresses,
DNS parsing, caching, failover, TLS certificate checks and HTTP/2 multiplexing.
The C callback and socket probes run too. The packaged launcher is started from
another directory and checked for dual-stack DNS and clean Ctrl+C shutdown.
Loopback aliases are added on the
disposable CI runner to exercise distinct client addresses; users do not need
those aliases for normal operation.

Native CI also installs the exact bundled helper and launchd service, verifies
unprivileged IPv4/IPv6 UDP/TCP HTTPS forwarding, restart after termination,
stop/start/uninstall, ownership guards and startup conflict rollback. The DNS
transaction engine is tested with injected preferences and real durable state
files (automatic/static settings, partial writes, failed health checks, external
edits and unavailable services). The real SystemConfiguration backend is read on
each runner, but CI does **not** change the runner's live adapter DNS or reboot it.
A physical Mac acceptance pass should cover actual DNS changes, sleep/wake,
reboot, Wi-Fi/Ethernet switching and any local VPN/profile configuration.
