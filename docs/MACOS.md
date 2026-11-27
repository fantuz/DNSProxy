# Native macOS builds

Native archives from release 4.10.0 onward include an optional
[Homebrew desktop interface](MACOS-GUI.md), with shared Python source and a Mac
launcher. The native resolver and service helper do not require Homebrew.
See the [4.10.0 release notes](releases/4.10.0.md).

DNSProxy uses the same C resolver on macOS, Linux and Windows. Native packages
are built separately for **Intel (x86-64)** and **Apple Silicon (arm64)**, with
**macOS 15 or newer** as the deployment target. Native CI uses macOS 15 for
Intel and macOS 26 for Apple Silicon; the latter does not verify every supported
older macOS version or physical Apple chip. Older macOS versions are not covered
by these packages.

## Download and start

Open the [latest release's download table](https://github.com/fantuz/DNSProxy/releases/latest#downloads)
and choose your Mac's architecture. **About This Mac** shows either an Intel
processor or an Apple chip. Download the corresponding
`dnsp-modern-VERSION-macos-x86_64.tar.gz` or
`dnsp-modern-VERSION-macos-arm64.tar.gz` and `SHA256SUMS` from the same release.
In Terminal, open the download directory and set `archive` to the exact
filename you downloaded. This example verifies the released Apple Silicon copy.
For Intel, use the filename ending in `-macos-x86_64.tar.gz`.

```sh
archive=dnsp-modern-4.12.0-macos-arm64.tar.gz
expected=$(awk -v f="$archive" '$2 == f {print $1}' SHA256SUMS)
actual=$(shasum -a 256 "$archive") && [ "${actual%% *}" = "$expected" ] && echo "Archive verified"
```

Proceed when you see **Archive verified**. In the extracted folder, run
`shasum -a 256 -c SHA256SUMS` to check the individual files.

**First launch on a personal Mac.** Open the verified app, command or binary
once. If macOS says the developer cannot be verified or Apple cannot check the
item, dismiss the alert. Open **System Settings → Privacy & Security**, scroll
to **Security**, click **Open Anyway** for the named item and confirm **Open**.
macOS can request authentication. A helper named in a separate alert has its own
approval. A managed Mac may reserve this decision for its administrator.
[Apple’s Open Anyway steps](https://support.apple.com/en-us/102445#openanyway) · [Full Apple guide to download alerts](https://support.apple.com/en-us/102445)

For a damaged-file or malware alert, stop and verify a fresh official download.

For the console resolver, double-click **Start-DNSProxy.command** in the extracted folder,
or run it in Terminal. It listens on **127.0.0.1:5053** and **[::1]:5053**, using
UDP and TCP, and forwards to Cloudflare over HTTPS. It enables 256 cache slots
and loopback metrics on port 9090. Ctrl+C stops the foreground process.

Test it from another terminal:

```sh
dig @127.0.0.1 -p 5053 example.com A
dig @::1 -p 5053 example.com AAAA
dig @::1 -p 5053 example.com AAAA +tcp
```

The native resolver and helper need no Homebrew installation, Rosetta or
third-party library downloads: the resolver links to Apple's system libcurl.
TLS and HTTP capabilities depend on the installed macOS libcurl;
`./dnsp-modern --version` reports them. HTTP/2 is
tested on both architectures. HTTP/3 is not guaranteed by these packages.
`BUILD-INFO.txt` records the source commit, architecture and build environment.
It also records the compiler profile and flags. Each executable contains only
its advertised native architecture; the build rejects Rosetta-translated shells.

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

Installation rejects existing installations, jobs or reserved log paths. Failed
startup rolls back files and jobs created by that installation attempt. Upgrade by
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

Stop and uninstall require restoring any saved DNS snapshot first. Commands are
serialized with a root-owned lock, and destructive commands verify the saved
job ownership record.

## Reversible DNS configuration

List the network services and select explicit UUIDs (names can change):

```sh
sudo ./dnsp-macos services
sudo ./dnsp-macos enable-dns YOUR-NETWORK-SERVICE-UUID
# Multiple Ethernet/Wi-Fi UUIDs can be supplied in the same transaction.
sudo ./dnsp-macos status
sudo ./dnsp-macos restore-dns
```

`enable-dns` tests real upstream DNS through both loopback families over UDP and
TCP, then arms recovery **before** changing DNS. It saves the configured DNS dictionary
for every selected service, including search domains and the absence of static
settings. Restoration returns an automatic/DHCP service to automatic mode; it
does not save DHCP's current DNS addresses as a new static configuration.

The snapshot is stored as root-only `dns-state.plist` under the installation
directory. A Pending transaction has a two-minute deadline. The recovery job
runs at boot and every minute, restoring expired Pending or unfinished Restoring
transactions. Failed post-change health checks attempt immediate rollback. An
Active transaction persists across reboots with the resolver service; a runtime
upstream outage does not silently switch to an unencrypted DNS provider.

`restore-dns` compares current settings to the saved Before/After values.
Administrator edits, removed services or write failures retain the snapshot and produce an
error instead of overwriting unrelated settings. Resolve the conflict/reconnect
the service, then retry `restore-dns`. Repeated `enable-dns` calls do not replace
the original snapshot. Do not delete the snapshot to bypass stop/uninstall guards.

Only enabled Ethernet and Wi-Fi services are supported. VPN, scoped/split DNS,
configuration-profile managed DNS and applications with their own DNS/DoH path
are outside this helper's support scope. macOS may retain supplemental resolvers;
inspect `scutil --dns` and verify the intended traffic path on your Mac. A profile
may reject or override changes; use the organization's management tools in that
case. The helper does not remove profiles or disable VPNs.

## Blocklists and allowlists

The native helper accepts `install --blocklist FILE --allowlist FILE` alongside
the existing upstream/bootstrap/CA arguments. It copies and validates policy
files for the unprivileged resolver. See [blocklists](BLOCKLISTS.md) for syntax,
DNSSEC behaviour, automatic reloads and the optional Python update helper.

## Download approval and signing

The v4.11.1 archives provide `.command` launchers. Starting with v4.12.0, the
archives also include **DNSProxy.app** for Finder. The app contains the desktop code and a copy of the
resolver, so it can be moved to `~/Applications` on its own. The desktop screen
uses the Homebrew GTK runtime. The console launcher works with the system
libraries already on the Mac. [Desktop setup](MACOS-GUI.md)

New builds ad-hoc sign the app, the resolver and the service helper before
producing the checksum manifest. An ad-hoc signature detects changes to the
sealed code. The publisher has no Apple Developer ID signature or notarization
ticket. Use the first-launch steps under [Download and start](#download-and-start).

Maintainers can verify the extracted app with
`codesign --verify --deep --strict --verbose=2 DNSProxy.app`. For a release
acceptance test, download the candidate archive in Safari on a clean personal
Mac, verify the checksum, extract it in Finder and follow the approval steps.
With the desktop dependencies installed, open the app, start and stop its bundled
resolver, then reopen the app. Record the macOS version, architecture and alert
wording. CI separately verifies LaunchServices startup and the app signature on
Intel and Apple Silicon. The interactive approval requires a human using the Mac.

## Build and validation

Install Apple's Command Line Tools (`xcode-select --install`), then run:

```sh
bash scripts/build-macos.sh
```

The release build retains `-O2`, explicitly selects the native architecture and
uses the system linker's dead-code stripping. Independent compiler jobs run in
batches of two. It does not use `-mcpu=native`, a newer Apple chip's instruction
set, fast-math or link-time optimization. The resolver is a single C translation
unit and uses system libcurl, without a separately compiled dependency tree.

For pull requests that change the Mac build scripts or native workflow, CI
compares the sequential `-O2` baseline with the release profile on the same
Apple Silicon runner. A first release build warms the toolchain. Each profile
then builds four times, with each taking the first position in two of the four
pairs. The reported medians cover compilation, linking, executable checks,
checksums and packaging. The report also records the first build separately,
all eight measured times, executable sizes, compiler identity and flags in
`macos-build-arm64.json`. The native workflow can also run this comparison
on manual request. Routine release jobs build the release profile once.
Protocol and GUI acceptance checks use the resulting release archive.

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
Actual adapter DNS changes, sleep/wake, reboot, Wi-Fi/Ethernet switching and
interactions with local VPNs or configuration profiles require validation on
the target Mac; these conditions are not covered by the CI fixtures.
