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

Record the original DNS settings for the selected network service before
changing anything. In **System Settings → Network → your connection → Details
→ DNS**, point that service at `127.0.0.1` and `::1` only after both listeners
have been tested. Restore the original DNS settings **before stopping the
resolver or rebooting**. The numeric bootstrap address avoids a DNS lookup loop.
VPNs and applications with their own DNS/DoH configuration may use other paths.

This first macOS package does not install a persistent launchd service or
automatically modify network services. Those integrations need separate
lifecycle and rollback testing on Macs; the Linux and Windows helpers do not
apply to macOS.

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
