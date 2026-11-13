# Native Windows proof of concept

This build runs `dnsp-modern.c` directly on Windows x86-64. DNS parsing, cache,
failover, EDNS, limits, metrics, and libcurl connection management are shared
with Linux. There is no second resolver tree, Cygwin runtime, WSL requirement,
or protocol rewrite. `dnsp-platform.h` adapts the OS interfaces.

## Download and start

From v4.0.3 onward, open [GitHub Releases](https://github.com/fantuz/DNSProxy/releases)
and download **dnsp-modern-VERSION-windows-amd64-poc.zip** and **SHA256SUMS**
from the same release. Check the ZIP's hash against its entry in `SHA256SUMS`:

```powershell
Get-FileHash .\dnsp-modern-4.0.3-windows-amd64-poc.zip -Algorithm SHA256
```

For an unreleased build, open a successful **DNSProxy modern - test and package**
Actions run and download the **dnsp-modern-windows-amd64-poc** artifact. It
contains the portable ZIP and its `.zip.sha256` checksum file. Release v4.0.2
published only Linux packages; its Windows ZIP was uploaded to the corresponding
Actions run. CI artifacts are retained for 14 days.

Extract the portable ZIP into a folder, keeping the EXE, DLLs and CA bundle
together. MSYS2, Python, and development tools are only build/test dependencies.
`BUILD-INFO.txt` inside the ZIP identifies the version and exact source commit.

Double-click **Start-DNSProxy.cmd**. It listens on **127.0.0.1:53**, using UDP
and TCP, and forwards to Cloudflare over HTTPS. It enables 256 cache slots and
loopback metrics at <http://127.0.0.1:9090/metrics>. Keep the console open; Ctrl+C
stops the proxy. This does not change Windows DNS settings.

Alternatively, run the resolver in PowerShell:

```powershell
.\dnsp-modern.exe -l 127.0.0.1 -p 53 --bootstrap-address 1.1.1.1 --cache-entries 256 -m 9090
```

In another terminal:

```powershell
Resolve-DnsName example.com -Server 127.0.0.1 -Type A -DnsOnly
Resolve-DnsName example.com -Server 127.0.0.1 -Type AAAA -DnsOnly
```

The bootstrap address avoids a DNS lookup loop after Windows points at DNSProxy.
For another provider, pass its HTTPS URL and matching numeric bootstrap address:

```powershell
.\Start-DNSProxy.ps1 -Upstream https://dns.google/dns-query -BootstrapAddress 8.8.8.8
```

The proxy verifies HTTPS certificates and hostnames. Default Windows trust uses
both the bundled CA certificates and Windows native trust. `--ca-file PATH`
selects a custom PEM trust bundle. `--version` reports actual libcurl, TLS,
HTTP/2 and HTTP/3 capabilities. HTTP/3 remains opt-in with
`--upstream-http=prefer-h3` and the same fallback policy as Linux.

## Administrator option and port conflicts

Windows does not generally reserve ports below 1024 for administrators. Port
53 can still be occupied or reserved by another service or system policy.
DNSProxy reports the listener role and Windows socket error and exits on a
conflict. It does not stop other services or share their DNS socket.

The EXE requests normal user privileges (`asInvoker`). To explicitly request
an elevated console with a UAC prompt:

```powershell
.\Start-DNSProxy.ps1 -RunAsAdministrator
```

Elevation does not make an occupied port available. Inspect conflicts with:

```powershell
Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue
```

If downloaded PowerShell scripts are blocked, inspect them and use
`Unblock-File .\Start-DNSProxy.ps1`. The CMD launcher or direct EXE command
also works. There is no need to weaken the machine's execution policy.

## Point Windows at DNSProxy

First test `Resolve-DnsName -Server 127.0.0.1`. Record the selected adapter's
existing DNS addresses and whether they are automatic (DHCP) or static. In an
**Administrator PowerShell**, identify the intended adapter:

```powershell
Get-NetAdapter | Select-Object Name, InterfaceIndex, Status
Get-DnsClientServerAddress -InterfaceIndex 12
```

Replace `12` with that adapter's index throughout. Select DNSProxy for it:

```powershell
Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses 127.0.0.1
Clear-DnsClientCache
Resolve-DnsName example.com -Type A -DnsOnly
```

Other adapters, IPv6 DNS, VPN settings, Windows resolution policies and
applications with their own DoH can select other resolvers. This PoC does not
enforce system-wide DNS routing. A public resolver configured as an alternate
Windows DNS server may receive queries directly; use DNSProxy's
`--backup-upstream` and matching `--backup-bootstrap-address` for encrypted
upstream failover instead.

**Restore the previous settings before stopping DNSProxy or rebooting.** If
the adapter previously obtained DNS automatically:

```powershell
Set-DnsClientServerAddress -InterfaceIndex 12 -ResetServerAddresses
Clear-DnsClientCache
```

For previous static DNS, restore the recorded addresses with `-ServerAddresses`
instead. Resetting to DHCP does not restore static settings. The foreground launcher does not change adapters. Service installation is a
separate explicit step described below.

## Persistent Windows Service

From an **Administrator PowerShell** in the extracted ZIP:

```powershell
.\Install-DNSProxyService.ps1
Get-Service DNSProxy
Get-Content "$env:ProgramData\DNSProxy\logs\service.log" -Tail 30
Stop-Service DNSProxy
Start-Service DNSProxy
```

The installer copies the bundle into `Program Files\DNSProxy`, registers an
SCM service with automatic startup, and starts it as `NT AUTHORITY\LocalService`.
It listens on `127.0.0.1:53` and `[::1]:53`, uses a numeric upstream bootstrap
address, and leaves adapter DNS settings unchanged. On an IPv6-disabled machine,
install with `-ListenAddress 127.0.0.1`. Optional parameters include `-Port`,
`-Upstream`, `-BootstrapAddress`, `-ServiceName`, and `-NoStart`.

Executable files are administrator-owned and read-only to LocalService. Only
`ProgramData\DNSProxy\logs` is service-writable. The console uses stderr;
service mode keeps `service.log` and one rotated log, targeting 4 MiB each.
Rotation checks occur once per second. SCM restarts a crashed process after
3 seconds, then 10 seconds; further failures within the 24-hour reset period
remain stopped. Invalid configuration/normal exits are not restarted.

Service startup reports RUNNING only after all configured listeners and core
resources are ready; it does not require the Internet to be reachable at boot.
Stop and shutdown requests use the resolver's existing bounded event loop and
cleanup. Logs show upstream failures when connectivity is unavailable. The
service uses machine/bundled CA trust, not an interactive user's private trust
or proxy environment. Test custom enterprise trust in the service account.

Before replacing or uninstalling an installation, restore any adapter settings
that point to DNSProxy. Then run the bundled uninstall script as Administrator:

```powershell
.\Uninstall-DNSProxyService.ps1
```

Installation refuses existing service names/directories, and uninstall checks
its installation record against SCM before removing anything. Reconfiguration
or upgrade currently uses explicit uninstall/reinstall after restoring DNS;
there is no silent replacement of an existing service. Service files are not
signed yet. Native CI tests real SCM startup/stop, LocalService HTTPS queries,
IPv4/IPv6 UDP and TCP, crash recovery, port conflicts, and uninstall.

## Portability and validation overview

| Area | Windows PoC |
| --- | --- |
| DNS wire parsing, all RR types, EDNS, padding and reply limits | Shared C implementation |
| TTL/DoH Age expiration, coalescing and failover | Shared C implementation |
| UDP/TCP, pipelining and backpressure | Shared logic; Winsock I/O adapter |
| Socket handles | Pointer-width `curl_socket_t`; `INVALID_SOCKET` checks |
| UDP reply source and scatter/gather | `WSARecvMsg`/`WSASendMsg`; Linux keeps packet metadata |
| Socket ownership | Windows `SO_EXCLUSIVEADDRUSE`; Linux `SO_REUSEADDR` |
| Polling and time | Winsock `select`, `GetTickCount64`; cache time includes suspend |
| Shutdown | Console Ctrl+C/Ctrl+Break; atomic stop flag |
| Expired upstream connection | One fresh retry within the existing attempt deadline for replay-safe queries |
| Statistics | Shared loopback `/metrics`; POSIX `SIGUSR1` remains Linux-only |
| Upstream transport | Packaged libcurl/OpenSSL with HTTP/2 and HTTP/3 |

GitHub's `windows-2022` runner builds with MSYS2 UCRT64 GCC and bundles the
recursive PE DLL imports, licenses, CA certificates, source SHA, build package
versions, and checksums. It runs the shared DNS integration suite (only the
POSIX signal test is skipped), local TLS HTTP/2 and HTTP/3 tests, and native
Windows acceptance on UDP/TCP port 53, `Resolve-DnsName`, exclusive binding,
and console shutdown. Runtime tests extract the ZIP into a path with spaces,
remove MSYS2 from PATH to detect missing DLLs, and check relocated default CA
discovery with both valid and invalid TLS hostnames. The required
**DNSProxy PR checks** status includes Windows when applicable.
The Linux packages and tests also validate changes to the shared core.

The artifact is a Windows **x86-64 PoC**, unsigned, without an MSI/MSIX installer
or signed installer. CI uses Windows Server 2022; desktop
Windows 10/11, non-administrator accounts, ARM64, Unicode/long paths,
suspend/resume, and VPN policies need a broader acceptance matrix before a
supported Windows release. The shared resolver supports IPv4 and IPv6 DNS listeners. Repeat `-l` to enable
both, for example `-l 127.0.0.1 -l ::1 -p 53`. The existing launchers still
default to IPv4. Configure Windows DNS to `::1` only after enabling and testing
that listener. IPv6 record types and upstream addresses remain independent of
the client transport family.

Windows wildcard UDP replies require an assigned source address. Unassigned
loopback aliases such as `127.0.0.2` are not supported for wildcard replies via
`IP_PKTINFO`. CI tests source preservation using `127.0.0.1` and an actual
adapter address (`DNSP_TEST_SECOND_ADDRESS`), without changing adapter settings.

Next decisions: signed installer, ARM64 builds,
and broader desktop acceptance. Releases include the PoC ZIP alongside the
eight Linux packages. Publication waits for the native Windows build, portable
bundle tests, Linux package builds, and sanitizer suite; all nine downloads
are included in the release's `SHA256SUMS`. Distribution in a regular release
does not change the Windows PoC support status described above.

## Build from source

Install MSYS2 and open a **UCRT64** shell:

```sh
pacman -Syu
pacman -S --needed git mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-curl \
  mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-python
bash scripts/build-windows.sh
```

If MSYS2 asks to restart the shell during its update, do so and finish updating
first. Output: `dist/dnsp-modern-VERSION-windows-amd64-poc.zip`. Use the regular
OpenSSL curl package: MSYS2 `curl-winssl` currently disables HTTP/2. The existing
Linux `make modern` flow remains available.

## Reversible adapter DNS configuration

After installing the service from this bundle, run the **installed** script in
an elevated Windows PowerShell window:

```powershell
$dns = "$env:ProgramFiles\DNSProxy\Set-DNSProxyDns.ps1"
& $dns -Action Status
# Copy the InterfaceGuid of the physical Ethernet/Wi-Fi adapter you want to use.
& $dns -Action Enable -AdapterGuid 'YOUR-ADAPTER-GUID' -WhatIf
& $dns -Action Enable -AdapterGuid 'YOUR-ADAPTER-GUID'
& $dns -Action Status
# Restore before stopping, replacing, or uninstalling the resolver:
& $dns -Action Restore
```

Selection is explicit; several GUIDs can be supplied. Only connected physical
Ethernet/Wi-Fi adapters with both protocol bindings enabled are accepted. VPNs,
virtual adapters, domain-joined hosts, NRPT and global DNS overrides need manual
integration. This does not promise that all traffic or every application will
use DNSProxy: other adapters, browser DoH and later VPN policy can still select
a different resolver. The helper does not disable IPv6, DHCP, or VPN software.

Preflight checks the owned automatic LocalService instance, both loopback
listeners on port 53, numeric upstream bootstrap, and real UDP/TCP DNS queries.
The helper snapshots configured DNS separately for each address family. An empty
per-interface `NameServer` means automatic DNS; static addresses retain their
order. Effective DHCP/RA server addresses are never frozen into static settings.
This snapshot applies to the supported Ethernet/Wi-Fi configuration; mobile,
third-party profile management and policy-driven adapters are excluded. Windows
cmdlets perform writes; registry access is read-only.

Before writes, the helper saves an administrator-protected `dns-state.json`
beside `installation.json` and registers a SYSTEM recovery task. Failed checks
roll back immediately. Interrupted setup is retried by the task after two minutes,
every minute thereafter, and at boot. A file lock serializes setup and recovery;
a still-running operation holds that lock, so the watchdog retries until the
operation exits. A transaction cannot commit after its deadline. Committed
settings persist across reboot; the setup watchdog is then removed.

Restoration resolves the current adapter index from its GUID and restores
**automatic mode** or the original ordered static list. A missing adapter or
externally changed DNS setting is left untouched, with the recovery record
retained and an explicit error. Reconnect the adapter or resolve the reported
conflict, then retry Restore. Repeated Enable refuses to overwrite an existing
snapshot. Uninstall refuses until DNS state has been restored. Never delete
`dns-state.json` to bypass this guard.

The service's crash recovery handles runtime crashes. A committed installation
does not silently switch to an unencrypted upstream if the service remains down;
use Restore to return control to the original DNS configuration.

CI exercises the transaction engine with synthetic adapters and real state files:
automatic/static restoration, IPv6, partial writes, failed health checks, failure
to arm recovery, conflicting administrator edits, and interrupted setup. Native
SCM tests exercise the installed script's status/preview entry points. Actual
adapter writes, task execution after process termination/reboot, VPN attach,
and Ethernet/Wi-Fi roaming still need acceptance on disposable Windows 10/11 VMs.
