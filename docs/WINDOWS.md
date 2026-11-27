# Native Windows builds

The native build runs `dnsp-modern.c` on Windows x86-64 and ARM64. DNS parsing, cache,
failover, EDNS, limits, metrics, and libcurl connection management are shared
with Linux. There is no second resolver tree, Cygwin runtime, WSL requirement,
or protocol rewrite. `dnsp-platform.h` adapts the OS interfaces.

## Download and start

Windows AMD64 portable ZIPs are published from v4.0.3 onward. Open
[GitHub Releases](https://github.com/fantuz/DNSProxy/releases) and select the ZIP
matching **Settings → System → About → System type**:

| System type | Download |
| --- | --- |
| x64-based processor (Intel/AMD) | `dnsp-modern-VERSION-windows-amd64-poc.zip` |
| ARM-based processor (Windows 11 ARM64) | `dnsp-modern-VERSION-windows-arm64-poc.zip` |

Native Windows 11 ARM64 ZIPs are available from v4.5.0 onward; older Windows
releases contain only the AMD64 ZIP. The historical `-poc` suffix in ZIP names
is retained for compatibility with existing download automation.
Download **SHA256SUMS** from the same release as the ZIP. Check the ZIP's hash against its entry in `SHA256SUMS`:

```powershell
Get-FileHash .\dnsp-modern-4.0.3-windows-amd64-poc.zip -Algorithm SHA256
```

For a source snapshot, open a successful **DNSProxy modern - test and package**
Actions run and download **dnsp-modern-windows-amd64-poc** or
**dnsp-modern-windows-arm64-poc**, matching your processor. Each artifact
contains the portable ZIP and its `.zip.sha256` checksum file. Release v4.0.2
published only Linux packages; its Windows ZIP was uploaded to the corresponding
Actions run. CI artifacts are retained for 14 days.

Extract the portable ZIP into a folder, keeping the EXE, DLLs and CA bundle
together. MSYS2, Python, and development tools are only build/test dependencies.
`BUILD-INFO.txt` inside the ZIP identifies the version and exact source commit.

Double-click **Start-DNSProxy.cmd**. It listens on **127.0.0.1:53** and **[::1]:53**,
using UDP and TCP, and forwards to Cloudflare over HTTPS. It enables 256 cache slots and
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

## Desktop interface and console launchers

`Start-DNSProxy.cmd` opens the resolver in a console. `Start-DNSProxy.ps1`
accepts launch options and can request UAC elevation. Service installation and
DNS configuration use the PowerShell commands below. The setup wizard below
provides installation and service settings. The optional
[bundled desktop interface](DESKTOP-GUI.md) provides live traffic/latency charts,
grouped startup options and diagnostics on both Windows architectures.

## Standard setup installer

The resolver/service setup filenames are
`dnsp-modern-VERSION-windows-amd64-setup.exe` and
`dnsp-modern-VERSION-windows-arm64-setup.exe`. Choose the setup EXE matching your
processor and verify its checksum before running it. CI artifacts include an
`.exe.sha256` sidecar; release packages use `SHA256SUMS`. Setup requests administrator
elevation and installs into the protected `%ProgramFiles%\DNSProxy` directory.
It bundles the resolver, native DLLs, CA certificates, licenses and scripts;
Python, MSYS2 and a separate service wrapper are not required.

**Availability:** resolver/service and bundled desktop setup EXEs are release
assets from v4.10.0-modern onward. The desktop variant uses the filename
`dnsp-modern-VERSION-windows-ARCH-gui-setup.exe` and includes the private GUI
runtime. Successful Windows workflow runs also provide installer artifacts.
Each build records its source revision alongside the version. Release 4.11.0
adds the **Modify DNSProxy service** shortcut for service installations.
See the [4.11.0 release notes](releases/4.11.0.md).

The wizard adds Start Menu shortcuts and a single Windows Apps uninstall entry.
The **Register DNSProxy as a Windows service** checkbox is initially off. Leave it
off to use the console launcher, or select it to configure the background server:

| Option | Default | Effect |
| --- | --- | --- |
| DNS port | `53` | UDP and TCP listener port |
| HTTPS upstream URL | `https://cloudflare-dns.com/dns-query` | DoH endpoint, without embedded credentials |
| Numeric bootstrap IP | `1.1.1.1` | Address of that upstream, avoiding a DNS lookup loop |
| IPv6 loopback | Enabled | Also listen on `::1`, alongside `127.0.0.1` |
| Start automatically with Windows | Enabled | Automatic SCM startup; clearing it selects Manual |
| Start after installation | Enabled | Start now; clearing it leaves the new service stopped |
| Loopback metrics port | `0` in resolver/service setup; `9090` in desktop setup | Read-only traffic metrics on `127.0.0.1`; `0` disables the listener |

The service uses the existing native SCM adapter, `NT AUTHORITY\LocalService`,
restricted program/configuration permissions, crash recovery and rotating logs.
The service accepts DNS requests on loopback only. Installation adds no firewall
exception or adapter DNS change. A port conflict or invalid upstream/bootstrap setting blocks installation
before replacing files. Startup still performs its own listener checks; if a
fresh service fails to start, its registration/state are rolled back and setup
reports failure. Installed application files can remain for repair or removal.

Service installs show a **Windows Services** shortcut in place of the console
launcher, avoiding a second instance on the same port. Manage the service through
that shortcut, `Get-Service DNSProxy`, `Start-Service`
and `Stop-Service`. Logs are in `%ProgramData%\DNSProxy\logs\service.log`.
The console shortcut is provided when service registration is not selected.
The installed reversible DNS helper is
`%ProgramFiles%\DNSProxy\bin\Set-DNSProxyDns.ps1`. Its automatic adapter integration
requires an automatic service on port 53 and both loopback families. A custom
port, Manual startup or IPv4-only choice requires explicit client configuration.

### Modify an installed service

Open **Modify DNSProxy service** from the Start menu. The administrator dialog shows the registered DNS and metrics ports, upstream, bootstrap IP, listeners and startup type. Apply validates the proposed settings, restarts the service and checks a DNS reply on UDP and TCP on each configured listener. Choose a health-check name your upstream and filtering policy permit. A previously stopped service runs for the checks and returns to its stopped state.

The installed PowerShell command also accepts partial updates. Existing policy paths, logs, recovery actions and the service account are preserved. For a portable installation use the script installed directly under the service's Program Files directory and supply its service name.

```powershell
& "$env:ProgramFiles\DNSProxy\bin\Set-DNSProxyService.ps1" -MetricsPort 9090
& "$env:ProgramFiles\DNSProxy\bin\Set-DNSProxyService.ps1" -Upstream https://dns.google/dns-query -BootstrapAddress 8.8.8.8
```

A failed restart or DNS check restores the previous command, startup mode and running state. An interrupted modification leaves a recovery record in the protected service state directory. Rerun the command or use `-Recover` to restore it. Active adapter integration requires automatic startup, port 53, both loopback listeners and independent upstream resolution. The settings tool leaves adapter DNS configuration in place.

### Upgrade, cancellation and uninstall

Run the setup EXE for the target version in the existing location. The installer verifies ownership
before stopping an existing setup-managed service. It retains the exact service
command, startup mode, protected state and logs, and restores its previous
running/stopped state after replacing files. Existing-service options are retained
rather than reconfigured by the wizard or silent-install arguments. To change
those options, use **Modify DNSProxy service** with the desired
settings. Portable PowerShell installations are not silently adopted: restore DNS
and remove them with their original uninstall script first.

Cancelling the wizard before installation changes no service. An interrupted
upgrade attempts to resume a previously running owned service; durable resume
state is retained if that recovery fails. After resolving the file/startup error,
rerun setup or use the installed `Setup-DNSProxy.ps1 -Action Resume` as Administrator.
Obsolete files listed in the previous bundle's checksum manifest are removed
only if their contents are unchanged. Unowned/modified files are retained.

Remove the application through Windows Apps or **Uninstall DNSProxy** in the
Start Menu. Before any service stop/removal, upgrade and uninstall refuse an
active `dns-state.json` recovery record and show the DNS restore command. Restore
the managed adapter configuration and retry. Manually changed adapter settings
also need restoring; the installer cannot infer their previous values. Uninstall
removes the owned service, installed files and managed service state/logs. Copy
logs you need before uninstalling. It does not remove unrelated services or data.

### Unattended setup and build evidence

For an elevated deployment with the same wizard defaults, including dual-stack
loopback, automatic startup and immediate start:

```powershell
.\dnsp-modern-VERSION-windows-amd64-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SERVICE=1
```

Optional arguments are `/PORT=53`, `/UPSTREAM=https://dns.google/dns-query`,
`/BOOTSTRAP=8.8.8.8`, `/IPV6=0`, `/AUTOSTART=0`, `/STARTNOW=0` and
`/METRICSPORT=9090`. The metrics port must differ from the DNS port; `0` disables
metrics. The desktop setup variant includes the GUI component and its runtime.
Pass URL and matching bootstrap together. Omitting `/SERVICE=1` installs only
the application. Silent upgrades preserve an existing service automatically.
The destination is fixed in protected Program Files; conflicting `/DIR` values
are rejected. Nonzero setup exit codes indicate failure. Configuration is passed
through a data file, never interpolated into a PowerShell command.

CI compiles the wizard with pinned, SHA-256-verified Inno Setup 6.6.1. Both native
architectures run the real setup EXE with MSYS2 removed from PATH. Acceptance
opens/cancels the wizard and saves screenshots, checks the optional-service
default, service options, local HTTPS DNS queries, retained configuration and logs
on reinstall, stopped-service preservation, stale-file cleanup, ownership/port
conflicts, DNS-state guards and uninstall. Installer logs and screenshots are
retained in `dnsp-windows-installer-evidence-ARCH` for 14 days. Publication includes
the same tested installer bytes and requires both architectures to pass.

Setup EXEs, resolver binaries and PowerShell scripts are unsigned, as are the
portable bundles. They do not provide Authenticode publisher verification.

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
applications with their own DoH can select other resolvers. DNSProxy does not
enforce system-wide DNS routing. A public resolver configured as an alternate
Windows DNS server may receive queries directly; use DNSProxy's
`--backup-upstream` and matching `--backup-bootstrap-address` for encrypted
upstream failover instead.

**For foreground-only operation, restore the previous settings before stopping
DNSProxy or rebooting.** If
the adapter previously obtained DNS automatically:

```powershell
Set-DnsClientServerAddress -InterfaceIndex 12 -ResetServerAddresses
Clear-DnsClientCache
```

For previous static DNS, restore the recorded addresses with `-ServerAddresses`
instead. Resetting to DHCP does not restore static settings. The foreground
launcher does not change adapters. A persistent automatic service can retain
explicitly configured adapter settings across reboot; service installation and
reversible adapter integration are described separately below.

## Persistent Windows Service

From an **Administrator PowerShell** in the extracted ZIP:

```powershell
.\Install-DNSProxyService.ps1
Get-Service DNSProxy
Get-Content "$env:ProgramData\DNSProxy\logs\service.log" -Tail 30
Stop-Service DNSProxy
Start-Service DNSProxy
```

The PowerShell installer copies the bundle into `Program Files\DNSProxy`, registers an
SCM service with automatic startup, and starts it as `NT AUTHORITY\LocalService`.
It listens on `127.0.0.1:53` and `[::1]:53`, uses a numeric upstream bootstrap
address, and leaves adapter DNS settings unchanged. On an IPv6-disabled machine,
install with `-ListenAddress 127.0.0.1`. Optional parameters include `-Port`,
`-Upstream`, `-BootstrapAddress`, `-ServiceName`, `-StartupType`, `-MetricsPort`
and `-NoStart`. Metrics are disabled by default; `-MetricsPort 9090` enables a
read-only listener on `127.0.0.1:9090`.

Executable files are administrator-owned and read-only to LocalService. Only
`ProgramData\DNSProxy\logs` is service-writable. The console uses stderr;
service mode keeps `service.log` and one rotated log, targeting 4 MiB each.
Rotation checks occur once per second. Failed rotation or writes suspend new log
output and retry each second; DNS continues, and logging resumes when possible.
SCM restarts crashes **and reported nonzero service exits** after 3 seconds, then
10 seconds; further failures within the 24-hour reset period remain stopped.
Normal Stop-Service/shutdown exits are not restarted. Failed initial installation
still rolls back the service and its files.

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

Portable PowerShell installation refuses existing service names/directories,
and uninstall checks its installation record against SCM before removing
anything. Use the installed settings command for in-place reconfiguration. Upgrading portable binaries requires explicit uninstall/reinstall after restoring DNS. Setup-managed installations use the
upgrade and removal procedures in the setup section. Service files are unsigned.
Native CI tests real SCM startup/stop, LocalService HTTPS queries,
IPv4/IPv6 UDP and TCP, crash and reported-error recovery, log-rotation failure,
intentional stops, port conflicts, both portable launchers, and uninstall.

## Portability and validation overview

Optional domain/hosts filtering uses the shared C implementation. Install with
`-BlocklistFile` and optional `-AllowlistFile`; the installer copies and validates
the lists inside its protected `policy` directory. See [blocklists](BLOCKLISTS.md)
for formats, reply modes, automatic reloads, SCM control and the optional Python updater.


| Area | Windows build |
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
| Statistics | Shared loopback `/metrics`; POSIX `SIGUSR1` is available on Linux/macOS |
| Upstream transport | Packaged libcurl/OpenSSL with HTTP/2 and HTTP/3 |

GitHub builds AMD64 on `windows-2022` with MSYS2 UCRT64 GCC, and ARM64 on
`windows-11-arm` with MSYS2 CLANGARM64 Clang. Both compile the same C resolver
and use the same launchers, service adapter and DNS configuration scripts.
The package builder checks the PE machine type of the resolver and every
bundled third-party DLL, rejecting mixed architectures. It bundles recursive
PE DLL imports, licenses, CA certificates, source SHA, build package versions
and checksums. It runs the shared DNS integration suite (only the
POSIX signal test is skipped), local TLS HTTP/2 and HTTP/3 tests, and native
Windows acceptance on UDP/TCP port 53, `Resolve-DnsName`, exclusive binding,
and console shutdown. Runtime tests extract the ZIP into a path with spaces,
remove MSYS2 from PATH to detect missing DLLs, and check relocated default CA
discovery with both valid and invalid TLS hostnames. The required
**DNSProxy PR checks** status includes Windows when applicable.
The Linux packages and tests also validate changes to the shared core.

Both architecture bundles are unsigned native Windows builds, offered as portable
ZIPs and setup EXEs; no MSI/MSIX package is produced. CI executes the resolver,
Python protocol fixtures, platform
probes, and service acceptance on Windows Server 2022 AMD64 and Windows 11 ARM64.
It also verifies the extracted bundle's checksums and PE architecture.
On the ARM64 runner, the Python test driver uses x64 emulation because the QUIC
fixture's Python dependencies do not all supply compatible ARM64 wheels. The
resolver, platform probes, service fixture and bundled DLLs are ARM64-native;
their PE machine types are checked and the full product tests execute them on
the ARM64 host. The Python driver is a CI dependency, outside the portable ZIP.
The CI matrix does not establish coverage of every Windows 10/11 configuration,
account policy, Unicode/long path, suspend/resume sequence or VPN policy.
The shared resolver supports IPv4 and IPv6 DNS listeners. Repeat `-l` to enable
both, for example `-l 127.0.0.1 -l ::1 -p 53`. Both portable launchers enable
IPv4 and IPv6 loopback by default. On an IPv6-disabled machine, run the EXE
directly with `-l 127.0.0.1`. Test the listener before changing Windows DNS. IPv6 record types and upstream addresses remain independent of
the client transport family.

Windows wildcard UDP replies require an assigned source address. Unassigned
loopback aliases such as `127.0.0.2` are not supported for wildcard replies via
`IP_PKTINFO`. CI tests source preservation using `127.0.0.1` and an actual
adapter address (`DNSP_TEST_SECOND_ADDRESS`), without changing adapter settings.

The publishing workflow requires both Windows portable ZIPs, both resolver/service
setup EXEs, both desktop setup EXEs and both matching runtime-source ZIPs,
alongside eight Linux daemon packages, four Linux GUI packages and two macOS
archives. Native Windows/macOS, desktop, packaging and sanitizer checks gate
publication. Release v4.12.0-modern contains this set of twenty-two deliverables,
all covered by `SHA256SUMS`.

## Build from source

For AMD64, install MSYS2 and open a **UCRT64** shell:

```sh
pacman -Syu
pacman -S --needed git mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-curl \
  mingw-w64-ucrt-x86_64-pkgconf mingw-w64-ucrt-x86_64-python
bash scripts/build-windows.sh
```

For ARM64, use Windows 11 ARM64 and open MSYS2's **CLANGARM64** shell:

```sh
pacman -Syu
pacman -S --needed git mingw-w64-clang-aarch64-clang mingw-w64-clang-aarch64-curl \
  mingw-w64-clang-aarch64-pkgconf mingw-w64-clang-aarch64-python
bash scripts/build-windows.sh
```

MSYS2's Unix build tools use x64 emulation on ARM hosts; the Clang
compiler, resolver and bundled third-party DLLs are ARM64-native. The packaged
resolver needs neither emulation nor MSYS2 at runtime. ARM64 Windows 10 is not
in this acceptance matrix.

If MSYS2 asks to restart the shell during its update, do so and finish updating
first. Output is `dist/dnsp-modern-VERSION-windows-ARCH-poc.zip`, with `ARCH`
`amd64` or `arm64`. Keep the two architecture bundles in separate folders. Use the regular
OpenSSL curl package used by CI, whose capabilities are checked during the build.
The Linux `make modern` build is independent of this Windows toolchain.

## Reversible adapter DNS configuration

For a service installed from a portable ZIP using `Install-DNSProxyService.ps1`,
run the **installed** script in an elevated Windows PowerShell window as shown
below. For a setup-managed service, the corresponding path is
`%ProgramFiles%\DNSProxy\bin\Set-DNSProxyDns.ps1`; substitute that path for `$dns`
in the same example:

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

The service's bounded recovery handles crashes and reported runtime errors. A committed installation
does not silently switch to an unencrypted upstream if the service remains down;
use Restore to return control to the original DNS configuration.

CI exercises the transaction engine with synthetic adapters and real state files:
automatic/static restoration, IPv6, partial writes, failed health checks, failure
to arm recovery, conflicting administrator edits, and interrupted setup. Native
SCM tests exercise the installed script's status/preview entry points. Live
adapter writes, task execution after process termination/reboot, VPN attach
and Ethernet/Wi-Fi roaming are outside this automated qualification and require
validation on disposable Windows 10/11 VMs.
