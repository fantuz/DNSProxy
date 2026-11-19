# DNSProxy desktop interface

The optional GTK 4 interface provides the same traffic, latency, startup options
and diagnostics views on Linux, Windows and macOS. The C resolver remains
independent of Python/GTK. The desktop runs as an ordinary user and does not
install services or change adapter DNS settings.

This guide describes the current source tree and its CI artifacts. The release
asset list identifies the available desktop distributions. Release 4.9.0 contains
the earlier Linux interface; its assets exclude the Windows desktop installers
and Mac GUI launcher.

## Platform delivery

| Platform | Desktop delivery |
| --- | --- |
| Debian 13 / Ubuntu 22.04 and 24.04 | Optional `dnsp-modern-gui` DEB |
| Rocky Linux 9 | Optional architecture-independent GUI RPM |
| Windows x64 | `dnsp-modern-VERSION-windows-amd64-gui-setup.exe` |
| Windows 11 ARM64 | `dnsp-modern-VERSION-windows-arm64-gui-setup.exe` with native ARM64 runtime |
| macOS 15+, Intel and Apple Silicon | `Start-DNSProxy-GUI.command` in the matching CLI archive; Homebrew GTK/PyGObject |

The Windows desktop setup includes private Python/GTK libraries and adds a
**DNSProxy desktop** Start Menu shortcut. No separate Python or MSYS2
installation is required.
The optional desktop component can be omitted; the smaller resolver/service
setup EXEs and portable ZIPs remain available separately. The private runtime
has no role in running the Windows service. Installed program files remain in
protected Program Files; GUI caches and runtime-startup error reports use
`%LOCALAPPDATA%\DNSProxy`. Resolver output in the **Diagnostics** tab is held
in bounded memory.

Windows runtime licenses, package/version records, hashes and exact corresponding
source archives accompany the installer. The matching
`dnsp-modern-VERSION-windows-ARCH-gui-sources.zip` is provided for redistribution
and is not required to run the application. Verify downloads with the release's
`SHA256SUMS`. Setup EXEs and native binaries are currently unsigned.

On macOS, install `gtk4 pygobject3` with Homebrew before opening the launcher.
The launcher chooses a compatible Homebrew Python without replacing system
Python or changing the user's global environment. Its runtime dependencies are
external; a self-contained `.app` is not included. The native CLI requires no
Homebrew packages. See the [Mac desktop guide](MACOS-GUI.md).

## Monitor an existing resolver

Enable the resolver's loopback metrics listener with `-m PORT`, then enter that
port under **Local metrics port** and select **Connect**. **Disconnect** stops
monitoring that endpoint. It does not stop a separately started resolver.
Requests go only to `127.0.0.1`; HTTP proxies and redirects are not followed.

The Windows desktop shortcut initially tries port 9090. When installing a new
Windows service with GUI setup, the wizard offers a separate **Loopback metrics
port** field; 0 disables monitoring. Existing services retain their recorded
command and startup behavior when upgraded. Adding the GUI does not enable
metrics on an existing service. Choose the actual configured port or explicitly
reinstall with monitoring enabled after restoring any adapter DNS integration. The portable
service script also accepts `-MetricsPort PORT`.

The Mac service helper offers the same explicit choice:

```sh
sudo ./dnsp-macos install --metrics-port 9090
./Start-DNSProxy-GUI.command --metrics-port 9090
```

For source launches on Linux or a GTK-enabled Windows Python:

```sh
python3 tools/desktop-gui/dnsp-gui.py --metrics-port 9090
```

Use **Resolver instance** to select a readable local process, or `--pid PID` at
startup. Native process identity and executable paths are checked before
attributing CPU, memory and arguments. Another account's process information may
be unavailable; permission failures are displayed as unavailable. In that case
use traffic-only monitoring with an explicit metrics port. Configured service arguments are not treated as
proof of the currently running process's arguments.

Service state is read independently through systemd, Windows SCM or launchd.
These are read-only status queries. Service management continues through the
platform's explicit tools.

## Start a resolver owned by the window

Select **Resolver options…** to choose a native executable and edit grouped
listener, upstream, cache and filtering settings. File pickers select blocklists,
CA bundles and executables. **Validate and apply** rejects invalid values without
changing the current configuration. Unchanged redacted endpoint values retain
their original URL rather than overwriting hidden credentials/query parameters.

Use **Start resolver** in the Launch resolver tab. The default is DNS port 5300
with loopback metrics on 9090, avoiding a conflict with a service on port 53.
Linux/macOS ordinary-user launches require ports at least 1024; Windows permits
lower ports when they are available. Options apply only to the next owned launch.
They do not reconfigure another process or an installed service.

**Stop launched resolver** and closing the GUI stop/reap only the process owned
by that window. Graceful shutdown is attempted before bounded forced termination;
a forced stop is reported explicitly. Other resolvers and services remain
running. The **Diagnostics** tab keeps a bounded, selectable, URL-redacted log
and the actual startup/exit failure, including missing executables and port
conflicts. It is available even when no terminal was opened.

## Charts and sampling

The overview shows queries per second, traffic totals, cache/filtering state and
estimated latency percentiles. Query activity can show all queries, UDP or TCP.
The latency plot selects client reply p95 or completed upstream attempt p95.
Both plots appear side by side on a wide desktop and stack on a compact window,
with aligned panels and consistent gutters.

The default refresh interval is 0.5 seconds, adjustable from 0.25 to 30 seconds.
Collection happens off the GTK thread, with only one worker active at a time.
Histories and logs are bounded. Paused, unavailable or failed samples create
gaps; stale views retain their last known values. Closing
or unmapping the window stops automatic sampling. See the [Linux monitor guide](LINUX-GUI.md)
for histogram interpretation and metric meanings.

## Native validation and packaging

Native tests open actual GTK windows, resize both layouts, change settings,
exercise connection failures, generate local UDP/TCP DNS traffic, verify real
metrics/latency updates and check owned-process shutdown while an unrelated
resolver stays running. Each scenario has an isolated application process to
respect AppKit's lifecycle. Screenshots and structured results are retained as
CI artifacts. The Linux matrix also runs GTK and model regressions.

Windows runtime staging runs in parallel with native CLI validation. Desktop
setup is compiled from that run's already-tested CLI bundle and matching runtime;
the installed GUI is exercised before/after replacement with build-time runtime
paths unavailable. Tests check architecture, manifests, licenses/sources,
private-DLL loading, rejection of replacement while the GUI is running,
stale-file removal, retained user data, component opt-out and uninstall. Publication requires both
desktop installer jobs to pass and publishes their exact tested bytes.

Mac tests use the GUI source and launcher extracted from the actual release
archive, on both Intel and Apple Silicon. The functional CI matrix does not cover
all physical devices, mixed-DPI or multi-monitor configurations, accessibility
tools, or long-duration desktop sessions.
