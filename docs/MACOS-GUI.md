# DNSProxy desktop GUI on macOS

The shared GTK 4 interface runs on Intel and Apple Silicon Macs. Native macOS
archives from release 4.10.0 onward include its Python modules under `gui/`
and an optional `Start-DNSProxy-GUI.command` launcher. The C resolver and its service helper
still link only to macOS system libraries; the console launcher and launchd
service do not require Homebrew, Python or GTK.

New native builds also include **DNSProxy.app**, a Finder entry point for the
same monitor. Both the Python modules and the native resolver are inside the
app. GTK and PyGObject come from the Mac’s Homebrew installation.

## Install the desktop dependencies

Install Homebrew, then run:

```sh
brew install gtk4 pygobject3
```

Download the native DNSProxy archive matching the Mac's processor from release
4.10.0 or later and verify it against that release's `SHA256SUMS`. CI artifacts
also provide the archives with accompanying checksum files. Extract
the complete archive. Keep `gui/`, `dnsp-modern` and
`Start-DNSProxy-GUI.command` together. The archive's
own checksum manifest covers every included source module and launcher.

If the archive contains **DNSProxy.app**, move it to Applications or
`~/Applications` and double-click it. At the first unidentified-developer
alert, use the [per-app approval steps](MACOS.md#download-and-start).
With the v4.11.1 archive, double-click **Start-DNSProxy-GUI.command**, or run
it in Terminal:

```sh
./Start-DNSProxy-GUI.command
```

The launcher finds Homebrew on PATH or in its usual Intel/Apple Silicon
locations, then selects a Homebrew Python able to import GTK 4, PyGObject and
Cairo. It does not replace system Python or change the user's global PATH.
If no compatible runtime is found, the launcher displays the dependency-install
command.
Use a native Homebrew interpreter for the Mac's processor. With an Intel Python
translated by Rosetta on Apple Silicon, CPU time and process uptime are shown
as unavailable because the native clock conversion cannot be verified. Traffic,
resident memory and process controls remain available.

The app uses an ad-hoc integrity signature. Developer identification and
notarization are explained in the [Mac guide](MACOS.md#download-approval-and-signing).

## Use the local resolver or connect to a service

Use **Resolver options…** and **Start resolver** to run a resolver owned by
that GUI window. The bundled executable is selected automatically.
**Stop launched resolver** stops that process. These actions do not install or
stop an existing launchd service or change system DNS.
Select nonconflicting local DNS and metrics ports when another resolver is
already running. A failed start, occupied port or missing executable is shown
in the GUI's diagnostics.

To observe an existing resolver, enable its loopback metrics listener with
`-m PORT` and connect to that port. For example:

```sh
./Start-DNSProxy-GUI.command --metrics-port 9090
```

The GUI's metrics requests stay on `127.0.0.1`; it does not expose a remote
management endpoint. Fields that cannot be inspected with the current user's
permissions are displayed as unavailable.

### Enable monitoring when installing the launchd service

The native helper accepts an explicit optional metrics port:

```sh
sudo ./dnsp-macos install --metrics-port 9090
```

An HTTPS upstream, numeric bootstrap IP and optional CA bundle remain supported:

```sh
sudo ./dnsp-macos install https://dns.google/dns-query 8.8.8.8 --metrics-port 9090
```

Omitting the option, or passing `--metrics-port 0`, keeps metrics disabled.
The metrics port must differ from the service's DNS port 53. The listener is
loopback only, and enabling it changes no adapter DNS settings. Existing
installations require explicit reconfiguration: restore any managed DNS state,
uninstall using the native helper and install again with the desired options.
See [service and reversible DNS integration](MACOS.md#persistent-launchd-service).

## Run from a source checkout

After building or obtaining a compatible native resolver, use:

```sh
tools/desktop-gui/dnsp-gui-macos --binary /absolute/path/dnsp-modern
```

The paths and arguments are passed directly, including paths containing spaces.
Use `--demo` for labelled synthetic data, or `--help` for connection and sampling
options. The application source remains shared with Linux and Windows.

## Native validation

The native macOS workflow runs on Intel and Apple Silicon runners. It checks
the C binaries' system-library dependencies, extracts the archive and verifies
its checksum manifest. After installing Homebrew GTK, it tests the packaged
launcher, native process adapters and real GTK interface against the bundled
resolver. CLI, launchd and protocol tests follow using the same extracted
executables. GTK scenarios use separate processes to satisfy AppKit's
application-lifetime requirements.

The workflow preserves screenshots, test results and Homebrew package versions
as `dnsp-macos-gui-evidence-ARCH` for 14 days. Launcher unit tests cover paths
with spaces, exact argv forwarding, compatible interpreter selection and clear
errors without requiring a Mac. Launchd acceptance also verifies the optional
metrics listener through real HTTP queries and rejects invalid/conflicting
metric port arguments before creating an installation.
