# Debian 13 slim OCI image

The image compiles the same `dnsp-modern.c` resolver used by the native packages.
It runs on **Linux AMD64 and ARM64**, including 64-bit Raspberry Pi installations.
Docker and Podman can run it; Windows/macOS need a Linux container runtime.
There is no separate resolver implementation or GUI inside the image.

The multi-stage build uses a pinned Debian 13 slim base, Debian's libcurl and
system CA certificates. Only the daemon, its runtime dependencies, a small
curl-based health check and license are copied into the runtime stage. The
compiler, Python, GTK and systemd are not installed there. HTTP/2 is the default;
the Debian 13 libcurl also supports optional HTTP/3 with HTTP/2 fallback.

## Build and try it

Registry publication starts with the first release containing the container
workflow. You can build the image from this checkout immediately:

```sh
docker build --tag dnsproxy:local .
docker run -d --name dnsproxy --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -p 127.0.0.1:5300:5300/udp -p 127.0.0.1:5300:5300/tcp dnsproxy:local
dig @127.0.0.1 -p 5300 example.com A
dig +tcp @127.0.0.1 -p 5300 example.com AAAA
docker logs dnsproxy
docker stop --time 10 dnsproxy
docker rm dnsproxy
```

For Podman, replace `docker` with `podman`. With rootless Docker/Podman, publish
host port 5300 as above; binding host port 53 may require host administrator
configuration. The process **inside** the container always runs as UID/GID
`10001:10001` and binds port 5300 without capabilities.

Published images use `ghcr.io/fantuz/dnsproxy`. Select an exact version, such as
`ghcr.io/fantuz/dnsproxy:MAJOR.MINOR.PATCH`, or pin the index digest printed in
the publishing workflow. Other tags are `MAJOR.MINOR`, `MAJOR` and `latest`.
Exact version tags are immutable; moving tags only advance to newer versions.
The runtime image includes its version, source revision and license in OCI labels.

## Docker Compose and port 53

The repository's `compose.yaml` publishes **UDP and TCP**, binds the host side
to IPv4 loopback, drops all capabilities and uses a read-only filesystem. For
a local build before the first registry image exists:

```sh
DNSP_IMAGE=dnsproxy:local docker compose up -d --build
dig @127.0.0.1 example.com
dig +tcp @127.0.0.1 example.com
docker compose logs --tail 50
docker compose down
```

Once a release image is available, use `docker compose pull` followed by
`docker compose up -d`. Override `DNSP_IMAGE` to pin a version or digest. If host
port 53 is occupied, use `DNSP_PORT=5300 docker compose up -d` and test with
`dig -p 5300`. Check existing listeners with `sudo ss -luntp '( sport = :53 )'`.
These commands do not modify the host's resolver settings.

To serve your LAN, change the host bind address in **both** Compose port mappings
to your chosen LAN address and restrict access to your clients at the firewall.
The default image listens on `0.0.0.0` **inside its isolated network namespace**;
host mappings control access from outside the container network. The default listener is
IPv4, so IPv6-disabled hosts can run it. Add an IPv6 `-l ADDRESS` only when both
the container runtime network and host support it; IPv6 upstream answers do not
require an IPv6 listener.

## Options, upstreams and blocklists

The default command is:

```sh
dnsp-modern -l 0.0.0.0 -p 5300 -m 9153 \
  -s https://cloudflare-dns.com/dns-query --bootstrap-address 1.1.1.1 \
  --cache-entries 256
```

The bootstrap IP avoids a DNS dependency on the resolver itself. The bounded
in-memory cache expires according to DNS TTLs/DoH Age and disappears on restart.
No persistent cache volume is needed.

Docker arguments after the image name, or Compose's `command`, **replace the
entire default command**. Repeat the listener, metrics and upstream options
you want to keep. For example, append the following `command` to the service
to opt into HTTP/3 and delayed backup requests:

```yaml
command:
  - -l
  - 0.0.0.0
  - -p
  - "5300"
  - -m
  - "9153"
  - -s
  - https://cloudflare-dns.com/dns-query
  - --bootstrap-address
  - 1.1.1.1
  - --backup-upstream
  - https://dns.google/dns-query
  - --backup-bootstrap-address
  - 8.8.8.8
  - --upstream-hedge-ms
  - "100"
  - --upstream-http=prefer-h3
  - --cache-entries
  - "256"
```

For blocklists, mount a directory read-only and add
`--blocklist /etc/dnsp/lists/deny.txt` to your full command:

```yaml
volumes:
  - ./lists:/etc/dnsp/lists:ro
```

The non-root UID must be able to traverse the directory and read its files.
Update lists on the host with the existing [blocklist updater](BLOCKLISTS.md),
which is intentionally kept outside the image. Mounting the **directory** lets
the daemon see atomic file replacements. Automatic reload remains enabled;
`docker compose kill -s SIGHUP dnsproxy` also requests a reload. For private
upstreams, mount a readable CA bundle and pass `--ca-file /path/in/container`.
Do not disable certificate verification.

## Health, logs, metrics and the desktop monitor

The daemon runs as PID 1, logs to stderr and exits cleanly on SIGTERM.
`docker compose logs -f` shows structured logs. `restart: unless-stopped`
restarts exited processes; Docker does not automatically restart a container
merely because its health status becomes unhealthy.

The health check reads the **container's loopback-only** `/metrics` endpoint.
It tests process/event-loop responsiveness without making public DNS requests;
it does not prove that an upstream or the Internet is currently reachable.
Check health and counters with:

```sh
docker inspect --format '{{.State.Health.Status}}' dnsproxy
docker compose exec dnsproxy curl -fsS --noproxy '*' http://127.0.0.1:9153/metrics
```

The `docker inspect` example uses the explicitly named `docker run` container
from the first example. For Compose, use its container ID from
`docker compose ps -q dnsproxy` instead.

If changing `-m`, set `DNSP_HEALTH_PORT` to the same port. If disabling metrics,
disable the health check too (`--no-healthcheck`, or Compose
`healthcheck: {disable: true}`). There is no health-driven dependency on curl's
environment proxy settings.

Publishing `9153:9153` in bridge mode will **not** make metrics reachable: the
daemon intentionally binds metrics to `127.0.0.1`. For the host's Linux desktop
monitor or Prometheus, an optional Linux-only setup is `--network host` with
the full command using `-l 127.0.0.1 -p 5300 -m 9153`. Omit port mappings in
that mode. The host can then read `http://127.0.0.1:9153/metrics`, and
`python3 tools/linux-gui/dnsp-gui.py --metrics-port 9153` displays it.
Use distinct metrics ports for additional instances. The monitor's process
inspection cannot discover startup options across a container's PID namespace;
it still displays metrics. Keep the GUI on the desktop.

## CI and registry publication

GitHub builds AMD64 and ARM64 on native runners, imports each OCI archive and
checks the imported image's configuration digest. Tests exercise published UDP
and TCP ports, A/AAAA/TXT/unknown RR forwarding, cache hits, EDNS truncation,
read-only directory reloads, non-root operation, health, clean shutdown and real
HTTP/2 and HTTP/3 multiplexing/reuse using local TLS fixtures.

The two tested archives are combined without rebuilding or changing their
manifest/configuration/layer bytes. Integrity checks reject mismatched source
revisions, versions, platforms and digests. A temporary local registry exercises
publication and retry behavior. The required **DNSProxy PR checks** gate includes
the applicable container jobs. Pull requests and snapshot merges upload the
`dnsp-oci-image` artifact without publishing registry tags. To try that artifact:

```sh
sha256sum -c dnsp-modern-linux.oci.tar.sha256
skopeo copy --override-arch amd64 oci-archive:dnsp-modern-linux.oci.tar docker-daemon:dnsproxy:ci
docker run --rm dnsproxy:ci --version
```

Use `--override-arch arm64` on ARM64. An OCI archive is not a Docker `save`
archive, so use `skopeo` to import it. Podman also accepts OCI archives with
`podman load -i dnsp-modern-linux.oci.tar`.

For a release, the existing package/sanitizer gates and container checks must
pass at the selected release commit. After the stable GitHub release is created,
a separate job with `packages: write` copies that same tested OCI index to GHCR
using `GITHUB_TOKEN` and verifies the registry digest. No registry credentials
are needed for PR builds. Staging `build-RUN-ATTEMPT` tags record uploads; stable
version tags cannot be replaced and aliases cannot roll back on an older rerun.

**One-time owner setting:** GitHub initially creates new container packages as
private. After the first publication, open the
[DNSProxy package settings](https://github.com/users/fantuz/packages/container/dnsproxy/settings),
set visibility to **Public**, and confirm the linked repository is
`fantuz/DNSProxy`. Allow that repository's Actions to write the package if it
was previously created outside this workflow. Confirm anonymous pulling from
a machine without registry credentials before announcing it.

Release builds refresh apt packages without the PR build cache. The Debian base
index is pinned in `Dockerfile`; refresh that digest and publish a new patch
release for future base/security updates. Exact version tags remain immutable.
OCI source labels and checked digests are included; cryptographic signatures,
SBOMs and build provenance attestations are follow-ups, not currently advertised.
