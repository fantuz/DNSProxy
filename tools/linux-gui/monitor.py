"""Read-only Linux process and DNSProxy Prometheus collectors (no GTK dependency)."""

from dataclasses import dataclass, field
import http.client
import math
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit, urlunsplit

# Defaults are for the current C resolver, not discovered runtime values. Keep
# this schema in step with usage()/dnsp_run(); CI checks option coverage.
DEFAULTS = {
    "-l": ("127.0.0.1",),
    "-p": ("5300",),
    "-s": ("https://cloudflare-dns.com/dns-query",),
    "-m": (),
    "--backup-upstream": (),
    "--backup-bootstrap-address": (),
    "--bootstrap-address": (),
    "--ca-file": (),
    "--edns-padding": (),
    "--upstream-http": ("auto",),
    "--max-host-connections": ("8",),
    "--tcp-max-per-source": ("32",),
    "--tcp-idle-ms": ("15000",),
    "--tcp-io-ms": ("15000",),
    "--doh-connect-ms": ("1500",),
    "--doh-timeout-ms": ("3000",),
    "--cache-entries": ("0",),
    "--blocklist": (),
    "--allowlist": (),
    "--block-response": ("refused",),
    "--blocklist-reload-ms": ("5000",),
    "--udp-reply-max": ("1232",),
}
FLAGS = {"--edns-padding"}
REPEATABLE = {"-l", "--blocklist", "--allowlist"}
MAX_RESPONSE = 64 * 1024
METRIC = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^{}]*)\})?\s+(\S+)(?:\s+\d+)?")
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\[\\"n])*)"(?:,|$)')


@dataclass
class Invocation:
    values: dict = field(default_factory=lambda: dict(DEFAULTS))
    explicit: set = field(default_factory=set)
    unknown: list = field(default_factory=list)

    def get(self, option):
        return ", ".join(self.values.get(option, ())) or "Disabled / unset"

    def number(self, option):
        values = self.values.get(option, ())
        return int(values[-1]) if values else 0

    @property
    def metrics_port(self):
        port = self.number("-m")
        if not 0 <= port <= 65535:
            raise ValueError("Invalid metrics port in process arguments")
        return port or None

    def toggles(self):
        def has(key):
            return bool(self.values[key])

        policy = has("--blocklist")
        return {
            "UDP and TCP listeners": True,
            "Metrics listener": bool(self.metrics_port),
            "In-memory DNS cache": self.number("--cache-entries") > 0,
            "EDNS request padding": has("--edns-padding"),
            "Backup upstream": has("--backup-upstream"),
            "Primary bootstrap address": has("--bootstrap-address"),
            "Backup bootstrap address": has("--backup-bootstrap-address"),
            "Prefer HTTP/3 (with fallback)": self.get("--upstream-http") == "prefer-h3",
            "Custom CA bundle": has("--ca-file"),
            "Domain blocklists": policy,
            "Allowlist exceptions": has("--allowlist"),
            "Periodic blocklist checks": policy
            and self.number("--blocklist-reload-ms") > 0,
        }


def parse_invocation(argv):
    """Read argv, never run it or interpret it as a shell command."""
    result = Invocation()
    i = 1
    while i < len(argv):
        option = argv[i]
        value = None
        if option.startswith("--upstream-http="):
            option, value = option.split("=", 1)
        if option in FLAGS:
            result.values[option] = ("on",)
        elif option in DEFAULTS:
            if value is None:
                i += 1
                if i >= len(argv):
                    raise ValueError(f"Missing value for {option}")
                value = argv[i]
            if option in REPEATABLE and option in result.explicit:
                result.values[option] += (value,)
            else:
                result.values[option] = (value,)
        else:
            # Unknown arguments may contain credentials. Do not display values.
            result.unknown.append("Unrecognised argument")
            i += 1
            continue
        result.explicit.add(option)
        i += 1
    return result


def display_value(option, value):
    if option not in {"-s", "--backup-upstream"} or not value:
        return value
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{parts.port}" if parts.port is not None else ""
        return urlunsplit(
            (
                parts.scheme,
                host + port,
                parts.path,
                "[redacted]" if parts.query else "",
                "",
            )
        )
    except ValueError:
        return "[invalid URL]"


@dataclass(frozen=True)
class Process:
    pid: int
    start_ticks: int
    cpu_seconds: float
    memory_bytes: int
    uptime: float
    invocation: Invocation

    @property
    def identity(self):
        return self.pid, self.start_ticks


def read_process(pid, proc=Path("/proc")):
    if pid <= 0:
        raise ValueError("PID must be positive")
    root = proc / str(pid)
    # Verify the executable instead of trusting the mutable argv[0].
    executable = os.readlink(root / "exe").removesuffix(" (deleted)")
    if Path(executable).name != "dnsp-modern":
        raise ValueError(f"PID {pid} is not a dnsp-modern executable")
    stat = (root / "stat").read_text()
    fields = stat[stat.rindex(")") + 2 :].split()
    clock = os.sysconf("SC_CLK_TCK")
    boot_seconds = float((proc / "uptime").read_text().split()[0])
    start = int(fields[19])
    with (root / "cmdline").open("rb") as stream:
        command = stream.read(MAX_RESPONSE + 1)
    if len(command) > MAX_RESPONSE:
        raise ValueError("Process command line is too large")
    argv = [
        part.decode("utf-8", "replace") for part in command.rstrip(b"\0").split(b"\0")
    ]
    return Process(
        pid,
        start,
        (int(fields[11]) + int(fields[12])) / clock,
        max(0, int(fields[21])) * os.sysconf("SC_PAGE_SIZE"),
        max(0, boot_seconds - start / clock),
        parse_invocation(argv),
    )


def discover_pid(proc=Path("/proc")):
    found = []
    for directory in proc.iterdir():
        if directory.name.isdecimal():
            try:
                if (
                    Path(os.readlink(directory / "exe").removesuffix(" (deleted)")).name
                    == "dnsp-modern"
                ):
                    found.append(int(directory.name))
            except OSError:
                continue
    if len(found) > 1:
        raise ValueError("Multiple DNSProxy processes found; select one with --pid PID")
    return found[0] if found else None


@dataclass(frozen=True)
class Metrics:
    samples: dict

    def get(self, name, **labels):
        return self.samples.get((name, tuple(sorted(labels.items()))))


def parse_metrics(body):
    if len(body) > MAX_RESPONSE:
        raise ValueError("Metrics response exceeds 64 KiB")
    samples = {}
    for line in body.decode("utf-8", "strict").splitlines():
        if not line or line.startswith("#"):
            continue
        match = METRIC.fullmatch(line)
        if not match:
            raise ValueError("Malformed Prometheus sample")
        name, _braces, raw_labels, raw_value = match.groups()
        labels = {}
        pos = 0
        while raw_labels and pos < len(raw_labels):
            label = LABEL.match(raw_labels, pos)
            if not label or label[1] in labels:
                raise ValueError("Malformed Prometheus labels")
            labels[label[1]] = re.sub(
                r'\\([\\"n])', lambda m: "\n" if m[1] == "n" else m[1], label[2]
            )
            pos = label.end()
        if len(raw_value) > 32:
            raise ValueError("Metric number is too large")
        value = int(raw_value) if raw_value.isdecimal() else float(raw_value)
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid DNSProxy metric value")
        key = name, tuple(sorted(labels.items()))
        if key in samples:
            raise ValueError("Duplicate Prometheus sample")
        samples[key] = value
        if len(samples) > 512:
            raise ValueError("Too many Prometheus samples")
    metrics = Metrics(samples)
    if any(
        metrics.get("dnsp_queries_total", transport=t) is None for t in ("udp", "tcp")
    ):
        raise ValueError("Endpoint does not expose DNSProxy query counters")
    return metrics


def fetch_metrics(port, timeout=1.0):
    """Literal IPv4 loopback only, no proxies, redirects, or new server."""
    if not 1 <= port <= 65535:
        raise ValueError("Metrics port must be 1..65535")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request(
            "GET", "/metrics", headers={"Accept": "text/plain", "Connection": "close"}
        )
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"Metrics returned HTTP {response.status}")
        media = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if media not in ("text/plain", "application/openmetrics-text"):
            raise ValueError("Unexpected metrics content type")
        return parse_metrics(response.read(MAX_RESPONSE + 1))
    finally:
        connection.close()


@dataclass(frozen=True)
class Snapshot:
    at: float
    process: Process | None
    metrics: Metrics | None
    port: int | None
    error: str = ""

    @property
    def identity(self):
        return (self.process.identity if self.process else None), self.port


class Collector:
    def __init__(self, pid=None, metrics_port=None):
        self.pid = pid
        self.metrics_port = metrics_port
        self.pinned_identity = None

    def collect(self):
        process = None
        port = self.metrics_port
        try:
            pid = (
                self.pid
                if self.pid is not None
                else discover_pid()
                if port is None
                else None
            )
            if pid is not None:
                process = read_process(pid)
                if self.pid is not None:
                    if (
                        self.pinned_identity
                        and process.identity != self.pinned_identity
                    ):
                        process = None
                        raise ValueError(
                            "Selected PID was reused; reopen with the new PID"
                        )
                    self.pinned_identity = process.identity
                if port and port != process.invocation.metrics_port:
                    raise ValueError(
                        "Selected process does not use that metrics port; omit --pid for traffic-only monitoring"
                    )
                port = port or process.invocation.metrics_port
            elif port is None:
                raise ValueError(
                    "No DNSProxy process found. Start dnsp-modern, then refresh."
                )
            if port is None:
                return Snapshot(
                    time.monotonic(),
                    process,
                    None,
                    None,
                    "Metrics disabled. Start dnsp-modern with -m PORT for live traffic.",
                )
            metrics = fetch_metrics(port)
            # Process could exit/restart during the HTTP request. Never attribute
            # a sample to an old process identity or carry rates across restarts.
            if process and read_process(process.pid).identity != process.identity:
                raise ValueError(
                    "DNSProxy restarted during the sample; refresh to reconnect"
                )
            return Snapshot(time.monotonic(), process, metrics, port)
        except (OSError, ValueError, http.client.HTTPException) as error:
            return Snapshot(time.monotonic(), process, None, port, str(error))


class Rates:
    def __init__(self):
        self.previous = None

    def reset(self):
        self.previous = None

    def update(self, snapshot):
        old, self.previous = self.previous, snapshot
        if not old or old.identity != snapshot.identity:
            return None, None, None
        dt = snapshot.at - old.at
        if dt <= 0:
            return None, None, None
        cpu = None
        if snapshot.process and old.process:
            elapsed = snapshot.process.cpu_seconds - old.process.cpu_seconds
            if elapsed >= 0:
                cpu = 100 * elapsed / dt
        if not snapshot.metrics or not old.metrics:
            return None, None, cpu
        deltas = []
        for transport in ("udp", "tcp"):
            now = snapshot.metrics.get("dnsp_queries_total", transport=transport)
            before = old.metrics.get("dnsp_queries_total", transport=transport)
            if now is None or before is None or now < before:
                return None, None, cpu
            deltas.append(now - before)
        return sum(deltas) / dt, sum(deltas), cpu


class DemoCollector:
    """Clearly labelled synthetic data; never binds sockets or sends DNS."""

    def __init__(self):
        self.started = time.monotonic()
        self.invocation = parse_invocation(
            [
                "dnsp-modern",
                "-m",
                "9090",
                "--cache-entries",
                "256",
                "--edns-padding",
                "--blocklist",
                "/etc/dnsp-modern/deny.txt",
                "--backup-upstream",
                "https://dns.google/dns-query",
            ]
        )

    def collect(self):
        at = time.monotonic()
        elapsed = at - self.started
        count = 4200 + int(elapsed * 8)
        values = {
            'dnsp_queries_total{transport="udp"}': count,
            'dnsp_queries_total{transport="tcp"}': 180 + int(elapsed),
            "dnsp_queries_satisfied_total": count + 174 + int(elapsed),
            "dnsp_cache_hits_total": count // 3,
            "dnsp_cache_misses_total": count * 2 // 3,
            "dnsp_blocked_queries_total": 124,
            "dnsp_blocked_aliases_total": 9,
            "dnsp_queries_inflight": 2,
            "dnsp_tcp_clients": 3,
            "dnsp_upstream_requests_total": 2841,
            "dnsp_upstream_success_total": 2835,
            "dnsp_upstream_failures_total": 6,
            "dnsp_upstream_timeouts_total": 1,
            "dnsp_upstream_duration_seconds_sum": 64.35,
            "dnsp_upstream_duration_seconds_count": 2841,
            'dnsp_upstream_http_responses_total{version="1"}': 0,
            'dnsp_upstream_http_responses_total{version="2"}': 2835,
            'dnsp_upstream_http_responses_total{version="3"}': 0,
            "dnsp_upstream_new_connections_total": 4,
            "dnsp_upstream_reused_requests_total": 2837,
            'dnsp_upstream_endpoint_requests_total{role="primary"}': 2840,
            'dnsp_upstream_endpoint_requests_total{role="backup"}': 1,
            "dnsp_invalid_queries_total": 0,
            "dnsp_invalid_responses_total": 0,
            "dnsp_overload_total": 0,
            "dnsp_truncated_responses_total": 2,
            "dnsp_udp_queries_coalesced_total": 94,
            'dnsp_blocklist_entries{action="deny"}': 100000,
            'dnsp_blocklist_entries{action="allow"}': 12,
            "dnsp_blocklist_reload_failures_total": 0,
        }
        metrics = parse_metrics(
            "\n".join(f"{key} {value}" for key, value in values.items()).encode()
        )
        process = Process(
            0, 1, elapsed * 0.03, 19 * 1024 * 1024, 480 + elapsed, self.invocation
        )
        return Snapshot(at, process, metrics, 9090)
