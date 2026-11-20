"""Read-only desktop process and DNSProxy Prometheus collectors (no GTK dependency)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import http.client
import math
import os
from pathlib import Path
import re
import subprocess
import sys
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
    "--upstream-hedge-ms": ("0",),
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
    available: bool = True

    def get(self, option):
        if not self.available:
            return "Unavailable"
        return ", ".join(self.values.get(option, ())) or "Disabled / unset"

    def number(self, option):
        if not self.available:
            return 0
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
        result = {
            "UDP and TCP listeners": True,
            "Metrics listener": bool(self.metrics_port),
            "In-memory DNS cache": self.number("--cache-entries") > 0,
            "EDNS request padding": has("--edns-padding"),
            "Backup upstream": has("--backup-upstream"),
            "Delayed parallel upstream": self.number("--upstream-hedge-ms") > 0,
            "Primary bootstrap address": has("--bootstrap-address"),
            "Backup bootstrap address": has("--backup-bootstrap-address"),
            "Prefer HTTP/3 (with fallback)": self.get("--upstream-http") == "prefer-h3",
            "Custom CA bundle": has("--ca-file"),
            "Domain blocklists": policy,
            "Allowlist exceptions": has("--allowlist"),
            "Periodic blocklist checks": policy
            and self.number("--blocklist-reload-ms") > 0,
        }
        return result if self.available else dict.fromkeys(result)


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
    cpu_seconds: float | None
    memory_bytes: int | None
    uptime: float | None
    invocation: Invocation

    @property
    def identity(self):
        return self.pid, self.start_ticks


def _native_process(value):
    invocation = (
        parse_invocation(value.argv) if value.argv else Invocation(available=False)
    )
    return Process(
        value.pid,
        value.start_ticks,
        value.cpu_seconds,
        value.memory_bytes,
        value.uptime,
        invocation,
    )


def read_process(pid, proc=Path("/proc")):
    if sys.platform in {"win32", "darwin"} and proc == Path("/proc"):
        from platform_monitor import read_native_process

        return _native_process(read_native_process(pid))
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
    if sys.platform in {"win32", "darwin"} and proc == Path("/proc"):
        rows = list_instances()
        if len(rows) > 1:
            raise ValueError(
                "Multiple DNSProxy processes found; select one with --pid PID"
            )
        return rows[0].pid if rows else None
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


def list_instances(proc=Path("/proc")):
    """Bound the picker to readable, verified DNSProxy executables."""
    if sys.platform in {"win32", "darwin"} and proc == Path("/proc"):
        from platform_monitor import list_native_instances

        return tuple(_native_process(value) for value in list_native_instances())
    found = []
    for directory in proc.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            if (
                Path(os.readlink(directory / "exe").removesuffix(" (deleted)")).name
                != "dnsp-modern"
            ):
                continue
            found.append(read_process(int(directory.name), proc))
        except (OSError, ValueError):
            continue
        if len(found) == 128:
            break
    return tuple(sorted(found, key=lambda process: process.pid))


@dataclass(frozen=True)
class ServiceStatus:
    load: str
    active: str
    substate: str
    pid: int = 0
    result: str = ""
    manager: str = "Systemd"

    def describe(self, process=None):
        if self.load == "not-found":
            return "Service not installed"
        if self.load == "unavailable":
            return f"{self.manager} status unavailable"
        suffix = (
            " · another instance"
            if process and self.pid and process.pid != self.pid
            else ""
        )
        result = f" · {self.result}" if self.result and self.result != "success" else ""
        return f"{self.active} / {self.substate}{result}{suffix}"


def read_service():
    """Read fixed service properties, never invoke privileged service controls."""
    if sys.platform in {"win32", "darwin"}:
        from platform_monitor import read_native_service

        return ServiceStatus(**read_native_service())
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "dnsp-modern.service",
                "--no-pager",
                "--property=LoadState,ActiveState,SubState,MainPID,Result",
            ],
            capture_output=True,
            text=True,
            timeout=0.75,
            check=False,
        )
        if len(result.stdout) > 4096:
            raise ValueError("Oversized service status")
        properties = dict(
            line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
        )
        if result.returncode and properties.get("LoadState") != "not-found":
            raise ValueError("Service manager unavailable")
        states = [
            properties.get(name, "unknown")
            for name in ("LoadState", "ActiveState", "SubState")
        ]
        if any(not re.fullmatch("[a-z-]{1,32}", value) for value in states):
            raise ValueError("Invalid service status")
        pid = int(properties.get("MainPID", "0"))
        outcome = properties.get("Result", "")
        if not 0 <= pid <= 2147483647 or (
            outcome and not re.fullmatch("[a-z-]{1,32}", outcome)
        ):
            raise ValueError("Invalid service identity")
        return ServiceStatus(*states, pid, outcome)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ServiceStatus("unavailable", "unknown", "unknown")


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
    instances: tuple = ()
    service: ServiceStatus | None = None

    @property
    def identity(self):
        return (self.process.identity if self.process else None), self.port


class Collector:
    def __init__(self, pid=None, metrics_port=None, timeout=1.0):
        self.timeout = timeout
        self.pid = pid
        self.metrics_port = metrics_port
        self.pinned_identity = None
        self.instances = ()
        self.service = None
        self.status_at = None

    def collect(self):
        process = None
        port = self.metrics_port
        now = time.monotonic()
        if self.status_at is None or now - self.status_at >= 5:
            try:
                self.instances = list_instances()
            except (OSError, ValueError):
                self.instances = ()
            self.service = read_service()
            self.status_at = now

        def snapshot(metrics, error=""):
            return Snapshot(
                time.monotonic(),
                process,
                metrics,
                port,
                error,
                self.instances,
                self.service,
            )

        try:
            if self.pid is None and port is None and len(self.instances) > 1:
                raise ValueError(
                    "Multiple DNSProxy instances found. Choose one in the instance selector."
                )
            pid = self.pid
            if pid is None and port is None and self.instances:
                pid = self.instances[0].pid
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
                if port and not process.invocation.available:
                    raise ValueError(
                        "Cannot verify this PID's metrics port; omit --pid for traffic-only monitoring"
                    )
                if (
                    port
                    and process.invocation.available
                    and port != process.invocation.metrics_port
                ):
                    raise ValueError(
                        "Selected process does not use that metrics port; omit --pid for traffic-only monitoring"
                    )
                port = port or process.invocation.metrics_port
            elif port is None:
                raise ValueError(
                    "No DNSProxy process found. Start dnsp-modern, then refresh."
                )
            if port is None:
                if process and not process.invocation.available:
                    return snapshot(
                        None,
                        "Process settings are unavailable. Enter its loopback metrics port to monitor traffic.",
                    )
                return snapshot(
                    None,
                    "Metrics disabled. Start dnsp-modern with -m PORT for live traffic.",
                )
            metrics = fetch_metrics(port, self.timeout)
            # Process could exit/restart during the HTTP request. Never attribute
            # a sample to an old process identity or carry rates across restarts.
            if process and read_process(process.pid).identity != process.identity:
                raise ValueError(
                    "DNSProxy restarted during the sample; refresh to reconnect"
                )
            return snapshot(metrics)
        except (OSError, ValueError, http.client.HTTPException) as error:
            return snapshot(None, str(error))


def same_instance(previous, snapshot):
    """Check process identity and observable metrics epoch without guessing.

    Traffic-only monitoring has no PID identity: resolver uptime and monotonic
    counters provide restart evidence. Missing metrics do not prove a restart.
    """
    if previous is None or previous.identity != snapshot.identity:
        return False
    if previous.metrics is None or snapshot.metrics is None:
        return True
    before = previous.metrics.get("dnsp_uptime_seconds")
    current = snapshot.metrics.get("dnsp_uptime_seconds")
    if before is not None and current is not None and current < before:
        return False
    for key, value in snapshot.metrics.samples.items():
        name, _labels = key
        if name.endswith(("_total", "_count", "_sum", "_bucket")):
            old_value = previous.metrics.samples.get(key)
            if old_value is not None and value < old_value:
                return False
    return True


class Rates:
    def __init__(self):
        self.previous = None

    def reset(self):
        self.previous = None

    def update(self, snapshot):
        old, self.previous = self.previous, snapshot
        if not same_instance(old, snapshot):
            return None, None, None
        dt = snapshot.at - old.at
        if dt <= 0:
            return None, None, None
        cpu = None
        if (
            snapshot.process
            and old.process
            and snapshot.process.cpu_seconds is not None
            and old.process.cpu_seconds is not None
        ):
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


def _histogram(metrics, name, populations):
    combined = None
    bounds = None
    for population in populations:
        rows = {}
        for (metric, labels), count in metrics.samples.items():
            labels = dict(labels)
            if metric != name + "_bucket" or set(labels) != set(population) | {"le"}:
                continue
            if any(labels[key] != value for key, value in population.items()):
                continue
            try:
                bound = float(labels["le"])
            except ValueError:
                return None
            if (
                math.isnan(bound)
                or bound <= 0
                or bound in rows
                or not isinstance(count, int)
            ):
                return None
            rows[bound] = count
        if not rows or math.inf not in rows:
            return None
        current_bounds = tuple(sorted(rows))
        counts = tuple(rows[bound] for bound in current_bounds)
        if any(a > b for a, b in zip(counts, counts[1:])):
            return None
        if metrics.get(name + "_count", **population) != counts[-1]:
            return None
        if bounds is None:
            bounds, combined = current_bounds, counts
        elif bounds != current_bounds:
            return None
        else:
            combined = tuple(a + b for a, b in zip(combined, counts))
    return bounds, combined


def _percentiles(bounds, counts):
    if not counts[-1] or any(a > b for a, b in zip(counts, counts[1:])):
        return None
    values = []
    for quantile in (0.5, 0.95, 0.99):
        target = quantile * counts[-1]
        lower, before = 0.0, 0
        for upper, count in zip(bounds, counts):
            if count >= target:
                values.append(
                    math.inf
                    if math.isinf(upper)
                    else lower + (upper - lower) * (target - before) / (count - before)
                )
                break
            lower, before = upper, count
    return tuple(values)


class LatencyWindow:
    """Bounded histogram deltas over at most 60 sampling intervals, no query log."""

    def __init__(self):
        self.history = deque(maxlen=61)
        self.identity = None
        self.previous = None

    def reset(self):
        self.history.clear()
        self.identity = None
        self.previous = None

    def update(self, snapshot):
        if snapshot.metrics is None:
            self.reset()
            return None, None
        current = (
            _histogram(
                snapshot.metrics,
                "dnsp_client_duration_seconds",
                ({"transport": "udp"}, {"transport": "tcp"}),
            ),
            _histogram(snapshot.metrics, "dnsp_upstream_duration_seconds", ({},)),
        )
        if self.identity != snapshot.identity or (
            self.previous is not None
            and (
                not same_instance(self.previous, snapshot)
                or snapshot.at <= self.previous.at
            )
        ):
            self.reset()
        if self.history:
            for old, new in zip(self.history[-1], current):
                if (old is None) != (new is None) or (
                    old is not None
                    and new is not None
                    and (old[0] != new[0] or any(a > b for a, b in zip(old[1], new[1])))
                ):
                    self.reset()
                    break
        self.identity = snapshot.identity
        self.previous = snapshot
        self.history.append(current)
        if len(self.history) < 2:
            return None, None
        results = []
        for baseline, latest in zip(self.history[0], current):
            if baseline is None or latest is None or baseline[0] != latest[0]:
                results.append(None)
                continue
            delta = tuple(a - b for a, b in zip(latest[1], baseline[1]))
            results.append(_percentiles(latest[0], delta))
        return tuple(results)


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
        completed = 2841 + int(elapsed * 6)
        failures = 6 + int(elapsed / 30)
        successful = completed - failures
        backup_completed = 1 + int(elapsed / 10)
        connections = 4 + int(elapsed / 60)
        values = {
            'dnsp_queries_total{transport="udp"}': count,
            'dnsp_queries_total{transport="tcp"}': 180 + int(elapsed),
            "dnsp_queries_satisfied_total": count + 174 + int(elapsed),
            "dnsp_cache_hits_total": count // 3,
            "dnsp_cache_misses_total": count * 2 // 3,
            "dnsp_blocked_queries_total": 124 + int(elapsed / 30),
            "dnsp_blocked_aliases_total": 9,
            "dnsp_queries_inflight": 2,
            "dnsp_tcp_clients": 3,
            "dnsp_upstream_requests_total": completed + 2,
            "dnsp_upstream_success_total": successful,
            "dnsp_upstream_failures_total": failures,
            "dnsp_upstream_timeouts_total": 1 + int(elapsed / 60),
            "dnsp_upstream_duration_max_seconds": 0.6,
            "dnsp_upstream_duration_seconds_sum": completed * 0.05,
            "dnsp_upstream_duration_seconds_count": completed,
            'dnsp_upstream_http_responses_total{version="1"}': 15,
            'dnsp_upstream_http_responses_total{version="2"}': successful - 15,
            'dnsp_upstream_http_responses_total{version="3"}': 0,
            "dnsp_upstream_new_connections_total": connections,
            "dnsp_upstream_reused_requests_total": successful - connections,
            'dnsp_upstream_endpoint_requests_total{role="primary"}': completed
            + 2
            - backup_completed,
            'dnsp_upstream_endpoint_requests_total{role="backup"}': backup_completed,
            'dnsp_upstream_endpoint_replies_total{role="primary"}': successful
            - backup_completed,
            'dnsp_upstream_endpoint_replies_total{role="backup"}': backup_completed,
            'dnsp_upstream_endpoint_failures_total{role="primary"}': failures,
            'dnsp_upstream_endpoint_failures_total{role="backup"}': 0,
            'dnsp_upstream_hedge_wins_total{role="primary"}': 19 + int(elapsed / 10),
            'dnsp_upstream_hedge_wins_total{role="backup"}': 1 + int(elapsed / 30),
            "dnsp_upstream_hedges_started_total": 20
            + int(elapsed / 10)
            + int(elapsed / 30),
            "dnsp_upstream_hedges_suppressed_total": 2,
            "dnsp_upstream_hedges_cancelled_total": 19 + int(elapsed / 10),
            "dnsp_upstream_hedges_inflight": 0,
            "dnsp_uptime_seconds": 480 + elapsed,
            "dnsp_cache_entries": 96 + int(elapsed) % 12,
            "dnsp_cache_capacity": 256,
            "dnsp_upstream_attempts_inflight": 2,
            "dnsp_queries_capacity": 128,
            "dnsp_tcp_clients_capacity": 128,
            "dnsp_tcp_connections_accepted_total": 42 + int(elapsed / 20),
            "dnsp_tcp_connections_closed_total": 39 + int(elapsed / 20),
            'dnsp_tcp_connections_rejected_total{reason="source_limit"}': 0,
            'dnsp_tcp_connections_rejected_total{reason="capacity"}': 0,
            "dnsp_tcp_idle_timeouts_total": 2,
            "dnsp_tcp_io_timeouts_total": 0,
            "dnsp_invalid_queries_total": 0,
            "dnsp_invalid_responses_total": 0,
            "dnsp_overload_total": 0,
            "dnsp_truncated_responses_total": 2,
            "dnsp_udp_queries_coalesced_total": 94,
            'dnsp_blocklist_entries{action="deny"}': 100000,
            'dnsp_blocklist_entries{action="allow"}': 12,
            "dnsp_blocklist_generation": 3,
            "dnsp_blocklist_memory_bytes": 5400000,
            "dnsp_blocklist_age_seconds": 90 + elapsed,
            "dnsp_blocklist_reload_success_total": 3,
            "dnsp_blocklist_reload_failures_total": 0,
        }
        for code, replies in (
            ("NOERROR", count),
            ("NXDOMAIN", 174 + int(elapsed)),
            ("SERVFAIL", failures),
            ("REFUSED", 3),
            ("FORMERR", 0),
            ("NOTIMP", 0),
            ("BADVERS", 0),
            ("OTHER", 0),
        ):
            values[f'dnsp_client_responses_total{{rcode="{code}"}}'] = replies
        for phase, observations, duration in (
            ("queue", completed, 0.001),
            ("tls", connections, 0.012),
            ("first_byte", completed, 0.024),
        ):
            values[f'dnsp_upstream_phase_duration_seconds_count{{phase="{phase}"}}'] = (
                observations
            )
            values[f'dnsp_upstream_phase_duration_seconds_sum{{phase="{phase}"}}'] = (
                observations * duration
            )
        values[
            'dnsp_build_info{version="demo",libcurl="demo",http2="yes",http3="no"}'
        ] = 1
        for name, labels, observations, duration in (
            ("dnsp_client_duration_seconds", 'transport="udp",', count, 0.025),
            (
                "dnsp_client_duration_seconds",
                'transport="tcp",',
                180 + int(elapsed),
                0.025,
            ),
            ("dnsp_upstream_duration_seconds", "", completed, 0.05),
        ):
            for bound in (
                0.001,
                0.0025,
                0.005,
                0.01,
                0.025,
                0.05,
                0.1,
                0.25,
                0.5,
                1,
                2.5,
                5,
                10,
                60,
            ):
                values[f'{name}_bucket{{{labels}le="{bound:g}"}}'] = (
                    observations if bound >= duration else 0
                )
            values[f'{name}_bucket{{{labels}le="+Inf"}}'] = observations
            suffix = "{" + labels.rstrip(",") + "}" if labels else ""
            values[name + "_count" + suffix] = observations
            values[name + "_sum" + suffix] = observations * duration
        metrics = parse_metrics(
            "\n".join(f"{key} {value}" for key, value in values.items()).encode()
        )
        process = Process(
            0, 1, elapsed * 0.03, 19 * 1024 * 1024, 480 + elapsed, self.invocation
        )
        samples = dict(metrics.samples)
        for transport, maximum in (("udp", 0.08), ("tcp", 0.12)):
            samples[
                ("dnsp_client_duration_max_seconds", (("transport", transport),))
            ] = maximum
        return Snapshot(at, process, Metrics(samples), 9090)
