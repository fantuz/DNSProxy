"""Aggregate interval diagnostics; no GTK, query names or resolver controls."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
import time

from monitor import Metrics, same_instance


COUNTERS = {
    "udp": ("dnsp_queries_total", {"transport": "udp"}),
    "tcp": ("dnsp_queries_total", {"transport": "tcp"}),
    "satisfied": ("dnsp_queries_satisfied_total", {}),
    "cache_hits": ("dnsp_cache_hits_total", {}),
    "cache_misses": ("dnsp_cache_misses_total", {}),
    "blocked_queries": ("dnsp_blocked_queries_total", {}),
    "blocked_aliases": ("dnsp_blocked_aliases_total", {}),
    "coalesced": ("dnsp_udp_queries_coalesced_total", {}),
    "attempts": ("dnsp_upstream_requests_total", {}),
    "success": ("dnsp_upstream_success_total", {}),
    "failures": ("dnsp_upstream_failures_total", {}),
    "timeouts": ("dnsp_upstream_timeouts_total", {}),
    "new_connections": ("dnsp_upstream_new_connections_total", {}),
    "reused_requests": ("dnsp_upstream_reused_requests_total", {}),
    "overload": ("dnsp_overload_total", {}),
    "invalid_queries": ("dnsp_invalid_queries_total", {}),
    "invalid_responses": ("dnsp_invalid_responses_total", {}),
    "truncated": ("dnsp_truncated_responses_total", {}),
    "reload_success": ("dnsp_blocklist_reload_success_total", {}),
    "reload_failures": ("dnsp_blocklist_reload_failures_total", {}),
    "hedges_started": ("dnsp_upstream_hedges_started_total", {}),
    "hedges_suppressed": ("dnsp_upstream_hedges_suppressed_total", {}),
    "hedges_cancelled": ("dnsp_upstream_hedges_cancelled_total", {}),
    "tcp_rejected_source": (
        "dnsp_tcp_connections_rejected_total",
        {"reason": "source_limit"},
    ),
    "tcp_rejected_capacity": (
        "dnsp_tcp_connections_rejected_total",
        {"reason": "capacity"},
    ),
    "tcp_idle_timeouts": ("dnsp_tcp_idle_timeouts_total", {}),
    "tcp_io_timeouts": ("dnsp_tcp_io_timeouts_total", {}),
    "tcp_accepted": ("dnsp_tcp_connections_accepted_total", {}),
    "tcp_closed": ("dnsp_tcp_connections_closed_total", {}),
}

RCODES = (
    "NOERROR",
    "NXDOMAIN",
    "SERVFAIL",
    "REFUSED",
    "FORMERR",
    "NOTIMP",
    "BADVERS",
    "OTHER",
)

GAUGES = {
    "uptime": ("dnsp_uptime_seconds", {}),
    "cache_entries": ("dnsp_cache_entries", {}),
    "cache_capacity": ("dnsp_cache_capacity", {}),
    "attempts_inflight": ("dnsp_upstream_attempts_inflight", {}),
    "queries_inflight": ("dnsp_queries_inflight", {}),
    "queries_capacity": ("dnsp_queries_capacity", {}),
    "tcp_clients": ("dnsp_tcp_clients", {}),
    "tcp_capacity": ("dnsp_tcp_clients_capacity", {}),
    "blocklist_age": ("dnsp_blocklist_age_seconds", {}),
    "generation": ("dnsp_blocklist_generation", {}),
    "blocklist_memory": ("dnsp_blocklist_memory_bytes", {}),
    "deny_entries": ("dnsp_blocklist_entries", {"action": "deny"}),
    "allow_entries": ("dnsp_blocklist_entries", {"action": "allow"}),
}


def total(*values):
    """A missing counter is unavailable, never an implicit zero."""
    return None if any(value is None for value in values) else sum(values)


def percentage(numerator, denominator):
    if numerator is None or denominator is None or denominator <= 0:
        return None
    # A ratio above 100% means this pair did not describe the same population.
    # Keep that visible as unavailable instead of concealing it with a clamp.
    if numerator < 0 or numerator > denominator:
        return None
    return 100 * numerator / denominator


@dataclass(frozen=True)
class Telemetry:
    status: str
    elapsed: float | None = None
    counts: dict = field(default_factory=dict)
    percentages: dict = field(default_factory=dict)
    protocols: dict = field(default_factory=dict)
    protocol_percentages: dict = field(default_factory=dict)
    roles: dict = field(default_factory=dict)
    phases: dict = field(default_factory=dict)
    gauges: dict = field(default_factory=dict)
    capacity_percentages: dict = field(default_factory=dict)
    rcodes: dict = field(default_factory=dict)


class TelemetryWindow:
    """Compare adjacent good samples; pauses, failures and restarts need a baseline.

    Outcome percentages use completed attempts (success + failure), not requests
    started in that interval. Phase averages use each phase's own observations.
    Cancellations are not completed attempts, nor evidence of a failed endpoint.
    """

    def __init__(self):
        self.previous = None

    def reset(self):
        self.previous = None

    def update(self, snapshot):
        old, self.previous = self.previous, snapshot
        missing = snapshot.metrics is None
        metrics = snapshot.metrics if not missing else Metrics({})
        if missing:
            self.reset()
        gauges = {
            key: metrics.get(name, **labels) for key, (name, labels) in GAUGES.items()
        }
        capacity = {
            "cache": percentage(gauges["cache_entries"], gauges["cache_capacity"]),
            "attempts": percentage(
                gauges["attempts_inflight"], gauges["queries_capacity"]
            ),
            "tcp": percentage(gauges["tcp_clients"], gauges["tcp_capacity"]),
        }
        status = "gap" if missing else "baseline"
        elapsed = None
        if not missing and old and old.metrics:
            if not same_instance(old, snapshot) or snapshot.at <= old.at:
                status = "reset"
            else:
                status, elapsed = "live", snapshot.at - old.at

        def delta(name, labels=None):
            if elapsed is None:
                return None
            now = metrics.get(name, **(labels or {}))
            before = old.metrics.get(name, **(labels or {}))
            return None if now is None or before is None else now - before

        counts = {key: delta(name, labels) for key, (name, labels) in COUNTERS.items()}
        counts["queries"] = total(counts["udp"], counts["tcp"])
        counts["completed"] = total(counts["success"], counts["failures"])
        percentages = {
            "success": percentage(counts["success"], counts["completed"]),
            "failure": percentage(counts["failures"], counts["completed"]),
            "timeout": percentage(counts["timeouts"], counts["completed"]),
            "cache_hit": percentage(
                counts["cache_hits"],
                total(counts["cache_hits"], counts["cache_misses"]),
            ),
            "reuse": percentage(counts["reused_requests"], counts["completed"]),
            "blocked": percentage(counts["blocked_queries"], counts["queries"]),
            "coalesced": percentage(counts["coalesced"], counts["udp"]),
        }
        protocols = {
            version: delta("dnsp_upstream_http_responses_total", {"version": version})
            for version in ("1", "2", "3")
        }
        protocol_count = total(*protocols.values())
        protocol_percentages = {
            version: percentage(count, protocol_count)
            for version, count in protocols.items()
        }
        roles = {}
        for role in ("primary", "backup"):
            row = {
                key: delta(name, {"role": role})
                for key, name in (
                    ("attempts", "dnsp_upstream_endpoint_requests_total"),
                    ("replies", "dnsp_upstream_endpoint_replies_total"),
                    ("failures", "dnsp_upstream_endpoint_failures_total"),
                    ("wins", "dnsp_upstream_hedge_wins_total"),
                )
            }
            row["failure_percent"] = percentage(
                row["failures"], total(row["replies"], row["failures"])
            )
            roles[role] = row
        phases = {}
        for phase in ("queue", "tls", "first_byte"):
            count = delta(
                "dnsp_upstream_phase_duration_seconds_count", {"phase": phase}
            )
            duration = delta(
                "dnsp_upstream_phase_duration_seconds_sum", {"phase": phase}
            )
            phases[phase] = (
                duration / count
                if duration is not None and count is not None and count > 0
                else None
            )
        return Telemetry(
            status,
            elapsed,
            counts,
            percentages,
            protocols,
            protocol_percentages,
            roles,
            phases,
            gauges,
            capacity,
            {
                code: delta("dnsp_client_responses_total", {"rcode": code})
                for code in RCODES
            },
        )


def diagnostic_report(snapshot, telemetry, *, now=None):
    """Return an aggregate-only JSON value, without argv, URLs, paths or logs.

    Export age is explicit so a last good sample cannot appear current after a
    collection failure. Build labels are limited to known, token-shaped values.
    No resolver control, file access or network access is performed here.
    """
    now = time.monotonic() if now is None else now
    age = max(0, now - snapshot.at) if snapshot else None
    build = {}
    if snapshot and snapshot.metrics:
        for (name, labels), value in snapshot.metrics.samples.items():
            if name != "dnsp_build_info" or value != 1:
                continue
            for key, label in labels:
                if key in {"version", "libcurl", "http2", "http3"} and re.fullmatch(
                    r"[A-Za-z0-9._+-]{1,64}", label
                ):
                    build[key] = label
    process = snapshot.process if snapshot else None
    report = {
        "schema_version": 1,
        "sample_age_seconds": age,
        "build": build,
        "process": {
            "uptime_seconds": process.uptime if process else None,
            "cpu_seconds": process.cpu_seconds if process else None,
            "resident_memory_bytes": process.memory_bytes if process else None,
        },
        "interval": {
            "status": telemetry.status,
            "seconds": telemetry.elapsed,
            "counts": telemetry.counts,
            "client_response_codes": telemetry.rcodes,
            "percentages": telemetry.percentages,
            "protocols": telemetry.protocols,
            "protocol_percentages": telemetry.protocol_percentages,
            "roles": telemetry.roles,
            "mean_phase_seconds": telemetry.phases,
        },
        "gauges": telemetry.gauges,
        "capacity_percentages": telemetry.capacity_percentages,
    }

    def finite(value):
        # Native adapters may be unavailable. Invalid non-finite measurements
        # remain unavailable and cannot break standards-compliant JSON export.
        if isinstance(value, float) and not math.isfinite(value):
            return None
        if isinstance(value, dict):
            return {key: finite(item) for key, item in value.items()}
        return value

    return finite(report)
