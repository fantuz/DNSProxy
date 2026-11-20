"""Interval health diagnostics, restart boundaries and aggregate-only export."""

from dataclasses import replace
import json
import math
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
GUI_SOURCE = Path(os.environ.get("DNSP_GUI_SOURCE", BASE / "tools/desktop-gui"))
sys.path.insert(0, str(GUI_SOURCE))
from monitor import (  # noqa: E402
    DemoCollector,
    Invocation,
    LatencyWindow,
    Metrics,
    Process,
    Rates,
    Snapshot,
    parse_metrics,
    same_instance,
)
from telemetry import TelemetryWindow, diagnostic_report  # noqa: E402


def sample(at=1, *, uptime=100, process=None, **values):
    metrics = {
        ("dnsp_queries_total", (("transport", "udp"),)): 100,
        ("dnsp_queries_total", (("transport", "tcp"),)): 10,
        ("dnsp_uptime_seconds", ()): uptime,
    }
    for name, value in values.items():
        metrics[("dnsp_" + name, ())] = value
    return Snapshot(at, process, Metrics(metrics), 9090)


def with_labels(snapshot, name, value, **labels):
    samples = dict(snapshot.metrics.samples)
    samples[("dnsp_" + name, tuple(sorted(labels.items())))] = value
    return replace(snapshot, metrics=Metrics(samples))


class TelemetryTests(unittest.TestCase):
    def test_outcome_ratios_use_completions_not_started_attempts(self):
        window = TelemetryWindow()
        window.update(
            sample(
                upstream_requests_total=100,
                upstream_success_total=90,
                upstream_failures_total=10,
                upstream_timeouts_total=4,
            )
        )
        result = window.update(
            sample(
                at=3,
                uptime=102,
                upstream_requests_total=200,
                upstream_success_total=98,
                upstream_failures_total=12,
                upstream_timeouts_total=5,
            )
        )
        self.assertEqual(result.status, "live")
        self.assertEqual(result.elapsed, 2)
        self.assertEqual(result.counts["attempts"], 100)
        self.assertEqual(result.counts["completed"], 10)
        self.assertEqual(result.percentages["success"], 80)
        self.assertEqual(result.percentages["failure"], 20)
        self.assertEqual(result.percentages["timeout"], 10)

    def test_missing_is_unavailable_and_idle_is_not_zero_percent_success(self):
        window = TelemetryWindow()
        first = window.update(
            sample(upstream_success_total=90, upstream_failures_total=10)
        )
        self.assertIsNone(first.percentages["success"])
        result = window.update(
            sample(
                at=2, uptime=101, upstream_success_total=90, upstream_failures_total=10
            )
        )
        self.assertEqual(result.counts["completed"], 0)
        self.assertIsNone(result.percentages["success"])
        self.assertIsNone(result.counts["timeouts"])
        self.assertIsNone(result.percentages["timeout"])
        self.assertIsNone(result.percentages["reuse"])

    def test_cache_and_reuse_denominators(self):
        first = sample(
            cache_hits_total=100,
            cache_misses_total=100,
            upstream_success_total=100,
            upstream_failures_total=10,
            upstream_reused_requests_total=90,
        )
        second = sample(
            at=3,
            uptime=102,
            cache_hits_total=103,
            cache_misses_total=101,
            upstream_success_total=107,
            upstream_failures_total=11,
            upstream_reused_requests_total=96,
        )
        window = TelemetryWindow()
        window.update(first)
        result = window.update(second)
        self.assertEqual(result.percentages["cache_hit"], 75)
        self.assertEqual(result.percentages["reuse"], 75)

    def test_all_counters_above_double_precision_preserve_integer_deltas(self):
        base = 2**60
        first = with_labels(sample(), "queries_total", base, transport="udp")
        second = with_labels(
            sample(at=2, uptime=101), "queries_total", base + 1, transport="udp"
        )
        window = TelemetryWindow()
        window.update(first)
        result = window.update(second)
        self.assertEqual(result.counts["udp"], 1)
        self.assertIsInstance(result.counts["udp"], int)

    def test_capacity_uses_attempt_slots_including_hedges(self):
        result = TelemetryWindow().update(
            sample(
                cache_entries=12,
                cache_capacity=24,
                queries_inflight=4,
                upstream_attempts_inflight=8,
                queries_capacity=128,
                tcp_clients=32,
                tcp_clients_capacity=128,
            )
        )
        self.assertEqual(
            result.capacity_percentages, {"cache": 50, "attempts": 6.25, "tcp": 25}
        )
        disabled = TelemetryWindow().update(sample(cache_entries=0, cache_capacity=0))
        self.assertIsNone(disabled.capacity_percentages["cache"])

    def test_phase_average_and_protocol_role_population(self):
        first, second = sample(), sample(at=2, uptime=101)
        for version, before, after in (("1", 10, 11), ("2", 20, 23), ("3", 0, 0)):
            first = with_labels(
                first, "upstream_http_responses_total", before, version=version
            )
            second = with_labels(
                second, "upstream_http_responses_total", after, version=version
            )
        for suffix, before, after in (("count", 10, 12), ("sum", 1.0, 1.1)):
            first = with_labels(
                first, "upstream_phase_duration_seconds_" + suffix, before, phase="tls"
            )
            second = with_labels(
                second, "upstream_phase_duration_seconds_" + suffix, after, phase="tls"
            )
        for suffix, before, after in (
            ("requests", 10, 20),
            ("replies", 8, 12),
            ("failures", 2, 3),
        ):
            first = with_labels(
                first, "upstream_endpoint_" + suffix + "_total", before, role="backup"
            )
            second = with_labels(
                second, "upstream_endpoint_" + suffix + "_total", after, role="backup"
            )
        window = TelemetryWindow()
        window.update(first)
        result = window.update(second)
        self.assertAlmostEqual(result.phases["tls"], 0.05)
        self.assertIsNone(result.phases["queue"])
        self.assertEqual(result.protocol_percentages, {"1": 25, "2": 75, "3": 0})
        self.assertEqual(result.roles["backup"]["failure_percent"], 20)
        self.assertEqual(result.roles["backup"]["attempts"], 10)

    def test_missing_protocol_never_silently_implies_zero(self):
        first = with_labels(sample(), "upstream_http_responses_total", 10, version="2")
        second = with_labels(
            sample(at=2, uptime=101), "upstream_http_responses_total", 20, version="2"
        )
        window = TelemetryWindow()
        window.update(first)
        result = window.update(second)
        self.assertEqual(result.protocols["2"], 10)
        self.assertTrue(all(v is None for v in result.protocol_percentages.values()))

    def test_gap_and_reset_take_new_baseline(self):
        window = TelemetryWindow()
        first = sample(uptime=100, upstream_requests_total=10)
        window.update(first)
        result = window.update(replace(first, at=2, metrics=None))
        self.assertEqual(result.status, "gap")
        self.assertIsNone(result.gauges["uptime"])
        self.assertIsNone(result.roles["primary"]["attempts"])
        result = window.update(sample(at=3, uptime=102, upstream_requests_total=20))
        self.assertEqual(result.status, "baseline")
        self.assertIsNone(result.counts["attempts"])
        # Uptime detects a traffic-only restart even if counters exceed the old process.
        result = window.update(sample(at=4, uptime=1, upstream_requests_total=30))
        self.assertEqual(result.status, "reset")
        self.assertIsNone(result.counts["attempts"])
        result = window.update(sample(at=5, uptime=2, upstream_requests_total=32))
        self.assertEqual(result.counts["attempts"], 2)

    def test_other_counter_reset_invalidates_whole_interval(self):
        window = TelemetryWindow()
        window.update(sample(upstream_requests_total=10, cache_hits_total=100))
        result = window.update(
            sample(at=2, uptime=101, upstream_requests_total=20, cache_hits_total=1)
        )
        self.assertEqual(result.status, "reset")
        self.assertIsNone(result.counts["attempts"])

    def test_reset_on_identity_and_nonpositive_elapsed(self):
        process = Process(10, 123, 1, 1024, 100, Invocation())
        first = sample(process=process)
        window = TelemetryWindow()
        window.update(first)
        changed = sample(at=2, uptime=101, process=replace(process, start_ticks=124))
        self.assertEqual(window.update(changed).status, "reset")
        self.assertEqual(window.update(replace(changed, at=1)).status, "reset")

    def test_tcp_counter_labels(self):
        window = TelemetryWindow()
        first, second = sample(), sample(at=2, uptime=101)
        for reason, before, after in (("source_limit", 2, 5), ("capacity", 3, 4)):
            first = with_labels(
                first, "tcp_connections_rejected_total", before, reason=reason
            )
            second = with_labels(
                second, "tcp_connections_rejected_total", after, reason=reason
            )
        window.update(first)
        result = window.update(second)
        self.assertEqual(result.counts["tcp_rejected_source"], 3)
        self.assertEqual(result.counts["tcp_rejected_capacity"], 1)

    def test_impossible_ratio_is_unavailable_instead_of_clamped(self):
        window = TelemetryWindow()
        window.update(
            sample(
                upstream_success_total=1,
                upstream_failures_total=0,
                upstream_timeouts_total=0,
            )
        )
        result = window.update(
            sample(
                at=2,
                uptime=101,
                upstream_success_total=2,
                upstream_failures_total=0,
                upstream_timeouts_total=2,
            )
        )
        self.assertIsNone(result.percentages["timeout"])


class BoundaryAndExportTests(unittest.TestCase):
    def test_same_instance_when_older_endpoint_has_no_uptime(self):
        first = sample()
        metrics = dict(first.metrics.samples)
        del metrics[("dnsp_uptime_seconds", ())]
        first = replace(first, metrics=Metrics(metrics))
        second = replace(first, at=2)
        self.assertTrue(same_instance(first, second))

    def test_query_rates_reset_on_uptime_even_if_query_counters_grow(self):
        rates = Rates()
        rates.update(sample())
        second = with_labels(
            sample(at=2, uptime=1), "queries_total", 200, transport="udp"
        )
        self.assertEqual(rates.update(second), (None, None, None))

    def test_latency_window_resets_on_uptime_and_unrelated_counter_reset(self):
        window = LatencyWindow()
        first = sample(upstream_requests_total=100)
        window.update(first)
        window.update(sample(at=2, uptime=101, upstream_requests_total=101))
        self.assertEqual(len(window.history), 2)
        self.assertEqual(
            window.update(sample(at=3, uptime=1, upstream_requests_total=200)),
            (None, None),
        )
        self.assertEqual(len(window.history), 1)
        window.update(sample(at=4, uptime=2, upstream_requests_total=1))
        self.assertEqual(len(window.history), 1)

    def test_export_only_includes_aggregate_allowlist(self):
        invocation = Invocation()
        invocation.values["-s"] = (
            "https://user:SECRET@example.org/dns-query?token=HIDDEN",
        )
        process = Process(4242, 123, 1.5, 2048, 100, invocation)
        snap = sample(process=process)
        snap = with_labels(
            snap,
            "build_info",
            1,
            version="4.10.0",
            libcurl="8.14.1",
            http2="yes",
            http3="no",
            url="https://SECRET.example.org",
        )
        snap = replace(snap, error="/private/path SECRET")
        telemetry = TelemetryWindow().update(snap)
        report = diagnostic_report(snap, telemetry, now=4)
        output = json.dumps(report, allow_nan=False)
        self.assertEqual(report["sample_age_seconds"], 3)
        self.assertEqual(
            report["build"],
            {"http2": "yes", "http3": "no", "libcurl": "8.14.1", "version": "4.10.0"},
        )
        self.assertEqual(report["process"]["resident_memory_bytes"], 2048)
        for private in (
            "SECRET",
            "HIDDEN",
            "example.org",
            "4242",
            "/private/path",
            "argv",
        ):
            self.assertNotIn(private, output)

    def test_export_rejects_url_shaped_build_labels_and_nonfinite_native_values(self):
        process = Process(1, 2, math.inf, 2048, math.nan, Invocation())
        snap = with_labels(
            sample(process=process), "build_info", 1, version="https://SECRET"
        )
        report = diagnostic_report(snap, TelemetryWindow().update(snap), now=math.inf)
        self.assertEqual(report["build"], {})
        self.assertIsNone(report["process"]["cpu_seconds"])
        self.assertIsNone(report["process"]["uptime_seconds"])
        self.assertIsNone(report["sample_age_seconds"])
        json.dumps(report, allow_nan=False)

    def test_integer_parser_keeps_real_counter_precision(self):
        metrics = parse_metrics(
            b'dnsp_queries_total{transport="udp"} 1152921504606846977\n'
            b'dnsp_queries_total{transport="tcp"} 0\n'
        )
        self.assertEqual(metrics.get("dnsp_queries_total", transport="udp"), 2**60 + 1)

    def test_demo_exercises_interval_telemetry_without_network(self):
        with patch("monitor.time.monotonic", return_value=10):
            collector = DemoCollector()
        with patch("monitor.time.monotonic", return_value=11):
            first = collector.collect()
        with patch("monitor.time.monotonic", return_value=13):
            second = collector.collect()
        window = TelemetryWindow()
        window.update(first)
        result = window.update(second)
        self.assertEqual(result.status, "live")
        self.assertGreater(result.counts["attempts"], 0)
        self.assertIsNotNone(result.percentages["cache_hit"])
        self.assertIsNotNone(result.percentages["reuse"])
        self.assertGreater(result.phases["first_byte"], 0)
        self.assertEqual(result.gauges["queries_capacity"], 128)
        self.assertIsNotNone(result.roles["primary"]["replies"])


if __name__ == "__main__":
    unittest.main()
