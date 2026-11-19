"""Run under Xvfb: GTK rendering, on-demand sampling and the actual C daemon."""

import importlib.util
from dataclasses import replace
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import uuid

from test_gui_monitor import (
    BINARY,
    GUI_SOURCE,
    live_resolver,
    mixed_query_cases,
    MixedQueryDoH,
    send_mixed_query,
    metrics_endpoint,
    sample,
    send_query,
    unused_ports,
)

spec = importlib.util.spec_from_file_location("dnsp_gui", GUI_SOURCE / "dnsp-gui.py")
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
from monitor import Collector, DemoCollector, Invocation, Metrics  # noqa: E402


def monitoring_sample(at, *, factor=0, uptime=100, process=True):
    """Known interval populations, including failures that are not new attempts."""
    values = {
        ("dnsp_queries_total", (("transport", "udp"),)): 12 * factor,
        ("dnsp_queries_total", (("transport", "tcp"),)): 8 * factor,
        ("dnsp_upstream_requests_total", ()): 13 * factor,
        ("dnsp_upstream_success_total", ()): 8 * factor,
        ("dnsp_upstream_failures_total", ()): 2 * factor,
        ("dnsp_upstream_timeouts_total", ()): factor,
        ("dnsp_upstream_reused_requests_total", ()): 5 * factor,
        ("dnsp_cache_hits_total", ()): 3 * factor,
        ("dnsp_cache_misses_total", ()): factor,
        ("dnsp_blocked_queries_total", ()): 2 * factor,
        ("dnsp_blocked_aliases_total", ()): factor,
        ("dnsp_udp_queries_coalesced_total", ()): factor,
        ("dnsp_uptime_seconds", ()): uptime,
        ("dnsp_cache_entries", ()): 4,
        ("dnsp_cache_capacity", ()): 8,
        ("dnsp_upstream_attempts_inflight", ()): 1,
        ("dnsp_queries_capacity", ()): 128,
        ("dnsp_tcp_clients", ()): 2,
        ("dnsp_tcp_clients_capacity", ()): 128,
    }
    for version, count in (("1", 0), ("2", 10), ("3", 0)):
        values[("dnsp_upstream_http_responses_total", (("version", version),))] = (
            count * factor
        )
    for phase in ("queue", "tls", "first_byte"):
        labels = (("phase", phase),)
        values[("dnsp_upstream_phase_duration_seconds_count", labels)] = 2 * factor
        values[("dnsp_upstream_phase_duration_seconds_sum", labels)] = 0.04 * factor
    snapshot = sample(at=at)
    return replace(
        snapshot,
        process=snapshot.process if process else None,
        metrics=Metrics(values),
    )


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.Gio, cls.GLib, cls.Gtk = gui.load_gtk()
        import gi

        gi.require_version("GdkX11", "4.0")
        from gi.repository import GdkX11

        cls.GdkX11 = GdkX11

    def setUp(self):
        self.app = gui.build_application(gui.arguments(["--demo", "--interval", ".5"]))
        self.app.set_application_id("org.dnsproxy.LinuxMonitor.Test" + uuid.uuid4().hex)
        self.app.register(None)
        self.app.activate()
        self.window = self.app.window

    def tearDown(self):
        if self.window is not None:
            self.window.close()
        self.app.quit()
        self.pump(0.05)

    def pump(self, seconds):
        end = time.monotonic() + seconds
        context = self.GLib.MainContext.default()
        while time.monotonic() < end:
            while context.pending():
                context.iteration(False)
            time.sleep(0.005)

    def wait_for(self, condition, seconds=5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.pump(0.025)
            if condition():
                return
        self.fail("GTK condition did not become true")

    def screenshot(self, name):
        directory = os.environ.get("GUI_SCREENSHOTS")
        if directory:
            target = Path(directory)
            target.mkdir(parents=True, exist_ok=True)
            self.pump(0.2)
            window_id = self.GdkX11.X11Surface.get_xid(self.window.get_surface())
            subprocess.run(
                ["import", "-window", str(window_id), str(target / name)],
                check=True,
                timeout=10,
            )

    def test_demo_pause_on_demand_and_bounded_history(self):
        self.wait_for(
            lambda: self.window.snapshot is not None
            and self.window.values["rate"].get_text() != "—"
        )
        self.assertIn("DEMO", self.window.status.get_text())
        self.assertIn("MiB", self.window.values["memory"].get_text())
        self.screenshot("demo-overview.png")
        self.window.notebook.set_current_page(1)
        self.pump(0.1)
        grid = self.window.startup.get_first_child().get_next_sibling()
        child = grid.get_first_child()
        radios = []
        while child:
            if isinstance(child, self.Gtk.CheckButton):
                radios.append(child)
            child = child.get_next_sibling()
        self.assertEqual(len(radios), 2 * len(Invocation().toggles()))
        self.assertTrue(all(not radio.get_sensitive() for radio in radios))
        self.screenshot("demo-startup-options.png")
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        before = self.window.snapshot
        self.pump(0.7)
        self.assertIs(self.window.snapshot, before)
        self.window.refresh.emit("clicked")
        self.wait_for(lambda: self.window.snapshot is not before)
        # Many updates cannot grow the in-memory chart indefinitely.
        demo = DemoCollector()
        for _ in range(75):
            self.window.apply(demo.collect())
        self.assertEqual(len(self.window.history), 60)
        self.window.pause.set_active(False)
        self.assertIsNone(self.window.rates.previous)

    def test_recent_monitoring_uses_completed_attempts_and_cache_populations(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.window.apply(monitoring_sample(10))
        self.window.apply(monitoring_sample(12, factor=1, uptime=102))
        labels = self.window.values
        for key, expected in (
            ("sample_state", "Live interval"),
            ("sample_elapsed", "2.00 s"),
            ("recent_completed", "10"),
            ("recent_failure", "2 · 20.0%"),
            ("recent_timeout", "1 · 10.0%"),
            ("recent_http", "0 · 10 · 0"),
            ("recent_queue", "20.00 ms"),
            ("health_failure", "20.0%"),
            ("health_cache", "75.0%"),
            ("health_reuse", "50.0%"),
            ("cache_used", "4 / 8 · 50.0%"),
        ):
            self.assertEqual(labels[key].get_text(), expected, key)
        page = self.window.notebook.get_n_pages() - 1
        self.assertEqual(
            self.window.notebook.get_tab_label_text(
                self.window.notebook.get_nth_page(page)
            ),
            "Monitoring",
        )
        self.window.notebook.set_current_page(page)
        self.screenshot("monitoring-recent-interval.png")
        # An idle interval has real zero counts but no outcome denominator.
        self.window.apply(monitoring_sample(14, factor=1, uptime=104))
        self.assertEqual(labels["recent_completed"].get_text(), "0")
        self.assertEqual(labels["health_failure"].get_text(), "—")
        self.assertEqual(labels["health_cache"].get_text(), "—")

    def test_monitoring_export_marks_retained_sample_and_excludes_startup_secrets(self):
        from monitor import parse_invocation

        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        first = monitoring_sample(10)
        second = monitoring_sample(12, factor=1, uptime=102)
        secret = (
            "https://private-user:private-password@example.test/dns?token=private-token"
        )
        invocation = parse_invocation(
            [
                "/private/location/dnsp-modern",
                "-s",
                secret,
                "--blocklist",
                "/private/list",
            ]
        )
        second = replace(second, process=replace(second.process, invocation=invocation))
        self.window.apply(first)
        self.window.apply(second)
        self.window.apply(replace(second, at=13, metrics=None, error="Timed out"))
        self.assertTrue(self.window.monitoring_page.has_css_class("stale"))
        self.assertEqual(self.window.values["health_failure"].get_text(), "20.0%")
        report = self.window.monitoring_report()
        encoded = json.dumps(report, allow_nan=False)
        self.assertFalse(report["monitor"]["latest_sample_succeeded"])
        self.assertEqual(report["interval"]["counts"]["completed"], 10)
        self.assertGreaterEqual(report["sample_age_seconds"], 0)
        for forbidden in (
            "private-user",
            "private-password",
            "private-token",
            "/private/",
            "argv",
            "logs",
        ):
            self.assertNotIn(forbidden, encoded)
        # Recovery cannot make a rate out of traffic accumulated in the gap.
        self.window.apply(monitoring_sample(20, factor=10, uptime=110))
        self.assertEqual(self.window.values["health_failure"].get_text(), "—")
        self.assertFalse(self.window.monitoring_page.has_css_class("stale"))
        self.assertEqual(self.window.telemetry_frame.status, "baseline")

    def test_metrics_uptime_restart_resets_traffic_only_peak_and_interval(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.window.apply(monitoring_sample(10, process=False))
        self.window.apply(monitoring_sample(12, factor=1, uptime=102, process=False))
        self.assertEqual(self.window.values["peak_qps"].get_text(), "10")
        # New counters may already exceed the old counts when a daemon restarts.
        self.window.apply(monitoring_sample(14, factor=2, uptime=1, process=False))
        self.assertEqual(self.window.values["peak_qps"].get_text(), "—")
        self.assertEqual(self.window.values["health_failure"].get_text(), "—")
        self.assertEqual(len(self.window.history), 0)
        self.assertEqual(self.window.telemetry_frame.status, "reset")
        self.assertIn("new baseline", self.window.values["sample_state"].get_text())
        # A failed scrape clears the interval baseline; the last good uptime
        # still proves a subsequent restart even if every query count grew.
        self.window.apply(monitoring_sample(16, factor=3, uptime=5, process=False))
        resets = self.window.baseline_resets
        self.window.apply(
            replace(
                monitoring_sample(17, factor=3, uptime=6, process=False), metrics=None
            )
        )
        self.window.apply(monitoring_sample(18, factor=4, uptime=1, process=False))
        self.assertEqual(self.window.baseline_resets, resets + 1)
        self.assertEqual(self.window.values["peak_qps"].get_text(), "—")
        self.assertEqual(len(self.window.history), 0)

    def test_export_response_saves_private_valid_json_and_cancels_cleanly(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.window.apply(monitoring_sample(10))
        self.window.apply(monitoring_sample(12, factor=1, uptime=102))
        with tempfile.TemporaryDirectory(prefix="dnsp report ") as directory:
            target = Path(directory) / "monitoring.json"
            # Selecting a native filename belongs to the OS dialog. Exercise
            # its response boundary with a real Gio file and actual disk I/O.
            chooser = Mock()
            chooser.get_file.return_value = self.Gio.File.new_for_path(str(target))
            with patch.object(self.Gtk.FileChooserNative, "new", return_value=chooser):
                self.window.export_button.emit("clicked")
                callback = chooser.connect.call_args.args[1]
                callback(chooser, self.Gtk.ResponseType.ACCEPT)
            self.assertIsNone(self.window.export_dialog)
            report = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(report["interval"]["counts"]["completed"], 10)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                self.window.export_status.get_text(), "Monitoring snapshot exported"
            )
            with patch.object(self.Gtk.FileChooserNative, "new", return_value=chooser):
                self.window.export_button.emit("clicked")
                callback = chooser.connect.call_args.args[1]
                callback(chooser, self.Gtk.ResponseType.CANCEL)
            self.assertIsNone(self.window.export_dialog)

    def test_time_axis_gaps_and_balanced_panels(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.window.apply(sample(at=10, udp=10))
        self.window.apply(sample(at=10.25, udp=12))
        self.assertEqual(self.window.values["rate"].get_text(), "8.0")
        self.assertEqual(list(self.window.history_times), [10.25])
        held = list(self.window.history)
        self.window.apply(replace(sample(at=10.5), metrics=None))
        self.assertEqual(list(self.window.history), held)
        self.window.apply(sample(at=10.75, udp=100))
        self.window.apply(sample(at=11, udp=102))
        self.assertIn(None, self.window.history)
        self.assertEqual(len(self.window.history), len(self.window.history_times))
        self.assertEqual(self.window.history_times[-1], 11)
        for width, height in ((1120, 920), (800, 680)):
            self.window.set_default_size(width, height)
            self.pump(0.3)
            self.assertTrue(self.window.notebook.get_scrollable())
            if width == 800:
                self.assertLessEqual(self.window.get_width(), 810)
            self.assertGreaterEqual(self.window.chart.get_content_height(), 160)
            self.assertLessEqual(self.window.chart.get_content_height(), 240)
            self.assertGreater(
                self.window.chart.get_width(),
                self.window.chart.get_height()
                * (2.3 if self.window.charts_wide else 3),
            )
            query = self.window.chart_panel.get_parent().get_allocation()
            latency = self.window.latency_panel.get_parent().get_allocation()
            if self.window.charts_wide:
                self.assertEqual(query.y, latency.y)
                self.assertGreaterEqual(latency.x, query.x + query.width)
            else:
                self.assertGreaterEqual(latency.y, query.y + query.height)
            grid = self.window.information_grid
            for row in (0, 1):
                left, right = grid.get_child_at(0, row), grid.get_child_at(1, row)
                self.assertTrue(left.has_css_class("info-panel"))
                self.assertEqual(left.get_allocation().y, right.get_allocation().y)
                self.assertEqual(left.get_height(), right.get_height())
            self.screenshot(f"balanced-overview-{width}.png")
        viewport = self.window.notebook.get_nth_page(0)
        adjustment = viewport.get_vadjustment()
        adjustment.set_value(adjustment.get_upper() - adjustment.get_page_size())
        self.pump(0.1)
        self.screenshot("balanced-information-panels.png")

    def test_quarter_second_sampling_updates_without_a_backlog(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        calls = []
        collector = self.window.collector

        class CountingCollector:
            def collect(self):
                calls.append(time.monotonic())
                return collector.collect()

        self.window.collector = CountingCollector()
        self.window.preference_spins["interval"].set_value(0.25)
        self.window.pause.set_active(False)
        self.pump(1.1)
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.assertGreaterEqual(len(calls), 3)
        self.assertLessEqual(len(calls), 5)
        self.assertTrue(all(b - a >= 0.2 for a, b in zip(calls, calls[1:])))

    def test_stalled_http_keeps_main_loop_responsive_and_one_worker(self):
        with metrics_endpoint() as server:
            server.delay = 0.8
            self.window.collector = Collector(metrics_port=server.server_port)
            self.window.request_sample()
            self.pump(0.05)
            start = time.monotonic()
            for _ in range(20):
                self.window.request_sample(force=True)
                self.window.notebook.set_current_page(1)
                self.window.notebook.set_current_page(0)
            self.assertLess(time.monotonic() - start, 0.3)
            self.assertTrue(self.window.busy)
            self.wait_for(lambda: self.window.snapshot is not None)
            self.assertLessEqual(len(server.requests), 2)

    def test_actual_dns_queries_appear_and_gui_close_leaves_daemon_running(self):
        with live_resolver() as (process, port, _metric):
            self.window.close()
            self.app.quit()
            self.pump(0.05)
            self.app = gui.build_application(
                gui.arguments(["--pid", str(process.pid), "--interval", ".5"])
            )
            self.app.set_application_id(
                "org.dnsproxy.LinuxMonitor.Test" + uuid.uuid4().hex
            )
            self.app.register(None)
            self.app.activate()
            self.window = self.app.window
            self.window.request_sample()
            self.wait_for(lambda: self.window.snapshot is not None)
            before = self.window.snapshot.metrics.get(
                "dnsp_queries_total", transport="udp"
            )
            for _ in range(4):
                send_query(port)
            self.window.refresh.emit("clicked")
            self.wait_for(
                lambda: self.window.snapshot.metrics.get(
                    "dnsp_queries_total", transport="udp"
                )
                >= before + 4
            )
            self.assertEqual(self.window.values["pid"].get_text(), str(process.pid))
            self.assertIn("Receiving metrics", self.window.status.get_text())
            self.screenshot("live-daemon-overview.png")
            self.window.set_default_size(800, 680)
            self.screenshot("live-daemon-compact.png")
            self.window.close()
            self.assertIsNone(process.poll())
            send_query(port)
            self.window = None

    def test_one_25_query_pass_with_five_nxdomains_keeps_numbers_visible(self):
        with live_resolver(handler=MixedQueryDoH) as (process, port, _metric):
            self.window.close()
            self.app.quit()
            self.pump(0.05)
            self.app = gui.build_application(
                gui.arguments(["--pid", str(process.pid), "--interval", ".5"])
            )
            self.app.set_application_id(
                "org.dnsproxy.LinuxMonitor.Test" + uuid.uuid4().hex
            )
            self.app.register(None)
            self.app.activate()
            self.window = self.app.window
            self.wait_for(
                lambda: self.window.snapshot is not None
                and self.window.snapshot.metrics is not None
                and self.window.values["rate"].get_text() != "—"
            )
            baseline = self.window.snapshot.metrics.get("dnsp_queries_satisfied_total")
            changes, samples = [], []
            for key in ("udp", "satisfied", "rate", "latency"):
                self.window.values[key].connect(
                    "notify::label",
                    lambda label, prop, key=key: changes.append(
                        (key, label.get_text())
                    ),
                )
            apply = self.window.apply

            def observe(snapshot):
                samples.append(snapshot.metrics is not None)
                apply(snapshot)

            self.window.apply = observe
            errors, replies = [], []
            stop = threading.Event()

            def queries():
                try:
                    for case in mixed_query_cases():
                        if stop.is_set():
                            break
                        replies.append(send_mixed_query(port, case))
                        stop.wait(
                            0.08
                        )  # One pass, one outstanding request, at most 12.5 QPS.
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=queries, daemon=True)
            worker.start()
            try:
                self.wait_for(lambda: not worker.is_alive(), seconds=15)
                self.assertEqual(errors, [])
                self.assertEqual(len(replies), 25)
                self.assertEqual(replies.count(3), 5)
                self.wait_for(
                    lambda: self.window.snapshot.metrics is not None
                    and self.window.snapshot.metrics.get("dnsp_queries_satisfied_total")
                    == baseline + 25
                )
                self.assertGreaterEqual(len(samples), 3)
                self.assertTrue(all(samples))
                self.assertTrue(changes)
                self.assertFalse(
                    any(value in ("", "—") for _, value in changes), changes
                )
                self.assertEqual(
                    self.window.values["satisfied"].get_text(), str(int(baseline + 25))
                )
                self.assertIn("Receiving metrics", self.window.status.get_text())
                self.screenshot("modest-25-query-nxdomain.png")
            finally:
                stop.set()
                worker.join(timeout=3)

    def test_connection_failure_holds_frame_history_and_recovers_without_rate_spike(
        self,
    ):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        first, second = sample(at=10), sample(at=11, udp=30)
        self.window.apply(first)
        self.window.apply(second)
        before = {key: label.get_text() for key, label in self.window.values.items()}
        history = list(self.window.history)
        startup = self.window.startup.get_first_child()
        changes = []
        for key, label in self.window.values.items():
            label.connect(
                "notify::label", lambda label, prop, key=key: changes.append(key)
            )
        for at, process in ((12, second.process), (13, None), (14, second.process)):
            self.window.apply(
                replace(second, at=at, process=process, metrics=None, error="Timed out")
            )
        self.assertEqual(
            {key: value for key, value in before.items() if key != "sample_state"},
            {
                key: label.get_text()
                for key, label in self.window.values.items()
                if key != "sample_state"
            },
        )
        self.assertEqual(changes, ["sample_state"])
        self.assertIn("No fresh metrics", self.window.values["sample_state"].get_text())
        self.assertEqual(list(self.window.history), history)
        self.assertIs(self.window.startup.get_first_child(), startup)
        self.assertEqual(self.window.last_success, 11)
        self.assertIn("No fresh data", self.window.status.get_text())
        self.screenshot("stale-data-retained.png")
        self.window.apply(sample(at=15, udp=999))
        self.assertEqual(self.window.values["rate"].get_text(), before["rate"])
        self.assertIn("baseline", self.window.activity.get_text())
        self.window.apply(sample(at=16, udp=1009))
        self.assertEqual(self.window.values["rate"].get_text(), "10.0")
        self.assertEqual(self.window.values["peak_qps"].get_text(), "20")
        self.assertEqual(self.window.values["missed"].get_text(), "3")
        # A confirmed new process must never inherit a stale frame or peaks.
        self.window.apply(sample(at=17, pid=2, start=200))
        self.assertEqual(self.window.values["rate"].get_text(), "—")
        self.assertEqual(self.window.values["peak_qps"].get_text(), "—")
        self.assertEqual(len(self.window.history), 0)

    def test_http_timeout_preserves_frame_and_main_loop_recovers(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        with metrics_endpoint() as server:
            self.window.collector = Collector(
                metrics_port=server.server_port, timeout=0.2
            )
            self.window.request_sample(force=True)
            self.wait_for(
                lambda: self.window.snapshot is not None
                and self.window.snapshot.port == server.server_port
            )
            self.assertEqual(self.window.values["udp"].get_text(), "10")
            server.delay = 0.8
            self.window.request_sample(force=True)
            start = time.monotonic()
            self.window.notebook.set_current_page(2)
            self.window.notebook.set_current_page(0)
            self.pump(0.04)
            self.assertLess(time.monotonic() - start, 0.3)
            self.wait_for(lambda: not self.window.busy)
            self.assertIsNone(self.window.snapshot.metrics)
            self.assertEqual(self.window.values["udp"].get_text(), "10")
            self.assertIn("No fresh data", self.window.status.get_text())
            server.delay = 0
            self.window.request_sample(force=True)
            self.wait_for(lambda: not self.window.busy)
            self.assertIsNotNone(self.window.snapshot.metrics)
            self.assertIn("Receiving metrics", self.window.status.get_text())

    def test_process_load_remains_available_without_metrics(self):
        self.window.pause.set_active(True)
        self.wait_for(lambda: not self.window.busy)
        self.window.apply(replace(sample(at=10), metrics=None))
        self.window.apply(replace(sample(at=11, cpu=0.3), metrics=None))
        self.assertEqual(self.window.values["cpu"].get_text(), "20.0%")
        self.assertEqual(self.window.values["uptime"].get_text(), "0h 00m 30s")
        self.assertEqual(self.window.values["pid"].get_text(), "1")
        self.assertIn("MiB", self.window.values["memory"].get_text())
        self.assertEqual(self.window.values["udp"].get_text(), "—")

    def test_preferences_and_launch_validation_in_demo(self):
        self.window.preference_spins["interval"].set_value(2.5)
        self.window.preference_spins["timeout"].set_value(0.4)
        self.window.preference_spins["history"].set_value(20)
        self.window.auto_refresh.set_active(False)
        self.window.show_chart.set_active(False)
        self.assertEqual(self.window.interval, 2.5)
        self.assertEqual(self.window.timeout, 0.4)
        self.assertEqual(self.window.history.maxlen, 20)
        self.assertTrue(self.window.pause.get_active())
        self.assertFalse(self.window.chart.get_visible())
        self.window.launch_checks["padding"].set_active(True)
        self.assertIn("--edns-padding", self.window.preview_launch())
        self.assertFalse(self.window.start_button.get_sensitive())
        self.window.launch_entries["port"].set_text("53")
        self.assertIsNone(self.window.preview_launch())
        self.assertIn("1024", self.window.launch_status.get_text())
        self.window.notebook.set_current_page(2)
        self.screenshot("monitor-preferences.png")

    def test_launch_and_stop_only_own_resolver(self):
        with live_resolver() as (existing, existing_port, _):
            self.window.close()
            self.app.quit()
            self.pump(0.05)
            self.app = gui.build_application(gui.arguments(["--paused"]))
            self.app.set_application_id(
                "org.dnsproxy.LinuxMonitor.Test" + uuid.uuid4().hex
            )
            self.app.register(None)
            self.app.activate()
            self.window = self.app.window
            port, metric = unused_ports()
            for key, value in (
                ("binary", str(BINARY)),
                ("port", str(port)),
                ("metrics_port", str(metric)),
            ):
                self.window.launch_entries[key].set_text(value)
            self.window.start_resolver()
            child = self.window.owned_process
            self.assertIsNotNone(child)
            try:
                self.window.pause.set_active(False)
                self.window.preference_spins["interval"].set_value(0.5)
                self.wait_for(
                    lambda: self.window.snapshot is not None
                    and self.window.snapshot.metrics is not None
                )
                self.assertEqual(self.window.snapshot.process.pid, child.pid)
                self.assertIn(
                    "metrics responding", self.window.launch_status.get_text()
                )
                self.window.notebook.set_current_page(3)
                self.screenshot("launch-resolver.png")
                self.window.stop_resolver()
                self.wait_for(lambda: child.poll() is not None)
                self.assertIsNone(existing.poll())
                send_query(existing_port)
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=5)

    def test_selecting_two_live_instances_resets_rates_and_shows_build_info(self):
        with (
            live_resolver() as (first, first_port, _),
            live_resolver() as (second, second_port, _),
        ):
            self.window.close()
            self.app.quit()
            self.pump(0.05)
            self.app = gui.build_application(gui.arguments(["--interval", ".5"]))
            self.app.set_application_id(
                "org.dnsproxy.LinuxMonitor.Test" + uuid.uuid4().hex
            )
            self.app.register(None)
            self.app.activate()
            self.window = self.app.window
            self.wait_for(
                lambda: first.pid in self.window.instance_ids
                and second.pid in self.window.instance_ids
            )
            self.assertIn("Choose one", self.window.detail.get_text())
            for process, port in ((first, first_port), (second, second_port)):
                self.window.instance_selector.set_selected(
                    self.window.instance_ids.index(process.pid)
                )
                self.assertIsNone(self.window.rates.previous)
                self.assertEqual(len(self.window.latencies.history), 0)
                self.wait_for(
                    lambda: self.window.snapshot is not None
                    and self.window.snapshot.process is not None
                    and self.window.snapshot.process.pid == process.pid
                )
                self.assertEqual(self.window.values["pid"].get_text(), str(process.pid))
                self.assertNotEqual(self.window.values["build"].get_text(), "—")
                self.assertNotEqual(self.window.values["capabilities"].get_text(), "—")
                before = self.window.snapshot.metrics.get(
                    "dnsp_queries_total", transport="udp"
                )
                send_query(port)
                self.window.refresh.emit("clicked")
                self.wait_for(
                    lambda: self.window.snapshot.metrics.get(
                        "dnsp_queries_total", transport="udp"
                    )
                    > before
                )
            self.screenshot("instance-selection.png")
            self.assertIsNone(first.poll())
            self.assertIsNone(second.poll())

    def test_startup_origin_refreshes_when_explicit_value_equals_default(self):
        from monitor import parse_invocation

        self.window.show_settings(parse_invocation(["dnsp-modern"]))
        values = self.window.startup.get_last_child()
        self.assertEqual(values.get_child_at(2, 1).get_text(), "Default")
        self.window.show_settings(parse_invocation(["dnsp-modern", "-p", "5300"]))
        values = self.window.startup.get_last_child()
        self.assertEqual(values.get_child_at(2, 1).get_text(), "Explicit")


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        raise SystemExit("Linux only")
    unittest.main(verbosity=2)
