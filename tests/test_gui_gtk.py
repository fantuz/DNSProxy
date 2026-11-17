"""Run under Xvfb: GTK rendering, on-demand sampling and the actual C daemon."""

import importlib.util
from dataclasses import replace
from pathlib import Path
import os
import subprocess
import sys
import time
import unittest
import uuid

from test_gui_monitor import (
    BINARY,
    GUI_SOURCE,
    live_resolver,
    metrics_endpoint,
    sample,
    send_query,
    unused_ports,
)

spec = importlib.util.spec_from_file_location("dnsp_gui", GUI_SOURCE / "dnsp-gui.py")
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
from monitor import Collector, DemoCollector, Invocation  # noqa: E402


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
        for _ in range(75):
            self.window.apply(DemoCollector().collect())
        self.assertEqual(len(self.window.history), 60)
        self.window.pause.set_active(False)
        self.assertIsNone(self.window.rates.previous)

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
            before, {key: label.get_text() for key, label in self.window.values.items()}
        )
        self.assertEqual(changes, [])
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
