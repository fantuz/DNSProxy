"""Run under Xvfb: GTK rendering, on-demand sampling and the actual C daemon."""

import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import time
import unittest
import uuid

from test_gui_monitor import BASE, live_resolver, metrics_endpoint, send_query

spec = importlib.util.spec_from_file_location(
    "dnsp_gui", BASE / "tools/linux-gui/dnsp-gui.py"
)
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)
from monitor import Collector, DemoCollector  # noqa: E402


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
        self.assertEqual(len(radios), 24)
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

    def test_connection_failure_clears_live_values_and_recovers(self):
        self.wait_for(lambda: self.window.snapshot is not None)
        from monitor import Snapshot

        snapshot = self.window.snapshot
        self.window.apply(
            Snapshot(time.monotonic(), snapshot.process, None, 1, "Connection refused")
        )
        self.assertEqual(self.window.values["satisfied"].get_text(), "—")
        self.assertEqual(self.window.values["rate"].get_text(), "—")
        self.assertIn("unavailable", self.window.status.get_text())
        self.window.apply(DemoCollector().collect())
        self.assertEqual(self.window.values["rate"].get_text(), "—")
        self.assertIn("Receiving metrics", self.window.status.get_text())

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
