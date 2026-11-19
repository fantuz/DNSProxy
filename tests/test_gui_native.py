#!/usr/bin/env python3
"""Native GTK acceptance with real local DNS traffic on Linux, Windows and macOS.

Each scenario gets its own process/GtkApplication for AppKit's application
lifecycle. Snapshot capture adapts entropy-service's MIT-licensed native test
pattern, Copyright (c) 2026 Massimiliano Fantuzzi HB9GUS; see the desktop notices.
"""

from contextlib import contextmanager
from dataclasses import replace
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_NAMESPACE = None
SCENARIOS = ("demo", "live", "controls")
QUESTION = struct.pack("!HHHHHH", 0x1267, 0x0100, 1, 0, 0, 0) + (
    b"\x07blocked\x07example\x00\x00\x01\x00\x01"
)


def invalid_port_error():
    minimum = 1 if sys.platform == "win32" else 1024
    return f"DNS port for a user process must be {minimum}..65535"


def windows_console_state():
    import ctypes
    from ctypes import wintypes as w

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleProcessList.argtypes = [ctypes.POINTER(w.DWORD), w.DWORD]
    kernel.GetConsoleProcessList.restype = w.DWORD
    kernel.GetConsoleWindow.argtypes = []
    kernel.GetConsoleWindow.restype = w.HWND
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.IsWindowVisible.argtypes = [w.HWND]
    user.IsWindowVisible.restype = w.BOOL
    window = kernel.GetConsoleWindow()
    return {
        "attached": bool(kernel.GetConsoleProcessList((w.DWORD * 1)(), 1)),
        "visible": bool(window and user.IsWindowVisible(window)),
    }


def runtime_from_environment():
    """Restore private DLL directories in every isolated Windows test process."""
    global RUNTIME_NAMESPACE
    bootstrap = os.environ.get("DNSP_GUI_RUNTIME_BOOTSTRAP")
    if bootstrap:
        bundle = os.environ.get("DNSP_GUI_BUNDLE_ROOT")
        state = os.environ.get("DNSP_GUI_STATE")
        if not bundle or not state:
            raise RuntimeError("Private GUI tests require bundle root and user state")
        RUNTIME_NAMESPACE = runpy.run_path(bootstrap)
        RUNTIME_NAMESPACE["configure_runtime"](Path(bundle), Path(state))
    # Local cloud tests can use extracted distribution packages without root.
    # Explicitly opt in; installed runtime acceptance never sets this variable.
    site = os.environ.get("DNSP_GUI_TEST_SITE")
    if site:
        if not Path(site).is_dir():
            raise RuntimeError("The native GUI test package directory is absent")
        sys.path.insert(0, site)


def wait_for(context, predicate, description, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        # Bound dispatch so a continuously ready source cannot hide a timeout.
        for _ in range(100):
            if not context.pending():
                break
            context.iteration(False)
            if predicate():
                return
        time.sleep(0.01)
    raise AssertionError("Timed out waiting for " + description)


def pump(context, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for _ in range(100):
            if not context.pending():
                break
            context.iteration(False)
        time.sleep(0.005)


def capture(context, window, path):
    """Capture native windows without unsafe old GskRenderNode marshalling."""
    import gi
    from gi.repository import GLib, Graphene, Gtk

    clock = window.get_frame_clock()
    if clock is not None:
        for _ in range(3):
            previous = clock.get_frame_counter()
            window.queue_draw()
            wait_for(
                context,
                lambda: clock.get_frame_counter() > previous,
                "settled native paint",
                timeout=4,
            )
    if sys.platform.startswith("linux"):
        # GTK 4.6/PyGObject 3.42 can mistake GskRenderNode for a GObject and
        # crash inside to_node(), before Python can handle an exception. The
        # supported Linux CI uses X11; use its native capture path just as the
        # existing GTK regression suite does. Windows/macOS use modern bindings.
        try:
            gi.require_version("GdkX11", "4.0")
            from gi.repository import GdkX11

            identifier = GdkX11.X11Surface.get_xid(window.get_surface())
            subprocess.run(
                ["import", "-window", str(identifier), str(path)],
                check=True,
                timeout=10,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if not path.is_file() or not path.stat().st_size:
                raise RuntimeError("Native X11 capture did not produce a PNG")
            return {
                "captured": True,
                "method": "x11-window",
                "file": path.name,
                "width": window.get_width(),
                "height": window.get_height(),
            }
        except (
            OSError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as error:
            return {
                "captured": False,
                "reason": type(error).__name__ + ": " + str(error),
            }
    if gi.version_info < (3, 50, 0):
        return {
            "captured": False,
            "reason": "This PyGObject runtime cannot safely marshal GskRenderNode",
        }
    try:
        width, height = window.get_width(), window.get_height()
        paintable = Gtk.WidgetPaintable.new(window)
        snapshot = Gtk.Snapshot()
        paintable.snapshot(snapshot, width, height)
        node = snapshot.to_node()
        if node is None:
            return {"captured": False, "reason": "GTK returned no render node"}
        bounds = Graphene.Rect()
        bounds.init(0, 0, width, height)
        texture = window.get_native().get_renderer().render_texture(node, bounds)
        texture.save_to_png(str(path))
        if not path.is_file() or not path.stat().st_size:
            raise RuntimeError("GTK snapshot did not produce a PNG")
        return {"captured": True, "file": path.name, "width": width, "height": height}
    except (TypeError, ValueError, AttributeError, RuntimeError, GLib.Error) as error:
        # Older distribution bindings may not marshal GskRenderNode. Native
        # paint/allocation assertions still run; retain the exact evidence gap.
        return {"captured": False, "reason": type(error).__name__ + ": " + str(error)}


def resize_window(window, width, height):
    """Request an actual native resize when Win32 ignores later default sizes."""
    window.unmaximize()
    window.set_default_size(width, height)
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes as w

    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.EnumWindows.argtypes = [callback_type, w.LPARAM]
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.SetWindowPos.argtypes = [
        w.HWND,
        w.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        w.UINT,
    ]
    owned = []

    @callback_type
    def collect(handle, _):
        pid = w.DWORD()
        user.GetWindowThreadProcessId(handle, ctypes.byref(pid))
        if pid.value == os.getpid():
            title = ctypes.create_unicode_buffer(512)
            user.GetWindowTextW(handle, title, len(title))
            if title.value == window.get_title():
                owned.append(handle)
        return True

    user.EnumWindows(collect, 0)
    if not owned:
        raise AssertionError("The native GTK Win32 window was not found")
    if not user.SetWindowPos(owned[0], None, 0, 0, width, height, 0x0002 | 0x0004):
        raise OSError(ctypes.get_last_error(), "Native GUI resize failed")


def query(port, tcp=False):
    if tcp:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(struct.pack("!H", len(QUESTION)) + QUESTION)
            length = receive(client, 2)
            response = receive(client, struct.unpack("!H", length)[0])
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(QUESTION, ("127.0.0.1", port))
            response = client.recv(4096)
    assert response[:2] == QUESTION[:2]
    assert response[3] & 15 == 5, "The local blocklist must answer REFUSED"
    return response


def receive(connection, length):
    parts = bytearray()
    while len(parts) < length:
        data = connection.recv(length - len(parts))
        if not data:
            raise RuntimeError("Incomplete DNS/TCP fixture response")
        parts.extend(data)
    return bytes(parts)


@contextmanager
def resolver(binary, blocklist, fixtures, *, no_console=False):
    port, metric = fixtures.unused_ports()
    with tempfile.TemporaryFile() as log:
        command = [
            str(binary),
            "-l",
            "127.0.0.1",
            "-p",
            str(port),
            "-m",
            str(metric),
            "--bootstrap-address",
            "1.1.1.1",
            "--blocklist",
            str(blocklist),
            "--blocklist-reload-ms",
            "0",
        ]
        if no_console:
            assert sys.platform == "win32"
            # spawn_proxy allocates a console for its CTRL_BREAK fixtures.
            # Keep this independent fixture detached so only the production
            # GUI-owned Start path can allocate the pythonw host's console.
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            process = fixtures.spawn_proxy(command, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    query(port)
                    break
                except (OSError, AssertionError):
                    time.sleep(0.05)
            else:
                log.seek(0)
                raise AssertionError(
                    "Fixture resolver did not start: "
                    + log.read().decode("utf-8", "replace")
                )
            yield process, port, metric
        finally:
            if process.poll() is None:
                if sys.platform == "win32" and not no_console:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    # The detached Windows fixture has no console to receive
                    # CTRL_BREAK. Terminate only this test-created fixture;
                    # GUI-owned children must still stop gracefully below.
                    process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


class NativeScenario:
    def __init__(self, options):
        self.options = options
        source = Path(
            os.environ.get("DNSP_GUI_SOURCE", ROOT / "tools/desktop-gui")
        ).resolve()
        sys.path.insert(0, str(source))
        sys.path.insert(0, str(ROOT / "tests"))
        os.environ["DNSP_TEST_BINARY"] = str(options.binary)
        import test_modern

        self.fixtures = test_modern
        spec = importlib.util.spec_from_file_location(
            "dnsp_native_gui", source / "dnsp-gui.py"
        )
        self.gui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.gui)
        self.callback_errors = []
        self.original_excepthook = sys.excepthook

        def callback_error(kind, value, trace):
            self.callback_errors.append(
                "".join(traceback.format_exception(kind, value, trace))
            )
            self.original_excepthook(kind, value, trace)

        sys.excepthook = callback_error
        self.Gio, self.GLib, self.Gtk = self.gui.load_gtk()
        self.context = self.GLib.MainContext.default()
        self.app = self.window = None
        self.evidence = {
            "scenario": options.scenario,
            "platform": sys.platform,
            "machine": platform.machine(),
            "binary": str(options.binary),
            "gui_source": str(source),
            "checks": [],
            "captures": [],
        }

    def open(self, *arguments):
        assert self.app is None, "Use one GtkApplication per native scenario"
        self.app = self.gui.build_application(
            self.gui.arguments(
                [
                    "--binary",
                    str(self.options.binary),
                    *arguments,
                ]
            )
        )
        self.app.set_application_id("org.dnsproxy.NativeTest.T" + uuid.uuid4().hex)
        assert self.app.register(None)
        self.app.activate()
        self.window = self.app.window
        wait_for(
            self.context, lambda: self.window.get_mapped(), "native window mapping"
        )
        return self.window

    def check(self, description):
        self.evidence["checks"].append(description)

    def screenshot(self, name, window=None):
        item = capture(
            self.context, window or self.window, self.options.artifacts / name
        )
        self.evidence["captures"].append(item)

    def close(self):
        if self.window is not None:
            child = self.window.owned_process
            if self.window.get_visible():
                self.window.close()
                wait_for(
                    self.context,
                    lambda: not self.window.get_visible(),
                    "native window close",
                )
            if child is not None:
                wait_for(
                    self.context,
                    lambda: child.poll() is not None,
                    "GUI-owned resolver cleanup",
                    timeout=10,
                )
                child.stop(wait=True)
        if self.app is not None:
            self.app.quit()
        self.window = self.app = None

    def demo(self):
        window = self.open("--demo", "--interval", "0.25", "--history", "20")
        wait_for(
            self.context,
            lambda: window.snapshot is not None and window.history,
            "demo traffic samples",
        )
        assert "DEMO" in window.status.get_text()
        assert len(window.history) <= 20
        self.check("labelled demo data and bounded quarter-second sampling")
        window.pause.set_active(True)
        wait_for(self.context, lambda: not window.busy, "paused collector")
        original = window.snapshot
        pump(self.context, 0.35)
        assert window.snapshot is original
        window.refresh.emit("clicked")
        wait_for(
            self.context, lambda: window.snapshot is not original, "on-demand sampling"
        )
        self.check("pause and one-shot refresh")
        collector = window.collector
        lock = threading.Lock()
        state = {"calls": 0, "active": 0, "peak": 0}

        class SlowCollector:
            def collect(self):
                with lock:
                    state["calls"] += 1
                    state["active"] += 1
                    state["peak"] = max(state["peak"], state["active"])
                try:
                    time.sleep(0.3)
                    return collector.collect()
                finally:
                    with lock:
                        state["active"] -= 1

        window.collector = SlowCollector()
        window.pause.set_active(False)
        pump(self.context, 1.1)
        started = time.monotonic()
        window.chart_series.set_selected(2)
        window.notebook.set_current_page(1)
        window.notebook.set_current_page(0)
        assert time.monotonic() - started < 0.3
        window.pause.set_active(True)
        wait_for(
            self.context, lambda: not window.busy, "single bounded sampling worker"
        )
        assert state["peak"] == 1 and 2 <= state["calls"] <= 4, state
        window.collector = collector
        self.check("slow sampling never overlaps or blocks native controls")
        window.chart_series.set_selected(0)
        for width, height in ((1120, 920), (800, 680)):
            resize_window(window, width, height)
            pump(self.context, 0.25)
            assert window.chart.get_width() > 200
            assert 160 <= window.chart.get_content_height() <= 240
            assert window.latency_chart.get_width() > 200
            assert window.chart_panel.has_css_class("info-panel")
            assert window.latency_panel.has_css_class("info-panel")
            assert window.information_grid.get_column_spacing() >= 12
            query_allocation = window.chart_panel.get_parent().get_allocation()
            latency_allocation = window.latency_panel.get_parent().get_allocation()
            if width >= 1000:
                assert window.charts_wide
                assert abs(query_allocation.y - latency_allocation.y) <= 2
                assert (
                    latency_allocation.x >= query_allocation.x + query_allocation.width
                )
            else:
                assert not window.charts_wide
                assert (
                    latency_allocation.y >= query_allocation.y + query_allocation.height
                )
            self.screenshot(f"demo-overview-{width}.png")
        window.chart_series.set_selected(1)
        window.latency_series.set_selected(1)
        window.chart.queue_draw()
        window.latency_chart.queue_draw()
        pump(self.context, 0.15)
        assert window.chart_series.get_selected() == 1
        assert window.latency_series.get_selected() == 1
        self.check("native resize and query/latency chart selection")
        window.open_settings()
        editor = window.settings_window
        wait_for(self.context, editor.get_mapped, "native settings window")
        assert {"binary", "upstream", "metrics_port", "blocklist"} <= set(
            editor.entries
        )
        original_config = window.launch_config
        editor.entries["port"].set_text("0")
        editor.apply_button.emit("clicked")
        assert editor.get_visible()
        assert editor.status_label.get_text() == invalid_port_error()
        assert window.launch_config == original_config
        assert editor.config == original_config
        self.check("grouped native settings and invalid-edit rollback")
        self.screenshot("demo-settings.png", editor)
        editor.close()

    def live(self):
        with tempfile.TemporaryDirectory(prefix="dnsp native GUI ") as directory:
            blocklist = Path(directory) / "blocked domains.txt"
            blocklist.write_text("blocked.example\n")
            with resolver(self.options.binary, blocklist, self.fixtures) as (
                external,
                port,
                metric,
            ):
                window = self.open("--metrics-port", str(metric), "--interval", "0.25")
                wait_for(
                    self.context,
                    lambda: window.snapshot is not None and window.snapshot.metrics,
                    "external resolver metrics",
                )
                before_udp = window.snapshot.metrics.get(
                    "dnsp_queries_total", transport="udp"
                )
                before_tcp = window.snapshot.metrics.get(
                    "dnsp_queries_total", transport="tcp"
                )
                for _ in range(12):
                    query(port)
                    query(port, tcp=True)
                    pump(self.context, 0.025)
                wait_for(
                    self.context,
                    lambda: window.snapshot.metrics
                    and window.snapshot.metrics.get(
                        "dnsp_queries_total", transport="udp"
                    )
                    >= before_udp + 12
                    and window.snapshot.metrics.get(
                        "dnsp_queries_total", transport="tcp"
                    )
                    >= before_tcp + 12,
                    "real UDP/TCP query counters",
                )
                wait_for(
                    self.context,
                    lambda: any(value is not None for value in window.latency_history),
                    "observed client latency history",
                )
                assert any(
                    value is not None and value > 0 for value in window.udp_history
                )
                assert any(
                    value is not None and value > 0 for value in window.tcp_history
                )
                self.screenshot("live-traffic.png")
                self.check("live UDP/TCP counters and measured client latency history")
                window.disconnect_button.emit("clicked")
                assert not window.monitor_connected
                assert external.poll() is None
                query(port)
                window.metrics_entry.set_text(str(metric))
                window.connect_button.emit("clicked")
                wait_for(
                    self.context,
                    lambda: window.monitor_connected
                    and window.snapshot is not None
                    and window.snapshot.metrics,
                    "explicit reconnect",
                )
                self.check("disconnect/reconnect affects only monitoring")
                self.close()
                assert external.poll() is None
                query(port)
                self.check("closing a monitor leaves its external resolver running")

    def controls(self):
        no_console = os.environ.get("DNSP_GUI_TEST_NO_CONSOLE") == "1"
        if no_console:
            assert sys.platform == "win32"
            initial_console = windows_console_state()
            assert not initial_console["attached"], initial_console
            self.evidence["initial_console"] = initial_console
        with tempfile.TemporaryDirectory(prefix="dnsp GUI owned paths ") as directory:
            blocklist = Path(directory) / "blocked domains.txt"
            blocklist.write_text("blocked.example\n")
            with resolver(
                self.options.binary, blocklist, self.fixtures, no_console=no_console
            ) as (
                external,
                external_port,
                _,
            ):
                window = self.open("--paused", "--interval", "0.25")
                window.open_settings()
                editor = window.settings_window
                wait_for(self.context, editor.get_mapped, "owned resolver options")
                original = editor.config
                secret_url = "https://native-user:native-secret@localhost/dns-query?token=native-token"
                secret_config = replace(original, upstream=secret_url)
                editor.config = secret_config
                editor.reset()
                assert "native-secret" not in editor.entries["upstream"].get_text()
                assert "native-token" not in editor.entries["upstream"].get_text()
                assert editor.draft().upstream == secret_url
                editor.entries["port"].set_text("0")
                editor.apply_button.emit("clicked")
                assert editor.get_visible()
                assert editor.status_label.get_text() == invalid_port_error()
                assert editor.config == secret_config
                assert window.launch_config == original
                self.check("secret-safe display and failed settings apply are lossless")
                editor.config = original
                editor.reset()
                port, metric = self.fixtures.unused_ports()
                for key, value in (
                    ("binary", str(self.options.binary)),
                    ("port", str(port)),
                    ("metrics_port", str(metric)),
                    ("blocklist", str(blocklist)),
                ):
                    editor.entries[key].set_text(value)
                editor.checks["filtering"].set_active(True)
                editor.checks["metrics"].set_active(True)
                editor.apply_button.emit("clicked")
                assert not editor.get_visible()
                assert window.launch_config.blocklist == str(blocklist)
                window.pause.set_active(False)
                if no_console:
                    before_start = windows_console_state()
                    assert not before_start["attached"], before_start
                    self.evidence["console_before_owned_start"] = before_start
                window.start_resolver()
                if no_console:
                    owned_console = windows_console_state()
                    assert owned_console["attached"], owned_console
                    assert not owned_console["visible"], owned_console
                    self.evidence["console_after_owned_start"] = owned_console
                    self.check("pythonw owned start allocates a hidden private console")
                child = window.owned_process
                assert child is not None and child.pid > 0
                wait_for(
                    self.context,
                    lambda: window.snapshot is not None
                    and window.snapshot.metrics
                    and window.snapshot.process
                    and window.snapshot.process.pid == child.pid,
                    "GUI-owned native resolver and process metadata",
                    timeout=25,
                )
                for _ in range(8):
                    query(port)
                    query(port, tcp=True)
                    pump(self.context, 0.025)
                wait_for(
                    self.context,
                    lambda: window.snapshot.metrics.get(
                        "dnsp_queries_total", transport="tcp"
                    )
                    >= 8,
                    "owned resolver traffic",
                )
                wait_for(
                    self.context,
                    lambda: bool(child.snapshot()["logs"]),
                    "captured resolver diagnostics",
                )
                window.notebook.set_current_page(4)
                buffer = window.diagnostics_view.get_buffer()
                wait_for(
                    self.context,
                    lambda: buffer.get_char_count() > 0,
                    "visible captured diagnostics",
                )
                logs = buffer.get_text(
                    buffer.get_start_iter(), buffer.get_end_iter(), True
                )
                assert logs and len(logs.encode("utf-8")) <= 65536
                assert not child.snapshot()["error"], child.snapshot()["error"]
                self.screenshot("owned-resolver-diagnostics.png")
                self.check(
                    "settings apply, owned start and bounded visible diagnostics"
                )
                window.open_settings()
                assert not editor.apply_button.get_sensitive()
                editor.close()
                window.stop_resolver()
                wait_for(
                    self.context,
                    lambda: child.poll() is not None and window.owned_process is None,
                    "graceful owned stop",
                    timeout=12,
                )
                assert not child.snapshot()["forced_stop"], child.snapshot()
                assert external.poll() is None
                query(external_port)
                self.check("graceful owned stop leaves the external instance running")
                window.start_resolver()
                child = window.owned_process
                assert child is not None
                wait_for(
                    self.context,
                    lambda: window.snapshot is not None
                    and window.snapshot.metrics
                    and window.snapshot.process
                    and window.snapshot.process.pid == child.pid,
                    "second GUI-owned start",
                    timeout=25,
                )
                self.close()
                assert child.poll() is not None
                assert not child.snapshot()["forced_stop"], child.snapshot()
                assert external.poll() is None
                query(external_port)
                self.check("window close reaps only its own resolver")

    def run(self):
        try:
            getattr(self, self.options.scenario)()
            self.close()
            assert not self.callback_errors, (
                "Native GTK callback errors:\n" + "\n".join(self.callback_errors)
            )
            self.evidence["passed"] = True
        except BaseException:
            self.evidence["passed"] = False
            self.evidence["error"] = traceback.format_exc()
            raise
        finally:
            try:
                self.close()
            finally:
                sys.excepthook = self.original_excepthook
                (
                    self.options.artifacts / f"results-{self.options.scenario}.json"
                ).write_text(
                    json.dumps(self.evidence, indent=2) + "\n", encoding="utf-8"
                )


def run_scenarios(options):
    """Collect every isolated scenario while retaining a failing overall gate."""
    results = {}
    aggregate = options.artifacts / "results.json"
    aggregate.unlink(missing_ok=True)
    for scenario in SCENARIOS:
        report = options.artifacts / f"results-{scenario}.json"
        report.unlink(missing_ok=True)
        command = [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--binary",
            str(options.binary),
            "--artifacts",
            str(options.artifacts),
            "--scenario",
            scenario,
        ]
        failure = None
        try:
            process = subprocess.run(command, check=False, timeout=180)
            if process.returncode:
                failure = f"Scenario process exited with status {process.returncode}"
        except (OSError, subprocess.TimeoutExpired) as error:
            failure = type(error).__name__ + ": " + str(error)
        try:
            item = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(item, dict):
                raise ValueError("The scenario report must be a JSON object")
        except (OSError, ValueError) as error:
            item = {
                "scenario": scenario,
                "platform": sys.platform,
                "passed": False,
                "checks": [],
                "captures": [],
                "error": "Scenario report unavailable: " + str(error),
            }
        if item.get("platform") != sys.platform or item.get("scenario") != scenario:
            failure = "The scenario report identifies a different platform or scenario"
        if failure:
            item["passed"] = False
            item["process_error"] = failure
        if item.get("passed") is not True:
            item["passed"] = False
        report.write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")
        results[scenario] = item
    failed = [name for name, item in results.items() if not item["passed"]]
    aggregate.write_text(
        json.dumps(
            {"passed": not failed, "platform": sys.platform, "scenarios": results},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if failed:
        raise SystemExit("Native GUI scenarios failed: " + ", ".join(failed))


def main():
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--scenario", choices=("all", *SCENARIOS), default="all")
    options = parser.parse_args()
    if os.environ.get("DNSP_GUI_TEST_NO_CONSOLE") == "1" and (
        sys.platform != "win32" or options.scenario != "controls"
    ):
        parser.error("No-console acceptance requires Windows and --scenario controls")
    options.binary = options.binary.resolve()
    options.artifacts = options.artifacts.resolve()
    if not options.binary.is_file():
        parser.error("The native resolver binary is absent")
    options.artifacts.mkdir(parents=True, exist_ok=True)
    runtime_from_environment()
    if options.scenario == "all":
        run_scenarios(options)
    else:
        NativeScenario(options).run()


if __name__ == "__main__":
    main()
