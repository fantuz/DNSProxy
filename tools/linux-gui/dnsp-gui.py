#!/usr/bin/python3
"""Optional Linux GTK 4 monitor. The resolver does not depend on this program."""

from __future__ import annotations

import argparse
from collections import deque
import math
import queue
import sys
import threading
import time

from monitor import (
    Collector,
    DEFAULTS,
    DemoCollector,
    LatencyWindow,
    Rates,
    Snapshot,
    display_value,
)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pid", type=int, help="Inspect one dnsp-modern PID (otherwise auto-detect)"
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        help="Read 127.0.0.1:PORT/metrics; never a remote host",
    )
    parser.add_argument(
        "--interval", type=float, default=1, help="Refresh seconds, 0.5..30 (default 1)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show labelled synthetic data without a running resolver",
    )
    options = parser.parse_args(argv)
    if options.pid is not None and options.pid <= 0:
        parser.error("--pid must be positive")
    if options.metrics_port is not None and not 1 <= options.metrics_port <= 65535:
        parser.error("--metrics-port must be 1..65535")
    if not 0.5 <= options.interval <= 30:
        parser.error("--interval must be 0.5..30 seconds")
    if options.demo and (options.pid or options.metrics_port):
        parser.error("--demo cannot be combined with a live process or metrics port")
    return options


def load_gtk():
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        from gi.repository import Gio, GLib, Gtk
    except (ImportError, ValueError) as error:
        raise RuntimeError(
            "GTK 4 bindings are missing. On Debian/Ubuntu install "
            "python3-gi python3-gi-cairo gir1.2-gtk-4.0, then run with /usr/bin/python3."
        ) from error
    return Gio, GLib, Gtk


def number(value, suffix=""):
    if value is None:
        return "—"
    return f"{value:,.0f}{suffix}"


def build_application(options):
    Gio, GLib, Gtk = load_gtk()

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title="DNSProxy · Linux monitor")
            self.set_default_size(1040, 880)
            self.collector = (
                DemoCollector()
                if options.demo
                else Collector(options.pid, options.metrics_port)
            )
            self.rates = Rates()
            self.latencies = LatencyWindow()
            self.selected_pid = options.pid
            self.instance_ids = [None]
            self.instance_labels = []
            self.updating_instances = False
            self.history = deque(maxlen=60)
            self.results = queue.Queue(maxsize=1)
            self.busy = False
            self.closed = False
            self.epoch = 0
            self.last_started = 0
            self.last_success = None
            self.signature = object()
            self.values = {}
            self.snapshot = None
            self.interval = options.interval
            self.set_titlebar(Gtk.HeaderBar())
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            for side in ("top", "bottom", "start", "end"):
                getattr(root, "set_margin_" + side)(16)
            self.set_child(root)

            toolbar = Gtk.Box(spacing=12)
            self.status = self.label("Connecting…", "title-3")
            self.status.set_hexpand(True)
            toolbar.append(self.status)
            self.pause = Gtk.ToggleButton(label="Pause")
            self.pause.set_tooltip_text(
                "Pause automatic sampling; Refresh now still takes one sample"
            )
            self.pause.connect("toggled", self.pause_changed)
            toolbar.append(self.pause)
            self.refresh = Gtk.Button(label="Refresh now")
            self.refresh.connect("clicked", lambda *_: self.request_sample(force=True))
            toolbar.append(self.refresh)
            root.append(toolbar)
            self.detail = self.label("Read-only monitor · detecting local DNSProxy")
            self.detail.set_wrap(True)
            root.append(self.detail)
            picker = Gtk.Box(spacing=12)
            picker.append(self.label("Resolver instance"))
            self.instance_selector = Gtk.DropDown.new_from_strings(
                ["Automatic selection"]
            )
            self.instance_selector.set_hexpand(True)
            self.instance_selector.set_sensitive(not options.demo)
            self.instance_selector.connect("notify::selected", self.instance_changed)
            picker.append(self.instance_selector)
            reconnect = Gtk.Button(label="Reconnect")
            reconnect.set_sensitive(not options.demo)
            reconnect.connect("clicked", lambda *_: self.instance_changed(force=True))
            picker.append(reconnect)
            root.append(picker)
            if options.demo:
                root.append(
                    self.label(
                        "DEMO · All values are synthetic. No DNS requests or listeners are created.",
                        "warning",
                    )
                )

            notebook = Gtk.Notebook()
            self.notebook = notebook
            notebook.set_vexpand(True)
            root.append(notebook)
            overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            cards = Gtk.Grid(column_spacing=14, row_spacing=10, column_homogeneous=True)
            for col, (key, title) in enumerate(
                (
                    ("rate", "Queries / second"),
                    ("satisfied", "Satisfied queries"),
                    ("latency", "Mean upstream time"),
                    ("memory", "Resident memory"),
                )
            ):
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                box.set_hexpand(True)
                box.append(self.label(title, "dim-label"))
                value = self.label("—", "title-1")
                self.values[key] = value
                box.append(value)
                cards.attach(box, col, 0, 1, 1)
            overview.append(cards)
            self.activity = self.label("Waiting for the first sample", "heading")
            overview.append(self.activity)
            self.chart = Gtk.DrawingArea()
            self.chart.set_content_height(90)
            self.chart.set_hexpand(True)
            self.chart.set_draw_func(self.draw_history)
            self.chart.set_tooltip_text(
                "Query rate, last 60 samples; vertical scale follows the visible peak"
            )
            overview.append(self.chart)
            self.chart_scale = self.label(
                "Activity history · up to 60 samples", "dim-label"
            )
            overview.append(self.chart_scale)
            overview.append(
                self.group(
                    "Estimated latency · last 60 sampling intervals",
                    [
                        ("client_percentiles", "Client reply p50 / p95 / p99"),
                        ("upstream_percentiles", "Completed attempt p50 / p95 / p99"),
                    ],
                )
            )
            columns = Gtk.Box(spacing=28, homogeneous=True)
            left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            columns.append(left)
            columns.append(right)
            left.append(
                self.group(
                    "DNS traffic",
                    [
                        ("udp", "UDP queries"),
                        ("tcp", "TCP queries"),
                        ("inflight", "In flight"),
                        ("clients", "TCP clients"),
                        ("coalesced", "Coalesced UDP queries"),
                        ("invalid", "Invalid queries / responses"),
                        ("overload", "Overload rejections"),
                        ("truncated", "Truncated UDP replies"),
                    ],
                )
            )
            left.append(
                self.group(
                    "Cache and filtering",
                    [
                        ("cache", "Cache hits / misses"),
                        ("blocked", "Blocked queries / aliases"),
                        ("lists", "Deny / allow entries"),
                        ("reload_errors", "Blocklist reload failures"),
                    ],
                )
            )
            right.append(
                self.group(
                    "DoH upstream",
                    [
                        ("requests", "Attempts"),
                        ("upstream_ok", "Successful / failed attempts"),
                        ("timeouts", "Timeouts"),
                        ("http", "HTTP/1 · HTTP/2 · HTTP/3 replies"),
                        ("reuse", "Reused requests / new connections"),
                        ("roles", "Primary / backup attempts"),
                        ("hedges", "Parallel backups / backup wins"),
                    ],
                )
            )
            right.append(
                self.group(
                    "Daemon load",
                    [
                        ("cpu", "CPU (% of one core)"),
                        ("uptime", "Process uptime"),
                        ("pid", "Process ID"),
                        ("service", "Packaged systemd service"),
                        ("build", "Daemon / libcurl version"),
                        ("capabilities", "Built HTTP/2 · HTTP/3 support"),
                    ],
                )
            )
            overview.append(columns)
            notebook.append_page(self.scroll(overview), self.label("Overview"))
            self.startup = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            self.startup.append(self.label("Waiting for a readable DNSProxy process…"))
            notebook.append_page(
                self.scroll(self.startup), self.label("Startup options")
            )
            notes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            for text in (
                "This monitor reads /proc and the existing loopback /metrics listener. It does not change "
                "settings, restart the daemon, bind DNS ports, or change system DNS.",
                "Incoming-query activity is inferred from counter changes between samples. This is not a "
                "packet capture: client addresses, query names and query contents are neither collected nor shown.",
                "The HTTP version preference is a startup setting. Actual HTTP/1, HTTP/2 and HTTP/3 reply "
                "counters show what libcurl used; preferring HTTP/3 does not prove that HTTP/3 was negotiated.",
                "Mean upstream time is the lifetime mean across completed attempts, including failures. "
                "Satisfied queries count complete NOERROR or NXDOMAIN replies written to client sockets; "
                "truncated replies, other DNS errors and local policy blocks are excluded. "
                "Attempts, client queries, coalesced queries and cache hits have different denominators.",
                "Traffic bytes and system interface throughput are not exposed by the daemon. They are not estimated "
                "from query counts. An unavailable metric is shown as a dash, rather than a zero.",
                "Pause switches to on-demand sampling with Refresh now. Automatic polling also stops while the "
                "window is unmapped. Closing the GUI leaves DNSProxy running.",
                "Use the instance selector when several resolvers run. Service state is read independently "
                "from dnsp-modern.service and never changes the daemon. If /proc is restricted, --metrics-port PORT offers "
                "traffic-only monitoring without root privileges or inferred startup settings.",
                "Percentiles are estimates interpolated from bounded histogram buckets over recent samples. "
                "Client timings include complete UDP/TCP replies, cache hits, policy blocks and DNS errors. "
                "Attempt timings include completed failures but exclude cancelled losing races. No query log is collected. "
                "A dash means insufficient samples or an older daemon without histograms; above range means the final unbounded bucket.",
            ):
                label = self.label(text)
                label.set_wrap(True)
                notes.append(label)
            notebook.append_page(self.scroll(notes), self.label("How to read this"))
            self.freshness = self.label(
                "Sampling every " + str(self.interval) + " s · Read only", "dim-label"
            )
            root.append(self.freshness)
            self.connect("close-request", self.close_monitor)
            self.connect("unmap", self.reset_baseline)
            self.tick_id = GLib.timeout_add(250, self.tick)

        @staticmethod
        def label(text, css=None):
            label = Gtk.Label(label=text, xalign=0)
            label.set_selectable(True)
            if css:
                label.add_css_class(css)
            return label

        @staticmethod
        def scroll(child):
            container = Gtk.ScrolledWindow()
            container.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            for side in ("top", "bottom", "start", "end"):
                getattr(child, "set_margin_" + side)(12)
            container.set_child(child)
            return container

        def group(self, title, rows):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            box.append(self.label(title, "heading"))
            grid = Gtk.Grid(column_spacing=16, row_spacing=7)
            for row, (key, caption) in enumerate(rows):
                label = self.label(caption)
                label.set_wrap(True)
                label.set_hexpand(True)
                grid.attach(label, 0, row, 1, 1)
                value = self.label("—")
                value.set_xalign(1)
                self.values[key] = value
                grid.attach(value, 1, row, 1, 1)
            box.append(grid)
            return box

        def pause_changed(self, *_):
            self.epoch += 1
            self.rates.reset()
            self.latencies.reset()
            self.pause.set_label("Resume" if self.pause.get_active() else "Pause")
            self.last_started = 0

        def reset_baseline(self, *_):
            self.epoch += 1
            self.rates.reset()
            self.latencies.reset()
            self.last_started = 0

        def instance_changed(self, *_args, force=False):
            if self.updating_instances or options.demo:
                return
            index = self.instance_selector.get_selected()
            if index >= len(self.instance_ids):
                return
            pid = self.instance_ids[index]
            if pid == self.selected_pid and not force:
                return
            self.selected_pid = pid
            self.collector = Collector(
                pid, options.metrics_port if pid is None else None
            )
            self.reset_baseline()
            self.history.clear()
            self.snapshot = None
            self.last_success = None
            for value in self.values.values():
                value.set_text("—")
            self.status.set_text("Connecting…")
            self.detail.set_text("Reading the selected instance")
            self.show_settings(None)
            self.chart.queue_draw()
            self.request_sample(force=True)

        def show_instances(self, snapshot):
            rows = list(snapshot.instances)
            if snapshot.process and all(p.pid != snapshot.process.pid for p in rows):
                rows.append(snapshot.process)
            ids = [None] + [p.pid for p in rows]
            labels = [
                f"Traffic only · port {options.metrics_port}"
                if options.metrics_port
                else "Automatic selection"
            ]
            labels += [
                f"PID {p.pid} · DNS port {p.invocation.get('-p')} · metrics {p.invocation.get('-m')}"
                for p in rows
            ]
            if self.selected_pid and self.selected_pid not in ids:
                ids.append(self.selected_pid)
                labels.append(f"Selected PID {self.selected_pid} · unavailable")
            if labels == self.instance_labels and ids == self.instance_ids:
                return
            self.updating_instances = True
            self.instance_ids, self.instance_labels = ids, labels
            self.instance_selector.set_model(Gtk.StringList.new(labels))
            self.instance_selector.set_selected(
                ids.index(self.selected_pid) if self.selected_pid in ids else 0
            )
            self.updating_instances = False

        def request_sample(self, force=False):
            if self.closed or self.busy or (self.pause.get_active() and not force):
                return
            self.busy = True
            self.last_started = time.monotonic()
            epoch = self.epoch

            def work():
                try:
                    result = self.collector.collect()
                except Exception as error:
                    result = Snapshot(
                        time.monotonic(),
                        None,
                        None,
                        None,
                        f"Monitor collection failed: {type(error).__name__}",
                    )
                if not self.closed:
                    self.results.put_nowait((epoch, result))

            # One bounded worker at a time; GTK is touched only on the main loop.
            threading.Thread(target=work, name="dnsp-monitor", daemon=True).start()

        def tick(self):
            if self.closed:
                return False
            try:
                epoch, result = self.results.get_nowait()
                self.busy = False
                if epoch == self.epoch:
                    self.apply(result)
            except queue.Empty:
                pass
            now = time.monotonic()
            if (
                self.get_mapped()
                and not self.pause.get_active()
                and now - self.last_started >= self.interval
            ):
                self.request_sample()
            mode = (
                "On demand" if self.pause.get_active() else f"Every {self.interval:g} s"
            )
            age = (
                f" · Last good traffic sample {int(now - self.last_success)} s ago"
                if self.last_success
                else ""
            )
            self.freshness.set_text(f"{mode}{age} · Read only")
            return True

        def apply(self, snapshot):
            if self.snapshot and self.snapshot.identity != snapshot.identity:
                self.history.clear()
            self.snapshot = snapshot
            process, metrics = snapshot.process, snapshot.metrics
            self.show_instances(snapshot)
            rate, delta, cpu = self.rates.update(snapshot)
            percentile_values = self.latencies.update(snapshot)
            if metrics:
                self.last_success = snapshot.at
            self.status.set_text(
                ("DEMO · " if options.demo else "")
                + ("Receiving metrics" if metrics else "Traffic unavailable")
            )
            self.detail.set_text(
                snapshot.error
                if snapshot.error
                else f"127.0.0.1:{snapshot.port}/metrics · "
                + (
                    f"DNSProxy PID {process.pid}"
                    if process and process.pid
                    else "Process settings unavailable"
                    if not options.demo
                    else "Synthetic process"
                )
            )
            for key in self.values:
                self.values[key].set_text("—")
            self.values["rate"].set_text(f"{rate:,.1f}" if rate is not None else "—")
            self.values["memory"].set_text(
                f"{process.memory_bytes / 1048576:.1f} MiB" if process else "—"
            )
            self.values["cpu"].set_text(f"{cpu:.1f}%" if cpu is not None else "—")
            self.values["pid"].set_text(
                str(process.pid) if process and process.pid else "—"
            )
            if snapshot.service:
                self.values["service"].set_text(snapshot.service.describe(process))
            for key, values in zip(
                ("client_percentiles", "upstream_percentiles"), percentile_values
            ):
                if values is not None:
                    self.values[key].set_text(
                        " / ".join(
                            "above range" if math.isinf(v) else f"{1000 * v:.1f} ms"
                            for v in values
                        )
                    )
            if process:
                hours, rest = divmod(int(process.uptime), 3600)
                self.values["uptime"].set_text(
                    f"{hours}h {rest // 60:02d}m {rest % 60:02d}s"
                )
            self.show_settings(process.invocation if process else None)
            if metrics:
                get = metrics.get

                def put(key, name, **labels):
                    self.values[key].set_text(number(get(name, **labels)))

                def pair(key, first, second):
                    self.values[key].set_text(
                        number(get(first)) + " / " + number(get(second))
                    )

                put("satisfied", "dnsp_queries_satisfied_total")
                for key, name in (
                    ("udp", "dnsp_queries_total"),
                    ("tcp", "dnsp_queries_total"),
                ):
                    put(key, name, transport=key)
                for key, name in (
                    ("inflight", "dnsp_queries_inflight"),
                    ("clients", "dnsp_tcp_clients"),
                    ("coalesced", "dnsp_udp_queries_coalesced_total"),
                    ("overload", "dnsp_overload_total"),
                    ("truncated", "dnsp_truncated_responses_total"),
                    ("requests", "dnsp_upstream_requests_total"),
                    ("timeouts", "dnsp_upstream_timeouts_total"),
                    ("reload_errors", "dnsp_blocklist_reload_failures_total"),
                ):
                    put(key, name)
                pair("cache", "dnsp_cache_hits_total", "dnsp_cache_misses_total")
                self.values["hedges"].set_text(
                    number(get("dnsp_upstream_hedges_started_total"))
                    + " / "
                    + number(get("dnsp_upstream_hedge_wins_total", role="backup"))
                )
                info = [
                    dict(labels)
                    for (name, labels), value in metrics.samples.items()
                    if name == "dnsp_build_info" and value == 1
                ]
                if len(info) == 1:
                    self.values["build"].set_text(
                        info[0].get("version", "unknown")
                        + " / "
                        + info[0].get("libcurl", "unknown")
                    )
                    self.values["capabilities"].set_text(
                        info[0].get("http2", "unknown")
                        + " · "
                        + info[0].get("http3", "unknown")
                    )
                pair(
                    "blocked",
                    "dnsp_blocked_queries_total",
                    "dnsp_blocked_aliases_total",
                )
                pair(
                    "invalid",
                    "dnsp_invalid_queries_total",
                    "dnsp_invalid_responses_total",
                )
                pair(
                    "reuse",
                    "dnsp_upstream_reused_requests_total",
                    "dnsp_upstream_new_connections_total",
                )
                pair(
                    "upstream_ok",
                    "dnsp_upstream_success_total",
                    "dnsp_upstream_failures_total",
                )
                self.values["http"].set_text(
                    " · ".join(
                        number(get("dnsp_upstream_http_responses_total", version=v))
                        for v in ("1", "2", "3")
                    )
                )
                for key, name, label, variants in (
                    ("lists", "dnsp_blocklist_entries", "action", ("deny", "allow")),
                    (
                        "roles",
                        "dnsp_upstream_endpoint_requests_total",
                        "role",
                        ("primary", "backup"),
                    ),
                ):
                    self.values[key].set_text(
                        " / ".join(number(get(name, **{label: v})) for v in variants)
                    )
                duration, count = (
                    get("dnsp_upstream_duration_seconds_sum"),
                    get("dnsp_upstream_duration_seconds_count"),
                )
                if duration is not None and count:
                    self.values["latency"].set_text(f"{1000 * duration / count:.1f} ms")
            self.activity.set_text(
                "Traffic unavailable — last history retained"
                if not metrics
                else "Collecting baseline…"
                if delta is None
                else f"● {int(delta):,} incoming queries since last sample"
                if delta
                else "○ Idle · no incoming queries since last sample"
            )
            self.history.append(rate)
            self.chart.queue_draw()
            peak = max(
                (value for value in self.history if value is not None), default=0
            )
            self.chart_scale.set_text(
                f"Activity history · last {len(self.history)} samples · visible peak {peak:,.1f} queries/s"
            )

        def show_settings(self, invocation):
            signature = (
                (
                    tuple(invocation.values.items()),
                    frozenset(invocation.explicit),
                    bool(invocation.unknown),
                )
                if invocation
                else None
            )
            if (
                signature == self.signature
                and self.startup.get_first_child() is not None
            ):
                return
            self.signature = signature
            while self.startup.get_first_child():
                self.startup.remove(self.startup.get_first_child())
            if invocation is None:
                self.startup.append(
                    self.label(
                        "Startup options unavailable. Attach to a readable process with --pid PID."
                    )
                )
                return
            hint = self.label(
                "Read-only startup settings. Omitted flags use the current C defaults; "
                "these are not measurements of negotiated transport or dynamic policy state."
            )
            hint.set_wrap(True)
            self.startup.append(hint)
            if invocation.unknown:
                self.startup.append(
                    self.label(
                        "Unrecognised arguments present: defaults may differ in this daemon version.",
                        "warning",
                    )
                )
            grid = Gtk.Grid(column_spacing=24, row_spacing=8)
            for row, (caption, enabled) in enumerate(invocation.toggles().items()):
                grid.attach(self.label(caption), 0, row, 1, 1)
                on, off = Gtk.CheckButton(label="On"), Gtk.CheckButton(label="Off")
                off.set_group(on)
                on.set_active(enabled)
                off.set_active(not enabled)
                on.set_sensitive(False)
                off.set_sensitive(False)
                grid.attach(on, 1, row, 1, 1)
                grid.attach(off, 2, row, 1, 1)
            self.startup.append(grid)
            self.startup.append(self.label("Invocation values", "heading"))
            values = Gtk.Grid(column_spacing=18, row_spacing=8)
            for row, option in enumerate(DEFAULTS):
                values.attach(self.label(option, "monospace"), 0, row, 1, 1)
                text = (
                    ", ".join(
                        display_value(option, value)
                        for value in invocation.values[option]
                    )
                    or "Disabled / unset"
                )
                value = self.label(text)
                value.set_wrap(True)
                value.set_hexpand(True)
                values.attach(value, 1, row, 1, 1)
                values.attach(
                    self.label(
                        "Explicit" if option in invocation.explicit else "Default",
                        "dim-label",
                    ),
                    2,
                    row,
                    1,
                    1,
                )
            self.startup.append(values)

        def draw_history(self, _area, cr, width, height):
            cr.set_source_rgba(0.35, 0.5, 0.65, 0.16)
            cr.rectangle(0, 0, width, height)
            cr.fill()
            peak = max(1, max((v for v in self.history if v is not None), default=1))
            cr.set_source_rgb(0.2, 0.55, 0.85)
            cr.set_line_width(2)
            drawing = False
            for i, value in enumerate(self.history):
                if value is None:
                    if drawing:
                        cr.stroke()
                    drawing = False
                    continue
                x, y = (
                    3 + i * (width - 6) / 59,
                    height - 5 - value / peak * (height - 10),
                )
                if drawing:
                    cr.line_to(x, y)
                else:
                    cr.move_to(x, y)
                drawing = True
            cr.stroke()
            # A single rate sample has no segment yet. Keep incoming activity
            # visible immediately instead of showing an empty chart at startup.
            for i, value in enumerate(self.history):
                if value is not None:
                    x = 3 + i * (width - 6) / 59
                    y = height - 5 - value / peak * (height - 10)
                    cr.arc(x, y, 2, 0, math.tau)
                    cr.fill()

        def close_monitor(self, *_):
            self.closed = True
            GLib.source_remove(self.tick_id)
            return False

    class Application(Gtk.Application):
        def __init__(self):
            super().__init__(
                application_id="org.dnsproxy.LinuxMonitor",
                flags=Gio.ApplicationFlags.NON_UNIQUE,
            )
            self.window = None

        def do_activate(self):
            if self.window is None:
                self.window = Window(self)
            self.window.present()
            self.window.refresh.grab_focus()

    return Application()


def main():
    options = arguments()
    if not sys.platform.startswith("linux"):
        print("This desktop monitor currently supports Linux only.", file=sys.stderr)
        return 2
    try:
        app = build_application(options)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2
    return app.run([])


if __name__ == "__main__":
    raise SystemExit(main())
