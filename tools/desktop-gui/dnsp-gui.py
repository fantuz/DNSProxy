#!/usr/bin/python3
"""DNSProxy GTK 4 desktop monitor and ordinary-user resolver controls."""

from __future__ import annotations

import argparse
from collections import deque
import json
import math
import sys
import threading
import time

from chart import draw as draw_chart, scale_ceiling
from telemetry import TelemetryWindow, diagnostic_report

from monitor import (
    Collector,
    DEFAULTS,
    DemoCollector,
    LatencyWindow,
    Rates,
    Snapshot,
    display_value,
    same_instance,
)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", help="Native resolver executable for GUI-owned runs"
    )
    parser.add_argument(
        "--pid", type=int, help="Inspect one dnsp-modern PID (otherwise auto-detect)"
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        help="Read 127.0.0.1:PORT/metrics; never a remote host",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Refresh seconds, 0.25..30 (default 0.5)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Show labelled synthetic data without a running resolver",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1,
        help="Metrics socket timeout, 0.2..5 seconds",
    )
    parser.add_argument(
        "--history", type=int, default=60, help="Chart samples, 20..300 (default 60)"
    )
    parser.add_argument(
        "--paused", action="store_true", help="Start with on-demand sampling"
    )
    parser.add_argument("--no-chart", action="store_true", help="Hide activity chart")
    options = parser.parse_args(argv)
    if options.pid is not None and options.pid <= 0:
        parser.error("--pid must be positive")
    if options.metrics_port is not None and not 1 <= options.metrics_port <= 65535:
        parser.error("--metrics-port must be 1..65535")
    if not 0.25 <= options.interval <= 30:
        parser.error("--interval must be 0.25..30 seconds")
    if not 0.2 <= options.timeout <= 5:
        parser.error("--timeout must be 0.2..5 seconds")
    if not 20 <= options.history <= 300:
        parser.error("--history must be 20..300 samples")
    if options.demo and (options.pid or options.metrics_port):
        parser.error("--demo cannot be combined with a live process or metrics port")
    return options


def load_gtk():
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_foreign("cairo")
        from gi.repository import Gio, GLib, Gtk
    except (ImportError, ValueError) as error:
        raise RuntimeError(
            "GTK 4 bindings are missing. Use the bundled Windows GUI, the macOS "
            "Homebrew launcher (brew install gtk4 pygobject3), or install "
            "python3-gi python3-gi-cairo gir1.2-gtk-4.0 on Debian/Ubuntu."
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
            super().__init__(application=app, title="DNSProxy · Desktop monitor")
            self.set_default_size(1120, 920)
            self.collector = (
                DemoCollector()
                if options.demo
                else Collector(options.pid, options.metrics_port, options.timeout)
            )
            self.rates = Rates()
            self.latencies = LatencyWindow()
            self.telemetry = TelemetryWindow()
            self.telemetry_frame = None
            self.collection_seconds = None
            self.baseline_resets = 0
            self.export_dialog = None
            self.selected_pid = options.pid
            self.metrics_port = options.metrics_port
            self.monitor_connected = True
            self.settings_window = None
            self.last_owned_snapshot = None
            self.log_revision = None
            self.instance_ids = [None]
            self.instance_labels = []
            self.updating_instances = False
            self.history = deque(maxlen=options.history)
            self.history_times = deque(maxlen=options.history)
            self.udp_history = deque(maxlen=options.history)
            self.tcp_history = deque(maxlen=options.history)
            self.latency_history = deque(maxlen=options.history)
            self.upstream_latency_history = deque(maxlen=options.history)
            self.history_gap = False
            self.good_snapshot = None
            self.peak_qps = self.peak_cpu = self.peak_memory = self.peak_inflight = None
            self.missed_samples = 0
            self.owned_process = None
            self.busy = False
            self.pending_sample = False
            self.closed = False
            self.epoch = 0
            self.last_started = 0
            self.last_success = None
            self.signature = object()
            self.values = {}
            self.snapshot = None
            self.interval = options.interval
            self.timeout = options.timeout
            self.set_titlebar(Gtk.HeaderBar())
            from gi.repository import Gdk

            provider = Gtk.CssProvider()
            self.css_provider = provider
            provider.load_from_data(
                b"""
                .metric { font-variant-numeric: tabular-nums; }
                .metric-card, .info-panel {
                    padding: 16px;
                    border: 1px solid alpha(currentColor, 0.12);
                    border-radius: 10px;
                    background-color: alpha(currentColor, 0.025);
                }
                .metric-card { padding: 14px 16px; }
                .section-heading { font-size: 14px; font-weight: 700; }
                .section-rule { margin-top: 2px; margin-bottom: 2px; }
                .stale { opacity: 0.72; }
                """
            )
            Gtk.StyleContext.add_provider_for_display(
                Gdk.Display.get_default(),
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
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
            self.options_button = Gtk.Button(label="Resolver options…")
            self.options_button.connect("clicked", self.open_settings)
            toolbar.append(self.options_button)
            connection = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            connection.add_css_class("info-panel")
            self.connection_panel = connection
            connection.append(toolbar)
            root.append(connection)
            self.detail = self.label("Detecting local DNSProxy")
            self.detail.set_wrap(True)
            connection.append(self.detail)
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
            connection.append(picker)
            endpoint = Gtk.Box(spacing=12)
            endpoint.append(self.label("Local metrics port"))
            self.metrics_entry = Gtk.Entry(hexpand=True)
            self.metrics_entry.set_placeholder_text("Automatic, or 9090")
            self.metrics_entry.set_text(str(options.metrics_port or ""))
            self.metrics_entry.set_tooltip_text(
                "Read only 127.0.0.1:PORT/metrics. Enable loopback metrics on an existing service explicitly, or start a separate resolver below."
            )
            endpoint.append(self.metrics_entry)
            self.connect_button = Gtk.Button(label="Connect")
            self.reconnect_control = self.connect_button
            self.connect_button.set_sensitive(not options.demo)
            self.connect_button.connect("clicked", self.connect_metrics)
            endpoint.append(self.connect_button)
            self.disconnect_button = Gtk.Button(label="Disconnect")
            self.disconnect_button.set_sensitive(not options.demo)
            self.disconnect_button.connect("clicked", self.disconnect_metrics)
            endpoint.append(self.disconnect_button)
            connection.append(endpoint)
            if options.demo:
                connection.append(
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
            self.overview = overview
            cards = Gtk.Grid(column_spacing=12, row_spacing=12, column_homogeneous=True)
            for col, (key, title) in enumerate(
                (
                    ("rate", "Queries / second"),
                    ("peak_qps", "Peak sampled QPS"),
                    ("satisfied", "Satisfied queries"),
                    ("latency", "Mean upstream time"),
                )
            ):
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
                box.set_hexpand(True)
                box.add_css_class("metric-card")
                caption = self.label(title, "dim-label")
                caption.set_wrap(True)
                box.append(caption)
                value = self.label("—", "title-2")
                value.add_css_class("metric")
                value.set_width_chars(8)
                self.values[key] = value
                box.append(value)
                cards.attach(box, col, 0, 1, 1)
            self.metric_cards = cards
            overview.append(cards)
            overview.append(
                self.group(
                    "Recent interval · completed attempts and cache lookups",
                    [
                        ("health_failure", "Failed upstream attempts"),
                        ("health_cache", "Cache hit ratio"),
                        ("health_reuse", "Reused upstream attempts"),
                    ],
                )
            )
            self.chart_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.chart_panel.add_css_class("info-panel")
            chart_heading = Gtk.Box(spacing=12)
            title = self.label("Query activity", "section-heading")
            title.set_hexpand(True)
            chart_heading.append(title)
            self.query_series = Gtk.DropDown.new_from_strings(
                ["All queries", "UDP", "TCP"]
            )
            self.chart_series = self.query_series
            self.query_series.connect("notify::selected", self.chart_series_changed)
            chart_heading.append(self.query_series)
            chart_heading.append(self.label("QUERIES / SECOND", "dim-label"))
            self.chart_panel.append(chart_heading)
            self.activity = self.label("Waiting for the first sample")
            self.chart_panel.append(self.activity)
            self.chart = Gtk.DrawingArea()
            self.chart.set_content_height(200)
            self.chart.set_hexpand(True)
            self.chart.set_draw_func(self.draw_history)
            self.chart.set_tooltip_text(
                "Observed query rates against elapsed time. Gaps separate paused or failed sampling; no synthetic points are inserted."
            )
            self.chart_panel.append(self.chart)
            self.chart_scale = self.label("Waiting for activity history", "dim-label")
            self.chart_panel.append(self.chart_scale)
            self.charts_grid = Gtk.FlowBox(
                column_spacing=16,
                row_spacing=16,
                homogeneous=True,
                min_children_per_line=1,
                max_children_per_line=2,
                hexpand=True,
            )
            self.charts_grid.set_selection_mode(Gtk.SelectionMode.NONE)
            self.charts_grid.set_activate_on_single_click(False)
            self.charts_wide = True
            self.chart_panel.set_hexpand(True)
            self.chart_panel.set_valign(Gtk.Align.FILL)
            self.activity.set_wrap(True)
            self.chart_scale.set_wrap(True)
            self.chart_scale.set_max_width_chars(45)
            self.charts_grid.append(self.chart_panel)
            self.latency_panel = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL, spacing=10
            )
            self.latency_panel.add_css_class("info-panel")
            latency_heading = Gtk.Box(spacing=12)
            latency_heading.append(self.label("Latency history", "section-heading"))
            latency_heading.append(Gtk.Box(hexpand=True))
            self.latency_series = Gtk.DropDown.new_from_strings(
                ["Client reply p95", "Upstream attempt p95"]
            )
            self.latency_series.connect(
                "notify::selected", lambda *_: self.latency_chart.queue_draw()
            )
            latency_heading.append(self.latency_series)
            latency_heading.append(self.label("MILLISECONDS", "dim-label"))
            self.latency_panel.append(latency_heading)
            self.latency_activity = self.label(
                "Estimated p95 · recent sampling window", "dim-label"
            )
            self.latency_activity.set_wrap(True)
            self.latency_panel.append(self.latency_activity)
            self.latency_chart = Gtk.DrawingArea(hexpand=True)
            self.latency_chart.set_content_height(160)
            self.latency_chart.set_draw_func(self.draw_latency_history)
            self.latency_chart.set_tooltip_text(
                "p95 estimates from bounded histogram buckets over the recent sampling window. Missing data and pauses create gaps; these are not individual request traces."
            )
            self.latency_panel.append(self.latency_chart)
            self.latency_scale = self.label("Waiting for timing samples", "dim-label")
            self.latency_scale.set_wrap(True)
            self.latency_scale.set_max_width_chars(45)
            self.latency_panel.append(self.latency_scale)
            self.latency_panel.set_hexpand(True)
            self.latency_panel.set_valign(Gtk.Align.FILL)
            self.charts_grid.append(self.latency_panel)
            overview.append(self.charts_grid)
            overview.append(
                self.group(
                    "Estimated latency · last 60 sampling intervals",
                    [
                        ("client_percentiles", "Client reply p50 / p95 / p99"),
                        ("upstream_percentiles", "Completed attempt p50 / p95 / p99"),
                    ],
                )
            )
            columns = Gtk.Grid(
                column_spacing=16, row_spacing=16, column_homogeneous=True
            )
            self.information_grid = columns
            left, right = [], []
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
                        ("peak_inflight", "Peak sampled in flight"),
                        ("client_max", "Max client reply · daemon lifetime"),
                    ],
                )
            )
            left.append(
                self.group(
                    "Cache and filtering",
                    [
                        ("cache", "Cache hits / misses"),
                        ("cache_ratio", "Cache hit ratio"),
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
                        ("upstream_max", "Max attempt · daemon lifetime"),
                        ("failure_ratio", "Failed completed attempts"),
                        ("reuse_ratio", "Reused attempts / completed attempts"),
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
                        ("peak_cpu", "Peak sampled CPU"),
                        ("memory", "Resident memory"),
                        ("peak_memory", "Peak sampled memory"),
                        ("missed", "Missed traffic samples · session"),
                        ("uptime", "Process uptime"),
                        ("pid", "Process ID"),
                        ("service", "Packaged system service"),
                        ("build", "Daemon / libcurl version"),
                        ("capabilities", "Built HTTP/2 · HTTP/3 support"),
                    ],
                )
            )
            for row, (left_panel, right_panel) in enumerate(zip(left, right)):
                left_panel.set_valign(Gtk.Align.FILL)
                right_panel.set_valign(Gtk.Align.FILL)
                columns.attach(left_panel, 0, row, 1, 1)
                columns.attach(right_panel, 1, row, 1, 1)
            overview.append(columns)
            notebook.append_page(self.scroll(overview), self.label("Overview"))
            self.startup = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            self.startup.append(self.label("Waiting for a readable DNSProxy process…"))
            notebook.append_page(
                self.scroll(self.startup), self.label("Startup options")
            )
            self.add_preferences(notebook)
            self.add_launcher(notebook)
            self.add_diagnostics(notebook)
            notes = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            for text in (
                "This monitor reads available native process/service status and the existing loopback /metrics listener. It does not change "
                "a monitored service or system DNS. The Launch resolver tab can start a separate ordinary-user process.",
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
                "window is unmapped. Closing the GUI stops its owned resolver; external daemons and services keep running.",
                "Use the instance selector when several resolvers run. Service state is read independently "
                "from the platform service manager and never changes the daemon. If process metadata is restricted, --metrics-port PORT offers "
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
            self.add_monitoring(notebook)
            self.freshness = self.label(
                "Sampling every " + str(self.interval) + " s · Read only", "dim-label"
            )
            root.append(self.freshness)
            self.connect("close-request", self.close_monitor)
            self.connect("unmap", self.reset_baseline)
            self.pause.set_active(options.paused)
            self.chart_panel.set_visible(not options.no_chart)
            self.chart.set_visible(not options.no_chart)
            self.chart_scale.set_visible(not options.no_chart)
            self.latency_panel.set_visible(not options.no_chart)
            self.tick_id = GLib.timeout_add(50, self.tick)

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
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            box.add_css_class("info-panel")
            box.append(self.label(title, "section-heading"))
            rule = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
            rule.add_css_class("section-rule")
            box.append(rule)
            grid = Gtk.Grid(column_spacing=16, row_spacing=9)
            for row, (key, caption) in enumerate(rows):
                label = self.label(caption)
                label.set_wrap(True)
                label.set_hexpand(True)
                grid.attach(label, 0, row, 1, 1)
                value = self.label("—", "metric")
                value.set_width_chars(15)
                value.set_xalign(1)
                self.values[key] = value
                grid.attach(value, 1, row, 1, 1)
            box.append(grid)
            return box

        def add_monitoring(self, notebook):
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            self.monitoring_page = page
            note = self.label(
                "Recent interval values use changes between consecutive successful samples. "
                "Idle ratios and unsupported metrics appear as a dash. Capacity and policy "
                "values describe the latest sample; overview totals describe daemon lifetime."
            )
            note.set_wrap(True)
            page.append(note)
            sections = (
                (
                    "Sample health",
                    [
                        ("sample_state", "Interval status"),
                        ("sample_elapsed", "Observed interval"),
                        ("sample_age", "Last good sample age"),
                        ("collection_ms", "Collection duration"),
                        ("sample_resets", "Detected resets · session"),
                    ],
                ),
                (
                    "Completed upstream attempts · recent interval",
                    [
                        ("recent_completed", "Completed attempts"),
                        ("recent_success", "Successful attempts"),
                        ("recent_failure", "Failed attempts"),
                        ("recent_timeout", "Timeouts / completed attempts"),
                        ("recent_reuse", "Reused / completed attempts"),
                        ("recent_http", "HTTP/1 · HTTP/2 · HTTP/3 replies"),
                    ],
                ),
                (
                    "Endpoints and transfer phases · recent interval",
                    [
                        ("recent_primary", "Primary attempts / replies / failures"),
                        ("recent_backup", "Backup attempts / replies / failures"),
                        ("recent_wins", "Primary / backup race wins"),
                        ("recent_hedges", "Hedges started / suppressed / cancelled"),
                        ("recent_queue", "Mean queue time"),
                        ("recent_tls", "Mean TLS time"),
                        ("recent_first_byte", "Mean time to first byte"),
                    ],
                ),
                (
                    "Cache and policy",
                    [
                        ("recent_cache", "Cache hits / misses · interval"),
                        ("recent_cache_ratio", "Cache hit ratio · interval"),
                        ("cache_used", "Live cache slots / capacity"),
                        ("recent_blocked", "Blocked queries / aliases · interval"),
                        ("recent_coalesced", "Coalesced UDP queries · interval"),
                        ("policy_generation", "Policy generation"),
                        ("policy_age", "Policy age"),
                        ("policy_memory", "Policy memory"),
                        ("recent_reload", "Reload successes / failures · interval"),
                    ],
                ),
                (
                    "Capacity and TCP",
                    [
                        ("slot_pressure", "Active attempts / shared slots"),
                        ("tcp_pressure", "TCP clients / capacity"),
                        ("recent_overload", "Overload rejections · interval"),
                        ("recent_tcp_rejected", "TCP source / capacity rejections"),
                        ("recent_tcp_timeouts", "TCP idle / I/O timeouts"),
                        ("daemon_uptime", "Resolver uptime from metrics"),
                    ],
                ),
            )
            for title, rows in sections:
                page.append(self.group(title, rows))
            notebook.append_page(self.scroll(page), self.label("Monitoring"))

        @staticmethod
        def telemetry_labels(telemetry):
            counts, percentages, gauges = (
                telemetry.counts,
                telemetry.percentages,
                telemetry.gauges,
            )

            def percent(value):
                return "—" if value is None else f"{value:.1f}%"

            def pair(*keys):
                return " / ".join(number(counts.get(key)) for key in keys)

            def capacity(used, total, key):
                label = number(gauges.get(used)) + " / " + number(gauges.get(total))
                value = telemetry.capacity_percentages.get(key)
                return label + (f" · {value:.1f}%" if value is not None else "")

            result = {
                "health_failure": percent(percentages.get("failure")),
                "health_cache": percent(percentages.get("cache_hit")),
                "health_reuse": percent(percentages.get("reuse")),
                "sample_state": {
                    "baseline": "Collecting baseline",
                    "live": "Live interval",
                    "reset": "Resolver counters reset · new baseline",
                    "gap": "No fresh metrics · interval unavailable",
                }[telemetry.status],
                "sample_elapsed": (
                    f"{telemetry.elapsed:.2f} s"
                    if telemetry.elapsed is not None
                    else "—"
                ),
                "recent_completed": number(counts.get("completed")),
                "recent_success": number(counts.get("success"))
                + " · "
                + percent(percentages.get("success")),
                "recent_failure": number(counts.get("failures"))
                + " · "
                + percent(percentages.get("failure")),
                "recent_timeout": number(counts.get("timeouts"))
                + " · "
                + percent(percentages.get("timeout")),
                "recent_reuse": number(counts.get("reused_requests"))
                + " · "
                + percent(percentages.get("reuse")),
                "recent_http": " · ".join(
                    number(telemetry.protocols.get(v)) for v in ("1", "2", "3")
                ),
                "recent_wins": " / ".join(
                    number(telemetry.roles[role].get("wins"))
                    for role in ("primary", "backup")
                ),
                "recent_hedges": pair(
                    "hedges_started", "hedges_suppressed", "hedges_cancelled"
                ),
                "recent_cache": pair("cache_hits", "cache_misses"),
                "recent_cache_ratio": percent(percentages.get("cache_hit")),
                "cache_used": capacity("cache_entries", "cache_capacity", "cache"),
                "recent_blocked": pair("blocked_queries", "blocked_aliases"),
                "recent_coalesced": number(counts.get("coalesced")),
                "policy_generation": number(gauges.get("generation")),
                "policy_age": number(gauges.get("blocklist_age"), " s"),
                "policy_memory": number(gauges.get("blocklist_memory"), " B"),
                "recent_reload": pair("reload_success", "reload_failures"),
                "slot_pressure": capacity(
                    "attempts_inflight", "queries_capacity", "attempts"
                ),
                "tcp_pressure": capacity("tcp_clients", "tcp_capacity", "tcp"),
                "recent_overload": number(counts.get("overload")),
                "recent_tcp_rejected": pair(
                    "tcp_rejected_source", "tcp_rejected_capacity"
                ),
                "recent_tcp_timeouts": pair("tcp_idle_timeouts", "tcp_io_timeouts"),
                "daemon_uptime": number(gauges.get("uptime"), " s"),
            }
            for role in ("primary", "backup"):
                result["recent_" + role] = " / ".join(
                    number(telemetry.roles[role].get(key))
                    for key in ("attempts", "replies", "failures")
                )
            for phase in ("queue", "tls", "first_byte"):
                value = telemetry.phases.get(phase)
                result["recent_" + phase] = (
                    f"{value * 1000:.2f} ms" if value is not None else "—"
                )
            return result

        def monitoring_report(self):
            if self.good_snapshot is None or self.telemetry_frame is None:
                raise ValueError("Collect a successful metrics sample before exporting")
            report = diagnostic_report(
                self.good_snapshot, self.telemetry_frame, now=time.monotonic()
            )
            report["monitor"] = {
                "demo": options.demo,
                "paused": self.pause.get_active(),
                "connected": self.monitor_connected,
                "latest_sample_succeeded": bool(
                    self.snapshot and self.snapshot.metrics
                ),
                "collection_seconds": self.collection_seconds,
                "missed_samples": self.missed_samples,
                "detected_resets": self.baseline_resets,
            }
            return report

        def export_monitoring(self, *_):
            try:
                self.monitoring_report()
            except ValueError as error:
                self.export_status.set_text(str(error))
                return
            if self.export_dialog is not None:
                self.export_dialog.show()
                return
            dialog = Gtk.FileChooserNative.new(
                "Export DNSProxy monitoring snapshot",
                self,
                Gtk.FileChooserAction.SAVE,
                "Save",
                "Cancel",
            )
            self.export_dialog = dialog
            dialog.set_current_name("dnsproxy-monitoring.json")

            def save(chooser, response):
                try:
                    if response == Gtk.ResponseType.ACCEPT:
                        target = chooser.get_file()
                        if target is None or target.get_path() is None:
                            raise ValueError(
                                "Choose a local file for the monitoring report"
                            )
                        data = (
                            json.dumps(
                                self.monitoring_report(), indent=2, allow_nan=False
                            )
                            + "\n"
                        )
                        target.replace_contents(
                            data.encode("utf-8"),
                            None,
                            False,
                            Gio.FileCreateFlags.PRIVATE,
                            None,
                        )
                        self.export_status.set_text("Monitoring snapshot exported")
                except (OSError, ValueError, GLib.Error) as error:
                    self.export_status.set_text(
                        f"Export failed: {type(error).__name__}"
                    )
                finally:
                    chooser.destroy()
                    self.export_dialog = None

            dialog.connect("response", save)
            dialog.show()

        def add_preferences(self, notebook):
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            page.append(
                self.label("Monitor preferences · apply immediately", "heading")
            )
            grid = Gtk.Grid(column_spacing=24, row_spacing=16)
            self.preference_spins = {}
            for row, (key, title, low, high, step, value) in enumerate(
                (
                    (
                        "interval",
                        "Refresh interval (seconds)",
                        0.25,
                        30,
                        0.25,
                        self.interval,
                    ),
                    (
                        "timeout",
                        "Metrics socket timeout (seconds)",
                        0.2,
                        5,
                        0.2,
                        self.timeout,
                    ),
                    ("history", "Chart samples", 20, 300, 10, options.history),
                )
            ):
                grid.attach(self.label(title), 0, row, 1, 1)
                spin = Gtk.SpinButton.new_with_range(low, high, step)
                spin.set_digits(
                    0 if key == "history" else 2 if key == "interval" else 1
                )
                spin.set_value(value)
                spin.connect("value-changed", self.preference_changed, key)
                self.preference_spins[key] = spin
                grid.attach(spin, 1, row, 1, 1)
            page.append(grid)
            self.auto_refresh = Gtk.CheckButton(label="Automatic refresh")
            self.auto_refresh.set_active(not options.paused)
            self.auto_refresh.connect(
                "toggled", lambda button: self.pause.set_active(not button.get_active())
            )
            page.append(self.auto_refresh)
            self.show_chart = Gtk.CheckButton(label="Show activity chart")
            self.show_chart.set_active(not options.no_chart)
            self.show_chart.connect("toggled", self.chart_visibility_changed)
            page.append(self.show_chart)
            note = self.label(
                "A timeout retains the last statistics and marks them as stale. Peak sampled values belong to the selected resolver in this GUI session; exact latency maxima belong to the daemon lifetime. Changing the refresh interval changes rate averaging and sampled peaks."
            )
            note.set_wrap(True)
            page.append(note)
            notebook.append_page(self.scroll(page), self.label("Preferences"))

        def preference_changed(self, spin, key):
            if key == "history":
                for name in (
                    "history",
                    "history_times",
                    "udp_history",
                    "tcp_history",
                    "latency_history",
                    "upstream_latency_history",
                ):
                    setattr(
                        self,
                        name,
                        deque(getattr(self, name), maxlen=spin.get_value_as_int()),
                    )
                self.chart.queue_draw()
                self.latency_chart.queue_draw()
            elif key == "interval":
                self.interval = spin.get_value()
            else:
                self.timeout = spin.get_value()
                # The next HTTP request uses the new socket timeout; an
                # already running request keeps its existing deadline.
                self.collector.timeout = self.timeout

        def chart_visibility_changed(self, button):
            self.chart_panel.set_visible(button.get_active())
            self.chart.set_visible(button.get_active())
            self.chart_scale.set_visible(button.get_active())
            self.latency_panel.set_visible(button.get_active())
            if button.get_active():
                self.chart.queue_draw()

        def add_launcher(self, notebook):
            from launcher import ResolverConfig, default_binary
            from settings import create_settings_window

            self.launch_config = ResolverConfig(
                binary=options.binary or default_binary()
            )
            self.settings_window = create_settings_window(
                self, self.launch_config, self.apply_launcher_config, Gtk
            )
            # Retain the controls as a simple test/programmatic editing boundary.
            self.launch_entries = self.settings_window.entries
            self.launch_checks = self.settings_window.checks
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            page.add_css_class("info-panel")
            note = self.label(
                "Start a separate resolver as your desktop user. Stop and close affect only the resolver started by this window. Existing services and system DNS are unchanged."
            )
            note.set_wrap(True)
            page.append(note)
            buttons = Gtk.Box(spacing=12)
            for title, handler in (
                ("Resolver options…", self.open_settings),
                ("Preview command", self.preview_launch),
                ("Start resolver", self.start_resolver),
                ("Stop launched resolver", self.stop_resolver),
            ):
                button = Gtk.Button(label=title)
                button.connect("clicked", handler)
                buttons.append(button)
                if title.startswith("Stop"):
                    self.stop_button = button
                    button.set_sensitive(False)
                if title.startswith("Start"):
                    self.start_button = button
                    button.add_css_class("suggested-action")
                    button.set_sensitive(not options.demo)
            page.append(buttons)
            self.launch_status = self.label(
                "Ready · options apply to the next GUI-owned resolver"
            )
            self.launch_status.set_wrap(True)
            page.append(self.launch_status)
            self.launch_summary = self.label("")
            self.launch_summary.set_wrap(True)
            page.append(self.launch_summary)
            self.update_launch_summary(self.launch_config)
            self.launch_command = Gtk.Entry()
            self.launch_command.set_editable(False)
            self.launch_command.set_placeholder_text(
                "Preview a validated command; URL credentials and query values are hidden"
            )
            page.append(self.launch_command)
            notebook.append_page(self.scroll(page), self.label("Launch resolver"))

        def open_settings(self, *_):
            running = (
                self.owned_process is not None and self.owned_process.poll() is None
            )
            for control in self.settings_window.controls.values():
                control.set_sensitive(not running)
            self.settings_window.form.set_sensitive(not running)
            self.settings_window.apply_button.set_sensitive(not running)
            if running:
                self.settings_window.status_label.set_text(
                    "Stop this window's resolver before changing its startup options."
                )
            self.settings_window.present()

        def update_launch_summary(self, config):
            features = []
            for enabled, caption in (
                (config.cache, "cache"),
                (config.filtering, "filtering"),
                (config.padding, "EDNS padding"),
                (config.http3, "HTTP/3 preference"),
                (config.backup_enabled, "backup upstream"),
            ):
                if enabled:
                    features.append(caption)
            self.launch_summary.set_text(
                f"DNS {config.listen.replace(chr(10), ', ')} · port {config.port} · "
                + (
                    f"metrics 127.0.0.1:{config.metrics_port}"
                    if config.metrics
                    else "metrics disabled"
                )
                + "\n"
                + display_value("-s", config.upstream)
                + "\n"
                + (", ".join(features) or "No optional features selected")
            )

        def apply_launcher_config(self, config):
            if self.owned_process is not None and self.owned_process.poll() is None:
                raise ValueError(
                    "Stop the GUI-owned resolver before applying startup options"
                )
            self.launch_config = config
            self.update_launch_summary(config)
            self.launch_status.set_text(
                "Options validated · Start launches a new GUI-owned resolver"
            )

        def launch_argv(self):
            return self.settings_window.draft().argv()

        def preview_launch(self, *_):
            from launcher import command_preview

            try:
                command = self.launch_argv()
                self.launch_command.set_text(command_preview(command))
                self.launch_status.set_text(
                    "Validated invocation · URL credentials and query values are hidden"
                )
                return command
            except (ValueError, OSError) as error:
                self.launch_command.set_text("")
                self.launch_status.set_text(str(error))
                return None

        def add_diagnostics(self, notebook):
            page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            heading = self.label("Resolver diagnostics", "section-heading")
            page.append(heading)
            note = self.label(
                "Recent output from a resolver started by this window. The log is bounded; URL credentials and query values are hidden. External service logs retain their operating-system permissions."
            )
            note.set_wrap(True)
            page.append(note)
            exports = Gtk.Box(spacing=12)
            self.export_button = Gtk.Button(label="Export monitoring snapshot…")
            self.export_button.set_tooltip_text(
                "Save aggregate metrics and resource readings as JSON. URLs, startup arguments, file paths and resolver logs are excluded."
            )
            self.export_button.connect("clicked", self.export_monitoring)
            exports.append(self.export_button)
            self.export_status = self.label("Aggregate metrics only", "dim-label")
            self.export_status.set_wrap(True)
            exports.append(self.export_status)
            page.append(exports)
            self.log_status = self.label(
                "No GUI-owned resolver has been started", "dim-label"
            )
            self.log_status.set_wrap(True)
            page.append(self.log_status)
            self.log_view = Gtk.TextView(
                editable=False, cursor_visible=False, monospace=True
            )
            self.diagnostics_view = self.log_view
            self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
            scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            scroller.set_min_content_height(260)
            scroller.set_child(self.log_view)
            page.append(scroller)
            notebook.append_page(self.scroll(page), self.label("Diagnostics"))

        def start_resolver(self, *_):
            from owned_process import OwnedResolver

            if options.demo or self.owned_process is not None:
                return
            command = self.preview_launch()
            if command is None:
                return
            self.log_view.get_buffer().set_text("")
            self.log_status.set_text("Starting the selected resolver…")
            try:
                child = OwnedResolver(command).start()
            except (OSError, ValueError, RuntimeError) as error:
                self.launch_status.set_text(f"Could not start resolver: {error}")
                self.log_status.set_text(f"Resolver launch failed: {error}")
                return
            self.owned_process = child
            self.last_owned_snapshot = None
            self.log_revision = None
            self.start_button.set_sensitive(False)
            self.stop_button.set_sensitive(True)
            self.launch_status.set_text(
                f"Started PID {child.pid} · waiting for readiness"
            )
            self.selected_pid = child.pid
            self.collector = Collector(child.pid, timeout=self.timeout)
            self.monitor_connected = True
            self.reset_baseline()
            self.clear_history()
            self.good_snapshot = self.snapshot = None
            self.last_success = None
            self.peak_qps = self.peak_cpu = self.peak_memory = self.peak_inflight = None
            for value in self.values.values():
                self.set_label(value, "—")
            self.request_sample(force=True)

        def stop_resolver(self, *_):
            if self.owned_process is not None and self.owned_process.poll() is None:
                self.owned_process.stop(wait=False)
                self.stop_button.set_sensitive(False)
                self.launch_status.set_text("Stopping the GUI-owned resolver…")

        def check_launched_resolver(self):
            if self.owned_process is None:
                return
            state = self.owned_process.snapshot()
            if state.get("revision") != self.log_revision:
                self.log_revision = state.get("revision")
                self.log_view.get_buffer().set_text(state.get("logs", ""))
            error = state.get("error", "")
            if state.get("stopping"):
                status = "Stopping the GUI-owned resolver…"
            elif state.get("running"):
                status = f"GUI-owned PID {state.get('pid')} · recent output retained"
            else:
                status = f"Resolver exited with status {state.get('returncode')}"
            if error:
                status += " · " + error
            self.log_status.set_text(status)
            if not state.get("running") and not state.get("stopping"):
                self.last_owned_snapshot = state
                self.launch_status.set_text(status + "; see Diagnostics")
                self.owned_process = None
                self.start_button.set_sensitive(not options.demo)
                self.stop_button.set_sensitive(False)

        def connect_metrics(self, *_):
            text = self.metrics_entry.get_text().strip()
            if text and (
                not text.isascii()
                or not text.isdecimal()
                or not 1 <= int(text) <= 65535
            ):
                self.detail.set_text(
                    "Choose a metrics port from 1 to 65535, or leave it blank for automatic selection"
                )
                return
            self.metrics_port = int(text) if text else None
            self.monitor_connected = True
            self.instance_selector.set_selected(0)
            self.selected_pid = None
            self.collector = Collector(
                metrics_port=self.metrics_port, timeout=self.timeout
            )
            self.reset_baseline()
            self.clear_history()
            self.good_snapshot = self.snapshot = None
            self.last_success = None
            self.request_sample(force=True)

        def disconnect_metrics(self, *_):
            self.monitor_connected = False
            self.pending_sample = False
            self.epoch += 1
            self.history_gap = True
            self.status.set_text("Disconnected · last values retained")
            self.detail.set_text(
                "Connect to a loopback metrics port to resume monitoring"
            )

        def clear_history(self):
            for history in (
                self.history,
                self.history_times,
                self.udp_history,
                self.tcp_history,
                self.latency_history,
                self.upstream_latency_history,
            ):
                history.clear()
            self.chart_scale.set_text("Waiting for activity history")
            self.latency_scale.set_text("Waiting for timing samples")
            self.chart.queue_draw()
            self.latency_chart.queue_draw()

        def pause_changed(self, *_):
            self.history_gap = True
            self.epoch += 1
            self.rates.reset()
            self.latencies.reset()
            self.telemetry.reset()
            self.pause.set_label("Resume" if self.pause.get_active() else "Pause")
            if hasattr(self, "auto_refresh"):
                self.auto_refresh.set_active(not self.pause.get_active())
            self.last_started = 0

        def reset_baseline(self, *_):
            self.history_gap = True
            self.epoch += 1
            self.rates.reset()
            self.latencies.reset()
            self.telemetry.reset()
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
            self.monitor_connected = True
            self.collector = Collector(
                pid, self.metrics_port if pid is None else None, self.timeout
            )
            self.reset_baseline()
            self.clear_history()
            self.good_snapshot = None
            self.peak_qps = self.peak_cpu = self.peak_memory = self.peak_inflight = None
            self.missed_samples = 0
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
                f"Traffic only · port {self.metrics_port}"
                if self.metrics_port
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
            if self.closed or not self.monitor_connected:
                return
            if self.busy:
                self.pending_sample = self.pending_sample or force
                return
            if self.pause.get_active() and not force:
                return
            self.busy = True
            self.last_started = time.monotonic()
            epoch = self.epoch
            collector = self.collector

            def work():
                try:
                    result = collector.collect()
                except Exception as error:
                    result = Snapshot(
                        time.monotonic(),
                        None,
                        None,
                        None,
                        f"Monitor collection failed: {type(error).__name__}",
                    )
                if not self.closed:
                    GLib.idle_add(self.finish_sample, epoch, result)

            # One bounded worker at a time; GTK is touched only on the main loop.
            threading.Thread(target=work, name="dnsp-monitor", daemon=True).start()

        def finish_sample(self, epoch, result):
            self.busy = False
            if not self.closed and epoch == self.epoch:
                self.collection_seconds = max(0.0, time.monotonic() - self.last_started)
                self.apply(result)
            if self.pending_sample and not self.closed and self.monitor_connected:
                self.pending_sample = False
                GLib.idle_add(self.request_sample, True)
            return False

        def tick(self):
            if self.closed:
                return False
            self.check_launched_resolver()
            wide = self.get_width() >= 1000
            columns = 2 if wide else 1
            if self.charts_grid.get_max_children_per_line() != columns:
                self.charts_grid.set_max_children_per_line(columns)
            query_bounds = self.chart_panel.get_parent().get_allocation()
            latency_bounds = self.latency_panel.get_parent().get_allocation()
            self.charts_wide = (
                wide
                and query_bounds.width > 0
                and latency_bounds.x > query_bounds.x
                and latency_bounds.y == query_bounds.y
            )
            if self.chart.get_visible() and self.chart.get_width() > 0:
                height = max(
                    160,
                    min(
                        190 if self.charts_wide else 240,
                        round(
                            self.chart.get_width() / (3.0 if self.charts_wide else 4.5)
                        ),
                    ),
                )
                if self.chart.get_content_height() != height:
                    self.chart.set_content_height(height)
                latency_height = (
                    height
                    if self.charts_wide
                    else max(160, min(200, round(self.latency_chart.get_width() / 4.5)))
                )
                if self.latency_chart.get_content_height() != latency_height:
                    self.latency_chart.set_content_height(latency_height)
            now = time.monotonic()
            if (
                self.get_mapped()
                and self.monitor_connected
                and not self.pause.get_active()
                and now - self.last_started >= self.interval
            ):
                self.request_sample()
            mode = (
                "On demand" if self.pause.get_active() else f"Every {self.interval:g} s"
            )
            if self.last_success is not None and now - self.last_success > max(
                2 * self.interval, self.timeout + 0.75
            ):
                self.set_label(self.status, "No fresh data · last values retained")
                self.overview.add_css_class("stale")
                self.monitoring_page.add_css_class("stale")
            age = (
                f" · Last good traffic sample {int(now - self.last_success)} s ago"
                if self.last_success
                else ""
            )
            self.set_label(
                self.freshness,
                f"{mode}{age}"
                if self.monitor_connected
                else "Disconnected · statistics held",
            )
            self.set_label(
                self.values["sample_age"],
                f"{max(0.0, now - self.last_success):.1f} s"
                if self.last_success is not None
                else "—",
            )
            return True

        @staticmethod
        def set_label(label, text):
            if label.get_text() != text:
                label.set_text(text)

        def apply(self, snapshot):
            previous = self.good_snapshot
            telemetry = self.telemetry.update(snapshot)
            if telemetry.status == "reset":
                self.baseline_resets += 1
            # An absent /proc read is not proof of a different resolver. Clear
            # retained values only after a confirmed identity/endpoint change.
            changed = previous and (
                (
                    snapshot.process is not None
                    and snapshot.identity != previous.identity
                )
                or (snapshot.port is not None and snapshot.port != previous.port)
                or (
                    snapshot.metrics is not None
                    and snapshot.identity != previous.identity
                )
            )
            if previous and snapshot.metrics and previous.identity == snapshot.identity:
                changed = changed or not same_instance(previous, snapshot)
            if changed:
                if telemetry.status != "reset":
                    self.baseline_resets += 1
                self.clear_history()
                self.rates.reset()
                self.latencies.reset()
                self.good_snapshot = None
                self.last_success = None
                self.peak_qps = self.peak_cpu = self.peak_memory = (
                    self.peak_inflight
                ) = None
                for value in self.values.values():
                    self.set_label(value, "—")
                self.chart.queue_draw()
            self.snapshot = snapshot
            process, metrics = snapshot.process, snapshot.metrics
            self.show_instances(snapshot)
            if snapshot.service:
                self.set_label(
                    self.values["service"], snapshot.service.describe(process)
                )
            if not metrics:
                self.history_gap = True
                self.missed_samples += 1
                self.latencies.reset()
                retained = self.good_snapshot is not None
                if retained:
                    self.rates.reset()
                    cpu = None
                else:
                    _, _, cpu = self.rates.update(snapshot)
                self.set_label(
                    self.status,
                    "No fresh data · last values retained"
                    if retained
                    else "Traffic unavailable",
                )
                explanation = snapshot.error or "Waiting for metrics"
                if snapshot.port and not options.demo:
                    explanation += ". Enable loopback metrics on the service explicitly, or start a separate resolver from Launch resolver."
                self.set_label(self.detail, explanation)
                self.set_label(
                    self.activity,
                    "No fresh data · chart and statistics held"
                    if retained
                    else "Waiting for the first traffic sample",
                )
                self.overview.add_css_class("stale")
                self.monitoring_page.add_css_class("stale")
                self.set_label(
                    self.values["sample_state"],
                    "No fresh metrics · last interval retained",
                )
                if not retained:
                    self.show_settings(process.invocation if process else None)
                    if process:
                        self.set_label(self.values["pid"], str(process.pid))
                        self.set_label(
                            self.values["memory"],
                            f"{process.memory_bytes / 1048576:.1f} MiB"
                            if process.memory_bytes is not None
                            else "—",
                        )
                        self.set_label(
                            self.values["cpu"],
                            f"{cpu:.1f}%" if cpu is not None else "—",
                        )
                        if process.uptime is not None:
                            hours, rest = divmod(int(process.uptime), 3600)
                            self.set_label(
                                self.values["uptime"],
                                f"{hours}h {rest // 60:02d}m {rest % 60:02d}s",
                            )
                        if snapshot.service:
                            self.set_label(
                                self.values["service"],
                                snapshot.service.describe(process),
                            )
                if (
                    self.owned_process is not None
                    and process
                    and process.pid == self.owned_process.pid
                ):
                    self.set_label(
                        self.launch_status,
                        f"Running PID {process.pid} · traffic metrics unavailable",
                    )
                return
            self.overview.remove_css_class("stale")
            self.monitoring_page.remove_css_class("stale")
            self.good_snapshot = snapshot
            self.telemetry_frame = telemetry
            if (
                self.owned_process is not None
                and process
                and process.pid == self.owned_process.pid
            ):
                self.set_label(
                    self.launch_status,
                    f"Running PID {process.pid} · metrics responding",
                )
            rate, delta, cpu = self.rates.update(snapshot)
            percentile_values = self.latencies.update(snapshot)
            self.last_success = snapshot.at
            self.set_label(
                self.status, ("DEMO · " if options.demo else "") + "Receiving metrics"
            )
            self.set_label(
                self.detail,
                f"127.0.0.1:{snapshot.port}/metrics · "
                + (
                    f"DNSProxy PID {process.pid}"
                    if process and process.pid
                    else "Process settings unavailable"
                ),
            )
            # Compute a complete frame, then update only changed labels. Never
            # blank the displayed frame between two successful snapshots.
            before = {key: label.get_text() for key, label in self.values.items()}
            frame = {key: "—" for key in self.values}
            frame.update(self.telemetry_labels(telemetry))
            frame["sample_age"] = "0.0 s"
            frame["sample_resets"] = number(self.baseline_resets)
            frame["collection_ms"] = (
                f"{self.collection_seconds * 1000:.1f} ms"
                if self.collection_seconds is not None
                else "—"
            )
            if (
                previous
                and not changed
                and self.rates.previous is snapshot
                and rate is None
            ):
                for key in ("client_percentiles", "upstream_percentiles"):
                    frame[key] = before[key]
            frame["rate"] = f"{rate:,.1f}" if rate is not None else before["rate"]
            frame["memory"] = (
                f"{process.memory_bytes / 1048576:.1f} MiB"
                if process and process.memory_bytes is not None
                else "—"
            )
            frame["cpu"] = f"{cpu:.1f}%" if cpu is not None else before["cpu"]
            if process is not None and process.cpu_seconds is None:
                frame["cpu"] = "—"
            frame["pid"] = str(process.pid) if process and process.pid else "—"
            if snapshot.service:
                frame["service"] = snapshot.service.describe(process)
            for key, values in zip(
                ("client_percentiles", "upstream_percentiles"), percentile_values
            ):
                if values is not None:
                    frame[key] = " / ".join(
                        (
                            "above range" if math.isinf(v) else f"{1000 * v:.1f} ms"
                            for v in values
                        )
                    )
            if process and process.uptime is not None:
                hours, rest = divmod(int(process.uptime), 3600)
                frame["uptime"] = f"{hours}h {rest // 60:02d}m {rest % 60:02d}s"
            self.show_settings(process.invocation if process else None)
            if metrics:
                get = metrics.get

                def put(key, name, **labels):
                    frame[key] = number(get(name, **labels))

                def pair(key, first, second):
                    frame[key] = number(get(first)) + " / " + number(get(second))

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
                frame["hedges"] = (
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
                    frame["build"] = (
                        info[0].get("version", "unknown")
                        + " / "
                        + info[0].get("libcurl", "unknown")
                    )
                    frame["capabilities"] = (
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
                frame["http"] = " · ".join(
                    (
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
                    frame[key] = " / ".join(
                        (number(get(name, **{label: v})) for v in variants)
                    )
                duration, count = (
                    get("dnsp_upstream_duration_seconds_sum"),
                    get("dnsp_upstream_duration_seconds_count"),
                )
                if duration is not None and count:
                    frame["latency"] = f"{1000 * duration / count:.1f} ms"

            def peak(attr, value):
                old = getattr(self, attr)
                if value is not None:
                    setattr(self, attr, value if old is None else max(old, value))
                return getattr(self, attr)

            frame["peak_qps"] = number(peak("peak_qps", rate))
            frame["peak_cpu"] = number(peak("peak_cpu", cpu), "%")
            memory = (
                process.memory_bytes / 1048576
                if process and process.memory_bytes is not None
                else None
            )
            maximum = peak("peak_memory", memory)
            frame["peak_memory"] = f"{maximum:.1f} MiB" if maximum is not None else "—"
            frame["peak_inflight"] = number(
                peak("peak_inflight", metrics.get("dnsp_queries_inflight"))
            )
            frame["missed"] = number(self.missed_samples)
            maximum = metrics.get("dnsp_upstream_duration_max_seconds")
            frame["upstream_max"] = (
                f"{maximum * 1000:.1f} ms"
                if maximum is not None
                and metrics.get("dnsp_upstream_duration_seconds_count")
                else "—"
            )
            maxima = [
                metrics.get("dnsp_client_duration_max_seconds", transport=t)
                for t in ("udp", "tcp")
            ]
            frame["client_max"] = (
                f"{max(maxima) * 1000:.1f} ms"
                if all((v is not None for v in maxima))
                and sum(
                    metrics.get("dnsp_client_duration_seconds_count", transport=t) or 0
                    for t in ("udp", "tcp")
                )
                else "—"
            )
            for key, first, second in (
                ("cache_ratio", "dnsp_cache_hits_total", "dnsp_cache_misses_total"),
                (
                    "failure_ratio",
                    "dnsp_upstream_failures_total",
                    "dnsp_upstream_success_total",
                ),
                (
                    "reuse_ratio",
                    "dnsp_upstream_reused_requests_total",
                    "dnsp_upstream_duration_seconds_count",
                ),
            ):
                a, b = metrics.get(first), metrics.get(second)
                frame[key] = (
                    f"{100 * a / (b if key == 'reuse_ratio' else a + b):.1f}%"
                    if a is not None
                    and b is not None
                    and (b if key == "reuse_ratio" else a + b)
                    else "—"
                )
            for key, text in frame.items():
                self.set_label(self.values[key], text)
            self.activity.set_text(
                "Traffic unavailable — last history retained"
                if not metrics
                else "Collecting baseline…"
                if delta is None
                else f"● {int(delta):,} incoming queries since last sample"
                if delta
                else "○ Idle · no incoming queries since last sample"
            )
            if rate is not None:
                if self.history_gap and self.history:
                    self.history.append(None)
                    self.history_times.append(snapshot.at)
                    for history in (
                        self.udp_history,
                        self.tcp_history,
                        self.latency_history,
                        self.upstream_latency_history,
                    ):
                        history.append(None)
                self.history_gap = False
                self.history.append(rate)
                self.history_times.append(snapshot.at)
                for history, transport in (
                    (self.udp_history, "udp"),
                    (self.tcp_history, "tcp"),
                ):
                    value = None
                    if (
                        previous
                        and previous.metrics
                        and snapshot.identity == previous.identity
                    ):
                        elapsed = snapshot.at - previous.at
                        current_count = metrics.get(
                            "dnsp_queries_total", transport=transport
                        )
                        old_count = previous.metrics.get(
                            "dnsp_queries_total", transport=transport
                        )
                        if (
                            elapsed > 0
                            and current_count is not None
                            and old_count is not None
                            and current_count >= old_count
                        ):
                            value = (current_count - old_count) / elapsed
                    history.append(value)
                for history, values in zip(
                    (self.latency_history, self.upstream_latency_history),
                    percentile_values,
                ):
                    value = values[1] * 1000 if values is not None else None
                    history.append(
                        value if value is not None and math.isfinite(value) else None
                    )
                if self.chart.get_visible():
                    self.chart.queue_draw()
                if self.latency_chart.get_visible():
                    self.latency_chart.queue_draw()
            self.update_chart_scale()
            self.latency_scale.set_text(
                "p95 estimates from histogram deltas · pauses and missing timings create gaps"
                if any(v is not None for v in self.latency_history)
                else "Waiting for timing samples"
            )

        def show_settings(self, invocation):
            if invocation is not None and not getattr(invocation, "available", True):
                invocation = None
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
                        "Startup options unavailable for this process. Traffic monitoring still works through loopback metrics."
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

        def draw_history(self, area, cr, width, height):
            color = area.get_style_context().get_color()
            series = (self.history, self.udp_history, self.tcp_history)[
                self.query_series.get_selected()
            ]
            draw_chart(
                cr,
                width,
                height,
                list(series),
                list(self.history_times),
                self.interval,
                (color.red, color.green, color.blue),
            )

        def chart_series_changed(self, *_):
            self.chart.queue_draw()
            self.update_chart_scale()

        def update_chart_scale(self):
            series = (self.history, self.udp_history, self.tcp_history)[
                self.query_series.get_selected()
            ]
            peak = max((value for value in series if value is not None), default=0)
            self.chart_scale.set_text(
                f"{sum(value is not None for value in series)} samples · "
                f"{self.history_times[-1] - self.history_times[0]:.1f} s recorded · "
                f"scale 0–{scale_ceiling(peak):g} queries/s"
                if self.history_times
                else "Waiting for activity history"
            )

        def draw_latency_history(self, area, cr, width, height):
            color = area.get_style_context().get_color()
            series = (self.latency_history, self.upstream_latency_history)[
                self.latency_series.get_selected()
            ]
            if not any(value is not None for value in series):
                cr.set_source_rgba(color.red, color.green, color.blue, 0.65)
                cr.set_font_size(12)
                caption = "Waiting for timing samples"
                cr.move_to(
                    max(12, (width - cr.text_extents(caption)[2]) / 2), height / 2
                )
                cr.show_text(caption)
                return
            draw_chart(
                cr,
                width,
                height,
                list(series),
                list(self.history_times),
                self.interval,
                (color.red, color.green, color.blue),
            )

        def close_monitor(self, *_):
            if self.closed:
                return False
            self.closed = True
            if self.owned_process is not None:
                self.owned_process.stop(wait=False)
            if self.settings_window is not None:
                if self.settings_window.chooser:
                    self.settings_window.chooser.destroy()
                self.settings_window.destroy()
            if self.export_dialog is not None:
                self.export_dialog.destroy()
                self.export_dialog = None
            from gi.repository import Gdk

            Gtk.StyleContext.remove_provider_for_display(
                Gdk.Display.get_default(), self.css_provider
            )
            GLib.source_remove(self.tick_id)
            return False

    class Application(Gtk.Application):
        def __init__(self):
            super().__init__(
                application_id=(
                    "org.dnsproxy.LinuxMonitor"
                    if sys.platform.startswith("linux")
                    else "org.dnsproxy.DesktopMonitor"
                ),
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
    try:
        app = build_application(options)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2
    return app.run([])


if __name__ == "__main__":
    raise SystemExit(main())
