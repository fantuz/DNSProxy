"""Grouped startup editor; keeping an endpoint unchanged retains its exact URL.

The interaction follows the MIT-licensed entropy-service desktop options editor
(Copyright 2026 Massimiliano Fantuzzi HB9GUS); DNSProxy validation stays separate.
"""

from dataclasses import replace
import threading

from launcher import endpoint_host, validate_policy

from monitor import display_value


GROUPS = (
    (
        "Local listeners",
        (
            ("binary", "Resolver executable", "file"),
            ("listen", "Listen addresses (up to 8)", "lines"),
            ("port", "DNS port", "text"),
            ("metrics_port", "Metrics port", "text"),
        ),
        (("metrics", "Enable loopback traffic metrics"),),
    ),
    (
        "DoH upstreams",
        (
            ("upstream", "Primary HTTPS URL", "url"),
            ("bootstrap", "Primary bootstrap IP", "text"),
            ("backup", "Backup HTTPS URL", "url"),
            ("backup_bootstrap", "Backup bootstrap IP", "text"),
            ("hedge_ms", "Parallel request delay (ms)", "text"),
            ("ca_file", "Custom CA bundle", "file"),
        ),
        (
            ("backup_enabled", "Enable backup upstream"),
            ("hedge", "Delay and race backup requests"),
            ("http3", "Prefer HTTP/3 with fallback"),
            ("padding", "Pad EDNS requests"),
        ),
    ),
    (
        "Cache and filtering",
        (
            ("cache_entries", "Cache entries", "text"),
            ("blocklist", "Blocklist files (one per line)", "files"),
            ("allowlist", "Allowlist files (one per line)", "files"),
            (
                "block_response",
                "Block response (refused / nxdomain / nodata / null)",
                "text",
            ),
            ("blocklist_reload_ms", "File check interval (ms; 0 disables)", "text"),
        ),
        (("cache", "Enable DNS cache"), ("filtering", "Enable domain filtering")),
    ),
    (
        "Connection limits and deadlines",
        (
            ("max_host_connections", "Upstream connections (1–16)", "text"),
            ("tcp_max_per_source", "TCP connections per source (1–128)", "text"),
            ("tcp_idle_ms", "TCP idle timeout (ms)", "text"),
            ("tcp_io_ms", "TCP read/write deadline (ms)", "text"),
            ("doh_connect_ms", "DoH connection deadline (ms)", "text"),
            ("doh_timeout_ms", "DoH total deadline (ms)", "text"),
            ("udp_reply_max", "UDP reply ceiling (512–4096 bytes)", "text"),
        ),
        (),
    ),
)


def edited_config(config, texts, displayed, checks, edited_pins=()):
    """Apply actual edits without replacing a saved URL with its redacted view."""
    values = {}
    for key, text in texts.items():
        text = text.strip()
        if key in ("upstream", "backup") and text == displayed[key]:
            values[key] = getattr(config, key)
        else:
            values[key] = text
    for endpoint, pin in (("upstream", "bootstrap"), ("backup", "backup_bootstrap")):
        if (
            pin not in edited_pins
            and values[pin] == getattr(config, pin)
            and endpoint_host(values[endpoint])
            != endpoint_host(getattr(config, endpoint))
        ):
            values[pin] = ""
    values.update(checks)
    return replace(config, **values)


def create_settings_window(parent, config, on_apply, Gtk):
    from gi.repository import GLib

    class MultilineField(Gtk.TextView):
        """Retain the entry editing boundary used by native interface tests."""

        def __init__(self):
            super().__init__(hexpand=True)
            self.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            self.set_top_margin(6)
            self.set_bottom_margin(6)
            self.set_left_margin(6)
            self.set_right_margin(6)

        def get_text(self):
            buffer = self.get_buffer()
            return buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), True)

        def set_text(self, text):
            self.get_buffer().set_text(text)

    class SettingsWindow(Gtk.Window):
        def __init__(self):
            super().__init__(
                title="DNSProxy · Resolver options",
                transient_for=parent,
                modal=True,
                destroy_with_parent=True,
            )
            self.config = config
            self.entries, self.checks, self.controls = {}, {}, {}
            self.displayed = {}
            self.chooser = None
            self.policy_check = None
            self.edited_pins = set()
            self.connect("unmap", lambda *_: self.cancel_check())
            self.set_default_size(760, 720)
            self.set_size_request(480, 400)
            self.set_titlebar(Gtk.HeaderBar())
            self.connect("close-request", self.close_requested)
            body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            for side in ("top", "bottom", "start", "end"):
                getattr(body, "set_margin_" + side)(16)
            self.set_child(body)
            hint = Gtk.Label(
                label="Settings apply to the next resolver started by this window. Existing services and adapter DNS are unchanged.",
                xalign=0,
                wrap=True,
            )
            hint.add_css_class("dim-label")
            body.append(hint)
            form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
            self.form = form
            scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
            scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
            scroller.set_child(form)
            body.append(scroller)
            for title, entries, switches in GROUPS:
                group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
                group.add_css_class("info-panel")
                heading = Gtk.Label(label=title, xalign=0)
                heading.add_css_class("section-heading")
                group.append(heading)
                grid = Gtk.Grid(column_spacing=16, row_spacing=10, hexpand=True)
                for row, (key, caption, kind) in enumerate(entries):
                    label = Gtk.Label(label=caption, xalign=0, wrap=True)
                    label.set_max_width_chars(23)
                    entry = (
                        MultilineField()
                        if kind in {"lines", "files"}
                        else Gtk.Entry(hexpand=True)
                    )
                    widget = entry
                    if kind in {"lines", "files"}:
                        widget = Gtk.ScrolledWindow(hexpand=True)
                        widget.set_policy(
                            Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC
                        )
                        widget.set_min_content_height(74)
                        widget.set_max_content_height(112)
                        widget.set_child(entry)
                        entry.set_tooltip_text(
                            "One complete file path per line. Spaces are part of the path; Browse appends a file."
                            if kind == "files"
                            else "One numeric IPv4 or IPv6 address per line; commas are also accepted."
                        )
                    label.set_mnemonic_widget(entry)
                    grid.attach(label, 0, row, 1, 1)
                    if kind in {"file", "files"}:
                        field = Gtk.Box(spacing=6, hexpand=True)
                        field.append(widget)
                        browse = Gtk.Button(label="Browse…")
                        browse.connect(
                            "clicked",
                            lambda _button,
                            target=entry,
                            name=caption,
                            append=kind == "files": self.browse(
                                target, name, append=append
                            ),
                        )
                        field.append(browse)
                        grid.attach(field, 1, row, 1, 1)
                    else:
                        grid.attach(widget, 1, row, 1, 1)
                    if kind == "url":
                        entry.set_tooltip_text(
                            "Saved credentials, query parameters and fragments are hidden. Leaving this field unchanged retains the original full URL; editing it replaces that URL."
                        )
                    if key in ("bootstrap", "backup_bootstrap"):
                        entry.set_tooltip_text(
                            "Changing the provider hostname clears its previous IP unless you also edit this field."
                        )
                        entry.connect(
                            "changed",
                            lambda _entry, name=key: self.edited_pins.add(name),
                        )
                    self.entries[key] = self.controls[key] = entry
                group.append(grid)
                for key, caption in switches:
                    check = Gtk.CheckButton(label=caption)
                    group.append(check)
                    self.checks[key] = self.controls[key] = check
                form.append(group)
            self.status_label = Gtk.Label(xalign=0, wrap=True, selectable=True)
            body.append(self.status_label)
            buttons = Gtk.Box(spacing=8)
            reset = self.reset_button = Gtk.Button(label="Reset changes")
            reset.connect("clicked", lambda *_: self.reset())
            buttons.append(reset)
            buttons.append(Gtk.Box(hexpand=True))
            close = Gtk.Button(label="Close")
            close.connect("clicked", lambda *_: self.close())
            buttons.append(close)
            self.apply_button = Gtk.Button(label="Validate and apply")
            self.apply_button.add_css_class("suggested-action")
            self.apply_button.connect("clicked", self.apply)
            buttons.append(self.apply_button)
            body.append(buttons)
            self.reset()

        def reset(self):
            for key, entry in self.entries.items():
                value = str(getattr(self.config, key))
                if key in ("upstream", "backup"):
                    value = display_value("-s", value)
                self.displayed[key] = value
                entry.set_text(value)
            for key, check in self.checks.items():
                check.set_active(getattr(self.config, key))
            self.edited_pins.clear()
            self.status_label.set_text("")

        def draft(self):
            return edited_config(
                self.config,
                {key: entry.get_text() for key, entry in self.entries.items()},
                self.displayed,
                {key: check.get_active() for key, check in self.checks.items()},
                self.edited_pins,
            )

        def cancel_check(self):
            if self.policy_check is not None:
                self.policy_check.set()
                self.policy_check = None
                self.form.set_sensitive(True)
                self.apply_button.set_sensitive(True)
                self.reset_button.set_sensitive(True)

        def finish_apply(self, changed, error=""):
            try:
                if error:
                    raise ValueError(error)
                on_apply(changed)
            except (ValueError, OSError) as failure:
                self.status_label.set_text(str(failure))
                self.status_label.add_css_class("error")
                return
            self.config = changed
            self.reset()
            self.status_label.remove_css_class("error")
            self.hide()

        def apply(self, *_):
            if self.policy_check is not None:
                return
            try:
                changed = self.draft()
                command = changed.argv(check_blocklists=changed.filtering)
            except (ValueError, OSError) as error:
                self.status_label.set_text(str(error))
                self.status_label.add_css_class("error")
                return
            if not changed.filtering:
                self.finish_apply(changed)
                return
            cancel = self.policy_check = threading.Event()
            self.form.set_sensitive(False)
            self.apply_button.set_sensitive(False)
            self.reset_button.set_sensitive(False)
            self.status_label.remove_css_class("error")
            self.status_label.set_text("Checking policy files with the resolver…")

            def finished(error):
                if self.policy_check is cancel:
                    self.cancel_check()
                    self.finish_apply(changed, error)
                return False

            def check():
                error = ""
                try:
                    validate_policy(command, cancel)
                except (ValueError, OSError) as failure:
                    error = str(failure)
                if not cancel.is_set():
                    GLib.idle_add(finished, error)

            threading.Thread(target=check, name="DNSProxy policy validation").start()

        def close_requested(self, *_):
            self.cancel_check()
            self.reset()
            self.hide()
            if self.chooser:
                self.chooser.destroy()
                self.chooser = None
            return True

        def browse(self, target, caption, *, append=False):
            if self.chooser:
                self.chooser.show()
                return
            chooser = Gtk.FileChooserNative.new(
                "Select " + caption.lower(),
                self,
                Gtk.FileChooserAction.OPEN,
                "Select",
                "Cancel",
            )
            self.chooser = chooser

            def selected(dialog, response):
                if response == Gtk.ResponseType.ACCEPT:
                    chosen = dialog.get_file()
                    if chosen and chosen.get_path():
                        path = chosen.get_path()
                        previous = target.get_text().strip()
                        target.set_text(
                            previous + "\n" + path if append and previous else path
                        )
                dialog.destroy()
                self.chooser = None

            chooser.connect("response", selected)
            chooser.show()

    return SettingsWindow()
