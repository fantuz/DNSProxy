"""Grouped startup editor; keeping an endpoint unchanged retains its exact URL.

The interaction follows the MIT-licensed entropy-service desktop options editor
(Copyright 2026 Massimiliano Fantuzzi HB9GUS); DNSProxy validation stays separate.
"""

from dataclasses import replace

from monitor import display_value


GROUPS = (
    (
        "Local listeners",
        (
            ("binary", "Resolver executable", "file"),
            ("listen", "Listen address", "text"),
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
            ("blocklist", "Blocklist file", "file"),
        ),
        (("cache", "Enable DNS cache"), ("filtering", "Enable domain filtering")),
    ),
)


def edited_config(config, texts, displayed, checks):
    """Apply actual edits without replacing a saved URL with its redacted view."""
    values = {}
    for key, text in texts.items():
        text = text.strip()
        if key in ("upstream", "backup") and text == displayed[key]:
            values[key] = getattr(config, key)
        else:
            values[key] = text
    values.update(checks)
    return replace(config, **values)


def create_settings_window(parent, config, on_apply, Gtk):
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
                    entry = Gtk.Entry(hexpand=True)
                    label.set_mnemonic_widget(entry)
                    grid.attach(label, 0, row, 1, 1)
                    if kind == "file":
                        field = Gtk.Box(spacing=6, hexpand=True)
                        field.append(entry)
                        browse = Gtk.Button(label="Browse…")
                        browse.connect(
                            "clicked",
                            lambda _button, target=entry, name=caption: self.browse(
                                target, name
                            ),
                        )
                        field.append(browse)
                        grid.attach(field, 1, row, 1, 1)
                    else:
                        grid.attach(entry, 1, row, 1, 1)
                    if kind == "url":
                        entry.set_tooltip_text(
                            "Saved credentials, query parameters and fragments are hidden. Leaving this field unchanged retains the original full URL; editing it replaces that URL."
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
            reset = Gtk.Button(label="Reset changes")
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
            self.status_label.set_text("")

        def draft(self):
            return edited_config(
                self.config,
                {key: entry.get_text() for key, entry in self.entries.items()},
                self.displayed,
                {key: check.get_active() for key, check in self.checks.items()},
            )

        def apply(self, *_):
            try:
                changed = self.draft()
                changed.argv()
                on_apply(changed)
            except (ValueError, OSError) as error:
                self.status_label.set_text(str(error))
                self.status_label.add_css_class("error")
                return
            self.config = changed
            self.reset()
            self.status_label.remove_css_class("error")
            self.hide()

        def close_requested(self, *_):
            self.reset()
            self.hide()
            if self.chooser:
                self.chooser.destroy()
                self.chooser = None
            return True

        def browse(self, target, caption):
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
                        target.set_text(chosen.get_path())
                dialog.destroy()
                self.chooser = None

            chooser.connect("response", selected)
            chooser.show()

    return SettingsWindow()
