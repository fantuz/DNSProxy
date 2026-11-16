"""Check the installed optional GUI with the distribution's system Python."""

import configparser
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

root = Path("/usr/share/dnsp-modern-gui")
sys.path.insert(0, str(root))
import monitor  # noqa: E402
import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

assert Gtk.get_major_version() == 4
assert monitor.Invocation().number("--upstream-hedge-ms") == 0
desktop = configparser.ConfigParser(interpolation=None)
desktop.read("/usr/share/applications/org.dnsproxy.LinuxMonitor.desktop")
assert desktop["Desktop Entry"]["Exec"] == "dnsp-gui"
assert desktop["Desktop Entry"]["Terminal"] == "false"
assert (
    ET.parse("/usr/share/icons/hicolor/scalable/apps/dnsp-modern.svg")
    .getroot()
    .tag.endswith("svg")
)
result = subprocess.run(
    ["/usr/bin/dnsp-gui", "--help"],
    capture_output=True,
    text=True,
    timeout=5,
    check=True,
)
assert "--pid" in result.stdout and "--demo" in result.stdout
print("Installed GUI launcher, GTK4 imports, desktop entry and icon are valid")
