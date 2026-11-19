"""GTK-independent regressions for lossless grouped startup settings."""

from pathlib import Path
import os
import sys
import tempfile
import unittest

SOURCE = Path(
    os.environ.get(
        "DNSP_GUI_SOURCE", Path(__file__).resolve().parents[1] / "tools/desktop-gui"
    )
)
sys.path.insert(0, str(SOURCE))
from launcher import ResolverConfig  # noqa: E402
from monitor import display_value  # noqa: E402
from settings import GROUPS, edited_config  # noqa: E402


def editor_values(config):
    texts, displayed, checks = {}, {}, {}
    for _, entries, switches in GROUPS:
        for name, _, kind in entries:
            value = str(getattr(config, name))
            if kind == "url":
                value = display_value("-s", value)
            texts[name] = displayed[name] = value
        for name, _ in switches:
            checks[name] = getattr(config, name)
    return texts, displayed, checks


class SettingsTests(unittest.TestCase):
    def test_unrelated_edit_retains_hidden_url_parts_exactly(self):
        original_url = (
            "https://user:secret@localhost/dns-query?token=private#private-fragment"
        )
        original = ResolverConfig(upstream=original_url)
        texts, displayed, checks = editor_values(original)
        self.assertNotIn("secret", texts["upstream"])
        self.assertNotIn("private", texts["upstream"])
        texts["port"] = "5301"
        changed = edited_config(original, texts, displayed, checks)
        self.assertEqual(changed.upstream, original_url)
        self.assertEqual(changed.port, "5301")
        self.assertEqual(original.port, "5300")

    def test_an_edited_url_replaces_the_complete_endpoint(self):
        original = ResolverConfig(
            upstream="https://user:secret@localhost/a?token=private"
        )
        texts, displayed, checks = editor_values(original)
        texts["upstream"] = "https://dns.google/dns-query"
        changed = edited_config(original, texts, displayed, checks)
        changed.argv()
        self.assertEqual(changed.upstream, texts["upstream"])
        self.assertEqual(
            original.upstream, "https://user:secret@localhost/a?token=private"
        )

    def test_invalid_edit_does_not_mutate_the_original_configuration(self):
        original = ResolverConfig()
        texts, displayed, checks = editor_values(original)
        texts["port"] = "0"
        changed = edited_config(original, texts, displayed, checks)
        with self.assertRaisesRegex(ValueError, "1024"):
            changed.argv()
        self.assertEqual(original.port, "5300")
        self.assertEqual(original.argv()[original.argv().index("-p") + 1], "5300")

    def test_file_paths_with_spaces_are_single_native_arguments(self):
        original = ResolverConfig()
        texts, displayed, checks = editor_values(original)
        with tempfile.TemporaryDirectory(prefix="DNSProxy settings ") as directory:
            path = Path(directory) / "blocked domains.txt"
            path.write_text("blocked.example\n")
            texts["blocklist"] = str(path)
            checks["filtering"] = True
            changed = edited_config(original, texts, displayed, checks)
            arguments = changed.argv()
            self.assertEqual(arguments[arguments.index("--blocklist") + 1], str(path))
            self.assertFalse(original.filtering)


if __name__ == "__main__":
    unittest.main()
