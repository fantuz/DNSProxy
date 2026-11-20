"""GTK-independent regressions for lossless grouped startup settings."""

from dataclasses import replace
from pathlib import Path
import re
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
from monitor import display_value, parse_invocation  # noqa: E402
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
        minimum = "1\\.\\.65535" if sys.platform == "win32" else "1024"
        with self.assertRaisesRegex(ValueError, minimum):
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

    def test_repeated_listeners_and_policy_paths_preserve_native_arguments(self):
        with tempfile.TemporaryDirectory(prefix="DNSProxy policies ") as directory:
            files = [
                Path(directory) / name
                for name in ("first list.txt", "second;literal.txt", "allow list.txt")
            ]
            for path in files:
                path.write_text("example.org\n")
            config = ResolverConfig(
                listen="127.0.0.1, ::1",
                filtering=True,
                blocklist="\n".join(map(str, files[:2])),
                allowlist=str(files[2]),
                block_response="nxdomain",
                blocklist_reload_ms="0",
            )
            parsed = parse_invocation(config.argv())
            self.assertEqual(parsed.values["-l"], ("127.0.0.1", "::1"))
            self.assertEqual(parsed.values["--blocklist"], tuple(map(str, files[:2])))
            self.assertEqual(parsed.values["--allowlist"], (str(files[2]),))
            self.assertEqual(parsed.get("--block-response"), "nxdomain")
            self.assertEqual(parsed.number("--blocklist-reload-ms"), 0)

    def test_all_running_cli_options_have_a_validated_editor_mapping(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "dnsp-modern.c").read_text()
        usage = source.split("static void usage(", 1)[1].split(
            "static int dnsp_run(", 1
        )[0]
        expected = set(re.findall(r'"  (--[a-z-]+|-[lpsm])\s', usage))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.txt"
            policy.write_text("example.org\n")
            ca_file = Path(directory) / "root.pem"
            ca_file.write_text(
                "fixture only; URL parsing is checked by the resolver at startup\n"
            )
            config = ResolverConfig(
                filtering=True,
                blocklist=str(policy),
                allowlist=str(policy),
                ca_file=str(ca_file),
                padding=True,
                http3=True,
                backup_enabled=True,
                hedge=True,
            )
            command = config.argv(check_blocklists=True)
            represented = {
                part.split("=", 1)[0] for part in command if part.startswith("-")
            }
            self.assertEqual(expected, represented)
            parsed = parse_invocation(config.argv())
            self.assertFalse(parsed.unknown)
            for option, value in (
                ("--max-host-connections", 8),
                ("--tcp-max-per-source", 32),
                ("--tcp-idle-ms", 15000),
                ("--tcp-io-ms", 15000),
                ("--doh-connect-ms", 1500),
                ("--doh-timeout-ms", 3000),
                ("--udp-reply-max", 1232),
            ):
                self.assertEqual(parsed.number(option), value)

    def test_cli_bounds_and_interdependent_deadlines_reject_invalid_drafts(self):
        invalid = (
            {"listen": ""},
            {"listen": "\n".join(["::1"] * 9)},
            {"max_host_connections": "17"},
            {"tcp_max_per_source": "129"},
            {"tcp_idle_ms": "99"},
            {"tcp_io_ms": "600001"},
            {"doh_connect_ms": "99"},
            {"doh_timeout_ms": "60001"},
            {"doh_connect_ms": "4000", "doh_timeout_ms": "3000"},
            {"udp_reply_max": "511"},
            {"udp_reply_max": "4097"},
            {"tcp_idle_ms": "100; echo bad"},
            {"tcp_io_ms": "١٠٠"},
            {"backup_enabled": True, "hedge": True, "hedge_ms": "3000"},
        )
        original = ResolverConfig()
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ValueError):
                replace(original, **values).argv()
        self.assertEqual(original, ResolverConfig())

    def test_policy_limits_match_cli_and_disabled_policy_keeps_saved_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "block.txt"
            path.write_text("example.org\n")
            base = ResolverConfig(filtering=True, blocklist=str(path))
            for values in (
                {"block_response": "anything"},
                {"blocklist_reload_ms": "1"},
                {"blocklist_reload_ms": "86400001"},
                {"allowlist": "\n".join([str(path)] * 64)},
            ):
                with self.subTest(values=values), self.assertRaises(ValueError):
                    replace(base, **values).argv()
            maximum = replace(base, allowlist="\n".join([str(path)] * 63))
            self.assertEqual(maximum.argv().count("--allowlist"), 63)
            disabled = replace(base, filtering=False, blocklist="/saved/missing/list")
            self.assertNotIn("--blocklist", disabled.argv())
            self.assertEqual(disabled.blocklist, "/saved/missing/list")
            self.assertIn("--check-blocklists", base.argv(check_blocklists=True))

    def test_all_editor_fields_apply_without_losing_advanced_values_or_secrets(self):
        original = ResolverConfig(
            upstream="https://user:secret@localhost/a?token=private",
            listen="127.0.0.1\n::1",
            max_host_connections="4",
            tcp_idle_ms="900",
            blocklist="first path.txt\nsecond path.txt",
            allowlist="exception path.txt",
        )
        texts, displayed, checks = editor_values(original)
        changed = edited_config(original, texts, displayed, checks)
        self.assertEqual(changed, original)
        self.assertEqual(set(texts) | set(checks), set(vars(original)))


if __name__ == "__main__":
    unittest.main()
