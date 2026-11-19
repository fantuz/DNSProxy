"""Private Windows runtime configuration and argument forwarding without GTK."""

import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
bootstrap = runpy.run_path(str(ROOT / "packaging/windows/gui-bootstrap.py"))


class BootstrapTests(unittest.TestCase):
    def test_default_binary_and_endpoint_are_absolute_and_explicit_values_are_kept(
        self,
    ):
        root = Path("/installed path/DNSProxy/gui")
        arguments = bootstrap["launch_arguments"](root, [])
        self.assertEqual(
            arguments,
            [
                "--binary",
                str(root.parent / "bin/dnsp-modern.exe"),
                "--metrics-port",
                "9090",
            ],
        )
        for explicit in (
            ["--metrics-port", "9911"],
            ["--metrics-port=9911"],
            ["--pid", "81"],
            ["--demo"],
        ):
            values = bootstrap["launch_arguments"](root, explicit)
            self.assertEqual(values[2:], explicit)
        explicit = [
            "--binary",
            "a selected binary.exe",
            "--metrics-port",
            "9911",
            "--interval",
            ".25",
        ]
        self.assertEqual(bootstrap["launch_arguments"](root, explicit), explicit)

    def test_runtime_resources_and_cache_relocate_without_writing_program_directory(
        self,
    ):
        with tempfile.TemporaryDirectory(prefix="DNSProxy GUI ") as temporary:
            # Windows runners may expose TEMP through an 8.3 alias. Match the
            # canonical paths used by the installed bootstrap.
            temporary = Path(temporary).resolve()
            root, state = (
                temporary / "installed/gui",
                temporary / "user state",
            )
            (root / "runtime/bin").mkdir(parents=True)
            before = set(root.rglob("*"))
            previous_directory, previous_path = Path.cwd(), list(sys.path)
            try:
                with (
                    patch.object(os, "add_dll_directory", create=True) as dll,
                    patch.dict(os.environ, {}, clear=True),
                ):
                    bootstrap["configure_runtime"](root, state)
                    dll.assert_called_once_with(str(root / "runtime/bin"))
                    self.assertEqual(
                        os.environ["GI_TYPELIB_PATH"],
                        str(root / "runtime/lib/girepository-1.0"),
                    )
                    self.assertEqual(
                        os.environ["FONTCONFIG_FILE"],
                        str(root / "runtime/etc/fonts/fonts.conf"),
                    )
                    self.assertEqual(os.environ["XDG_CACHE_HOME"], str(state / "cache"))
                    self.assertEqual(Path.cwd(), state)
                    self.assertEqual(sys.path[0], str(root / "app"))
                    self.assertEqual(set(root.rglob("*")), before)
            finally:
                os.chdir(previous_directory)
                sys.path[:] = previous_path


if __name__ == "__main__":
    unittest.main()
