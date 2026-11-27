"""Homebrew interpreter selection, argv integrity and the extracted Mac GUI."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools/desktop-gui/dnsp-gui-macos"


@unittest.skipIf(sys.platform == "win32", "POSIX launcher fixtures")
class MacGuiLauncherTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="DNSProxy GUI launcher ") as temporary:
            root = Path(temporary)
            commands, source, prefix = (
                root / "commands",
                root / "GUI source",
                root / "Homebrew prefix",
            )
            for path in (commands, source, prefix / "bin"):
                path.mkdir(parents=True)
            launcher = source / "dnsp-gui-macos"
            shutil.copyfile(LAUNCHER, launcher)
            for name, variable in (
                ("uname", "TEST_UNAME"),
                ("brew", "TEST_BREW_PREFIX"),
            ):
                path = commands / name
                path.write_text(f"#!/bin/sh\nprintf '%s\\n' \"${variable}\"\n")
                path.chmod(0o755)
            environment = dict(
                os.environ,
                PATH=str(commands) + os.pathsep + os.defpath,
                TEST_UNAME="Darwin",
                TEST_BREW_PREFIX=str(prefix),
                TEST_GUI_ARGV=str(root / "argv.json"),
            )
            yield root, launcher, prefix, environment

    def python(self, path, *, valid=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"#!{sys.executable}\n"
            "import json,os,sys\nfrom pathlib import Path\n"
            f'if sys.argv[1] == "-c": raise SystemExit({0 if valid else 1})\n'
            'Path(os.environ["TEST_GUI_ARGV"]).write_text(json.dumps('
            '{"argv":sys.argv[1:],"executable":sys.argv[0],"PATH":os.environ["PATH"]}))\n'
        )
        path.chmod(0o755)

    @staticmethod
    def run_launcher(launcher, environment, *arguments):
        return subprocess.run(
            ["/bin/sh", str(launcher), *arguments],
            env=environment,
            text=True,
            capture_output=True,
            timeout=5,
        )

    def test_source_launcher_preserves_paths_arguments_and_environment(self):
        with self.fixture() as (root, launcher, prefix, environment):
            self.python(prefix / "bin/python3")
            arguments = [
                "--binary",
                "/a path/dnsp-modern",
                "--metrics-port",
                "9090",
                "--example",
                "an apostrophe's value; $(not-a-command)",
            ]
            result = self.run_launcher(launcher, environment, *arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((root / "argv.json").read_text())
            self.assertEqual(
                record["argv"],
                [str((launcher.parent / "dnsp-gui.py").resolve()), *arguments],
            )
            self.assertEqual(record["PATH"], environment["PATH"])

    def test_finder_reports_the_compatible_python_with_its_full_path(self):
        with self.fixture() as (root, launcher, prefix, environment):
            selected = prefix / "bin/python3"
            self.python(selected)
            result = self.run_launcher(launcher, environment, "--print-python")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, str(selected) + "\n")
            self.assertFalse((root / "argv.json").exists())

    def test_python_check_uses_the_selected_interpreter_without_inserting_gui(self):
        with self.fixture() as (root, launcher, prefix, environment):
            self.python(prefix / "bin/python3")
            arguments = [
                "/a path/test script.py",
                "--binary",
                "/another path/dnsp-modern",
            ]
            result = self.run_launcher(
                launcher, environment, "--python-check", *arguments
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads((root / "argv.json").read_text())["argv"], arguments
            )

    def test_missing_bindings_fall_back_to_a_compatible_versioned_python(self):
        with self.fixture() as (root, launcher, prefix, environment):
            self.python(prefix / "bin/python3", valid=False)
            versioned = prefix / "opt/python@3.14/bin/python3.14"
            self.python(versioned)
            result = self.run_launcher(launcher, environment, "--demo")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads((root / "argv.json").read_text())["executable"],
                str(versioned),
            )

    def test_missing_runtime_and_incomplete_python_check_are_actionable(self):
        with self.fixture() as (_, launcher, prefix, environment):
            result = self.run_launcher(launcher, environment)
            self.assertEqual(result.returncode, 2)
            self.assertIn("brew install gtk4 pygobject3", result.stderr)
            self.python(prefix / "bin/python3")
            result = self.run_launcher(launcher, environment, "--python-check")
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires a Python script or option", result.stderr)

    def test_non_macos_diagnostic_does_not_launch_a_runtime(self):
        with self.fixture() as (root, launcher, prefix, environment):
            self.python(prefix / "bin/python3")
            environment["TEST_UNAME"] = "Linux"
            result = self.run_launcher(launcher, environment)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires macOS", result.stderr)
            self.assertFalse((root / "argv.json").exists())

    def test_packaged_command_selects_adjacent_binary_from_another_directory(self):
        with tempfile.TemporaryDirectory(prefix="DNSProxy portable GUI ") as temporary:
            root = Path(temporary) / "portable bundle"
            (root / "gui").mkdir(parents=True)
            command = root / "Start-DNSProxy-GUI.command"
            shutil.copyfile(
                ROOT / "packaging/macos/Start-DNSProxy-GUI.command", command
            )
            log = root / "argv.json"
            handoff = root / "gui/dnsp-gui-macos"
            handoff.write_text(
                f"#!{sys.executable}\nimport json,sys\nfrom pathlib import Path\n"
                f"Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n"
            )
            handoff.chmod(0o755)
            result = subprocess.run(
                ["/bin/sh", str(command), "--metrics-port", "9110"],
                cwd=temporary,
                text=True,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(log.read_text()),
                [
                    "--binary",
                    str((root / "dnsp-modern").resolve()),
                    "--metrics-port",
                    "9110",
                ],
            )


@unittest.skipUnless(
    sys.platform == "darwin" and os.environ.get("DNSP_TEST_BINARY"),
    "Requires the extracted native macOS archive and Homebrew GUI runtime",
)
class NativeMacGuiPackageTests(unittest.TestCase):
    def test_payload_checksums_and_launcher_from_another_directory(self):
        root = Path(os.environ["DNSP_TEST_BINARY"]).resolve().parent
        expected = {
            "Start-DNSProxy-GUI.command",
            "MACOS-GUI.md",
            "gui/dnsp-gui.py",
            "gui/dnsp-gui-macos",
            "gui/chart.py",
            "gui/monitor.py",
            "gui/launcher.py",
        }
        found = set()
        for line in (root / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ", 1)
            relative = PurePosixPath(name)
            self.assertFalse(relative.is_absolute())
            self.assertNotIn("..", relative.parts)
            found.add(relative.as_posix().removeprefix("./"))
            self.assertEqual(
                hashlib.sha256((root / name).read_bytes()).hexdigest(), digest, name
            )
        self.assertTrue(expected <= found, expected - found)
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        }
        self.assertEqual(found, actual)
        self.assertTrue(os.access(root / "Start-DNSProxy-GUI.command", os.X_OK))
        self.assertTrue(os.access(root / "gui/dnsp-gui-macos", os.X_OK))
        with tempfile.TemporaryDirectory() as current:
            result = subprocess.run(
                [str(root / "Start-DNSProxy-GUI.command"), "--help"],
                cwd=current,
                text=True,
                capture_output=True,
                timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--metrics-port", result.stdout)
        self.assertIn("--binary", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
