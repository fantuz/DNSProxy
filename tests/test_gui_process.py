"""Real owned-process lifecycle, bounded diagnostics and platform launch rules."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GUI_SOURCE = Path(
    os.environ.get("DNSP_GUI_SOURCE", ROOT / "tools/desktop-gui")
).resolve()
sys.path.insert(0, str(GUI_SOURCE))
from owned_process import MAX_LOG_BYTES, OwnedResolver, safe_text  # noqa: E402
from launcher import ResolverConfig, command_preview, default_binary  # noqa: E402


def wait_for(test, condition, seconds=5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return
        time.sleep(0.02)
    test.fail("Owned process condition did not complete")


class OwnedProcessTests(unittest.TestCase):
    def process(self, code):
        process = OwnedResolver([sys.executable, "-I", "-B", "-u", "-c", code]).start()
        self.addCleanup(process.close)
        return process

    def test_graceful_stop_reaps_only_owned_process_and_keeps_logs(self):
        unrelated = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(20)"]
        )
        self.addCleanup(
            lambda: (unrelated.terminate(), unrelated.wait(timeout=5))
            if unrelated.poll() is None
            else None
        )
        code = (
            "import signal,sys,time; "
            "signal.signal(getattr(signal,'SIGBREAK',signal.SIGTERM),lambda *_:sys.exit(0)); "
            "sys.stderr.write('ready\\n'); sys.stderr.flush()\n"
            # Windows SIGBREAK handlers run on the next Python bytecode check;
            # one long native sleep delays the fixture's handler past Stop's limit.
            "while True: time.sleep(.02)"
        )
        process = self.process(code)
        wait_for(self, lambda: "ready" in process.snapshot()["logs"])
        before = time.monotonic()
        process.stop()
        self.assertLess(time.monotonic() - before, 0.5)
        wait_for(
            self,
            lambda: not process.snapshot()["running"]
            and not process.snapshot()["stopping"],
        )
        self.assertEqual(process.poll(), 0, process.snapshot())
        self.assertFalse(process.snapshot()["forced_stop"])
        self.assertIn("ready", process.snapshot()["logs"])
        self.assertIsNone(unrelated.poll())
        self.assertFalse(
            process._stopper.daemon, "Interpreter exit must wait for bounded shutdown"
        )

    def test_log_ring_is_bounded_and_never_discloses_partial_or_url_secrets(self):
        code = (
            "import sys; sys.stderr.write('https://user:secret@example.org/path?token=private#fragment\\n'); "
            f"sys.stderr.write('a'*{MAX_LOG_BYTES * 2}); "
            "sys.stderr.write('\\nlast https://user:secret@example.org/path?token=private#fragment\\n'); sys.stderr.flush()"
        )
        process = self.process(code)
        process.wait(timeout=5)
        snapshot = process.snapshot()
        self.assertLessEqual(len(process._logs), MAX_LOG_BYTES)
        self.assertLessEqual(len(snapshot["logs"]), MAX_LOG_BYTES)
        self.assertIn("last https://example.org/path?[redacted]", snapshot["logs"])
        for secret in ("secret", "user:", "token=private", "fragment", "a" * 100):
            self.assertNotIn(secret, snapshot["logs"])

    def test_forced_stop_is_reported_and_is_bounded(self):
        code = (
            "import signal,sys,time; signal.signal(getattr(signal,'SIGBREAK',signal.SIGTERM),signal.SIG_IGN); "
            "sys.stderr.write('ready\\n'); sys.stderr.flush(); time.sleep(20)"
        )
        process = self.process(code)
        wait_for(self, lambda: "ready" in process.snapshot()["logs"])
        start = time.monotonic()
        process.stop(wait=True, timeout=0.15)
        self.assertLess(time.monotonic() - start, 4)
        self.assertTrue(process.snapshot()["forced_stop"])
        self.assertIn("forced termination", process.snapshot()["error"])

    def test_missing_executable_and_concurrent_start_fail_without_losing_ownership(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            missing = OwnedResolver([str(Path(directory) / "missing-resolver")])
            with self.assertRaisesRegex(RuntimeError, "Could not start"):
                missing.start()
            self.assertFalse(missing.snapshot()["running"])
            self.assertTrue(missing.snapshot()["error"])
        process = self.process("import time; time.sleep(20)")
        with self.assertRaisesRegex(RuntimeError, "already running"):
            process.start()
        self.assertTrue(process.snapshot()["running"])

    def test_windows_command_scripts_and_nul_arguments_are_rejected(self):
        with patch("owned_process.sys.platform", "win32"):
            for binary in ("run.cmd", "run.BAT", "run.cmd "):
                with self.assertRaisesRegex(RuntimeError, "native resolver"):
                    OwnedResolver([binary]).start()
            with self.assertRaisesRegex(ValueError, "native resolver"):
                ResolverConfig(binary="run.cmd").argv()
        with self.assertRaisesRegex(RuntimeError, "NUL"):
            OwnedResolver([sys.executable, "\0"]).start()

    def test_eof_pipe_does_not_claim_a_running_child_exited(self):
        process = self.process("import os,time; os.close(2); time.sleep(20)")
        wait_for(
            self, lambda: process._reader is not None and not process._reader.is_alive()
        )
        self.assertTrue(process.snapshot()["running"])
        process.stop(wait=True)
        self.assertFalse(process.snapshot()["running"])


class LaunchPresentationTests(unittest.TestCase):
    def test_platform_quoting_and_url_redaction_do_not_change_actual_argv(self):
        command = [
            r"C:\Program Files\DNSProxy\bin\dnsp-modern.exe",
            "-s",
            "https://user:secret@example.org/query?token=private",
            "--ca-file",
            r"C:\a path\root.pem",
        ]
        original = list(command)
        with patch("launcher.sys.platform", "win32"):
            display = command_preview(command)
            exact = command_preview(command, redact=False)
        self.assertIn('"C:\\Program Files\\DNSProxy\\bin\\dnsp-modern.exe"', display)
        self.assertIn("https://example.org/query?[redacted]", display)
        self.assertNotIn("secret", display)
        self.assertIn("secret", exact)
        self.assertEqual(command, original)
        self.assertNotIn(
            "secret",
            safe_text("failure https://user:sec'ret@example.org/path?secret=token"),
        )
        self.assertNotIn(
            "sec'ret",
            safe_text("failure https://user:sec'ret@example.org/path?secret=token"),
        )
        self.assertNotIn(
            "\x1b", safe_text("error\x1b https://user:secret@example.org/?key=value")
        )

    def test_windows_low_ports_are_valid_without_changing_posix_user_defaults(self):
        config = ResolverConfig(port="53")
        with patch("launcher.sys.platform", "win32"):
            self.assertEqual(config.argv()[config.argv().index("-p") + 1], "53")
        with patch("launcher.sys.platform", "darwin"):
            with self.assertRaisesRegex(ValueError, "1024"):
                config.argv()
        with patch("launcher.sys.platform", "win32"):
            with self.assertRaises(ValueError):
                ResolverConfig(port="0").argv()

    def test_explicit_bundled_binary_is_preserved_without_changing_path(self):
        with patch.dict(os.environ, DNSP_GUI_BINARY="/a private bundle/dnsp-modern"):
            self.assertEqual(default_binary(), "/a private bundle/dnsp-modern")


if __name__ == "__main__":
    unittest.main()
