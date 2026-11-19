"""Native metadata boundaries plus actual native DNSProxy process sampling."""

from dataclasses import replace
import ctypes
import os
from pathlib import Path
import struct
import tempfile
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GUI_SOURCE = Path(
    os.environ.get("DNSP_GUI_SOURCE", ROOT / "tools/desktop-gui")
).resolve()
sys.path.insert(0, str(GUI_SOURCE))
import monitor  # noqa: E402
import platform_monitor as native  # noqa: E402


class NativeParsingTests(unittest.TestCase):
    def test_exiting_during_native_inspection_reaps_its_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "orphan-helper"
            child_code = f"import time; from pathlib import Path; time.sleep(2); Path({str(marker)!r}).touch()"
            script = (
                f"import sys,threading,time; sys.path.insert(0,{str(GUI_SOURCE)!r}); "
                "import platform_monitor as p; "
                f"threading.Thread(target=lambda:p._run_inspection([sys.executable,'-c',{child_code!r}],timeout=10),daemon=True).start(); "
                "\nwhile not p._INSPECTIONS: time.sleep(.01)\n"
            )
            result = subprocess.run(
                [sys.executable, "-c", script], capture_output=True, timeout=4
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            time.sleep(2.1)
            self.assertFalse(
                marker.exists(), "Read-only inspection child escaped GUI exit cleanup"
            )

    def test_cim_microseconds_match_kernel_filetime_without_weakening_identity(self):
        kernel = native.NativeProcess(42, 133000000000000019, 0, 4096, 1, None)
        cim = 133000000000000010
        cache = {native.windows_argv_key(42, cim): ("dnsp-modern.exe", "-m", "9090")}
        self.assertEqual(
            cache[native.windows_argv_key(kernel.pid, kernel.start_ticks)][-1], "9090"
        )
        self.assertEqual(kernel.start_ticks, 133000000000000019)
        self.assertNotEqual(
            native.windows_argv_key(42, kernel.start_ticks),
            native.windows_argv_key(43, cim),
        )

    def test_cold_cim_lookup_is_bounded_and_failed_refresh_is_throttled(self):
        class Kernel:
            def GetSystemDirectoryW(self, buffer, length):
                buffer.value = r"C:\Windows\System32"
                return len(buffer.value)

        process = native._Windows.__new__(native._Windows)
        process.kernel = Kernel()
        process._argv = {}
        process._argv_at = float("-inf")
        process._argv_lock = threading.Lock()
        clock = [100]

        def timeout(*args, **kwargs):
            self.assertEqual(kwargs["timeout"], native.CIM_TIMEOUT)
            clock[0] += native.CIM_TIMEOUT
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

        with (
            patch("platform_monitor.time.monotonic", side_effect=lambda: clock[0]),
            patch("platform_monitor.subprocess.CREATE_NO_WINDOW", 0, create=True),
            patch("platform_monitor._run_inspection", side_effect=timeout) as run,
        ):
            process._refresh_argv()
            self.assertIn("timed out", process.argv_status)
            self.assertEqual(process._argv_at, clock[0])
            process._refresh_argv()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(process._argv, {})

    def test_macos_image_read_is_bracketed_by_identity_and_scaled_ticks(self):
        class Usage(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in ("start", "user", "system", "resident")
            ]

        calls = []

        class Libproc:
            changed = False

            def proc_pid_rusage(self, pid, flavor, pointer):
                calls.append("usage")
                pointer._obj.start = (
                    200 if self.changed and calls.count("usage") > 1 else 100
                )
                pointer._obj.user = 20
                pointer._obj.system = 10
                pointer._obj.resident = 4096
                return 0

            def proc_pidpath(self, pid, buffer, length):
                calls.append("path")
                buffer.value = b"/a path/dnsp-modern"
                return len(buffer.value)

        process = native._Mac.__new__(native._Mac)
        process.Usage = Usage
        process.proc = Libproc()
        process.libc = type("Clock", (), {"mach_absolute_time": lambda self: 500})()
        process.seconds_per_tick = 0.001
        process.translated = False
        process.argv = lambda pid: (calls.append("argv") or ("dnsp-modern",))
        sample = process.read(42)
        self.assertEqual(calls, ["usage", "path", "argv", "usage"])
        self.assertAlmostEqual(sample.cpu_seconds, 0.03)
        self.assertAlmostEqual(sample.uptime, 0.4)
        process.translated = True
        self.assertIsNone(process.read(42).cpu_seconds)
        self.assertIsNone(process.read(42).uptime)
        process.proc.changed = True
        calls.clear()
        with self.assertRaisesRegex(ValueError, "identity changed"):
            process.read(42)

    def test_unknown_process_metadata_never_attributes_an_unverified_metrics_port(self):
        process = monitor.Process(
            42, 999, 0, 4096, 1, monitor.Invocation(available=False)
        )
        with (
            patch("monitor.list_instances", return_value=()),
            patch("monitor.read_service", return_value=None),
            patch("monitor.read_process", return_value=process),
            patch("monitor.fetch_metrics") as fetch,
        ):
            snapshot = monitor.Collector(pid=42, metrics_port=9090).collect()
            self.assertIn("Cannot verify", snapshot.error)
            fetch.assert_not_called()
        metrics = monitor.parse_metrics(
            b'dnsp_queries_total{transport="udp"} 1\ndnsp_queries_total{transport="tcp"} 0\n'
        )
        with (
            patch("monitor.list_instances", return_value=()),
            patch("monitor.read_service", return_value=None),
            patch("monitor.fetch_metrics", return_value=metrics),
        ):
            snapshot = monitor.Collector(metrics_port=9090).collect()
            self.assertIsNone(snapshot.process)
            self.assertIs(snapshot.metrics, metrics)
            self.assertFalse(snapshot.error)

    def test_macos_argv_preserves_spaces_empty_arguments_and_excludes_environment(self):
        argv = (
            b"/a path/dnsp-modern",
            b"-m",
            b"9090",
            b"--ca-file",
            b"/a path/ca.pem",
            b"",
        )
        data = (
            struct.pack("=i", len(argv))
            + argv[0]
            + b"\0\0\0"
            + b"\0".join(argv)
            + b"\0SECRET_ENV=not-an-argument\0"
        )
        self.assertEqual(
            native.parse_macos_arguments(data), tuple(x.decode() for x in argv)
        )
        for bad in (
            b"",
            struct.pack("=i", 0) + b"\0",
            struct.pack("=i", 1) + b"/exe\0\0unterminated",
        ):
            with self.assertRaises(ValueError):
                native.parse_macos_arguments(bad)

    def test_launchd_service_status_uses_fixed_fields_and_distinguishes_failure(self):
        status = native.parse_launchctl_status(
            "system/net.fantuz.dnsproxy = {\n state = running\n pid = 42\n last exit code = 0\n}",
            0,
        )
        self.assertEqual(status["pid"], 42)
        self.assertEqual(status["substate"], "running")
        self.assertEqual(
            native.parse_launchctl_status(
                'Could not find service "net.fantuz.dnsproxy" in domain for system', 113
            )["load"],
            "not-found",
        )
        self.assertEqual(
            native.parse_launchctl_status("Permission denied", 1)["load"], "unavailable"
        )
        with self.assertRaises(ValueError):
            native.parse_launchctl_status("x" * (65536 + 1), 0)

    def test_native_dispatch_preserves_identity_and_unavailable_settings(self):
        value = native.NativeProcess(42, 999, 1.0, 4096, 2.0, None)
        with (
            patch("monitor.sys.platform", "darwin"),
            patch("platform_monitor.read_native_process", return_value=value),
        ):
            process = monitor.read_process(42)
        self.assertEqual(process.identity, (42, 999))
        self.assertFalse(process.invocation.available)
        self.assertEqual(process.invocation.get("-s"), "Unavailable")
        self.assertIsNone(process.invocation.metrics_port)
        self.assertTrue(all(v is None for v in process.invocation.toggles().values()))
        value = replace(value, argv=("dnsp-modern", "-m", "9090"))
        with (
            patch("monitor.sys.platform", "win32"),
            patch("platform_monitor.list_native_instances", return_value=(value,)),
        ):
            self.assertEqual(monitor.list_instances()[0].invocation.metrics_port, 9090)
            self.assertEqual(monitor.discover_pid(), 42)

    def test_unavailable_resource_fields_do_not_become_zero_cpu(self):
        process = monitor.Process(
            42, 100, None, None, None, monitor.Invocation(available=False)
        )
        rates = monitor.Rates()
        rates.update(monitor.Snapshot(1, process, None, 9090))
        self.assertIsNone(rates.update(monitor.Snapshot(2, process, None, 9090))[2])

    def test_native_discovery_rejects_unverified_and_unreadable_images(self):
        class Adapter:
            def pids(self):
                return [1, 2, 3]

            def read(self, pid, *, with_argv=True):
                if pid == 1:
                    raise ValueError("Not DNSProxy")
                if pid == 2:
                    raise PermissionError("No process access")
                return native.NativeProcess(
                    pid, 100, 0, 4096, 2, ("dnsp-modern", "-m", "9090")
                )

        with patch("platform_monitor.adapter", return_value=Adapter()):
            self.assertEqual([p.pid for p in native.list_native_instances()], [3])
        for pid in (-1, 0, 2147483648, "1"):
            with self.assertRaises(ValueError):
                native.read_native_process(pid)


@unittest.skipUnless(
    sys.platform in {"win32", "darwin"} and os.environ.get("DNSP_TEST_BINARY"),
    "Requires a native Windows/macOS DNSProxy binary",
)
class NativeProcessTests(unittest.TestCase):
    def test_real_native_executable_identity_resources_arguments_and_service_status(
        self,
    ):
        binary = Path(os.environ["DNSP_TEST_BINARY"]).resolve()
        self.assertTrue(binary.is_file())
        # A local listener with no queries requires no upstream network access.
        import socket

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        child = subprocess.Popen(
            [str(binary), "-l", "127.0.0.1", "-p", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 30
            reason = "No process sample was returned"
            while time.monotonic() < deadline and child.poll() is None:
                try:
                    process = monitor.read_process(child.pid)
                    if process.invocation.available:
                        break
                    reason = "Invocation unavailable: " + getattr(
                        native.adapter(), "argv_status", "Native argv unavailable"
                    )
                except (OSError, ValueError) as error:
                    reason = f"{type(error).__name__}: {error}"
                time.sleep(0.1)
            else:
                self.fail(
                    "Native process inspection did not become available "
                    f"(exit={child.poll()}, {reason})"
                )
            self.assertEqual(process.pid, child.pid)
            self.assertGreater(process.start_ticks, 0)
            self.assertGreater(process.memory_bytes, 0)
            self.assertGreaterEqual(process.cpu_seconds, 0)
            self.assertGreaterEqual(process.uptime, 0)
            self.assertEqual(process.invocation.number("-p"), port)
            self.assertEqual(monitor.read_process(child.pid).identity, process.identity)
            self.assertIn(child.pid, [p.pid for p in monitor.list_instances()])
            status = monitor.read_service()
            self.assertIn(status.load, ("loaded", "not-found", "unavailable"))
            self.assertNotIn("Systemd", status.describe())
        finally:
            child.terminate()
            child.wait(timeout=5)
            child.stderr.close()


if __name__ == "__main__":
    unittest.main()
