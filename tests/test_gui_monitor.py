"""Focused Linux monitor tests; real loopback DNS/HTTP and synthetic /proc fixtures."""

from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "tools/linux-gui"))
import monitor  # noqa: E402 - optional tool lives outside the tests package
from test_modern import BINARY, DoH, HTTP, query, unused_ports  # noqa: E402

BODY = (
    b'dnsp_queries_total{transport="udp"} 10\ndnsp_queries_total{transport="tcp"} 2\n'
)


def sample(at=1, udp=10, tcp=2, pid=1, start=100, cpu=0.1, port=9090):
    body = f'dnsp_queries_total{{transport="udp"}} {udp}\ndnsp_queries_total{{transport="tcp"}} {tcp}\n'.encode()
    process = monitor.Process(pid, start, cpu, 4096, 30, monitor.Invocation())
    return monitor.Snapshot(at, process, monitor.parse_metrics(body), port)


class MetricsHTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.server.delay:
            time.sleep(self.server.delay)
        self.send_response(self.server.status)
        self.send_header("Content-Type", self.server.media)
        self.send_header("Location", "http://127.0.0.1:1/must-not-follow")
        self.send_header("Content-Length", str(len(self.server.body)))
        self.end_headers()
        try:
            self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


@contextmanager
def metrics_endpoint():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MetricsHTTP)
    server.requests, server.status, server.media, server.body, server.delay = (
        [],
        200,
        "text/plain; version=0.0.4",
        BODY,
        0,
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def live_resolver(metrics=True):
    server = HTTP(("127.0.0.1", 0), DoH)
    worker = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    worker.start()
    port, metric = unused_ports()
    command = [
        str(BINARY),
        "-p",
        str(port),
        "-s",
        f"http://127.0.0.1:{server.server_port}/dns-query",
    ]
    if metrics:
        command += ["-m", str(metric)]
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read().decode())
                try:
                    send_query(port)
                    break
                except OSError:
                    time.sleep(0.025)
            else:
                raise AssertionError("DNSProxy did not become ready")
            yield process, port, metric
        finally:
            process.terminate()
            process.wait(timeout=5)
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


def send_query(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.3)
        packet = query()
        client.sendto(packet, ("127.0.0.1", port))
        answer = client.recv(4096)
        if answer[:2] != packet[:2] or answer[3] & 15:
            raise AssertionError("Invalid DNS answer")


class InvocationTests(unittest.TestCase):
    def test_defaults_and_explicit_repeated_options(self):
        parsed = monitor.parse_invocation(
            [
                "dnsp-modern",
                "-l",
                "::1",
                "-l",
                "127.0.0.1",
                "-p",
                "53",
                "--cache-entries",
                "16",
                "--edns-padding",
                "--blocklist",
                "one",
                "--blocklist",
                "two",
                "--allowlist",
                "allow",
                "--upstream-http=prefer-h3",
                "--blocklist-reload-ms",
                "0",
            ]
        )
        self.assertEqual(parsed.values["-l"], ("::1", "127.0.0.1"))
        self.assertEqual(parsed.values["--blocklist"], ("one", "two"))
        self.assertEqual(parsed.number("-p"), 53)
        self.assertEqual(parsed.number("--udp-reply-max"), 1232)
        self.assertTrue(parsed.toggles()["In-memory DNS cache"])
        self.assertTrue(parsed.toggles()["Prefer HTTP/3 (with fallback)"])
        self.assertFalse(parsed.toggles()["Periodic blocklist checks"])
        self.assertIsNone(parsed.metrics_port)
        self.assertNotIn("--udp-reply-max", parsed.explicit)
        with self.assertRaises(ValueError):
            monitor.parse_invocation(["dnsp-modern", "-p"])

    def test_credentials_and_unknown_values_are_not_displayed(self):
        url = "https://user:password@[::1]:443/dns-query?token=secret#secret"
        self.assertEqual(
            monitor.display_value("-s", url), "https://[::1]:443/dns-query?[redacted]"
        )
        parsed = monitor.parse_invocation(["dnsp-modern", "--future-token", "secret"])
        self.assertNotIn("secret", repr(parsed.unknown))

    def test_schema_covers_the_current_cli(self):
        source = (BASE / "dnsp-modern.c").read_text()
        usage = source[
            source.index("static void usage(") : source.index("static int dnsp_run(")
        ]
        flags = set(re.findall(r'"  ((?:--?)[a-z][a-z-]*)', usage)) - {
            "-h",
            "-V",
            "--check-blocklists",
        }
        self.assertEqual(flags, set(monitor.DEFAULTS))
        # Detect changed defaults, rather than silently misrepresenting options.
        for expected in (
            "TCP_MAX_PER_SOURCE=32",
            "TCP_IDLE_MS=15000",
            "TCP_IO_MS=15000",
            "DOH_CONNECT_MS=1500",
            "DOH_TIMEOUT_MS=3000",
            "UDP_REPLY_DEFAULT=1232",
            "int port=5300,metrics_port=0",
            "int max_host_connections=8",
        ):
            self.assertIn(expected, source)


class MetricTests(unittest.TestCase):
    def test_labels_numbers_missing_values_and_order(self):
        metrics = monitor.parse_metrics(
            BODY + b'dnsp_extra{z="one\\nline",a="x"} 1.5e2 1234\n'
        )
        self.assertEqual(metrics.get("dnsp_queries_total", transport="udp"), 10)
        self.assertEqual(metrics.get("dnsp_extra", a="x", z="one\nline"), 150)
        self.assertIsNone(metrics.get("dnsp_cache_hits_total"))

    def test_malformed_and_oversized_samples(self):
        for addition in (
            b"bad",
            b"x NaN",
            b"x -1",
            b"x 1e999",
            b"x " + b"9" * 500,
            b"x{bad} 1",
            b'x{a="x",a="y"} 1',
            b'dnsp_queries_total{transport="udp"} 11',
        ):
            with self.subTest(addition=addition[:50]), self.assertRaises(ValueError):
                monitor.parse_metrics(BODY + addition)
        with self.assertRaises(ValueError):
            monitor.parse_metrics(b"x" * (monitor.MAX_RESPONSE + 1))
        with self.assertRaises(ValueError):
            monitor.parse_metrics(b"other_daemon 1\n")

    def test_real_http_redirect_limit_content_type_and_timeout(self):
        with metrics_endpoint() as server:
            self.assertEqual(
                monitor.fetch_metrics(server.server_port).get(
                    "dnsp_queries_total", transport="tcp"
                ),
                2,
            )
            for status, media, body in (
                (302, "text/plain", BODY),
                (500, "text/plain", BODY),
                (200, "text/html", BODY),
                (200, "text/plain", b"x" * (monitor.MAX_RESPONSE + 1)),
            ):
                server.status, server.media, server.body = status, media, body
                with self.assertRaises(ValueError):
                    monitor.fetch_metrics(server.server_port)
            server.status, server.media, server.body, server.delay = (
                200,
                "text/plain",
                BODY,
                0.2,
            )
            with self.assertRaises(TimeoutError):
                monitor.fetch_metrics(server.server_port, timeout=0.03)
            self.assertEqual(server.requests, ["/metrics"] * 6)


class ProcessTests(unittest.TestCase):
    def test_proc_comm_parentheses_discovery_permissions_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "uptime").write_text("600.0 100.0")
            pid = root / "42"
            pid.mkdir()
            (pid / "exe").symlink_to("/usr/bin/dnsp-modern")
            (pid / "cmdline").write_bytes(b"dnsp-modern\0-m\09090\0")
            fields = ["0"] * 22
            fields[0], fields[11], fields[12], fields[19], fields[21] = (
                "S",
                "100",
                "50",
                "200",
                "10",
            )
            (pid / "stat").write_text("42 (name (with) spaces) " + " ".join(fields))
            parsed = monitor.read_process(42, root)
            self.assertEqual(parsed.memory_bytes, 10 * os.sysconf("SC_PAGE_SIZE"))
            self.assertEqual(parsed.invocation.metrics_port, 9090)
            self.assertEqual(monitor.discover_pid(root), 42)
            another = root / "43"
            another.mkdir()
            (another / "exe").symlink_to("/usr/bin/dnsp-modern")
            with self.assertRaisesRegex(ValueError, "Multiple"):
                monitor.discover_pid(root)
            (pid / "exe").unlink()
            (pid / "exe").symlink_to("/usr/bin/other")
            with self.assertRaisesRegex(ValueError, "not a dnsp-modern"):
                monitor.read_process(42, root)

    def test_reused_pid_and_wrong_port_never_fetch_metrics(self):
        process = sample().process
        process.invocation.values["-m"] = ("9090",)
        collector = monitor.Collector(pid=1)
        collector.pinned_identity = (1, 99)
        with (
            patch.object(monitor, "read_process", return_value=process),
            patch.object(monitor, "fetch_metrics") as fetch,
        ):
            self.assertIn("reused", collector.collect().error)
            fetch.assert_not_called()
            collector = monitor.Collector(pid=1, metrics_port=9091)
            self.assertIn("does not use", collector.collect().error)
            fetch.assert_not_called()

    def test_explicit_metrics_port_does_not_require_process_access(self):
        with (
            metrics_endpoint() as server,
            patch.object(monitor, "discover_pid", side_effect=PermissionError),
        ):
            snapshot = monitor.Collector(metrics_port=server.server_port).collect()
            self.assertFalse(snapshot.error)
            self.assertIsNone(snapshot.process)
            self.assertIsNotNone(snapshot.metrics)


class RateTests(unittest.TestCase):
    def test_rates_and_restart_counter_reset_port_change(self):
        rates = monitor.Rates()
        self.assertEqual(rates.update(sample()), (None, None, None))
        qps, delta, cpu = rates.update(sample(at=3, udp=18, tcp=4, cpu=0.5))
        self.assertEqual((qps, delta), (5, 10))
        self.assertAlmostEqual(cpu, 20)
        for next_sample in (
            sample(at=4, udp=1, tcp=0),
            sample(at=5, start=101),
            sample(at=6, start=101, port=9191),
        ):
            self.assertIsNone(rates.update(next_sample)[0])
        rates.reset()
        self.assertIsNone(rates.update(sample(at=9))[0])

    def test_missing_metrics_do_not_zero_counters_or_spike_on_recovery(self):
        rates = monitor.Rates()
        rates.update(sample())
        self.assertEqual(
            rates.update(replace(sample(at=2, cpu=0.2), metrics=None))[:2], (None, None)
        )
        self.assertIsNone(rates.update(sample(at=3, udp=999))[0])
        self.assertEqual(rates.update(sample(at=4, udp=1000))[0], 1)


@unittest.skipUnless(
    sys.platform.startswith("linux") and BINARY.exists(),
    "Requires Linux and make modern",
)
class LiveMonitorTests(unittest.TestCase):
    def test_actual_daemon_traffic_and_process_settings(self):
        with live_resolver() as (process, port, metric):
            collector = monitor.Collector(pid=process.pid)
            before = collector.collect()
            self.assertFalse(before.error)
            self.assertEqual(before.process.invocation.metrics_port, metric)
            self.assertEqual(before.process.invocation.number("-p"), port)
            for _ in range(3):
                send_query(port)
            after = collector.collect()
            self.assertEqual(
                after.metrics.get("dnsp_queries_total", transport="udp")
                - before.metrics.get("dnsp_queries_total", transport="udp"),
                3,
            )
            self.assertEqual(
                after.metrics.get("dnsp_queries_satisfied_total")
                - before.metrics.get("dnsp_queries_satisfied_total"),
                3,
            )
            self.assertGreater(after.process.memory_bytes, 0)

    def test_daemon_without_metrics_still_exposes_settings_and_load(self):
        with live_resolver(metrics=False) as (process, _port, _metric):
            collector = monitor.Collector(pid=process.pid)
            snapshot = collector.collect()
            self.assertIn("Metrics disabled", snapshot.error)
            self.assertIsNotNone(snapshot.process)
            self.assertIsNone(snapshot.metrics)


if __name__ == "__main__":
    unittest.main(verbosity=2)
