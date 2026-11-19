"""Focused Linux monitor tests; real loopback DNS/HTTP and synthetic /proc fixtures."""

from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import math
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
GUI_SOURCE = Path(os.environ.get("DNSP_GUI_SOURCE", BASE / "tools/desktop-gui"))
sys.path.insert(0, str(GUI_SOURCE))
import monitor  # noqa: E402 - optional tool lives outside the tests package
from test_modern import (  # noqa: E402
    BINARY,
    DoH,
    HTTP,
    make_response,
    question_end,
    query,
    unused_ports,
)

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
def live_resolver(metrics=True, handler=DoH):
    server = HTTP(("127.0.0.1", 0), handler)
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


# A small original fixture in dnsperf/resperf's NAME TYPE format. These names
# are reserved; all positive/negative answers come from the local DoH mock.
def mixed_query_cases():
    types = {"A": 1, "AAAA": 28, "TXT": 16, "MX": 15, "NS": 2, "SOA": 6}
    cases = []
    for ident, line in enumerate(
        (BASE / "tests/gui-queries-25.txt").read_text().splitlines()
    ):
        name, kind = line.split()
        labels = [label.encode("ascii") for label in name.rstrip(".").split(".")]
        question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
        packet = (
            struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0)
            + question
            + struct.pack("!HH", types[kind], 1)
        )
        cases.append((packet, 3 if name.endswith(".invalid.") else 0))
    return cases


class MixedQueryDoH(DoH):
    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        end = question_end(data)
        if data[12 : end - 4].endswith(b"\x07invalid\0"):
            answer = data[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, 0) + data[12:end]
        else:
            answer = make_response(data)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


def send_mixed_query(port, case):
    packet, rcode = case
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, ("127.0.0.1", port))
        answer = client.recv(4096)
    if answer[:2] != packet[:2] or answer[3] & 15 != rcode:
        raise AssertionError("Unexpected ID or RCODE in the mixed query fixture")
    return rcode


class LauncherTests(unittest.TestCase):
    def test_validated_argv_preserves_spaces_without_shell(self):
        from launcher import ResolverConfig

        config = ResolverConfig(
            binary="/some path/dnsp-modern",
            padding=True,
            http3=True,
            backup_enabled=True,
            hedge=True,
        )
        command = config.argv()
        self.assertEqual(command[0], "/some path/dnsp-modern")
        self.assertIn("--edns-padding", command)
        self.assertIn("--upstream-hedge-ms", command)
        self.assertIn("--upstream-http=prefer-h3", command)
        self.assertEqual(
            monitor.parse_invocation(command).number("--cache-entries"), 256
        )

    def test_invalid_configuration_never_produces_command(self):
        from launcher import ResolverConfig

        for settings in (
            {"port": "53"},
            {"listen": "example.com"},
            {"metrics_port": "5300"},
            {"cache_entries": "1025"},
            {"hedge": True},
            {"upstream": "http://example.com/"},
            {"filtering": True},
            {"bootstrap": "localhost"},
            {"port": "5300; touch /tmp/x"},
        ):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                ResolverConfig(**settings).argv()


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
            self.assertEqual(monitor.list_instances(root), (parsed,))
            another = root / "43"
            another.mkdir()
            (another / "exe").symlink_to("/usr/bin/dnsp-modern")
            self.assertEqual(monitor.list_instances(root), (parsed,))
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


class ServiceTests(unittest.TestCase):
    def test_fixed_read_only_service_lookup_and_other_instance(self):
        result = subprocess.CompletedProcess(
            [],
            0,
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=42\nResult=success\n",
            "",
        )
        with patch.object(monitor.subprocess, "run", return_value=result) as run:
            status = monitor.read_service()
        self.assertEqual(status.describe(), "active / running")
        self.assertIn("another instance", status.describe(sample(pid=43).process))
        args, kwargs = run.call_args
        self.assertEqual(
            args[0][:3], ["/usr/bin/systemctl", "show", "dnsp-modern.service"]
        )
        self.assertLessEqual(kwargs["timeout"], 1)
        self.assertNotIn("start", args[0])

    def test_absent_unavailable_timeout_and_untrusted_status(self):
        for code, body, expected in (
            (1, "LoadState=not-found\n", "Service not installed"),
            (1, "", "Systemd status unavailable"),
            (0, "MainPID=-1\n", "Systemd status unavailable"),
            (0, "Result=unsafe result\n", "Systemd status unavailable"),
            (0, "x" * 4097, "Systemd status unavailable"),
        ):
            with (
                self.subTest(body=body[:30]),
                patch.object(
                    monitor.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], code, body, ""),
                ),
            ):
                self.assertEqual(monitor.read_service().describe(), expected)
        with patch.object(
            monitor.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("systemctl", 0.75),
        ):
            self.assertEqual(monitor.read_service().load, "unavailable")

    def test_multiple_instances_are_exposed_without_fetching_ambiguous_metrics(self):
        processes = (sample(pid=42).process, sample(pid=43).process)
        with (
            patch.object(monitor, "list_instances", return_value=processes),
            patch.object(monitor, "read_service", return_value=None),
            patch.object(monitor, "fetch_metrics") as fetch,
        ):
            snapshot = monitor.Collector().collect()
            self.assertEqual(snapshot.instances, processes)
            self.assertIn("Choose one", snapshot.error)
            fetch.assert_not_called()


class LatencyTests(unittest.TestCase):
    @staticmethod
    def histogram(counts=(0, 0, 0), *, at=1, **changes):
        values = dict(monitor.parse_metrics(BODY).samples)
        for name, labels in (
            ("dnsp_client_duration_seconds", (("transport", "udp"),)),
            ("dnsp_client_duration_seconds", (("transport", "tcp"),)),
            ("dnsp_upstream_duration_seconds", ()),
        ):
            for bound, count in zip(("0.01", "0.1", "+Inf"), counts):
                values[(name + "_bucket", tuple(sorted(labels + (("le", bound),))))] = (
                    count
                )
            values[(name + "_count", labels)] = counts[-1]
        return replace(sample(at=at, **changes), metrics=monitor.Metrics(values))

    def test_recent_percentiles_idle_reset_and_bound(self):
        window = monitor.LatencyWindow()
        self.assertEqual(window.update(self.histogram()), (None, None))
        client, upstream = window.update(self.histogram((5, 10, 10), at=2))
        for values in (client, upstream):
            self.assertAlmostEqual(values[0], 0.01)
            self.assertAlmostEqual(values[1], 0.091)
            self.assertAlmostEqual(values[2], 0.0982)
        # An idle interval preserves the recent window, not a synthetic zero.
        self.assertEqual(
            window.update(self.histogram((5, 10, 10), at=3)), (client, upstream)
        )
        for tick in range(4, 100):
            window.update(self.histogram((5, 10, 10), at=tick))
        self.assertEqual(len(window.history), 61)
        self.assertEqual(
            window.update(self.histogram((5, 10, 10), at=100)), (None, None)
        )
        self.assertEqual(window.update(self.histogram((1, 2, 2), at=101)), (None, None))
        self.assertEqual(
            window.update(self.histogram((5, 10, 10), at=102, start=101)), (None, None)
        )

    def test_legacy_missing_and_invalid_histograms_recover(self):
        window = monitor.LatencyWindow()
        window.update(sample())
        self.assertEqual(window.update(self.histogram()), (None, None))
        self.assertIsNotNone(window.update(self.histogram((1, 2, 2), at=2))[0])
        self.assertEqual(window.update(replace(sample(), metrics=None)), (None, None))
        window.update(self.histogram())
        self.assertEqual(window.update(self.histogram((2, 1, 3))), (None, None))
        self.assertEqual(window.update(self.histogram((0, 0, 5))), (None, None))
        client, upstream = window.update(self.histogram((0, 0, 6), at=3))
        self.assertTrue(all(math.isinf(value) for value in client + upstream))


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
            maximum = after.metrics.get("dnsp_upstream_duration_max_seconds")
            self.assertGreaterEqual(
                maximum, before.metrics.get("dnsp_upstream_duration_max_seconds")
            )
            self.assertGreaterEqual(
                maximum,
                after.metrics.get("dnsp_upstream_duration_seconds_sum")
                / after.metrics.get("dnsp_upstream_duration_seconds_count"),
            )
            self.assertGreaterEqual(
                after.metrics.get("dnsp_client_duration_max_seconds", transport="udp"),
                0,
            )
            self.assertEqual(
                after.metrics.get("dnsp_client_duration_max_seconds", transport="tcp"),
                0,
            )

    def test_exact_latency_maximum_survives_faster_replies(self):
        class SlowFirstReply(DoH):
            def do_POST(self):
                if not getattr(self.server, "slow_reply_done", False):
                    self.server.slow_reply_done = True
                    time.sleep(0.04)
                super().do_POST()

        with live_resolver(handler=SlowFirstReply) as (_, port, metric):
            initial = monitor.fetch_metrics(metric)
            maximum = initial.get("dnsp_upstream_duration_max_seconds")
            self.assertGreaterEqual(maximum, 0.03)
            for _ in range(3):
                send_query(port)
            current = monitor.fetch_metrics(metric)
            self.assertGreaterEqual(
                current.get("dnsp_upstream_duration_max_seconds"), maximum
            )
            self.assertGreaterEqual(
                current.get("dnsp_client_duration_max_seconds", transport="udp"), 0.03
            )

    def test_modest_mixed_queries_count_nxdomain_as_satisfied(self):
        cases = mixed_query_cases()
        self.assertEqual(len(cases), 25)
        self.assertEqual(sum(rcode == 3 for _, rcode in cases), 5)
        with live_resolver(handler=MixedQueryDoH) as (_, port, metric):
            before = monitor.fetch_metrics(metric)
            for case in cases:
                send_mixed_query(port, case)
                time.sleep(0.02)
            after = monitor.fetch_metrics(metric)
            self.assertEqual(
                after.get("dnsp_queries_total", transport="udp")
                - before.get("dnsp_queries_total", transport="udp"),
                25,
            )
            self.assertEqual(
                after.get("dnsp_queries_satisfied_total")
                - before.get("dnsp_queries_satisfied_total"),
                25,
            )
            self.assertEqual(
                after.get("dnsp_upstream_failures_total")
                - before.get("dnsp_upstream_failures_total"),
                0,
            )

    def test_metrics_remain_available_during_nxdomain_burst(self):
        with live_resolver() as (process, port, metric):
            before = monitor.fetch_metrics(metric)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                for ident in range(48):
                    client.sendto(query(qtype=65024, ident=ident), ("127.0.0.1", port))
                snapshots = [monitor.fetch_metrics(metric) for _ in range(4)]
                replies = [client.recv(4096) for _ in range(48)]
            self.assertTrue(all(reply[3] & 15 == 3 for reply in replies))
            self.assertTrue(
                all(
                    snapshot.get("dnsp_queries_total", transport="udp")
                    >= before.get("dnsp_queries_total", transport="udp")
                    for snapshot in snapshots
                )
            )
            self.assertIsNone(process.poll())

    def test_daemon_without_metrics_still_exposes_settings_and_load(self):
        with live_resolver(metrics=False) as (process, _port, _metric):
            collector = monitor.Collector(pid=process.pid)
            snapshot = collector.collect()
            self.assertIn("Metrics disabled", snapshot.error)
            self.assertIsNotNone(snapshot.process)
            self.assertIsNone(snapshot.metrics)


if __name__ == "__main__":
    unittest.main(verbosity=2)
