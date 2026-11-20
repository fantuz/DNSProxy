"""Validated ordinary-user resolver invocations; no shell or service controls."""

from dataclasses import dataclass
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit


def default_binary():
    """Prefer an explicitly supplied bundled companion, then native install paths."""
    configured = os.environ.get("DNSP_GUI_BINARY")
    if configured:
        return configured
    name = "dnsp-modern.exe" if sys.platform == "win32" else "dnsp-modern"
    root = Path(__file__).resolve()
    candidates = [root.parents[2] / "bin" / name, root.parents[2] / name]
    if sys.platform == "win32":
        program = os.environ.get("ProgramFiles", r"C:\Program Files")
        candidates += [Path(program) / "DNSProxy/bin" / name]
    elif sys.platform == "darwin":
        candidates += [Path("/Library/Application Support/DNSProxy") / name]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name) or name


def command_preview(command, redact=True):
    """Display platform-appropriate quoting without using a shell to launch."""
    values = list(command)
    if redact:
        from owned_process import safe_text

        values = [safe_text(value) for value in values]
    return (
        subprocess.list2cmdline(values)
        if sys.platform == "win32"
        else shlex.join(values)
    )


def endpoint_host(url):
    return (urlsplit(url).hostname or "").rstrip(".").lower()


def bootstrap_args(option, url, address):
    if not address:
        return []
    try:
        ipaddress.ip_address(endpoint_host(url))
    except ValueError:
        pass
    else:
        raise ValueError("Leave the bootstrap IP empty for a numeric HTTPS endpoint")
    if "%" in address:
        raise ValueError("Use an unscoped numeric bootstrap IP")
    ipaddress.ip_address(address)
    return [option, address]


def validate_policy(command, cancel):
    """Run the selected resolver's offline policy parser without blocking GTK."""
    from owned_process import safe_text

    with (
        tempfile.TemporaryFile() as diagnostic,
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostic,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        ) as child,
    ):
        deadline = time.monotonic() + 30
        try:
            while child.poll() is None:
                if cancel.wait(0.05):
                    return
                if time.monotonic() >= deadline:
                    raise ValueError("Policy validation timed out after 30 seconds")
            if child.returncode:
                diagnostic.seek(0)
                detail = safe_text(
                    diagnostic.read(4096).decode("utf-8", "replace")
                ).strip()
                raise ValueError(
                    detail or f"Policy validation exited with status {child.returncode}"
                )
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


@dataclass
class ResolverConfig:
    binary: str = "dnsp-modern"
    listen: str = "127.0.0.1"
    port: str = "5300"
    metrics_port: str = "9090"
    upstream: str = "https://cloudflare-dns.com/dns-query"
    bootstrap: str = "1.1.1.1"
    cache_entries: str = "256"
    backup: str = "https://dns.google/dns-query"
    backup_bootstrap: str = "8.8.8.8"
    hedge_ms: str = "100"
    blocklist: str = ""
    ca_file: str = ""
    allowlist: str = ""
    block_response: str = "refused"
    blocklist_reload_ms: str = "5000"
    max_host_connections: str = "8"
    tcp_max_per_source: str = "32"
    tcp_idle_ms: str = "15000"
    tcp_io_ms: str = "15000"
    doh_connect_ms: str = "1500"
    doh_timeout_ms: str = "3000"
    udp_reply_max: str = "1232"
    cache: bool = True
    metrics: bool = True
    padding: bool = False
    http3: bool = False
    backup_enabled: bool = False
    hedge: bool = False
    filtering: bool = False

    def argv(self, *, check_blocklists=False):
        """Return native arguments with the resolver's bounds and dependencies.

        Listener addresses are separated by commas or lines. Policy paths use
        one complete path per line, so spaces and shell punctuation stay literal.
        ``check_blocklists`` is the CLI's validation-only mode, not a service
        operation; callers must capture its output and bound its lifetime.
        """

        def integer(value, low, high, name):
            if (
                not str(value).isascii()
                or not str(value).isdecimal()
                or not low <= int(value) <= high
            ):
                raise ValueError(f"{name} must be {low}..{high}")
            return str(int(value))

        def url(value):
            parts = urlsplit(value)
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.fragment
                or any(
                    character.isspace() or ord(character) < 32 for character in value
                )
            ):
                raise ValueError(
                    "Upstreams must be HTTPS URLs without whitespace or fragments"
                )
            _ = parts.port
            return value

        if sys.platform == "win32" and self.binary.rstrip(" .").lower().endswith(
            (".bat", ".cmd")
        ):
            raise ValueError(
                "Choose the native resolver EXE, not a Windows command script"
            )
        if not self.binary.strip() or "\x00" in self.binary:
            raise ValueError("Choose the dnsp-modern executable")
        listeners = [
            value.strip() for value in re.split(r"[,\n]", self.listen) if value.strip()
        ]
        if not 1 <= len(listeners) <= 8:
            raise ValueError(
                "Choose 1..8 numeric listen addresses, one per line or separated by commas"
            )
        for address in listeners:
            ipaddress.ip_address(address)
        minimum = 1 if sys.platform == "win32" else 1024
        port = integer(self.port, minimum, 65535, "DNS port for a user process")
        command = [self.binary]
        for address in listeners:
            command += ["-l", address]
        command += ["-p", port, "-s", url(self.upstream)]
        if self.metrics:
            metric = integer(self.metrics_port, minimum, 65535, "Metrics port")
            if metric == port:
                raise ValueError("DNS and metrics ports must differ")
            command += ["-m", metric]
        command += bootstrap_args("--bootstrap-address", self.upstream, self.bootstrap)
        if self.cache:
            command += [
                "--cache-entries",
                integer(self.cache_entries, 1, 1024, "Cache entries"),
            ]
        if self.padding:
            command += ["--edns-padding"]
        if self.http3:
            command += ["--upstream-http=prefer-h3"]
        if self.backup_enabled:
            command += ["--backup-upstream", url(self.backup)]
            if (endpoint_host(self.upstream), urlsplit(self.upstream).port or 443) == (
                endpoint_host(self.backup),
                urlsplit(self.backup).port or 443,
            ):
                raise ValueError(
                    "Choose a different host or port for the backup upstream"
                )
            command += bootstrap_args(
                "--backup-bootstrap-address", self.backup, self.backup_bootstrap
            )
        limits = (
            (
                "--max-host-connections",
                self.max_host_connections,
                1,
                16,
                "Upstream connection limit",
            ),
            (
                "--tcp-max-per-source",
                self.tcp_max_per_source,
                1,
                128,
                "TCP connections per source",
            ),
            ("--tcp-idle-ms", self.tcp_idle_ms, 100, 600000, "TCP idle timeout (ms)"),
            (
                "--tcp-io-ms",
                self.tcp_io_ms,
                100,
                600000,
                "TCP read/write deadline (ms)",
            ),
            (
                "--doh-connect-ms",
                self.doh_connect_ms,
                100,
                60000,
                "DoH connection deadline (ms)",
            ),
            (
                "--doh-timeout-ms",
                self.doh_timeout_ms,
                100,
                60000,
                "DoH total deadline (ms)",
            ),
            (
                "--udp-reply-max",
                self.udp_reply_max,
                512,
                4096,
                "UDP reply ceiling (bytes)",
            ),
        )
        for option, value, low, high, caption in limits:
            command += [option, integer(value, low, high, caption)]
        if int(self.doh_connect_ms) > int(self.doh_timeout_ms):
            raise ValueError(
                "DoH connection deadline must not exceed the total deadline"
            )
        if self.hedge:
            if not self.backup_enabled:
                raise ValueError("Delayed parallel requests require a backup upstream")
            delay = integer(self.hedge_ms, 1, 60000, "Hedge delay")
            if int(delay) >= int(self.doh_timeout_ms):
                raise ValueError("Hedge delay must be below the DoH total deadline")
            command += ["--upstream-hedge-ms", delay]
        if self.filtering or check_blocklists:
            deny = [
                value.strip() for value in self.blocklist.splitlines() if value.strip()
            ]
            allow = [
                value.strip() for value in self.allowlist.splitlines() if value.strip()
            ]
            if not deny:
                raise ValueError("Choose an existing file for --blocklist")
            if len(deny) + len(allow) > 64:
                raise ValueError(
                    "Blocklists and allowlists may use at most 64 files in total"
                )
            for option, paths in (("--blocklist", deny), ("--allowlist", allow)):
                for path in paths:
                    if "\x00" in path or not Path(path).is_file():
                        raise ValueError(f"Choose an existing file for {option}")
                    command += [option, path]
            if self.block_response not in {"refused", "nxdomain", "nodata", "null"}:
                raise ValueError(
                    "Block response must be refused, nxdomain, nodata or null"
                )
            reload_ms = integer(
                self.blocklist_reload_ms, 0, 86400000, "Blocklist reload interval (ms)"
            )
            if 0 < int(reload_ms) < 100:
                raise ValueError(
                    "Blocklist reload interval must be 0 or 100..86400000 ms"
                )
            command += [
                "--block-response",
                self.block_response,
                "--blocklist-reload-ms",
                reload_ms,
            ]
            if check_blocklists:
                command += ["--check-blocklists"]
        if self.ca_file:
            if "\x00" in self.ca_file or not Path(self.ca_file).is_file():
                raise ValueError("Choose an existing file for --ca-file")
            command += ["--ca-file", self.ca_file]
        return command
