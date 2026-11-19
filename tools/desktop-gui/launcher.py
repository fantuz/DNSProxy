"""Validated ordinary-user resolver invocations; no shell or service controls."""

from dataclasses import dataclass
import ipaddress
import os
import shlex
import shutil
import subprocess
import sys
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
    cache: bool = True
    metrics: bool = True
    padding: bool = False
    http3: bool = False
    backup_enabled: bool = False
    hedge: bool = False
    filtering: bool = False

    def argv(self):
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
        ipaddress.ip_address(self.listen)
        minimum = 1 if sys.platform == "win32" else 1024
        port = integer(self.port, minimum, 65535, "DNS port for a user process")
        command = [self.binary, "-l", self.listen, "-p", port, "-s", url(self.upstream)]
        if self.metrics:
            metric = integer(self.metrics_port, minimum, 65535, "Metrics port")
            if metric == port:
                raise ValueError("DNS and metrics ports must differ")
            command += ["-m", metric]
        if self.bootstrap:
            ipaddress.ip_address(self.bootstrap)
            command += ["--bootstrap-address", self.bootstrap]
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
            if self.backup_bootstrap:
                ipaddress.ip_address(self.backup_bootstrap)
                command += ["--backup-bootstrap-address", self.backup_bootstrap]
        if self.hedge:
            if not self.backup_enabled:
                raise ValueError("Delayed parallel requests require a backup upstream")
            command += [
                "--upstream-hedge-ms",
                integer(self.hedge_ms, 1, 60000, "Hedge delay"),
            ]
        for enabled, value, option in (
            (self.filtering, self.blocklist, "--blocklist"),
            (bool(self.ca_file), self.ca_file, "--ca-file"),
        ):
            if enabled:
                if not value or not Path(value).is_file():
                    raise ValueError(f"Choose an existing file for {option}")
                command += [option, value]
        return command
