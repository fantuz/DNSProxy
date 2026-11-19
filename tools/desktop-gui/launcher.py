"""Validated ordinary-user resolver invocations; no shell or service controls."""

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


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
            if parts.scheme != "https" or not parts.hostname or parts.fragment:
                raise ValueError("Upstreams must be HTTPS URLs without fragments")
            _ = parts.port
            return value

        if not self.binary.strip() or "\x00" in self.binary:
            raise ValueError("Choose the dnsp-modern executable")
        ipaddress.ip_address(self.listen)
        port = integer(self.port, 1024, 65535, "DNS port for a user process")
        command = [self.binary, "-l", self.listen, "-p", port, "-s", url(self.upstream)]
        if self.metrics:
            metric = integer(self.metrics_port, 1024, 65535, "Metrics port")
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
