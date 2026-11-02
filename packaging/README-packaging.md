# dnsp-modern experimental package

This package installs `/usr/bin/dnsp-modern` and a systemd unit. It does **not** replace the legacy DNSProxy executables, modify `/etc/resolv.conf`, or take over port 53.

Build on Debian/Ubuntu with `sudo apt install build-essential pkg-config libcurl4-openssl-dev dpkg-dev python3`, then `sh scripts/build-deb.sh`.

Inspect the result with `dpkg-deb --info dist/*.deb` and `dpkg-deb --contents dist/*.deb`.

Install with `sudo apt install ./dist/dnsp-modern_*.deb` (use an exact filename if more than one package exists).

The service is **not automatically enabled or started**. For manual startup use `sudo systemctl enable --now dnsp-modern`. Check `systemctl status dnsp-modern` and `journalctl -u dnsp-modern -f`. The default listens on `127.0.0.1:5300` and forwards to Cloudflare DoH. To customize it, use `sudo systemctl edit dnsp-modern`, clear `ExecStart=` and specify a new `ExecStart=` with the desired options.

Test with `dig @127.0.0.1 -p 5300 example.com A` and `dig +tcp @127.0.0.1 -p 5300 example.com A`.

This is an experimental release. Do not expose the resolver publicly until protocol correctness, rate limits, and load testing have been expanded.
