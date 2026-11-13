"""Render release download links, optionally preserving an existing changelog."""
import argparse
import json
import os
from pathlib import Path
import re
from urllib.parse import quote


START = "<!-- dnsp-downloads:start -->"
END = "<!-- dnsp-downloads:end -->"
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def downloads(version, repository):
    if not re.fullmatch(VERSION, version):
        raise ValueError("Expected a MAJOR.MINOR.PATCH release version")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected an owner/repository name")
    root = f"https://github.com/{repository}"
    tag = f"v{version}-modern"
    assets = []

    def asset(label, name):
        assets.append(name)
        return f"[{label}]({root}/releases/download/{tag}/{quote(name, safe='')})"

    lines = [START, "## Downloads", "",
             "Choose your operating system and processor architecture:", "",
             "| Platform | x86-64 / amd64 | ARM64 / aarch64 |",
             "| --- | --- | --- |",
             "| Windows (PoC) | " + asset("**Portable ZIP**", f"dnsp-modern-{version}-windows-amd64-poc.zip") + " | Not available |"]
    for label, distro in (("Ubuntu 22.04", "ubuntu22.04"),
                         ("Ubuntu 24.04", "ubuntu24.04"),
                         ("Debian 13", "debian13")):
        links = [asset("DEB", f"dnsp-modern_{version}+{distro}_{arch}.deb")
                 for arch in ("amd64", "arm64")]
        lines.append(f"| {label} | {' | '.join(links)} |")
    links = [asset("RPM", f"dnsp-modern-{version}-1.el9.{arch}.rpm")
             for arch in ("x86_64", "aarch64")]
    lines.append(f"| Rocky Linux 9 | {' | '.join(links)} |")
    checksums = asset("SHA256SUMS", "SHA256SUMS")
    lines.extend(["",
                  "**Windows:** extract the entire ZIP and double-click **Start-DNSProxy.cmd**. "
                  "Keep the EXE, DLLs and certificate bundle together.", "",
                  f"[Windows setup guide]({root}/blob/{tag}/docs/WINDOWS.md) · "
                  f"[Linux installation guide]({root}/blob/{tag}/packaging/README-packaging.md) · "
                  f"[Checksum instructions]({root}/blob/{tag}/packaging/README-packaging.md#automatic-and-manual-releases) · {checksums}",
                  "", END])
    return "\n".join(lines), set(assets)


def refresh(release, repository):
    match = re.fullmatch(f"v({VERSION})-modern", release["tag_name"])
    if not match or release.get("draft") or release.get("prerelease"):
        raise ValueError("Expected a published stable DNSProxy modern release")
    block, expected = downloads(match.group(1), repository)
    missing = expected - {asset["name"] for asset in release["assets"]}
    if missing:
        raise ValueError("Release is missing downloads: " + ", ".join(sorted(missing)))
    body = release.get("body") or ""
    if START in body or END in body:
        if body.count(START) != 1 or body.count(END) != 1 or body.index(START) > body.index(END):
            raise ValueError("Release has malformed download table markers")
        before, rest = body.split(START, 1)
        _, after = rest.split(END, 1)
        body = before + after
    return block + "\n\n" + body.lstrip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "fantuz/DNSProxy"))
    parser.add_argument("--release-json", type=Path, help="GitHub REST release response to refresh")
    args = parser.parse_args()
    if bool(args.version) == bool(args.release_json):
        parser.error("Provide either a version or --release-json")
    try:
        if args.release_json:
            notes = refresh(json.loads(args.release_json.read_text()), args.repository)
        else:
            notes, _ = downloads(args.version, args.repository)
    except (ValueError, KeyError) as error:
        parser.error(str(error))
    print(notes.rstrip())


if __name__ == "__main__":
    main()
