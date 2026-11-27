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


def downloads(version, repository, *, macos=True, windows_arm64=True, gui=True, windows_installer=True, windows_gui=True):
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
             "| Windows | " + asset("**Portable ZIP**", f"dnsp-modern-{version}-windows-amd64-poc.zip") + " | " +
             (asset("**ARM64 ZIP**", f"dnsp-modern-{version}-windows-arm64-poc.zip") if windows_arm64 else "Not available") + " |"]
    if windows_installer:
        links = [asset("**Setup EXE**", f"dnsp-modern-{version}-windows-{arch}-setup.exe")
                 for arch in ("amd64", "arm64")]
        lines.insert(-1, f"| Windows installer | {' | '.join(links)} |")
    if windows_gui:
        links = [asset("**Desktop setup**", f"dnsp-modern-{version}-windows-{arch}-gui-setup.exe") + " · " +
                 asset("runtime sources", f"dnsp-modern-{version}-windows-{arch}-gui-sources.zip")
                 for arch in ("amd64", "arm64")]
        lines.insert(-1, f"| Windows desktop GUI | {' | '.join(links)} |")
    if macos:
        links = [asset(label, f"dnsp-modern-{version}-macos-{arch}.tar.gz")
                 for label, arch in (("**Intel archive**", "x86_64"), ("**Apple Silicon archive**", "arm64"))]
        lines.append(f"| macOS 15+ | {' | '.join(links)} |")
    for label, distro in (("Ubuntu 22.04", "ubuntu22.04"),
                         ("Ubuntu 24.04", "ubuntu24.04"),
                         ("Debian 13", "debian13")):
        links = [asset("DEB", f"dnsp-modern_{version}+{distro}_{arch}.deb")
                 for arch in ("amd64", "arm64")]
        lines.append(f"| {label} | {' | '.join(links)} |")
    links = [asset("RPM", f"dnsp-modern-{version}-1.el9.{arch}.rpm")
             for arch in ("x86_64", "aarch64")]
    lines.append(f"| Rocky Linux 9 | {' | '.join(links)} |")
    if macos:
        lines.extend(["", "**Mac first launch:** Verify the archive against this release’s `SHA256SUMS`, "
                      "then try opening the app or launcher once. If macOS cannot verify the developer "
                      "and you trust the copy, choose **System Settings → Privacy & Security → Open Anyway**, "
                      "then confirm **Open** for the named item. "
                      "[Apple’s Open Anyway steps](https://support.apple.com/en-us/102445#openanyway)"
                      " · [Full Apple guide](https://support.apple.com/en-us/102445)."])
    if gui:
        lines.extend(["", "Optional Linux desktop monitor (works on both processor architectures):", "",
                      "| Platform | GUI package |", "| --- | --- |"])
        for label, distro in (("Ubuntu 22.04", "ubuntu22.04"),
                              ("Ubuntu 24.04", "ubuntu24.04"), ("Debian 13", "debian13")):
            lines.append(f"| {label} | " + asset("GUI DEB", f"dnsp-modern-gui_{version}+{distro}_all.deb") + " |")
        lines.append("| Rocky Linux 9 | " + asset("GUI RPM", f"dnsp-modern-gui-{version}-1.el9.noarch.rpm") + " |")
    checksums = asset("SHA256SUMS", "SHA256SUMS")
    lines.extend(["",
                  "**Windows:** " + ("use Setup EXE for Start Menu/Apps registration and optional Windows service, or " if windows_installer else "") +
                  "choose the ZIP matching your system type (amd64 or ARM64), "
                  "extract the entire ZIP and double-click **Start-DNSProxy.cmd**. "
                  "Keep the EXE, DLLs and certificate bundle together."])
    if macos:
        lines.extend(["", "**macOS:** extract the archive into its own folder and run **Start-DNSProxy.command**. "
                      "The launcher uses local port 5053; system DNS setup and download approval are covered in the "
                      f"[macOS guide]({root}/blob/{tag}/docs/MACOS.md)."])
    if windows_gui:
        lines.extend(["", "**Desktop interface:** Windows desktop setup bundles its private GTK/Python runtime; "
                      "the matching source ZIP is provided for runtime redistribution and is not needed to run it. "
                      "On macOS, install `gtk4 pygobject3` with Homebrew, then open **DNSProxy.app** if included, or **Start-DNSProxy-GUI.command**. "
                      f"See the [desktop guide]({root}/blob/{tag}/docs/DESKTOP-GUI.md)."])
    lines.extend(["",
                  f"[Windows setup guide]({root}/blob/{tag}/docs/WINDOWS.md) · "
                  f"[Linux installation guide]({root}/blob/{tag}/packaging/README-packaging.md) · "
                  f"[Checksum instructions]({root}/blob/{tag}/packaging/README-packaging.md#automatic-and-manual-releases) · {checksums}",
                  "", END])
    return "\n".join(lines), set(assets)


def refresh(release, repository):
    match = re.fullmatch(f"v({VERSION})-modern", release["tag_name"])
    if not match or release.get("draft") or release.get("prerelease"):
        raise ValueError("Expected a published stable DNSProxy modern release")
    available = {asset["name"] for asset in release["assets"]}
    # Older releases have no macOS packages. Never add broken links to them;
    # if either architecture is present, require the complete pair.
    macos = any(name.endswith(("-macos-x86_64.tar.gz", "-macos-arm64.tar.gz")) for name in available)
    windows_arm64 = any(name.endswith('-windows-arm64-poc.zip') for name in available)
    gui = any(name.startswith(("dnsp-modern-gui_", "dnsp-modern-gui-")) for name in available)
    windows_installer = any(name.endswith(('-windows-amd64-setup.exe', '-windows-arm64-setup.exe')) for name in available)
    windows_gui = any(name.endswith(('-gui-setup.exe', '-gui-sources.zip')) for name in available)
    block, expected = downloads(match.group(1), repository, macos=macos, windows_arm64=windows_arm64,
                                gui=gui, windows_installer=windows_installer, windows_gui=windows_gui)
    missing = expected - available
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
