#!/usr/bin/env python3
"""Stage a native MSYS2 GTK/Python dependency closure and corresponding sources.

The native resolver bundle remains separate. Only packages needed by the desktop
runtime are copied, not the compiler/build prefix. Runtime/source manifests bind
the installed bytes to the same project revision and installed package versions.
"""

from concurrent.futures import ThreadPoolExecutor
import argparse
from functools import partial
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURES = {
    "amd64": ("ucrt64", "mingw-w64-ucrt-x86_64-"),
    "arm64": ("clangarm64", "mingw-w64-clang-aarch64-"),
}
SEEDS = ("gtk4", "python-gobject", "python-cairo")
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fields(text):
    """Read pacman's installed database without locale-dependent CLI output."""
    result, key = {}, None
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%"):
            key = line[1:-1]
            result[key] = []
        elif line and key:
            result[key].append(line)
    return result


def dependency_name(value):
    return re.split(r"[<>=]", value, maxsplit=1)[0]


def package_database(directory):
    packages = {}
    for desc in sorted(Path(directory).glob("*/desc")):
        info = fields(desc.read_text(encoding="utf-8"))
        if not info.get("NAME") or not info.get("VERSION"):
            raise ValueError(f"Incomplete installed package metadata: {desc}")
        name = info["NAME"][0]
        if name in packages:
            raise ValueError(f"Duplicate installed package: {name}")
        packages[name] = (info, desc.parent)
    return packages


def dependency_closure(packages, package_prefix):
    providers = {}
    for name, (info, _) in packages.items():
        if name.startswith(package_prefix):
            for provided in info.get("PROVIDES", []):
                providers.setdefault(dependency_name(provided), []).append(name)
    needed, pending = set(), [package_prefix + name for name in SEEDS]
    while pending:
        name = dependency_name(pending.pop())
        if name not in packages:
            candidates = providers.get(name, [])
            if len(candidates) != 1:
                raise ValueError(f"No unique installed native provider for {name}")
            name = candidates[0]
        if not name.startswith(package_prefix):
            raise ValueError(f"Non-native runtime dependency: {name}")
        if name in needed:
            continue
        needed.add(name)
        pending.extend(packages[name][0].get("DEPENDS", []))
    return sorted(needed)


def relative_file(value, prefix_name):
    """Reject archive/path traversal and files outside the selected prefix."""
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in (".", "..") for part in path.parts)
    ):
        raise ValueError(f"Invalid package file path: {value}")
    if (
        path.parts[0] != prefix_name
        or len(path.parts) < 2
        or "\\" in value
        or ":" in value
    ):
        raise ValueError(f"Package file is outside {prefix_name}: {value}")
    return Path(*path.parts[1:])


def source_request(info, source_directory):
    name, version = info["NAME"][0], info["VERSION"][0]
    base = info.get("BASE", [name])[0]
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", base) or not re.fullmatch(
        r"[A-Za-z0-9_.+:-]+", version
    ):
        raise ValueError("Unexpected installed package name/version")
    filename = f"{base}-{version.split(':')[-1]}.src.tar.zst"
    return "https://repo.msys2.org/mingw/sources/" + filename, Path(
        source_directory
    ) / filename


def validate_source_archive(path, tar):
    """Reject HTTP error bodies and require a readable complete source package."""
    path = Path(path)
    with path.open("rb") as stream:
        if stream.read(4) != ZSTD_MAGIC:
            raise ValueError(f"Not a Zstandard source archive: {path.name}")
    listing = subprocess.check_output(
        [str(tar), "-tf", str(path)], text=True, timeout=90
    ).splitlines()
    members = [PurePosixPath(name) for name in listing]
    if not members or any(
        member.is_absolute() or ".." in member.parts for member in members
    ):
        raise ValueError(f"Unsafe/empty runtime source archive: {path.name}")
    if not any(member.name == "PKGBUILD" for member in members):
        raise ValueError(f"Runtime source package has no PKGBUILD: {path.name}")


def download_source(item, *, tar):
    url, destination = item
    request = urllib.request.Request(
        url, headers={"User-Agent": "DNSProxy-runtime-sources"}
    )
    with (
        urllib.request.urlopen(request, timeout=120) as response,
        destination.open("wb") as output,
    ):
        shutil.copyfileobj(response, output)
    validate_source_archive(destination, tar)
    return {
        "url": url,
        "file": destination.name,
        "sha256": sha256_file(destination),
        "size": destination.stat().st_size,
    }


def validate_manifest(bundle, version, source_sha, architecture):
    """Release/acceptance boundary: reject stale identity or altered payloads."""
    bundle = Path(bundle)
    manifest = json.loads((bundle / "bundle-manifest.json").read_text(encoding="utf-8"))
    expected = {
        "schema_version": 1,
        "project": "DNSProxy",
        "version": version,
        "source_sha": source_sha,
        "architecture": architecture,
    }
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise ValueError("GUI bundle version, source or architecture does not match")
    files = manifest.get("files", {})
    present = {
        p.relative_to(bundle).as_posix()
        for p in bundle.rglob("*")
        if p.is_file()
        and p.relative_to(bundle).as_posix()
        not in ("bundle-manifest.json", "SHA256SUMS")
    }
    if not files or present != set(files):
        raise ValueError("GUI bundle inventory differs from its manifest")
    for name, digest in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
            raise ValueError("Unsafe GUI bundle manifest path")
        if sha256_file(bundle / name) != digest:
            raise ValueError(f"GUI bundle checksum mismatch: {name}")
    if not manifest.get("packages") or not manifest.get("sources"):
        raise ValueError("GUI runtime provenance/source inventory is missing")
    return manifest


def validate_sources(archive, version, source_sha, architecture):
    """Verify complete flat source ZIP inventory and exact build identity."""
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(names) != len(set(names)) or any(
            PurePosixPath(name).name != name or "\\" in name or ":" in name
            for name in names
        ):
            raise ValueError("Unsafe/duplicate GUI source archive entries")
        manifest = json.loads(package.read("bundle-manifest.json"))
        expected = {
            "schema_version": 1,
            "project": "DNSProxy",
            "version": version,
            "source_sha": source_sha,
            "architecture": architecture,
        }
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError("GUI source archive does not match this build")
        records = manifest.get("sources", [])
        expected_files = {"bundle-manifest.json", "LICENSE", "THIRD_PARTY_NOTICES.txt"}
        expected_files.update(record["file"] for record in records)
        if not records or set(names) != expected_files:
            raise ValueError("GUI source archive inventory is incomplete")
        for record in records:
            digest = hashlib.sha256()
            size = 0
            with package.open(record["file"]) as source:
                magic = source.read(4)
                if magic != ZSTD_MAGIC:
                    raise ValueError(
                        f"Not a Zstandard source archive: {record['file']}"
                    )
                digest.update(magic)
                size += len(magic)
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if size != record["size"] or digest.hexdigest() != record["sha256"]:
                raise ValueError(
                    f"GUI source archive checksum mismatch: {record['file']}"
                )
    return manifest


def is_package_hook_metadata(member):
    """ALPM hook metadata belongs to the build host, not the native runtime."""
    if member in (
        "usr/",
        "usr/share/",
        "usr/share/libalpm/",
        "usr/share/libalpm/hooks/",
    ):
        return True
    path = PurePosixPath(member)
    return (
        len(path.parts) == 5
        and path.parts[:4] == ("usr", "share", "libalpm", "hooks")
        and bool(re.fullmatch(r"[A-Za-z0-9_.+-]+\.hook", path.name))
        and "\\" not in member
    )


def stage_runtime(prefix, output, needed, packages):
    msys, target = prefix.parent, output / "runtime"
    metadata = output / "runtime-package-metadata"
    target.mkdir()
    metadata.mkdir()
    copied = set()
    for name in needed:
        info, directory = packages[name]
        shutil.copy2(directory / "desc", metadata / (name + ".desc"))
        shutil.copy2(directory / "files", metadata / (name + ".files"))
        for member in fields((directory / "files").read_text(encoding="utf-8")).get(
            "FILES", []
        ):
            if member == prefix.name + "/" or is_package_hook_metadata(member):
                continue
            relative = relative_file(member.rstrip("/"), prefix.name)
            source, destination = msys / member, target / relative
            if member.endswith("/"):
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not source.is_file() or not source.resolve().is_relative_to(
                prefix.resolve()
            ):
                raise ValueError(f"Missing/unsafe installed runtime file: {member}")
            if relative in copied:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied.add(relative)
    return metadata


def compile_runtime_caches(runtime):
    """Recreate generated ALPM-hook files omitted from package-owned inventories."""
    runtime = Path(runtime)
    schemas = runtime / "share/glib-2.0/schemas"
    if schemas.is_dir():
        subprocess.run(
            [str(runtime / "bin/glib-compile-schemas.exe"), str(schemas)], check=True
        )
    modules = runtime / "lib/gio/modules"
    if modules.is_dir():
        subprocess.run(
            [str(runtime / "bin/gio-querymodules.exe"), str(modules)], check=True
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--sources", type=Path, help="Source directory; writes DIR.zip alongside it"
    )
    parser.add_argument(
        "--validate-bundle", type=Path, help="Verify an existing bundle without MSYS2"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    args = parser.parse_args()
    if args.validate_bundle:
        validate_manifest(
            args.validate_bundle, args.version, args.source_sha, args.architecture
        )
        return
    if args.output is None or args.sources is None:
        parser.error("Building requires --output and --sources")
    prefix_name, package_prefix = ARCHITECTURES[args.architecture]
    prefix = Path(sys.prefix).resolve()
    if sys.platform != "win32" or prefix.name.lower() != prefix_name:
        parser.error(f"Use the native {prefix_name} Python for {args.architecture}")
    if not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", args.version
    ):
        parser.error("Invalid project version")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("Invalid source revision")
    output, sources = args.output.resolve(), args.sources.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources.mkdir(parents=True, exist_ok=False)
    msys = prefix.parent
    packages = package_database(msys / "var/lib/pacman/local")
    needed = dependency_closure(packages, package_prefix)
    pacman, tar = msys / "usr/bin/pacman.exe", msys / "usr/bin/bsdtar.exe"
    subprocess.run([str(pacman), "-Sw", "--noconfirm", *needed], check=True)
    records, requests = [], {}
    cache = msys / "var/cache/pacman/pkg"
    for name in needed:
        info, _ = packages[name]
        version = info["VERSION"][0]
        archives = list(cache.glob(f"{name}-{version.split(':')[-1]}-*.pkg.tar.zst"))
        if len(archives) != 1:
            raise ValueError(
                f"No unique verified archive for installed {name} {version}"
            )
        package_info = subprocess.check_output(
            [str(tar), "-xOf", str(archives[0]), ".PKGINFO"], text=True
        )
        metadata = dict(
            line.split(" = ", 1) for line in package_info.splitlines() if " = " in line
        )
        if metadata.get("pkgname") != name or metadata.get("pkgver") != version:
            raise ValueError(f"Installed/downloaded package identity mismatch: {name}")
        request = source_request(info, sources)
        requests[request[1].name] = request
        records.append(
            {
                "name": name,
                "version": version,
                "licenses": info.get("LICENSE", []),
                "source": request[1].name,
                "archive_sha256": sha256_file(archives[0]),
            }
        )
    stage_runtime(prefix, output, needed, packages)
    compile_runtime_caches(output / "runtime")
    # Check every native image, including Python extension modules.
    import runpy

    check_machine = runpy.run_path(str(ROOT / "scripts/bundle-windows.py"))[
        "check_machine"
    ]
    for path in (output / "runtime").rglob("*"):
        if path.suffix.lower() in (".exe", ".dll", ".pyd"):
            check_machine(path, args.architecture)
    with ThreadPoolExecutor(max_workers=4) as pool:
        source_inventory = list(
            pool.map(partial(download_source, tar=tar), sorted(requests.values()))
        )
    shutil.copytree(
        ROOT / "tools/desktop-gui",
        output / "app",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copy2(
        ROOT / "packaging/windows/gui-bootstrap.py", output / "app/gui-bootstrap.py"
    )
    shutil.copy2(ROOT / "LICENSE", output / "LICENSE")
    shutil.copy2(
        ROOT / "packaging/windows/GUI-NOTICES.txt", output / "THIRD_PARTY_NOTICES.txt"
    )
    identity = (
        f"DNSProxy desktop {args.version}\nSource commit: {args.source_sha}\n"
        f"Target: native Windows {args.architecture}\n"
    )
    (output / "BUILD-INFO.txt").write_text(identity, encoding="utf-8")
    files = {
        p.relative_to(output).as_posix(): sha256_file(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    manifest = {
        "schema_version": 1,
        "project": "DNSProxy",
        "version": args.version,
        "source_sha": args.source_sha,
        "architecture": args.architecture,
        "packages": records,
        "sources": source_inventory,
        "files": files,
    }
    (output / "bundle-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    (sources / "bundle-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    shutil.copy2(ROOT / "LICENSE", sources / "LICENSE")
    shutil.copy2(
        ROOT / "packaging/windows/GUI-NOTICES.txt", sources / "THIRD_PARTY_NOTICES.txt"
    )
    with zipfile.ZipFile(
        str(sources) + ".zip", "w", zipfile.ZIP_STORED, allowZip64=True
    ) as archive:
        for path in sorted(sources.iterdir()):
            archive.write(path, path.name)
    validate_sources(
        str(sources) + ".zip", args.version, args.source_sha, args.architecture
    )
    validate_manifest(output, args.version, args.source_sha, args.architecture)
    checksums = sorted(
        p for p in output.rglob("*") if p.is_file() and p.name != "SHA256SUMS"
    )
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{sha256_file(p)}  {p.relative_to(output).as_posix()}\n" for p in checksums
        ),
        encoding="utf-8",
    )
    print(
        f"GUI bundle: {output}; {len(needed)} native runtime packages; sources: {sources}.zip"
    )


if __name__ == "__main__":
    main()
