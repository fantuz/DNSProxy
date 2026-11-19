#!/usr/bin/env python3
"""Qualify the installed desktop without depending on the builder's MSYS2.

Private-runtime and real replacement checks adapt the MIT-licensed
entropy-service installer harness. Copyright (c) 2026 Massimiliano Fantuzzi
HB9GUS. See tools/desktop-gui/THIRD_PARTY_NOTICES.txt.
"""

from contextlib import contextmanager
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def powershell(command, environment, *, timeout=60):
    shell = (
        Path(os.environ["SystemRoot"])
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    return subprocess.run(
        [
            str(shell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; " + command,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            key: value
            for key, value in environment.items()
            if key.lower() != "psmodulepath"
        },
    )


def ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def setup(executable, artifacts, name, environment, *, success=True, arguments=()):
    log = artifacts / (name + ".log")
    completed = subprocess.run(
        [
            str(executable),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/SP-",
            f"/LOG={log}",
            *arguments,
        ],
        env=environment,
        capture_output=True,
        timeout=240,
    )
    if (completed.returncode == 0) != success:
        detail = (
            log.read_text(encoding="utf-8-sig", errors="replace")
            if log.exists()
            else ""
        )
        raise AssertionError(
            f"{name}: exit={completed.returncode}\n{detail}\n"
            f"{completed.stdout!r}\n{completed.stderr!r}"
        )
    return completed.returncode


def assert_no_service(environment):
    count = powershell(
        "@(Get-Service DNSProxy -ErrorAction SilentlyContinue).Count", environment
    )
    assert count.stdout.strip() == "0", (
        "Desktop-only setup unexpectedly registered a service"
    )


def validate_inventory(gui, version, source_sha, architecture):
    builder = runpy.run_path(str(ROOT / "scripts/build-windows-gui-bundle.py"))
    manifest = builder["validate_manifest"](gui, version, source_sha, architecture)
    checksums = {}
    for line in (gui / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and ".." not in relative.parts
        assert "\\" not in name and ":" not in name
        assert name not in checksums, f"Duplicate GUI checksum: {name}"
        checksums[name] = expected
        assert digest(gui / name) == expected, (
            f"Installed GUI checksum mismatch: {name}"
        )
    assert set(checksums) == set(manifest["files"]) | {"bundle-manifest.json"}
    check_machine = runpy.run_path(str(ROOT / "scripts/bundle-windows.py"))[
        "check_machine"
    ]
    native_images = []
    for path in (gui / "runtime").rglob("*"):
        if path.is_file() and path.suffix.lower() in (".exe", ".dll", ".pyd"):
            check_machine(path, architecture)
            native_images.append(path.relative_to(gui).as_posix())
    assert native_images, "No native private runtime was installed"
    assert (gui / "runtime/share/licenses").is_dir(), (
        "Runtime license files are missing"
    )
    assert (gui / "runtime-package-metadata").is_dir(), (
        "Runtime package metadata is missing"
    )
    assert (gui / "THIRD_PARTY_NOTICES.txt").is_file()
    return manifest, native_images


def verify_shortcut(app, environment):
    script = (
        "$folder=Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'DNSProxy'; "
        "$path=Join-Path $folder 'DNSProxy desktop.lnk'; "
        "if (-not (Test-Path -LiteralPath $path)) { throw 'Missing desktop shortcut' }; "
        "$link=(New-Object -ComObject WScript.Shell).CreateShortcut($path); "
        "@{Target=$link.TargetPath; Arguments=$link.Arguments; WorkingDirectory=$link.WorkingDirectory} "
        "| ConvertTo-Json"
    )
    result = json.loads(powershell(script, environment).stdout)
    assert (
        Path(result["Target"]).resolve()
        == (app / "gui/runtime/bin/pythonw.exe").resolve()
    )
    assert "-I -B" in result["Arguments"]
    assert str(app / "gui/app/gui-bootstrap.py") in result["Arguments"]
    assert Path(result["WorkingDirectory"]).resolve() == (app / "gui").resolve()
    return result


@contextmanager
def unavailable_msys(prefix):
    """Hide a build prefix when the controller itself does not depend on it."""
    if prefix is None:
        yield False
        return
    prefix = prefix.resolve()
    assert prefix.name.lower() in ("ucrt64", "clangarm64")
    assert (prefix / "bin/python.exe").is_file()
    # A native-MSYS test controller cannot hide its own Python's standard
    # library. The child still undergoes exact loaded-module path checks below.
    if Path(sys.executable).resolve().is_relative_to(prefix):
        yield False
        return
    hidden = prefix.with_name(prefix.name + "-unavailable-for-dnsp-gui-test")
    assert not hidden.exists(), "A previous test prefix rename was not restored"
    prefix.rename(hidden)
    try:
        yield True
    finally:
        hidden.rename(prefix)


def runtime_environment(gui, state, inherited):
    environment = dict(inherited)
    for name in tuple(environment):
        if name.upper() in {
            "PYTHONPATH",
            "PYTHONHOME",
            "GI_TYPELIB_PATH",
            "GSETTINGS_SCHEMA_DIR",
            "XDG_DATA_DIRS",
            "GTK_EXE_PREFIX",
            "GTK_DATA_PREFIX",
            "GIO_MODULE_DIR",
            "GDK_PIXBUF_MODULE_FILE",
            "GDK_PIXBUF_MODULEDIR",
            "FONTCONFIG_PATH",
            "FONTCONFIG_FILE",
            "PSMODULEPATH",
        }:
            environment.pop(name)
    windows = Path(os.environ["SystemRoot"])
    environment["PATH"] = os.pathsep.join(
        (str(gui / "runtime/bin"), str(windows / "System32"), str(windows))
    )
    environment.update(
        GDK_BACKEND="win32",
        GSK_RENDERER="cairo",
        PYTHONDONTWRITEBYTECODE="1",
        DNSP_GUI_SOURCE=str(gui / "app"),
        DNSP_GUI_RUNTIME_BOOTSTRAP=str(gui / "app/gui-bootstrap.py"),
        DNSP_GUI_BUNDLE_ROOT=str(gui),
        DNSP_GUI_STATE=str(state),
        LOCALAPPDATA=str(state.parent),
    )
    return environment


def probe_private_runtime(gui, state, environment, original_prefix):
    """Inspect actual native DLL paths after importing GTK, not just PATH."""
    probe = r"""
import ctypes, json, os, runpy, sys
from ctypes import wintypes
from pathlib import Path
gui = Path(os.environ['DNSP_GUI_BUNDLE_ROOT']).resolve()
namespace = runpy.run_path(os.environ['DNSP_GUI_RUNTIME_BOOTSTRAP'])
namespace['configure_runtime'](gui, Path(os.environ['DNSP_GUI_STATE']))
import gi, cairo
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk
assert Gtk.get_major_version() == 4
assert Path(sys.prefix).resolve() == (gui/'runtime').resolve(), sys.prefix
for module in (gi, cairo):
    assert Path(module.__file__).resolve().is_relative_to(gui/'runtime'), module.__file__
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.GetCurrentProcess.restype = wintypes.HANDLE
kernel.K32EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel.K32EnumProcessModules.restype = wintypes.BOOL
kernel.GetModuleFileNameW.argtypes = [wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
kernel.GetModuleFileNameW.restype = wintypes.DWORD
modules = (wintypes.HMODULE * 2048)()
needed = wintypes.DWORD()
assert kernel.K32EnumProcessModules(kernel.GetCurrentProcess(), modules, ctypes.sizeof(modules), ctypes.byref(needed))
assert needed.value <= ctypes.sizeof(modules)
loaded = []
for module in modules[:needed.value//ctypes.sizeof(wintypes.HMODULE)]:
    filename = ctypes.create_unicode_buffer(32768)
    assert kernel.GetModuleFileNameW(module, filename, len(filename))
    loaded.append(str(Path(filename.value).resolve()))
assert any('libgtk-4' in Path(path).name.lower() for path in loaded), loaded
original = os.environ.get('DNSP_ORIGINAL_MSYS_PREFIX')
if original:
    assert not any(Path(path).is_relative_to(Path(original).resolve()) for path in loaded), loaded
print(json.dumps({'python':sys.executable,'prefix':sys.prefix,'gi':gi.__file__,
                  'cairo':cairo.__file__,'gtk':Gtk.get_major_version(),'loaded_modules':loaded}))
"""
    if original_prefix:
        environment = environment | {
            "DNSP_ORIGINAL_MSYS_PREFIX": str(original_prefix.resolve())
        }
    result = subprocess.run(
        [str(gui / "runtime/bin/python.exe"), "-I", "-B", "-c", probe],
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def exercise_native_gui(gui, app, artifacts, name, environment):
    destination = artifacts / name
    harness = ROOT / "tests/test_gui_native.py"
    command = [
        str(gui / "runtime/bin/python.exe"),
        "-I",
        "-B",
        str(harness),
        "--binary",
        str(app / "bin/dnsp-modern.exe"),
        "--artifacts",
        str(destination),
    ]
    process = subprocess.Popen(
        command,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=420)
    except subprocess.TimeoutExpired:
        timed_out = True
        # The all-scenarios runner owns child GUI processes. Bound teardown of
        # that exact process tree without touching any unrelated application.
        killer = Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"
        subprocess.run(
            [str(killer), "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            timeout=20,
        )
        stdout, stderr = process.communicate(timeout=20)
    (artifacts / (name + "-stdout.txt")).write_text(stdout, encoding="utf-8")
    (artifacts / (name + "-stderr.txt")).write_text(stderr, encoding="utf-8")
    assert not timed_out and process.returncode == 0, stdout + stderr
    result = json.loads((destination / "results.json").read_text(encoding="utf-8"))
    assert result["passed"] and result["platform"] == "win32", result
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--installer", type=Path, default=os.environ.get("DNSP_TEST_GUI_INSTALLER")
    )
    parser.add_argument(
        "--architecture",
        choices=("amd64", "arm64"),
        default=os.environ.get("DNSP_TEST_WINDOWS_ARCH"),
    )
    parser.add_argument(
        "--msys-prefix", type=Path, default=os.environ.get("DNSP_TEST_MSYS_PREFIX")
    )
    parser.add_argument(
        "--sources", type=Path, default=os.environ.get("DNSP_TEST_GUI_SOURCES")
    )
    parser.add_argument(
        "--artifacts", type=Path, default=ROOT / "dist/windows-gui-installer-evidence"
    )
    args = parser.parse_args()
    if sys.platform != "win32":
        parser.error("Run this acceptance test on native Windows")
    if args.installer is None or args.architecture is None:
        parser.error(
            "--installer/DNSP_TEST_GUI_INSTALLER and --architecture/DNSP_TEST_WINDOWS_ARCH are required"
        )
    installer = args.installer.resolve()
    assert installer.is_file()
    sources = args.sources or installer.with_name(
        installer.name.replace("-gui-setup.exe", "-gui-sources.zip")
    )
    assert sources.is_file(), f"Missing matching GUI runtime sources: {sources}"
    artifacts = args.artifacts.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.lower() != "psmodulepath"
    }
    folders = powershell(
        "@{ProgramFiles=[Environment]::GetFolderPath('ProgramFiles'); "
        "ProgramData=[Environment]::GetFolderPath('CommonApplicationData')} | ConvertTo-Json",
        environment,
    )
    folders = json.loads(folders.stdout)
    app, state = (
        Path(folders["ProgramFiles"]) / "DNSProxy",
        Path(folders["ProgramData"]) / "DNSProxy",
    )
    assert not app.exists() and not state.exists(), (
        "GUI acceptance requires a clean disposable installation"
    )
    assert_no_service(environment)
    version = (ROOT / "VERSION").read_text().strip()
    git = shutil.which("git")
    source_sha = os.environ.get("DNSP_TEST_SOURCE_SHA")
    if not source_sha:
        assert git, "Set DNSP_TEST_SOURCE_SHA when Git is unavailable"
        source_sha = subprocess.check_output(
            [git, "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
    builder = runpy.run_path(str(ROOT / "scripts/build-windows-gui-bundle.py"))
    builder["validate_sources"](sources, version, source_sha, args.architecture)
    evidence = {
        "version": version,
        "source_sha": source_sha,
        "architecture": args.architecture,
        "sources_sha256": digest(sources),
        "passed": False,
    }
    install_arguments = ("/COMPONENTS=core,gui", "/SERVICE=0")
    with tempfile.TemporaryDirectory(prefix="DNSProxy GUI user data ") as temporary:
        user_state = Path(temporary) / "LocalAppData/DNSProxy"
        user_state.mkdir(parents=True)
        retained = user_state / "retain-user-data.txt"
        retained.write_text("Keep user preferences and exports.", encoding="utf-8")
        gui = app / "gui"
        try:
            setup(
                installer,
                artifacts,
                "install",
                environment,
                arguments=install_arguments,
            )
            manifest, images = validate_inventory(
                gui, version, source_sha, args.architecture
            )
            evidence["native_image_count"] = len(images)
            evidence["shortcut"] = verify_shortcut(app, environment)
            assert_no_service(environment)
            isolated = runtime_environment(gui, user_state, environment)
            with unavailable_msys(args.msys_prefix) as hidden:
                evidence["msys_prefix_hidden"] = hidden
                evidence["runtime"] = probe_private_runtime(
                    gui, user_state, isolated, args.msys_prefix
                )
                evidence["native_initial"] = exercise_native_gui(
                    gui, app, artifacts, "native-initial", isolated
                )
                validate_inventory(gui, version, source_sha, args.architecture)
                obsolete_app = gui / "app/obsolete-ci-fixture.py"
                obsolete_runtime = gui / "runtime/obsolete-ci-fixture.dll"
                obsolete_app.write_text("old installer-owned code", encoding="utf-8")
                obsolete_runtime.write_bytes(b"old installer-owned runtime")
                unowned = app / "retain-unowned-file.txt"
                unowned.write_text("keep unowned data", encoding="utf-8")
                active = subprocess.Popen(
                    [
                        str(gui / "runtime/bin/python.exe"),
                        "-I",
                        "-B",
                        "-u",
                        "-c",
                        "import time; print('ready',flush=True); time.sleep(180)",
                    ],
                    env=isolated,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    assert active.stdout.readline().strip() == b"ready"
                    setup(
                        installer,
                        artifacts,
                        "active-runtime-blocks-upgrade",
                        environment,
                        success=False,
                        arguments=install_arguments,
                    )
                    assert active.poll() is None, (
                        "Setup killed a live application process"
                    )
                    assert obsolete_app.exists() and obsolete_runtime.exists()
                    assert (
                        retained.read_text(encoding="utf-8")
                        == "Keep user preferences and exports."
                    )
                    evidence["active_runtime_guard"] = True
                finally:
                    if active.poll() is None:
                        active.terminate()
                    active.wait(timeout=15)
                    active.stdout.close()
                    active.stderr.close()
                setup(
                    installer,
                    artifacts,
                    "upgrade",
                    environment,
                    arguments=install_arguments,
                )
                assert not obsolete_app.exists() and not obsolete_runtime.exists()
                assert (
                    retained.read_text(encoding="utf-8")
                    == "Keep user preferences and exports."
                )
                assert unowned.read_text(encoding="utf-8") == "keep unowned data"
                upgraded, _ = validate_inventory(
                    gui, version, source_sha, args.architecture
                )
                assert upgraded == manifest
                evidence["native_upgraded"] = exercise_native_gui(
                    gui, app, artifacts, "native-upgraded", isolated
                )
                validate_inventory(gui, version, source_sha, args.architecture)
                assert_no_service(environment)
            evidence["upgrade_retained_user_data"] = True
        finally:
            uninstaller = app / "unins000.exe"
            if uninstaller.exists():
                setup(uninstaller, artifacts, "uninstall", environment)
                deadline = time.monotonic() + 20
                while uninstaller.exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
            assert not (app / "bin/dnsp-modern.exe").exists()
            assert not (app / "gui/runtime").exists() and not (app / "gui/app").exists()
            assert not state.exists()
            assert_no_service(environment)
            assert (
                retained.read_text(encoding="utf-8")
                == "Keep user preferences and exports."
            )
            (app / "retain-unowned-file.txt").unlink(missing_ok=True)
            for path in (app / "gui", app / "bin", app):
                if path.exists() and not any(path.iterdir()):
                    path.rmdir()
        # A user may choose the CLI-only component even in the GUI setup EXE.
        setup(
            installer,
            artifacts,
            "component-opt-out",
            environment,
            arguments=("/COMPONENTS=core", "/SERVICE=0"),
        )
        try:
            assert (app / "bin/dnsp-modern.exe").is_file()
            assert not (app / "gui").exists()
            assert_no_service(environment)
        finally:
            setup(
                app / "unins000.exe",
                artifacts,
                "component-opt-out-uninstall",
                environment,
            )
        evidence["optional_component"] = True
        evidence["uninstall_retained_user_data"] = True
    evidence["passed"] = True
    (artifacts / "results.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    print(
        "Bundled GUI install, native controls, protected runtime, upgrade and uninstall passed."
    )


if __name__ == "__main__":
    main()
