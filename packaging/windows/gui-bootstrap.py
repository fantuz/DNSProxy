"""Relocatable DNSProxy entry point for its private Windows Python/GTK runtime.

Runtime setup adapted from entropy-service's MIT-licensed gui_bootstrap.py.
Copyright (c) 2026 Massimiliano Fantuzzi HB9GUS. See THIRD_PARTY_NOTICES.txt.
"""

import ctypes
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import traceback

DLL_DIRECTORIES = []


def configure_runtime(root, state):
    """Configure this GUI process only; installed program files stay read-only."""
    root, state = Path(root).resolve(), Path(state).resolve()
    runtime = root / "runtime"
    state.mkdir(parents=True, exist_ok=True)
    DLL_DIRECTORIES.append(os.add_dll_directory(str(runtime / "bin")))
    os.environ["PATH"] = str(runtime / "bin") + os.pathsep + os.environ.get("PATH", "")
    for variable, relative in {
        "GI_TYPELIB_PATH": "lib/girepository-1.0",
        "GSETTINGS_SCHEMA_DIR": "share/glib-2.0/schemas",
        "XDG_DATA_DIRS": "share",
        "GTK_EXE_PREFIX": ".",
        "GTK_DATA_PREFIX": ".",
        "GIO_MODULE_DIR": "lib/gio/modules",
        "FONTCONFIG_PATH": "etc/fonts",
        "FONTCONFIG_FILE": "etc/fonts/fonts.conf",
    }.items():
        os.environ[variable] = str(runtime / relative)
    os.environ["XDG_CACHE_HOME"] = str(state / "cache")
    os.environ["GDK_BACKEND"] = "win32"
    os.environ.setdefault("GSK_RENDERER", "cairo")
    loaders = runtime / "lib/gdk-pixbuf-2.0/2.10.0/loaders"
    query = runtime / "bin/gdk-pixbuf-query-loaders.exe"
    if query.is_file() and loaders.is_dir():
        os.environ["GDK_PIXBUF_MODULEDIR"] = str(loaders)
        cache = state / "pixbuf-loaders.cache"
        with tempfile.NamedTemporaryFile(dir=state, delete=False) as output:
            temporary = Path(output.name)
            try:
                subprocess.run(
                    [str(query)],
                    stdout=output,
                    stderr=subprocess.PIPE,
                    timeout=15,
                    check=True,
                )
            except BaseException:
                output.close()
                temporary.unlink(missing_ok=True)
                raise
        os.replace(temporary, cache)
        os.environ["GDK_PIXBUF_MODULE_FILE"] = str(cache)
    os.chdir(state)
    sys.path.insert(0, str(root / "app"))
    return root


def launch_arguments(root, arguments):
    """Only explicit application flags; no shell command/test execution path."""
    root = Path(root)
    arguments = list(arguments)
    if not any(
        value == "--binary" or value.startswith("--binary=") for value in arguments
    ):
        arguments = ["--binary", str(root.parent / "bin/dnsp-modern.exe"), *arguments]
    if not any(
        value in ("--demo", "--pid", "--metrics-port")
        or value.startswith(("--pid=", "--metrics-port="))
        for value in arguments
    ):
        arguments = [*arguments, "--metrics-port", "9090"]
    return arguments


def main():
    root = Path(__file__).resolve().parents[1]
    state = Path(os.environ["LOCALAPPDATA"]) / "DNSProxy"
    try:
        configure_runtime(root, state)
        launcher = root / "app/dnsp-gui.py"
        sys.argv = [str(launcher), *launch_arguments(root, sys.argv[1:])]
        try:
            runpy.run_path(str(launcher), run_name="__main__")
        except SystemExit as error:
            if error.code not in (None, 0):
                raise RuntimeError(f"GUI exited with status {error.code}") from error
        return 0
    except Exception:
        state.mkdir(parents=True, exist_ok=True)
        log = state / "gui-startup-error.txt"
        log.write_text(traceback.format_exc(), encoding="utf-8")
        ctypes.windll.user32.MessageBoxW(
            None, "DNSProxy could not open. Diagnostics: " + str(log), "DNSProxy", 0x10
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
