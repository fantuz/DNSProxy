"""One GUI-owned resolver, bounded diagnostics and graceful native shutdown.

Windows console/process-group handling adapts the MIT-licensed entropy-service
implementation, Copyright (c) 2026 Massimiliano Fantuzzi HB9GUS.
The GUI never sends a signal to a separately observed process or OS service.
"""

from __future__ import annotations

import ctypes
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

MAX_LOG_BYTES = 64 * 1024
_URL = re.compile(r"https?://\S+", re.IGNORECASE)
_CONSOLE_LOCK = threading.Lock()
_WINDOWS = None


def safe_text(value):
    """Keep diagnostics readable while hiding URL secrets and terminal controls."""

    def endpoint(match):
        try:
            parts = urlsplit(match[0])
            hostname = parts.hostname or ""
            if ":" in hostname:
                hostname = "[" + hostname + "]"
            port = ":" + str(parts.port) if parts.port else ""
            return urlunsplit(
                (
                    parts.scheme,
                    hostname + port,
                    parts.path,
                    "[redacted]" if parts.query else "",
                    "",
                )
            )
        except ValueError:
            return "[redacted URL]"

    text = _URL.sub(endpoint, str(value))
    return "".join(
        character
        for character in text
        if character in "\n\t" or (ord(character) >= 32 and ord(character) != 127)
    )


def _windows():
    global _WINDOWS
    if _WINDOWS is None:
        from ctypes import wintypes as w

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetConsoleProcessList.argtypes = [ctypes.POINTER(w.DWORD), w.DWORD]
        kernel.GetConsoleProcessList.restype = w.DWORD
        kernel.AllocConsole.argtypes = []
        kernel.AllocConsole.restype = w.BOOL
        kernel.GetConsoleWindow.argtypes = []
        kernel.GetConsoleWindow.restype = w.HWND
        kernel.GenerateConsoleCtrlEvent.argtypes = [w.DWORD, w.DWORD]
        kernel.GenerateConsoleCtrlEvent.restype = w.BOOL
        kernel.PeekNamedPipe.argtypes = [
            w.HANDLE,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
            ctypes.POINTER(w.DWORD),
            ctypes.POINTER(w.DWORD),
        ]
        kernel.PeekNamedPipe.restype = w.BOOL
        _WINDOWS = kernel
    return _WINDOWS


def _ensure_console():
    from ctypes import wintypes as w

    with _CONSOLE_LOCK:
        kernel = _windows()
        if kernel.GetConsoleProcessList((w.DWORD * 1)(), 1):
            return
        if kernel.AllocConsole():
            window = kernel.GetConsoleWindow()
            if window:
                user = ctypes.WinDLL("user32", use_last_error=True)
                user.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
                user.ShowWindow.restype = w.BOOL
                user.ShowWindow(
                    window, 0
                )  # Hide only the private console just allocated.


def _spawn(command):
    if not command or any(
        not isinstance(value, str) or "\x00" in value for value in command
    ):
        raise ValueError("Choose an executable and text arguments without NUL bytes")
    options = {}
    if sys.platform == "win32":
        if command[0].rstrip(" .").lower().endswith((".cmd", ".bat")):
            raise ValueError("Choose the native resolver EXE, not a command script")
        _ensure_console()
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        bufsize=0,
        close_fds=True,
        **options,
    )


def _interrupt(child):
    if sys.platform == "win32":
        if child.pid > 0 and _windows().GenerateConsoleCtrlEvent(1, child.pid):
            return True
        if child.poll() is not None:
            return True
        child.terminate()
        return False
    child.terminate()
    return True


class OwnedResolver:
    """Own one process; Start/Stop never operate on monitored PIDs.

    stop() starts a non-daemon bounded shutdown worker. Closing GTK can therefore
    return immediately while interpreter shutdown still waits for reap/cleanup.
    """

    def __init__(self, command):
        self.command = list(command)
        self._lock = threading.RLock()
        self._child = None
        self._reader = None
        self._stopper = None
        self._logs = bytearray()
        self._log_text = ""
        self._leading_partial = False
        self._error = ""
        self._revision = 0
        self._forced = False
        self._stopping = False

    @property
    def pid(self):
        with self._lock:
            return self._child.pid if self._child else None

    def poll(self):
        with self._lock:
            return self._child.poll() if self._child else None

    def start(self):
        with self._lock:
            if (
                (self._child and self._child.poll() is None)
                or self._stopping
                or (self._reader and self._reader.is_alive())
            ):
                raise RuntimeError(
                    "The owned resolver is already running or still stopping"
                )
            self._logs.clear()
            self._log_text = ""
            self._leading_partial = False
            self._error = ""
            self._forced = False
            try:
                child = _spawn(self.command)
            except (OSError, ValueError) as error:
                self._error = safe_text(error)
                self._revision += 1
                raise RuntimeError(
                    "Could not start resolver: " + self._error
                ) from error
            self._child = child
            self._revision += 1
            reader = threading.Thread(
                target=self._pump, args=(child,), name="dnsp-gui-logs", daemon=True
            )
            self._reader = reader
            try:
                reader.start()
            except RuntimeError:
                child.kill()
                child.wait(timeout=2)
                child.stderr.close()
                self._reader = None
                raise
        return self

    def _append(self, data):
        with self._lock:
            self._logs.extend(data)
            self._log_text = None
            excess = len(self._logs) - MAX_LOG_BYTES
            if excess > 0:
                self._leading_partial = self._logs[excess - 1] != 10
                del self._logs[:excess]
            self._revision += 1

    def _pump(self, child):
        selector = None
        try:
            if sys.platform != "win32":
                os.set_blocking(child.stderr.fileno(), False)
                selector = selectors.DefaultSelector()
                selector.register(child.stderr, selectors.EVENT_READ)
            exit_deadline = None
            while True:
                if child.poll() is not None and exit_deadline is None:
                    exit_deadline = time.monotonic() + 0.5
                if exit_deadline is not None and time.monotonic() >= exit_deadline:
                    break
                if selector:
                    if not selector.select(0.05):
                        continue
                    chunk = os.read(child.stderr.fileno(), 8192)
                else:
                    from ctypes import wintypes as w
                    import msvcrt

                    available = w.DWORD()
                    handle = msvcrt.get_osfhandle(child.stderr.fileno())
                    if not _windows().PeekNamedPipe(
                        handle, None, 0, None, ctypes.byref(available), None
                    ):
                        error = ctypes.get_last_error()
                        if error in (
                            109,
                            232,
                            233,
                        ):  # Broken/closing/disconnected pipe: EOF.
                            break
                        raise OSError(
                            error, "Native resolver log pipe inspection failed"
                        )
                    if not available.value:
                        time.sleep(0.025)
                        continue
                    chunk = os.read(child.stderr.fileno(), min(8192, available.value))
                if not chunk:
                    break
                self._append(chunk)
        except (OSError, ValueError) as error:
            with self._lock:
                if child.poll() is None and not self._stopping:
                    self._error = "Resolver log capture failed: " + safe_text(error)
                    self.stop()
        finally:
            if selector:
                selector.close()
            child.stderr.close()
            # EOF does not prove the child exited. Keep ownership until poll()
            # confirms it; the user can still stop a running silent resolver.
            with self._lock:
                self._revision += 1

    def _stop(self, child, timeout):
        forced = False
        try:
            if child.poll() is None:
                try:
                    forced = not _interrupt(child)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=timeout)
                    if child.returncode == 0:
                        forced = False
                except subprocess.TimeoutExpired:
                    forced = True
                    child.kill()
                    child.wait(timeout=2)
            if self._reader:
                self._reader.join(timeout=1)
        except (OSError, subprocess.TimeoutExpired) as error:
            with self._lock:
                self._error = "Resolver shutdown failed: " + safe_text(error)
        finally:
            with self._lock:
                self._forced = forced
                self._stopping = False
                if forced and not self._error:
                    self._error = "Resolver required forced termination; shutdown may be incomplete"
                self._revision += 1

    def stop(self, wait=False, timeout=2):
        with self._lock:
            child = self._child
            if child is None:
                return False
            if self._stopper and self._stopper.is_alive():
                worker = self._stopper
            else:
                self._stopping = True
                worker = threading.Thread(
                    target=self._stop,
                    args=(child, timeout),
                    name="dnsp-gui-stop",
                    daemon=False,
                )
                self._stopper = worker
                worker.start()
        if wait:
            worker.join(timeout=timeout + 4)
            if worker.is_alive():
                raise RuntimeError("Owned resolver shutdown did not complete")
        return self._forced

    def terminate(self):
        return self.stop()

    def wait(self, timeout=None):
        with self._lock:
            child = self._child
        if child is None:
            return None
        result = child.wait(timeout=timeout)
        if self._reader:
            self._reader.join(timeout=1)
        return result

    def close(self):
        self.stop(wait=True)

    def snapshot(self):
        with self._lock:
            child = self._child
            returncode = child.poll() if child else None
            if self._log_text is None:
                data = bytes(self._logs)
                if self._leading_partial:
                    newline = data.find(b"\n")
                    data = data[newline + 1 :] if newline >= 0 else b""
                self._log_text = safe_text(data.decode("utf-8", "replace"))
            return {
                "pid": child.pid if child else None,
                "running": child is not None and returncode is None,
                "stopping": self._stopping,
                "returncode": returncode,
                "forced_stop": self._forced,
                "logs": self._log_text,
                "error": self._error,
                "revision": self._revision,
            }
