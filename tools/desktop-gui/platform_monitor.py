"""Read-only native process/service adapters; no GTK or third-party packages.

Windows uses documented process/SCM queries and a cached, fixed CIM inspection
for argv. macOS uses libproc, sysctl and read-only launchctl status. All process
samples verify the executable image independently of mutable argv[0].
"""

from __future__ import annotations

import atexit
import ctypes
from dataclasses import dataclass
import json
import os
from pathlib import Path, PureWindowsPath
import re
import struct
import subprocess
import sys
import threading
import time

MAX_COMMAND = 64 * 1024
MAX_INSTANCES = 128
MAX_PIDS = 8192

_INSPECTIONS = set()
_INSPECTION_LOCK = threading.Lock()
_INSPECTIONS_CLOSED = False


def _close_inspections():
    """Reap only our read-only inspection helpers if GTK exits mid-sample."""
    global _INSPECTIONS_CLOSED
    with _INSPECTION_LOCK:
        _INSPECTIONS_CLOSED = True
        children = tuple(_INSPECTIONS)
    for child in children:
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass


atexit.register(_close_inspections)


def _run_inspection(command, *, timeout, env=None, creationflags=0, text=False):
    with _INSPECTION_LOCK:
        if _INSPECTIONS_CLOSED:
            raise OSError("Desktop process inspection is closing")
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            creationflags=creationflags,
        )
        _INSPECTIONS.add(child)
    try:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=1)
            raise
        if text:
            stdout, stderr = (
                stdout.decode("utf-8", "replace"),
                stderr.decode("utf-8", "replace"),
            )
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    finally:
        with _INSPECTION_LOCK:
            _INSPECTIONS.discard(child)
        child.stdout.close()
        child.stderr.close()


def windows_argv_key(pid, filetime):
    """CIM_DATETIME has microseconds; native FILETIME identity keeps 100ns.

    Only the metadata lookup is normalized. PID-reuse checks always retain the
    full kernel creation timestamp in NativeProcess.start_ticks.
    """
    return int(pid), int(filetime) // 10


@dataclass(frozen=True)
class NativeProcess:
    pid: int
    start_ticks: int
    cpu_seconds: float | None
    memory_bytes: int | None
    uptime: float | None
    argv: tuple | None


def parse_macos_arguments(data):
    """Decode KERN_PROCARGS2's argc, executable and NUL-separated argv only."""
    if len(data) < 5 or len(data) > MAX_COMMAND:
        raise ValueError("Invalid native process arguments")
    argc = struct.unpack_from("=i", data)[0]
    if not 1 <= argc <= 4096:
        raise ValueError("Invalid native process argument count")
    end = data.find(b"\0", 4)
    if end < 0:
        raise ValueError("Missing native executable terminator")
    pos = end + 1
    while pos < len(data) and data[pos] == 0:
        pos += 1
    argv = []
    for _ in range(argc):
        end = data.find(b"\0", pos)
        if end < 0:
            raise ValueError("Truncated native process arguments")
        argv.append(data[pos:end].decode("utf-8", "replace"))
        pos = end + 1
    return tuple(argv)


def parse_launchctl_status(body, returncode):
    if len(body) > 64 * 1024:
        raise ValueError("Oversized launchd status")
    if returncode:
        # A missing job has a distinct launchctl message; permissions and other
        # failures must never be reported as an absent installation.
        if re.search(r"Could not find service|Could not find specified service", body):
            return dict(
                load="not-found",
                active="inactive",
                substate="unknown",
                manager="launchd",
            )
        return dict(
            load="unavailable", active="unknown", substate="unknown", manager="launchd"
        )
    state = re.search(r"^\s*state = ([a-z -]{1,40})\s*$", body, re.MULTILINE)
    pid = re.search(r"^\s*pid = ([0-9]+)\s*$", body, re.MULTILINE)
    exit_code = re.search(r"^\s*last exit code = (-?[0-9]+)\s*$", body, re.MULTILINE)
    if not state:
        raise ValueError("Invalid launchd status")
    result = "" if not exit_code or exit_code[1] == "0" else "exit " + exit_code[1]
    return dict(
        load="loaded",
        active="active" if state[1] == "running" else "inactive",
        substate=state[1],
        pid=int(pid[1]) if pid else 0,
        result=result,
        manager="launchd",
    )


class _Windows:
    def __init__(self):
        from ctypes import wintypes as w

        self.w = w
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.shell = ctypes.WinDLL("shell32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.QueryFullProcessImageNameW.argtypes = [
            w.HANDLE,
            w.DWORD,
            w.LPWSTR,
            ctypes.POINTER(w.DWORD),
        ]
        self.kernel.QueryFullProcessImageNameW.restype = w.BOOL
        self.kernel.GetProcessTimes.argtypes = [
            w.HANDLE,
            ctypes.POINTER(w.FILETIME),
            ctypes.POINTER(w.FILETIME),
            ctypes.POINTER(w.FILETIME),
            ctypes.POINTER(w.FILETIME),
        ]
        self.kernel.GetProcessTimes.restype = w.BOOL
        self.kernel.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetExitCodeProcess.restype = w.BOOL
        self.kernel.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(w.FILETIME)]
        self.kernel.GetSystemDirectoryW.argtypes = [w.LPWSTR, w.UINT]
        self.kernel.GetSystemDirectoryW.restype = w.UINT
        self.kernel.LocalFree.argtypes = [w.HLOCAL]
        self.kernel.LocalFree.restype = w.HLOCAL
        self.psapi.EnumProcesses.argtypes = [
            ctypes.POINTER(w.DWORD),
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        self.psapi.EnumProcesses.restype = w.BOOL

        class Memory(ctypes.Structure):
            _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD)] + [
                (name, ctypes.c_size_t)
                for name in (
                    "PeakWorkingSetSize",
                    "WorkingSetSize",
                    "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage",
                    "PagefileUsage",
                    "PeakPagefileUsage",
                    "PrivateUsage",
                )
            ]

        self.Memory = Memory
        self.psapi.GetProcessMemoryInfo.argtypes = [
            w.HANDLE,
            ctypes.POINTER(Memory),
            w.DWORD,
        ]
        self.psapi.GetProcessMemoryInfo.restype = w.BOOL
        self.shell.CommandLineToArgvW.argtypes = [
            w.LPCWSTR,
            ctypes.POINTER(ctypes.c_int),
        ]
        self.shell.CommandLineToArgvW.restype = ctypes.POINTER(w.LPWSTR)
        self.advapi.OpenSCManagerW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
        self.advapi.OpenSCManagerW.restype = w.HANDLE
        self.advapi.OpenServiceW.argtypes = [w.HANDLE, w.LPCWSTR, w.DWORD]
        self.advapi.OpenServiceW.restype = w.HANDLE
        self.advapi.CloseServiceHandle.argtypes = [w.HANDLE]
        self.advapi.CloseServiceHandle.restype = w.BOOL

        class Status(ctypes.Structure):
            _fields_ = [
                (name, w.DWORD)
                for name in (
                    "service_type",
                    "state",
                    "controls",
                    "exit_code",
                    "specific_exit_code",
                    "checkpoint",
                    "wait_hint",
                    "pid",
                    "flags",
                )
            ]

        self.Status = Status
        self.advapi.QueryServiceStatusEx.argtypes = [
            w.HANDLE,
            ctypes.c_int,
            ctypes.POINTER(Status),
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        self.advapi.QueryServiceStatusEx.restype = w.BOOL
        self._argv = {}
        self._argv_at = float("-inf")
        self._argv_lock = threading.Lock()

    @staticmethod
    def ticks(value):
        return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)

    def pids(self):
        array = (self.w.DWORD * MAX_PIDS)()
        count = self.w.DWORD()
        if not self.psapi.EnumProcesses(
            array, ctypes.sizeof(array), ctypes.byref(count)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return [
            int(pid)
            for pid in array[: count.value // ctypes.sizeof(self.w.DWORD)]
            if pid
        ]

    def split_command(self, text):
        if not text or len(text.encode("utf-16-le")) > MAX_COMMAND:
            return None
        count = ctypes.c_int()
        values = self.shell.CommandLineToArgvW(text, ctypes.byref(count))
        if not values:
            return None
        try:
            if not 1 <= count.value <= 4096:
                return None
            return tuple(values[i] for i in range(count.value))
        finally:
            self.kernel.LocalFree(ctypes.cast(values, self.w.HLOCAL))

    def _refresh_argv(self):
        with self._argv_lock:
            if time.monotonic() - self._argv_at < 5:
                return
            self._argv_at = time.monotonic()
            self._argv = {}
            directory = ctypes.create_unicode_buffer(32768)
            length = self.kernel.GetSystemDirectoryW(directory, len(directory))
            if not 0 < length < len(directory):
                return
            shell = str(Path(directory.value) / "WindowsPowerShell/v1.0/powershell.exe")
            command = (
                "$ErrorActionPreference='Stop'; $env:PSModulePath=\"$PSHOME\\Modules\"; "
                "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
                "@(Get-CimInstance Win32_Process -Filter \"Name='dnsp-modern.exe'\" | Select-Object -First 128 | "
                "Select-Object ProcessId,CommandLine,@{n='Created';e={$_.CreationDate.ToFileTimeUtc()}}) | "
                "ConvertTo-Json -Compress"
            )
            environment = {
                k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"
            }
            try:
                result = _run_inspection(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", command],
                    timeout=4,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
                    return
                rows = json.loads(result.stdout.decode("utf-8-sig"))
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows or ():
                    pid, created, text = (
                        int(row["ProcessId"]),
                        int(row["Created"]),
                        row.get("CommandLine"),
                    )
                    if isinstance(text, str):
                        argv = self.split_command(text)
                        if argv:
                            self._argv[windows_argv_key(pid, created)] = argv
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                subprocess.TimeoutExpired,
            ):
                return

    def read(self, pid, *, with_argv=True):
        handle = self.kernel.OpenProcess(
            0x1000, False, pid
        )  # QUERY_LIMITED_INFORMATION
        if not handle:
            raise OSError(ctypes.get_last_error(), "Process information unavailable")
        try:
            path = ctypes.create_unicode_buffer(32768)
            size = self.w.DWORD(len(path))
            if not self.kernel.QueryFullProcessImageNameW(
                handle, 0, path, ctypes.byref(size)
            ):
                raise OSError(
                    ctypes.get_last_error(), "Executable information unavailable"
                )
            if PureWindowsPath(path.value).name.casefold() != "dnsp-modern.exe":
                raise ValueError(f"PID {pid} is not a dnsp-modern executable")
            created, exited, kernel, user = (self.w.FILETIME() for _ in range(4))
            if not self.kernel.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                raise OSError(
                    ctypes.get_last_error(), "Process time information unavailable"
                )
            memory = self.Memory()
            memory.cb = ctypes.sizeof(memory)
            resident = (
                memory.WorkingSetSize
                if self.psapi.GetProcessMemoryInfo(
                    handle, ctypes.byref(memory), memory.cb
                )
                else None
            )
            now = self.w.FILETIME()
            self.kernel.GetSystemTimeAsFileTime(ctypes.byref(now))
            start = self.ticks(created)
            argv = None
            if with_argv:
                argv = self._argv.get(windows_argv_key(pid, start))
                if argv is None:
                    self._refresh_argv()
                    argv = self._argv.get(windows_argv_key(pid, start))
                # A process may have exited while CIM/SCM metadata was read.
                if not self.kernel.GetProcessTimes(
                    handle,
                    ctypes.byref(created),
                    ctypes.byref(exited),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    raise OSError("Process information changed during inspection")
                exit_code = self.w.DWORD()
                if (
                    not self.kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                    or exit_code.value != 259
                ):
                    raise OSError("Process exited during inspection")
                # Align resources with collection time after a slow cold CIM
                # lookup, rather than creating a CPU spike on the next sample.
                memory = self.Memory()
                memory.cb = ctypes.sizeof(memory)
                resident = (
                    memory.WorkingSetSize
                    if self.psapi.GetProcessMemoryInfo(
                        handle, ctypes.byref(memory), memory.cb
                    )
                    else None
                )
                self.kernel.GetSystemTimeAsFileTime(ctypes.byref(now))
            return NativeProcess(
                pid,
                start,
                (self.ticks(kernel) + self.ticks(user)) / 1e7,
                resident,
                max(0, (self.ticks(now) - start) / 1e7),
                argv,
            )
        finally:
            self.kernel.CloseHandle(handle)

    def service(self):
        manager = self.advapi.OpenSCManagerW(None, None, 1)  # CONNECT only
        if not manager:
            raise OSError(ctypes.get_last_error(), "Service manager unavailable")
        try:
            service = self.advapi.OpenServiceW(
                manager, "DNSProxy", 4
            )  # QUERY_STATUS only
            if not service:
                if ctypes.get_last_error() == 1060:
                    return dict(
                        load="not-found",
                        active="inactive",
                        substate="unknown",
                        manager="Windows service",
                    )
                raise OSError(
                    ctypes.get_last_error(), "Service information unavailable"
                )
            try:
                status, needed = self.Status(), self.w.DWORD()
                if not self.advapi.QueryServiceStatusEx(
                    service,
                    0,
                    ctypes.byref(status),
                    ctypes.sizeof(status),
                    ctypes.byref(needed),
                ):
                    raise OSError(ctypes.get_last_error(), "Service status unavailable")
                states = {
                    1: "stopped",
                    2: "start-pending",
                    3: "stop-pending",
                    4: "running",
                    5: "continue-pending",
                    6: "pause-pending",
                    7: "paused",
                }
                return dict(
                    load="loaded",
                    active="active" if status.state == 4 else "inactive",
                    substate=states.get(status.state, "unknown"),
                    pid=int(status.pid),
                    result=""
                    if not status.exit_code
                    else "exit " + str(status.exit_code),
                    manager="Windows service",
                )
            finally:
                self.advapi.CloseServiceHandle(service)
        finally:
            self.advapi.CloseServiceHandle(manager)


class _Mac:
    def __init__(self):
        self.proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.proc.proc_pidpath.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.proc.proc_pidpath.restype = ctypes.c_int
        self.proc.proc_listpids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        self.proc.proc_listpids.restype = ctypes.c_int

        class Usage(ctypes.Structure):
            _fields_ = [("uuid", ctypes.c_ubyte * 16)] + [
                (name, ctypes.c_uint64)
                for name in (
                    "user",
                    "system",
                    "idle_wakeups",
                    "interrupt_wakeups",
                    "pageins",
                    "wired",
                    "resident",
                    "footprint",
                    "start",
                    "exit",
                    "child_user",
                    "child_system",
                    "child_idle_wakeups",
                    "child_interrupt_wakeups",
                    "child_pageins",
                    "child_elapsed",
                    "disk_read",
                    "disk_write",
                )
            ]

        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

        self.Usage = Usage
        self.proc.proc_pid_rusage.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        self.proc.proc_pid_rusage.restype = ctypes.c_int
        self.libc.mach_absolute_time.argtypes = []
        self.libc.mach_absolute_time.restype = ctypes.c_uint64
        self.libc.mach_timebase_info.argtypes = [ctypes.POINTER(Timebase)]
        self.libc.mach_timebase_info.restype = ctypes.c_int
        self.libc.sysctlbyname.argtypes = [
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.libc.sysctlbyname.restype = ctypes.c_int
        translated = ctypes.c_int()
        translated_size = ctypes.c_size_t(ctypes.sizeof(translated))
        self.translated = (
            self.libc.sysctlbyname(
                b"sysctl.proc_translated",
                ctypes.byref(translated),
                ctypes.byref(translated_size),
                None,
                0,
            )
            == 0
            and translated.value == 1
        )
        base = Timebase()
        if self.libc.mach_timebase_info(ctypes.byref(base)) or not base.denom:
            raise OSError("Mach timebase unavailable")
        self.seconds_per_tick = base.numer / base.denom / 1e9
        self.libc.sysctl.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.libc.sysctl.restype = ctypes.c_int

    def pids(self):
        array = (ctypes.c_int * MAX_PIDS)()
        size = self.proc.proc_listpids(
            1, 0, array, ctypes.sizeof(array)
        )  # PROC_ALL_PIDS
        if size <= 0:
            raise OSError(ctypes.get_errno(), "Process listing unavailable")
        return [int(pid) for pid in array[: size // ctypes.sizeof(ctypes.c_int)] if pid]

    def argv(self, pid):
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
        data = ctypes.create_string_buffer(MAX_COMMAND)
        size = ctypes.c_size_t(len(data))
        if self.libc.sysctl(mib, 3, data, ctypes.byref(size), None, 0):
            return None
        try:
            return parse_macos_arguments(data.raw[: size.value])
        except ValueError:
            return None

    def read(self, pid, *, with_argv=True):
        usage = self.Usage()
        if self.proc.proc_pid_rusage(pid, 2, ctypes.byref(usage)):
            raise OSError(ctypes.get_errno(), "Process usage information unavailable")
        path = ctypes.create_string_buffer(4096)
        if self.proc.proc_pidpath(pid, path, len(path)) <= 0:
            raise OSError(ctypes.get_errno(), "Executable information unavailable")
        if Path(os.fsdecode(path.value)).name != "dnsp-modern":
            raise ValueError(f"PID {pid} is not a dnsp-modern executable")
        argv = self.argv(pid) if with_argv else None
        after = self.Usage()
        if (
            self.proc.proc_pid_rusage(pid, 2, ctypes.byref(after))
            or after.start != usage.start
        ):
            raise ValueError("Process identity changed during inspection")
        return NativeProcess(
            pid,
            int(usage.start),
            None
            if self.translated
            else (after.user + after.system) * self.seconds_per_tick,
            int(after.resident),
            None
            if self.translated
            else max(
                0,
                (self.libc.mach_absolute_time() - usage.start) * self.seconds_per_tick,
            ),
            argv,
        )

    def service(self):
        result = _run_inspection(
            ["/bin/launchctl", "print", "system/net.fantuz.dnsproxy"],
            text=True,
            timeout=0.75,
        )
        return parse_launchctl_status(result.stdout + result.stderr, result.returncode)


_ADAPTER = None


def adapter():
    global _ADAPTER
    if _ADAPTER is None:
        if sys.platform == "win32":
            _ADAPTER = _Windows()
        elif sys.platform == "darwin":
            _ADAPTER = _Mac()
        else:
            raise OSError("Native process adapter is unavailable")
    return _ADAPTER


def read_native_process(pid):
    if not isinstance(pid, int) or not 0 < pid <= 2147483647:
        raise ValueError("PID must be positive")
    return adapter().read(pid)


def list_native_instances():
    native = adapter()
    result = []
    for pid in native.pids():
        try:
            # Cheap image validation before the potentially slower argv query.
            native.read(pid, with_argv=False)
            result.append(native.read(pid))
        except (OSError, ValueError):
            continue
        if len(result) == MAX_INSTANCES:
            break
    return tuple(sorted(result, key=lambda process: process.pid))


def read_native_service():
    manager = "Windows service" if sys.platform == "win32" else "launchd"
    try:
        return adapter().service()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return dict(
            load="unavailable", active="unknown", substate="unknown", manager=manager
        )
