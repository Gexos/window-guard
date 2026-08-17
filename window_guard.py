"""
Window Guard v0.3.0

Windows privacy/convenience utility that can protect multiple running
applications with one PIN.

Main features:
- Select real running applications by visible window.
- Protect multiple applications.
- Lock Now hides currently visible protected windows.
- While locked, newly opened protected windows are hidden automatically.
- Unlock restores windows with the correct PIN.
- System tray controls.
- Optional Start with Windows.
- Salted PBKDF2-HMAC-SHA256 PIN storage.

This is not a replacement for Windows account security.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import winreg

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    Image = None
    ImageDraw = None


APP_NAME = "Window Guard"
APP_VERSION = "0.3.0"
CONFIG_VERSION = 3

PBKDF2_ITERATIONS = 310_000

SW_HIDE = 0
SW_SHOW = 5

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002

STARTUP_REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_VALUE_NAME = "WindowGuard"


def require_windows() -> None:
    if os.name != "nt":
        raise SystemExit("Window Guard runs only on Windows.")


require_windows()

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

WNDENUMPROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL,
    wintypes.HWND,
    wintypes.LPARAM,
)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL

user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL

user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL

user32.GetWindowThreadProcessId.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(wintypes.DWORD),
]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD

user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL

user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int

user32.GetWindowTextW.argtypes = [
    wintypes.HWND,
    wintypes.LPWSTR,
    ctypes.c_int,
]
user32.GetWindowTextW.restype = ctypes.c_int

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32NextW.restype = wintypes.BOOL


def get_config_directory() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "WindowGuard"
    return Path.home() / ".window_guard"


CONFIG_DIR = get_config_directory()
CONFIG_FILE = CONFIG_DIR / "config.json"


def normalize_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def get_process_image_path(pid: int) -> str | None:
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not handle:
        return None

    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)

        if not kernel32.QueryFullProcessImageNameW(
            handle,
            0,
            buffer,
            ctypes.byref(size),
        ):
            return None

        return buffer.value
    finally:
        kernel32.CloseHandle(handle)


def current_program_path() -> str:
    if getattr(sys, "frozen", False):
        return normalize_path(sys.executable)
    return normalize_path(Path(__file__).resolve())


def get_window_title(hwnd: int) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""

    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buffer, length + 1)
    return buffer.value


def get_window_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)


def get_running_processes() -> dict[int, dict]:
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0,
    )

    invalid_handle = ctypes.c_void_p(-1).value
    if not snapshot or snapshot == invalid_handle:
        return {}

    processes: dict[int, dict] = {}

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not kernel32.Process32FirstW(
            snapshot,
            ctypes.byref(entry),
        ):
            return processes

        while True:
            processes[int(entry.th32ProcessID)] = {
                "name": entry.szExeFile,
                "parent_pid": int(entry.th32ParentProcessID),
            }

            entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

            if not kernel32.Process32NextW(
                snapshot,
                ctypes.byref(entry),
            ):
                break

    finally:
        kernel32.CloseHandle(snapshot)

    return processes


def get_descendant_pids(
    processes: dict[int, dict],
    root_pids: set[int],
) -> set[int]:
    descendants = set(root_pids)
    changed = True

    while changed:
        changed = False

        for pid, info in processes.items():
            if pid in descendants:
                continue

            if info.get("parent_pid") in descendants:
                descendants.add(pid)
                changed = True

    return descendants


def get_target_pids_for_app(
    app: dict,
    processes: dict[int, dict] | None = None,
) -> set[int]:
    if processes is None:
        processes = get_running_processes()

    wanted_name = str(app.get("name", "")).casefold()
    wanted_path = str(app.get("path", "")).strip()

    exact_path_pids: set[int] = set()
    name_pids: set[int] = set()

    for pid, info in processes.items():
        if pid == os.getpid():
            continue

        exe_name = str(info.get("name", ""))

        if wanted_name and exe_name.casefold() == wanted_name:
            name_pids.add(pid)

            if wanted_path:
                actual_path = get_process_image_path(pid)

                if actual_path:
                    try:
                        if normalize_path(actual_path) == normalize_path(
                            wanted_path
                        ):
                            exact_path_pids.add(pid)
                    except (OSError, ValueError):
                        pass

    roots = exact_path_pids or name_pids

    if not roots:
        return set()

    return get_descendant_pids(processes, roots)


def enumerate_windows_for_app(
    app: dict,
    visible_only: bool = True,
    processes: dict[int, dict] | None = None,
) -> list[int]:
    if processes is None:
        processes = get_running_processes()

    target_pids = get_target_pids_for_app(app, processes)

    if not target_pids:
        return []

    found: list[int] = []

    @WNDENUMPROC
    def callback(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindow(hwnd):
            return True

        if visible_only and not user32.IsWindowVisible(hwnd):
            return True

        if get_window_pid(hwnd) in target_pids:
            found.append(int(hwnd))

        return True

    user32.EnumWindows(callback, 0)
    return found


def enumerate_selectable_applications() -> list[dict]:
    processes = get_running_processes()
    own_pid = os.getpid()

    items: list[dict] = []

    @WNDENUMPROC
    def callback(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindow(hwnd):
            return True

        if not user32.IsWindowVisible(hwnd):
            return True

        title = get_window_title(hwnd).strip()

        if not title:
            return True

        pid = get_window_pid(hwnd)

        if pid == 0 or pid == own_pid:
            return True

        info = processes.get(pid, {})
        exe_name = str(info.get("name", "?"))
        process_path = get_process_image_path(pid) or ""

        items.append(
            {
                "hwnd": int(hwnd),
                "pid": pid,
                "title": title,
                "name": exe_name,
                "path": process_path,
            }
        )

        return True

    user32.EnumWindows(callback, 0)

    items.sort(
        key=lambda item: (
            item["title"].casefold(),
            item["name"].casefold(),
            item["pid"],
        )
    )

    return items


def hide_window(hwnd: int) -> bool:
    if not user32.IsWindow(hwnd):
        return False

    user32.ShowWindow(hwnd, SW_HIDE)
    return True


def show_window(hwnd: int) -> bool:
    if not user32.IsWindow(hwnd):
        return False

    user32.ShowWindow(hwnd, SW_SHOW)
    return True


def default_config() -> dict:
    return {
        "config_version": CONFIG_VERSION,
        "pin": None,
        "protected_apps": [],
        "locked": False,
        "hidden_handles": [],
        "start_with_windows": False,
    }


def migrate_config(config: dict) -> dict:
    """
    Migrate configuration from earlier Window Guard versions.

    v0.1/v0.2 used a single target_path. v0.3 uses protected_apps.
    """
    if "protected_apps" not in config:
        config["protected_apps"] = []

    old_target = str(config.get("target_path", "")).strip()

    if old_target and not config["protected_apps"]:
        config["protected_apps"].append(
            {
                "name": Path(old_target).name,
                "path": old_target,
            }
        )

    config["config_version"] = CONFIG_VERSION
    config.setdefault("pin", None)
    config.setdefault("locked", False)
    config.setdefault("hidden_handles", [])
    config.setdefault("start_with_windows", False)

    return config


def load_config() -> dict:
    config = default_config()

    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(
                CONFIG_FILE.read_text(encoding="utf-8")
            )

            if isinstance(loaded, dict):
                config.update(loaded)

        except (OSError, json.JSONDecodeError):
            pass

    return migrate_config(config)


def save_config(config: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    temporary = CONFIG_FILE.with_suffix(".tmp")

    temporary.write_text(
        json.dumps(config, indent=2),
        encoding="utf-8",
    )

    temporary.replace(CONFIG_FILE)


def create_pin_record(pin: str) -> dict:
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return {
        "algorithm": "pbkdf2_hmac_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def verify_pin(pin: str, record: dict | None) -> bool:
    if not isinstance(record, dict):
        return False

    try:
        iterations = int(record["iterations"])
        salt = base64.b64decode(
            record["salt"],
            validate=True,
        )
        expected = base64.b64decode(
            record["hash"],
            validate=True,
        )

    except (KeyError, TypeError, ValueError):
        return False

    actual = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(actual, expected)


def validate_new_pin(pin: str) -> str | None:
    if not pin.isdigit():
        return "The PIN must contain digits only."

    if len(pin) < 4:
        return "The PIN must contain at least 4 digits."

    if len(pin) > 12:
        return "The PIN cannot contain more than 12 digits."

    return None


def get_startup_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --startup'

    script = Path(__file__).resolve()
    python_exe = Path(sys.executable)
    pythonw = python_exe.with_name("pythonw.exe")

    runner = pythonw if pythonw.exists() else python_exe

    return f'"{runner}" "{script}" --startup'


def set_start_with_windows(enabled: bool) -> None:
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        STARTUP_REGISTRY_PATH,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:

        if enabled:
            winreg.SetValueEx(
                key,
                STARTUP_VALUE_NAME,
                0,
                winreg.REG_SZ,
                get_startup_command(),
            )
        else:
            try:
                winreg.DeleteValue(
                    key,
                    STARTUP_VALUE_NAME,
                )
            except FileNotFoundError:
                pass


def startup_entry_exists() -> bool:
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_REGISTRY_PATH,
            0,
            winreg.KEY_QUERY_VALUE,
        ) as key:

            winreg.QueryValueEx(
                key,
                STARTUP_VALUE_NAME,
            )

            return True

    except (FileNotFoundError, OSError):
        return False


def create_tray_image():
    if Image is None or ImageDraw is None:
        return None

    image = Image.new(
        "RGB",
        (64, 64),
        (32, 38, 46),
    )

    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        (14, 26, 50, 55),
        radius=6,
        fill=(225, 230, 236),
    )

    draw.arc(
        (20, 8, 44, 38),
        start=180,
        end=360,
        fill=(225, 230, 236),
        width=6,
    )

    return image


class WindowGuardApp:
    MONITOR_INTERVAL_MS = 400
    FAILED_ATTEMPT_LIMIT = 3
    COOLDOWN_SECONDS = 15

    def __init__(
        self,
        root: tk.Tk,
        start_hidden: bool = False,
    ) -> None:
        self.root = root
        self.config = load_config()

        self.locked = bool(self.config.get("locked"))

        self.hidden_handles: set[int] = {
            int(value)
            for value in self.config.get(
                "hidden_handles",
                [],
            )
            if isinstance(value, int)
            or str(value).isdigit()
        }

        self.failed_attempts = 0
        self.cooldown_until = 0.0

        self.lock_window: tk.Toplevel | None = None
        self.pin_entry: ttk.Entry | None = None
        self.unlock_button: ttk.Button | None = None

        self.tray_icon = None

        self.status_var = tk.StringVar(
            value="Ready."
        )

        self.lock_message_var = tk.StringVar(
            value="Enter your PIN to unlock."
        )

        self.startup_var = tk.BooleanVar(
            value=startup_entry_exists()
        )

        self._build_main_window()
        self.refresh_protected_apps()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.hide_to_tray,
        )

        self.start_tray_icon()

        if self.locked:
            self.root.after(
                150,
                self.resume_locked_state,
            )
        elif start_hidden:
            self.root.after(
                100,
                self.root.withdraw,
            )

    def _build_main_window(self) -> None:
        self.root.title(
            f"{APP_NAME} {APP_VERSION}"
        )

        self.root.geometry("820x520")
        self.root.minsize(740, 460)

        main = ttk.Frame(
            self.root,
            padding=16,
        )

        main.pack(
            fill="both",
            expand=True,
        )

        main.columnconfigure(
            0,
            weight=1,
        )

        main.rowconfigure(
            3,
            weight=1,
        )

        ttk.Label(
            main,
            text=APP_NAME,
            font=("Segoe UI", 20, "bold"),
        ).grid(
            row=0,
            column=0,
            sticky="w",
        )

        ttk.Label(
            main,
            text=(
                "Protect multiple Windows applications "
                "with one PIN."
            ),
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=(2, 14),
        )

        toolbar = ttk.Frame(main)

        toolbar.grid(
            row=2,
            column=0,
            sticky="ew",
            pady=(0, 8),
        )

        ttk.Button(
            toolbar,
            text="Add Running App",
            command=self.select_running_application,
        ).pack(
            side="left",
        )

        ttk.Button(
            toolbar,
            text="Browse EXE...",
            command=self.browse_application,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Button(
            toolbar,
            text="Remove Selected",
            command=self.remove_selected_app,
        ).pack(
            side="left",
            padx=(8, 0),
        )

        ttk.Button(
            toolbar,
            text="Diagnostics",
            command=self.show_diagnostics,
        ).pack(
            side="right",
        )

        list_frame = ttk.LabelFrame(
            main,
            text="Protected applications",
            padding=8,
        )

        list_frame.grid(
            row=3,
            column=0,
            sticky="nsew",
        )

        list_frame.rowconfigure(
            0,
            weight=1,
        )

        list_frame.columnconfigure(
            0,
            weight=1,
        )

        columns = (
            "name",
            "path",
        )

        self.apps_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.apps_tree.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        self.apps_tree.heading(
            "name",
            text="Executable",
        )

        self.apps_tree.heading(
            "path",
            text="Executable Path",
        )

        self.apps_tree.column(
            "name",
            width=160,
            minwidth=120,
        )

        self.apps_tree.column(
            "path",
            width=560,
            minwidth=300,
        )

        scrollbar = ttk.Scrollbar(
            list_frame,
            orient="vertical",
            command=self.apps_tree.yview,
        )

        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        self.apps_tree.configure(
            yscrollcommand=scrollbar.set
        )

        actions = ttk.Frame(main)

        actions.grid(
            row=4,
            column=0,
            sticky="ew",
            pady=(14, 8),
        )

        ttk.Button(
            actions,
            text="Set / Change PIN",
            command=self.set_or_change_pin,
        ).pack(
            side="left",
        )

        self.lock_button = ttk.Button(
            actions,
            text="Lock Now",
            command=self.lock_now,
        )

        self.lock_button.pack(
            side="right",
        )

        ttk.Checkbutton(
            main,
            text="Start Window Guard with Windows",
            variable=self.startup_var,
            command=self.toggle_startup,
        ).grid(
            row=5,
            column=0,
            sticky="w",
            pady=(2, 8),
        )

        ttk.Separator(main).grid(
            row=6,
            column=0,
            sticky="ew",
            pady=(4, 10),
        )

        ttk.Label(
            main,
            textvariable=self.status_var,
            wraplength=760,
        ).grid(
            row=7,
            column=0,
            sticky="w",
        )

        ttk.Label(
            main,
            text=(
                "Closing this window minimizes Window Guard "
                "to the system tray. Use the tray menu to exit."
            ),
            wraplength=760,
        ).grid(
            row=8,
            column=0,
            sticky="w",
            pady=(8, 0),
        )

    def get_protected_apps(self) -> list[dict]:
        apps = self.config.get(
            "protected_apps",
            [],
        )

        if not isinstance(apps, list):
            return []

        clean: list[dict] = []

        for app in apps:
            if not isinstance(app, dict):
                continue

            name = str(
                app.get("name", "")
            ).strip()

            path = str(
                app.get("path", "")
            ).strip()

            if name:
                clean.append(
                    {
                        "name": name,
                        "path": path,
                    }
                )

        return clean

    def refresh_protected_apps(self) -> None:
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)

        for index, app in enumerate(
            self.get_protected_apps()
        ):
            self.apps_tree.insert(
                "",
                "end",
                iid=f"app_{index}",
                values=(
                    app["name"],
                    app["path"],
                ),
            )

    def app_is_duplicate(
        self,
        name: str,
        path: str,
    ) -> bool:
        wanted_name = name.casefold()

        try:
            wanted_path = (
                normalize_path(path)
                if path
                else ""
            )
        except (OSError, ValueError):
            wanted_path = ""

        for app in self.get_protected_apps():
            existing_name = str(
                app.get("name", "")
            ).casefold()

            existing_path = str(
                app.get("path", "")
            )

            if wanted_path and existing_path:
                try:
                    if (
                        normalize_path(existing_path)
                        == wanted_path
                    ):
                        return True
                except (OSError, ValueError):
                    pass

            if (
                existing_name == wanted_name
                and not wanted_path
            ):
                return True

        return False

    def add_protected_app(
        self,
        name: str,
        path: str,
    ) -> None:
        if self.app_is_duplicate(
            name,
            path,
        ):
            messagebox.showinfo(
                APP_NAME,
                "That application is already protected.",
                parent=self.root,
            )
            return

        apps = self.get_protected_apps()

        apps.append(
            {
                "name": name,
                "path": path,
            }
        )

        self.config["protected_apps"] = apps

        save_config(self.config)
        self.refresh_protected_apps()

        self.status_var.set(
            f"Added protected application: {name}"
        )

    def select_running_application(self) -> None:
        selector = tk.Toplevel(self.root)

        selector.title(
            "Select Running Application"
        )

        selector.geometry("1000x570")
        selector.minsize(780, 430)
        selector.transient(self.root)

        outer = ttk.Frame(
            selector,
            padding=12,
        )

        outer.pack(
            fill="both",
            expand=True,
        )

        outer.rowconfigure(
            2,
            weight=1,
        )

        outer.columnconfigure(
            0,
            weight=1,
        )

        ttk.Label(
            outer,
            text="Select Running Application",
            font=("Segoe UI", 16, "bold"),
        ).grid(
            row=0,
            column=0,
            sticky="w",
        )

        ttk.Label(
            outer,
            text=(
                "Choose the visible application you want "
                "to add to Window Guard."
            ),
        ).grid(
            row=1,
            column=0,
            sticky="w",
            pady=(4, 10),
        )

        columns = (
            "title",
            "exe",
            "pid",
            "path",
        )

        tree = ttk.Treeview(
            outer,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        tree.grid(
            row=2,
            column=0,
            sticky="nsew",
        )

        tree.heading(
            "title",
            text="Window Title",
        )

        tree.heading(
            "exe",
            text="Executable",
        )

        tree.heading(
            "pid",
            text="PID",
        )

        tree.heading(
            "path",
            text="Executable Path",
        )

        tree.column(
            "title",
            width=320,
            minwidth=180,
        )

        tree.column(
            "exe",
            width=140,
            minwidth=100,
        )

        tree.column(
            "pid",
            width=80,
            minwidth=60,
            anchor="center",
        )

        tree.column(
            "path",
            width=420,
            minwidth=220,
        )

        scrollbar = ttk.Scrollbar(
            outer,
            orient="vertical",
            command=tree.yview,
        )

        scrollbar.grid(
            row=2,
            column=1,
            sticky="ns",
        )

        tree.configure(
            yscrollcommand=scrollbar.set
        )

        bottom = ttk.Frame(outer)

        bottom.grid(
            row=3,
            column=0,
            sticky="ew",
            pady=(10, 0),
        )

        result_var = tk.StringVar()

        ttk.Label(
            bottom,
            textvariable=result_var,
        ).pack(
            side="left",
        )

        app_items: dict[str, dict] = {}

        def refresh() -> None:
            for child in tree.get_children():
                tree.delete(child)

            app_items.clear()

            applications = (
                enumerate_selectable_applications()
            )

            for index, item in enumerate(
                applications
            ):
                iid = f"running_{index}"
                app_items[iid] = item

                tree.insert(
                    "",
                    "end",
                    iid=iid,
                    values=(
                        item["title"],
                        item["name"],
                        item["pid"],
                        item["path"]
                        or "(path unavailable)",
                    ),
                )

            result_var.set(
                f"{len(applications)} visible window(s) found."
            )

        def choose() -> None:
            selection = tree.selection()

            if not selection:
                messagebox.showwarning(
                    APP_NAME,
                    "Select an application first.",
                    parent=selector,
                )
                return

            item = app_items.get(
                selection[0]
            )

            if not item:
                return

            path = str(
                item.get("path", "")
            )

            if not path:
                messagebox.showerror(
                    APP_NAME,
                    (
                        "Windows did not provide the executable "
                        "path. Try running Window Guard as "
                        "administrator or use Browse EXE."
                    ),
                    parent=selector,
                )
                return

            try:
                if (
                    normalize_path(path)
                    == current_program_path()
                ):
                    messagebox.showerror(
                        APP_NAME,
                        "Window Guard cannot protect itself.",
                        parent=selector,
                    )
                    return

            except (OSError, ValueError):
                pass

            self.add_protected_app(
                str(item["name"]),
                path,
            )

            selector.destroy()

        ttk.Button(
            bottom,
            text="Refresh",
            command=refresh,
        ).pack(
            side="right",
            padx=(8, 0),
        )

        ttk.Button(
            bottom,
            text="Add Selected App",
            command=choose,
        ).pack(
            side="right",
        )

        tree.bind(
            "<Double-1>",
            lambda _event: choose(),
        )

        tree.bind(
            "<Return>",
            lambda _event: choose(),
        )

        refresh()

    def browse_application(self) -> None:
        path = filedialog.askopenfilename(
            title="Select an application",
            filetypes=[
                (
                    "Windows applications",
                    "*.exe",
                ),
                (
                    "All files",
                    "*.*",
                ),
            ],
        )

        if not path:
            return

        selected = Path(path)

        if selected.suffix.lower() != ".exe":
            messagebox.showerror(
                APP_NAME,
                "Please select a Windows .exe file.",
                parent=self.root,
            )
            return

        try:
            if (
                normalize_path(selected)
                == current_program_path()
            ):
                messagebox.showerror(
                    APP_NAME,
                    "Window Guard cannot protect itself.",
                    parent=self.root,
                )
                return

        except (OSError, ValueError):
            pass

        self.add_protected_app(
            selected.name,
            str(selected),
        )

    def remove_selected_app(self) -> None:
        selection = self.apps_tree.selection()

        if not selection:
            messagebox.showwarning(
                APP_NAME,
                "Select a protected application first.",
                parent=self.root,
            )
            return

        item_id = selection[0]

        try:
            index = int(
                item_id.split("_", 1)[1]
            )
        except (IndexError, ValueError):
            return

        apps = self.get_protected_apps()

        if not (
            0 <= index < len(apps)
        ):
            return

        removed = apps.pop(index)

        self.config["protected_apps"] = apps

        save_config(self.config)
        self.refresh_protected_apps()

        self.status_var.set(
            f"Removed: {removed['name']}"
        )

    def set_or_change_pin(self) -> None:
        existing_record = self.config.get(
            "pin"
        )

        if existing_record:
            current = simpledialog.askstring(
                APP_NAME,
                "Enter the current PIN:",
                show="*",
                parent=self.root,
            )

            if current is None:
                return

            if not verify_pin(
                current,
                existing_record,
            ):
                messagebox.showerror(
                    APP_NAME,
                    "The current PIN is incorrect.",
                    parent=self.root,
                )
                return

        new_pin = simpledialog.askstring(
            APP_NAME,
            "Enter a new PIN (4 to 12 digits):",
            show="*",
            parent=self.root,
        )

        if new_pin is None:
            return

        error = validate_new_pin(new_pin)

        if error:
            messagebox.showerror(
                APP_NAME,
                error,
                parent=self.root,
            )
            return

        confirmation = simpledialog.askstring(
            APP_NAME,
            "Enter the new PIN again:",
            show="*",
            parent=self.root,
        )

        if confirmation is None:
            return

        if new_pin != confirmation:
            messagebox.showerror(
                APP_NAME,
                "The PINs do not match.",
                parent=self.root,
            )
            return

        self.config["pin"] = (
            create_pin_record(new_pin)
        )

        save_config(self.config)

        self.status_var.set(
            "PIN saved."
        )

        messagebox.showinfo(
            APP_NAME,
            "The PIN has been saved.",
            parent=self.root,
        )

    def lock_now(self) -> None:
        if self.locked:
            self.show_lock_window()
            return

        apps = self.get_protected_apps()

        if not apps:
            messagebox.showerror(
                APP_NAME,
                (
                    "Add at least one protected "
                    "application first."
                ),
                parent=self.root,
            )
            return

        if not self.config.get("pin"):
            messagebox.showerror(
                APP_NAME,
                "Set a PIN before using Lock Now.",
                parent=self.root,
            )
            return

        processes = get_running_processes()
        found_handles: set[int] = set()

        for app in apps:
            for hwnd in enumerate_windows_for_app(
                app,
                visible_only=True,
                processes=processes,
            ):
                found_handles.add(hwnd)

        for hwnd in found_handles:
            if hide_window(hwnd):
                self.hidden_handles.add(hwnd)

        self.locked = True

        self.config["locked"] = True
        self.config["hidden_handles"] = sorted(
            self.hidden_handles
        )

        save_config(self.config)

        self.failed_attempts = 0
        self.cooldown_until = 0.0

        self.lock_message_var.set(
            "Enter your PIN to unlock."
        )

        self.root.withdraw()
        self.show_lock_window()
        self.monitor_locked_apps()

        if found_handles:
            self.status_var.set(
                (
                    f"Locked. Hidden windows: "
                    f"{len(found_handles)}"
                )
            )
        else:
            self.status_var.set(
                (
                    "Lock mode is active. No protected "
                    "windows are currently visible; "
                    "new ones will be hidden automatically."
                )
            )

    def show_lock_window(self) -> None:
        if (
            self.lock_window
            and self.lock_window.winfo_exists()
        ):
            self.lock_window.deiconify()
            self.lock_window.lift()

            if self.pin_entry:
                self.pin_entry.focus_force()

            return

        window = tk.Toplevel(self.root)

        self.lock_window = window

        window.title(APP_NAME)
        window.geometry("450x270")
        window.resizable(False, False)
        window.attributes("-topmost", True)

        window.protocol(
            "WM_DELETE_WINDOW",
            self.refuse_lock_window_close,
        )

        frame = ttk.Frame(
            window,
            padding=24,
        )

        frame.pack(
            fill="both",
            expand=True,
        )

        ttk.Label(
            frame,
            text=APP_NAME,
            font=("Segoe UI", 18, "bold"),
        ).pack()

        ttk.Label(
            frame,
            text="Protected applications are locked.",
        ).pack(
            pady=(8, 16),
        )

        ttk.Label(
            frame,
            textvariable=self.lock_message_var,
        ).pack()

        self.pin_entry = ttk.Entry(
            frame,
            show="*",
            justify="center",
            font=("Segoe UI", 14),
        )

        self.pin_entry.pack(
            fill="x",
            pady=12,
        )

        self.pin_entry.bind(
            "<Return>",
            lambda _event: self.try_unlock(),
        )

        self.unlock_button = ttk.Button(
            frame,
            text="Unlock",
            command=self.try_unlock,
        )

        self.unlock_button.pack()

        window.update_idletasks()

        x = (
            window.winfo_screenwidth()
            - window.winfo_width()
        ) // 2

        y = (
            window.winfo_screenheight()
            - window.winfo_height()
        ) // 2

        window.geometry(
            f"+{x}+{y}"
        )

        self.pin_entry.focus_force()

    def refuse_lock_window_close(self) -> None:
        if self.lock_window:
            self.lock_window.bell()
            self.lock_window.lift()

        self.lock_message_var.set(
            "Enter the PIN to unlock Window Guard."
        )

    def monitor_locked_apps(self) -> None:
        if not self.locked:
            return

        apps = self.get_protected_apps()
        processes = get_running_processes()

        changed = False

        for app in apps:
            handles = enumerate_windows_for_app(
                app,
                visible_only=True,
                processes=processes,
            )

            for hwnd in handles:
                if hide_window(hwnd):
                    if hwnd not in self.hidden_handles:
                        self.hidden_handles.add(hwnd)
                        changed = True

        invalid = {
            hwnd
            for hwnd in self.hidden_handles
            if not user32.IsWindow(hwnd)
        }

        if invalid:
            self.hidden_handles.difference_update(
                invalid
            )
            changed = True

        if changed:
            self.config["hidden_handles"] = sorted(
                self.hidden_handles
            )

            save_config(self.config)

        if (
            self.lock_window
            and self.lock_window.winfo_exists()
        ):
            self.lock_window.attributes(
                "-topmost",
                True,
            )

        self.root.after(
            self.MONITOR_INTERVAL_MS,
            self.monitor_locked_apps,
        )

    def try_unlock(self) -> None:
        if not self.locked:
            return

        if self.pin_entry is None:
            return

        remaining = int(
            self.cooldown_until - time.time()
        )

        if remaining > 0:
            self.lock_message_var.set(
                (
                    "Too many attempts. Try again in "
                    f"{remaining + 1} seconds."
                )
            )
            return

        entered = self.pin_entry.get()

        self.pin_entry.delete(
            0,
            "end",
        )

        if verify_pin(
            entered,
            self.config.get("pin"),
        ):
            self.unlock_all()
            return

        self.failed_attempts += 1

        attempts_left = (
            self.FAILED_ATTEMPT_LIMIT
            - self.failed_attempts
        )

        if attempts_left > 0:
            self.lock_message_var.set(
                (
                    f"Incorrect PIN. "
                    f"{attempts_left} attempt(s) remaining."
                )
            )

            self.pin_entry.focus_force()
            return

        self.failed_attempts = 0

        self.cooldown_until = (
            time.time()
            + self.COOLDOWN_SECONDS
        )

        self.start_cooldown()

    def start_cooldown(self) -> None:
        if not self.locked:
            return

        if self.pin_entry is None:
            return

        remaining = int(
            self.cooldown_until - time.time()
        )

        if remaining <= 0:
            self.cooldown_until = 0.0

            self.lock_message_var.set(
                "You can try again."
            )

            self.pin_entry.configure(
                state="normal"
            )

            if self.unlock_button:
                self.unlock_button.configure(
                    state="normal"
                )

            self.pin_entry.focus_force()
            return

        self.pin_entry.configure(
            state="disabled"
        )

        if self.unlock_button:
            self.unlock_button.configure(
                state="disabled"
            )

        self.lock_message_var.set(
            (
                "Too many attempts. Try again in "
                f"{remaining + 1} seconds."
            )
        )

        self.root.after(
            250,
            self.start_cooldown,
        )

    def unlock_all(self) -> None:
        first_restored = None

        for hwnd in list(
            self.hidden_handles
        ):
            if show_window(hwnd):
                if first_restored is None:
                    first_restored = hwnd

        self.hidden_handles.clear()
        self.locked = False

        self.config["locked"] = False
        self.config["hidden_handles"] = []

        save_config(self.config)

        if (
            self.lock_window
            and self.lock_window.winfo_exists()
        ):
            self.lock_window.attributes(
                "-topmost",
                False,
            )

            self.lock_window.destroy()

        self.lock_window = None
        self.pin_entry = None
        self.unlock_button = None

        self.root.deiconify()
        self.root.lift()

        self.status_var.set(
            "Protected applications unlocked."
        )

        if (
            first_restored
            and user32.IsWindow(first_restored)
        ):
            user32.SetForegroundWindow(
                first_restored
            )

    def resume_locked_state(self) -> None:
        if not self.locked:
            return

        if not self.config.get("pin"):
            self.locked = False
            self.config["locked"] = False
            self.config["hidden_handles"] = []

            save_config(self.config)

            self.status_var.set(
                (
                    "Incomplete lock state cleared "
                    "because no PIN exists."
                )
            )

            return

        apps = self.get_protected_apps()
        processes = get_running_processes()

        allowed_pids: set[int] = set()

        for app in apps:
            allowed_pids.update(
                get_target_pids_for_app(
                    app,
                    processes,
                )
            )

        valid_handles: set[int] = set()

        for hwnd in self.hidden_handles:
            if not user32.IsWindow(hwnd):
                continue

            if get_window_pid(hwnd) in allowed_pids:
                valid_handles.add(hwnd)

        self.hidden_handles = valid_handles

        self.root.withdraw()
        self.show_lock_window()
        self.monitor_locked_apps()

    def toggle_startup(self) -> None:
        enabled = bool(
            self.startup_var.get()
        )

        try:
            set_start_with_windows(
                enabled
            )

        except OSError as exc:
            self.startup_var.set(
                startup_entry_exists()
            )

            messagebox.showerror(
                APP_NAME,
                (
                    "Could not change the Windows "
                    f"startup setting.\n\n{exc}"
                ),
                parent=self.root,
            )

            return

        self.config["start_with_windows"] = (
            enabled
        )

        save_config(self.config)

        self.status_var.set(
            (
                "Start with Windows enabled."
                if enabled
                else "Start with Windows disabled."
            )
        )

    def build_diagnostic_report(self) -> str:
        apps = self.get_protected_apps()
        processes = get_running_processes()

        lines = [
            f"{APP_NAME} {APP_VERSION} diagnostic report",
            "",
            f"Locked: {self.locked}",
            f"Protected apps: {len(apps)}",
            "",
        ]

        all_target_pids: set[int] = set()

        for index, app in enumerate(
            apps,
            start=1,
        ):
            pids = get_target_pids_for_app(
                app,
                processes,
            )

            all_target_pids.update(pids)

            lines.extend(
                [
                    f"[{index}] {app['name']}",
                    f"Path: {app['path']}",
                    f"Matched PIDs: {sorted(pids) or '(none)'}",
                    "",
                ]
            )

        lines.extend(
            [
                "VISIBLE WINDOWS",
                "-" * 70,
            ]
        )

        @WNDENUMPROC
        def callback(
            hwnd: int,
            _lparam: int,
        ) -> bool:
            if not user32.IsWindow(hwnd):
                return True

            if not user32.IsWindowVisible(hwnd):
                return True

            title = get_window_title(
                hwnd
            ).strip()

            if not title:
                return True

            pid = get_window_pid(hwnd)

            info = processes.get(
                pid,
                {},
            )

            name = info.get(
                "name",
                "?",
            )

            tag = (
                " <== PROTECTED"
                if pid in all_target_pids
                else ""
            )

            lines.append(
                (
                    f"PID={pid} | EXE={name} | "
                    f"HWND={int(hwnd)} | "
                    f"TITLE={title}{tag}"
                )
            )

            return True

        user32.EnumWindows(
            callback,
            0,
        )

        return "\n".join(lines)

    def show_diagnostics(self) -> None:
        report = self.build_diagnostic_report()

        dialog = tk.Toplevel(
            self.root
        )

        dialog.title(
            f"{APP_NAME} Diagnostics"
        )

        dialog.geometry("940x560")
        dialog.minsize(720, 420)

        frame = ttk.Frame(
            dialog,
            padding=10,
        )

        frame.pack(
            fill="both",
            expand=True,
        )

        text = tk.Text(
            frame,
            wrap="none",
            font=("Consolas", 10),
        )

        text.pack(
            fill="both",
            expand=True,
        )

        text.insert(
            "1.0",
            report,
        )

        text.configure(
            state="disabled"
        )

        def copy_report() -> None:
            dialog.clipboard_clear()
            dialog.clipboard_append(
                report
            )

            self.status_var.set(
                "Diagnostic report copied."
            )

        ttk.Button(
            dialog,
            text="Copy Report",
            command=copy_report,
        ).pack(
            pady=(0, 10),
        )

    def start_tray_icon(self) -> None:
        if pystray is None:
            self.status_var.set(
                (
                    "Tray support is unavailable. Install "
                    "'pystray' and 'pillow'."
                )
            )
            return

        image = create_tray_image()

        menu = pystray.Menu(
            pystray.MenuItem(
                "Show Window Guard",
                self.tray_show,
                default=True,
            ),
            pystray.MenuItem(
                "Lock Now",
                self.tray_lock,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Exit",
                self.tray_exit,
            ),
        )

        self.tray_icon = pystray.Icon(
            "WindowGuard",
            image,
            APP_NAME,
            menu,
        )

        thread = threading.Thread(
            target=self.tray_icon.run,
            daemon=True,
        )

        thread.start()

    def tray_show(
        self,
        _icon=None,
        _item=None,
    ) -> None:
        self.root.after(
            0,
            self.show_from_tray,
        )

    def tray_lock(
        self,
        _icon=None,
        _item=None,
    ) -> None:
        self.root.after(
            0,
            self.lock_now,
        )

    def tray_exit(
        self,
        _icon=None,
        _item=None,
    ) -> None:
        self.root.after(
            0,
            self.exit_application,
        )

    def show_from_tray(self) -> None:
        if self.locked:
            self.show_lock_window()
            return

        self.root.deiconify()
        self.root.lift()

    def hide_to_tray(self) -> None:
        if pystray is None:
            if self.locked:
                self.show_lock_window()
            else:
                self.root.destroy()
            return

        self.root.withdraw()

    def exit_application(self) -> None:
        if self.locked:
            self.show_lock_window()
            self.lock_message_var.set(
                "Unlock Window Guard before exiting."
            )
            return

        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass

        self.root.destroy()


def main() -> None:
    missing = []

    if pystray is None:
        missing.append("pystray")

    if Image is None:
        missing.append("pillow")

    if missing:
        root = tk.Tk()
        root.withdraw()

        messagebox.showerror(
            APP_NAME,
            (
                "Window Guard v0.3.0 needs these Python "
                "packages:\n\n"
                + "\n".join(missing)
                + "\n\nRun:\n"
                "python -m pip install pystray pillow"
            ),
        )

        root.destroy()
        return

    root = tk.Tk()

    try:
        style = ttk.Style(root)

        if "vista" in style.theme_names():
            style.theme_use("vista")

    except tk.TclError:
        pass

    start_hidden = (
        "--startup" in sys.argv
    )

    WindowGuardApp(
        root,
        start_hidden=start_hidden,
    )

    root.mainloop()


if __name__ == "__main__":
    main()
