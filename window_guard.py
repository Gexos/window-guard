"""Window Guard: lock selected Windows app windows with a PIN."""
from __future__ import annotations

import base64, ctypes, hashlib, hmac, json, os, queue, secrets, sys, threading, time, uuid, winreg, webbrowser
from ctypes import wintypes
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    Image = ImageDraw = None

APP_NAME = "Window Guard"
APP_VERSION = "0.6.0"
CONFIG_VERSION = 5
PBKDF2_ITERATIONS = 310_000
MONITOR_MS = 350
FAILED_LIMIT = 3
COOLDOWN_SECONDS = 15
SW_HIDE, SW_SHOW = 0, 5
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "WindowGuard"

GITHUB_REPO_URL = "https://github.com/gexos/window-guard"
GITHUB_RELEASES_URL = GITHUB_REPO_URL + "/releases"
GITHUB_LATEST_RELEASE_URL = GITHUB_REPO_URL + "/releases/latest"
GITHUB_ISSUES_URL = GITHUB_REPO_URL + "/issues"
GITHUB_NEW_ISSUE_URL = GITHUB_REPO_URL + "/issues/new/choose"

if os.name != "nt":
    raise SystemExit("Window Guard runs only on Windows.")

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
    ]

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
user32.ShowWindow.restype = wintypes.BOOL
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.SetForegroundWindow.restype = wintypes.BOOL
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL

# A dedicated thread owns the Win32 hotkey message queue.
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_NOREPEAT = 0x4000
HOTKEY_ID = 0x4A32

user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
user32.RegisterHotKey.restype = wintypes.BOOL
user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
user32.UnregisterHotKey.restype = wintypes.BOOL
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype = ctypes.c_int
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostThreadMessageW.restype = wintypes.BOOL
kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wintypes.DWORD


class LockHotkey:
    """Registers Ctrl+Shift+L globally without additional packages."""

    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.thread = None
        self.thread_id = None
        self.stop_event = threading.Event()

    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._worker, name="WindowGuardHotkey", daemon=True)
        self.thread.start()

    def _worker(self):
        self.thread_id = int(kernel32.GetCurrentThreadId())
        registered = bool(user32.RegisterHotKey(
            None, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT, ord("L")
        ))
        if not registered:
            self.event_queue.put(("hotkey-error", ctypes.get_last_error()))
            self.thread_id = None
            return
        self.event_queue.put(("hotkey-ready", None))
        try:
            msg = wintypes.MSG()
            while not self.stop_event.is_set():
                result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result <= 0:
                    break
                if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID:
                    self.event_queue.put(("lock-all", None))
        finally:
            user32.UnregisterHotKey(None, HOTKEY_ID)
            self.thread_id = None

    def stop(self):
        self.stop_event.set()
        thread_id = self.thread_id
        if thread_id:
            user32.PostThreadMessageW(thread_id, WM_QUIT, 0, 0)
        if self.thread is not None:
            self.thread.join(timeout=0.8)
        self.thread = None

APPDATA = Path(os.environ.get("APPDATA", str(Path.home()))) / "WindowGuard"
CONFIG_FILE = APPDATA / "config.json"

def norm(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))

def process_path(pid: int) -> str | None:
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        return buf.value if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)) else None
    finally:
        kernel32.CloseHandle(h)

def own_path() -> str:
    return norm(sys.executable if getattr(sys, "frozen", False) else Path(__file__).resolve())

def window_title(hwnd: int) -> str:
    n = user32.GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value

def window_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value)

def processes() -> dict[int, dict]:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return {}
    result = {}
    try:
        e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(e)):
            return result
        while True:
            result[int(e.th32ProcessID)] = {"name": e.szExeFile, "parent": int(e.th32ParentProcessID)}
            e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not kernel32.Process32NextW(snap, ctypes.byref(e)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return result

def descendants(procs: dict[int, dict], roots: set[int]) -> set[int]:
    out = set(roots)
    changed = True
    while changed:
        changed = False
        for pid, info in procs.items():
            if pid not in out and info.get("parent") in out:
                out.add(pid); changed = True
    return out

def target_pids(app: dict, procs: dict[int, dict] | None = None) -> set[int]:
    procs = procs or processes()
    wanted_name = str(app.get("name", "")).casefold()
    wanted_path = str(app.get("path", "")).strip()
    same_name, exact = set(), set()
    for pid, info in procs.items():
        if pid == os.getpid() or str(info.get("name", "")).casefold() != wanted_name:
            continue
        same_name.add(pid)
        if wanted_path:
            p = process_path(pid)
            if p:
                try:
                    if norm(p) == norm(wanted_path):
                        exact.add(pid)
                except (OSError, ValueError):
                    pass
    roots = exact or same_name
    return descendants(procs, roots) if roots else set()

def app_windows(app: dict, visible_only=True, procs=None) -> list[int]:
    procs = procs or processes()
    pids = target_pids(app, procs)
    if not pids:
        return []
    found = []
    @WNDENUMPROC
    def cb(hwnd, _):
        if not user32.IsWindow(hwnd): return True
        if visible_only and not user32.IsWindowVisible(hwnd): return True
        if window_pid(hwnd) in pids: found.append(int(hwnd))
        return True
    user32.EnumWindows(cb, 0)
    return found

def visible_apps() -> list[dict]:
    procs = processes(); own = os.getpid(); out = []
    @WNDENUMPROC
    def cb(hwnd, _):
        if not user32.IsWindow(hwnd) or not user32.IsWindowVisible(hwnd): return True
        title = window_title(hwnd).strip()
        if not title: return True
        pid = window_pid(hwnd)
        if not pid or pid == own: return True
        info = procs.get(pid, {})
        out.append({"pid": pid, "title": title, "name": str(info.get("name", "?")), "path": process_path(pid) or ""})
        return True
    user32.EnumWindows(cb, 0)
    return sorted(out, key=lambda x: (x["title"].casefold(), x["name"].casefold(), x["pid"]))

def hide(hwnd: int) -> bool:
    if not user32.IsWindow(hwnd): return False
    user32.ShowWindow(hwnd, SW_HIDE); return True

def show(hwnd: int) -> bool:
    if not user32.IsWindow(hwnd): return False
    user32.ShowWindow(hwnd, SW_SHOW); return True

def app_id(name: str, path: str) -> str:
    return hashlib.sha256(f"{name.casefold()}|{path.casefold()}".encode()).hexdigest()[:16]

DEFAULT_SETTINGS = {
    "close_to_tray": True,
    "start_hidden_at_startup": True,
    "confirm_remove": True,
    "enable_global_hotkey": False,
    "monitor_ms": 350,
}


def clean_settings(value):
    data = value if isinstance(value, dict) else {}
    settings = DEFAULT_SETTINGS.copy()
    for key in ("close_to_tray", "start_hidden_at_startup", "confirm_remove", "enable_global_hotkey"):
        if key in data:
            settings[key] = bool(data[key])
    try:
        ms = int(data.get("monitor_ms", 350))
    except (TypeError, ValueError):
        ms = 350
    settings["monitor_ms"] = ms if ms in (250, 350, 500, 1000) else 350
    return settings


def default_config():
    return {
        "config_version": CONFIG_VERSION,
        "pin": None,
        "protected_apps": [],
        "start_with_windows": False,
        "settings": DEFAULT_SETTINGS.copy(),
    }

def save_config(cfg):
    APPDATA.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)

def load_config():
    cfg = default_config()
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict): cfg.update(data)
        except (OSError, json.JSONDecodeError):
            pass
    apps = cfg.get("protected_apps") if isinstance(cfg.get("protected_apps"), list) else []
    old = str(cfg.get("target_path", "")).strip()
    if old and not apps: apps = [{"name": Path(old).name, "path": old}]
    migrated = []
    for a in apps:
        if not isinstance(a, dict): continue
        name, path = str(a.get("name", "")).strip(), str(a.get("path", "")).strip()
        if not name and path: name = Path(path).name
        if not name: continue
        migrated.append({"id": str(a.get("id") or app_id(name, path)), "name": name, "path": path, "relock_on_close": True})
    cfg = {
        "config_version": CONFIG_VERSION,
        "pin": cfg.get("pin"),
        "protected_apps": migrated,
        "start_with_windows": bool(cfg.get("start_with_windows", False)),
        "settings": clean_settings(cfg.get("settings")),
    }
    save_config(cfg)
    return cfg

def make_pin(pin: str) -> dict:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, PBKDF2_ITERATIONS)
    return {"algorithm": "pbkdf2_hmac_sha256", "iterations": PBKDF2_ITERATIONS, "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(digest).decode()}

def check_pin(pin: str, rec: dict | None) -> bool:
    if not isinstance(rec, dict): return False
    try:
        salt = base64.b64decode(rec["salt"], validate=True)
        expected = base64.b64decode(rec["hash"], validate=True)
        actual = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, int(rec["iterations"]))
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False

def startup_cmd():
    if getattr(sys, "frozen", False): return f'"{sys.executable}" --startup'
    exe = Path(sys.executable); pyw = exe.with_name("pythonw.exe"); runner = pyw if pyw.exists() else exe
    return f'"{runner}" "{Path(__file__).resolve()}" --startup'

def set_startup(enabled: bool):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled: winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, startup_cmd())
        else:
            try: winreg.DeleteValue(key, RUN_VALUE)
            except FileNotFoundError: pass

def startup_exists() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_QUERY_VALUE) as key:
            winreg.QueryValueEx(key, RUN_VALUE); return True
    except OSError: return False

def resource_path(filename: str) -> Path:
    """Resolve files in the source tree or in PyInstaller's temporary bundle."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / filename


def apply_window_icon(window) -> None:
    icon_path = resource_path("assets/window_guard.ico")
    if icon_path.is_file():
        try:
            window.iconbitmap(str(icon_path))
        except tk.TclError:
            pass


def new_window(parent):
    win = tk.Toplevel(parent)
    apply_window_icon(win)
    return win


def tray_image():
    """Load the PNG used by the tray icon."""
    icon_path = resource_path("assets/window_guard_icon.png")
    return Image.open(icon_path).convert("RGBA").resize((64, 64), Image.Resampling.LANCZOS)


def program_dir() -> Path:
    """Folder containing WindowGuard.exe or window_guard.py."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def open_local_document(filename: str, parent=None) -> None:
    path = program_dir() / filename
    if not path.exists():
        messagebox.showerror(
            APP_NAME,
            f"Help file not found:\n\n{path}\n\nKeep the help files in the same folder as WindowGuard.exe.",
            parent=parent,
        )
        return
    try:
        if path.suffix.lower() == ".html":
            webbrowser.open(path.as_uri())
        else:
            os.startfile(str(path))
    except Exception as exc:
        messagebox.showerror(APP_NAME, f"Could not open the help file.\n\n{exc}", parent=parent)

def open_web_url(url: str, parent=None, label: str = "web page") -> None:
    try:
        opened = webbrowser.open_new_tab(url)
        if opened is False:
            raise RuntimeError("The default browser did not accept the request.")
    except Exception as exc:
        messagebox.showerror(APP_NAME, f"Could not open the {label}.\n\n{exc}", parent=parent)

class WindowGuard:
    def __init__(self, root: tk.Tk, start_hidden=False):
        self.root = root
        self.cfg = load_config()
        self.unlocked: set[str] = set()
        self.last_pids: dict[str, set[int]] = {}
        self.hidden: dict[str, set[int]] = {}
        self.queue: list[str] = []
        self.current: str | None = None
        self.lock_win = self.pin_entry = self.unlock_btn = None
        self.failed = 0
        self.cooldown_until = 0.0
        self.tray = None
        self._closing = False
        self._settings_win = None
        self._last_refresh = 0.0
        self.status = tk.StringVar(value="Protection monitor is active.")
        self.lock_text = tk.StringVar(value="Enter your PIN.")
        self.startup_var = tk.BooleanVar(value=startup_exists())
        self.events = queue.Queue()
        self.hotkey = LockHotkey(self.events)

        self.build_ui()
        self.refresh()
        self.root.protocol("WM_DELETE_WINDOW", self.on_main_close)
        self.start_tray()
        self.update_global_hotkey()

        if start_hidden and self.settings().get("start_hidden_at_startup", True):
            self.root.after(100, self.root.withdraw)
        self.root.after(200, self.poll_events)
        self.root.after(250, self.monitor)

    def settings(self):
        return self.cfg.get("settings", DEFAULT_SETTINGS)

    def update_global_hotkey(self):
        self.hotkey.stop()
        if self.settings().get("enable_global_hotkey", False):
            self.hotkey.start()

    def poll_events(self):
        if self._closing:
            return
        try:
            while True:
                action, data = self.events.get_nowait()
                if action == "lock-all":
                    self.lock_all()
                elif action == "hotkey-ready":
                    self.status.set("Global shortcut Ctrl+Shift+L is active.")
                elif action == "hotkey-error":
                    self.status.set("Ctrl+Shift+L could not be registered; another app may already use it.")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_events)

    def on_main_close(self):
        if self.settings().get("close_to_tray", True):
            self.hide_to_tray()
        else:
            self.exit_app()

    def apps(self): return self.cfg.get("protected_apps", [])
    def by_id(self, aid): return next((a for a in self.apps() if a.get("id") == aid), None)

    def build_ui(self):
        self.root.title(f"{APP_NAME} {APP_VERSION}"); self.root.geometry("900x560"); self.root.minsize(800,500)
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Lock All Now", command=self.lock_all)
        file_menu.add_command(label="Hide to Tray", command=self.hide_to_tray)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        menubar.add_cascade(label="File", menu=file_menu)

        apps_menu = tk.Menu(menubar, tearoff=0)
        apps_menu.add_command(label="Add Running App...", command=self.add_running)
        apps_menu.add_command(label="Browse EXE...", command=self.browse)
        apps_menu.add_separator()
        apps_menu.add_command(label="Lock Selected App", command=self.lock_selected)
        apps_menu.add_command(label="Remove Selected", command=self.remove)
        menubar.add_cascade(label="Applications", menu=apps_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Set / Change PIN", command=self.set_pin)
        tools_menu.add_command(label="Diagnostics", command=self.diagnostics)
        tools_menu.add_command(label="Export Diagnostics...", command=self.export_diagnostics)
        tools_menu.add_command(label="Settings...", command=self.open_settings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Open Configuration Folder", command=self.open_config_folder)
        tools_menu.add_command(label="Open Application Folder", command=self.open_program_folder)
        tools_menu.add_separator()
        tools_menu.add_checkbutton(
            label="Start Window Guard with Windows",
            variable=self.startup_var,
            command=self.toggle_startup,
        )
        menubar.add_cascade(label="Tools", menu=tools_menu)

        github_menu = tk.Menu(menubar, tearoff=0)
        github_menu.add_command(label="Open Repository", command=self.open_github_repository)
        github_menu.add_command(label="Latest Release", command=self.open_github_latest_release)
        github_menu.add_command(label="Check for Updates (GitHub)", command=self.check_for_updates)
        github_menu.add_command(label="All Releases", command=self.open_github_releases)
        github_menu.add_separator()
        github_menu.add_command(label="Report Bug / Request Feature", command=self.open_github_new_issue)
        github_menu.add_command(label="View Issues", command=self.open_github_issues)
        github_menu.add_separator()
        github_menu.add_command(label="Copy Repository URL", command=self.copy_github_url)
        menubar.add_cascade(label="GitHub", menu=github_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Help Contents (HTML)", command=self.open_help_html)
        help_menu.add_command(label="User Manual (PDF)", command=self.open_help_pdf)
        help_menu.add_separator()
        help_menu.add_command(label="About Window Guard", command=self.about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)
        main = ttk.Frame(self.root, padding=16); main.pack(fill="both", expand=True); main.columnconfigure(0,weight=1); main.rowconfigure(3,weight=1)
        ttk.Label(main,text=APP_NAME,font=("Segoe UI",20,"bold")).grid(row=0,column=0,sticky="w")
        ttk.Label(main,text="Protected apps stay registered. Unlock applies only until that app fully closes.",wraplength=840).grid(row=1,column=0,sticky="w",pady=(2,14))
        bar=ttk.Frame(main); bar.grid(row=2,column=0,sticky="ew",pady=(0,8))
        ttk.Button(bar,text="Add Running App",command=self.add_running).pack(side="left")
        ttk.Button(bar,text="Browse EXE...",command=self.browse).pack(side="left",padx=(8,0))
        ttk.Button(bar,text="Remove Selected",command=self.remove).pack(side="left",padx=(8,0))
        ttk.Button(bar,text="Settings",command=self.open_settings).pack(side="right")
        ttk.Button(bar,text="Diagnostics",command=self.diagnostics).pack(side="right",padx=(0,8))
        box=ttk.LabelFrame(main,text="Protected applications",padding=8); box.grid(row=3,column=0,sticky="nsew"); box.columnconfigure(0,weight=1); box.rowconfigure(0,weight=1)
        self.tree=ttk.Treeview(box,columns=("name","state","running","path"),show="headings",selectmode="browse"); self.tree.grid(row=0,column=0,sticky="nsew")
        for col,title,width in (("name","Executable",150),("state","Protection",110),("running","Running",90),("path","Executable Path",500)):
            self.tree.heading(col,text=title); self.tree.column(col,width=width,anchor="center" if col in ("state","running") else "w")
        sc=ttk.Scrollbar(box,orient="vertical",command=self.tree.yview); sc.grid(row=0,column=1,sticky="ns"); self.tree.configure(yscrollcommand=sc.set)
        acts=ttk.Frame(main); acts.grid(row=4,column=0,sticky="ew",pady=(14,8))
        ttk.Button(acts,text="Set / Change PIN",command=self.set_pin).pack(side="left")
        ttk.Button(acts,text="Lock Selected App",command=self.lock_selected).pack(side="right")
        ttk.Button(acts,text="Lock All Now",command=self.lock_all).pack(side="right",padx=(0,8))
        ttk.Checkbutton(main,text="Start Window Guard with Windows",variable=self.startup_var,command=self.toggle_startup).grid(row=5,column=0,sticky="w",pady=(2,8))
        ttk.Separator(main).grid(row=6,column=0,sticky="ew",pady=(4,10)); ttk.Label(main,textvariable=self.status,wraplength=840).grid(row=7,column=0,sticky="w")
        ttk.Label(main,text="When an Unlocked app fully closes, it automatically returns to Locked for its next launch.",wraplength=840).grid(row=8,column=0,sticky="w",pady=(8,0))

    def refresh(self):
        selected=self.tree.selection(); idx=None
        if selected:
            try: idx=int(selected[0].split("_",1)[1])
            except: pass
        for x in self.tree.get_children(): self.tree.delete(x)
        procs=processes()
        for i,a in enumerate(self.apps()):
            aid=str(a["id"]); running="Yes" if target_pids(a,procs) else "No"; state="Unlocked" if aid in self.unlocked else "Locked"
            self.tree.insert("","end",iid=f"app_{i}",values=(a["name"],state,running,a["path"]))
        if idx is not None and self.tree.exists(f"app_{idx}"): self.tree.selection_set(f"app_{idx}")

    def selected_app(self):
        s=self.tree.selection()
        if not s: return None
        try: i=int(s[0].split("_",1)[1]); return self.apps()[i]
        except: return None

    def duplicate(self,name,path):
        for a in self.apps():
            try:
                if path and a.get("path") and norm(path)==norm(a["path"]): return True
            except: pass
        return False

    def add_app(self,name,path):
        if self.duplicate(name,path): messagebox.showinfo(APP_NAME,"That application is already protected.",parent=self.root); return
        self.apps().append({"id":uuid.uuid4().hex[:16],"name":name,"path":path,"relock_on_close":True}); save_config(self.cfg); self.status.set(f"Added {name}. It is Locked by default."); self.refresh()

    def add_running(self):
        win=new_window(self.root); win.title("Select Running Application"); win.geometry("1000x570"); win.transient(self.root)
        f=ttk.Frame(win,padding=12); f.pack(fill="both",expand=True); f.rowconfigure(2,weight=1); f.columnconfigure(0,weight=1)
        ttk.Label(f,text="Select Running Application",font=("Segoe UI",16,"bold")).grid(row=0,column=0,sticky="w")
        ttk.Label(f,text="Choose the real visible application executable. Window Guard will remember it after it closes.").grid(row=1,column=0,sticky="w",pady=(4,10))
        tree=ttk.Treeview(f,columns=("title","exe","pid","path"),show="headings"); tree.grid(row=2,column=0,sticky="nsew")
        for c,t,w in (("title","Window Title",320),("exe","Executable",140),("pid","PID",80),("path","Executable Path",420)):
            tree.heading(c,text=t); tree.column(c,width=w)
        items={}; status=tk.StringVar(); bottom=ttk.Frame(f); bottom.grid(row=3,column=0,sticky="ew",pady=(10,0)); ttk.Label(bottom,textvariable=status).pack(side="left")
        def refill():
            for x in tree.get_children(): tree.delete(x)
            items.clear(); data=visible_apps()
            for i,a in enumerate(data):
                iid=f"run_{i}"; items[iid]=a; tree.insert("","end",iid=iid,values=(a["title"],a["name"],a["pid"],a["path"] or "(path unavailable)"))
            status.set(f"{len(data)} visible window(s) found.")
        def choose():
            s=tree.selection()
            if not s: return messagebox.showwarning(APP_NAME,"Select an application first.",parent=win)
            a=items.get(s[0]); path=a.get("path","") if a else ""
            if not a or not path: return messagebox.showerror(APP_NAME,"Executable path unavailable. Try Browse EXE or run Window Guard as administrator.",parent=win)
            try:
                if norm(path)==own_path(): return messagebox.showerror(APP_NAME,"Window Guard cannot protect itself.",parent=win)
            except: pass
            self.add_app(a["name"],path); win.destroy()
        ttk.Button(bottom,text="Refresh",command=refill).pack(side="right",padx=(8,0)); ttk.Button(bottom,text="Add Selected App",command=choose).pack(side="right")
        tree.bind("<Double-1>",lambda e:choose()); refill()

    def browse(self):
        p=filedialog.askopenfilename(title="Select an application",filetypes=[("Windows applications","*.exe"),("All files","*.*")])
        if not p: return
        try:
            if norm(p)==own_path(): return messagebox.showerror(APP_NAME,"Window Guard cannot protect itself.",parent=self.root)
        except: pass
        self.add_app(Path(p).name,p)

    def remove(self):
        app = self.selected_app()
        if not app:
            messagebox.showwarning(APP_NAME, "Select a protected application first.", parent=self.root)
            return
        if self.settings().get("confirm_remove", True):
            confirm = messagebox.askyesno(
                APP_NAME,
                f"Remove protection for {app['name']}?\nThis app will no longer ask for your PIN.",
                parent=self.root,
            )
            if not confirm:
                return
        aid = str(app["id"])
        self.unlocked.discard(aid)
        for hwnd in self.hidden.pop(aid, set()):
            show(hwnd)
        self.queue = [item for item in self.queue if item != aid]
        self.cfg["protected_apps"] = [x for x in self.apps() if x.get("id") != aid]
        save_config(self.cfg)
        if self.current == aid:
            self.finish_prompt()
        self.status.set(f"Removed protection from {app['name']}.")
        self.refresh()

    def set_pin(self):
        old=self.cfg.get("pin")
        if old:
            cur=simpledialog.askstring(APP_NAME,"Enter the current PIN:",show="*",parent=self.root)
            if cur is None: return
            if not check_pin(cur,old): return messagebox.showerror(APP_NAME,"The current PIN is incorrect.",parent=self.root)
        pin=simpledialog.askstring(APP_NAME,"Enter a new PIN (4 to 12 digits):",show="*",parent=self.root)
        if pin is None: return
        if not pin.isdigit() or not 4<=len(pin)<=12: return messagebox.showerror(APP_NAME,"PIN must contain 4 to 12 digits.",parent=self.root)
        again=simpledialog.askstring(APP_NAME,"Enter the new PIN again:",show="*",parent=self.root)
        if again is None: return
        if pin!=again: return messagebox.showerror(APP_NAME,"The PINs do not match.",parent=self.root)
        self.cfg["pin"]=make_pin(pin); save_config(self.cfg); self.status.set("PIN saved."); messagebox.showinfo(APP_NAME,"The PIN has been saved.",parent=self.root)

    def lock_one(self,a,prompt=True):
        if not self.cfg.get("pin"): return messagebox.showerror(APP_NAME,"Set a PIN first.",parent=self.root)
        aid=str(a["id"]); self.unlocked.discard(aid); h=self.hidden.setdefault(aid,set()); procs=processes()
        for hwnd in app_windows(a,True,procs):
            if hide(hwnd): h.add(hwnd)
        if h and prompt: self.enqueue(aid)
        self.status.set(f"{a['name']} is Locked."); self.refresh()

    def lock_selected(self):
        a=self.selected_app()
        if not a: return messagebox.showwarning(APP_NAME,"Select a protected application first.",parent=self.root)
        self.lock_one(a)

    def lock_all(self):
        if not self.cfg.get("pin"): return messagebox.showerror(APP_NAME,"Set a PIN first.",parent=self.root)
        self.unlocked.clear(); procs=processes()
        for a in self.apps():
            aid=str(a["id"]); h=self.hidden.setdefault(aid,set())
            for hwnd in app_windows(a,True,procs):
                if hide(hwnd): h.add(hwnd)
            if h: self.enqueue(aid,False)
        self.show_next(); self.status.set("All protected applications are Locked."); self.refresh()

    def enqueue(self,aid,show_now=True):
        if aid in self.unlocked or aid==self.current: return
        if aid not in self.queue: self.queue.append(aid)
        if show_now: self.show_next()

    def show_next(self):
        if self.current is not None: return
        while self.queue:
            aid=self.queue.pop(0); a=self.by_id(aid)
            if not a or aid in self.unlocked: continue
            if not target_pids(a) and not self.hidden.get(aid): continue
            self.current=aid; self.failed=0; self.cooldown_until=0; self.lock_text.set(f"{a['name']} is protected. Enter your PIN to unlock it."); self.make_lock_window(a); return

    def make_lock_window(self,a):
        if self.lock_win and self.lock_win.winfo_exists(): self.lock_win.lift(); return
        w=new_window(self.root); self.lock_win=w; w.title(f"{APP_NAME} - {a['name']}"); w.geometry("480x290"); w.resizable(False,False); w.attributes("-topmost",True); w.protocol("WM_DELETE_WINDOW",self.refuse_close)
        f=ttk.Frame(w,padding=24); f.pack(fill="both",expand=True); ttk.Label(f,text=APP_NAME,font=("Segoe UI",18,"bold")).pack(); ttk.Label(f,text=f"{a['name']} is locked.",font=("Segoe UI",11)).pack(pady=(8,12)); ttk.Label(f,textvariable=self.lock_text,wraplength=420,justify="center").pack()
        self.pin_entry=ttk.Entry(f,show="*",justify="center",font=("Segoe UI",14)); self.pin_entry.pack(fill="x",pady=12); self.pin_entry.bind("<Return>",lambda e:self.try_unlock()); self.unlock_btn=ttk.Button(f,text="Unlock",command=self.try_unlock); self.unlock_btn.pack(); self.pin_entry.focus_force()

    def refuse_close(self):
        if self.lock_win: self.lock_win.bell(); self.lock_win.lift()
        self.lock_text.set("Enter the PIN to unlock this application.")

    def try_unlock(self):
        if self.current is None or self.pin_entry is None: return
        remain=int(self.cooldown_until-time.time())
        if remain>0: self.lock_text.set(f"Too many attempts. Try again in {remain+1} seconds."); return
        entered=self.pin_entry.get(); self.pin_entry.delete(0,"end")
        if check_pin(entered,self.cfg.get("pin")): return self.unlock_current()
        self.failed+=1; left=FAILED_LIMIT-self.failed
        if left>0: self.lock_text.set(f"Incorrect PIN. {left} attempt(s) remaining."); return
        self.failed=0; self.cooldown_until=time.time()+COOLDOWN_SECONDS; self.cooldown_tick()

    def cooldown_tick(self):
        if self.pin_entry is None: return
        remain=int(self.cooldown_until-time.time())
        if remain<=0:
            self.pin_entry.configure(state="normal"); self.unlock_btn.configure(state="normal"); self.lock_text.set("You can try again."); self.pin_entry.focus_force(); return
        self.pin_entry.configure(state="disabled"); self.unlock_btn.configure(state="disabled"); self.lock_text.set(f"Too many attempts. Try again in {remain+1} seconds."); self.root.after(250,self.cooldown_tick)

    def unlock_current(self):
        aid=self.current; a=self.by_id(aid)
        if not a: return self.finish_prompt()
        first=None
        for hwnd in list(self.hidden.get(aid,set())):
            if show(hwnd) and first is None: first=hwnd
        self.hidden[aid]=set(); self.unlocked.add(aid); self.status.set(f"{a['name']} is Unlocked for this running session."); self.finish_prompt(); self.refresh()
        if first and user32.IsWindow(first): user32.SetForegroundWindow(first)

    def finish_prompt(self):
        if self.lock_win and self.lock_win.winfo_exists(): self.lock_win.attributes("-topmost",False); self.lock_win.destroy()
        self.lock_win=self.pin_entry=self.unlock_btn=None; self.current=None; self.root.after(100,self.show_next)

    def monitor(self):
        if self._closing:
            return
        # Until a PIN is configured, do not hide windows with no way to unlock them.
        if not self.cfg.get("pin"):
            self.root.after(self.settings()["monitor_ms"], self.monitor)
            return
        procs=processes(); changed=False
        for a in self.apps():
            aid=str(a["id"]); now=target_pids(a,procs); before=self.last_pids.get(aid,set())
            if aid in self.unlocked and before and not now:
                self.unlocked.discard(aid); self.hidden[aid]=set(); self.status.set(f"{a['name']} closed and was automatically relocked."); changed=True
            self.last_pids[aid]=set(now)
            if not now and aid in self.hidden:
                self.hidden[aid] = {h for h in self.hidden[aid] if user32.IsWindow(h)}
                if self.current == aid and not self.hidden[aid]:
                    self.finish_prompt()
            if aid not in self.unlocked and now:
                h=self.hidden.setdefault(aid,set())
                for hwnd in app_windows(a,True,procs):
                    if hide(hwnd): h.add(hwnd)
                h.difference_update({x for x in h if not user32.IsWindow(x)})
                if h: self.enqueue(aid)
        if changed: self.refresh()
        # Avoid rebuilding the Treeview on every monitoring tick.
        if changed or time.monotonic() - self._last_refresh > 1.0:
            self.refresh()
            self._last_refresh = time.monotonic()
        if self.lock_win and self.lock_win.winfo_exists():
            self.lock_win.attributes("-topmost", True)
        self.root.after(self.settings()["monitor_ms"], self.monitor)

    def open_settings(self):
        if self._settings_win and self._settings_win.winfo_exists():
            self._settings_win.lift()
            self._settings_win.focus_force()
            return
        win = new_window(self.root)
        self._settings_win = win
        win.title("Window Guard - Settings")
        win.geometry("575x465")
        win.minsize(525, 445)
        win.transient(self.root)
        win.protocol("WM_DELETE_WINDOW", win.destroy)

        frame = ttk.Frame(win, padding=22)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Settings", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(frame, text="These preferences are saved for future sessions.").pack(anchor="w", pady=(2, 16))

        opts = self.settings()
        start_var = tk.BooleanVar(value=startup_exists())
        tray_var = tk.BooleanVar(value=opts["close_to_tray"])
        start_hidden_var = tk.BooleanVar(value=opts["start_hidden_at_startup"])
        remove_var = tk.BooleanVar(value=opts["confirm_remove"])
        hotkey_var = tk.BooleanVar(value=opts["enable_global_hotkey"])
        interval_var = tk.StringVar(value=str(opts["monitor_ms"]))

        for title, var in (
            ("Start Window Guard with Windows", start_var),
            ("Close main window to the system tray", tray_var),
            ("Start hidden when launched by Windows startup", start_hidden_var),
            ("Confirm before removing a protected application", remove_var),
            ("Enable global shortcut Ctrl+Shift+L (Lock All)", hotkey_var),
        ):
            ttk.Checkbutton(frame, text=title, variable=var).pack(anchor="w", pady=5)

        interval_row = ttk.Frame(frame)
        interval_row.pack(anchor="w", fill="x", pady=(15, 4))
        ttk.Label(interval_row, text="Monitoring interval:").pack(side="left", padx=(0, 12))
        interval_box = ttk.Combobox(
            interval_row, textvariable=interval_var, state="readonly",
            values=("250", "350", "500", "1000"), width=9,
        )
        interval_box.pack(side="left")
        ttk.Label(interval_row, text="milliseconds").pack(side="left", padx=8)
        ttk.Label(
            frame,
            text="Shorter intervals check more often but consume more CPU. 350 ms is recommended.",
            wraplength=500,
        ).pack(anchor="w", pady=(4, 18))

        def save_settings():
            enable_startup = bool(start_var.get())
            try:
                set_startup(enable_startup)
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"Could not change Windows startup.\n\n{exc}", parent=win)
                return
            new_opts = clean_settings({
                "close_to_tray": tray_var.get(),
                "start_hidden_at_startup": start_hidden_var.get(),
                "confirm_remove": remove_var.get(),
                "enable_global_hotkey": hotkey_var.get(),
                "monitor_ms": interval_var.get(),
            })
            previous_hotkey = bool(self.settings().get("enable_global_hotkey"))
            self.cfg["settings"] = new_opts
            self.cfg["start_with_windows"] = enable_startup
            self.startup_var.set(enable_startup)
            save_config(self.cfg)
            if previous_hotkey != new_opts["enable_global_hotkey"]:
                self.update_global_hotkey()
            self.status.set("Settings saved.")
            win.destroy()
            self._settings_win = None

        buttons = ttk.Frame(frame)
        buttons.pack(side="bottom", anchor="e", fill="x")
        ttk.Button(buttons, text="Save", command=save_settings).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right", padx=(0, 10))

    def toggle_startup(self):
        enabled=bool(self.startup_var.get())
        try: set_startup(enabled)
        except OSError as e: self.startup_var.set(startup_exists()); return messagebox.showerror(APP_NAME,f"Could not change startup setting.\n\n{e}",parent=self.root)
        self.cfg["start_with_windows"]=enabled; save_config(self.cfg); self.status.set("Start with Windows enabled." if enabled else "Start with Windows disabled.")

    def open_config_folder(self):
        try:
            APPDATA.mkdir(parents=True, exist_ok=True)
            os.startfile(str(APPDATA))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not open the configuration folder.\n\n{exc}", parent=self.root)

    def open_program_folder(self):
        try:
            os.startfile(str(program_dir()))
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not open the application folder.\n\n{exc}", parent=self.root)

    def open_github_repository(self):
        open_web_url(GITHUB_REPO_URL, self.root, "GitHub repository")

    def open_github_latest_release(self):
        open_web_url(GITHUB_LATEST_RELEASE_URL, self.root, "latest GitHub release")

    def check_for_updates(self):
        self.status.set("Opening GitHub Releases to check for newer versions.")
        open_web_url(GITHUB_RELEASES_URL, self.root, "GitHub releases page")

    def open_github_releases(self):
        open_web_url(GITHUB_RELEASES_URL, self.root, "GitHub releases page")

    def open_github_new_issue(self):
        open_web_url(GITHUB_NEW_ISSUE_URL, self.root, "GitHub issue form")

    def open_github_issues(self):
        open_web_url(GITHUB_ISSUES_URL, self.root, "GitHub issues page")

    def copy_github_url(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(GITHUB_REPO_URL)
        self.status.set("GitHub repository URL copied to the clipboard.")

    def open_help_html(self):
        open_local_document("WindowGuard_Help.html", self.root)

    def open_help_pdf(self):
        open_local_document("WindowGuard_Help.pdf", self.root)

    def about(self):
        win = new_window(self.root)
        win.title(f"About {APP_NAME}")
        win.geometry("565x550")
        win.resizable(False, False)
        win.transient(self.root)

        frame = ttk.Frame(win, padding=22)
        frame.pack(fill="both", expand=True)
        try:
            full_icon = tk.PhotoImage(file=str(resource_path("assets/window_guard_icon.png")))
            small_icon = full_icon.subsample(14, 14)
            win._wg_icon_image = small_icon
            ttk.Label(frame, image=small_icon).pack(pady=(0, 6))
        except tk.TclError:
            pass

        ttk.Label(frame, text=APP_NAME, font=("Segoe UI", 19, "bold")).pack()
        ttk.Label(frame, text=f"Version {APP_VERSION}").pack(pady=(1, 10))
        ttk.Label(
            frame,
            text="Lock selected Windows programs with a PIN. Each app relocks when it closes.",
            wraplength=490, justify="center",
        ).pack(pady=(0, 13))
        ttk.Label(frame, text="Giorgos Xanthopoulos aka gexos", font=("Segoe UI", 10, "bold")).pack()
        ttk.Label(frame, text="MIT License").pack(pady=(5, 0))
        ttk.Label(frame, text="github.com/gexos/window-guard").pack(pady=(5, 0))
        ttk.Label(
            frame,
            text="Window Guard hides app windows. It does not replace Windows account security.",
            wraplength=490, justify="center",
        ).pack(pady=(14, 12))
        row = ttk.Frame(frame)
        row.pack(pady=6)
        ttk.Button(row, text="GitHub", command=self.open_github_repository).pack(side="left", padx=4)
        ttk.Button(row, text="Open Help", command=self.open_help_html).pack(side="left", padx=4)
        ttk.Button(row, text="Close", command=win.destroy).pack(side="left", padx=4)

    def make_diagnostics_report(self):
        procs = processes()
        lines = [
            f"{APP_NAME} {APP_VERSION} diagnostic report", "",
            f"Unlocked runtime IDs: {sorted(self.unlocked)}", "",
        ]
        all_pids = set()
        for i, app in enumerate(self.apps(), 1):
            pids = target_pids(app, procs)
            all_pids.update(pids)
            state = "Unlocked" if str(app["id"]) in self.unlocked else "Locked"
            lines += [
                f"[{i}] {app['name']}", f"State: {state}", f"Path: {app['path']}",
                f"Matched PIDs: {sorted(pids) or '(none)'}", "",
            ]
        lines += ["VISIBLE WINDOWS", "-" * 70]

        @WNDENUMPROC
        def callback(hwnd, _):
            if user32.IsWindow(hwnd) and user32.IsWindowVisible(hwnd):
                title = window_title(hwnd).strip()
                pid = window_pid(hwnd)
                if title:
                    exe_name = procs.get(pid, {}).get("name", "?")
                    tag = " <== PROTECTED" if pid in all_pids else ""
                    lines.append(
                        f"PID={pid} | EXE={exe_name} | HWND={int(hwnd)} | TITLE={title}{tag}"
                    )
            return True

        user32.EnumWindows(callback, 0)
        return "\n".join(lines)

    def export_diagnostics(self, report=None):
        if report is None:
            report = self.make_diagnostics_report()
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export Window Guard Diagnostics",
            defaultextension=".txt",
            initialfile=f"WindowGuard_Diagnostics_v{APP_VERSION}.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not destination:
            return
        try:
            Path(destination).write_text(report, encoding="utf-8")
            self.status.set(f"Diagnostic report saved: {destination}")
            messagebox.showinfo(APP_NAME, "Diagnostic report saved.", parent=self.root)
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not save the report.\n\n{exc}", parent=self.root)

    def diagnostics(self):
        report = self.make_diagnostics_report()
        win = new_window(self.root)
        win.title(f"{APP_NAME} Diagnostics")
        win.geometry("980x600")
        frame = ttk.Frame(win, padding=10)
        frame.pack(fill="both", expand=True)
        text = tk.Text(frame, wrap="none", font=("Consolas", 10))
        text.pack(fill="both", expand=True)
        text.insert("1.0", report)
        text.configure(state="disabled")
        buttons = ttk.Frame(frame)
        buttons.pack(pady=(8, 0))

        def copy_report():
            win.clipboard_clear()
            win.clipboard_append(report)
            self.status.set("Diagnostic report copied.")

        ttk.Button(buttons, text="Copy Report", command=copy_report).pack(side="left", padx=4)
        ttk.Button(buttons, text="Save to TXT...", command=lambda: self.export_diagnostics(report)).pack(side="left", padx=4)
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="left", padx=4)

    def start_tray(self):
        if pystray is None: return
        menu=pystray.Menu(pystray.MenuItem("Show Window Guard",lambda i,x:self.root.after(0,self.show_main),default=True),pystray.MenuItem("Lock All Now",lambda i,x:self.root.after(0,self.lock_all)),pystray.Menu.SEPARATOR,pystray.MenuItem("Exit",lambda i,x:self.root.after(0,self.exit_app)))
        self.tray=pystray.Icon("WindowGuard",tray_image(),APP_NAME,menu); threading.Thread(target=self.tray.run,daemon=True).start()

    def show_main(self): self.root.deiconify(); self.root.lift()
    def hide_to_tray(self): self.root.withdraw() if pystray is not None else self.exit_app()
    def exit_app(self):
        if self._closing:
            return
        self._closing = True
        self.hotkey.stop()
        for handles in self.hidden.values():
            for hwnd in list(handles): show(hwnd)
        if self.tray:
            try: self.tray.stop()
            except: pass
        self.root.destroy()

def main():
    if pystray is None or Image is None:
        r=tk.Tk(); r.withdraw(); messagebox.showerror(APP_NAME,"Install required packages:\n\npython -m pip install pystray pillow"); r.destroy(); return
    r=tk.Tk()
    icon_file = resource_path("assets/window_guard.ico")
    if icon_file.is_file():
        try:
            r.iconbitmap(default=str(icon_file))
        except tk.TclError:
            pass
    png_icon = resource_path("assets/window_guard_icon.png")
    if png_icon.is_file():
        try:
            r._wg_iconphoto = tk.PhotoImage(file=str(png_icon))
            r.iconphoto(True, r._wg_iconphoto)
        except tk.TclError:
            pass
    try:
        style=ttk.Style(r)
        if "vista" in style.theme_names(): style.theme_use("vista")
    except tk.TclError: pass
    WindowGuard(r,start_hidden="--startup" in sys.argv); r.mainloop()

if __name__ == "__main__": main()
