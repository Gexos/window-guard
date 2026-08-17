# Window Guard

**Window Guard** is an open-source Windows privacy utility that lets you protect selected desktop applications with a PIN.

It can hide protected application windows, keep watching for newly opened protected windows while locked, restore them after PIN verification, run from the Windows system tray, and optionally start with Windows.

> **Current release:** v0.3.0 — Early Preview

## Features

- Protect multiple Windows applications
- Select the real running application from a visible-window list
- Manual `.exe` selection when needed
- Lock all protected applications with **Lock Now**
- Automatically hide protected windows opened while Window Guard is locked
- Restore hidden windows after the correct PIN is entered
- System tray support
- Start with Windows option
- Failed-PIN cooldown after repeated incorrect attempts
- Salted PBKDF2-HMAC-SHA256 PIN hashing
- Diagnostics window for troubleshooting
- Portable single-EXE build with PyInstaller

## Requirements

For running from Python:

- Windows 10 or Windows 11
- Python 3.10 or newer
- `pystray`
- `Pillow`

Install the runtime dependencies:

```bat
python -m pip install -r requirements.txt
```

## Running from Source

```bat
python window_guard.py
```

Or double-click:

```text
run_window_guard.bat
```

## First Use

1. Open the application you want to protect.
2. Start Window Guard.
3. Click **Add Running App**.
4. Select the visible application window.
5. Confirm that the executable shown is the real application executable.
6. Add more applications if desired.
7. Click **Set / Change PIN**.
8. Create a PIN containing 4 to 12 digits.
9. Click **Lock Now**.
10. Enter the correct PIN to restore the protected windows.

### Firefox Portable

Portable launchers can be misleading because the launcher may not own the visible application window.

For Firefox Portable, use **Add Running App** and select the row whose executable is:

```text
firefox.exe
```

## System Tray

Closing the main Window Guard window minimizes it to the Windows system tray.

The tray menu provides:

- **Show Window Guard**
- **Lock Now**
- **Exit**

Window Guard refuses to exit normally while it is locked.

## Start with Windows

Enable:

```text
Start Window Guard with Windows
```

Window Guard creates a per-user startup entry under:

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

When Windows launches Window Guard at startup, the main window starts hidden in the tray.

## Building WindowGuard.exe

Install the build dependencies:

```bat
python -m pip install -r requirements-build.txt
```

Then build:

```bat
python -m PyInstaller --noconfirm --clean --onefile --windowed --name WindowGuard window_guard.py
```

Or double-click:

```text
build_window_guard.bat
```

The finished executable will be created at:

```text
dist\WindowGuard.exe
```

## Release Hash

After building the EXE, run:

```text
hash_release.bat
```

This creates `SHA256SUMS.txt` containing the SHA-256 hash of `dist\WindowGuard.exe`.

## Configuration

Window Guard stores its configuration under:

```text
%APPDATA%\WindowGuard\config.json
```

The PIN itself is not stored in plain text. Window Guard stores a salt and a PBKDF2-derived hash.

## Security Model and Limitations

Window Guard is a **privacy and convenience lock**, not a replacement for Windows account security.

A user with sufficient access to the computer may still be able to bypass Window Guard by:

- Ending `WindowGuard.exe` in Task Manager
- Deleting or modifying its configuration
- Restarting protected applications in another context
- Using another Windows account
- Using administrative or debugging tools

For actual workstation security, use Windows account protection and lock the workstation with `Windows + L`.

These limitations are intentional and documented. Window Guard does not claim to provide tamper-resistant or administrator-proof application isolation.

## Antivirus / False Positives

Window Guard can be packaged as a standalone executable with PyInstaller. Some antivirus engines may occasionally flag PyInstaller-generated executables even when the underlying source code is legitimate.

The complete source code is available in this repository so users can inspect the program and build it themselves.

If you distribute a release build, publish its SHA-256 hash alongside the download.

## Project Status

Window Guard is under active development. v0.3.0 should be treated as an early preview.

Bug reports, testing, code review, and improvement suggestions are welcome.

## Screenshots

Screenshots will be added as the interface is finalized.

## License

Window Guard is released under the [MIT License](LICENSE).

## Author

gexos
