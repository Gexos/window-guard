# Window Guard

**Window Guard** is an open-source Windows privacy utility that protects selected desktop applications with a PIN.

Protected applications remain registered after they close. When an unlocked application fully exits, Window Guard automatically returns it to **Locked**, so the next launch requires the PIN again.

> Current development release: **v0.5.0**

## Highlights

- Persistent per-application protection
- Independent **Locked / Unlocked** state for each protected app
- Automatic relock when an unlocked app closes
- Select the real application from currently visible windows
- Protect multiple applications with one PIN
- System tray support
- Optional Start with Windows
- Diagnostics for application/process detection
- Complete HTML and PDF help manual
- Direct GitHub menu for repository, releases, issues, and bug reports
- Open source under the MIT License

## Quick Start

1. Open the application you want to protect.
2. Start Window Guard.
3. Click **Add Running App**.
4. Select the real application executable from the list.
5. Click **Set / Change PIN**.
6. Enter the PIN when Window Guard hides the protected app.
7. Close the protected app completely.
8. The application automatically returns to **Locked** for its next launch.

## Menu Bar

Window Guard v0.5.0 adds a more complete menu system:

- **File** - Lock All Now, Hide to Tray, Exit
- **Applications** - Add Running App, Browse EXE, Lock Selected, Remove Selected
- **Tools** - PIN management, Diagnostics, configuration/application folders, Start with Windows
- **GitHub** - Repository, Latest Release, Releases, Issues, Report Bug / Request Feature
- **Help** - HTML help, PDF manual, About Window Guard

## Firefox Portable

For Firefox Portable, protect the real browser process shown by **Add Running App**:

```text
firefox.exe
```

Do not rely on `FirefoxPortable.exe` if the visible Firefox window belongs to `firefox.exe`.

## Requirements

### Standalone EXE

- Windows 10 or Windows 11
- No Python installation required

### Running from source

- Python 3.10+
- pystray
- Pillow

```bat
python -m pip install -r requirements.txt
python window_guard.py
```

## Building the EXE

```bat
python -m pip install -r requirements-build.txt
python -m PyInstaller --noconfirm --clean --onefile --windowed --name WindowGuard window_guard.py
```

Or run:

```text
build_window_guard.bat
```

The build script also copies the HTML and PDF help files into `dist`.

## Configuration

Window Guard stores user configuration at:

```text
%APPDATA%\WindowGuard\config.json
```

The PIN is not stored in plain text. Window Guard stores a random salt and a PBKDF2-HMAC-SHA256 derived hash.

Do not commit your personal `config.json` to GitHub.

## Security Model

Window Guard is a **privacy and convenience lock**, not an operating-system security boundary.

A user with enough access may bypass it by terminating Window Guard, deleting or modifying its configuration, using another Windows account, or using administrative/debugging tools.

For genuine workstation security, use a Windows account password/PIN and `Windows + L`.

## Antivirus / False Positives

The standalone EXE is built with PyInstaller. Some antivirus engines occasionally flag PyInstaller-packaged executables. The full source is published so users can inspect and build Window Guard themselves.

Official binary releases should include a SHA-256 hash.

## Documentation

- `WindowGuard_Help.html`
- `WindowGuard_Help.pdf`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`

## Author

**Giorgos Xanthopoulos**  
**aka gexos**

## License

Window Guard is released under the [MIT License](LICENSE).
