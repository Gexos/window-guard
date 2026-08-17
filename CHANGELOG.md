# Changelog

## [0.3.0] - 2026-08-16

### Added
- Multiple protected applications
- Windows system tray icon
- Tray actions: Show Window Guard, Lock Now, Exit
- Start with Windows option
- Continuous lock monitoring
- Automatic hiding of protected windows opened while locked
- Migration from older single-application configuration
- Exit protection while Window Guard is locked

### Kept
- Select Running App workflow
- Manual `.exe` selection
- PIN creation and change
- PBKDF2-HMAC-SHA256 PIN hashing
- Failed-attempt cooldown
- Diagnostics window
- Portable PyInstaller build support

## [0.2.0]

### Added
- Select Running App
- Visible-window list showing title, executable, PID, and path
- Double-click application selection
- Refresh button

## [0.1.3]

### Changed
- Improved portable-launcher handling

## [0.1.2]

### Added
- Diagnostics report
- Native Windows process enumeration

## [0.1.1]

### Fixed
- Improved executable matching

## [0.1.0]

### Added
- Initial prototype
- Single protected application
- PIN lock/unlock
- Window hide/restore
