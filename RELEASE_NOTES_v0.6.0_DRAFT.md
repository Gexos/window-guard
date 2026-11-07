# Window Guard v0.6.0 — Release notes (draft)

**This is a draft. Test the Windows build before publishing the release.**

## What's changed

- New icon for the EXE, app windows and tray.
- New Settings window.
- Optional **Ctrl+Shift+L** shortcut for Lock All.
- Diagnostic reports can now be saved as TXT.
- **Check for Updates** opens the GitHub Releases page.
- Updated HTML and PDF Help files.
- Updated Windows build script and GitHub Actions build workflow.
- A few fixes to the app list, PIN setup and removal prompts.

## Before releasing

Test app detection, PIN unlock, relock-on-close, Settings, global shortcut, tray, help links and the built EXE. Check Firefox Portable using the real `firefox.exe` process.

## Known limits

Window Guard can be bypassed by someone who can stop its process or edit its configuration. A protected window might appear briefly before it is hidden. The global shortcut might be unavailable if another program has registered it.

## Files to attach after testing

- `WindowGuard.exe`
- `SHA256SUMS.txt`
- `WindowGuard_Help.html`
- `WindowGuard_Help.pdf`
