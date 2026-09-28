# Security Policy

Window Guard is a privacy and convenience utility. It is not intended to provide tamper-resistant security against Windows administrators, users who can terminate processes, debugging tools, another Windows account, or privileged software.

Known architectural limitations include:

- Ending `WindowGuard.exe` can defeat protection.
- The local configuration can be deleted or modified by a user who controls the Windows account.
- Window Guard monitors normal desktop windows; it does not create an OS-level application sandbox.
- A protected window can briefly appear before the monitor hides it.

## Reporting a Security Problem

Use the repository's GitHub Issues only for reports that are safe to discuss publicly. Do not post passwords, PINs, private keys, personal data, or confidential window titles.

Repository: https://github.com/gexos/window-guard
