@echo off
cd /d "%~dp0"
if not exist "dist\WindowGuard.exe" (
    echo Build WindowGuard.exe first.
    pause
    exit /b 1
)
certutil -hashfile "dist\WindowGuard.exe" SHA256 > SHA256SUMS.txt
type SHA256SUMS.txt
pause
