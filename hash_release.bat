@echo off
title Window Guard SHA-256
cd /d "%~dp0"

if not exist "dist\WindowGuard.exe" (
    echo dist\WindowGuard.exe was not found.
    echo Build Window Guard first.
    pause
    exit /b 1
)

certutil -hashfile "dist\WindowGuard.exe" SHA256 > SHA256SUMS.txt

echo.
echo SHA-256 written to:
echo %~dp0SHA256SUMS.txt
echo.
type SHA256SUMS.txt
echo.
pause
