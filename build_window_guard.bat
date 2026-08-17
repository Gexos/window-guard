@echo off
title Build Window Guard
cd /d "%~dp0"

echo Installing/updating build dependencies...
python -m pip install --upgrade -r requirements-build.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo Building WindowGuard.exe...
python -m PyInstaller --noconfirm --clean --onefile --windowed --name WindowGuard window_guard.py
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Build completed successfully.
echo EXE: %~dp0dist\WindowGuard.exe
pause
