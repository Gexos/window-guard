@echo off
title Build Window Guard v0.5.0
cd /d "%~dp0"

python -m pip install --upgrade -r requirements-build.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

python -m PyInstaller --noconfirm --clean --onefile --windowed --name WindowGuard window_guard.py
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

copy /Y "WindowGuard_Help.html" "dist\WindowGuard_Help.html" >nul
copy /Y "WindowGuard_Help.pdf" "dist\WindowGuard_Help.pdf" >nul

echo.
echo Build complete.
echo Release folder: %~dp0dist
echo.
pause
