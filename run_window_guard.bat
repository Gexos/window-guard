@echo off
title Run Window Guard
cd /d "%~dp0"

python -c "import pystray, PIL" >nul 2>&1
if errorlevel 1 (
    echo Installing runtime dependencies...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Dependency installation failed.
        pause
        exit /b 1
    )
)

python window_guard.py
if errorlevel 1 pause
