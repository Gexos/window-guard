@echo off
cd /d "%~dp0"
python -c "import pystray, PIL" >nul 2>&1
if errorlevel 1 python -m pip install -r requirements.txt
python window_guard.py
if errorlevel 1 pause
