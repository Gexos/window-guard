@echo off
setlocal
cd /d "%~dp0"
title Build Window Guard v0.6.1

for %%F in ("assets\window_guard.ico" "assets\window_guard_icon.png" "assets\tray_icon_32.png") do (
  if not exist %%F (
    echo ERROR: %%F is missing.
    pause
    exit /b 1
  )
)

python -m pip install --upgrade -r requirements-build.txt
if errorlevel 1 goto :failed

python -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --name WindowGuard ^
  --icon "assets\window_guard.ico" ^
  --add-data "assets\window_guard.ico:assets" ^
  --add-data "assets\window_guard_icon.png:assets" ^
  --add-data "assets\tray_icon_32.png:assets" ^
  window_guard.py
if errorlevel 1 goto :failed

copy /Y "WindowGuard_Help.html" "dist\WindowGuard_Help.html" >nul
if errorlevel 1 goto :failed
copy /Y "WindowGuard_Help.pdf" "dist\WindowGuard_Help.pdf" >nul
if errorlevel 1 goto :failed

if exist "README.md" copy /Y "README.md" "dist\README.md" >nul
if exist "LICENSE" copy /Y "LICENSE" "dist\LICENSE" >nul

echo.
echo Build completed: dist\WindowGuard.exe
echo.
pause
exit /b 0

:failed
echo.
echo Build failed. Review the errors above.
pause
exit /b 1
