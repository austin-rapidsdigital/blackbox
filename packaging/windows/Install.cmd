@echo off
setlocal
rem Blackbox setup. Double-click to install, or to change settings later
rem (the current settings are offered as defaults).

if not exist "%~dp0blackbox.exe" (
  echo blackbox.exe was not found next to this file.
  echo Extract the whole zip to a folder first, then run Install.cmd from there.
  echo.
  pause
  exit /b 1
)

rem Ask Windows for administrator rights if we do not have them yet.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

cd /d "%~dp0"
blackbox.exe install
echo.
pause
