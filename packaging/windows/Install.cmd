@echo off
setlocal
rem Blackbox installer. Double-click to run; Windows asks for administrator approval.

net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
cd /d "%~dp0"

echo.
echo  Blackbox - audit log reports
echo  ============================
echo.
set "SITE="
set /p "SITE=Site or system name to show on reports (press Enter to skip): "
set "EVERY="
set /p "EVERY=How often to produce a report - daily, weekly or monthly (press Enter for weekly): "
if "%EVERY%"=="" set "EVERY=weekly"
echo.

blackbox.exe install --site "%SITE%" --report-every %EVERY%
echo.
pause
