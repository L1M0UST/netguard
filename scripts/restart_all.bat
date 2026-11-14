@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart_all.ps1" %*
if errorlevel 1 (
  echo.
  echo Full system restart failed. Review the error above and the logs directory.
  pause
)
