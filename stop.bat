@echo off
REM Zscaler Assessment - stop server
echo Stopping Zscaler Assessment server...
taskkill /fi "WindowTitle eq Zscaler Assessment Server*" /f >nul 2>&1
if errorlevel 1 (
  echo No server window found. If running directly, press Ctrl+C in that window.
) else (
  echo Server stopped.
)
