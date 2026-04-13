@echo off
REM ════════════════════════════════════════════════════════════════════
REM  Zscaler Platform Assessment - UNINSTALL
REM  Removes desktop/start menu shortcuts and stops the background service
REM ════════════════════════════════════════════════════════════════════

echo.
echo  Uninstalling Zscaler Platform Assessment...
echo.

REM Stop any running server
echo  [1/3] Stopping background service...
taskkill /f /im pythonw.exe >nul 2>&1
taskkill /fi "WindowTitle eq Zscaler Assessment*" /f >nul 2>&1

REM Remove desktop shortcut
echo  [2/3] Removing desktop shortcut...
powershell -NoProfile -Command ^
  "$desktop = [Environment]::GetFolderPath('Desktop');" ^
  "Remove-Item -Path \"$desktop\Zscaler Assessment.lnk\" -ErrorAction SilentlyContinue;" >nul 2>&1

REM Remove Start Menu shortcut
echo  [3/3] Removing Start Menu shortcut...
powershell -NoProfile -Command ^
  "$start = [Environment]::GetFolderPath('Programs');" ^
  "Remove-Item -Path \"$start\Zscaler Assessment.lnk\" -ErrorAction SilentlyContinue;" >nul 2>&1

REM Remove launcher VBS
del /q "%~dp0zscaler_launcher.vbs" >nul 2>&1

echo.
echo  Uninstall complete. The project files remain in this folder.
echo  To remove them entirely, delete the folder.
echo.
pause
