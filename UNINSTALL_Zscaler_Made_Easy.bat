@echo off
REM ====================================================================
REM  Zscaler Made Easy - UNINSTALL
REM  Removes desktop/start menu shortcuts and stops the background service
REM ====================================================================

echo.
echo  Uninstalling Zscaler Made Easy...
echo.

REM Stop the running server the way STOP_Zscaler_Made_Easy.bat does:
REM whatever listens on the app's port. (The server runs as python.exe
REM under a hidden window titled "Zscaler Made Easy", so neither
REM an image-name kill of pythonw.exe nor a window-title match finds it.)
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"
if not defined ZSCALER_PORT set ZSCALER_PORT=8000
echo  [1/3] Stopping the server (whatever listens on port %ZSCALER_PORT%)...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /C:":%ZSCALER_PORT% " ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>&1
    echo        Stopped PID %%a
)

REM Remove the desktop shortcut, under its name and the name shortcuts had
REM before the rename to Zscaler Made Easy.
echo  [2/3] Removing desktop shortcut...
powershell -NoProfile -Command ^
  "$desktop = [Environment]::GetFolderPath('Desktop');" ^
  "foreach ($name in 'Zscaler Made Easy.lnk', 'Zscaler Assessment.lnk') { Remove-Item -LiteralPath (Join-Path $desktop $name) -ErrorAction SilentlyContinue };" >nul 2>&1

REM Remove the Start Menu shortcut, under both names.
echo  [3/3] Removing Start Menu shortcut...
powershell -NoProfile -Command ^
  "$start = [Environment]::GetFolderPath('Programs');" ^
  "foreach ($name in 'Zscaler Made Easy.lnk', 'Zscaler Assessment.lnk') { Remove-Item -LiteralPath (Join-Path $start $name) -ErrorAction SilentlyContinue };" >nul 2>&1

echo.
echo  Uninstall complete. The project files remain in this folder.
echo  To remove them entirely, delete the folder.
echo.
timeout /t 3 >nul 2>&1
exit /b 0
