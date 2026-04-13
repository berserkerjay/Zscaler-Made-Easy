@echo off
REM ════════════════════════════════════════════════════════════════════
REM  Zscaler Platform Assessment - INSTALL
REM  Sets up the app to run as a true desktop app:
REM    - Creates a desktop shortcut with a custom icon
REM    - Server runs silently in the background (no console window)
REM    - Launching the shortcut opens the GUI in the default browser
REM ════════════════════════════════════════════════════════════════════

echo.
echo  Installing Zscaler Platform Assessment...
echo.

REM Get current install directory
set INSTALL_DIR=%~dp0
set INSTALL_DIR=%INSTALL_DIR:~0,-1%

REM Install Python dependencies (silently)
echo  [1/4] Installing dependencies (this may take a minute)...
python -m pip install --quiet --disable-pip-version-check fastapi uvicorn python-docx zscaler-sdk-python requests rich pydantic >nul 2>&1
if errorlevel 1 (
    echo  WARNING: Some dependencies may have failed to install.
    echo  Try running this script as Administrator.
)

REM Create the launcher VBS that runs python silently (no console window)
echo  [2/4] Creating silent launcher...
(
echo Set WshShell = CreateObject("WScript.Shell"^)
echo WshShell.CurrentDirectory = "%INSTALL_DIR%"
echo WshShell.Run "pythonw.exe dlp_api_server.py", 0, False
echo WScript.Sleep 3000
echo WshShell.Run "http://localhost:8000", 1, False
) > "%INSTALL_DIR%\zscaler_launcher.vbs"

REM Create the icon (Zscaler blue Z favicon)
echo  [3/4] Creating desktop shortcut...

REM Build the shortcut using PowerShell
powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell;" ^
  "$desktop = [Environment]::GetFolderPath('Desktop');" ^
  "$lnk = $ws.CreateShortcut(\"$desktop\Zscaler Assessment.lnk\");" ^
  "$lnk.TargetPath = 'wscript.exe';" ^
  "$lnk.Arguments = '\"%INSTALL_DIR%\zscaler_launcher.vbs\"';" ^
  "$lnk.WorkingDirectory = '%INSTALL_DIR%';" ^
  "$lnk.IconLocation = 'shell32.dll,14';" ^
  "$lnk.Description = 'Zscaler Platform Assessment - Run security configuration audits';" ^
  "$lnk.Save();"

if errorlevel 1 (
    echo  ERROR: Could not create desktop shortcut.
    echo  Closing in 5 seconds...
timeout /t 5 >nul
exit
    exit /b 1
)

REM Also create a Start Menu shortcut
echo  [4/4] Creating Start Menu shortcut...
powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell;" ^
  "$start = [Environment]::GetFolderPath('Programs');" ^
  "$lnk = $ws.CreateShortcut(\"$start\Zscaler Assessment.lnk\");" ^
  "$lnk.TargetPath = 'wscript.exe';" ^
  "$lnk.Arguments = '\"%INSTALL_DIR%\zscaler_launcher.vbs\"';" ^
  "$lnk.WorkingDirectory = '%INSTALL_DIR%';" ^
  "$lnk.IconLocation = 'shell32.dll,14';" ^
  "$lnk.Description = 'Zscaler Platform Assessment';" ^
  "$lnk.Save();" >nul 2>&1

echo.
echo  ════════════════════════════════════════════════════════════
echo   Installation complete!
echo  ════════════════════════════════════════════════════════════
echo.
echo   A "Zscaler Assessment" shortcut has been added to your
echo   Desktop and Start Menu.
echo.
echo   Double-click it to launch the app — it runs silently in
echo   the background and opens in your browser automatically.
echo.
echo   To stop the background service, run:
echo     STOP_Zscaler_Assessment.bat
echo.
echo   To uninstall, run:
echo     UNINSTALL_Zscaler_Assessment.bat
echo.
echo  Closing in 5 seconds...
timeout /t 5 >nul
exit
