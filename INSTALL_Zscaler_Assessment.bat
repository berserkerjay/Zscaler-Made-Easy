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
REM First locate real Python (skip Microsoft Store stub)
set PYTHON_EXE=
for /f "delims=" %%i in ('where python 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE set "PYTHON_EXE=python"

echo  [1/4] Installing dependencies (this may take a minute)...
"%PYTHON_EXE%" -m pip install --quiet --disable-pip-version-check fastapi uvicorn python-docx zscaler-sdk-python requests rich pydantic >nul 2>&1
if errorlevel 1 (
    echo  WARNING: Some dependencies may have failed to install.
    echo  Try running this script as Administrator.
)

REM Find the real pythonw.exe (avoid the Microsoft Store stub)
echo  Locating Python installation...
set PYTHONW_PATH=
for /f "delims=" %%i in ('where pythonw 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYTHONW_PATH set "PYTHONW_PATH=%%i"
    )
)

if not defined PYTHONW_PATH (
    echo  ERROR: Could not find a real pythonw.exe installation.
    echo  Only the Microsoft Store stub was found, which won't work.
    echo.
    echo  Please install Python from https://www.python.org/downloads/
    echo  and check "Add Python to PATH" during installation.
    timeout /t 10 >nul
    exit /b 1
)

echo  Found Python at: %PYTHONW_PATH%

REM Create the launcher VBS that runs python silently (no console window)
REM This launcher polls the server until it's actually responding, then opens the browser
echo  [2/4] Creating silent launcher...
(
echo Set WshShell = CreateObject("WScript.Shell"^)
echo Set fso = CreateObject("Scripting.FileSystemObject"^)
echo WshShell.CurrentDirectory = "%INSTALL_DIR%"
echo.
echo ' Check if server is already running by trying to connect
echo Set http = CreateObject("MSXML2.ServerXMLHTTP"^)
echo http.SetTimeouts 1000, 1000, 1000, 1000
echo serverRunning = False
echo On Error Resume Next
echo http.Open "GET", "http://localhost:8000/api/health", False
echo http.Send
echo If Err.Number = 0 And http.Status = 200 Then serverRunning = True
echo On Error Goto 0
echo.
echo ' Start server if not already running (use full path to avoid Store stub^)
echo If Not serverRunning Then
echo     WshShell.Run """%PYTHONW_PATH%"" dlp_api_server.py", 0, False
echo End If
echo.
echo ' Poll the server until it's responding (up to 30 seconds^)
echo ready = False
echo For i = 1 To 30
echo     WScript.Sleep 1000
echo     On Error Resume Next
echo     Set http = CreateObject("MSXML2.ServerXMLHTTP"^)
echo     http.SetTimeouts 1000, 1000, 1000, 1000
echo     http.Open "GET", "http://localhost:8000/api/health", False
echo     http.Send
echo     If Err.Number = 0 And http.Status = 200 Then
echo         ready = True
echo         Exit For
echo     End If
echo     On Error Goto 0
echo Next
echo.
echo If ready Then
echo     WshShell.Run "http://localhost:8000", 1, False
echo Else
echo     MsgBox "Zscaler Assessment server failed to start within 30 seconds." ^& vbCrLf ^& vbCrLf ^& "Try running INSTALL_Zscaler_Assessment.bat again, or check that Python is installed.", vbExclamation, "Zscaler Assessment"
echo End If
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
