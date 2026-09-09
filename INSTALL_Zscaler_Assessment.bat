@echo off
title Zscaler Platform Assessment - Install
echo.
echo  Installing Zscaler Platform Assessment...
echo.

set INSTALL_DIR=%~dp0
set INSTALL_DIR=%INSTALL_DIR:~0,-1%

REM Find real Python (skip Microsoft Store stub)
set PYTHON_EXE=
for /f "delims=" %%i in ('where python 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)

if not defined PYTHON_EXE (
    echo  ERROR: Python is not installed.
    echo  Please install Python from https://www.python.org/downloads/
    echo  and check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo  Found Python: %PYTHON_EXE%
echo.
echo  [1/2] Installing Python dependencies...
"%PYTHON_EXE%" -m pip install --quiet --disable-pip-version-check fastapi uvicorn python-docx zscaler-sdk-python requests rich pydantic
if errorlevel 1 (
    echo  WARNING: Some dependencies may have failed.
)

echo  [2/2] Creating desktop shortcut...

REM Desktop shortcut: silent launcher (no console window); server output goes to server.log
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $desktop = [Environment]::GetFolderPath('Desktop'); $lnk = $ws.CreateShortcut(\"$desktop\Zscaler Assessment.lnk\"); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = '""%INSTALL_DIR%\START_Zscaler_Assessment.vbs""'; $lnk.WorkingDirectory = '%INSTALL_DIR%'; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Platform Assessment (opens the browser; the server runs silently)'; $lnk.Save();"

REM Also create Start Menu shortcut
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $start = [Environment]::GetFolderPath('Programs'); $lnk = $ws.CreateShortcut(\"$start\Zscaler Assessment.lnk\"); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = '""%INSTALL_DIR%\START_Zscaler_Assessment.vbs""'; $lnk.WorkingDirectory = '%INSTALL_DIR%'; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Platform Assessment (opens the browser; the server runs silently)'; $lnk.Save();" >nul 2>&1

echo.
echo  ════════════════════════════════════════════════════════════
echo   Installation complete!
echo  ════════════════════════════════════════════════════════════
echo.
echo   Desktop shortcut: "Zscaler Assessment"
echo.
echo   Double-click the shortcut to launch.
echo   A console window will open showing server logs.
echo   Your browser will open automatically.
echo   To stop the server, close the console window.
echo.
echo  Closing in 5 seconds...
timeout /t 5 >nul
exit
