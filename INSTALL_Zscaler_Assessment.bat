@echo off
title Zscaler Platform Assessment - Install
echo.
echo  Installing Zscaler Platform Assessment...
echo.

set INSTALL_DIR=%~dp0
set INSTALL_DIR=%INSTALL_DIR:~0,-1%

REM Machine-specific settings (proxy, corporate root CA for TLS inspection)
REM live in local_settings.bat next to this file, so pip can reach pypi.org
REM from a laptop behind Zscaler or another inspecting proxy. INSTALL.md
REM says how to create it.
if exist "%INSTALL_DIR%\local_settings.bat" call "%INSTALL_DIR%\local_settings.bat"
if defined REQUESTS_CA_BUNDLE if not defined PIP_CERT set "PIP_CERT=%REQUESTS_CA_BUNDLE%"

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
    echo  and tick "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

echo  Found Python: %PYTHON_EXE%

REM The app needs Python 3.11 or newer. An older Python installed by
REM another tool often comes first on PATH; say so instead of installing
REM into it and failing at start with a syntax error in server.log.
set "PYTHON_VER=unknown version"
for /f "delims=" %%v in ('""%PYTHON_EXE%" --version 2^>^&1"') do set "PYTHON_VER=%%v"
"%PYTHON_EXE%" -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
REM (a goto, not a parenthesised block: a Python path such as
REM  "C:\Program Files (x86)\Python39\python.exe" would close the block early)
if errorlevel 1 goto :oldpython

echo.
echo  [1/2] Installing Python dependencies...
echo        (this can sit with no output for a few minutes; that is normal)
if not exist "%INSTALL_DIR%\requirements.lock" (
    echo.
    echo  requirements.lock is missing from this folder, so the dependencies cannot be
    echo  installed hash-verified. Get a complete copy of the app and run this again.
    pause
    exit /b 1
)
"%PYTHON_EXE%" -m pip install --quiet --disable-pip-version-check --require-hashes --no-deps -r "%INSTALL_DIR%\requirements.lock"
if errorlevel 1 (
    echo.
    echo  ============================================================
    echo   INSTALL FAILED - the dependency install did not finish.
    echo  ============================================================
    echo.
    echo   The lines above say why. The usual causes: no access to pypi.org
    echo   from this network, or a work laptop behind TLS inspection or a
    echo   proxy. Put the CA bundle or proxy in local_settings.bat next to
    echo   this file ^(INSTALL.md, "Work laptop", says how^), then run this
    echo   installer again. Nothing was installed and no shortcut was made.
    echo.
    pause
    exit /b 1
)

echo  [2/2] Creating desktop shortcut...

REM Desktop shortcut: silent launcher (no console window); server output goes to server.log
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $desktop = [Environment]::GetFolderPath('Desktop'); $lnk = $ws.CreateShortcut(\"$desktop\Zscaler Assessment.lnk\"); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = '""%INSTALL_DIR%\START_Zscaler_Assessment.vbs""'; $lnk.WorkingDirectory = '%INSTALL_DIR%'; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Platform Assessment (opens the browser; the server runs silently)'; $lnk.Save();"

REM Also create Start Menu shortcut
powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $start = [Environment]::GetFolderPath('Programs'); $lnk = $ws.CreateShortcut(\"$start\Zscaler Assessment.lnk\"); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = '""%INSTALL_DIR%\START_Zscaler_Assessment.vbs""'; $lnk.WorkingDirectory = '%INSTALL_DIR%'; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Platform Assessment (opens the browser; the server runs silently)'; $lnk.Save();" >nul 2>&1

REM A locked-down PowerShell (Constrained Language Mode) refuses COM objects and makes no shortcut; say so.
set "SHORTCUT_NOTE=Desktop shortcut: "Zscaler Assessment""
powershell -NoProfile -Command "if (Test-Path (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Zscaler Assessment.lnk')) { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 set "SHORTCUT_NOTE=No desktop shortcut could be made on this computer. Double-click START_Zscaler_Assessment.bat in this folder to start the app instead."

echo.
echo  ============================================================
echo   Installation complete!
echo  ============================================================
echo.
echo   %SHORTCUT_NOTE%
echo.
echo   Double-click the shortcut to launch. Your browser opens by itself.
echo   The server runs in the background with no window; its output is
echo   in server.log next to this file. STOP_Zscaler_Assessment.bat
echo   stops it (closing the browser does not).
echo.
echo  Closing in 5 seconds...
timeout /t 5 >nul
exit /b 0

:oldpython
echo.
echo  ERROR: this app needs Python 3.11 or newer; %PYTHON_EXE% is %PYTHON_VER%.
echo  An older Python installed by another tool comes first on PATH. Install
echo  the current version from https://www.python.org/downloads/ with
echo  "Add python.exe to PATH" ticked, or uninstall the old one, then run
echo  this installer again.
pause
exit /b 1
