@echo off
title Zscaler Made Easy - Update

REM The pull replaces this very file. cmd reads a batch file as it runs,
REM so run from a copy in %TEMP% and remember the app folder.
if not defined DLPCHECK_UPDATE_COPY (
    set "DLPCHECK_APP_DIR=%~dp0"
    set "DLPCHECK_UPDATE_COPY=1"
    copy /y "%~f0" "%TEMP%\dlpcheck_update.bat" >nul
    call "%TEMP%\dlpcheck_update.bat" %*
    exit /b
)
setlocal
set "INSTALL_DIR=%DLPCHECK_APP_DIR:~0,-1%"
cd /d "%INSTALL_DIR%"

echo ============================================================
echo  Zscaler Made Easy - Update to Latest Code
echo  Folder: %INSTALL_DIR%
echo ============================================================
echo.

REM Machine-specific settings (proxy, CA bundle, port) live in local_settings.bat.
if exist "%INSTALL_DIR%\local_settings.bat" call "%INSTALL_DIR%\local_settings.bat"
if not defined ZSCALER_PORT set ZSCALER_PORT=8000

REM ----- Step 1: Stop running server -----
echo [1/4] Stopping running server...
set FOUND=
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /C:":%ZSCALER_PORT% " ^| findstr "LISTENING"') do (
    set FOUND=1
    taskkill /f /pid %%a >nul 2>&1
    echo       Stopped PID %%a on port %ZSCALER_PORT%.
)
if not defined FOUND echo       No server was running.
timeout /t 2 /nobreak >nul
echo.

REM ----- Step 2: Locate real Python -----
echo [2/4] Locating Python...
set "PYTHON_EXE="
if exist "%INSTALL_DIR%\.venv\Scripts\python.exe" set "PYTHON_EXE=%INSTALL_DIR%\.venv\Scripts\python.exe"
for /f "delims=" %%i in ('where python 2^>nul') do (
    echo "%%i" | findstr /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE (
    echo       ERROR: Python is not installed or only the Microsoft Store stub was found.
    echo       Install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)
echo       Using: %PYTHON_EXE%
echo.

REM ----- Step 3: Pull the latest code (edits preserved, settings moved to local_settings.bat) -----
echo [3/4] Updating from GitHub...
where git >nul 2>&1
if errorlevel 1 (
    echo       ERROR: git is not installed or not on PATH.
    echo       Install Git from https://git-scm.com/download/win and run this again.
    pause
    exit /b 1
)
REM Optional first argument: the branch to update to - main, qa or dev
REM (default: the branch this install is on). Example: UPDATE_Zscaler_Made_Easy.bat dev
set "BRANCH_ARG="
if not "%~1"=="" set "BRANCH_ARG=--branch %~1"
"%PYTHON_EXE%" "%INSTALL_DIR%\app_update.py" --dir "%INSTALL_DIR%" %BRANCH_ARG%
if errorlevel 1 (
    echo.
    echo       The update did not complete. Read the lines above for the reason.
    echo       If it says the repository needs a sign-in: run   git fetch   in this folder once,
    echo       sign in to GitHub when asked, then run this script again.
    pause
    exit /b 1
)
echo.

REM ----- Step 3b: Refresh the desktop / Start Menu shortcuts -----
REM A shortcut made before the rename to Zscaler Made Easy had the old name; it is
REM removed once the new one exists.
powershell -NoProfile -Command "$app = $env:INSTALL_DIR; $ws = New-Object -ComObject WScript.Shell; $desktop = [Environment]::GetFolderPath('Desktop'); $new = Join-Path $desktop 'Zscaler Made Easy.lnk'; $lnk = $ws.CreateShortcut($new); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = [char]34 + (Join-Path $app 'START_Zscaler_Made_Easy.vbs') + [char]34; $lnk.WorkingDirectory = $app; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Made Easy (opens the browser; the server runs silently)'; $lnk.Save(); if (Test-Path -LiteralPath $new) { Remove-Item -LiteralPath (Join-Path $desktop 'Zscaler Assessment.lnk') -ErrorAction SilentlyContinue }"
powershell -NoProfile -Command "$app = $env:INSTALL_DIR; $ws = New-Object -ComObject WScript.Shell; $start = [Environment]::GetFolderPath('Programs'); $new = Join-Path $start 'Zscaler Made Easy.lnk'; $lnk = $ws.CreateShortcut($new); $lnk.TargetPath = 'wscript.exe'; $lnk.Arguments = [char]34 + (Join-Path $app 'START_Zscaler_Made_Easy.vbs') + [char]34; $lnk.WorkingDirectory = $app; $lnk.IconLocation = 'shell32.dll,14'; $lnk.Description = 'Zscaler Made Easy (opens the browser; the server runs silently)'; $lnk.Save(); if (Test-Path -LiteralPath $new) { Remove-Item -LiteralPath (Join-Path $start 'Zscaler Assessment.lnk') -ErrorAction SilentlyContinue }" >nul 2>&1
echo       Shortcuts refreshed (silent launcher).
echo.

REM ----- Step 4: Restart server (silently) + open browser -----
echo [4/4] Starting server...
echo.
echo ============================================================
echo  Update complete. Server starting at http://localhost:%ZSCALER_PORT%
echo  The server runs in the background (output in server.log).
echo  STOP_Zscaler_Made_Easy.bat stops it. Next time, use the
echo  Update app button on the Start here card instead.
echo ============================================================
echo.
wscript.exe "%INSTALL_DIR%\START_Zscaler_Made_Easy.vbs"
timeout /t 3 >nul 2>&1

endlocal
exit /b 0
