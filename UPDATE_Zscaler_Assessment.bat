@echo off
title Zscaler Assessment - Update
setlocal

cd /d "%~dp0"

echo ============================================================
echo  Zscaler Assessment - Update to Latest Code
echo ============================================================
echo.

REM ----- Step 1: Stop running server -----
echo [1/4] Stopping running server...
taskkill /f /im pythonw.exe >nul 2>&1
taskkill /f /fi "WINDOWTITLE eq Zscaler Platform Assessment*" >nul 2>&1
timeout /t 2 /nobreak >nul
echo       Done.
echo.

REM ----- Step 2: Pull latest code -----
echo [2/4] Pulling latest code from claude/review-repo-xRk8y...
where git >nul 2>&1
if errorlevel 1 (
    echo       ERROR: git is not installed or not on PATH.
    echo       Install Git from https://git-scm.com/download/win
    pause
    exit /b 1
)
git fetch origin
git checkout claude/review-repo-xRk8y
git pull origin claude/review-repo-xRk8y
if errorlevel 1 (
    echo.
    echo       ERROR: git pull failed. Check your connection and credentials.
    pause
    exit /b 1
)
echo.
echo       Current commit:
git log --oneline -1
echo.

REM ----- Step 3: Locate real Python -----
echo [3/4] Locating Python...
set PYTHON_EXE=
for /f "delims=" %%i in ('where python 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
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

REM ----- Step 4: Restart server + open browser -----
echo [4/4] Starting server...
start "" /b cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:8000"
echo.
echo ============================================================
echo  Update complete. Server starting at http://localhost:8000
echo  IMPORTANT: in your browser press Ctrl+F5 to hard-refresh
echo  (otherwise the browser will keep showing the cached UI)
echo ============================================================
echo.
"%PYTHON_EXE%" dlp_api_server.py

endlocal
