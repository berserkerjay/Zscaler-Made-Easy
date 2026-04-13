@echo off
title Zscaler Platform Assessment

REM Find real Python (skip Microsoft Store stub)
set PYTHON_EXE=
for /f "delims=" %%i in ('where python 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE (
    echo ERROR: Python is not installed or only the Microsoft Store stub was found.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

cd /d "%~dp0"

REM Open browser after 4 seconds (in parallel with server startup)
start "" /b cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:8000"

REM Run the server (this window stays open showing logs - close to stop)
"%PYTHON_EXE%" dlp_api_server.py
