@echo off
title Zscaler Platform Assessment

REM ════════════════════════════════════════════════════════════════
REM Secure-by-design defaults:
REM   - Bind to localhost only. Set ZSCALER_BIND_HOST=0.0.0.0 to expose
REM     to the network (you almost never want this).
REM   - Write actions (rule create/delete) are blocked unless
REM     ENABLE_WRITE_ACTIONS is set to YES_I_UNDERSTAND.
REM   - Tracebacks are hidden in non-debug mode. Set ZSCALER_DEBUG=1
REM     to surface them while developing.
REM ════════════════════════════════════════════════════════════════
if not defined ZSCALER_BIND_HOST set ZSCALER_BIND_HOST=127.0.0.1
if not defined ZSCALER_PORT      set ZSCALER_PORT=8000

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
start "" /b cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:%ZSCALER_PORT%"

REM Run the server (this window stays open showing logs - close to stop)
"%PYTHON_EXE%" dlp_api_server.py
