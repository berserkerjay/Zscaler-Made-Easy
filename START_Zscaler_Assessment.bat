@echo off
title Zscaler Platform Assessment

REM Double-clicked (or an old shortcut)? Relaunch silently through the VBS
REM launcher so no console window stays open. Pass --console to keep this
REM window (for troubleshooting); the launcher sets DLPCHECK_HIDDEN itself.
if /i "%~1"=="--console" goto :console
if defined DLPCHECK_HIDDEN goto :console
if exist "%~dp0START_Zscaler_Assessment.vbs" (
    start "" wscript.exe "%~dp0START_Zscaler_Assessment.vbs"
    exit /b 0
)
:console

REM ================================================================
REM Secure-by-design defaults:
REM   - Bind to localhost only. Set ZSCALER_BIND_HOST=0.0.0.0 to expose
REM     to the network (you almost never want this).
REM   - Write actions (rule create/delete) are blocked unless
REM     ENABLE_WRITE_ACTIONS is set to YES_I_UNDERSTAND.
REM   - Tracebacks are hidden in non-debug mode. Set ZSCALER_DEBUG=1
REM     to surface them while developing.
REM ================================================================
if not defined ZSCALER_BIND_HOST set ZSCALER_BIND_HOST=127.0.0.1
if not defined ZSCALER_PORT      set ZSCALER_PORT=8000

REM Machine-specific settings that must survive updates (proxy, corporate
REM root CA for TLS inspection, credentials) live in local_settings.bat
REM next to this file. It is git-ignored; copy local_settings.bat.example.
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"

REM --------------------------------------------------------------
REM  If you're behind a corporate proxy, uncomment and edit one of:
REM    set HTTPS_PROXY=http://user:pass@proxy.corp:8080
REM    set ZSCALER_UPDATE_PROXY=http://proxy.corp:8080
REM  If corporate TLS inspection breaks the update checker, trust the
REM  proxy's root certificate (a .pem file) instead of switching checks off:
REM    set REQUESTS_CA_BUNDLE=C:\certs\corporate-root-ca.pem
REM  (see local_settings.bat.example). ZSCALER_UPDATE_VERIFY_TLS=0 is a
REM  last resort: the update and documentation checks then accept
REM  any certificate, so anyone on the network path can feed them false
REM  content.
REM --------------------------------------------------------------

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

REM Open browser after 4 seconds (in parallel with server startup). The
REM silent launcher opens it itself, so skip when running hidden.
if not defined DLPCHECK_HIDDEN start "" /b cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:%ZSCALER_PORT%"

REM Run the server (this window stays open showing logs - close to stop)
"%PYTHON_EXE%" dlp_api_server.py
