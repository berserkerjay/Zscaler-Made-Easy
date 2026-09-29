@echo off
REM ═════════════════════════════════════════════════════════════════════
REM  START with WRITE ACTIONS ENABLED
REM  --------------------------------
REM  This variant enables the safety-gated write endpoints:
REM    - Delete All Rules (Step 3b in the migration wizard)
REM    - Post Live rules (Step 5 in the migration wizard)
REM    - Enable Evaluate All Rules toggle
REM
REM  Use this batch file ONLY when you intend to make changes to the
REM  tenant. For read-only assessment, reporting, and bypass-inventory,
REM  use the regular START_Zscaler_Assessment.bat.
REM
REM  The server still:
REM    - Binds to 127.0.0.1 (no network exposure)
REM    - Requires credential entry in the GUI
REM    - Runs every write as dry-run unless the caller explicitly passes
REM      dry_run=false (which the GUI only sends after a confirm prompt)
REM ═════════════════════════════════════════════════════════════════════

title Zscaler Platform Assessment (WRITES ENABLED)

setlocal
set ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND
if not defined ZSCALER_BIND_HOST set ZSCALER_BIND_HOST=127.0.0.1
if not defined ZSCALER_PORT      set ZSCALER_PORT=8000

REM Machine-specific settings that must survive updates (proxy, corporate
REM root CA for TLS inspection, credentials) live in local_settings.bat
REM next to this file. It is git-ignored; copy local_settings.bat.example.
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"

echo.
echo  ============================================================
echo   Zscaler Platform Assessment  -  WRITE ACTIONS ENABLED
echo  ============================================================
echo   ENABLE_WRITE_ACTIONS = YES_I_UNDERSTAND
echo   Binding: %ZSCALER_BIND_HOST%:%ZSCALER_PORT%
echo.
echo   Destructive actions (Delete All, Post Live) are now
echo   permitted. The GUI still confirms before firing them.
echo  ============================================================
echo.

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
    echo Install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

cd /d "%~dp0"

REM Open browser after 4 seconds (in parallel with server startup)
start "" /b cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:%ZSCALER_PORT%"

REM Run the server (writes enabled for this process only)
"%PYTHON_EXE%" dlp_api_server.py

endlocal
