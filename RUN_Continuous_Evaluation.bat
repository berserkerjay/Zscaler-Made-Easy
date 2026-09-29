@echo off
REM One run of the continuous evaluation without the browser: guidance,
REM Detection Health, SaaS tenants and drift for every tenant profile that
REM remembers its secret, then the digest (and the e-mail / webhook when
REM configured in local_settings.bat). Schedule this file in Windows Task
REM Scheduler (for example every 6 hours) so the loop runs while the app
REM is not open. Nothing is written to any tenant.
setlocal
cd /d "%~dp0"
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"
set "PY="
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if not defined PY for /f "delims=" %%i in ('where python 2^>nul') do if not defined PY set "PY=%%i"
if not defined PY (
    echo Python was not found. Run INSTALL_Zscaler_Assessment.bat first.
    exit /b 1
)
"%PY%" continuous_eval.py --once %*
endlocal
