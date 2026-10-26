@echo off
REM One run of the continuous evaluation without the browser: guidance and,
REM for every tenant profile that remembers its secret, only what its Scope
REM page puts in scope (Detection Health and pack drift when DLP is in scope,
REM SaaS tenants when SaaS Security runs on Zscaler; nothing when no scope is
REM saved), then the digest (and the e-mail / webhook when configured in
REM local_settings.bat). Every tenant read counts against the ZIA API rate
REM limit, so nothing schedules this for you: schedule it in Windows Task
REM Scheduler yourself if you want it to run unattended. Nothing is written
REM to any tenant.
setlocal
cd /d "%~dp0"
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"
set "PY="
if exist "%~dp0.venv\Scripts\python.exe" set "PY=%~dp0.venv\Scripts\python.exe"
if not defined PY for /f "delims=" %%i in ('where python 2^>nul') do if not defined PY set "PY=%%i"
if not defined PY (
    echo Python was not found. Run INSTALL_Zscaler_Made_Easy.bat first.
    exit /b 1
)
"%PY%" continuous_eval.py --once %*
endlocal
