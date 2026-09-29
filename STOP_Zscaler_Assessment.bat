@echo off
title Zscaler Assessment - Stop
echo Stopping Zscaler Assessment server...

REM The port comes from local_settings.bat when it was changed there (the
REM start and update scripts read the same file), else 8000.
if exist "%~dp0local_settings.bat" call "%~dp0local_settings.bat"
if not defined ZSCALER_PORT set ZSCALER_PORT=8000

REM Kill ONLY the process listening on that port.
REM Avoids killing other Python apps or Explorer windows that happen
REM to have the assessment folder open.
set FOUND=
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%ZSCALER_PORT% " ^| findstr "LISTENING"') do (
    set FOUND=1
    taskkill /f /pid %%a >nul 2>&1
    echo   Stopped PID %%a (was listening on :%ZSCALER_PORT%)
)
if not defined FOUND echo   No server was running on port %ZSCALER_PORT%.

echo Done.
timeout /t 2 >nul
exit
