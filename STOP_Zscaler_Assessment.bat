@echo off
title Zscaler Assessment - Stop
echo Stopping Zscaler Assessment server...

REM Kill ONLY the process listening on port 8000.
REM Avoids killing other Python apps or Explorer windows that happen
REM to have the assessment folder open.
set FOUND=
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    set FOUND=1
    taskkill /f /pid %%a >nul 2>&1
    echo   Stopped PID %%a (was listening on :8000)
)
if not defined FOUND echo   No server was running on port 8000.

echo Done.
timeout /t 2 >nul
exit
