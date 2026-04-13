@echo off
REM ════════════════════════════════════════════════════════════════════
REM  Zscaler Platform Assessment - START
REM  Launches the silent VBS launcher (no console window remains)
REM  Run INSTALL_Zscaler_Assessment.bat first to set up.
REM ════════════════════════════════════════════════════════════════════

if not exist "%~dp0zscaler_launcher.vbs" (
    echo Launcher not found. Please run INSTALL_Zscaler_Assessment.bat first.
    timeout /t 5 >nul
    exit /b 1
)

start /b wscript.exe "%~dp0zscaler_launcher.vbs"
exit
