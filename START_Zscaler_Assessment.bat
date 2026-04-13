@echo off
REM ════════════════════════════════════════════════════════════════════
REM  Zscaler Platform Assessment - START
REM  Launches the silent VBS launcher (no console window remains)
REM  This script auto-closes after launching.
REM ════════════════════════════════════════════════════════════════════

if not exist "%~dp0zscaler_launcher.vbs" (
    echo Creating silent launcher...
    (
    echo Set WshShell = CreateObject("WScript.Shell"^)
    echo WshShell.CurrentDirectory = "%~dp0"
    echo WshShell.Run "pythonw.exe dlp_api_server.py", 0, False
    echo WScript.Sleep 3000
    echo WshShell.Run "http://localhost:8000", 1, False
    ) > "%~dp0zscaler_launcher.vbs"
)

start /b wscript.exe "%~dp0zscaler_launcher.vbs"
exit
