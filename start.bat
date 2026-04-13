@echo off
REM Zscaler Assessment - Windows launcher
REM Starts server in background, opens browser, and closes this window

REM Start server in a minimized background window
start "Zscaler Assessment Server" /min cmd /c "python dlp_api_server.py"

REM Wait for server to start
timeout /t 3 /nobreak >nul

REM Open browser
start http://localhost:8000

REM Exit launcher window
exit
