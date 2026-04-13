@echo off
REM Zscaler Assessment - Windows launcher
REM Starts the server in the background and opens the browser

echo.
echo  Starting Zscaler Platform Assessment...
echo.

REM Start server in background
start "Zscaler Assessment Server" /min cmd /c "python dlp_api_server.py"

REM Wait for server to start
timeout /t 3 /nobreak >nul

REM Open browser
echo  Opening http://localhost:8000 in your browser...
start http://localhost:8000

echo.
echo  Server running in background.
echo  To stop the server: close the "Zscaler Assessment Server" window
echo  or run: taskkill /fi "WindowTitle eq Zscaler Assessment Server*" /f
echo.
