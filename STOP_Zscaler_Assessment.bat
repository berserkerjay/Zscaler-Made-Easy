@echo off
REM Zscaler Assessment - stop background server
echo Stopping Zscaler Assessment background service...
taskkill /f /im pythonw.exe >nul 2>&1
taskkill /fi "WindowTitle eq Zscaler Assessment*" /f >nul 2>&1
echo Done.
timeout /t 2 >nul
exit
