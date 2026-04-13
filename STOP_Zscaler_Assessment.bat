@echo off
title Zscaler Assessment - Stop
echo Stopping Zscaler Assessment server...
taskkill /f /im pythonw.exe >nul 2>&1
taskkill /f /fi "WINDOWTITLE eq Zscaler Platform Assessment*" >nul 2>&1
echo Done.
timeout /t 2 >nul
exit
