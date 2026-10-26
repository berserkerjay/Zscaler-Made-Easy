@echo off
REM Exists only for shortcuts made before the rename to Zscaler Made Easy; UPDATE_Zscaler_Made_Easy.bat does the update.
REM Hands over with the same arguments; without "call", cmd never comes back to this file.
"%~dp0UPDATE_Zscaler_Made_Easy.bat" %*
