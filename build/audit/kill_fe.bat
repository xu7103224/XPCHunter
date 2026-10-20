@echo off
taskkill /f /im xpch_frontend.exe > C:\Users\Public\kill.txt 2>&1
echo kill_rc=%ERRORLEVEL% >> C:\Users\Public\kill.txt
ping -n 3 127.0.0.1 >nul
