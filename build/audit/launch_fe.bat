@echo off
set OUT=C:\Users\Public\launch_fe.txt
echo BEGIN > "%OUT%"
taskkill /f /im xpch_frontend.exe >> "%OUT%" 2>&1
schtasks /delete /tn XPCH_FE2 /f >> "%OUT%" 2>&1
schtasks /create /tn XPCH_FE2 /tr "C:\Users\Public\xpch_frontend.exe" /sc once /st 23:45 /ru xuq /rp 123 /it /rl HIGHEST /f >> "%OUT%" 2>&1
echo create_rc=%ERRORLEVEL% >> "%OUT%"
schtasks /run /tn XPCH_FE2 >> "%OUT%" 2>&1
echo run_rc=%ERRORLEVEL% >> "%OUT%"
ping -n 6 127.0.0.1 >nul
tasklist /v /fo list /fi "imagename eq xpch_frontend.exe" >> "%OUT%" 2>&1
