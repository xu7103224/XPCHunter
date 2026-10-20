@echo off
set OUT=C:\Users\Public\launch2.txt
echo BEGIN > "%OUT%"
taskkill /f /im PCHunter64.exe >> "%OUT%" 2>&1
schtasks /delete /tn XPCH_FE /f >> "%OUT%" 2>&1
schtasks /create /tn XPCH_FE /tr "C:\Users\Public\PCHunter64.exe" /sc once /st 23:45 /ru xuq /rp 123 /it /rl HIGHEST /f >> "%OUT%" 2>&1
echo create_rc=%ERRORLEVEL% >> "%OUT%"
schtasks /query /tn XPCH_FE /fo list /v >> "%OUT%" 2>&1
schtasks /run /tn XPCH_FE >> "%OUT%" 2>&1
echo run_rc=%ERRORLEVEL% >> "%OUT%"
ping -n 10 127.0.0.1 >nul
tasklist /v /fo list /fi "imagename eq PCHunter64.exe" >> "%OUT%" 2>&1
echo ==== WDONE ==== >> "%OUT%"
