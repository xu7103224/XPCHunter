@echo off
set OUT=C:\Users\Public\scrl.txt
echo === RL %DATE% %TIME% === > %OUT%
sc stop RTZ15 >> %OUT% 2>&1
timeout /t 2 /nobreak >nul
sc start RTZ15 >> %OUT% 2>&1
sc query RTZ15 >> %OUT% 2>&1
echo END >> %OUT%