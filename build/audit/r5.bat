@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
set OUT=C:\Users\Public\sc5.txt
echo === R5 RUN %DATE% %TIME% === > %OUT%
for %%S in (RTZ4 RT_FIX RTZ3) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
sc stop RTZ5 >> %OUT% 2>&1
sc delete RTZ5 >> %OUT% 2>&1
sc create RTZ5 type= kernel start= demand binPath= C:\Users\Public\rtZ5.sys >> %OUT% 2>&1
sc start RTZ5 >> %OUT% 2>&1
sc query RTZ5 >> %OUT% 2>&1
echo === DONE === >> %OUT%
