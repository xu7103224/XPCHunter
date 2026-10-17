@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
set OUT=C:\Users\Public\sc10.txt
echo === R9 RUN %DATE% %TIME% === > %OUT%
for %%S in (RTZ6 RTZ7 RTZ8 RTZ10) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
sc create RTZ10 type= kernel start= demand binPath= C:\Users\Public\rtZ10.sys >> %OUT% 2>&1
sc start RTZ10 >> %OUT% 2>&1
sc query RTZ10 >> %OUT% 2>&1
echo === DONE === >> %OUT%
