@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
set OUT=C:\Users\Public\sc7.txt
echo === R7 RUN %DATE% %TIME% === > %OUT%
sc stop RTZ7 >> %OUT% 2>&1
sc delete RTZ7 >> %OUT% 2>&1
sc create RTZ7 type= kernel start= demand binPath= C:\Users\Public\rtZ7.sys >> %OUT% 2>&1
sc start RTZ7 >> %OUT% 2>&1
sc query RTZ7 >> %OUT% 2>&1
echo === DONE === >> %OUT%
