@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
set OUT=C:\Users\Public\sc6.txt
echo === R6 RUN %DATE% %TIME% === > %OUT%
for %%S in (RTZ4 RTZ5 RTZ3 RT_FIX) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
for %%F in (rtZ4.sys rtZ5.sys rtZ3.sys) do (if exist C:\Users\Public\%%F del /f /q C:\Users\Public\%%F >> %OUT% 2>&1)
sc create RTZ6 type= kernel start= demand binPath= C:\Users\Public\rtZ6.sys >> %OUT% 2>&1
sc start RTZ6 >> %OUT% 2>&1
sc query RTZ6 >> %OUT% 2>&1
echo === DONE === >> %OUT%
