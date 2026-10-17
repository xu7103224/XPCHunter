@echo off
set OUT=C:\Users\Public\sc14.txt
echo === R14 %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12 RTZ13 RTZ14) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 4 /nobreak >nul
sc create RTZ14 type= kernel start= demand binPath= C:\Users\Public\rtZ14.sys >> %OUT% 2>&1
sc start RTZ14 >> %OUT% 2>&1
sc query RTZ14 >> %OUT% 2>&1
echo END >> %OUT%
