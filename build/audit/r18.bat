@echo off
set OUT=C:\Users\Public\sc18.txt
echo === R18 %DATE% %TIME% === > %OUT%
for %%S in (RTZ14 RTZ15 RTZ16 RTZ17 RTZ18) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 5 /nobreak >nul
sc create RTZ18 type= kernel start= demand binPath= C:\Users\Public\rtZ18.sys >> %OUT% 2>&1
sc start RTZ18 >> %OUT% 2>&1
sc query RTZ18 >> %OUT% 2>&1
echo END >> %OUT%