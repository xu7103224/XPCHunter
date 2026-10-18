@echo off
set OUT=C:\Users\Public\sc19.txt
echo === R19 %DATE% %TIME% === > %OUT%
for %%S in (RTZ14 RTZ15 RTZ16 RTZ17 RTZ18 RTZ19) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 5 /nobreak >nul
sc create RTZ19 type= kernel start= demand binPath= C:\Users\Public\rtZ19.sys >> %OUT% 2>&1
sc start RTZ19 >> %OUT% 2>&1
sc query RTZ19 >> %OUT% 2>&1
echo END >> %OUT%