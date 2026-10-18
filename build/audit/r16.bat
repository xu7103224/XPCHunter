@echo off
set OUT=C:\Users\Public\sc16.txt
echo === R16 %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12 RTZ13 RTZ14 RTZ15 RTZ16) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 3 /nobreak >nul
copy /y C:\Users\Public\rtZ15.sys C:\Users\Public\rtZ16.sys >> %OUT% 2>&1
sc create RTZ16 type= kernel start= demand binPath= C:\Users\Public\rtZ16.sys >> %OUT% 2>&1
sc start RTZ16 >> %OUT% 2>&1
sc query RTZ16 >> %OUT% 2>&1
echo END >> %OUT%
