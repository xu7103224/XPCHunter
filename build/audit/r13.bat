@echo off
set OUT=C:\Users\Public\sc13.txt
echo === R13 %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12 RTZ13) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 4 /nobreak >nul
sc create RTZ13 type= kernel start= demand binPath= C:\Users\Public\rtZ13.sys >> %OUT% 2>&1
sc start RTZ13 >> %OUT% 2>&1
sc query RTZ13 >> %OUT% 2>&1
echo END >> %OUT%
