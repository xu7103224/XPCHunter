@echo off
set OUT=C:\Users\Public\sc12c.txt
echo === R12C %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 3 /nobreak >nul
sc create RTZ12 type= kernel start= demand binPath= C:\Users\Public\rtZ12.sys >> %OUT% 2>&1
sc start RTZ12 >> %OUT% 2>&1
sc query RTZ12 >> %OUT% 2>&1
echo END >> %OUT%
