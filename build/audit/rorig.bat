@echo off
set OUT=C:\Users\Public\scorig.txt
echo === RORIG %DATE% %TIME% === > %OUT%
for %%S in (RTZ15 RTZ16) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 3 /nobreak >nul
sc start ORIGDRV >> %OUT% 2>&1
sc query ORIGDRV >> %OUT% 2>&1
echo END >> %OUT%