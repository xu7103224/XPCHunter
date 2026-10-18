@echo off
set OUT=C:\Users\Public\sc17.txt
echo === R17 %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12 RTZ13 RTZ14 RTZ15 RTZ16 RTZ17) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 5 /nobreak >nul
sc create RTZ17 type= kernel start= demand binPath= C:\Users\Public\rtZ17.sys >> %OUT% 2>&1
sc start RTZ17 >> %OUT% 2>&1
sc query RTZ17 >> %OUT% 2>&1
echo END >> %OUT%