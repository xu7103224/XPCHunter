@echo off
set OUT=C:\Users\Public\sc15.txt
echo === R15 %DATE% %TIME% === > %OUT%
for %%S in (RTZ9 RTZ10 RTZ11 RTZ12 RTZ13 RTZ14 RTZ15) do (sc stop %%S >> %OUT% 2>&1 & sc delete %%S >> %OUT% 2>&1)
timeout /t 5 /nobreak >nul
del /f /q C:\Users\Public\rtZ15.sys >> %OUT% 2>&1
echo DELETED >> %OUT%
