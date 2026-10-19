@echo off
set OUT=C:\Users\xuq\orig.txt
echo BEGIN > %OUT%
sc stop ORIGX >nul 2>&1
sc delete ORIGX >nul 2>&1
sc create ORIGX type= kernel binPath= C:\Users\xuq\origdrv.sys >> %OUT% 2>&1
sc start ORIGX >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query ORIGX >> %OUT% 2>&1
echo WDONE >> %OUT%
