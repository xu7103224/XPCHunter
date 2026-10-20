@echo off
set OUT=C:\Users\xuq\res43.txt
echo BEGIN > %OUT%
sc stop OGT >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete OGT >nul 2>&1
sc create RTZ43 type= kernel binPath= C:\Users\xuq\drv43.sys >> %OUT% 2>&1
sc start RTZ43 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ43 >> %OUT% 2>&1
echo WDONE >> %OUT%
