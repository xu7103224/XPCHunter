@echo off
set OUT=C:\Users\xuq\orig45.txt
echo BEGIN > %OUT%
sc stop RTZ42 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ42 >nul 2>&1
sc create OGT type= kernel binPath= C:\Users\xuq\origdrv.sys >> %OUT% 2>&1
sc start OGT >> %OUT% 2>&1
ping -n 6 127.0.0.1 >nul
sc query OGT >> %OUT% 2>&1
echo WDONE >> %OUT%
