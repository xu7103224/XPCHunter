@echo off
set OUT=C:\Users\xuq\res46.txt
echo BEGIN > %OUT%
sc stop RTZ45 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ45 >nul 2>&1
sc create RTZ46 type= kernel binPath= C:\Users\xuq\drv46.sys >> %OUT% 2>&1
sc start RTZ46 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ46 >> %OUT% 2>&1
echo WDONE >> %OUT%
