@echo off
set OUT=C:\Users\xuq\res41.txt
echo BEGIN > %OUT%
sc stop RTZ40 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ40 >nul 2>&1
sc create RTZ41 type= kernel binPath= C:\Users\xuq\drv41.sys >> %OUT% 2>&1
sc start RTZ41 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ41 >> %OUT% 2>&1
echo WDONE >> %OUT%
