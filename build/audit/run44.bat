@echo off
set OUT=C:\Users\xuq\res44.txt
echo BEGIN > %OUT%
sc stop RTZ43 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ43 >nul 2>&1
sc create RTZ44 type= kernel binPath= C:\Users\xuq\drv44.sys >> %OUT% 2>&1
sc start RTZ44 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ44 >> %OUT% 2>&1
echo WDONE >> %OUT%
