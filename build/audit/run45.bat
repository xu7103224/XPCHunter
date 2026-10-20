@echo off
set OUT=C:\Users\xuq\res45.txt
echo BEGIN > %OUT%
sc stop RTZ44 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ44 >nul 2>&1
sc create RTZ45 type= kernel binPath= C:\Users\xuq\drv45.sys >> %OUT% 2>&1
sc start RTZ45 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ45 >> %OUT% 2>&1
echo WDONE >> %OUT%
