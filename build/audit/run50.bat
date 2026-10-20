@echo off
set OUT=C:\Users\xuq\res50.txt
echo BEGIN > %OUT%
sc stop RTZ49 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ49 >nul 2>&1
sc create RTZ50 type= kernel binPath= C:\Users\xuq\drv50.sys >> %OUT% 2>&1
sc start RTZ50 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ50 >> %OUT% 2>&1
echo WDONE >> %OUT%
