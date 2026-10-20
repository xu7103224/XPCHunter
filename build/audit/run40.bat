@echo off
set OUT=C:\Users\xuq\res40.txt
echo BEGIN > %OUT%
sc stop RTZ39 >> %OUT% 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ39 >> %OUT% 2>&1
sc create RTZ40 type= kernel binPath= C:\Users\xuq\drv40.sys >> %OUT% 2>&1
sc start RTZ40 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ40 >> %OUT% 2>&1
echo WDONE >> %OUT%
