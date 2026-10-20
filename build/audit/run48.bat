@echo off
set OUT=C:\Users\xuq\res48.txt
echo BEGIN > %OUT%
sc stop RTZ47 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ47 >nul 2>&1
sc create RTZ48 type= kernel binPath= C:\Users\xuq\drv48.sys >> %OUT% 2>&1
sc start RTZ48 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ48 >> %OUT% 2>&1
echo WDONE >> %OUT%
