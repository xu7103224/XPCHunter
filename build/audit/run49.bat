@echo off
set OUT=C:\Users\xuq\res49.txt
echo BEGIN > %OUT%
sc stop RTZ48 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ48 >nul 2>&1
sc create RTZ49 type= kernel binPath= C:\Users\xuq\drv49.sys >> %OUT% 2>&1
sc start RTZ49 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ49 >> %OUT% 2>&1
echo WDONE >> %OUT%
