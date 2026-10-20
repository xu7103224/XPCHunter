@echo off
set OUT=C:\Users\xuq\res42.txt
echo BEGIN > %OUT%
sc stop RTZ41 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ41 >nul 2>&1
sc create RTZ42 type= kernel binPath= C:\Users\xuq\drv42.sys >> %OUT% 2>&1
sc start RTZ42 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ42 >> %OUT% 2>&1
echo WDONE >> %OUT%
