@echo off
set OUT=C:\Users\xuq\res47.txt
echo BEGIN > %OUT%
sc stop RTZ46 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ46 >nul 2>&1
sc create RTZ47 type= kernel binPath= C:\Users\xuq\drv47.sys >> %OUT% 2>&1
sc start RTZ47 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ47 >> %OUT% 2>&1
echo WDONE >> %OUT%
