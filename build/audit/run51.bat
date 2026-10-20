@echo off
set OUT=C:\Users\xuq\res51.txt
echo BEGIN > %OUT%
sc stop RTZ50 >nul 2>&1
ping -n 3 127.0.0.1 >nul
sc delete RTZ50 >nul 2>&1
sc create RTZ51 type= kernel binPath= C:\Users\xuq\drv51.sys >> %OUT% 2>&1
sc start RTZ51 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ51 >> %OUT% 2>&1
echo WDONE >> %OUT%
