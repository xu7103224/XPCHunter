@echo off
set OUT=C:\Users\xuq\res.txt
echo BEGIN > %OUT%
whoami >> %OUT% 2>&1
sc stop RTZ35 >> %OUT% 2>&1
sc delete RTZ35 >> %OUT% 2>&1
sc create RTZ35 type= kernel binPath= C:\Users\xuq\drv.sys >> %OUT% 2>&1
sc start RTZ35 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ35 >> %OUT% 2>&1
echo WDONE >> %OUT%
