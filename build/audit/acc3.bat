@echo off
set OUT=C:\Users\xuq\res2.txt
echo BEGIN > %OUT%
sc stop RTZ36 >nul 2>&1
sc delete RTZ36 >nul 2>&1
copy /y C:\Users\xuq\drv.sys C:\Users\xuq\drv36.sys >> %OUT% 2>&1
sc create RTZ36 type= kernel binPath= C:\Users\xuq\drv36.sys >> %OUT% 2>&1
sc start RTZ36 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ36 >> %OUT% 2>&1
echo WDONE >> %OUT%
