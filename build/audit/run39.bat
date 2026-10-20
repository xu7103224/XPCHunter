@echo off
set OUT=C:\Users\xuq\res39.txt
echo BEGIN > %OUT%
sc create RTZ39 type= kernel binPath= C:\Users\xuq\drv.sys >> %OUT% 2>&1
sc start RTZ39 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ39 >> %OUT% 2>&1
echo WDONE >> %OUT%
