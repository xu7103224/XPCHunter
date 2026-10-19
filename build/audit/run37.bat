@echo off
set OUT=C:\Users\xuq\res37.txt
echo BEGIN > %OUT%
sc create RTZ37 type= kernel binPath= C:\Users\xuq\drv36.sys >> %OUT% 2>&1
sc start RTZ37 >> %OUT% 2>&1
ping -n 5 127.0.0.1 >nul
sc query RTZ37 >> %OUT% 2>&1
echo WDONE >> %OUT%
