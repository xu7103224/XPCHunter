@echo off
set OUT=C:\Users\xuq\rel38.txt
echo BEGIN > %OUT%
copy /y C:\Users\xuq\drv.sys C:\Users\xuq\drv38.sys >> %OUT% 2>&1
sc create RTZ38 type= kernel binPath= C:\Users\xuq\drv38.sys >> %OUT% 2>&1
sc start RTZ38 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ38 >> %OUT% 2>&1
echo WDONE >> %OUT%
