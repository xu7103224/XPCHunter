@echo off
set OUT=C:\Users\xuq\unload.txt
echo BEGIN > %OUT%
sc stop RTZ37 >> %OUT% 2>&1
ping -n 3 127.0.0.1 >nul
sc query RTZ37 >> %OUT% 2>&1
echo WDONE >> %OUT%
