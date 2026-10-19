@echo off
set OUT=C:\Users\xuq\rel37.txt
echo BEGIN > %OUT%
sc start RTZ37 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ37 >> %OUT% 2>&1
echo WDONE >> %OUT%
