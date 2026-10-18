@echo off
set OUT=C:\Users\Public\sc15.txt
echo === R15C %DATE% %TIME% === > %OUT%
sc create RTZ15 type= kernel start= demand binPath= C:\Users\Public\rtZ15.sys >> %OUT% 2>&1
sc start RTZ15 >> %OUT% 2>&1
sc query RTZ15 >> %OUT% 2>&1
echo END >> %OUT%
