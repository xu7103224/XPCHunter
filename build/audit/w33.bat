@echo off
sc stop RTZ32 > C:\Users\Public\z33.txt 2>&1
sc delete RTZ32 >> C:\Users\Public\z33.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ33 type= kernel start= demand binPath= C:\Users\Public\rtZ33.sys >> C:\Users\Public\z33.txt 2>&1
sc start RTZ33 >> C:\Users\Public\z33.txt 2>&1
sc query RTZ33 >> C:\Users\Public\z33.txt 2>&1
echo WDONE >> C:\Users\Public\z33.txt
