@echo off
sc stop RTZ31 > C:\Users\Public\z32.txt 2>&1
sc delete RTZ31 >> C:\Users\Public\z32.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ32 type= kernel start= demand binPath= C:\Users\Public\rtZ32.sys >> C:\Users\Public\z32.txt 2>&1
sc start RTZ32 >> C:\Users\Public\z32.txt 2>&1
sc query RTZ32 >> C:\Users\Public\z32.txt 2>&1
echo WDONE >> C:\Users\Public\z32.txt
