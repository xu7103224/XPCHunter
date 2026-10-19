@echo off
sc stop RTZ30 > C:\Users\Public\z31.txt 2>&1
sc delete RTZ30 >> C:\Users\Public\z31.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ31 type= kernel start= demand binPath= C:\Users\Public\rtZ31.sys >> C:\Users\Public\z31.txt 2>&1
sc start RTZ31 >> C:\Users\Public\z31.txt 2>&1
sc query RTZ31 >> C:\Users\Public\z31.txt 2>&1
echo WDONE >> C:\Users\Public\z31.txt
