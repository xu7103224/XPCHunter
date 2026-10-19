@echo off
sc stop RTZ27 > C:\Users\Public\z28.txt 2>&1
sc delete RTZ27 >> C:\Users\Public\z28.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ28 type= kernel start= demand binPath= C:\Users\Public\rtZ28.sys >> C:\Users\Public\z28.txt 2>&1
sc start RTZ28 >> C:\Users\Public\z28.txt 2>&1
sc query RTZ28 >> C:\Users\Public\z28.txt 2>&1
echo WDONE >> C:\Users\Public\z28.txt
