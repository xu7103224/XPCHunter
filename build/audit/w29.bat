@echo off
sc stop RTZ28 > C:\Users\Public\z29.txt 2>&1
sc delete RTZ28 >> C:\Users\Public\z29.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ29 type= kernel start= demand binPath= C:\Users\Public\rtZ29.sys >> C:\Users\Public\z29.txt 2>&1
sc start RTZ29 >> C:\Users\Public\z29.txt 2>&1
sc query RTZ29 >> C:\Users\Public\z29.txt 2>&1
echo WDONE >> C:\Users\Public\z29.txt
