@echo off
sc stop RTZ23 > C:\Users\Public\z24.txt 2>&1
sc delete RTZ23 >> C:\Users\Public\z24.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ24 type= kernel start= demand binPath= C:\Users\Public\rtZ24.sys >> C:\Users\Public\z24.txt 2>&1
sc start RTZ24 >> C:\Users\Public\z24.txt 2>&1
sc query RTZ24 >> C:\Users\Public\z24.txt 2>&1
echo WDONE >> C:\Users\Public\z24.txt
