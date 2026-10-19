@echo off
sc stop RTZ24 > C:\Users\Public\z25.txt 2>&1
sc delete RTZ24 >> C:\Users\Public\z25.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ25 type= kernel start= demand binPath= C:\Users\Public\rtZ25.sys >> C:\Users\Public\z25.txt 2>&1
sc start RTZ25 >> C:\Users\Public\z25.txt 2>&1
sc query RTZ25 >> C:\Users\Public\z25.txt 2>&1
echo WDONE >> C:\Users\Public\z25.txt
