@echo off
sc stop RTZ25 > C:\Users\Public\z26.txt 2>&1
sc delete RTZ25 >> C:\Users\Public\z26.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ26 type= kernel start= demand binPath= C:\Users\Public\rtZ26.sys >> C:\Users\Public\z26.txt 2>&1
sc start RTZ26 >> C:\Users\Public\z26.txt 2>&1
sc query RTZ26 >> C:\Users\Public\z26.txt 2>&1
echo WDONE >> C:\Users\Public\z26.txt
