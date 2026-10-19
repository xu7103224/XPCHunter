@echo off
sc stop RTZ26 > C:\Users\Public\z27.txt 2>&1
sc delete RTZ26 >> C:\Users\Public\z27.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ27 type= kernel start= demand binPath= C:\Users\Public\rtZ27.sys >> C:\Users\Public\z27.txt 2>&1
sc start RTZ27 >> C:\Users\Public\z27.txt 2>&1
sc query RTZ27 >> C:\Users\Public\z27.txt 2>&1
echo WDONE >> C:\Users\Public\z27.txt
