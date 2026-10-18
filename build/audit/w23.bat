@echo off
sc stop RTZ22 > C:\Users\Public\z23.txt 2>&1
sc delete RTZ22 >> C:\Users\Public\z23.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ23 type= kernel start= demand binPath= C:\Users\Public\rtZ23.sys >> C:\Users\Public\z23.txt 2>&1
sc start RTZ23 >> C:\Users\Public\z23.txt 2>&1
sc query RTZ23 >> C:\Users\Public\z23.txt 2>&1
echo WDONE >> C:\Users\Public\z23.txt
