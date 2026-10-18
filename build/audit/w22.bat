@echo off
sc stop RTZ21 > C:\Users\Public\z22.txt 2>&1
sc delete RTZ21 >> C:\Users\Public\z22.txt 2>&1
sc stop RTZ22 >> C:\Users\Public\z22.txt 2>&1
sc delete RTZ22 >> C:\Users\Public\z22.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ22 type= kernel start= demand binPath= C:\Users\Public\rtZ22.sys >> C:\Users\Public\z22.txt 2>&1
sc start RTZ22 >> C:\Users\Public\z22.txt 2>&1
sc query RTZ22 >> C:\Users\Public\z22.txt 2>&1
echo WDONE >> C:\Users\Public\z22.txt
