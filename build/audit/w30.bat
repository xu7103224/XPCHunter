@echo off
sc stop RTZ29 > C:\Users\Public\z30.txt 2>&1
sc delete RTZ29 >> C:\Users\Public\z30.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ30 type= kernel start= demand binPath= C:\Users\Public\rtZ30.sys >> C:\Users\Public\z30.txt 2>&1
sc start RTZ30 >> C:\Users\Public\z30.txt 2>&1
sc query RTZ30 >> C:\Users\Public\z30.txt 2>&1
echo WDONE >> C:\Users\Public\z30.txt
