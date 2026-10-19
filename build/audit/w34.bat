@echo off
sc stop RTZ33 > C:\Users\Public\z34.txt 2>&1
sc delete RTZ33 >> C:\Users\Public\z34.txt 2>&1
timeout /t 3 /nobreak >nul
sc create RTZ34 type= kernel start= demand binPath= C:\Users\Public\rtZ34.sys >> C:\Users\Public\z34.txt 2>&1
sc start RTZ34 >> C:\Users\Public\z34.txt 2>&1
sc query RTZ34 >> C:\Users\Public\z34.txt 2>&1
echo WDONE >> C:\Users\Public\z34.txt
