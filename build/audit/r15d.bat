@echo off
sc stop RTZ15 > C:\Users\Public\k15.txt 2>&1
timeout /t 3 /nobreak >nul
sc start RTZ15 >> C:\Users\Public\k15.txt 2>&1
sc query RTZ15 >> C:\Users\Public\k15.txt 2>&1
echo END >> C:\Users\Public\k15.txt
