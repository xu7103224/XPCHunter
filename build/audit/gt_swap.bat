@echo off
sc stop ORIGDRV > C:\Users\Public\gtswap.txt 2>&1
timeout /t 3 /nobreak >nul
sc start RTZ10 >> C:\Users\Public\gtswap.txt 2>&1
sc query RTZ10 >> C:\Users\Public\gtswap.txt 2>&1
echo END >> C:\Users\Public\gtswap.txt
