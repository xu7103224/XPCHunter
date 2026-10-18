@echo off
sc create RTZ21 type= kernel start= demand binPath= C:\Users\Public\rtZ21.sys > C:\Users\Public\w.txt 2>&1
sc start RTZ21 >> C:\Users\Public\w.txt 2>&1
sc query RTZ21 >> C:\Users\Public\w.txt 2>&1
echo WDONE >> C:\Users\Public\w.txt
