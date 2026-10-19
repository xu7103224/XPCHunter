@echo off
sc create RTZ20 type= kernel start= demand binPath= C:\Users\Public\rtZ19.sys > C:\Users\Public\z.txt 2>&1
sc start RTZ20 >> C:\Users\Public\z.txt 2>&1
sc query RTZ20 >> C:\Users\Public\z.txt 2>&1
echo ZDONE >> C:\Users\Public\z.txt
