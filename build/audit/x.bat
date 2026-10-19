@echo off
whoami > C:\Users\Public\out.txt 2>&1
whoami /groups | findstr /i "S-1-16-12288 S-1-5-32-544" >> C:\Users\Public\out.txt 2>&1
for %%S in (RTZ14 RTZ15 RTZ16 RTZ17 RTZ18 RTZ19) do (sc stop %%S >> C:\Users\Public\out.txt 2>&1 & sc delete %%S >> C:\Users\Public\out.txt 2>&1)
sc create RTZ19 type= kernel start= demand binPath= C:\Users\Public\rtZ19.sys >> C:\Users\Public\out.txt 2>&1
sc start RTZ19 >> C:\Users\Public\out.txt 2>&1
sc query RTZ19 >> C:\Users\Public\out.txt 2>&1
echo BATCH_DONE >> C:\Users\Public\out.txt
