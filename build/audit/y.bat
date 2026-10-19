@echo off
whoami /groups | findstr /i "S-1-16-12288 S-1-16-8192 S-1-5-32-544" > C:\Users\Public\adm.txt 2>&1
echo --- >> C:\Users\Public\adm.txt
sc query type= driver state= all | findstr /i "SERVICE_NAME" >> C:\Users\Public\adm.txt 2>&1
echo YDONE >> C:\Users\Public\adm.txt
