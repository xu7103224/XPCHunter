@echo off
set OUT=C:\Users\Public\wq2.txt
echo BEGIN > "%OUT%"
tasklist /v /fo list /fi "imagename eq PCHunter64.exe" >> "%OUT%" 2>&1
echo --- END --- >> "%OUT%"
