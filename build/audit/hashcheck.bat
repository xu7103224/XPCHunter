@echo off
set OUT=C:\Users\Public\hash.txt
echo BEGIN > "%OUT%"
certutil -hashfile C:\Windows\System32\drivers\View++_Driver64.sys MD5 >> "%OUT%" 2>&1
dir C:\Windows\System32\drivers\View++_Driver64.sys >> "%OUT%" 2>&1
certutil -hashfile C:\Users\Public\XPCHunterDrv_signed.sys MD5 >> "%OUT%" 2>&1
echo ==== END ==== >> "%OUT%"
