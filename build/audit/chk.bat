@echo off
set OUT=C:\Users\xuq\chk.txt
echo BEGIN > %OUT%
sc query type= driver state= all | findstr /i "XPCH RTZ" >> %OUT% 2>&1
sc query XPCHunterDrv >> %OUT% 2>&1
driverquery /v | findstr /i "XPCH" >> %OUT% 2>&1
echo ---SERVICES--- >> %OUT%
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /f XPCH /k >> %OUT% 2>&1
echo WDONE >> %OUT%
