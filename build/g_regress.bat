@echo off
set OUT=C:\Users\Public\regress.txt
echo BEGIN > %OUT%
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
sc stop XPCHunterDrv >> %OUT% 2>&1
sc delete XPCHunterDrv >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo MINE_START=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
sc query XPCHunterDrv | findstr STATE >> %OUT% 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x047 --dump 8192 > C:\Users\Public\r047.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\r0d5.txt 2>&1
echo DONE >> %OUT%