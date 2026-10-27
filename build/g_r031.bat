@echo off
set OUT=C:\Users\Public\r031.txt
echo BEGIN > %OUT%
rem baseline: mine running
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\r031_m1.txt 2>&1
sc stop XPCHunterDrv >nul 2>&1
sc delete XPCHunterDrv >nul 2>&1
ping -n 4 127.0.0.1 > nul
sc create ViewPlusPlusByLinxer type= kernel binPath= C:\Users\Public\ViewPlusPlusByLinxer.sys >nul 2>&1
sc start ViewPlusPlusByLinxer >nul 2>&1
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\r031_o1.txt 2>&1
sc stop ViewPlusPlusByLinxer >nul 2>&1
sc delete ViewPlusPlusByLinxer >nul 2>&1
ping -n 4 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >nul 2>&1
sc start XPCHunterDrv >nul 2>&1
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\r031_m2.txt 2>&1
sc stop XPCHunterDrv >nul 2>&1
sc delete XPCHunterDrv >nul 2>&1
ping -n 4 127.0.0.1 > nul
sc start ViewPlusPlusByLinxer >nul 2>&1
echo ORIG2_START=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\r031_o2.txt 2>&1
echo DONE >> %OUT%