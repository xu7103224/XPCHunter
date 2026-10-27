@echo off
set OUT=C:\Users\Public\first_run.txt
echo BEGIN > %OUT%
rem === ORIGINAL: delete service, recreate, start, first probe ===
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc create ViewPlusPlusByLinxer type= kernel binPath= C:\Users\Public\ViewPlusPlusByLinxer.sys >> %OUT% 2>&1
sc start ViewPlusPlusByLinxer >> %OUT% 2>&1
echo ORIG_START=%errorlevel% >> %OUT%
ping -n 5 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\fr_orig1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\fr_orig2.txt 2>&1
rem === MINE: delete service, recreate, start, first probe ===
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
sc stop XPCHunterDrv >> %OUT% 2>&1
sc delete XPCHunterDrv >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo MINE_START=%errorlevel% >> %OUT%
ping -n 5 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\fr_mine1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\fr_mine2.txt 2>&1
echo DONE >> %OUT%