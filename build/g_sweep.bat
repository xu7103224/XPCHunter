@echo off
set OUT=C:\Users\Public\sweep_log.txt
echo BEGIN > %OUT%
rem ===== ORIGINAL =====
sc stop XPCHunterDrv >> %OUT% 2>&1
sc delete XPCHunterDrv >> %OUT% 2>&1
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc create ViewPlusPlusByLinxer type= kernel binPath= C:\Users\Public\ViewPlusPlusByLinxer.sys >> %OUT% 2>&1
sc start ViewPlusPlusByLinxer >> %OUT% 2>&1
echo ORIG_START=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\sw_orig.txt >> %OUT% 2>&1
echo ORIG_SWEEP_EXIT=%errorlevel% >> %OUT%
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
rem ===== MINE =====
ping -n 4 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo MINE_START=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\sw_mine.txt >> %OUT% 2>&1
echo MINE_SWEEP_EXIT=%errorlevel% >> %OUT%
echo DONE >> %OUT%