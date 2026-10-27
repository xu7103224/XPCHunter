@echo off
set OUT=C:\Users\Public\sweep3_log.txt
echo BEGIN > %OUT%
sc stop XPCHunterDrv >> %OUT% 2>&1
sc delete XPCHunterDrv >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
ping -n 4 127.0.0.1 > nul
sc create ViewPlusPlusByLinxer type= kernel binPath= C:\Users\Public\ViewPlusPlusByLinxer.sys >> %OUT% 2>&1
sc start ViewPlusPlusByLinxer >> %OUT% 2>&1
echo ORIG_A_START=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
sc query ViewPlusPlusByLinxer | findstr STATE >> %OUT% 2>&1
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\sw_oA.txt >> %OUT% 2>&1
echo SWEEP_A_EXIT=%errorlevel% >> %OUT%
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\sw_oB.txt >> %OUT% 2>&1
echo SWEEP_B_EXIT=%errorlevel% >> %OUT%
echo DONE >> %OUT%