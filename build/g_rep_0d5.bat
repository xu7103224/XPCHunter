@echo off
set OUT=C:\Users\Public\rep_0d5.txt
echo BEGIN > %OUT%
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 | findstr /c:"dump 0xD5" > C:\Users\Public\r_orig1.txt 2>&1
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
ping -n 3 127.0.0.1 > nul
sc start ViewPlusPlusByLinxer >> %OUT% 2>&1
ping -n 3 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\out_0d5_orig2.txt 2>&1
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo MINE_START=%errorlevel% >> %OUT%
ping -n 4 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\out_0d5_mine2.txt 2>&1
sc stop XPCHunterDrv >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo MINE_START2=%errorlevel% >> %OUT%
ping -n 4 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D5 --dump 8192 > C:\Users\Public\out_0d5_mine3.txt 2>&1
echo DONE >> %OUT%