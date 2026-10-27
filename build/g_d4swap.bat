@echo off
sc stop XPCHunterDrv >nul 2>&1
sc delete XPCHunterDrv >nul 2>&1
ping -n 4 127.0.0.1 > nul
sc create ViewPlusPlusByLinxer type= kernel binPath= C:\Users\Public\ViewPlusPlusByLinxer.sys >nul 2>&1
sc start ViewPlusPlusByLinxer >nul 2>&1
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\y_d4_1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\y_d4_2.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\y_d4_3.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\y_d4_4.txt 2>&1
echo DONE > C:\Users\Public\y_done.txt
