@echo off
rem 当前: 原版在跑（上一轮收尾状态）
C:\Users\Public\xpch_probe.exe --live --cmd 0x04D --dump 8192 > C:\Users\Public\o4d_1.txt 2>&1
ping -n 3 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x04D --dump 8192 > C:\Users\Public\o4d_2.txt 2>&1
sc stop ViewPlusPlusByLinxer >nul 2>&1
sc delete ViewPlusPlusByLinxer >nul 2>&1
ping -n 4 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >nul 2>&1
sc start XPCHunterDrv >nul 2>&1
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x04D --dump 8192 > C:\Users\Public\m4d_1.txt 2>&1
ping -n 3 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x04D --dump 8192 > C:\Users\Public\m4d_2.txt 2>&1
echo DONE > C:\Users\Public\m4d_done.txt