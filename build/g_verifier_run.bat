@echo off
set OUT=C:\Users\Public\vrun.txt
echo BEGIN > %OUT%
verifier /query > C:\Users\Public\vq_boot.txt 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo START_EXIT=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
sc query XPCHunterDrv | findstr STATE >> %OUT% 2>&1
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\gv_mine.txt >> %OUT% 2>&1
echo SWEEP_EXIT=%errorlevel% >> %OUT%
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\s031_1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\s031_2.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\s031_3.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\s0d4_1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\s0d4_2.txt 2>&1
verifier /query > C:\Users\Public\vq_after.txt 2>&1
echo DONE >> %OUT%