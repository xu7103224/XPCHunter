@echo off
set OUT=C:\Users\Public\vgrow.txt
echo BEGIN > %OUT%
sc create XPCHunterDrv type= kernel binPath= C:\Users\Public\XPCHunterDrv_new.sys >> %OUT% 2>&1
sc start XPCHunterDrv >> %OUT% 2>&1
echo START_EXIT=%errorlevel% >> %OUT%
ping -n 6 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\gr_1.txt >> %OUT% 2>&1
verifier /query > C:\Users\Public\vg_1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --ab --ab-lo 0x20 --ab-hi 0x13A --ab-out C:\Users\Public\gr_2.txt >> %OUT% 2>&1
verifier /query > C:\Users\Public\vg_2.txt 2>&1
echo ---VG1--- >> %OUT%
type C:\Users\Public\vg_1.txt >> %OUT% 2>&1
echo ---VG2--- >> %OUT%
type C:\Users\Public\vg_2.txt >> %OUT% 2>&1
echo DONE >> %OUT%
