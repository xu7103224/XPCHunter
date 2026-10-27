@echo off
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\t031_1.txt 2>&1
ping -n 3 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\t031_2.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\t0d4_1.txt 2>&1
ping -n 3 127.0.0.1 > nul
C:\Users\Public\xpch_probe.exe --live --cmd 0x0D4 --dump 8192 > C:\Users\Public\t0d4_2.txt 2>&1
echo DONE > C:\Users\Public\t_done.txt