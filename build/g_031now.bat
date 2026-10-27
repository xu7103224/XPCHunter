@echo off
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\n031_1.txt 2>&1
C:\Users\Public\xpch_probe.exe --live --cmd 0x031 --dump 8192 > C:\Users\Public\n031_2.txt 2>&1
echo DONE > C:\Users\Public\n_done.txt
