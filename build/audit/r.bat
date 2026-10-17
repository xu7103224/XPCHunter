@echo off
if not exist C:\kd_tmp\ mkdir C:\kd_tmp\
sc stop RTZ1 >nul 2>&1
sc delete RTZ1 >nul 2>&1
sc create RTZ1 type= kernel start= demand binPath= C:\Users\Public\rtZ1.sys > C:\Users\Public\sc1.txt 2>&1
sc start RTZ1 >> C:\Users\Public\sc1.txt 2>&1
sc query RTZ1 >> C:\Users\Public\sc1.txt 2>&1
