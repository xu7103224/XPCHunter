@echo off
if not exist C:\kd_tmp\ mkdir C:\kd_tmp\
sc stop RTZ2 >nul 2>&1
sc delete RTZ2 >nul 2>&1
sc create RTZ2 type= kernel start= demand binPath= C:\Users\Public\rtZ2.sys > C:\Users\Public\sc2.txt 2>&1
sc start RTZ2 >> C:\Users\Public\sc2.txt 2>&1
sc query RTZ2 >> C:\Users\Public\sc2.txt 2>&1
