@echo off
net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" & exit /b)
if not exist C:\kd_tmp\ mkdir C:\kd_tmp\
sc stop RTZ4 >nul 2>&1
sc delete RTZ4 >nul 2>&1
sc create RTZ4 type= kernel start= demand binPath= C:\Users\Public\rtZ4.sys > C:\Users\Public\sc4.txt 2>&1
sc start RTZ4 >> C:\Users\Public\sc4.txt 2>&1
sc query RTZ4 >> C:\Users\Public\sc4.txt 2>&1
