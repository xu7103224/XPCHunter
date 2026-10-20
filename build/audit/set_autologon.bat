@echo off
set KEY=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
echo ==== BEGIN ==== > C:\Users\Public\alo.txt
reg add "%KEY%" /v AutoAdminLogon /t REG_SZ /d 1 /f >> C:\Users\Public\alo.txt 2>&1
reg add "%KEY%" /v DefaultUserName /t REG_SZ /d xuq /f >> C:\Users\Public\alo.txt 2>&1
reg add "%KEY%" /v DefaultPassword /t REG_SZ /d 123 /f >> C:\Users\Public\alo.txt 2>&1
reg add "%KEY%" /v AutoLogonCount /t REG_DWORD /d 30 /f >> C:\Users\Public\alo.txt 2>&1
reg add "%KEY%" /v ForceAutoLogon /t REG_SZ /d 1 /f >> C:\Users\Public\alo.txt 2>&1
echo --- verify --- >> C:\Users\Public\alo.txt
reg query "%KEY%" /v AutoAdminLogon >> C:\Users\Public\alo.txt 2>&1
reg query "%KEY%" /v DefaultUserName >> C:\Users\Public\alo.txt 2>&1
reg query "%KEY%" /v AutoLogonCount >> C:\Users\Public\alo.txt 2>&1
echo ==== WDONE ==== >> C:\Users\Public\alo.txt
