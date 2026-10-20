$ErrorActionPreference='Continue'
$bat='C:\kd_tmp\acc.bat'
@'
@echo off
set OUT=C:\kd_tmp\result.txt
echo BEGIN > %OUT%
sc stop RTZ35 >> %OUT% 2>&1
sc delete RTZ35 >> %OUT% 2>&1
sc create RTZ35 type= kernel binPath= C:\kd_tmp\XPCHunterDrv.sys >> %OUT% 2>&1
sc start RTZ35 >> %OUT% 2>&1
timeout /t 3 >nul
sc query RTZ35 >> %OUT% 2>&1
echo WDONE >> %OUT%
'@ | Out-File -Encoding ascii $bat
schtasks /Create /TN XpchAcc /TR "C:\kd_tmp\acc.bat" /SC ONCE /ST 23:59 /RU SYSTEM /RL HIGHEST /F | Out-File -Append -Encoding utf8 C:\kd_tmp\sched.txt
schtasks /Run /TN XpchAcc | Out-File -Append -Encoding utf8 C:\kd_tmp\sched.txt
Start-Sleep -Seconds 8
"RUNNER_DONE" | Out-File -Append -Encoding utf8 C:\kd_tmp\sched.txt
