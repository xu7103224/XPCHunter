@echo off
set OUT=C:\kd_tmp\result.txt
echo BEGIN > %OUT%
sc stop RTZ35 >> %OUT% 2>&1
sc delete RTZ35 >> %OUT% 2>&1
copy /y C:\kd_tmp\XPCHunterDrv.sys C:\kd_tmp\drvload.sys >> %OUT% 2>&1
sc create RTZ35 type= kernel binPath= C:\kd_tmp\drvload.sys >> %OUT% 2>&1
sc start RTZ35 >> %OUT% 2>&1
ping -n 4 127.0.0.1 >nul
sc query RTZ35 >> %OUT% 2>&1
echo WDONE >> %OUT%
