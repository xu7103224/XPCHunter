@echo off
set OUT=C:\Users\Public\vsetup.txt
echo BEGIN > %OUT%
sc stop ViewPlusPlusByLinxer >> %OUT% 2>&1
sc delete ViewPlusPlusByLinxer >> %OUT% 2>&1
sc stop XPCHunterDrv >> %OUT% 2>&1
sc delete XPCHunterDrv >> %OUT% 2>&1
ping -n 3 127.0.0.1 > nul
sc create XPCHunterDrv type= kernel start= demand binPath= C:\Users\Public\XPCHunterDrv_new.sys >> %OUT% 2>&1
verifier /standard /driver XPCHunterDrv_new.sys >> %OUT% 2>&1
echo VERIFIER_EXIT=%errorlevel% >> %OUT%
verifier /query >> %OUT% 2>&1
echo DONE >> %OUT%