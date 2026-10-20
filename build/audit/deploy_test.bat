@echo off
REM ============================================
REM XPCHunter driver deploy + test on win10dev
REM Output: C:\Users\Public\xpch_out.txt
REM ============================================
set OUT=C:\Users\Public\xpch_out.txt
set SRC=C:\Users\Public\XPCHunterDrv_signed.sys
set DST=C:\Windows\System32\drivers\ViewPlusPlusByLinxer.sys

echo ==== BEGIN ==== > "%OUT%"

echo [1] teardown old services >> "%OUT%"
sc stop "View++ByLinxer" >> "%OUT%" 2>&1
sc delete "View++ByLinxer" >> "%OUT%" 2>&1

echo [2] copy driver >> "%OUT%"
copy /y "%SRC%" "%DST%" >> "%OUT%" 2>&1
echo copy_rc=%ERRORLEVEL% >> "%OUT%"
if exist "%DST%" (echo DST_EXISTS) >> "%OUT%"

echo [3] create service >> "%OUT%"
sc create "View++ByLinxer" type= kernel start= demand binPath= "%DST%" >> "%OUT%" 2>&1
echo create_rc=%ERRORLEVEL% >> "%OUT%"

echo [4] start service >> "%OUT%"
sc start "View++ByLinxer" >> "%OUT%" 2>&1
echo start_rc=%ERRORLEVEL% >> "%OUT%"

echo [5] query >> "%OUT%"
sc query "View++ByLinxer" >> "%OUT%" 2>&1

echo [6] probe live >> "%OUT%"
C:\Users\Public\xpch_probe.exe --live >> "%OUT%" 2>&1

echo ==== WDONE ==== >> "%OUT%"

