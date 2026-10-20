@echo off
REM ============================================================
REM Compatibility check: our driver serving the ORIGINAL front end
REM
REM The original PCHunter64.exe looks for:
REM   file   : View++_Driver64.sys
REM   path   : \drivers\View++_Driver64.sys
REM   name   : \\.\View++ByLinxer
REM (strings at PCHunter64.exe +0x456f88 .. +0x457010)
REM
REM So we install OUR signed driver under exactly those names, then let
REM the original front end load and drive it.
REM ============================================================
set OUT=C:\Users\Public\compat_out.txt
set SRC=C:\Users\Public\XPCHunterDrv_signed.sys
set DST=C:\Windows\System32\drivers\View++_Driver64.sys

echo ==== BEGIN ==== > "%OUT%"

echo [1] teardown any previous instance >> "%OUT%"
sc stop "View++ByLinxer" >> "%OUT%" 2>&1
sc delete "View++ByLinxer" >> "%OUT%" 2>&1
sc stop "View++_Driver64" >> "%OUT%" 2>&1
sc delete "View++_Driver64" >> "%OUT%" 2>&1

echo [2] install our driver under the original file name >> "%OUT%"
copy /y "%SRC%" "%DST%" >> "%OUT%" 2>&1
echo copy_rc=%ERRORLEVEL% >> "%OUT%"
if exist "%DST%" (echo DST_EXISTS) >> "%OUT%"

echo [3] create the service name the original front end uses >> "%OUT%"
sc create "View++ByLinxer" type= kernel start= demand binPath= "%DST%" >> "%OUT%" 2>&1
echo create_rc=%ERRORLEVEL% >> "%OUT%"

echo [4] start it and confirm the device exists >> "%OUT%"
sc start "View++ByLinxer" >> "%OUT%" 2>&1
echo start_rc=%ERRORLEVEL% >> "%OUT%"
sc query "View++ByLinxer" >> "%OUT%" 2>&1

echo [5] run the ORIGINAL front end against our driver >> "%OUT%"
start "" /b C:\Users\Public\PCHunter64.exe
echo launched=%ERRORLEVEL% >> "%OUT%"
ping -n 20 127.0.0.1 >nul
tasklist /fi "imagename eq PCHunter64.exe" >> "%OUT%" 2>&1
echo ==== WDONE ==== >> "%OUT%"