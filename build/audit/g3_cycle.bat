@echo off
echo === G3 unload/reload cycles (current build) ===
for /L %%i in (1,1,3) do (
  echo.
  echo --- round %%i ---
  sc stop View++ByLinxer > nul 2>&1
  timeout /t 3 >nul
  sc start XPCHunterDrv > nul 2>&1
  timeout /t 3 >nul
  sc query XPCHunterDrv | findstr STATE
  echo REG_ACTIVITY:
  reg query HKLM\SYSTEM\CurrentControlSet\Services\XPCHunterDrv > nul 2>&1 && echo   reg-ok || echo   reg-FAIL
  reg add HKLM\SOFTWARE\ZqG3Test /v R%%i /t REG_SZ /d ok /f > nul 2>&1 && echo   reg-write-ok || echo   reg-write-FAIL
  echo FILE_ACTIVITY:
  echo g3-round-%%i > C:\Users\Public\g3_r%%i.txt
  dir C:\Users\Public\g3_r%%i.txt | findstr g3_r > nul && echo   file-ok || echo   file-FAIL
  echo CMD_ACTIVITY:
  C:\Users\Public\xpch_probe.exe --live --handshake --cmd 0x24 2>&1 | findstr "command 0x24"
  echo.
  echo --- stop round %%i ---
  sc stop XPCHunterDrv > nul 2>&1
  timeout /t 3 >nul
  sc query XPCHunterDrv | findstr STATE
  sc start View++ByLinxer > nul 2>&1
  timeout /t 3 >nul
  sc query View++ByLinxer | findstr STATE
  sc stop View++ByLinxer > nul 2>&1
  timeout /t 3 >nul
)
echo.
echo === G3 done, guest still alive ===
reg delete HKLM\SOFTWARE\ZqG3Test /f > nul 2>&1
