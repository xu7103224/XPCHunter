@echo off
set OUT=C:\Users\xuq\clean.txt
echo BEGIN > %OUT%
for %%S in (RTZ1 RTZ9 RTZ14 RTZ35 RTZ36) do (
  echo --- %%S >> %OUT%
  sc query %%S >> %OUT% 2>&1
  sc stop %%S >> %OUT% 2>&1
  ping -n 2 127.0.0.1 >nul
  sc delete %%S >> %OUT% 2>&1
)
echo WDONE >> %OUT%
