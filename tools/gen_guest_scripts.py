# -*- coding: utf-8 -*-
"""生成 guest 端部署/诊断批处理，强制 CRLF（cmd.exe 对 LF-only 的多行结构会解析失败）。"""
import io
import os

CRLF = "\r\n"

KILLDIAG = r"""@echo off
set LOG=C:\Users\Public\kill_diag.txt
set PUB=C:\Users\Public
echo BEGIN > %LOG%
date /t >> %LOG%
time /t >> %LOG%

echo ==== STEP1 stop/delete old services ==== >> %LOG%
for %%S in (RTZ70 RTZ71 RTZ56 View++ByLinxer OrigDrv OGT) do call :kill %%S
ping -n 3 127.0.0.1 > nul

echo ==== STEP2 create+start RTZ71 ==== >> %LOG%
sc create RTZ71 type= kernel binPath= %PUB%\ViewPlusPlusNew.sys >> %LOG% 2>&1
echo CREATE=%errorlevel% >> %LOG%
sc start RTZ71 >> %LOG% 2>&1
echo START=%errorlevel% >> %LOG%
sc query RTZ71 >> %LOG% 2>&1

echo ==== STEP3 spawn test process ==== >> %LOG%
start "" /b cmd /c "timeout /t 900 /nobreak > nul"
ping -n 3 127.0.0.1 > nul
set TESTPID=
for /f "tokens=2 delims=," %%P in ('tasklist /fi "imagename eq timeout.exe" /fo csv /nh') do set TESTPID=%%~P
echo TESTPID=%TESTPID% >> %LOG%
tasklist /fi "imagename eq timeout.exe" >> %LOG% 2>&1

echo ==== STEP4 stats BEFORE kill ==== >> %LOG%
%PUB%\xpch_probe.exe --live --stats >> %LOG% 2>&1
echo STATS1_EXIT=%errorlevel% >> %LOG%

echo ==== STEP5 0xA2 kill attempt ==== >> %LOG%
%PUB%\xpch_frontend.exe --kill-cli %TESTPID% >> %LOG% 2>&1
echo KILL_EXIT=%errorlevel% >> %LOG%
ping -n 3 127.0.0.1 > nul

echo ==== STEP6 alive after 0xA2 ==== >> %LOG%
tasklist /fi "imagename eq timeout.exe" >> %LOG% 2>&1

echo ==== STEP7 0x28 kill attempt ==== >> %LOG%
%PUB%\xpch_frontend.exe --kill28-cli %TESTPID% >> %LOG% 2>&1
echo KILL28_EXIT=%errorlevel% >> %LOG%
ping -n 4 127.0.0.1 > nul

echo ==== STEP8 alive after 0x28 ==== >> %LOG%
tasklist /fi "imagename eq timeout.exe" >> %LOG% 2>&1

echo ==== STEP9 stats ==== >> %LOG%
%PUB%\xpch_probe.exe --live --stats >> %LOG% 2>&1
echo STATS2_EXIT=%errorlevel% >> %LOG%

echo DONE >> %LOG%
exit /b 0

:kill
sc stop %1 >> %LOG% 2>&1
sc delete %1 >> %LOG% 2>&1
exit /b 0
"""

# 只做"起测试进程 + 0xA2 + 存活检查"，用于驱动已加载时复测客户端改动。
KILLONLY = r"""@echo off
set LOG=C:\Users\Public\kill_only.txt
set PUB=C:\Users\Public
echo BEGIN > %LOG%
date /t >> %LOG%
time /t >> %LOG%

echo ==== spawn test process ==== >> %LOG%
start "" /b cmd /c "timeout /t 900 /nobreak > nul"
ping -n 3 127.0.0.1 > nul
set TESTPID=
for /f "tokens=2 delims=," %%P in ('tasklist /fi "imagename eq timeout.exe" /fo csv /nh') do set TESTPID=%%~P
echo TESTPID=%TESTPID% >> %LOG%
tasklist /fi "imagename eq timeout.exe" >> %LOG% 2>&1

echo ==== 0xA2 kill attempt ==== >> %LOG%
%PUB%\xpch_frontend.exe --kill-cli %TESTPID% >> %LOG% 2>&1
echo KILL_EXIT=%errorlevel% >> %LOG%
ping -n 4 127.0.0.1 > nul

echo ==== alive check ==== >> %LOG%
tasklist /fi "imagename eq timeout.exe" >> %LOG% 2>&1

echo ==== stats (0xA2 trace) ==== >> %LOG%
%PUB%\xpch_probe.exe --live --stats >> %LOG% 2>&1

echo DONE >> %LOG%
exit /b 0
"""

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sign = os.path.join(HERE, "build", "sign")
for name, text in (("killdiag.bat", KILLDIAG), ("killonly.bat", KILLONLY)):
    out = os.path.join(sign, name)
    io.open(out, "wb").write(text.replace("\n", CRLF).encode("ascii"))
    print("wrote", out, os.path.getsize(out), "bytes")
