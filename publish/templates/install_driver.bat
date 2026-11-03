@echo off
REM ============================================================================
REM install_driver.bat - Install / start / stop / uninstall XPCHunterDrv
REM
REM Must be run as Administrator.
REM
REM Usage:
REM   install_driver.bat install     register and start the driver
REM   install_driver.bat start       start an already registered driver
REM   install_driver.bat stop        stop the running driver
REM   install_driver.bat uninstall   stop and remove the service
REM   install_driver.bat status      show current state
REM
REM The driver is loaded as a plain kernel service (no INF / no PnP).
REM For the driver to load, one of the following must hold:
REM   a) testsigning is on :  bcdedit /set testsigning on  (then reboot)
REM   b) the certificate in this package (xpch.cer) is installed into
REM      "Trusted Root Certification Authorities" + "Trusted Publishers"
REM ============================================================================
setlocal enabledelayedexpansion

set SERVICE_NAME=XPCHDrv
set SYS_NAME=XPCHunterDrv.sys
set HERE=%~dp0
set SYS_PATH=%HERE%bin\x64\%SYS_NAME%
set CER_PATH=%HERE%xpch.cer

if /I "%~1"=="" goto :usage
if /I "%~1"=="install"   goto :install
if /I "%~1"=="start"     goto :start
if /I "%~1"=="stop"      goto :stop
if /I "%~1"=="uninstall" goto :uninstall
if /I "%~1"=="status"    goto :status
goto :usage

REM ---------------------------------------------------------------- install
:install
call :require_admin || exit /b 1

if not exist "%SYS_PATH%" (
    echo ERROR: driver not found: %SYS_PATH%
    exit /b 1
)

echo [1/3] Unblocking driver file...
powershell -NoProfile -Command "Unblock-File -LiteralPath '%SYS_PATH%'" >nul 2>&1

echo [2/3] Registering service %SERVICE_NAME%...
sc.exe query %SERVICE_NAME% >nul 2>&1
if !errorlevel! equ 0 (
    echo       service already exists, removing old one first
    sc.exe stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc.exe delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)
sc.exe create %SERVICE_NAME% type= kernel binPath= "%SYS_PATH%"
if !errorlevel! neq 0 (
    echo ERROR: sc create failed
    exit /b 1
)

echo [3/3] Starting driver...
sc.exe start %SERVICE_NAME%
set RC=!errorlevel!
if !RC! neq 0 (
    echo.
    echo ============================================================
    echo START FAILED with code !RC!
    echo ============================================================
    if !RC! equ 577 (
        echo 577 = signature could not be verified. Fix with ONE of:
        echo   a^) enable test signing:
        echo        bcdedit /set testsigning on
        echo        bcdedit /set nointegritychecks on
        echo        shutdown /r /t 0
        echo   b^) install the certificate in this package:
        echo        certutil -addstore -f Root "%CER_PATH%"
        echo        certutil -addstore -f TrustedPublisher "%CER_PATH%"
        echo    then run: install_driver.bat start
    ) else if !RC! equ 1058 (
        echo 1058 = service is disabled. Run: sc config %SERVICE_NAME% start= demand
    )
    exit /b !RC!
)

echo.
sc.exe query %SERVICE_NAME% | findstr /i "STATE"
echo.
echo Driver installed and running.
echo Device name: \\.\View++ByLinxer
exit /b 0

REM ------------------------------------------------------------------ start
:start
call :require_admin || exit /b 1
sc.exe start %SERVICE_NAME%
if !errorlevel! neq 0 (
    echo.
    echo If this fails with 577, see the signature notes printed by:
    echo     install_driver.bat install
    exit /b !errorlevel!
)
sc.exe query %SERVICE_NAME% | findstr /i "STATE"
exit /b 0

REM ------------------------------------------------------------------- stop
:stop
call :require_admin || exit /b 1
sc.exe stop %SERVICE_NAME%
timeout /t 2 /nobreak >nul
sc.exe query %SERVICE_NAME% | findstr /i "STATE"
exit /b 0

REM -------------------------------------------------------------- uninstall
:uninstall
call :require_admin || exit /b 1
echo Stopping service...
sc.exe stop %SERVICE_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul
echo Deleting service...
sc.exe delete %SERVICE_NAME%
if !errorlevel! neq 0 (
    echo NOTE: sc delete returned !errorlevel! ^(service may not exist^)
)
echo Done. The driver file itself was NOT removed.
exit /b 0

REM ----------------------------------------------------------------- status
:status
sc.exe query %SERVICE_NAME%
exit /b 0

REM ------------------------------------------------------------------ usage
:usage
echo Usage: install_driver.bat {install^|start^|stop^|uninstall^|status}
echo.
echo   install     register and start the driver
echo   start       start an already registered driver
echo   stop        stop the running driver
echo   uninstall   stop and remove the service
echo   status      show current state
echo.
echo Run as Administrator.
exit /b 1

REM ------------------------------------------------------------ admin check
:require_admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: this command requires Administrator privileges.
    echo        Right-click cmd.exe and choose "Run as administrator".
    exit /b 1
)
exit /b 0