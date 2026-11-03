@echo off
REM ============================================================================
REM install_driver.bat - Install / start / stop / uninstall XPCHunterDrv
REM
REM Must be run as Administrator.
REM
REM Usage:
REM   install_driver.bat install     register and start via sc create (quick path)
REM   install_driver.bat cab         install from driver.cab (standard package)
REM   install_driver.bat start       start an already registered driver
REM   install_driver.bat stop        stop the running driver
REM   install_driver.bat uninstall   stop and remove the service
REM   install_driver.bat status      show current state
REM
REM Two install paths:
REM   sc create  - fast, no driver store entry, works with testsigning
REM   cab        - pnputil + INF, produces a proper driver package entry
REM                (oemXX.inf in the driver store); use this when you want
REM                the OS to track the package, or for unattended deployment.
REM
REM For either path the driver must pass signature checks:
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
set CAB_PATH=%HERE%driver.cab

if /I "%~1"=="" goto :usage
if /I "%~1"=="install"   goto :install
if /I "%~1"=="cab"       goto :cabinstall
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
    call :explain_start_failure !RC!
    exit /b !RC!
)

echo.
sc.exe query %SERVICE_NAME% | findstr /i "STATE"
echo.
echo Driver installed and running.
echo Device name: \\.\View++ByLinxer
exit /b 0

REM ------------------------------------------------------------ cabinstall
REM Standard driver-package path: extract driver.cab, then
REM   pnputil /add-driver XPCHunterDrv.inf /install
REM Produces a proper driver-store entry (oemXX.inf) and registers the
REM service from the INF. Falls back to :install when the cab is absent.
:cabinstall
call :require_admin || exit /b 1

if not exist "%CAB_PATH%" (
    echo driver.cab not found: %CAB_PATH%
    echo Falling back to the sc create route...
    goto :install
)

echo [1/4] Removing any previous service...
sc.exe query %SERVICE_NAME% >nul 2>&1
if !errorlevel! equ 0 (
    sc.exe stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc.exe delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

echo [2/4] Extracting driver.cab...
set EXDIR=%TEMP%\xpchcab_%RANDOM%
mkdir "%EXDIR%" 2>nul
expand "%CAB_PATH%" -F:* "%EXDIR%" >nul
if not exist "%EXDIR%\XPCHunterDrv.inf" (
    echo ERROR: extraction failed, no INF inside driver.cab
    rmdir /s /q "%EXDIR%" 2>nul
    exit /b 1
)

echo [3/4] Installing driver package with pnputil...
pnputil /add-driver "%EXDIR%\XPCHunterDrv.inf" /install
set RC=!errorlevel!
rmdir /s /q "%EXDIR%" 2>nul
REM 3010 = ERROR_SUCCESS_REBOOT_REQUIRED. The package WAS added; the OS
REM only recommends a reboot for the PnP path to settle. For a legacy
REM kernel service the entry is usable right away, so treat it as success.
if !RC! equ 3010 (
    echo       pnputil returned 3010 ^(installed, reboot recommended^)
    set RC=0
)
if !RC! neq 0 (
    echo.
    echo ============================================================
    echo pnputil FAILED with code !RC!
    echo ============================================================
    echo If the message mentions the catalog, an untrusted certificate,
    echo or "signature", run one of the following and retry:
    echo.
    echo   a^) enable test signing:
    echo        bcdedit /set testsigning on
    echo        shutdown /r /t 0
    echo   b^) trust this package's certificate:
    echo        certutil -addstore -f Root "%CER_PATH%"
    echo        certutil -addstore -f TrustedPublisher "%CER_PATH%"
    exit /b !RC!
)

echo [4/4] Starting driver...
sc.exe start %SERVICE_NAME% >nul 2>&1
sc.exe query %SERVICE_NAME% | findstr /i "STATE"
echo.
echo Driver installed from driver.cab (driver store entry created).
echo Device name: \\.\View++ByLinxer
exit /b 0

REM ------------------------------------------------------------------ start
:start
call :require_admin || exit /b 1
sc.exe start %SERVICE_NAME%
if !errorlevel! neq 0 (
    echo.
    call :explain_start_failure !errorlevel!
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
echo.
echo If the driver was installed via "install_driver.bat cab", also remove
echo the driver store entry:
echo     pnputil /enum-drivers
echo     pnputil /delete-driver oemNN.inf /uninstall
exit /b 0

REM ----------------------------------------------------------------- status
:status
sc.exe query %SERVICE_NAME%
exit /b 0

REM ------------------------------------------------------------------ usage
:usage
echo Usage: install_driver.bat {install^|cab^|start^|stop^|uninstall^|status}
echo.
echo   install     register and start via sc create (quick path)
echo   cab         install from driver.cab via pnputil (standard package)
echo   start       start an already registered driver
echo   stop        stop the running driver
echo   uninstall   stop and remove the service
echo   status      show current state
echo.
echo Run as Administrator.
exit /b 1

REM ------------------------------------------------------- start failure help
:explain_start_failure
if %1 equ 577 (
    echo 577 = the signature could not be verified. Fix with ONE of:
    echo   a^) enable test signing:
    echo        bcdedit /set testsigning on
    echo        bcdedit /set nointegritychecks on
    echo        shutdown /r /t 0
    echo   b^) trust this package's certificate:
    echo        certutil -addstore -f Root "%CER_PATH%"
    echo        certutil -addstore -f TrustedPublisher "%CER_PATH%"
    echo    then run: install_driver.bat start
) else if %1 equ 1058 (
    echo 1058 = the service is disabled. Run:
    echo        sc config %SERVICE_NAME% start= demand
) else if %1 equ 1053 (
    echo 1053 = the service did not respond in time. Check the driver
    echo        actually implements DriverEntry and returns success.
)
exit /b 0

REM ------------------------------------------------------------ admin check
:require_admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: this command requires Administrator privileges.
    echo        Right-click cmd.exe and choose "Run as administrator".
    exit /b 1
)
exit /b 0