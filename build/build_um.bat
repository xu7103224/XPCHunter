@echo off
REM ============================================
REM XPCHunterUM build script (user-mode client)
REM ============================================
setlocal enabledelayedexpansion

set BUILD_CFG=%1
if "%BUILD_CFG%"=="" set BUILD_CFG=Release

set VS2019_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools
set BASE_DIR=%~dp0..
set SRC_DIR=%BASE_DIR%\XPCHunterUM\src
set INC_DIR=%BASE_DIR%\XPCHunterUM\inc
set OBJ_DIR=%BASE_DIR%\build\obj\%BUILD_CFG%\um_x64
set BIN_DIR=%BASE_DIR%\build\bin\%BUILD_CFG%\um_x64

call "%VS2019_DIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

if /I "%BUILD_CFG%"=="Clean" (
    rmdir /s /q "%OBJ_DIR%" 2>nul
    rmdir /s /q "%BIN_DIR%" 2>nul
    echo Clean complete.
    exit /b 0
)

mkdir "%OBJ_DIR%" 2>nul
mkdir "%BIN_DIR%" 2>nul

echo Compiling user-mode client...
cl /nologo /c /W3 /O2 /GS /guard:cf- /utf-8 /DUNICODE /D_UNICODE ^
   /I"%INC_DIR%" ^
   /Fo"%OBJ_DIR%\\" ^
   "%SRC_DIR%\Protocol.c" "%SRC_DIR%\ProcessList.c" "%SRC_DIR%\ProcessViews.c" "%SRC_DIR%\KernelViews.c" "%SRC_DIR%\StartupViews.c" "%SRC_DIR%\ServiceViews.c" "%SRC_DIR%\RegistryViews.c" "%SRC_DIR%\FileViews.c" "%SRC_DIR%\OtherViews.c" "%SRC_DIR%\ExaminationViews.c" "%SRC_DIR%\FireeyeViews.c" "%SRC_DIR%\SettingViews.c" "%SRC_DIR%\TrojanViews.c" "%SRC_DIR%\probe.c" "%SRC_DIR%\frontend.c"

if errorlevel 1 (
    echo ERROR: compile failed
    exit /b 1
)

echo Linking probe...
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OPT:REF /OPT:NOICF ^
     /OUT:"%BIN_DIR%\xpch_probe.exe" ^
     "%OBJ_DIR%\Protocol.obj" "%OBJ_DIR%\probe.obj" ^
     kernel32.lib user32.lib advapi32.lib

if errorlevel 1 (
    echo ERROR: link probe failed
    exit /b 1
)

echo Linking frontend...
link /nologo /SUBSYSTEM:WINDOWS /MACHINE:X64 /OPT:REF /OPT:NOICF ^
     /OUT:"%BIN_DIR%\xpch_frontend.exe" ^
     "%OBJ_DIR%\Protocol.obj" "%OBJ_DIR%\frontend.obj" "%OBJ_DIR%\ProcessList.obj" "%OBJ_DIR%\ProcessViews.obj" "%OBJ_DIR%\KernelViews.obj" "%OBJ_DIR%\StartupViews.obj" "%OBJ_DIR%\ServiceViews.obj" "%OBJ_DIR%\RegistryViews.obj" "%OBJ_DIR%\FileViews.obj" "%OBJ_DIR%\OtherViews.obj" "%OBJ_DIR%\ExaminationViews.obj" "%OBJ_DIR%\FireeyeViews.obj" "%OBJ_DIR%\SettingViews.obj" "%OBJ_DIR%\TrojanViews.obj" ^
     kernel32.lib user32.lib advapi32.lib comctl32.lib psapi.lib gdi32.lib version.lib shell32.lib wintrust.lib crypt32.lib

if errorlevel 1 (
    echo ERROR: link frontend failed
    exit /b 1
)

echo Build complete: %BIN_DIR%\xpch_probe.exe
echo Build complete: %BIN_DIR%\xpch_frontend.exe
exit /b 0