@echo off
REM ============================================
REM XPCHunterDrv - Build Script for VS2019 + WDK
REM ============================================
REM Uses msbuild for compilation, then manual link for linking
REM ============================================
setlocal enabledelayedexpansion

set BUILD_CFG=%1
if "%BUILD_CFG%"=="" set BUILD_CFG=Release

set BUILD_ARCH=%2
if "%BUILD_ARCH%"=="" set BUILD_ARCH=x64

set VS2019_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools
set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.19041.0

echo ============================================
echo XPCHunterDrv Build
echo Configuration: %BUILD_CFG%
echo Architecture:  %BUILD_ARCH%
echo ============================================

call "%VS2019_DIR%\VC\Auxiliary\Build\vcvarsall.bat" x64

if /I "%BUILD_CFG%"=="Clean" (
    echo Cleaning...
    rmdir /s /q "%~dp0..\build\obj" 2>nul
    rmdir /s /q "%~dp0..\build\bin" 2>nul
    echo Clean complete.
    exit /b 0
)

set BASE_DIR=%~dp0..
set OBJ_DIR=%BASE_DIR%\build\obj\%BUILD_CFG%\%BUILD_ARCH%
set BIN_DIR=%BASE_DIR%\build\bin\%BUILD_CFG%\%BUILD_ARCH%
set SRC_DIR=%BASE_DIR%\src
set INC_DIR=%BASE_DIR%\inc

mkdir "%OBJ_DIR%" 2>nul
mkdir "%BIN_DIR%" 2>nul

for %%f in ("%WDK_DIR%") do set WDK_S=%%~sf

REM Step 1: Use msbuild to compile only (the vcxproj has the right WDK config)
echo Step 1: Compiling with msbuild...
msbuild "%BASE_DIR%\XPCHunterDrv.vcxproj" /p:Configuration=%BUILD_CFG% /p:Platform=%BUILD_ARCH% /t:ClCompile /p:CLToolPath="%VS2019_DIR%\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64" /v:m

if errorlevel 1 (
    echo ERROR: Compilation failed!
    exit /b 1
)

echo.
echo Step 2: Linking...
link /nologo /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no ^
    /LIBPATH:"%WDK_S%\Lib\%WDK_VER%\km\x64" ^
    /LIBPATH:"%WDK_S%\Lib\%WDK_VER%\km\x64\crt" ^
    /out:"%BIN_DIR%\XPCHunterDrv.sys" ^
    /pdb:"%BIN_DIR%\XPCHunterDrv.pdb" ^
    /map:"%BIN_DIR%\XPCHunterDrv.map" ^
    "%OBJ_DIR%\*.obj" ^
    ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib ^
    BufferOverflowK.lib bufferoverflowfastfailk.lib

if errorlevel 1 (
    echo ERROR: Link failed!
    exit /b 1
)

echo Build complete!
echo Output: %BIN_DIR%\XPCHunterDrv.sys
dir "%BIN_DIR%\XPCHunterDrv.sys"

exit /b 0