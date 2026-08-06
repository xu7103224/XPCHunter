@echo off
setlocal enabledelayedexpansion
cd /d "E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv"

REM Step 1: Set VC environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo ERROR: vcvarsall failed & exit /b 1)

REM Step 2: msbuild compile
msbuild XPCHunterDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /t:ClCompile /v:m
if errorlevel 1 (echo ERROR: msbuild failed & exit /b 1)

REM Step 3: Link
set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.19041.0
set OBJ_DIR=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\build\obj\Release\x64
set BIN_DIR=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\build\bin\Release\x64

link /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no ^
    /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64" ^
    /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64\crt" ^
    /out:"%BIN_DIR%\XPCHunterDrv.sys" ^
    /pdb:"%BIN_DIR%\XPCHunterDrv.pdb" ^
    /map:"%BIN_DIR%\XPCHunterDrv.map" ^
    "%OBJ_DIR%\*.obj" ^
    ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib ^
    BufferOverflowK.lib bufferoverflowfastfailk.lib
if errorlevel 1 (echo ERROR: link failed & exit /b 1)

echo BUILD SUCCESS
dir "%BIN_DIR%\XPCHunterDrv.sys"
