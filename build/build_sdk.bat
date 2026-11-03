@echo off
REM ============================================
REM XpchSdk build script (static library)
REM
REM Output: build\bin\%CFG%\sdk_x64\XpchSdk.lib
REM         build\bin\%CFG%\sdk_x64\XpchSdk.h
REM ============================================
setlocal enabledelayedexpansion

set BUILD_CFG=%1
if "%BUILD_CFG%"=="" set BUILD_CFG=Release

set VS2019_DIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools
set BASE_DIR=%~dp0..
set SDK_DIR=%BASE_DIR%\src\sdk
set SRC_DIR=%SDK_DIR%\src
set INC_DIR=%SDK_DIR%\inc
set OBJ_DIR=%BASE_DIR%\build\obj\%BUILD_CFG%\sdk_x64
set BIN_DIR=%BASE_DIR%\build\bin\%BUILD_CFG%\sdk_x64

call "%VS2019_DIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul

if /I "%BUILD_CFG%"=="Clean" (
    rmdir /s /q "%OBJ_DIR%" 2>nul
    rmdir /s /q "%BIN_DIR%" 2>nul
    echo Clean complete.
    exit /b 0
)

mkdir "%OBJ_DIR%" 2>nul
mkdir "%BIN_DIR%" 2>nul

echo Compiling XpchSdk...
cl /nologo /c /W3 /O2 /GS /guard:cf- /utf-8 /DUNICODE /D_UNICODE ^
   /I"%INC_DIR%" /I"%SRC_DIR%" ^
   /Fo"%OBJ_DIR%\\" ^
   "%SRC_DIR%\core.c" "%SRC_DIR%\handshake.c" "%SRC_DIR%\process.c" "%SRC_DIR%\system.c" "%SRC_DIR%\hook.c" "%SRC_DIR%\inject.c"

if errorlevel 1 (
    echo ERROR: compile failed
    exit /b 1
)

echo Creating static library...
lib /nologo /OUT:"%BIN_DIR%\XpchSdk.lib" "%OBJ_DIR%\*.obj"

if errorlevel 1 (
    echo ERROR: lib failed
    exit /b 1
)

copy /y "%INC_DIR%\XpchSdk.h" "%BIN_DIR%\XpchSdk.h" >nul

echo Build complete: %BIN_DIR%\XpchSdk.lib
echo Public header   : %BIN_DIR%\XpchSdk.h
dir "%BIN_DIR%\XpchSdk.lib"

exit /b 0