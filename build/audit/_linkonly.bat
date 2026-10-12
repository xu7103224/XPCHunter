@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
set WDK_S=C:\Program Files (x86)\Windows Kits\10
set OBJ=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\obj\Release\x64
set BIN=E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\build\bin\Release\x64
link /nologo /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no /ignore:4257 /ignore:4254 /LIBPATH:"%WDK_S%\Lib\10.0.19041.0\km\x64" /LIBPATH:"%WDK_S%\Lib\10.0.19041.0\km\x64\crt" /out:"%BIN%\XPCHunterDrv.sys" /pdb:"%BIN%\XPCHunterDrv.pdb" /map:"%BIN%\XPCHunterDrv.map" "%OBJ%\*.obj" ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib BufferOverflowK.lib bufferoverflowfastfailk.lib
exit /b %errorlevel%
