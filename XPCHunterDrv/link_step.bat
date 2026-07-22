@echo off
set WDK_DIR=C:\Program Files (x86)\Windows Kits\10
set WDK_VER=10.0.19041.0
set LINK_EXE=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe
call "%LINK_EXE%" /nologo /kernel /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /driver /merge:.data=.text /manifest:no /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64" /LIBPATH:"%WDK_DIR%\Lib\%WDK_VER%\km\x64\crt" /out:"build\bin\Release\x64\XPCHunterDrv.sys" /pdb:"build\bin\Release\x64\XPCHunterDrv.pdb" /map:"build\bin\Release\x64\XPCHunterDrv.map" "build\obj\Release\x64\*.obj" ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib BufferOverflowK.lib bufferoverflowfastfailk.lib
echo link_exit=%errorlevel%
