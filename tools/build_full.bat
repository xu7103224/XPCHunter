@echo off
chdir /d "E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv"
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
set MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe
set LINK=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe
echo %MSBUILD% XPCHunterDrv.vcxproj /property:Configuration=Release /property:Platform=x64 /target:Rebuild /v:m
%MSBUILD% XPCHunterDrv.vcxproj /property:Configuration=Release /property:Platform=x64 /target:Rebuild /v:m > build_rebuild.log 2>&1
echo msbuild_exit=%errorlevel%
%LINK% /DRIVER /subsystem:native /entry:GsDriverEntry /base:0x140000000 /fixed:no /merge:.data=.text /manifest:no /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\km\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.19041.0\km\x64\crt" /out:"build\bin\Release\x64\XPCHunterDrv.sys" /pdb:"build\bin\Release\x64\XPCHunterDrv.pdb" "build\obj\Release\x64\*.obj" ntoskrnl.lib hal.lib fltMgr.lib wmilib.lib BufferOverflowK.lib bufferoverflowfastfailk.lib
echo link_exit=%errorlevel%
