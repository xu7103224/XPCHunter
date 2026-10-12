@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
msbuild "E:\Work\Dev\Windows\wmprotected\APK\XPCHunter\XPCHunterDrv\XPCHunterDrv.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:ClCompile /p:CLToolMultiProcessor=false /p:SelectedFiles="src\kernel\Minifilter.c" /v:m
exit /b %errorlevel%
