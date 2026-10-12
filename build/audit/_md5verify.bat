@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
cl /nologo /W3 /source-charset:utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:_md5verify.exe _md5verify.c
