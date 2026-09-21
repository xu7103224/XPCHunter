# FindKernelDataSectionV2Dispatch  ea=0x1400130A4  size=31
0x1400130A4: sub     rsp, 28h; 内核数据节 V2 查找分发。版本检查（>= 0x1DB0），条件满足时调用 FindKernelDataSectionV2。
0x1400130A8: mov     ecx, 914h; Index
0x1400130AD: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400130B2: cmp     eax, 1DB0h
0x1400130B7: jb      short loc_1400130BE
0x1400130B9: call    FindKernelDataSectionV2
0x1400130BE: add     rsp, 28h
0x1400130C2: retn