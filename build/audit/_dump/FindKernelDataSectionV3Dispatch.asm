# FindKernelDataSectionV3Dispatch  ea=0x14001356C  size=31
0x14001356C: sub     rsp, 28h; 内核数据节 V3 查找分发。版本检查（>= 0x1DB0），条件满足时调用 ParseNtKernelDataSectionsV2。
0x140013570: mov     ecx, 914h; Index
0x140013575: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001357A: cmp     eax, 1DB0h
0x14001357F: jb      short loc_140013586
0x140013581: call    ParseNtKernelDataSectionsV2
0x140013586: add     rsp, 28h
0x14001358A: retn