# InitCallbackFunctions  ea=0x140033EE8  size=84
0x140033EE8: sub     rsp, 28h
0x140033EEC: call    InitProcessNotify
0x140033EF1: call    InitThreadNotify
0x140033EF6: mov     ecx, 18Fh; Index
0x140033EFB: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140033F00: test    eax, eax
0x140033F02: jnz     short loc_140033F0B
0x140033F04: xor     ecx, ecx
0x140033F06: call    InitCallbackFunctionTable
0x140033F0B: mov     ecx, 190h; Index
0x140033F10: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140033F15: test    eax, eax
0x140033F17: jnz     short loc_140033F21
0x140033F19: lea     ecx, [rax+2]
0x140033F1C: call    InitCallbackFunctionTable
0x140033F21: mov     ecx, 2A4h; Index
0x140033F26: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140033F2B: test    eax, eax
0x140033F2D: jnz     short loc_140033F37
0x140033F2F: lea     ecx, [rax+1]
0x140033F32: call    InitCallbackFunctionTable
0x140033F37: add     rsp, 28h
0x140033F3B: retn