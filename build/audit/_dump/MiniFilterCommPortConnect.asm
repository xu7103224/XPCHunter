# MiniFilterCommPortConnect  ea=0x140019784  size=54
0x140019784: push    rbx
0x140019786: sub     rsp, 20h
0x14001978A: mov     ecx, 8F2h; Index
0x14001978F: xor     ebx, ebx
0x140019791: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140019796: test    eax, eax
0x140019798: jnz     short loc_1400197B2
0x14001979A: call    RegisterCommPortReplyCallback
0x14001979F: cmp     al, 1
0x1400197A1: jnz     short loc_1400197B2
0x1400197A3: lea     edx, [rbx+1]; Value
0x1400197A6: mov     ecx, 8F2h; Index
0x1400197AB: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400197B0: mov     bl, 1
0x1400197B2: mov     al, bl
0x1400197B4: add     rsp, 20h
0x1400197B8: pop     rbx
0x1400197B9: retn