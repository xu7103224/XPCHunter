# InitWin32kTableByVersion  ea=0x14008850C  size=76
0x14008850C: sub     rsp, 28h
0x140088510: mov     ecx, 914h; Index
0x140088515: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14008851A: cmp     eax, 2800h
0x14008851F: jnb     short loc_140088528
0x140088521: call    ResolveWin32kSyscallAddresses
0x140088526: jmp     short loc_140088553
0x140088528: lea     rdx, [rsp+28h+arg_0]
0x14008852D: lea     rcx, [rsp+28h+arg_8]
0x140088532: call    ReadWin32kFullDriverFile
0x140088537: cmp     al, 1
0x140088539: jnz     short loc_140088553
0x14008853B: mov     edx, [rsp+28h+arg_0]
0x14008853F: mov     rcx, [rsp+28h+arg_8]
0x140088544: call    ResolveWin32kExportAddresses
0x140088549: mov     rcx, [rsp+28h+arg_8]
0x14008854E: call    ExFree
0x140088553: add     rsp, 28h
0x140088557: retn