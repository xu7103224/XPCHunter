# ResolveWin32kSyscallAddresses  ea=0x140088558  size=175
0x140088558: mov     [rsp+arg_0], rbx
0x14008855D: mov     [rsp+arg_8], rbp
0x140088562: mov     [rsp+arg_10], rsi
0x140088567: push    rdi
0x140088568: sub     rsp, 20h
0x14008856C: mov     ebx, 1FAh
0x140088571: mov     ecx, ebx; Index
0x140088573: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140088578: mov     rsi, rax
0x14008857B: test    rax, rax
0x14008857E: jnz     short loc_14008858F
0x140088580: call    ReadNtOsKrnlAndParseServiceTable
0x140088585: mov     ecx, ebx; Index
0x140088587: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14008858C: mov     rsi, rax
0x14008858F: mov     ecx, 50h ; 'P'; Index
0x140088594: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140088599: mov     rbp, rax
0x14008859C: test    rsi, rsi
0x14008859F: jz      short loc_1400885F2
0x1400885A1: test    rax, rax
0x1400885A4: jz      short loc_1400885F2
0x1400885A6: mov     ecx, 303h; Index
0x1400885AB: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400885B0: test    eax, eax
0x1400885B2: jnz     short loc_1400885F2
0x1400885B4: mov     ecx, 1E2h; Index
0x1400885B9: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400885BE: mov     ecx, 1E7h; Index
0x1400885C3: mov     rbx, rax
0x1400885C6: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400885CB: mov     ecx, ebx
0x1400885CD: mov     edx, [rsi+rcx*4]
0x1400885D0: mov     ecx, 1F2h; Index
0x1400885D5: mov     rdi, rax
0x1400885D8: add     rdx, rbp; Value
0x1400885DB: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400885E0: mov     eax, edi
0x1400885E2: mov     ecx, 1F7h; Index
0x1400885E7: mov     edx, [rsi+rax*4]
0x1400885EA: add     rdx, rbp; Value
0x1400885ED: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400885F2: mov     rbx, [rsp+28h+arg_0]
0x1400885F7: mov     rbp, [rsp+28h+arg_8]
0x1400885FC: mov     rsi, [rsp+28h+arg_10]
0x140088601: add     rsp, 20h
0x140088605: pop     rdi
0x140088606: retn