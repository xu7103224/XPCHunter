# SendWriteMemoryIoControl  ea=0x140072EC8  size=811
0x140072EC8: mov     rax, rsp
0x140072ECB: mov     [rax+10h], rbx
0x140072ECF: mov     [rax+20h], r9d
0x140072ED3: mov     [rax+18h], r8d
0x140072ED7: mov     [rax+8], rcx
0x140072EDB: push    rbp
0x140072EDC: push    rsi
0x140072EDD: push    rdi
0x140072EDE: push    r12
0x140072EE0: push    r13
0x140072EE2: push    r14
0x140072EE4: push    r15
0x140072EE6: lea     rbp, [rax-3Fh]
0x140072EEA: sub     rsp, 0A0h
0x140072EF1: xor     ebx, ebx
0x140072EF3: mov     rdi, rdx
0x140072EF6: lea     edx, [rbx+1]
0x140072EF9: mov     [rcx], dl
0x140072EFB: cmp     r9d, 2
0x140072EFF: ja      loc_1400731D6
0x140072F05: lea     ecx, [rbx+27h]; Index
0x140072F08: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F0D: mov     ecx, 41C6h; Index
0x140072F12: mov     r15, rax
0x140072F15: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F1A: mov     ecx, 4223h; Index
0x140072F1F: mov     rsi, rax
0x140072F22: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F27: mov     ecx, 17Bh; Index
0x140072F2C: mov     r13, rax
0x140072F2F: mov     [rbp+37h+var_70], rax
0x140072F33: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F38: mov     ecx, 179h; Index
0x140072F3D: mov     r12, rax
0x140072F40: mov     qword ptr [rbp+37h+var_60], rax
0x140072F44: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F49: mov     r14, rax
0x140072F4C: cmp     r15d, 0FFFFFFFFh
0x140072F50: jz      loc_1400731D6
0x140072F56: test    rsi, rsi
0x140072F59: jz      loc_1400731D6
0x140072F5F: test    r13, r13
0x140072F62: jz      loc_1400731D6
0x140072F68: test    r12, r12
0x140072F6B: jz      loc_1400731D6
0x140072F71: test    rax, rax
0x140072F74: jz      loc_1400731D6
0x140072F7A: mov     ecx, 914h; Index
0x140072F7F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072F84: lea     edx, [rbx+1]
0x140072F87: mov     rcx, rdi
0x140072F8A: cmp     eax, 1DB0h
0x140072F8F: jnb     short loc_140072FA9
0x140072F91: mov     r8, [r14]
0x140072F94: lea     rax, [rbp+37h+var_88]
0x140072F98: xor     r9d, r9d
0x140072F9B: mov     [rsp+0D0h+NumberOfBytes], rbx
0x140072FA0: mov     [rsp+0D0h+Dst], rax
0x140072FA5: call    rsi
0x140072FA7: jmp     short loc_140072FBA
0x140072FA9: lea     r9, [rbp+37h+var_88]
0x140072FAD: xor     r8d, r8d
0x140072FB0: mov     [rsp+0D0h+Dst], rbx
0x140072FB5: call    SendDeviceIoControlWithRetry
0x140072FBA: test    eax, eax
0x140072FBC: js      loc_1400731D6
0x140072FC2: mov     rax, gs:188h
0x140072FCB: mov     rsi, [rbp+37h+arg_20]
0x140072FCF: mov     r15d, r15d
0x140072FD2: mov     cl, [r15+rax]
0x140072FD6: mov     [r15+rax], bl
0x140072FDA: lea     rdx, [rbp+37h+var_50]
0x140072FDE: mov     [rbp+37h+var_90], cl
0x140072FE1: mov     rcx, qword ptr [rbp+37h+var_88]
0x140072FE5: mov     [rbp+37h+var_8C], ebx
0x140072FE8: mov     r12d, ebx
0x140072FEB: mov     r14, rsi
0x140072FEE: mov     [rbp+37h+var_40], rax
0x140072FF2: mov     [rbp+37h+var_78], r15
0x140072FF6: call    DispatchHookSwapByVersion
0x140072FFB: mov     ecx, 914h; Index
0x140073000: mov     [rbp+37h+var_58], rax
0x140073004: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073009: mov     edi, 0C0000001h
0x14007300E: cmp     eax, 1770h
0x140073013: jb      loc_140073199
0x140073019: mov     ecx, 197h; Index
0x14007301E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073023: mov     r15, rax
0x140073026: test    rax, rax
0x140073029: jz      loc_140073195
0x14007302F: mov     ecx, 198h; Index
0x140073034: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073039: lea     r8, [rbp+37h+var_80]
0x14007303D: lea     rdx, [rbp+37h+var_88]
0x140073041: mov     qword ptr [rbp+37h+var_48], rax
0x140073045: mov     eax, 1
0x14007304A: xor     r9d, r9d
0x14007304D: mov     rcx, r15
0x140073050: mov     qword ptr [rbp+37h+var_80], rbx
0x140073054: mov     dword ptr [rsp+0D0h+Dst], eax
0x140073058: call    DispatchIoControlByBuildNumber
0x14007305D: mov     edi, eax
0x14007305F: test    eax, eax
0x140073061: jnz     loc_140073195
0x140073067: mov     rcx, qword ptr [rbp+37h+var_80]
0x14007306B: mov     r13, rbx
0x14007306E: mov     [rbp+37h+var_68], rbx
0x140073072: test    rcx, rcx
0x140073075: jz      short loc_140073083
0x140073077: lea     rdx, [rbp+37h+var_68]
0x14007307B: call    DispatchHookSwapByVersion
0x140073080: mov     r13, rax
0x140073083: mov     r15d, dword ptr [rbp+37h+arg_28]
0x140073087: mov     r8d, 1
0x14007308D: mov     rcx, qword ptr [rbp+37h+var_80]
0x140073091: mov     edi, 0C0000001h
0x140073096: test    rcx, rcx
0x140073099: jz      short loc_1400730D5
0x14007309B: mov     r10, qword ptr [rbp+37h+var_48]
0x14007309F: test    r10, r10
0x1400730A2: jz      short loc_140073105
0x1400730A4: mov     r9d, [rbp+37h+arg_18]
0x1400730A8: mov     rax, [rbp+37h+arg_30]
0x1400730AC: mov     rdx, qword ptr [rbp+37h+var_88]; int
0x1400730B0: mov     [rsp+38h], rax; __int64
0x1400730B5: mov     dword ptr [rsp+0D0h+var_A0], r15d; NumberOfBytes
0x1400730BA: mov     r8, rcx; int
0x1400730BD: mov     [rsp+0D0h+NumberOfBytes], rsi; Dst
0x1400730C2: mov     dword ptr [rsp+0D0h+Dst], r9d; int
0x1400730C7: mov     r9d, [rbp+37h+arg_10]; int
0x1400730CB: mov     rcx, r10; int
0x1400730CE: call    AllocBufferAndSendIoControl
0x1400730D3: jmp     short loc_1400730FD
0x1400730D5: mov     rax, [rbp+37h+arg_30]
0x1400730D9: mov     r9d, [rbp+37h+arg_18]; int
0x1400730DD: mov     r8d, [rbp+37h+arg_10]; int
0x1400730E1: mov     rdx, qword ptr [rbp+37h+var_88]; int
0x1400730E5: mov     rcx, qword ptr [rbp+37h+var_60]; int
0x1400730E9: mov     [rsp+0D0h+var_A0], rax; __int64
0x1400730EE: mov     dword ptr [rsp+0D0h+NumberOfBytes], r15d; NumberOfBytes
0x1400730F3: mov     [rsp+0D0h+Dst], rsi; Dst
0x1400730F8: call    SendIoControlWithQuotaBufferEx
0x1400730FD: mov     r8d, 1
0x140073103: mov     edi, eax
0x140073105: cmp     [rbp+37h+arg_18], r8d
0x140073109: jnz     short loc_14007316C
0x14007310B: cmp     [rbp+37h+arg_38], r8b
0x14007310F: jz      short loc_140073165
0x140073111: test    edi, edi
0x140073113: jnz     short loc_140073157
0x140073115: mov     [r14], r12d
0x140073118: mov     ecx, [rsi+8]
0x14007311B: cmp     ecx, 0FFFFFFFFh
0x14007311E: jz      short loc_140073129
0x140073120: mov     r12d, [rsi+0Ch]
0x140073124: add     r12d, ecx
0x140073127: jmp     short loc_140073131
0x140073129: mov     r12d, [rsi+10h]
0x14007312D: add     r12d, 14h
0x140073131: lea     rcx, [r12+4]
0x140073136: mov     eax, r15d
0x140073139: mov     edx, r12d
0x14007313C: cmp     rax, rcx
0x14007313F: jbe     short loc_140073169
0x140073141: add     [rbp+37h+arg_10], r8d
0x140073145: mov     r14, rsi
0x140073148: sub     r15d, r12d
0x14007314B: add     rsi, rdx
0x14007314E: add     [rbp+37h+var_8C], r8d
0x140073152: jmp     loc_14007308D
0x140073157: mov     eax, [rbp+37h+var_8C]
0x14007315A: mov     [r14], ebx
0x14007315D: test    eax, eax
0x14007315F: jz      short loc_14007316C
0x140073161: mov     edi, ebx
0x140073163: jmp     short loc_14007316C
0x140073165: test    edi, edi
0x140073167: jnz     short loc_14007316C
0x140073169: mov     [r14], ebx
0x14007316C: cmp     qword ptr [rbp+37h+var_80], rbx
0x140073170: jz      short loc_140073191
0x140073172: test    r13, r13
0x140073175: jz      short loc_14007317F
0x140073177: mov     rax, [rbp+37h+var_68]
0x14007317B: mov     [r13+0], rax
0x14007317F: mov     rcx, qword ptr [rbp+37h+var_80]
0x140073183: mov     r13, [rbp+37h+var_70]
0x140073187: test    rcx, rcx
0x14007318A: jz      short loc_140073195
0x14007318C: call    r13
0x14007318F: jmp     short loc_140073195
0x140073191: mov     r13, [rbp+37h+var_70]
0x140073195: mov     r15, [rbp+37h+var_78]
0x140073199: mov     rcx, [rbp+37h+var_58]
0x14007319D: test    rcx, rcx
0x1400731A0: jz      short loc_1400731A9
0x1400731A2: mov     rax, [rbp+37h+var_50]
0x1400731A6: mov     [rcx], rax
0x1400731A9: mov     rax, [rbp+37h+var_40]
0x1400731AD: mov     cl, [rbp+37h+var_90]
0x1400731B0: mov     [r15+rax], cl
0x1400731B4: mov     rcx, qword ptr [rbp+37h+var_88]
0x1400731B8: call    r13
0x1400731BB: cmp     edi, 8000001Ah
0x1400731C1: jnz     short loc_1400731C9
0x1400731C3: mov     rax, [rbp+37h+arg_0]
0x1400731C7: mov     [rax], bl
0x1400731C9: movzx   ebx, bl
0x1400731CC: test    edi, edi
0x1400731CE: mov     ecx, 1
0x1400731D3: cmovz   ebx, ecx
0x1400731D6: mov     al, bl
0x1400731D8: mov     rbx, [rsp+0D0h+arg_8]
0x1400731E0: add     rsp, 0A0h
0x1400731E7: pop     r15
0x1400731E9: pop     r14
0x1400731EB: pop     r13
0x1400731ED: pop     r12
0x1400731EF: pop     rdi
0x1400731F0: pop     rsi
0x1400731F1: pop     rbp
0x1400731F2: retn