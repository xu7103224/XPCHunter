# SendReadMemoryIoControl  ea=0x140072B64  size=866
0x140072B64: mov     rax, rsp
0x140072B67: mov     [rax+10h], rbx
0x140072B6B: mov     [rax+18h], r8d
0x140072B6F: mov     [rax+8], rcx
0x140072B73: push    rbp
0x140072B74: push    rsi
0x140072B75: push    rdi
0x140072B76: push    r12
0x140072B78: push    r13
0x140072B7A: push    r14
0x140072B7C: push    r15
0x140072B7E: lea     rbp, [rax-3Fh]
0x140072B82: sub     rsp, 0A0h
0x140072B89: mov     rax, [rbp+37h+arg_40]
0x140072B90: xor     ebx, ebx
0x140072B92: mov     r12d, r9d
0x140072B95: mov     al, [rax+1]
0x140072B98: mov     rdi, rdx
0x140072B9B: mov     [rbp+37h+arg_18], al
0x140072B9E: lea     eax, [rbx+1]
0x140072BA1: mov     [rcx], al
0x140072BA3: cmp     r9d, 2
0x140072BA7: ja      loc_140072EA3
0x140072BAD: lea     ecx, [rbx+27h]; Index
0x140072BB0: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072BB5: mov     ecx, 41C6h; Index
0x140072BBA: mov     r15, rax
0x140072BBD: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072BC2: mov     ecx, 4223h; Index
0x140072BC7: mov     rsi, rax
0x140072BCA: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072BCF: mov     ecx, 17Ah; Index
0x140072BD4: mov     r13, rax
0x140072BD7: mov     [rbp+37h+var_68], rax
0x140072BDB: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072BE0: mov     ecx, 179h; Index
0x140072BE5: mov     qword ptr [rbp+37h+var_70], rax
0x140072BE9: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072BEE: mov     r14, rax
0x140072BF1: cmp     r15d, 0FFFFFFFFh
0x140072BF5: jz      loc_140072EA3
0x140072BFB: test    rsi, rsi
0x140072BFE: jz      loc_140072EA3
0x140072C04: test    r13, r13
0x140072C07: jz      loc_140072EA3
0x140072C0D: cmp     qword ptr [rbp+37h+var_70], rbx
0x140072C11: jz      loc_140072EA3
0x140072C17: test    rax, rax
0x140072C1A: jz      loc_140072EA3
0x140072C20: mov     ecx, 914h; Index
0x140072C25: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072C2A: lea     edx, [rbx+8]
0x140072C2D: mov     rcx, rdi
0x140072C30: cmp     eax, 1DB0h
0x140072C35: jnb     short loc_140072C4F
0x140072C37: mov     r8, [r14]
0x140072C3A: lea     rax, [rbp+37h+var_80]
0x140072C3E: xor     r9d, r9d
0x140072C41: mov     [rsp+0D0h+Dst], rbx
0x140072C46: mov     qword ptr [rsp+0D0h+var_B0], rax
0x140072C4B: call    rsi
0x140072C4D: jmp     short loc_140072C60
0x140072C4F: lea     r9, [rbp+37h+var_80]
0x140072C53: xor     r8d, r8d
0x140072C56: mov     qword ptr [rsp+0D0h+var_B0], rbx
0x140072C5B: call    SendDeviceIoControlWithRetry
0x140072C60: test    eax, eax
0x140072C62: js      loc_140072EA3
0x140072C68: mov     rax, gs:188h
0x140072C71: mov     rsi, [rbp+37h+arg_20]
0x140072C75: mov     ecx, r15d
0x140072C78: mov     dl, [rcx+rax]
0x140072C7B: mov     [rbp+37h+var_38], rcx
0x140072C7F: mov     [rcx+rax], bl
0x140072C82: mov     rcx, qword ptr [rbp+37h+var_80]
0x140072C86: mov     [rbp+37h+var_90], dl
0x140072C89: lea     rdx, [rbp+37h+var_40]
0x140072C8D: mov     [rbp+37h+var_78], ebx
0x140072C90: mov     r14, rsi
0x140072C93: mov     [rbp+37h+var_48], rax
0x140072C97: call    DispatchHookSwapByVersion
0x140072C9C: mov     ecx, 914h; Index
0x140072CA1: mov     [rbp+37h+var_50], rax
0x140072CA5: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072CAA: mov     edi, 0C0000001h
0x140072CAF: cmp     eax, 1770h
0x140072CB4: jb      loc_140072E63
0x140072CBA: mov     ecx, 197h; Index
0x140072CBF: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140072CC4: test    rax, rax
0x140072CC7: jz      loc_140072E63
0x140072CCD: lea     r8, [rbp+37h+var_88]
0x140072CD1: lea     rdx, [rbp+37h+var_80]
0x140072CD5: xor     r9d, r9d
0x140072CD8: mov     rcx, rax
0x140072CDB: mov     qword ptr [rbp+37h+var_88], rbx
0x140072CDF: mov     [rsp+0D0h+var_B0], 8
0x140072CE7: call    DispatchIoControlByBuildNumber
0x140072CEC: mov     edi, eax
0x140072CEE: test    eax, eax
0x140072CF0: jnz     loc_140072EC0
0x140072CF6: mov     r8, qword ptr [rbp+37h+var_88]
0x140072CFA: mov     r15, rbx
0x140072CFD: mov     r13, rbx
0x140072D00: mov     [rbp+37h+var_58], rbx
0x140072D04: test    r8, r8
0x140072D07: jz      short loc_140072D20
0x140072D09: lea     rdx, [rbp+37h+var_58]
0x140072D0D: mov     rcx, r8
0x140072D10: call    DispatchHookSwapByVersion
0x140072D15: mov     r8, qword ptr [rbp+37h+var_88]; int
0x140072D19: mov     r13, [rbp+37h+var_58]
0x140072D1D: mov     r15, rax
0x140072D20: mov     rax, [rbp+37h+arg_30]
0x140072D24: mov     r9d, [rbp+37h+arg_10]; int
0x140072D28: mov     rdx, qword ptr [rbp+37h+var_80]; int
0x140072D2C: mov     rcx, qword ptr [rbp+37h+var_70]; int
0x140072D30: mov     [rsp+38h], rax; __int64
0x140072D35: mov     eax, dword ptr [rbp+37h+arg_28]
0x140072D38: mov     dword ptr [rsp+0D0h+NumberOfBytes], eax; NumberOfBytes
0x140072D3C: mov     [rsp+0D0h+Dst], rsi; Dst
0x140072D41: mov     [rsp+0D0h+var_B0], r12d; int
0x140072D46: call    SendIoControlWithQuotaBuffer
0x140072D4B: mov     edi, eax
0x140072D4D: test    r12d, r12d
0x140072D50: jnz     loc_140072E42
0x140072D56: mov     r12d, ebx
0x140072D59: mov     r8d, 1
0x140072D5F: cmp     [rbp+37h+arg_18], r8b
0x140072D63: jz      loc_140072E12
0x140072D69: test    edi, edi
0x140072D6B: jnz     loc_140072E06
0x140072D71: cmp     [rbp+37h+arg_38], r8b
0x140072D75: jnz     short loc_140072D9E
0x140072D77: mov     r9d, [rbp+37h+arg_50]
0x140072D7E: mov     r8, [rbp+37h+arg_48]
0x140072D85: mov     rcx, [rbp+37h+arg_40]
0x140072D8C: mov     rdx, rsi
0x140072D8F: call    SendIoControlWithBufferSwap
0x140072D94: lea     r8d, [rdi+1]
0x140072D98: movzx   eax, al
0x140072D9B: mov     [rsi+8], eax
0x140072D9E: mov     eax, [rbp+37h+var_78]
0x140072DA1: mov     ecx, dword ptr [rbp+37h+arg_28]
0x140072DA4: mov     [r14], eax
0x140072DA7: mov     edx, [rsi+0Ch]
0x140072DAA: add     edx, 10h
0x140072DAD: mov     [rbp+37h+var_78], edx
0x140072DB0: lea     eax, [rdx+10h]
0x140072DB3: cmp     ecx, eax
0x140072DB5: jbe     short loc_140072E01
0x140072DB7: sub     ecx, edx
0x140072DB9: mov     eax, edx
0x140072DBB: mov     edx, [rbp+37h+arg_10]
0x140072DBE: add     edx, r8d
0x140072DC1: add     r12d, r8d
0x140072DC4: mov     r8, qword ptr [rbp+37h+var_88]; int
0x140072DC8: mov     dword ptr [rbp+37h+arg_28], ecx
0x140072DCB: mov     [rbp+37h+arg_10], edx
0x140072DCE: mov     r9d, edx; int
0x140072DD1: mov     rdx, qword ptr [rbp+37h+var_80]; int
0x140072DD5: mov     r14, rsi
0x140072DD8: add     rsi, rax
0x140072DDB: mov     rax, [rbp+37h+arg_30]
0x140072DDF: mov     [rsp+38h], rax; __int64
0x140072DE4: mov     dword ptr [rsp+0D0h+NumberOfBytes], ecx; NumberOfBytes
0x140072DE8: mov     rcx, qword ptr [rbp+37h+var_70]; int
0x140072DEC: mov     [rsp+0D0h+Dst], rsi; Dst
0x140072DF1: mov     [rsp+0D0h+var_B0], ebx; int
0x140072DF5: call    SendIoControlWithQuotaBuffer
0x140072DFA: mov     edi, eax
0x140072DFC: jmp     loc_140072D59
0x140072E01: mov     [r14], ebx
0x140072E04: jmp     short loc_140072E42
0x140072E06: mov     [r14], ebx
0x140072E09: test    r12d, r12d
0x140072E0C: jz      short loc_140072E42
0x140072E0E: mov     edi, ebx
0x140072E10: jmp     short loc_140072E42
0x140072E12: mov     [r14], ebx
0x140072E15: test    edi, edi
0x140072E17: jnz     short loc_140072E42
0x140072E19: cmp     [rbp+37h+arg_38], r8b
0x140072E1D: jnz     short loc_140072E42
0x140072E1F: mov     r9d, [rbp+37h+arg_50]
0x140072E26: mov     r8, [rbp+37h+arg_48]
0x140072E2D: mov     rcx, [rbp+37h+arg_40]
0x140072E34: mov     rdx, rsi
0x140072E37: call    SendIoControlWithBufferSwap
0x140072E3C: movzx   eax, al
0x140072E3F: mov     [rsi+8], eax
0x140072E42: mov     rcx, qword ptr [rbp+37h+var_88]
0x140072E46: test    rcx, rcx
0x140072E49: jz      short loc_140072E63
0x140072E4B: test    r15, r15
0x140072E4E: jz      short loc_140072E57
0x140072E50: mov     [r15], r13
0x140072E53: mov     rcx, qword ptr [rbp+37h+var_88]
0x140072E57: mov     r13, [rbp+37h+var_68]
0x140072E5B: test    rcx, rcx
0x140072E5E: jz      short loc_140072E63
0x140072E60: call    r13
0x140072E63: mov     rcx, [rbp+37h+var_50]
0x140072E67: test    rcx, rcx
0x140072E6A: jz      short loc_140072E73
0x140072E6C: mov     rax, [rbp+37h+var_40]
0x140072E70: mov     [rcx], rax
0x140072E73: mov     rax, [rbp+37h+var_48]
0x140072E77: mov     rcx, [rbp+37h+var_38]
0x140072E7B: mov     dl, [rbp+37h+var_90]
0x140072E7E: mov     [rcx+rax], dl
0x140072E81: mov     rcx, qword ptr [rbp+37h+var_80]
0x140072E85: call    [rbp+37h+var_68]
0x140072E88: cmp     edi, 8000001Ah
0x140072E8E: jnz     short loc_140072E96
0x140072E90: mov     rax, [rbp+37h+arg_0]
0x140072E94: mov     [rax], bl
0x140072E96: movzx   ebx, bl
0x140072E99: test    edi, edi
0x140072E9B: mov     ecx, 1
0x140072EA0: cmovz   ebx, ecx
0x140072EA3: mov     al, bl
0x140072EA5: mov     rbx, [rsp+0D0h+arg_8]
0x140072EAD: add     rsp, 0A0h
0x140072EB4: pop     r15
0x140072EB6: pop     r14
0x140072EB8: pop     r13
0x140072EBA: pop     r12
0x140072EBC: pop     rdi
0x140072EBD: pop     rsi
0x140072EBE: pop     rbp
0x140072EBF: retn
0x140072EC0: mov     rcx, qword ptr [rbp+37h+var_88]
0x140072EC4: jmp     short loc_140072E5B