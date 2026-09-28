# ReadKernelMemoryViaSwap  ea=0x140074D5C  size=411
0x140074D5C: mov     rax, rsp
0x140074D5F: mov     [rax+8], rbx
0x140074D63: mov     [rax+10h], rsi
0x140074D67: mov     [rax+18h], rdi
0x140074D6B: push    rbp
0x140074D6C: push    r12
0x140074D6E: push    r13
0x140074D70: push    r14
0x140074D72: push    r15
0x140074D74: lea     rbp, [rax-5Fh]
0x140074D78: sub     rsp, 90h
0x140074D7F: mov     r14, rcx
0x140074D82: mov     ecx, 16Eh; Index
0x140074D87: mov     r13d, r9d
0x140074D8A: mov     rdi, r8
0x140074D8D: mov     r15, rdx
0x140074D90: xor     ebx, ebx
0x140074D92: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140074D97: mov     ecx, 4334h; Index
0x140074D9C: mov     [rbp+57h+var_78], rax
0x140074DA0: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140074DA5: mov     ecx, 172h; Index
0x140074DAA: mov     rsi, rax
0x140074DAD: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140074DB2: mov     r12, rax
0x140074DB5: cmp     [rbp+57h+var_78], rbx
0x140074DB9: jz      loc_140074ED4
0x140074DBF: test    rsi, rsi
0x140074DC2: jz      loc_140074ED4
0x140074DC8: test    rax, rax
0x140074DCB: jz      loc_140074ED4
0x140074DD1: mov     edx, [r15+0Ch]
0x140074DD5: mov     r8d, [r14+4]; MaxCount
0x140074DD9: add     edx, r8d
0x140074DDC: add     rdx, 2
0x140074DE0: cmp     rdx, r13
0x140074DE3: jnb     loc_140074ED4
0x140074DE9: mov     rdx, [r14+8]; Src
0x140074DED: mov     rcx, rdi; Dst
0x140074DF0: call    memmove
0x140074DF5: mov     eax, [r14+4]
0x140074DF9: lea     ecx, [rbx+5Ch]
0x140074DFC: mov     [rax+rdi-2], cx
0x140074E01: mov     ecx, [r14+4]
0x140074E05: mov     r8d, [r15+0Ch]; MaxCount
0x140074E09: lea     rdx, [r15+10h]; Src
0x140074E0D: add     rcx, rdi; Dst
0x140074E10: call    memmove
0x140074E15: mov     edx, [r15+0Ch]
0x140074E19: mov     ecx, [r14+4]
0x140074E1D: add     rcx, rdi
0x140074E20: mov     [rdx+rcx], bx
0x140074E24: mov     edx, [r15+0Ch]
0x140074E28: lea     r15d, [rbx+2]
0x140074E2C: add     edx, 2
0x140074E2F: add     edx, [r14+4]
0x140074E33: cmp     edx, r15d
0x140074E36: jb      short loc_140074E4A
0x140074E38: mov     word ptr [rbp+57h+var_60+2], dx
0x140074E3C: sub     dx, r15w
0x140074E40: mov     [rbp+57h+var_58], rdi
0x140074E44: mov     word ptr [rbp+57h+var_60], dx
0x140074E48: jmp     short loc_140074E51
0x140074E4A: mov     [rbp+57h+var_58], rbx
0x140074E4E: mov     [rbp+57h+var_60], ebx
0x140074E51: lea     rax, [rbp+57h+var_60]
0x140074E55: xorps   xmm0, xmm0
0x140074E58: lea     rcx, [rbp+57h+var_68]
0x140074E5C: mov     [rbp+57h+var_50], 30h ; '0'
0x140074E63: mov     [rbp+57h+var_48], rbx
0x140074E67: mov     [rbp+57h+var_38], 240h
0x140074E6E: movdqu  [rbp+57h+var_30], xmm0
0x140074E73: mov     [rbp+57h+var_40], rax
0x140074E77: call    SwapKernelMemoryPointer
0x140074E7C: lea     r8, [rbp+57h+var_50]
0x140074E80: lea     rcx, [rbp+57h+var_70]
0x140074E84: mov     edx, 20019h
0x140074E89: mov     r14, rax
0x140074E8C: call    [rbp+57h+var_78]
0x140074E8F: mov     ecx, eax
0x140074E91: test    r14, r14
0x140074E94: jz      short loc_140074E9D
0x140074E96: mov     rax, [rbp+57h+var_68]
0x140074E9A: mov     [r14], rax
0x140074E9D: test    ecx, ecx
0x140074E9F: js      short loc_140074ED4
0x140074EA1: mov     rcx, [rbp+57h+var_70]
0x140074EA5: lea     rax, [rbp+57h+var_80]
0x140074EA9: mov     r9d, r13d
0x140074EAC: mov     r8, rdi
0x140074EAF: mov     edx, r15d
0x140074EB2: mov     [rsp+0B0h+var_90], rax
0x140074EB7: call    r12
0x140074EBA: test    eax, eax
0x140074EBC: js      short loc_140074ECE
0x140074EBE: cmp     [rdi+14h], ebx
0x140074EC1: movzx   eax, bl
0x140074EC4: mov     ecx, 1
0x140074EC9: cmova   eax, ecx
0x140074ECC: mov     bl, al
0x140074ECE: mov     rcx, [rbp+57h+var_70]
0x140074ED2: call    rsi
0x140074ED4: lea     r11, [rsp+0B0h+var_20]
0x140074EDC: mov     al, bl
0x140074EDE: mov     rbx, [r11+30h]
0x140074EE2: mov     rsi, [r11+38h]
0x140074EE6: mov     rdi, [r11+40h]
0x140074EEA: mov     rsp, r11
0x140074EED: pop     r15
0x140074EEF: pop     r14
0x140074EF1: pop     r13
0x140074EF3: pop     r12
0x140074EF5: pop     rbp
0x140074EF6: retn