# ParseMiniFilterDataSection  ea=0x140014ACC  size=530
0x140014ACC: mov     rax, rsp; 解析 Minifilter 数据节。解析 Minifilter 驱动的数据节信息，提取回调相关的偏移量。
0x140014ACF: mov     [rax+8], rbx
0x140014AD3: mov     [rax+10h], rsi
0x140014AD7: mov     [rax+18h], rdi
0x140014ADB: mov     [rax+20h], r12
0x140014ADF: push    rbp
0x140014AE0: push    r14
0x140014AE2: push    r15
0x140014AE4: lea     rbp, [rax-0D8h]
0x140014AEB: sub     rsp, 1C0h
0x140014AF2: mov     rax, cs:__security_cookie
0x140014AF9: xor     rax, rsp
0x140014AFC: mov     [rbp+0D0h+var_20], rax
0x140014B03: mov     ecx, 20h ; ' '; Index
0x140014B08: xor     r14b, r14b
0x140014B0B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014B10: mov     ecx, 21h ; '!'; Index
0x140014B15: mov     r12, rax
0x140014B18: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014B1D: mov     ecx, 3; Index
0x140014B22: mov     rsi, rax
0x140014B25: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014B2A: mov     ecx, 174h; Index
0x140014B2F: mov     rdi, rax
0x140014B32: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014B37: mov     rdx, rax
0x140014B3A: test    r12, r12
0x140014B3D: jz      loc_140014CAE
0x140014B43: test    esi, esi
0x140014B45: jz      loc_140014CAE
0x140014B4B: test    rdi, rdi
0x140014B4E: jz      loc_140014CAE
0x140014B54: cmp     rax, rdi
0x140014B57: jbe     loc_140014CAE
0x140014B5D: mov     ecx, eax
0x140014B5F: sub     ecx, edi
0x140014B61: cmp     ecx, esi
0x140014B63: jnb     loc_140014CAE
0x140014B69: lea     rax, [rcx+rdi]
0x140014B6D: cmp     rdx, rax
0x140014B70: jnz     loc_140014CAE
0x140014B76: add     rcx, r12
0x140014B79: mov     edx, r12d
0x140014B7C: lea     rax, [rsp+1D0h+var_190]
0x140014B81: mov     qword ptr [rsp+1D0h+var_198], rax
0x140014B86: and     [rsp+1D0h+var_1A0], 0
0x140014B8C: and     [rsp+1D0h+var_1A8], 0
0x140014B92: or      dword ptr [rsp+1D0h+var_1B0], 0FFFFFFFFh
0x140014B97: xor     r9d, r9d
0x140014B9A: sub     edx, ecx
0x140014B9C: lea     r8d, [r9+2]
0x140014BA0: add     edx, esi
0x140014BA2: call    InitPESectionReadContext
0x140014BA7: xor     ebx, ebx
0x140014BA9: xor     r15d, r15d
0x140014BAC: lea     rdx, [rbp+0D0h+var_140]
0x140014BB0: lea     rcx, [rsp+1D0h+var_190]
0x140014BB5: call    ReadPESectionEntry
0x140014BBA: test    eax, eax
0x140014BBC: jnz     loc_140014CAE
0x140014BC2: mov     eax, [rbp+0D0h+var_50]
0x140014BC8: add     [rsp+1D0h+var_188], rax
0x140014BCD: mov     rax, [rbp+0D0h+var_28]
0x140014BD4: movzx   ecx, word ptr [rax+6]
0x140014BD8: mov     eax, 43Eh
0x140014BDD: cmp     ax, cx
0x140014BE0: jnz     short loc_140014BFB
0x140014BE2: cmp     [rbp+0D0h+var_B8], 80000h
0x140014BEA: jnz     short loc_140014BFB
0x140014BEC: cmp     [rbp+0D0h+var_D0], 2
0x140014BF1: jnz     short loc_140014BFB
0x140014BF3: mov     r14b, 1
0x140014BF6: jmp     loc_140014C86
0x140014BFB: mov     eax, 558h
0x140014C00: cmp     ax, cx
0x140014C03: jnz     short loc_140014C3B
0x140014C05: test    [rbp+0D0h+var_F0], 4000000h
0x140014C0D: jz      short loc_140014C3B
0x140014C0F: cmp     [rbp+0D0h+var_108], 0
0x140014C13: jz      short loc_140014C3B
0x140014C15: mov     ecx, 914h; Index
0x140014C1A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014C1F: cmp     eax, 4F7Ch
0x140014C24: jnz     short loc_140014C2C
0x140014C26: cmp     r14b, 1
0x140014C2A: jnz     short loc_140014C36
0x140014C2C: mov     ebx, [rbp+0D0h+var_108]
0x140014C2F: sub     ebx, r12d
0x140014C32: add     ebx, dword ptr [rsp+1D0h+var_188]
0x140014C36: xor     r14b, r14b
0x140014C39: jmp     short loc_140014C86
0x140014C3B: mov     eax, 53Dh
0x140014C40: cmp     ax, cx
0x140014C43: jnz     short loc_140014C86
0x140014C45: cmp     [rbp+0D0h+var_B8], 800000h
0x140014C4D: jnz     short loc_140014C86
0x140014C4F: cmp     dword ptr [rbp+0D0h+var_D0], 10h
0x140014C53: jnz     short loc_140014C86
0x140014C55: cmp     [rbp+0D0h+var_F0], 20h ; ' '
0x140014C5A: jnz     short loc_140014C86
0x140014C5C: cmp     [rbp+0D0h+var_E8], 1
0x140014C60: jnz     short loc_140014C86
0x140014C62: lea     rdx, [rbp+0D0h+var_140]
0x140014C66: lea     rcx, [rsp+1D0h+var_190]
0x140014C6B: call    ReadPESectionEntry
0x140014C70: test    eax, eax
0x140014C72: jnz     short loc_140014C86
0x140014C74: mov     rax, [rbp+0D0h+var_28]
0x140014C7B: mov     ecx, 558h
0x140014C80: cmp     cx, [rax+6]
0x140014C84: jz      short loc_140014C97
0x140014C86: inc     r15d
0x140014C89: cmp     r15d, 200h
0x140014C90: jnb     short loc_140014CAE
0x140014C92: jmp     loc_140014BAC
0x140014C97: test    ebx, ebx
0x140014C99: jz      short loc_140014CAE
0x140014C9B: cmp     ebx, esi
0x140014C9D: jnb     short loc_140014CAE
0x140014C9F: mov     edx, ebx
0x140014CA1: mov     ecx, 17Eh; Index
0x140014CA6: add     rdx, rdi; Value
0x140014CA9: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014CAE: mov     rcx, [rbp+0D0h+var_20]
0x140014CB5: xor     rcx, rsp; StackCookie
0x140014CB8: call    __security_check_cookie
0x140014CBD: lea     r11, [rsp+1D0h+var_10]
0x140014CC5: mov     rbx, [r11+20h]
0x140014CC9: mov     rsi, [r11+28h]
0x140014CCD: mov     rdi, [r11+30h]
0x140014CD1: mov     r12, [r11+38h]
0x140014CD5: mov     rsp, r11
0x140014CD8: pop     r15
0x140014CDA: pop     r14
0x140014CDC: pop     rbp
0x140014CDD: retn