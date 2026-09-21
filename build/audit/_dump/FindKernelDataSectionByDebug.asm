# FindKernelDataSectionByDebug  ea=0x140013E6C  size=454
0x140013E6C: mov     rax, rsp; 通过 DEBUG 节查找内核数据节。解析 PE 的 DEBUG 目录信息，定位数据节范围。
0x140013E6F: mov     [rax+8], rbx
0x140013E73: mov     [rax+10h], rsi
0x140013E77: mov     [rax+18h], rdi
0x140013E7B: push    rbp
0x140013E7C: push    r14
0x140013E7E: push    r15
0x140013E80: lea     rbp, [rax-0D8h]
0x140013E87: sub     rsp, 1C0h
0x140013E8E: mov     rax, cs:__security_cookie
0x140013E95: xor     rax, rsp
0x140013E98: mov     [rbp+0D0h+var_20], rax
0x140013E9F: mov     ecx, 914h; Index
0x140013EA4: xor     r14b, r14b
0x140013EA7: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013EAC: cmp     eax, 1770h
0x140013EB1: jb      loc_140014006
0x140013EB7: mov     ecx, 20h ; ' '; Index
0x140013EBC: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013EC1: mov     ecx, 21h ; '!'; Index
0x140013EC6: mov     r15, rax
0x140013EC9: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013ECE: mov     ecx, 3; Index
0x140013ED3: mov     rdi, rax
0x140013ED6: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013EDB: mov     ecx, 16Eh; Index
0x140013EE0: mov     rbx, rax
0x140013EE3: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013EE8: mov     rdx, rax
0x140013EEB: test    r15, r15
0x140013EEE: jz      loc_140014006
0x140013EF4: test    edi, edi
0x140013EF6: jz      loc_140014006
0x140013EFC: test    rbx, rbx
0x140013EFF: jz      loc_140014006
0x140013F05: cmp     rax, rbx
0x140013F08: jbe     loc_140014006
0x140013F0E: mov     ecx, eax
0x140013F10: sub     ecx, ebx
0x140013F12: cmp     ecx, edi
0x140013F14: jnb     loc_140014006
0x140013F1A: lea     rax, [rcx+rbx]
0x140013F1E: cmp     rdx, rax
0x140013F21: jnz     loc_140014006
0x140013F27: add     rcx, r15
0x140013F2A: mov     edx, r15d
0x140013F2D: lea     rax, [rsp+1D0h+var_190]
0x140013F32: mov     qword ptr [rsp+1D0h+var_198], rax
0x140013F37: and     [rsp+1D0h+var_1A0], 0
0x140013F3D: and     [rsp+1D0h+var_1A8], 0
0x140013F43: or      dword ptr [rsp+1D0h+var_1B0], 0FFFFFFFFh
0x140013F48: xor     r9d, r9d
0x140013F4B: sub     edx, ecx
0x140013F4D: lea     r8d, [r9+2]
0x140013F51: add     edx, edi
0x140013F53: call    InitPESectionReadContext
0x140013F58: xor     esi, esi
0x140013F5A: lea     rdx, [rbp+0D0h+var_140]
0x140013F5E: lea     rcx, [rsp+1D0h+var_190]
0x140013F63: call    ReadPESectionEntry
0x140013F68: test    eax, eax
0x140013F6A: jnz     loc_140014006
0x140013F70: mov     eax, [rbp+0D0h+var_50]
0x140013F76: mov     rcx, [rsp+1D0h+var_188]
0x140013F7B: add     rcx, rax
0x140013F7E: mov     rax, [rbp+0D0h+var_28]
0x140013F85: mov     [rsp+1D0h+var_188], rcx
0x140013F8A: movzx   edx, word ptr [rax+6]
0x140013F8E: mov     eax, 545h
0x140013F93: cmp     ax, dx
0x140013F96: jz      short loc_140014006
0x140013F98: mov     eax, 4D7h
0x140013F9D: cmp     ax, dx
0x140013FA0: jnz     short loc_140013FC1
0x140013FA2: cmp     [rbp+0D0h+var_F0], 20h ; ' '
0x140013FA7: jnz     short loc_140013FC1
0x140013FA9: cmp     [rbp+0D0h+var_E8], 9
0x140013FAD: jnz     short loc_140013FC1
0x140013FAF: cmp     [rbp+0D0h+var_B8], 20h ; ' '
0x140013FB4: jnz     short loc_140013FC1
0x140013FB6: cmp     [rbp+0D0h+var_B0], 9
0x140013FBA: jnz     short loc_140013FC1
0x140013FBC: mov     r14b, 1
0x140013FBF: jmp     short loc_140013FE2
0x140013FC1: mov     eax, 558h
0x140013FC6: cmp     ax, dx
0x140013FC9: jnz     short loc_140013FE2
0x140013FCB: test    [rbp+0D0h+var_F0], 4000000h
0x140013FD3: jz      short loc_140013FE2
0x140013FD5: mov     eax, [rbp+0D0h+var_108]
0x140013FD8: test    eax, eax
0x140013FDA: jz      short loc_140013FE2
0x140013FDC: cmp     r14b, 1
0x140013FE0: jz      short loc_140013FEE
0x140013FE2: inc     esi
0x140013FE4: cmp     esi, 64h ; 'd'
0x140013FE7: jnb     short loc_140014006
0x140013FE9: jmp     loc_140013F5A
0x140013FEE: sub     eax, r15d
0x140013FF1: add     eax, ecx
0x140013FF3: cmp     eax, edi
0x140013FF5: jnb     short loc_140014006
0x140013FF7: mov     edx, eax
0x140013FF9: mov     ecx, 184h; Index
0x140013FFE: add     rdx, rbx; Value
0x140014001: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014006: mov     rcx, [rbp+0D0h+var_20]
0x14001400D: xor     rcx, rsp; StackCookie
0x140014010: call    __security_check_cookie
0x140014015: lea     r11, [rsp+1D0h+var_10]
0x14001401D: mov     rbx, [r11+20h]
0x140014021: mov     rsi, [r11+28h]
0x140014025: mov     rdi, [r11+30h]
0x140014029: mov     rsp, r11
0x14001402C: pop     r15
0x14001402E: pop     r14
0x140014030: pop     rbp
0x140014031: retn