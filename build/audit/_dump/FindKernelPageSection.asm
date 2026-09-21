# FindKernelPageSection  ea=0x140012E0C  size=662
0x140012E0C: mov     rax, rsp; 查找内核 PAGE 节。读取 PE 基址、大小和镜像基址，遍历 PE 节表查找 PAGE 节，计算其偏移和大小信息。
0x140012E0F: mov     [rax+8], rbx
0x140012E13: mov     [rax+10h], rsi
0x140012E17: mov     [rax+18h], rdi
0x140012E1B: push    rbp
0x140012E1C: push    r12
0x140012E1E: push    r13
0x140012E20: push    r14
0x140012E22: push    r15
0x140012E24: lea     rbp, [rax-0F8h]
0x140012E2B: sub     rsp, 1D0h
0x140012E32: mov     rax, cs:__security_cookie
0x140012E39: xor     rax, rsp
0x140012E3C: mov     [rbp+0F0h+var_30], rax
0x140012E43: mov     ecx, 20h ; ' '; Index
0x140012E48: xor     r13b, r13b
0x140012E4B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012E50: mov     ecx, 21h ; '!'; Index
0x140012E55: mov     r12, rax
0x140012E58: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012E5D: mov     ecx, 3; Index
0x140012E62: mov     r14, rax
0x140012E65: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012E6A: mov     ecx, 175h; Index
0x140012E6F: mov     rsi, rax
0x140012E72: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012E77: mov     rdx, rax
0x140012E7A: test    r12, r12
0x140012E7D: jz      loc_140013072
0x140012E83: test    r14d, r14d
0x140012E86: jz      loc_140013072
0x140012E8C: test    rsi, rsi
0x140012E8F: jz      loc_140013072
0x140012E95: cmp     rax, rsi
0x140012E98: jbe     loc_140013072
0x140012E9E: mov     ecx, eax
0x140012EA0: sub     ecx, esi
0x140012EA2: cmp     ecx, r14d
0x140012EA5: jnb     loc_140013072
0x140012EAB: lea     rax, [rcx+rsi]
0x140012EAF: cmp     rdx, rax
0x140012EB2: jnz     loc_140013072
0x140012EB8: add     rcx, r12
0x140012EBB: mov     edx, r12d
0x140012EBE: lea     rax, [rsp+1F0h+var_1A0]
0x140012EC3: mov     [rsp+1F0h+var_1B8], rax
0x140012EC8: and     [rsp+1F0h+var_1C0], 0
0x140012ECE: and     [rsp+1F0h+var_1C8], 0
0x140012ED4: or      dword ptr [rsp+1F0h+var_1D0], 0FFFFFFFFh
0x140012ED9: xor     r9d, r9d
0x140012EDC: sub     edx, ecx
0x140012EDE: lea     r8d, [r9+2]
0x140012EE2: add     edx, r14d
0x140012EE5: call    InitPESectionReadContext
0x140012EEA: mov     ecx, 446Bh; Index
0x140012EEF: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012EF4: xor     ebx, ebx
0x140012EF6: xor     r15d, r15d
0x140012EF9: mov     [rsp+1F0h+var_1B0], rax
0x140012EFE: lea     rdx, [rbp+0F0h+var_150]
0x140012F02: lea     rcx, [rsp+1F0h+var_1A0]
0x140012F07: mov     edi, 558h
0x140012F0C: call    ReadPESectionEntry
0x140012F11: test    eax, eax
0x140012F13: jnz     loc_140013072
0x140012F19: mov     eax, [rbp+0F0h+var_60]
0x140012F1F: mov     rcx, [rsp+1F0h+var_198]
0x140012F24: mov     r8, [rbp+0F0h+var_C8]
0x140012F28: add     rcx, rax
0x140012F2B: mov     rax, [rbp+0F0h+var_38]
0x140012F32: mov     [rsp+1F0h+var_198], rcx
0x140012F37: movzx   edx, word ptr [rax+6]
0x140012F3B: mov     eax, 461h
0x140012F40: cmp     ax, dx
0x140012F43: jnz     short loc_140012F5D
0x140012F45: cmp     r8, 80000h
0x140012F4C: jnz     short loc_140012F5D
0x140012F4E: cmp     [rbp+0F0h+var_E0], 4
0x140012F53: jnz     short loc_140012F5D
0x140012F55: mov     r13b, 1
0x140012F58: jmp     loc_140013049
0x140012F5D: mov     rax, [rbp+0F0h+var_100]
0x140012F61: cmp     di, dx
0x140012F64: jnz     short loc_140012FA9
0x140012F66: bt      rax, 1Ah
0x140012F6B: jnb     short loc_140012FA9
0x140012F6D: mov     edi, [rbp+0F0h+var_118]
0x140012F70: test    edi, edi
0x140012F72: jz      short loc_140012FA4
0x140012F74: sub     edi, r12d
0x140012F77: add     edi, ecx
0x140012F79: cmp     dword ptr [rsp+1F0h+var_1B0], edi
0x140012F7D: jz      loc_14001305A
0x140012F83: mov     ecx, 914h; Index
0x140012F88: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140012F8D: cmp     eax, 4F7Ch
0x140012F92: jnz     short loc_140012F9D
0x140012F94: test    r13b, r13b
0x140012F97: jnz     loc_140013049
0x140012F9D: mov     ebx, edi
0x140012F9F: jmp     loc_140013049
0x140012FA4: mov     edi, 558h
0x140012FA9: mov     ecx, 53Dh
0x140012FAE: cmp     cx, dx
0x140012FB1: jnz     short loc_140012FCE
0x140012FB3: cmp     r8, 800000h
0x140012FBA: jnz     short loc_140012FCE
0x140012FBC: cmp     dword ptr [rbp+0F0h+var_E0], 0Fh
0x140012FC0: jnz     short loc_140012FCE
0x140012FC2: cmp     rax, 20h ; ' '
0x140012FC6: jnz     short loc_140012FCE
0x140012FC8: cmp     [rbp+0F0h+var_F8], 1
0x140012FCC: jz      short loc_140012FF3
0x140012FCE: mov     ecx, 512h
0x140012FD3: cmp     cx, dx
0x140012FD6: jnz     short loc_140013049
0x140012FD8: cmp     rax, 20h ; ' '
0x140012FDC: jnz     short loc_140013049
0x140012FDE: cmp     [rbp+0F0h+var_F8], 1
0x140012FE2: jnz     short loc_140013049
0x140012FE4: cmp     [rbp+0F0h+var_D8], 0Fh
0x140012FE8: jnz     short loc_140013049
0x140012FEA: cmp     r8, 4041h
0x140012FF1: jnz     short loc_140013049
0x140012FF3: lea     rdx, [rbp+0F0h+var_150]
0x140012FF7: lea     rcx, [rsp+1F0h+var_1A0]
0x140012FFC: call    ReadPESectionEntry
0x140013001: test    eax, eax
0x140013003: jnz     short loc_140013049
0x140013005: mov     rax, [rbp+0F0h+var_38]
0x14001300C: cmp     di, [rax+6]
0x140013010: jz      short loc_140013043
0x140013012: mov     eax, [rbp+0F0h+var_60]
0x140013018: lea     rdx, [rbp+0F0h+var_150]
0x14001301C: lea     rcx, [rsp+1F0h+var_1A0]
0x140013021: add     [rsp+1F0h+var_198], rax
0x140013026: call    ReadPESectionEntry
0x14001302B: test    eax, eax
0x14001302D: jnz     short loc_14001303C
0x14001302F: mov     rax, [rbp+0F0h+var_38]
0x140013036: movzx   ecx, word ptr [rax+6]
0x14001303A: jmp     short loc_140013045
0x14001303C: mov     ecx, 53Dh
0x140013041: jmp     short loc_140013045
0x140013043: mov     ecx, edi
0x140013045: cmp     ecx, edi
0x140013047: jz      short loc_14001305A
0x140013049: inc     r15d
0x14001304C: cmp     r15d, 200h
0x140013053: jnb     short loc_140013072
0x140013055: jmp     loc_140012EFE
0x14001305A: test    ebx, ebx
0x14001305C: jz      short loc_140013072
0x14001305E: cmp     ebx, r14d
0x140013061: jnb     short loc_140013072
0x140013063: mov     edx, ebx
0x140013065: mov     ecx, 17Fh; Index
0x14001306A: add     rdx, rsi; Value
0x14001306D: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140013072: mov     rcx, [rbp+0F0h+var_30]
0x140013079: xor     rcx, rsp; StackCookie
0x14001307C: call    __security_check_cookie
0x140013081: lea     r11, [rsp+1F0h+var_20]
0x140013089: mov     rbx, [r11+30h]
0x14001308D: mov     rsi, [r11+38h]
0x140013091: mov     rdi, [r11+40h]
0x140013095: mov     rsp, r11
0x140013098: pop     r15
0x14001309A: pop     r14
0x14001309C: pop     r13
0x14001309E: pop     r12
0x1400130A0: pop     rbp
0x1400130A1: retn