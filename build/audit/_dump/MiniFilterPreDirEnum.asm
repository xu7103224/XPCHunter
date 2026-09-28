# MiniFilterPreDirEnum  ea=0x140015A48  size=1257
0x140015A48: mov     rax, rsp; Minifilter 目录枚举回调。处理目录枚举前的 Minifilter 回调逻辑（反编译失败，约 0x4E9 字节）。
0x140015A4B: mov     [rax+8], rbx
0x140015A4F: mov     [rax+10h], rsi
0x140015A53: mov     [rax+18h], rdi
0x140015A57: push    rbp
0x140015A58: push    r12
0x140015A5A: push    r13
0x140015A5C: push    r14
0x140015A5E: push    r15
0x140015A60: lea     rbp, [rax-118h]
0x140015A67: sub     rsp, 1F0h
0x140015A6E: mov     rax, cs:__security_cookie
0x140015A75: xor     rax, rsp
0x140015A78: mov     [rbp+110h+var_30], rax
0x140015A7F: mov     ecx, 20h ; ' '; Index
0x140015A84: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015A89: mov     ecx, 21h ; '!'; Index
0x140015A8E: mov     r12, rax
0x140015A91: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015A96: mov     ecx, 3; Index
0x140015A9B: mov     r14, rax
0x140015A9E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015AA3: mov     r13, rax
0x140015AA6: mov     [rsp+210h+var_1B8], rax
0x140015AAB: test    r12, r12
0x140015AAE: jz      loc_140015F01
0x140015AB4: test    r14d, r14d
0x140015AB7: jz      loc_140015F01
0x140015ABD: test    rax, rax
0x140015AC0: jz      loc_140015F01
0x140015AC6: mov     eax, r14d
0x140015AC9: lea     r8, [rsp+210h+var_1C8]
0x140015ACE: mov     edx, r14d
0x140015AD1: add     rax, r12
0x140015AD4: mov     rcx, r12
0x140015AD7: mov     dword ptr [rsp+210h+var_1C8], 4741502Eh
0x140015ADF: mov     [rsp+210h+var_1B0], rax
0x140015AE4: mov     dword ptr [rsp+210h+var_1C8+4], 45h ; 'E'
0x140015AEC: call    FindPESectionByName; 按名称查找 PE 节。遍历节表，返回匹配节名的节在文件中的偏移。
0x140015AF1: cmp     eax, r14d
0x140015AF4: lea     r8, [rsp+210h+var_1C8]
0x140015AF9: mov     edx, r14d
0x140015AFC: sbb     ebx, ebx
0x140015AFE: mov     rcx, r12
0x140015B01: and     ebx, eax
0x140015B03: call    FindPESectionByNameReturnVa; 按名称查找 PE 节返回 VA。遍历节表，返回匹配节名的虚拟地址。
0x140015B08: mov     ecx, eax
0x140015B0A: test    eax, eax
0x140015B0C: jnz     short loc_140015B13
0x140015B0E: mov     ecx, r14d
0x140015B11: sub     ecx, ebx
0x140015B13: mov     eax, r14d
0x140015B16: lea     rsi, [rbx+r12]
0x140015B1A: sub     eax, ebx
0x140015B1C: cmp     ecx, eax
0x140015B1E: cmova   ecx, eax
0x140015B21: xor     dil, dil
0x140015B24: xor     r9b, r9b
0x140015B27: xor     r8b, r8b
0x140015B2A: xor     dl, dl
0x140015B2C: mov     r15d, ecx
0x140015B2F: mov     eax, ebx
0x140015B31: mov     byte ptr [rsp+210h+var_1D0+3], dil
0x140015B36: mov     byte ptr [rsp+210h+var_1D0+2], r9b
0x140015B3B: add     r15, rax
0x140015B3E: mov     byte ptr [rsp+210h+var_1D0+1], r8b
0x140015B43: mov     byte ptr [rsp+210h+var_1D0], dl
0x140015B47: add     r15, r12
0x140015B4A: mov     [rsp+210h+var_1C0], r15
0x140015B4F: cmp     rsi, r15
0x140015B52: jnb     loc_140015F01
0x140015B58: mov     r10d, 1
0x140015B5E: lea     rax, [rsi+30h]
0x140015B62: cmp     rax, r15
0x140015B65: jnb     loc_140015EF5
0x140015B6B: mov     al, [rsi]
0x140015B6D: cmp     al, 48h ; 'H'
0x140015B6F: jnz     loc_140015EF5
0x140015B75: cmp     byte ptr [rsi+1], 8Dh
0x140015B79: jnz     loc_140015DB3
0x140015B7F: mov     edx, [rsi+3]
0x140015B82: mov     ecx, esi
0x140015B84: add     edx, 7
0x140015B87: sub     ecx, r12d
0x140015B8A: add     edx, ecx; Value
0x140015B8C: jz      loc_140015EEA
0x140015B92: cmp     edx, r14d
0x140015B95: jnb     loc_140015EEA
0x140015B9B: test    dil, dil
0x140015B9E: jnz     loc_140015C24
0x140015BA4: cmp     byte ptr [rsi+0Dh], 8
0x140015BA8: jnz     short loc_140015C24
0x140015BAA: cmp     [rsi+0Eh], al
0x140015BAD: jnz     short loc_140015C24
0x140015BAF: cmp     byte ptr [rsi+0Fh], 8Dh
0x140015BB3: jnz     short loc_140015C24
0x140015BB5: cmp     byte ptr [rsi+18h], 10h
0x140015BB9: jnz     short loc_140015C24
0x140015BBB: mov     eax, [rsi+11h]
0x140015BBE: lea     ebx, [rsi+15h]
0x140015BC1: sub     eax, r12d
0x140015BC4: add     ebx, eax
0x140015BC6: cmp     edx, r14d
0x140015BC9: jnb     loc_140015EEA
0x140015BCF: cmp     ebx, r14d
0x140015BD2: jnb     loc_140015EEA
0x140015BD8: mov     ecx, 32Eh; Index
0x140015BDD: mov     edi, edx
0x140015BDF: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015BE4: mov     edx, ebx; Value
0x140015BE6: mov     ecx, 330h; Index
0x140015BEB: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015BF0: lea     rdx, [rdi+r13]; Value
0x140015BF4: mov     ecx, 32Fh; Index
0x140015BF9: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015BFE: lea     rdx, [rbx+r13]; Value
0x140015C02: mov     ecx, 331h; Index
0x140015C07: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015C0C: mov     r9b, byte ptr [rsp+210h+var_1D0+2]
0x140015C11: mov     r8d, 1
0x140015C17: mov     dil, r8b
0x140015C1A: mov     byte ptr [rsp+210h+var_1D0+3], r8b
0x140015C1F: jmp     loc_140015D31
0x140015C24: test    r9b, r9b
0x140015C27: jnz     short loc_140015C82
0x140015C29: cmp     byte ptr [rsi+7], 48h ; 'H'
0x140015C2D: jnz     short loc_140015C82
0x140015C2F: cmp     byte ptr [rsi+8], 89h
0x140015C33: jnz     short loc_140015C82
0x140015C35: cmp     byte ptr [rsi+0Ah], 8
0x140015C39: jnz     short loc_140015C82
0x140015C3B: cmp     dword ptr [rsi+11h], 0A0h
0x140015C42: jnz     short loc_140015C82
0x140015C44: test    edx, edx
0x140015C46: jz      loc_140015D22
0x140015C4C: cmp     edx, r14d
0x140015C4F: jnb     loc_140015D22
0x140015C55: mov     ecx, 332h; Index
0x140015C5A: mov     ebx, edx
0x140015C5C: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015C61: lea     rdx, [rbx+r13]; Value
0x140015C65: mov     ecx, 333h; Index
0x140015C6A: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015C6F: mov     r8d, 1
0x140015C75: mov     r9b, r8b
0x140015C78: mov     byte ptr [rsp+210h+var_1D0+2], r8b
0x140015C7D: jmp     loc_140015D17
0x140015C82: test    r8b, r8b
0x140015C85: jnz     loc_140015D22
0x140015C8B: lea     rcx, [rsi+7]
0x140015C8F: cmp     byte ptr [rcx], 41h ; 'A'
0x140015C92: jnz     loc_140015D22
0x140015C98: cmp     byte ptr [rsi+8], 0F6h
0x140015C9C: jnz     loc_140015D22
0x140015CA2: mov     edx, dword ptr [rsp+210h+var_1B0]
0x140015CA6: lea     rax, [rsp+210h+var_1A0]
0x140015CAB: xor     r9d, r9d
0x140015CAE: mov     qword ptr [rsp+210h+var_1D8], rax
0x140015CB3: and     [rsp+210h+var_1E0], 0
0x140015CB9: and     [rsp+210h+var_1E8], 0
0x140015CBF: or      dword ptr [rsp+210h+var_1F0], 0FFFFFFFFh
0x140015CC4: sub     edx, esi
0x140015CC6: lea     r8d, [r9+2]
0x140015CCA: sub     edx, 7
0x140015CCD: call    InitPESectionReadContext
0x140015CD2: xor     ebx, ebx
0x140015CD4: lea     rdx, [rbp+110h+var_150]
0x140015CD8: lea     rcx, [rsp+210h+var_1A0]
0x140015CDD: call    ReadPESectionEntry
0x140015CE2: test    eax, eax
0x140015CE4: jnz     short loc_140015D12
0x140015CE6: mov     eax, [rbp+110h+var_60]
0x140015CEC: add     [rsp+210h+var_198], rax
0x140015CF1: cmp     [rbp+110h+var_C8], 800000h
0x140015CF9: jnz     short loc_140015D04
0x140015CFB: cmp     [rbp+110h+var_E0], 1000h
0x140015D02: jz      short loc_140015D60
0x140015D04: mov     r8d, 1
0x140015D0A: add     ebx, r8d
0x140015D0D: cmp     ebx, 0Ah
0x140015D10: jb      short loc_140015CD4
0x140015D12: mov     r9b, byte ptr [rsp+210h+var_1D0+2]
0x140015D17: mov     r8b, byte ptr [rsp+210h+var_1D0+1]
0x140015D1C: mov     r10d, 1
0x140015D22: cmp     dil, r10b
0x140015D25: jnz     loc_140015EEA
0x140015D2B: mov     r8d, 1
0x140015D31: mov     dl, byte ptr [rsp+210h+var_1D0]
0x140015D35: cmp     r9b, r8b
0x140015D38: mov     r8b, byte ptr [rsp+210h+var_1D0+1]
0x140015D3D: mov     r10d, 1
0x140015D43: jnz     loc_140015EF5
0x140015D49: cmp     r8b, r10b
0x140015D4C: jnz     loc_140015EF5
0x140015D52: cmp     dl, r10b
0x140015D55: jz      loc_140015F01
0x140015D5B: jmp     loc_140015EF5
0x140015D60: mov     edx, [rsi+3]
0x140015D63: mov     ecx, esi
0x140015D65: add     edx, 7
0x140015D68: sub     ecx, r12d
0x140015D6B: add     edx, ecx; Value
0x140015D6D: jz      short loc_140015D9E
0x140015D6F: cmp     edx, r14d
0x140015D72: jnb     short loc_140015D12
0x140015D74: mov     ecx, 334h; Index
0x140015D79: mov     ebx, edx
0x140015D7B: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015D80: lea     rdx, [rbx+r13]; Value
0x140015D84: mov     ecx, 335h; Index
0x140015D89: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015D8E: mov     r10d, 1
0x140015D94: mov     r8b, r10b
0x140015D97: mov     byte ptr [rsp+210h+var_1D0+1], r10b
0x140015D9C: jmp     short loc_140015DA9
0x140015D9E: mov     r8b, byte ptr [rsp+210h+var_1D0+1]
0x140015DA3: mov     r10d, 1
0x140015DA9: mov     r9b, byte ptr [rsp+210h+var_1D0+2]
0x140015DAE: jmp     loc_140015D22
0x140015DB3: cmp     al, 48h ; 'H'
0x140015DB5: jnz     loc_140015EF5
0x140015DBB: cmp     byte ptr [rsi+1], 8Bh
0x140015DBF: jnz     loc_140015EF5
0x140015DC5: mov     eax, [rsi+3]
0x140015DC8: lea     edi, [rsi+7]
0x140015DCB: sub     eax, r12d
0x140015DCE: add     edi, eax
0x140015DD0: jz      loc_140015EF0
0x140015DD6: cmp     edi, r14d
0x140015DD9: jnb     loc_140015EF0
0x140015DDF: test    dl, dl
0x140015DE1: jnz     loc_140015EB5
0x140015DE7: mov     edx, dword ptr [rsp+210h+var_1B0]
0x140015DEB: lea     rax, [rsp+210h+var_1A0]
0x140015DF0: xor     r9d, r9d
0x140015DF3: mov     qword ptr [rsp+210h+var_1D8], rax
0x140015DF8: and     [rsp+210h+var_1E0], 0
0x140015DFE: and     [rsp+210h+var_1E8], 0
0x140015E04: or      dword ptr [rsp+210h+var_1F0], 0FFFFFFFFh
0x140015E09: sub     edx, esi
0x140015E0B: lea     rcx, [rsi+7]
0x140015E0F: lea     r8d, [r9+2]
0x140015E13: sub     edx, 7
0x140015E16: xor     r13b, r13b
0x140015E19: xor     bl, bl
0x140015E1B: call    InitPESectionReadContext
0x140015E20: xor     r15d, r15d
0x140015E23: lea     rdx, [rbp+110h+var_150]
0x140015E27: lea     rcx, [rsp+210h+var_1A0]
0x140015E2C: call    ReadPESectionEntry
0x140015E31: test    eax, eax
0x140015E33: jnz     short loc_140015E97
0x140015E35: mov     eax, [rbp+110h+var_60]
0x140015E3B: add     [rsp+210h+var_198], rax
0x140015E40: mov     rax, [rbp+110h+var_C8]
0x140015E44: bt      rax, 10h
0x140015E49: jnb     short loc_140015E6A
0x140015E4B: mov     ecx, 336h; Index
0x140015E50: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015E55: mov     ecx, [rbp+110h+var_D8]
0x140015E58: add     eax, ecx
0x140015E5A: jnz     short loc_140015E64
0x140015E5C: lea     edx, [rax+1]
0x140015E5F: mov     r13b, dl
0x140015E62: jmp     short loc_140015E8A
0x140015E64: mov     rax, [rbp+110h+var_C8]
0x140015E68: jmp     short loc_140015E6D
0x140015E6A: mov     ecx, [rbp+110h+var_D8]
0x140015E6D: mov     edx, 1
0x140015E72: bt      rax, 10h
0x140015E77: jnb     short loc_140015E85
0x140015E79: movzx   ebx, bl
0x140015E7C: cmp     ecx, 0BC0h
0x140015E82: cmovz   ebx, edx
0x140015E85: cmp     r13b, dl
0x140015E88: jnz     short loc_140015E8E
0x140015E8A: cmp     bl, dl
0x140015E8C: jz      short loc_140015EC7
0x140015E8E: add     r15d, edx
0x140015E91: cmp     r15d, 0Ah
0x140015E95: jb      short loc_140015E23
0x140015E97: mov     dl, byte ptr [rsp+210h+var_1D0]
0x140015E9B: mov     r13, [rsp+210h+var_1B8]
0x140015EA0: mov     r15, [rsp+210h+var_1C0]
0x140015EA5: mov     r8b, byte ptr [rsp+210h+var_1D0+1]
0x140015EAA: mov     r9b, byte ptr [rsp+210h+var_1D0+2]
0x140015EAF: mov     r10d, 1
0x140015EB5: mov     dil, byte ptr [rsp+210h+var_1D0+3]
0x140015EBA: cmp     dil, r10b
0x140015EBD: jnz     short loc_140015EF5
0x140015EBF: cmp     r9b, r10b
0x140015EC2: jmp     loc_140015D43
0x140015EC7: mov     r13, [rsp+210h+var_1B8]
0x140015ECC: mov     edx, edi
0x140015ECE: mov     ecx, 337h; Index
0x140015ED3: add     rdx, r13; Value
0x140015ED6: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015EDB: mov     r8d, 1
0x140015EE1: mov     dl, r8b
0x140015EE4: mov     byte ptr [rsp+210h+var_1D0], dl
0x140015EE8: jmp     short loc_140015EA0
0x140015EEA: mov     dl, byte ptr [rsp+210h+var_1D0]
0x140015EEE: jmp     short loc_140015EF5
0x140015EF0: mov     dil, byte ptr [rsp+210h+var_1D0+3]
0x140015EF5: add     rsi, r10
0x140015EF8: cmp     rsi, r15
0x140015EFB: jb      loc_140015B5E
0x140015F01: mov     rcx, [rbp+110h+var_30]
0x140015F08: xor     rcx, rsp; StackCookie
0x140015F0B: call    __security_check_cookie
0x140015F10: lea     r11, [rsp+210h+var_20]
0x140015F18: mov     rbx, [r11+30h]
0x140015F1C: mov     rsi, [r11+38h]
0x140015F20: mov     rdi, [r11+40h]
0x140015F24: mov     rsp, r11
0x140015F27: pop     r15
0x140015F29: pop     r14
0x140015F2B: pop     r13
0x140015F2D: pop     r12
0x140015F2F: pop     rbp
0x140015F30: retn