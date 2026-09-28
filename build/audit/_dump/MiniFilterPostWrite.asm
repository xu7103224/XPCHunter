# MiniFilterPostWrite  ea=0x140014D08  size=474
0x140014D08: mov     [rsp+arg_0], rbx; Minifilter 写后回调。遍历 PE 节表查找 PostWrite 相关节，匹配已存在的偏移量，写入全局表 GT 索引 0x1A4 和 0x179。
0x140014D0D: mov     [rsp+arg_8], rbp
0x140014D12: mov     [rsp+arg_10], rsi
0x140014D17: push    rdi
0x140014D18: push    r12
0x140014D1A: push    r13
0x140014D1C: push    r14
0x140014D1E: push    r15
0x140014D20: sub     rsp, 1C0h
0x140014D27: mov     rax, cs:__security_cookie
0x140014D2E: xor     rax, rsp
0x140014D31: mov     [rsp+1E8h+var_38], rax
0x140014D39: mov     ecx, 20h ; ' '; Index
0x140014D3E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014D43: mov     ecx, 21h ; '!'; Index
0x140014D48: mov     rbp, rax
0x140014D4B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014D50: mov     ecx, 3; Index
0x140014D55: mov     rdi, rax
0x140014D58: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014D5D: mov     r14, rax
0x140014D60: call    ScanFileForPeSectionInfo
0x140014D65: mov     ecx, 439Fh; Index
0x140014D6A: movsxd  rbx, eax
0x140014D6D: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014D72: mov     ecx, 41C5h; Index
0x140014D77: mov     r12, rax
0x140014D7A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014D7F: mov     r15, rax
0x140014D82: test    rbp, rbp
0x140014D85: jz      loc_140014E83
0x140014D8B: test    edi, edi
0x140014D8D: jz      loc_140014E83
0x140014D93: test    r14, r14
0x140014D96: jz      loc_140014E83
0x140014D9C: test    ebx, ebx
0x140014D9E: jle     loc_140014E83
0x140014DA4: cmp     ebx, edi
0x140014DA6: jnb     loc_140014E83
0x140014DAC: test    r12d, r12d
0x140014DAF: jz      loc_140014E83
0x140014DB5: test    eax, eax
0x140014DB7: jz      loc_140014E83
0x140014DBD: movsxd  rax, dword ptr [rbp+3Ch]
0x140014DC1: lea     rcx, [rbx+rbp]
0x140014DC5: mov     edx, ebp
0x140014DC7: mov     r13, [rax+rbp+30h]
0x140014DCC: lea     rax, [rsp+1E8h+var_1A8]
0x140014DD1: xor     r9d, r9d
0x140014DD4: mov     [rsp+1E8h+var_1B0], rax
0x140014DD9: and     [rsp+1E8h+var_1B8], 0
0x140014DDF: and     [rsp+1E8h+var_1C0], 0
0x140014DE5: or      [rsp+1E8h+var_1C8], 0FFFFFFFFh
0x140014DEA: sub     edx, ecx
0x140014DEC: lea     r8d, [r9+2]
0x140014DF0: add     edx, edi
0x140014DF2: call    InitPESectionReadContext
0x140014DF7: xor     ebx, ebx
0x140014DF9: xor     esi, esi
0x140014DFB: lea     rdx, [rsp+1E8h+var_158]
0x140014E03: lea     rcx, [rsp+1E8h+var_1A8]
0x140014E08: call    ReadPESectionEntry
0x140014E0D: test    eax, eax
0x140014E0F: jnz     short loc_140014E83
0x140014E11: mov     eax, [rsp+1E8h+var_68]
0x140014E18: mov     rcx, [rsp+1E8h+var_1A0]
0x140014E1D: mov     edx, 558h
0x140014E22: add     rcx, rax
0x140014E25: mov     rax, [rsp+1E8h+var_40]
0x140014E2D: mov     [rsp+1E8h+var_1A0], rcx
0x140014E32: cmp     dx, [rax+6]
0x140014E36: jnz     short loc_140014EB4
0x140014E38: test    [rsp+1E8h+var_108], 4000000h
0x140014E44: jz      short loc_140014EB4
0x140014E46: mov     eax, [rsp+1E8h+var_120]
0x140014E4D: test    eax, eax
0x140014E4F: jz      short loc_140014EB4
0x140014E51: sub     eax, ebp
0x140014E53: add     eax, ecx
0x140014E55: cmp     eax, r12d
0x140014E58: jz      short loc_140014E5F
0x140014E5A: cmp     eax, r15d
0x140014E5D: jnz     short loc_140014ED3
0x140014E5F: test    ebx, ebx
0x140014E61: jz      short loc_140014ED3
0x140014E63: cmp     ebx, edi
0x140014E65: jnb     short loc_140014ED3
0x140014E67: lea     rdx, [rbx+r13]; Value
0x140014E6B: mov     ecx, 1A4h; Index
0x140014E70: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014E75: lea     rdx, [rbx+r14]; Value
0x140014E79: mov     ecx, 179h; Index
0x140014E7E: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014E83: mov     rcx, [rsp+1E8h+var_38]
0x140014E8B: xor     rcx, rsp; StackCookie
0x140014E8E: call    __security_check_cookie
0x140014E93: lea     r11, [rsp+1E8h+var_28]
0x140014E9B: mov     rbx, [r11+30h]
0x140014E9F: mov     rbp, [r11+38h]
0x140014EA3: mov     rsi, [r11+40h]
0x140014EA7: mov     rsp, r11
0x140014EAA: pop     r15
0x140014EAC: pop     r14
0x140014EAE: pop     r13
0x140014EB0: pop     r12
0x140014EB2: pop     rdi
0x140014EB3: retn
0x140014EB4: cmp     [rsp+1E8h+var_D0], 40000h
0x140014EC0: jnz     short loc_140014ED3
0x140014EC2: mov     eax, [rsp+1E8h+var_E0]
0x140014EC9: test    eax, eax
0x140014ECB: jz      short loc_140014ED3
0x140014ECD: mov     ebx, eax
0x140014ECF: sub     ebx, ebp
0x140014ED1: add     ebx, ecx
0x140014ED3: inc     esi
0x140014ED5: cmp     esi, 100h
0x140014EDB: jnb     short loc_140014E83
0x140014EDD: jmp     loc_140014DFB