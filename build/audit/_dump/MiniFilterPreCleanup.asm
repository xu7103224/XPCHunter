# MiniFilterPreCleanup  ea=0x140014EE4  size=509
0x140014EE4: mov     [rsp+arg_0], rbx; Minifilter 预清理回调。遍历 PE 节表查找预清理相关节偏移，匹配已存在的后写偏移量，写入全局表 GT 索引 0x1A4 和 0x179。
0x140014EE9: mov     [rsp+arg_8], rbp
0x140014EEE: mov     [rsp+arg_10], rsi
0x140014EF3: push    rdi
0x140014EF4: push    r12
0x140014EF6: push    r13
0x140014EF8: push    r14
0x140014EFA: push    r15
0x140014EFC: sub     rsp, 1C0h
0x140014F03: mov     rax, cs:__security_cookie
0x140014F0A: xor     rax, rsp
0x140014F0D: mov     [rsp+1E8h+var_38], rax
0x140014F15: mov     ecx, 20h ; ' '; Index
0x140014F1A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F1F: mov     ecx, 21h ; '!'; Index
0x140014F24: mov     r14, rax
0x140014F27: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F2C: mov     ecx, 3; Index
0x140014F31: mov     rsi, rax
0x140014F34: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F39: mov     ecx, 170h; Index
0x140014F3E: mov     rdi, rax
0x140014F41: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F46: mov     ecx, 439Fh; Index
0x140014F4B: mov     rbx, rax
0x140014F4E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F53: mov     ecx, 41C5h; Index
0x140014F58: mov     r12, rax
0x140014F5B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014F60: mov     r15, rax
0x140014F63: test    r14, r14
0x140014F66: jz      loc_140015081
0x140014F6C: test    esi, esi
0x140014F6E: jz      loc_140015081
0x140014F74: test    rdi, rdi
0x140014F77: jz      loc_140015081
0x140014F7D: test    rbx, rbx
0x140014F80: jz      loc_140015081
0x140014F86: cmp     rbx, rdi
0x140014F89: jbe     loc_140015081
0x140014F8F: test    r12d, r12d
0x140014F92: jz      loc_140015081
0x140014F98: test    eax, eax
0x140014F9A: jz      loc_140015081
0x140014FA0: mov     eax, ebx
0x140014FA2: sub     eax, edi
0x140014FA4: cmp     eax, esi
0x140014FA6: jnb     loc_140015081
0x140014FAC: mov     ecx, eax
0x140014FAE: add     rax, rdi
0x140014FB1: cmp     rbx, rax
0x140014FB4: jnz     loc_140015081
0x140014FBA: movsxd  rax, dword ptr [r14+3Ch]
0x140014FBE: add     rcx, r14
0x140014FC1: mov     edx, r14d
0x140014FC4: mov     r13, [rax+r14+30h]
0x140014FC9: lea     rax, [rsp+1E8h+var_1A8]
0x140014FCE: xor     r9d, r9d
0x140014FD1: mov     [rsp+1E8h+var_1B0], rax
0x140014FD6: and     [rsp+1E8h+var_1B8], 0
0x140014FDC: and     [rsp+1E8h+var_1C0], 0
0x140014FE2: or      [rsp+1E8h+var_1C8], 0FFFFFFFFh
0x140014FE7: sub     edx, ecx
0x140014FE9: lea     r8d, [r9+2]
0x140014FED: add     edx, esi
0x140014FEF: call    InitPESectionReadContext
0x140014FF4: xor     ebx, ebx
0x140014FF6: xor     ebp, ebp
0x140014FF8: lea     rdx, [rsp+1E8h+var_158]
0x140015000: lea     rcx, [rsp+1E8h+var_1A8]
0x140015005: call    ReadPESectionEntry
0x14001500A: test    eax, eax
0x14001500C: jnz     short loc_140015081
0x14001500E: mov     eax, [rsp+1E8h+var_68]
0x140015015: mov     rcx, [rsp+1E8h+var_1A0]
0x14001501A: mov     edx, 558h
0x14001501F: add     rcx, rax
0x140015022: mov     rax, [rsp+1E8h+var_40]
0x14001502A: mov     [rsp+1E8h+var_1A0], rcx
0x14001502F: cmp     dx, [rax+6]
0x140015033: jnz     short loc_1400150B2
0x140015035: test    [rsp+1E8h+var_108], 4000000h
0x140015041: jz      short loc_1400150B2
0x140015043: mov     eax, [rsp+1E8h+var_120]
0x14001504A: test    eax, eax
0x14001504C: jz      short loc_1400150B2
0x14001504E: sub     eax, r14d
0x140015051: add     eax, ecx
0x140015053: cmp     eax, r12d
0x140015056: jz      short loc_14001505D
0x140015058: cmp     eax, r15d
0x14001505B: jnz     short loc_1400150D2
0x14001505D: test    ebx, ebx
0x14001505F: jz      short loc_1400150D2
0x140015061: cmp     ebx, esi
0x140015063: jnb     short loc_1400150D2
0x140015065: lea     rdx, [rbx+r13]; Value
0x140015069: mov     ecx, 1A4h; Index
0x14001506E: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015073: lea     rdx, [rbx+rdi]; Value
0x140015077: mov     ecx, 179h; Index
0x14001507C: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015081: mov     rcx, [rsp+1E8h+var_38]
0x140015089: xor     rcx, rsp; StackCookie
0x14001508C: call    __security_check_cookie
0x140015091: lea     r11, [rsp+1E8h+var_28]
0x140015099: mov     rbx, [r11+30h]
0x14001509D: mov     rbp, [r11+38h]
0x1400150A1: mov     rsi, [r11+40h]
0x1400150A5: mov     rsp, r11
0x1400150A8: pop     r15
0x1400150AA: pop     r14
0x1400150AC: pop     r13
0x1400150AE: pop     r12
0x1400150B0: pop     rdi
0x1400150B1: retn
0x1400150B2: cmp     [rsp+1E8h+var_D0], 40000h
0x1400150BE: jnz     short loc_1400150D2
0x1400150C0: mov     eax, [rsp+1E8h+var_E0]
0x1400150C7: test    eax, eax
0x1400150C9: jz      short loc_1400150D2
0x1400150CB: mov     ebx, eax
0x1400150CD: sub     ebx, r14d
0x1400150D0: add     ebx, ecx
0x1400150D2: inc     ebp
0x1400150D4: cmp     ebp, 100h
0x1400150DA: jnb     short loc_140015081
0x1400150DC: jmp     loc_140014FF8