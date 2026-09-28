# MiniFilterPreWrite  ea=0x1400148D4  size=492
0x1400148D4: mov     rax, rsp; Minifilter 预写回调。遍历 PE 节表查找 PreWrite 相关节，排除已存在的偏移，找到新的匹配偏移写入全局表 GT 索引 0x17D。
0x1400148D7: mov     [rax+8], rbx
0x1400148DB: mov     [rax+10h], rbp
0x1400148DF: mov     [rax+18h], rsi
0x1400148E3: mov     [rax+20h], rdi
0x1400148E7: push    r12
0x1400148E9: push    r14
0x1400148EB: push    r15
0x1400148ED: sub     rsp, 1C0h
0x1400148F4: mov     rax, cs:__security_cookie
0x1400148FB: xor     rax, rsp
0x1400148FE: mov     [rsp+1D8h+var_28], rax
0x140014906: mov     ecx, 20h ; ' '; Index
0x14001490B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014910: mov     ecx, 21h ; '!'; Index
0x140014915: mov     r12, rax
0x140014918: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001491D: mov     ecx, 3; Index
0x140014922: mov     rsi, rax
0x140014925: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001492A: mov     ecx, 443Eh; Index
0x14001492F: mov     rbx, rax
0x140014932: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014937: mov     ecx, 173h; Index
0x14001493C: mov     r14, rax
0x14001493F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014944: mov     ecx, 444Ah; Index
0x140014949: mov     rdi, rax
0x14001494C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014951: mov     r15, rax
0x140014954: test    r12, r12
0x140014957: jz      loc_140014A8E
0x14001495D: test    esi, esi
0x14001495F: jz      loc_140014A8E
0x140014965: test    rbx, rbx
0x140014968: jz      loc_140014A8E
0x14001496E: test    r14d, r14d
0x140014971: jz      loc_140014A8E
0x140014977: cmp     rdi, rbx
0x14001497A: jbe     loc_140014A8E
0x140014980: test    eax, eax
0x140014982: jz      loc_140014A8E
0x140014988: mov     eax, edi
0x14001498A: sub     eax, ebx
0x14001498C: cmp     eax, esi
0x14001498E: jnb     loc_140014A8E
0x140014994: mov     ecx, eax
0x140014996: add     rax, rbx
0x140014999: cmp     rdi, rax
0x14001499C: jnz     loc_140014A8E
0x1400149A2: add     rcx, r12
0x1400149A5: mov     edx, r12d
0x1400149A8: lea     rax, [rsp+1D8h+var_198]
0x1400149AD: mov     [rsp+1D8h+var_1A0], rax
0x1400149B2: and     [rsp+1D8h+var_1A8], 0
0x1400149B8: and     [rsp+1D8h+var_1B0], 0
0x1400149BE: or      [rsp+1D8h+var_1B8], 0FFFFFFFFh
0x1400149C3: xor     r9d, r9d
0x1400149C6: sub     edx, ecx
0x1400149C8: lea     r8d, [r9+2]
0x1400149CC: add     edx, esi
0x1400149CE: call    InitPESectionReadContext
0x1400149D3: xor     dil, dil
0x1400149D6: xor     ebp, ebp
0x1400149D8: lea     rdx, [rsp+1D8h+var_148]
0x1400149E0: lea     rcx, [rsp+1D8h+var_198]
0x1400149E5: call    ReadPESectionEntry
0x1400149EA: test    eax, eax
0x1400149EC: jnz     loc_140014A8E
0x1400149F2: mov     eax, [rsp+1D8h+var_58]
0x1400149F9: mov     rcx, [rsp+1D8h+var_190]
0x1400149FE: add     rcx, rax
0x140014A01: mov     rax, [rsp+1D8h+var_30]
0x140014A09: mov     [rsp+1D8h+var_190], rcx
0x140014A0E: movzx   edx, word ptr [rax+6]
0x140014A12: mov     eax, 1E3h
0x140014A17: cmp     ax, dx
0x140014A1A: jnz     short loc_140014A2F
0x140014A1C: cmp     [rsp+1D8h+var_F8], 10041h
0x140014A28: jnz     short loc_140014A2F
0x140014A2A: mov     dil, 1
0x140014A2D: jmp     short loc_140014A70
0x140014A2F: mov     eax, 558h
0x140014A34: cmp     ax, dx
0x140014A37: jnz     short loc_140014A70
0x140014A39: test    [rsp+1D8h+var_F8], 4000000h
0x140014A45: jz      short loc_140014A70
0x140014A47: mov     eax, [rsp+1D8h+var_110]
0x140014A4E: test    eax, eax
0x140014A50: jz      short loc_140014A70
0x140014A52: sub     eax, r12d
0x140014A55: add     eax, ecx
0x140014A57: jz      short loc_140014A6D
0x140014A59: cmp     eax, esi
0x140014A5B: jnb     short loc_140014A6D
0x140014A5D: cmp     dil, 1
0x140014A61: jnz     short loc_140014A6D
0x140014A63: cmp     eax, r14d
0x140014A66: jz      short loc_140014A6D
0x140014A68: cmp     eax, r15d
0x140014A6B: jnz     short loc_140014A7F
0x140014A6D: xor     dil, dil
0x140014A70: inc     ebp
0x140014A72: cmp     ebp, 200h
0x140014A78: jnb     short loc_140014A8E
0x140014A7A: jmp     loc_1400149D8
0x140014A7F: mov     edx, eax
0x140014A81: mov     ecx, 17Dh; Index
0x140014A86: add     rdx, rbx; Value
0x140014A89: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014A8E: mov     rcx, [rsp+1D8h+var_28]
0x140014A96: xor     rcx, rsp; StackCookie
0x140014A99: call    __security_check_cookie
0x140014A9E: lea     r11, [rsp+1D8h+var_18]
0x140014AA6: mov     rbx, [r11+20h]
0x140014AAA: mov     rbp, [r11+28h]
0x140014AAE: mov     rsi, [r11+30h]
0x140014AB2: mov     rdi, [r11+38h]
0x140014AB6: mov     rsp, r11
0x140014AB9: pop     r15
0x140014ABB: pop     r14
0x140014ABD: pop     r12
0x140014ABF: retn