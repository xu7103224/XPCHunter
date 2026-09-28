# MiniFilterPreRead  ea=0x1400144A8  size=515
0x1400144A8: mov     [rsp+arg_0], rbx; Minifilter 预读回调。遍历 PE 节表查找 PreRead 相关节，计算目标偏移并写入全局表 GT 索引 0x17C。
0x1400144AD: mov     [rsp+arg_8], rbp
0x1400144B2: mov     [rsp+arg_10], rsi
0x1400144B7: push    rdi
0x1400144B8: push    r12
0x1400144BA: push    r13
0x1400144BC: push    r14
0x1400144BE: push    r15
0x1400144C0: sub     rsp, 1C0h
0x1400144C7: mov     rax, cs:__security_cookie
0x1400144CE: xor     rax, rsp
0x1400144D1: mov     [rsp+1E8h+var_38], rax
0x1400144D9: mov     ecx, 20h ; ' '; Index
0x1400144DE: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400144E3: mov     ecx, 21h ; '!'; Index
0x1400144E8: mov     r14, rax
0x1400144EB: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400144F0: mov     ecx, 3; Index
0x1400144F5: mov     rbp, rax
0x1400144F8: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400144FD: mov     ecx, 439Fh; Index
0x140014502: mov     rdi, rax
0x140014505: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001450A: mov     ecx, 41C5h; Index
0x14001450F: mov     r15, rax
0x140014512: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014517: mov     ecx, 4444h; Index
0x14001451C: mov     r12, rax
0x14001451F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014524: mov     ecx, 172h; Index
0x140014529: mov     r13, rax
0x14001452C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140014531: mov     rcx, rax
0x140014534: test    r14, r14
0x140014537: jz      loc_14001463C
0x14001453D: test    ebp, ebp
0x14001453F: jz      loc_14001463C
0x140014545: test    rdi, rdi
0x140014548: jz      loc_14001463C
0x14001454E: test    r15d, r15d
0x140014551: jz      loc_14001463C
0x140014557: test    r12d, r12d
0x14001455A: jz      loc_14001463C
0x140014560: cmp     rax, rdi
0x140014563: jbe     loc_14001463C
0x140014569: sub     eax, edi
0x14001456B: cmp     eax, ebp
0x14001456D: jnb     loc_14001463C
0x140014573: mov     edx, eax
0x140014575: add     rax, rdi
0x140014578: cmp     rcx, rax
0x14001457B: jnz     loc_14001463C
0x140014581: lea     rcx, [rdx+r14]
0x140014585: lea     rax, [rsp+1E8h+var_1A8]
0x14001458A: xor     r9d, r9d
0x14001458D: mov     [rsp+1E8h+var_1B0], rax
0x140014592: and     [rsp+1E8h+var_1B8], 0
0x140014598: and     [rsp+1E8h+var_1C0], 0
0x14001459E: or      [rsp+1E8h+var_1C8], 0FFFFFFFFh
0x1400145A3: mov     edx, r14d
0x1400145A6: lea     r8d, [r9+2]
0x1400145AA: sub     edx, ecx
0x1400145AC: add     edx, ebp
0x1400145AE: call    InitPESectionReadContext
0x1400145B3: xor     ebx, ebx
0x1400145B5: xor     esi, esi
0x1400145B7: lea     rdx, [rsp+1E8h+var_158]
0x1400145BF: lea     rcx, [rsp+1E8h+var_1A8]
0x1400145C4: call    ReadPESectionEntry
0x1400145C9: test    eax, eax
0x1400145CB: jnz     short loc_14001463C
0x1400145CD: mov     eax, [rsp+1E8h+var_68]
0x1400145D4: mov     rcx, [rsp+1E8h+var_1A0]
0x1400145D9: add     rcx, rax
0x1400145DC: mov     rax, [rsp+1E8h+var_40]
0x1400145E4: mov     [rsp+1E8h+var_1A0], rcx
0x1400145E9: movzx   edx, word ptr [rax+6]
0x1400145ED: mov     eax, 430h
0x1400145F2: cmp     ax, dx
0x1400145F5: jnz     short loc_14001466D
0x1400145F7: cmp     [rsp+1E8h+var_118], 0
0x1400145FF: jz      short loc_14001466D
0x140014601: cmp     [rsp+1E8h+var_108], 40000h
0x14001460D: jnz     short loc_14001466D
0x14001460F: cmp     [rsp+1E8h+var_E8], 0
0x140014618: jnz     short loc_14001466D
0x14001461A: test    ebx, ebx
0x14001461C: jz      short loc_14001469C
0x14001461E: cmp     r15d, ebx
0x140014621: jz      short loc_14001469C
0x140014623: cmp     r12d, ebx
0x140014626: jz      short loc_14001469C
0x140014628: cmp     r13d, ebx
0x14001462B: jz      short loc_14001469C
0x14001462D: mov     edx, ebx
0x14001462F: mov     ecx, 17Ch; Index
0x140014634: add     rdx, rdi; Value
0x140014637: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001463C: mov     rcx, [rsp+1E8h+var_38]
0x140014644: xor     rcx, rsp; StackCookie
0x140014647: call    __security_check_cookie
0x14001464C: lea     r11, [rsp+1E8h+var_28]
0x140014654: mov     rbx, [r11+30h]
0x140014658: mov     rbp, [r11+38h]
0x14001465C: mov     rsi, [r11+40h]
0x140014660: mov     rsp, r11
0x140014663: pop     r15
0x140014665: pop     r14
0x140014667: pop     r13
0x140014669: pop     r12
0x14001466B: pop     rdi
0x14001466C: retn
0x14001466D: mov     eax, 558h
0x140014672: cmp     ax, dx
0x140014675: jnz     short loc_14001469C
0x140014677: test    [rsp+1E8h+var_108], 4000000h
0x140014683: jz      short loc_14001469C
0x140014685: mov     eax, [rsp+1E8h+var_120]
0x14001468C: test    eax, eax
0x14001468E: jz      short loc_14001469C
0x140014690: sub     eax, r14d
0x140014693: add     eax, ecx
0x140014695: jz      short loc_14001469C
0x140014697: cmp     eax, ebp
0x140014699: cmovb   ebx, eax
0x14001469C: inc     esi
0x14001469E: cmp     esi, 200h
0x1400146A4: jnb     short loc_14001463C
0x1400146A6: jmp     loc_1400145B7