# FindKernelDataSectionV3  ea=0x1400132EC  size=638
0x1400132EC: mov     rax, rsp; 查找内核数据节 V3。查找内核数据节的另一种实现，读取 PE 基址、大小和镜像基址，遍历节表定位数据节。
0x1400132EF: mov     [rax+8], rbx
0x1400132F3: mov     [rax+10h], rsi
0x1400132F7: mov     [rax+18h], rdi
0x1400132FB: push    rbp
0x1400132FC: push    r12
0x1400132FE: push    r13
0x140013300: push    r14
0x140013302: push    r15
0x140013304: lea     rbp, [rax-0F8h]
0x14001330B: sub     rsp, 1D0h
0x140013312: mov     rax, cs:__security_cookie
0x140013319: xor     rax, rsp
0x14001331C: mov     [rbp+0F0h+var_30], rax
0x140013323: mov     ecx, 20h ; ' '; Index
0x140013328: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001332D: mov     ecx, 21h ; '!'; Index
0x140013332: mov     r15, rax
0x140013335: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001333A: mov     ecx, 3; Index
0x14001333F: mov     r14, rax
0x140013342: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013347: mov     ecx, 170h; Index
0x14001334C: mov     rbx, rax
0x14001334F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013354: xor     esi, esi
0x140013356: mov     rdx, rax
0x140013359: test    r15, r15
0x14001335C: jz      loc_14001353A
0x140013362: test    r14d, r14d
0x140013365: jz      loc_14001353A
0x14001336B: test    rbx, rbx
0x14001336E: jz      loc_14001353A
0x140013374: cmp     rax, rbx
0x140013377: jbe     loc_14001353A
0x14001337D: mov     ecx, eax
0x14001337F: sub     ecx, ebx
0x140013381: cmp     ecx, r14d
0x140013384: jnb     loc_14001353A
0x14001338A: lea     rax, [rcx+rbx]
0x14001338E: cmp     rdx, rax
0x140013391: jnz     loc_14001353A
0x140013397: add     rcx, r15
0x14001339A: mov     edx, r15d
0x14001339D: lea     rax, [rsp+1F0h+var_1A0]
0x1400133A2: mov     qword ptr [rsp+1F0h+var_1B8], rax
0x1400133A7: sub     edx, ecx
0x1400133A9: mov     [rsp+1F0h+var_1C0], rsi
0x1400133AE: lea     r8d, [rsi+2]
0x1400133B2: xor     r9d, r9d
0x1400133B5: add     edx, r14d
0x1400133B8: mov     [rsp+1F0h+var_1C8], rsi
0x1400133BD: or      dword ptr [rsp+1F0h+var_1D0], 0FFFFFFFFh
0x1400133C2: call    InitPESectionReadContext
0x1400133C7: mov     r13d, esi
0x1400133CA: mov     [rsp+1F0h+var_1AC], esi
0x1400133CE: mov     [rsp+1F0h+var_1B0], esi
0x1400133D2: mov     r12b, sil
0x1400133D5: mov     edi, esi
0x1400133D7: lea     rdx, [rbp+0F0h+var_150]
0x1400133DB: lea     rcx, [rsp+1F0h+var_1A0]
0x1400133E0: call    ReadPESectionEntry
0x1400133E5: test    eax, eax
0x1400133E7: jnz     loc_14001353A
0x1400133ED: mov     eax, [rbp+0F0h+var_60]
0x1400133F3: mov     ecx, 512h
0x1400133F8: add     [rsp+1F0h+var_198], rax
0x1400133FD: mov     rax, [rbp+0F0h+var_38]
0x140013404: cmp     cx, [rax+6]
0x140013408: jnz     short loc_140013464
0x14001340A: cmp     [rbp+0F0h+var_100], 40h ; '@'
0x14001340F: jnz     short loc_140013464
0x140013411: mov     eax, [rbp+0F0h+var_F8]
0x140013414: cmp     eax, 2
0x140013417: jnz     short loc_140013421
0x140013419: mov     r13d, esi
0x14001341C: jmp     loc_14001351C
0x140013421: cmp     eax, 9
0x140013424: jnz     short loc_14001342F
0x140013426: mov     [rsp+1F0h+var_1AC], esi
0x14001342A: jmp     loc_14001351C
0x14001342F: cmp     eax, 1
0x140013432: jnz     loc_14001351C
0x140013438: test    r13d, r13d
0x14001343B: jz      short loc_140013445
0x14001343D: lea     eax, [r13+1]
0x140013441: cmp     eax, esi
0x140013443: jz      short loc_14001345C
0x140013445: mov     eax, [rsp+1F0h+var_1AC]
0x140013449: test    eax, eax
0x14001344B: jz      loc_14001351C
0x140013451: add     eax, 3
0x140013454: cmp     eax, esi
0x140013456: jnz     loc_14001351C
0x14001345C: mov     r12b, 1
0x14001345F: jmp     loc_14001351C
0x140013464: cmp     r12b, 1
0x140013468: jnz     loc_14001351C
0x14001346E: mov     ecx, 914h; Index
0x140013473: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013478: cmp     eax, 42EEh
0x14001347D: mov     rax, [rbp+0F0h+var_38]
0x140013484: jnb     short loc_1400134C5
0x140013486: mov     ecx, 558h
0x14001348B: cmp     cx, [rax+6]
0x14001348F: jnz     loc_14001351C
0x140013495: test    [rbp+0F0h+var_100], 4000000h
0x14001349D: jz      short loc_14001351C
0x14001349F: mov     eax, [rbp+0F0h+var_118]
0x1400134A2: test    eax, eax
0x1400134A4: jz      short loc_14001351C
0x1400134A6: mov     ecx, [rsp+1F0h+var_1B0]
0x1400134AA: inc     ecx
0x1400134AC: mov     [rsp+1F0h+var_1B0], ecx
0x1400134B0: cmp     ecx, 2
0x1400134B3: jnz     short loc_14001351C
0x1400134B5: sub     eax, r15d
0x1400134B8: add     eax, dword ptr [rsp+1F0h+var_198]
0x1400134BC: cmp     eax, r14d
0x1400134BF: jnb     short loc_14001353A
0x1400134C1: mov     edx, eax
0x1400134C3: jmp     short loc_14001352D
0x1400134C5: movzx   ecx, word ptr [rax+6]
0x1400134C9: mov     eax, 558h
0x1400134CE: cmp     ax, cx
0x1400134D1: jnz     short loc_1400134EF
0x1400134D3: test    [rbp+0F0h+var_100], 4000000h
0x1400134DB: jz      short loc_1400134EF
0x1400134DD: mov     eax, [rbp+0F0h+var_118]
0x1400134E0: test    eax, eax
0x1400134E2: jz      short loc_1400134EF
0x1400134E4: mov     edi, eax
0x1400134E6: sub     edi, r15d
0x1400134E9: add     edi, dword ptr [rsp+1F0h+var_198]
0x1400134ED: jmp     short loc_14001351C
0x1400134EF: mov     eax, 420h
0x1400134F4: cmp     ax, cx
0x1400134F7: jnz     short loc_14001351C
0x1400134F9: cmp     [rbp+0F0h+var_C8], 800000h
0x140013501: jnz     short loc_14001351C
0x140013503: cmp     [rbp+0F0h+var_E0], 0C0000023h
0x14001350A: jnz     short loc_14001351C
0x14001350C: cmp     [rbp+0F0h+var_100], 20h ; ' '
0x140013511: jnz     short loc_14001351C
0x140013513: test    edi, edi
0x140013515: jz      short loc_14001351C
0x140013517: cmp     edi, r14d
0x14001351A: jb      short loc_14001352B
0x14001351C: inc     esi
0x14001351E: cmp     esi, 200h
0x140013524: jnb     short loc_14001353A
0x140013526: jmp     loc_1400133D7
0x14001352B: mov     edx, edi
0x14001352D: add     rdx, rbx; Value
0x140013530: mov     ecx, 17Ah; Index
0x140013535: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001353A: mov     rcx, [rbp+0F0h+var_30]
0x140013541: xor     rcx, rsp; StackCookie
0x140013544: call    __security_check_cookie
0x140013549: lea     r11, [rsp+1F0h+var_20]
0x140013551: mov     rbx, [r11+30h]
0x140013555: mov     rsi, [r11+38h]
0x140013559: mov     rdi, [r11+40h]
0x14001355D: mov     rsp, r11
0x140013560: pop     r15
0x140013562: pop     r14
0x140013564: pop     r13
0x140013566: pop     r12
0x140013568: pop     rbp
0x140013569: retn