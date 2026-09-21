# MiniFilterPreCreate  ea=0x140014078  size=557
0x140014078: mov     rax, rsp; Minifilter 预创建回调。查找 ntoskrnl 中 PreCreate 相关的数据节，遍历 PE 节表定位目标偏移。
0x14001407B: mov     [rax+8], rbx
0x14001407F: mov     [rax+10h], rsi
0x140014083: mov     [rax+18h], rdi
0x140014087: push    rbp
0x140014088: push    r12
0x14001408A: push    r13
0x14001408C: push    r14
0x14001408E: push    r15
0x140014090: lea     rbp, [rax-0F8h]
0x140014097: sub     rsp, 1D0h
0x14001409E: mov     rax, cs:__security_cookie
0x1400140A5: xor     rax, rsp
0x1400140A8: mov     [rbp+0F0h+var_30], rax
0x1400140AF: mov     ecx, 20h ; ' '; Index
0x1400140B4: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400140B9: mov     ecx, 21h ; '!'; Index
0x1400140BE: mov     rbx, rax
0x1400140C1: mov     [rsp+1F0h+var_1B0], rax
0x1400140C6: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400140CB: mov     ecx, 3; Index
0x1400140D0: mov     r14, rax
0x1400140D3: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400140D8: mov     ecx, 172h; Index
0x1400140DD: mov     rsi, rax
0x1400140E0: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400140E5: mov     rdx, rax
0x1400140E8: test    rbx, rbx
0x1400140EB: jz      loc_140014275
0x1400140F1: test    r14d, r14d
0x1400140F4: jz      loc_140014275
0x1400140FA: test    rsi, rsi
0x1400140FD: jz      loc_140014275
0x140014103: cmp     rax, rsi
0x140014106: jbe     loc_140014275
0x14001410C: mov     ecx, eax
0x14001410E: sub     ecx, esi
0x140014110: cmp     ecx, r14d
0x140014113: jnb     loc_140014275
0x140014119: lea     rax, [rcx+rsi]
0x14001411D: cmp     rdx, rax
0x140014120: jnz     loc_140014275
0x140014126: add     rcx, rbx
0x140014129: mov     edx, ebx
0x14001412B: lea     rax, [rsp+1F0h+var_1A0]
0x140014130: mov     [rsp+1F0h+var_1B8], rax
0x140014135: and     [rsp+1F0h+var_1C0], 0
0x14001413B: and     [rsp+1F0h+var_1C8], 0
0x140014141: or      dword ptr [rsp+1F0h+var_1D0], 0FFFFFFFFh
0x140014146: xor     r9d, r9d
0x140014149: sub     edx, ecx
0x14001414B: lea     r8d, [r9+2]
0x14001414F: add     edx, r14d
0x140014152: call    InitPESectionReadContext
0x140014157: xor     r13d, r13d
0x14001415A: xor     r15d, r15d
0x14001415D: xor     r12b, r12b
0x140014160: xor     edi, edi
0x140014162: xor     ebx, ebx
0x140014164: lea     rdx, [rbp+0F0h+var_150]
0x140014168: lea     rcx, [rsp+1F0h+var_1A0]
0x14001416D: call    ReadPESectionEntry
0x140014172: test    eax, eax
0x140014174: jnz     loc_140014275
0x14001417A: mov     eax, [rbp+0F0h+var_60]
0x140014180: mov     rdx, [rsp+1F0h+var_198]
0x140014185: mov     r8, [rbp+0F0h+var_100]
0x140014189: add     rdx, rax
0x14001418C: mov     rax, [rbp+0F0h+var_38]
0x140014193: mov     [rsp+1F0h+var_198], rdx
0x140014198: movzx   ecx, word ptr [rax+6]
0x14001419C: mov     eax, 512h
0x1400141A1: cmp     ax, cx
0x1400141A4: jnz     short loc_1400141F9
0x1400141A6: cmp     r8, 40h ; '@'
0x1400141AA: jnz     short loc_1400141F9
0x1400141AC: mov     eax, [rbp+0F0h+var_F8]
0x1400141AF: cmp     eax, 2
0x1400141B2: jnz     short loc_1400141BC
0x1400141B4: mov     r13d, ebx
0x1400141B7: jmp     loc_140014257
0x1400141BC: cmp     eax, 9
0x1400141BF: jnz     short loc_1400141C9
0x1400141C1: mov     r15d, ebx
0x1400141C4: jmp     loc_140014257
0x1400141C9: cmp     eax, 1
0x1400141CC: jnz     loc_140014257
0x1400141D2: test    r13d, r13d
0x1400141D5: jz      short loc_1400141DF
0x1400141D7: lea     eax, [r13+1]
0x1400141DB: cmp     eax, ebx
0x1400141DD: jz      short loc_1400141F4
0x1400141DF: test    r15d, r15d
0x1400141E2: jz      short loc_140014257
0x1400141E4: lea     eax, [r15+3]
0x1400141E8: cmp     eax, ebx
0x1400141EA: jz      short loc_1400141F4
0x1400141EC: lea     eax, [r15+4]
0x1400141F0: cmp     eax, ebx
0x1400141F2: jnz     short loc_140014257
0x1400141F4: mov     r12b, 1
0x1400141F7: jmp     short loc_140014257
0x1400141F9: cmp     r12b, 1
0x1400141FD: jnz     short loc_140014257
0x1400141FF: mov     eax, 558h
0x140014204: cmp     ax, cx
0x140014207: jnz     short loc_140014221
0x140014209: bt      r8, 1Ah
0x14001420E: jnb     short loc_140014221
0x140014210: mov     eax, [rbp+0F0h+var_118]
0x140014213: test    eax, eax
0x140014215: jz      short loc_140014221
0x140014217: mov     edi, eax
0x140014219: sub     edi, dword ptr [rsp+1F0h+var_1B0]
0x14001421D: add     edi, edx
0x14001421F: jmp     short loc_140014257
0x140014221: mov     eax, 420h
0x140014226: cmp     ax, cx
0x140014229: jz      short loc_140014235
0x14001422B: mov     eax, 4DFh
0x140014230: cmp     ax, cx
0x140014233: jnz     short loc_140014257
0x140014235: cmp     [rbp+0F0h+var_C8], 800000h
0x14001423D: jnz     short loc_140014257
0x14001423F: cmp     [rbp+0F0h+var_E0], 0C0000023h
0x140014246: jnz     short loc_140014257
0x140014248: cmp     r8, 20h ; ' '
0x14001424C: jnz     short loc_140014257
0x14001424E: test    edi, edi
0x140014250: jz      short loc_140014257
0x140014252: cmp     edi, r14d
0x140014255: jb      short loc_140014266
0x140014257: inc     ebx
0x140014259: cmp     ebx, 300h
0x14001425F: jnb     short loc_140014275
0x140014261: jmp     loc_140014164
0x140014266: mov     edx, edi
0x140014268: mov     ecx, 17Ch; Index
0x14001426D: add     rdx, rsi; Value
0x140014270: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014275: mov     rcx, [rbp+0F0h+var_30]
0x14001427C: xor     rcx, rsp; StackCookie
0x14001427F: call    __security_check_cookie
0x140014284: lea     r11, [rsp+1F0h+var_20]
0x14001428C: mov     rbx, [r11+30h]
0x140014290: mov     rsi, [r11+38h]
0x140014294: mov     rdi, [r11+40h]
0x140014298: mov     rsp, r11
0x14001429B: pop     r15
0x14001429D: pop     r14
0x14001429F: pop     r13
0x1400142A1: pop     r12
0x1400142A3: pop     rbp
0x1400142A4: retn