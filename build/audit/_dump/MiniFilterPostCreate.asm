# MiniFilterPostCreate  ea=0x1400142A8  size=512
0x1400142A8: mov     [rsp+arg_0], rbx; Minifilter 创建后回调。遍历 PE 节表定位 PostCreate 相关的数据节偏移，第 2 个匹配的 1368 类型节写入全局表 GT 索引 0x17C。
0x1400142AD: mov     [rsp+arg_8], rbp
0x1400142B2: mov     [rsp+arg_10], rsi
0x1400142B7: push    rdi
0x1400142B8: push    r12
0x1400142BA: push    r13
0x1400142BC: push    r14
0x1400142BE: push    r15
0x1400142C0: sub     rsp, 1C0h
0x1400142C7: mov     rax, cs:__security_cookie
0x1400142CE: xor     rax, rsp
0x1400142D1: mov     [rsp+1E8h+var_38], rax
0x1400142D9: mov     ecx, 20h ; ' '; Index
0x1400142DE: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400142E3: mov     ecx, 21h ; '!'; Index
0x1400142E8: mov     r12, rax
0x1400142EB: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400142F0: mov     ecx, 3; Index
0x1400142F5: mov     rsi, rax
0x1400142F8: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400142FD: mov     ecx, 172h; Index
0x140014302: mov     rdi, rax
0x140014305: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001430A: mov     rdx, rax
0x14001430D: test    r12, r12
0x140014310: jz      loc_140014477
0x140014316: test    esi, esi
0x140014318: jz      loc_140014477
0x14001431E: test    rdi, rdi
0x140014321: jz      loc_140014477
0x140014327: cmp     rax, rdi
0x14001432A: jbe     loc_140014477
0x140014330: mov     ecx, eax
0x140014332: sub     ecx, edi
0x140014334: cmp     ecx, esi
0x140014336: jnb     loc_140014477
0x14001433C: lea     rax, [rcx+rdi]
0x140014340: cmp     rdx, rax
0x140014343: jnz     loc_140014477
0x140014349: add     rcx, r12
0x14001434C: mov     edx, r12d
0x14001434F: lea     rax, [rsp+1E8h+var_1A8]
0x140014354: mov     [rsp+1E8h+var_1B0], rax
0x140014359: and     [rsp+1E8h+var_1B8], 0
0x14001435F: and     [rsp+1E8h+var_1C0], 0
0x140014365: or      [rsp+1E8h+var_1C8], 0FFFFFFFFh
0x14001436A: xor     r9d, r9d
0x14001436D: sub     edx, ecx
0x14001436F: lea     r8d, [r9+2]
0x140014373: add     edx, esi
0x140014375: call    InitPESectionReadContext
0x14001437A: xor     ebp, ebp
0x14001437C: xor     r14d, r14d
0x14001437F: xor     r13d, r13d
0x140014382: xor     r15b, r15b
0x140014385: xor     ebx, ebx
0x140014387: lea     rdx, [rsp+1E8h+var_158]
0x14001438F: lea     rcx, [rsp+1E8h+var_1A8]
0x140014394: call    ReadPESectionEntry
0x140014399: test    eax, eax
0x14001439B: jnz     loc_140014477
0x1400143A1: mov     eax, [rsp+1E8h+var_68]
0x1400143A8: mov     rcx, [rsp+1E8h+var_1A0]
0x1400143AD: add     rcx, rax
0x1400143B0: mov     rax, [rsp+1E8h+var_40]
0x1400143B8: mov     [rsp+1E8h+var_1A0], rcx
0x1400143BD: movzx   edx, word ptr [rax+6]
0x1400143C1: mov     eax, 512h
0x1400143C6: cmp     ax, dx
0x1400143C9: jnz     short loc_14001441C
0x1400143CB: cmp     [rsp+1E8h+var_108], 40h ; '@'
0x1400143D4: jnz     short loc_14001441C
0x1400143D6: cmp     [rsp+1E8h+var_C8], 4
0x1400143DE: jnz     short loc_14001441C
0x1400143E0: mov     eax, [rsp+1E8h+var_100]
0x1400143E7: cmp     eax, 2
0x1400143EA: jnz     short loc_1400143F0
0x1400143EC: mov     ebp, ebx
0x1400143EE: jmp     short loc_14001444E
0x1400143F0: cmp     eax, 9
0x1400143F3: jnz     short loc_1400143FA
0x1400143F5: mov     r14d, ebx
0x1400143F8: jmp     short loc_14001444E
0x1400143FA: cmp     eax, 1
0x1400143FD: jnz     short loc_14001444E
0x1400143FF: test    ebp, ebp
0x140014401: jz      short loc_14001440A
0x140014403: lea     eax, [rbp+1]
0x140014406: cmp     eax, ebx
0x140014408: jz      short loc_140014417
0x14001440A: test    r14d, r14d
0x14001440D: jz      short loc_14001444E
0x14001440F: lea     eax, [r14+3]
0x140014413: cmp     eax, ebx
0x140014415: jnz     short loc_14001444E
0x140014417: mov     r15b, 1
0x14001441A: jmp     short loc_14001444E
0x14001441C: cmp     r15b, 1
0x140014420: jnz     short loc_14001444E
0x140014422: mov     eax, 558h
0x140014427: cmp     ax, dx
0x14001442A: jnz     short loc_14001444E
0x14001442C: test    [rsp+1E8h+var_108], 4000000h
0x140014438: jz      short loc_14001444E
0x14001443A: mov     eax, [rsp+1E8h+var_120]
0x140014441: test    eax, eax
0x140014443: jz      short loc_14001444E
0x140014445: inc     r13d
0x140014448: cmp     r13d, 2
0x14001444C: jz      short loc_14001445D
0x14001444E: inc     ebx
0x140014450: cmp     ebx, 200h
0x140014456: jnb     short loc_140014477
0x140014458: jmp     loc_140014387
0x14001445D: sub     eax, r12d
0x140014460: add     eax, ecx
0x140014462: jz      short loc_140014477
0x140014464: cmp     eax, esi
0x140014466: jnb     short loc_140014477
0x140014468: mov     edx, eax
0x14001446A: mov     ecx, 17Ch; Index
0x14001446F: add     rdx, rdi; Value
0x140014472: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140014477: mov     rcx, [rsp+1E8h+var_38]
0x14001447F: xor     rcx, rsp; StackCookie
0x140014482: call    __security_check_cookie
0x140014487: lea     r11, [rsp+1E8h+var_28]
0x14001448F: mov     rbx, [r11+30h]
0x140014493: mov     rbp, [r11+38h]
0x140014497: mov     rsi, [r11+40h]
0x14001449B: mov     rsp, r11
0x14001449E: pop     r15
0x1400144A0: pop     r14
0x1400144A2: pop     r13
0x1400144A4: pop     r12
0x1400144A6: pop     rdi
0x1400144A7: retn