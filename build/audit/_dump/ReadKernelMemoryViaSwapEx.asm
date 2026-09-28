# ReadKernelMemoryViaSwapEx  ea=0x140075874  size=385
0x140075874: mov     rax, rsp
0x140075877: mov     [rax+8], rbx
0x14007587B: mov     [rax+10h], rsi
0x14007587F: mov     [rax+18h], rdi
0x140075883: push    rbp
0x140075884: push    r12
0x140075886: push    r13
0x140075888: push    r14
0x14007588A: push    r15
0x14007588C: lea     rbp, [rax-5Fh]
0x140075890: sub     rsp, 90h
0x140075897: mov     r14, rcx
0x14007589A: mov     ecx, 41F3h; Index
0x14007589F: mov     r12d, r9d
0x1400758A2: mov     rdi, r8
0x1400758A5: mov     r13, rdx
0x1400758A8: xor     ebx, ebx
0x1400758AA: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400758AF: mov     ecx, 4334h; Index
0x1400758B4: mov     [rbp+57h+var_78], rax
0x1400758B8: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400758BD: mov     ecx, 4205h; Index
0x1400758C2: mov     rsi, rax
0x1400758C5: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400758CA: mov     r15, rax
0x1400758CD: cmp     [rbp+57h+var_78], rbx
0x1400758D1: jz      loc_1400759D2
0x1400758D7: test    rsi, rsi
0x1400758DA: jz      loc_1400759D2
0x1400758E0: test    rax, rax
0x1400758E3: jz      loc_1400759D2
0x1400758E9: mov     edx, [r13+0Ch]
0x1400758ED: mov     r8d, [r14+4]; MaxCount
0x1400758F1: add     edx, r8d
0x1400758F4: add     rdx, 2
0x1400758F8: cmp     rdx, r12
0x1400758FB: jnb     loc_1400759D2
0x140075901: mov     rdx, [r14+8]; Src
0x140075905: mov     rcx, rdi; Dst
0x140075908: call    memmove
0x14007590D: mov     eax, [r14+4]
0x140075911: lea     ecx, [rbx+5Ch]
0x140075914: mov     [rax+rdi-2], cx
0x140075919: mov     ecx, [r14+4]
0x14007591D: mov     r8d, [r13+0Ch]; MaxCount
0x140075921: lea     rdx, [r13+10h]; Src
0x140075925: add     rcx, rdi; Dst
0x140075928: call    memmove
0x14007592D: mov     ecx, [r14+4]
0x140075931: mov     edx, [r13+0Ch]
0x140075935: add     rcx, rdi
0x140075938: mov     [rdx+rcx], bx
0x14007593C: mov     edx, [r13+0Ch]
0x140075940: add     edx, 2
0x140075943: add     edx, [r14+4]
0x140075947: lea     r14d, [rbx+2]
0x14007594B: cmp     edx, r14d
0x14007594E: jb      short loc_140075962
0x140075950: mov     word ptr [rbp+57h+var_68+2], dx
0x140075954: sub     dx, r14w
0x140075958: mov     [rbp+57h+var_60], rdi
0x14007595C: mov     word ptr [rbp+57h+var_68], dx
0x140075960: jmp     short loc_140075969
0x140075962: mov     [rbp+57h+var_60], rbx
0x140075966: mov     [rbp+57h+var_68], ebx
0x140075969: lea     rax, [rbp+57h+var_68]
0x14007596D: xorps   xmm0, xmm0
0x140075970: lea     r8, [rbp+57h+var_58]
0x140075974: lea     rcx, [rbp+57h+var_70]
0x140075978: mov     edx, 20019h
0x14007597D: mov     [rbp+57h+var_58], 30h ; '0'
0x140075984: movdqu  [rbp+57h+var_38], xmm0
0x140075989: mov     [rbp+57h+var_48], rax
0x14007598D: mov     [rbp+57h+var_50], rbx
0x140075991: mov     [rbp+57h+var_40], 240h
0x140075998: call    [rbp+57h+var_78]
0x14007599B: test    eax, eax
0x14007599D: js      short loc_1400759D2
0x14007599F: mov     rcx, [rbp+57h+var_70]
0x1400759A3: lea     rax, [rbp+57h+var_80]
0x1400759A7: mov     r9d, r12d
0x1400759AA: mov     r8, rdi
0x1400759AD: mov     edx, r14d
0x1400759B0: mov     [rsp+0B0h+var_90], rax
0x1400759B5: call    r15
0x1400759B8: test    eax, eax
0x1400759BA: js      short loc_1400759CC
0x1400759BC: cmp     [rdi+14h], ebx
0x1400759BF: movzx   eax, bl
0x1400759C2: mov     ecx, 1
0x1400759C7: cmova   eax, ecx
0x1400759CA: mov     bl, al
0x1400759CC: mov     rcx, [rbp+57h+var_70]
0x1400759D0: call    rsi
0x1400759D2: lea     r11, [rsp+0B0h+var_20]
0x1400759DA: mov     al, bl
0x1400759DC: mov     rbx, [r11+30h]
0x1400759E0: mov     rsi, [r11+38h]
0x1400759E4: mov     rdi, [r11+40h]
0x1400759E8: mov     rsp, r11
0x1400759EB: pop     r15
0x1400759ED: pop     r14
0x1400759EF: pop     r13
0x1400759F1: pop     r12
0x1400759F3: pop     rbp
0x1400759F4: retn