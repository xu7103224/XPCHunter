# ParseSyscallTableSections  ea=0x140086150  size=856
0x140086150: mov     rax, rsp
0x140086153: mov     [rax+10h], rbx
0x140086157: mov     [rax+18h], rsi
0x14008615B: mov     [rax+20h], rdi
0x14008615F: push    rbp
0x140086160: push    r12
0x140086162: push    r13
0x140086164: push    r14
0x140086166: push    r15
0x140086168: lea     rbp, [rax-138h]
0x14008616F: sub     rsp, 210h
0x140086176: mov     rax, cs:__security_cookie
0x14008617D: xor     rax, rsp
0x140086180: mov     [rbp+130h+var_30], rax
0x140086187: movsxd  rbx, dword ptr [rcx+3Ch]
0x14008618B: mov     r15, rcx
0x14008618E: mov     ecx, 39BCh; Index
0x140086193: mov     rdi, r8
0x140086196: mov     [rsp+230h+var_1F0], r8
0x14008619B: mov     esi, edx
0x14008619D: xor     r12b, r12b
0x1400861A0: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400861A5: mov     r13, rax
0x1400861A8: test    rdi, rdi
0x1400861AB: jz      loc_14008641B
0x1400861B1: mov     ebx, [rbx+r15+28h]
0x1400861B6: mov     edi, 545h
0x1400861BB: cmp     ebx, esi
0x1400861BD: jnb     loc_140086278
0x1400861C3: lea     eax, [rbx+1000h]
0x1400861C9: cmp     eax, esi
0x1400861CB: jnb     loc_140086278
0x1400861D1: lea     rcx, [r15+rbx]
0x1400861D5: mov     eax, r15d
0x1400861D8: lea     edx, [rbx+1000h]
0x1400861DE: sub     eax, ecx
0x1400861E0: xor     r9d, r9d
0x1400861E3: xor     dil, dil
0x1400861E6: add     edx, eax
0x1400861E8: lea     rax, [rsp+230h+var_1E0]
0x1400861ED: lea     r8d, [r9+2]
0x1400861F1: mov     [rsp+230h+var_1F8], rax
0x1400861F6: and     [rsp+230h+var_200], 0
0x1400861FC: and     [rsp+230h+var_208], 0
0x140086202: or      dword ptr [rsp+230h+var_210], 0FFFFFFFFh
0x140086207: call    InitPESectionReadContext
0x14008620C: xor     r14d, r14d
0x14008620F: lea     rdx, [rbp+130h+var_190]
0x140086213: lea     rcx, [rsp+230h+var_1E0]
0x140086218: call    ReadPESectionEntry
0x14008621D: test    eax, eax
0x14008621F: jnz     short loc_140086273
0x140086221: mov     eax, [rbp+130h+var_A0]
0x140086227: mov     rdx, [rsp+230h+var_1D8]
0x14008622C: add     rdx, rax
0x14008622F: mov     rax, [rbp+130h+var_78]
0x140086236: mov     [rsp+230h+var_1D8], rdx
0x14008623B: movzx   ecx, word ptr [rax+6]
0x14008623F: mov     eax, 545h
0x140086244: cmp     ax, cx
0x140086247: jz      loc_1400864A1
0x14008624D: mov     eax, 559h
0x140086252: cmp     ax, cx
0x140086255: jnz     loc_14008644E
0x14008625B: mov     eax, [rbp+130h+var_158]
0x14008625E: sub     eax, r15d
0x140086261: add     eax, edx
0x140086263: jz      loc_14008648F
0x140086269: cmp     eax, esi
0x14008626B: jnb     loc_14008648F
0x140086271: mov     ebx, eax
0x140086273: mov     edi, 545h
0x140086278: test    ebx, ebx
0x14008627A: jz      loc_14008641B
0x140086280: cmp     ebx, esi
0x140086282: jnb     loc_14008641B
0x140086288: lea     eax, [rbx+1000h]
0x14008628E: cmp     eax, esi
0x140086290: jnb     loc_14008641B
0x140086296: mov     edx, r15d
0x140086299: lea     rax, [rsp+230h+var_1E0]
0x14008629E: xor     r9d, r9d
0x1400862A1: mov     [rsp+230h+var_1F8], rax
0x1400862A6: and     [rsp+230h+var_200], 0
0x1400862AC: and     [rsp+230h+var_208], 0
0x1400862B2: or      dword ptr [rsp+230h+var_210], 0FFFFFFFFh
0x1400862B7: mov     ecx, ebx
0x1400862B9: lea     r8d, [r9+2]
0x1400862BD: add     rcx, r15
0x1400862C0: sub     edx, ecx
0x1400862C2: add     edx, 1000h
0x1400862C8: add     edx, ebx
0x1400862CA: call    InitPESectionReadContext
0x1400862CF: xor     edx, edx; Val
0x1400862D1: lea     rcx, [rbp+130h+Dst]; Dst
0x1400862D8: lea     r8d, [rdx+40h]; Size
0x1400862DC: call    memset
0x1400862E1: xor     r14d, r14d
0x1400862E4: lea     rdx, [rbp+130h+var_190]
0x1400862E8: lea     rcx, [rsp+230h+var_1E0]
0x1400862ED: call    ReadPESectionEntry
0x1400862F2: test    eax, eax
0x1400862F4: jnz     loc_14008641B
0x1400862FA: mov     eax, [rbp+130h+var_A0]
0x140086300: mov     rdx, [rsp+230h+var_1D8]
0x140086305: add     rdx, rax
0x140086308: mov     rax, [rbp+130h+var_78]
0x14008630F: mov     [rsp+230h+var_1D8], rdx
0x140086314: movzx   ebx, word ptr [rax+6]
0x140086318: cmp     di, bx
0x14008631B: jz      loc_14008641B
0x140086321: mov     rdi, [rbp+130h+var_140]
0x140086325: mov     eax, 512h
0x14008632A: cmp     ax, bx
0x14008632D: jnz     short loc_14008635B
0x14008632F: cmp     [rbp+130h+var_108], 40000h
0x140086337: jnz     short loc_14008635B
0x140086339: mov     ecx, [rbp+130h+var_118]
0x14008633C: test    ecx, ecx
0x14008633E: jz      short loc_14008635B
0x140086340: cmp     rdi, 40h ; '@'
0x140086344: jnz     short loc_14008635B
0x140086346: sub     ecx, r15d
0x140086349: add     ecx, edx
0x14008634B: jz      short loc_14008635B
0x14008634D: cmp     ecx, esi
0x14008634F: jnb     short loc_14008635B
0x140086351: mov     eax, [rbp+130h+var_138]
0x140086354: mov     [rbp+rax*4+130h+Dst], ecx
0x14008635B: mov     eax, 473h
0x140086360: cmp     ax, bx
0x140086363: jz      short loc_14008636F
0x140086365: mov     eax, 558h
0x14008636A: cmp     ax, bx
0x14008636D: jnz     short loc_14008638B
0x14008636F: xor     edx, edx; Val
0x140086371: lea     rcx, [rbp+130h+Dst]; Dst
0x140086378: lea     r8d, [rdx+40h]; Size
0x14008637C: call    memset
0x140086381: cmp     r12b, 1
0x140086385: jz      loc_14008641B
0x14008638B: mov     eax, 50Eh
0x140086390: cmp     ax, bx
0x140086393: jnz     short loc_140086406
0x140086395: test    rdi, 14000h
0x14008639C: jz      short loc_140086406
0x14008639E: test    dil, 40h
0x1400863A2: jz      short loc_140086406
0x1400863A4: mov     eax, [rbp+130h+var_B4]
0x1400863A7: and     eax, 0Fh
0x1400863AA: cmp     al, 4
0x1400863AC: jz      short loc_140086406
0x1400863AE: cmp     [rbp+130h+var_108], 40h ; '@'
0x1400863B3: jnz     short loc_140086406
0x1400863B5: mov     eax, [rbp+130h+var_150]
0x1400863B8: lea     ecx, [rax-70h]
0x1400863BB: cmp     ecx, 0D8h
0x1400863C1: ja      short loc_140086406
0x1400863C3: and     eax, 7
0x1400863C6: test    al, al
0x1400863C8: jnz     short loc_140086406
0x1400863CA: shr     ecx, 3
0x1400863CD: cmp     ecx, 1Bh
0x1400863D0: ja      short loc_140086406
0x1400863D2: mov     eax, [rbp+130h+var_100]
0x1400863D5: mov     r8d, [rbp+rax*4+130h+Dst]
0x1400863DD: test    r8d, r8d
0x1400863E0: jz      short loc_140086406
0x1400863E2: lea     rdx, [rcx+rcx*2]
0x1400863E6: add     rdx, rdx
0x1400863E9: cmp     dword ptr [r13+rdx*8+4], 0
0x1400863EF: jnz     short loc_140086406
0x1400863F1: mov     ecx, r8d
0x1400863F4: mov     r12b, 1
0x1400863F7: mov     [r13+rdx*8+4], r8d
0x1400863FC: add     rcx, [rsp+230h+var_1F0]
0x140086401: mov     [r13+rdx*8+8], rcx
0x140086406: inc     r14d
0x140086409: mov     edi, 545h
0x14008640E: cmp     r14d, 1F4h
0x140086415: jb      loc_1400862E4
0x14008641B: mov     al, r12b
0x14008641E: mov     rcx, [rbp+130h+var_30]
0x140086425: xor     rcx, rsp; StackCookie
0x140086428: call    __security_check_cookie
0x14008642D: lea     r11, [rsp+230h+var_20]
0x140086435: mov     rbx, [r11+38h]
0x140086439: mov     rsi, [r11+40h]
0x14008643D: mov     rdi, [r11+48h]
0x140086441: mov     rsp, r11
0x140086444: pop     r15
0x140086446: pop     r14
0x140086448: pop     r13
0x14008644A: pop     r12
0x14008644C: pop     rbp
0x14008644D: retn
0x14008644E: mov     eax, 510h
0x140086453: cmp     ax, cx
0x140086456: jnz     short loc_14008646A
0x140086458: cmp     [rbp+130h+var_140], 40h ; '@'
0x14008645D: jnz     short loc_14008646A
0x14008645F: cmp     [rbp+130h+var_138], 1
0x140086463: jnz     short loc_14008646A
0x140086465: mov     dil, 1
0x140086468: jmp     short loc_14008648F
0x14008646A: mov     eax, 558h
0x14008646F: cmp     ax, cx
0x140086472: jnz     short loc_14008648F
0x140086474: cmp     dil, 1
0x140086478: jnz     short loc_14008648C
0x14008647A: mov     eax, [rbp+130h+var_158]
0x14008647D: sub     eax, r15d
0x140086480: add     eax, edx
0x140086482: jz      short loc_14008648C
0x140086484: cmp     eax, esi
0x140086486: jb      loc_140086271
0x14008648C: xor     dil, dil
0x14008648F: inc     r14d
0x140086492: cmp     r14d, 14h
0x140086496: jnb     loc_140086273
0x14008649C: jmp     loc_14008620F
0x1400864A1: mov     edi, eax
0x1400864A3: jmp     loc_140086278