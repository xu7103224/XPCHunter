# ParseNtExportSectionsForProcessContext  ea=0x140039214  size=972
0x140039214: mov     rax, rsp
0x140039217: mov     [rax+10h], rbx
0x14003921B: mov     [rax+18h], rsi
0x14003921F: mov     [rax+20h], rdi
0x140039223: push    rbp
0x140039224: push    r12
0x140039226: push    r13
0x140039228: push    r14
0x14003922A: push    r15
0x14003922C: lea     rbp, [rax-148h]
0x140039233: sub     rsp, 220h
0x14003923A: mov     rax, cs:__security_cookie
0x140039241: xor     rax, rsp
0x140039244: mov     [rbp+140h+var_30], rax
0x14003924B: mov     r12, rcx
0x14003924E: mov     ecx, 8C4h; Index
0x140039253: mov     esi, edx
0x140039255: xor     edi, edi
0x140039257: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003925C: mov     ecx, 2024h; Index
0x140039261: mov     r13, rax
0x140039264: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x140039269: mov     ecx, 20D2h; Index
0x14003926E: mov     r15, rax
0x140039271: mov     [rsp+240h+var_1F8], rax
0x140039276: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x14003927B: mov     [rsp+240h+var_1F0], rax
0x140039280: test    r13, r13
0x140039283: jz      loc_1400394C3
0x140039289: movsxd  rax, dword ptr [r12+3Ch]
0x14003928E: mov     ebx, [rax+r12+28h]
0x140039293: mov     r14, [rax+r12+30h]
0x140039298: mov     [rsp+240h+var_200], r14
0x14003929D: cmp     ebx, esi
0x14003929F: jnb     loc_14003934F
0x1400392A5: lea     eax, [rbx+1000h]
0x1400392AB: cmp     eax, esi
0x1400392AD: jnb     loc_14003934F
0x1400392B3: lea     rcx, [r12+rbx]
0x1400392B7: mov     eax, r12d
0x1400392BA: lea     edx, [rbx+1000h]
0x1400392C0: sub     eax, ecx
0x1400392C2: lea     r8d, [rdi+2]
0x1400392C6: xor     r9d, r9d
0x1400392C9: add     edx, eax
0x1400392CB: lea     rax, [rsp+240h+var_1E0]
0x1400392D0: mov     r14b, dil
0x1400392D3: mov     [rsp+240h+var_208], rax
0x1400392D8: mov     [rsp+240h+var_210], rdi
0x1400392DD: mov     [rsp+240h+var_218], rdi
0x1400392E2: or      dword ptr [rsp+240h+var_220], 0FFFFFFFFh
0x1400392E7: call    InitPESectionReadContext
0x1400392EC: mov     r15d, edi
0x1400392EF: lea     rdx, [rbp+140h+var_190]
0x1400392F3: lea     rcx, [rsp+240h+var_1E0]
0x1400392F8: call    ReadPESectionEntry
0x1400392FD: test    eax, eax
0x1400392FF: jnz     short loc_140039345
0x140039301: mov     eax, [rbp+140h+var_A0]
0x140039307: mov     rcx, [rsp+240h+var_1D8]
0x14003930C: add     rcx, rax
0x14003930F: mov     rax, [rbp+140h+var_78]
0x140039316: mov     [rsp+240h+var_1D8], rcx
0x14003931B: movzx   edx, word ptr [rax+6]
0x14003931F: mov     eax, 559h
0x140039324: cmp     ax, dx
0x140039327: jnz     loc_1400394F6
0x14003932D: mov     eax, [rbp+140h+var_158]
0x140039330: sub     eax, r12d
0x140039333: add     eax, ecx
0x140039335: jz      loc_140039537
0x14003933B: cmp     eax, esi
0x14003933D: jnb     loc_140039537
0x140039343: mov     ebx, eax
0x140039345: mov     r15, [rsp+240h+var_1F8]
0x14003934A: mov     r14, [rsp+240h+var_200]
0x14003934F: test    ebx, ebx
0x140039351: jz      loc_1400394C3
0x140039357: cmp     ebx, esi
0x140039359: jnb     loc_1400394C3
0x14003935F: lea     eax, [rbx+1000h]
0x140039365: cmp     eax, esi
0x140039367: jnb     loc_1400394C3
0x14003936D: mov     eax, r12d
0x140039370: lea     edx, [rbx+1000h]
0x140039376: xor     r9d, r9d
0x140039379: mov     ecx, ebx
0x14003937B: lea     r8d, [r9+2]
0x14003937F: add     rcx, r12
0x140039382: sub     eax, ecx
0x140039384: add     edx, eax
0x140039386: lea     rax, [rsp+240h+var_1E0]
0x14003938B: mov     [rsp+240h+var_208], rax
0x140039390: mov     [rsp+240h+var_210], rdi
0x140039395: mov     [rsp+240h+var_218], rdi
0x14003939A: or      dword ptr [rsp+240h+var_220], 0FFFFFFFFh
0x14003939F: call    InitPESectionReadContext
0x1400393A4: xor     edx, edx; Val
0x1400393A6: lea     r8d, [rdx+40h]; Size
0x1400393AA: lea     rcx, [rbp+140h+Dst]; Dst
0x1400393B1: call    memset
0x1400393B6: mov     ebx, edi
0x1400393B8: lea     rdx, [rbp+140h+var_190]
0x1400393BC: lea     rcx, [rsp+240h+var_1E0]
0x1400393C1: call    ReadPESectionEntry
0x1400393C6: test    eax, eax
0x1400393C8: jnz     loc_1400394C3
0x1400393CE: mov     eax, [rbp+140h+var_A0]
0x1400393D4: mov     rdx, [rsp+240h+var_1D8]
0x1400393D9: mov     r10, [rbp+140h+var_108]
0x1400393DD: mov     r8, [rbp+140h+var_140]
0x1400393E1: add     rdx, rax
0x1400393E4: mov     rax, [rbp+140h+var_78]
0x1400393EB: mov     [rsp+240h+var_1D8], rdx
0x1400393F0: movzx   r9d, word ptr [rax+6]
0x1400393F5: mov     eax, 512h
0x1400393FA: cmp     ax, r9w
0x1400393FE: jnz     short loc_140039431
0x140039400: cmp     r10, 40000h
0x140039407: jnz     short loc_140039431
0x140039409: mov     ecx, [rbp+140h+var_118]
0x14003940C: test    ecx, ecx
0x14003940E: jz      short loc_140039431
0x140039410: cmp     r8, 40h ; '@'
0x140039414: jnz     short loc_140039431
0x140039416: sub     ecx, r12d
0x140039419: add     ecx, edx
0x14003941B: jz      short loc_140039431
0x14003941D: cmp     ecx, esi
0x14003941F: jnb     short loc_140039431
0x140039421: cmp     [rbp+140h+var_138], 10h
0x140039425: jnb     short loc_140039431
0x140039427: mov     eax, [rbp+140h+var_138]
0x14003942A: mov     [rbp+rax*4+140h+Dst], ecx
0x140039431: mov     ecx, [rbp+140h+var_B4]
0x140039437: mov     edx, [rbp+140h+var_100]
0x14003943A: mov     eax, 50Eh
0x14003943F: cmp     ax, r9w
0x140039443: jnz     loc_1400395CD
0x140039449: mov     eax, [rbp+140h+var_B8]
0x14003944F: mov     r11d, 300h
0x140039455: and     eax, r11d
0x140039458: cmp     eax, 100h
0x14003945D: jnz     loc_140039549
0x140039463: cmp     [rbp+140h+var_150], 70h ; 'p'
0x140039467: jnz     loc_140039549
0x14003946D: mov     eax, ecx
0x14003946F: and     eax, r11d
0x140039472: cmp     eax, r11d
0x140039475: jnz     loc_140039549
0x14003947B: cmp     r10, 40h ; '@'
0x14003947F: jnz     loc_140039549
0x140039485: cmp     edx, 10h
0x140039488: jnb     loc_140039549
0x14003948E: mov     ecx, [rbp+rdx*4+140h+Dst]
0x140039495: test    ecx, ecx
0x140039497: jz      loc_1400395CD
0x14003949D: cmp     ecx, esi
0x14003949F: jnb     loc_1400395CD
0x1400394A5: lea     r8, [rcx+r13]
0x1400394A9: lea     rax, [r15+8]
0x1400394AD: lea     edx, [r10-24h]
0x1400394B1: mov     [rax-4], ecx
0x1400394B4: mov     [rax], r8
0x1400394B7: lea     rax, [rax+30h]
0x1400394BB: dec     rdx
0x1400394BE: jnz     short loc_1400394B1
0x1400394C0: mov     dil, 1
0x1400394C3: mov     al, dil
0x1400394C6: mov     rcx, [rbp+140h+var_30]
0x1400394CD: xor     rcx, rsp; StackCookie
0x1400394D0: call    __security_check_cookie
0x1400394D5: lea     r11, [rsp+240h+var_20]
0x1400394DD: mov     rbx, [r11+38h]
0x1400394E1: mov     rsi, [r11+40h]
0x1400394E5: mov     rdi, [r11+48h]
0x1400394E9: mov     rsp, r11
0x1400394EC: pop     r15
0x1400394EE: pop     r14
0x1400394F0: pop     r13
0x1400394F2: pop     r12
0x1400394F4: pop     rbp
0x1400394F5: retn
0x1400394F6: mov     eax, 510h
0x1400394FB: cmp     ax, dx
0x1400394FE: jnz     short loc_140039512
0x140039500: cmp     [rbp+140h+var_140], 40h ; '@'
0x140039505: jnz     short loc_140039512
0x140039507: cmp     [rbp+140h+var_138], 1
0x14003950B: jnz     short loc_140039512
0x14003950D: mov     r14b, 1
0x140039510: jmp     short loc_140039537
0x140039512: mov     eax, 558h
0x140039517: cmp     ax, dx
0x14003951A: jnz     short loc_140039537
0x14003951C: cmp     r14b, 1
0x140039520: jnz     short loc_140039534
0x140039522: mov     eax, [rbp+140h+var_158]
0x140039525: sub     eax, r12d
0x140039528: add     eax, ecx
0x14003952A: jz      short loc_140039534
0x14003952C: cmp     eax, esi
0x14003952E: jb      loc_140039343
0x140039534: mov     r14b, dil
0x140039537: inc     r15d
0x14003953A: cmp     r15d, 14h
0x14003953E: jnb     loc_140039345
0x140039544: jmp     loc_1400392EF
0x140039549: mov     eax, 50Eh
0x14003954E: cmp     ax, r9w
0x140039552: jnz     short loc_1400395CD
0x140039554: test    r8, 14000h
0x14003955B: jz      short loc_1400395CD
0x14003955D: test    r8b, 40h
0x140039561: jz      short loc_1400395CD
0x140039563: and     ecx, 0Fh
0x140039566: cmp     cl, 4
0x140039569: jz      short loc_1400395CD
0x14003956B: cmp     r10, 40h ; '@'
0x14003956F: jnz     short loc_1400395CD
0x140039571: cmp     [rbp+140h+var_150], 50h ; 'P'
0x140039575: jnz     short loc_1400395CD
0x140039577: mov     ecx, [rbp+rdx*4+140h+Dst]
0x14003957E: test    ecx, ecx
0x140039580: jz      short loc_1400395CD
0x140039582: cmp     ecx, esi
0x140039584: jnb     short loc_1400395CD
0x140039586: mov     edx, ecx
0x140039588: add     rcx, 0E0h
0x14003958F: cmp     rcx, rsi
0x140039592: ja      short loc_1400395CD
0x140039594: mov     rcx, [rsp+240h+var_1F0]
0x140039599: add     rdx, 8
0x14003959D: lea     r8d, [r10-25h]
0x1400395A1: add     rcx, 8
0x1400395A5: add     rdx, r12
0x1400395A8: mov     rax, [rdx]
0x1400395AB: cmp     rax, r14
0x1400395AE: jbe     short loc_1400395C0
0x1400395B0: sub     eax, r14d
0x1400395B3: cmp     esi, eax
0x1400395B5: jbe     short loc_1400395C0
0x1400395B7: mov     [rcx-4], eax
0x1400395BA: add     rax, r13
0x1400395BD: mov     [rcx], rax
0x1400395C0: add     rdx, 8
0x1400395C4: add     rcx, 30h ; '0'
0x1400395C8: dec     r8
0x1400395CB: jnz     short loc_1400395A8
0x1400395CD: inc     ebx
0x1400395CF: cmp     ebx, 1F4h
0x1400395D5: jnb     loc_1400394C3
0x1400395DB: jmp     loc_1400393B8