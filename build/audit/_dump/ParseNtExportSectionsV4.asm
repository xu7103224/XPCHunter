# ParseNtExportSectionsV4  ea=0x1400382FC  size=727
0x1400382FC: mov     rax, rsp
0x1400382FF: mov     [rax+8], rbx
0x140038303: mov     [rax+10h], rsi
0x140038307: mov     [rax+18h], rdi
0x14003830B: push    rbp
0x14003830C: push    r12
0x14003830E: push    r13
0x140038310: push    r14
0x140038312: push    r15
0x140038314: lea     rbp, [rax-0E8h]
0x14003831B: sub     rsp, 1C0h
0x140038322: mov     rax, cs:__security_cookie
0x140038329: xor     rax, rsp
0x14003832C: mov     [rbp+0E0h+var_30], rax
0x140038333: xor     ebx, ebx
0x140038335: lea     ecx, [rbx+3]; Index
0x140038338: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003833D: lea     ecx, [rbx+20h]; Index
0x140038340: mov     r12, rax
0x140038343: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140038348: lea     ecx, [rbx+21h]; Index
0x14003834B: mov     r15, rax
0x14003834E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140038353: mov     ecx, 43A5h; Index
0x140038358: mov     rsi, rax
0x14003835B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140038360: mov     rcx, rax
0x140038363: test    r12, r12
0x140038366: jz      loc_1400385A1
0x14003836C: test    r15, r15
0x14003836F: jz      loc_1400385A1
0x140038375: test    esi, esi
0x140038377: jz      loc_1400385A1
0x14003837D: test    eax, eax
0x14003837F: jz      loc_1400385A1
0x140038385: cmp     eax, esi
0x140038387: jnb     loc_1400385A1
0x14003838D: add     eax, 1000h
0x140038392: cmp     eax, esi
0x140038394: jnb     loc_1400385A1
0x14003839A: lea     rax, [rsp+1E0h+var_1A0]
0x14003839F: mov     ecx, ecx
0x1400383A1: lea     r8d, [rbx+2]
0x1400383A5: mov     qword ptr [rsp+1E0h+var_1A8], rax
0x1400383AA: mov     [rsp+1E0h+var_1B0], rbx
0x1400383AF: xor     r9d, r9d
0x1400383B2: add     rcx, r15
0x1400383B5: mov     edx, 1000h
0x1400383BA: mov     [rsp+1E0h+var_1B8], rbx
0x1400383BF: or      dword ptr [rsp+1E0h+var_1C0], 0FFFFFFFFh
0x1400383C4: call    InitPESectionReadContext
0x1400383C9: mov     edi, ebx
0x1400383CB: mov     r14d, ebx
0x1400383CE: mov     r13d, 558h
0x1400383D4: lea     rdx, [rbp+0E0h+var_150]
0x1400383D8: lea     rcx, [rsp+1E0h+var_1A0]
0x1400383DD: call    ReadPESectionEntry
0x1400383E2: test    eax, eax
0x1400383E4: jnz     loc_1400385A1
0x1400383EA: mov     eax, [rbp+0E0h+var_60]
0x1400383F0: mov     rcx, [rsp+1E0h+var_198]
0x1400383F5: add     rcx, rax
0x1400383F8: mov     rax, [rbp+0E0h+var_38]
0x1400383FF: mov     [rsp+1E0h+var_198], rcx
0x140038404: cmp     r13w, [rax+6]
0x140038409: jnz     short loc_14003841A
0x14003840B: cmp     [rbp+0E0h+var_118], ebx
0x14003840E: jz      short loc_14003841A
0x140038410: mov     edi, [rbp+0E0h+var_118]
0x140038413: sub     edi, r15d
0x140038416: add     edi, ecx
0x140038418: jmp     short loc_140038435
0x14003841A: cmp     [rbp+0E0h+var_C8], 800000h
0x140038422: jnz     short loc_140038435
0x140038424: cmp     [rbp+0E0h+var_E0], 0C0000259h
0x14003842B: jnz     short loc_140038435
0x14003842D: test    edi, edi
0x14003842F: jz      short loc_140038435
0x140038431: cmp     edi, esi
0x140038433: jb      short loc_140038444
0x140038435: inc     r14d
0x140038438: cmp     r14d, 64h ; 'd'
0x14003843C: jnb     loc_1400385A1
0x140038442: jmp     short loc_1400383D4
0x140038444: test    edi, edi
0x140038446: jz      loc_1400385A1
0x14003844C: lea     rax, [rsp+1E0h+var_1A0]
0x140038451: xor     r9d, r9d
0x140038454: mov     ecx, edi
0x140038456: mov     qword ptr [rsp+1E0h+var_1A8], rax
0x14003845B: mov     [rsp+1E0h+var_1B0], rbx
0x140038460: lea     r8d, [r9+2]
0x140038464: add     rcx, r15
0x140038467: mov     edx, 1000h
0x14003846C: mov     [rsp+1E0h+var_1B8], rbx
0x140038471: or      dword ptr [rsp+1E0h+var_1C0], 0FFFFFFFFh
0x140038476: call    InitPESectionReadContext
0x14003847B: mov     r14b, bl
0x14003847E: mov     edi, ebx
0x140038480: mov     r13d, 40000h
0x140038486: lea     rdx, [rbp+0E0h+var_150]
0x14003848A: lea     rcx, [rsp+1E0h+var_1A0]
0x14003848F: call    ReadPESectionEntry
0x140038494: test    eax, eax
0x140038496: jnz     loc_1400385A1
0x14003849C: mov     rcx, [rsp+1E0h+var_198]
0x1400384A1: mov     eax, [rbp+0E0h+var_60]
0x1400384A7: add     rcx, rax
0x1400384AA: cmp     [rbp+0E0h+var_100], 200h
0x1400384B2: mov     [rsp+1E0h+var_198], rcx
0x1400384B7: jnz     short loc_1400384C4
0x1400384B9: cmp     [rbp+0E0h+var_C8], r13
0x1400384BD: jnz     short loc_1400384C4
0x1400384BF: mov     r14b, 1
0x1400384C2: jmp     short loc_1400384EE
0x1400384C4: cmp     r14b, 1
0x1400384C8: jnz     short loc_1400384EE
0x1400384CA: mov     rax, [rbp+0E0h+var_38]
0x1400384D1: mov     edx, 558h
0x1400384D6: cmp     dx, [rax+6]
0x1400384DA: jnz     short loc_1400384EE
0x1400384DC: mov     eax, [rbp+0E0h+var_118]
0x1400384DF: test    eax, eax
0x1400384E1: jz      short loc_1400384EE
0x1400384E3: sub     eax, r15d
0x1400384E6: add     eax, ecx
0x1400384E8: jz      short loc_1400384EE
0x1400384EA: cmp     eax, esi
0x1400384EC: jb      short loc_1400384FE
0x1400384EE: inc     edi
0x1400384F0: cmp     edi, 12Ch
0x1400384F6: jnb     loc_1400385A1
0x1400384FC: jmp     short loc_140038486
0x1400384FE: mov     ecx, eax
0x140038500: xor     r9d, r9d
0x140038503: lea     rax, [rsp+1E0h+var_1A0]
0x140038508: mov     qword ptr [rsp+1E0h+var_1A8], rax
0x14003850D: mov     [rsp+1E0h+var_1B0], rbx
0x140038512: lea     r8d, [r9+2]
0x140038516: add     rcx, r15
0x140038519: mov     edx, 1000h
0x14003851E: mov     [rsp+1E0h+var_1B8], rbx
0x140038523: or      dword ptr [rsp+1E0h+var_1C0], 0FFFFFFFFh
0x140038528: call    InitPESectionReadContext
0x14003852D: mov     edi, ebx
0x14003852F: lea     rdx, [rbp+0E0h+var_150]
0x140038533: lea     rcx, [rsp+1E0h+var_1A0]
0x140038538: call    ReadPESectionEntry
0x14003853D: test    eax, eax
0x14003853F: jnz     short loc_1400385A1
0x140038541: mov     eax, [rbp+0E0h+var_60]
0x140038547: mov     rcx, [rsp+1E0h+var_198]
0x14003854C: mov     edx, 510h
0x140038551: add     rcx, rax
0x140038554: mov     rax, [rbp+0E0h+var_38]
0x14003855B: mov     [rsp+1E0h+var_198], rcx
0x140038560: cmp     dx, [rax+6]
0x140038564: jnz     short loc_140038587
0x140038566: cmp     [rbp+0E0h+var_100], 40h ; '@'
0x14003856B: jnz     short loc_140038587
0x14003856D: cmp     [rbp+0E0h+var_C8], r13
0x140038571: jnz     short loc_140038587
0x140038573: cmp     [rbp+0E0h+var_F8], 2
0x140038577: jnz     short loc_140038587
0x140038579: mov     eax, [rbp+0E0h+var_D8]
0x14003857C: sub     eax, r15d
0x14003857F: add     eax, ecx
0x140038581: jz      short loc_140038587
0x140038583: cmp     eax, esi
0x140038585: jb      short loc_140038590
0x140038587: inc     edi
0x140038589: cmp     edi, 64h ; 'd'
0x14003858C: jnb     short loc_1400385A1
0x14003858E: jmp     short loc_14003852F
0x140038590: mov     edx, eax
0x140038592: mov     ecx, 1A3h; Index
0x140038597: add     rdx, r12; Value
0x14003859A: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14003859F: mov     bl, 1
0x1400385A1: mov     al, bl
0x1400385A3: mov     rcx, [rbp+0E0h+var_30]
0x1400385AA: xor     rcx, rsp; StackCookie
0x1400385AD: call    __security_check_cookie
0x1400385B2: lea     r11, [rsp+1E0h+var_20]
0x1400385BA: mov     rbx, [r11+30h]
0x1400385BE: mov     rsi, [r11+38h]
0x1400385C2: mov     rdi, [r11+40h]
0x1400385C6: mov     rsp, r11
0x1400385C9: pop     r15
0x1400385CB: pop     r14
0x1400385CD: pop     r13
0x1400385CF: pop     r12
0x1400385D1: pop     rbp
0x1400385D2: retn