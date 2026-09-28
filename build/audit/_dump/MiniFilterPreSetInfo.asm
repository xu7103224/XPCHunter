# MiniFilterPreSetInfo  ea=0x140015F34  size=1231
0x140015F34: mov     rax, rsp; Minifilter 设置信息回调。处理设置信息操作前的 Minifilter 回调逻辑（反编译失败，约 0x4CF 字节）。
0x140015F37: mov     [rax+8], rbx
0x140015F3B: mov     [rax+10h], rsi
0x140015F3F: mov     [rax+18h], rdi
0x140015F43: push    rbp
0x140015F44: push    r12
0x140015F46: push    r13
0x140015F48: push    r14
0x140015F4A: push    r15
0x140015F4C: lea     rbp, [rax-128h]
0x140015F53: sub     rsp, 200h
0x140015F5A: mov     rax, cs:__security_cookie
0x140015F61: xor     rax, rsp
0x140015F64: mov     [rbp+120h+var_30], rax
0x140015F6B: mov     ecx, 20h ; ' '; Index
0x140015F70: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015F75: mov     ecx, 21h ; '!'; Index
0x140015F7A: mov     r12, rax
0x140015F7D: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015F82: mov     ecx, 3; Index
0x140015F87: mov     rsi, rax
0x140015F8A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015F8F: mov     ecx, 8CCh; Index
0x140015F94: mov     rbx, rax
0x140015F97: mov     [rsp+220h+var_1C8], rax
0x140015F9C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015FA1: mov     ecx, 8CDh; Index
0x140015FA6: mov     rdi, rax
0x140015FA9: mov     [rsp+220h+var_1B8], rax
0x140015FAE: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015FB3: mov     [rsp+220h+var_1C0], rax
0x140015FB8: test    r12, r12
0x140015FBB: jz      loc_140016188
0x140015FC1: test    esi, esi
0x140015FC3: jz      loc_140016188
0x140015FC9: test    rbx, rbx
0x140015FCC: jz      loc_140016188
0x140015FD2: test    edi, edi
0x140015FD4: jz      loc_140016188
0x140015FDA: test    eax, eax
0x140015FDC: jz      loc_140016188
0x140015FE2: mov     edi, esi
0x140015FE4: lea     r8, [rsp+220h+var_1D0]
0x140015FE9: mov     edx, esi
0x140015FEB: add     rdi, r12
0x140015FEE: mov     rcx, r12
0x140015FF1: mov     dword ptr [rsp+220h+var_1D0], 4741502Eh
0x140015FF9: mov     qword ptr [rsp+220h+var_1D8], rdi
0x140015FFE: mov     dword ptr [rsp+220h+var_1D0+4], 45h ; 'E'
0x140016006: call    FindPESectionByName; 按名称查找 PE 节。遍历节表，返回匹配节名的节在文件中的偏移。
0x14001600B: cmp     eax, esi
0x14001600D: lea     r8, [rsp+220h+var_1D0]
0x140016012: mov     edx, esi
0x140016014: sbb     ebx, ebx
0x140016016: mov     rcx, r12
0x140016019: and     ebx, eax
0x14001601B: call    FindPESectionByNameReturnVa; 按名称查找 PE 节返回 VA。遍历节表，返回匹配节名的虚拟地址。
0x140016020: mov     ecx, eax
0x140016022: test    eax, eax
0x140016024: jnz     short loc_14001602A
0x140016026: mov     ecx, esi
0x140016028: sub     ecx, ebx
0x14001602A: mov     eax, esi
0x14001602C: mov     byte ptr [rsp+220h+var_1E0+2], 0
0x140016031: sub     eax, ebx
0x140016033: cmp     ecx, eax
0x140016035: cmova   ecx, eax
0x140016038: mov     eax, ebx
0x14001603A: xor     r9b, r9b
0x14001603D: xor     r8b, r8b
0x140016040: mov     r13d, ecx
0x140016043: mov     byte ptr [rsp+220h+var_1E0+1], r9b
0x140016048: add     r13, rax
0x14001604B: mov     byte ptr [rsp+220h+var_1E0], r8b
0x140016050: add     r13, r12
0x140016053: add     rbx, r12
0x140016056: jmp     loc_14001617F
0x14001605B: lea     rdx, [rbx+1]
0x14001605F: mov     [rsp+220h+var_1B0], rdx
0x140016064: lea     rax, [rdx+2Fh]
0x140016068: cmp     rax, r13
0x14001606B: jnb     loc_140016175
0x140016071: cmp     byte ptr [rbx], 48h ; 'H'
0x140016074: jnz     loc_140016175
0x14001607A: cmp     byte ptr [rdx], 8Dh
0x14001607D: jnz     loc_140016175
0x140016083: lea     r14, [rbx+3]
0x140016087: mov     ecx, ebx
0x140016089: mov     r15d, [r14]
0x14001608C: sub     ecx, r12d
0x14001608F: add     r15d, 7
0x140016093: add     r15d, ecx
0x140016096: jz      loc_140016175
0x14001609C: cmp     r15d, esi
0x14001609F: jnb     loc_140016175
0x1400160A5: cmp     byte ptr [rsp+220h+var_1E0+2], 0
0x1400160AA: jnz     loc_1400161EF
0x1400160B0: lea     rcx, [rbx+7]
0x1400160B4: cmp     byte ptr [rcx], 48h ; 'H'
0x1400160B7: jnz     loc_1400161EF
0x1400160BD: cmp     byte ptr [rbx+8], 89h
0x1400160C1: jnz     loc_1400161EF
0x1400160C7: cmp     byte ptr [rbx+0Ah], 8
0x1400160CB: jnz     loc_1400161EF
0x1400160D1: test    r15d, r15d
0x1400160D4: jz      loc_140016175
0x1400160DA: cmp     r15d, esi
0x1400160DD: jnb     loc_140016175
0x1400160E3: mov     edx, [rsp+220h+var_1D8]
0x1400160E7: lea     rax, [rbp+120h+var_1A0]
0x1400160EB: xor     r9d, r9d
0x1400160EE: mov     qword ptr [rsp+220h+var_1E8], rax
0x1400160F3: and     [rsp+220h+var_1F0], 0
0x1400160F9: and     [rsp+220h+var_1F8], 0
0x1400160FF: or      dword ptr [rsp+220h+var_200], 0FFFFFFFFh
0x140016104: sub     edx, ebx
0x140016106: lea     r8d, [r9+2]
0x14001610A: sub     edx, 7
0x14001610D: xor     r14b, r14b
0x140016110: xor     dil, dil
0x140016113: call    InitPESectionReadContext
0x140016118: xor     ebx, ebx
0x14001611A: lea     rdx, [rbp+120h+var_150]
0x14001611E: lea     rcx, [rbp+120h+var_1A0]
0x140016122: call    ReadPESectionEntry
0x140016127: test    eax, eax
0x140016129: jnz     short loc_14001616B
0x14001612B: mov     eax, [rbp+120h+var_60]
0x140016131: mov     r8d, 1
0x140016137: add     [rbp+120h+var_198], rax
0x14001613B: mov     rax, [rsp+220h+var_1B8]
0x140016140: cmp     eax, [rbp+120h+var_110]
0x140016143: jnz     short loc_14001614A
0x140016145: mov     r14b, r8b
0x140016148: jmp     short loc_14001615E
0x14001614A: cmp     [rbp+120h+var_110], 0FF8h
0x140016151: movzx   edi, dil
0x140016155: cmovz   edi, r8d
0x140016159: cmp     r14b, r8b
0x14001615C: jnz     short loc_140016163
0x14001615E: cmp     dil, r8b
0x140016161: jz      short loc_1400161B8
0x140016163: add     ebx, r8d
0x140016166: cmp     ebx, 6
0x140016169: jb      short loc_14001611A
0x14001616B: mov     r9b, byte ptr [rsp+220h+var_1E0+1]
0x140016170: mov     r8b, byte ptr [rsp+220h+var_1E0]
0x140016175: mov     rbx, [rsp+220h+var_1B0]
0x14001617A: mov     rdi, qword ptr [rsp+220h+var_1D8]
0x14001617F: cmp     rbx, r13
0x140016182: jb      loc_14001605B
0x140016188: mov     rcx, [rbp+120h+var_30]
0x14001618F: xor     rcx, rsp; StackCookie
0x140016192: call    __security_check_cookie
0x140016197: lea     r11, [rsp+220h+var_20]
0x14001619F: mov     rbx, [r11+30h]
0x1400161A3: mov     rsi, [r11+38h]
0x1400161A7: mov     rdi, [r11+40h]
0x1400161AB: mov     rsp, r11
0x1400161AE: pop     r15
0x1400161B0: pop     r14
0x1400161B2: pop     r13
0x1400161B4: pop     r12
0x1400161B6: pop     rbp
0x1400161B7: retn
0x1400161B8: mov     edx, r15d; Value
0x1400161BB: mov     ecx, 332h; Index
0x1400161C0: mov     ebx, r15d
0x1400161C3: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400161C8: mov     rdx, [rsp+220h+var_1C8]
0x1400161CD: mov     ecx, 333h; Index
0x1400161D2: add     rdx, rbx; Value
0x1400161D5: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400161DA: mov     r9b, byte ptr [rsp+220h+var_1E0+1]
0x1400161DF: mov     r14d, 1
0x1400161E5: mov     byte ptr [rsp+220h+var_1E0+2], r14b
0x1400161EA: jmp     loc_1400162E4
0x1400161EF: test    r9b, r9b
0x1400161F2: jnz     loc_14001633B
0x1400161F8: lea     rcx, [rbx+7]
0x1400161FC: cmp     byte ptr [rcx], 41h ; 'A'
0x1400161FF: jnz     short loc_140016207
0x140016201: cmp     byte ptr [rbx+8], 0F6h
0x140016205: jz      short loc_14001621B
0x140016207: cmp     byte ptr [rbx+0Ah], 41h ; 'A'
0x14001620B: jnz     loc_14001633B
0x140016211: cmp     byte ptr [rbx+0Bh], 0F6h
0x140016215: jnz     loc_14001633B
0x14001621B: mov     edx, edi
0x14001621D: lea     rax, [rbp+120h+var_1A0]
0x140016221: xor     r9d, r9d
0x140016224: mov     qword ptr [rsp+220h+var_1E8], rax
0x140016229: and     [rsp+220h+var_1F0], 0
0x14001622F: and     [rsp+220h+var_1F8], 0
0x140016235: or      dword ptr [rsp+220h+var_200], 0FFFFFFFFh
0x14001623A: sub     edx, ebx
0x14001623C: lea     r8d, [r9+2]
0x140016240: sub     edx, 7
0x140016243: call    InitPESectionReadContext
0x140016248: xor     edi, edi
0x14001624A: lea     r15d, [rdi+1]
0x14001624E: lea     rdx, [rbp+120h+var_150]
0x140016252: lea     rcx, [rbp+120h+var_1A0]
0x140016256: call    ReadPESectionEntry
0x14001625B: test    eax, eax
0x14001625D: jnz     short loc_14001628E
0x14001625F: mov     eax, [rbp+120h+var_60]
0x140016265: add     [rbp+120h+var_198], rax
0x140016269: cmp     [rbp+120h+var_C8], 800000h
0x140016271: jnz     short loc_140016286
0x140016273: cmp     [rbp+120h+var_E0], 1000h
0x14001627A: jnz     short loc_140016286
0x14001627C: mov     rax, [rsp+220h+var_1C0]
0x140016281: cmp     eax, [rbp+120h+var_110]
0x140016284: jz      short loc_140016300
0x140016286: add     edi, r15d
0x140016289: cmp     edi, 0Ah
0x14001628C: jb      short loc_14001624E
0x14001628E: lea     rcx, [rbx-30h]
0x140016292: cmp     rbx, r12
0x140016295: jbe     short loc_1400162C9
0x140016297: cmp     rcx, r12
0x14001629A: jbe     short loc_1400162C9
0x14001629C: lea     rdx, [rbx-7]
0x1400162A0: cmp     rcx, rdx
0x1400162A3: jnb     short loc_1400162C9
0x1400162A5: mov     r8, [rsp+220h+var_1C0]
0x1400162AA: cmp     byte ptr [rcx], 0C7h
0x1400162AD: jnz     short loc_1400162C1
0x1400162AF: movzx   eax, byte ptr [rcx+2]
0x1400162B3: cmp     r8d, eax
0x1400162B6: jnz     short loc_1400162C1
0x1400162B8: cmp     dword ptr [rcx+3], 1000h
0x1400162BF: jz      short loc_140016300
0x1400162C1: add     rcx, r15
0x1400162C4: cmp     rcx, rdx
0x1400162C7: jb      short loc_1400162AA
0x1400162C9: mov     r9b, byte ptr [rsp+220h+var_1E0+1]
0x1400162CE: mov     r8b, byte ptr [rsp+220h+var_1E0]
0x1400162D3: mov     r14d, 1
0x1400162D9: cmp     byte ptr [rsp+220h+var_1E0+2], r14b
0x1400162DE: jnz     loc_140016175
0x1400162E4: cmp     r9b, r14b
0x1400162E7: jnz     loc_140016170
0x1400162ED: mov     r8b, byte ptr [rsp+220h+var_1E0]
0x1400162F2: cmp     r8b, r14b
0x1400162F5: jz      loc_140016188
0x1400162FB: jmp     loc_140016175
0x140016300: mov     ecx, [r14]
0x140016303: sub     ebx, r12d
0x140016306: add     ecx, 7
0x140016309: add     ecx, ebx
0x14001630B: jz      short loc_1400162C9
0x14001630D: cmp     ecx, esi
0x14001630F: jnb     short loc_1400162C9
0x140016311: mov     ebx, ecx
0x140016313: mov     edx, ecx; Value
0x140016315: mov     ecx, 334h; Index
0x14001631A: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001631F: mov     rdx, [rsp+220h+var_1C8]
0x140016324: mov     ecx, 335h; Index
0x140016329: add     rdx, rbx; Value
0x14001632C: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140016331: mov     r9b, r15b
0x140016334: mov     byte ptr [rsp+220h+var_1E0+1], r15b
0x140016339: jmp     short loc_1400162CE
0x14001633B: test    r8b, r8b
0x14001633E: jnz     short loc_1400162D3
0x140016340: cmp     byte ptr [rbx+7], 48h ; 'H'
0x140016344: jnz     short loc_1400162D3
0x140016346: cmp     byte ptr [rbx+8], 5
0x14001634A: jnz     short loc_1400162D3
0x14001634C: mov     ecx, 336h; Index
0x140016351: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140016356: cmp     eax, [rbx+9]
0x140016359: jnz     loc_1400162C9
0x14001635F: mov     edx, [rsp+220h+var_1D8]
0x140016363: lea     rax, [rbp+120h+var_1A0]
0x140016367: xor     r9d, r9d
0x14001636A: mov     qword ptr [rsp+220h+var_1E8], rax
0x14001636F: and     [rsp+220h+var_1F0], 0
0x140016375: and     [rsp+220h+var_1F8], 0
0x14001637B: or      dword ptr [rsp+220h+var_200], 0FFFFFFFFh
0x140016380: sub     edx, ebx
0x140016382: lea     r8d, [r9+2]
0x140016386: lea     rcx, [rbx+7]
0x14001638A: sub     edx, 7
0x14001638D: call    InitPESectionReadContext
0x140016392: xor     ebx, ebx
0x140016394: lea     rdx, [rbp+120h+var_150]
0x140016398: lea     rcx, [rbp+120h+var_1A0]
0x14001639C: call    ReadPESectionEntry
0x1400163A1: test    eax, eax
0x1400163A3: jnz     short loc_1400163F4
0x1400163A5: mov     eax, [rbp+120h+var_60]
0x1400163AB: mov     ecx, 0E5h
0x1400163B0: add     [rbp+120h+var_198], rax
0x1400163B4: mov     rax, [rbp+120h+var_38]
0x1400163BB: cmp     cx, [rax+6]
0x1400163BF: jnz     short loc_1400163CB
0x1400163C1: cmp     [rbp+120h+var_100], 40000h
0x1400163C9: jz      short loc_1400163D8
0x1400163CB: inc     ebx
0x1400163CD: cmp     ebx, 0Fh
0x1400163D0: jnb     loc_1400162C9
0x1400163D6: jmp     short loc_140016394
0x1400163D8: mov     edx, r15d
0x1400163DB: mov     ecx, 337h; Index
0x1400163E0: add     rdx, [rsp+220h+var_1C8]; Value
0x1400163E5: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400163EA: mov     r8b, 1
0x1400163ED: mov     byte ptr [rsp+220h+var_1E0], r8b
0x1400163F2: jmp     short loc_1400163F9
0x1400163F4: mov     r8b, byte ptr [rsp+220h+var_1E0]
0x1400163F9: mov     r9b, byte ptr [rsp+220h+var_1E0+1]
0x1400163FE: jmp     loc_1400162D3