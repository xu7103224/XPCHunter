# MiniFilterPreClose  ea=0x1400152D4  size=1908
0x1400152D4: mov     rax, rsp; Minifilter 预关闭回调。处理文件关闭前的 Minifilter 回调逻辑（反编译失败，约 0x774 字节）。
0x1400152D7: mov     [rax+8], rbx
0x1400152DB: mov     [rax+10h], rsi
0x1400152DF: mov     [rax+18h], rdi
0x1400152E3: push    rbp
0x1400152E4: push    r12
0x1400152E6: push    r13
0x1400152E8: push    r14
0x1400152EA: push    r15
0x1400152EC: lea     rbp, [rax-148h]
0x1400152F3: sub     rsp, 220h
0x1400152FA: mov     rax, cs:__security_cookie
0x140015301: xor     rax, rsp
0x140015304: mov     [rbp+140h+var_30], rax
0x14001530B: mov     ecx, 20h ; ' '; Index
0x140015310: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015315: mov     ecx, 21h ; '!'; Index
0x14001531A: mov     rsi, rax
0x14001531D: mov     [rsp+240h+var_1F8], rax
0x140015322: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015327: mov     ecx, 3; Index
0x14001532C: mov     r12, rax
0x14001532F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015334: mov     ecx, 8CCh; Index
0x140015339: mov     rdi, rax
0x14001533C: mov     [rsp+240h+var_1F0], rax
0x140015341: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015346: mov     ecx, 900h; Index
0x14001534B: mov     r14, rax
0x14001534E: mov     [rbp+140h+var_1C0], rax
0x140015352: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015357: mov     ecx, 8CDh; Index
0x14001535C: mov     r15, rax
0x14001535F: mov     [rbp+140h+var_1B0], rax
0x140015363: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140015368: mov     ecx, 4459h; Index
0x14001536D: mov     rbx, rax
0x140015370: mov     [rsp+240h+var_1D0], rax
0x140015375: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001537A: mov     [rbp+140h+var_1B8], rax
0x14001537E: test    rsi, rsi
0x140015381: jz      loc_1400159F4
0x140015387: test    r12d, r12d
0x14001538A: jz      loc_1400159F4
0x140015390: test    rdi, rdi
0x140015393: jz      loc_1400159F4
0x140015399: test    r14d, r14d
0x14001539C: jz      loc_1400159F4
0x1400153A2: test    r15d, r15d
0x1400153A5: jz      loc_1400159F4
0x1400153AB: test    ebx, ebx
0x1400153AD: jz      loc_1400159F4
0x1400153B3: mov     edi, r12d
0x1400153B6: lea     r8, [rsp+240h+var_1E0]
0x1400153BB: mov     edx, r12d
0x1400153BE: add     rdi, rsi
0x1400153C1: mov     rcx, rsi
0x1400153C4: mov     dword ptr [rsp+240h+var_1E0], 4741502Eh
0x1400153CC: mov     qword ptr [rsp+240h+var_1E8], rdi
0x1400153D1: mov     dword ptr [rsp+240h+var_1E0+4], 45h ; 'E'
0x1400153D9: call    FindPESectionByName; 按名称查找 PE 节。遍历节表，返回匹配节名的节在文件中的偏移。
0x1400153DE: cmp     eax, r12d
0x1400153E1: lea     r8, [rsp+240h+var_1E0]
0x1400153E6: mov     edx, r12d
0x1400153E9: sbb     ebx, ebx
0x1400153EB: mov     rcx, rsi
0x1400153EE: and     ebx, eax
0x1400153F0: call    FindPESectionByNameReturnVa; 按名称查找 PE 节返回 VA。遍历节表，返回匹配节名的虚拟地址。
0x1400153F5: mov     ecx, eax
0x1400153F7: test    eax, eax
0x1400153F9: jnz     short loc_140015400
0x1400153FB: mov     ecx, r12d
0x1400153FE: sub     ecx, ebx
0x140015400: mov     eax, r12d
0x140015403: lea     r13, [rbx+rsi]
0x140015407: sub     eax, ebx
0x140015409: mov     [rsp+240h+var_1C8], r13
0x14001540E: cmp     ecx, eax
0x140015410: cmova   ecx, eax
0x140015413: xor     r8b, r8b
0x140015416: xor     r14b, r14b
0x140015419: xor     dl, dl
0x14001541B: mov     eax, ebx
0x14001541D: mov     byte ptr [rsp+240h+Value+2], r8b
0x140015422: add     rcx, rax
0x140015425: mov     byte ptr [rsp+240h+Value], r14b
0x14001542A: mov     byte ptr [rsp+240h+Value+1], dl
0x14001542E: add     rcx, rsi
0x140015431: mov     [rsp+240h+var_1D8], rcx
0x140015436: cmp     r13, rcx
0x140015439: jnb     loc_1400159F4
0x14001543F: mov     r9d, 7
0x140015445: lea     rax, [r13+30h]
0x140015449: cmp     rax, rcx
0x14001544C: jnb     loc_1400159E3
0x140015452: cmp     byte ptr [r13+0], 48h ; 'H'
0x140015457: jnz     loc_1400159E3
0x14001545D: cmp     byte ptr [r13+1], 8Dh
0x140015462: jnz     loc_1400159E3
0x140015468: mov     eax, [r13+3]
0x14001546C: lea     r14d, [r13+7]
0x140015470: sub     eax, esi
0x140015472: add     r14d, eax
0x140015475: mov     dword ptr [rsp+240h+Value+4], r14d
0x14001547A: jz      loc_1400159E3
0x140015480: cmp     r14d, r12d
0x140015483: jnb     loc_1400159E3
0x140015489: lea     r15, [r13+7]
0x14001548D: cmp     byte ptr [r15], 48h ; 'H'
0x140015491: jnz     loc_140015856
0x140015497: cmp     byte ptr [r13+8], 89h
0x14001549C: jnz     loc_140015856
0x1400154A2: cmp     byte ptr [r13+0Ah], 8
0x1400154A7: jnz     loc_140015856
0x1400154AD: test    r8b, r8b
0x1400154B0: jnz     loc_140015584
0x1400154B6: mov     edx, [rsp+240h+var_1E8]
0x1400154BA: xor     edi, edi
0x1400154BC: lea     rax, [rbp+140h+var_1A0]
0x1400154C0: mov     qword ptr [rsp+240h+var_208], rax
0x1400154C5: and     [rsp+240h+var_210], rdi
0x1400154CA: and     [rsp+240h+var_218], rdi
0x1400154CF: or      dword ptr [rsp+240h+var_220], 0FFFFFFFFh
0x1400154D4: sub     edx, r13d
0x1400154D7: lea     r8d, [rdi+2]
0x1400154DB: sub     edx, r9d
0x1400154DE: mov     rcx, r15
0x1400154E1: xor     r9d, r9d
0x1400154E4: xor     r14b, r14b
0x1400154E7: xor     bl, bl
0x1400154E9: call    InitPESectionReadContext
0x1400154EE: xor     esi, esi
0x1400154F0: lea     rdx, [rbp+140h+var_150]
0x1400154F4: lea     rcx, [rbp+140h+var_1A0]
0x1400154F8: call    ReadPESectionEntry
0x1400154FD: test    eax, eax
0x1400154FF: jnz     short loc_140015570
0x140015501: mov     eax, [rbp+140h+var_60]
0x140015507: mov     rcx, [rbp+140h+var_198]
0x14001550B: mov     edx, 512h
0x140015510: add     rcx, rax
0x140015513: mov     rax, [rbp+140h+var_38]
0x14001551A: mov     [rbp+140h+var_198], rcx
0x14001551E: cmp     dx, [rax+6]
0x140015522: jnz     loc_14001566D
0x140015528: cmp     [rbp+140h+var_C8], 40000h
0x140015530: jnz     short loc_140015553
0x140015532: mov     eax, [rbp+140h+var_D8]
0x140015535: test    eax, eax
0x140015537: jz      short loc_140015553
0x140015539: cmp     [rbp+140h+var_100], 40h ; '@'
0x14001553E: jnz     short loc_140015553
0x140015540: sub     eax, dword ptr [rsp+240h+var_1F8]
0x140015544: add     eax, ecx
0x140015546: jz      short loc_140015553
0x140015548: cmp     eax, r12d
0x14001554B: jnb     short loc_140015553
0x14001554D: test    edi, edi
0x14001554F: jnz     short loc_140015553
0x140015551: mov     edi, eax
0x140015553: mov     eax, 1
0x140015558: cmp     r14b, al
0x14001555B: jnz     short loc_140015569
0x14001555D: cmp     bl, al
0x14001555F: jnz     short loc_140015569
0x140015561: test    edi, edi
0x140015563: jnz     loc_14001569A
0x140015569: add     esi, eax
0x14001556B: cmp     esi, 0Ah
0x14001556E: jb      short loc_1400154F0
0x140015570: mov     r8b, byte ptr [rsp+240h+Value+2]
0x140015575: mov     r14d, dword ptr [rsp+240h+Value+4]
0x14001557A: mov     dl, byte ptr [rsp+240h+Value+1]
0x14001557E: mov     r9d, 7
0x140015584: cmp     byte ptr [rsp+240h+Value], 0
0x140015589: jnz     loc_1400159B6
0x14001558F: test    r14d, r14d
0x140015592: jz      loc_1400159B6
0x140015598: cmp     r14d, r12d
0x14001559B: jnb     loc_1400159B6
0x1400155A1: mov     edx, [rsp+240h+var_1E8]
0x1400155A5: xor     r14d, r14d
0x1400155A8: lea     rax, [rbp+140h+var_1A0]
0x1400155AC: mov     qword ptr [rsp+240h+var_208], rax
0x1400155B1: and     [rsp+240h+var_210], r14
0x1400155B6: and     [rsp+240h+var_218], r14
0x1400155BB: or      dword ptr [rsp+240h+var_220], 0FFFFFFFFh
0x1400155C0: sub     edx, r13d
0x1400155C3: lea     r8d, [r14+2]
0x1400155C7: sub     edx, r9d
0x1400155CA: mov     rcx, r15
0x1400155CD: xor     r9d, r9d
0x1400155D0: xor     bl, bl
0x1400155D2: xor     dil, dil
0x1400155D5: call    InitPESectionReadContext
0x1400155DA: mov     r13, [rsp+240h+var_1F8]
0x1400155DF: xor     esi, esi
0x1400155E1: lea     r15d, [r14+1]
0x1400155E5: lea     rdx, [rbp+140h+var_150]
0x1400155E9: lea     rcx, [rbp+140h+var_1A0]
0x1400155ED: call    ReadPESectionEntry
0x1400155F2: test    eax, eax
0x1400155F4: jnz     loc_14001575B
0x1400155FA: mov     eax, [rbp+140h+var_60]
0x140015600: mov     rdx, [rbp+140h+var_198]
0x140015604: add     rdx, rax
0x140015607: mov     rax, [rbp+140h+var_38]
0x14001560E: mov     [rbp+140h+var_198], rdx
0x140015612: movzx   ecx, word ptr [rax+6]
0x140015616: mov     eax, 512h
0x14001561B: cmp     ax, cx
0x14001561E: jnz     loc_1400156EC
0x140015624: cmp     [rbp+140h+var_C8], 40000h
0x14001562C: jnz     loc_14001574F
0x140015632: mov     eax, [rbp+140h+var_D8]
0x140015635: test    eax, eax
0x140015637: jz      loc_14001574F
0x14001563D: cmp     [rbp+140h+var_100], 40h ; '@'
0x140015642: jnz     loc_14001574F
0x140015648: sub     eax, r13d
0x14001564B: add     eax, edx
0x14001564D: jz      loc_14001574F
0x140015653: cmp     eax, r12d
0x140015656: jnb     loc_14001574F
0x14001565C: test    r14d, r14d
0x14001565F: jnz     loc_14001574F
0x140015665: mov     r14d, eax
0x140015668: jmp     loc_14001574F
0x14001566D: mov     rax, [rbp+140h+var_1C0]
0x140015671: cmp     eax, [rbp+140h+var_110]
0x140015674: jnz     short loc_140015683
0x140015676: mov     eax, 1
0x14001567B: mov     r14d, eax
0x14001567E: jmp     loc_14001555D
0x140015683: mov     rax, [rbp+140h+var_1B0]
0x140015687: movzx   ebx, bl
0x14001568A: cmp     eax, [rbp+140h+var_110]
0x14001568D: mov     eax, 1
0x140015692: cmovz   ebx, eax
0x140015695: jmp     loc_140015558
0x14001569A: mov     r14d, dword ptr [rsp+240h+Value+4]
0x14001569F: mov     ecx, 332h; Index
0x1400156A4: mov     edx, r14d; Value
0x1400156A7: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400156AC: mov     rsi, [rsp+240h+var_1F0]
0x1400156B1: mov     ecx, 333h; Index
0x1400156B6: lea     rdx, [r14+rsi]; Value
0x1400156BA: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400156BF: mov     edx, edi; Value
0x1400156C1: mov     ecx, 8EEh; Index
0x1400156C6: mov     ebx, edi
0x1400156C8: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400156CD: lea     rdx, [rbx+rsi]; Value
0x1400156D1: mov     ecx, 8EFh; Index
0x1400156D6: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400156DB: mov     edx, 1
0x1400156E0: mov     r8b, dl
0x1400156E3: mov     byte ptr [rsp+240h+Value+2], dl
0x1400156E7: jmp     loc_14001557A
0x1400156EC: mov     eax, 547h
0x1400156F1: cmp     ax, cx
0x1400156F4: jnz     short loc_14001571D
0x1400156F6: test    [rbp+140h+var_C8], 800000h
0x1400156FE: jz      short loc_14001574F
0x140015700: cmp     dword ptr [rbp+140h+var_E0], 1000h
0x140015707: jnz     short loc_14001574F
0x140015709: mov     rax, [rsp+240h+var_1D0]
0x14001570E: cmp     eax, [rbp+140h+var_110]
0x140015711: jnz     short loc_14001574F
0x140015713: mov     ebx, 1
0x140015718: mov     r15d, ebx
0x14001571B: jmp     short loc_14001574F
0x14001571D: mov     eax, 53Ch
0x140015722: sub     cx, ax
0x140015725: mov     eax, 7
0x14001572A: cmp     cx, ax
0x14001572D: ja      short loc_14001574F
0x14001572F: cmp     [rbp+140h+var_C8], 2000000h
0x140015737: jnz     short loc_14001574F
0x140015739: mov     rax, 0FFFFF78000000014h
0x140015743: movzx   edi, dil
0x140015747: cmp     [rbp+140h+var_E0], rax
0x14001574B: cmovz   edi, r15d
0x14001574F: add     esi, r15d
0x140015752: cmp     esi, 14h
0x140015755: jb      loc_1400155E5
0x14001575B: mov     r13d, 1
0x140015761: cmp     dil, r13b
0x140015764: mov     r13, [rsp+240h+var_1C8]
0x140015769: jnz     loc_1400159AD
0x14001576F: test    r14d, r14d
0x140015772: jz      loc_1400159AD
0x140015778: test    bl, bl
0x14001577A: jnz     short loc_1400157EE
0x14001577C: mov     rax, [rsp+240h+var_1F8]
0x140015781: lea     rcx, [r13-30h]
0x140015785: cmp     r13, rax
0x140015788: jbe     loc_1400159AD
0x14001578E: cmp     rcx, rax
0x140015791: jbe     loc_1400159AD
0x140015797: lea     r8, [r13-7]
0x14001579B: cmp     rcx, r8
0x14001579E: ja      loc_1400159AD
0x1400157A4: mov     dl, [rcx]
0x1400157A6: mov     r9, [rsp+240h+var_1D0]
0x1400157AB: cmp     dl, 0C7h
0x1400157AE: jnz     short loc_1400157C2
0x1400157B0: movzx   eax, byte ptr [rcx+2]
0x1400157B4: cmp     r9d, eax
0x1400157B7: jnz     short loc_1400157C2
0x1400157B9: cmp     dword ptr [rcx+3], 1000h
0x1400157C0: jz      short loc_1400157E9
0x1400157C2: lea     rax, [r13-0Ah]
0x1400157C6: cmp     rcx, rax
0x1400157C9: ja      short loc_1400157DF
0x1400157CB: cmp     dl, 0C7h
0x1400157CE: jnz     short loc_1400157DF
0x1400157D0: cmp     r9d, [rcx+2]
0x1400157D4: jnz     short loc_1400157DF
0x1400157D6: cmp     dword ptr [rcx+6], 1000h
0x1400157DD: jz      short loc_1400157E9
0x1400157DF: mov     edx, 1
0x1400157E4: add     rcx, rdx
0x1400157E7: jmp     short loc_14001579B
0x1400157E9: mov     ebx, 1
0x1400157EE: mov     edx, 1
0x1400157F3: cmp     bl, dl
0x1400157F5: jnz     loc_1400159AD
0x1400157FB: mov     ebx, dword ptr [rsp+240h+Value+4]
0x1400157FF: mov     ecx, 334h; Index
0x140015804: mov     edx, ebx; Value
0x140015806: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001580B: mov     rdi, [rsp+240h+var_1F0]
0x140015810: mov     ecx, 335h; Index
0x140015815: lea     rdx, [rbx+rdi]; Value
0x140015819: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001581E: mov     edx, r14d; Value
0x140015821: mov     ecx, 8ECh; Index
0x140015826: mov     ebx, r14d
0x140015829: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001582E: lea     rdx, [rbx+rdi]; Value
0x140015832: mov     ecx, 8EDh; Index
0x140015837: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14001583C: mov     r8b, byte ptr [rsp+240h+Value+2]
0x140015841: mov     edx, 1
0x140015846: mov     r14b, dl
0x140015849: mov     byte ptr [rsp+240h+Value], dl
0x14001584D: mov     dl, byte ptr [rsp+240h+Value+1]
0x140015851: jmp     loc_1400159BB
0x140015856: test    dl, dl
0x140015858: jnz     loc_1400159B6
0x14001585E: mov     edx, edi
0x140015860: lea     rax, [rbp+140h+var_1A0]
0x140015864: mov     rcx, r15
0x140015867: mov     qword ptr [rsp+240h+var_208], rax
0x14001586C: and     [rsp+240h+var_210], 0
0x140015872: and     [rsp+240h+var_218], 0
0x140015878: or      dword ptr [rsp+240h+var_220], 0FFFFFFFFh
0x14001587D: sub     edx, r13d
0x140015880: xor     bl, bl
0x140015882: sub     edx, r9d
0x140015885: xor     r9d, r9d
0x140015888: lea     r8d, [r9+2]
0x14001588C: call    InitPESectionReadContext
0x140015891: xor     edi, edi
0x140015893: lea     rdx, [rbp+140h+var_150]
0x140015897: lea     rcx, [rbp+140h+var_1A0]
0x14001589B: call    ReadPESectionEntry
0x1400158A0: test    eax, eax
0x1400158A2: jnz     loc_1400159AD
0x1400158A8: mov     eax, [rbp+140h+var_60]
0x1400158AE: mov     r8, [rbp+140h+var_198]
0x1400158B2: mov     ecx, 4B5h
0x1400158B7: add     r8, rax
0x1400158BA: mov     rax, [rbp+140h+var_38]
0x1400158C1: mov     [rbp+140h+var_198], r8
0x1400158C5: cmp     cx, [rax+6]
0x1400158C9: jnz     short loc_1400158F7
0x1400158CB: cmp     [rbp+140h+var_60], 6
0x1400158D2: jnz     short loc_1400158F7
0x1400158D4: mov     ecx, 336h; Index
0x1400158D9: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400158DE: mov     r8, [rbp+140h+var_198]
0x1400158E2: movzx   ebx, bl
0x1400158E5: cmp     eax, dword ptr [rbp+140h+var_E0]
0x1400158E8: mov     eax, 1
0x1400158ED: cmovz   ebx, eax
0x1400158F0: mov     rax, [rbp+140h+var_38]
0x1400158F7: cmp     edi, 4
0x1400158FA: jbe     short loc_140015904
0x1400158FC: test    bl, bl
0x1400158FE: jz      loc_1400159AD
0x140015904: movzx   edx, word ptr [rax+6]
0x140015908: mov     rcx, [rbp+140h+var_100]
0x14001590C: mov     eax, 0E5h
0x140015911: cmp     ax, dx
0x140015914: jnz     short loc_14001592C
0x140015916: cmp     rcx, 40000h
0x14001591D: jnz     short loc_14001592C
0x14001591F: mov     eax, 1
0x140015924: cmp     bl, al
0x140015926: jz      loc_140015A24
0x14001592C: mov     eax, 558h
0x140015931: cmp     ax, dx
0x140015934: jnz     short loc_140015959
0x140015936: bt      rcx, 1Ah
0x14001593B: jnb     short loc_140015959
0x14001593D: mov     eax, [rbp+140h+var_118]
0x140015940: test    eax, eax
0x140015942: jz      short loc_140015959
0x140015944: test    bl, bl
0x140015946: jz      short loc_1400159AD
0x140015948: mov     rcx, [rbp+140h+var_1B8]
0x14001594C: test    ecx, ecx
0x14001594E: jz      short loc_14001599B
0x140015950: sub     eax, esi
0x140015952: add     eax, r8d
0x140015955: cmp     ecx, eax
0x140015957: jmp     short loc_140015995
0x140015959: mov     eax, 50Eh
0x14001595E: cmp     ax, dx
0x140015961: jnz     short loc_14001599B
0x140015963: cmp     rcx, 40000h
0x14001596A: jnz     short loc_14001599B
0x14001596C: cmp     [rbp+140h+var_C8], 40h ; '@'
0x140015971: jnz     short loc_14001599B
0x140015973: mov     eax, 1
0x140015978: cmp     bl, al
0x14001597A: jnz     short loc_14001599B
0x14001597C: mov     eax, [rbp+140h+var_110]
0x14001597F: sub     eax, esi
0x140015981: add     eax, r8d
0x140015984: jz      short loc_14001599B
0x140015986: cmp     eax, r12d
0x140015989: jnb     short loc_14001599B
0x14001598B: mov     ecx, r14d
0x14001598E: add     rcx, 8
0x140015992: cmp     rcx, rax
0x140015995: jz      loc_140015A24
0x14001599B: mov     r8d, 1
0x1400159A1: add     edi, r8d
0x1400159A4: cmp     edi, 0Fh
0x1400159A7: jb      loc_140015893
0x1400159AD: mov     dl, byte ptr [rsp+240h+Value+1]
0x1400159B1: mov     r8b, byte ptr [rsp+240h+Value+2]
0x1400159B6: mov     r14b, byte ptr [rsp+240h+Value]
0x1400159BB: mov     ecx, 1
0x1400159C0: cmp     r8b, cl
0x1400159C3: jnz     short loc_1400159CE
0x1400159C5: cmp     r14b, cl
0x1400159C8: jnz     short loc_1400159CE
0x1400159CA: cmp     dl, cl
0x1400159CC: jz      short loc_1400159F4
0x1400159CE: mov     rsi, [rsp+240h+var_1F8]
0x1400159D3: mov     rcx, [rsp+240h+var_1D8]
0x1400159D8: mov     rdi, qword ptr [rsp+240h+var_1E8]
0x1400159DD: mov     r9d, 7
0x1400159E3: inc     r13
0x1400159E6: mov     [rsp+240h+var_1C8], r13
0x1400159EB: cmp     r13, rcx
0x1400159EE: jb      loc_140015445
0x1400159F4: mov     rcx, [rbp+140h+var_30]
0x1400159FB: xor     rcx, rsp; StackCookie
0x1400159FE: call    __security_check_cookie
0x140015A03: lea     r11, [rsp+240h+var_20]
0x140015A0B: mov     rbx, [r11+30h]
0x140015A0F: mov     rsi, [r11+38h]
0x140015A13: mov     rdi, [r11+40h]
0x140015A17: mov     rsp, r11
0x140015A1A: pop     r15
0x140015A1C: pop     r14
0x140015A1E: pop     r13
0x140015A20: pop     r12
0x140015A22: pop     rbp
0x140015A23: retn
0x140015A24: mov     edx, r14d
0x140015A27: mov     ecx, 337h; Index
0x140015A2C: add     rdx, [rsp+240h+var_1F0]; Value
0x140015A31: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140015A36: mov     r8d, 1
0x140015A3C: mov     dl, r8b
0x140015A3F: mov     byte ptr [rsp+240h+Value+1], dl
0x140015A43: jmp     loc_1400159B1