# ParseNtKernelDataSectionsV2  ea=0x1400137BC  size=682
0x1400137BC: mov     rax, rsp; 解析 ntoskrnl 数据节 V2。读取 PE 基址、大小和镜像基址，遍历内核文件的数据节，解析并存储内核数据节信息用于后续分析。
0x1400137BF: mov     [rax+8], rbx
0x1400137C3: mov     [rax+10h], rsi
0x1400137C7: mov     [rax+18h], rdi
0x1400137CB: push    rbp
0x1400137CC: push    r12
0x1400137CE: push    r13
0x1400137D0: push    r14
0x1400137D2: push    r15
0x1400137D4: lea     rbp, [rax-0F8h]
0x1400137DB: sub     rsp, 1D0h
0x1400137E2: mov     rax, cs:__security_cookie
0x1400137E9: xor     rax, rsp
0x1400137EC: mov     [rbp+0F0h+var_30], rax
0x1400137F3: mov     ecx, 20h ; ' '; Index
0x1400137F8: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400137FD: mov     ecx, 21h ; '!'; Index
0x140013802: mov     r14, rax
0x140013805: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001380A: mov     ecx, 3; Index
0x14001380F: mov     rsi, rax
0x140013812: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013817: mov     ecx, 41C5h; Index
0x14001381C: mov     rbx, rax
0x14001381F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013824: mov     ecx, 171h; Index
0x140013829: mov     rdi, rax
0x14001382C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140013831: xor     r15d, r15d
0x140013834: mov     rcx, rax
0x140013837: test    r14, r14
0x14001383A: jz      loc_1400139C4
0x140013840: test    esi, esi
0x140013842: jz      loc_1400139C4
0x140013848: test    rbx, rbx
0x14001384B: jz      loc_1400139C4
0x140013851: test    edi, edi
0x140013853: jz      loc_1400139C4
0x140013859: cmp     rax, rbx
0x14001385C: jbe     loc_1400139C4
0x140013862: sub     eax, ebx
0x140013864: cmp     eax, esi
0x140013866: jnb     loc_1400139C4
0x14001386C: mov     edx, eax
0x14001386E: add     rax, rbx
0x140013871: cmp     rcx, rax
0x140013874: jnz     loc_1400139C4
0x14001387A: lea     rcx, [rdx+r14]
0x14001387E: lea     rax, [rsp+1F0h+var_1A0]
0x140013883: mov     edx, r14d
0x140013886: mov     qword ptr [rsp+1F0h+var_1B8], rax
0x14001388B: sub     edx, ecx
0x14001388D: mov     [rsp+1F0h+var_1C0], r15
0x140013892: lea     r8d, [r15+2]
0x140013896: xor     r9d, r9d
0x140013899: add     edx, esi
0x14001389B: mov     [rsp+1F0h+var_1C8], r15
0x1400138A0: or      dword ptr [rsp+1F0h+var_1D0], 0FFFFFFFFh
0x1400138A5: call    InitPESectionReadContext
0x1400138AA: mov     r12d, r15d
0x1400138AD: mov     r13d, r15d
0x1400138B0: mov     [rsp+1F0h+var_1AC], r15d
0x1400138B5: mov     [rsp+1F0h+var_1B0], r12b
0x1400138BA: xor     edi, edi
0x1400138BC: lea     rdx, [rbp+0F0h+var_150]
0x1400138C0: lea     rcx, [rsp+1F0h+var_1A0]
0x1400138C5: call    ReadPESectionEntry
0x1400138CA: test    eax, eax
0x1400138CC: jnz     loc_1400139C4
0x1400138D2: mov     eax, [rbp+0F0h+var_60]
0x1400138D8: mov     ecx, 512h
0x1400138DD: add     [rsp+1F0h+var_198], rax
0x1400138E2: mov     rax, [rbp+0F0h+var_38]
0x1400138E9: cmp     cx, [rax+6]
0x1400138ED: jnz     short loc_140013947
0x1400138EF: cmp     [rbp+0F0h+var_100], 40h ; '@'
0x1400138F4: jnz     short loc_140013947
0x1400138F6: mov     eax, [rbp+0F0h+var_F8]
0x1400138F9: cmp     eax, 2
0x1400138FC: jnz     short loc_140013906
0x1400138FE: mov     r13d, edi
0x140013901: jmp     loc_140013A53
0x140013906: cmp     eax, 9
0x140013909: jnz     short loc_140013913
0x14001390B: mov     r12d, edi
0x14001390E: jmp     loc_140013A53
0x140013913: cmp     eax, 1
0x140013916: jnz     loc_140013A53
0x14001391C: test    r13d, r13d
0x14001391F: jz      short loc_140013929
0x140013921: lea     eax, [r13+1]
0x140013925: cmp     eax, edi
0x140013927: jz      short loc_14001393F
0x140013929: test    r12d, r12d
0x14001392C: jz      loc_140013A53
0x140013932: lea     eax, [r12+3]
0x140013937: cmp     eax, edi
0x140013939: jnz     loc_140013A53
0x14001393F: mov     r15b, 1
0x140013942: jmp     loc_140013A53
0x140013947: cmp     r15b, 1
0x14001394B: jnz     loc_140013A53
0x140013951: mov     ecx, 914h; Index
0x140013956: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14001395B: cmp     eax, 42EEh
0x140013960: mov     rax, [rbp+0F0h+var_38]
0x140013967: jnb     loc_1400139F4
0x14001396D: mov     ecx, 558h
0x140013972: cmp     cx, [rax+6]
0x140013976: jnz     loc_140013A53
0x14001397C: test    [rbp+0F0h+var_100], 4000000h
0x140013984: jz      loc_140013A53
0x14001398A: mov     eax, [rbp+0F0h+var_118]
0x14001398D: test    eax, eax
0x14001398F: jz      loc_140013A53
0x140013995: mov     ecx, [rsp+1F0h+var_1AC]
0x140013999: inc     ecx
0x14001399B: mov     [rsp+1F0h+var_1AC], ecx
0x14001399F: cmp     ecx, 2
0x1400139A2: jnz     loc_140013A53
0x1400139A8: sub     eax, r14d
0x1400139AB: add     eax, dword ptr [rsp+1F0h+var_198]
0x1400139AF: jz      short loc_1400139C4
0x1400139B1: cmp     eax, esi
0x1400139B3: jnb     short loc_1400139C4
0x1400139B5: mov     edx, eax
0x1400139B7: mov     ecx, 17Bh; Index
0x1400139BC: add     rdx, rbx; Value
0x1400139BF: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400139C4: mov     rcx, [rbp+0F0h+var_30]
0x1400139CB: xor     rcx, rsp; StackCookie
0x1400139CE: call    __security_check_cookie
0x1400139D3: lea     r11, [rsp+1F0h+var_20]
0x1400139DB: mov     rbx, [r11+30h]
0x1400139DF: mov     rsi, [r11+38h]
0x1400139E3: mov     rdi, [r11+40h]
0x1400139E7: mov     rsp, r11
0x1400139EA: pop     r15
0x1400139EC: pop     r14
0x1400139EE: pop     r13
0x1400139F0: pop     r12
0x1400139F2: pop     rbp
0x1400139F3: retn
0x1400139F4: movzx   ecx, word ptr [rax+6]
0x1400139F8: mov     eax, 510h
0x1400139FD: cmp     ax, cx
0x140013A00: jnz     short loc_140013A20
0x140013A02: cmp     [rbp+0F0h+var_100], 40h ; '@'
0x140013A07: jnz     short loc_140013A20
0x140013A09: cmp     [rbp+0F0h+var_F8], 9
0x140013A0D: jnz     short loc_140013A20
0x140013A0F: cmp     [rbp+0F0h+var_C8], 10041h
0x140013A17: jnz     short loc_140013A20
0x140013A19: mov     [rsp+1F0h+var_1B0], 1
0x140013A1E: jmp     short loc_140013A53
0x140013A20: cmp     [rsp+1F0h+var_1B0], 1
0x140013A25: jnz     short loc_140013A53
0x140013A27: mov     eax, 558h
0x140013A2C: cmp     ax, cx
0x140013A2F: jnz     short loc_140013A53
0x140013A31: test    [rbp+0F0h+var_100], 4000000h
0x140013A39: jz      short loc_140013A53
0x140013A3B: mov     eax, [rbp+0F0h+var_118]
0x140013A3E: test    eax, eax
0x140013A40: jz      short loc_140013A53
0x140013A42: sub     eax, r14d
0x140013A45: add     eax, dword ptr [rsp+1F0h+var_198]
0x140013A49: jz      short loc_140013A53
0x140013A4B: cmp     eax, esi
0x140013A4D: jb      loc_1400139B5
0x140013A53: inc     edi
0x140013A55: cmp     edi, 300h
0x140013A5B: jnb     loc_1400139C4
0x140013A61: jmp     loc_1400138BC