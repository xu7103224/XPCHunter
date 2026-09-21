# SendIoControlWithBufferSwap  ea=0x1400731F4  size=760
0x1400731F4: mov     rax, rsp
0x1400731F7: mov     [rax+8], rbx
0x1400731FB: mov     [rax+10h], rsi
0x1400731FF: mov     [rax+18h], rdi
0x140073203: mov     [rax+20h], r9d
0x140073207: push    rbp
0x140073208: push    r12
0x14007320A: push    r13
0x14007320C: push    r14
0x14007320E: push    r15
0x140073210: lea     rbp, [rax-5Fh]
0x140073214: sub     rsp, 0D0h
0x14007321B: mov     rdi, rcx
0x14007321E: mov     ecx, 184h; Index
0x140073223: mov     r12, r8
0x140073226: mov     rsi, rdx
0x140073229: xor     ebx, ebx
0x14007322B: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073230: mov     ecx, 41C6h; Index
0x140073235: mov     [rbp+57h+var_B0], rax
0x140073239: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14007323E: mov     ecx, 4223h; Index
0x140073243: mov     r14, rax
0x140073246: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14007324B: mov     ecx, 17Ch; Index
0x140073250: mov     r13, rax
0x140073253: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073258: mov     ecx, 4334h; Index
0x14007325D: mov     qword ptr [rbp+57h+var_78], rax
0x140073261: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073266: mov     ecx, 179h; Index
0x14007326B: mov     [rbp+57h+var_70], rax
0x14007326F: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073274: mov     ecx, 197h; Index
0x140073279: mov     r15, rax
0x14007327C: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140073281: mov     [rbp+57h+var_90], rax
0x140073285: cmp     [rbp+57h+var_B0], rbx
0x140073289: jz      loc_1400734C9
0x14007328F: test    r14, r14
0x140073292: jz      loc_1400734C9
0x140073298: test    r13, r13
0x14007329B: jz      loc_1400734C9
0x1400732A1: cmp     qword ptr [rbp+57h+var_78], rbx
0x1400732A5: jz      loc_1400734C9
0x1400732AB: cmp     [rbp+57h+var_70], rbx
0x1400732AF: jz      loc_1400734C9
0x1400732B5: test    r15, r15
0x1400732B8: jz      loc_1400734C9
0x1400732BE: test    rax, rax
0x1400732C1: jz      loc_1400734C9
0x1400732C7: mov     edx, [rsi+0Ch]
0x1400732CA: mov     r8d, [rdi+4]; MaxCount
0x1400732CE: mov     eax, dword ptr [rbp+57h+arg_18]
0x1400732D1: add     edx, r8d
0x1400732D4: add     rdx, 2
0x1400732D8: cmp     rdx, rax
0x1400732DB: jnb     loc_1400734C9
0x1400732E1: mov     rdx, [rdi+8]; Src
0x1400732E5: mov     rcx, r12; Dst
0x1400732E8: call    memmove
0x1400732ED: mov     eax, [rdi+4]
0x1400732F0: lea     ecx, [rbx+5Ch]
0x1400732F3: mov     [rax+r12-2], cx
0x1400732F9: mov     ecx, [rdi+4]
0x1400732FC: mov     r8d, [rsi+0Ch]; MaxCount
0x140073300: lea     rdx, [rsi+10h]; Src
0x140073304: add     rcx, r12; Dst
0x140073307: call    memmove
0x14007330C: mov     ecx, [rdi+4]
0x14007330F: mov     edx, [rsi+0Ch]
0x140073312: add     rcx, r12
0x140073315: lea     eax, [rbx+2]
0x140073318: mov     [rdx+rcx], bx
0x14007331C: mov     edx, [rsi+0Ch]
0x14007331F: add     edx, 2
0x140073322: add     edx, [rdi+4]
0x140073325: cmp     edx, eax
0x140073327: jb      short loc_14007333A
0x140073329: mov     word ptr [rbp+57h+var_88+2], dx
0x14007332D: sub     dx, ax
0x140073330: mov     [rbp+57h+var_80], r12
0x140073334: mov     word ptr [rbp+57h+var_88], dx
0x140073338: jmp     short loc_140073341
0x14007333A: mov     [rbp+57h+var_80], rbx
0x14007333E: mov     [rbp+57h+var_88], ebx
0x140073341: lea     rax, [rbp+57h+var_88]
0x140073345: xorps   xmm0, xmm0
0x140073348: lea     rcx, [rbp+57h+var_60]
0x14007334C: mov     [rbp+57h+var_58], 30h ; '0'
0x140073353: mov     [rbp+57h+var_50], rbx
0x140073357: mov     [rbp+57h+var_40], 240h
0x14007335E: movdqu  [rbp+57h+var_38], xmm0
0x140073363: mov     [rbp+57h+var_48], rax
0x140073367: call    SwapKernelMemoryPointer
0x14007336C: mov     rcx, [rbp+57h+var_B0]
0x140073370: mov     byte ptr [rsp+0F0h+var_C0], bl
0x140073374: lea     r9, [rbp+57h+var_58]
0x140073378: lea     rdx, [rbp+57h+var_98]
0x14007337C: mov     r8d, 20019h
0x140073382: mov     [rsp+0F0h+NumberOfBytes], rbx
0x140073387: mov     rdi, rax
0x14007338A: mov     dword ptr [rsp+0F0h+Dst], ebx
0x14007338E: call    DispatchIoControlForServer2022
0x140073393: mov     ecx, eax
0x140073395: test    rdi, rdi
0x140073398: jz      short loc_1400733A1
0x14007339A: mov     rax, [rbp+57h+var_60]
0x14007339E: mov     [rdi], rax
0x1400733A1: test    ecx, ecx
0x1400733A3: js      loc_1400734C9
0x1400733A9: mov     ecx, 914h; Index
0x1400733AE: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400733B3: mov     rcx, [rbp+57h+var_98]
0x1400733B7: mov     edi, 1
0x1400733BC: mov     edx, edi
0x1400733BE: cmp     eax, 1DB0h
0x1400733C3: jnb     short loc_1400733DE
0x1400733C5: mov     r8, [r15]
0x1400733C8: lea     rax, [rbp+57h+var_A8]
0x1400733CC: xor     r9d, r9d
0x1400733CF: mov     [rsp+0F0h+NumberOfBytes], rbx
0x1400733D4: mov     [rsp+0F0h+Dst], rax
0x1400733D9: call    r14
0x1400733DC: jmp     short loc_1400733EF
0x1400733DE: lea     r9, [rbp+57h+var_A8]
0x1400733E2: xor     r8d, r8d
0x1400733E5: mov     [rsp+0F0h+Dst], rbx
0x1400733EA: call    SendDeviceIoControlWithRetry
0x1400733EF: test    eax, eax
0x1400733F1: js      loc_1400734C2
0x1400733F7: mov     rcx, [rbp+57h+var_90]
0x1400733FB: lea     r8, [rbp+57h+var_A0]
0x1400733FF: lea     rdx, [rbp+57h+var_A8]
0x140073403: xor     r9d, r9d
0x140073406: mov     qword ptr [rbp+57h+var_A0], rbx
0x14007340A: mov     dword ptr [rsp+0F0h+Dst], edi
0x14007340E: call    DispatchIoControlByBuildNumber
0x140073413: test    eax, eax
0x140073415: js      loc_1400734BB
0x14007341B: mov     rcx, qword ptr [rbp+57h+var_A8]
0x14007341F: lea     rdx, [rbp+57h+var_90]
0x140073423: call    DispatchHookSwapByVersion
0x140073428: mov     r8, qword ptr [rbp+57h+var_A0]
0x14007342C: mov     rsi, rbx
0x14007342F: mov     r14, rbx
0x140073432: mov     [rbp+57h+var_B0], rbx
0x140073436: mov     r15, rax
0x140073439: test    r8, r8
0x14007343C: jz      short loc_140073455
0x14007343E: lea     rdx, [rbp+57h+var_B0]
0x140073442: mov     rcx, r8
0x140073445: call    DispatchHookSwapByVersion
0x14007344A: mov     r8, qword ptr [rbp+57h+var_A0]; int
0x14007344E: mov     r14, [rbp+57h+var_B0]
0x140073452: mov     rsi, rax
0x140073455: mov     rdx, qword ptr [rbp+57h+var_A8]; int
0x140073459: mov     rcx, qword ptr [rbp+57h+var_78]; int
0x14007345D: lea     rax, [rbp+57h+var_68]
0x140073461: mov     [rsp+0F0h+var_C0], rax; __int64
0x140073466: mov     eax, dword ptr [rbp+57h+arg_18]
0x140073469: mov     r9d, 2; int
0x14007346F: mov     dword ptr [rsp+0F0h+NumberOfBytes], eax; NumberOfBytes
0x140073473: mov     [rsp+0F0h+Dst], r12; Dst
0x140073478: call    AllocBufferAndQuerySystemInfo
0x14007347D: mov     dword ptr [rbp+57h+var_B0], eax
0x140073480: test    r15, r15
0x140073483: jz      short loc_14007348C
0x140073485: mov     rax, [rbp+57h+var_90]
0x140073489: mov     [r15], rax
0x14007348C: mov     rcx, qword ptr [rbp+57h+var_A0]
0x140073490: test    rcx, rcx
0x140073493: jz      short loc_1400734A9
0x140073495: test    rsi, rsi
0x140073498: jz      short loc_1400734A1
0x14007349A: mov     [rsi], r14
0x14007349D: mov     rcx, qword ptr [rbp+57h+var_A0]
0x1400734A1: test    rcx, rcx
0x1400734A4: jz      short loc_1400734A9
0x1400734A6: call    r13
0x1400734A9: cmp     dword ptr [rbp+57h+var_B0], ebx
0x1400734AC: jl      short loc_1400734BB
0x1400734AE: cmp     [r12+14h], ebx
0x1400734B3: movzx   eax, bl
0x1400734B6: cmova   eax, edi
0x1400734B9: mov     bl, al
0x1400734BB: mov     rcx, qword ptr [rbp+57h+var_A8]
0x1400734BF: call    r13
0x1400734C2: mov     rcx, [rbp+57h+var_98]
0x1400734C6: call    [rbp+57h+var_70]
0x1400734C9: lea     r11, [rsp+0F0h+var_20]
0x1400734D1: mov     al, bl
0x1400734D3: mov     rbx, [r11+30h]
0x1400734D7: mov     rsi, [r11+38h]
0x1400734DB: mov     rdi, [r11+40h]
0x1400734DF: mov     rsp, r11
0x1400734E2: pop     r15
0x1400734E4: pop     r14
0x1400734E6: pop     r13
0x1400734E8: pop     r12
0x1400734EA: pop     rbp
0x1400734EB: retn