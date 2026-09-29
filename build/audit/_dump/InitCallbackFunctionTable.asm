# InitCallbackFunctionTable  ea=0x1400344BC  size=2359
0x1400344BC: mov     rax, rsp; 初始化回调函数表。根据 Type(0/1/2) 选择 GT 索引(82/0x2A1/84)，读取 ntoskrnl 文件，查找 MmFlushImageSection 导出，通过 ParsePESectionHeaders 解析 Init 节区，然后调用 ParseCallbackFunctionSections 填充目标函数表和备用表。备份原始函数字节到 GT 0x8D8/0x8D9 并置标志。
0x1400344BF: mov     [rax+8], rbx
0x1400344C3: mov     [rax+10h], rsi
0x1400344C7: mov     [rax+18h], rdi
0x1400344CB: push    rbp
0x1400344CC: push    r12
0x1400344CE: push    r13
0x1400344D0: push    r14
0x1400344D2: push    r15
0x1400344D4: lea     rbp, [rax-5Fh]
0x1400344D8: sub     rsp, 0D0h
0x1400344DF: mov     rax, cs:__security_cookie
0x1400344E6: xor     rax, rsp
0x1400344E9: mov     [rbp+57h+var_28], rax
0x1400344ED: mov     r14d, ecx
0x1400344F0: mov     ecx, 421Dh; Index
0x1400344F5: xor     esi, esi
0x1400344F7: xor     ebx, ebx
0x1400344F9: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400344FE: mov     ecx, 421Ah; Index
0x140034503: mov     rdi, rax
0x140034506: mov     [rbp+57h+var_98], rax
0x14003450A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003450F: mov     ecx, 4223h; Index
0x140034514: mov     r13, rax
0x140034517: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003451C: mov     ecx, 4160h; Index
0x140034521: mov     r12, rax
0x140034524: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034529: xor     r15b, r15b
0x14003452C: mov     [rbp+57h+var_90], rax
0x140034530: test    rdi, rdi
0x140034533: jz      loc_140034DC6
0x140034539: test    r13, r13
0x14003453C: jz      loc_140034DC6
0x140034542: test    r12, r12
0x140034545: jz      loc_140034DC6
0x14003454B: test    rax, rax
0x14003454E: jz      loc_140034DC6
0x140034554: test    r14d, r14d
0x140034557: jnz     short loc_14003455E
0x140034559: lea     ecx, [rsi+52h]
0x14003455C: jmp     short loc_140034575
0x14003455E: cmp     r14d, 2
0x140034562: jnz     short loc_14003456A
0x140034564: lea     ecx, [r14+52h]
0x140034568: jmp     short loc_140034575
0x14003456A: cmp     r14d, 1
0x14003456E: jnz     short loc_14003457F
0x140034570: mov     ecx, 2A1h; Index
0x140034575: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003457A: mov     rdi, rax
0x14003457D: jmp     short loc_140034581
0x14003457F: xor     edi, edi
0x140034581: test    rdi, rdi
0x140034584: jz      loc_140034DC6
0x14003458A: lea     rdx, [rbp+57h+var_B0]
0x14003458E: lea     rcx, [rbp+57h+var_A8]
0x140034592: mov     r8d, r14d
0x140034595: call    ReadNtFileForCallbackTable
0x14003459A: cmp     al, 1
0x14003459C: jnz     loc_140034DC6
0x1400345A2: mov     edx, [rbp+57h+var_B0]
0x1400345A5: mov     rcx, [rbp+57h+var_A8]
0x1400345A9: and     [rbp+57h+var_2C], ebx
0x1400345AC: lea     rax, [rbp+57h+var_AC]
0x1400345B0: lea     r9, [rbp+57h+var_78]
0x1400345B4: lea     r8, [rbp+57h+var_38]
0x1400345B8: mov     [rbp+57h+var_38], 736F746Eh
0x1400345BF: mov     [rbp+57h+var_34], 6C6E726Bh
0x1400345C6: mov     [rbp+57h+var_30], 6578652Eh
0x1400345CD: mov     qword ptr [rsp+0F0h+var_D0], rax
0x1400345D2: mov     [rbp+57h+var_78], 6C466D4Dh
0x1400345D9: mov     [rbp+57h+var_74], 49687375h
0x1400345E0: mov     [rbp+57h+var_70], 6567616Dh
0x1400345E7: mov     [rbp+57h+var_6C], 74636553h
0x1400345EE: mov     [rbp+57h+var_68], 6E6F69h
0x1400345F5: call    ParsePESectionHeaders; 解析 PE 节头表。遍历节表查找指定名称的节，返回该节的节头偏移。
0x1400345FA: cmp     al, 1
0x1400345FC: jnz     short loc_14003462D
0x1400345FE: cmp     r14d, 2
0x140034602: jnz     short loc_14003460B
0x140034604: mov     ecx, 187h
0x140034609: jmp     short loc_140034622
0x14003460B: test    r14d, r14d
0x14003460E: jnz     short loc_140034617
0x140034610: mov     ecx, 188h
0x140034615: jmp     short loc_140034622
0x140034617: cmp     r14d, 1
0x14003461B: jnz     short loc_14003462D
0x14003461D: mov     ecx, 2A5h; Index
0x140034622: mov     edx, [rbp+57h+var_AC]
0x140034625: add     rdx, rdi; Value
0x140034628: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14003462D: mov     edx, [rbp+57h+var_B0]
0x140034630: mov     rcx, [rbp+57h+var_A8]
0x140034634: lea     rax, [rbp+57h+var_AC]
0x140034638: lea     r9, [rbp+57h+var_78]
0x14003463C: lea     r8, [rbp+57h+var_38]
0x140034640: mov     qword ptr [rsp+0F0h+var_D0], rax
0x140034645: mov     [rbp+57h+var_78], 43666F49h
0x14003464C: mov     [rbp+57h+var_74], 6C706D6Fh
0x140034653: mov     [rbp+57h+var_70], 52657465h
0x14003465A: mov     [rbp+57h+var_6C], 65757165h
0x140034661: mov     [rbp+57h+var_68], 7473h
0x140034668: call    ParsePESectionHeaders; 解析 PE 节头表。遍历节表查找指定名称的节，返回该节的节头偏移。
0x14003466D: cmp     al, 1
0x14003466F: jnz     short loc_1400346A0
0x140034671: cmp     r14d, 2
0x140034675: jnz     short loc_14003467E
0x140034677: mov     ecx, 2ACh
0x14003467C: jmp     short loc_140034695
0x14003467E: test    r14d, r14d
0x140034681: jnz     short loc_14003468A
0x140034683: mov     ecx, 2ABh
0x140034688: jmp     short loc_140034695
0x14003468A: cmp     r14d, 1
0x14003468E: jnz     short loc_1400346A0
0x140034690: mov     ecx, 2ADh; Index
0x140034695: mov     edx, [rbp+57h+var_AC]
0x140034698: add     rdx, rdi; Value
0x14003469B: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400346A0: mov     [rbp+57h+var_60], 46005Ch
0x1400346A7: mov     [rbp+57h+var_5C], 6C0069h
0x1400346AE: mov     [rbp+57h+var_58], 530065h
0x1400346B5: mov     [rbp+57h+var_54], 730079h
0x1400346BC: mov     [rbp+57h+var_50], 650074h
0x1400346C3: mov     [rbp+57h+var_4C], 5C006Dh
0x1400346CA: test    r14d, r14d
0x1400346CD: jnz     loc_14003483C
0x1400346D3: mov     ecx, 0A4Ch; Index
0x1400346D8: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400346DD: mov     ecx, 0AFAh; Index
0x1400346E2: mov     rsi, rax
0x1400346E5: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400346EA: mov     edx, [rbp+57h+var_B0]
0x1400346ED: mov     rcx, [rbp+57h+var_A8]
0x1400346F1: mov     r9, rsi
0x1400346F4: mov     r8, rdi
0x1400346F7: mov     byte ptr [rsp+0F0h+var_C8], 1
0x1400346FC: mov     rbx, rax
0x1400346FF: mov     qword ptr [rsp+0F0h+var_D0], rax
0x140034704: call    ParseCallbackFunctionSections
0x140034709: cmp     al, 1
0x14003470B: jnz     loc_140034B06
0x140034711: mov     edx, [rbp+57h+var_B0]
0x140034714: mov     rcx, [rbp+57h+var_A8]
0x140034718: xor     r9d, r9d
0x14003471B: mov     r8, rdi
0x14003471E: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x140034723: cmp     al, 1
0x140034725: jnz     loc_140034B06
0x14003472B: lea     r8, [rsi+4]
0x14003472F: lea     edx, [r14+1Ch]
0x140034733: xor     edi, edi
0x140034735: mov     ecx, [r8]
0x140034738: mov     [r8-4], edi
0x14003473C: test    ecx, ecx
0x14003473E: jz      short loc_14003475E
0x140034740: lea     eax, [rcx+10h]
0x140034743: cmp     eax, [rbp+57h+var_B0]
0x140034746: ja      short loc_14003475E
0x140034748: mov     dword ptr [r8-4], 1
0x140034750: mov     rax, [rbp+57h+var_A8]
0x140034754: movups  xmm0, xmmword ptr [rcx+rax]
0x140034758: movdqu  xmmword ptr [r8+0Ch], xmm0
0x14003475E: add     r8, 30h ; '0'
0x140034762: dec     rdx
0x140034765: jnz     short loc_140034735
0x140034767: lea     r8, [rbx+4]
0x14003476B: mov     edx, 1Bh
0x140034770: mov     ecx, [r8]
0x140034773: mov     [r8-4], edi
0x140034777: test    ecx, ecx
0x140034779: jz      short loc_140034799
0x14003477B: lea     eax, [rcx+10h]
0x14003477E: cmp     eax, [rbp+57h+var_B0]
0x140034781: ja      short loc_140034799
0x140034783: mov     dword ptr [r8-4], 1
0x14003478B: mov     rax, [rbp+57h+var_A8]
0x14003478F: movups  xmm0, xmmword ptr [rcx+rax]
0x140034793: movdqu  xmmword ptr [r8+0Ch], xmm0
0x140034799: add     r8, 30h ; '0'
0x14003479D: dec     rdx
0x1400347A0: jnz     short loc_140034770
0x1400347A2: lea     rdx, [rbp+57h+var_60]
0x1400347A6: lea     rcx, [rbp+57h+var_88]
0x1400347AA: mov     [rbp+57h+var_48], 610046h
0x1400347B1: mov     dword ptr [rbp+57h+var_44], 740073h
0x1400347B8: mov     dword ptr [rbp+57h+var_44+4], 610066h
0x1400347BF: mov     [rbp+57h+var_3C], 74h ; 't'
0x1400347C6: call    [rbp+57h+var_98]
0x1400347C9: lea     rax, [rbp+57h+Value]
0x1400347CD: xor     r9d, r9d
0x1400347D0: mov     [rsp+0F0h+var_B8], rax
0x1400347D5: mov     rax, [rbp+57h+var_90]
0x1400347D9: mov     [rsp+0F0h+var_C0], rdi
0x1400347DE: mov     rax, [rax]
0x1400347E1: lea     edx, [r9+40h]
0x1400347E5: lea     rcx, [rbp+57h+var_88]
0x1400347E9: xor     r8d, r8d
0x1400347EC: mov     byte ptr [rsp+0F0h+var_C8], dil
0x1400347F1: mov     qword ptr [rsp+0F0h+var_D0], rax
0x1400347F6: call    r13
0x1400347F9: test    eax, eax
0x1400347FB: js      loc_140034B06
0x140034801: mov     rcx, [rbp+57h+Value]
0x140034805: test    rcx, rcx
0x140034808: jz      loc_140034B06
0x14003480E: call    r12
0x140034811: mov     rdx, [rbp+57h+Value]; Value
0x140034815: mov     ecx, 195h; Index
0x14003481A: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14003481F: mov     r15d, 1
0x140034825: mov     ecx, 18Fh; Index
0x14003482A: mov     edx, r15d; Value
0x14003482D: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034832: mov     ecx, 8A3h
0x140034837: jmp     loc_140034AFE
0x14003483C: cmp     r14d, 2
0x140034840: jnz     loc_14003499D
0x140034846: mov     ecx, 0BA8h; Index
0x14003484B: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x140034850: mov     ecx, 0C56h; Index
0x140034855: mov     rsi, rax
0x140034858: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x14003485D: mov     edx, [rbp+57h+var_B0]
0x140034860: mov     rcx, [rbp+57h+var_A8]
0x140034864: mov     r9, rsi
0x140034867: mov     r8, rdi
0x14003486A: mov     rbx, rax
0x14003486D: mov     qword ptr [rsp+0F0h+var_D0], rax
0x140034872: call    ParseCallbackContextSections
0x140034877: cmp     al, 1
0x140034879: jnz     loc_140034B06
0x14003487F: mov     edx, [rbp+57h+var_B0]
0x140034882: mov     rcx, [rbp+57h+var_A8]
0x140034886: xor     r9d, r9d
0x140034889: mov     r8, rdi
0x14003488C: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x140034891: cmp     al, 1
0x140034893: jnz     loc_140034B06
0x140034899: lea     r8, [rsi+4]
0x14003489D: lea     edx, [r14+1Ah]
0x1400348A1: xor     edi, edi
0x1400348A3: mov     ecx, [r8]
0x1400348A6: mov     [r8-4], edi
0x1400348AA: test    ecx, ecx
0x1400348AC: jz      short loc_1400348CC
0x1400348AE: lea     eax, [rcx+10h]
0x1400348B1: cmp     eax, [rbp+57h+var_B0]
0x1400348B4: ja      short loc_1400348CC
0x1400348B6: mov     dword ptr [r8-4], 1
0x1400348BE: mov     rax, [rbp+57h+var_A8]
0x1400348C2: movups  xmm0, xmmword ptr [rcx+rax]
0x1400348C6: movdqu  xmmword ptr [r8+0Ch], xmm0
0x1400348CC: add     r8, 30h ; '0'
0x1400348D0: dec     rdx
0x1400348D3: jnz     short loc_1400348A3
0x1400348D5: lea     r8, [rbx+4]
0x1400348D9: mov     edx, 1Bh
0x1400348DE: mov     ecx, [r8]
0x1400348E1: mov     [r8-4], edi
0x1400348E5: test    ecx, ecx
0x1400348E7: jz      short loc_140034907
0x1400348E9: lea     eax, [rcx+10h]
0x1400348EC: cmp     eax, [rbp+57h+var_B0]
0x1400348EF: ja      short loc_140034907
0x1400348F1: mov     dword ptr [r8-4], 1
0x1400348F9: mov     rax, [rbp+57h+var_A8]
0x1400348FD: movups  xmm0, xmmword ptr [rcx+rax]
0x140034901: movdqu  xmmword ptr [r8+0Ch], xmm0
0x140034907: add     r8, 30h ; '0'
0x14003490B: dec     rdx
0x14003490E: jnz     short loc_1400348DE
0x140034910: lea     rdx, [rbp+57h+var_60]
0x140034914: lea     rcx, [rbp+57h+var_88]
0x140034918: mov     [rbp+57h+var_48], 74004Eh
0x14003491F: mov     [rbp+57h+var_44], 730066h
0x140034927: call    [rbp+57h+var_98]
0x14003492A: lea     rax, [rbp+57h+Value]
0x14003492E: mov     [rsp+0F0h+var_B8], rax
0x140034933: mov     rax, [rbp+57h+var_90]
0x140034937: xor     r9d, r9d
0x14003493A: mov     rax, [rax]
0x14003493D: mov     [rsp+0F0h+var_C0], rdi
0x140034942: lea     rcx, [rbp+57h+var_88]
0x140034946: lea     edx, [r9+40h]
0x14003494A: xor     r8d, r8d
0x14003494D: mov     byte ptr [rsp+0F0h+var_C8], dil
0x140034952: mov     qword ptr [rsp+0F0h+var_D0], rax
0x140034957: call    r13
0x14003495A: test    eax, eax
0x14003495C: js      loc_140034B06
0x140034962: mov     rcx, [rbp+57h+Value]
0x140034966: test    rcx, rcx
0x140034969: jz      loc_140034B06
0x14003496F: call    r12
0x140034972: mov     rdx, [rbp+57h+Value]; Value
0x140034976: mov     ecx, 194h; Index
0x14003497B: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034980: mov     r15d, 1
0x140034986: mov     ecx, 190h; Index
0x14003498B: mov     edx, r15d; Value
0x14003498E: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034993: mov     ecx, 8A2h
0x140034998: jmp     loc_140034AFE
0x14003499D: cmp     r14d, 1
0x1400349A1: jnz     loc_140034B06
0x1400349A7: mov     ecx, 0D04h; Index
0x1400349AC: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400349B1: mov     ecx, 0DB2h; Index
0x1400349B6: mov     rsi, rax
0x1400349B9: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400349BE: mov     edx, [rbp+57h+var_B0]
0x1400349C1: mov     rcx, [rbp+57h+var_A8]
0x1400349C5: mov     r9, rsi
0x1400349C8: mov     r8, rdi
0x1400349CB: mov     byte ptr [rsp+0F0h+var_C8], 0
0x1400349D0: mov     rbx, rax
0x1400349D3: mov     qword ptr [rsp+0F0h+var_D0], rax
0x1400349D8: call    ParseCallbackFunctionSections
0x1400349DD: cmp     al, r14b
0x1400349E0: jnz     loc_140034B06
0x1400349E6: mov     edx, [rbp+57h+var_B0]
0x1400349E9: mov     rcx, [rbp+57h+var_A8]
0x1400349ED: xor     r9d, r9d
0x1400349F0: mov     r8, rdi
0x1400349F3: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x1400349F8: cmp     al, r14b
0x1400349FB: jnz     loc_140034B06
0x140034A01: lea     r8, [rsi+4]
0x140034A05: lea     edx, [r14+1Bh]
0x140034A09: xor     edi, edi
0x140034A0B: mov     ecx, [r8]
0x140034A0E: mov     [r8-4], edi
0x140034A12: test    ecx, ecx
0x140034A14: jz      short loc_140034A34
0x140034A16: lea     eax, [rcx+10h]
0x140034A19: cmp     eax, [rbp+57h+var_B0]
0x140034A1C: ja      short loc_140034A34
0x140034A1E: mov     dword ptr [r8-4], 1
0x140034A26: mov     rax, [rbp+57h+var_A8]
0x140034A2A: movups  xmm0, xmmword ptr [rcx+rax]
0x140034A2E: movdqu  xmmword ptr [r8+0Ch], xmm0
0x140034A34: add     r8, 30h ; '0'
0x140034A38: dec     rdx
0x140034A3B: jnz     short loc_140034A0B
0x140034A3D: lea     r8, [rbx+4]
0x140034A41: mov     edx, 1Bh
0x140034A46: mov     ecx, [r8]
0x140034A49: mov     [r8-4], edi
0x140034A4D: test    ecx, ecx
0x140034A4F: jz      short loc_140034A6F
0x140034A51: lea     eax, [rcx+10h]
0x140034A54: cmp     eax, [rbp+57h+var_B0]
0x140034A57: ja      short loc_140034A6F
0x140034A59: mov     dword ptr [r8-4], 1
0x140034A61: mov     rax, [rbp+57h+var_A8]
0x140034A65: movups  xmm0, xmmword ptr [rcx+rax]
0x140034A69: movdqu  xmmword ptr [r8+0Ch], xmm0
0x140034A6F: add     r8, 30h ; '0'
0x140034A73: dec     rdx
0x140034A76: jnz     short loc_140034A46
0x140034A78: lea     rdx, [rbp+57h+var_60]
0x140034A7C: lea     rcx, [rbp+57h+var_88]
0x140034A80: mov     [rbp+57h+var_48], 780065h
0x140034A87: mov     dword ptr [rbp+57h+var_44], 610066h
0x140034A8E: mov     dword ptr [rbp+57h+var_44+4], 74h ; 't'
0x140034A95: call    [rbp+57h+var_98]
0x140034A98: lea     rax, [rbp+57h+Value]
0x140034A9C: xor     r9d, r9d
0x140034A9F: lea     rcx, [rbp+57h+var_88]
0x140034AA3: mov     [rsp+0F0h+var_B8], rax
0x140034AA8: mov     rax, [rbp+57h+var_90]
0x140034AAC: mov     [rsp+0F0h+var_C0], rdi
0x140034AB1: mov     rax, [rax]
0x140034AB4: lea     edx, [r9+40h]
0x140034AB8: xor     r8d, r8d
0x140034ABB: mov     byte ptr [rsp+0F0h+var_C8], dil
0x140034AC0: mov     qword ptr [rsp+0F0h+var_D0], rax
0x140034AC5: call    r13
0x140034AC8: test    eax, eax
0x140034ACA: js      short loc_140034B06
0x140034ACC: mov     rcx, [rbp+57h+Value]
0x140034AD0: test    rcx, rcx
0x140034AD3: jz      short loc_140034B06
0x140034AD5: call    r12
0x140034AD8: mov     rdx, [rbp+57h+Value]; Value
0x140034ADC: mov     ecx, 2A3h; Index
0x140034AE1: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034AE6: mov     r15d, 1
0x140034AEC: mov     ecx, 2A4h; Index
0x140034AF1: mov     edx, r15d; Value
0x140034AF4: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034AF9: mov     ecx, 8A4h; Index
0x140034AFE: mov     rdx, r15; Value
0x140034B01: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140034B06: mov     rcx, [rbp+57h+var_A8]
0x140034B0A: call    ExFree
0x140034B0F: cmp     r15b, 1
0x140034B13: jnz     loc_140034DC6
0x140034B19: mov     rcx, rsi
0x140034B1C: call    FillExportEntrySlot
0x140034B21: mov     ecx, 4Ch ; 'L'; Index
0x140034B26: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034B2B: mov     ecx, 21h ; '!'; Index
0x140034B30: mov     rsi, rax
0x140034B33: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034B38: mov     ecx, 3; Index
0x140034B3D: mov     r15, rax
0x140034B40: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034B45: mov     rdi, rax
0x140034B48: test    rsi, rsi
0x140034B4B: jz      loc_140034DC6
0x140034B51: test    r15d, r15d
0x140034B54: jz      loc_140034DC6
0x140034B5A: test    rax, rax
0x140034B5D: jz      loc_140034DC6
0x140034B63: mov     r15d, 1
0x140034B69: cmp     r14d, r15d
0x140034B6C: jnz     short loc_140034BD4
0x140034B6E: mov     ecx, 4429h; Index
0x140034B73: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034B78: test    eax, eax
0x140034B7A: jz      short loc_140034B9C
0x140034B7C: cmp     dword ptr [rbx+34h], 0
0x140034B80: jnz     short loc_140034B9C
0x140034B82: mov     ecx, eax
0x140034B84: mov     [rbx+34h], eax
0x140034B87: mov     [rbx+30h], r15d
0x140034B8B: lea     rax, [rcx+rdi]
0x140034B8F: mov     [rbx+38h], rax
0x140034B93: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034B97: movdqu  xmmword ptr [rbx+40h], xmm0
0x140034B9C: mov     ecx, 442Ch; Index
0x140034BA1: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034BA6: test    eax, eax
0x140034BA8: jz      loc_140034C4E
0x140034BAE: cmp     dword ptr [rbx+64h], 0
0x140034BB2: jnz     loc_140034C4E
0x140034BB8: mov     ecx, eax
0x140034BBA: mov     [rbx+64h], eax
0x140034BBD: mov     [rbx+60h], r15d
0x140034BC1: lea     rax, [rcx+rdi]
0x140034BC5: mov     [rbx+68h], rax
0x140034BC9: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034BCD: movdqu  xmmword ptr [rbx+70h], xmm0
0x140034BD2: jmp     short loc_140034C4E
0x140034BD4: test    r14d, r14d
0x140034BD7: jnz     loc_140034D4C
0x140034BDD: mov     ecx, 4429h; Index
0x140034BE2: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034BE7: test    eax, eax
0x140034BE9: jz      short loc_140034C0B
0x140034BEB: cmp     [rbx+34h], r14d
0x140034BEF: jnz     short loc_140034C0B
0x140034BF1: mov     ecx, eax
0x140034BF3: mov     [rbx+34h], eax
0x140034BF6: mov     [rbx+30h], r15d
0x140034BFA: lea     rax, [rcx+rdi]
0x140034BFE: mov     [rbx+38h], rax
0x140034C02: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034C06: movdqu  xmmword ptr [rbx+40h], xmm0
0x140034C0B: mov     ecx, 442Ch; Index
0x140034C10: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034C15: test    eax, eax
0x140034C17: jz      short loc_140034C39
0x140034C19: cmp     dword ptr [rbx+64h], 0
0x140034C1D: jnz     short loc_140034C39
0x140034C1F: mov     ecx, eax
0x140034C21: mov     [rbx+64h], eax
0x140034C24: mov     [rbx+60h], r15d
0x140034C28: lea     rax, [rcx+rdi]
0x140034C2C: mov     [rbx+68h], rax
0x140034C30: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034C34: movdqu  xmmword ptr [rbx+70h], xmm0
0x140034C39: mov     ecx, 914h; Index
0x140034C3E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034C43: cmp     eax, 1772h
0x140034C48: jb      loc_140034DC6
0x140034C4E: mov     ecx, 442Fh; Index
0x140034C53: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034C58: test    eax, eax
0x140034C5A: jz      short loc_140034C8B
0x140034C5C: cmp     dword ptr [rbx+304h], 0
0x140034C63: jnz     short loc_140034C8B
0x140034C65: mov     ecx, eax
0x140034C67: mov     [rbx+304h], eax
0x140034C6D: mov     [rbx+300h], r15d
0x140034C74: lea     rax, [rcx+rdi]
0x140034C78: mov     [rbx+308h], rax
0x140034C7F: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034C83: movdqu  xmmword ptr [rbx+310h], xmm0
0x140034C8B: mov     ecx, 4432h; Index
0x140034C90: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034C95: test    eax, eax
0x140034C97: jz      short loc_140034CC8
0x140034C99: cmp     dword ptr [rbx+364h], 0
0x140034CA0: jnz     short loc_140034CC8
0x140034CA2: mov     ecx, eax
0x140034CA4: mov     [rbx+364h], eax
0x140034CAA: mov     [rbx+360h], r15d
0x140034CB1: lea     rax, [rcx+rdi]
0x140034CB5: mov     [rbx+368h], rax
0x140034CBC: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034CC0: movdqu  xmmword ptr [rbx+370h], xmm0
0x140034CC8: mov     ecx, 4435h; Index
0x140034CCD: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034CD2: test    eax, eax
0x140034CD4: jz      short loc_140034D05
0x140034CD6: cmp     dword ptr [rbx+2D4h], 0
0x140034CDD: jnz     short loc_140034D05
0x140034CDF: mov     ecx, eax
0x140034CE1: mov     [rbx+2D4h], eax
0x140034CE7: mov     [rbx+2D0h], r15d
0x140034CEE: lea     rax, [rcx+rdi]
0x140034CF2: mov     [rbx+2D8h], rax
0x140034CF9: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034CFD: movdqu  xmmword ptr [rbx+2E0h], xmm0
0x140034D05: mov     ecx, 4438h; Index
0x140034D0A: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034D0F: test    eax, eax
0x140034D11: jz      loc_140034DC6
0x140034D17: cmp     dword ptr [rbx+334h], 0
0x140034D1E: jnz     loc_140034DC6
0x140034D24: mov     ecx, eax
0x140034D26: mov     [rbx+334h], eax
0x140034D2C: mov     [rbx+330h], r15d
0x140034D33: lea     rax, [rcx+rdi]
0x140034D37: mov     [rbx+338h], rax
0x140034D3E: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034D42: movdqu  xmmword ptr [rbx+340h], xmm0
0x140034D4A: jmp     short loc_140034DC6
0x140034D4C: mov     ecx, 442Fh; Index
0x140034D51: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034D56: test    eax, eax
0x140034D58: jz      short loc_140034D89
0x140034D5A: cmp     dword ptr [rbx+304h], 0
0x140034D61: jnz     short loc_140034D89
0x140034D63: mov     ecx, eax
0x140034D65: mov     [rbx+304h], eax
0x140034D6B: mov     [rbx+300h], r15d
0x140034D72: lea     rax, [rcx+rdi]
0x140034D76: mov     [rbx+308h], rax
0x140034D7D: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034D81: movdqu  xmmword ptr [rbx+310h], xmm0
0x140034D89: mov     ecx, 4432h; Index
0x140034D8E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140034D93: test    eax, eax
0x140034D95: jz      short loc_140034DC6
0x140034D97: cmp     dword ptr [rbx+364h], 0
0x140034D9E: jnz     short loc_140034DC6
0x140034DA0: mov     ecx, eax
0x140034DA2: mov     [rbx+364h], eax
0x140034DA8: mov     [rbx+360h], r15d
0x140034DAF: lea     rax, [rcx+rdi]
0x140034DB3: mov     [rbx+368h], rax
0x140034DBA: movups  xmm0, xmmword ptr [rcx+rsi]
0x140034DBE: movdqu  xmmword ptr [rbx+370h], xmm0
0x140034DC6: mov     rcx, [rbp+57h+var_28]
0x140034DCA: xor     rcx, rsp; StackCookie
0x140034DCD: call    __security_check_cookie
0x140034DD2: lea     r11, [rsp+0F0h+var_20]
0x140034DDA: mov     rbx, [r11+30h]
0x140034DDE: mov     rsi, [r11+38h]
0x140034DE2: mov     rdi, [r11+40h]
0x140034DE6: mov     rsp, r11
0x140034DE9: pop     r15
0x140034DEB: pop     r14
0x140034DED: pop     r13
0x140034DEF: pop     r12
0x140034DF1: pop     rbp
0x140034DF2: retn