# ResolveWin32kExportAddresses  ea=0x140088608  size=277
0x140088608: mov     [rsp-18h+arg_10], rbx
0x14008860D: push    rbp
0x14008860E: push    rsi
0x14008860F: push    rdi
0x140088610: mov     rbp, rsp
0x140088613: sub     rsp, 50h
0x140088617: mov     rax, cs:__security_cookie
0x14008861E: xor     rax, rsp
0x140088621: mov     [rbp+var_10], rax
0x140088625: and     [rbp+var_30], 0
0x140088629: mov     rsi, rcx
0x14008862C: mov     ecx, 8F6h; Index
0x140088631: mov     ebx, edx
0x140088633: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140088638: mov     rdi, rax
0x14008863B: test    rax, rax
0x14008863E: jz      loc_140088701
0x140088644: mov     ecx, 8FBh; Index
0x140088649: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14008864E: test    eax, eax
0x140088650: jnz     loc_140088701
0x140088656: and     dword ptr [rbp+var_28+14h], eax
0x140088659: lea     r9, [rbp+var_30]
0x14008865D: lea     r8, [rbp+var_28]
0x140088661: mov     edx, ebx
0x140088663: mov     rcx, rsi
0x140088666: mov     dword ptr [rbp+var_28], 7355744Eh
0x14008866D: mov     dword ptr [rbp+var_28+4], 75427265h
0x140088674: mov     dword ptr [rbp+var_28+8], 48646C69h
0x14008867B: mov     dword ptr [rbp+var_28+0Ch], 4C646E77h
0x140088682: mov     dword ptr [rbp+var_28+10h], 747369h
0x140088689: call    LookupExportByName; 按名称查找导出函数。遍历 PE 导出目录的名称表，比较字符串，返回地址到输出参数。
0x14008868E: cmp     al, 1
0x140088690: jnz     short loc_1400886AB
0x140088692: mov     eax, [rbp+var_30]
0x140088695: test    eax, eax
0x140088697: jz      short loc_1400886AB
0x140088699: cmp     eax, ebx
0x14008869B: jnb     short loc_1400886AB
0x14008869D: lea     rdx, [rdi+rax]; Value
0x1400886A1: mov     ecx, 1F2h; Index
0x1400886A6: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400886AB: and     dword ptr [rbp+var_28+14h], 0
0x1400886AF: lea     r9, [rbp+var_30]
0x1400886B3: lea     r8, [rbp+var_28]
0x1400886B7: mov     edx, ebx
0x1400886B9: mov     rcx, rsi
0x1400886BC: mov     dword ptr [rbp+var_28], 7355744Eh
0x1400886C3: mov     dword ptr [rbp+var_28+4], 75517265h
0x1400886CA: mov     dword ptr [rbp+var_28+8], 57797265h
0x1400886D1: mov     dword ptr [rbp+var_28+0Ch], 6F646E69h
0x1400886D8: mov     dword ptr [rbp+var_28+10h], 77h ; 'w'
0x1400886DF: call    LookupExportByName; 按名称查找导出函数。遍历 PE 导出目录的名称表，比较字符串，返回地址到输出参数。
0x1400886E4: cmp     al, 1
0x1400886E6: jnz     short loc_140088701
0x1400886E8: mov     eax, [rbp+var_30]
0x1400886EB: test    eax, eax
0x1400886ED: jz      short loc_140088701
0x1400886EF: cmp     eax, ebx
0x1400886F1: jnb     short loc_140088701
0x1400886F3: lea     rdx, [rdi+rax]; Value
0x1400886F7: mov     ecx, 1F7h; Index
0x1400886FC: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140088701: mov     rcx, [rbp+var_10]
0x140088705: xor     rcx, rsp; StackCookie
0x140088708: call    __security_check_cookie
0x14008870D: mov     rbx, [rsp+50h+arg_10]
0x140088715: add     rsp, 50h
0x140088719: pop     rdi
0x14008871A: pop     rsi
0x14008871B: pop     rbp
0x14008871C: retn