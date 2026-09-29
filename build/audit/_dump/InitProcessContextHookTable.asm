# InitProcessContextHookTable  ea=0x140039728  size=322
0x140039728: mov     [rsp+arg_10], rbx
0x14003972D: mov     [rsp+arg_18], rsi
0x140039732: push    rdi
0x140039733: sub     rsp, 20h
0x140039737: mov     edi, 8C4h
0x14003973C: mov     ecx, edi; Index
0x14003973E: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140039743: mov     rbx, rax
0x140039746: test    rax, rax
0x140039749: jnz     short loc_140039763
0x14003974B: call    InitThreadNotify
0x140039750: mov     ecx, edi; Index
0x140039752: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140039757: mov     rbx, rax
0x14003975A: test    rax, rax
0x14003975D: jz      loc_14003985A
0x140039763: lea     rdx, [rsp+28h+arg_0]
0x140039768: lea     rcx, [rsp+28h+arg_8]
0x14003976D: call    ReadNtoskrnlToBuffer
0x140039772: mov     esi, 1
0x140039777: cmp     al, sil
0x14003977A: jnz     loc_14003985A
0x140039780: mov     edx, [rsp+28h+arg_0]
0x140039784: mov     rcx, [rsp+28h+arg_8]
0x140039789: call    ParseNtExportSectionsForProcessContext
0x14003978E: cmp     al, sil
0x140039791: jnz     loc_140039850
0x140039797: mov     edx, [rsp+28h+arg_0]
0x14003979B: mov     rcx, [rsp+28h+arg_8]
0x1400397A0: xor     r9d, r9d
0x1400397A3: mov     r8, rbx
0x1400397A6: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x1400397AB: cmp     al, sil
0x1400397AE: jnz     loc_140039850
0x1400397B4: mov     ecx, 2024h; Index
0x1400397B9: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400397BE: lea     edi, [rsi+1Bh]
0x1400397C1: lea     rbx, [rax+4]
0x1400397C5: mov     eax, [rbx]
0x1400397C7: and     dword ptr [rbx-4], 0
0x1400397CB: test    eax, eax
0x1400397CD: jz      short loc_1400397F8
0x1400397CF: add     eax, 10h
0x1400397D2: cmp     eax, [rsp+28h+arg_0]
0x1400397D6: ja      short loc_1400397F8
0x1400397D8: mov     rdx, rsi; Value
0x1400397DB: mov     ecx, 8C6h; Index
0x1400397E0: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x1400397E5: mov     ecx, [rbx]
0x1400397E7: mov     [rbx-4], esi
0x1400397EA: mov     rax, [rsp+28h+arg_8]
0x1400397EF: movups  xmm0, xmmword ptr [rcx+rax]
0x1400397F3: movdqu  xmmword ptr [rbx+0Ch], xmm0
0x1400397F8: add     rbx, 30h ; '0'
0x1400397FC: sub     rdi, rsi
0x1400397FF: jnz     short loc_1400397C5
0x140039801: mov     ecx, 20D2h; Index
0x140039806: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x14003980B: mov     edi, 1Bh
0x140039810: lea     rbx, [rax+4]
0x140039814: mov     eax, [rbx]
0x140039816: and     dword ptr [rbx-4], 0
0x14003981A: test    eax, eax
0x14003981C: jz      short loc_140039847
0x14003981E: add     eax, 10h
0x140039821: cmp     eax, [rsp+28h+arg_0]
0x140039825: ja      short loc_140039847
0x140039827: mov     rdx, rsi; Value
0x14003982A: mov     ecx, 8C7h; Index
0x14003982F: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140039834: mov     ecx, [rbx]
0x140039836: mov     [rbx-4], esi
0x140039839: mov     rax, [rsp+28h+arg_8]
0x14003983E: movups  xmm0, xmmword ptr [rcx+rax]
0x140039842: movdqu  xmmword ptr [rbx+0Ch], xmm0
0x140039847: add     rbx, 30h ; '0'
0x14003984B: sub     rdi, rsi
0x14003984E: jnz     short loc_140039814
0x140039850: mov     rcx, [rsp+28h+arg_8]
0x140039855: call    ExFree
0x14003985A: mov     rbx, [rsp+28h+arg_10]
0x14003985F: mov     rsi, [rsp+28h+arg_18]
0x140039864: add     rsp, 20h
0x140039868: pop     rdi
0x140039869: retn