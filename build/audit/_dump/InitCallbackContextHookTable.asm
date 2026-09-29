# InitCallbackContextHookTable  ea=0x14003E5BC  size=239
0x14003E5BC: mov     [rsp+arg_10], rbx
0x14003E5C1: mov     [rsp+arg_18], rsi
0x14003E5C6: push    rdi
0x14003E5C7: sub     rsp, 20h
0x14003E5CB: mov     ecx, 3BC6h; Index
0x14003E5D0: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x14003E5D5: mov     ecx, 8D3h; Index
0x14003E5DA: xor     ebx, ebx
0x14003E5DC: mov     rdi, rax
0x14003E5DF: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x14003E5E4: mov     rsi, rax
0x14003E5E7: test    rax, rax
0x14003E5EA: jz      loc_14003E69B
0x14003E5F0: lea     rdx, [rsp+28h+arg_0]
0x14003E5F5: lea     rcx, [rsp+28h+arg_8]
0x14003E5FA: call    ReadNtoskrnlForCallbackContext
0x14003E5FF: cmp     al, 1
0x14003E601: jnz     loc_14003E69B
0x14003E607: mov     edx, [rsp+28h+arg_0]
0x14003E60B: mov     rcx, [rsp+28h+arg_8]
0x14003E610: mov     r8, rdi
0x14003E613: call    ParseNtFileForCallbackContext
0x14003E618: cmp     al, 1
0x14003E61A: jnz     short loc_14003E684
0x14003E61C: mov     edx, [rsp+28h+arg_0]
0x14003E620: mov     rcx, [rsp+28h+arg_8]
0x14003E625: xor     r9d, r9d
0x14003E628: mov     r8, rsi
0x14003E62B: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x14003E630: cmp     al, 1
0x14003E632: jnz     short loc_14003E684
0x14003E634: lea     rdx, [rdi+4]
0x14003E638: lea     r8d, [rbx+1Ch]
0x14003E63C: mov     ecx, [rdx]
0x14003E63E: mov     [rdx-4], ebx
0x14003E641: test    ecx, ecx
0x14003E643: jz      short loc_14003E66B
0x14003E645: lea     eax, [rcx+20h]
0x14003E648: cmp     eax, [rsp+28h+arg_0]
0x14003E64C: ja      short loc_14003E66B
0x14003E64E: mov     dword ptr [rdx-4], 1
0x14003E655: mov     rax, [rsp+28h+arg_8]
0x14003E65A: movups  xmm0, xmmword ptr [rcx+rax]
0x14003E65E: movups  xmmword ptr [rdx+0Ch], xmm0
0x14003E662: movups  xmm1, xmmword ptr [rcx+rax+10h]
0x14003E667: movups  xmmword ptr [rdx+1Ch], xmm1
0x14003E66B: add     rdx, 30h ; '0'
0x14003E66F: dec     r8
0x14003E672: jnz     short loc_14003E63C
0x14003E674: lea     edx, [r8+1]; Value
0x14003E678: mov     ecx, 8D5h; Index
0x14003E67D: mov     bl, 1
0x14003E67F: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14003E684: mov     rcx, [rsp+28h+arg_8]
0x14003E689: call    ExFree
0x14003E68E: cmp     bl, 1
0x14003E691: jnz     short loc_14003E69B
0x14003E693: mov     rcx, rdi
0x14003E696: call    FillExportEntrySlot
0x14003E69B: mov     rbx, [rsp+28h+arg_10]
0x14003E6A0: mov     rsi, [rsp+28h+arg_18]
0x14003E6A5: add     rsp, 20h
0x14003E6A9: pop     rdi
0x14003E6AA: retn