# BuildCallbackContextHookTargets  ea=0x140035EE0  size=231
0x140035EE0: mov     [rsp+arg_10], rbx
0x140035EE5: mov     [rsp+arg_18], rsi
0x140035EEA: push    rdi
0x140035EEB: sub     rsp, 20h
0x140035EEF: mov     ecx, 3FE6h; Index
0x140035EF4: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x140035EF9: mov     ecx, 902h; Index
0x140035EFE: xor     ebx, ebx
0x140035F00: mov     rdi, rax
0x140035F03: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x140035F08: mov     rsi, rax
0x140035F0B: test    rax, rax
0x140035F0E: jz      loc_140035FB7
0x140035F14: lea     rdx, [rsp+28h+arg_0]
0x140035F19: lea     rcx, [rsp+28h+arg_8]
0x140035F1E: call    ReadNtoskrnlForCallbackCtx
0x140035F23: cmp     al, 1
0x140035F25: jnz     loc_140035FB7
0x140035F2B: mov     edx, [rsp+28h+arg_0]
0x140035F2F: mov     rcx, [rsp+28h+arg_8]
0x140035F34: mov     r8, rdi
0x140035F37: call    ParseNtExportSectionsV3
0x140035F3C: cmp     al, 1
0x140035F3E: jnz     short loc_140035FA0
0x140035F40: mov     edx, [rsp+28h+arg_0]
0x140035F44: mov     rcx, [rsp+28h+arg_8]
0x140035F49: xor     r9d, r9d
0x140035F4C: mov     r8, rsi
0x140035F4F: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x140035F54: cmp     al, 1
0x140035F56: jnz     short loc_140035FA0
0x140035F58: lea     rdx, [rdi+4]
0x140035F5C: lea     r8d, [rbx+1Ch]
0x140035F60: mov     ecx, [rdx]
0x140035F62: mov     [rdx-4], ebx
0x140035F65: test    ecx, ecx
0x140035F67: jz      short loc_140035F87
0x140035F69: lea     eax, [rcx+10h]
0x140035F6C: cmp     eax, [rsp+28h+arg_0]
0x140035F70: ja      short loc_140035F87
0x140035F72: mov     dword ptr [rdx-4], 1
0x140035F79: mov     rax, [rsp+28h+arg_8]
0x140035F7E: movups  xmm0, xmmword ptr [rcx+rax]
0x140035F82: movdqu  xmmword ptr [rdx+0Ch], xmm0
0x140035F87: add     rdx, 30h ; '0'
0x140035F8B: dec     r8
0x140035F8E: jnz     short loc_140035F60
0x140035F90: lea     edx, [r8+1]; Value
0x140035F94: mov     ecx, 904h; Index
0x140035F99: mov     bl, 1
0x140035F9B: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x140035FA0: mov     rcx, [rsp+28h+arg_8]
0x140035FA5: call    ExFree
0x140035FAA: cmp     bl, 1
0x140035FAD: jnz     short loc_140035FB7
0x140035FAF: mov     rcx, rdi
0x140035FB2: call    FillExportEntrySlot
0x140035FB7: mov     rbx, [rsp+28h+arg_10]
0x140035FBC: mov     rsi, [rsp+28h+arg_18]
0x140035FC1: add     rsp, 20h
0x140035FC5: pop     rdi
0x140035FC6: retn