# BuildContextTableFromNtFile  ea=0x1400473A0  size=211
0x1400473A0: mov     [rsp+arg_10], rbx; 从 NT 文件构建上下文表。读取 GT 2272 的 ntoskrnl 基址，读取上下文表驱动文件，解析 PE 节区和导出目录，复制 28 项上下文条目。
0x1400473A5: push    rdi
0x1400473A6: sub     rsp, 20h
0x1400473AA: mov     ecx, 8E0h; Index
0x1400473AF: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400473B4: mov     rbx, rax
0x1400473B7: test    rax, rax
0x1400473BA: jz      loc_140047468
0x1400473C0: lea     rdx, [rsp+28h+arg_0]
0x1400473C5: lea     rcx, [rsp+28h+arg_8]
0x1400473CA: call    ReadNtFileForContextTable; 读取上下文表驱动文件。通过编码路径解码 ntoskrnl 文件路径，调用 ReadFileRawData 读取，然后用 ReadNtFileToBuffer 解析 PE 格式。
0x1400473CF: cmp     al, 1
0x1400473D1: jnz     loc_140047468
0x1400473D7: mov     ecx, 3F32h; Index
0x1400473DC: call    GtAlloc; 返回全局表中指定索引的指针。用于直接访问全局表条目。
0x1400473E1: mov     edx, [rsp+28h+arg_0]
0x1400473E5: mov     rcx, [rsp+28h+arg_8]
0x1400473EA: mov     r8, rax
0x1400473ED: mov     rdi, rax
0x1400473F0: call    ParseNtSectionsForContextTable; 解析 NT PE 节区查找上下文表偏移。读取 GT 2272，三阶段扫描：先找 Type 1369/1296/1368 标记获取偏移，再扫描最多 0xC8 项。Win8(9200) 时找第 2 个 Type 1298 节区，其他版本找 Type 1298 且 Type 1327 标记确认的节区。结果填充 28 项导出表。
0x1400473F5: cmp     al, 1
0x1400473F7: jnz     short loc_14004745E
0x1400473F9: mov     edx, [rsp+28h+arg_0]
0x1400473FD: mov     rcx, [rsp+28h+arg_8]
0x140047402: xor     r9d, r9d
0x140047405: mov     r8, rbx
0x140047408: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x14004740D: cmp     al, 1
0x14004740F: jnz     short loc_14004745E
0x140047411: lea     r8, [rdi+4]
0x140047415: mov     r9d, 1Ch
0x14004741B: mov     ecx, [r8]
0x14004741E: and     dword ptr [r8-4], 0
0x140047423: test    ecx, ecx
0x140047425: jz      short loc_140047447
0x140047427: lea     eax, [rcx+10h]
0x14004742A: cmp     eax, [rsp+28h+arg_0]
0x14004742E: ja      short loc_140047447
0x140047430: mov     dword ptr [r8-4], 1
0x140047438: mov     rax, [rsp+28h+arg_8]
0x14004743D: movups  xmm0, xmmword ptr [rcx+rax]
0x140047441: movdqu  xmmword ptr [r8+0Ch], xmm0
0x140047447: add     r8, 30h ; '0'
0x14004744B: dec     r9
0x14004744E: jnz     short loc_14004741B
0x140047450: lea     edx, [r9+1]; Value
0x140047454: mov     ecx, 8E2h; Index
0x140047459: call    GtWrite; 写入 64 位值到全局表指定索引。核心数据写入接口。
0x14004745E: mov     rcx, [rsp+28h+arg_8]
0x140047463: call    ExFree
0x140047468: mov     rbx, [rsp+28h+arg_10]
0x14004746D: add     rsp, 20h
0x140047471: pop     rdi
0x140047472: retn