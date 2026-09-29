# ParseSyscallTableExportDir  ea=0x1400865C8  size=200
0x1400865C8: mov     [rsp-8+arg_10], rbx
0x1400865CD: push    rbp
0x1400865CE: mov     rbp, rsp
0x1400865D1: sub     rsp, 20h
0x1400865D5: mov     ecx, 8AEh; Index
0x1400865DA: call    GtRead; 读取全局表指定索引的 64 位值。核心数据访问接口。
0x1400865DF: mov     rbx, rax
0x1400865E2: test    rax, rax
0x1400865E5: jz      loc_140086685
0x1400865EB: lea     rdx, [rbp+arg_0]
0x1400865EF: lea     rcx, [rbp+arg_8]
0x1400865F3: call    ReadWdfLibraryModule
0x1400865F8: cmp     al, 1
0x1400865FA: jnz     loc_140086685
0x140086600: mov     edx, [rbp+arg_0]
0x140086603: mov     rcx, [rbp+arg_8]
0x140086607: mov     r8, rbx
0x14008660A: call    FindSyscallTableDescriptor
0x14008660F: mov     edx, [rbp+arg_0]
0x140086612: mov     rcx, [rbp+arg_8]
0x140086616: call    BuildExportSectionMapping
0x14008661B: mov     edx, [rbp+arg_0]
0x14008661E: mov     rcx, [rbp+arg_8]
0x140086622: mov     r8, rbx
0x140086625: call    ParseSyscallTableDataSection
0x14008662A: mov     edx, [rbp+arg_0]
0x14008662D: mov     rcx, [rbp+arg_8]
0x140086631: mov     r8, rbx
0x140086634: call    ParseSyscallTableSections
0x140086639: mov     edx, [rbp+arg_0]
0x14008663C: mov     rcx, [rbp+arg_8]
0x140086640: xor     r9d, r9d
0x140086643: mov     r8, rbx
0x140086646: call    ParseNtExportDir; 解析 PE 导出目录的重定位。遍历基址重定位块，根据节偏移修正导出函数地址。
0x14008664B: cmp     al, 1
0x14008664D: jnz     short loc_14008667C
0x14008664F: mov     edx, [rbp+arg_0]
0x140086652: mov     rcx, [rbp+arg_8]
0x140086656: mov     r8, rbx
0x140086659: call    CollectSyscallEntries4
0x14008665E: mov     edx, [rbp+arg_0]
0x140086661: mov     rcx, [rbp+arg_8]
0x140086665: mov     r8, rbx
0x140086668: call    CollectTwoSyscallTables
0x14008666D: mov     edx, [rbp+arg_0]
0x140086670: mov     rcx, [rbp+arg_8]
0x140086674: mov     r8, rbx
0x140086677: call    CollectSyscallExportEntries
0x14008667C: mov     rcx, [rbp+arg_8]
0x140086680: call    ExFree
0x140086685: mov     rbx, [rsp+20h+arg_10]
0x14008668A: add     rsp, 20h
0x14008668E: pop     rbp
0x14008668F: retn