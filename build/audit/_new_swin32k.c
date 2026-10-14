// ScanWin32kDriverForPatterns — 扫描 ntdll 导出的系统调用桩（0x140052320）
// 对应原始驱动 0x140052320（968 字节 / 237 条指令）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**（4 条指令），与被注释地址无关。
//   发现方式：差分报原始调用 ReadFileRawData / ReadNtFileToBuffer / StringLength /
//   memmove 并读 GT 0x80F，我方只有 4 条指令；逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【语义】读 ntdll.dll，遍历其**导出表**，对每个导出函数检查入口是否匹配
//   系统调用桩的机器码模式：偏移 0 起为 4C 8B D1 B8（mov r10,rcx; mov eax,imm32，
//   Win10 x64 syscall stub 的标准前 4 字节），且 [+6]==0、[+7]==0；
//   函数名须以 'Nt'(0x744E) 开头。
//   命中项按 **0x58 字节/项**填入输出表：
//     +0x00 = 服务号（入口 +4 处的 imm32）
//     +0x04 = 函数名（memmove 拷贝，长度由 StringLength 求得，须 < 0x40）
//   返回：匹配数 == 传入上限时返回 1，否则返回“是否至少匹配一个”。
// 【参数】PatternBase = 输出表基址；PatternSize = 可容纳项数（同时是服务号上限）。
// 【原始汇编骨架】
//   ① 构造 \SystemRoot\system32\ntdll.dll（15 个 DWORD 写入栈局部）
//   ② ReadFileRawData(路径, &FileBuf, &FileSize, 1)（0x14002F680）；非 0 即失败
//   ③ ReadNtFileToBuffer(FileBuf, FileSize, &MappedBase, &MappedSize, 0)（0x140005D4C）
//      返回 1 才继续
//   ④ 取 e_lfanew=[+0x3C]，导出目录 RVA=[+0x88]、大小=[+0x8C]，一串边界校验
//   ⑤ 遍历 AddressOfNames / AddressOfNameOrdinals / AddressOfFunctions
//   ⑥ ExFree(映射基址)、ExFree(文件缓冲)；返回前读 GT 0x80F（副作用保留）
__int64 ScanWin32kDriverForPatterns(ULONG_PTR PatternBase, ULONG_PTR PatternSize)
{
    WCHAR    PathBuf[32];
    ULONG64  FileBuffer = 0;
    ULONG    FileSize = 0;
    PUCHAR   MappedBase = 0;
    ULONG    MappedSize = 0;
    __int64  NtHeaders;
    ULONG    ExportRva, ExportSize, ExportEnd;
    PUCHAR   NamesTable, NameOrdinals, FunctionsTable;
    ULONG    FuncCount, Index, MatchCount = 0;
    UCHAR    Result;
    ULONG    NameLen;
    ULONG    k;

    /* ① 路径 */
    {
        static const WCHAR kPath[] = L"\\SystemRoot\\system32\\ntdll.dll";
        for (k = 0; k < 31 && kPath[k]; ++k) PathBuf[k] = kPath[k];
        PathBuf[k] = 0;
    }

    /* ② 读文件（RequirePeHeader=1） */
    if ((ULONG)ReadFileRawData(PathBuf, (void **)&FileBuffer, &FileSize, 1) != 0)   // 0x1400523DA
    {
        return 0;
    }

    /* ③ 映射为可解析形态 */
    if ((char)ReadNtFileToBuffer((PUCHAR)FileBuffer, FileSize,
                                 &MappedBase, &MappedSize, 0) != 1)               // 0x1400523FB
    {
        ExFree((void *)FileBuffer);                                                  // 0x140052624
        return 0;
    }

    /* ④ 取导出目录 */
    NtHeaders = (__int64)(MappedBase + *(int *)(MappedBase + 0x3C));                 // 0x140052411
    ExportRva  = *(ULONG *)(NtHeaders + 0x88);                                       // 0x140052415
    ExportSize = *(ULONG *)(NtHeaders + 0x8C);                                       // 0x14005241D
    ExportEnd  = ExportRva + ExportSize;                                             // 0x140052425

    if (ExportRva >= MappedSize || ExportRva + 0x28 >= MappedSize                    // 0x14005242C/439
        || ExportSize >= MappedSize || ExportEnd >= MappedSize)                      // 0x140052442/44B
        goto L_FREE;

    {
        PUCHAR ExpDir = MappedBase + ExportRva;
        ULONG  AddrOfFunctions = *(ULONG *)(ExpDir + 0x1C);                          // 0x1400524B1
        ULONG  AddrOfNames     = *(ULONG *)(ExpDir + 0x20);                          // 0x140052461
        ULONG  AddrOfOrdinals  = *(ULONG *)(ExpDir + 0x24);                          // 0x140052493
        ULONG  OrdBase         = *(ULONG *)(ExpDir + 0x14);                          // 0x140052454

        FuncCount = *(ULONG *)(ExpDir + 0x18);                                       // 0x140052459

        if (AddrOfNames < ExportRva) goto L_FREE;                                    // 0x140052466
        if (AddrOfNames + 4 * (ULONG64)FuncCount >= MappedSize) goto L_FREE;         // 0x140052481/48A
        if (AddrOfOrdinals < ExportRva) goto L_FREE;                                 // 0x140052498
        if (AddrOfOrdinals + 2 * (ULONG64)FuncCount >= MappedSize) goto L_FREE;      // 0x1400524A8
        if (AddrOfFunctions < ExportRva) goto L_FREE;                                // 0x1400524B6
        if (AddrOfFunctions + 4 * (ULONG64)OrdBase >= MappedSize) goto L_FREE;       // 0x1400524C9
        if (!FuncCount) goto L_FREE;                                                 // 0x1400524E6

        NamesTable     = MappedBase + AddrOfNames;
        NameOrdinals   = MappedBase + AddrOfOrdinals;
        FunctionsTable = MappedBase + AddrOfFunctions;

        for (Index = 0; Index < FuncCount; ++Index)                                  // 0x14005260A
        {
            ULONG  Ordinal;
            ULONG  FuncRva;
            PUCHAR FuncEntry;
            ULONG  NameRva;
            PUCHAR FuncName;

            Ordinal = *(USHORT *)NameOrdinals;                                       // 0x1400524EF
            if (Ordinal >= OrdBase) goto NEXT;
            FuncRva = *(ULONG *)(FunctionsTable + 4 * (ULONG64)Ordinal);             // 0x1400524FC
            if (FuncRva >= MappedSize) goto NEXT;                                    // 0x140052500
            if (FuncRva < ExportRva || FuncRva >= ExportEnd) goto NEXT;              // 0x140052509/50A

            FuncEntry = MappedBase + FuncRva;
            if (FuncEntry < MappedBase) goto NEXT;                                   // 0x14005251B
            if (FuncEntry >= MappedBase + MappedSize) goto NEXT;                     // 0x14005252A
            if (FuncEntry + 2 >= MappedBase + MappedSize) goto NEXT;                 // 0x140052537

            if (*(USHORT *)FuncEntry != 0x744E) goto NEXT;                           // 0x140052545（'Nt'）

            NameRva  = *(ULONG *)NamesTable;                                         // 0x140052516
            FuncName = MappedBase + NameRva;                                         // 0x14005254E
            if (FuncName < MappedBase) goto NEXT;                                    // 0x140052551
            if (FuncName >= MappedBase + MappedSize) goto NEXT;                      // 0x14005255A
            if (FuncName + 0xB >= MappedBase + MappedSize) goto NEXT;                // 0x140052563

            if (FuncName[0] != 0x4C || FuncName[1] != 0x8B                           // 0x140052570..588
                || FuncName[2] != 0xD1 || FuncName[3] != 0xB8) goto NEXT_PATTERN;
            if (FuncName[6] != 0 || FuncName[7] != 0) goto NEXT;                     // 0x140052594/59A

            {
                ULONG ServiceNo = *(ULONG *)(FuncName + 4);                          // 0x1400525A0
                NameLen = (ULONG)StringLength((_WORD *)FuncEntry);                   // 0x1400525A6
                if (ServiceNo >= (ULONG)PatternSize) goto NEXT;                      // 0x1400525AB
                if (NameLen >= 0x40) goto NEXT;                                      // 0x1400525B0

                ++MatchCount;                                                        // 0x1400525B5
                {
                    PUCHAR Slot = (PUCHAR)(PatternBase + 0x58ULL * ServiceNo);       // 0x1400525B8
                    *(ULONG *)Slot = ServiceNo;                                      // 0x1400525C6
                    memmove(Slot + 4, FuncEntry, NameLen);                           // 0x1400525D2
                    Slot[4 + NameLen] = 0;                                           // 0x1400525E3
                }
            }

        NEXT_PATTERN:
            ;
        NEXT:
            NamesTable += 4;                                                         // 0x1400525FA
            NameOrdinals += 2;                                                       // 0x1400525FE
        }
    }

L_FREE:
    if (MappedBase) ExFree(MappedBase);                                              // 0x14005261B
    ExFree((void *)FileBuffer);                                                      // 0x140052624

    (void)GtRead((GLOBAL_TABLE_INDEX)0x80F);                                         // 0x1400526B8

    Result = (MatchCount == (ULONG)PatternSize) ? 1 : (MatchCount ? 1 : 0);          // 0x140052629..635
    return Result;
}