// CmdInitFwpsDispatchTables — 建立 Fwps 分发表副本（0x14001BC08）
// 对应原始驱动 0x14001BC08（316 字节）
// 【⚠ 修正记录 2026-10-13】原实现漏掉了**全部全局表访问**：
//   原稿直接校验输出缓冲后调用 EnumerateAleEndpointLayers。原始函数
//   先读 GT 0x800（懒初始化，为空则 call 0x14001BE80）与 GT 0x801，
//   再以这两个值为指针做内存校验，然后拷贝到用户缓冲。
//   发现方式：windows-driver-emulation skill 逐函数差分——原始读 0x800，
//   我方读 0 个；逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001BC08（按语义分四段）：
//   段 1（取全局表）：
//     `mov edi,0x800; call GtRead`；为空 → `call 0x14001BE80`；
//     再 `GtRead(0x800)` → r14；`GtRead(0x801)` → edi；
//     要求 r14 非 0 且 edi 非 0。
//   段 2（校验 r14 指向的结构）：
//     要求 r14 > MmSystemRangeStart、edi < 0x100；
//     r14 = *(ULONG64*)r14；要求 r14 > MmSystemRangeStart；
//     CheckMemoryValid(r14, 1) 必须返回 1（0x140059BC4）；
//     CheckMemoryValid(r14 - 1 + edi*8, 1) 必须返回 1。
//   段 3（校验用户输出缓冲）：
//     要求 r8(输出) 非 0；edi >= 1 且 大小 >= (edi-1)*8 + 0x10；
//     输出 < MmUserProbeAddress 且 输出+大小 < MmUserProbeAddress。
//   段 4（拷贝并返回）：
//     ProbeForWrite(输出, 大小, 8)；
//     memset(输出, 0, 大小)；
//     *(ULONG*)输出 = edi；
//     memmove(输出 + 8, r14, edi * 8)；
//     返回 1。
// 【返回值】1 = 成功；0 = 任一校验失败。
char CmdInitFwpsDispatchTables(__int64 Reserved1, __int64 Reserved2,
                               _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char    Result = 0;
    ULONG64 TablePtr;      // r14：GT 0x800
    ULONG   EntryCount;    // edi：GT 0x801
    ULONG64 RangeStart;

    /* ---- 段 1：取全局表（0x800 懒初始化，0x801 为条目数）---- */
    if (!GtRead((GLOBAL_TABLE_INDEX)0x800))                   // 0x14001BC30
        InitFwpsDispatchTables();                              // 0x14001BC3A

    TablePtr   = GtRead((GLOBAL_TABLE_INDEX)0x800);            // 0x14001BC41（r14）
    EntryCount = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x801);     // 0x14001BC4E（edi）

    if (!TablePtr || !EntryCount)                              // 0x14001BC56 / BC5F
        return Result;

    /* ---- 段 2：校验 TablePtr 指向的结构 ---- */
    RangeStart = *(ULONG64 *)MmSystemRangeStart;               // 0x14001BC67/6E
    if (TablePtr <= RangeStart                                 // 0x14001BC71
        || EntryCount >= 0x100)                                // 0x14001BC7A
        return Result;                                         // 0x14001BD28

    TablePtr = *(ULONG64 *)TablePtr;                           // 0x14001BC86
    if (TablePtr <= RangeStart)                                // 0x14001BC8C
        return Result;

    if ((char)CheckMemoryValid(TablePtr, 1) != 1)              // 0x14001BC97
        return Result;
    if ((char)CheckMemoryValid(TablePtr - 1 + (ULONG64)EntryCount * 8, 1) != 1)  // 0x14001BCB4
        return Result;

    /* ---- 段 3：校验用户输出缓冲 ---- */
    if (!OutputBuffer)                                         // 0x14001BCBD
        goto L_DONE;
    if ((ULONG64)BufferSize < (ULONG64)(EntryCount - 1) * 8 + 0x10)   // 0x14001BCC5/CCD
        goto L_DONE;
    if ((ULONG64)OutputBuffer >= *(ULONG64 *)MmUserProbeAddress)      // 0x14001BCD9/CDC
        goto L_DONE;
    if ((ULONG64)OutputBuffer + BufferSize >= *(ULONG64 *)MmUserProbeAddress)  // 0x14001BCE5
        goto L_DONE;

    /* ---- 段 4：拷贝 ---- */
    ProbeForWrite(OutputBuffer, BufferSize, 8);                // 0x14001BCF6
    memset(OutputBuffer, 0, BufferSize);                       // 0x14001BD04
    *OutputBuffer = EntryCount;                                // 0x14001BD09
    memmove(OutputBuffer + 2, (const void *)TablePtr,          // 0x14001BD15
            (ULONG64)EntryCount * 8);
    Result = 1;                                                // 0x14001BD1A

L_DONE:
    return Result;                                             // 0x14001BD28
}
