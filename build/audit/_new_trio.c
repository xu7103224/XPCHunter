// ============================================================
// Syscall/Context 表初始化三兄弟（L2-4）
//
// InitProcessContextExportTableWin7 / InitUSBPortSyscallTable / InitThreadContextTable
// 三者**结构完全同构**（各 231 字节，指令序列逐一对应，仅 GT 索引与
// Read*/Parse* 辅助函数不同），原实现均为 `return;` 空壳。
//
// 统一模板（逐条转写自 0x140039FF4 / 0x140055914 / 0x1400570C8）：
//   ① GtAlloc(<分配索引>)                 → 目标表（rdi）
//   ② GtRead(<门限索引>)                  → 校验值（rsi），为 0 则整体跳过
//   ③ Read*(&Ptr, &Size)                  → 须返回 1
//   ④ Parse*(Ptr, Size, 目标表)           → 须返回 1
//   ⑤ ParseNtExportDir(Ptr, Size, 读表, 0) → 须返回 1
//   ⑥ 展开 0x1C 项：把 *(ULONG*)(表+4+i*0x30) 视为相对偏移，
//      非零且 (偏移 + 0x10) <= Size 时置 标志=1 并把该偏移处的 16 字节
//      拷入 (表 + i*0x30 + 0x10)；每轮的旧值先清零
//   ⑦ GtWrite(<就绪索引>, 1)
//   ⑧ ExFree(读表)；成功时调 FillExportEntrySlot(目标表)
// ============================================================

// InitProcessContextExportTableWin7 — 进程上下文导出表（Win7 版）
// 对应原始驱动 0x140039FF4（231 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return;` 空壳。
void InitProcessContextExportTableWin7(void)
{
    __int64 Table;              // rdi = GtAlloc(0x3A6A)
    __int64 Loaded;             // rsi = GtRead(0x8C1)
    ULONG   Size;               // [rsp+0x30]
    ULONG64 Ptr;                // [rsp+0x38]
    UCHAR   Ok;                 // bl
    ULONG   i;

    Table  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x3A6A);   // 0x14003A003
    Loaded = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8C1);     // 0x14003A00D
    Ok = 0;

    if (!Loaded)                                             // 0x14003A01F
        return;

    if ((UCHAR)ReadIpsecSysFile(&Ptr, &Size) != 1)            // 0x14003A032
        return;                                              // 0x14003A039

    if (ParseRsdsDebugInfo((PUCHAR)Ptr, Size, Table) != 1)    // 0x14003A048
        goto L_FREE;

    if ((UCHAR)ParseNtExportDir((PUCHAR)Ptr, Size, (ULONG64)Loaded, 0) != 1)  // 0x14003A063
        goto L_FREE;

    // 0x14003A06C~0A0A：展开 0x1C 项
    for (i = 0; i < 0x1C; ++i)
    {
        ULONG *DstSlot = (ULONG *)(Table + 4 + (ULONG64)i * 0x30);
        ULONG  RelOfs  = *DstSlot;                           // 0x14003A074
        *((ULONG *)DstSlot - 1) = 0;                         // 0x14003A076 标志清零
        if (RelOfs != 0 && RelOfs + 0x10 <= Size)            // 0x14003A079/07D/080
        {
            *((ULONG *)DstSlot - 1) = 1;                     // 0x14003A086
            *(ULONG64 *)((PUCHAR)DstSlot + 0x0C) = *(ULONG64 *)(Ptr + RelOfs);      // 0x14003A092
            *(ULONG64 *)((PUCHAR)DstSlot + 0x14) = *(ULONG64 *)(Ptr + RelOfs + 8);  // 0x14003A096
        }
    }

    GtWrite((GLOBAL_TABLE_INDEX)0x8C3, 1);                   // 0x14003A0A8/0AD
    Ok = 1;

L_FREE:
    ExFree((void *)Ptr);                                     // 0x14003A0B9
    if (Ok == 1)                                             // 0x14003A0BE
        FillExportEntrySlot(Table);                          // 0x14003A0C6
}

// InitUSBPortSyscallTable — USB 端口系统调用表
// 对应原始驱动 0x140055914（231 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return;` 空壳。
void InitUSBPortSyscallTable(void)
{
    __int64 Table;              // rdi = GtAlloc(0x3DD0)
    __int64 Loaded;             // rsi = GtRead(0x8DA)
    ULONG   Size;
    ULONG64 Ptr;
    UCHAR   Ok;
    ULONG   i;

    Table  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x3DD0);   // 0x140055923
    Loaded = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8DA);     // 0x14005592D
    Ok = 0;

    if (!Loaded)                                             // 0x14005593F
        return;

    if ((UCHAR)ReadUSBPortDriverFile(&Ptr, &Size) != 1)       // 0x140055952
        return;

    if (ParseUSBPortSyscallStubs((PUCHAR)Ptr, Size, Table) != 1)   // 0x14005596B
        goto L_FREE;

    if ((UCHAR)ParseNtExportDir((PUCHAR)Ptr, Size, (ULONG64)Loaded, 0) != 1)  // 0x140055983
        goto L_FREE;

    for (i = 0; i < 0x1C; ++i)
    {
        ULONG *DstSlot = (ULONG *)(Table + 4 + (ULONG64)i * 0x30);
        ULONG  RelOfs  = *DstSlot;
        *((ULONG *)DstSlot - 1) = 0;
        if (RelOfs != 0 && RelOfs + 0x10 <= Size)
        {
            *((ULONG *)DstSlot - 1) = 1;
            *(ULONG64 *)((PUCHAR)DstSlot + 0x0C) = *(ULONG64 *)(Ptr + RelOfs);
            *(ULONG64 *)((PUCHAR)DstSlot + 0x14) = *(ULONG64 *)(Ptr + RelOfs + 8);
        }
    }

    GtWrite((GLOBAL_TABLE_INDEX)0x8DC, 1);                   // 0x1400559C8/9CD
    Ok = 1;

L_FREE:
    ExFree((void *)Ptr);                                     // 0x1400559D9
    if (Ok == 1)
        FillExportEntrySlot(Table);                          // 0x1400559E6
}

// InitThreadContextTable — 线程上下文表
// 对应原始驱动 0x1400570C8（231 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return;` 空壳。
void InitThreadContextTable(void)
{
    __int64 Table;              // rdi = GtAlloc(0x409A)
    __int64 Loaded;             // rsi = GtRead(0x905)
    ULONG   Size;
    ULONG64 Ptr;
    UCHAR   Ok;
    ULONG   i;

    Table  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x409A);   // 0x1400570D7
    Loaded = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x905);     // 0x1400570E1
    Ok = 0;

    if (!Loaded)                                             // 0x1400570F3
        return;

    if ((UCHAR)ReadVolumeSysFile(&Ptr, &Size) != 1)           // 0x140057106
        return;

    if (ParseNtDebugSection((PUCHAR)Ptr, Size, Table) != 1)   // 0x14005711F
        goto L_FREE;

    if ((UCHAR)ParseNtExportDir((PUCHAR)Ptr, Size, (ULONG64)Loaded, 0) != 1)  // 0x140057137
        goto L_FREE;

    for (i = 0; i < 0x1C; ++i)
    {
        ULONG *DstSlot = (ULONG *)(Table + 4 + (ULONG64)i * 0x30);
        ULONG  RelOfs  = *DstSlot;
        *((ULONG *)DstSlot - 1) = 0;
        if (RelOfs != 0 && RelOfs + 0x10 <= Size)
        {
            *((ULONG *)DstSlot - 1) = 1;
            *(ULONG64 *)((PUCHAR)DstSlot + 0x0C) = *(ULONG64 *)(Ptr + RelOfs);
            *(ULONG64 *)((PUCHAR)DstSlot + 0x14) = *(ULONG64 *)(Ptr + RelOfs + 8);
        }
    }

    GtWrite((GLOBAL_TABLE_INDEX)0x907, 1);                   // 0x14005717C/181
    Ok = 1;

L_FREE:
    ExFree((void *)Ptr);                                     // 0x14005718D
    if (Ok == 1)
        FillExportEntrySlot(Table);                          // 0x140057197
}