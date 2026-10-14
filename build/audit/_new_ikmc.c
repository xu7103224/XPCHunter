// InitKernelMemoryContext — 初始化 WFP/KFD/NSI 节区上下文（0x14006BF2C）
// 对应原始驱动 0x14006BF2C（515 字节 / 200 条指令）
// 【⚠ 修正记录 2026-10-13】原为**完全不相干**的实现：
//     `Offset = GtRead(GtEprocessExtField08); return ReadObjectHeaderField(NULL, Offset, 0);`
//   原始是一个 **28 路条件分派器**：先读 netio.sys 文件到缓冲，
//   然后对 26 组「结果槽 → 解析函数」逐组判断——**仅当该结果槽为空时**
//   才调用对应的解析函数（传入文件缓冲与大小），最后释放缓冲。
//   发现方式：差分包原始读 GT 0x7B2/0x7B4/0x7B8/0x7BB… 一串索引并调用
//   众多函数，我方只有 2 条指令；逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编骨架】
//   ① 保存 rbx/rdi；rbp = rsp；sub rsp,0x20
//   ② `ReadNetioDriverFile(&FileBuffer, &FileSize)`（0x14006C22C）；须返回 1
//   ③ 26 组重复模式（槽, 函数）：
//        `mov ecx,<槽>; call GtRead; test rax,rax; jne 跳过`
//        `mov edx,[rbp+0x10](FileSize); mov rcx,[rbp+0x18](FileBuffer); call <函数>`
//   ④ `ExFree(FileBuffer)`
//   ⑤ 恢复寄存器返回
// 【分派表（GT 槽 → 被调函数，按原始顺序）】
//   0x7B2 FindWfpNblInfoDispatchTableClear     0x7B4 ScanWfpNblInfoSections
//   0x7B8 FindKfdGetOffloadEpochExport         0x7BB ScanKernelDataPartitionSection
//   0x7BC FindKfdRegisterLayerCallbackExport   0x7BE FindKfdDeregisterLayerCallbackExport
//   0x7C0 ScanKfdDriverSections                0x7C1 FindWfpStartStreamShimExport
//   0x7C3 FindWfpStopStreamShimExport          0x7C7 ScanWfpStreamShimSections
//   0x7C8 FindNsiDeregisterChangeNotificationEx 0x7CA FindNsiGetModuleHandle
//   0x7CD ScanNsiGetModuleDataSection          0x7CE FindNsiDeregisterLegacyHandler
//   0x7D0 ScanNsiDeregisterDataSection         0x7D1 FindWfpStartMacShimExport
//   0x7D3 ScanWfpMacShimSections               0x7D4 FindSetWfpDeviceObject
//   0x7D6 ScanWfpDeviceObjectSection           0x7D7 FindNmrRegisterProviderExport
//   0x7D9 ScanKernelMemoryDataSection          0x7DA FindKfdGetRefCalloutExport
//   0x914（构建号，非槽）→ 按值二选一 V2/V3     0x7DE FindKfdDeleteCalloutEntryExport
//   0x7E0 FindKfdUnregisterCalloutEntryExport
//   （0x914 组之后是按构建号二选一：>=0x47BA 用 ScanKfdDriverSectionV3，
//     否则用 ScanKfdDriverSectionV2——两者是同一槽位的两个版本实现。）
__int64 InitKernelMemoryContext(void)
{
    ULONG64 FileBuffer = 0;     // [rbp+0x18]
    ULONG   FileSize = 0;       // [rbp+0x10]

    /* ① 读 netio.sys 到缓冲；失败即返回 */
    if ((char)ReadNetioDriverFile(&FileBuffer, &FileSize) != 1)   // 0x14006BF46（call 0x14006C22C）
        return 0;

    /* ② 26 组"槽空才调用"的分派 */
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7B2))                       // 0x14006BF58
        FindWfpNblInfoDispatchTableClear(FileBuffer, FileSize);    // 0x14006BF69
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7B4))                       // 0x14006BF73
        ScanWfpNblInfoSections(FileBuffer, FileSize);              // 0x14006BF84
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7B8))                       // 0x14006BF8E
        FindKfdGetOffloadEpochExport(FileBuffer, FileSize);        // 0x14006BF9F
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7BB))                       // 0x14006BFA9
        ScanKernelDataPartitionSection(FileBuffer, FileSize);      // 0x14006BFBA
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7BC))                       // 0x14006BFC4
        FindKfdRegisterLayerCallbackExport(FileBuffer, FileSize);  // 0x14006BFD5
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7BE))
        FindKfdDeregisterLayerCallbackExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7C0))
        ScanKfdDriverSections(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7C1))
        FindWfpStartStreamShimExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7C3))
        FindWfpStopStreamShimExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7C7))
        ScanWfpStreamShimSections(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7C8))
        FindNsiDeregisterChangeNotificationEx(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7CA))
        FindNsiGetModuleHandle(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7CD))
        ScanNsiGetModuleDataSection(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7CE))
        FindNsiDeregisterLegacyHandler(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D0))
        ScanNsiDeregisterDataSection(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D1))
        FindWfpStartMacShimExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D3))
        ScanWfpMacShimSections(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D4))
        FindSetWfpDeviceObject(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D6))
        ScanWfpDeviceObjectSection(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D7))
        FindNmrRegisterProviderExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D9))
        ScanKernelMemoryDataSection(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7DA))
        FindKfdGetRefCalloutExport(FileBuffer, FileSize);

    /* 0x914 组之后：按构建号二选一（构建号 >= 0x47BA 用 V3，否则用 V2） */
    {
        ULONG Build = (ULONG)GtRead(GtWindowsBuildNumber);         // 0x14006C1C0（0x914）
        if (Build >= 0x47BA)                                       // 0x14006C1CA
            ScanKfdDriverSectionV3(FileBuffer, FileSize);          // 0x14006C1D8
        else
            ScanKfdDriverSectionV2(FileBuffer, FileSize);          // 0x14006C1D1
    }                                                              // 汇合于 0x14006C1DD

    if (!GtRead((GLOBAL_TABLE_INDEX)0x7DE))
        FindKfdDeleteCalloutEntryExport(FileBuffer, FileSize);
    if (!GtRead((GLOBAL_TABLE_INDEX)0x7E0))
        FindKfdUnregisterCalloutEntryExport(FileBuffer, FileSize);

    /* ③ 释放缓冲 */
    ExFree((void *)FileBuffer);                                    // 0x14006C217
    return 0;
}
