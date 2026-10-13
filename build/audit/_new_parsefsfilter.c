// ParseFsFilterDriverExport — 解析文件系统过滤驱动导出
// 对应原始驱动 0x14000E3A0（365 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：读 GtFsFilterDriverBase /
//   GtFsFilterDriverSize 再调一次 FindExportInFileByName 就返回。虽注释写着
//   "对应原始驱动 sub_14000E3A0"，函数体却与该地址无关。
//   发现方式：用 windows-driver-emulation skill 做「原始 vs 重编译」逐函数差分，
//   运行时观测到 GT 读索引完全不同（原始读 0x914/0x2F1，旧稿读的是别的索引
//   且无版本判断），再逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写**（IDA 对本函数报
//   "function frame is wrong"，无伪代码可用）。
// 【逻辑】按 Is64Bit 分两支，两支都是「读文件 → 查导出 → 填表」，
//   差别只在 GtAlloc 的表索引与条目偏移基数：
//
//   分支 A（Is64Bit == 1）：
//     ① 构建号 = GtRead(0x914)；
//     ② 若 构建号 >= 0x1770 且 构建号 < 0x23F0 → 直接返回；
//     ③ 导出表基址 = GtRead(0x2F1)；为空则返回；
//     ④ 表 = GtAlloc(0x1BB0)；
//     ⑤ ReadNtFileForSsdtTargets2(&Buf,&Size) 必须返回 1；
//     ⑥ 系数 = (构建号 < 0x1770) ? 0x1F : 0x0A
//        （反汇编 `cmp; sbb; and 0x15; add 0x0A` 的等价展开）；
//        条目偏移 = 系数 * 48（`lea rbx,[rcx+rcx*2]; shl rbx,4`）+ 表基址；
//     ⑦ FindExportInFileByName(Buf, Size, 条目偏移) 必须返回 1；
//     ⑧ 转公共尾段。
//   分支 B（Is64Bit != 1）：
//     ① 构建号 = GtRead(0x914)；若 >= 0x1770 → 直接返回；
//     ② 导出表基址 = GtRead(0x2F1)；为空则返回；
//     ③ 表 = GtAlloc(0x1D3C)；
//     ④ ReadNtFileForSsdtTargets2(&Buf,&Size) 必须返回 1；
//     ⑤ 条目偏移 = 表基址 + 0x5D0（`add rbx,0x5D0`，固定值）；
//     ⑥ FindExportInFileByName(...) 必须返回 1；
//     ⑦ 转公共尾段。
//   公共尾段（0x14000E4B9）：
//     ParseNtExportDir(Buf, Size, 导出表基址, 0) 必须返回 1；
//     *条目 = 0；Rva = 条目[+4]；若 Rva 非零且 Rva+0x10 <= Size →
//       置 *条目 = 1，并把文件内 (Buf + Rva) 处的 16 字节拷到 条目+0x10；
//     ExFree(Buf)。
// 【注意】GtRead(0x914) 在反汇编中于 0x14000E3C3 / 3D5 / 41F（分支 A）与
//   0x14000E45A（分支 B）各出现一次，此处按原始顺序如实保留多次调用。
void ParseFsFilterDriverExport(char Is64Bit)
{
    __int64  ExportTableAddr;    // rsi(分支A)/rdi(分支B)：GtRead(0x2F1)
    __int64  AllocTable;         // r14(分支A)/rbx(分支B)：GtAlloc(...)
    __int64  EntryOffset;        // rbx：条目偏移
    ULONG64  FileBuffer = 0;     // [rbp+0x28]
    unsigned int FileSize = 0;   // [rbp+0x20]
    ULONG    BuildNumber;
    ULONG    Coeff;

    if (Is64Bit == 1)
    {
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);       // 0x14000E3C3（0x914）
        if (BuildNumber >= 0x1770 && BuildNumber < 0x23F0)       // 0x14000E3CF / 3DA
            return;

        ExportTableAddr = (__int64)GtRead(GtFsFilterExportTable);   // 0x14000E3EA（0x2F1）
        if (!ExportTableAddr)                                    // 0x14000E3F2
            return;

        AllocTable = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1BB0);  // 0x14000E400

        if ((unsigned int)ReadNtFileForSsdtTargets2(&FileBuffer, &FileSize) != 1)  // 0x14000E410
            return;

        // 系数：构建号 < 0x1770 取 0x1F，否则 0x0A（见上方 ⑥ 的等价展开说明）
        Coeff = ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1770) ? 0x1F : 0x0A;   // 0x14000E41F
        EntryOffset = (__int64)Coeff * 48 + AllocTable;           // 0x14000E431/439/43D

        if ((unsigned int)FindExportInFileByName((__int64)FileBuffer, FileSize, EntryOffset) != 1)  // 0x14000E443
            goto L_FREE;
    }
    else
    {
        if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)       // 0x14000E45A / 464
            return;

        ExportTableAddr = (__int64)GtRead(GtFsFilterExportTable);   // 0x14000E471（0x2F1）
        if (!ExportTableAddr)                                    // 0x14000E479
            return;

        AllocTable = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1D3C);  // 0x14000E483

        if ((unsigned int)ReadNtFileForSsdtTargets2(&FileBuffer, &FileSize) != 1)  // 0x14000E493
            return;

        EntryOffset = AllocTable + 0x5D0;                        // 0x14000E4A3

        if ((unsigned int)FindExportInFileByName((__int64)FileBuffer, FileSize, EntryOffset) != 1)  // 0x14000E4B2
            goto L_FREE;
    }

    /* ---- 公共尾段（0x14000E4B9）---- */
    if ((unsigned int)ParseNtExportDir((PUCHAR)FileBuffer, FileSize,
                                       (ULONG64)ExportTableAddr, 0) != 1)   // 0x14000E4C3
        goto L_FREE;

    *(ULONG *)EntryOffset = 0;                                   // 0x14000E4CC
    {
        ULONG Rva = *(ULONG *)(EntryOffset + 4);                 // 0x14000E4CF
        if (Rva && (Rva + 0x10) <= FileSize)                     // 0x14000E4D2 / 4D9
        {
            *(ULONG *)EntryOffset = 1;                           // 0x14000E4DE
            *(_OWORD *)(EntryOffset + 0x10) =
                *(const _OWORD *)(FileBuffer + Rva);             // 0x14000E4E8 / 4EC
        }
    }

L_FREE:
    ExFree((void *)FileBuffer);                                  // 0x14000E4F5
}
