// ParseNtFileForCallbackContext — 解析 NT 文件填充回调上下文表
// 对应原始驱动 0x14003E1F4（781 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（147 行伪代码），故按伪代码实现
//   （见待实现函数结构分析 §六：先试反编译，失败才走"出表+转写"）。
// 【参数】pFileBuffer / FileSize / pExportTable（0x30 字节/项）
// 【逻辑】与 ParseNtExportSectionsV3 **高度同构**（同一两段扫描、同样的类型码
//   1369/1296/1368/1298/1139/1294 与字段偏移），差异三处：
//   1) 镜像基址取自 GT 复合值 (GtFwpsDispatchTableCount|GtEprocessField184|GtEprocessField06)
//   2) 段 2 循环上限为 **0x3E8**（V3 为 0xC8）
//   3) 段 2 里 1298 型写**局部槽表 SlotAddresses**，由 1294 型消费（逻辑同 V3）
char ParseNtFileForCallbackContext(__int64 pFileBuffer, unsigned int FileSize, __int64 pExportTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 NtoskrnlBase;
    ULONG CurrentRva;
    char IsTargetSection = 0;
    int SectionIndex;
    PE_DECODE_CONTEXT SectionContext;
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD SlotAddresses[16];
    ULONG SectionRva, EntryRva, TargetRva;

    PeOffset = *(int *)(pFileBuffer + 60);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableCount |
                                                       GtEprocessField184 | GtEprocessField06));
    if (!NtoskrnlBase)
        return Result;

    CurrentRva = *(ULONG *)(PeOffset + pFileBuffer + 40);
    if (CurrentRva >= FileSize || (int)CurrentRva + 4096 >= FileSize)
        return Result;

    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        ULONG ComputedOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 1369)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
            if (SectionRva && SectionRva < FileSize) { CurrentRva = SectionRva; break; }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x70) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            IsTargetSection = 1;
        }
        else if (SectionType == 1368 && IsTargetSection == 1)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
            if (SectionRva && SectionRva < FileSize) { CurrentRva = SectionRva; break; }
            IsTargetSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14) break;
    }

    if (CurrentRva >= FileSize || (int)CurrentRva + 4096 >= FileSize)
        return Result;

    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    memset(SlotAddresses, 0, sizeof(SlotAddresses));
    for (ULONG I = 0; I < 0x3E8; I++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;
        ULONG ComputedOffset2 = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        if (SectionType2 == 1349) break;

        if (SectionType2 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            ULONG v = *(ULONG *)((char *)SectionEntry + 0x38);
            if (v && *(__int64 *)((char *)SectionEntry + 0x70) == 64)
            {
                EntryRva = ComputedOffset2 + v - (ULONG)pFileBuffer;
                if (EntryRva && EntryRva < FileSize)
                    SlotAddresses[*(ULONG *)((char *)SectionEntry + 0x58)] = EntryRva;
            }
        }
        if (SectionType2 == 1139) memset(SlotAddresses, 0, sizeof(SlotAddresses));

        if (SectionType2 == 1294)
        {
            ULONG SecFlags = *(ULONG *)((char *)SectionEntry + 0x50);
            ULONG MiscFlags = *(ULONG *)((char *)SectionEntry + 0xDC);
            ULONG FieldOffset = *(ULONG *)((char *)SectionEntry + 0x38);
            if ((SecFlags & 0x14000) && (SecFlags & 0x40) && (MiscFlags & 0xF) != 4 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
                (FieldOffset - 112) <= 0xD8 && (FieldOffset & 7) == 0)
            {
                ULONG SlotIndex = (FieldOffset - 112) >> 3;
                if (SlotIndex <= 0x1B)
                {
                    TargetRva = SlotAddresses[*(ULONG *)((char *)SectionEntry + 0x100)];
                    if (TargetRva && !*(_DWORD *)(pExportTable + 48 * SlotIndex + 4))
                    {
                        Result = 1;
                        *(_DWORD *)(pExportTable + 48 * SlotIndex + 4) = TargetRva;
                        *(_QWORD *)(pExportTable + 48 * SlotIndex + 8) = NtoskrnlBase + TargetRva;
                    }
                }
            }
        }
    }
    return Result;
}

// ParseNtSectionsForContextTable — 解析 NT 节区填充上下文表（批量填 28 项）
// 对应原始驱动 0x140046FEC（767 字节）
// 【逆向来源】同上（可反编译，163 行伪代码）
// 【逻辑】段 1 与同族一致（定位目标节）；段 2 与前两个**不同**：不做槽位填写，
//   而是按构建号二选一确认目标节区后，把同一个 RVA **批量填满 28 项**
//   （每项 0x30：+4 = RVA、+8 = RVA + 镜像基址）：
//     - 构建号 == 9200(20480, Win10 1809) → 要求"0x1298 型且 +0x88==0x40000 且
//       +0x38!=0 且 +0x70==64"的节区出现**第 2 次**
//     - 其他构建号 → 先记 0x1298 型（+0x58==0 时）的 RVA，再由"1327 型且 +0x50 带 0x10"确认
char ParseNtSectionsForContextTable(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 NtoskrnlBase;
    ULONG SectionDirRva;
    char IsTargetSection = 0;
    int SectionIndex;
    PE_DECODE_CONTEXT SectionContext;
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];
    ULONG SectionRva, ExportDirRva;
    int Win8SectionCount;

    PeOffset = *(int *)(ImageBase + 60);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)(GtNtReadVirtualMemoryFunc | GtEprocessField54));
    if (!NtoskrnlBase)
        return Result;

    SectionDirRva = *(ULONG *)(PeOffset + ImageBase + 40);
    if (SectionDirRva >= ImageSize || (int)SectionDirRva + 4096 >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        ULONG ComputedOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 1369)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (SectionRva && SectionRva < ImageSize) { SectionDirRva = SectionRva; break; }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x70) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            IsTargetSection = 1;
        }
        else if (SectionType == 1368 && IsTargetSection == 1)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (SectionRva && SectionRva < ImageSize) { SectionDirRva = SectionRva; break; }
            IsTargetSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14) break;
    }

    if (SectionDirRva >= ImageSize || (int)SectionDirRva + 4096 >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    ExportDirRva = 0;
    Win8SectionCount = 0;

    for (ULONG EntryIndex = 0; EntryIndex < 0xC8; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            return Result;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);

        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200)
        {
            if (*(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1298 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x38) != 0 &&
                *(__int64 *)((char *)SectionEntry + 0x70) == 64)
            {
                if (++Win8SectionCount == 2)
                {
                    ULONG Rva = (ULONG)AccumulatedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                    if (Rva >= ImageSize)
                        return Result;
                    for (ULONG k = 0; k < 28; k++)
                    {
                        *(_DWORD *)(pOutputTable + 48 * k + 4) = Rva;
                        *(_QWORD *)(pOutputTable + 48 * k + 8) = NtoskrnlBase + Rva;
                    }
                    return 1;
                }
            }
        }
        else
        {
            __int16 SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SectionType2 == 1298 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x38) != 0 &&
                *(__int64 *)((char *)SectionEntry + 0x70) == 64 &&
                *(_DWORD *)((char *)SectionEntry + 0x58) == 0)
            {
                ExportDirRva = (ULONG)AccumulatedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                if (ExportDirRva >= ImageSize)
                    ExportDirRva = 0;
            }
            else if (SectionType2 == 1327 &&
                     (*(ULONG64 *)((char *)SectionEntry + 0x50) & 0x10) &&
                     ExportDirRva)
            {
                for (ULONG k = 0; k < 28; k++)
                {
                    *(_DWORD *)(pOutputTable + 48 * k + 4) = ExportDirRva;
                    *(_QWORD *)(pOutputTable + 48 * k + 8) = NtoskrnlBase + ExportDirRva;
                }
                return 1;
            }
        }
    }
    return Result;
}