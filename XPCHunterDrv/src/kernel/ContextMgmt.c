// ContextMgmt.c — 上下文/回调管理函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"
#pragma warning(disable:4700)

// BuildCallbackContextHookTargets — 构建回调上下文 Hook 目标表（补全空壳）
// 对应原始驱动 0x140035EE0（231 字节）
// 【逆向来源】同上（可反编译，43 行伪代码）
// 【逻辑】GtAlloc(0x3FE6) + GtRead(GtNtoskrnlFileSize)；
//   ReadNtoskrnlForCallbackCtx 读 volmgr.sys/ftdisk.sys → ParseNtExportSectionsV3
//   → ParseNtExportDir(...,0)；遍历 28 项（+4 为 RVA），命中则置 +0=1 并拷 **16 字节**；
//   成功则 GtWrite(0x904, 1)，ExFree，FillExportEntrySlot。
void BuildCallbackContextHookTargets(void)
{
    char Result = 0;
    __int64 *pTargetTable;
    __int64 SectionBase;
    unsigned int *pRvaEntry;
    __int64 EntryCount;
    __int64 TargetRva;
    unsigned int FileSize = 0;
    char *pFileBuffer = NULL;

    pTargetTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3FE6);
    SectionBase = (__int64)GtRead(GtNtoskrnlFileSize);
    if (SectionBase && ReadNtoskrnlForCallbackCtx((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseNtExportSectionsV3((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1 &&
            ParseNtExportDir((__int64)pFileBuffer, FileSize, SectionBase, 0) == 1)
        {
            pRvaEntry = (unsigned int *)pTargetTable + 1;
            EntryCount = 28;
            do
            {
                TargetRva = *pRvaEntry;
                *(pRvaEntry - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= (int)FileSize)
                {
                    *(pRvaEntry - 1) = 1;
                    memcpy(pRvaEntry + 3, &pFileBuffer[TargetRva], 16);
                }
                pRvaEntry += 12;
                --EntryCount;
            } while (EntryCount);
            Result = 1;
            GtWrite((GLOBAL_TABLE_INDEX)0x904, 1);
        }
        ExFree(pFileBuffer);
        if (Result == 1)
            FillExportEntrySlot((__int64)pTargetTable);
    }
}

// BuildContextTableFromNtFile — 从 NT 文件构建上下文表（补全空壳）
// 对应原始驱动 0x1400473A0（211 字节）
// 【逆向来源】同上（可反编译，44 行伪代码）
// 【逻辑】GtRead(0x8E0) 取镜像基址；ReadNtFileForContextTable 读 partmgr.sys
//   → GtAlloc(0x3F32) → ParseNtSectionsForContextTable → ParseNtExportDir(...,0)；
//   遍历 28 项（+4 为 RVA），命中则置 +0=1 并拷 16 字节；
//   成功后 GtWrite(0x8E2, 1) 并 ExFree。
//   注：本函数**不调用** FillExportEntrySlot（与同族另两个不同）。
void BuildContextTableFromNtFile(void)
{
    __int64 NtoskrnlBase;
    __int64 *pExportTable;
    unsigned int *pIndexPtr;
    __int64 EntryCount;
    __int64 TargetRva;
    unsigned int FileSize = 0;
    char *pRawData = NULL;

    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8E0);
    if (NtoskrnlBase && ReadNtFileForContextTable((_QWORD *)&pRawData, &FileSize))
    {
        pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3F32);
        if (ParseNtSectionsForContextTable((__int64)pRawData, FileSize, (__int64)pExportTable) == 1 &&
            ParseNtExportDir((__int64)pRawData, FileSize, NtoskrnlBase, 0) == 1)
        {
            pIndexPtr = (unsigned int *)pExportTable + 1;
            EntryCount = 28;
            do
            {
                TargetRva = *pIndexPtr;
                *(pIndexPtr - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= (int)FileSize)
                {
                    *(pIndexPtr - 1) = 1;
                    memcpy(pIndexPtr + 3, &pRawData[TargetRva], 16);
                }
                pIndexPtr += 12;
                --EntryCount;
            } while (EntryCount);
            GtWrite((GLOBAL_TABLE_INDEX)0x8E2, 1);
        }
        ExFree(pRawData);
    }
}

// CopyCallbackContextHookTable — 复制回调上下文 Hook 表
// 对应原始驱动 sub_140035FC8
// 从 GT 16358 的表复制 28 条目标到目标表，每条 48 字节
__int64 CopyCallbackContextHookTable(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3FE6);
    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int Count = 28; Count; Count--)
    {
        *(unsigned int *)(pSrcEntry + DeltaOffset) = *(unsigned int *)pSrcEntry;
        if (*(unsigned int *)pSrcEntry && *((unsigned int *)pSrcEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pSrcEntry + DeltaOffset + 4) = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)(pSrcEntry + DeltaOffset + 22) = *(_OWORD *)(pSrcEntry + 12);
        }
        pSrcEntry += 48;
    }
    return Result;
}

// CopyCallbackContextTable — 复制回调上下文表
// 对应原始驱动 sub_140034DF4
__int64 CopyCallbackContextTable(__int64 pSourceTable, int ContextType)
{
    GLOBAL_TABLE_INDEX GtIndex;
    switch (ContextType)
    {
        case 0:  GtIndex = GtNtCreateThreadHookSuccess|GtObjectTypeField08; break;
        case 2:  GtIndex = GtEprocessModuleListOffset|GtEprocessField60|0x400; break;
        case 1:  GtIndex = GtFltPeSectionOfs6|GtEprocessField22|0x500; break;
        default: GtIndex = (GLOBAL_TABLE_INDEX)0; break;
    }
    __int64 *pDestTable = (ContextType >= 0 && ContextType <= 2) ? GtAlloc(GtIndex) : NULL;
    if (!pDestTable)
        return 0;
    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int EntryCount = 27; EntryCount; EntryCount--)
    {
        *(_DWORD *)&pSrcEntry[DeltaOffset] = *(_DWORD *)pSrcEntry;
        if (*(_DWORD *)pSrcEntry && *((_DWORD *)pSrcEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)&pSrcEntry[DeltaOffset + 28] = *(_OWORD *)(pSrcEntry + 12);
        }
        pSrcEntry += 48;
    }
    return Result;
}

// CopyCallbackContextV3Table — 复制回调上下文 V3 表
// 对应原始驱动 sub_14003E6AC
// 从 GT 15302 的表复制 28 条目标（源 48 字节，目标 64 字节）
__int64 CopyCallbackContextV3Table(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3BC6);
    char Result = 0;
    if (pDestTable)
    {
        char *pDestSlot = (char *)pDestTable + 4;
        __int64 pDestEntry = pSourceTable + 8;
        for (int Count = 28; Count; Count--)
        {
            *(unsigned int *)(pDestEntry - 4) = *(unsigned int *)pDestSlot;
            if (*(unsigned int *)pDestSlot && *((unsigned int *)pDestSlot - 1) == 1)
            {
                Result = 1;
                *(_QWORD *)pDestEntry = *(_QWORD *)(pDestSlot + 4);
                *(_OWORD *)(pDestEntry + 18) = *(_OWORD *)(pDestSlot + 12);
                *(_OWORD *)(pDestEntry + 34) = *(_OWORD *)(pDestSlot + 28);
            }
            pDestSlot += 48;
            pDestEntry += 64;
        }
    }
    return Result;
}

// CopyContextTableEntries — 复制上下文表条目
// 对应原始驱动 sub_140047474
// 从 GT 16178 的表复制 28 项条目到输出缓冲区，每项 48 字节
__int64 CopyContextTableEntries(__int64 pOutputTable)
{
    __int64 *pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtCallbackField81 | 0x3400));
    char *pSrcSlot = (char *)pExportTable + 4;
    __int64 DeltaOffset = pOutputTable - (__int64)pExportTable;
    char Result = 0;

    for (int EntryCount = 28; EntryCount; EntryCount--)
    {
        *(unsigned int *)(pSrcSlot + DeltaOffset) = *(unsigned int *)pSrcSlot;
        if (*(unsigned int *)pSrcSlot && *((unsigned int *)pSrcSlot - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pSrcSlot + DeltaOffset + 4) = *(_QWORD *)(pSrcSlot + 4);
            *(_OWORD *)(pSrcSlot + DeltaOffset + 22) = *(_OWORD *)(pSrcSlot + 12);
        }
        pSrcSlot += 48;
    }
    return Result;
}

// CopyHookEntryArray — 复制钩子条目数组
// 对应原始驱动 sub_1400860B4
// 将源钩子数组条目复制到目标缓冲区（每 40 字节一个条目）
__int64 CopyHookEntryArray(__int64 DestBuffer, _QWORD *pSourceArray, unsigned int EntryCount)
{
    for (unsigned int Index = 0; Index < EntryCount; Index++)
    {
        *(unsigned int *)(DestBuffer + 4 + 40LL * Index) = Index;
        *(_QWORD *)(DestBuffer + 16 + 40LL * Index) = pSourceArray[Index];
    }
    return 1;
}

// CopyKernelArrayToUserBuffer — 复制内核数组到用户缓冲区
// 对应原始驱动 sub_14006BC78
// 读取 GT 1973/1974，将内核数组（8 字节/项）复制到用户缓冲区
__int64 CopyKernelArrayToUserBuffer(__int64 UnusedParam1, __int64 UnusedParam2, unsigned int *pOutputBuffer, unsigned int BufferSize)
{
    char *pContextArray = (char *)GtRead(GtEprocessExtField58|GtEprocessField27|0x400);
    if (!pContextArray)
    {
        InitKernelMemoryContext();
        pContextArray = (char *)GtRead(GtEprocessExtField58|GtEprocessField27|0x400);
    }
    unsigned int EntryCount = (unsigned int)GtRead(GtEprocessExtField58|GtEprocessField28|0x400);

    if (pContextArray && EntryCount && pContextArray > (char *)MmSystemRangeStart && EntryCount < 0x100
        && CheckMemoryValid(pContextArray) == 1
        && CheckMemoryValid(&pContextArray[8 * EntryCount - 1]) == 1
        && pOutputBuffer
        && BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 8u);
        memset(pOutputBuffer, 0, BufferSize);
        *pOutputBuffer = EntryCount;
        memmove(pOutputBuffer + 2, pContextArray, 8LL * EntryCount);
        return 1;
    }
    return 0;
}

// CopyKernelDualArrayToUserBuffer — 复制内核双数组到用户缓冲区
// 对应原始驱动 sub_14006BDA4
// 将内核内存的双数组（两个并排数组，8 字节/项）复制到用户缓冲区
__int64 CopyKernelDualArrayToUserBuffer(__int64 UnusedParam1, __int64 UnusedParam2, unsigned int *pOutputBuffer, unsigned int BufferSize)
{
    char *pContextArray = (char *)GtRead(GtEprocessExtField48|GtEprocessField54|0x400);
    if (!pContextArray)
    {
        InitKernelMemoryContext();
        pContextArray = (char *)GtRead(GtEprocessExtField48|GtEprocessField54|0x400);
    }
    unsigned int EntryCount = (unsigned int)GtRead(GtEprocessExtField47|GtEprocessField54|0x400);
    if (!pContextArray || !EntryCount)
        return 0;
    if (pContextArray <= (char *)MmSystemRangeStart || EntryCount >= 0x100)
        return 0;
    if (CheckMemoryValid(pContextArray) != 1)
        return 0;
    __int64 MaxCount = 8LL * EntryCount;
    char *pSecondArray = &pContextArray[MaxCount];
    if (CheckMemoryValid(&pContextArray[MaxCount - 1]) != 1)
        return 0;
    if (!pOutputBuffer)
        return 0;
    unsigned int LastIndex = EntryCount - 1;
    if (BufferSize < 8 * (unsigned __int64)(EntryCount - 1) + 16)
        return 0;
    if ((unsigned __int64)pOutputBuffer >= MmUserProbeAddress || (unsigned __int64)pOutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(pOutputBuffer, BufferSize, 8u);
    memset(pOutputBuffer, 0, BufferSize);
    *pOutputBuffer = EntryCount;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        memmove(pOutputBuffer + 2, pContextArray, MaxCount);
    }
    else
    {
        memmove(pOutputBuffer + 2, pContextArray, 8LL * LastIndex);
        if (CheckMemoryValid(pSecondArray) == 1)
            *(_QWORD *)&pOutputBuffer[2 * LastIndex + 2] = *(_QWORD *)pSecondArray;
    }
    return 1;
}

// CopyObjectContextHookTable — 复制对象上下文 Hook 表
// 对应原始驱动 sub_140037B74
// 从 GT 15998 的表复制 29 条目标到目标表，每条 48 字节
__int64 CopyObjectContextHookTable(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3E7E);
    char *pDestEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int Count = 29; Count; Count--)
    {
        *(unsigned int *)(pDestEntry + DeltaOffset) = *(unsigned int *)pDestEntry;
        if (*(unsigned int *)pDestEntry && *((unsigned int *)pDestEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pDestEntry + DeltaOffset + 4) = *(_QWORD *)(pDestEntry + 4);
            *(_OWORD *)(pDestEntry + DeltaOffset + 22) = *(_OWORD *)(pDestEntry + 12);
        }
        pDestEntry += 48;
    }
    return Result;
}

// CopyPhysicalMemoryContextTable — 复制物理内存上下文表
// 对应原始驱动 sub_1400343A0
// 根据 ContextType 选择不同 GT 索引分配表，复制 28 条条目
__int64 CopyPhysicalMemoryContextTable(__int64 pSourceTable, int ContextType)
{
    __int64 *pDestTable;
    switch (ContextType)
    {
        case 0:
            pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)(GtObjectTypeField31 | GtPathBuffer00 | 0x800));
            break;
        case 2:
            pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs1 | GtCallbackField79));
            break;
        case 1:
            pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)3332);
            break;
        default:
            pDestTable = NULL;
            break;
    }
    if (!pDestTable)
        return 0;

    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    for (int Count = 28; Count; Count--)
    {
        *(unsigned int *)(pSrcEntry + DeltaOffset) = *(unsigned int *)pSrcEntry;
        if (*(unsigned int *)pSrcEntry)
        {
            *(_QWORD *)(pSrcEntry + DeltaOffset + 4) = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)(pSrcEntry + DeltaOffset + 28) = *(_OWORD *)(pSrcEntry + 12);
        }
        pSrcEntry += 48;
    }
    return 1;
}

// CopyProcessContextTable1 — 复制进程上下文表 1
// 对应原始驱动 sub_1400320B8
// 从 GT 15476 的表复制 28 条上下文字段到目标表
__int64 CopyProcessContextTable1(__int64 pTargetTable)
{
    __int64 *pSourceTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3C74);
    char *pSourceEntry = (char *)pSourceTable + 4;
    __int64 DeltaOffset = pTargetTable - (__int64)pSourceTable;
    char Result = 0;
    for (int Count = 28; Count; Count--)
    {
        *(unsigned int *)(pSourceEntry + DeltaOffset) = *(unsigned int *)pSourceEntry;
        if (*(unsigned int *)pSourceEntry && *((unsigned int *)pSourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pSourceEntry + DeltaOffset + 4) = *(_QWORD *)(pSourceEntry + 4);
            *(_OWORD *)(pSourceEntry + DeltaOffset + 22) = *(_OWORD *)(pSourceEntry + 12);
        }
        pSourceEntry += 48;
    }
    return Result;
}

// CopyProcessContextTable2 — 复制进程上下文表 2
// 对应原始驱动 sub_14003211C
__int64 CopyProcessContextTable2(__int64 pTargetTable)
{
    __int64 *pSourceTable = GtAlloc((GLOBAL_TABLE_INDEX)15650);
    char *pSourceEntry = (char *)pSourceTable + 4;
    __int64 DeltaOffset = pTargetTable - (__int64)pSourceTable;
    char Result = 0;
    for (int EntryCount = 27; EntryCount; EntryCount--)
    {
        *(_DWORD *)&pSourceEntry[DeltaOffset] = *(_DWORD *)pSourceEntry;
        if (*(_DWORD *)pSourceEntry && *((_DWORD *)pSourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSourceEntry[DeltaOffset + 4] = *(_QWORD *)(pSourceEntry + 4);
            *(_OWORD *)&pSourceEntry[DeltaOffset + 22] = *(_OWORD *)(pSourceEntry + 12);
        }
        pSourceEntry += 48;
    }
    return Result;
}

// CopyProcessContextTableWin7 — 复制进程上下文表（Win7 版）
// 对应原始驱动 sub_14003A0DC
// 从 GT 14954 的表复制 28 条目标到目标表
__int64 CopyProcessContextTableWin7(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3A6A);
    char *pDestEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int Count = 28; Count; Count--)
    {
        *(unsigned int *)(pDestEntry + DeltaOffset) = *(unsigned int *)pDestEntry;
        if (*(unsigned int *)pDestEntry && *((unsigned int *)pDestEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pDestEntry + DeltaOffset + 4) = *(_QWORD *)(pDestEntry + 4);
            *(_OWORD *)(pDestEntry + DeltaOffset + 22) = *(_OWORD *)(pDestEntry + 12);
        }
        pDestEntry += 48;
    }
    return Result;
}

// CopyProcessContextV2HookTable — 复制进程上下文 V2 Hook 表
// 对应原始驱动 sub_14003986C
// 从 GT 8228 的表复制 28 条目标到目标表
__int64 CopyProcessContextV2HookTable(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
    char *pDestEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int Count = 28; Count; Count--)
    {
        *(unsigned int *)(pDestEntry + DeltaOffset) = *(unsigned int *)pDestEntry;
        if (*(unsigned int *)pDestEntry && *((unsigned int *)pDestEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pDestEntry + DeltaOffset + 4) = *(_QWORD *)(pDestEntry + 4);
            *(_OWORD *)(pDestEntry + DeltaOffset + 22) = *(_OWORD *)(pDestEntry + 12);
        }
        pDestEntry += 48;
    }
    return Result;
}

// CopyProcessContextV3HookTable — 复制进程上下文 V3 Hook 表
// 对应原始驱动 sub_1400398D0
// 从 GT 8402 的表复制 27 条目标到目标表
__int64 CopyProcessContextV3HookTable(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)0x20D2);
    char *pDestEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int Count = 27; Count; Count--)
    {
        *(unsigned int *)(pDestEntry + DeltaOffset) = *(unsigned int *)pDestEntry;
        if (*(unsigned int *)pDestEntry && *((unsigned int *)pDestEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)(pDestEntry + DeltaOffset + 4) = *(_QWORD *)(pDestEntry + 4);
            *(_OWORD *)(pDestEntry + DeltaOffset + 22) = *(_OWORD *)(pDestEntry + 12);
        }
        pDestEntry += 48;
    }
    return Result;
}

// CopyUSBPortServiceTable — 复制 USB 端口服务表
// 对应原始驱动 sub_140055860
// 打开 usbport.sys 驱动节区，遍历 28 项服务表填充索引和函数地址
__int64 CopyUSBPortServiceTable(__int64 pOutputBuffer)
{
    __int64 ContextBase = OpenUSBPortSection();
    if (ContextBase)
    {
        _QWORD *pFuncEntry = (_QWORD *)(ContextBase + 112);
        for (unsigned int EntryIndex = 0; EntryIndex <= 0x1B; EntryIndex++)
        {
            *(_DWORD *)pOutputBuffer = EntryIndex;
            *(_QWORD *)(pOutputBuffer + 16) = *pFuncEntry;
            pOutputBuffer += 48;
            ++pFuncEntry;
        }
        return 1;
    }
    return 0;
}

// DecryptProcessContextStr — 解密进程上下文字符串
// 对应原始驱动 sub_140031F2C
__int64 DecryptProcessContextStr(void)
{
    _DWORD EncodedPath[6];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 4587585;
    EncodedPath[5] = 68;
    return OpenFileSection((__int64)EncodedPath);
}

// DuplicateUSBPortSyscallOutput — 复制 USB 端口系统调用输出
// 对应原始驱动 sub_1400559FC
__int64 DuplicateUSBPortSyscallOutput(__int64 pSourceTable)
{
    __int64 *pDestTable = GtAlloc((GLOBAL_TABLE_INDEX)15824);
    char *pDestSlot = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;
    char Result = 0;
    for (int EntryCount = 28; EntryCount; EntryCount--)
    {
        *(_DWORD *)&pDestSlot[DeltaOffset] = *(_DWORD *)pDestSlot;
        if (*(_DWORD *)pDestSlot && *((_DWORD *)pDestSlot - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pDestSlot[DeltaOffset + 4] = *(_QWORD *)(pDestSlot + 4);
            *(_OWORD *)&pDestSlot[DeltaOffset + 22] = *(_OWORD *)(pDestSlot + 12);
        }
        pDestSlot += 48;
    }
    return Result;
}

// EnumCallbackContextTable — 枚举回调上下文表
// 对应原始驱动 sub_140035E0C
__int64 EnumCallbackContextTable(__int64 pOutputTable)
{
    __int64 pContextBase = GetCallbackContextBase();
    if (pContextBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(pContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumCallbackContextV3Table — 枚举回调上下文 V3 表
// 对应原始驱动 sub_14003E504
__int64 EnumCallbackContextV3Table(__int64 pOutputTable)
{
    __int64 CallbackContextBase2 = GetCallbackContextBase2();
    if (CallbackContextBase2)
    {
        _QWORD *pFuncPtr = (_QWORD *)(CallbackContextBase2 + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 64;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumDeviceObjectTypeList — 枚举设备对象类型列表
// 对应原始驱动 sub_140033F3C
__int64 EnumDeviceObjectTypeList(int DeviceIndex, __int64 pOutputTable)
{
    enum _GLOBAL_TABLE_INDEX GtIndex;
    switch (DeviceIndex)
    {
        case 2:  GtIndex = GtSavedDeviceObject; break;
        case 0:  GtIndex = GtSavedDeviceObject2; break;
        case 1:  GtIndex = GtSavedDeviceObject3; break;
        default: GtIndex = (GLOBAL_TABLE_INDEX)0; break;
    }
    __int64 pFunctionBase;
    if (DeviceIndex >= 0 && DeviceIndex <= 2)
        pFunctionBase = GtRead(GtIndex);
    else
        pFunctionBase = 0;
    if (pFunctionBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(pFunctionBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumObjectContextTable — 枚举对象上下文表
// 对应原始驱动 sub_1400379BC
__int64 EnumObjectContextTable(__int64 pOutputBuffer)
{
    __int64 ContextBase = GetObjectContextBase();
    if (ContextBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(ContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputBuffer = EntryIndex++;
            *(_QWORD *)(pOutputBuffer + 16) = *pFuncPtr;
            pOutputBuffer += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumObjectTypeCleanupList — 枚举对象类型清理链表
// 对应原始驱动 sub_140042068
// 遍历两个链表（GT 700 和 GT 2090），查找目标对象并从链表中移除
__int64 EnumObjectTypeCleanupList(PVOID *pTargetObject)
{
    char Found = 0;
    for (int i = 0; i < 2; i++)
    {
        PVOID **pListHead;
        if (i)
        {
            if (GtRead(GtWindowsBuildNumber) < 0x23F0)
                pListHead = NULL;
            else
                pListHead = (PVOID **)GtRead((GLOBAL_TABLE_INDEX)((10 + 32) | 0x800));
        }
        else
        {
            pListHead = (PVOID **)GtRead((GLOBAL_TABLE_INDEX)700);
        }

        if (pListHead && MmIsAddressValid(pListHead) == 1)
        {
            PVOID *pCurrent = *pListHead;
            int IterCount = 0;
            while (pCurrent != (PVOID *)pListHead)
            {
                if (pCurrent <= (PVOID *)MmSystemRangeStart)
                    break;
                if (MmIsAddressValid(pCurrent) != 1)
                    break;
                if (++IterCount > 0x1000)
                    break;
                if (pCurrent == pTargetObject)
                {
                    if (MmIsAddressValid(*pCurrent) == 1)
                    {
                        PVOID *pPrev = (PVOID *)*pCurrent;
                        PVOID **pNext = (PVOID **)pCurrent[1];
                        Found = 1;
                        pPrev[1] = pNext;
                        *pNext = pPrev;
                    }
                    break;
                }
                pCurrent = (PVOID *)*pCurrent;
            }
        }
        if (Found)
            break;
    }
    return Found;
}

// EnumProcessContextSsdtTable — 枚举进程上下文 SSDT 表
// 对应原始驱动 sub_140031EE8
__int64 EnumProcessContextSsdtTable(__int64 pOutputTable)
{
    __int64 ContextBase = DecryptProcessContextStr();
    if (ContextBase)
    {
        _QWORD *pFuncEntry = (_QWORD *)(ContextBase + 112);
        unsigned int Index = 0;
        do
        {
            *(_DWORD *)pOutputTable = Index++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncEntry;
            pOutputTable += 48;
            ++pFuncEntry;
        }
        while (Index <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumProcessContextTable — 枚举进程上下文表
// 对应原始驱动 sub_140031E64
__int64 EnumProcessContextTable(__int64 pOutputTable)
{
    __int64 ContextBase = DecryptProcessContextStr();
    if (ContextBase)
    {
        unsigned __int64 FuncTableAddr = *(_QWORD *)(ContextBase + 80);
        if (FuncTableAddr && FuncTableAddr > (unsigned __int64)MmSystemRangeStart
            && MmIsAddressValid((PVOID)FuncTableAddr) == 1
            && MmIsAddressValid((PVOID)(FuncTableAddr + 223)) == 1)
        {
            _QWORD *pFuncEntry = (_QWORD *)(FuncTableAddr + 8);
            unsigned int Index = 0;
            do
            {
                *(_DWORD *)pOutputTable = Index++;
                *(_QWORD *)(pOutputTable + 16) = *pFuncEntry;
                pOutputTable += 48;
                ++pFuncEntry;
            }
            while (Index < 0x1B);
            return 1;
        }
    }
    return 0;
}

// EnumProcessContextV2Table — 枚举进程上下文 V2 表（Win8+）
// 对应原始驱动 sub_1400395E0
__int64 EnumProcessContextV2Table(__int64 pOutputTable)
{
    __int64 ContextBase = GetProcessContextBase();
    if (ContextBase)
    {
        unsigned __int64 pFunctionTable = *(_QWORD *)(ContextBase + 80);
        if (pFunctionTable && pFunctionTable > (unsigned __int64)MmSystemRangeStart
            && MmIsAddressValid((PVOID)pFunctionTable) == 1
            && MmIsAddressValid((PVOID)(pFunctionTable + 223)) == 1)
        {
            _QWORD *pFuncPtr = (_QWORD *)(pFunctionTable + 8);
            unsigned int EntryIndex = 0;
            do
            {
                *(_DWORD *)pOutputTable = EntryIndex++;
                *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
                pOutputTable += 48;
                ++pFuncPtr;
            }
            while (EntryIndex < 0x1B);
            return 1;
        }
    }
    return 0;
}

// EnumProcessContextV3Table — 枚举进程上下文 V3 表（Win10+）
// 对应原始驱动 sub_140039664
__int64 EnumProcessContextV3Table(__int64 pOutputTable)
{
    __int64 ContextBase = GetProcessContextBase();
    if (ContextBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(ContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumProcessContextV3TableWin7 — 枚举进程上下文 V3 表（Win7）
// 对应原始驱动 sub_140039F48
__int64 EnumProcessContextV3TableWin7(__int64 pOutputTable)
{
    __int64 ContextBase = OpenIpsecDriverSection();
    if (ContextBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(ContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumThreadContextTable — 枚举线程上下文表
// 对应原始驱动 sub_140057014
__int64 EnumThreadContextTable(__int64 OutputBuffer)
{
    __int64 ContextBase = OpenVolumeDriverSection();
    if (ContextBase)
    {
        _QWORD *pFuncEntry = (_QWORD *)(ContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)OutputBuffer = EntryIndex++;
            *(_QWORD *)(OutputBuffer + 16) = *pFuncEntry;
            OutputBuffer += 48;
            ++pFuncEntry;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumerateRegistryContextTable — 枚举注册表上下文表
// 对应原始驱动 sub_140045EA0
__int64 EnumerateRegistryContextTable(__int64 pOutputTable)
{
    __int64 pDriverSection = BuildRegistryDriverPath();
    if (pDriverSection)
    {
        _QWORD *pFuncPtr = (_QWORD *)(pDriverSection + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// EnumerateSyscallContextVector — 枚举系统调用上下文向量
// 对应原始驱动 sub_1400472EC
__int64 EnumerateSyscallContextVector(__int64 pOutputTable)
{
    __int64 SyscallContextBase = GetSyscallContextBase();
    if (SyscallContextBase)
    {
        _QWORD *pFuncPtr = (_QWORD *)(SyscallContextBase + 112);
        unsigned int EntryIndex = 0;
        do
        {
            *(_DWORD *)pOutputTable = EntryIndex++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
            pOutputTable += 48;
            ++pFuncPtr;
        }
        while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// GetCallbackContextBase — 获取回调上下文基址
// 对应原始驱动 sub_140035E50
// 通过编码后的名称字符串调用 OpenFileSection 打开文件节区
__int64 GetCallbackContextBase(void)
{
    _DWORD EncodedName[4];
    int SuffixEncoded1, SuffixEncoded2, SuffixEncoded3;
    int Terminator = 0;

    EncodedName[0] = 4456540;
    EncodedName[1] = 6881394;
    EncodedName[2] = 6619254;
    EncodedName[3] = 6029426;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        SuffixEncoded1 = 7274582;
        SuffixEncoded2 = 7143532;
        SuffixEncoded3 = 7471207;
    }
    else
    {
        SuffixEncoded1 = 7602246;
        SuffixEncoded2 = 6881380;
        SuffixEncoded3 = 7012467;
    }

    return OpenFileSection((__int64)EncodedName);
}

// GetCallbackContextBase2 — 获取回调上下文基址 V2
// 对应原始驱动 sub_14003E548
__int64 GetCallbackContextBase2(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4587612;
    EncodedPath[1] = 7077993;
    EncodedPath[2] = 5439589;
    EncodedPath[3] = 7536761;
    EncodedPath[4] = 6619252;
    EncodedPath[5] = 6029421;
    EncodedPath[6] = 7536717;
    EncodedPath[7] = 7536742;
    return OpenFileSection((__int64)EncodedPath);
}

// GetObjectContextBase — 获取对象上下文基址
// 对应原始驱动 sub_140037A18
__int64 GetObjectContextBase(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 3670121;
    EncodedPath[5] = 3407920;
    EncodedPath[6] = 7340082;
    EncodedPath[7] = 7602290;
    return OpenFileSection((__int64)EncodedPath);
}

// GetProcessContextBase — 获取进程上下文基址
// 对应原始驱动 sub_1400396A8
__int64 GetProcessContextBase(void)
{
    _DWORD EncodedName[12];
    EncodedName[11] = 0;
    EncodedName[0] = 4456540;
    EncodedName[1] = 6881394;
    EncodedName[2] = 6619254;
    EncodedName[3] = 6029426;
    EncodedName[4] = 7340105;
    EncodedName[5] = 6881350;
    EncodedName[6] = 7602284;
    EncodedName[7] = 7471205;
    EncodedName[8] = 7471172;
    EncodedName[9] = 7733353;
    EncodedName[10] = 7471205;
    return OpenFileSection((__int64)EncodedName);
}

// ReadNtoskrnlForCallbackContext — 读取 msfs.sys 供回调上下文解析
// 对应原始驱动 0x14003E80C（285 字节）
// 【逆向来源】本轮发现该函数**可被 Hex-Rays 反编译**（伪代码可用），
//   故按伪代码 + 路径字符串的精确解码还原（字符串由伪代码的
//   `EncodedPath[N] = <十进制>` 赋值序列按 DWORD 索引重建并验证）。
// 【路径】\SystemRoot\system32\drivers\msfs.sys
// 【逻辑】构造编码路径 → ReadFileRawData（**返回 0 表示成功**）→
//   ReadNtFileToBuffer 解析进缓冲区 → ExFree 原始数据；返回是否成功。
bool ReadNtoskrnlForCallbackContext(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    bool Result = false;
    void *pRawData = NULL;
    size_t RawDataSize = 0;
    WCHAR EncodedPath[40];

    wcscpy(EncodedPath, L"\SystemRoot\system32\drivers\msfs.sys");

    if (!(unsigned int)ReadFileRawData(EncodedPath, &pRawData, (ULONG *)&RawDataSize, 1))
    {
        Result = (ReadNtFileToBuffer((PUCHAR)pRawData, (ULONG)RawDataSize,
                                     (PUCHAR *)pFileBuffer, (PULONG)pFileSize) == 1);
        ExFree(pRawData);
    }
    return Result;
}

// ReadNtoskrnlForCallbackCtx — 读取 volmgr.sys / ftdisk.sys（按构建号二选一）
// 对应原始驱动 0x14003612C（344 字节）
// 【逆向来源】同上（反编译可得）
// 【路径】前缀 \SystemRoot\system32\drivers 固定，
//   构建号 >= 0x1770(6000, Vista) 时用 **volmgr.sys**，否则用 **ftdisk.sys**
//   （两者是同一"卷管理器"驱动的不同代际实现，故按构建号选择）
bool ReadNtoskrnlForCallbackCtx(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    bool Result = false;
    void *pRawData = NULL;
    size_t RawDataSize = 0;
    WCHAR EncodedPath[40];

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        wcscpy(EncodedPath, L"\SystemRoot\system32\drivers\volmgr.sys");
    else
        wcscpy(EncodedPath, L"\SystemRoot\system32\drivers\ftdisk.sys");

    if (!(unsigned int)ReadFileRawData(EncodedPath, &pRawData, (ULONG *)&RawDataSize, 1))
    {
        Result = (ReadNtFileToBuffer((PUCHAR)pRawData, (ULONG)RawDataSize,
                                     (PUCHAR *)pFileBuffer, (PULONG)pFileSize) == 1);
        ExFree(pRawData);
    }
    return Result;
}

// ReadNtFileForContextTable — 读取 partmgr.sys 供上下文表解析
// 对应原始驱动 0x1400475C8（293 字节）
// 【逆向来源】同上（反编译可得）
// 【路径】\SystemRoot\system32\drivers\partmgr.sys
// 【逻辑】与上面两个完全同构（构造路径 → ReadFileRawData → ReadNtFileToBuffer → ExFree）
bool ReadNtFileForContextTable(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    bool Result = false;
    void *pRawData = NULL;
    size_t FileSize = 0;
    WCHAR EncodedBuffer[40];

    wcscpy(EncodedBuffer, L"\SystemRoot\system32\drivers\partmgr.sys");

    if (!(unsigned int)ReadFileRawData(EncodedBuffer, &pRawData, (ULONG *)&FileSize, 1))
    {
        Result = (ReadNtFileToBuffer((PUCHAR)pRawData, (ULONG)FileSize,
                                     (PUCHAR *)pFileBuffer, (PULONG)pFileSize) == 1);
        ExFree(pRawData);
    }
    return Result;
}

// InitCallbackContextHookTable — 初始化回调上下文 Hook 表（补全空壳）
// 对应原始驱动 0x14003E5BC（239 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（50 行伪代码），按伪代码实现
// 【逻辑】GtAlloc(0x3BC6) 取表 + GtRead(0x8D3) 取镜像基址；
//   ReadNtoskrnlForCallbackContext 读 msfs.sys → ParseNtFileForCallbackContext 填表
//   → ParseNtExportDir(...,0) 修正重定位；
//   然后遍历 28 项（步长 0x30）：+4 为 RVA，置 +0 为命中标志；
//   若 RVA 非 0 且 RVA+32 <= 文件大小，则置 +0=1 并从文件缓冲拷贝 **32 字节**
//   （注意：本表每项拷贝 32 字节节头，比同族的 16 字节多）；
//   成功则 GtWrite(0x8D5, 1)，ExFree，最后 FillExportEntrySlot。
void InitCallbackContextHookTable(void)
{
    char IsReady = 0;
    __int64 *pExportTable;
    __int64 NtoskrnlBase;
    unsigned int *pSlot;
    __int64 EntryCount;
    __int64 RvaValue;
    char *pFileBuffer = NULL;
    unsigned int FileSize = 0;

    pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x3BC6);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8D3);
    if (!NtoskrnlBase || !ReadNtoskrnlForCallbackContext((_QWORD *)&pFileBuffer, &FileSize))
        return;

    if (ParseNtFileForCallbackContext((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1 &&
        ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
    {
        pSlot = (unsigned int *)pExportTable + 1;
        EntryCount = 28;
        do
        {
            RvaValue = *pSlot;
            *(pSlot - 1) = 0;
            if ((_DWORD)RvaValue && (int)RvaValue + 32 <= (int)FileSize)
            {
                *(pSlot - 1) = 1;
                memcpy(pSlot + 3, &pFileBuffer[RvaValue], 32);   // 32 字节节头（同族为 16）
            }
            pSlot += 12;                                          // 0x30/4
            --EntryCount;
        } while (EntryCount);
        IsReady = 1;
        GtWrite((GLOBAL_TABLE_INDEX)0x8D5, 1);
    }
    ExFree(pFileBuffer);
    if (IsReady == 1)
        FillExportEntrySlot((__int64)pExportTable);
}

// InitPhysicalMemoryContextTable — 初始化物理内存上下文表
// 对应原始驱动 sub_140034420
__int64 InitPhysicalMemoryContextTable(int DeviceIndex, __int64 pOutputTable)
{
    GLOBAL_TABLE_INDEX GtIndex;
    if (DeviceIndex == 2)
        GtIndex = GtSavedDeviceObject;
    else if (DeviceIndex == 0)
        GtIndex = GtSavedDeviceObject2;
    else if (DeviceIndex == 1)
        GtIndex = GtSavedDeviceObject3;
    else
        GtIndex = (GLOBAL_TABLE_INDEX)0;

    __int64 pFunctionBase;
    if (DeviceIndex >= 0 && DeviceIndex <= 2)
        pFunctionBase = GtRead(GtIndex);
    else
        pFunctionBase = 0;

    if (pFunctionBase)
    {
        __int64 pContextBase = *(_QWORD *)(pFunctionBase + 80);
        if (pContextBase && MmIsAddressValid(*(PVOID *)(pFunctionBase + 80)) == 1
            && MmIsAddressValid((PVOID)(pContextBase + 223)) == 1)
        {
            _QWORD *pFuncPtr = (_QWORD *)(pContextBase + 8);
            unsigned int EntryIndex = 0;
            do
            {
                *(_DWORD *)pOutputTable = EntryIndex++;
                *(_QWORD *)(pOutputTable + 16) = *pFuncPtr;
                pOutputTable += 48;
                ++pFuncPtr;
            }
            while (EntryIndex < 0x1B);
            return 1;
        }
    }
    return 0;
}

// InitProcessContextExportTableWin7
void InitProcessContextExportTableWin7(void)
{
    return;
}

// ParseNtExportSectionsForProcessContext — 解析 ntoskrnl 节区并按节序号批填两张表
// 对应原始驱动 0x140039214（972 字节，253 行反汇编）
// 【逆向来源】人工阅读反汇编**按原始地址逐标签机械转写**（goto + L<地址>），
//   依据 build/audit/_pnepc_listing.txt。IDA 无法分析该函数（Hex-Rays 失败）。
// 【参数】rcx = ntoskrnl PE 文件缓冲、edx = 文件大小（**无第三参**）
// 【输出表】本函数自己 GtAlloc 两处：GT 0x2024（r15，0x30 字节/项）
//   与 GT 0x20D2（var_1F0，0x30 字节/项）
// 【结构】
//   段 1（上限 0x14）：用节头 +0x28 定位首个目标节；类型 0x559 记录偏移；
//     类型 0x510(且 +0x38==0x40 且 +0x58==1) 置 FlagDil；0x558 在 FlagDil 置位后记录偏移。
//   段 2（上限 0x1F4）：先 memset Dst[0x40]；类型 0x512(且 +0x88==0x40000 且
//     +0x38!=0 且 +0x50==0x40 且 +0x58 < 0x10) → Dst[+0x58] = 偏移；
//     类型 0x50E 分两条路径：
//       a) +0xB8 的 0x300 位 == 0x100、+0x38 == 0x70、+0xDC 的 0x300 位 == 0x300、
//          +0x88 == 0x40、Dst 序号 < 0x10 → 对 Dst[序号] 连续写
//          (+0x88 - 0x24) 个 0x30 字节条目（每项 +0 = 偏移、+4 = 偏移 + 节 VA 基址）
//       b) +0x50 带 0x14000/0x40、+0xDC 低 4 位 != 4、+0x88 == 0x40、+0x38 == 0x50、
//          Dst[+0x100] 有效、偏移 + 0xE0 <= 文件大小 → 写 (+0x88 - 0x25) 个 0x30 字节条目
//          （从 缓冲 + 偏移 + 8 读 QWORD，减去节 VA 后若有效则写 +0 = 差值、+4 = 差值 + 基址）
ULONG64 ParseNtExportSectionsForProcessContext(__int64 FileBuffer, unsigned int FileSize)
{
    ULONG64 Base = (ULONG64)FileBuffer;   // r12
    ULONG   Size = FileSize;              // esi
    ULONG64 VaBase;                       // r13 <- GT 0x8C4
    ULONG64 Tab1;                         // r15 / var_1F8 <- GtAlloc(0x2024)
    ULONG64 Tab2;                         // var_1F0 <- GtAlloc(0x20D2)
    UCHAR   Result = 0;                   // dil
    UCHAR   FlagDil = 0;                  // r14b
    ULONG   SecOff;                       // ebx
    ULONG   Count;                        // r15d / ebx
    ULONG64 PeHdrOff;
    ULONG   SecType;
    ULONG64 SecFlags, SecFlags88;
    ULONG   v;
    ULONG   i, n;
    ULONG64 p, q;
    ULONG64 SectionVa;                    // r14 / var_200
    PE_DECODE_CONTEXT Ctx;                // var_1E0
    _DWORD  SectionInfo[112];             // var_190
    UCHAR   Dst[0x40];

    VaBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
    Tab1 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
    Tab2 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x20D2);
    if (!VaBase) goto L1400394C3;

    PeHdrOff = (ULONG64)(LONG)*(LONG *)(Base + 0x3C);
    SecOff = *(ULONG *)(PeHdrOff + Base + 0x28);
    SectionVa = *(ULONG64 *)(PeHdrOff + Base + 0x30);
    if (SecOff >= Size) goto L14003934F;
    if (SecOff + 0x1000 >= Size) goto L14003934F;

    InitPESectionReadContext((__int64)(Base + SecOff), 0x1000, 2, 0, -1, 0, 0, (__int64)&Ctx);
    Count = 0; FlagDil = 0;
    goto L1400392EF;

L1400392EF:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L140039345;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    SecType = *(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6);
    if (SecType != 0x559) goto L1400394F6;
    v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
    if (v == 0) goto L140039537;
    if (v >= Size) goto L140039537;
    SecOff = v;

L140039345:
    Tab1 = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
L14003934F:
    if (SecOff == 0) goto L1400394C3;
    if (SecOff >= Size) goto L1400394C3;
    if (SecOff + 0x1000 >= Size) goto L1400394C3;
    InitPESectionReadContext((__int64)(Base + SecOff), 0x1000, 2, 0, -1, 0, 0, (__int64)&Ctx);
    memset(Dst, 0, 0x40);
    Count = 0;

L1400393B8:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L1400394C3;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    SecType = *(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6);
    SecFlags88 = *(__int64 *)((char *)SectionInfo + 0x88);
    SecFlags = *(__int64 *)((char *)SectionInfo + 0x50);

    if (SecType == 0x512 && SecFlags88 == 0x40000 &&
        *(ULONG *)((char *)SectionInfo + 0x38) != 0 && SecFlags == 0x40)
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x58);
        v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
        if (v != 0 && v < Size && idx < 0x10) Dst[idx] = (UCHAR)v;
    }

    if (SecType != 0x50E) goto L1400395CD;

    // ---- 路径 a ----
    if (((*(ULONG *)((char *)SectionInfo + 0xB8) & 0x300) == 0x100) &&
        (*(ULONG *)((char *)SectionInfo + 0x38) == 0x70) &&
        ((*(ULONG *)((char *)SectionInfo + 0xDC) & 0x300) == 0x300) &&
        (SecFlags88 == 0x40))
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x100);
        if (idx < 0x10)
        {
            v = Dst[idx];
            if (v != 0 && v < Size)
            {
                p = Tab1 + 4;
                q = (ULONG64)v + VaBase;
                n = (ULONG)(SecFlags88 - 0x24);
                for (i = 0; i < n; i++, p += 0x30)
                {
                    *(ULONG *)(p - 4) = v;
                    *(ULONG64 *)p = q;
                }
                Result = 1;
            }
        }
        goto L1400395CD;
    }
    goto L140039549;

L140039549:
    // ---- 路径 b ----
    if ((*(ULONG64 *)((char *)SectionInfo + 0x50) & 0x14000) &&
        (*(ULONG64 *)((char *)SectionInfo + 0x50) & 0x40) &&
        ((*(ULONG *)((char *)SectionInfo + 0xDC) & 0xF) != 4) &&
        (SecFlags88 == 0x40) &&
        (*(ULONG64 *)((char *)SectionInfo + 0x38) == 0x50))
    {
        ULONG idx = *(ULONG *)((char *)SectionInfo + 0x100);
        v = Dst[idx];
        if (v != 0 && v < Size && (ULONG64)v + 0xE0 <= Size)
        {
            p = Tab2 + 8;
            q = (ULONG64)v + 8 + Base;
            n = (ULONG)(SecFlags88 - 0x25);
            for (i = 0; i < n; i++, p += 0x30, q += 8)
            {
                ULONG64 w = *(ULONG64 *)q;
                if ((w > SectionVa) && (Size > (ULONG)(w - (ULONG)SectionVa)))
                {
                    *(ULONG *)(p - 4) = (ULONG)(w - (ULONG)SectionVa);
                    *(ULONG64 *)p = (w - SectionVa) + VaBase;
                }
            }
            Result = 1;
        }
    }

L1400395CD:
    Count++;
    if (Count >= 0x1F4) goto L1400394C3;
    goto L1400393B8;

L1400394F6:
    if (SecType == 0x510 && *(__int64 *)((char *)SectionInfo + 0x38) == 0x40 &&
        *(__int64 *)((char *)SectionInfo + 0x58) == 1)
    {
        FlagDil = 1;
        goto L140039537;
    }
    if (SecType == 0x558 && FlagDil == 1)
    {
        v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)Base + (ULONG)Ctx.ReadPtr;
        if (v != 0 && v < Size) { SecOff = v; goto L140039343; }
    }
    FlagDil = 0;
L140039537:
    Count++;
    if (Count >= 0x14) goto L140039345;
    goto L1400392EF;

L140039343:
    goto L140039345;

L1400394C3:
    (void)Tab2; (void)PeHdrOff;
    return (ULONG64)Result;
}

// InitProcessContextHookTable — 初始化进程上下文 Hook 表（补全空壳）
// 对应原始驱动 0x140039728（322 字节）
// 【逆向来源】人工阅读反汇编逐条还原
// 【⚠ 修正记录】此前本函数是空壳（`return;`），而它在 Operation.c:291 被真实调用。
// 【逻辑】GtRead(GT 0x8C4) 取 ntoskrnl 缓冲；为空则先调 InitThreadNotify 再重取，
//   仍为空则退出。ReadNtoskrnlToBuffer(&buf, &size) 读 PE 文件；
//   依次 ParseNtExportSectionsForProcessContext / ParseNtExportDir(...,0)；
//   然后遍历 GtAlloc(GT 0x2024) 的 0x1C 项与 GtAlloc(GT 0x20D2) 的 0x1B 项
//   （步长 0x30；条目 +0 = 命中标志、+4 = 节偏移、+0x0C 起 16 字节为节头副本）：
//   若偏移非 0 且 偏移+0x10 <= 文件大小，则 GtWrite(GT 0x8C6/0x8C7, 1)、
//   把标志置 1，并从 PE 缓冲该偏移处拷 16 字节到条目 +0x0C。最后 ExFree 缓冲区。
void InitProcessContextHookTable(void)
{
    ULONG64 Ctx8C4;                       // rbx
    unsigned int FileSize = 0;            // [rsp+arg_0]
    ULONG64 FileBuf = 0;                  // [rsp+arg_8]
    ULONG64 Tab;
    ULONG64 p;
    ULONG   i;

    Ctx8C4 = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
    if (!Ctx8C4)
    {
        InitThreadNotify();
        Ctx8C4 = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8C4);
        if (!Ctx8C4)
            return;
    }

    if (!ReadNtoskrnlToBuffer((void **)&FileBuf, &FileSize))
        return;

    ParseNtExportSectionsForProcessContext((__int64)FileBuf, FileSize);
    ParseNtExportDir((__int64)FileBuf, FileSize, Ctx8C4, 0);

    Tab = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x2024);
    for (i = 0, p = Tab; i < 0x1C; i++, p += 0x30)
    {
        ULONG off = *(ULONG *)(p + 4);
        *(ULONG *)p = 0;
        if (off != 0 && off + 0x10 <= FileSize)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x8C6, 1);
            *(ULONG *)p = 1;
            memcpy((void *)(p + 0x0C), (void *)(FileBuf + off), 0x10);
        }
    }

    Tab = (ULONG64)GtAlloc((GLOBAL_TABLE_INDEX)0x20D2);
    for (i = 0, p = Tab; i < 0x1B; i++, p += 0x30)
    {
        ULONG off = *(ULONG *)(p + 4);
        *(ULONG *)p = 0;
        if (off != 0 && off + 0x10 <= FileSize)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x8C7, 1);
            *(ULONG *)p = 1;
            memcpy((void *)(p + 0x0C), (void *)(FileBuf + off), 0x10);
        }
    }

    ExFree((PVOID)FileBuf);
}

// InitThreadContextTable
void InitThreadContextTable(void)
{
    return;
}

// InitUSBPortSyscallTable
void InitUSBPortSyscallTable(void)
{
    return;
}

// InitWin32kTableByVersion — 按构建号初始化 Win32k 表（补全空壳）
// 对应原始驱动 0x14008850C（76 字节）
// 【逆向来源】反汇编逐条还原
// 【逻辑】构建号 >= 0x2800(10240, Win10 1507) 走新路径：
//   读 win32k 完整驱动文件（ReadWin32kFullDriverFile）→ 解析导出（ResolveWin32kExportAddresses）
//   → ExFree；否则走旧路径：直接用 ResolveWin32kSyscallAddresses（读 ntoskrnl 服务表）。
void InitWin32kTableByVersion(void)
{
    unsigned int FileSize = 0;
    __int64 FileBuf = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        if (!ReadWin32kFullDriverFile(&FileBuf, &FileSize))
            return;
        ResolveWin32kExportAddresses(FileBuf, FileSize);
        ExFree((PVOID)FileBuf);
    }
    else
    {
        ResolveWin32kSyscallAddresses();
    }
}

// ResolveWin32kSyscallAddresses — 由 ntoskrnl 服务表解析 Win32k 调用地址
// 对应原始驱动 0x140088558（175 字节）
// 【逆向来源】反汇编逐条还原
// 【逻辑】GtRead(GT 0x1FA) 取服务表指针；为空则先调 ReadNtOsKrnlAndParseServiceTable
//   再重取。再取 GT 0x50（服务表基址）与 GT 0x303（标志）——若标志已置位或任一为空则返回。
//   然后取 GT 0x1E2 与 GT 0x1E7 作索引，从服务表 [索引] 读出两个 RVA，分别加基址后
//   写入 GT 0x1F2 与 GT 0x1F7（即两个 Win32k 目标函数的解析地址）。
void ResolveWin32kSyscallAddresses(void)
{
    __int64 ServiceTable = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1FA);
    __int64 Base, Index1, Index2;

    if (!ServiceTable)
    {
        ReadNtOsKrnlAndParseServiceTable();
        ServiceTable = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1FA);
    }
    Base = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x50);
    if (!ServiceTable || !Base)
        return;
    if ((unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x303) != 0)
        return;

    Index1 = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1E2);
    Index2 = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1E7);
    {
        ULONG Rva1 = *(ULONG *)(ServiceTable + (unsigned int)Index1 * 4);
        ULONG Rva2 = *(ULONG *)(ServiceTable + (unsigned int)Index2 * 4);
        GtWrite((GLOBAL_TABLE_INDEX)0x1F2, (__int64)(Rva1 + Base));
        GtWrite((GLOBAL_TABLE_INDEX)0x1F7, (__int64)(Rva2 + Base));
    }
}

// ResolveWin32kExportAddresses — 由 win32k 导出表解析两个目标函数地址
// 对应原始驱动 0x140088608（277 字节）
// 【逆向来源】反汇编逐条还原（含两个字符串常量的字节还原）
// 【参数】rcx = 文件缓冲、edx = 文件大小
// 【逻辑】GtRead(GT 0x8F6) 取镜像基址（为空返回）；若 GT 0x8FB 已置位则直接返回。
//   依次按名查找两个导出并写回 GT 槽：
//     "NtUserBuildHwndList" → GT 0x1F2
//     "NtUserQueryWindow"   → GT 0x1F7
//   仅在查找成功、结果非 0 且 < 文件大小时写入（偏移 + 镜像基址）。
void ResolveWin32kExportAddresses(__int64 FileBuffer, unsigned int FileSize)
{
    __int64 ImageBase;
    ULONG Out1 = 0, Out2 = 0;
    WCHAR Name1[24];
    WCHAR Name2[24];

    ImageBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8F6);
    if (!ImageBase)
        return;
    if ((unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x8FB) != 0)
        return;

    memcpy(Name1, L"NtUserBuildHwndList", 40);
    if (LookupExportByName((PUCHAR)FileBuffer, FileSize, (PCHAR)Name1, &Out1))
    {
        if (Out1 != 0 && Out1 < FileSize)
            GtWrite((GLOBAL_TABLE_INDEX)0x1F2, (__int64)(Out1 + ImageBase));
    }

    memcpy(Name2, L"NtUserQueryWindow", 34);
    if (LookupExportByName((PUCHAR)FileBuffer, FileSize, (PCHAR)Name2, &Out2))
    {
        if (Out2 != 0 && Out2 < FileSize)
            GtWrite((GLOBAL_TABLE_INDEX)0x1F7, (__int64)(Out2 + ImageBase));
    }
}

// InstallCallbackContextHookEntry — 安装回调上下文 Hook 条目
// 对应原始驱动 sub_140036284
__int64 InstallCallbackContextHookEntry(unsigned int *pInputEntry)
{
    __int64 pContextBase = GetCallbackContextBase();
    if (pContextBase)
    {
        unsigned int EntryIndex = *pInputEntry;
        if (EntryIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(pContextBase + 8 * EntryIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// OpenUSBPortSection — 打开 USB 端口驱动节区
// 对应原始驱动 sub_1400558A4
__int64 OpenUSBPortSection(void)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7536757;
    EncodedPath[5] = 6619234;
    EncodedPath[6] = 6488168;
    EncodedPath[7] = 105;
    return OpenFileSection((__int64)EncodedPath);
}

// OpenIpsecDriverSection — 打开 ipsec 驱动节区
// 对应原始驱动 sub_140039F8C
__int64 OpenIpsecDriverSection(void)
{
    _DWORD EncodedName[8];
    EncodedName[0] = 4456540;
    EncodedName[1] = 6881394;
    EncodedName[2] = 6619254;
    EncodedName[3] = 6029426;
    EncodedName[4] = 7340105;
    EncodedName[5] = 6619251;
    EncodedName[6] = 99;
    return OpenFileSection((__int64)EncodedName);
}

// OpenVolumeDriverSection — 打开卷驱动节区
// 对应原始驱动 sub_140057058
__int64 OpenVolumeDriverSection(void)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7274582;
    EncodedPath[5] = 7536748;
    EncodedPath[6] = 6357102;
    EncodedPath[7] = 112;
    return OpenFileSection((__int64)EncodedPath);
}

// SetCallbackContextEntry — 设置回调上下文条目
// 对应原始驱动 sub_14003E92C
__int64 SetCallbackContextEntry(ULONG *pInputEntry)
{
    __int64 CallbackContextBase2 = GetCallbackContextBase2();
    if (CallbackContextBase2)
    {
        unsigned int SlotIndex = *pInputEntry;
        if (SlotIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(CallbackContextBase2 + 8 * SlotIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// SetObjectContextEntry — 设置对象上下文条目
// 对应原始驱动 sub_140037E04
__int64 SetObjectContextEntry(ULONG *pInputEntry)
{
    __int64 ContextBase = GetObjectContextBase();
    if (ContextBase)
    {
        unsigned int EntryIndex = *pInputEntry;
        if (EntryIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(ContextBase + 8 * EntryIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
        if (EntryIndex == 28)
        {
            WritePhysicalMemoryQword(ContextBase + 96, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// SetProcessContextEntry — 设置进程上下文条目
// 对应原始驱动 sub_140039BB8
__int64 SetProcessContextEntry(__int64 pInputEntry)
{
    __int64 ContextBase = DecryptProcessContextStr();
    if (!ContextBase)
        return 0;
    __int64 FuncTableAddr;
    if (*(_BYTE *)pInputEntry)
    {
        FuncTableAddr = *(_QWORD *)(ContextBase + 80);
        if (!FuncTableAddr)
            return 0;
        if (MmIsAddressValid(*(PVOID *)(ContextBase + 80)) != 1
            || MmIsAddressValid((PVOID)(FuncTableAddr + 223)) != 1)
            return 0;
        unsigned int EntryIndex = *(unsigned int *)(pInputEntry + 8);
        if (EntryIndex < 0x1B)
        {
            WritePhysicalMemoryQword(FuncTableAddr + 8 * (EntryIndex + 1), *(_QWORD *)(pInputEntry + 16));
            return 1;
        }
    }
    else
    {
        __int64 ValueToWrite = *(_QWORD *)(pInputEntry + 16);
        if (ValueToWrite)
        {
            unsigned int Index = *(unsigned int *)(pInputEntry + 8);
            if (Index <= 0x1B)
            {
                WritePhysicalMemoryQword(ContextBase + 8 * (Index + 14), ValueToWrite);
                return 1;
            }
        }
    }
    return 0;
}

// SetRegistryContextEntry — 设置注册表上下文条目
// 对应原始驱动 sub_1400462C8
__int64 SetRegistryContextEntry(ULONG *pInputEntry)
{
    __int64 pDriverSection = BuildRegistryDriverPath();
    if (pDriverSection)
    {
        unsigned int SlotIndex = *pInputEntry;
        if (SlotIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(pDriverSection + 8 * SlotIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// SetSyscallContextByIndex — 按索引设置系统调用上下文
// 对应原始驱动 sub_1400476F0
__int64 SetSyscallContextByIndex(ULONG *pInputEntry)
{
    __int64 SyscallContextBase = GetSyscallContextBase();
    if (SyscallContextBase)
    {
        unsigned int SlotIndex = *pInputEntry;
        if (SlotIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(SyscallContextBase + 8 * SlotIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// SetUSBPortServiceTableEntry — 设置 USB 端口服务表条目
// 对应原始驱动 sub_140055C78
__int64 SetUSBPortServiceTableEntry(ULONG *pInputEntry)
{
    __int64 ContextBase = OpenUSBPortSection();
    if (ContextBase)
    {
        unsigned int SlotIndex = *pInputEntry;
        if (SlotIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(ContextBase + 8 * SlotIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// ValidateCallbackContextTable — 验证回调上下文表
// 对应原始驱动 sub_14003E0BC
__int64 ValidateCallbackContextTable(__int64 pContextTable)
{
    _BYTE *pEntry = (_BYTE *)(pContextTable + 8);
    for (int EntryCount = 28; EntryCount; EntryCount--)
    {
        if (*(_QWORD *)pEntry && *(_QWORD *)pEntry != *(_QWORD *)(pEntry + 8))
            *(pEntry + 16) = 1;
        pEntry += 64;
    }
    for (unsigned int EntryIndex = 0; EntryIndex <= 0x1B; EntryIndex++)
    {
        _BYTE *pCurEntry = (_BYTE *)(pContextTable + 8 + 64LL * EntryIndex);
        if (!*(_QWORD *)pCurEntry)
            continue;
        if (MmIsAddressValid((PVOID)(*(_QWORD *)pCurEntry + 15LL)) != 1)
            continue;
        unsigned __int64 EntryOffset = (unsigned __int64)EntryIndex << 6;
        if ((unsigned int)MemoryCompare(*(_QWORD *)pCurEntry, (char *)(EntryOffset + pContextTable + 26), 0x10u))
        {
            pCurEntry[17] = 1;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563
                && MmIsAddressValid((PVOID)(*(_QWORD *)pCurEntry + 31LL)) == 1
                && ScanPESectionPatterns((_BYTE *)(EntryOffset + pContextTable + 26), *(char **)pCurEntry, 32, 1))
            {
                pCurEntry[17] = 0;
            }
            if (pCurEntry[17] == 1 && !pCurEntry[16])
            {
                unsigned int i;
                for (i = 0; i < 0x10; i++)
                {
                    if (!MmIsAddressValid((PVOID)(*(_QWORD *)pCurEntry + i)))
                        break;
                }
                if (i && ReturnFalseStub() == 1)
                    *((_QWORD *)pCurEntry + 1) = *(unsigned int *)(64LL * EntryIndex + pContextTable + 8);
            }
        }
    }
    return 1;
}

// ValidateFsFilterEntries — 验证文件系统过滤器条目
// 对应原始驱动 sub_14000DADC
__int64 ValidateFsFilterEntries(__int64 FilterContext)
{
    // Phase 1: Mark modified entries
    for (int EntryCount = 64; EntryCount; EntryCount--)
    {
        __int64 CurrentEntry = FilterContext + 16 + 56LL * (64 - EntryCount);
        if (*(_QWORD *)CurrentEntry && *(_QWORD *)CurrentEntry != *(_QWORD *)(CurrentEntry + 8))
            *(_BYTE *)(CurrentEntry + 16) = 1;
    }
    // Phase 2: Verify bytes at each entry
    for (unsigned int EntryIndex = 0; EntryIndex < 0x40; EntryIndex++)
    {
        __int64 EntryPtr = FilterContext + 16 + 56LL * EntryIndex;
        if (*(_QWORD *)EntryPtr)
        {
            if (MmIsAddressValid((PVOID)(*(_QWORD *)EntryPtr + 15LL)) == 1)
            {
                if ((unsigned int)MemoryCompare(*(_QWORD *)EntryPtr, (char *)(56LL * EntryIndex + FilterContext + 34), 0x10u))
                {
                    char IsEntryEmpty = *(_BYTE *)(EntryPtr + 16) == 0;
                    *(_BYTE *)(EntryPtr + 17) = 1;
                    if (IsEntryEmpty)
                    {
                        unsigned int ByteIndex;
                        for (ByteIndex = 0; ByteIndex < 0x10; ByteIndex++)
                        {
                            if (!MmIsAddressValid((PVOID)(*(_QWORD *)EntryPtr + ByteIndex)))
                                break;
                        }
                        if (ByteIndex && ReturnFalseStub() == 1)
                            *(_QWORD *)(EntryPtr + 8) = *(unsigned int *)(56LL * EntryIndex + FilterContext + 8);
                    }
                }
            }
        }
    }
    return 1;
}

// ValidateSingleHookEntry — 验证单个钩子条目
// 对应原始驱动 sub_140085ADC
__int64 ValidateSingleHookEntry(__int64 pEntry)
{
    __int64 pTargetFunc = *(_QWORD *)(pEntry + 8);
    if (pTargetFunc)
    {
        if (pTargetFunc != *(_QWORD *)(pEntry + 16))
            *(_BYTE *)pEntry = 1;
        if (CheckMemoryValid((void *)(pTargetFunc + 15)) == 1)
        {
            if ((unsigned int)MemoryCompare(*(_QWORD *)(pEntry + 8), (char *)(pEntry + 24), 0x10u))
            {
                char IsOriginal = *(_BYTE *)pEntry == 0;
                *(_BYTE *)(pEntry + 1) = 1;
                if (IsOriginal)
                {
                    unsigned int i;
                    for (i = 0; i < 0x10; i++)
                    {
                        if (!CheckMemoryValid((void *)(*(_QWORD *)(pEntry + 8) + i)))
                            break;
                    }
                    if (i && ReturnFalseStub() == 1)
                        *(_QWORD *)(pEntry + 16) = *(unsigned int *)(pEntry + 12);
                }
            }
        }
    }
    return 1;
}

// WriteProcessContextEntry — 写入进程上下文条目
// 对应原始驱动 sub_1400323F0
__int64 WriteProcessContextEntry(__int64 pInputEntry)
{
    __int64 ContextBase = DecryptProcessContextStr();
    if (!ContextBase)
        return 0;
    __int64 FuncTableAddr;
    __int64 ValueToWrite;
    if (*(_BYTE *)pInputEntry)
    {
        FuncTableAddr = *(_QWORD *)(ContextBase + 80);
        if (!FuncTableAddr)
            return 0;
        if (MmIsAddressValid(*(PVOID *)(ContextBase + 80)) != 1
            || MmIsAddressValid((PVOID)(FuncTableAddr + 223)) != 1)
            return 0;
        unsigned int EntryIndex = *(unsigned int *)(pInputEntry + 8);
        if (EntryIndex < 0x1B)
        {
            ValueToWrite = *(_QWORD *)(pInputEntry + 16);
            WritePhysicalMemoryQword(FuncTableAddr + 8 * (EntryIndex + 1), ValueToWrite);
            return 1;
        }
    }
    else
    {
        ValueToWrite = *(_QWORD *)(pInputEntry + 16);
        if (ValueToWrite)
        {
            unsigned int Index = *(unsigned int *)(pInputEntry + 8);
            if (Index <= 0x1B)
            {
                WritePhysicalMemoryQword(ContextBase + 8 * (Index + 14), ValueToWrite);
                return 1;
            }
        }
    }
    return 0;
}

// WriteProcessContextEntryWin7 — 写入进程上下文条目（Win7）
// 对应原始驱动 sub_14003A368
__int64 WriteProcessContextEntryWin7(ULONG *pInputEntry)
{
    __int64 ContextBase = OpenIpsecDriverSection();
    if (ContextBase)
    {
        unsigned int EntryIndex = *pInputEntry;
        if (EntryIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(ContextBase + 8 * EntryIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// WriteThreadContextEntryWin10 — 写入线程上下文条目（Win10）
// 对应原始驱动 sub_14005742C
__int64 WriteThreadContextEntryWin10(ULONG *pInputEntry)
{
    __int64 ContextBase = OpenVolumeDriverSection();
    if (ContextBase)
    {
        unsigned int EntryIndex = *pInputEntry;
        if (EntryIndex <= 0x1B)
        {
            WritePhysicalMemoryQword(ContextBase + 8 * EntryIndex + 112, *((__int64 *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}

// InitObjectAndQueryName — 初始化对象并查询名称
// 挂载对象上下文，初始化内核对象头，使用回调函数查询对象名称
// 对应原始驱动 sub_14007E87C
__int64 InitObjectAndQueryName(__int64 VirtualAddress, int Flags)
{
    __int64 Result;
    unsigned int ServiceCount;
    unsigned int (__fastcall *AttachProcessFunc)(__int64, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *);
    __int64 ServiceCountVal;
    enum _GLOBAL_TABLE_INDEX GtIndex;
    _QWORD *ServiceCountPtr;
    __int64 (__fastcall *QueryFunc)(__int64, char *);
    void (__fastcall *FreePoolFunc)(__int64);
    enum _GLOBAL_TABLE_INDEX GtIndex2;
    struct _KTHREAD *CurrentThread;
    char SavedByte;
    int QueryResult;
    char NameBuffer;
    __int64 ContextBuffer;

    Result = 0;
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    AttachProcessFunc = (unsigned int (__fastcall *)(__int64, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54);
    ServiceCountVal = GtRead(GtTotalSize | GtEprocessField95 | 0x100);
    GtIndex = GtKiFastCallEntryAddr | GtEprocessField06;
    ServiceCountPtr = (_QWORD *)ServiceCountVal;
    if (Flags != 1)
        GtIndex = GtNtQuerySystemInformationFunc | GtEprocessField55;
    QueryFunc = (__int64 (__fastcall *)(__int64, char *))GtRead(GtIndex);
    FreePoolFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    if (!QueryFunc)
    {
        ResolveKernelModuleFunctionAddrs();
        GtIndex2 = GtKiFastCallEntryAddr | GtEprocessField06;
        if (Flags != 1)
            GtIndex2 = GtNtQuerySystemInformationFunc | GtEprocessField55;
        QueryFunc = (__int64 (__fastcall *)(__int64, char *))GtRead(GtIndex2);
    }
    if (!GtRead(GtKiInsertQueueApcFunc))
    {
        InitHookFunctionTable();
        GtRead(GtKiInsertQueueApcFunc);
    }
    if (Flags == 1 && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28 && !GtRead(GtCallbackField12))
    {
        ScanKernelModulePESectionsEx();
        GtRead(GtCallbackField12);
    }
    if (ServiceCount != -1
        && AttachProcessFunc
        && QueryFunc
        && FreePoolFunc
        && ServiceCountPtr
        && !AttachProcessFunc(VirtualAddress, 512, 0, 0x10000000, *ServiceCountPtr, 0, &ContextBuffer))
    {
        InitKernelObjectHeader((char *)VirtualAddress);
        CurrentThread = KeGetCurrentThread();
        SavedByte = *((_BYTE *)CurrentThread + ServiceCount);
        *((_BYTE *)CurrentThread + ServiceCount) = 0;
        QueryResult = (int)QueryFunc(ContextBuffer, &NameBuffer);
        *((_BYTE *)CurrentThread + ServiceCount) = SavedByte;
        Result = QueryResult == 0;
        FreePoolFunc(ContextBuffer);
    }
    return Result;
}


// InitObjectOperationEntry — 初始化对象操作条目
// 根据版本号选择读取 win32k 或 ntoskrnl 文件，获取系统调用偏移，依次调用
// FindObjectOperationDataSection/QueryObjectOperationByVersion/FindObjectOperationBaseOffset 解析对象操作基址
// 对应原始驱动 sub_140036BD8
void InitObjectOperationEntry(void)
{
    unsigned int SyscallOffset;
    __int64 FileOffset;
    int pEndPtr;
    unsigned int DataSectionOffset;
    unsigned int VersionOffset;
    __int64 BaseOffset;
    unsigned int FileSize;
    void *pFileBuffer;

    pFileBuffer = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        if (ReadWin32kFullDriverFile((__int64 *)&pFileBuffer, &FileSize) != 1)
            return;
        SyscallOffset = (unsigned int)GtRead(GtCallbackField21);
        if (SyscallOffset)
            goto LABEL_10;
        DispatchObjectOperationInit((__int64)pFileBuffer, FileSize);
        SyscallOffset = (unsigned int)GtRead(GtCallbackField21);
LABEL_9:
        if (!SyscallOffset)
        {
LABEL_17:
            ExFree(pFileBuffer);
            return;
        }
LABEL_10:
        if (SyscallOffset < FileSize)
        {
            FileOffset = SyscallOffset;
            pEndPtr = (_DWORD)(ULONG_PTR)pFileBuffer + FileSize;
            DataSectionOffset = (unsigned int)FindObjectOperationDataSection(
                (__int64)pFileBuffer + FileOffset,
                (unsigned int)(ULONG_PTR)pFileBuffer + FileSize,
                (int)(ULONG_PTR)pFileBuffer);
            if (DataSectionOffset)
            {
                if (DataSectionOffset < FileSize)
                {
                    VersionOffset = (unsigned int)QueryObjectOperationByVersion(
                        (__int64)pFileBuffer + DataSectionOffset,
                        pEndPtr,
                        (int)(ULONG_PTR)pFileBuffer);
                    if (VersionOffset)
                    {
                        if (VersionOffset < FileSize)
                        {
                            BaseOffset = FindObjectOperationBaseOffset(
                                (__int64)pFileBuffer + VersionOffset,
                                pEndPtr,
                                (int)(ULONG_PTR)pFileBuffer);
                            if (BaseOffset)
                                GtWrite(GtCallbackField22, BaseOffset);
                        }
                    }
                }
            }
        }
        goto LABEL_17;
    }
    SyscallOffset = (unsigned int)GtRead(GtCallbackField21);
    if (SyscallOffset || (DispatchObjectOperationInit(0, 0), (SyscallOffset = (unsigned int)GtRead(GtCallbackField21)) != 0))
    {
        if (ReadNtOsKrnlFile((__int64 *)&pFileBuffer, (__int64 *)&FileSize))
            goto LABEL_9;
    }
}


// InitObjectTypeTable — 初始化对象类型表
// 构建注册表路径 L"\Registry\Machine\System\CurrentControlSet\Services\" + 输入名称，
// 通过回调函数注册对象类型
// 读取 GtRtlInitUnicodeStringFunc(0x421D)、GtCallbackField01(0x2CC)、GtCallbackField02(0x2CD)、GtEprocessField51(0x27)
// 对应原始驱动 sub_1400837D8
__int64 InitObjectTypeTable(_QWORD InputName)
{
    __int64 Result;
    __int64 RtlInitUnicodeString;
    __int64 CallbackFunc1;
    __int64 CallbackFunc2;
    __int64 ThreadOffset;
    char SavedByte;
    __int64 Size;
    int InputLen;
    _WORD *PathBuffer;
    __int64 OutputBuffer;
    PRKTHREAD CurrentThread;
    _WORD RegPath[64];

    Result = 0;
    RtlInitUnicodeString = GtRead(GtRtlInitUnicodeStringFunc);
    if (!RtlInitUnicodeString)
        return Result;
    CallbackFunc1 = GtRead(GtCallbackField01);
    if (!CallbackFunc1)
    {
        ResolvePESectionOffset();
        CallbackFunc1 = GtRead(GtCallbackField01);
    }
    CallbackFunc2 = GtRead(GtCallbackField02);
    ThreadOffset = GtRead(GtEprocessField51);
    if (!CallbackFunc1 || ThreadOffset == -1)
        return Result;
    InputLen = (int)GetStringLength((_WORD *)InputName);
    if (!InputLen)
        return Result;

    // 构建路径 L"\Registry\Machine\System\CurrentControlSet\Services\"
    RegPath[0] = L'\\'; RegPath[1] = L'R'; RegPath[2] = L'e'; RegPath[3] = L'g';
    RegPath[4] = L'i'; RegPath[5] = L's'; RegPath[6] = L't'; RegPath[7] = L'r';
    RegPath[8] = L'y'; RegPath[9] = L'\\'; RegPath[10] = L'M'; RegPath[11] = L'a';
    RegPath[12] = L'c'; RegPath[13] = L'h'; RegPath[14] = L'i'; RegPath[15] = L'n';
    RegPath[16] = L'e'; RegPath[17] = L'\\'; RegPath[18] = L'S'; RegPath[19] = L'y';
    RegPath[20] = L's'; RegPath[21] = L't'; RegPath[22] = L'e'; RegPath[23] = L'm';
    RegPath[24] = L'\\'; RegPath[25] = L'C'; RegPath[26] = L'u'; RegPath[27] = L'r';
    RegPath[28] = L'r'; RegPath[29] = L'e'; RegPath[30] = L'n'; RegPath[31] = L't';
    RegPath[32] = L'C'; RegPath[33] = L'o'; RegPath[34] = L'n'; RegPath[35] = L't';
    RegPath[36] = L'r'; RegPath[37] = L'o'; RegPath[38] = L'l'; RegPath[39] = L'S';
    RegPath[40] = L'e'; RegPath[41] = L't'; RegPath[42] = L'\\'; RegPath[43] = L'S';
    RegPath[44] = L'e'; RegPath[45] = L'r'; RegPath[46] = L'v'; RegPath[47] = L'i';
    RegPath[48] = L'c'; RegPath[49] = L'e'; RegPath[50] = L's'; RegPath[51] = L'\\';
    RegPath[52] = 0;

    // 计算总大小并分配缓冲区
    Size = (GetStringLength(RegPath) + InputLen + 1) * 2 + 4;
    PathBuffer = ExAlloc(1, (ULONG)Size);
    if (!PathBuffer)
        return Result;
    memset(PathBuffer, 0, Size);
    WStringCopy(PathBuffer, RegPath);
    WStringConcat(PathBuffer, (_WORD *)InputName, InputLen);

    // 保存当前线程字节并清除
    CurrentThread = KeGetCurrentThread();
    SavedByte = *((_BYTE *)CurrentThread + ThreadOffset);
    *((_BYTE *)CurrentThread + ThreadOffset) = 0;

    // 调用 RtlInitUnicodeString 初始化路径
    ((void (__fastcall *)(__int64 *, _WORD *))RtlInitUnicodeString)(&OutputBuffer, PathBuffer);

    // 调用回调函数处理结果
    if (CallbackFunc2)
    {
        // 版本检查，但不影响最终调用
        unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
        if (BuildNumber >= 0x1770 && BuildNumber != 0x23F0)
            GtRead(GtWindowsBuildNumber);
        ((void (__fastcall *)(__int64, ULONG))CallbackFunc2)(OutputBuffer, 0);
    }
    else
    {
        ((void (__fastcall *)(__int64))CallbackFunc1)(OutputBuffer);
    }

    // 恢复线程字节
    *((_BYTE *)CurrentThread + ThreadOffset) = SavedByte;

    ExFree(PathBuffer);
    return 1;
}


// LookupMsrTableEntry — 查找 MSR 表条目
// 读取 GT 0x20/0x21/3/0x4402，通过 InitPESectionReadContext+ReadPESectionEntry 遍历节区
// 第1阶段匹配 EntryType 0x558/0x559 查找基址偏移，第2阶段匹配 0x418+0x13E/0x512/0x50E
// 写入 GtMsrEntryOffset1-4 (0x86C-0x86F)
// 对应原始驱动 sub_140030C5C
__int64 LookupMsrTableEntry(void)
{
    __int64 Result;
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    int FieldValue;
    int FieldValue2;
    __int64 SectionAlignment;
    unsigned int SectionType;
    unsigned int EntrySize;
    __int64 ImageBase;
    unsigned int ImageSize;
    __int64 NtoskrnlBase;
    unsigned int BaseOffset;
    int Phase1Offset;
    unsigned int Phase1Count;
    int Dst[16];
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>）又被取址当解码上下文，
                            //   不能只改类型；需与 CumulativeSize 家族同一轮按"角色拆分"处理
    char EntryBuffer[448];              // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [80] 仅 80 字节

    Result = 0;
    ImageBase = GtRead(GtNtoskrnlPeFileBase);
    ImageSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead(GtMsrTableBaseOffset);
    if (!ImageBase || !ImageSize || !NtoskrnlBase || !BaseOffset || BaseOffset >= ImageSize)
        return Result;

    // 阶段1：搜索 EntryType 0x558/0x559 的节区
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + BaseOffset), ImageSize - BaseOffset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 5)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) >= 0x558 &&
            *(unsigned short *)(SectionDataPtr + 6) <= 0x559)
        {
            int Offset = *(int *)&EntryBuffer[0x20] - (int)ImageBase + (int)CumulativeSize;
            if (Offset && (unsigned int)Offset < ImageSize)
            {
                Phase1Offset = Offset;
                break;
            }
        }
        ++Phase1Count;
    }

    // 阶段2：遍历节区，匹配 0x418+0x13E、0x512、0x50E
    if (!Phase1Offset)
        return Result;
    memset(Dst, 0, sizeof(Dst));
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + Phase1Offset), ImageSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    Phase1Count = 0;
    while (Phase1Count < 0x100)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (Phase1Count < 10 && *(unsigned short *)(SectionDataPtr + 6) == 0x418)
        {
            // 检查 CumulativeSize == 0x40000 和 var_108 == 0x80000 和 var_110 == 0
            if (CumulativeSize == 0x40000 &&
                *(__int64 *)&EntryBuffer[0x30] == 0x80000 &&
                *(int *)&EntryBuffer[0x10] == 0)
            {
                // 读取下一个条目
                if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                    break;
                SectionSize = *(unsigned int *)&EntryBuffer[0x38];
                CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
                CumulativeSize += SectionSize;
                SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
                *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
                if (*(unsigned short *)(SectionDataPtr + 6) == 0x13E)
                {
                    int Offset = *(int *)&EntryBuffer[0x20] - (int)ImageBase + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < ImageSize)
                    {
                        // 找到匹配，直接跳转到写入
                        NtoskrnlBase = ImageBase + Offset;
                        goto WRITE_RESULT;
                    }
                }
            }
        }
        if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
        {
            if (CumulativeSize == 0x40000)
            {
                FieldValue = *(int *)&EntryBuffer[0x20];
                if (FieldValue)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(unsigned int *)&EntryBuffer[0x18];
                        if (SectionType < 0x10)
                        {
                            int Offset = FieldValue - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize)
                                Dst[SectionType] = Offset;
                        }
                    }
                }
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x50E)
        {
            if (CumulativeSize == 0x40000)
            {
                FieldValue2 = *(int *)&EntryBuffer[0x30];
                if (FieldValue2)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x20];
                    if (SectionAlignment == 0x40)
                    {
                        EntrySize = *(unsigned int *)&EntryBuffer[0x10];
                        if (EntrySize < 0x10)
                        {
                            int Offset = FieldValue2 - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize && Dst[EntrySize])
                            {
                                GtWrite(GtMsrEntryOffset1, Offset);
                                GtWrite(GtMsrEntryOffset2, Offset + NtoskrnlBase);
                                GtWrite(GtMsrEntryOffset3, Dst[EntrySize]);
                                GtWrite(GtMsrEntryOffset4, Dst[EntrySize] + NtoskrnlBase);
                                return Result;
                            }
                        }
                    }
                }
            }
        }
        ++Phase1Count;
    }
    return Result;

WRITE_RESULT:
    GtWrite(GtMsrEntryOffset1, (int)(NtoskrnlBase - ImageBase));
    GtWrite(GtMsrEntryOffset2, NtoskrnlBase);
    GtWrite(GtMsrEntryOffset3, Dst[0]);
    GtWrite(GtMsrEntryOffset4, Dst[0] + NtoskrnlBase);
    return Result;
}


// ParseMsrRelatedSections — 解析 MSR 相关节区
// 读取全局表 0x20/0x21/3/0x4405/0x86C/0x86E，通过 InitPESectionReadContext+ReadPESectionEntry 循环遍历节区
// 第1阶段匹配 EntryType 0x558 查找 MSR 相关基址偏移，第2阶段填充 Dst 偏移数组并写入全局表 0x870/0x871
// 对应原始驱动 sub_1400306C0
__int64 ParseMsrRelatedSections(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    int FieldValue2;
    __int64 SectionAlignment;
    unsigned int SectionType;
    __int64 MiscInfo;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    unsigned int MiscInfo2;
    __int64 Result;
    int Phase1Offset;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    __int64 ImageBase;
    unsigned int ImageSize;
    __int64 NtoskrnlBase;
    unsigned int BaseOffset;
    unsigned int Offset1;
    unsigned int Offset2;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>）又被取址当解码上下文，
                            //   不能只改类型；需与 CumulativeSize 家族同一轮按"角色拆分"处理
    char EntryBuffer[448];              // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [80] 仅 80 字节

    Result = 0;
    ImageBase = GtRead(0x20);
    ImageSize = (unsigned int)GtRead(0x21);
    NtoskrnlBase = GtRead(3);
    BaseOffset = (unsigned int)GtRead(0x4405);
    Offset1 = (unsigned int)GtRead(0x86C);
    Offset2 = (unsigned int)GtRead(0x86E);
    if (!ImageBase || !ImageSize || !NtoskrnlBase || !BaseOffset || BaseOffset >= ImageSize || !Offset1 || !Offset2)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + BaseOffset), ImageSize - BaseOffset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0x64)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
        {
            FieldValue = *(int *)&EntryBuffer[0x20];
            Phase1Offset = FieldValue - (int)ImageBase + (int)CumulativeSize;
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x53D)
        {
            SectionType = *(unsigned int *)&EntryBuffer[0x28];
            MiscInfo = *(__int64 *)&EntryBuffer[0x30];
            if (SectionType == 1 && MiscInfo == 5 && Phase1Offset && (unsigned int)Phase1Offset < ImageSize)
                break;
        }
        ++Phase1Count;
    }
    memset(Dst, 0, sizeof(Dst));
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + Phase1Offset), ImageSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    LoopIndex = 0;
    while (LoopIndex < 0x100)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
        {
            if (CumulativeSize == 0x40000)
            {
                EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                if (EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(unsigned int *)&EntryBuffer[0x18];
                        if (SectionType < 0x10)
                        {
                            int Offset = EntrySize - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize)
                                Dst[SectionType] = Offset;
                        }
                    }
                }
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x50E)
        {
            if (SectionAlignment == 0x40000)
            {
                FieldValue2 = *(int *)&EntryBuffer[0x30];
                if (FieldValue2)
                {
                    if (CumulativeSize == 0x40)
                    {
                        EntrySize = *(unsigned int *)&EntryBuffer[0x10];
                        if (EntrySize < 0x10)
                        {
                            int Offset = FieldValue2 - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize && (unsigned int)Offset == Offset1)
                            {
                                if (Dst[EntrySize] && Dst[EntrySize] != Phase1Count)
                                {
                                    GtWrite(0x870, Dst[EntrySize]);
                                    MiscInfo2 = *(unsigned int *)&EntryBuffer[0x10];
                                    GtWrite(0x871, Dst[MiscInfo2] + NtoskrnlBase);
                                }
                            }
                        }
                    }
                }
            }
        }
        ++LoopIndex;
    }
    return Result;
}


// ParseMsrTableFromSections — 从节区解析 MSR 表
// 与 ParseMsrRelatedSections 类似，使用 GtRead(0x443B) 替代 0x4405
// 对应原始驱动 sub_1400309A0
__int64 ParseMsrTableFromSections(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    int FieldValue2;
    __int64 SectionAlignment;
    unsigned int SectionType;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    unsigned int MiscInfo2;
    __int64 Result;
    int Phase1Offset;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    __int64 ImageBase;
    unsigned int ImageSize;
    __int64 NtoskrnlBase;
    unsigned int BaseOffset;
    unsigned int Offset1;
    unsigned int Offset2;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>）又被取址当解码上下文，
                            //   不能只改类型；需与 CumulativeSize 家族同一轮按"角色拆分"处理
    char EntryBuffer[448];              // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [80] 仅 80 字节

    Result = 0;
    ImageBase = GtRead(0x20);
    ImageSize = (unsigned int)GtRead(0x21);
    NtoskrnlBase = GtRead(3);
    BaseOffset = (unsigned int)GtRead(0x443B);
    Offset1 = (unsigned int)GtRead(0x86C);
    Offset2 = (unsigned int)GtRead(0x86E);
    if (!ImageBase || !ImageSize || !NtoskrnlBase || !BaseOffset || BaseOffset >= ImageSize || !Offset1 || !Offset2)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + BaseOffset), ImageSize - BaseOffset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0x14)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
        {
            FieldValue = *(int *)&EntryBuffer[0x20];
            int Offset = FieldValue - (int)ImageBase + (int)CumulativeSize;
            if (Offset && (unsigned int)Offset < ImageSize)
            {
                Phase1Offset = Offset;
                break;
            }
        }
        ++Phase1Count;
    }
    memset(Dst, 0, sizeof(Dst));
    PeContext = 0;
    InitPESectionReadContext((__int64)((char *)ImageBase + Phase1Offset), ImageSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, 0);
    LoopIndex = 0;
    while (LoopIndex < 0x100)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
        {
            if (CumulativeSize == 0x40000)
            {
                EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                if (EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(unsigned int *)&EntryBuffer[0x18];
                        if (SectionType < 0x10)
                        {
                            int Offset = EntrySize - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize)
                                Dst[SectionType] = Offset;
                        }
                    }
                }
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x50E)
        {
            if (SectionAlignment == 0x40000)
            {
                FieldValue2 = *(int *)&EntryBuffer[0x30];
                if (FieldValue2)
                {
                    if (CumulativeSize == 0x40)
                    {
                        EntrySize = *(unsigned int *)&EntryBuffer[0x10];
                        if (EntrySize < 0x10)
                        {
                            int Offset = FieldValue2 - (int)ImageBase + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize && (unsigned int)Offset == Offset1)
                            {
                                if (Dst[EntrySize] && Dst[EntrySize] != Phase1Count)
                                {
                                    GtWrite(0x870, Dst[EntrySize]);
                                    MiscInfo2 = *(unsigned int *)&EntryBuffer[0x10];
                                    GtWrite(0x871, Dst[MiscInfo2] + NtoskrnlBase);
                                }
                            }
                        }
                    }
                }
            }
        }
        ++LoopIndex;
    }
    return Result;
}


// ResolveStreamHandleContext — 解析流句柄上下文
// 对应原始驱动 sub_14001AFA0
__int64 ResolveStreamHandleContext(void)
{
    __int64 Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *TargetProcessCopy;
    __int64 ModuleBase;
    unsigned int ModuleSize;
    __int64 NtImageBase;
    unsigned int KernelPESectionByType;
    unsigned int KnownSectionCount;
    unsigned int SyscallOffset;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    TargetProcessCopy = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    ModuleBase = GtRead(GtEprocessField22);
    ModuleSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    KernelPESectionByType = (unsigned int)FindKernelPESectionByType(GtTotalSize | GtIrpBufferSize | GtPathBuffer00);
    KnownSectionCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);

    if (ModuleBase && ModuleSize && NtImageBase && KernelPESectionByType && KernelPESectionByType < KnownSectionCount)
    {
        SyscallOffset = (unsigned int)ResolveSyscallToAddress(KernelPESectionByType);
        if (SyscallOffset && SyscallOffset < ModuleSize)
        {
            Result = NtImageBase + SyscallOffset;
            ScanKernelDiscardableSection(SyscallOffset);
        }
    }

    if (TargetProcessCopy)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}


// GetSystemRootForThread — 获取线程系统根目录
// 对应原始驱动 sub_14004CDDC
__int64 GetSystemRootForThread(PRKPROCESS PROCESS)
{
    __int64 SystemRootEntry;
    int *pAllocBuffer;
    int *pBuffer;

    SystemRootEntry = 0;
    pAllocBuffer = (int *)ExAlloc(PagedPool, 0x200000u);
    pBuffer = pAllocBuffer;
    if (pAllocBuffer)
    {
        memset(pAllocBuffer, 0, 0x200000u);
        *pBuffer = 0;
        EnumProcessThreadInfo(PROCESS, 1, pBuffer, 0x200000u);
        EnumProcessThreadInfo(PROCESS, 0, pBuffer, 0x200000u);
        SystemRootEntry = FindSystemRootEntry(pBuffer);
        ExFree(pBuffer);
    }
    return SystemRootEntry;
}

// ScanKernelDiscardableSection — 扫描内核可丢弃节区
// 对应原始驱动 sub_14001A8C4
__int64 ScanKernelDiscardableSection(unsigned int SectionIndex)
{
    __int64 ModuleBase;
    unsigned int ModuleSize;
    __int64 NtImageBase;
    int ModuleInfo;
    __int64 result;
    int DiscardableOffset;
    unsigned int j;
    int MatchSize;
    char FoundFlag;
    unsigned int i;
    int MatchSize2;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    unsigned int EntryFlags;
    __int64 FieldValue;
    unsigned int SectionSize;
    __int64 SectionDataPtr;

    ModuleBase = GtRead(GtEprocessField22);
    ModuleSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        result = GtRead((enum _GLOBAL_TABLE_INDEX)2313);
    else
        result = GtRead(GtNtDeleteKeyPeSectionOffset | GtEprocessField02);
    DiscardableOffset = (int)result;

    if (ModuleBase && ModuleSize && NtImageBase && ModuleInfo && DiscardableOffset)
    {
        result = GtRead(GtWindowsBuildNumber);
        if ((unsigned int)result < 0x23F0)
            goto LABEL_23;

        if (!SectionIndex)
            return result;

        if (SectionIndex >= ModuleSize)
        {
LABEL_23:
            if (SectionIndex && SectionIndex < ModuleSize)
            {
                InitPESectionReadContext(
                    (__int64)(ModuleBase + SectionIndex),
                    ModuleSize - SectionIndex,
                    2,
                    0,
                    -1,
                    0,
                    0,
                    (__int64)&ReadContext);
                FoundFlag = 0;
                for (i = 0; i < 0x64; i++)
                {
                    result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
                    if ((_DWORD)result)
                        break;
                    MatchSize2 = SectionSize + (int)CumulativeSize;
                    result = SectionDataPtr;
                    CumulativeSize += SectionSize;
                    if (*(_WORD *)(SectionDataPtr + 6) == 1368 && (FieldValue & 0x4000000) != 0)
                    {
                        result = EntryFlags;
                        if (EntryFlags)
                        {
                            result = MatchSize2 + EntryFlags - (unsigned int)ModuleBase;
                            if (DiscardableOffset == (_DWORD)result)
                            {
                                FoundFlag = 1;
                            }
                            else if (FoundFlag == 1 && (_DWORD)result && (unsigned int)result < ModuleSize)
                            {
                                return GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessField140 | 0x100), NtImageBase + (unsigned int)result);
                            }
                        }
                    }
                }
            }
        }
        else
        {
            InitPESectionReadContext(
                (__int64)(ModuleBase + SectionIndex),
                ModuleSize - SectionIndex,
                2,
                0,
                -1,
                0,
                0,
                (__int64)&ReadContext);
            for (j = 0; j < 0x14; j++)
            {
                result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
                if ((_DWORD)result)
                    break;
                MatchSize = SectionSize + (int)CumulativeSize;
                CumulativeSize += SectionSize;
                if (*(_WORD *)(SectionDataPtr + 6) == 1369 && (FieldValue & 0x4000000) != 0)
                    goto LABEL_22;
                result = GtRead(GtWindowsBuildNumber);
                if ((unsigned int)result >= 0x3FAB)
                {
                    result = SectionDataPtr;
                    if (*(_WORD *)(SectionDataPtr + 6) == 1368 && (FieldValue & 0x4000000) != 0)
                    {
                        MatchSize = (int)CumulativeSize;
LABEL_22:
                        result = MatchSize + EntryFlags - (unsigned int)ModuleBase;
                        SectionIndex = ((unsigned int)result < ModuleSize) ? (unsigned int)result : 0;
                        goto LABEL_23;
                    }
                }
            }
        }
    }
    return result;
}

// 前向声明
char ReadIoPortDescriptorTable(_DWORD *pOutputTable);
char ParseIoPortDescriptorTable(__int64 pContextTable);
char TranslateIoPortAddresses(__int64 pContextTable);
char ResolveIoPortContext(__int64 pContextTable);

char ReadIoPortDataForProcess(__int64 DeviceObject, __int64 *pIoPortContext)
{
    char IsContextResolved;
    char Result;
    struct _KPROCESS *TargetProcess;
    _OWORD *pDestBuffer;
    _OWORD *pSrcBuffer;
    __int64 CopyCount;
    _DWORD *pOutputCounter;
    struct _KAPC_STATE ApcState;

    IsContextResolved = 0;
    Result = 1;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    if (TargetProcess)
    {
        KeStackAttachProcess(TargetProcess, &ApcState);
        if (ReadIoPortDescriptorTable((_DWORD *)*pIoPortContext) == 1
            && ParseIoPortDescriptorTable(*pIoPortContext) == 1
            && TranslateIoPortAddresses(*pIoPortContext) == 1)
        {
            IsContextResolved = ResolveIoPortContext(*pIoPortContext) == 1;
        }
        KeUnstackDetachProcess(&ApcState);
    }
    if (IsContextResolved)
    {
        pOutputCounter = (_DWORD *)pIoPortContext[1];
        if (14336 * (unsigned __int64)(unsigned int)*pOutputCounter + 14344 > *((unsigned int *)pIoPortContext + 4))
            return 0;
        pDestBuffer = (_OWORD *)&pOutputCounter[3584 * *pOutputCounter + 2];
        pSrcBuffer = (_OWORD *)*pIoPortContext;
        CopyCount = 112;
        do
        {
            *pDestBuffer = *pSrcBuffer;
            pDestBuffer[1] = pSrcBuffer[1];
            pDestBuffer[2] = pSrcBuffer[2];
            pDestBuffer[3] = pSrcBuffer[3];
            pDestBuffer[4] = pSrcBuffer[4];
            pDestBuffer[5] = pSrcBuffer[5];
            pDestBuffer[6] = pSrcBuffer[6];
            pDestBuffer += 8;
            *(pDestBuffer - 1) = pSrcBuffer[7];
            pSrcBuffer += 8;
            --CopyCount;
        }
        while (CopyCount);
        ++*pOutputCounter;
        return 1;
    }
    return Result;
}


char ReadIoPortDescriptorTable(_DWORD *pOutputTable)
{
    unsigned int EntryIndex;
    void **pIdtEntryArray;
    unsigned __int64 NtoskrnlBase;
    unsigned int NtoskrnlSize;
    unsigned __int16 *pIdtBase;
    _QWORD *pFiberData;
    unsigned __int16 *pIdtEntry;
    unsigned __int64 OffsetHigh;
    __int64 OffsetLow;

    EntryIndex = 0;
    pIdtEntryArray = (void **)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField153 | 0x100));
    if (!pIdtEntryArray)
    {
        ParseNtExportSectionsV4();
        pIdtEntryArray = (void **)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField153 | 0x100));
    }

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlSize = (unsigned int)GtRead(GtEprocessField23);

    if (pIdtEntryArray
        && NtoskrnlBase
        && NtoskrnlSize
        && (unsigned __int64)pIdtEntryArray > NtoskrnlBase
        && (ULONG)((ULONG_PTR)pIdtEntryArray - (ULONG)NtoskrnlBase) < NtoskrnlSize)
    {
        pIdtBase = (unsigned __int16 *)*pIdtEntryArray;
        if (!MmIsAddressValid(pIdtBase))
        {
            pFiberData = (_QWORD *)GetCurrentFiber();
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3AD7)
                pIdtBase = (unsigned __int16 *)pFiberData[45];
            else
                pIdtBase = (unsigned __int16 *)pFiberData[21];
        }

        if (MmIsAddressValid(pIdtBase) == 1)
        {
            pIdtEntry = pIdtBase + 3;
            do
            {
                pOutputTable[0] = EntryIndex;
                pOutputTable += 14;

                // IDT条目格式: 2字节偏移低16位 + 2字节段选择器 + 1字节零 + 1字节标志 + 2字节偏移中16位 + 4字节偏移高32位 + 4字节保留
                // 低16位偏移在 pIdtEntry[-3] (= pIdtEntry - 3)
                // 中16位偏移在 pIdtEntry[0]
                // 高32位偏移在 pIdtEntry[1]
                OffsetLow = *(pIdtEntry - 3);
                OffsetHigh = *pIdtEntry + ((unsigned __int64)*(unsigned int *)(pIdtEntry + 1) << 16);

                pIdtEntry += 8;

                *((_QWORD *)pOutputTable - 6) = OffsetLow + (OffsetHigh << 16) - NtoskrnlBase;

                EntryIndex++;
            } while (EntryIndex < 0x100);

            EntryIndex = 1;
        }
    }
    return (char)EntryIndex;
}


char ParseIoPortDescriptorTable(__int64 pContextTable)
{
    char Result;
    __int64 IdtBase;
    unsigned int GdtEntryCount;
    unsigned __int16 *pIdtEntry;
    _BYTE *pEntry;
    __int64 EntryCount;
    unsigned int SegmentSelector;
    __int64 OffsetLow;
    unsigned __int64 OffsetHigh;
    char IdtrValue[10];             // IDTR: 2字节Limit + 8字节Base
    unsigned short GdtrValue[8];    // GDTR: 2字节Limit + 8字节Base (填充到16字节)

    Result = 0;
    ReadIdtr(IdtrValue);
    ReadGdtr(GdtrValue);

    IdtBase = *(__int64 *)(IdtrValue + 2);
    GdtEntryCount = GdtrValue[0] >> 3;
    if (GdtEntryCount)
        GdtEntryCount--;

    if (CheckMemoryValid((void *)IdtBase) == 1 && CheckMemoryValid((void *)(IdtBase + 4095)) == 1)
    {
        pIdtEntry = (unsigned __int16 *)(IdtBase + 2);
        pEntry = (_BYTE *)(pContextTable + 32);
        EntryCount = 256;

        do
        {
            // 段选择器 = pIdtEntry[0] >> 3 (索引部分)
            SegmentSelector = *pIdtEntry >> 3;
            *((_DWORD *)pEntry - 7) = SegmentSelector;

            // 检查RPL (请求特权级)
            if ((*(_BYTE *)pIdtEntry & 3) != 0)
                *pEntry = 1;

            if (!SegmentSelector)
                goto LABEL_INVALID_SELECTOR;

            if (SegmentSelector != 2)
                *pEntry = 1;

            if (SegmentSelector >= GdtEntryCount)
LABEL_INVALID_SELECTOR:
                *pEntry = 1;

            // 合并中断处理函数地址
            OffsetLow = *(pIdtEntry - 1);                              // 低16位 (pIdtEntry[-1])
            OffsetHigh = (unsigned __int64)pIdtEntry[2] << 16;         // 中16位 (pIdtEntry[2])

            pEntry += 56;
            pIdtEntry += 8;

            // 高32位 (pIdtEntry[-5] = pIdtEntry + 3, 即原来的pIdtEntry[3])
            *((_QWORD *)pEntry - 8) = ((unsigned __int64)*(unsigned int *)(pIdtEntry - 5) << 32)
                                        | (OffsetLow + OffsetHigh);

            EntryCount--;
        } while (EntryCount);

        return 1;
    }
    return Result;
}


char TranslateIoPortAddresses(__int64 pContextTable)
{
    char Result;
    __int64 NtoskrnlBase;
    __int64 HalDispatchTable;
    unsigned int HalDispatchTableSize;
    __int64 pEntry;
    __int64 EntryCount;
    unsigned __int64 AddressValue;

    Result = 0;
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    HalDispatchTable = GtRead(GtEprocessField66);
    HalDispatchTableSize = (unsigned int)GtRead(GtEprocessField23);

    if (NtoskrnlBase && HalDispatchTable && HalDispatchTableSize)
    {
        pEntry = pContextTable + 8;
        EntryCount = 256;

        do
        {
            AddressValue = *(_QWORD *)pEntry;
            if (AddressValue && AddressValue < HalDispatchTableSize && AddressValue + 16 < HalDispatchTableSize)
            {
                *(_QWORD *)(pEntry + 8) = AddressValue + NtoskrnlBase;
                *(_OWORD *)(pEntry + 26) = *(_OWORD *)(AddressValue + HalDispatchTable);
            }
            pEntry += 56;
            EntryCount--;
        } while (EntryCount);

        return 1;
    }
    return Result;
}


char ResolveIoPortContext(__int64 pContextTable)
{
    char Result;
    unsigned __int64 IoPortSectionBase;
    unsigned __int64 ProcessStart;
    unsigned int ProcessSize;
    unsigned __int64 NtoskrnlBase;
    unsigned int NtoskrnlSize;
    unsigned int EntryIndex;
    __int64 pEntry;
    unsigned __int64 ProcessEnd;
    unsigned __int64 TargetAddress;
    unsigned int ByteIndex;
    __int64 TableSectionBase;
    __int64 TranslatedAddress;
    unsigned int IoPortSectionSize;

    Result = 0;
    if (!GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableCount | GtEprocessField114)))
        DispatchParseNtExportSectionsV2();

    IoPortSectionBase = GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableBase | GtEprocessField112));
    IoPortSectionSize = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableCount | GtEprocessField112));
    TableSectionBase = GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableCount | GtEprocessField114));

    ProcessStart = GtRead(GtEprocessField76);
    ProcessSize = (unsigned int)GtRead(GtEprocessField77);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);

    if (ProcessStart && ProcessSize && NtoskrnlBase && NtoskrnlSize)
    {
        EntryIndex = 0;
        pEntry = pContextTable + 16;
        ProcessEnd = ProcessStart + ProcessSize;
        Result = 1;

        do
        {
            TargetAddress = *(_QWORD *)(pEntry + 8);

            // 如果在进程地址范围内，跳过
            if (TargetAddress < ProcessEnd && TargetAddress >= ProcessStart)
                goto LABEL_NEXT_ENTRY;

            // 如果在ntoskrnl范围外且不是零，且地址已变化，标记为已修改
            if (TargetAddress >= NtoskrnlBase + NtoskrnlSize || TargetAddress < NtoskrnlBase)
            {
                if (!TargetAddress)
                    goto LABEL_CHECK_ZERO;
                if (*(_QWORD *)pEntry != TargetAddress)
                    *(_BYTE *)(pEntry + 16) = 1;    // 标记已修改
            }

            if (!TargetAddress)
            {
LABEL_CHECK_ZERO:
                if (!*(_QWORD *)pEntry)
                    *(_BYTE *)(pEntry + 16) = 0;    // 清除修改标记
            }

            if (*(_QWORD *)pEntry)
            {
                // 验证原始地址的内存有效性
                if (MmIsAddressValid(*(PVOID *)pEntry) == 1
                    && MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15)) == 1)
                {
                    // 比较备份数据与当前内存数据
                    if ((unsigned int)MemoryCompare(
                            pContextTable + (ULONG64)EntryIndex * 56 + 34,
                            *(char **)pEntry,
                            0x10))
                    {
                        // 数据不一致，检查是否在IO端口节区内
                        if (!IoPortSectionBase
                            || !IoPortSectionSize
                            || !TableSectionBase
                            || *(_QWORD *)pEntry < IoPortSectionBase
                            || *(_QWORD *)pEntry >= IoPortSectionBase + IoPortSectionSize
                            || ValidateIoPortSection(*(_QWORD *)pEntry))
                        {
                            *(_BYTE *)(pEntry + 17) = 1;   // 标记已Hook

                            if (*(_BYTE *)(pEntry + 16) == 0)   // 未标记为已修改
                            {
                                // 验证所有16字节的内存有效性
                                for (ByteIndex = 0; ByteIndex < 0x10; ByteIndex++)
                                {
                                    if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + ByteIndex)))
                                        break;
                                }
                                if (ByteIndex)
                                {
                                    // 此分支在原始驱动中为死代码（ReturnFalseStub始终返回0）
                                    if (ReturnFalseStub() == 1)
                                        *(_QWORD *)(pEntry + 8) = TranslatedAddress;
                                }
                            }
                        }
                    }
                }
            }

LABEL_NEXT_ENTRY:
            EntryIndex++;
            pEntry += 56;
        } while (EntryIndex < 0x100);
    }
    return Result;
}



// ReadIdtr �� ��ȡ IDTR���ж����������Ĵ�������ִ�� SIDT ָ�
// ��Ӧԭʼ���� sub_1400015BF
void ReadIdtr(void *pIdtr)
{
    __sidt(pIdtr);
}

// DispatchParseNtExportSectionsV2 �� �ַ����� NT �������� V2��
// ���� GT 2324 �������жϣ��� > 0x23F0��Win10+������� ParseNtExportSectionsV2��������� ParseNtExportSectionsWin10��
// ��Ӧԭʼ���� sub_140038B08
__int64 DispatchParseNtExportSectionsV2(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
        return ParseNtExportSectionsV2();
    else
        return ParseNtExportSectionsWin10();
}


// ParseNtExportSectionsV4 — 解析 NT 导出节区 V4（三段递进扫描）
// 对应原始驱动 0x1400382FC（727 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x1400382FC~0x1400385D2
//   的 194 条指令逐条还原
// 【⚠ 修正记录】此前本函数是空壳（`void ParseNtExportSectionsV4(void) { return; }`），
//   属 CLAUDE.md 明令禁止的占位实现。本次补齐真实逻辑，并把返回类型由 `void`
//   更正为 `char` —— 原始结尾是 `mov al, bl`，成功路径 `mov bl, 1`，是布尔返回
//   （调用点 ContextMgmt.c 忽略返回值，故更正后调用点无需改动）。
// 【验证依据】描述符字段偏移由 rbp 位移换算（条目基址 var_150 = rbp-0x70）：
//   0xF0 / 0x118 / 0x88 / 0x70 / 0x50 / 0x58 / 0x38 / 0x78，与已验证的 0x120
//   布局吻合；帧布局与其它扫描器一致（ctx = rsp+0x40，读指针 = rsp+0x48 = ctx+8，
//   同样是"ReadPESectionEntry 只读上下文、调用方推进读指针"）
// 【与其它扫描器的差异（差分结论）】
//   1) 三段递进，每段都用 InitPESectionReadContext 重新初始化，且窗口大小**固定
//      0x1000**(4096) 字节，不是"扫到文件末尾"
//   2) 前置校验：GT 0x43A5 的值 v 须满足 v < 文件大小 且 v+0x1000 < 文件大小
//   3) 三段识别条件各不相同，循环上限分别为 0x64 / 0x12C / 0x64
//   4) 结果写 GT 0x1A3，返回布尔（其它扫描器返回 0 且靠 GT 传结果）
// 【⚠ GT 0x43A5 说明】该索引落在原始驱动的"哈希表区"(0x4158-0x4479)，运行时会被
//   解析结果覆盖，此处按"第 1 段的起始偏移"使用，语义存疑但操作忠实。
// 【逻辑】
//   第 1 段：从「文件缓冲基址 + GT 0x43A5」起扫 0x1000 字节，遇到 0x558 型且
//           +0x38(VA) 非 0 的节区就记候选偏移（候选 = VA - 文件缓冲低 32 位 +
//           读指针低 32 位）；随后若遇到 +0x88==0x800000 且 +0x70==0xC0000259
//           的节区且候选合法（非 0 且 < 文件大小）则进入第 2 段
//   第 2 段：以候选偏移为基址再扫 0x1000 字节，先置位"见到 +0x50==0x200 且
//           +0x88==0x40000 的节区"标志；标志置位后再遇 0x558 型且 +0x38 非 0，
//           算出新偏移且 < 文件大小者进入第 3 段
//   第 3 段：以该偏移为基址再扫 0x1000 字节，找 0x510 型且 +0x50==0x40 且
//           +0x88==0x40000 且 +0x58==2 的节区，取 +0x78 算出末偏移，非 0 且
//           < 文件大小时写入 GT 0x1A3（末偏移 + GT 0x3 镜像基址），返回 1
//   任一段失败/越界一律返回 0
char ParseNtExportSectionsV4(void)
{
    char Result = 0;
    char FoundFlag = 0;
    unsigned int PhaseBase;
    unsigned int KernelSize;
    unsigned int Candidate = 0;
    unsigned int EntryIndex;
    unsigned int ReadPtr32;
    ULONG64 ExpectedValue;
    ULONG64 NtImageBase;
    ULONG64 FileBase;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    FileBase = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    KernelSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    PhaseBase = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43A5);

    if (!NtImageBase || !FileBase || !KernelSize || !PhaseBase)
        return Result;
    if (PhaseBase >= KernelSize)
        return Result;
    if (PhaseBase + 0x1000 >= KernelSize)
        return Result;

    // ---- 第 1 段：定位候选偏移 ----
    InitPESectionReadContext(FileBase + PhaseBase, 0x1000, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ExpectedValue = 0x558;

    for (EntryIndex = 0; EntryIndex < 0x64; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return Result;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        ReadPtr32 = (unsigned int)ReadContext.ReadPtr;

        if ((unsigned __int16)ExpectedValue ==
                *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) &&
            *(_DWORD *)((char *)SectionEntry + 0x38) != 0)
        {
            Candidate = *(_DWORD *)((char *)SectionEntry + 0x38) - (unsigned int)FileBase + ReadPtr32;
            continue;
        }

        if (*(__int64 *)((char *)SectionEntry + 0x88) == 0x800000 &&
            *(__int64 *)((char *)SectionEntry + 0x70) == 0xC0000259 &&
            Candidate != 0 &&
            Candidate < KernelSize)
            break;
    }

    if (EntryIndex >= 0x64)
        return Result;

    // ---- 第 2 段：由候选偏移再定位下一级偏移 ----
    InitPESectionReadContext(FileBase + Candidate, 0x1000, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ExpectedValue = 0x40000;
    FoundFlag = 0;

    for (EntryIndex = 0; EntryIndex < 0x12C; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return Result;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        ReadPtr32 = (unsigned int)ReadContext.ReadPtr;

        if (*(__int64 *)((char *)SectionEntry + 0x50) == 0x200 &&
            *(__int64 *)((char *)SectionEntry + 0x88) == ExpectedValue)
        {
            FoundFlag = 1;
            continue;
        }

        if (FoundFlag != 1)
            continue;
        if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) != 0x558)
            continue;

        PhaseBase = *(_DWORD *)((char *)SectionEntry + 0x38);
        if (!PhaseBase)
            continue;

        PhaseBase = PhaseBase - (unsigned int)FileBase + ReadPtr32;
        if (!PhaseBase)
            continue;
        if (PhaseBase >= KernelSize)
            continue;

        break;
    }

    if (EntryIndex >= 0x12C)
        return Result;

    // ---- 第 3 段：由下一级偏移定位最终节区并写结果 ----
    InitPESectionReadContext(FileBase + PhaseBase, 0x1000, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (EntryIndex = 0; EntryIndex < 0x64; EntryIndex++)
    {
        unsigned int FinalOffset;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return Result;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        ReadPtr32 = (unsigned int)ReadContext.ReadPtr;

        if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) != 0x510)
            continue;
        if (*(__int64 *)((char *)SectionEntry + 0x50) != 0x40)
            continue;
        if (*(__int64 *)((char *)SectionEntry + 0x88) != ExpectedValue)
            continue;
        if (*(__int64 *)((char *)SectionEntry + 0x58) != 2)
            continue;

        FinalOffset = *(_DWORD *)((char *)SectionEntry + 0x78);
        FinalOffset = FinalOffset - (unsigned int)FileBase + ReadPtr32;
        if (!FinalOffset)
            continue;
        if (FinalOffset >= KernelSize)
            continue;

        GtWrite((GLOBAL_TABLE_INDEX)0x1A3, (__int64)(FinalOffset + NtImageBase));
        Result = 1;
        return Result;
    }

    return Result;
}

// ValidateIoPortSection -- 验证 IO 端口节区
// 对应原始驱动 sub_1400389A8
char ValidateIoPortSection(__int64 Address)
{
    if (!Address)
        return 0;
    if (MmIsAddressValid((PVOID)Address) != 1)
        return 0;
    if (*(unsigned int *)Address != 0xFFFF)
        return 0;
    if (*(unsigned short *)(Address + 4) != 0xFFFF)
        return 0;
    if (*(unsigned short *)(Address + 6) != 0xFFFF)
        return 0;
    return 1;
}

// ScanKernelModulePESectionsEx — 扫描内核模块 PE 节区（扩展版）
// 从 GT 3/32/33 获取 ntoskrnl 基址和大小，使用 InitPESectionReadContext 扫描所有 PE 节区
// 对应原始驱动 sub_14007DAB8
__int64 ScanKernelModulePESectionsEx(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ParseNtExportSectionsV2 -- 解析 NT 导出节区 V2（Win8+）
// 三阶段扫描：Phase1 搜索 0xFE/0x558 节 → Phase2 搜索 0x512/0x53C 节 → Phase3 搜索 0x559 节
__int64 ParseNtExportSectionsV2(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase;
    __int64 PeFileBase;
    unsigned int PeFileSize;
    unsigned int ExportDirSize;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>）又被取址当解码上下文，
                            //   不能只改类型；需与 CumulativeSize 家族同一轮按"角色拆分"处理
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int Phase1Count;
    unsigned int Phase2Count;
    unsigned int Phase3Count;
    unsigned int Phase1Offset = 0;
    ULONG EntryBuffer[0x80];

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    if (!NtoskrnlBase || !PeFileBase || !PeFileSize)
        return 0;

    ExportDirSize = *(unsigned int *)(PeFileBase + 0x3C);
    ExportDirSize = *(unsigned int *)(ExportDirSize + PeFileBase + 0x28);
    if (!ExportDirSize || ExportDirSize >= PeFileSize)
        return 0;

    // Phase1：在 PE 文件导出目录范围内搜索 0xFE / 0x558 节区
    InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + ExportDirSize), PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x38 >> 2];
        CumulativeSize = EntryBuffer[0x40 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x48 >> 2];
        EntryBuffer[0x40 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(SectionDataPtr + 6);
        if (SectionType == 0xFE || SectionType == 0x558)
        {
            if (SectionType == 0x558)
            {
                __int64 F0 = EntryBuffer[0xE8 >> 2];
                if (!(F0 & 0x4000000) || !EntryBuffer[0xD0 >> 2] || Phase1Offset)
                    goto next_phase1;
            }
            int Offset = (int)EntryBuffer[0xD0 >> 2] - (int)PeFileBase + (int)CumulativeSize;
            if (Offset && (unsigned int)Offset < PeFileSize)
            {
                Phase1Offset = (unsigned int)Offset;
                break;
            }
        }
next_phase1:
        ++Phase1Count;
    }

    // Phase2：在 Phase1 找到的偏移处继续搜索 0x512 / 0x53C 节区
    if (Phase1Offset)
    {
        InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + Phase1Offset), PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
        Phase2Count = 0;
        while (Phase2Count < 0x1F4)
        {
            if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                break;
            SectionSize = EntryBuffer[0x38 >> 2];
            CumulativeSize = EntryBuffer[0x40 >> 2];
            CumulativeSize += SectionSize;
            SectionDataPtr = EntryBuffer[0x48 >> 2];
            EntryBuffer[0x40 >> 2] = (ULONG)CumulativeSize;
            SectionType = *(unsigned short *)(SectionDataPtr + 6);
            if (SectionType == 0x512)
            {
                __int64 B8 = EntryBuffer[0x120 >> 2];
                unsigned int C8 = EntryBuffer[0x110 >> 2];
                if (B8 == 0x40000 && C8 && EntryBuffer[0xE8 >> 2] == 0x40)
                {
                    int Offset = (int)C8 - (int)PeFileBase + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < PeFileSize)
                    {
                        Phase1Offset = (unsigned int)Offset;
                        break;
                    }
                }
            }
            else if (SectionType == 0x53C)
            {
                __int64 D0 = EntryBuffer[0x108 >> 2];
                if (D0 == 0xF8 && Phase1Offset && Phase1Offset < PeFileSize)
                {
                    int Offset = Phase1Offset + 0x800;
                    if (Offset < (int)PeFileSize)
                    {
                        Phase1Offset = (unsigned int)Offset;
                        break;
                    }
                }
            }
            ++Phase2Count;
        }
    }

    if (Phase1Offset)
    {
        GtWrite(GtNtosExportSectionOffset, Phase1Offset);
        GtWrite(GtNtosExportSectionVa, Phase1Offset + NtoskrnlBase);
        GtWrite(GtNtosExportSectionSize, 0x800);
    }

    // Phase3：如果 Phase2 有结果，继续搜索 0x559 节区
    if (Phase1Offset)
    {
        Phase1Offset = (unsigned int)GtRead(GtNtosExportSectionOffset);
        if (Phase1Offset)
        {
            InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + Phase1Offset), PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
            Phase3Count = 0;
            while (Phase3Count < 0xA)
            {
                if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                    break;
                SectionSize = EntryBuffer[0x38 >> 2];
                CumulativeSize = EntryBuffer[0x40 >> 2];
                CumulativeSize += SectionSize;
                SectionDataPtr = EntryBuffer[0x48 >> 2];
                EntryBuffer[0x40 >> 2] = (ULONG)CumulativeSize;
                SectionType = *(unsigned short *)(SectionDataPtr + 6);
                if (SectionType == 0x559 && EntryBuffer[0xD0 >> 2])
                {
                    int Offset = (int)EntryBuffer[0xD0 >> 2] - (int)PeFileBase + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < PeFileSize)
                    {
                        GtWrite(GtNtosExportSectionOffset2, Offset);
                        GtWrite(GtNtosExportSectionVa2, Offset + NtoskrnlBase);
                    }
                    break;
                }
                ++Phase3Count;
            }
        }
    }

    Result = Phase1Offset;
    return Result;
}

// ParseNtExportSectionsWin10 -- 解析 NT 导出节区（Win10）
// Win10 专用版本：先按名称查找 .data 节，再执行三阶段扫描
__int64 ParseNtExportSectionsWin10(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase;
    __int64 PeFileBase;
    unsigned int PeFileSize;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>）又被取址当解码上下文，
                            //   不能只改类型；需与 CumulativeSize 家族同一轮按"角色拆分"处理
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int Phase1Offset = 0;
    unsigned int Phase2Count;
    ULONG EntryBuffer[0x80];
    unsigned int DataSectionOffset;
    unsigned int DataSectionVa;
    unsigned int ExportDirSize;

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    if (!NtoskrnlBase || !PeFileBase || !PeFileSize)
        return 0;

    // Win10 特有：按名称查找 .data 节
    DataSectionOffset = (unsigned int)FindPESectionByName((PUCHAR)PeFileBase, ".data");
    DataSectionVa = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)PeFileBase, ".data");
    if (DataSectionOffset && DataSectionOffset < PeFileSize && DataSectionVa && DataSectionVa < PeFileSize && DataSectionOffset + DataSectionVa <= PeFileSize)
    {
        GtWrite(GtNtosExportSectionOffset, DataSectionOffset);
        GtWrite(GtNtosExportSectionVa, DataSectionOffset + NtoskrnlBase);
        GtWrite(GtNtosExportSectionSize, DataSectionVa);
    }

    ExportDirSize = *(unsigned int *)(PeFileBase + 0x3C);
    ExportDirSize = *(unsigned int *)(ExportDirSize + PeFileBase + 0x28);
    if (!ExportDirSize || ExportDirSize >= PeFileSize)
        return 0;

    // Phase1：搜索 0xFE / 0x558 节区
    InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + ExportDirSize), PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    unsigned int Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x38 >> 2];
        CumulativeSize = EntryBuffer[0x40 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x48 >> 2];
        EntryBuffer[0x40 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(SectionDataPtr + 6);
        if (SectionType == 0xFE || SectionType == 0x558)
        {
            if (SectionType == 0x558)
            {
                __int64 F0 = EntryBuffer[0xF8 >> 2];
                if (!(F0 & 0x4000000) || !EntryBuffer[0xE0 >> 2] || Phase1Offset)
                    goto win10_next_phase1;
            }
            int Offset = (int)EntryBuffer[0xE0 >> 2] - (int)PeFileBase + (int)CumulativeSize;
            if (Offset && (unsigned int)Offset < PeFileSize)
            {
                Phase1Offset = (unsigned int)Offset;
                break;
            }
        }
win10_next_phase1:
        ++Phase1Count;
    }

    // Phase2：搜索 0x512 / 0x42E 节区
    if (Phase1Offset)
    {
        InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + Phase1Offset), PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
        Phase2Count = 0;
        while (Phase2Count < 0x1F4)
        {
            if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                break;
            SectionSize = EntryBuffer[0x38 >> 2];
            CumulativeSize = EntryBuffer[0x40 >> 2];
            CumulativeSize += SectionSize;
            SectionDataPtr = EntryBuffer[0x48 >> 2];
            EntryBuffer[0x40 >> 2] = (ULONG)CumulativeSize;
            SectionType = *(unsigned short *)(SectionDataPtr + 6);
            if (SectionType == 0x512)
            {
                __int64 B8 = EntryBuffer[0x130 >> 2];
                unsigned int C8 = EntryBuffer[0x120 >> 2];
                if (B8 == 0x40000 && C8 && EntryBuffer[0xF8 >> 2] == 0x40)
                {
                    int Offset = (int)C8 - (int)PeFileBase + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < PeFileSize)
                    {
                        Phase1Offset = (unsigned int)Offset;
                        break;
                    }
                }
            }
            else if (SectionType == 0x42E)
            {
                __int64 D0 = EntryBuffer[0x118 >> 2];
                if (D0 == 0xB && Phase1Offset && Phase1Offset < PeFileSize)
                {
                    Phase1Offset = Phase1Offset;
                    break;
                }
            }
            ++Phase2Count;
        }
    }

    if (Phase1Offset)
    {
        GtWrite(GtNtosExportSectionOffset2, Phase1Offset);
        GtWrite(GtNtosExportSectionVa2, Phase1Offset + NtoskrnlBase);
    }

    Result = Phase1Offset;
    return Result;
}

// SkipContextEntries — 跳过上下文条目 (0x14001239C)
// 根据条目计数偏移遍历上下文表，计算跳过后的下一个条目指针
_DWORD *__fastcall SkipContextEntries(_DWORD *ContextEntry)
{
    _DWORD *result;
    __int64 EntryCount;
    unsigned int CurrentEntry;

    result = ContextEntry + 2;
    if (*ContextEntry)
    {
        EntryCount = (unsigned int)*ContextEntry;
        do
        {
            CurrentEntry = result[19];
            result += 26;
            if (CurrentEntry > 1)
                result += 6 * CurrentEntry - 6;
            --EntryCount;
        } while (EntryCount);
    }
    return result;
}

// FindContextEntry — 查找上下文条目 (0x1400123C8)
// 在上下文表中搜索匹配的目标对象，找到返回 1，否则返回 0
char __fastcall FindContextEntry(__int64 TargetObject, _DWORD *ContextTable)
{
    char Result;
    _DWORD *CurrentEntry;
    int EntryIndex;
    unsigned int MaxCount;

    Result = 0;
    CurrentEntry = ContextTable + 2;
    EntryIndex = 0;
    if (*ContextTable)
    {
        while (*(_QWORD *)CurrentEntry)
        {
            if (TargetObject == *(_QWORD *)CurrentEntry)
                return 1;
            CurrentEntry += 26;
            MaxCount = CurrentEntry[19];
            if (MaxCount > 1)
                CurrentEntry += 6 * MaxCount - 6;
            if ((unsigned int)++EntryIndex >= *ContextTable)
                return Result;
        }
    }
    return Result;
}
