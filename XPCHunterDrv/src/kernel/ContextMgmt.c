// ContextMgmt.c — 上下文/回调管理函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"
#pragma warning(disable:4700)

// BuildCallbackContextHookTargets
void BuildCallbackContextHookTargets(void)
{
    return;
}

// BuildContextTableFromNtFile
void BuildContextTableFromNtFile(void)
{
    return;
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
                if (pCurrent <= MmSystemRangeStart)
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

// InitCallbackContextHookTable
void InitCallbackContextHookTable(void)
{
    return;
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

// InitProcessContextHookTable
void InitProcessContextHookTable(void)
{
    return;
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

// InitWin32kTableByVersion
void InitWin32kTableByVersion(void)
{
    return;
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
    ServiceCount = GtRead(GtSdstServiceCount);
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
        ResolveKernelModuleFunctionAddrs(0, 0, 0);
        GtIndex2 = GtKiFastCallEntryAddr | GtEprocessField06;
        if (Flags != 1)
            GtIndex2 = GtNtQuerySystemInformationFunc | GtEprocessField55;
        QueryFunc = (__int64 (__fastcall *)(__int64, char *))GtRead(GtIndex2);
    }
    if (!GtRead(GtKiInsertQueueApcFunc))
    {
        InitHookFunctionTable(0, 0, 0, 0);
        GtRead(GtKiInsertQueueApcFunc);
    }
    if (Flags == 1 && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28 && !GtRead(GtCallbackField12))
    {
        ScanKernelModulePESectionsEx(0, 0, 0, 0, 0, 0);
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
        QueryResult = QueryFunc(ContextBuffer, &NameBuffer);
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
        SyscallOffset = GtRead(GtCallbackField21);
        if (SyscallOffset)
            goto LABEL_10;
        DispatchObjectOperationInit((__int64)pFileBuffer, FileSize);
        SyscallOffset = GtRead(GtCallbackField21);
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
            pEndPtr = (_DWORD)pFileBuffer + FileSize;
            DataSectionOffset = FindObjectOperationDataSection(
                (__int64)pFileBuffer + FileOffset,
                (unsigned int)pFileBuffer + FileSize,
                (int)pFileBuffer);
            if (DataSectionOffset)
            {
                if (DataSectionOffset < FileSize)
                {
                    VersionOffset = QueryObjectOperationByVersion(
                        (__int64)pFileBuffer + DataSectionOffset,
                        pEndPtr,
                        (int)pFileBuffer);
                    if (VersionOffset)
                    {
                        if (VersionOffset < FileSize)
                        {
                            BaseOffset = FindObjectOperationBaseOffset(
                                (__int64)pFileBuffer + VersionOffset,
                                pEndPtr,
                                (int)pFileBuffer);
                            if (BaseOffset)
                                GtWrite(GtCallbackField22, BaseOffset);
                        }
                    }
                }
            }
        }
        goto LABEL_17;
    }
    SyscallOffset = GtRead(GtCallbackField21);
    if (SyscallOffset || (DispatchObjectOperationInit(0, 0), (SyscallOffset = GtRead(GtCallbackField21)) != 0))
    {
        if (ReadNtOsKrnlFile(&pFileBuffer, &FileSize))
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
    InputLen = GetStringLength((_WORD *)InputName);
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
    __int64 MiscInfo;
    __int64 ImageBase;
    unsigned int ImageSize;
    __int64 NtoskrnlBase;
    unsigned int BaseOffset;
    int Phase1Offset;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    __int64 PeContext;
    char EntryBuffer[80];

    Result = 0;
    ImageBase = GtRead(GtNtoskrnlPeFileBase);
    ImageSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead(GtMsrTableBaseOffset);
    if (!ImageBase || !ImageSize || !NtoskrnlBase || !BaseOffset || BaseOffset >= ImageSize)
        return Result;

    // 阶段1：搜索 EntryType 0x558/0x559 的节区
    PeContext = 0;
    InitPESectionReadContext((char *)ImageBase + BaseOffset, ImageSize - BaseOffset, 2, &PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 5)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    InitPESectionReadContext((char *)ImageBase + Phase1Offset, ImageSize - Phase1Offset, 2, &PeContext, -1, 0, 0, 0);
    Phase1Count = 0;
    while (Phase1Count < 0x100)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
                if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    __int64 PeContext;
    char EntryBuffer[80];

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
    InitPESectionReadContext((char *)ImageBase + BaseOffset, ImageSize - BaseOffset, 2, &PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0x64)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    InitPESectionReadContext((char *)ImageBase + Phase1Offset, ImageSize - Phase1Offset, 2, &PeContext, -1, 0, 0, 0);
    LoopIndex = 0;
    while (LoopIndex < 0x100)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    __int64 PeContext;
    char EntryBuffer[80];

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
    InitPESectionReadContext((char *)ImageBase + BaseOffset, ImageSize - BaseOffset, 2, &PeContext, -1, 0, 0, 0);
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0x14)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    InitPESectionReadContext((char *)ImageBase + Phase1Offset, ImageSize - Phase1Offset, 2, &PeContext, -1, 0, 0, 0);
    LoopIndex = 0;
    while (LoopIndex < 0x100)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
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
    ModuleSize = GtRead(GtEprocessField23);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    KernelPESectionByType = FindKernelPESectionByType(GtTotalSize | GtIrpBufferSize | GtPathBuffer00);
    KnownSectionCount = GtRead(GtWin32kServiceEntryCount);

    if (ModuleBase && ModuleSize && NtImageBase && KernelPESectionByType && KernelPESectionByType < KnownSectionCount)
    {
        SyscallOffset = ResolveSyscallToAddress(KernelPESectionByType);
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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    unsigned int EntryFlags;
    __int64 FieldValue;
    unsigned int SectionSize;
    __int64 SectionDataPtr;

    ModuleBase = GtRead(GtEprocessField22);
    ModuleSize = GtRead(GtEprocessField23);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = GtRead(GtNtoskrnlImageSize);

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
                    (PUCHAR)(ModuleBase + SectionIndex),
                    ModuleSize - SectionIndex,
                    2,
                    0,
                    -1,
                    0,
                    0,
                    (PUCHAR)&ReadContext);
                FoundFlag = 0;
                for (i = 0; i < 0x64; i++)
                {
                    result = ReadPESectionEntry(&ReadContext, SectionEntry);
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
                (PUCHAR)(ModuleBase + SectionIndex),
                ModuleSize - SectionIndex,
                2,
                0,
                -1,
                0,
                0,
                (PUCHAR)&ReadContext);
            for (j = 0; j < 0x14; j++)
            {
                result = ReadPESectionEntry(&ReadContext, SectionEntry);
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
    unsigned __int64 AddressValue;
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


// ParseNtExportSectionsV4 -- 解析 NT 导出节区 V4
// 对应原始驱动 sub_1400382FC
void ParseNtExportSectionsV4(void)
{
    return;
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
    __int64 PeContext;
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
    InitPESectionReadContext((PUCHAR)PeFileBase + ExportDirSize, PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
        InitPESectionReadContext((PUCHAR)PeFileBase + Phase1Offset, PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
            InitPESectionReadContext((PUCHAR)PeFileBase + Phase1Offset, PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int Phase1Offset = 0;
    unsigned int Phase2Count;
    unsigned int Phase3Count;
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
    InitPESectionReadContext((PUCHAR)PeFileBase + ExportDirSize, PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
        InitPESectionReadContext((PUCHAR)PeFileBase + Phase1Offset, PeFileSize - Phase1Offset, 2, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
