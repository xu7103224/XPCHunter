// ContextMgmt.c — 上下文/回调管理函数
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

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
__int64 CopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    if (!GtRead(GtEprocessExtField58|GtEprocessField27|0x400))
        InitKernelMemoryContext();

    char *v7 = (char *)GtRead(GtEprocessExtField58|GtEprocessField27|0x400);
    unsigned int v9 = (unsigned int)GtRead(GtEprocessExtField58|GtEprocessField28|0x400);

    if (v7 && v9 && v7 > (char *)MmSystemRangeStart && v9 < 0x100
        && CheckMemoryValid(v7) == 1
        && CheckMemoryValid(&v7[8 * v9 - 1]) == 1
        && a3
        && a4 >= 8 * (unsigned __int64)(v9 - 1) + 16
        && (unsigned __int64)a3 < MmUserProbeAddress
        && (unsigned __int64)a3 + a4 < MmUserProbeAddress)
    {
        ProbeForWrite(a3, a4, 8u);
        memset(a3, 0, a4);
        *a3 = v9;
        memmove(a3 + 2, v7, 8LL * v9);
        return 1;
    }
    return 0;
}

// CopyKernelDualArrayToUserBuffer — 复制内核双数组到用户缓冲区
// 对应原始驱动 sub_14006BDA4
// 将内核内存的双数组（两个并排数组，8 字节/项）复制到用户缓冲区
__int64 CopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    if (!GtRead(GtEprocessExtField48|GtEprocessField54|0x400))
        InitKernelMemoryContext();
    char *v7 = (char *)GtRead(GtEprocessExtField48|GtEprocessField54|0x400);
    unsigned int v9 = (unsigned int)GtRead(GtEprocessExtField47|GtEprocessField54|0x400);
    if (!v7 || !v9)
        return 0;
    if (v7 <= (char *)MmSystemRangeStart || v9 >= 0x100)
        return 0;
    if (CheckMemoryValid(v7) != 1)
        return 0;
    __int64 MaxCount = 8LL * v9;
    char *v10 = &v7[MaxCount];
    if (CheckMemoryValid(&v7[MaxCount - 1]) != 1)
        return 0;
    if (!a3)
        return 0;
    unsigned int v11 = v9 - 1;
    if (a4 < 8 * (unsigned __int64)(v9 - 1) + 16)
        return 0;
    if ((unsigned __int64)a3 >= MmUserProbeAddress || (unsigned __int64)a3 + a4 >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(a3, a4, 8u);
    memset(a3, 0, a4);
    *a3 = v9;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        memmove(a3 + 2, v7, MaxCount);
    }
    else
    {
        memmove(a3 + 2, v7, 8LL * v11);
        if (CheckMemoryValid(v10) == 1)
            *(_QWORD *)&a3[2 * v11 + 2] = *(_QWORD *)v10;
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
    __int64 v3 = OpenUSBPortSection();
    if (v3)
    {
        _QWORD *v4 = (_QWORD *)(v3 + 112);
        for (unsigned int v2 = 0; v2 <= 0x1B; v2++)
        {
            *(_DWORD *)pOutputBuffer = v2;
            *(_QWORD *)(pOutputBuffer + 16) = *v4;
            pOutputBuffer += 48;
            ++v4;
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
    __int64 *v3 = GtAlloc((GLOBAL_TABLE_INDEX)15824);
    char *v5 = (char *)v3 + 4;
    __int64 v6 = pSourceTable - (__int64)v3;
    char v2 = 0;
    for (int v4 = 28; v4; v4--)
    {
        *(_DWORD *)&v5[v6] = *(_DWORD *)v5;
        if (*(_DWORD *)v5 && *((_DWORD *)v5 - 1) == 1)
        {
            v2 = 1;
            *(_QWORD *)&v5[v6 + 4] = *(_QWORD *)(v5 + 4);
            *(_OWORD *)&v5[v6 + 22] = *(_OWORD *)(v5 + 12);
        }
        v5 += 48;
    }
    return v2;
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
    __int64 v3 = OpenVolumeDriverSection();
    if (v3)
    {
        _QWORD *v4 = (_QWORD *)(v3 + 112);
        unsigned int v2 = 0;
        do
        {
            *(_DWORD *)OutputBuffer = v2++;
            *(_QWORD *)(OutputBuffer + 16) = *v4;
            OutputBuffer += 48;
            ++v4;
        }
        while (v2 <= 0x1B);
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
__int64 SetUSBPortServiceTableEntry(ULONG *a1)
{
    __int64 v3 = OpenUSBPortSection();
    if (v3)
    {
        unsigned int v4 = *a1;
        if (v4 <= 0x1B)
        {
            WritePhysicalMemoryQword(v3 + 8 * v4 + 112, *((__int64 *)a1 + 1));
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
__int64 ValidateSingleHookEntry(__int64 a1)
{
    __int64 v2 = *(_QWORD *)(a1 + 8);
    if (v2)
    {
        if (v2 != *(_QWORD *)(a1 + 16))
            *(_BYTE *)a1 = 1;
        if (CheckMemoryValid((void *)(v2 + 15)) == 1)
        {
            if ((unsigned int)MemoryCompare(*(_QWORD *)(a1 + 8), (char *)(a1 + 24), 0x10u))
            {
                char IsOriginal = *(_BYTE *)a1 == 0;
                *(_BYTE *)(a1 + 1) = 1;
                if (IsOriginal)
                {
                    unsigned int i;
                    for (i = 0; i < 0x10; i++)
                    {
                        if (!CheckMemoryValid((void *)(*(_QWORD *)(a1 + 8) + i)))
                            break;
                    }
                    if (i && ReturnFalseStub() == 1)
                        *(_QWORD *)(a1 + 16) = *(unsigned int *)(a1 + 12);
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
__int64 WriteThreadContextEntryWin10(ULONG *a1)
{
    __int64 v3 = OpenVolumeDriverSection();
    if (v3)
    {
        unsigned int v4 = *a1;
        if (v4 <= 0x1B)
        {
            WritePhysicalMemoryQword(v3 + 8 * v4 + 112, *((__int64 *)a1 + 1));
            return 1;
        }
    }
    return 0;
}