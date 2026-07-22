// MemoryCleanup.c â åå­æ¸ç/éæ¾å½æ°
// 1:1 å¤å»èª View++_Driver64.sysï¼PCHunter é©±å¨ï¼
#include "..\inc\XPCHunterDrv.h"

// AllocProcessInfoBuffer — 分配进程信息缓冲区
// 对应原始驱动 sub_1400813F0
// 从全局表分配结构体，返回指针指向缓冲区中的子结构
void *AllocProcessInfoBuffer(void)
{
    __int64 *Buffer = GtAlloc(GtCommandHandlerBase);
    Buffer[158] = 0;
    Buffer[159] = 0;
    memset(Buffer + 198, 0, 0xD8);
    Buffer[237] = 0;
    Buffer[238] = 0;
    Buffer[239] = 0;
    Buffer[240] = 0;
    memset(Buffer + 249, 0, 0x70);
    Buffer[273] = 0;
    Buffer[274] = 0;
    Buffer[275] = 0;
    Buffer[276] = 0;
    return Buffer + 249;
}

// CallKernelFreeEntryV1 — 调用内核释放条目 V1（被 DispatchKernelMemoryCleanup 调用）
// 对应原始驱动 sub_1400421B4
// 从 GT 17105 获取释放函数指针，验证虚拟地址有效性后，调用该函数释放地址结构中的第 3 个字段指向的内存
__int64 CallKernelFreeEntryV1(_QWORD *VirtualAddress)
{
    char Result;
    void (*pFreeFunc)(_QWORD);

    Result = 0;
    pFreeFunc = (void (*)(_QWORD))GtRead(GtTotalSize | GtCallbackField06);

    if (pFreeFunc && MmIsAddressValid(VirtualAddress) == 1 && MmIsAddressValid((char *)VirtualAddress + 79) == 1)
    {
        pFreeFunc(VirtualAddress[3]);
        return 1;
    }
    return Result;
}

// CallKernelFreeEntryV2 — 调用内核释放条目 V2（被 DispatchKernelMemoryCleanup 调用）
// 对应原始驱动 sub_140042210
// 除了释放内存对象外，还会遍历回调链表清理匹配的回调条目
__int64 CallKernelFreeEntryV2(__int64 TargetAddress)
{
    char Result;
    void (*pFreeFunc)(_QWORD);
    _QWORD *pEntryPtr;
    char *pCallbackList;
    __int64 CallbackListSize;
    _DWORD *pCounter;
    char *pListEnd;
    _QWORD *pEntryObj;
    __int64 pDataPtr;

    Result = 0;
    pFreeFunc = (void (*)(_QWORD))GtRead(GtTotalSize | GtCallbackField06);

    if (pFreeFunc)
    {
        if ((TargetAddress & 0xFFFFFFF8) != 0
            && MmIsAddressValid((PVOID)((unsigned int)TargetAddress & 0xFFFFFFF8)) == 1
            && MmIsAddressValid((PVOID)(((unsigned int)TargetAddress & 0xFFFFFFF8) + 15)) == 1)
        {
            pEntryPtr = *(_QWORD **)(((unsigned int)TargetAddress & 0xFFFFFFF8) + 8);
            if (pEntryPtr)
            {
                if (MmIsAddressValid(pEntryPtr) == 1 && MmIsAddressValid((char *)pEntryPtr + 39) == 1)
                {
                    pFreeFunc(*pEntryPtr);
                    Result = 1;
                }
            }
        }
    }

    pCallbackList = (char *)GtRead(GtKernelDataField38);
    CallbackListSize = GtRead(GtKernelDataField40);
    pCounter = (_DWORD *)CallbackListSize;

    if (pCallbackList && CallbackListSize)
    {
        pListEnd = &pCallbackList[(unsigned int)GtRead(GtKernelDataField39)];
        while (pCallbackList < pListEnd && MmIsAddressValid(pCallbackList))
        {
            if (TargetAddress == *(_QWORD *)pCallbackList)
            {
                *(_QWORD *)pCallbackList = 0;
                if (*pCounter)
                    --*pCounter;

                pEntryObj = (_QWORD *)((unsigned int)TargetAddress & 0xFFFFFFF8);
                if (MmIsAddressValid(pEntryObj) == 1 && MmIsAddressValid((char *)pEntryObj + 15) == 1)
                {
                    pDataPtr = pEntryObj[1];
                    if (MmIsAddressValid((PVOID)pDataPtr) == 1 && MmIsAddressValid((PVOID)(pDataPtr + 39)) == 1)
                        ExFreePoolWithTag((PVOID)pDataPtr, 0);
                    ExFreePoolWithTag(pEntryObj, 0);
                }
                return 1;
            }
            pCallbackList += 8;
        }
    }
    return Result;
}

// CleanupProcessMemoryEntry — 清理进程内存条目
// 对应原始驱动 sub_140044B00
// 调用清理回调处理目标条目，然后遍历链表查找匹配条目并调用释放回调
__int64 CleanupProcessMemoryEntry(_QWORD *pTargetEntry)
{
    int IterCount = 0;
    char Result = 0;
    void (__fastcall *pCleanupCallback)(_QWORD *) = (void (__fastcall *)(_QWORD *))GtRead((GLOBAL_TABLE_INDEX)0x43D9);

    if (pCleanupCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pCleanupCallback(pTargetEntry);
        Result = 1;
    }

    _QWORD *pExAllocListHead = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField24 | 0x800));
    void (__fastcall *pFreeCallback)(_QWORD *) = (void (__fastcall *)(_QWORD *))GtRead((GLOBAL_TABLE_INDEX)0x43E8);

    if (pExAllocListHead && pFreeCallback && MmIsAddressValid(pExAllocListHead) == 1)
    {
        _QWORD **pListHead = (_QWORD **)*pExAllocListHead;
        if (pListHead && MmIsAddressValid(pListHead) == 1)
        {
            _QWORD **pSentinel = pListHead + 2;
            if (MmIsAddressValid(pListHead + 2) == 1)
            {
                for (_QWORD *pCurrent = *pSentinel; pCurrent != (_QWORD *)pSentinel; pCurrent = (_QWORD *)*pCurrent)
                {
                    if (pCurrent <= MmSystemRangeStart)
                        break;
                    if (MmIsAddressValid(pCurrent) != 1)
                        break;
                    if (++IterCount > 0x1000)
                        break;
                    if (pCurrent == pTargetEntry)
                    {
                        pFreeCallback(pTargetEntry);
                        return 1;
                    }
                }
            }
        }
    }
    return Result;
}

// ClearKernelObjectEntry — 清除内核对象条目
// 对应原始驱动 sub_140042374
// 释放目标地址，遍历 SSDT 表清理匹配条目，支持 Win7/Win10
__int64 ClearKernelObjectEntry(__int64 TargetAddress)
{
    char Result = 0;
    int IsWin7 = GtRead(GtEprocessField28);
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    void (__fastcall *pFreeFunc)(__int64, __int64) = (void (__fastcall *)(__int64, __int64))GtRead((GLOBAL_TABLE_INDEX)0x41A8);
    if (pFreeFunc)
    {
        __int64 FreeParam;
        if (IsWin7)
            FreeParam = TargetAddress;
        else
        {
            if (MmIsAddressValid((PVOID)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 8)) != 1)
                goto SKIP_FREE;
            FreeParam = *(_QWORD *)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 8);
        }
        pFreeFunc(FreeParam, 1);
        Result = 1;
    }
SKIP_FREE:
    _QWORD *pSsdtTable = (_QWORD *)GtRead(GtEprocessField80);
    _DWORD *pCounterEnd = (_DWORD *)GtRead(GtEprocessField81);
    if (TargetAddress && pSsdtTable && pCounterEnd)
    {
        _DWORD *pCounter = NULL;
        _DWORD *pTempCounter;
        if (BuildNumber > 0x1770)
        {
            if (BuildNumber > 0x1DB1)
            {
                pTempCounter = pSsdtTable + 512;
                if (BuildNumber == 9200)
                    pCounter = pSsdtTable + 512;
                else
                {
                    if (BuildNumber < 0x3839 || BuildNumber == 14393)
                        pCounter = pCounterEnd - 1;
                    else if (BuildNumber == 15063)
                        pCounter = pCounterEnd + 2;
                    else if (BuildNumber == 16299)
                        pCounter = pCounterEnd + 1;
                    else if (BuildNumber == 17134 || BuildNumber == 17763)
                        pCounter = pCounterEnd - 1;
                    else
                    {
                        pCounter = pCounterEnd + 4;
                        if (BuildNumber != 18362)
                            pCounter = pCounterEnd - 2;
                    }
                }
            }
            else
            {
                pCounter = pCounterEnd - 1;
                pTempCounter = pCounterEnd - 1;
            }
        }
        else
            pTempCounter = pCounterEnd;

        while (pSsdtTable < (_QWORD *)pTempCounter && MmIsAddressValid(pSsdtTable))
        {
            if (TargetAddress == *pSsdtTable && MmIsAddressValid((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64)) == 1)
            {
                if (BuildNumber >= 0x1771 && *(_BYTE *)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 0x10))
                {
                    if (*pCounter)
                        --*pCounter;
                }
                else if (!IsWin7 && *pCounterEnd)
                    --*pCounterEnd;
                *pSsdtTable = 0;
                if (!IsWin7)
                    ExFreePoolWithTag((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64), 0);
                return 1;
            }
            ++pSsdtTable;
        }
    }
    return Result;
}

// ClearSsdtRelatedEntry — 清除 SSDT 相关条目
// 对应原始驱动 sub_140042718
// 释放目标地址，遍历 SSDT3 表清理匹配项
__int64 ClearSsdtRelatedEntry(__int64 TargetAddress)
{
    char Result = 0;
    int IsWin7 = GtRead(GtEprocessField28);
    void (__fastcall *pFreeFunc)(__int64) = (void (__fastcall *)(__int64))GtRead((GLOBAL_TABLE_INDEX)0x41B7);
    if (pFreeFunc)
    {
        if (IsWin7)
            pFreeFunc(TargetAddress);
        else
        {
            if (MmIsAddressValid((PVOID)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 8)) == 1)
            {
                __int64 FreeParam = *(_QWORD *)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 8);
                pFreeFunc(FreeParam);
            }
        }
        Result = 1;
    }
    _QWORD *pSsdtTable = (_QWORD *)GtRead(GtEprocessField82);
    __int64 SsdtTableEnd = GtRead(GtEprocessField83);
    _DWORD *pCounter = (_DWORD *)SsdtTableEnd;
    if (pSsdtTable && SsdtTableEnd)
    {
        unsigned __int64 SsdtOffset = (unsigned __int64)GetSsdtTableOffset((__int64)pSsdtTable, SsdtTableEnd);
        while ((unsigned __int64)pSsdtTable < SsdtOffset && MmIsAddressValid(pSsdtTable))
        {
            if (TargetAddress == *pSsdtTable)
            {
                *pSsdtTable = 0;
                if (!IsWin7)
                {
                    if (*pCounter)
                        --*pCounter;
                    ExFreePoolWithTag((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64), 0);
                }
                return 1;
            }
            ++pSsdtTable;
        }
    }
    return Result;
}

// CopyRegistryContextEntryArray moved to Registry.c

// CopyThreadContextTable moved to ThreadMgmt.c
// CopyFsFilterEntryTable moved to Minifilter.c

// DispatchFreeProcessMemory — 释放进程内存分发函数
// 对应原始驱动 sub_140044C00
__int64 DispatchFreeProcessMemory(char *VirtualAddress)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x42EE)
        return FreeProcessMemoryEntry((__int64)VirtualAddress);
    if (VirtualAddress)
    {
        void (__fastcall *pFreeFunc)(char *) = (void (__fastcall *)(char *))GtRead(GtTotalSize|GtEprocessExtField44|GtEprocessField86);
        if (pFreeFunc && MmIsAddressValid(VirtualAddress) == 1 && MmIsAddressValid(VirtualAddress + 71) == 1)
        {
            pFreeFunc(VirtualAddress);
            return 1;
        }
    }
    return 0;
}

// DispatchKernelMemoryCleanup — 内核内存清理分发函数
// 对应原始驱动 sub_140042150
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber == 2600 || BuildNumber == 3790)
        return CallKernelFreeEntryV2((__int64)VirtualAddress);
    if (BuildNumber >= 0x1770)
        return CallKernelFreeEntryV1(VirtualAddress);
    return 0;
}

// EnumKernelMemoryContext — 枚举内核内存上下文
// 对应原始驱动 sub_14006A968
// 遍历内核内存上下文链表，根据构建号选择步长写入输出缓冲区
__int64 EnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, unsigned int a4)
{
    __int64 EprocessExtField58 = GtRead(GtEprocessExtField58|GtEprocessField32|0x400);
    if (!EprocessExtField58)
    {
        InitKernelMemoryContext();
        EprocessExtField58 = GtRead(GtEprocessExtField58|GtEprocessField32|0x400);
    }
    _QWORD *v7 = (_QWORD *)EprocessExtField58;
    unsigned int v8 = (unsigned int)GtRead(GtEprocessExtField42|GtEprocessField54|0x400);
    if (!v7 || !v8)
        return 0;
    if (v7 <= (_QWORD *)MmSystemRangeStart)
        return 0;
    if (*v7 <= (unsigned __int64)MmSystemRangeStart)
        return 0;
    _QWORD *v9 = (_QWORD *)(*v7 + v8);
    if (CheckMemoryValid(v9) != 1)
        return 0;
    if (!a3 || a4 < 0x18)
        return 0;
    if ((unsigned __int64)a3 >= MmUserProbeAddress || (unsigned __int64)a3 + a4 >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(a3, a4, 8u);
    memset(a3, 0, a4);
    *a3 = 0;
    unsigned __int64 v10 = ((a4 - 24) >> 4) + 1;
    unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);

    if (BuildNumber < 0x4563)
    {
        if (BuildNumber < 0x23F0)
        {
            // Win7 (7600/7601 specific)
            if (BuildNumber == 7600
                || BuildNumber == 7601)
            {
                for (unsigned int i = 0; i < 3 && (_DWORD)v10
                    && CheckMemoryValid(v9) == 1
                    && CheckMemoryValid((char *)v9 + 15) == 1; i++)
                {
                    if (v9[1])
                    {
                        a3[4 * *a3 + 2] = *(_DWORD *)v9;
                        *(_QWORD *)&a3[4 * (*a3)++ + 4] = v9[1];
                        v10--;
                    }
                    v9 += 2;
                }
            }
        }
        else
        {
            // Win8.x
            for (unsigned int j = 0; j < 5 && (_DWORD)v10
                && CheckMemoryValid(v9) == 1
                && CheckMemoryValid((char *)v9 + 15) == 1; j++)
            {
                if (v9[1])
                {
                    a3[4 * *a3 + 2] = *(_DWORD *)v9;
                    *(_QWORD *)&a3[4 * (*a3)++ + 4] = v9[1];
                    v10--;
                }
                v9 += 2;
            }
        }
    }
    else
    {
        // Win10+
        for (unsigned int k = 0; k < 5 && (_DWORD)v10
            && CheckMemoryValid(v9) == 1
            && CheckMemoryValid((char *)v9 + 31) == 1; k++)
        {
            if (v9[1])
            {
                a3[4 * *a3 + 2] = *(_DWORD *)v9;
                *(_QWORD *)&a3[4 * (*a3)++ + 4] = v9[1];
                v10--;
            }
            v9 += 4;
        }
    }
    return 1;
}

// FreeObjectByCallback — 通过回调释放对象
// 对应原始驱动 sub_1400429EC
// 从 GT 17153 获取释放回调，验证地址后调用回调释放对象
__int64 FreeObjectByCallback(_QWORD *pObjectEntry)
{
    void (__fastcall *pFreeCallback)(_QWORD) = (void (__fastcall *)(_QWORD))GtRead((GLOBAL_TABLE_INDEX)0x4301);
    if (pFreeCallback && MmIsAddressValid(pObjectEntry) == 1 && MmIsAddressValid((char *)pObjectEntry + 15) == 1)
    {
        pFreeCallback(pObjectEntry[1]);
        return 1;
    }
    return 0;
}

// FreeProcessMemoryEntry — 释放进程内存条目
// 对应原始驱动 sub_140044C7C
// 先通过释放回调释放目标地址，然后遍历 Win8+ 链表头数组查找匹配条目并 ExFreePoolWithTag
char FreeProcessMemoryEntry(__int64 TargetAddress)
{
    char Result = 0;
    if (TargetAddress)
    {
        void (__fastcall *pFreeCallback)(unsigned __int64) = (void (__fastcall *)(unsigned __int64))GtRead(GtTotalSize|GtEprocessExtField44|GtEprocessField86);
        if (pFreeCallback
            && (TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) != 0
            && MmIsAddressValid((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64)) == 1
            && MmIsAddressValid((PVOID)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 47)) == 1)
        {
            pFreeCallback(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64);
            Result = 1;
        }
        _QWORD *pWin8ListHead = (_QWORD *)GtRead(GtEprocessField26|0x800);
        _DWORD *pCounter = (_DWORD *)GtRead(GtEprocessField27|0x800);
        if (pWin8ListHead && pCounter)
        {
            unsigned int BuildNumber = GtRead(GtWindowsBuildNumber);
            unsigned int EntryIndex = 0;
            unsigned int EntryCount = BuildNumber < 0x3FAB ? 8 : 32;
            while (MmIsAddressValid(pWin8ListHead))
            {
                if (TargetAddress == *pWin8ListHead)
                {
                    void *pAlignedAddr = (void *)(*pWin8ListHead & 0xFFFFFFFFFFFFFFF0ui64);
                    if (pAlignedAddr && MmIsAddressValid(pAlignedAddr) == 1)
                    {
                        if (*pCounter)
                            --*pCounter;
                        *pWin8ListHead = 0;
                        ExFreePoolWithTag(pAlignedAddr, 0);
                        return 1;
                    }
                }
                ++EntryIndex;
                ++pWin8ListHead;
                if (EntryIndex >= EntryCount)
                    return Result;
            }
        }
    }
    return Result;
}

// FreeProcessMemoryAllocation — 释放进程内存分配
// 对应原始驱动 sub_140045160
__int64 FreeProcessMemoryAllocation(__int64 TargetAddress)
{
    if (!TargetAddress)
        return 0;
    void (__fastcall *pFreeCallback)(_QWORD) = (void (__fastcall *)(_QWORD))GtRead(GtTotalSize|GtEprocessExtField58|GtEprocessField60);
    if (pFreeCallback && (TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) != 0
        && MmIsAddressValid((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64)) == 1
        && MmIsAddressValid((PVOID)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 39)) == 1)
    {
        pFreeCallback(*(_QWORD *)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 0x20));
    }
    _QWORD *pModuleBaseTable = (_QWORD *)GtRead(GtDisableHookProtectionAddr2|GtPathBuffer03);
    _DWORD *pCounter = (_DWORD *)GtRead((GLOBAL_TABLE_INDEX)2080);
    if (pModuleBaseTable && pCounter)
    {
        for (unsigned int EntryIndex = 0; EntryIndex < 8; EntryIndex++)
        {
            if (!MmIsAddressValid(pModuleBaseTable))
                break;
            if (TargetAddress == *pModuleBaseTable)
            {
                void *pAlignedAddr = (void *)(*pModuleBaseTable & 0xFFFFFFFFFFFFFFF0ui64);
                if (pAlignedAddr && MmIsAddressValid(pAlignedAddr) == 1)
                {
                    if (*pCounter)
                        --*pCounter;
                    *pModuleBaseTable = 0;
                    ExFreePoolWithTag(pAlignedAddr, 0);
                    return 1;
                }
            }
            ++pModuleBaseTable;
        }
    }
    return 0;
}

// FreeProcessMemoryAllocationEx — 释放进程内存分配（扩展版）
// 对应原始驱动 sub_140044E5C
__int64 FreeProcessMemoryAllocationEx(_QWORD *pTargetEntry)
{
    char Result = 0;
    void (__fastcall *pFreeCallback)(_QWORD) = (void (__fastcall *)(_QWORD))GtRead(GtUninstallHookSyscallPeOffset|GtEprocessField188|0x100);
    if (pFreeCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pFreeCallback(pTargetEntry[3]);
        Result = 1;
    }
    PVOID *pSectionListHead = (PVOID *)GtRead(GtEprocessField30|0x800);
    if (pSectionListHead && MmIsAddressValid(pSectionListHead) == 1)
    {
        int IterationCount = 0;
        PVOID *pCurrentNode = pSectionListHead;
        PVOID *pNextNode;
        if (*pSectionListHead != pSectionListHead)
        {
            do
            {
                if (*pCurrentNode <= MmSystemRangeStart) break;
                if (MmIsAddressValid(*pCurrentNode) != 1) break;
                if ((unsigned int)++IterationCount > 0x1000) break;
                pNextNode = (PVOID *)*pCurrentNode;
                if (*pCurrentNode == (PVOID)pTargetEntry)
                {
                    *pCurrentNode = *pNextNode;
                    ExFreePoolWithTag(pTargetEntry, 0x494D4E4Bu);
                    return 1;
                }
                pCurrentNode = (PVOID *)*pCurrentNode;
            }
            while (*pNextNode != pSectionListHead);
        }
    }
    return Result;
}

// FreeProcessMemoryBuffer — 释放进程内存缓冲区
// 对应原始驱动 sub_14004510C
// 通过 GT 17381 的回调函数释放目标进程内存缓冲区
__int64 FreeProcessMemoryBuffer(PVOID VirtualAddress)
{
    void (__fastcall *pFreeFunc)(PVOID) = (void (__fastcall *)(PVOID))GtRead(GtTotalSize|GtEprocessExtField47|GtEprocessField86);
    if (pFreeFunc && VirtualAddress && MmIsAddressValid(VirtualAddress) == 1)
    {
        pFreeFunc(VirtualAddress);
        return 1;
    }
    return 0;
}

// InitKernelObjectHeader — 初始化内核对象头
// 对应原始驱动 sub_14007E034
char InitKernelObjectHeader(char *VirtualAddress)
{
    int v2 = (int)GtRead(GtEprocessField53);
    int v3 = (int)GtRead(GtEprocessField94);
    int v4 = (int)GtRead(GtEprocessField95);
    unsigned int v6 = (unsigned int)GtRead(GtObjectTypeCount);
    if (!v2 || v3 == -1 || !v4 || !v6)
        return 0;
    if (MmIsAddressValid(VirtualAddress) != 1)
        return 0;
    if (MmIsAddressValid(&VirtualAddress[v6 - 1]) != 1)
        return 0;
    *(_DWORD *)&VirtualAddress[v3] &= ~1u;
    ModifyObjectHeaderFlagsByVersion((__int64)VirtualAddress, 1);
    VirtualAddress[v2] = 5;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
        *(_DWORD *)&VirtualAddress[v4] = 0;
    return 1;
}

// ReadKernelMemoryToUserBuffer — 读取内核内存到用户缓冲区
// 对应原始驱动 sub_14006AFEC
// 读取 GT 2000（内核内存上下文指针），验证后复制 QWORD 到用户缓冲区
__int64 ReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    __int64 EprocessExtField58 = GtRead(GtEprocessExtField58|GtEprocessField54|0x400);
    if (!EprocessExtField58)
    {
        InitKernelMemoryContext();
        EprocessExtField58 = GtRead(GtEprocessExtField58|GtEprocessField54|0x400);
    }
    _QWORD *v8 = (_QWORD *)EprocessExtField58;
    if (v8 && v8 > (_QWORD *)MmSystemRangeStart && CheckMemoryValid(v8) == 1
        && a3 && a4 == 8
        && (unsigned __int64)a3 < MmUserProbeAddress
        && (unsigned __int64)(a3 + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(a3, 8u, 8u);
        *a3 = 0;
        *a3 = *v8;
        return 1;
    }
    return 0;
}

// UnlinkFromMemoryBlockList — 从内存块链表中摘除指定指针
// 对应原始驱动 sub_140045370
__int64 UnlinkFromMemoryBlockList(PVOID *pTargetPointer)
{
    PVOID **pListHead = (PVOID **)GtRead(GtEprocessField28|0x800);
    if (!pListHead || MmIsAddressValid(pListHead) != 1)
        return 0;
    PVOID *pCurrentNode = *pListHead;
    int IterationCount = 0;
    while (pCurrentNode != (PVOID *)pListHead)
    {
        if (pCurrentNode <= MmSystemRangeStart) break;
        if (MmIsAddressValid(pCurrentNode) != 1) break;
        if ((unsigned int)++IterationCount > 0x1000) break;
        if (pCurrentNode == pTargetPointer)
        {
            if (MmIsAddressValid(*pCurrentNode) == 1)
            {
                PVOID *pPrevEntry = (PVOID *)*pCurrentNode;
                PVOID **pNextEntry = (PVOID **)pCurrentNode[1];
                pPrevEntry[1] = pNextEntry;
                *pNextEntry = pPrevEntry;
                return 1;
            }
            return 0;
        }
        pCurrentNode = (PVOID *)*pCurrentNode;
    }
    return 0;
}

// UnlinkProcessMemoryBlock — 解除进程内存块链接
// 对应原始驱动 sub_140045260
__int64 UnlinkProcessMemoryBlock(ULONG_PTR *pTargetEntry)
{
    char Result = 0;
    void (__fastcall *pCleanupCallback)(_QWORD) = (void (__fastcall *)(_QWORD))GtRead(GtTotalSize|GtEprocessExtField58|GtEprocessField66);
    if (pCleanupCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pCleanupCallback(pTargetEntry[4]);
        Result = 1;
    }
    _QWORD *pType2ListHead = (_QWORD *)GtRead(GtEprocessField23|0x800);
    void (__fastcall *pFreeCallback)(_QWORD) = (void (__fastcall *)(_QWORD))GtRead(GtObjectProtectCallback);
    int IterationCount = 0;
    if (pType2ListHead && pFreeCallback && MmIsAddressValid(pType2ListHead) == 1)
    {
        for (_QWORD *pCurrentNode = (_QWORD *)*pType2ListHead; pCurrentNode != pType2ListHead; pCurrentNode = (_QWORD *)*pCurrentNode)
        {
            if (pCurrentNode <= MmSystemRangeStart) break;
            if (MmIsAddressValid(pCurrentNode) != 1) break;
            if ((unsigned int)++IterationCount > 0x1000) break;
            if (pCurrentNode == (_QWORD *)pTargetEntry)
            {
                if (MmIsAddressValid((PVOID)*pCurrentNode) == 1)
                {
                    ObfDereferenceObject((PVOID)pTargetEntry[2]);
                    pFreeCallback(pTargetEntry[4]);
                    _QWORD *pPrevEntry = (_QWORD *)*pCurrentNode;
                    _QWORD *pNextEntry = (_QWORD *)pCurrentNode[1];
                    pPrevEntry[1] = pNextEntry;
                    *pNextEntry = pPrevEntry;
                    ExFreePoolWithTag(pTargetEntry, 0);
                    return 1;
                }
                return Result;
            }
        }
    }
    return Result;
}

