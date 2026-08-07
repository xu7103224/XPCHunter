// MissingFuncs.c — 暂未分配到各源文件的函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"

// C4700 抑制：各种函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
#include <intrin.h>

// 前向声明 — 定义在 Protocol.c 中
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// 前向声明 — 内部辅助函数
extern char OpenDeviceTarget(__int64 EncodedPath, __int64 *pDeviceHandle, __int64 *pDeviceObjectHandle);
extern __int64 GetDeviceObjectFromContext(__int64 DeviceHandle);
extern char GetDiskDriverInfo(char State, void *pBuffer, __int64 *pFuncTable);
extern char SetDiskDriverInfo(char State, char Flags, void *pBuffer);
extern char FindPeSectionByTypeRsrc(__int64 Buffer, unsigned int Size, __int64 Address);
extern char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
extern __int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex);
extern __int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex);
extern __int64 ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern __int64 ReadWriteKernelMemory(void);

// =======================================================================
// 简单函数实现
// =======================================================================

char RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    char Result;
    enum _GLOBAL_TABLE_INDEX GtIndex;
    PVOID **pListHead;
    PVOID **pSentinel;
    PVOID *pCurrentNode;
    int IterationCount;

    Result = 0;
    GtIndex = GtDisableHookProtectionAddr2 | GtEprocessField123;
    if (ListType != 1)
        GtIndex = GtDisableHookProtectionAddr2 | GtEprocessField122;
    pListHead = (PVOID **)GtRead(GtIndex);
    pSentinel = pListHead;
    if (pListHead && MmIsAddressValid(pListHead) == 1)
    {
        pCurrentNode = *pSentinel;
        IterationCount = 0;
        while (pCurrentNode != (PVOID *)pSentinel)
        {
            if (pCurrentNode <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrentNode) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrentNode == pTargetEntry)
            {
                if (MmIsAddressValid(*pCurrentNode) == 1)
                {
                    PVOID *pPrevEntry;
                    PVOID **pNextEntry;

                    ObfDereferenceObject(pTargetEntry[2]);
                    pPrevEntry = (PVOID *)*pCurrentNode;
                    pNextEntry = (PVOID **)pCurrentNode[1];
                    pPrevEntry[1] = pNextEntry;
                    *pNextEntry = pPrevEntry;
                    ExFreePoolWithTag(pTargetEntry, 0x69526F49u);
                    return 1;
                }
                return Result;
            }
            pCurrentNode = (PVOID *)*pCurrentNode;
        }
    }
    return Result;
}

char RemoveObjectFromLinkedList(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int BucketIndex;
    unsigned int EntryCount;
    _QWORD *pEntry;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (BucketIndex = 0; BucketIndex < 0x7F; ++BucketIndex)
        {
            EntryCount = 0;
            pEntry = pObjectTable;
            if (*pObjectTable)
            {
                while (ValidateFunc(*pEntry) && EntryCount <= 0x10000)
                {
                    CurrentEntry = *pEntry;
                    if (TargetHandle == *pEntry)
                    {
                        Success = 1;
                        *pEntry = *(_QWORD *)(CurrentEntry + 40);
                        break;
                    }
                    pEntry = (_QWORD *)(CurrentEntry + 40);
                    ++EntryCount;
                    if (!*(_QWORD *)(CurrentEntry + 40))
                        break;
                }
            }
            if (Success == 1)
                break;
            ++pObjectTable;
        }
    }
    return Success;
}

char RemoveObjectFromLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int BucketIndex;
    unsigned int EntryCount;
    _QWORD *pEntry;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (BucketIndex = 0; BucketIndex < 0x7F; ++BucketIndex)
        {
            EntryCount = 0;
            pEntry = pObjectTable;
            if (*pObjectTable)
            {
                while (ValidateFunc(*pEntry) && EntryCount <= 0x10000)
                {
                    CurrentEntry = *pEntry;
                    if (TargetHandle == *pEntry)
                    {
                        Success = 1;
                        *pEntry = *(_QWORD *)(CurrentEntry + 32);
                        break;
                    }
                    pEntry = (_QWORD *)(CurrentEntry + 32);
                    ++EntryCount;
                    if (!*(_QWORD *)(CurrentEntry + 32))
                        break;
                }
            }
            if (Success == 1)
                break;
            ++pObjectTable;
        }
    }
    return Success;
}

char RemoveObjectSingleLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int EntryIndex;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (EntryIndex = 0; *pObjectTable && ValidateFunc(*pObjectTable) && EntryIndex <= 0x10000; ++EntryIndex)
        {
            CurrentEntry = *pObjectTable;
            if (TargetHandle == *pObjectTable)
            {
                Success = 1;
                *pObjectTable = *(_QWORD *)(CurrentEntry + 32);
                return Success;
            }
            pObjectTable = (_QWORD *)(CurrentEntry + 32);
        }
    }
    return Success;
}

char EnumKernelModules(__int64 UnusedParam1, __int64 UnusedParam2, _DWORD *pOutputBuffer, unsigned int BufferSize)
{
    SIZE_T RemainingSize;
    char Result;
    _QWORD *pModuleListHead;
    unsigned int BuildNumber;
    unsigned __int64 MaxCount;
    _QWORD *pCurrentEntry;
    PVOID MinAddress;
    unsigned int ModuleIndex;
    unsigned __int64 EntryOffset;
    unsigned __int16 NameLength;
    __int64 OutputIndex;
    _OWORD *pOutputEntry;
    _OWORD *pSrcEntry;
    __int64 CopyCount;
    unsigned __int64 EntryOffset2;
    unsigned __int64 EntryOffset3;
    unsigned __int64 EntryOffset4;
    unsigned __int16 NameLength2;
    __int64 OutputIndex2;
    _OWORD *pOutputEntry2;
    _OWORD *pSrcEntry2;
    __int64 CopyCount2;
    unsigned __int64 EntryOffset5;
    unsigned __int16 NameLength3;
    __int64 OutputIndex3;
    _OWORD *pOutputEntry3;
    _OWORD *pSrcEntry3;
    __int64 CopyCount3;

    RemainingSize = BufferSize;
    Result = 0;
    pModuleListHead = (_QWORD *)GtRead(GtEprocessExtField41);
    if (!pModuleListHead)
    {
        InitKernelDataSectionTable();
        pModuleListHead = (_QWORD *)GtRead(GtEprocessExtField41);
    }
    BuildNumber = GtRead(GtEprocessExtField13);
    if (pModuleListHead
        && pModuleListHead > MmSystemRangeStart
        && BuildNumber >= 0x60000
        && pOutputBuffer
        && (unsigned int)RemainingSize >= 0x278
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + RemainingSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, RemainingSize, 4u);
        memset(pOutputBuffer, 0, RemainingSize);
        MaxCount = (RemainingSize - 632) / 0x270 + 1;
        *(_DWORD *)pOutputBuffer = 0;
        pCurrentEntry = (_QWORD *)*pModuleListHead;
        MinAddress = MmSystemRangeStart;
        if (*pModuleListHead > (unsigned __int64)MmSystemRangeStart && pCurrentEntry != pModuleListHead)
        {
            ModuleIndex = 0;
            if (BuildNumber >= 0x60028)
            {
                EntryOffset3 = (unsigned __int64)(pCurrentEntry - 154);
                if (BuildNumber >= 0x60053)
                {
                    while (ModuleIndex < 0x1000 && EntryOffset3 > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset3) == 1 && (_DWORD)MaxCount)
                    {
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset3;
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset3 + 560);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset3 + 1120);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset3 + 1216);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset3 + 528);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset3 + 532);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset3 + 536);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset3 + 564);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset3 + 1220);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset3 + 1224);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset3 + 1192);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset3 + 1112);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset3 + 4);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset3 + 1320);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset3 + 1328);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset3 + 540);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset3 + 580);
                        NameLength3 = *(_WORD *)(EntryOffset3 + 8);
                        OutputIndex3 = (unsigned int)*(_DWORD *)pOutputBuffer;
                        if (NameLength3 >= 0x200u)
                        {
                            pOutputEntry3 = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex3))[24];
                            pSrcEntry3 = (_OWORD *)(EntryOffset3 + 10);
                            CopyCount3 = 4;
                            do
                            {
                                *pOutputEntry3 = *pSrcEntry3;
                                pOutputEntry3[1] = pSrcEntry3[1];
                                pOutputEntry3[2] = pSrcEntry3[2];
                                pOutputEntry3[3] = pSrcEntry3[3];
                                pOutputEntry3[4] = pSrcEntry3[4];
                                pOutputEntry3[5] = pSrcEntry3[5];
                                pOutputEntry3[6] = pSrcEntry3[6];
                                pOutputEntry3 += 8;
                                *(pOutputEntry3 - 1) = pSrcEntry3[7];
                                pSrcEntry3 += 8;
                                --CopyCount3;
                            }
                            while (CopyCount3);
                        }
                        else
                        {
                            memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex3 + 24], (const void *)(EntryOffset3 + 10), NameLength3);
                        }
                        ++*(_DWORD *)pOutputBuffer;
                        LODWORD_LV(MaxCount) = MaxCount - 1;
                        EntryOffset5 = *(_QWORD *)(EntryOffset3 + 1232);
                        if ((_QWORD *)EntryOffset5 == pModuleListHead)
                            break;
                        MinAddress = MmSystemRangeStart;
                        if (EntryOffset5 <= (unsigned __int64)MmSystemRangeStart)
                            break;
                        EntryOffset3 = EntryOffset5 - 1232;
                        ++ModuleIndex;
                    }
                }
                else
                {
                    while (ModuleIndex < 0x1000 && EntryOffset3 > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset3) == 1 && (_DWORD)MaxCount)
                    {
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset3;
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset3 + 560);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset3 + 1120);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset3 + 1216);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset3 + 528);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset3 + 532);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset3 + 536);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset3 + 564);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset3 + 1220);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset3 + 1224);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset3 + 1192);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset3 + 1112);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset3 + 4);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset3 + 1320);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset3 + 1328);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset3 + 540);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset3 + 580);
                        NameLength2 = *(_WORD *)(EntryOffset3 + 8);
                        OutputIndex2 = (unsigned int)*(_DWORD *)pOutputBuffer;
                        if (NameLength2 >= 0x200u)
                        {
                            pOutputEntry2 = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex2))[24];
                            pSrcEntry2 = (_OWORD *)(EntryOffset3 + 10);
                            CopyCount2 = 4;
                            do
                            {
                                *pOutputEntry2 = *pSrcEntry2;
                                pOutputEntry2[1] = pSrcEntry2[1];
                                pOutputEntry2[2] = pSrcEntry2[2];
                                pOutputEntry2[3] = pSrcEntry2[3];
                                pOutputEntry2[4] = pSrcEntry2[4];
                                pOutputEntry2[5] = pSrcEntry2[5];
                                pOutputEntry2[6] = pSrcEntry2[6];
                                pOutputEntry2 += 8;
                                *(pOutputEntry2 - 1) = pSrcEntry2[7];
                                pSrcEntry2 += 8;
                                --CopyCount2;
                            }
                            while (CopyCount2);
                        }
                        else
                        {
                            memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex2 + 24], (const void *)(EntryOffset3 + 10), NameLength2);
                        }
                        ++*(_DWORD *)pOutputBuffer;
                        LODWORD_LV(MaxCount) = MaxCount - 1;
                        EntryOffset4 = *(_QWORD *)(EntryOffset3 + 1232);
                        if ((_QWORD *)EntryOffset4 == pModuleListHead)
                            break;
                        MinAddress = MmSystemRangeStart;
                        if (EntryOffset4 <= (unsigned __int64)MmSystemRangeStart)
                            break;
                        EntryOffset3 = EntryOffset4 - 1232;
                        ++ModuleIndex;
                    }
                }
            }
            else
            {
                EntryOffset = (unsigned __int64)(pCurrentEntry - 1);
                while (ModuleIndex < 0x1000 && EntryOffset > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset) == 1 && (_DWORD)MaxCount)
                {
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset;
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset + 708);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset + 1264);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset + 1360);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset + 676);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset + 680);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset + 684);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset + 712);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset + 1364);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset + 1368);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset + 1336);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset + 1256);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset + 152);
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset + 96);
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset + 104);
                    *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset + 688);
                    *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset + 724);
                    NameLength = *(_WORD *)(EntryOffset + 156);
                    OutputIndex = (unsigned int)*(_DWORD *)pOutputBuffer;
                    if (NameLength >= 0x200u)
                    {
                        pOutputEntry = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex))[24];
                        pSrcEntry = (_OWORD *)(EntryOffset + 158);
                        CopyCount = 4;
                        do
                        {
                            *pOutputEntry = *pSrcEntry;
                            pOutputEntry[1] = pSrcEntry[1];
                            pOutputEntry[2] = pSrcEntry[2];
                            pOutputEntry[3] = pSrcEntry[3];
                            pOutputEntry[4] = pSrcEntry[4];
                            pOutputEntry[5] = pSrcEntry[5];
                            pOutputEntry[6] = pSrcEntry[6];
                            pOutputEntry += 8;
                            *(pOutputEntry - 1) = pSrcEntry[7];
                            pSrcEntry += 8;
                            --CopyCount;
                        }
                        while (CopyCount);
                    }
                    else
                    {
                        memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex + 24], (const void *)(EntryOffset + 158), NameLength);
                    }
                    ++*(_DWORD *)pOutputBuffer;
                    LODWORD_LV(MaxCount) = MaxCount - 1;
                    EntryOffset2 = *(_QWORD *)(EntryOffset + 8);
                    if ((_QWORD *)EntryOffset2 == pModuleListHead)
                        break;
                    MinAddress = MmSystemRangeStart;
                    if (EntryOffset2 <= (unsigned __int64)MmSystemRangeStart)
                        break;
                    EntryOffset = EntryOffset2 - 8;
                    ++ModuleIndex;
                }
            }
        }
        return *(_DWORD *)pOutputBuffer != 0;
    }
    return Result;
}
