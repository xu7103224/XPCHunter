# -*- coding: utf-8 -*-
import sys

def append_to_file(filepath, content):
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(content)
    print(f'Written to {filepath}')

# IoctlDispatch.c functions
ioctl_content = """

// ReadServiceTableEntries -- 读取服务表条目。
// 从 GT 506 获取服务表指针，若为空则先调用 ParseServiceTable 解析。
// 遍历服务表填充 12 字节每项的条目到输出缓冲区，包含索引号和服务表地址。
// 对应原始驱动 sub_140051214
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 a2, char *PeFileData, unsigned int PeFileSize)
{
    unsigned int Index = 0;
    unsigned int ServiceCount = GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        _DWORD *pServiceTable = (_DWORD *)GtRead(GtIrpBufferSize);
        if (pServiceTable || (ParseServiceTable(PeFileData, PeFileSize), pServiceTable = (_DWORD *)GtRead(GtIrpBufferSize), ServiceCount = GtRead(GtEprocessField57), pServiceTable))
        {
            _DWORD *pOutputEntry = (_DWORD *)(OutputBuffer + 8);
            if (ServiceCount)
            {
                do
                {
                    *pOutputEntry = Index++;
                    pOutputEntry[1] = *pServiceTable;
                    pOutputEntry += 12;
                    ++pServiceTable;
                } while (Index < ServiceCount);
            }
            return 1;
        }
    }
    return 0;
}

// RemoveFromObjectTypeList -- 从对象类型链表中移除指定目标对象。
// 遍历链表（GT 699），查找匹配的 pTargetObject 指针，找到后从双向链表中摘除该节点。
// 使用 MmIsAddressValid 验证地址有效性，最多遍历 0x1000 次。
// 对应原始驱动 sub_140041FB4
char RemoveFromObjectTypeList(PVOID *pTargetObject)
{
    char Result = 0;
    PVOID **pListHead = (PVOID **)GtRead(GtKernelDataField41);
    PVOID **pListHeadCopy = pListHead;
    if (pListHead && MmIsAddressValid(pListHead) == 1)
    {
        PVOID *pCurrent = *pListHeadCopy;
        int IterationCount = 0;
        while (pCurrent != (PVOID *)pListHeadCopy)
        {
            if (pCurrent <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrent) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrent == pTargetObject)
            {
                if (MmIsAddressValid(*pCurrent) == 1)
                {
                    PVOID *pPrev = (PVOID *)*pCurrent;
                    PVOID **pNext = (PVOID **)pCurrent[1];
                    Result = 1;
                    pPrev[1] = pNext;
                    *pNext = pPrev;
                }
                return Result;
            }
            pCurrent = (PVOID *)*pCurrent;
        }
    }
    return Result;
}

// RemoveFromObjectTypeListEx -- 从对象类型链表中删除指定的指针条目（扩展版）。
// 从 GT 824 获取 13 个链表头数组，在每个链表中搜索匹配目标指针（最多 0x10000 条），找到后从双向链表中摘除。
// 对应原始驱动 sub_140042914
char RemoveFromObjectTypeListEx(PVOID *pTargetPointer)
{
    char Result = 0;
    PVOID **pListHeadArray = (PVOID **)GtRead(GtCallbackField103);
    PVOID **pCurrentListHead = pListHeadArray;
    if (pListHeadArray && MmIsAddressValid(pListHeadArray) == 1)
    {
        for (unsigned int ListIndex = 0; ListIndex < 0xD; ++ListIndex)
        {
            if (MmIsAddressValid(pCurrentListHead) == 1)
            {
                PVOID *pCurrentNode = *pCurrentListHead;
                int IterationCount = 0;
                while (pCurrentNode != (PVOID *)pCurrentListHead)
                {
                    if (pCurrentNode <= MmSystemRangeStart)
                        break;
                    if (MmIsAddressValid(pCurrentNode) != 1)
                        break;
                    if ((unsigned int)++IterationCount > 0x10000)
                        break;
                    if (pTargetPointer == pCurrentNode)
                    {
                        if (MmIsAddressValid(*pCurrentNode) == 1)
                        {
                            PVOID *pPrevEntry = (PVOID *)*pCurrentNode;
                            PVOID **pNextEntry = (PVOID **)pCurrentNode[1];
                            Result = 1;
                            pPrevEntry[1] = pNextEntry;
                            *pNextEntry = pPrevEntry;
                        }
                        break;
                    }
                    pCurrentNode = (PVOID *)*pCurrentNode;
                }
                if (Result == 1)
                    break;
            }
            pCurrentListHead += 2;
        }
    }
    return Result;
}

// RemoveObjectFromTypeList -- 从对象类型链表中删除指定对象并释放内存。
// 先调用 GT 16820 的释放回调处理目标对象，然后遍历 GT 95 和 GT 719 两个双向链表，
// 搜索匹配的对象条目（最多 0x10000 条），找到后从链表摘除，非 Win7 时调用 ObfDereferenceObject，
// 最后 ExFreePoolWithTag 释放节点内存。
// 对应原始驱动 sub_140042A48
char RemoveObjectFromTypeList(PVOID pTargetObject)
{
    char Result = 0;
    void (__fastcall *pFreeCallback)(PVOID) = (void (__fastcall *)(PVOID))GtRead(GtTotalSize | GtEprocessField170 | 0x100);
    if (pFreeCallback)
    {
        pFreeCallback(pTargetObject);
        Result = 1;
    }
    _QWORD ListHeadBuffer[7];
    ListHeadBuffer[0] = GtRead(GtEprocessField85);
    PVOID ***pListHeadArray = (PVOID ***)ListHeadBuffer;
    ListHeadBuffer[1] = GtRead(GtCallbackField04);
    __int64 ListCount = 2;
    do
    {
        PVOID **pListHead = *pListHeadArray;
        if (*pListHeadArray)
        {
            PVOID *pCurrentNode = *pListHead;
            int IterationCount = 0;
            while (pCurrentNode != (PVOID *)pListHead)
            {
                if (pCurrentNode <= MmSystemRangeStart)
                    break;
                if (MmIsAddressValid(pCurrentNode) != 1)
                    break;
                if ((unsigned int)++IterationCount > 0x10000)
                    break;
                PVOID pObjectEntry = pCurrentNode[2];
                if (pTargetObject == pObjectEntry)
                {
                    if (MmIsAddressValid(*pCurrentNode) == 1)
                    {
                        PVOID *pPrevEntry = (PVOID *)*pCurrentNode;
                        PVOID **pNextEntry = (PVOID **)pCurrentNode[1];
                        pPrevEntry[1] = pNextEntry;
                        *pNextEntry = pPrevEntry;
                        if (!(unsigned int)GtRead(GtEprocessField28))
                            ObfDereferenceObject(pObjectEntry);
                        ExFreePoolWithTag(pCurrentNode, 0);
                        Result = 1;
                    }
                    break;
                }
                pCurrentNode = (PVOID *)*pCurrentNode;
            }
        }
        ++pListHeadArray;
        --ListCount;
    } while (ListCount);
    return Result;
}

// RemoveKernelObjectEntry -- 移除内核对象条目。
// 在 SSDT2 表（GT 88）中查找匹配目标地址的条目，清零并从计数器中递减。
// 非 Win7 时释放条目内存。然后调用释放函数（GT 16826）释放目标地址对应的数据。
// 对应原始驱动 sub_140042578
char RemoveKernelObjectEntry(__int64 TargetAddress)
{
    char Result = 0;
    int IsWin7 = GtRead(GtEprocessField28);
    _QWORD *pSsdtTable = (_QWORD *)GtRead(GtEprocessField78);
    __int64 SsdtTableEnd = GtRead(GtEprocessField79);
    _DWORD *pCounter = (_DWORD *)SsdtTableEnd;
    if (pSsdtTable && SsdtTableEnd)
    {
        _QWORD *pEndPtr = (_QWORD *)SsdtTableEnd;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
            pEndPtr = pSsdtTable + 64;
        while (pSsdtTable < pEndPtr && MmIsAddressValid(pSsdtTable))
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
                Result = 1;
                break;
            }
            ++pSsdtTable;
        }
    }
    void (__fastcall *pFreeFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtTotalSize | GtNtQuerySystemInformationFunc | GtEprocessField22);
    if (pFreeFunc)
    {
        __int64 FreeParam;
        if (IsWin7)
        {
            FreeParam = TargetAddress;
            goto LABEL_FREE;
        }
        __int64 FreeAddr = TargetAddress & 0xFFFFFFFFFFFFFFF0ui64;
        if (MmIsAddressValid((PVOID)(FreeAddr + 8)) == 1)
        {
            FreeParam = *(_QWORD *)(FreeAddr + 8);
LABEL_FREE:
            pFreeFunc(FreeParam);
            return 1;
        }
    }
    return Result;
}

// ReleaseProcessMemoryBlock -- 释放进程内存块。
// 先调用回调释放目标条目，然后遍历进程内存链表查找匹配条目并从链表中摘除后释放。
// 对应原始驱动 sub_14004501C
char ReleaseProcessMemoryBlock(_QWORD *pTargetEntry)
{
    int IterationCount = 0;
    char Result = 0;
    void (__fastcall *pFreeCallback)(_QWORD *) = (void (__fastcall *)(_QWORD *))GtRead(GtNtDeleteKeyPeSectionOffset);
    if (pFreeCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pFreeCallback(pTargetEntry);
        Result = 1;
    }
    _QWORD **pProcessMemListHead = (_QWORD **)GtRead(GtFwpsDispatchTableCount);
    _QWORD **pSentinel = pProcessMemListHead;
    if (pProcessMemListHead && MmIsAddressValid(pProcessMemListHead) == 1)
    {
        for (_QWORD *pCurrentNode = *pSentinel; pCurrentNode != pSentinel; pCurrentNode = (_QWORD *)*pCurrentNode)
        {
            if (pCurrentNode <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrentNode) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrentNode == pTargetEntry)
            {
                if (MmIsAddressValid((PVOID)*pCurrentNode) == 1)
                {
                    _QWORD *pPrevEntry = (_QWORD *)*pCurrentNode;
                    _QWORD *pNextEntry = (_QWORD *)pCurrentNode[1];
                    pPrevEntry[1] = pNextEntry;
                    *pNextEntry = pPrevEntry;
                    ExFreePoolWithTag(pTargetEntry, 0x72546F49u);
                    return 1;
                }
                return Result;
            }
        }
    }
    return Result;
}

// PatchFsFilterDriverIndex -- 修补文件系统过滤驱动索引。
// 对应原始驱动 sub_14000EEF4
char PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit)
{
    char Result = 0;
    __int64 FileSection;
    if (Is64Bit == 1)
        FileSection = BuildFsFilterDriverPath2();
    else
        FileSection = BuildFsFilterDriverPath1();
    if (FileSection)
    {
        if (*(_DWORD *)(PatchEntry + 4) < 0x40u && *(_BYTE *)PatchEntry == 1)
        {
            __int64 ExportDirEntry = *(_QWORD *)(FileSection + 48);
            if (ExportDirEntry)
            {
                __int64 ExportFuncTable = *(_QWORD *)(ExportDirEntry + 40);
                if (ExportFuncTable)
                {
                    if (CheckMemoryValid((void *)ExportFuncTable) == 1 && CheckMemoryValid((void *)(ExportFuncTable + 425)) == 1)
                    {
                        WritePhysicalMemoryQword(
                            ExportFuncTable + 8 * (*(unsigned int *)(PatchEntry + 4) + 4LL),
                            *(_QWORD *)(PatchEntry + 16));
                        return 1;
                    }
                }
            }
        }
    }
    return Result;
}

// QuerySsdHookByProcessInfo -- 通过进程信息查询 SSDT Hook。
// 验证输入缓冲区，分配临时缓冲区，通过 DecryptAesHexString 解密后调用 CheckSsdtHookIntegrity 检查 SSDT Hook 完整性。
// 对应原始驱动 sub_1400310B4
char QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize)
{
    unsigned int MaxCountCopy = MaxCount;
    char Result = 0;
    _BYTE Dst[304];
    if (Src)
    {
        if ((unsigned __int64)Src < MmUserProbeAddress
            && (unsigned int)MaxCount < 0x1000
            && (unsigned __int64)Src + (unsigned int)MaxCount < MmUserProbeAddress)
        {
            if (Address)
            {
                if ((unsigned __int64)Address < MmUserProbeAddress
                    && OutputSize == 4
                    && (unsigned __int64)(Address + 1) < MmUserProbeAddress)
                {
                    ProbeForRead(Src, (unsigned int)MaxCount, 1u);
                    ProbeForWrite(Address, 4u, 1u);
                    __int64 *pSyscallCount = GtAlloc(GtEncryptionKey);
                    if (MaxCountCopy <= 0x12C)
                    {
                        memmove(Dst, Src, MaxCountCopy);
                        --*pSyscallCount;
                        if (!(unsigned int)DecryptAesHexString(Dst, MaxCountCopy, pSyscallCount))
                            return CheckSsdtHookIntegrity((unsigned __int64)Dst, MaxCountCopy, Address, 4);
                    }
                }
            }
        }
    }
    return Result;
}
"""

append_to_file('src/IoctlDispatch.c', ioctl_content)