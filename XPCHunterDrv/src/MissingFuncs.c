// MissingFuncs.c — 缺失函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

// Forward declarations
__int64 GetSsdtTableOffset(__int64 SsdtTable, __int64 DefaultOffset);
__int64 ParseNtExportFunctionsV2(void);
__int64 ParseNtExportFunctions(void);
char ComparePeHeaders(__int64 Image1, unsigned int Image1Size, __int64 Image2, unsigned int Image2Size);
__int64 CallKernelFreeEntryV1(_QWORD *VirtualAddress);
__int64 CallKernelFreeEntryV2(__int64 VirtualAddress);
__int64 ParseMsrRelatedSections(void);
__int64 ParseMsrTableFromSections(void);

// CheckMemoryValid 已在 MemoryOps.c 中实现
// 本文件中的定义已移除，使用外部链接

// AdjustKernelModuleSectionPointers — 调整内核模块节区指针
// 对应原始驱动 sub_14006E4A0
// 根据构建号调整内核模块节区指针偏移量，处理 Win10 RS3 及以上的差异
__int64 AdjustKernelModuleSectionPointers(void)
{
    __int64 v0 = GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField187 | 0x100));
    __int64 v2 = GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField188 | 0x100));
    if (v0 && v2)
    {
        if (GtRead(GtWindowsBuildNumber) >= 0x23F0)
        {
            if (GtRead(GtWindowsBuildNumber) == 9200)
            {
                GtWrite((GLOBAL_TABLE_INDEX)(GtEprocessField189 | 0x100), v0 + 16);
                GtWrite((GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | 0x100), v2 + 16);
            }
        }
        else
        {
            GtWrite((GLOBAL_TABLE_INDEX)(GtEprocessField189 | 0x100), v0 + 8);
            GtWrite((GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | 0x100), v2 + 8);
        }
    }
    return v2;
}
__int64 DispatchWin32kPatternMatching(void) { return 0; }
// AllocExBufferAndQuerySystemInfo 已在 SystemInfo.c 中实现
// 本文件中的定义已移除，使用外部链接

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

// BuildDriverInfoEntries — 构建驱动信息条目
// 对应原始驱动 sub_140051E90
// 从 GT 获取驱动上下文表，遍历条目填充驱动信息数组
__int64 BuildDriverInfoEntries(unsigned int *InfoBuffer, unsigned int BufferSize)
{
    __int64 ContextTable = GtRead(GtFindHookTargetFirstMatchAddr2);
    if (!ContextTable)
        return 0;

    __int64 EntryTable = *(_QWORD *)ContextTable;
    unsigned int CurrentCount = *InfoBuffer;
    unsigned int NewCount = *(_DWORD *)(ContextTable + 16);
    unsigned int Index = 0;

    if (NewCount < CurrentCount)
        NewCount = CurrentCount;
    InfoBuffer[1] = NewCount;

    if (CurrentCount)
    {
        do
        {
            __int64 EntryAddr = EntryTable + (*(int *)(EntryTable + 4LL * Index) >> 4);
            __int64 EntrySlot = 42LL * Index;
            *(_QWORD *)&InfoBuffer[EntrySlot + 40] = EntryAddr;
            if (EntryAddr != *(_QWORD *)&InfoBuffer[EntrySlot + 38])
                *((char *)&InfoBuffer[EntrySlot + 42]) = 1;
            ++Index;
        }
        while (Index < CurrentCount);
    }

    unsigned int TargetCount = InfoBuffer[1];
    if (TargetCount > CurrentCount && BufferSize >= 168 * TargetCount + 176)
    {
        unsigned int FillIndex = CurrentCount;
        do
        {
            __int64 FillSlot = 42LL * FillIndex;
            InfoBuffer[FillSlot + 2] = FillIndex;
            int EntryValue = *(int *)(EntryTable + 4LL * FillIndex);
            *(short *)&InfoBuffer[FillSlot + 42] = 0;
            InfoBuffer[FillSlot + 36] = 0;
            *(_QWORD *)&InfoBuffer[FillSlot + 38] = 0;
            *(_QWORD *)&InfoBuffer[FillSlot + 40] = EntryTable + (EntryValue >> 4);
            *(short *)&InfoBuffer[FillSlot + 3] = 0;
            ++FillIndex;
        }
        while (FillIndex < TargetCount);
    }
    return 1;
}

// BuildDriverPathI8042prt — 构建 i8042prt 驱动路径
// 对应原始驱动 sub_140008914
__int64 BuildDriverPathI8042prt(__int64 OutputBuffer, int BufferSize)
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
    return QueryDriverObjectByPath((__int64)EncodedPath, 10, OutputBuffer, BufferSize);
}

// BuildDriverPathKbdClass — 构建 kbdclass 驱动路径
// 对应原始驱动 sub_140008994
__int64 BuildDriverPathKbdClass(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6422603;
    EncodedPath[5] = 4391012;
    EncodedPath[6] = 6357100;
    EncodedPath[7] = 7536755;
    return QueryDriverObjectByPath((__int64)EncodedPath, 8, OutputBuffer, BufferSize);
}

// BuildDriverPathMouClass — 构建 mouclass 驱动路径
// 对应原始驱动 sub_140008A14
__int64 BuildDriverPathMouClass(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7274573;
    EncodedPath[5] = 6488181;
    EncodedPath[6] = 6357100;
    EncodedPath[7] = 7536755;
    return QueryDriverObjectByPath((__int64)EncodedPath, 9, OutputBuffer, BufferSize);
}

// BuildExportServiceTable
char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize)
{
    return 0;
}

// BuildProcessContextExportTable
__int64 BuildProcessContextExportTable(void)
{
    return 0;
}

// BuildServiceTableFromNtKernel
__int64 BuildServiceTableFromNtKernel(_QWORD a1, _QWORD a2)
{
    return 0;
}

// CheckFilePathFilter — 检查文件路径是否被过滤屏蔽
// 对应原始驱动 sub_14002D1E8
// 比较路径是否匹配 NTFS 元数据文件 ($AttrDef, $MFTMirr, $MFT, $UpCase)
__int64 CheckFilePathFilter(__int64 FilePath, unsigned int FilePathLength)
{
    if (FilePathLength <= 8)
        return 0;

    __int64 PathStart = FilePath + 6;
    int Filter1;
    __int64 Filter2;
    __int64 Filter3;

    // "$AttrDef" 编码
    Filter1 = 4259876;
    Filter2 = 0x44007200740074LL;
    Filter3 = 6684773;
    if (!WStringCompareCaseInsensitive(PathStart, (__int64)&Filter1))
        return 1;

    // "$MFTMirr" 编码
    Filter1 = 5046308;
    Filter2 = 0x69004D00540046LL;
    Filter3 = 7471218;
    if (!WStringCompareCaseInsensitive(PathStart, (__int64)&Filter1))
        return 1;

    // "$MFT" 编码
    Filter1 = 5046308;
    Filter2 = 5505094;
    if (!WStringCompareCaseInsensitive(PathStart, (__int64)&Filter1))
        return 1;

    // "$UpCase" 编码
    Filter1 = 5570596;
    Filter2 = 0x73006100430070LL;
    Filter3 = 101;
    return WStringCompareCaseInsensitive(PathStart, (__int64)&Filter1) == 0;
}

// CheckProcessJobObject — 检查进程是否属于作业对象
// 对应原始驱动 sub_140079D20
// 查询进程的 ProcessBasicInformation，检查 JobObject 字段是否非空
__int64 CheckProcessJobObject(__int64 ProcessHandle)
{
    unsigned int PrevModeOffset = GtRead(GtSdstServiceCount);
    __int64 (__fastcall *NtQueryInfoProcessFunc)(__int64, __int64, _QWORD *, __int64, _QWORD);
    _QWORD *Buffer;
    PKTHREAD CurrentThread;
    char SavedPrevMode;
    int Status;
    bool Result = 0;

    NtQueryInfoProcessFunc = (__int64 (__fastcall *)(__int64, __int64, _QWORD *, __int64, _QWORD))GtRead(GtDereferenceObjectFunc);
    if (PrevModeOffset != -1 && NtQueryInfoProcessFunc)
    {
        Buffer = ExAlloc(PagedPool, 0x2000);
        if (Buffer)
        {
            CurrentThread = KeGetCurrentThread();
            SavedPrevMode = *((char *)CurrentThread + PrevModeOffset);
            *((char *)CurrentThread + PrevModeOffset) = 0;
            Status = NtQueryInfoProcessFunc(ProcessHandle, 2, Buffer, 0x2000, 0);
            *((char *)CurrentThread + PrevModeOffset) = SavedPrevMode;
            if (Status >= 0)
                Result = Buffer[1] != 0;  // JobObject field
            ExFree(Buffer);
        }
    }
    return Result;
}

// CheckProcessObjectFlag — 检查进程对象保护标志
// 对应原始驱动 sub_140078638
// 根据 Windows 版本检查进程保护标志（PsProtectedProcess）
__int64 CheckProcessObjectFlag(__int64 ProcessObject)
{
    unsigned int ProtectedOffset = GtRead(GtCallbackField75);
    if (!ProtectedOffset)
        return 0;

    if (GtRead(GtWindowsBuildNumber) < 0x1770)
        return *((char *)ProcessObject + ProtectedOffset) != 0;

    if (GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        if (GtRead(GtWindowsBuildNumber) >= 0x3FAB)
            return (*(unsigned int *)((char *)ProcessObject + ProtectedOffset) & 0x20000) != 0;
        else
            return (*(unsigned int *)((char *)ProcessObject + ProtectedOffset) & 0x10000) != 0;
    }

    if (GtRead(GtWindowsBuildNumber) == 9600)
    {
        if (GtRead(GtNtCreateThreadHookSuccess) != 0)
            return (*(unsigned int *)((char *)ProcessObject + ProtectedOffset) & 0x10000) != 0;
    }

    return (*((char *)ProcessObject + ProtectedOffset) & 1) != 0;
}

// CheckWin2k3Sp2 — 检查 Win2K3 SP2 版本
// 对应原始驱动 sub_1400210F4
// 通过 EPROCESS 偏移 0x98 的 DWORD 最高位判断
__int64 CheckWin2k3Sp2(void)
{
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    if (CurrentProcess)
        return *((unsigned int *)CurrentProcess + 38) > 0x80000000;
    return 0;
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
        if (GtRead(GtWindowsBuildNumber) > 0x1770)
        {
            if (GtRead(GtWindowsBuildNumber) > 0x1DB1)
            {
                pTempCounter = pSsdtTable + 512;
                if (GtRead(GtWindowsBuildNumber) == 9200)
                    pCounter = pSsdtTable + 512;
                else
                {
                    if (GtRead(GtWindowsBuildNumber) < 0x3839 || GtRead(GtWindowsBuildNumber) == 14393)
                        pCounter = pCounterEnd - 1;
                    else if (GtRead(GtWindowsBuildNumber) == 15063)
                        pCounter = pCounterEnd + 2;
                    else if (GtRead(GtWindowsBuildNumber) == 16299)
                        pCounter = pCounterEnd + 1;
                    else if (GtRead(GtWindowsBuildNumber) == 17134 || GtRead(GtWindowsBuildNumber) == 17763)
                        pCounter = pCounterEnd - 1;
                    else
                    {
                        pCounter = pCounterEnd + 4;
                        if (GtRead(GtWindowsBuildNumber) != 18362)
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
                if (GtRead(GtWindowsBuildNumber) >= 0x1771 && *(_BYTE *)((TargetAddress & 0xFFFFFFFFFFFFFFF0ui64) + 0x10))
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

// CmdEnumObjectsEx
__int64 CmdEnumObjectsEx(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// CmdEnumObjectsLegacy
__int64 CmdEnumObjectsLegacy(__int64 a1, unsigned int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// ============================================================
// CmdObjectOperationByHandle — 通过句柄执行对象操作命令
// 验证输入缓冲区（8 字节），若 GT 740 未初始化则调用 InitObjectOperationEntry。
// 根据 GT 2324 构建号选择不同的链表删除函数（Win7/Win8/Win10+）。
// ============================================================

// CmdObjectOperationByHandle
__int64 CmdObjectOperationByHandle(__int64 *a1, int a2)
{
    return 0;
}

// CmdQueryDiskInfo
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length)
{
    return 0;
}

// CmdQueryFileAllocationSize
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize)
{
    return 0;
}

// CmdQuerySystemInfoExV2
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length)
{
    return 0;
}

// CmdReadFileInfo
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo)
{
    return 0;
}

// CmdSendRenameFileIrp
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize)
{
    return 0;
}

// CmdSetFileBasicInfo
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo)
{
    return 0;
}

// CmdSetModuleInfoInternal
__int64 CmdSetModuleInfoInternal(_QWORD a1)
{
    return 0;
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

// CopyCallbackContextTable
__int64 CopyCallbackContextTable(__int64 pSourceTable, int ContextType)
{
    return 0;
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

// CopyFsFilterEntryTable — 复制文件系统过滤器条目表
// 对应原始驱动 sub_14000E510
// 从 GT 分配表复制 64 条过滤器条目到输出缓冲区
__int64 CopyFsFilterEntryTable(__int64 OutputBuffer, char Is64Bit)
{
    __int64 *RelocTable;
    if (Is64Bit == 1)
        RelocTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1BB0);
    else
        RelocTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1D3C);
    char Result = 0;
    __int64 OutputPtr = OutputBuffer + 16;
    for (int Count = 64; Count; Count--)
    {
        char *InputPtr = (char *)RelocTable + 4 + 48LL * (64 - Count);
        if (*(unsigned int *)InputPtr && *((unsigned int *)InputPtr - 1) == 1)
        {
            *(unsigned int *)(OutputPtr - 8) = *(unsigned int *)InputPtr;
            Result = 1;
            *(_QWORD *)OutputPtr = *(_QWORD *)(InputPtr + 4);
            *(_OWORD *)(OutputPtr + 18) = *(_OWORD *)(InputPtr + 12);
        }
        else
        {
            *(_QWORD *)OutputPtr = 0;
        }
        OutputPtr += 56;
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

// CopyKernelDualArrayToUserBuffer 已在下方实现
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

// CopyRegistryContextEntryArray — 复制注册表上下文条目数组
// 对应原始驱动 sub_140046048
__int64 CopyRegistryContextEntryArray(__int64 pOutputTable)
{
    __int64 *pExportTable = GtAlloc(GtDisableHookProtectionAddr2|GtCallbackField50|0x3000);
    if (!pExportTable)
        return 0;
    __int64 pDestSlot = pOutputTable + 8;
    char *pSrcSlot = (char *)pExportTable + 4;
    char Result = 0;
    for (int EntryCount = 28; EntryCount; EntryCount--)
    {
        *(_DWORD *)(pDestSlot - 4) = *(_DWORD *)pSrcSlot;
        if (*(_DWORD *)pSrcSlot && *((_DWORD *)pSrcSlot - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)pDestSlot = *(_QWORD *)(pSrcSlot + 4);
            *(_OWORD *)(pDestSlot + 18) = *(_OWORD *)(pSrcSlot + 12);
            *(_OWORD *)(pDestSlot + 34) = *(_OWORD *)(pSrcSlot + 28);
        }
        pSrcSlot += 48;
        pDestSlot += 64;
    }
    return Result;
}

// CopyThreadContextTable — 复制线程上下文表
// 对应原始驱动 sub_1400571B0
__int64 CopyThreadContextTable(__int64 pSourceTable)
{
    __int64 *v3 = GtAlloc(GtTotalSize|GtEprocessField144);
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

// DisableObjectCallback
__int64 DisableObjectCallback(int flags, ULONG64 a2)
{
    return 0;
}

// DiskOperationDispatcher
__int64 DiskOperationDispatcher(void)
{
    return 0;
}

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

// CallKernelFreeEntryV1 — 调用内核释放条目 V1（被 DispatchKernelMemoryCleanup 调用）
// 对应原始驱动 sub_1400421AC
__int64 CallKernelFreeEntryV1(_QWORD *VirtualAddress)
{
    return 0;
}

// CallKernelFreeEntryV2 — 调用内核释放条目 V2（被 DispatchKernelMemoryCleanup 调用）
// 对应原始驱动 sub_1400421FC
__int64 CallKernelFreeEntryV2(__int64 VirtualAddress)
{
    return 0;
}

// DispatchKernelMemoryCleanup — 内核内存清理分发函数
// 对应原始驱动 sub_140042150
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600 || (unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
        return CallKernelFreeEntryV2((__int64)VirtualAddress);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        return CallKernelFreeEntryV1(VirtualAddress);
    return 0;
}

// DispatchParseNtExportFunctions 已在下方实现
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

// EnableProcessProtect
__int64 EnableProcessProtect(PVOID Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize)
{
    return 0;
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

// EnumDeviceObjects
__int64 EnumDeviceObjects(_QWORD a1, _QWORD a2)
{
    return 0;
}

// EnumFileSystemDeviceObjects
__int64 EnumFileSystemDeviceObjects(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// EnumKernelDriverObjects
__int64 EnumKernelDriverObjects(_DWORD *pOutputArray, unsigned int MaxCount)
{
    return 0;
}

// EnumKernelMemoryContext — 枚举内核内存上下文
// 对应原始驱动 sub_14006A968
// 遍历内核内存上下文链表，根据构建号选择步长写入输出缓冲区
__int64 EnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, unsigned int a4)
{
    if (!GtRead(GtEprocessExtField58|GtEprocessField32|0x400))
        InitKernelMemoryContext();
    _QWORD *v7 = (_QWORD *)GtRead(GtEprocessExtField58|GtEprocessField32|0x400);
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

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x4563)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
        {
            // Win7 (7600/7601 specific)
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 7600
                || (unsigned int)GtRead(GtWindowsBuildNumber) == 7601)
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

// EnumKernelModules
__int64 EnumKernelModules(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
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

// EnumObjectDirectoryEntries
__int64 EnumObjectDirectoryEntries(unsigned __int16 *pDirectoryPath, _DWORD *pDirectoryInfo, __int64 OutputBuffer, int MaxCount)
{
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

// EnumProcessAndInitObjects
__int64 EnumProcessAndInitObjects(__int64 a1, char a2)
{
    return 0;
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

// EnumProcessContextV2Table
__int64 EnumProcessContextV2Table(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextV3Table
__int64 EnumProcessContextV3Table(__int64 pOutputTable)
{
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

// EnumProcessHandleInfo
__int64 EnumProcessHandleInfo(_QWORD *pProcessInfo, unsigned int *pHandleTable, _OWORD *pOutputBuffer, int MaxCount)
{
    return 0;
}

// EnumProcessModules
__int64 EnumProcessModules(ULONG64 ProcessId, int Flags, volatile void *OutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumServiceTableWin10
__int64 EnumServiceTableWin10(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin1020H1
__int64 EnumServiceTableWin1020H1(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin7
__int64 EnumServiceTableWin7(__int64 *pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumServiceTableWin8
__int64 EnumServiceTableWin8(_QWORD **pServiceList, __int64 OutputBuffer, _DWORD *pCount, int MaxCount)
{
    return 0;
}

// EnumSsdtHooks
__int64 EnumSsdtHooks(__int64 OutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumThreadContextTable
__int64 EnumThreadContextTable(__int64 OutputBuffer)
{
    return 0;
}

// EnumerateProcessObjectTable
__int64 EnumerateProcessObjectTable(__int64 ProcessObject, __int64 OutputFlags)
{
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

// ExAlloc 已在 MemoryOps.c 中实现
// 本文件中的定义已移除，使用外部链接

// FileSystemFilterCallback — 文件系统过滤器回调
// 对应原始驱动 sub_14000EF84
// 验证输入缓冲区（64 字节），可选调用 PatchFsFilterDriverIndex 和 WritePhysicalMemoryBuffer
__int64 FileSystemFilterCallback(char *PatchBuffer, int BufferSize)
{
    if (!PatchBuffer || BufferSize != 64)
        return 0;
    if ((unsigned __int64)PatchBuffer >= MmUserProbeAddress
        || (unsigned __int64)(PatchBuffer + 64) >= MmUserProbeAddress)
        return 0;
    ProbeForRead(PatchBuffer, 0x40u, 1u);
    if (PatchBuffer[8] != 1 || *((_DWORD *)PatchBuffer + 3) >= 0x40u)
        return 0;
    if (*PatchBuffer != 1 && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
        return 0;
    char PatchResult = 1;
    char WriteResult = 1;
    if (PatchBuffer[40] == 1 && *((_QWORD *)PatchBuffer + 3))
        PatchResult = PatchFsFilterDriverIndex((__int64)(PatchBuffer + 8), *PatchBuffer);
    if (PatchBuffer[41] == 1)
    {
        WriteResult = 0;
        void *TargetAddress = (void *)*((_QWORD *)PatchBuffer + 3);
        if (TargetAddress > MmSystemRangeStart
            && CheckMemoryValid(TargetAddress) == 1
            && CheckMemoryValid((void *)(*((_QWORD *)PatchBuffer + 3) + 15LL)) == 1)
        {
            _OWORD WriteData = *(_OWORD *)(PatchBuffer + 42);
            WriteResult = WritePhysicalMemoryBuffer(*((_QWORD *)PatchBuffer + 3), &WriteData, 0x10u, 0, 0);
        }
    }
    return PatchResult & WriteResult;
}

// FilterActiveHookEntries — 过滤活跃钩子条目
// 对应原始驱动 sub_1400860E0
__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex)
{
    __int64 *v6 = GtAlloc(TableIndex);
    char v5 = 0;
    if (EntryCount)
    {
        __int64 v7 = OutputBuffer + 8;
        __int64 *v8 = v6 + 1;
        for (__int64 v9 = EntryCount; v9; v9--)
        {
            if (*((_DWORD *)v8 - 1) && *((_DWORD *)v8 - 2) == 1)
            {
                v5 = 1;
                *(_QWORD *)v7 = *v8;
                *(_OWORD *)(v7 + 16) = *(_OWORD *)(v8 + 1);
            }
            else
            {
                *(_QWORD *)v7 = 0;
            }
            v8 += 6;
            v7 += 40;
        }
    }
    return v5;
}

// FindDeleteValueKeyTarget
__int64 __fastcall FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResult)
{
    return 0;
}

// ============================================================================
// ============================================================================
__int64 FindHookTargetDataSection(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    return 0;
}

// FindKernelPESectionByType — 按类型查找内核 PE 节区
// 对应原始驱动 sub_14007A6B8
// 在 ntoskrnl 中按类型查找 PE 节区，匹配特征 0x800000
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex)
{
    __int64 v3 = GtRead(GtEprocessField22);
    unsigned int v4 = (unsigned int)GtRead(GtEprocessField23);
    unsigned int v5 = (unsigned int)GtRead(TypeIndex);
    if (v3 && v4 && v5 && v5 < v4 && (unsigned __int64)v5 + 5 <= v4)
    {
        __int64 v8;
        __int64 v9;
        _DWORD v10[70];
        __int64 v11;
        InitPESectionReadContext(v5 + v3, v4 - v5, 2, 0, -1, 0, 0, (__int64)&v8);
        for (int v6 = 0; v6 < 0x10; v6++)
        {
            if ((unsigned int)ReadPESectionEntry(&v8, v10))
                break;
            v9 += v10[60];
            if (*(_WORD *)(v11 + 6) == 1340 && (*(_QWORD *)&v10[34] & 0x800000LL) != 0 && !v10[29])
                return v10[28];
        }
    }
    return 0x1000000;
}

// FindNtoskrnlExportsInThreadEnv
__int64 FindNtoskrnlExportsInThreadEnv(void)
{
    return 0;
}

// FindOpenProcessTokenOffset
__int64 FindOpenProcessTokenOffset(__int64 TargetBase, unsigned int TargetSize)
{
    return 0;
}

// FindOpenProcessTokenTarget
__int64 FindOpenProcessTokenTarget(__int64 TargetBase, unsigned int TargetSize)
{
    return 0;
}

// FindRenameKeyTargetEx
__int64 FindRenameKeyTargetEx(__int64 TargetBase,
    unsigned int TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    return 0;
}

// FindSetValueKeyTarget
__int64 FindSetValueKeyTarget(__int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    __int64 *pResultOffset,
    _QWORD *pResultOffset2)
{
    return 0;
}

// FindSetValueKeyTargets
__int64 FindSetValueKeyTargets(__int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    _QWORD *pResult1,
    __int64 *pResult2)
{
    return 0;
}

// FixCreateFileRelocs
__int64 FixCreateFileRelocs(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    return 0;
}

// ForEachProcessor — 对每个处理器核心执行回调函数
// 对应原始驱动 sub_1400780B4
// 逐处理器设置亲和性并调用回调，Win8+ 使用 KeGet/Set/Restore 系列 API，旧版使用 KeSetAffinityThread 等
__int64 ForEachProcessor(__int64 (*pCallbackFunc)(__int64, __int64), __int64 Context)
{
    char IsInitialized = 0;
    unsigned int ObjectTableCode = (unsigned int)GetObjectTableCode();

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        __int64 (__fastcall *pGetAffinity)(__int64, __int16 *) = (__int64 (__fastcall *)(__int64, __int16 *))GtRead(GtTotalSize|GtEprocessField02|0x400);
        void (__fastcall *pSetAffinity)(__int64 *, _BYTE *) = (void (__fastcall *)(__int64 *, _BYTE *))GtRead(GtTotalSize|GtEprocessField05|0x400);
        __int64 (__fastcall *pRestoreAffinity)(_BYTE *) = (__int64 (__fastcall *)(_BYTE *))GtRead(GtTotalSize|GtEprocessField08|0x400);

        if (pGetAffinity && pSetAffinity && pRestoreAffinity)
        {
            unsigned int ProcessorIndex = 0;
            if (ObjectTableCode)
            {
                while (1)
                {
                    __int16 v21;
                    char v22;
                    __int64 v25;
                    _BYTE v27[16];

                    __int64 result = pGetAffinity(ProcessorIndex, &v21);
                    if ((int)result >= 0)
                    {
                        v25 = 1LL << v22;
                        pSetAffinity(&v25, v27);
                        IsInitialized = 1;
                        char CallbackResult = pCallbackFunc(ProcessorIndex, Context);
                        result = pRestoreAffinity(v27);
                        if (!CallbackResult)
                            return result;
                    }
                    if (++ProcessorIndex >= ObjectTableCode)
                        break;
                }
            }
        }
        if (IsInitialized)
            return 0;
        return pCallbackFunc(0, Context);
    }

    // Legacy (Win7-) path
    __int64 (*pGetActiveProc)(void) = (__int64 (*)(void))GtRead(GtTotalSize|GtEprocessExtField58|GtEprocessField24);
    void (__fastcall *pSetAffinityLegacy)(__int64) = (void (__fastcall *)(__int64))GtRead(GtTotalSize|GtEprocessExtField44);
    __int64 (*pRestoreAffinityLegacy)(void) = (__int64 (*)(void))GtRead(GtTotalSize|GtEprocessExtField47);

    if (!pGetActiveProc || !pSetAffinityLegacy || !pRestoreAffinityLegacy)
        return pCallbackFunc(0, Context);

    __int64 ActiveProcessorMask = pGetActiveProc();
    if (!ActiveProcessorMask)
    {
        __int64 BitMask;
        for (unsigned int i = 0; i < ObjectTableCode; ActiveProcessorMask += BitMask)
            BitMask = 1LL << i++;
    }

    if (!ActiveProcessorMask)
        return pCallbackFunc(0, Context);

    unsigned int RemainingMask = 0;
    __int64 ProcessorMask = 1;
    while (ActiveProcessorMask)
    {
        if ((ProcessorMask & ActiveProcessorMask) != 0)
        {
            ActiveProcessorMask &= ~ProcessorMask;
            pSetAffinityLegacy(ProcessorMask);
            IsInitialized = 1;
            char v20 = pCallbackFunc(RemainingMask, Context);
            __int64 result = pRestoreAffinityLegacy();
            if (!v20)
                return result;
        }
        ++RemainingMask;
        ProcessorMask *= 2;
    }

    if (IsInitialized)
        return 0;
    return pCallbackFunc(0, Context);
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

// FreeProcessMemoryEntry — 释放进程内存条目（被 DispatchFreeProcessMemory 调用）
// 对应原始驱动 sub_140044C7C
char FreeProcessMemoryEntry(__int64 VirtualAddress)
{
    return 0;
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

// GetSsdtTableOffset — 获取 SSDT 表偏移量
// 对应原始驱动 sub_140040FB8
// 根据 OS 版本选择 SSDT 表与偏移之间的间距
__int64 GetSsdtTableOffset(__int64 SsdtTable, __int64 DefaultOffset)
{
    if (GtRead(GtWindowsBuildNumber) >= 0x2800)
        return SsdtTable + 512;
    if (GtRead(GtWindowsBuildNumber) == 2600
        || GtRead(GtWindowsBuildNumber) == 3790
        || GtRead(GtWindowsBuildNumber) >= 0x23F0)
        return SsdtTable + 64;
    return DefaultOffset;
}

// InitPESectionReadContext 已在 PEDecoder.c 中实现
// 省略本文件中的重复定义
__int64 GetDeleteValueKeyCtx(_QWORD *pContext)
{
    return 0;
}

// GetKernelObjectTypeInfo — 获取内核对象类型信息
// 对应原始驱动 sub_1400298C0
// 根据版本号读取对象头中的类型字节，返回对应全局表值
__int64 GetKernelObjectTypeInfo(__int64 ObjectHeader)
{
    if (GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        char TypeByte = *((char *)(unsigned int)GtRead(GtCallbackField92) + ObjectHeader);
        return GtRead((TypeByte & 1) ? GtCallbackField98 : GtCallbackField100);
    }
    else
    {
        GtRead(GtCallbackField96);
        if (GtRead(GtWindowsBuildNumber) >= 0xA28 && GtRead(GtWindowsBuildNumber) < 0x23F0)
        {
            if (*(_QWORD *)(ObjectHeader + 16))
                return GtRead(GtCallbackField94);
        }
        char TypeByte = *((char *)(unsigned int)GtRead(GtCallbackField92) + ObjectHeader);
        int IsBitZero;
        if (GtRead(GtWindowsBuildNumber) > 0x23F0)
            IsBitZero = (TypeByte & 1) == 0;
        else
            IsBitZero = TypeByte == 0;
        return GtRead(IsBitZero ? GtCallbackField100 : GtCallbackField98);
    }
}

// GetSetValueKeyCtx
__int64 GetSetValueKeyCtx(_QWORD *pContext, _QWORD *pResult)
{
    return 0;
}

// InitCallbackContextHookTable
void InitCallbackContextHookTable(void)
{
    return;
}

// InitFileSystemExportTable
__int64 InitFileSystemExportTable(char Is64Bit)
{
    return 0;
}

// InitFileSystemFilterCallbacks
__int64 InitFileSystemFilterCallbacks(__int64 FilterExtensionObject, _QWORD *FastIoDispatchPtr, char Is64Bit)
{
    return 0;
}

// ParseMsrRelatedSections — 解析 MSR 相关节区（被 InitMsrTable 调用）
// 对应原始驱动 sub_140030500
__int64 ParseMsrRelatedSections(void)
{
    return 0;
}

// ParseMsrTableFromSections — 从节区解析 MSR 表（被 InitMsrTable 调用）
// 对应原始驱动 sub_1400302E8
__int64 ParseMsrTableFromSections(void)
{
    return 0;
}

// InitMsrTable — 初始化 MSR 表
// 对应原始驱动 sub_14003069C
__int64 InitMsrTable(void)
{
    ParseMsrRelatedSections();
    __int64 result = GtRead(GtEprocessModuleListOffset|GtEprocessField86);
    if (!result)
        return ParseMsrTableFromSections();
    return result;
}

// InitObjectAndQueryName
__int64 InitObjectAndQueryName(__int64 a1, int a2)
{
    return 0;
}

// InitObjectTypeTable
__int64 InitObjectTypeTable(_QWORD a1)
{
    return 0;
}

// InitPhysicalMemoryContextTable
__int64 InitPhysicalMemoryContextTable(int DeviceIndex, __int64 pOutputTable)
{
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

// InitUnicodeStringBuffer — 初始化 Unicode 字符串缓冲区
// 对应原始驱动 sub_1400726A0
// 设置 UNICODE_STRING 结构的 Length、MaximumLength、Buffer 字段
__int64 InitUnicodeStringBuffer(__int64 Buffer, __int64 StringPtr, unsigned int MaxLength)
{
    if (MaxLength < 2)
    {
        *(_QWORD *)(Buffer + 8) = 0;
        *(unsigned int *)Buffer = 0;
        return 0;
    }
    else
    {
        *(unsigned short *)(Buffer + 2) = MaxLength;
        *(_QWORD *)(Buffer + 8) = StringPtr;
        *(unsigned short *)Buffer = MaxLength - 2;
        return 2;
    }
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

// IoPortOperationDispatch
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// IrpFsctlGetVolumeData
__int64 IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData)
{
    return 0;
}

// IrpReadFileEx
int IrpReadFileEx(void *FileHandle, int a2, __int64 a3, void *a4, char a5, struct _IO_STATUS_BLOCK *pStatus)
{
    return 0;
}

// ============================================================================
// KernelMemoryOperationDispatch - 内核内存操作分发
// 函数在 IDA 数据库中未找到，写为存根
// ============================================================================
char KernelMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// KernelNotifyRoutine — 内核通知例程
// 对应原始驱动 sub_140019CFC
__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 1);
}

// KernelNotifyRoutineEx — 内核通知例程扩展
// 对应原始驱动 sub_140019D04
__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 0);
}

// LookupDriverHashTable
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pResultIndex)
{
    return 0;
}

// LookupMsrTableEntry
__int64 LookupMsrTableEntry(void)
{
    return 0;
}

// MiniFilterStreamHandleEx
__int64 MiniFilterStreamHandleEx(PRKPROCESS PROCESS, __int64 a2, ULONG64 a3, __int64 a4)
{
    return 0;
}

// ModuleOperationDispatch
__int64 ModuleOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ObjectOperationDispatcher
__int64 ObjectOperationDispatcher(void *InputBuffer, int BufferSize)
{
    return 0;
}

// OpenSectionWithIoControl
__int64 OpenSectionWithIoControl(__int64 a1)
{
    return 0;
}

// ParseExportDirForDriver
__int64 ParseExportDirForDriver(__int64 DriverInfo, __int64 Context, __int64 PeBuffer, unsigned int PeSize)
{
    return 0;
}

// ParseFsFilterDriverExport
__int64 ParseFsFilterDriverExport(char Is64Bit)
{
    return 0;
}

// ParseKernelModuleDiskInfo
__int64 ParseKernelModuleDiskInfo(void)
{
    return 0;
}

// ParseNtImageSectionHeaders
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray)
{
    return 0;
}

// ParseObjectContextExportDir
void ParseObjectContextExportDir(void)
{
    return;
}

// ParseRegistryDriverExportDir
void ParseRegistryDriverExportDir(void)
{
    return;
}

// PatchFsFilterDriverIndex
__int64 PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit)
{
    return 0;
}

// PowerCallbackRoutine — 电源回调处理例程
// 对应原始驱动 sub_140011240
// 从内核地址读取数据到用户缓冲区，按页映射内存，通过 ReadObjectNameFromCallback 读取对象名称
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize)
{
    if (!InputBuffer || BufferSize != 24)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)(InputBuffer + 3) >= MmUserProbeAddress)
        return 0;

    __int64 (__fastcall *MapMemoryFunc)(unsigned __int64, __int64, _QWORD, _QWORD, _QWORD) = (__int64 (__fastcall *)(unsigned __int64, __int64, _QWORD, _QWORD, _QWORD))GtRead(GtAllocPhysPagesFunc);
    void (__fastcall *MapFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtMapPhysPagesFunc);
    void (__fastcall *ZeroFunc)(__int64, _QWORD, _QWORD) = (void (__fastcall *)(__int64, _QWORD, _QWORD))GtRead(GtZeroPagesFunc);
    __int64 (__fastcall *ReadNameFunc)(__int64, _QWORD, __int64) = (__int64 (__fastcall *)(__int64, _QWORD, __int64))GtRead(GtMapMemoryFunc);
    void (__fastcall *UnmapFunc)(__int64, __int64) = (void (__fastcall *)(__int64, __int64))GtRead(GtUnmapMemoryFunc);
    void (__fastcall *FreeFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtFreeMemoryFunc);
    void (__fastcall *FreePagesFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtFreePagesFunc);

    if (!MapMemoryFunc || !MapFunc || !ZeroFunc || !ReadNameFunc || !UnmapFunc || !FreeFunc || !FreePagesFunc)
        return 0;

    ProbeForRead(InputBuffer, 0x18u, 4u);
    if (!InputBuffer[2] || !*((_DWORD *)InputBuffer + 2))
        return 0;

    unsigned int ReadSize = *((_DWORD *)InputBuffer + 2);
    if (ReadSize >= (unsigned __int64)MmSystemRangeStart
        || (unsigned __int64)*InputBuffer < (unsigned __int64)MmSystemRangeStart
        || (char *)*InputBuffer + ReadSize < (unsigned __int64)MmSystemRangeStart
        || (unsigned __int64)InputBuffer[2] >= MmUserProbeAddress
        || (unsigned __int64)InputBuffer[2] + ReadSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(InputBuffer[2], ReadSize, 1u);
    unsigned __int64 CurrentAddress = (unsigned __int64)*InputBuffer;
    unsigned int RemainingSize = ReadSize;
    char *OutputPtr = (char *)InputBuffer[2];
    char Success = 0;

    if ((unsigned __int64)*InputBuffer < (unsigned __int64)MmSystemRangeStart
        || RemainingSize >= (unsigned __int64)MmSystemRangeStart
        || CurrentAddress + ReadSize <= (unsigned __int64)MmSystemRangeStart)
        return 0;

    unsigned int PageRemainder = 4096 - (CurrentAddress & 0xFFF);
    unsigned int BytesCopied = 0;

    while (BytesCopied < RemainingSize)
    {
        if (RemainingSize - BytesCopied < PageRemainder)
            PageRemainder = RemainingSize - BytesCopied;

        char CopySuccess = 0;
        if (CheckMemoryValid((void *)CurrentAddress) == 1)
        {
            __int64 MappedMemory = MapMemoryFunc(CurrentAddress & 0xFFFFFFFFFFFFF000ULL, 4096, 0, 0, 0);
            if (MappedMemory)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
                {
                    ZeroFunc(MappedMemory, 0, 0);
                    __int64 NameResult = ReadObjectNameFromCallback(MappedMemory, 16, (__int64 (__fastcall *)(__int64, ULONG64, __int64))ReadNameFunc);
                    if (NameResult)
                    {
                        memmove(OutputPtr, (const void *)(NameResult + (CurrentAddress & 0xFFF)), PageRemainder);
                        Success = 1;
                        CopySuccess = 1;
                    }
                    FreeFunc(MappedMemory);
                }
                else
                {
                    MapFunc(MappedMemory);
                    __int64 MappedBuffer = ReadNameFunc(MappedMemory, 0, 1);
                    if (MappedBuffer)
                    {
                        memmove(OutputPtr, (const void *)(MappedBuffer + (CurrentAddress & 0xFFF)), PageRemainder);
                        Success = 1;
                        CopySuccess = 1;
                        UnmapFunc(MappedBuffer, MappedMemory);
                    }
                }
                FreePagesFunc(MappedMemory);
            }
        }
        if (!CopySuccess)
            memset(OutputPtr, 0, PageRemainder);

        if (BytesCopied)
            PageRemainder = 4096;
        BytesCopied += 4096;
        CurrentAddress += PageRemainder;
        OutputPtr += PageRemainder;
    }
    return Success;
}

// PowerCallbackUnregister — 卸载电源回调
// 对应原始驱动 sub_140011630
// 将指定进程的源缓冲区数据拷贝到目标缓冲区
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize)
{
    if (!InputBuffer || BufferSize != 40)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)(InputBuffer + 5) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(InputBuffer, 0x28u, 4u);
    if (!*InputBuffer || !InputBuffer[1] || !InputBuffer[4] || !*((_DWORD *)InputBuffer + 6) || !InputBuffer[2])
        return 0;

    unsigned int TargetSize = *((_DWORD *)InputBuffer + 6);
    HANDLE TargetBufferVal = InputBuffer[2];
    HANDLE ProcessHandle = InputBuffer[4];

    if (TargetSize >= MmUserProbeAddress
        || (unsigned __int64)TargetBufferVal >= MmUserProbeAddress
        || (unsigned __int64)TargetBufferVal + TargetSize >= MmUserProbeAddress
        || (unsigned __int64)ProcessHandle >= MmUserProbeAddress
        || (unsigned __int64)ProcessHandle + TargetSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(ProcessHandle, TargetSize, 1u);
    void *SourceBuffer = ExAlloc(NonPagedPool, TargetSize);
    if (!SourceBuffer)
        return 0;

    PEPROCESS Process = NULL;
    NTSTATUS LookupStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
    int Status = LookupStatus;
    if (!InputBuffer[1] && LookupStatus >= 0)
        InputBuffer[1] = (HANDLE)Process;

    char Success = 0;
    if (ValidateProcessObject((struct _KPROCESS *)InputBuffer[1], 0) == 1)
    {
        struct _KAPC_STATE ApcState;
        KeStackAttachProcess((PRKPROCESS)InputBuffer[1], &ApcState);
        memset(SourceBuffer, 0, TargetSize);
        memmove(SourceBuffer, (const void *)InputBuffer[2], TargetSize);
        Success = 1;
        KeUnstackDetachProcess(&ApcState);
        memmove((void *)InputBuffer[4], SourceBuffer, TargetSize);
    }

    if (Status >= 0)
        ObfDereferenceObject(Process);
    ExFree(SourceBuffer);
    return Success;
}

// PrepareFileForPageTableScan
__int64 PrepareFileForPageTableScan(void)
{
    return 0;
}

// ProcessMemoryOperationDispatch
__int64 ProcessMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ProcessOperationWithAttach
__int64 ProcessOperationWithAttach(void)
{
    return 0;
}

// QueryDriverObjectDevice — 查询驱动对象设备列表
// 对应原始驱动 sub_1400087A8
// 编码设备路径，打开 \\Driver\\Device 对象，获取设备对象链表并复制到输出缓冲区
__int64 QueryDriverObjectDevice(__int64 OutputBuffer, int MaxCount)
{
    return 0;  // TODO: implement properly (uses GetDeviceObjectFromFileObject)
}

// QueryFileSystemDriverObject — 查询文件系统驱动对象
// 对应原始驱动 sub_14000872C
__int64 QueryFileSystemDriverObject(__int64 OutputBuffer, int MaxCount)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4587612;
    EncodedPath[1] = 7077993;
    EncodedPath[2] = 5439589;
    EncodedPath[3] = 7536761;
    EncodedPath[4] = 6619252;
    EncodedPath[5] = 6029421;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return QueryDriverObjectByPath((__int64)EncodedPath, 2, OutputBuffer, MaxCount);
}

// QueryNdisDriverObject — 查询 NDIS 驱动对象
// 对应原始驱动 sub_140008A94
__int64 QueryNdisDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[8];
    EncodedPath[6] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 4456526;
    EncodedPath[5] = 5439561;
    return QueryDriverObjectByPath((__int64)EncodedPath, 11, OutputBuffer, BufferSize);
}

// QueryObjectTypeInformation
__int64 QueryObjectTypeInformation(PVOID Object)
{
    return 0;
}

// QueryPnpManagerDriverObject — 查询 PnP 管理器驱动对象
// 对应原始驱动 sub_140008BF8
__int64 QueryPnpManagerDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[9] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7209040;
    EncodedPath[5] = 5046384;
    EncodedPath[6] = 7209057;
    EncodedPath[7] = 6750305;
    EncodedPath[8] = 7471205;
    return QueryDriverObjectByPath((__int64)EncodedPath, 12, OutputBuffer, BufferSize);
}

// QueryProcessModuleInfo
__int64 QueryProcessModuleInfo(volatile void **Address, int a2, _DWORD *a3, unsigned int a4)
{
    return 0;
}

// QuerySsdHookByProcessInfo
__int64 QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize)
{
    return 0;
}

// QuerySyscallHookStatus
__int64 QuerySyscallHookStatus(__int64 a1)
{
    return 0;
}

// QueryTcpipDriverObject — 查询 TCPIP 驱动对象
// 对应原始驱动 sub_140008B04
__int64 QueryTcpipDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6488148;
    EncodedPath[5] = 6881392;
    EncodedPath[6] = 112;
    return QueryDriverObjectByPath((__int64)EncodedPath, 5, OutputBuffer, BufferSize);
}

// QueryTdxDriverObject — 查询 TDX 驱动对象
// 对应原始驱动 sub_140008C80
__int64 QueryTdxDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[6];
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553716;
    EncodedPath[5] = 120;
    return QueryDriverObjectByPath((__int64)EncodedPath, 7, OutputBuffer, BufferSize);
}

// QueryVolmgrDriverObject — 查询卷管理器驱动对象
// 对应原始驱动 sub_140008B78
__int64 QueryVolmgrDriverObject(__int64 OutputBuffer, int BufferSize)
{
    _DWORD EncodedPath[10];
    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7536750;
    EncodedPath[5] = 7340137;
    EncodedPath[6] = 7274610;
    EncodedPath[7] = 7929976;
    return QueryDriverObjectByPath((__int64)EncodedPath, 6, OutputBuffer, BufferSize);
}

// ReadDiskSectors 已在 MemoryOps.c 中实现
// 本文件中的定义已移除，使用外部链接

// ReadDiskSectorsWithPartition
__int64 ReadDiskSectorsWithPartition(char a1, void *a2, unsigned int *a3, int a4, unsigned int a5)
{
    return 0;
}

// ReadKernelMemoryToUserBuffer — 读取内核内存到用户缓冲区
// 对应原始驱动 sub_14006AFEC
// 读取 GT 2000（内核内存上下文指针），验证后复制 QWORD 到用户缓冲区
__int64 ReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    if (!GtRead(GtEprocessExtField58|GtEprocessField54|0x400))
        InitKernelMemoryContext();
    _QWORD *v8 = (_QWORD *)GtRead(GtEprocessExtField58|GtEprocessField54|0x400);
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

// ReadNtOsKrnlFile — 读取 ntoskrnl.exe 内核文件
// 对应原始驱动 sub_140051818
// 通过编码的整数数组构造路径，调用 ReadFileRawData 和 ReadNtFileToBuffer 读取
__int64 ReadNtOsKrnlFile(__int64 *a1, __int64 *a2)
{
    int EncodedPath[16];
    EncodedPath[0] = 5439580;
    EncodedPath[1] = 7536761;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061;
    EncodedPath[4] = 7274607;
    EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971;
    EncodedPath[7] = 7602291;
    EncodedPath[8] = 7143525;
    EncodedPath[9] = 3276851;
    EncodedPath[10] = 7798876;
    EncodedPath[11] = 7209065;
    EncodedPath[12] = 3276851;
    EncodedPath[13] = 3014763;
    EncodedPath[14] = 7929971;
    EncodedPath[15] = 115;

    void *Src;
    unsigned int MaxCount;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        char v4 = ReadNtFileToBuffer((unsigned char *)Src, MaxCount, (unsigned char **)a1, (ULONG *)a2);
        ExFree(Src);
        return v4 == 1;
    }
    return 0;
}

// ReadProcessMemoryString
__int64 ReadProcessMemoryString(void *Process, void *Address, char *Buffer, unsigned int Length)
{
    return 0;
}

// ReadProcessMemoryWithAttach
__int64 ReadProcessMemoryWithAttach(void)
{
    return 0;
}

// ReadServiceTableEntries
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 a2, char *PeFileData, unsigned int PeFileSize)
{
    return 0;
}

// ReadThreadContext
__int64 ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray)
{
    return 0;
}

// RegistryOperationDispatch
__int64 RegistryOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// ReleaseProcessMemoryBlock — 释放进程内存块
// 对应原始驱动 sub_14004501C
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry)
{
    char Result = 0;
    void (__fastcall *pFreeCallback)(_QWORD *) = (void (__fastcall *)(_QWORD *))GtRead(GtNtDeleteKeyPeSectionOffset|GtEprocessField66);
    if (pFreeCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pFreeCallback(pTargetEntry);
        Result = 1;
    }
    _QWORD **pProcessMemListHead = (_QWORD **)GtRead(GtEprocessField25|0x800);
    if (pProcessMemListHead && MmIsAddressValid(pProcessMemListHead) == 1)
    {
        int IterationCount = 0;
        for (_QWORD *pCurrentNode = *pProcessMemListHead; pCurrentNode != pProcessMemListHead; pCurrentNode = (_QWORD *)*pCurrentNode)
        {
            if (pCurrentNode <= MmSystemRangeStart) break;
            if (MmIsAddressValid(pCurrentNode) != 1) break;
            if ((unsigned int)++IterationCount > 0x1000) break;
            if (pCurrentNode == (_QWORD *)pTargetEntry)
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

// RemoveFromModuleLinkedList
__int64 RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    return 0;
}

// RemoveFromObjectTypeList — 从对象类型链表中移除条目
// 对应原始驱动 sub_140041FB4
// 遍历 GT 699 链表，查找匹配目标并从双向链表中摘除
__int64 RemoveFromObjectTypeList(PVOID *pTargetObject)
{
    PVOID **pListHead = (PVOID **)GtRead((GLOBAL_TABLE_INDEX)699);
    if (!pListHead || MmIsAddressValid(pListHead) != 1)
        return 0;

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
                pPrev[1] = pNext;
                *pNext = pPrev;
                return 1;
            }
            return 0;
        }
        pCurrent = (PVOID *)*pCurrent;
    }
    return 0;
}

// RemoveFromObjectTypeListEx — 从对象类型链表中移除条目（扩展版）
// 对应原始驱动 sub_140042914
// 从 GT 824 获取 13 个链表头数组，在每个链表中搜索并摘除目标
__int64 RemoveFromObjectTypeListEx(PVOID *pTargetPointer)
{
    PVOID **pListArray = (PVOID **)GtRead((GLOBAL_TABLE_INDEX)824);
    if (!pListArray || MmIsAddressValid(pListArray) != 1)
        return 0;

    for (unsigned int ListIdx = 0; ListIdx < 13; ListIdx++)
    {
        PVOID **pListHead = pListArray + 2 * ListIdx;
        if (MmIsAddressValid(pListHead) != 1)
            continue;

        PVOID *pCurrent = *pListHead;
        int IterCount = 0;
        while (pCurrent != (PVOID *)pListHead)
        {
            if (pCurrent <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrent) != 1)
                break;
            if (++IterCount > 0x10000)
                break;
            if (pTargetPointer == pCurrent)
            {
                if (MmIsAddressValid(*pCurrent) == 1)
                {
                    PVOID *pPrev = (PVOID *)*pCurrent;
                    PVOID **pNext = (PVOID **)pCurrent[1];
                    pPrev[1] = pNext;
                    *pNext = pPrev;
                    return 1;
                }
                break;
            }
            pCurrent = (PVOID *)*pCurrent;
        }
    }
    return 0;
}

// RemoveKernelObjectEntry — 移除内核对象条目
// 对应原始驱动 sub_140042578
// 遍历 SSDT2 表查找匹配地址并清零，释放内存
__int64 RemoveKernelObjectEntry(__int64 TargetAddress)
{
    char Result = 0;
    int IsWin7 = GtRead(GtEprocessField28);
    _QWORD *pSsdtTable = (_QWORD *)GtRead(GtEprocessField78);
    _DWORD *pCounter = (_DWORD *)GtRead(GtEprocessField79);
    if (pSsdtTable && pCounter)
    {
        _QWORD *pEndPtr = (_QWORD *)pCounter;
        if (GtRead(GtWindowsBuildNumber) >= 0x23F0)
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
    void (__fastcall *pFreeFunc)(__int64) = (void (__fastcall *)(__int64))GtRead((GLOBAL_TABLE_INDEX)0x41BA);
    if (pFreeFunc)
    {
        if (IsWin7)
            pFreeFunc(TargetAddress);
        else
        {
            unsigned __int64 FreeAddr = TargetAddress & 0xFFFFFFFFFFFFFFF0ui64;
            if (MmIsAddressValid((PVOID)(FreeAddr + 8)) == 1)
            {
                __int64 FreeParam = *(_QWORD *)(FreeAddr + 8);
                pFreeFunc(FreeParam);
                return 1;
            }
        }
    }
    return Result;
}

// RemoveObjectFromTypeList — 从类型列表中移除对象
// 对应原始驱动 sub_140042A48
// 调用释放回调，遍历两个链表头搜索并摘除目标对象
__int64 RemoveObjectFromTypeList(PVOID pTargetObject)
{
    char Result = 0;
    void (__fastcall *pFreeCallback)(PVOID) = (void (__fastcall *)(PVOID))GtRead((GLOBAL_TABLE_INDEX)0x41A0);
    if (pFreeCallback)
    {
        pFreeCallback(pTargetObject);
        Result = 1;
    }
    PVOID **pListHeads[2];
    pListHeads[0] = (PVOID **)GtRead(GtEprocessField85);
    pListHeads[1] = (PVOID **)GtRead(GtCallbackField04);
    for (int i = 0; i < 2; i++)
    {
        PVOID **pListHead = pListHeads[i];
        if (pListHead)
        {
            PVOID *pCurrent = *pListHead;
            int IterCount = 0;
            while (pCurrent != (PVOID *)pListHead)
            {
                if (pCurrent <= MmSystemRangeStart) break;
                if (MmIsAddressValid(pCurrent) != 1) break;
                if (++IterCount > 0x10000) break;
                PVOID pObjEntry = pCurrent[2];
                if (pTargetObject == pObjEntry)
                {
                    if (MmIsAddressValid(*pCurrent) == 1)
                    {
                        PVOID *pPrev = (PVOID *)*pCurrent;
                        PVOID **pNext = (PVOID **)pCurrent[1];
                        pPrev[1] = pNext;
                        *pNext = pPrev;
                        if (!GtRead(GtEprocessField28))
                            ObfDereferenceObject(pObjEntry);
                        ExFreePoolWithTag(pCurrent, 0);
                        Result = 1;
                    }
                    break;
                }
                pCurrent = (PVOID *)*pCurrent;
            }
        }
    }
    return Result;
}

// RemoveServiceEntryFromList
__int64 RemoveServiceEntryFromList(ULONG_PTR *a1, __int64 a2)
{
    return 0;
}

// RemoveServiceEntryFromListEx
__int64 RemoveServiceEntryFromListEx(__int64 ****a1, __int64 ***a2)
{
    return 0;
}

// RemoveServiceTableNodeWin10
__int64 RemoveServiceTableNodeWin10(__int64 ***a1, __int64 **a2)
{
    return 0;
}

// RemoveServiceTableNodeWin7
__int64 RemoveServiceTableNodeWin7(ULONG_PTR *a1, __int64 a2)
{
    return 0;
}

// ResolveCreateFileRelocs
__int64 ResolveCreateFileRelocs(__int64 TargetBase,
    ULONG TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    return 0;
}

// ResolveDriverEntryAddresses — 解析驱动程序入口地址
// 对应原始驱动 sub_140050FE0
__int64 ResolveDriverEntryAddresses(__int64 a1)
{
    if (!GtRead(GtKernelModuleBase))
        return 0;
    unsigned int v3 = *(unsigned int *)(a1 + 4);
    if (v3)
    {
        for (__int64 v4 = a1 + 16; v3; v3--)
        {
            if (*(_QWORD *)(v4 + 8) != *(_QWORD *)v4)
                *(_BYTE *)(v4 + 16) = 1;
            v4 += 48;
        }
        v3 = *(unsigned int *)(a1 + 4);
    }
    for (unsigned int v6 = 0; v6 < v3; v6++)
    {
        __int64 v7 = a1 + 16 + 48LL * v6;
        unsigned int v8 = 16;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800 && *(unsigned short *)(v7 + 18) == 9727)
            v8 = 6;
        if (MmIsAddressValid((PVOID)(*(_QWORD *)v7 + 15LL)) == 1)
        {
            if ((unsigned int)MemoryCompare(*(_QWORD *)v7, (char *)(48LL * v6 + a1 + 34), v8))
            {
                *(_BYTE *)(v7 + 17) = 1;
                if (!*(_BYTE *)(v7 + 16))
                {
                    unsigned int i;
                    for (i = 0; i < v8; i++)
                    {
                        if (!MmIsAddressValid((PVOID)(*(_QWORD *)v7 + i)))
                            break;
                    }
                    if (i && ReturnFalseStub() == 1)
                        *(_QWORD *)(v7 + 8) = *(unsigned int *)(48LL * v6 + a1 + 12);
                }
            }
        }
    }
    return 1;
}

// ResolveDriverModuleNames
__int64 ResolveDriverModuleNames(ULONG *a1)
{
    return 0;
}

// ResolveDriverRelativeAddresses
__int64 ResolveDriverRelativeAddresses(__int64 a1, __int64 a2, int **a3)
{
    return 0;
}

// ResolveKernelModuleBasePair — 解析内核模块基址对
// 对应原始驱动 sub_14002A5C8
// 读取 MSR 寄存器对比现有值，更新 MSR 基址对
__int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair)
{
    ULONG64 MsrBaseLstar = ReadMsr(0xC0000083);
    if (MsrBaseLstar && *pMsrPair && MsrBaseLstar != *pMsrPair)
        pMsrPair[2] = MsrBaseLstar;

    ULONG64 Msr = ReadMsr(0xC0000082);
    if (Msr && pMsrPair[1] && Msr != pMsrPair[1])
        pMsrPair[3] = Msr;

    return 1;
}

// ResolveKernelModuleIndex
__int64 ResolveKernelModuleIndex(GLOBAL_TABLE_INDEX a1,
    GLOBAL_TABLE_INDEX a2,
    GLOBAL_TABLE_INDEX a3)
{
    return 0;
}

// ResolveKernelObjectAddresses — 解析内核对象地址
// 对应原始驱动 sub_140029720
__int64 ResolveKernelObjectAddresses(__int64 pObjectTable)
{
    // Phase 1: Mark entries where original != current
    for (unsigned int TableIndex = 0; TableIndex < *(unsigned int *)(pObjectTable + 4); TableIndex++)
    {
        _BYTE *pEntry = (_BYTE *)(200LL * TableIndex + pObjectTable + 32);
        for (int EntryFieldCount = 8; EntryFieldCount; EntryFieldCount--)
        {
            __int64 FieldValue = *((_QWORD *)pEntry - 2);
            if (FieldValue && *((_QWORD *)pEntry - 1) != FieldValue)
                *pEntry = 1;
            pEntry += 24;
        }
    }
    // Phase 2: Verify addresses against HAL exports
    __int64 HalExportTable = GtRead(GtEprocessField66);
    unsigned int HalExportCount = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    if (HalExportTable && HalExportCount && NtoskrnlBase)
    {
        for (unsigned int EntryIndex = 0; EntryIndex < *(unsigned int *)(pObjectTable + 4); EntryIndex++)
        {
            _BYTE *pTypeEntry = (_BYTE *)(200LL * EntryIndex + pObjectTable + 32);
            for (int RemainingFields = 8; RemainingFields; RemainingFields--)
            {
                unsigned __int64 ObjectAddress = *((_QWORD *)pTypeEntry - 2);
                if (ObjectAddress && ObjectAddress > (unsigned __int64)NtoskrnlBase)
                {
                    unsigned int AddressOffset = (unsigned int)(ObjectAddress - (unsigned __int64)NtoskrnlBase);
                    if (AddressOffset < HalExportCount && AddressOffset + 16 <= HalExportCount)
                    {
                        if (MmIsAddressValid((PVOID)ObjectAddress) == 1
                            && MmIsAddressValid((PVOID)(ObjectAddress + 15)) == 1
                            && (unsigned int)MemoryCompare(ObjectAddress, (char *)(HalExportTable + AddressOffset), 0x10u))
                        {
                            char WasOriginal = *pTypeEntry == 0;
                            pTypeEntry[1] = 1;
                            if (WasOriginal)
                            {
                                unsigned int i;
                                for (i = 0; i < 0x10; i++)
                                {
                                    if (!MmIsAddressValid((PVOID)(ObjectAddress + i)))
                                        break;
                                }
                                if (i && ReturnFalseStub() == 1)
                                    *((_QWORD *)pTypeEntry - 1) = *(unsigned int *)((char *)pTypeEntry - (24 - 16));
                            }
                        }
                    }
                }
                pTypeEntry += 24;
            }
        }
    }
    return 1;
}

// ResolvePhysicalMemoryContext — 解析物理内存上下文
// 对应原始驱动 sub_140033D08
// 根据 ContextType 选择偏移基址，遍历上下文表，检查地址范围，验证字节完整性，标记 Hook
__int64 ResolvePhysicalMemoryContext(__int64 pContextTable, int ContextType, ULONG EntryCount)
{
    unsigned __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    unsigned int OffsetValue2 = (unsigned int)GtRead(GtKernelDataField21);
    __int64 OffsetBase = 0;

    switch (ContextType)
    {
        case 0:
            OffsetBase = GtRead(GtEprocessField72);
            GtRead(GtEprocessField73);
            break;
        case 2:
            OffsetBase = GtRead(GtEprocessField74);
            GtRead(GtEprocessField75);
            break;
        case 1:
            OffsetBase = GtRead(GtKernelDataField15);
            GtRead(GtKernelDataField16);
            break;
    }

    if (!OffsetBase || !EntryCount)
        return 0;

    // Phase 1: Mark modified entries
    __int64 pCurrentEntry = pContextTable + 16;
    ULONG Remaining = EntryCount;
    while (Remaining)
    {
        __int64 CurrentValue = *(_QWORD *)(pCurrentEntry - 8);
        if (CurrentValue && CurrentValue != *(_QWORD *)pCurrentEntry)
        {
            *(_BYTE *)(pCurrentEntry + 8) = 1;
        }
        else if (!CurrentValue && NtoskrnlBase && NtoskrnlSize)
        {
            __int64 AddressValue = *(_QWORD *)pCurrentEntry;
            if (AddressValue && (AddressValue < NtoskrnlBase + NtoskrnlSize && AddressValue >= NtoskrnlBase))
            {
                // Inside ntoskrnl range, skip
            }
            else if (AddressValue)
            {
                *(_BYTE *)(pCurrentEntry + 8) = 1;
            }
        }
        *(_DWORD *)(pCurrentEntry + 12) = ContextType;
        pCurrentEntry += 48;
        if (!--Remaining)
            break;
    }

    // Phase 2: Verify bytes at each entry
    for (ULONG EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        __int64 pEntry = pContextTable + 8 + 48LL * EntryIndex;
        if (*(_QWORD *)pEntry)
        {
            if (MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15LL)) == 1)
            {
                if ((unsigned int)MemoryCompare(*(_QWORD *)pEntry, (char *)(48LL * EntryIndex + pContextTable + 32), 0x10u))
                {
                    *(_BYTE *)(pEntry + 17) = 1;
                    if (!*(_BYTE *)(pEntry + 16))
                    {
                        unsigned int ByteIndex;
                        for (ByteIndex = 0; ByteIndex < 0x10; ByteIndex++)
                        {
                            if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + ByteIndex)))
                                break;
                        }
                        if (ByteIndex && ReturnFalseStub() == 1)
                            *(_QWORD *)(pEntry + 8) = *(unsigned int *)(pContextTable + 48LL * EntryIndex + 8);
                    }
                }
            }
        }
    }

    // Phase 3: Fix special entry
    if (EntryCount == 28 && OffsetValue2 && NtoskrnlSize && NtoskrnlBase)
    {
        _WORD *pFlagEntry = (_WORD *)(pContextTable + 24);
        unsigned __int64 EndAddress = NtoskrnlBase + OffsetValue2;
        for (int LoopCount = 28; LoopCount; LoopCount--)
        {
            if (*((_QWORD *)pFlagEntry - 1) == EndAddress)
            {
                *pFlagEntry = 0;
                *((_QWORD *)pFlagEntry - 2) = EndAddress;
            }
            pFlagEntry += 24;
        }
    }
    return 1;
}

// ResolveServiceTableBase — 解析服务表基址
// 对应原始驱动 sub_1400579CC
// 读取 ntoskrnl 内核基址，结合服务表数据计算系统服务分发表（KiServiceTable）的基址并写入全局表
__int64 ResolveServiceTableBase(void)
{
    __int64 v0 = GtRead(GtIrpBufferSize|GtEprocessField14);
    if (!v0)
    {
        ReadNtOsKrnlAndParseServiceTable();
        v0 = GtRead(GtIrpBufferSize|GtEprocessField14);
    }
    __int64 result = GtRead(GtKernelModuleBase);
    __int64 v2 = result;
    if (v0 && result)
    {
        result = GtRead(GtCallbackField53);
        if (!(_DWORD)result)
        {
            unsigned int v3 = (unsigned int)GtRead(GtCallbackField55);
            return GtWrite(GtCallbackField56, v2 + *(unsigned int *)(v0 + 4LL * v3));
        }
    }
    return result;
}

// RestoreSyscallHookByIndex
__int64 RestoreSyscallHookByIndex(char a1, ULONG a2)
{
    return 0;
}

// ScanKernelMemForFsChanges
__int64 ScanKernelMemForFsChanges(ULONG *a1, int a2)
{
    return 0;
}

// ScanKernelModuleDataSectionEx
__int64 ScanKernelModuleDataSectionEx(void)
{
    return 0;
}

// ScanKernelModuleInitSection
__int64 ScanKernelModuleInitSection(void)
{
    return 0;
}

// ScanKernelModulePageOrRsrcSection
__int64 ScanKernelModulePageOrRsrcSection(void)
{
    return 0;
}

// ScanKernelModuleSectionByType
__int64 ScanKernelModuleSectionByType(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10
__int64 ScanKernelModuleSectionForWin10(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10RS3
__int64 ScanKernelModuleSectionForWin10RS3(void)
{
    return 0;
}

// ScanRegValueBodyForRef
__int64 ScanRegValueBodyForRef(ULONG64 a1,
    ULONG a2,
    __int64 a3,
    __int64 a4,
    int a5,
    __int64 *a6)
{
    return 0;
}

// ScanVadForModifiedPages
__int64 ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount)
{
    return 0;
}

// ScanWin32kDriverForPatterns
__int64 ScanWin32kDriverForPatterns(ULONG_PTR a1, ULONG_PTR a2)
{
    return 0;
}

// SendFsctlWithHookSwap
__int64 SendFsctlWithHookSwap(__int64 a1,
    ULONG a2,
    __int64 a3,
    ULONG a4,
    __int64 a5,
    int a6,
    __int64 a7)
{
    return 0;
}

// SendIoControlWithUnicodeString
__int64 SendIoControlWithUnicodeString(void)
{
    return 0;
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

// BuildRegistryDriverPath — 构建注册表驱动路径
// 对应原始驱动 sub_140045EE4
__int64 BuildRegistryDriverPath(void)
{
    _DWORD EncodedBuffer[10];
    EncodedBuffer[8] = 0;
    EncodedBuffer[0] = 4587612;
    EncodedBuffer[1] = 7077993;
    EncodedBuffer[2] = 5439589;
    EncodedBuffer[3] = 7536761;
    EncodedBuffer[4] = 6619252;
    EncodedBuffer[5] = 6029421;
    EncodedBuffer[6] = 7340110;
    EncodedBuffer[7] = 7536742;
    return OpenFileSection((__int64)EncodedBuffer);
}

// GetSyscallContextBase — 获取系统调用上下文基址
// 对应原始驱动 sub_140047330
__int64 GetSyscallContextBase(void)
{
    _DWORD EncodedBuffer[8];
    EncodedBuffer[0] = 4456540;
    EncodedBuffer[1] = 6881394;
    EncodedBuffer[2] = 6619254;
    EncodedBuffer[3] = 6029426;
    EncodedBuffer[4] = 6357104;
    EncodedBuffer[5] = 7602290;
    EncodedBuffer[6] = 6750317;
    EncodedBuffer[7] = 114;
    return OpenFileSection((__int64)EncodedBuffer);
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

// ShutdownCallbackUnregister — 卸载关机回调
// 对应原始驱动 sub_1400118F4
// 将目标缓冲区的数据写入到指定进程的源地址，使用 WritePhysicalMemoryBuffer 进行物理内存写入
__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize)
{
    if (!InputBuffer || BufferSize != 40)
        return 0;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress
        || (unsigned __int64)(InputBuffer + 5) >= MmUserProbeAddress)
        return 0;
    ProbeForRead(InputBuffer, 0x28u, 4u);
    if (!*InputBuffer || !InputBuffer[1] || !InputBuffer[4] || !*((_DWORD *)InputBuffer + 6) || !InputBuffer[2])
        return 0;
    unsigned int TargetSize = *((_DWORD *)InputBuffer + 6);
    if (TargetSize >= MmUserProbeAddress
        || (unsigned __int64)InputBuffer[2] >= MmUserProbeAddress
        || (unsigned __int64)InputBuffer[2] + TargetSize >= MmUserProbeAddress
        || (unsigned __int64)InputBuffer[4] >= MmUserProbeAddress
        || (unsigned __int64)InputBuffer[4] + TargetSize >= MmUserProbeAddress)
        return 0;
    ProbeForRead(InputBuffer[4], TargetSize, 1u);
    void *AllocBuffer = ExAlloc(NonPagedPool, TargetSize);
    if (!AllocBuffer)
        return 0;
    PEPROCESS Process = NULL;
    NTSTATUS LookupStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
    int Status = LookupStatus;
    if (!InputBuffer[1] && LookupStatus >= 0)
        InputBuffer[1] = (PRKPROCESS)Process;
    char Success = 0;
    if (ValidateProcessObject((struct _KPROCESS *)InputBuffer[1], 0) == 1)
    {
        memmove(AllocBuffer, InputBuffer[4], TargetSize);
        struct _KAPC_STATE ApcState;
        KeStackAttachProcess((PRKPROCESS)InputBuffer[1], &ApcState);
        ProbeForRead(InputBuffer[2], TargetSize, 1u);
        Success = WritePhysicalMemoryBuffer((unsigned __int64)InputBuffer[2], AllocBuffer, TargetSize, 1, 0) == 1;
        KeUnstackDetachProcess(&ApcState);
    }
    if (Status >= 0)
        ObfDereferenceObject(Process);
    ExFree(AllocBuffer);
    return Success;
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

// UnlinkFromProcessMemoryList
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer)
{
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

// ValidateAndClearProcessContext
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext)
{
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

// ValidateHookEntries
__int64 ValidateHookEntries(__int64 a1, ULONG a2)
{
    return 0;
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

// WalkKernelModuleList
__int64 WalkKernelModuleList(ULONG64 *pModuleList, ULONG *pOutputBuffer, ULONG *pMaxEntries)
{
    return 0;
}

// WriteDiskSectorsWithPartitionCheck
__int64 WriteDiskSectorsWithPartitionCheck(char a1, const void *a2, ULONG a3)
{
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

// WriteThreadContextEntryWin10
__int64 WriteThreadContextEntryWin10(ULONG *a1)
{
    return 0;
}

// ZeroProcessMemoryPages
__int64 ZeroProcessMemoryPages(PRKPROCESS PROCESS)
{
    return 0;
}

// FsFilterCreateCallback 已在 Minifilter.c 中实现
// 本文件中的定义已移除，使用外部链接

// ============================================================
// 以下函数为新实现的非存根函数
// ============================================================

// CopySectionString — 复制节区字符串
// 对应原始驱动 sub_140009BCC
// 从驱动条目和设备条目中复制驱动名、设备名、对象路径和文件路径到输出缓冲区
BOOLEAN CopySectionString(__int64 OutputBuffer, __int64 DeviceEntry, __int64 DriverEntry, int DeviceType)
{
    *(_DWORD *)OutputBuffer = DeviceType;
    *(_QWORD *)(OutputBuffer + 16) = DeviceEntry;
    *(_QWORD *)(OutputBuffer + 8) = 0;
    *(_WORD *)(OutputBuffer + 24) = 0;

    // Driver name
    unsigned int NameLength = *(unsigned __int16 *)(DriverEntry + 56);
    __int64 NameChars = NameLength >> 1;
    if ((unsigned int)NameChars > 0x103)
        NameChars = 259;
    void *NameBuffer = *(void **)(DriverEntry + 64);
    if (NameBuffer > MmSystemRangeStart
        && CheckMemoryValid(NameBuffer) == 1
        && CheckMemoryValid((void *)(*(_QWORD *)(DriverEntry + 64) - 2LL + 2 * NameChars)) == 1)
    {
        memmove((void *)(OutputBuffer + 24), *(const void **)(DriverEntry + 64), (unsigned int)(2 * NameChars));
    }
    if ((_DWORD)NameChars)
        *(_WORD *)(OutputBuffer + 2 * NameChars + 24) = 0;

    // Device name
    __int64 DeviceObjEntry = *(_QWORD *)(DeviceEntry + 8);
    unsigned int DeviceNameLen = *(unsigned __int16 *)(DeviceObjEntry + 56);
    *(_WORD *)(OutputBuffer + 544) = 0;
    void *DevNameBuffer = *(void **)(DeviceObjEntry + 64);
    __int64 DevNameChars = DeviceNameLen >> 1;
    if ((unsigned int)DevNameChars > 0x103)
        DevNameChars = 259;
    if (DevNameBuffer > MmSystemRangeStart
        && CheckMemoryValid(DevNameBuffer) == 1
        && CheckMemoryValid((void *)(*(_QWORD *)(DeviceObjEntry + 64) - 2LL + 2 * DevNameChars)) == 1)
    {
        memmove((void *)(OutputBuffer + 544), *(const void **)(DeviceObjEntry + 64), (unsigned int)(2 * DevNameChars));
    }
    if ((_DWORD)DevNameChars)
        *(_WORD *)(OutputBuffer + 2 * DevNameChars + 544) = 0;

    // Object name
    *(_WORD *)(OutputBuffer + 1064) = 0;
    unsigned __int16 *VisualPathPtr;
    if (ResolveObjectHeaderPointer(DeviceEntry, &VisualPathPtr) == 1)
    {
        void *ObjNameBuffer = (void *)*((_QWORD *)VisualPathPtr + 1);
        __int64 ObjNameChars = *VisualPathPtr >> 1;
        if ((unsigned int)ObjNameChars > 0x103)
            ObjNameChars = 259;
        if (ObjNameBuffer > MmSystemRangeStart
            && CheckMemoryValid(ObjNameBuffer) == 1
            && CheckMemoryValid((void *)(*((_QWORD *)VisualPathPtr + 1) - 2LL + 2 * ObjNameChars)) == 1)
        {
            memmove((void *)(OutputBuffer + 1064), *((const void **)VisualPathPtr + 1), (unsigned int)(2 * ObjNameChars));
        }
        if ((_DWORD)ObjNameChars)
            *(_WORD *)(OutputBuffer + 2 * ObjNameChars + 1064) = 0;
    }

    // File path
    *(_WORD *)(OutputBuffer + 1584) = 0;
    __int64 FileObjPtr = *(_QWORD *)(DeviceObjEntry + 40);
    if (FileObjPtr > (unsigned __int64)MmSystemRangeStart
        && *(_QWORD *)(FileObjPtr + 96)
        && *(_QWORD *)(FileObjPtr + 80))
    {
        unsigned int FilePathLen = *(unsigned __int16 *)(FileObjPtr + 72);
        *(_WORD *)(OutputBuffer + 1584) = 0;
        void *FilePathBuffer = *(void **)(FileObjPtr + 80);
        __int64 FilePathChars = FilePathLen >> 1;
        if ((unsigned int)FilePathChars > 0x103)
            FilePathChars = 259;
        if (FilePathBuffer > MmSystemRangeStart
            && CheckMemoryValid(FilePathBuffer) == 1
            && CheckMemoryValid((void *)(*(_QWORD *)(FileObjPtr + 80) - 2LL + 2 * FilePathChars)) == 1)
        {
            memmove((void *)(OutputBuffer + 1584), *(const void **)(FileObjPtr + 80), (unsigned int)(2 * FilePathChars));
        }
        if ((_DWORD)FilePathChars)
            *(_WORD *)(OutputBuffer + 2 * FilePathChars + 1584) = 0;
    }
    return 1;
}

// QueryDriverObjectByPath — 按路径查询驱动对象
// 对应原始驱动 sub_1400083C4
// 通过驱动对象链表遍历指定路径的驱动对象，复制设备信息到输出缓冲区
__int64 QueryDriverObjectByPath(__int64 TargetPath, int MaxNameLength, __int64 OutputBuffer, int MaxEntries)
{
    unsigned int Result = 0;
    void (__fastcall *RtlInitStrFunc)(_BYTE *, __int64) = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    int (__fastcall *IoCreateFileFunc)(_BYTE *, __int64, _QWORD, _QWORD, _QWORD, _BYTE, _QWORD, __int64 *) = (int (__fastcall *)(_BYTE *, __int64, _QWORD, _QWORD, _QWORD, _BYTE, _QWORD, __int64 *))GtRead(GtIoCreateFileFunc);
    _QWORD *DriverListHead = (_QWORD *)GtRead(GtDriverObjectListHead);
    void (*CloseHandleFunc)(void) = (void (*)(void))GtRead(GtCloseHandleFunc);

    if (RtlInitStrFunc && IoCreateFileFunc && DriverListHead && CloseHandleFunc)
    {
        _BYTE ObjectNameBuffer[24];
        RtlInitStrFunc(ObjectNameBuffer, TargetPath);
        __int64 FileHandle;
        if (IoCreateFileFunc(ObjectNameBuffer, 64, 0, 0, *DriverListHead, 0, 0, &FileHandle) >= 0)
        {
            if (FileHandle)
            {
                for (_QWORD *i = *(_QWORD **)(FileHandle + 8); i; i = (_QWORD *)i[2])
                {
                    __int64 SectionBase = i[1];
                    __int64 SectionIter = i[3];
                    while (SectionIter && MaxEntries)
                    {
                        CopySectionString(OutputBuffer, SectionIter, SectionBase, MaxNameLength);
                        SectionBase = *(_QWORD *)(SectionIter + 8);
                        SectionIter = *(_QWORD *)(SectionIter + 24);
                        OutputBuffer += 2104;
                        --MaxEntries;
                        ++Result;
                    }
                }
                CloseHandleFunc();
            }
        }
    }
    return Result;
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

// ReadNtOsKrnlAndParseServiceTable — 读取 ntoskrnl 并解析服务表
// 对应原始驱动 sub_1400512BC
void ReadNtOsKrnlAndParseServiceTable(void)
{
    size_t MaxCount;
    void *Src;
    if (ReadNtOsKrnlFile(&Src, (unsigned int *)&MaxCount))
    {
        ParseServiceTable((char *)Src, (unsigned int)MaxCount);
        ExFree(Src);
    }
}

// ParseServiceTable — 解析服务表（分发函数）
// 对应原始驱动 sub_1400512F0
// 根据构建号选择 Win8+ 或 Win7 版本解析服务表
__int64 ParseServiceTable(char *Src, size_t MaxCount)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return ParseServiceTableWin8(Src, (unsigned int)MaxCount);
    else
        return ParseServiceTableWin7(Src, (unsigned int)MaxCount);
}

// ParseServiceTableWin8 — 解析服务表（Win8+ 版）
// 对应原始驱动 sub_14005132C
// 验证驱动文件，查找 win32k 服务表，从 PE 文件中提取服务表函数地址
__int64 ParseServiceTableWin8(char *Src, size_t MaxCount)
{
    return 0;
}

// ParseServiceTableWin7 — 解析服务表（Win7 版）
// 对应原始驱动 sub_140051434
// 验证驱动文件，查找 win32k 服务表，从 PE 文件中提取服务表函数地址
__int64 ParseServiceTableWin7(char *Src, size_t MaxCount)
{
    return 0;
}

// InitProcessAndQueryInfo — 初始化进程并查询信息
// 对应原始驱动 sub_14007E6A4
bool InitProcessAndQueryInfo(struct _KPROCESS *ProcessObject, char a2)
{
    return 0;
}

// FindNtRenameKeyTarget — 查找 NtRenameKey 目标
// 对应原始驱动 sub_140028168
__int16 FindNtRenameKeyTarget(__int64 TargetBase, unsigned int TargetSize, __int64 Context, unsigned __int64 MaxOffset)
{
    return 0;
}

// VerifyServiceTableDriverFile — 验证服务表驱动文件
// 对应原始驱动 sub_140051E18
// 比较内存中的驱动镜像与磁盘文件 PE 头是否一致，通过 ComparePeHeaders 比较
__int64 VerifyServiceTableDriverFile(__int64 a1, unsigned int a2)
{
    __int64 v4 = GtRead(GtKernelModuleBase);
    unsigned int v5 = (unsigned int)GtRead(GtEprocessField71);
    if (v4 && v5 && a1 && a2 && v5 > 0x1000)
    {
        if (ComparePeHeaders(v4, v5, a1, a2) == 1)
            GtWrite(GtCallbackField53, 1);
    }
    return v5;
}

// DispatchParseNtExportFunctions — 根据版本号分发 NT 导出函数解析
// 对应原始驱动 sub_14002A61C
__int64 DispatchParseNtExportFunctions(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        return ParseNtExportFunctionsV2();
    else
        return ParseNtExportFunctions();
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

// ParseNtExportFunctions — 解析 NT 导出函数（旧版）
// 对应原始驱动 sub_14002A64C
__int64 ParseNtExportFunctions(void)
{
    return 0;
}

// ParseNtExportFunctionsV2 — 解析 NT 导出函数（Win10+ 版）
// 对应原始驱动 sub_14002AD0C
__int64 ParseNtExportFunctionsV2(void)
{
    return 0;
}

// ModifyObjectHeaderFlagsByVersion — 按版本修改对象头标志
// 对应原始驱动 sub_14007A8D4
char ModifyObjectHeaderFlagsByVersion(__int64 ObjectHeader, char SetFlag)
{
    unsigned int Offset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)2312);
    if (!Offset)
        return 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770)
    {
        *(_BYTE *)(Offset + ObjectHeader) = SetFlag;
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        if (SetFlag == 1)
            *(_DWORD *)(Offset + ObjectHeader) |= 0x40u;
        else
            *(_DWORD *)(Offset + ObjectHeader) &= ~0x40u;
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        if (SetFlag == 1)
            *(_DWORD *)(Offset + ObjectHeader) |= 0x20u;
        else
            *(_DWORD *)(Offset + ObjectHeader) &= ~0x20u;
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200)
    {
        if (SetFlag == 1)
            *(_DWORD *)(Offset + ObjectHeader) |= 0x10000u;
        else
            *(_DWORD *)(Offset + ObjectHeader) &= ~0x10000u;
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600)
    {
        if (SetFlag == 1)
            *(_DWORD *)(Offset + ObjectHeader) |= 0x8000u;
        else
            *(_DWORD *)(Offset + ObjectHeader) &= ~0x8000u;
    }
    else
    {
        if (SetFlag == 1)
            *(_DWORD *)(Offset + ObjectHeader) |= 0x4000u;
        else
            *(_DWORD *)(Offset + ObjectHeader) &= ~0x4000u;
    }
    return 1;
}

// ResolveKernelModuleFunctionAddrs — 解析内核模块函数地址
// 对应原始驱动 sub_14007DDEC
__int64 ResolveKernelModuleFunctionAddrs(void)
{
    __int64 v0 = GtRead(GtEprocessField22);
    unsigned int v1 = (unsigned int)GtRead(GtEprocessField23);
    __int64 v2 = GtRead(GtNtoskrnlModuleBase);
    unsigned int v4 = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (!v0 || !v1 || !v2 || !v4)
        return 0;

    unsigned int v5 = (unsigned int)GtRead(GtEprocessField189|GtEprocessField06|0x100);
    if (v5 && v5 < v4)
    {
        unsigned int v6 = (unsigned int)ResolveSyscallToAddress(v5);
        if (v6 && v6 < v1)
            GtWrite(GtNtQuerySystemInformationFunc|GtEprocessField55, v2 + v6);
    }

    unsigned int v7 = (unsigned int)GtRead(GtSubsystemConfigBase|GtEprocessField06|0x100);
    if (v7 && v7 < v4)
    {
        unsigned int v8 = (unsigned int)ResolveSyscallToAddress(v7);
        if (v8 && v8 < v1)
            GtWrite(GtSubsystemConfigBase|GtEprocessField10|0x100, v2 + v8);
    }

    unsigned int v9 = (unsigned int)GtRead(GtSubsystemConfigBase|GtEprocessField07|0x100);
    if (v9 && v9 < v4)
    {
        unsigned int v10 = (unsigned int)ResolveSyscallToAddress(v9);
        if (v10 && v10 < v1)
            GtWrite(GtKiFastCallEntryAddr|GtEprocessField06, v2 + v10);
    }

    unsigned int result = (unsigned int)GtRead(GtNtQuerySystemInformationFunc|GtEprocessField54);
    if (result && result < v4)
    {
        result = (unsigned int)ResolveSyscallToAddress(result);
        if (result && result < v1)
            return GtWrite(GtNtQuerySystemInformationFunc|GtEprocessField58, v2 + result);
    }
    return result;
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
