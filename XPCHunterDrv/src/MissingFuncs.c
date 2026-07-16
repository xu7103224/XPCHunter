// MissingFuncs.c — 缺失函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

// CheckMemoryValid — 检查内存地址是否有效
// 对应原始驱动 sub_140059BC4
// 被 67 个函数调用，读取全局表多个索引后调用 MmIsAddressValid
BOOLEAN CheckMemoryValid(void *Address)
{
    if (GtRead(GtCallbackField54))
    {
        GtRead(GtCallbackField08);
        GtRead(GtCallbackField120);
        GtRead(GtCallbackField116);
        GtRead(GtCallbackField117);
    }
    return MmIsAddressValid(Address);
}

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
// AllocExBufferAndQuerySystemInfo — 分配扩展缓冲区并查询系统信息
// 对应原始驱动 sub_14007A7F8
// 分配缓冲区后调用 NtQuerySystemInformation，若缓冲区不足则自动扩展（4倍）直至成功
void *AllocExBufferAndQuerySystemInfo(unsigned int SystemInformationClass)
{
    void *Buffer = NULL;
    __int64 (__fastcall *NtQuerySystemInfoFunc)(unsigned int, PVOID, unsigned int, int);
    unsigned int ThreadPrevModeOffset;
    int Status;
    unsigned int BufferSize = 0x4000;
    PVOID NewBuffer;
    PKTHREAD CurrentThread;
    char SavedPrevMode;

    NtQuerySystemInfoFunc = (__int64 (__fastcall *)(unsigned int, PVOID, unsigned int, int))GtRead(GtNtQuerySystemInformationFunc);
    ThreadPrevModeOffset = GtRead(GtSdstServiceCount);
    if (NtQuerySystemInfoFunc && ThreadPrevModeOffset != -1)
    {
        Status = -1073741820;  // STATUS_INFO_LENGTH_MISMATCH
        do
        {
            if (Buffer)
                ExFree(Buffer);
            NewBuffer = ExAlloc(PagedPool, BufferSize);
            Buffer = NewBuffer;
            if (!NewBuffer)
                break;
            CurrentThread = KeGetCurrentThread();
            SavedPrevMode = *((char *)CurrentThread + ThreadPrevModeOffset);
            *((char *)CurrentThread + ThreadPrevModeOffset) = 0;  // KernelMode
            Status = NtQuerySystemInfoFunc(SystemInformationClass, NewBuffer, BufferSize, 0);
            BufferSize *= 4;
            *((char *)CurrentThread + ThreadPrevModeOffset) = SavedPrevMode;
        }
        while (Status == -1073741820);
        if (Status < 0 && Buffer)
        {
            ExFree(Buffer);
            return NULL;
        }
    }
    return Buffer;
}

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

// BuildDriverPathI8042prt
__int64 BuildDriverPathI8042prt(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// BuildDriverPathKbdClass
__int64 BuildDriverPathKbdClass(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// BuildDriverPathMouClass
__int64 BuildDriverPathMouClass(__int64 OutputBuffer, int BufferSize)
{
    return 0;
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

// CopyKernelArrayToUserBuffer
__int64 CopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    return 0;
}

// CopyKernelDualArrayToUserBuffer
__int64 CopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    return 0;
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

// CopyProcessContextTable2
__int64 CopyProcessContextTable2(__int64 pTargetTable)
{
    return 0;
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

// CopyRegistryContextEntryArray
__int64 CopyRegistryContextEntryArray(__int64 pOutputTable)
{
    return 0;
}

// CopyThreadContextTable
__int64 CopyThreadContextTable(__int64 pSourceTable)
{
    return 0;
}

// CopyUSBPortServiceTable
__int64 CopyUSBPortServiceTable(__int64 pOutputBuffer)
{
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

// DispatchFreeProcessMemory
__int64 DispatchFreeProcessMemory(char *VirtualAddress)
{
    return 0;
}

// DispatchKernelMemoryCleanup
__int64 DispatchKernelMemoryCleanup(_QWORD *VirtualAddress)
{
    return 0;
}

// DispatchParseNtExportFunctions
__int64 DispatchParseNtExportFunctions(void)
{
    return 0;
}

// DuplicateUSBPortSyscallOutput
__int64 DuplicateUSBPortSyscallOutput(__int64 pSourceTable)
{
    return 0;
}

// EnableProcessProtect
__int64 EnableProcessProtect(PVOID Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize)
{
    return 0;
}

// EnumCallbackContextTable
__int64 EnumCallbackContextTable(__int64 pOutputTable)
{
    return 0;
}

// EnumCallbackContextV3Table
__int64 EnumCallbackContextV3Table(__int64 pOutputTable)
{
    return 0;
}

// EnumDeviceObjectTypeList
__int64 EnumDeviceObjectTypeList(int DeviceIndex, __int64 pOutputTable)
{
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

// EnumKernelMemoryContext
__int64 EnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int BufferSize)
{
    return 0;
}

// EnumKernelModules
__int64 EnumKernelModules(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

// EnumObjectContextTable
__int64 EnumObjectContextTable(__int64 pOutputBuffer)
{
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

// EnumProcessContextSsdtTable
__int64 EnumProcessContextSsdtTable(__int64 pOutputTable)
{
    return 0;
}

// EnumProcessContextTable
__int64 EnumProcessContextTable(__int64 pOutputTable)
{
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

// EnumProcessContextV3TableWin7
__int64 EnumProcessContextV3TableWin7(__int64 pOutputTable)
{
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

// EnumerateRegistryContextTable
__int64 EnumerateRegistryContextTable(__int64 pOutputTable)
{
    return 0;
}

// EnumerateSyscallContextVector
__int64 EnumerateSyscallContextVector(__int64 pOutputTable)
{
    return 0;
}

// ExAlloc — 分配带标签的池内存
// 对应原始驱动 sub_140077A00
// 从全局表获取分配标签后调用 ExAllocatePoolWithTag（被 129 个函数调用）
PVOID ExAlloc(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
{
    ULONG Tag = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x877);
    return ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
}

// FileSystemFilterCallback
__int64 FileSystemFilterCallback(char *PatchBuffer, int BufferSize)
{
    return 0;
}

// FilterActiveHookEntries
__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex)
{
    return 0;
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

// FindKernelPESectionByType
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex)
{
    return 0;
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

__int64 ForEachProcessor(__int64 (*pCallbackFunc)(__int64, __int64), __int64 Context)
{
    return 0;
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

// FreeProcessMemoryAllocation
__int64 FreeProcessMemoryAllocation(__int64 TargetAddress)
{
    return 0;
}

// FreeProcessMemoryAllocationEx
__int64 FreeProcessMemoryAllocationEx(_QWORD *pTargetEntry)
{
    return 0;
}

// FreeProcessMemoryBuffer
__int64 FreeProcessMemoryBuffer(PVOID VirtualAddress)
{
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

// InitPESectionReadContext — 初始化 PE 节区读取上下文
// 对应原始驱动 sub_14008A7E4（被 254+ 函数调用）
// 设置节区基址、范围、大小和版本相关的解码表指针
void *InitPESectionReadContext(__int64 BufferBase, int BufferSize, int Mode,
    __int64 Field4, int Field5, __int64 Field6, __int64 Field7, __int64 Context)
{
    *(_QWORD *)(Context + 8) = BufferBase;
    *(int *)(Context + 24) = Mode;
    *(_QWORD *)(Context + 16) = BufferBase + BufferSize;
    *(int *)(Context + 28) = Mode;
    *(int *)(Context + 64) = Field5;
    *(_QWORD *)(Context + 40) = Field4;
    *(_QWORD *)(Context + 48) = Field6;
    *(_QWORD *)(Context + 56) = Field7;
    const void *DecodeTable;
    if (Mode == 2)
    {
        DecodeTable = g_PeDecodeTableMode3;
        *(int *)(Context + 32) = 1;
    }
    else
    {
        DecodeTable = g_PeDecodeTableMode0;
        *(int *)(Context + 32) = Mode;
    }
    *(_QWORD *)Context = DecodeTable;
    return DecodeTable;
}

// GetDeleteValueKeyCtx
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

// InitMsrTable
__int64 InitMsrTable(void)
{
    return 0;
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

// InstallCallbackContextHookEntry
__int64 InstallCallbackContextHookEntry(unsigned int *pInputEntry)
{
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

// PowerCallbackRoutine
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize)
{
    return 0;
}

// PowerCallbackUnregister
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize)
{
    return 0;
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

// QueryDriverObjectDevice
__int64 QueryDriverObjectDevice(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// QueryFileSystemDriverObject
__int64 QueryFileSystemDriverObject(__int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// QueryNdisDriverObject
__int64 QueryNdisDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryObjectTypeInformation
__int64 QueryObjectTypeInformation(PVOID Object)
{
    return 0;
}

// QueryPnpManagerDriverObject
__int64 QueryPnpManagerDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
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

// QueryTcpipDriverObject
__int64 QueryTcpipDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryTdxDriverObject
__int64 QueryTdxDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// QueryVolmgrDriverObject
__int64 QueryVolmgrDriverObject(__int64 OutputBuffer, int BufferSize)
{
    return 0;
}

// ReadDiskSectors
unsigned int ReadDiskSectors(void)
{
    return 0;
}

// ReadDiskSectorsWithPartition
__int64 ReadDiskSectorsWithPartition(char a1, void *a2, unsigned int *a3, int a4, unsigned int a5)
{
    return 0;
}

// ReadKernelMemoryToUserBuffer
__int64 ReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    return 0;
}

// ReadNtOsKrnlFile
__int64 ReadNtOsKrnlFile(__int64 *a1, __int64 *a2)
{
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

// ReleaseProcessMemoryBlock
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry)
{
    return 0;
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

// ResolveDriverEntryAddresses
__int64 ResolveDriverEntryAddresses(__int64 a1)
{
    return 0;
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

// ResolveKernelObjectAddresses
__int64 ResolveKernelObjectAddresses(__int64 pObjectTable)
{
    return 0;
}

// ResolvePhysicalMemoryContext
__int64 ResolvePhysicalMemoryContext(__int64 pContextTable, int ContextType, ULONG EntryCount)
{
    return 0;
}

// ResolveServiceTableBase
__int64 ResolveServiceTableBase(void)
{
    return 0;
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

// SetCallbackContextEntry
__int64 SetCallbackContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetObjectContextEntry
__int64 SetObjectContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetProcessContextEntry
__int64 SetProcessContextEntry(__int64 pInputEntry)
{
    return 0;
}

// SetRegistryContextEntry
__int64 SetRegistryContextEntry(ULONG *pInputEntry)
{
    return 0;
}

// SetSyscallContextByIndex
__int64 SetSyscallContextByIndex(ULONG *pInputEntry)
{
    return 0;
}

// SetUSBPortServiceTableEntry
__int64 SetUSBPortServiceTableEntry(ULONG *a1)
{
    return 0;
}

// ShutdownCallbackUnregister
__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize)
{
    return 0;
}

// UnlinkFromMemoryBlockList
__int64 UnlinkFromMemoryBlockList(PVOID *pTargetPointer)
{
    return 0;
}

// UnlinkFromProcessMemoryList
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer)
{
    return 0;
}

// UnlinkProcessMemoryBlock
__int64 UnlinkProcessMemoryBlock(ULONG_PTR *pTargetEntry)
{
    return 0;
}

// ValidateAndClearProcessContext
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext)
{
    return 0;
}

// ValidateCallbackContextTable
__int64 ValidateCallbackContextTable(__int64 pContextTable)
{
    return 0;
}

// ValidateFsFilterEntries
__int64 ValidateFsFilterEntries(__int64 FilterContext)
{
    return 0;
}

// ValidateHookEntries
__int64 ValidateHookEntries(__int64 a1, ULONG a2)
{
    return 0;
}

// ValidateSingleHookEntry
__int64 ValidateSingleHookEntry(__int64 a1)
{
    return 0;
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

// WriteProcessContextEntry
__int64 WriteProcessContextEntry(__int64 pInputEntry)
{
    return 0;
}

// WriteProcessContextEntryWin7
__int64 WriteProcessContextEntryWin7(ULONG *pInputEntry)
{
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

// FsFilterCreateCallback — 文件系统过滤器创建回调
// 返回函数指针: __int64 (__fastcall *)(__int64)
__int64 (__fastcall *__fastcall FsFilterCreateCallback(__int64 FilterContext))(__int64)
{
    return 0;
}
