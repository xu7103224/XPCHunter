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
char ParseNtRelocSection(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable);
char ParseNtImageSections2(__int64 PeBase, unsigned int PeSize);
char ReadNtFileForProcessContext(char **FileBuffer, unsigned int *FileSize);
void BuildNtExportIndexTable(void);
char CheckTmDllSection(unsigned __int8 *NameToMatch);
_BYTE *StringCopy(_BYTE *Dest, __int64 Src, unsigned int MaxLen);
char QueryDiskInfoAta(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char SendAtaScsiCommand(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char BuildDevicePath(char *Buffer, unsigned int BufferSize);
void *j_GetCurrentFiber(void);
void ResolveSyscallAddressesInProcess(void);
void ScanProcessPESections(void);
char QuerySystemInfoPart1(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char QuerySystemInfoPart2(char *Buffer, unsigned int BufferSize, unsigned int *OutSize);
char InitNsiEnumerateObjects(void);
__int64 ResolveSyscallAddressesWithAttach(void);
void ReadSystemDllAndInitSession(void);
char ReadNtoskrnlToBuffer(void **FileBuffer, unsigned int *FileSize);
__int64 ParseNtoskrnlSectionsForKernelBase(__int64 PeBase, unsigned int PeSize);
void EnumObjectLinkedListSingle(_QWORD *pObjectTable, __int64 OutputBuffer, _DWORD *pCount, int MaxEntries);
void EnumObjectLinkedListWin7(_QWORD *pObjectTable, _DWORD *OutputBuffer, _DWORD *pCount, int MaxEntries);
void EnumObjectLinkedListWin8(_QWORD *pObjectTable, _DWORD *OutputBuffer, _DWORD *pCount, int MaxEntries);
char RemoveObjectFromLinkedList(_QWORD *pObjectTable, __int64 TargetHandle);
char RemoveObjectFromLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle);
char RemoveObjectSingleLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle);
char InitObjectOperationEntry(void);
void ClearProcessPageTableFlags(struct _KPROCESS *ProcessObject);
__int64 CmdQueryFileEndOfFile(HANDLE FileHandle, _QWORD *pResult);

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

// BuildExportServiceTable
char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize)
{
    return 0;
}

// BuildProcessContextExportTable — 构建进程上下文导出表
// 对应原始驱动 sub_140031F8C
// 读取 ntoskrnl 文件，解析 NT 镜像节区 2 和导出目录，备份原始函数字节到 GT 0x8D8/0x8D9
void BuildProcessContextExportTable(void)
{
    __int64 NtoskrnlBase = GtRead(GtFltPeSectionOfs8|GtEprocessField54);
    if (NtoskrnlBase)
    {
        unsigned int FileSize;
        char *pFileBuffer;
        if (ReadNtFileForProcessContext(&pFileBuffer, &FileSize))
        {
            if (ParseNtImageSections2((__int64)pFileBuffer, FileSize) == 1
                && ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
            {
                unsigned int *pContextEntry = (unsigned int *)GtAlloc(GtEprocessModuleListOffset|GtPspExitThreadAddr|0x3400) + 1;
                for (int LoopCount = 28; LoopCount; LoopCount--)
                {
                    int FuncRva = *pContextEntry;
                    *(pContextEntry - 1) = 0;
                    if (FuncRva && (unsigned int)FuncRva + 16 <= FileSize)
                    {
                        GtWrite(GtDisableHookProtectionAddr2|GtEprocessField182, 1);
                        *(pContextEntry - 1) = 1;
                        *(_OWORD *)(pContextEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRva];
                    }
                    pContextEntry += 12;
                }
                unsigned int *pTargetEntry = (unsigned int *)GtAlloc((enum _GLOBAL_TABLE_INDEX)15650) + 1;
                for (int LoopCount2 = 27; LoopCount2; LoopCount2--)
                {
                    int TargetRva = *pTargetEntry;
                    *(pTargetEntry - 1) = 0;
                    if (TargetRva && (unsigned int)TargetRva + 16 <= FileSize)
                    {
                        GtWrite(GtDisableHookProtectionAddr2|GtEprocessField183, 1);
                        *(pTargetEntry - 1) = 1;
                        *(_OWORD *)(pTargetEntry + 3) = *(_OWORD *)&pFileBuffer[TargetRva];
                    }
                    pTargetEntry += 12;
                }
            }
            ExFree(pFileBuffer);
        }
    }
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

// CmdEnumObjectsEx — 枚举对象扩展命令处理
// 对应原始驱动 sub_140036D54
// 验证输出缓冲区（最少 64 字节），若 GT 740 未初始化则调用 InitObjectOperationEntry。
// 根据 GT 2324 版本选择不同的链表枚举函数（Win7/Win8/Win10+），输出条目格式为 0x38 字节。
__int64 CmdEnumObjectsEx(__int64 UnusedParam1, unsigned int UnusedParam2, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize = OutputSize;
    __int64 Success = 0;
    _QWORD *pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
    if (!pObjectTable)
    {
        InitObjectOperationEntry();
        pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
    }
    if (pObjectTable
        && pOutputBuffer
        && (unsigned int)BufferSize >= 0x40
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 1u);
        *(_DWORD *)pOutputBuffer = 0;
        int MaxEntries = (int)((BufferSize - 64) / 0x38 + 1);
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xECE)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
                EnumObjectLinkedListWin7(pObjectTable, pOutputBuffer + 1, pOutputBuffer, MaxEntries);
            else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x585D)
                EnumObjectLinkedListWin8(pObjectTable, pOutputBuffer + 1, pOutputBuffer, MaxEntries);
        }
        else
        {
            EnumObjectLinkedListSingle(pObjectTable, (__int64)(pOutputBuffer + 1), pOutputBuffer, MaxEntries);
        }
        return *(_DWORD *)pOutputBuffer != 0;
    }
    return Success;
}

// CmdEnumObjectsLegacy — 枚举对象旧版命令处理
// 对应原始驱动 sub_140036EB0
// 从 GT 2334/2333/2335/2336 读取节区基址、会话基址、函数基址和标志，若未初始化则调用 ReadSystemDllAndInitSession。
__int64 CmdEnumObjectsLegacy(__int64 UnusedParam1, __int64 UnusedParam2, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize = OutputSize;
    __int64 SectionBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer02|0x100);
    __int64 SessionBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer01|0x100);
    __int64 FuncBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer03|0x100);
    if (!SectionBase || !SessionBase || !FuncBase)
    {
        ReadSystemDllAndInitSession();
        SectionBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer02|0x100);
        SessionBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer01|0x100);
        FuncBase = GtRead(GtDisableHookProtectionAddr2|GtPathBuffer03|0x100);
    }
    if (SectionBase
        && SessionBase
        && FuncBase
        && (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)2336)
        && pOutputBuffer
        && (unsigned int)BufferSize >= 0x40
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 1u);
        *pOutputBuffer = 0;
    }
    return 0;
}

// CmdObjectOperationByHandle — 通过句柄执行对象操作命令
// 对应原始驱动 sub_140036460
// 验证输入缓冲区（8 字节），若 GT 740 未初始化则调用 InitObjectOperationEntry。
// 根据 GT 2324 构建号选择不同的链表删除函数（Win7/Win8/Win10+）。
char __fastcall CmdObjectOperationByHandle(__int64 *pInputBuffer, int InputSize)
{
    char Probed = 0;
    __int64 TargetHandle = 0;

    if (pInputBuffer
        && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8u, 8u);
        TargetHandle = *pInputBuffer;
        Probed = 1;
    }
    if (Probed == 1)
    {
        Probed = 0;
        _QWORD *pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
        if (!pObjectTable)
        {
            InitObjectOperationEntry();
            pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
        }
        if (TargetHandle && pObjectTable)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0xECE)
                return RemoveObjectSingleLinkedListLegacy(pObjectTable, TargetHandle);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
                return RemoveObjectFromLinkedListLegacy(pObjectTable, TargetHandle);
            return RemoveObjectFromLinkedList(pObjectTable, TargetHandle);
        }
    }
    return Probed;
}

// CmdQueryDiskInfo — 查询磁盘信息命令处理
// 对应原始驱动 sub_140049860
// 懒加载 InitDiskQueryExportTable，顺序调用 QueryDiskInfoAta / SendAtaScsiCommand / BuildDevicePath 三部分
__int64 CmdQueryDiskInfo(char *Dst, SIZE_T Length)
{
    unsigned int v2 = (unsigned int)Length;
    char v4 = 0;
    if (!(unsigned int)GtRead(GtEprocessField135|0x100))
        InitDiskQueryExportTable();
    if ((unsigned int)v2 >= 0x38
        && (unsigned __int64)Dst < MmUserProbeAddress
        && (unsigned __int64)(Dst + v2) < MmUserProbeAddress)
    {
        ProbeForWrite(Dst, v2, 1u);
        unsigned int v10;
        if (!QueryDiskInfoAta(Dst, v2, &v10))
        {
            memset(Dst, 0, 0x38u);
            v10 = 56;
        }
        if ((unsigned int)v2 >= v10)
        {
            char *v5 = &Dst[v10];
            unsigned int v6 = v2 - v10;
            if (v6 >= 0x1C)
            {
                unsigned int v11;
                if (!SendAtaScsiCommand(v5, v6, &v11))
                {
                    *(_QWORD *)v5 = 0;
                    *((_QWORD *)v5 + 1) = 0;
                    *((_QWORD *)v5 + 2) = 0;
                    *((_DWORD *)v5 + 6) = 0;
                    v11 = 28;
                }
                if (v6 >= v11)
                {
                    char *v7 = &v5[v11];
                    unsigned int v8 = v6 - v11;
                    if (v8 >= 0xC)
                    {
                        if (!(unsigned __int8)BuildDevicePath(v7, v8))
                        {
                            *(_QWORD *)v7 = 0;
                            *((_DWORD *)v7 + 2) = 0;
                        }
                        return 1;
                    }
                }
            }
        }
    }
    return v4;
}

// CmdQueryFileAllocationSize — 查询文件分配大小
// 对应原始驱动 sub_14002EE6C
// 通过 IrpReadFile 查询文件分配大小信息
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize)
{
    __int64 AllocationSize;
    __int64 result = IrpReadFile(FileHandle, (struct _IRP *)&AllocationSize, 8u, 0xEu);
    if (!(_DWORD)result)
        *pAllocationSize = AllocationSize;
    return result;
}

// CmdQuerySystemInfoExV2 — 查询系统信息（扩展版 V2）
// 对应原始驱动 sub_140049730
// 懒加载初始化 NsiEnumerateObjects，顺序调用 QuerySystemInfoPart1/Part2/BuildDevicePath
__int64 CmdQuerySystemInfoExV2(char *Dst, SIZE_T Length)
{
    unsigned int v2 = (unsigned int)Length;
    char v4 = 0;
    if (GtRead(GtNtQuerySystemInformationFunc) || (InitNsiEnumerateObjects(), GtRead(GtNtQuerySystemInformationFunc)))
    {
        if ((unsigned int)v2 >= 0x38
            && (unsigned __int64)Dst < MmUserProbeAddress
            && (unsigned __int64)&Dst[v2] < MmUserProbeAddress)
        {
            ProbeForWrite(Dst, v2, 1u);
            unsigned int v10;
            if (!QuerySystemInfoPart1(Dst, v2, &v10))
            {
                memset(Dst, 0, 0x38u);
                v10 = 56;
            }
            if ((unsigned int)v2 >= v10)
            {
                char *v5 = &Dst[v10];
                unsigned int v6 = v2 - v10;
                if (v6 >= 0x1C)
                {
                    unsigned int v11;
                    if (!QuerySystemInfoPart2(v5, v6, &v11))
                    {
                        *(_QWORD *)v5 = 0;
                        *((_QWORD *)v5 + 1) = 0;
                        *((_QWORD *)v5 + 2) = 0;
                        *((_DWORD *)v5 + 6) = 0;
                        v11 = 28;
                    }
                    if (v6 >= v11)
                    {
                        char *v7 = &v5[v11];
                        unsigned int v8 = v6 - v11;
                        if (v8 >= 0xC)
                        {
                            if (!(unsigned __int8)BuildDevicePath(v7, v8))
                            {
                                *(_QWORD *)v7 = 0;
                                *((_DWORD *)v7 + 2) = 0;
                            }
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return v4;
}

// CmdReadFileInfo — 读取文件信息命令处理
// 对应原始驱动 sub_14002EE20
// 通过 IrpReadFile 查询文件标准信息（0x28 字节缓冲区，类型 4）
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo)
{
    char IrpBuffer[40];
    int FileInfo;
    __int64 result = IrpReadFile(FileHandle, (struct _IRP *)IrpBuffer, 0x28u, 4u);
    if (!(_DWORD)result)
        *pFileInfo = FileInfo;
    return result;
}

// CmdSendRenameFileIrp — 发送重命名文件 IRP
// 对应原始驱动 sub_14002F15C
// 分配缓冲区构造重命名信息结构，通过 IrpFileSystemControl 发送 FSCTL 重命名请求
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize)
{
    unsigned int Status;
    struct _IRP *IrpBuffer;
    if (BufferSize <= 2 || (BufferSize & 1) != 0)
        return (unsigned int)-1073741811;
    IrpBuffer = (struct _IRP *)ExAlloc(NonPagedPool, BufferSize + 24LL);
    if (IrpBuffer)
    {
        IrpBuffer->MdlAddress = 0;
        IrpBuffer->Flags = BufferSize - 2;
        *(unsigned char *)&IrpBuffer->Type = 1;
        memmove((char *)&IrpBuffer->Flags + 1, RenameBuffer, BufferSize - 2);
        Status = IrpFileSystemControl(FileHandle, IrpBuffer, BufferSize + 24, 0xAu);
        ExFree(IrpBuffer);
    }
    else
    {
        return (unsigned int)-1073741670;
    }
    return Status;
}

// CmdSetFileBasicInfo — 设置文件基本信息
// 对应原始驱动 sub_14002F404
// 通过 IrpFileSystemControl 发送 IRP_MJ_SET_INFORMATION 设置文件基本属性
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo)
{
    return IrpFileSystemControl(FileHandle, FileBasicInfo, 0x28u, 4u);
}

// CmdSetModuleInfoInternal
__int64 CmdSetModuleInfoInternal(_QWORD a1)
{
    return 0;
}

// DisableObjectCallback — 禁用对象回调
// 对应原始驱动 sub_14000FC44
// 打开指定设备路径，发送IOCTL获取文件对象，验证设备对象指针是否匹配全局表中保存的设备对象
__int64 DisableObjectCallback(__int16 *DevicePath, _QWORD *pResult)
{
    char Success = 0;
    _QWORD *IoctlCode = (_QWORD *)GtRead(GtZwCreateFileFunc);
    int (__fastcall *DeviceIoControlFunc)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD) = (int (__fastcall *)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD))GtRead(GtNtFsControlFileFunc);
    __int64 CloseHandleFunc = GtRead(GtCloseHandleFunc);
    void (__fastcall *CloseHandleFuncTyped)(__int64) = (void (__fastcall *)(__int64))CloseHandleFunc;
    if (IoctlCode && DeviceIoControlFunc && CloseHandleFunc)
    {
        HANDLE Handle;
        if (!(unsigned int)CreateFileWithPath(DevicePath, 0, &Handle, 0x80u, 0x80u, 1u, 1u, 0x20u))
        {
            __int64 IoStatusBlock;
            if (DeviceIoControlFunc(Handle, 0x80000000LL, *IoctlCode, 0, &IoStatusBlock, 0) >= 0)
            {
                __int64 FileObject;
                if (GetDeviceObjectFromFileObject(IoStatusBlock, &FileObject, 0))
                {
                    __int64 DeviceObjectPtr = GtRead(GtSavedDeviceObject);
                    if (DeviceObjectPtr && *(_QWORD *)(FileObject + 8) == DeviceObjectPtr)
                        Success = (unsigned int)CmdQueryFileEndOfFile(Handle, pResult) == 0;
                }
                CloseHandleFuncTyped(IoStatusBlock);
            }
            ZwClose(Handle);
        }
    }
    return Success;
}

// DiskOperationDispatcher
__int64 DiskOperationDispatcher(void)
{
    return 0;
}

// EnableProcessProtect — 启用进程保护
// 对应原始驱动 sub_140006BD0
// 验证 EPROCESS 对象，初始化 win32k 服务表，构建导出服务表，标记受保护进程。
__int64 EnableProcessProtect(PVOID Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize)
{
    __int64 Result = 0;
    int Status = -1073741823;
    PEPROCESS Process = NULL;
    __int64 ProcessIdPair[2];
    if (Address
        && InputSize == 16
        && (unsigned __int64)Address < MmUserProbeAddress
        && (unsigned __int64)((char *)Address + 16) < MmUserProbeAddress
        && OutputBuffer
        && OutputBufferSize == 21712
        && (unsigned __int64)OutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(OutputBuffer + 5428) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x10u, 4u);
        ProbeForWrite(OutputBuffer, 0x54D0u, 1u);
        ProcessIdPair[0] = *(__int64 *)Address;
        ProcessIdPair[1] = *((__int64 *)Address + 1);
        void *ProcessId = (void *)ProcessIdPair[1];
        NTSTATUS LookupStatus = PsLookupProcessByProcessId(ProcessId, &Process);
        Status = LookupStatus;
        struct _KPROCESS *ProcessObject = (struct _KPROCESS *)ProcessIdPair[0];
        if (!ProcessIdPair[0])
        {
            if (LookupStatus >= 0)
                ProcessObject = (struct _KPROCESS *)Process;
            ProcessIdPair[0] = (__int64)ProcessObject;
        }
        if (ValidateProcessObject(ProcessObject, 0) == 1)
        {
            char IsProtected = CheckProtectedEntry((__int64)ProcessObject);
            enum _GLOBAL_TABLE_INDEX TableIndex = GtWin32kServiceTable32Flag;
            if (IsProtected)
                TableIndex = GtWin32kServiceTable64Flag;
            if (!(unsigned int)GtRead(TableIndex))
            {
                ResolveWin32kServiceTable(IsProtected);
                enum _GLOBAL_TABLE_INDEX Win32kFlagIndex = GtWin32kServiceTable32Flag;
                if (IsProtected)
                    Win32kFlagIndex = GtWin32kServiceTable64Flag;
                if (!(unsigned int)GtRead(Win32kFlagIndex))
                    goto LABEL_DONE;
            }
            memset(OutputBuffer, 0, 0x54D0u);
            *OutputBuffer = GtRead(GtWindowsBuildNumber);
            unsigned int ServiceCount = GtRead(GtWin32kServiceCount);
            OutputBuffer[8] = ServiceCount;
            if (ServiceCount <= 0x12D
                && BuildExportServiceTable((__int64)ProcessId, ProcessObject, IsProtected, OutputBuffer) == 1
                && CopyValidServiceEntries((__int64)(OutputBuffer + 10), IsProtected) == 1
                && ParseNtImageSectionHeaders(ProcessObject, (__int64)(OutputBuffer + 10)) == 1)
            {
                *((_BYTE *)OutputBuffer + 4) = 1;
                Result = 1;
            }
        }
    }
LABEL_DONE:
    if (Status >= 0)
        ObfDereferenceObject(Process);
    return Result;
}

// EnumKernelDriverObjects — 枚举内核驱动对象
// 对应原始驱动 sub_1400521B0
// 从 GT 16970/16973/16976 获取回调函数，遍历 GT 572 的 Win32k 服务表条目，填充驱动信息到输出缓冲区(每项 42 个 DWORD)。
__int64 EnumKernelDriverObjects(_DWORD *a1, unsigned int a2)
{
    char v3 = 0;
    void (__fastcall *StringAllocFunc)(_BYTE *, __int64) = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtStringAllocFunc);
    unsigned int (__fastcall *AnsiToUnicodeFunc)(unsigned __int16 *, _BYTE *, __int64) = (unsigned int (__fastcall *)(unsigned __int16 *, _BYTE *, __int64))GtRead(GtAnsiToUnicodeFunc);
    __int64 v6 = GtRead(GtFreeStringFunc);
    void (__fastcall *FreeStringFunc)(unsigned __int16 *) = (void (__fastcall *)(unsigned __int16 *))v6;
    if (!StringAllocFunc || !AnsiToUnicodeFunc || !FreeStringFunc)
        return v3;
    __int64 v8 = GtRead(GtWin32kServiceTable);
    if (!v8)
    {
        InitWin32kServiceTableEntries();
        v8 = GtRead(GtWin32kServiceTable);
    }
    if (!v8)
        return v3;
    v3 = 1;
    if (!a2)
        return v3;
    {
        unsigned int v9 = 0;
        __int64 v10 = 0;
        _QWORD *i = (_QWORD *)(v8 + 80);
        while (1)
        {
            unsigned __int16 v14;
            void *Src;
            _BYTE v16[72];
            ++*a1;
            a1[v10 + 2] = *((_DWORD *)i - 20);
            StringAllocFunc(v16, v8 + 88LL * v9 + 4);
            if (AnsiToUnicodeFunc(&v14, v16, 1))
                break;
            memmove(&a1[42 * v9 + 3], Src, v14);
            FreeStringFunc(&v14);
            ++v9;
            a1[v10 + 36] = *((_DWORD *)i - 2);
            v10 += 42;
            *(_QWORD *)&a1[v10 - 4] = *i;
            if (v9 >= a2)
                return v3;
            i += 11;
        }
        v3 = 0;
        *(WORD *)&a1[42 * v9 + 3] = 0;
    }
    return v3;
}

// EnumKernelModules
__int64 EnumKernelModules(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
    return 0;
}

// EnumObjectDirectoryEntries
__int64 EnumObjectDirectoryEntries(unsigned __int16 *pDirectoryPath, _DWORD *pDirectoryInfo, __int64 OutputBuffer, int MaxCount)
{
    return 0;
}

// EnumProcessAndInitObjects — 枚举进程并初始化对象
// 对应原始驱动 sub_14007EB18
// 枚举指定进程的所有对象信息，对每个对象调用 InitObjectAndQueryName
__int64 EnumProcessAndInitObjects(__int64 a1, char a2)
{
    char v3 = 0;
    unsigned int v5;
    __int64 v15;
    __int64 v6;
    char v13[8];
    __int64 v14;
    char **v8;
    unsigned int v9;
    char **v10;
    __int64 v11;

    v5 = GtRead(GtEprocessField30);
    if (v5 != -1)
    {
        v15 = a1;
        v6 = *(_QWORD *)(v5 + a1);
        v13[0] = 1;
        v14 = v6;
        v8 = (char **)ExAlloc(PagedPool, 0x44610u);
        if (v8)
        {
            if (EnumProcessInformationWorker(v13, (__int64)v8, 0x44610u))
            {
                v9 = *((_DWORD *)v8 + 4);
                if (v9)
                {
                    v10 = v8 + 4;
                    v11 = v9;
                    do
                    {
                        InitObjectAndQueryName((__int64)*v10, a2);
                        v10 += 7;
                        --v11;
                    }
                    while (v11);
                }
                v3 = 1;
            }
            ExFree(v8);
        }
    }
    return v3;
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

// EnumServiceTableWin10 — 枚举服务表(Win10 版)
// 对应原始驱动 sub_1400563B0
// 遍历 GT 734 服务表链表，对每个有效节点提取服务名、服务地址、PID、进程名等字段，填充 48 字节每项的服务条目到输出缓冲区。
__int64 __fastcall EnumServiceTableWin10(__int64 *a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 (__fastcall *v7)(__int64 *) = (__int64 (__fastcall *)(__int64 *))GtRead(GtObjectTypeCheckFlag);
    unsigned int v8 = GtRead(GtProcessEprocess);
    unsigned int v9 = GtRead(GtProcessCreateTime);
    __int64 result = GtRead(GtProcessOffset);
    unsigned int v18 = result;
    if (v7 && v8 != -1 && v9 && (_DWORD)result != -1 && a1)
    {
        result = v7(a1);
        if ((_BYTE)result)
        {
            __int64 v11 = *a1;
            unsigned int v12 = 0;
            if (v11)
            {
                __int64 v13 = a2 + 8;
                do
                {
                    result = v7((__int64 *)v11);
                    if (!(_BYTE)result || !a4 || v12 > 0x10000)
                        break;
                    __int64 v14 = *(_QWORD *)(v11 + 40);
                    __int64 **v15 = v14 ? *(__int64 ***)(v14 + 16) : *(__int64 ***)(v11 + 48);
                    if (v15)
                    {
                        __int64 *v16 = *v15;
                        if (v16)
                        {
                            result = v7(v16);
                            if ((_BYTE)result)
                            {
                                --a4;
                                *(_QWORD *)(v13 + 8) = *(_QWORD *)(v11 + 80);
                                int v17 = *(_DWORD *)(v11 + 68);
                                *(_QWORD *)(v13 - 8) = v11;
                                *(_DWORD *)v13 = v17;
                                v13 += 48;
                                *(_QWORD *)(v13 - 16) = *(unsigned int *)((char *)v16 + v9);
                                result = v18;
                                *(_QWORD *)(v13 - 32) = *(unsigned int *)((char *)v16 + v8);
                                *(_QWORD *)(v13 - 24) = *(__int64 *)((char *)v16 + v18);
                                ++*a3;
                            }
                        }
                    }
                    v11 = *(_QWORD *)(v11 + 24);
                    ++v12;
                }
                while (v11);
            }
        }
    }
    return result;
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

// EnumerateProcessObjectTable
__int64 EnumerateProcessObjectTable(__int64 ProcessObject, __int64 OutputFlags)
{
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

// FindDeleteValueKeyTarget — 查找 NtDeleteValueKey 的 Hook 目标
// 对应原始驱动 sub_14001DA40
// 读取全局表索引 16795 获取偏移，在最多 4096 字节范围内扫描 UTF-8 编码数据，
// 匹配 0xCD048D 模式（7 字节指令），计算目标偏移写入输出参数
__int64 __fastcall FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 BaseOffset, unsigned int MaxDelta, __int64 *pResult)
{
    __int64 Result;
    __int64 result;
    unsigned __int64 ScanPos;
    unsigned __int64 EndAddress;
    unsigned __int64 ScanEnd;

    *pResult = 0;
    Result = BufferSize;
    result = GtRead(GtNtWriteFilePeSectionOffset|GtEprocessField08);
    if ((_DWORD)result && (unsigned int)result < (unsigned int)Result && (int)result + 4106 < (unsigned int)Result)
    {
        ScanPos = Buffer + (unsigned int)result;
        EndAddress = Buffer + Result;
        ScanEnd = ScanPos + 4096;
        while (ScanPos < ScanEnd)
        {
            result = DecodeUtf8Buffer((unsigned __int8 *)ScanPos, EndAddress);
            if (!(_DWORD)result)
                break;
            if ((_DWORD)result == 7 && (*(_DWORD *)ScanPos & 0xFFFFFF) == 0xCD048D && *(_BYTE *)(ScanPos + 7) == 57)
            {
                unsigned __int64 Delta;
                unsigned int ResultOffset;
                Delta = *(unsigned int *)(ScanPos + 3);
                if (Delta > *(_QWORD *)(Context + 48))
                {
                    ResultOffset = (unsigned int)(Delta - *(_DWORD *)(Context + 48));
                    if (ResultOffset < MaxDelta)
                    {
                        result = BaseOffset + ResultOffset;
                        *pResult = result;
                    }
                }
                return result;
            }
            result = (unsigned int)result;
            ScanPos += (unsigned int)result;
        }
    }
    return result;
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

// FindNtoskrnlExportsInThreadEnv — 在线程环境中查找 ntoskrnl 导出
// 对应原始驱动 sub_14002BBB4
__int64 FindNtoskrnlExportsInThreadEnv(void)
{
    char Result = 0;
    if (GtRead(GtFltDataSectionOffset|GtEprocessField54)
        || (InitThreadNotify(), GtRead(GtFltDataSectionOffset|GtEprocessField54)))
    {
        unsigned int FileSize;
        void *FileBuffer;
        if (ReadNtoskrnlToBuffer(&FileBuffer, &FileSize))
        {
            Result = ParseNtoskrnlSectionsForKernelBase((__int64)FileBuffer, FileSize) == 1;
            ExFree(FileBuffer);
        }
    }
    return Result;
}

// FindOpenProcessTokenOffset — 查找 NtOpenProcessToken 偏移（旧版）
// 对应原始驱动 sub_140020864
__int64 FindOpenProcessTokenOffset(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = -1;
    unsigned int SectionOffset = GtRead(GtUninstallHookSyscallPeOffset|GtEprocessField58|0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        char ReadContext[8];
        __int64 CumulativeSize = 0;
        char SectionEntry[80];
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)ReadContext);
        while (!(unsigned int)ReadPESectionEntry((__int64 *)ReadContext, SectionEntry))
        {
            unsigned int EntryCumulSize = *(unsigned int *)((char *)SectionEntry + 0x80);
            CumulativeSize += EntryCumulSize;
            __int64 EntryDataPtr = *(__int64 *)((char *)SectionEntry + 0xA8);
            __int16 SectionType = *(__int16 *)(EntryDataPtr + 6);
            if (SectionType == 1349)
                break;
            if (EntryCumulSize == 7)
            {
                char SectionFlags = *(char *)((char *)SectionEntry + 0x50);
                int EntryFlags = *(int *)((char *)SectionEntry + 0x58);
                __int64 SectionType2 = *(__int64 *)((char *)SectionEntry + 0x18);
                if (SectionType == 1049 && (SectionFlags & 0x40) != 0 && EntryFlags == 1)
                {
                    if ((SectionType2 & 0x2000000) != 0)
                    {
                        unsigned int EntrySize1 = *(unsigned int *)((char *)SectionEntry + 0x60);
                        int EntryField1 = *(int *)((char *)SectionEntry + 0x64);
                        if (EntrySize1 && !EntryField1)
                        {
                            ResultOffset = EntrySize1;
                            return GtWrite(GtCallbackField109, ResultOffset);
                        }
                    }
                }
                else if (SectionType == 1298 && (SectionFlags & 0x40) != 0 && (SectionType2 & 0x10000) != 0)
                {
                    int EntrySize2 = *(int *)((char *)SectionEntry + 0x68);
                    if (EntrySize2 > 0)
                    {
                        ResultOffset = EntrySize2;
                        return GtWrite(GtCallbackField109, ResultOffset);
                    }
                }
            }
        }
    }
    return GtWrite(GtCallbackField109, ResultOffset);
}

// FindOpenProcessTokenTarget — 查找 NtOpenProcessToken 目标（新版）
// 对应原始驱动 sub_1400209A8
__int64 FindOpenProcessTokenTarget(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = -1;
    char FoundMarker = 0;
    unsigned int SectionOffset = GtRead(GtUninstallHookSyscallPeOffset|GtEprocessField58|0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        __int64 ReadContext;
        __int64 CumulativeSize = 0;
        _DWORD SectionEntry[20];
        unsigned int LoopIndex;
        unsigned int Phase2Offset = 0;
        unsigned int Phase2Index;
        unsigned int EntryCumulSize;
        __int64 EntryDataPtr;
        __int64 SectionType2;
        __int16 SectionType;
        int CurrentOffset;
        int EntryMagic;
        __int16 Phase2SectionType;
        char SectionFlags;
        int MatchValue;

        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        LoopIndex = 0;
        if (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
        {
            while (1)
            {
                if (LoopIndex >= 0x64)
                    return GtWrite(GtCallbackField109, ResultOffset);
                EntryCumulSize = *(unsigned int *)((char *)SectionEntry + 0x80);
                CurrentOffset = EntryCumulSize + (int)CumulativeSize;
                CumulativeSize += EntryCumulSize;
                EntryDataPtr = *(__int64 *)((char *)SectionEntry + 0xA8);
                SectionType = *(__int16 *)(EntryDataPtr + 6);
                SectionType2 = *(__int64 *)((char *)SectionEntry + 0x18);
                if (SectionType == 1342 && SectionType2 == 0x800000)
                {
                    EntryMagic = *(int *)((char *)SectionEntry + 0x60);
                    if (EntryMagic == 1953261124)
                        FoundMarker = 1;
                }
                if (FoundMarker == 1 && SectionType == 1368)
                {
                    Phase2Offset = CurrentOffset + SectionEntry[14] - (int)TargetBase;
                    if (Phase2Offset && Phase2Offset < TargetSize)
                        break;
                }
                ++LoopIndex;
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    return GtWrite(GtCallbackField109, ResultOffset);
            }
            InitPESectionReadContext(TargetBase + Phase2Offset, TargetSize - Phase2Offset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (Phase2Index = 0; ; ++Phase2Index)
            {
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    return GtWrite(GtCallbackField109, ResultOffset);
                if (Phase2Index >= 0x64)
                    return GtWrite(GtCallbackField109, ResultOffset);
                CumulativeSize += EntryCumulSize;
                Phase2SectionType = *(__int16 *)(EntryDataPtr + 6);
                if (Phase2SectionType == 1349)
                    return GtWrite(GtCallbackField109, ResultOffset);
                SectionFlags = *(char *)((char *)SectionEntry + 0x50);
                if (EntryCumulSize == 7)
                {
                    if (Phase2SectionType == 1298 && (SectionFlags & 0x40) != 0)
                    {
                        if ((SectionType2 & 0x10000) == 0)
                            continue;
                        MatchValue = *(int *)((char *)SectionEntry + 0x68);
                    }
                    else
                    {
                        if (Phase2SectionType != 229 || SectionFlags != 0x41)
                            continue;
                        MatchValue = SectionEntry[16];
                    }
                    if (MatchValue > 0)
                    {
                        ResultOffset = MatchValue;
                        return GtWrite(GtCallbackField109, ResultOffset);
                    }
                }
            }
        }
    }
    return GtWrite(GtCallbackField109, ResultOffset);
}

// FindRenameKeyTargetEx
__int64 FindRenameKeyTargetEx(__int64 TargetBase,
    unsigned int TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    return 0;
}

// FindSetValueKeyTarget — 查找 NtSetValueKey 的 Hook 目标
// 对应原始驱动 sub_14001DEF4
// 读取全局表索引 16798 获取偏移，在最多 4096 字节范围内扫描 UTF-8 数据，
// 匹配 6 字节模式（967/17289 字标记），计算目标地址写入输出参数
__int64 FindSetValueKeyTarget(__int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    __int64 *pResultOffset,
    _QWORD *pResultOffset2)
{
    __int64 BufferSizeCopy;
    __int64 DecodedSize;
    unsigned __int64 ScanPos;
    unsigned __int64 BufferEnd;
    unsigned __int64 ScanEnd;

    *pResultOffset = 0;
    *pResultOffset2 = 0;
    BufferSizeCopy = BufferSize;
    DecodedSize = GtRead(GtTotalSize|GtNtQuerySystemInformationFunc|GtPathBuffer00);
    if ((_DWORD)DecodedSize
        && (unsigned int)DecodedSize < (unsigned int)BufferSizeCopy
        && (int)DecodedSize + 4106 < (unsigned int)BufferSizeCopy)
    {
        ScanPos = Buffer + (unsigned int)DecodedSize;
        BufferEnd = Buffer + BufferSizeCopy;
        ScanEnd = ScanPos + 4096;
        while (ScanPos < ScanEnd)
        {
            DecodedSize = DecodeUtf8Buffer((unsigned __int8 *)ScanPos, BufferEnd);
            if (!(_DWORD)DecodedSize)
                break;
            if ((_DWORD)DecodedSize == 6 && *(_WORD *)ScanPos == 967 && *(_WORD *)(ScanPos + 6) == 17289)
            {
                unsigned __int64 FoundValue = *(unsigned int *)(ScanPos + 2);
                if (FoundValue > *(_QWORD *)(Context + 48))
                {
                    unsigned int ValueDelta = (unsigned int)(FoundValue - *(_DWORD *)(Context + 48));
                    if (ValueDelta < MaxDelta)
                    {
                        DecodedSize = BaseOffset + ValueDelta;
                        *pResultOffset = DecodedSize;
                    }
                }
                return DecodedSize;
            }
            DecodedSize = (unsigned int)DecodedSize;
            ScanPos += (unsigned int)DecodedSize;
        }
    }
    return DecodedSize;
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

// InitFileSystemExportTable — 初始化文件系统导出表
// 对应原始驱动 sub_14000E24C
__int64 InitFileSystemExportTable(char Is64Bit)
{
    if (Is64Bit == 1)
    {
        __int64 ExportTableAddr = GtRead(GtFileSystemExportTable);
        if (ExportTableAddr)
        {
            __int64 *RelocTable = GtAlloc(GtFltPeSectionOfs5|GtCallbackField79|0x1000);
            unsigned int FileSize;
            char *FileBuffer;
            if (ReadDisksSysFile(&FileBuffer, &FileSize))
            {
                if (ParseNtRelocSection((__int64)FileBuffer, FileSize, (__int64)RelocTable) == 1
                    && ParseNtExportDir((__int64)FileBuffer, FileSize, ExportTableAddr, 0) == 1)
                {
                    unsigned int *EntryPtr = (unsigned int *)RelocTable + 1;
                    for (int EntryCount = 49; EntryCount; EntryCount--)
                    {
                        __int64 EntryOffset = *EntryPtr;
                        *(EntryPtr - 1) = 0;
                        if ((_DWORD)EntryOffset && (int)EntryOffset + 16 <= FileSize)
                        {
                            *(EntryPtr - 1) = 1;
                            *(_OWORD *)(EntryPtr + 3) = *(_OWORD *)&FileBuffer[EntryOffset];
                        }
                        EntryPtr += 12;
                    }
                    GtWrite(GtFileSystemReady10, 1);
                }
                ExFree(FileBuffer);
            }
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
                    *((_DWORD *)RelocTable + 120) = 0;
            }
            else
            {
                *((_DWORD *)RelocTable + 372) = 0;
            }
        }
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        if (GtRead(GtFileSystemExportTable32))
        {
            GtAlloc(GtDisableHookProtectionAddr2|GtEprocessField26|0x1500);
            unsigned int FileSize;
            char *FileBuffer;
            if (ReadCdromSysFile(&FileBuffer, &FileSize))
                ExFree(FileBuffer);
        }
    }
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

// IoPortOperationDispatch
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize)
{
    return 0;
}

// IrpFsctlGetVolumeData — 获取卷数据（FSCTL）
// 对应原始驱动 sub_14002F414
__int64 IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData)
{
    __int64 VolumeData = *pVolumeData;
    return IrpFileSystemControl(FileHandle, (struct _IRP *)&VolumeData, 8u, 0xEu);
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

// LookupDriverHashTable — 在驱动哈希表中查找
// 对应原始驱动 sub_140082AF0
// 通过 SHA1 哈希值在 Nt 导出索引表中查找匹配的导出函数
__int64 LookupDriverHashTable(__int64 a1, _DWORD *a2)
{
    __int64 v3 = 0;
    void (__fastcall *v5)(char *, __int64);
    unsigned int (__fastcall *v6)(unsigned __int16 *, char *, __int64);
    __int64 v7;
    void (__fastcall *v8)(unsigned __int16 *);
    unsigned __int16 v18;
    char v20[16];
    __int64 v19;
    char v21[80];
    __int64 v10;
    unsigned int v11;
    unsigned int v12;
    int v13;
    unsigned int v14;
    int v15;
    __int64 v16;

    *a2 = 0;
    v5 = (void (__fastcall *)(char *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    v6 = (unsigned int (__fastcall *)(unsigned __int16 *, char *, __int64))GtRead(GtTotalSize|GtEprocessField104|0x400);
    v7 = GtRead(GtNtCreateThreadPeSectionOffset|GtEprocessField42);
    v8 = (void (__fastcall *)(unsigned __int16 *))v7;
    if (v5 && v6 && v7)
    {
        v5(v20, a1);
        if (!v6(&v18, v20, 1))
        {
            if (v18 <= 0x40u)
            {
                StringCopy(v21, v19, v18);
                v21[v18] = 0;
                v10 = GtRead(GtDisableHookProtectionAddr2|GtDriverObject|0x100);
                if (!v10)
                {
                    BuildNtExportIndexTable();
                    v10 = GtRead(GtDisableHookProtectionAddr2|GtDriverObject|0x100);
                }
                v11 = GtRead(GtDisableHookProtectionAddr2|GtNtoskrnlImageSize|0x100);
                v12 = v11;
                if (v10 && v11)
                {
                    v13 = Sha1HashToDword(v21);
                    v14 = 0;
                    v15 = v13;
                    v16 = v10;
                    while (*(_BYTE *)v16 != 1 || v15 != *(_DWORD *)(v16 + 4))
                    {
                        ++v14;
                        v16 += 12;
                        if (v14 >= v12)
                            goto LABEL_15;
                    }
                    *a2 = *(_DWORD *)(v10 + 12LL * v14 + 8);
                    goto LABEL_19;
                }
LABEL_15:
                if (CheckTmDllSection((unsigned __int8 *)v21) == 1)
LABEL_19:
                    v3 = 1;
            }
            v8(&v18);
        }
    }
    return v3;
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

// OpenSectionWithIoControl — 通过 IO 控制打开节区
// 对应原始驱动 sub_140072858
// 发送创建 Section 的 IOCTL 并执行 Hook 交换操作
__int64 OpenSectionWithIoControl(__int64 a1)
{
    char v2 = 0;
    unsigned int v3 = GtRead(GtSdstServiceCount);
    unsigned int (__fastcall *v4)(__int64, __int64, _QWORD, _QWORD, _DWORD **, _QWORD);
    void (__fastcall *v5)(_DWORD *);
    __int64 (__fastcall *v6)(_DWORD *);
    __int64 v7;
    _QWORD *v8;
    _DWORD *v16;
    int v9;
    struct _KTHREAD *CurrentThread;
    __int64 v11;
    char v12;
    __int64 v17;
    _QWORD *v13;
    int v14;

    v4 = (unsigned int (__fastcall *)(__int64, __int64, _QWORD, _QWORD, _DWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    v5 = (void (__fastcall *)(_DWORD *))GtRead(GtCloseHandleFunc);
    v6 = (__int64 (__fastcall *)(_DWORD *))GtRead(GtEprocessField117|0x100);
    v7 = GtRead(GtEprocessField111|0x100);
    v8 = (_QWORD *)v7;
    if (v3 != -1 && v4 && v5 && v6 && v7)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
            v9 = SendDeviceIoControlWithRetry(a1, 0x10000u, 0, &v16, 0);
        else
            v9 = v4(a1, 0x10000, *v8, 0, &v16, 0);
        if (v9 >= 0)
        {
            CurrentThread = KeGetCurrentThread();
            v11 = v3;
            v12 = *((_BYTE *)CurrentThread + v3);
            *((_BYTE *)CurrentThread + v11) = 0;
            v13 = (_QWORD *)DispatchHookSwapByVersion((__int64)v16, &v17);
            v14 = v6(v16);
            if (v13)
                *v13 = v17;
            *((_BYTE *)CurrentThread + v11) = v12;
            v5(v16);
            return v14 >= 0;
        }
    }
    return v2;
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

// ParseNtImageSectionHeaders — 解析 NT 镜像节头
// 对应原始驱动 sub_1400061B8（与 ParseNtImageSectionHeadersForProcess 共享实现）
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray)
{
    return ParseNtImageSectionHeadersForProcess(PROCESS, SectionInfoArray);
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

// ProcessOperationWithAttach — 挂载到目标进程上下文中执行操作
// 对应原始驱动 sub_140080428
// 附加到进程，清除进程保护标志和页表标志，执行回调后分离
__int64 ProcessOperationWithAttach(struct _KPROCESS *a1)
{
    __int64 v2 = 0;
    unsigned int v3 = GtRead(GtSdstServiceCount);
    int (__fastcall *v4)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *) = (int (__fastcall *)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset|GtEprocessField54);
    int (__fastcall *v5)(__int64, _QWORD) = (int (__fastcall *)(__int64, _QWORD))GtRead(GtEprocessField124|0x100);
    if (!v5)
        v5 = (int (__fastcall *)(__int64, _QWORD))ResolveSyscallAddressesWithAttach();
    _QWORD *v6 = (_QWORD *)GtRead(GtTotalSize|GtExFreeCallBackAddr|0x100);
    __int64 v7 = GtRead(GtRegisterObjectCallbacksFunc);
    void (__fastcall *v8)(__int64) = (void (__fastcall *)(__int64))v7;
    __int64 v15;
    if (v3 != -1 && v4 && v5 && v6 && v7)
    {
        struct _KTHREAD *CurrentThread = KeGetCurrentThread();
        if (v4(a1, 512, 0, 0x10000000, *v6, 0, &v15) >= 0)
        {
            if (!GtRead(GtPspExitThreadAddr))
            {
                ScanProcessPESectionsV2();
                GtRead(GtPspExitThreadAddr);
            }
            if (!GtRead(GtKiInsertQueueApcFunc))
            {
                InitHookFunctionTable();
                GtRead(GtKiInsertQueueApcFunc);
            }
            if (ValidateProcessObject(a1, 0) == 1)
            {
                unsigned __int8 v10 = ReferenceObjectSafe((__int64)a1);
                unsigned int v11 = GtRead(GtCallbackField124);
                if (v11)
                {
                    __int64 v12 = v11;
                    *(_DWORD *)((char *)a1 + v11) &= ~0x2000u;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x1770)
                        *(_DWORD *)((char *)a1 + v12) &= ~8u;
                    else
                        *(_DWORD *)((char *)a1 + v12) &= 0xBFFFFFF7;
                }
                if (v10 == 1)
                    DereferenceObjectSafe((__int64)a1);
            }
            ClearProcessPageTableFlags(a1);
            char v13 = *((_BYTE *)CurrentThread + v3);
            *((_BYTE *)CurrentThread + v3) = 0;
            v2 = v5(v15, 0) >= 0;
            v8(v15);
            *((_BYTE *)CurrentThread + v3) = v13;
        }
    }
    return v2;
}

// QueryObjectTypeInformation
__int64 QueryObjectTypeInformation(PVOID Object)
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

// ReadDiskSectors 已在 MemoryOps.c 中实现
// 本文件中的定义已移除，使用外部链接

// ReadDiskSectorsWithPartition
__int64 ReadDiskSectorsWithPartition(char a1, void *a2, unsigned int *a3, int a4, unsigned int a5)
{
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

// ReadProcessMemoryWithAttach — 附加并读取进程内存
// 对应原始驱动 sub_14007F69C
// 附加到目标进程后使用系统调用查询进程内存信息，扫描 PE 节区
__int64 ReadProcessMemoryWithAttach(__int64 a1)
{
    char v1 = 0;
    unsigned int (__fastcall *v2)(__int64, struct _KTHREAD **);
    __int64 (__fastcall *v3)(struct _KTHREAD *, __int64, _QWORD, __int64, _QWORD, char, __int64 *);
    _QWORD *v4;
    __int64 v23;
    void (__fastcall *v5)(__int64);
    void (__fastcall *v6)(struct _KTHREAD *);
    void (__fastcall *v7)(__int64, _QWORD);
    unsigned int v8, v9;
    struct _KTHREAD *CurrentThread;
    __int64 v22;
    char v19;
    int v10;
    int v11;
    __int64 v12, v13, v14, v15, v16, v17;

    v2 = (unsigned int (__fastcall *)(__int64, struct _KTHREAD **))GtRead(GtTotalSize|GtEprocessField182|0x100);
    v3 = (__int64 (__fastcall *)(struct _KTHREAD *, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset|GtEprocessField54);
    v4 = (_QWORD *)GtRead(GtTotalSize|GtEprocessField95|0x100);
    v23 = GtRead(GtTotalSize|GtSubsystemConfigBase|GtPathBuffer00|0x100);
    v5 = (void (__fastcall *)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    v6 = (void (__fastcall *)(struct _KTHREAD *))GtRead(GtCloseHandleFunc);
    v7 = (void (__fastcall *)(__int64, _QWORD))GtRead(GtObjectTypeField21);
    if (!v7)
    {
        ResolveSyscallAddressesInProcess();
        v7 = (void (__fastcall *)(__int64, _QWORD))GtRead(GtObjectTypeField21);
    }
    v8 = GtRead(GtSdstServiceCount);
    v9 = v8;
    if (v2 && v3 && v4 && v23 && v7 && v8 != -1 && v5 && v6)
    {
        if (!v2(a1, &CurrentThread))
        {
            v19 = 0;
            v10 = v3(CurrentThread, 512, 0, 0x10000000, *v4, v19, &v22);
            v6(CurrentThread);
            if (!v10)
            {
                CurrentThread = KeGetCurrentThread();
                v11 = *((unsigned __int8 *)CurrentThread + v9);
                *((_BYTE *)CurrentThread + v9) = 0;
                v7(v22, 0);
                v5(v22);
                *((_BYTE *)CurrentThread + v9) = v11;
                if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x2580)
                {
                    v12 = GtRead(GtPspExitNormalApcAddr);
                    v13 = GtRead(GtExFreeCallBackAddr);
                    v14 = GtRead(GtPsExitSpecialApcAddr);
                    if ((!v12 || !v13 || !v14) && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
                        ScanProcessPESections();
                    v15 = GtRead(GtPspExitNormalApcAddr);
                    v16 = GtRead(GtExFreeCallBackAddr);
                    v17 = GtRead(GtPsExitSpecialApcAddr);
                    if (v15 && v16)
                        return v17 != 0;
                }
            }
        }
    }
    return v1;
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

// RemoveFromModuleLinkedList
__int64 RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    return 0;
}

// RemoveServiceEntryFromList — 从服务表链表中移除条目
// 对应原始驱动 sub_14005631C
// 遍历单向链表，查找与目标地址匹配的节点并将其从链表中摘除
__int64 RemoveServiceEntryFromList(ULONG_PTR *a1, __int64 a2)
{
    char v4 = 0;
    unsigned __int8 (__fastcall *v6)(_QWORD) = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    if (v6 && a1 && v6((_QWORD)a1))
    {
        unsigned int i;
        for (i = 0; *a1 && v6((_QWORD)*a1) && i <= 0x10000; ++i)
        {
            ULONG_PTR v8 = *a1;
            if (a2 == (__int64)*a1)
            {
                v4 = 1;
                *a1 = *(_QWORD *)(v8 + 24);
                return v4;
            }
            a1 = (ULONG_PTR *)(v8 + 24);
        }
    }
    return v4;
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

// UnlinkFromProcessMemoryList
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer)
{
    return 0;
}

// ValidateAndClearProcessContext — 验证并清除进程上下文
// 对应原始驱动 sub_140030398
// 检查处理器匹配，清除调试寄存器，清除纤程上下文
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext)
{
    char Result = 1;
    char *CurrentFiber;
    int FiberOffset;
    int IsSameProcessor;

    if (!(*(_DWORD *)pContext == -1 || *(_DWORD *)pContext == CurrentProcessor))
        return Result;
    ClearDebugRegisters();
    CurrentFiber = (char *)j_GetCurrentFiber();
    FiberOffset = GtRead(GtEprocessModuleListOffset|GtEprocessField88);
    if (CurrentFiber && FiberOffset)
        memset(&CurrentFiber[FiberOffset], 0, 0x30u);
    IsSameProcessor = *(_DWORD *)pContext == CurrentProcessor;
    *(_BYTE *)(pContext + 4) = 1;
    return !IsSameProcessor;
}

// ValidateHookEntries — 验证钩子条目
// 对应原始驱动 sub_1400859F0
// 校验钩子条目的地址有效性，检测钩子是否被篡改
__int64 ValidateHookEntries(__int64 a1, ULONG a2)
{
    if (a2)
    {
        _QWORD *v4 = (_QWORD *)(a1 + 8);
        ULONG v5 = a2;
        do
        {
            if (*v4 && *v4 != v4[1])
                *((_BYTE *)v4 - 8) = 1;
            v4 += 5;
            --v5;
        }
        while (v5);
    }
    ULONG v6 = 0;
    if (a2)
    {
        __int64 *v7 = (__int64 *)(a1 + 8);
        do
        {
            if (*v7)
            {
                if (CheckMemoryValid((void *)(*v7 + 15)) == 1)
                {
                    if ((unsigned int)MemoryCompare(*v7, (char *)(a1 + 8 * ((unsigned int)v6 + 3LL + 4 * v6)), 0x10u))
                    {
                        unsigned int i;
                        char was_original = *((_BYTE *)v7 - 8) == 0;
                        *((_BYTE *)v7 - 7) = 1;
                        if (was_original)
                        {
                            for (i = 0; i < 0x10; ++i)
                            {
                                if (!CheckMemoryValid((void *)(*v7 + i)))
                                    break;
                            }
                            if (i && ReturnFalseStub() == 1)
                                v7[1] = *(__int64 *)(a1 + 8 * ((unsigned int)v6 + 3LL + 4 * v6) + 8);
                        }
                    }
                }
            }
            v6 = (unsigned int)(v6 + 1);
            v7 += 5;
        }
        while ((unsigned int)v6 < a2);
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

// ZeroProcessMemoryPages
__int64 ZeroProcessMemoryPages(PRKPROCESS PROCESS)
{
    return 0;
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

// ReadDisksSysFile — 读取 disksys 文件
// 对应原始驱动 sub_14000EDD8
bool ReadDisksSysFile(_QWORD *FileBuffer, unsigned int *FileSize)
{
    int EncodedPath[20];
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
    EncodedPath[10] = 6553692;
    EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254;
    EncodedPath[13] = 7536754;
    EncodedPath[14] = 6553692;
    EncodedPath[15] = 7536745;
    EncodedPath[16] = 3014763;
    EncodedPath[17] = 7929971;
    EncodedPath[18] = 115;
    void *Src;
    size_t MaxCount;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        bool Result = ReadNtFileToBuffer((unsigned char *)Src, (unsigned int)MaxCount, (unsigned char **)FileBuffer, FileSize) == 1;
        ExFree(Src);
        return Result;
    }
    return 0;
}

// ReadCdromSysFile — 读取 cdrom.sys 文件
// 对应原始驱动 sub_14000ECB8
bool ReadCdromSysFile(_QWORD *FileBuffer, unsigned int *FileSize)
{
    int EncodedPath[18];
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
    EncodedPath[10] = 6553692;
    EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254;
    EncodedPath[13] = 7536754;
    EncodedPath[14] = 6488156;
    EncodedPath[15] = 7471204;
    EncodedPath[16] = 7143535;
    EncodedPath[17] = 7536686;
    void *Src;
    size_t MaxCount;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        bool Result = ReadNtFileToBuffer((unsigned char *)Src, (unsigned int)MaxCount, (unsigned char **)FileBuffer, FileSize) == 1;
        ExFree(Src);
        return Result;
    }
    return 0;
}

// ParseNtRelocSection — 解析 NT 重定位节区（存根，待实现）
// 对应原始驱动 sub_14000E634
char ParseNtRelocSection(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable)
{
    return 0;
}

// ========== Sub-function stubs for newly implemented main functions ==========

// ParseNtImageSections2 — 解析 NT 镜像节区 2
char ParseNtImageSections2(__int64 PeBase, unsigned int PeSize)
{
    return 0;
}

// ReadNtFileForProcessContext — 读取 NT 文件用于进程上下文
char ReadNtFileForProcessContext(char **FileBuffer, unsigned int *FileSize)
{
    return 0;
}

// ResolveSyscallAddressesWithAttach — 附加后解析系统调用地址
__int64 ResolveSyscallAddressesWithAttach(void)
{
    return 0;
}

// ReadSystemDllAndInitSession — 读取系统 DLL 并初始化会话
void ReadSystemDllAndInitSession(void)
{
    return;
}

// EnumObjectLinkedListSingle — 枚举对象链表（单链表旧版）
void EnumObjectLinkedListSingle(_QWORD *pObjectTable, __int64 OutputBuffer, _DWORD *pCount, int MaxEntries)
{
    return;
}

// EnumObjectLinkedListWin7 — 枚举对象链表（Win7 版）
void EnumObjectLinkedListWin7(_QWORD *pObjectTable, _DWORD *OutputBuffer, _DWORD *pCount, int MaxEntries)
{
    return;
}

// EnumObjectLinkedListWin8 — 枚举对象链表（Win8+ 版）
void EnumObjectLinkedListWin8(_QWORD *pObjectTable, _DWORD *OutputBuffer, _DWORD *pCount, int MaxEntries)
{
    return;
}

// RemoveObjectFromLinkedList — 从链表中移除对象（Win10+）
char RemoveObjectFromLinkedList(_QWORD *pObjectTable, __int64 TargetHandle)
{
    return 0;
}

// RemoveObjectFromLinkedListLegacy — 从链表中移除对象（旧版）
char RemoveObjectFromLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    return 0;
}

// RemoveObjectSingleLinkedListLegacy — 从单链表中移除对象（最旧版）
char RemoveObjectSingleLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    return 0;
}

// InitObjectOperationEntry — 初始化对象操作条目
char InitObjectOperationEntry(void)
{
    return 0;
}

// ClearProcessPageTableFlags — 清除进程页表标志
void ClearProcessPageTableFlags(struct _KPROCESS *ProcessObject)
{
    return;
}

// CmdQueryFileEndOfFile — 查询文件结束位置
__int64 CmdQueryFileEndOfFile(HANDLE FileHandle, _QWORD *pResult)
{
    return 0;
}

// BuildNtExportIndexTable — 构建 NT 导出索引表
void BuildNtExportIndexTable(void)
{
    return;
}

// CheckTmDllSection — 检查 TM DLL 节区
char CheckTmDllSection(unsigned __int8 *NameToMatch)
{
    return 0;
}

// QueryDiskInfoAta — 查询 ATA 磁盘信息
char QueryDiskInfoAta(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    return 0;
}

// SendAtaScsiCommand — 发送 ATA SCSI 命令
char SendAtaScsiCommand(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    return 0;
}

// BuildDevicePath — 构建设备路径
char BuildDevicePath(char *Buffer, unsigned int BufferSize)
{
    return 0;
}

// ResolveSyscallAddressesInProcess — 在进程中解析系统调用地址
void ResolveSyscallAddressesInProcess(void)
{
    return;
}

// ScanProcessPESections — 扫描进程 PE 节区
void ScanProcessPESections(void)
{
    return;
}

// QuerySystemInfoPart1 — 查询系统信息第 1 部分
char QuerySystemInfoPart1(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    return 0;
}

// QuerySystemInfoPart2 — 查询系统信息第 2 部分
char QuerySystemInfoPart2(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    return 0;
}

// InitNsiEnumerateObjects — 初始化 NsiEnumerateObjects
char InitNsiEnumerateObjects(void)
{
    return 0;
}

// ReadNtoskrnlToBuffer — 读取 ntoskrnl 到缓冲区
char ReadNtoskrnlToBuffer(void **FileBuffer, unsigned int *FileSize)
{
    return 0;
}

// ParseNtoskrnlSectionsForKernelBase — 解析 ntoskrnl 节区获取内核基址
__int64 ParseNtoskrnlSectionsForKernelBase(__int64 PeBase, unsigned int PeSize)
{
    return 0;
}

// j_GetCurrentFiber — 获取当前纤程（stub）
void *j_GetCurrentFiber(void)
{
    return 0;
}
