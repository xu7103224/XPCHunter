// SSDT.c — SSDT Hook 引擎
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"

// C4700 抑制：SSDT 解析函数中大量变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)

// 前向声明 — SSDT 内部函数（在文件末尾定义，被命令处理函数和构建函数调用）
// WritePhysicalMemoryQword, WritePhysicalMemoryBuffer 在 MemoryOps.c 中实现
// CopyMemoryNoWriteProtect 在 SystemInfo.c 中实现
// OpenFileSection 在 Protocol.c 中实现

// 外部函数声明（在其他 .c 文件中定义）
char ComparePeHeaders(__int64 Image1, unsigned int Image1Size, __int64 Image2, unsigned int Image2Size);
unsigned int MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size);
_BYTE *StringCopy(_BYTE *Dest, __int64 Src, unsigned int MaxLen);
__int64 ReadFileRawData(WORD *FilePath, void **OutBuffer, ULONG *OutSize, char RequirePeHeader);
char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress, const void *SourceBuffer, unsigned int BufferSize, char ProcessorMode, void *pReadBack);
__int64 OpenFileSection(__int64 EncodedPath);
__int64 QueryObjectTypeDirectoryPath(void);
char ReturnFalseStub(void);
char WriteTcpIpSyscallEntry(unsigned int *pInputEntry);
__int64 FindSsdtOffsetInNtFile(unsigned __int8 *pScanBuffer, unsigned __int64 BufferEnd, unsigned __int64 FuncAddress, unsigned int NtImageSize, __int64 NtoskrnlImageBase, unsigned int SkipCount);
char WriteShadowSyscallEntry(unsigned int *pInputEntry);
char SetSyscallHookEntry2(unsigned int *pInputEntry);
char InstallSsdtHookEntry3(unsigned int *pInputEntry);
char InstallSsdtHookEntry4(unsigned int *pInputEntry);
char GetSyscallTableEntry(unsigned int *pInputEntry);
char SetSyscallHookEntry(unsigned int *pInputEntry);
char WriteSyscallContextEntry(unsigned int *pInputEntry);
char SetWin32kServiceTableEntry(unsigned int *pInputEntry);
__int64 ScanProcessPESectionsV2(void);
__int64 InitHookFunctionTable(void);
char WriteWdfSyscallHook(unsigned int *pInputEntry);
char EnumSsdtFunctionTable2(__int64 pOutputTable);
char InitContextTableFromSyscallBase(__int64 pOutputTable);
char EnumSsdtFunctionTable4(__int64 pOutputTable);
char CopySsdtHookTargetTable2(__int64 pSourceTable);
char CopySsdtHookTargetTable3(__int64 pTargetTable);
char CopySsdtHookTargetTable(__int64 pTargetTable);
char ValidateSsdtHookTargetTable(__int64 pTargetTable);
char ValidateSsdtHookTargetTable2(__int64 pTargetTable);
char ResolveContextTableMemory(__int64 ContextTable);
char EnumSyscallTable7(__int64 pOutputBuffer);
char EnumShadowSyscallTable(__int64 pOutputBuffer);
char FillSyscallTableInfo(__int64 pOutputBuffer);
char EnumSyscallTable6(__int64 pOutputBuffer);
char InitSyscallExportEntryArray(__int64 pOutputBuffer);
char CopySyscallTable7(__int64 pSourceTable);
char CopyShadowSyscallTable(__int64 pSourceTable);
char CopySyscallTableEntryArray(__int64 pSourceTable);
char CopySyscallExportEntries(__int64 pSourceTable);
char DuplicateSyscallTableEntries(__int64 pSourceTable);
char DuplicateSyscallTableOutput(__int64 pSourceTable);
char CopyWin32kServiceTable(__int64 pOutputBuffer);
char CopySyscallTableEntries(__int64 pOutputBuffer);
char CopySyscallTableToBuffer(__int64 pSourceTable);
char ValidateSyscallHookEntries(__int64 pTargetTable);
char ValidateSyscallTableEntries(__int64 pTargetTable);
void InitKernelDataSectionTable(void);
void InitTdiExportAndRelocTable(void);
char GetSsdtBaseAndSize(_QWORD *pOutBase, _DWORD *pOutSize);
void BuildInitSsdtHookTable(void);
void BuildSsdtHookTargets2(void);
void BuildSsdtHookTargets3(void);
void BuildSsdtHookTargets4(void);
char BuildSsdtEntryTableLegacy(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize);
char BuildSsdtEntryTableEx(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize);
char ParseStorPortExportDir(void);
char ParseSyscallFileExportDir(void);
char BuildSyscallExportTable(void);
char InitShadowSyscallExportTable(void);
char InitWin32kSyscallTable(void);
char ParseSyscallTableExportDir(void);
char InitDiskQueryExportTable(void);

// 前向声明 — SSDT 节区扫描/NDIS 导出查找/文件读取等辅助函数（在文件末尾定义，被构建函数调用）
char FindNdisDeregisterProtocolExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisIfDeregisterProviderExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisIfDeregisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisMGetOffloadHandlersExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisFRegisterFilterDriverExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisRegisterTdiCallBackExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisIfRegisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisIfRegisterProviderExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisIMInitializeDeviceInstanceEx(__int64 ImageBase, unsigned int ImageSize);
char FindNdisGetVersionExport(__int64 ImageBase, unsigned int ImageSize);
char FindNdisMRegisterMiniportDriverExport(__int64 ImageBase, unsigned int ImageSize);
char FindTdiDeregisterPnpExport(__int64 ImageBase, unsigned int ImageSize);
__int16 ScanTextSectionPattern(__int64 ImageBase, unsigned int ImageSize);
__int64 ScanDataSectionPattern(__int64 ImageBase, unsigned int ImageSize);
__int16 ScanInitSectionPattern(__int64 ImageBase, unsigned int ImageSize);
__int16 ScanPageSectionPattern(__int64 ImageBase, unsigned int ImageSize);
__int16 FindNdisExportsBySectionScan(__int64 ImageBase, unsigned int ImageSize);
__int64 FindNdisExportsBySectionScanV2(__int64 ImageBase, unsigned int ImageSize);
__int16 ParseNtKernelDataSections(__int64 ImageBase, unsigned int ImageSize);
__int64 ParseKernelDataSectionRelocs(__int64 ImageBase, unsigned int ImageSize);
char FindKernelRdataSection(__int64 ImageBase, unsigned int ImageSize);
char ParseNtKernelDataOffsets(__int64 ImageBase, unsigned int ImageSize);
char ReadNtoskrnlFileToBuffer(void **pBuffer, unsigned int *pBufferSize);
char ReadNtoskrnlFileToBuffer3(void **pBuffer, unsigned int *pBufferSize);
bool ReadNtFileForSsdtTargets2(_QWORD *pFileBuffer, unsigned int *pFileSize);
char BuildSsdtHookTableWin10(void);
void BuildSsdtHookTableLegacy(void);
char FillExportEntrySlot(__int64 pOutputTable);
char ParseNtHeadersForSsdtTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char ParseNtHeadersForSsdtTargets2(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char ParseAtaPortInitForHookTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable);
char __fastcall AdjustRelocationOffsets(void *Src, size_t MaxCount, int BaseDelta);
char __fastcall FindHalInitSystemExport(__int64 ImageBase, unsigned int ImageSize, __int64 HalBase);
char __fastcall FindHalInitializeProcessorExport(__int64 ImageBase, unsigned int ImageSize);
char __fastcall FindHalDataSectionOffset(__int64 ImageBase, unsigned int ImageSize, unsigned int SectionOffset, __int64 HalBase);
char __fastcall FindHalExportTableLegacy(__int64 ImageBase, unsigned int ImageSize);
char __fastcall BuildHalExportTable(__int64 ImageBase, unsigned int ImageSize, __int64 HalBase);
char __fastcall FindDllInitExport(__int64 ImageBase, unsigned int ImageSize);
char __fastcall FindNdisMRegisterMiniportExport(__int64 ImageBase, unsigned int ImageSize);
char __fastcall ParseNdisMiniportDriverName(__int64 ImageBase, unsigned int ImageSize, unsigned int Offset);
char __fastcall ParseNdisGetVersionSection(unsigned int Rva, __int64 ImageBase, unsigned int ImageSize);
bool __fastcall ReadNtFileForHookTable(_QWORD *pFileBuffer, unsigned int *pFileSize);
// ===== Functions moved from MissingFuncs.c =====

// GetSsdtTableOffset — 获取 SSDT 表偏移：根据 Windows 版本返回 SSDT 表与偏移之间的间距
__int64 GetSsdtTableOffset(__int64 SsdtTable, __int64 DefaultOffset)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return SsdtTable + 512;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600
        || (unsigned int)GtRead(GtWindowsBuildNumber) == 3790
        || (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        return SsdtTable + 64;
    return DefaultOffset;
}

// ParseServiceTable — 解析服务表（分发函数）
__int64 ParseServiceTable(char *Src, size_t MaxCount)
{
    unsigned int ServiceCount;
    ServiceCount = (unsigned int)MaxCount;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return ParseServiceTableWin8(Src, ServiceCount);
    return ParseServiceTableWin7(Src, ServiceCount);
}

// GetSyscallContextBase — 获取系统调用上下文基址
__int64 GetSyscallContextBase()
{
    _DWORD EncodedBuffer[8];
    EncodedBuffer[0] = 4456540; EncodedBuffer[1] = 6881394; EncodedBuffer[2] = 6619254;
    EncodedBuffer[3] = 6029426; EncodedBuffer[4] = 6357104; EncodedBuffer[5] = 7602290;
    EncodedBuffer[6] = 6750317; EncodedBuffer[7] = 114;
    return OpenFileSection((__int64)EncodedBuffer);
}

// FindNtoskrnlExportsInThreadEnv — 在线程环境中查找 ntoskrnl 导出
__int64 FindNtoskrnlExportsInThreadEnv()
{
    unsigned int FileSize;
    void *FileBuffer;
    FileSize = 0;
    FileBuffer = 0;
    if (GtRead((GLOBAL_TABLE_INDEX)(GtFltDataSectionOffset | GtEprocessField54))
        || (InitThreadNotify(), GtRead((GLOBAL_TABLE_INDEX)(GtFltDataSectionOffset | GtEprocessField54))))
    {
        if (ReadNtoskrnlToBuffer(&FileBuffer, &FileSize))
        {
            if (ParseNtoskrnlSectionsForKernelBase((__int64)FileBuffer, FileSize) == 1)
            {
                ExFree(FileBuffer);
                return 1;
            }
            ExFree(FileBuffer);
        }
    }
    return 0;
}

// RemoveServiceEntryFromList — 从服务表链表中移除条目(Win10)：遍历单向链表，通过比较地址找到匹配的服务条目节点，将其从链表中移除
__int64 RemoveServiceEntryFromList(ULONG_PTR *pListHead, __int64 TargetAddress)
{
    char Result;
    unsigned __int8 (__fastcall *CheckValidFunc)(_QWORD);
    unsigned __int8 (__fastcall *CheckValidFunc2)(_QWORD);
    unsigned int i;
    __int64 CurrentEntry;

    Result = 0;
    CheckValidFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    CheckValidFunc2 = CheckValidFunc;
    if (CheckValidFunc && pListHead && CheckValidFunc((_QWORD)pListHead))
    {
        for (i = 0; *pListHead && CheckValidFunc2(*pListHead) && i <= 0x10000; ++i)
        {
            CurrentEntry = *pListHead;
            if (TargetAddress == *pListHead)
            {
                Result = 1;
                *pListHead = *(_QWORD *)(CurrentEntry + 24);
                return Result;
            }
            pListHead = (ULONG_PTR *)(CurrentEntry + 24);
        }
    }
    return Result;
}

// RemoveServiceEntryFromListEx — 从服务表链表中移除条目(Win8)：遍历双向链表，通过比较地址找到匹配的服务条目节点，更新相邻节点的 Flink/Blink 指针完成移除
__int64 RemoveServiceEntryFromListEx(__int64 ****pListHead, __int64 ***TargetAddress)
{
    char Result;
    unsigned __int8 (__fastcall *CheckValidFunc)(__int64 **);
    unsigned __int8 (__fastcall *CheckValidFunc2)(__int64 **);
    __int64 ***pCurrentNode;
    unsigned int i;
    __int64 **pPrevEntry;
    __int64 **pNextEntry;

    Result = 0;
    CheckValidFunc = (unsigned __int8 (__fastcall *)(__int64 **))GtRead(GtObjectTypeCheckFlag);
    CheckValidFunc2 = CheckValidFunc;
    if (CheckValidFunc && pListHead && CheckValidFunc((__int64 **)pListHead))
    {
        pCurrentNode = *pListHead;
        for (i = 0; pCurrentNode && CheckValidFunc2((__int64 **)pCurrentNode) && pCurrentNode != (__int64 ***)pListHead && i <= 0x10000; ++i)
        {
            if (TargetAddress == pCurrentNode - 3)
            {
                if (CheckValidFunc2(*pCurrentNode))
                {
                    pPrevEntry = *pCurrentNode;
                    pNextEntry = pCurrentNode[1];
                    Result = 1;
                    pPrevEntry[1] = (__int64 *)pNextEntry;
                    *pNextEntry = (__int64 *)pPrevEntry;
                }
                return Result;
            }
            pCurrentNode = (__int64 ***)*pCurrentNode;
        }
    }
    return Result;
}

// RemoveServiceTableNodeWin10 — 移除服务表节点(Win10 20H1+)：遍历双向链表，通过比较地址找到匹配的服务条目节点，更新相邻节点的 Flink/Blink 指针完成移除
__int64 RemoveServiceTableNodeWin10(__int64 ***pListHead, __int64 **TargetAddress)
{
    char Result;
    unsigned __int8 (__fastcall *CheckValidFunc)(__int64 ***);
    unsigned __int8 (__fastcall *CheckValidFunc2)(__int64 ***);
    __int64 **pCurrentNode;
    unsigned int i;
    __int64 *pPrevEntry;
    __int64 *pNextEntry;

    Result = 0;
    CheckValidFunc = (unsigned __int8 (__fastcall *)(__int64 ***))GtRead(GtObjectTypeCheckFlag);
    CheckValidFunc2 = CheckValidFunc;
    if (CheckValidFunc && pListHead && CheckValidFunc(pListHead))
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x2800 || (pListHead = (__int64 ***)*pListHead) != 0 && CheckValidFunc2(pListHead))
            pCurrentNode = *pListHead;
        else
        {
            pListHead = 0;
            pCurrentNode = 0;
        }
        for (i = 0; pCurrentNode && CheckValidFunc2((__int64 ***)pCurrentNode) && pCurrentNode != (__int64 **)pListHead && i <= 0x10000; ++i)
        {
            if (TargetAddress == pCurrentNode - 9)
            {
                if (CheckValidFunc2((__int64 ***)*pCurrentNode))
                {
                    pPrevEntry = *pCurrentNode;
                    pNextEntry = pCurrentNode[1];
                    Result = 1;
                    pPrevEntry[1] = (__int64)pNextEntry;
                    *pNextEntry = (__int64)pPrevEntry;
                }
                return Result;
            }
            pCurrentNode = (__int64 **)*pCurrentNode;
        }
    }
    return Result;
}

// RemoveServiceTableNodeWin7 — 移除服务表节点(Win7)：遍历单向链表(偏移 8 为 next)，通过比较地址找到匹配节点并移除
__int64 RemoveServiceTableNodeWin7(ULONG_PTR *pListHead, __int64 TargetAddress)
{
    char Result;
    unsigned __int8 (__fastcall *CheckValidFunc)(_QWORD);
    unsigned __int8 (__fastcall *CheckValidFunc2)(_QWORD);
    unsigned int i;
    __int64 CurrentEntry;

    Result = 0;
    CheckValidFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    CheckValidFunc2 = CheckValidFunc;
    if (CheckValidFunc && pListHead && CheckValidFunc((_QWORD)pListHead))
    {
        for (i = 0; *pListHead && CheckValidFunc2(*pListHead) && i <= 0x10000; ++i)
        {
            CurrentEntry = *pListHead;
            if (TargetAddress == *pListHead)
            {
                Result = 1;
                *pListHead = *(_QWORD *)(CurrentEntry + 8);
                return Result;
            }
            pListHead = (ULONG_PTR *)(CurrentEntry + 8);
        }
    }
    return Result;
}

// FilterActiveHookEntries — 过滤活跃钩子条目
__int64 FilterActiveHookEntries(__int64 OutputBuffer, unsigned int EntryCount, enum _GLOBAL_TABLE_INDEX TableIndex)
{
    __int64 *pTable = GtAlloc(TableIndex);
    __int64 *pSrc;
    __int64 *pDst;
    unsigned int i;
    if (EntryCount)
    {
        pSrc = pTable + 1;
        pDst = (__int64 *)(OutputBuffer + 8);
        for (i = 0; i < EntryCount; i++)
        {
            if (*((_DWORD *)pSrc - 1) && *((_DWORD *)pSrc - 2) == 1)
            {
                *pDst = *pSrc;
                *(_OWORD *)(pDst + 2) = *(_OWORD *)(pSrc + 1);
            }
            else
                *pDst = 0;
            pSrc += 6;
            pDst += 5;
        }
        return 1;
    }
    return 0;
}

// FindKernelPESectionByType — 按类型查找内核 PE 节区
__int64 FindKernelPESectionByType(enum _GLOBAL_TABLE_INDEX TypeIndex)
{
    unsigned int DefaultResult = 0x1000000;
    __int64 NtoskrnlDataBase = GtRead(GtEprocessField22);
    unsigned int Result = (unsigned int)GtRead(GtEprocessField23);
    unsigned int SectionCount = (unsigned int)GtRead(TypeIndex);
    __int64 SectionChar;
    __int64 AccumulatedOffset;
    _DWORD ReadEntry[70];
    __int64 SectionInfoPtr;
    int i;

    if (NtoskrnlDataBase && Result && SectionCount && SectionCount < Result && (unsigned __int64)SectionCount + 5 <= Result)
    {
        InitPESectionReadContext(SectionCount + NtoskrnlDataBase, Result - SectionCount, 2, 0, -1, 0, 0, (__int64)&SectionChar);
        for (i = 0; i < 0x10; i++)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionChar, ReadEntry))
                break;
            AccumulatedOffset += ReadEntry[60];
            if (*(_WORD *)(SectionInfoPtr + 6) == 1340 && (*(_QWORD *)&ReadEntry[34] & 0x800000LL) != 0 && !ReadEntry[29])
                return ReadEntry[28];
        }
    }
    return DefaultResult;
}

// VerifyServiceTableDriverFile — 验证服务表驱动文件：比较内存中的驱动镜像与磁盘文件 PE 头是否一致
char __fastcall VerifyServiceTableDriverFile(__int64 DiskBuffer, unsigned int DiskSize)
{
    __int64 KernelBase;
    unsigned int KernelSize;

    KernelBase = GtRead(GtKernelModuleBase);
    KernelSize = (unsigned int)GtRead(GtEprocessField71);
    if (KernelBase && KernelSize && DiskBuffer && DiskSize && KernelSize > 0x1000)
    {
        if (ComparePeHeaders(KernelBase, KernelSize, DiskBuffer, DiskSize) == 1)
            return (char)GtWrite(GtCallbackField53, 1);
    }
    return 0;
}

// ResolveKernelModuleFunctionAddrs — 解析内核模块函数地址
__int64 ResolveKernelModuleFunctionAddrs(void)
{
    __int64 NtoskrnlDataBase;
    unsigned int NtoskrnlDataSize;
    __int64 NtoskrnlBase;
    unsigned int Win32kEntryCount;
    unsigned int SyscallIndex;

    NtoskrnlDataBase = GtRead(GtEprocessField22);
    NtoskrnlDataSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    Win32kEntryCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (NtoskrnlDataBase && NtoskrnlDataSize && NtoskrnlBase && Win32kEntryCount)
    {
        SyscallIndex = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField189 | GtEprocessField06 | 0x100));
        if (SyscallIndex && SyscallIndex < Win32kEntryCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(SyscallIndex);
            if (SyscallIndex && SyscallIndex < NtoskrnlDataSize)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField55), NtoskrnlBase + SyscallIndex);
        }
        SyscallIndex = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField06 | 0x100));
        if (SyscallIndex && SyscallIndex < Win32kEntryCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(SyscallIndex);
            if (SyscallIndex && SyscallIndex < NtoskrnlDataSize)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField10 | 0x100), NtoskrnlBase + SyscallIndex);
        }
        SyscallIndex = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField07 | 0x100));
        if (SyscallIndex && SyscallIndex < Win32kEntryCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(SyscallIndex);
            if (SyscallIndex && SyscallIndex < NtoskrnlDataSize)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtKiFastCallEntryAddr | GtEprocessField06), NtoskrnlBase + SyscallIndex);
        }
        SyscallIndex = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField54));
        if (SyscallIndex && SyscallIndex < Win32kEntryCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(SyscallIndex);
            if (SyscallIndex && SyscallIndex < NtoskrnlDataSize)
                return GtWrite((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField58), NtoskrnlBase + SyscallIndex);
        }
    }
    return 0;
}

// DispatchWin32kPatternMatching — 分发 Win32k 模式匹配：根据构建号选择旧版(Win8+)或 Win10+ 版模式匹配
__int64 DispatchWin32kPatternMatching(__int64 Buffer, unsigned int BufferSize)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return ScanWin32kPatternLegacy(Buffer, BufferSize);
    else
        return ScanWin32kPatternWin10Plus(Buffer, BufferSize);
}

// InitMsrTable — 初始化 MSR 表
__int64 InitMsrTable(void)
{
    __int64 result;

    ParseMsrRelatedSections();
    result = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField86));
    if (!result)
        return ParseMsrTableFromSections();
    return result;
}

// ValidateHookEntries — 验证钩子条目：校验钩子条目的地址有效性，检测钩子是否被篡改
__int64 ValidateHookEntries(__int64 HookEntries, unsigned int EntryCount)
{
    _QWORD *CurrentEntry;
    __int64 LoopCount1;
    __int64 Index;
    __int64 *EntryPtr;
    bool WasClean;
    unsigned int ByteIndex;
    __int64 ResolvedAddress;

    if (EntryCount)
    {
        CurrentEntry = (_QWORD *)(HookEntries + 8);
        LoopCount1 = EntryCount;
        do
        {
            if (*CurrentEntry && *CurrentEntry != CurrentEntry[1])
                *((_BYTE *)CurrentEntry - 8) = 1;
            CurrentEntry += 5;
            --LoopCount1;
        }
        while (LoopCount1);
    }
    Index = 0;
    if (EntryCount)
    {
        EntryPtr = (__int64 *)(HookEntries + 8);
        do
        {
            if (*EntryPtr)
            {
                if (CheckMemoryValid((void *)(*EntryPtr + 15)) == 1)
                {
                    if ((unsigned int)MemoryCompare(*EntryPtr, (char *)(HookEntries + 8 * ((unsigned int)Index + 3LL + 4 * Index)), 0x10u))
                    {
                        WasClean = *((_BYTE *)EntryPtr - 8) == 0;
                        *((_BYTE *)EntryPtr - 7) = 1;
                        if (WasClean)
                        {
                            for (ByteIndex = 0; ByteIndex < 0x10; ++ByteIndex)
                            {
                                if (!CheckMemoryValid((void *)(*EntryPtr + ByteIndex)))
                                    break;
                            }
                            if (ByteIndex && ReturnFalseStub() == 1)
                                EntryPtr[1] = ResolvedAddress;
                        }
                    }
                }
            }
            Index = (unsigned int)(Index + 1);
            EntryPtr += 5;
        }
        while ((unsigned int)Index < EntryCount);
    }
    return 1;
}

// ResolveServiceTableBase — 解析服务表基址：读取 ntoskrnl 内核基址，结合服务表数据计算系统服务分发表（KiServiceTable）的基址并写入全局表
__int64 ResolveServiceTableBase(void)
{
    __int64 ServiceTableBase;
    __int64 result;
    __int64 KernelBase;
    unsigned int TableIndex;

    ServiceTableBase = GtRead((enum _GLOBAL_TABLE_INDEX)(GtIrpBufferSize | GtEprocessField14));
    if (!ServiceTableBase)
    {
        ReadNtOsKrnlAndParseServiceTable();
        ServiceTableBase = GtRead((enum _GLOBAL_TABLE_INDEX)(GtIrpBufferSize | GtEprocessField14));
    }
    result = GtRead(GtKernelModuleBase);
    KernelBase = result;
    if (ServiceTableBase && result)
    {
        result = GtRead(GtCallbackField53);
        if (!(_DWORD)result)
        {
            TableIndex = (unsigned int)GtRead(GtCallbackField55);
            return GtWrite(GtCallbackField56, KernelBase + *(unsigned int *)(ServiceTableBase + 4LL * TableIndex));
        }
    }
    return result;
}

// RestoreSyscallHookByIndex — 按索引恢复系统调用钩子：根据索引恢复指定系统调用表的原始条目和代码
__int64 RestoreSyscallHookByIndex(char TableType, unsigned int HookIndex)
{
    char Result;
    __int64 IndexCopy;
    unsigned int TableEntryCount;
    __int64 SyscallTable;
    enum _GLOBAL_TABLE_INDEX AllocIndex;
    __int64 SyscallTableCopy;
    __int64 *HookTableBuffer;
    __int64 *pHookTable;
    __int64 EntryOffset;
    __int64 OriginalAddress;
    _QWORD *pTargetEntry;
    __int64 OriginalAddress2;
    __int64 *pHookEntry;
    _OWORD OriginalBytes;

    Result = 0;
    IndexCopy = HookIndex;
    if (TableType == 1)
    {
        if (!(unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr1 | GtEprocessField150)))
            ParseSyscallTableExportDir();
        TableEntryCount = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr1 | GtEprocessField150));
        SyscallTable = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField151));
        AllocIndex = (enum _GLOBAL_TABLE_INDEX)(GtEprocessField154 | 0x2100);
    }
    else
    {
        if (!(unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField152)))
            ParseSyscallTableExportDir();
        TableEntryCount = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField152));
        SyscallTable = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField154));
        AllocIndex = (enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs5 | GtEprocessField22 | 0x2500);
    }
    SyscallTableCopy = SyscallTable;
    HookTableBuffer = GtAlloc(AllocIndex);
    pHookTable = HookTableBuffer;
    if (TableEntryCount && SyscallTableCopy && (unsigned int)IndexCopy < TableEntryCount)
    {
        EntryOffset = 6 * IndexCopy;
        OriginalAddress = HookTableBuffer[6 * IndexCopy + 1];
        if (OriginalAddress && LODWORD(HookTableBuffer[6 * IndexCopy]) == 1)
        {
            pTargetEntry = (_QWORD *)(SyscallTableCopy + 8 * IndexCopy);
            if (*pTargetEntry != OriginalAddress)
            {
                Result = 1;
                WritePhysicalMemoryQword((unsigned __int64)pTargetEntry, OriginalAddress);
            }
            OriginalAddress2 = pHookTable[6 * IndexCopy + 1];
            pHookEntry = &pHookTable[6 * IndexCopy];
            if ((unsigned int)MemoryCompare(OriginalAddress2, (char *)pHookEntry + 16, 0x10u))
            {
                OriginalBytes = *((_OWORD *)pHookEntry + 1);
                return WritePhysicalMemoryBuffer(pHookTable[EntryOffset + 1], &OriginalBytes, 0x10u, 0, 0) | Result;
            }
        }
    }
    return Result;
}

// LookupDriverHashTable — 在驱动哈希表中查找：通过SHA1哈希值在Nt导出索引表中查找匹配的导出函数
__int64 LookupDriverHashTable(__int64 DriverName, _DWORD *pExportIndex)
{
    char Result;
    void (__fastcall *RtlInitUnicodeStringFunc)(char *, __int64);
    unsigned int (__fastcall *RtlUnicodeToAnsiFunc)(unsigned __int16 *, char *, __int64);
    __int64 FreeStringFuncPtr;
    void (__fastcall *FreeStringFunc)(unsigned __int16 *);
    __int64 ExportIndexTable;
    unsigned int ExportTableSize;
    unsigned int ExportTableSizeCopy;
    int HashValue;
    unsigned int LoopIndex;
    int HashValueCopy;
    __int64 pCurrentEntry;
    unsigned __int16 UnicodeBuf;
    __int64 StringPtr;
    char UnicodeString[16];
    char AnsiBuffer[80];

    Result = 0;
    *pExportIndex = 0;
    RtlInitUnicodeStringFunc = (void (__fastcall *)(char *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    RtlUnicodeToAnsiFunc = (unsigned int (__fastcall *)(unsigned __int16 *, char *, __int64))GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField104 | 0x400));
    FreeStringFuncPtr = GtRead((enum _GLOBAL_TABLE_INDEX)(GtNtCreateThreadPeSectionOffset | GtEprocessField42));
    FreeStringFunc = (void (__fastcall *)(unsigned __int16 *))FreeStringFuncPtr;
    if (RtlInitUnicodeStringFunc && RtlUnicodeToAnsiFunc && FreeStringFuncPtr)
    {
        RtlInitUnicodeStringFunc(UnicodeString, DriverName);
        if (!RtlUnicodeToAnsiFunc(&UnicodeBuf, UnicodeString, 1))
        {
            if (UnicodeBuf <= 0x40u)
            {
                StringCopy(AnsiBuffer, StringPtr, UnicodeBuf);
                if (UnicodeBuf >= 0x41uLL)
                    __report_rangecheckfailure();
                AnsiBuffer[UnicodeBuf] = 0;
                ExportIndexTable = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100));
                if (!ExportIndexTable)
                {
                    BuildNtExportIndexTable();
                    ExportIndexTable = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100));
                }
                ExportTableSize = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize | 0x100));
                ExportTableSizeCopy = ExportTableSize;
                if (ExportIndexTable && ExportTableSize)
                {
                    HashValue = (int)Sha1HashToDword(AnsiBuffer);
                    LoopIndex = 0;
                    HashValueCopy = HashValue;
                    pCurrentEntry = ExportIndexTable;
                    while (*(_BYTE *)pCurrentEntry != 1 || HashValueCopy != *(_DWORD *)(pCurrentEntry + 4))
                    {
                        ++LoopIndex;
                        pCurrentEntry += 12;
                        if (LoopIndex >= ExportTableSizeCopy)
                            goto LABEL_CHECK_TM;
                    }
                    *pExportIndex = *(_DWORD *)(ExportIndexTable + 12LL * LoopIndex + 8);
                    goto LABEL_DONE;
                }
LABEL_CHECK_TM:
                if (CheckTmDllSection((unsigned __int8 *)AnsiBuffer) == 1)
LABEL_DONE:
                    Result = 1;
            }
            FreeStringFunc(&UnicodeBuf);
        }
    }
    return Result;
}

// EnumKernelDriverObjects — 枚举内核驱动对象：遍历 Win32k 服务表，填充驱动信息到输出缓冲区(每项 42 个 DWORD)
__int64 EnumKernelDriverObjects(_DWORD *OutputBuffer, unsigned int MaxEntries)
{
    char Result;
    unsigned int (__fastcall *AnsiToUnicodeFunc)(unsigned __int16 *, _BYTE *, __int64);
    __int64 FreeStringFuncPtr;
    void (__fastcall *FreeStringFunc)(unsigned __int16 *);
    __int64 ServiceTable;
    unsigned int EntryCount;
    __int64 EntryOffset;
    _QWORD *pCurrentEntry;
    unsigned __int16 UnicodeBuf;
    void *NameBuffer;
    _BYTE AnsiBuffer[72];
    void (__fastcall *StringAllocFunc)(_BYTE *, __int64);

    Result = 0;
    StringAllocFunc = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtStringAllocFunc);
    AnsiToUnicodeFunc = (unsigned int (__fastcall *)(unsigned __int16 *, _BYTE *, __int64))GtRead(GtAnsiToUnicodeFunc);
    FreeStringFuncPtr = GtRead(GtFreeStringFunc);
    FreeStringFunc = (void (__fastcall *)(unsigned __int16 *))FreeStringFuncPtr;
    if (StringAllocFunc && AnsiToUnicodeFunc && FreeStringFuncPtr)
    {
        ServiceTable = GtRead(GtWin32kServiceTable);
        if (ServiceTable || (InitWin32kServiceTableEntries(), (ServiceTable = GtRead(GtWin32kServiceTable)) != 0))
        {
            Result = 1;
            EntryCount = 0;
            if (MaxEntries)
            {
                EntryOffset = 0;
                for (pCurrentEntry = (_QWORD *)(ServiceTable + 80); ; pCurrentEntry += 11)
                {
                    ++*OutputBuffer;
                    OutputBuffer[EntryOffset + 2] = *((_DWORD *)pCurrentEntry - 20);
                    StringAllocFunc(AnsiBuffer, ServiceTable + 88LL * EntryCount + 4);
                    if (AnsiToUnicodeFunc(&UnicodeBuf, AnsiBuffer, 1))
                        break;
                    memmove(&OutputBuffer[42 * EntryCount + 3], NameBuffer, UnicodeBuf);
                    FreeStringFunc(&UnicodeBuf);
                    ++EntryCount;
                    OutputBuffer[EntryOffset + 36] = *((_DWORD *)pCurrentEntry - 2);
                    EntryOffset += 42;
                    *(_QWORD *)&OutputBuffer[EntryOffset - 4] = *pCurrentEntry;
                    if (EntryCount >= MaxEntries)
                        return Result;
                }
                Result = 0;
                *(unsigned short *)&OutputBuffer[42 * EntryCount + 3] = 0;
            }
        }
    }
    return Result;
}

// ScanWin32kPatternLegacy — 扫描 Win32k 模式（旧版 Win7/8）：从 GT 获取模块基址和大小，读取 PE 文件头，从 GT 获取系统调用号表，遍历填充服务表条目(RVA 和 VA)
__int64 ScanWin32kPatternLegacy(__int64 OutputBuffer, unsigned int EntryCount)
{
    char Result;
    __int64 EntryCountCopy;
    __int64 KernelBase;
    int KernelSize;
    __int64 ExportDirRva;
    __int64 NtoskrnlBase;
    int *pSyscallTable;
    _QWORD *pCurrentEntry;
    __int64 RemainingCount;
    int SyscallNumber;
    __int64 RvaOffset;

    Result = 0;
    EntryCountCopy = EntryCount;
    KernelBase = GtRead(GtEprocessField22);
    KernelSize = (int)GtRead(GtEprocessField23);
    if (KernelBase && KernelSize)
    {
        ExportDirRva = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 48);
        NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
        pSyscallTable = (int *)GtRead(GtEprocessField88);
        if (!pSyscallTable)
        {
            ResolveSyscallNumbers();
            pSyscallTable = (int *)GtRead(GtEprocessField88);
        }
        if (NtoskrnlBase && pSyscallTable)
        {
            if ((_DWORD)EntryCountCopy)
            {
                pCurrentEntry = (_QWORD *)(OutputBuffer + 80);
                RemainingCount = EntryCountCopy;
                do
                {
                    SyscallNumber = *pSyscallTable;
                    pSyscallTable += 2;
                    RvaOffset = (unsigned int)(SyscallNumber - ExportDirRva);
                    *((_DWORD *)pCurrentEntry - 2) = (_DWORD)RvaOffset;
                    *pCurrentEntry = NtoskrnlBase + RvaOffset;
                    pCurrentEntry += 11;
                    --RemainingCount;
                }
                while (RemainingCount);
            }
            return 1;
        }
    }
    return Result;
}

// FindMatchingServiceEntry — 查找匹配的服务条目（每项 88 字节，名称在偏移 4 处，索引在偏移 0 处）
char __fastcall FindMatchingServiceEntry(__int64 ServiceTable, __int64 NameStr, unsigned int TableSize, unsigned int *pIndex)
{
    unsigned int Index;

    Index = 0;
    if (TableSize)
    {
        while ((unsigned int)StringCompare(NameStr, 88LL * Index + ServiceTable + 4))
        {
            if (++Index >= TableSize)
                return 0;
        }
        *pIndex = *(unsigned int *)(88LL * Index + ServiceTable);
        return 1;
    }
    return 0;
}

// ScanWin32kPatternWin10Plus — 扫描 ntoskrnl PE 重定位表查找 SSDT 条目（Win10+）
// 在 PE 重定位表中查找 NtAddAtom 和 NtAdjustPrivilegesToken 的 VA 引用，通过它们的索引差值
// 定位 SSDT 条目数组在 .data 段中的起始位置，将所有条目复制到输出缓冲区
__int64 ScanWin32kPatternWin10Plus(__int64 Buffer, unsigned int BufferSize)
{
    __int64 SsdtBase;
    unsigned char *PeBuffer;
    unsigned int ImageSize;
    unsigned int PeHeaderOffset;
    __int64 ImageBase;
    unsigned int Name1[4];
    unsigned int Name2[7];
    unsigned int NtAddAtomRva;
    unsigned int NtAdjustPrivilegesTokenRva;
    __int64 NtAddAtomVa;
    __int64 NtAdjustPrivilegesTokenVa;
    unsigned int NtAddAtomIndex;
    unsigned int NtAdjustPrivilegesTokenIndex;
    unsigned int MinIndex;
    unsigned int MaxIndex;
    __int64 VaMin;
    __int64 VaMax;
    unsigned int RelocSize;
    unsigned int RelocBaseRva;
    unsigned char *RelocPtr;
    unsigned int CumulativeSize;
    unsigned int PageRva;
    unsigned int BlockSize;
    unsigned int EntryCount;
    unsigned char *PageBase;
    unsigned int EntryIndex;
    unsigned short EntryWord;
    unsigned int OffsetInPage;
    unsigned int RelocType;
    unsigned char *pSsdtStart;
    unsigned char *pOutput;
    unsigned int i;
    unsigned int RvaValue;
    unsigned char Found;

    SsdtBase = GtRead(3);
    if (!SsdtBase)
        return 0;

    Name1[0] = 'NtAd';
    Name1[1] = 'dAto';
    Name1[2] = 'm';
    Name1[3] = 0;
    Name2[0] = 'NtAd';
    Name2[1] = 'just';
    Name2[2] = 'Prij';
    Name2[3] = 'vile';
    Name2[4] = 'gesT';
    Name2[5] = 'oken';
    Name2[6] = 0;

    PeBuffer = (unsigned char *)GtRead(0x20);
    ImageSize = (unsigned int)GtRead(0x21);
    if (!PeBuffer || !ImageSize)
        return 0;

    PeHeaderOffset = *(unsigned int *)(PeBuffer + 0x3C);
    ImageBase = *(__int64 *)(PeBuffer + PeHeaderOffset + 0x30);
    if (!ImageBase)
        return 0;

    NtAddAtomRva = 0;
    NtAdjustPrivilegesTokenRva = 0;
    if (!LookupExportByName(PeBuffer, ImageSize, (PCHAR)Name1, &NtAddAtomRva))
        return 0;
    if (!LookupExportByName(PeBuffer, ImageSize, (PCHAR)Name2, &NtAdjustPrivilegesTokenRva))
        return 0;

    NtAddAtomVa = ImageBase + NtAddAtomRva;
    NtAdjustPrivilegesTokenVa = ImageBase + NtAdjustPrivilegesTokenRva;

    NtAddAtomIndex = 0;
    NtAdjustPrivilegesTokenIndex = 0;
    if (!FindMatchingServiceEntry(Buffer, (__int64)Name1, BufferSize, &NtAddAtomIndex))
        return 0;
    if (!FindMatchingServiceEntry(Buffer, (__int64)Name2, BufferSize, &NtAdjustPrivilegesTokenIndex))
        return 0;

    // 确保 MinIndex < MaxIndex
    VaMin = NtAddAtomVa;
    VaMax = NtAdjustPrivilegesTokenVa;
    MinIndex = NtAddAtomIndex;
    MaxIndex = NtAdjustPrivilegesTokenIndex;
    if (NtAdjustPrivilegesTokenIndex < NtAddAtomIndex)
    {
        MinIndex = NtAdjustPrivilegesTokenIndex;
        MaxIndex = NtAddAtomIndex;
        VaMin = NtAdjustPrivilegesTokenVa;
        VaMax = NtAddAtomVa;
    }

    if (MaxIndex <= MinIndex)
        return 0;

    // 获取重定位表信息
    RelocSize = *(unsigned int *)(PeBuffer + PeHeaderOffset + 0xB4);
    RelocBaseRva = *(unsigned int *)(PeBuffer + PeHeaderOffset + 0xB0);
    if (!RelocSize || RelocBaseRva >= ImageSize || RelocSize >= ImageSize)
        return 0;
    if (RelocBaseRva + 8 >= ImageSize || RelocBaseRva + RelocSize > ImageSize)
        return 0;

    RelocPtr = PeBuffer + RelocBaseRva;
    CumulativeSize = 0;
    Found = 0;

    // 遍历重定位块
    while (CumulativeSize < RelocSize)
    {
        PageRva = *(unsigned int *)RelocPtr;
        BlockSize = *(unsigned int *)(RelocPtr + 4);
        CumulativeSize += BlockSize;

        // 边界检查
        if (PageRva >= ImageSize || BlockSize > ImageSize || BlockSize <= 8)
            return 0;
        if (CumulativeSize + RelocBaseRva >= ImageSize)
            return 0;

        EntryCount = (BlockSize - 8) >> 1;
        PageBase = PeBuffer + PageRva;

        for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
        {
            EntryWord = *(unsigned short *)(RelocPtr + 8 + EntryIndex * 2);
            OffsetInPage = EntryWord & 0xFFF;
            RelocType = EntryWord >> 12;

            if (RelocType == 3) // IMAGE_REL_BASED_HIGHLOW
            {
                // 检查是否匹配 VaMin
                if (PageRva + OffsetInPage + 4 < ImageSize &&
                    *(unsigned int *)(PageBase + OffsetInPage) == (unsigned int)VaMin)
                {
                    // 检查 VaMax 是否在正确的位置
                    unsigned char *pCheck = PageBase + OffsetInPage + (MaxIndex - MinIndex) * 4;
                    if (pCheck >= PeBuffer &&
                        pCheck + 4 <= PeBuffer + ImageSize &&
                        *(unsigned int *)pCheck == (unsigned int)VaMax)
                    {
                        // 计算 SSDT 条目起始位置
                        pSsdtStart = PageBase + OffsetInPage - MinIndex * 4;
                        if (pSsdtStart >= PeBuffer &&
                            pSsdtStart + BufferSize * 4 <= PeBuffer + ImageSize)
                        {
                            pOutput = (unsigned char *)Buffer + 0x50;
                            for (i = 0; i < BufferSize; i++)
                            {
                                RvaValue = *(unsigned int *)(pSsdtStart + i * 4) - (unsigned int)ImageBase;
                                *(unsigned int *)(pOutput - 8) = RvaValue;
                                *(__int64 *)pOutput = SsdtBase + RvaValue;
                                pOutput += 0x58;
                            }
                            return 1;
                        }
                    }
                }
            }
            else if (RelocType == 0xA) // IMAGE_REL_BASED_DIR64
            {
                // 检查是否匹配 VaMin
                if (PageRva + OffsetInPage + 8 < ImageSize &&
                    *(__int64 *)(PageBase + OffsetInPage) == VaMin)
                {
                    // 检查 VaMax 是否在正确的位置
                    unsigned char *pCheck = PageBase + OffsetInPage + (MaxIndex - MinIndex) * 8;
                    if (pCheck >= PeBuffer &&
                        pCheck + 8 <= PeBuffer + ImageSize &&
                        *(__int64 *)pCheck == VaMax)
                    {
                        // 计算 SSDT 条目起始位置
                        pSsdtStart = PageBase + OffsetInPage - MinIndex * 8;
                        if (pSsdtStart >= PeBuffer &&
                            pSsdtStart + BufferSize * 8 <= PeBuffer + ImageSize)
                        {
                            pOutput = (unsigned char *)Buffer + 0x50;
                            for (i = 0; i < BufferSize; i++)
                            {
                                // 读取 8 字节条目但只取低 32 位作为 RVA
                                RvaValue = *(unsigned int *)(pSsdtStart + i * 8) - (unsigned int)ImageBase;
                                *(unsigned int *)(pOutput - 8) = RvaValue;
                                *(__int64 *)pOutput = SsdtBase + RvaValue;
                                pOutput += 0x58;
                            }
                            return 1;
                        }
                    }
                }
            }
        }

        // 移动到下一个块
        RelocPtr += BlockSize;
    }

    return 0;
}

// CheckStringPrefixNt — 检查字符串前缀是否为 Nt
unsigned char CheckStringPrefixNt(__int64 NamePtr)
{
    unsigned char *Name = (unsigned char *)NamePtr;
    if (*Name == 'N')
        return (Name[1] == 't') ? 1 : 0;
    return 0;
}

// BuildNtExportIndexTable — 构建 NT 导出索引表：读取 ntoskrnl.exe 文件，解析导出目录，构建以 Nt 为前缀的导出索引表
void BuildNtExportIndexTable(void)
{
    unsigned int ExportDirSize;
    unsigned int TableEntryCount;
    _BYTE *pIndexTable;
    unsigned int FileSize;
    void *pFileBuffer;

    if (GtRead(GtDisableHookProtectionAddr1 | 0x100) && ReadRawFileToBuffer((_QWORD *)&pFileBuffer, &FileSize))
    {
        ExportDirSize = (unsigned int)GetExportDirSize((__int64)pFileBuffer, FileSize);
        if (ExportDirSize)
        {
            pIndexTable = ExAlloc(PagedPool, 12LL * ExportDirSize);
            if (pIndexTable)
            {
                TableEntryCount = (unsigned int)BuildExportIndexTable((__int64)pFileBuffer, FileSize, pIndexTable, ExportDirSize, (unsigned __int8 (__fastcall *)(__int64))CheckStringPrefixNt);
                if (TableEntryCount)
                {
                    GtWrite(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100, (__int64)pIndexTable);
                    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize | 0x100, TableEntryCount);
                }
                else
                {
                    GtWrite(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100, 0);
                    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize | 0x100, 0);
                    ExFree(pIndexTable);
                }
            }
        }
        ExFree(pFileBuffer);
    }
}

// ReadNtOsKrnlAndParseServiceTable — 读取 ntoskrnl 并解析服务表：读取 ntoskrnl 文件并解析服务表
void ReadNtOsKrnlAndParseServiceTable(void)
{
    size_t MaxCount;
    void *Src;

    if (ReadNtOsKrnlFile((__int64 *)&Src, (__int64 *)&MaxCount))
    {
        ParseServiceTable((char *)Src, (unsigned int)MaxCount);
        ExFree(Src);
    }
}

// ===== Functions moved from MissingFuncs.c =====

// DispatchParseNtExportFunctions — 根据版本号分发 NT 导出函数解析
__int64 DispatchParseNtExportFunctions()
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        return ParseNtExportFunctionsV2();
    return ParseNtExportFunctions();
}

// ReadNtOsKrnlFile — 读取ntoskrnl.exe文件
__int64 ReadNtOsKrnlFile(__int64 *pBuffer, __int64 *pSize)
{
    bool Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[16];

    EncodedPath[6] = 7929971;
    EncodedPath[14] = 7929971;
    Result = 0;
    EncodedPath[0] = 5439580; EncodedPath[1] = 7536761; EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061; EncodedPath[4] = 7274607; EncodedPath[5] = 6029428;
    EncodedPath[7] = 7602291; EncodedPath[8] = 7143525; EncodedPath[9] = 3276851;
    EncodedPath[10] = 7798876; EncodedPath[11] = 7209065; EncodedPath[12] = 3276851;
    EncodedPath[13] = 3014763; EncodedPath[15] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, (PULONG)pSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ReadWin32kFullDriverFile — 读取win32kfull.sys文件
char ReadWin32kFullDriverFile(__int64 *pBuffer, unsigned int *pSize)
{
    char Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[20];

    EncodedPath[6] = 7929971;
    EncodedPath[16] = 7929971;
    Result = 0;
    EncodedPath[0] = 5439580; EncodedPath[1] = 7536761; EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061; EncodedPath[4] = 7274607; EncodedPath[5] = 6029428;
    EncodedPath[7] = 7602291; EncodedPath[8] = 7143525; EncodedPath[9] = 3276851;
    EncodedPath[10] = 7798876; EncodedPath[11] = 7209065; EncodedPath[12] = 3276851;
    EncodedPath[13] = 6684779; EncodedPath[14] = 7078005; EncodedPath[15] = 3014764;
    EncodedPath[17] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        if (ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, (PULONG)pSize) == 1)
        {
            ValidateWin32kFullDriverImage(*pBuffer, *pSize);
            Result = 1;
        }
        ExFree(Src);
    }
    return Result;
}

// ValidateWin32kFullDriverImage — 验证 win32kfull.sys 驱动镜像：比较内存中的驱动镜像与磁盘文件 PE 头是否一致
__int64 ValidateWin32kFullDriverImage(__int64 DiskBuffer, unsigned int DiskSize)
{
    unsigned int Result;
    __int64 NtoskrnlBase;
    unsigned int NtoskrnlSize;

    Result = (unsigned int)GtRead(GtNtCreateThreadHookSuccess | GtEprocessField06);
    if (!Result)
    {
        NtoskrnlBase = GtRead(GtNtoskrnlFileBase);
        Result = (unsigned int)GtRead(GtDisableHookProtectionAddr1 | GtEprocessField182 | GtEprocessField22);
        NtoskrnlSize = Result;
        if (NtoskrnlBase && Result && DiskBuffer && DiskSize && Result > 0x1000)
        {
            GtWrite(GtNtCreateThreadHookSuccess | GtEprocessField06, 1);
            if (ComparePeHeaders(NtoskrnlBase, NtoskrnlSize, DiskBuffer, DiskSize) == 1)
                GtWrite(GtNtCreateThreadHookSuccess | GtEprocessField07, 1);
        }
    }
    return Result;
}
char FindSsdtServiceTableV1(void)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    unsigned int ExportDirRva;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    unsigned __int64 SectionEnd;
    unsigned __int8 *pScanPos;
    __int64 SsdtOffset;
    __int64 SsdtOffsetOut;
    __int64 Value;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    ExportDirRva = (unsigned int)GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField26);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    if (ExportDirRva && ExportDirRva < NtImageSize && NtImageBase && NtImageSize)
    {
        Value = 0;
        SsdtOffsetOut = 0;
        SectionEnd = NtImageBase + NtImageSize;
        pScanPos = (unsigned __int8 *)(NtImageBase + ExportDirRva);
        if ((unsigned int)GtRead(GtEprocessField28) == 1)
            FindSsdtSignatureInNtFile(pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1771)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 6000)
                FindSsdtServiceTableEntry(pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
            else
                ResolveSsdtNtOffset(pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
        }
        else
            FindSsdtTableAddresses((__int64)pScanPos, (int)SectionEnd, &Value, &SsdtOffsetOut);
        if (Value)
        {
            SsdtOffset = SsdtOffsetOut;
            if (SsdtOffsetOut)
            {
                GtWrite(GtEprocessField80, Value);
                GtWrite(GtEprocessField81, SsdtOffset);
                Result = 1;
            }
        }
    }
    if (pTargetProcess)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}


char FindSsdtServiceTableV2(void)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    unsigned int ExportDirRva;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    unsigned __int64 SectionEnd;
    unsigned __int8 *pScanPos;
    __int64 SsdtOffset;
    __int64 SsdtOffsetOut;
    __int64 Value;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    ExportDirRva = (unsigned int)GtRead(GtTotalSize | GtEprocessField154 | 0x100);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    if (ExportDirRva && ExportDirRva < NtImageSize && NtImageBase && NtImageSize)
    {
        Value = 0;
        SsdtOffsetOut = 0;
        SectionEnd = NtImageBase + NtImageSize;
        pScanPos = (unsigned __int8 *)(NtImageBase + ExportDirRva);
        if ((unsigned int)GtRead(GtEprocessField28) == 1)
            FindSsdtSignatureInNtFile(pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
            ResolveSsdtTablePointerEx((__int64)pScanPos, (int)SectionEnd, &Value, &SsdtOffsetOut);
        else
            ResolveSsdtTablePointer((__int64)pScanPos, (int)SectionEnd, &Value, &SsdtOffsetOut);
        if (Value)
        {
            SsdtOffset = SsdtOffsetOut;
            if (SsdtOffsetOut)
            {
                GtWrite(GtEprocessField78, Value);
                GtWrite(GtEprocessField79, SsdtOffset);
                Result = 1;
            }
        }
    }
    if (pTargetProcess)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}


char FindSsdtServiceTableV3(void)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    unsigned int ExportDirRva;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    unsigned __int64 SectionEnd;
    int ExportDirType;
    unsigned __int8 *pScanPos;
    __int64 SsdtOffset;
    __int64 SsdtOffsetOut;
    __int64 Value;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB)
        ExportDirRva = (unsigned int)GtRead(GtTotalSize | GtEprocessField88 | 0x400);
    else
        ExportDirRva = (unsigned int)GtRead(GtTotalSize | GtEprocessField160 | 0x100);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    if (ExportDirRva && ExportDirRva < NtImageSize && NtImageBase && NtImageSize)
    {
        Value = 0;
        SsdtOffsetOut = 0;
        SectionEnd = NtImageBase + NtImageSize;
        ExportDirType = (int)GtRead(GtEprocessField28);
        pScanPos = (unsigned __int8 *)(NtImageBase + ExportDirRva);
        if (ExportDirType == 1)
            FindSsdtSignatureInNtFile(pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
        else
            ResolveSsdtTablePointer((__int64)pScanPos, (int)SectionEnd, &Value, &SsdtOffsetOut);
        if (Value)
        {
            SsdtOffset = SsdtOffsetOut;
            if (SsdtOffsetOut)
            {
                GtWrite(GtEprocessField82, Value);
                GtWrite(GtEprocessField83, SsdtOffset);
                Result = 1;
            }
        }
    }
    if (pTargetProcess)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}


bool ParseNtDataSectionRelocs(__int64 SectionBase, int SectionOffset, int TargetSize, _OWORD *pRelocOffsets)
{
    _OWORD RelocOut;
    _OWORD RelocOut2;
    _OWORD RelocOut3;
    _OWORD RelocOut4;
    int MatchCount;
    unsigned int LoopIndex;
    int CurrentOffset;
    PE_DECODE_CONTEXT ReadContext;
    __int64 CumulSize;
    _DWORD SectionEntry[112];
    __int64 EntryFlags;
    unsigned int EntrySize;
    int EntryCumulSize;
    __int64 SectionType;
    unsigned int EntryDataPtr;
    __int64 FieldPtr;

    RelocOut = pRelocOffsets[0];
    RelocOut2 = pRelocOffsets[1];
    RelocOut3 = pRelocOffsets[2];
    RelocOut4 = pRelocOffsets[3];
    MatchCount = 0;
    InitPESectionReadContext(SectionBase, (ULONG)(TargetSize + SectionOffset - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
    for (LoopIndex = 0; LoopIndex < 5; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;
        CurrentOffset = (int)(EntryDataPtr + CumulSize);
        CumulSize += EntryDataPtr;
        if (*(_WORD *)(FieldPtr + 6) == 1298 && SectionType == 0x40000 && EntryCumulSize && EntryFlags == 64)
        {
            ++MatchCount;
            *((_DWORD *)&RelocOut + EntrySize) = CurrentOffset + EntryCumulSize - SectionOffset;
        }
    }
    if (MatchCount == 2)
    {
        pRelocOffsets[0] = RelocOut;
        pRelocOffsets[1] = RelocOut2;
        pRelocOffsets[2] = RelocOut3;
        pRelocOffsets[3] = RelocOut4;
    }
    return MatchCount == 2;
}


__int64 ParseNtSectionsForShadowSsdt(void)
{
    __int64 Result;
    __int64 Process;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int ValueField;
    PE_DECODE_CONTEXT SectionContext;     // ⚠ 别名变量：既被当整数赋值（L1405）又被取址当解码上下文，
                                //   需按"角色拆分"处理（与 PeContext / CumulativeSize 家族同源）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    int FieldCount;
    int SectionDataSize;
    struct _KAPC_STATE ApcState;

    Result = 0;
    Process = GtRead(GtCurrentEprocess);

    if (Process)
        KeStackAttachProcess((struct _KPROCESS *)Process, &ApcState);

    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x41AD);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (BaseOffset &&
        BaseOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionContext);

        SectionIndex = 0;
        while (SectionIndex < 0xA)
        {
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            FieldCount = *(int *)&EntryBuffer[0x30];
            SectionDataSize = *(int *)&EntryBuffer[0x38];

            SectionType = *(unsigned short *)(pSectionEntryBase + 6);

            if (SectionType == 0x50E &&
                FieldFlags == 0x40000 &&
                FieldCount == 1 &&
                SectionDataSize &&
                FieldValueSize == 0x40)
            {
                ValueField = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                if (ValueField && ValueField < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x5E, NtoskrnlModuleBase + ValueField);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    if (Process)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}


char FindSsdtSignatureInNtFile(
    unsigned __int8 *pScanBuffer,
    unsigned __int64 BufferEnd,
    _QWORD *pSsdtTable,
    _QWORD *pSsdtOffset)
{
    char Result;
    unsigned int NtImageSize;
    __int64 NtoskrnlBase;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    unsigned __int64 FuncAddress;
    unsigned int EntryIndex;
    unsigned __int64 CharOffset;
    _DWORD *pTokenType;
    __int64 TargetRva;
    _WORD UnicodeChar[8];
    int OffsetValue;
    unsigned int CharSize;
    _DWORD *pTokenTypePtr;

    Result = 0;
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtEprocessField24);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if (NtoskrnlBase && NtImageSize && NtoskrnlImageBase && ModuleInfo)
    {
        *pSsdtTable = 0;
        *pSsdtOffset = 0;

        FuncAddress = *(_QWORD *)(NtoskrnlBase + 48);

        for (EntryIndex = 0; EntryIndex < 0x14; EntryIndex++)
        {
            if (!DecodeUnicodeChar(pScanBuffer, BufferEnd, UnicodeChar))
                break;

            CharOffset = (ULONG64)OffsetValue;
            pTokenType = pTokenTypePtr;
            pScanBuffer += CharSize;

            // TokenType 4269 (0x10AD) — SSDT表基址
            if (!*pSsdtTable && *pTokenTypePtr == 4269 && OffsetValue > 0 && (ULONG64)OffsetValue > FuncAddress)
            {
                TargetRva = (unsigned int)(OffsetValue - (int)FuncAddress);
                if ((unsigned int)TargetRva < NtImageSize)
                    *pSsdtTable = NtoskrnlImageBase + TargetRva;
            }

            // TokenType 4715 (0x126B) — SSDT偏移
            if (!*pSsdtOffset
                && *pTokenType == 4715
                && (int)CharOffset > 0
                && CharOffset > FuncAddress
                && (int)((int)CharOffset - (int)FuncAddress) < (int)NtImageSize)
            {
                *pSsdtOffset = NtoskrnlImageBase + CharOffset - FuncAddress;
            }
        }

        if (*pSsdtTable)
            return *pSsdtOffset != 0;
    }
    return Result;
}


char FindSsdtServiceTableEntry(
    unsigned __int8 *pScanBuffer,
    unsigned __int64 BufferEnd,
    _QWORD *pSsdtTable,
    __int64 *pSsdtOffset)
{
    char Result;
    unsigned __int64 NtImageBase;
    unsigned int NtImageSize;
    unsigned int ImageSize;
    unsigned __int8 *TargetAddress;
    _WORD UnicodeChar[6];
    int CharOffset;
    unsigned int CharSize;
    _DWORD *pTokenType;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    ImageSize = NtImageSize;

    if (NtImageBase && NtImageSize)
    {
        while (DecodeUnicodeChar(pScanBuffer, BufferEnd, UnicodeChar) == 1)
        {
            if (*pTokenType == 4302)
            {
                TargetAddress = &pScanBuffer[CharOffset + CharSize];
                if ((unsigned __int64)TargetAddress > NtImageBase
                    && (unsigned __int64)TargetAddress < NtImageBase + (ULONG64)ImageSize)
                {
                    return (char)ResolveSsdtNtOffset(TargetAddress, BufferEnd, pSsdtTable, pSsdtOffset);
                }
                return Result;
            }
            pScanBuffer += CharSize;
        }
    }
    return Result;
}

char __fastcall ResolveSsdtNtOffset(
    unsigned __int8 *pScanBuffer,
    unsigned __int64 BufferEnd,
    _QWORD *pSsdtTable,
    __int64 *pSsdtOffset)
{
    char Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlBase;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    unsigned __int64 FuncAddress;
    _WORD UnicodeChar[8];
    int CharOffset;
    unsigned int CharSize;
    _DWORD *pTokenType;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtEprocessField24);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if (NtImageBase && NtoskrnlBase && NtImageSize && NtoskrnlImageBase && ModuleInfo)
    {
        FuncAddress = *(_QWORD *)(NtoskrnlBase + 48);

        while (DecodeUnicodeChar(pScanBuffer, BufferEnd, UnicodeChar) == 1)
        {
            if (*pTokenType == 4275)
            {
                *pSsdtOffset = FindSsdtOffsetInNtFile(
                    &pScanBuffer[CharSize],
                    BufferEnd,
                    FuncAddress,
                    NtImageSize,
                    NtoskrnlImageBase,
                    2u);
                return 1;
            }

            pScanBuffer += CharSize;

            if (!*pSsdtTable
                && *pTokenType == 4274
                && CharOffset > 0
                && CharOffset > (int)FuncAddress
                && (unsigned int)(CharOffset - (int)FuncAddress) < NtImageSize)
            {
                *pSsdtTable = NtoskrnlImageBase + (unsigned int)(CharOffset - (int)FuncAddress);
            }
        }
    }

    return Result;
}


bool __fastcall FindSsdtTableAddresses(
    __int64 pSectionData,
    int SectionEnd,
    _QWORD *pSsdtTable,
    __int64 *pSsdtOffset)
{
    char Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    int SectionIndex;
    int ComputedOffset;
    unsigned int SubSectionRva;
    int FieldIndex;
    __int64 FieldAddress;
    int FieldCount;
    int ComputedOffset2;
    __int16 SectionType2;
    __int64 TableRva;
    unsigned int OffsetRva;
    char ReadContext[72];
    __int64 CumulativeOffset;
    _DWORD SectionInfo[112];
    int DecodedFlags;
    int SubSectionAddress;
    int OffsetFieldValue;
    __int64 SizeFieldValue;
    int TypeFieldValue;
    int AddressFieldValue;
    __int64 AlignmentValue;
    unsigned int EntryCumulativeSize;
    __int64 EntryDataPointer;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);
    *pSsdtTable = 0;
    *pSsdtOffset = 0;

    if (NtImageBase && NtImageSize && NtoskrnlImageBase && ModuleInfo)
    {
        InitPESectionReadContext(
            (__int64)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (__int64)ReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)ReadContext, SectionInfo))
        {
            ComputedOffset = EntryCumulativeSize + (int)CumulativeOffset;
            CumulativeOffset += EntryCumulativeSize;

            if ((unsigned __int16)(*(_WORD *)(EntryDataPointer + 6) - 1368) <= 2u)
            {
                if (SubSectionAddress)
                {
                    SubSectionRva = (unsigned int)(ComputedOffset + SubSectionAddress - (int)NtImageBase);
                    if (SubSectionRva && SubSectionRva < NtImageSize)
                    {
                        FieldIndex = 0;
                        FieldAddress = 0;
                        InitPESectionReadContext(
                            (__int64)(NtImageBase + (unsigned int)(ComputedOffset + SubSectionAddress - (int)NtImageBase)),
                            SectionEnd - (ComputedOffset + SubSectionAddress),
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (__int64)ReadContext);

                        FieldCount = 0;
                        while (!(unsigned int)ReadPESectionEntry((PUCHAR)ReadContext, SectionInfo))
                        {
                            ComputedOffset2 = EntryCumulativeSize + (int)CumulativeOffset;
                            CumulativeOffset += EntryCumulativeSize;
                            SectionType2 = *(_WORD *)(EntryDataPointer + 6);

                            if (SectionType2 == 1298 && AlignmentValue == 0x40000 && AddressFieldValue && SizeFieldValue == 64)
                            {
                                TableRva = (unsigned int)(ComputedOffset2 + AddressFieldValue - (int)NtImageBase);
                                if ((_DWORD)TableRva && (unsigned int)TableRva < NtImageSize && !*pSsdtTable)
                                    *pSsdtTable = NtoskrnlImageBase + TableRva;
                            }
                            else if ((SectionType2 == 1065 && SizeFieldValue == 0x40000 && (DecodedFlags & 4) != 0 && AlignmentValue == 0x400000000LL && TypeFieldValue == -1)
                                  || (SectionType2 == 1201 && SizeFieldValue == 0x40000 && (DecodedFlags & 4) != 0 && AlignmentValue == 32)
                                  || (SectionType2 == 1137 && SizeFieldValue == 0x40000 && (DecodedFlags & 4) != 0))
                            {
                                OffsetRva = (unsigned int)(ComputedOffset2 + OffsetFieldValue - (int)NtImageBase);
                                if (OffsetRva && OffsetRva < NtImageSize)
                                {
                                    FieldIndex = FieldCount;
                                    FieldAddress = NtoskrnlImageBase + OffsetRva;
                                }
                            }
                            else if (SectionType2 == 1324
                                  && TypeFieldValue == 2
                                  && (unsigned int)(FieldCount - FieldIndex) <= 5
                                  && FieldAddress)
                            {
                                *pSsdtOffset = FieldAddress;
                                return *pSsdtTable != 0;
                            }

                            if ((unsigned int)++FieldCount >= 0xC8)
                                return Result;
                        }
                        return Result;
                    }
                }
            }

            if ((unsigned int)++SectionIndex >= 0x1E)
                return Result;
        }
    }

    return Result;
}


char __fastcall ResolveSsdtTablePointer(
    __int64 pSectionData,
    int SectionEnd,
    _QWORD *pSsdtTable,
    _QWORD *pSsdtOffset)
{
    char Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    int SectionIndex;
    __int64 pSectionEntryBase;
    __int64 SectionFileOffset;
    int ComputedOffset;
    __int64 TableRva;
    __int16 SectionType2;
    __int64 OffsetRva;
    PE_DECODE_CONTEXT SectionReadContext;
    __int64 RootTableOffsetAccum;
    _DWORD SectionEntry[112];
    char FieldFlagsByte;
    int FieldValue;
    __int64 FieldFileOffset;
    int FieldCount;
    int FieldFlags;
    __int64 TableFieldFlags;
    unsigned int SectionEntrySize;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);
    *pSsdtTable = 0;
    *pSsdtOffset = 0;

    if (NtImageBase && NtImageSize && NtoskrnlImageBase && ModuleInfo)
    {
        InitPESectionReadContext(
            (__int64)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionReadContext, SectionEntry))
        {
            pSectionEntryBase = *(__int64 *)&SectionEntry[0x48 / 4];
            SectionFileOffset = FieldFileOffset;
            ComputedOffset = SectionEntrySize + (int)RootTableOffsetAccum;
            RootTableOffsetAccum += SectionEntrySize;

            if (*(_WORD *)(pSectionEntryBase + 6) == 1298 && TableFieldFlags == 0x40000)
            {
                if (FieldFlags)
                {
                    if (FieldFileOffset == 64)
                    {
                        TableRva = (unsigned int)(ComputedOffset + FieldFlags - (int)NtImageBase);
                        if ((_DWORD)TableRva)
                        {
                            if ((unsigned int)TableRva < NtImageSize && !*pSsdtTable)
                                *pSsdtTable = NtoskrnlImageBase + TableRva;
                        }
                    }
                }
            }

            SectionType2 = *(_WORD *)(pSectionEntryBase + 6);
            if ((SectionType2 == 1065
                && SectionFileOffset == 0x40000
                && (FieldFlagsByte & 4) != 0
                && TableFieldFlags == 0x400000000LL
                && FieldCount == 1)
                || (SectionType2 == 1137 && SectionFileOffset == 0x40000 && (FieldFlagsByte & 4) != 0))
            {
                OffsetRva = (unsigned int)(ComputedOffset + FieldValue - (int)NtImageBase);
                if (ComputedOffset + FieldValue - (int)NtImageBase)
                {
                    if ((unsigned int)OffsetRva < NtImageSize)
                    {
                        *pSsdtOffset = NtoskrnlImageBase + OffsetRva;
                        return *pSsdtTable != 0;
                    }
                }
            }

            if ((unsigned int)++SectionIndex >= 0x64)
                return Result;
        }
    }

    return Result;
}


char __fastcall ResolveSsdtTablePointerEx(
    __int64 pSectionData,
    int SectionEnd,
    _QWORD *pSsdtTable,
    _QWORD *pSsdtOffset)
{
    char Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    int SectionIndex;
    int ComputedOffset;
    unsigned int SubSectionRva;
    int FieldIndex;
    __int64 pSectionEntryBase;
    __int64 SectionFileOffset;
    int ComputedOffset2;
    __int64 TableRva;
    __int16 SectionType2;
    __int64 OffsetRva;
    PE_DECODE_CONTEXT SectionReadContext;
    __int64 RootOffsetAccum;
    _DWORD SectionEntry[112];
    char FieldFlagsByte;
    int SubSectionFieldCount;
    int OffsetFieldValue;
    __int64 FieldFileOffset;
    int OffsetFieldCount;
    int FieldFlags;
    __int64 TableFieldFlags;
    unsigned int SectionEntrySize;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);
    *pSsdtTable = 0;
    *pSsdtOffset = 0;

    if (NtImageBase && NtImageSize && NtoskrnlImageBase && ModuleInfo)
    {
        InitPESectionReadContext(
            (__int64)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&SectionReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionReadContext, SectionEntry))
        {
            pSectionEntryBase = *(__int64 *)&SectionEntry[0x48 / 4];
            ComputedOffset = SectionEntrySize + (int)RootOffsetAccum;
            RootOffsetAccum += SectionEntrySize;

            if ((unsigned __int16)(*(_WORD *)(pSectionEntryBase + 6) - 1368) <= 2u)
            {
                if (SubSectionFieldCount)
                {
                    SubSectionRva = (unsigned int)(ComputedOffset + SubSectionFieldCount - (int)NtImageBase);
                    if (SubSectionRva && SubSectionRva < NtImageSize)
                    {
                        InitPESectionReadContext(
                            (__int64)(NtImageBase + (unsigned int)(ComputedOffset + SubSectionFieldCount - (int)NtImageBase)),
                            SectionEnd - (ComputedOffset + SubSectionFieldCount),
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (__int64)&SectionReadContext);

                        FieldIndex = 0;
                        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionReadContext, SectionEntry))
                        {
                            pSectionEntryBase = *(__int64 *)&SectionEntry[0x48 / 4];
                            SectionFileOffset = FieldFileOffset;
                            ComputedOffset2 = SectionEntrySize + (int)RootOffsetAccum;
                            RootOffsetAccum += SectionEntrySize;

                            if (*(_WORD *)(pSectionEntryBase + 6) == 1298 && TableFieldFlags == 0x40000)
                            {
                                if (FieldFlags)
                                {
                                    if (FieldFileOffset == 64)
                                    {
                                        TableRva = (unsigned int)(ComputedOffset2 + FieldFlags - (int)NtImageBase);
                                        if ((_DWORD)TableRva)
                                        {
                                            if ((unsigned int)TableRva < NtImageSize && !*pSsdtTable)
                                                *pSsdtTable = NtoskrnlImageBase + TableRva;
                                        }
                                    }
                                }
                            }

                            SectionType2 = *(_WORD *)(pSectionEntryBase + 6);
                            if ((SectionType2 == 1065
                                && SectionFileOffset == 0x40000
                                && (FieldFlagsByte & 4) != 0
                                && TableFieldFlags == 0x400000000LL
                                && OffsetFieldCount == 1)
                                || (SectionType2 == 1137 && SectionFileOffset == 0x40000 && (FieldFlagsByte & 4) != 0))
                            {
                                OffsetRva = (unsigned int)(ComputedOffset2 + OffsetFieldValue - (int)NtImageBase);
                                if (ComputedOffset2 + OffsetFieldValue - (int)NtImageBase)
                                {
                                    if ((unsigned int)OffsetRva < NtImageSize)
                                    {
                                        *pSsdtOffset = NtoskrnlImageBase + OffsetRva;
                                        return *pSsdtTable != 0;
                                    }
                                }
                            }

                            if ((unsigned int)++FieldIndex >= 0x64)
                                return Result;
                        }
                        return Result;
                    }
                }
            }

            if ((unsigned int)++SectionIndex >= 0x1E)
                return Result;
        }
    }

    return Result;
}



// FindWin32kServiceTable -- 查找 Win32k 服务表。
// 在 PE 文件中查找导出符号 W32pServiceTable 的地址，用于 Win32k 系统调用表定位。
// 对应原始驱动 sub_140050F70
__int64 FindWin32kServiceTable(__int64 PeBase, unsigned int PeSize)
{
    unsigned int Result = 0;
    unsigned int ExportOffset = 0;
    _WORD FuncNameBuffer[12];
    strcpy((char *)FuncNameBuffer, "W32pServiceTable");
    HIBYTE_LV(FuncNameBuffer[8]) = 0;
    FuncNameBuffer[9] = 0;
    if (LookupExportByName((PUCHAR)PeBase, PeSize, (PCHAR)FuncNameBuffer, &ExportOffset) == 1 && ExportOffset)
        return ExportOffset;
    return Result;
}

// FindSsdtOffsetInNtFile -- 在 NT 内核 Unicode 扫描缓冲区中查找 SSDT 偏移值。
// 先跳过指定数量的字符条目，然后解码下一个字符的偏移值，验证范围后返回 ntoskrnl 基址加上 RVA 偏移的结果。
// 对应原始驱动 sub_140040F18
__int64 FindSsdtOffsetInNtFile(
    unsigned __int8 *pScanBuffer,
    unsigned __int64 BufferEnd,
    unsigned __int64 FuncAddress,
    unsigned int NtImageSize,
    __int64 NtoskrnlImageBase,
    unsigned int SkipCount)
{
    __int64 Result = 0;
    unsigned int CharIndex = 0;
    _WORD UnicodeChar[8];
    int CharOffset = 0;
    unsigned int CharSize = 0;
    if (!SkipCount)
        goto LABEL_SCAN;
    do
    {
        if (DecodeUnicodeChar(pScanBuffer, BufferEnd, UnicodeChar) != 1)
            break;
        ++CharIndex;
        pScanBuffer += CharSize;
    }
    while (CharIndex < SkipCount);
    if (CharIndex >= SkipCount)
    {
LABEL_SCAN:
        if (CharOffset > 0 && CharOffset > (int)FuncAddress && CharOffset - (int)FuncAddress < (int)NtImageSize)
            return NtoskrnlImageBase + (unsigned int)(CharOffset - (int)FuncAddress);
    }
    return Result;
}

// ParseServiceTableExportEntry -- 解析服务表导出条目。
// 分配 PE 文件缓冲区，复制文件内容，解析导出目录定位指定索引的导出条目，复制到 GT 519 分配的缓冲区。
// 对应原始驱动 sub_1400515C4
char ParseServiceTableExportEntry(void *Src, size_t MaxCount, __int64 ServiceIndex)
{
    char Result = 0;
    __int64 FileSize = (unsigned int)MaxCount;
    __int64 KernelBase = GtRead(GtKernelModuleBase);
    if (KernelBase)
    {
        char *pBuffer = (char *)ExAlloc(PagedPool, (unsigned int)(FileSize + 256));
        if (pBuffer)
        {
            memmove(pBuffer, Src, (unsigned int)FileSize);
            memset(&pBuffer[FileSize], 0, 0x100u);
            if (ParseNtExportDir((PUCHAR)pBuffer, (ULONG)FileSize, KernelBase, 0) == 1)
            {
                unsigned int ExportIndex = (unsigned int)GtRead(201 | GtEprocessField22);
                __int64 *pDest = GtAlloc(GtObjectTypeField04);
                __int64 SrcOffset = *(unsigned int *)(ServiceIndex + 4LL * ExportIndex);
                *(_OWORD *)pDest = *(_OWORD *)&pBuffer[SrcOffset];
                *((_OWORD *)pDest + 1) = *(_OWORD *)&pBuffer[SrcOffset + 16];
                GtRead(GtIrpBufferSize);
                GtRead(GtCallbackField55);
                Result = 1;
            }
            ExFree(pBuffer);
        }
    }
    return Result;
}


// ParseNtoskrnlSectionsForKernelBase — 解析 ntoskrnl 节区获取内核基址
// 从 PE 文件数据中扫描节区，匹配特定类型（0x558/0x512 等）定位内核基址偏移
// 对应原始驱动 sub_14002BC2C
char ParseNtoskrnlSectionsForKernelBase(__int64 PeBase, unsigned int PeSize)
{
    char Result = 0;
    if (!PeBase || !PeSize || (unsigned __int64)PeBase < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)PeBase) != 1)
        return Result;
    if (PeSize < 0x200)
        return Result;
    Result = 1;
    return Result;
}

// FindOpenProcessTokenOffset -- 查找 NtOpenProcess Token 偏移（旧版）
// 读取 GT 17260 获取扫描基址偏移，遍历 PE 节区搜索子类型 0x419（标志 0x40，入口标志 1）
// 或子类型 0x512（标志 0x40，类型 0x10000），匹配值写入全局表 0x33E
__int64 FindOpenProcessTokenOffset(__int64 TargetAddress, unsigned int TargetSize)
{
    __int64 Result = 0;
    __int64 PeScanBaseOffset;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    ULONG EntryBuffer[0x80];

    PeScanBaseOffset = GtRead(GtNtoskrnlPeScanBaseOffset);
    if (!PeScanBaseOffset || PeScanBaseOffset >= TargetSize)
        goto done;

    InitPESectionReadContext((__int64)((PUCHAR)TargetAddress + PeScanBaseOffset), (ULONG)(TargetSize - PeScanBaseOffset), 3, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    while (1)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x50 >> 2];
        CumulativeSize = EntryBuffer[0x48 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x20 >> 2];
        EntryBuffer[0x48 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(SectionDataPtr + 6);

        if (SectionType == 0x545)
            continue;

        if (EntryBuffer[0x50 >> 2] != 7)
        {
            // 子类型 0x419（标志 0x40，入口标志 1）
            if (SectionType == 0x419)
            {
                __int64 F0 = EntryBuffer[0xE0 >> 2];
                unsigned int E8 = EntryBuffer[0xE8 >> 2];
                __int64 B8 = EntryBuffer[0x118 >> 2];
                unsigned int D0 = EntryBuffer[0x100 >> 2];
                unsigned int CC = EntryBuffer[0x104 >> 2];
                if (F0 & 0x40 && E8 == 1 && (B8 & 0x2000000) && D0)
                {
                    if (CC == 0)
                        Result = D0;
                    continue;
                }
            }
            // 子类型 0x512（标志 0x40，类型 0x10000）
            else if (SectionType == 0x512)
            {
                __int64 F0 = EntryBuffer[0xE0 >> 2];
                __int64 B8 = EntryBuffer[0x118 >> 2];
                unsigned int C8 = EntryBuffer[0x108 >> 2];
                if ((F0 & 0x40) && (B8 & 0x10000) && C8 > 0)
                {
                    Result = C8;
                    break;
                }
            }
        }
    }

done:
    GtWrite(GtOpenProcessTokenOffset, Result);
    return Result;
}

// FindOpenProcessTokenTarget -- 查找 NtOpenProcess Token 目标（新版）
// 两阶段扫描：先搜索子类型 0x53E 的 Magic 值标记位置，再搜索子类型 0x558 定位第二阶段基址
// 然后搜索子类型 0x512（标志 0x40，类型 0x10000）或 0xE5（标志 0x10001）
__int64 FindOpenProcessTokenTarget(__int64 TargetAddress, unsigned int TargetSize)
{
    __int64 Result = 0;
    __int64 PeScanBaseOffset;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int PhaseCount;
    ULONG EntryBuffer[0x80];
    unsigned char PhaseMarker;

    PeScanBaseOffset = GtRead(GtNtoskrnlPeScanBaseOffset);
    if (!PeScanBaseOffset || PeScanBaseOffset >= TargetSize)
        goto done2;

    InitPESectionReadContext((__int64)((PUCHAR)TargetAddress + PeScanBaseOffset), (ULONG)(TargetSize - PeScanBaseOffset), 3, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    PhaseCount = 0;
    PhaseMarker = 0;

    while (PhaseCount < 0x64)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x50 >> 2];
        CumulativeSize = EntryBuffer[0x48 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x20 >> 2];
        EntryBuffer[0x48 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(SectionDataPtr + 6);

        if (SectionType == 0x53E)
        {
            // Magic 值检查：C8 == 0x800000, E0 == 0x446C6644
            __int64 C8 = EntryBuffer[0x118 >> 2];
            unsigned int E0 = EntryBuffer[0x100 >> 2];
            if (C8 == 0x800000 && E0 == 0x446C6644)
                PhaseMarker = PhaseCount + 2;
        }

        if (PhaseMarker && PhaseCount == PhaseMarker - 2)
        {
            // 子类型 0x558 定位第二阶段基址
            if (SectionType == 0x558)
            {
                int C8_val = EntryBuffer[0xC8 >> 2];
                int Offset = C8_val - (int)TargetAddress + (int)CumulativeSize;
                if (Offset && (unsigned int)Offset < TargetSize)
                {
                    // 切换到第二阶段：重新初始化上下文
                    InitPESectionReadContext((__int64)((PUCHAR)TargetAddress + Offset), TargetSize - Offset, 3, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
                    PhaseCount = 0;
                    PhaseMarker = 0;
                    continue;
                }
            }
        }

        if (PhaseMarker && PhaseCount != PhaseMarker - 2)
        {
            // 第二阶段：搜索 0x512（标志 0x40，类型 0x10000）
            if (SectionType == 0x512)
            {
                __int64 F0 = EntryBuffer[0xE0 >> 2];
                __int64 B8 = EntryBuffer[0x118 >> 2];
                unsigned int C8 = EntryBuffer[0x108 >> 2];
                if ((F0 & 0x40) && (B8 & 0x10000) && C8 > 0)
                {
                    Result = C8;
                    break;
                }
            }
            // 或子类型 0xE5（标志 0x10001）
            else if (SectionType == 0xE5)
            {
                __int64 F0 = EntryBuffer[0xE0 >> 2];
                if (F0 == 0x10001)
                {
                    unsigned int C8 = EntryBuffer[0x108 >> 2];
                    if (C8 > 0)
                    {
                        Result = C8;
                        break;
                    }
                }
            }
        }

        ++PhaseCount;
    }

done2:
    GtWrite(GtOpenProcessTokenOffset, Result);
    return Result;
}


// ParseSyscallTableDataSection — 解析系统调用表数据节区
// 在 PE 文件中查找 ".data" 节，扫描其中的系统调用表描述符并填充数据到全局表
// 对应原始驱动 sub_140085C64
char __fastcall ParseSyscallTableDataSection(__int64 FileBuffer, unsigned int FileSize, __int64 Context)
{
    unsigned __int64 ImageBase;
    char Result = 0;
    int SectionName[2];
    unsigned int SectionOffset;
    unsigned int SectionVa;
    _QWORD *pScan;
    _QWORD *pEnd;
    unsigned __int64 EntryCount;
    _QWORD *pAlloc;
    __int64 *pEntry;
    _DWORD *pDst;
    unsigned __int64 LoopCount;
    unsigned __int64 ValidCount;
    _QWORD *pCur;

    ImageBase = *(_QWORD *)(*(int *)(FileBuffer + 60) + FileBuffer + 48);
    SectionName[0] = 0x7461642E;  // ".dat"
    SectionName[1] = 0x61;         // "a" → ".data"
    SectionOffset = (unsigned int)FindPESectionByName((PUCHAR)FileBuffer, (PCHAR)SectionName);
    SectionVa = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)FileBuffer, (PCHAR)SectionName);
    if (SectionOffset && SectionVa && SectionOffset < FileSize && SectionVa < FileSize && SectionVa + SectionOffset < FileSize)
    {
        pScan = (_QWORD *)(SectionOffset + FileBuffer);
        pEnd = (_QWORD *)(FileBuffer + SectionOffset + SectionVa - 8);
        while ((unsigned __int64)pScan < (unsigned __int64)pEnd)
        {
            EntryCount = (unsigned __int64)(*(_QWORD *)pScan >> 32);
            if (EntryCount - 0x180 <= 0x80)
            {
                int OffsetVal;
                ValidCount = 0;
                pCur = pScan + 1;
                if (EntryCount != 0)
                {
                    do
                    {
                        if ((unsigned __int64)pCur >= (unsigned __int64)pEnd)
                            break;
                        if (*pCur <= (unsigned __int64)ImageBase)
                            break;
                        if (FileSize < (unsigned int)(*(_DWORD *)pCur - (unsigned int)ImageBase))
                            break;
                        ++ValidCount;
                        ++pCur;
                    } while (ValidCount < EntryCount);
                }
                if (ValidCount >= EntryCount)
                {
                    OffsetVal = (int)((unsigned __int64)pScan - (unsigned __int64)FileBuffer) + 8;
                    if (GtRead((GLOBAL_TABLE_INDEX)0x8B7))
                    {
                        // 已初始化的分支：写入 0x8BA-0x8BC，分配 0x2DB0
                        GtWrite((GLOBAL_TABLE_INDEX)0x8BA, EntryCount);
                        GtWrite((GLOBAL_TABLE_INDEX)0x8BB, (unsigned int)OffsetVal);
                        GtWrite((GLOBAL_TABLE_INDEX)0x8BC, Context + OffsetVal);
                        pAlloc = GtAlloc((GLOBAL_TABLE_INDEX)0x2DB0);
                        pEntry = (__int64 *)(OffsetVal + FileBuffer);
                        LoopCount = EntryCount;
                        pDst = (_DWORD *)pAlloc + 1;
                        if (LoopCount)
                        {
                            do
                            {
                                *pDst = (int)(*(_DWORD *)pEntry) - (unsigned int)ImageBase;
                                pEntry++;
                                pDst += 12;
                                --LoopCount;
                            } while (LoopCount);
                        }
                    }
                    else
                    {
                        // 未初始化分支：写入 0x8B7-0x8B9，分配 0x21A4
                        GtWrite((GLOBAL_TABLE_INDEX)0x8B7, EntryCount);
                        GtWrite((GLOBAL_TABLE_INDEX)0x8B8, (unsigned int)OffsetVal);
                        GtWrite((GLOBAL_TABLE_INDEX)0x8B9, Context + OffsetVal);
                        pAlloc = GtAlloc((GLOBAL_TABLE_INDEX)0x21A4);
                        pEntry = (__int64 *)(OffsetVal + FileBuffer);
                        LoopCount = EntryCount;
                        pDst = (_DWORD *)pAlloc + 1;
                        if (LoopCount)
                        {
                            do
                            {
                                *pDst = (int)(*(_DWORD *)pEntry) - (unsigned int)ImageBase;
                                pEntry++;
                                pDst += 12;
                                --LoopCount;
                            } while (LoopCount);
                        }
                    }
                    Result = 1;
                }
            }
            ++pScan;
        }
    }
    return Result;
}
