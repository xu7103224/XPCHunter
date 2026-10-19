// SSDT.c — SSDT Hook 引擎（从 SsdtHook.c 拆分后保留）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：SSDT 表构建、Hook 安装/卸除、各 Nt* Hook 函数

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
void ParseStorPortExportDir(void);
char ParseSyscallFileExportDir(void);
char BuildSyscallExportTable(void);
char InitShadowSyscallExportTable(void);
char InitWin32kSyscallTable(void);
void ParseSyscallTableExportDir(void);
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
__int64 FindHookTargetInExportWin7(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);
__int64 FindHookTargetInExportWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress);

// ============================================================
// SSDT 内部辅助函数实现
// ============================================================

// CheckAddressInPhysicalMemoryRange — 在 MemoryOps.c 中实现
// OpenFileSection — 在 Protocol.c 中实现
// 这些函数在其他文件中实现，此处仅声明引用：
//   WritePhysicalMemory, WritePhysicalMemoryQword, WritePhysicalMemoryBuffer (MemoryOps.c)
//   CopyMemoryNoWriteProtect (SystemInfo.c)

// ---- 9 个驱动节区打开函数 ----

// WriteTcpIpSyscallEntry — 写入 TcpIp 系统调用表项
// 对应原始驱动 sub_1400539B8（67 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x1400537FC 且描述为 "OpenTcpIpDriverSection" ——
//   那是**被调用的** OpenTcpIpDriverSection 的信息；本函数真实地址 0x1400539B8。
char WriteTcpIpSyscallEntry(unsigned int *pInputEntry)
{
    __int64 SectionBase = OpenTcpIpDriverSection();
    if (SectionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(SectionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char WriteShadowSyscallEntry(unsigned int *pInputEntry)
{
    __int64 SectionBase = OpenKbdClassDriverSection();
    if (SectionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(SectionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char SetSyscallHookEntry2(unsigned int *pInputEntry)
{
    __int64 FunctionBase = GetSsdtFunctionBase2();
    if (FunctionBase)
    {
        if (*pInputEntry <= 0x1B)
        {
            WritePhysicalMemoryQword(FunctionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
            return 1;
        }
        if (*pInputEntry == 28)
        {
            WritePhysicalMemoryQword(FunctionBase + 96, *((_QWORD *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}
char InstallSsdtHookEntry3(unsigned int *pInputEntry)
{
    __int64 ContextBase = DecryptDiskDeviceContextStr();
    if (ContextBase)
    {
        if (*pInputEntry <= 0x1B)
        {
            WritePhysicalMemoryQword(ContextBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
            return 1;
        }
        if (*pInputEntry == 28)
        {
            WritePhysicalMemoryQword(ContextBase + 96, *((_QWORD *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}
char InstallSsdtHookEntry4(unsigned int *pInputEntry)
{
    __int64 FunctionBase = GetSsdtFunctionBase4();
    if (FunctionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(FunctionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char GetSyscallTableEntry(unsigned int *pInputEntry)
{
    _QWORD *DiskDriverSection = GetDiskDriverSection();
    if (DiskDriverSection)
    {
        if (*pInputEntry <= 0x1B)
        {
            WritePhysicalMemoryQword((unsigned __int64)&DiskDriverSection[*pInputEntry + 14], *((_QWORD *)pInputEntry + 1));
            return 1;
        }
        if (*pInputEntry == 28)
        {
            WritePhysicalMemoryQword((unsigned __int64)(DiskDriverSection + 12), *((_QWORD *)pInputEntry + 1));
            return 1;
        }
    }
    return 0;
}
char SetSyscallHookEntry(unsigned int *pInputEntry)
{
    __int64 SectionBase = OpenMountMgrDriverSection();
    if (SectionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(SectionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char WriteSyscallContextEntry(unsigned int *pInputEntry)
{
    __int64 DriverSection = BuildSyscallDriverPath();
    if (DriverSection && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(DriverSection + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char SetWin32kServiceTableEntry(unsigned int *pInputEntry)
{
    __int64 SectionBase = OpenWin32kSection();
    if (SectionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(SectionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char WriteWdfSyscallHook(unsigned int *pInputEntry)
{
    __int64 SectionBase = OpenWdfDriverSection();
    if (SectionBase && *pInputEntry <= 0x1B)
    {
        WritePhysicalMemoryQword(SectionBase + 8 * (*pInputEntry) + 112, *((_QWORD *)pInputEntry + 1));
        return 1;
    }
    return 0;
}
char EnumSsdtFunctionTable2(__int64 pOutputTable)
{
    unsigned int Index = 0;
    __int64 FunctionBase = GetSsdtFunctionBase2();
    if (FunctionBase)
    {
        __int64 pEntry = pOutputTable;
        _QWORD *pFuncPtr = (_QWORD *)(FunctionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputTable + 1344) = Index;
        *(_QWORD *)(pOutputTable + 1360) = *(_QWORD *)(FunctionBase + 96);
        return 1;
    }
    return 0;
}
char InitContextTableFromSyscallBase(__int64 pOutputTable)
{
    unsigned int Index = 0;
    __int64 ContextBase = DecryptDiskDeviceContextStr();
    if (ContextBase)
    {
        __int64 pOutputEntry = pOutputTable;
        _QWORD *pFuncEntry = (_QWORD *)(ContextBase + 112);
        do
        {
            *(_DWORD *)pOutputEntry = Index++;
            *(_QWORD *)(pOutputEntry + 16) = *pFuncEntry;
            pOutputEntry += 64;
            pFuncEntry++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputTable + 1792) = Index;
        *(_QWORD *)(pOutputTable + 1808) = *(_QWORD *)(ContextBase + 96);
        return 1;
    }
    return 0;
}
char EnumSsdtFunctionTable4(__int64 pOutputTable)
{
    unsigned int Index = 0;
    __int64 FunctionBase = GetSsdtFunctionBase4();
    if (FunctionBase)
    {
        _QWORD *pFuncTable = (_QWORD *)(FunctionBase + 112);
        do
        {
            *(_DWORD *)pOutputTable = Index++;
            *(_QWORD *)(pOutputTable + 16) = *pFuncTable;
            pOutputTable += 48;
            pFuncTable++;
        } while (Index <= 0x1B);
        return 1;
    }
    return 0;
}
char CopySsdtHookTargetTable2(__int64 pSourceTable)
{
    char Result = 0;
    __int64 *pDestTable = GtAlloc(GtEprocessModuleEntrySize | GtCallbackField50 | 0x400);
    __int64 EntryCount = 29;
    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;

    do
    {
        *(_DWORD *)&pSrcEntry[DeltaOffset] = *(_DWORD *)pSrcEntry;
        if (*(_DWORD *)pSrcEntry && *((_DWORD *)pSrcEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)&pSrcEntry[DeltaOffset + 22] = *(_OWORD *)(pSrcEntry + 12);
        }
        else
        {
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = 0;
        }
        pSrcEntry += 48;
        EntryCount--;
    } while (EntryCount);
    return Result;
}
char CopySsdtHookTargetTable3(__int64 pTargetTable)
{
    char Result = 0;
    __int64 *pSourceTable = GtAlloc(GtFltUnregisterFilterOffset | GtDebugPortOffset | 0x400);
    __int64 pTargetEntry = pTargetTable + 8;
    __int64 EntryCount = 29;
    char *pSourceEntry = (char *)pSourceTable + 4;

    do
    {
        *(_DWORD *)(pTargetEntry - 4) = *(_DWORD *)pSourceEntry;
        if (*(_DWORD *)pSourceEntry && *((_DWORD *)pSourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)pTargetEntry = *(_QWORD *)(pSourceEntry + 4);
            *(_OWORD *)(pTargetEntry + 18) = *(_OWORD *)(pSourceEntry + 12);
            *(_OWORD *)(pTargetEntry + 34) = *(_OWORD *)(pSourceEntry + 28);
        }
        else
        {
            *(_QWORD *)pTargetEntry = 0;
        }
        pSourceEntry += 48;
        pTargetEntry += 64;
        EntryCount--;
    } while (EntryCount);
    return Result;
}
char CopySsdtHookTargetTable(__int64 pTargetTable)
{
    char Result = 0;
    __int64 *pSourceTable = GtAlloc(GtEprocessField108 | 0x1000);
    __int64 EntryCount = 28;
    char *pSourceEntry = (char *)pSourceTable + 4;
    __int64 DeltaOffset = pTargetTable - (__int64)pSourceTable;

    do
    {
        *(_DWORD *)&pSourceEntry[DeltaOffset] = *(_DWORD *)pSourceEntry;
        if (*(_DWORD *)pSourceEntry && *((_DWORD *)pSourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSourceEntry[DeltaOffset + 4] = *(_QWORD *)(pSourceEntry + 4);
            *(_OWORD *)&pSourceEntry[DeltaOffset + 22] = *(_OWORD *)(pSourceEntry + 12);
        }
        pSourceEntry += 48;
        EntryCount--;
    } while (EntryCount);
    return Result;
}
char ValidateSsdtHookTargetTable(__int64 pTargetTable)
{
    __int64 pEntry = pTargetTable + 8;
    __int64 EntryCount = 29;
    __int64 pScanEntry = pTargetTable + 8;
    __int64 EntryIndex = 0;
    unsigned int ByteIndex = 0;
    __int64 SavedOriginalAddr = 0;

    do
    {
        if (*(_QWORD *)pScanEntry && *(_QWORD *)pScanEntry != *(_QWORD *)(pScanEntry + 8))
            *(_BYTE *)(pScanEntry + 16) = 1;
        pScanEntry += 48;
        EntryCount--;
    } while (EntryCount);

    for (EntryIndex = 0; (unsigned int)EntryIndex <= 0x1C; EntryIndex++)
    {
        if (*(_QWORD *)pEntry)
        {
            if (MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15LL)) == 1)
            {
                if ((unsigned int)MemoryCompare(*(_QWORD *)pEntry, (char *)(48 * EntryIndex + pTargetTable + 26), 0x10u))
                {
                    *(_BYTE *)(pEntry + 17) = 1;
                    if (*(_BYTE *)(pEntry + 16) == 0)
                    {
                        for (ByteIndex = 0; ByteIndex < 0x10; ByteIndex++)
                        {
                            if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + ByteIndex)))
                                break;
                        }
                        if (ByteIndex && ReturnFalseStub() == 1)
                            *(_QWORD *)(pEntry + 8) = SavedOriginalAddr;
                    }
                }
            }
        }
        pEntry += 48;
    }
    return 1;
}
char ValidateSsdtHookTargetTable2(__int64 pTargetTable)
{
    __int64 pEntry = pTargetTable + 8;
    __int64 EntryCount = 28;
    __int64 pScanEntry = pTargetTable + 8;
    __int64 EntryIndex = 0;
    unsigned int ByteIndex = 0;
    __int64 SavedOriginalAddr = 0;

    do
    {
        if (*(_QWORD *)pScanEntry && *(_QWORD *)pScanEntry != *(_QWORD *)(pScanEntry + 8))
            *(_BYTE *)(pScanEntry + 16) = 1;
        pScanEntry += 48;
        EntryCount--;
    } while (EntryCount);

    for (EntryIndex = 0; (unsigned int)EntryIndex <= 0x1B; EntryIndex++)
    {
        if (*(_QWORD *)pEntry)
        {
            if (MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15LL)) == 1)
            {
                if ((unsigned int)MemoryCompare(*(_QWORD *)pEntry, (char *)(48 * EntryIndex + pTargetTable + 26), 0x10u))
                {
                    *(_BYTE *)(pEntry + 17) = 1;
                    if (*(_BYTE *)(pEntry + 16) == 0)
                    {
                        for (ByteIndex = 0; ByteIndex < 0x10; ByteIndex++)
                        {
                            if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + ByteIndex)))
                                break;
                        }
                        if (ByteIndex && ReturnFalseStub() == 1)
                            *(_QWORD *)(pEntry + 8) = SavedOriginalAddr;
                    }
                }
            }
        }
        pEntry += 48;
    }
    return 1;
}
char ResolveContextTableMemory(__int64 ContextTable)
{
    _BYTE *pEntry = (_BYTE *)(ContextTable + 8);
    __int64 EntryCount = 29;
    __int64 pCurrentEntry = ContextTable + 8;
    unsigned int LoopIndex = 0;
    unsigned int i;
    __int64 ContextValue = 0;

    do
    {
        if (*(_QWORD *)pCurrentEntry && *(_QWORD *)pCurrentEntry != *(_QWORD *)(pCurrentEntry + 8))
            *(_BYTE *)(pCurrentEntry + 16) = 1;
        pCurrentEntry += 64;
        EntryCount--;
    } while (EntryCount);

    for (LoopIndex = 0; LoopIndex <= 0x1C; LoopIndex++)
    {
        if (*(_QWORD *)pEntry)
        {
            if (MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15LL)) == 1)
            {
                unsigned __int64 EntryOffset = (unsigned __int64)LoopIndex << 6;
                if ((unsigned int)MemoryCompare(*(_QWORD *)pEntry, (char *)(EntryOffset + ContextTable + 26), 0x10u))
                {
                    pEntry[17] = 1;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563
                        && MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 31LL)) == 1
                        && ScanPESectionPatterns((_BYTE *)(EntryOffset + ContextTable + 26), *(char **)pEntry, 32, 1))
                    {
                        pEntry[17] = 0;
                    }
                    if (pEntry[17] == 1 && !pEntry[16])
                    {
                        for (i = 0; i < 0x10; i++)
                        {
                            if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + i)))
                                break;
                        }
                        if (i && ReturnFalseStub() == 1)
                            *((_QWORD *)pEntry + 1) = ContextValue;
                    }
                }
            }
        }
        pEntry += 64;
    }
    return 1;
}
char ReadKernelExportDirFile(_QWORD *OutBuffer, unsigned int *OutSize)
{
    char Result = 0;
    size_t MaxCount;
    void *Src;
    _DWORD EncodedPath[20];

    EncodedPath[0] = 5439580;  EncodedPath[1] = 7536761;
    EncodedPath[2] = 6619252;  EncodedPath[3] = 5374061;
    EncodedPath[4] = 7274607;  EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971;  EncodedPath[7] = 7602291;
    EncodedPath[8] = 7143525;  EncodedPath[9] = 3276851;
    EncodedPath[10] = 6553692; EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254; EncodedPath[13] = 7536754;
    EncodedPath[14] = 7209052; EncodedPath[15] = 6881380;
    EncodedPath[16] = 3014771; EncodedPath[17] = 7929971;
    EncodedPath[18] = 115;     EncodedPath[19] = 0;

    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}
char ReadSystemDriverFile(_QWORD *OutBuffer, unsigned int *OutSize)
{
    char Result = 0;
    size_t MaxCount;
    void *Src;
    _DWORD EncodedPath[20];

    EncodedPath[0] = 5439580;  EncodedPath[1] = 7536761;
    EncodedPath[2] = 6619252;  EncodedPath[3] = 5374061;
    EncodedPath[4] = 7274607;  EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971;  EncodedPath[7] = 7602291;
    EncodedPath[8] = 7143525;  EncodedPath[9] = 3276851;
    EncodedPath[10] = 6553692; EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254; EncodedPath[13] = 7536754;
    EncodedPath[14] = 7602268; EncodedPath[15] = 6881380;
    EncodedPath[16] = 7536686; EncodedPath[17] = 7536761;
    EncodedPath[18] = 0;       EncodedPath[19] = 0;

    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}
void InitKernelDataSectionTable(void)
{
    unsigned int FileSize = 0;
    void *pFileBuffer = NULL;

    if (ReadKernelExportDirFile((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (!GtRead(GtEprocessExtField13))
            FindNdisGetVersionExport((__int64)pFileBuffer, FileSize);
        if (!(unsigned int)GtRead(GtEprocessExtField14))
            FindNdisDeregisterProtocolExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField16))
            ScanTextSectionPattern((__int64)pFileBuffer, FileSize);
        if (!(unsigned int)GtRead(GtEprocessExtField17))
            FindNdisFRegisterFilterDriverExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField19))
            ScanPageSectionPattern((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField25))
            FindNdisMRegisterMiniportDriverExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField27))
            ScanInitSectionPattern((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField20))
            FindNdisIMInitializeDeviceInstanceEx((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField22))
            ParseNtKernelDataSections((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField28))
            FindNdisRegisterTdiCallBackExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField31))
            ScanDataSectionPattern((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField32))
            FindNdisIfRegisterProviderExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField36))
            FindNdisIfDeregisterProviderExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField35))
            FindNdisExportsBySectionScanV2((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField38))
            FindNdisIfRegisterInterfaceExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField42))
            FindNdisIfDeregisterInterfaceExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField41))
            FindNdisExportsBySectionScan((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField44))
            FindNdisMGetOffloadHandlersExport((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField47))
            ParseNtKernelDataOffsets((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessExtField56))
            FindKernelRdataSection((__int64)pFileBuffer, FileSize);
        ExFree(pFileBuffer);
    }
}
void InitTdiExportAndRelocTable(void)
{
    unsigned int FileSize = 0;
    void *pFileBuffer = NULL;

    if (ReadSystemDriverFile((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (!GtRead(GtEprocessField01 | 0x800))
            ParseKernelDataSectionRelocs((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessField02 | 0x800))
            FindTdiDeregisterPnpExport((__int64)pFileBuffer, FileSize);
        ExFree(pFileBuffer);
    }
}
char GetSsdtBaseAndSize(_QWORD *pOutBase, _DWORD *pOutSize)
{
    __int64 Base = 0;
    enum _GLOBAL_TABLE_INDEX SizeIndex;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
    {
        Base = GtRead(GtNtoskrnlModuleBase);
        SizeIndex = GtNtoskrnlImageSize;
    }
    else
    {
        Base = GtRead(GtEprocessField76);
        SizeIndex = GtEprocessField77;
    }
    *pOutBase = Base;
    *pOutSize = (_DWORD)GtRead(SizeIndex);
    if (*pOutBase)
        return *pOutSize != 0;
    return 0;
}
void BuildInitSsdtHookTable(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        BuildSsdtHookTableWin10();
    else
        BuildSsdtHookTableLegacy();
}
void BuildSsdtHookTargets2(void)
{
    char Result = 0;
    __int64 *pTargetTable = GtAlloc(GtEprocessModuleEntrySize | GtCallbackField50 | 0x400);
    __int64 SectionBase = GtRead(GtFsFilterExportTable);
    char *pFileBuffer;
    unsigned int FileSize = 0;
    unsigned int CompleteRva = 0;
    _WORD KernelName[8];
    char ExportName[24];

    if (SectionBase && ReadNtFileForSsdtTargets2((_QWORD *)&pFileBuffer, &FileSize))
    {
        strcpy((char *)KernelName, "ntoskrnl.exe");
        HIBYTE_LV(KernelName[6]) = 0;
        KernelName[7] = 0;
        strcpy(ExportName, "IofCompleteRequest");
        ExportName[19] = 0;
        if (ParsePESectionHeaders((__int64)pFileBuffer, FileSize, (__int64)KernelName, (unsigned __int8 *)ExportName, &CompleteRva) == 1)
            GtWrite(GtCallbackField38, SectionBase + CompleteRva);
        if (pTargetTable
            && ParseNtHeadersForSsdtTargets2((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, SectionBase, 0) == 1)
        {
            unsigned int *pRvaEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 29;
            do
            {
                __int64 TargetRva = *pRvaEntry;
                *(pRvaEntry - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= (int)FileSize)
                {
                    *(pRvaEntry - 1) = 1;
                    *(_OWORD *)(pRvaEntry + 3) = *(_OWORD *)&pFileBuffer[TargetRva];
                }
                pRvaEntry += 12;
                EntryCount--;
            } while (EntryCount);
            Result = 1;
            GtWrite(GtCallbackField37, 1);
        }
        ExFree(pFileBuffer);
        if (Result == 1)
            FillExportEntrySlot((__int64)pTargetTable);
    }
}
void BuildSsdtHookTargets3(void)
{
    char Result = 0;
    __int64 *pTargetTable = GtAlloc(GtFltUnregisterFilterOffset | GtDebugPortOffset | 0x400);
    unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    enum _GLOBAL_TABLE_INDEX BaseIndex = GtCallbackField40;
    char *pFileBuffer;
    unsigned int FileSize = 0;
    unsigned int FuncOffset = 0;
    _WORD KernelNameW[8];
    char FuncNameA[24];

    if (BuildNumber >= 0x1770)
        BaseIndex = GtCallbackField42;
    __int64 NtoskrnlBase = GtRead(BaseIndex);
    if (NtoskrnlBase && ReadNtoskrnlFileToBuffer3(&pFileBuffer, &FileSize))
    {
        strcpy((char *)KernelNameW, "ntoskrnl.exe");
        HIBYTE_LV(KernelNameW[6]) = 0;
        KernelNameW[7] = 0;
        strcpy(FuncNameA, "IofCompleteRequest");
        FuncNameA[19] = 0;
        if (ParsePESectionHeaders((__int64)pFileBuffer, FileSize, (__int64)KernelNameW, (unsigned __int8 *)FuncNameA, &FuncOffset) == 1)
            GtWrite(GtCallbackField45, NtoskrnlBase + FuncOffset);
        if (ParseAtaPortInitForHookTargets((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
        {
            unsigned int *pEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 29;
            do
            {
                __int64 FuncRva = *pEntry;
                *(pEntry - 1) = 0;
                if ((_DWORD)FuncRva && (int)FuncRva + 32 <= (int)FileSize)
                {
                    *(pEntry - 1) = 1;
                    *(_OWORD *)(pEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRva];
                    *(_OWORD *)(pEntry + 7) = *(_OWORD *)&pFileBuffer[FuncRva + 16];
                }
                pEntry += 12;
                EntryCount--;
            } while (EntryCount);
            Result = 1;
            GtWrite(GtCallbackField44, 1);
        }
        ExFree(pFileBuffer);
        if (Result == 1)
            FillExportEntrySlot((__int64)pTargetTable);
    }
}
void BuildSsdtHookTargets4(void)
{
    __int64 NtoskrnlBase = GtRead(GtCallbackField47);
    char *pFileBuffer;
    unsigned int FileSize = 0;
    unsigned int FuncOffset = 0;
    _WORD KernelNameW2[8];
    char FuncNameA2[24];

    if (NtoskrnlBase && ReadNtoskrnlFileToBuffer(&pFileBuffer, &FileSize))
    {
        HIBYTE_LV(KernelNameW2[6]) = 0;
        KernelNameW2[7] = 0;
        strcpy((char *)KernelNameW2, "ntoskrnl.exe");
        strcpy(FuncNameA2, "IofCompleteRequest");
        FuncNameA2[19] = 0;
        if (ParsePESectionHeaders((__int64)pFileBuffer, FileSize, (__int64)KernelNameW2, (unsigned __int8 *)FuncNameA2, &FuncOffset) == 1)
            GtWrite(GtCallbackField50, NtoskrnlBase + FuncOffset);
        __int64 *pTargetTable = GtAlloc(GtEprocessField108 | 0x1000);
        if (ParseNtHeadersForSsdtTargets((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
        {
            unsigned int *pEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 28;
            do
            {
                __int64 FuncRva = *pEntry;
                *(pEntry - 1) = 0;
                if ((_DWORD)FuncRva)
                {
                    if ((int)FuncRva + 16 <= (int)FileSize)
                    {
                        *(pEntry - 1) = 1;
                        *(_OWORD *)(pEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRva];
                    }
                }
                pEntry += 12;
                EntryCount--;
            } while (EntryCount);
            GtWrite(GtCallbackField49, 1);
        }
        ExFree(pFileBuffer);
    }
}
char BuildSsdtEntryTableLegacy(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    // 简单封装：调用 BuildInitSsdtHookTable 初始化，然后输出到用户缓冲区
    if (!GtRead(GtEprocessModuleListOffset | GtEprocessField23))
        BuildInitSsdtHookTable();
    __int64 HookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField23);
    unsigned int HookTableCount = (unsigned int)GtRead(GtEprocessModuleListOffset | GtEprocessField24);

    if (HookTableBase && (unsigned __int64)HookTableBase > (unsigned __int64)MmSystemRangeStart && HookTableCount
        && OutputBuffer && BufferSize >= 8 * (unsigned __int64)(HookTableCount - 1) + 16
        && (unsigned __int64)OutputBuffer < MmUserProbeAddress
        && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, BufferSize, 8u);
        memset(OutputBuffer, 0, BufferSize);
        OutputBuffer[1] = HookTableCount;
        *OutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
        for (unsigned int Index = 0; Index < HookTableCount; Index++)
            *(_QWORD *)&OutputBuffer[2 * Index + 2] = *(_QWORD *)(HookTableBase + 16LL * Index);
        return 1;
    }
    return 0;
}
char BuildSsdtEntryTableEx(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!GtRead(GtEprocessModuleListOffset | GtEprocessField25))
        BuildInitSsdtHookTable();
    __int64 HookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField25);
    unsigned int HookTableSize = (unsigned int)GtRead(GtEprocessModuleListOffset | GtEprocessField26);

    if (HookTableBase && HookTableSize > 8
        && (unsigned __int64)HookTableBase > (unsigned __int64)MmSystemRangeStart && HookTableSize < 0x1000)
    {
        unsigned int EntryCount = (HookTableSize - 8) >> 3;
        if (EntryCount && OutputBuffer && BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16
            && (unsigned __int64)OutputBuffer < MmUserProbeAddress
            && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress)
        {
            __int64 SsdtBase = TargetBase;
            unsigned int SsdtSize = TargetSize;
            if (HookTableBase > SsdtBase
                && HookTableBase < SsdtSize + SsdtBase
                && HookTableBase + HookTableSize < SsdtSize + SsdtBase)
            {
                ProbeForWrite(OutputBuffer, BufferSize, 8u);
                memset(OutputBuffer, 0, BufferSize);
                OutputBuffer[1] = EntryCount;
                *OutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
                for (unsigned int Index = 0; Index < EntryCount; Index++)
                    *(_QWORD *)&OutputBuffer[2 * Index + 2] = *(_QWORD *)(HookTableBase + 8LL * (Index + 1));
                return 1;
            }
        }
    }
    return 0;
}
char EnumSyscallTable7(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 SectionBase = OpenTcpIpDriverSection();
    if (SectionBase)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(SectionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(SectionBase + 96);
        return 1;
    }
    return 0;
}
char EnumShadowSyscallTable(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 SectionBase = OpenKbdClassDriverSection();
    if (SectionBase)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(SectionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(SectionBase + 96);
        return 1;
    }
    return 0;
}
char FillSyscallTableInfo(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    _QWORD *DiskDriverSection = GetDiskDriverSection();
    if (DiskDriverSection)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = DiskDriverSection + 14;
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(DiskDriverSection + 12);
        return 1;
    }
    return 0;
}
char EnumSyscallTable6(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 SectionBase = OpenMountMgrDriverSection();
    if (SectionBase)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(SectionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(SectionBase + 96);
        return 1;
    }
    return 0;
}
char InitSyscallExportEntryArray(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 DriverSection = BuildSyscallDriverPath();
    if (DriverSection)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(DriverSection + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(DriverSection + 96);
        return 1;
    }
    return 0;
}
char CopySyscallTable7(__int64 pSourceTable)
{
    char Result = 0;
    __int64 *pDestTable = GtAlloc(GtEprocessModuleEntrySize | GtCallbackField50 | 0x400);
    __int64 EntryCount = 29;
    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;

    do
    {
        *(_DWORD *)&pSrcEntry[DeltaOffset] = *(_DWORD *)pSrcEntry;
        if (*(_DWORD *)pSrcEntry && *((_DWORD *)pSrcEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)&pSrcEntry[DeltaOffset + 22] = *(_OWORD *)(pSrcEntry + 12);
        }
        else
        {
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = 0;
        }
        pSrcEntry += 48;
        EntryCount--;
    } while (EntryCount);
    return Result;
}
char CopyShadowSyscallTable(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}
char CopySyscallTableEntryArray(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}
char CopySyscallExportEntries(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}
char DuplicateSyscallTableEntries(__int64 pSourceTable)
{
    char Result = 0;
    __int64 *pDestTable = GtAlloc(GtEprocessModuleEntrySize | GtCallbackField50 | 0x400);
    __int64 EntryCount = 29;
    char *pSrcEntry = (char *)pDestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)pDestTable;

    do
    {
        *(_DWORD *)&pSrcEntry[DeltaOffset] = *(_DWORD *)pSrcEntry;
        if (*(_DWORD *)pSrcEntry && *((_DWORD *)pSrcEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&pSrcEntry[DeltaOffset + 4] = *(_QWORD *)(pSrcEntry + 4);
            *(_OWORD *)&pSrcEntry[DeltaOffset + 22] = *(_OWORD *)(pSrcEntry + 12);
        }
        pSrcEntry += 48;
        EntryCount--;
    } while (EntryCount);
    return Result;
}
char DuplicateSyscallTableOutput(__int64 pSourceTable)
{
    return DuplicateSyscallTableEntries(pSourceTable);
}
char CopyWin32kServiceTable(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 SectionBase = OpenWin32kSection();
    if (SectionBase)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(SectionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(SectionBase + 96);
        return 1;
    }
    return 0;
}
char CopySyscallTableEntries(__int64 pOutputBuffer)
{
    unsigned int Index = 0;
    __int64 SectionBase = OpenWdfDriverSection();
    if (SectionBase)
    {
        __int64 pEntry = pOutputBuffer;
        _QWORD *pFuncPtr = (_QWORD *)(SectionBase + 112);
        do
        {
            *(_DWORD *)pEntry = Index++;
            *(_QWORD *)(pEntry + 16) = *pFuncPtr;
            pEntry += 48;
            pFuncPtr++;
        } while (Index <= 0x1B);
        *(_DWORD *)(pOutputBuffer + 1344) = Index;
        *(_QWORD *)(pOutputBuffer + 1360) = *(_QWORD *)(SectionBase + 96);
        return 1;
    }
    return 0;
}
char CopySyscallTableToBuffer(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}
char ValidateSyscallHookEntries(__int64 pTargetTable)
{
    return ValidateSsdtHookTargetTable(pTargetTable);
}
char ValidateSyscallTableEntries(__int64 pTargetTable)
{
    return ValidateSsdtHookTargetTable2(pTargetTable);
}
// ParseStorPortExportDir — 解析 StorPort 驱动导出目录
// 对应原始驱动 0x140050578（398 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写。
// 【GT 依据】调用序：GtAlloc(4388=0x1124) 取导出表 → 读 0x914（构建号）；
//   构建号 >= 0x1770 用 0x309（GtCallbackField59）否则用 0x307（GtCallbackField57）
//   作为 storport.sys 基址槽 → 读该槽得 v4；命中写 0x30C（v4 + RVA）与
//   0x30B（就绪位 1）。
// 【逻辑】1) ReadDiskPortDriverFile 读 storport.sys 到 v9/v8；
//   2) ParsePESectionHeaders(v9, v8, "ntoskrnl.exe", "IofCompleteRequest", &v10)==1
//      → GtWrite(0x30C, v4 + v10)；
//   3) ParseStorPortExportSections(v9,v8,v1)==1 且 ParseNtExportDir(v9,v8,v4,0)==1
//      → 循环 29 项：v7 = v1[12i+1]（表项 +4 的 RVA），清 v1[12i+0]=0，
//        若 v7 非零且 (int)v7+16 <= v8 → 置 v1[12i+0]=1 并复制文件内 16 字节
//        节头到 v1[12i+3]；随后置 v0=1、写就绪位 0x30B=1；
//   4) ExFree(v9)；若 v0==1 → FillExportEntrySlot(v1)。
void ParseStorPortExportDir(void)
{
    char  IsReady = 0;
    __int64 *pExportTable;
    ULONG BuildNumber;
    GLOBAL_TABLE_INDEX BaseIndex;
    __int64 StorportBase;
    ULONG64 FileBuffer = 0;      // ReadDiskPortDriverFile 输出（文件缓冲）
    unsigned int FileSize = 0;
    unsigned int SectionOffset = 0;
    unsigned int *pEntry;
    __int64 EntryCount;
    __int64 EntryRva;
    _WORD NtName[16];
    char FuncName[24];

    pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1124);           // 0x1400505B1（4388）

    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);            // 0x1400505B4（0x914）
    BaseIndex = (GLOBAL_TABLE_INDEX)GtCallbackField57;            // 0x1400505B9（0x307）
    if (BuildNumber >= 0x1770)                                    // 0x1400505C3
        BaseIndex = (GLOBAL_TABLE_INDEX)GtCallbackField59;        // 0x1400505C5（0x309）

    StorportBase = (__int64)GtRead(BaseIndex);                    // 0x1400505CF
    if (!StorportBase || !ReadDiskPortDriverFile(&FileBuffer, &FileSize))  // 0x1400505E3
        return;

    strcpy((char *)NtName, "ntoskrnl.exe");                       // 0x140050608
    ((char *)NtName)[12] = 0;                                     // 0x140050616（HIBYTE(v11[6])）
    NtName[7] = 0;                                                // 0x140050616（v11[7]）

    strcpy(FuncName, "IofCompleteRequest");                       // 0x14005061E
    FuncName[19] = 0;                                             // 0x14005063A

    if ((unsigned int)ParsePESectionHeaders((__int64)FileBuffer, FileSize,
                                            (__int64)NtName, (unsigned __int8 *)FuncName,
                                            &SectionOffset) == 1)  // 0x140050648
        GtWrite(GtCallbackField62, StorportBase + SectionOffset);  // 0x140050655（0x30C）

    if ((unsigned int)ParseStorPortExportSections((__int64)FileBuffer, FileSize,
                                                  (__int64)pExportTable) == 1
        && (unsigned int)ParseNtExportDir((PUCHAR)FileBuffer, FileSize,
                                          (ULONG64)StorportBase, 0) == 1)  // 0x140050681
    {
        pEntry = (unsigned int *)pExportTable + 1;                // 0x140050683
        for (EntryCount = 29; EntryCount; --EntryCount)           // 0x140050687
        {
            EntryRva = *pEntry;                                   // 0x14005068D（表项 +4）
            *(pEntry - 1) = 0;                                    // 0x14005068F（表项 +0 命中位）
            if ((_DWORD)EntryRva && (int)EntryRva + 16 <= (int)FileSize)  // 0x14005069C
            {
                *(pEntry - 1) = 1;                                // 0x14005069E
                *(_OWORD *)(pEntry + 3) = *(_OWORD *)(FileBuffer + EntryRva);  // 0x1400506AD（表项 +16）
            }
            pEntry += 12;                                         // 0x1400506B2（每项 0x30 = 12 个 DWORD）
        }
        IsReady = 1;                                              // 0x1400506C4
        GtWrite(GtCallbackField61, 1);                            // 0x1400506C6（0x30B 就绪位）
    }

    ExFree((void *)FileBuffer);                                   // 0x1400506CF
    if (IsReady == 1)                                             // 0x1400506D7
        FillExportEntrySlot((__int64)pExportTable);                // 0x1400506DC
}
// ParseSyscallFileExportDir — 解析系统调用文件导出目录（补全空壳）
// 对应原始驱动 0x14003DBE0（231 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（44 行伪代码），按伪代码实现。
// 【逻辑】GtAlloc(GT 0x63F8) 取导出表 → GtRead(GT 0x311) 取 ntoskrnl 基址；
//   ReadSyscallDriverFile 读 mouclass.sys；
//   ParseSyscallFileExportSections 填表 → ParseNtExportDir 修正重定位；
//   随后循环 28 项填 {+0=命中, +4=RVA, +8=地址, +0x10=16 字节节头}；
//   成功则置就绪位(GT 0x319) 并 FillExportEntrySlot。
char ParseSyscallFileExportDir(void)
{
    char IsReady = 0;
    __int64 *pExportTable;
    __int64 NtoskrnlBase;
    unsigned int *pSlot;
    __int64 EntryCount;
    __int64 RvaValue;
    unsigned int FileSize = 0;
    char *pFileBuffer = 0;

    pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0x18F8);   // 实测立即数（伪代码显示为复合 GT 名）
    NtoskrnlBase = GtRead(GtCallbackField70);
    if (NtoskrnlBase && ReadSyscallDriverFile((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseSyscallFileExportSections((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, (ULONG64)NtoskrnlBase, 0) == 1)
        {
            pSlot = (unsigned int *)pExportTable + 1;
            EntryCount = 28;
            do
            {
                RvaValue = *pSlot;
                *(pSlot - 1) = 0;
                if ((_DWORD)RvaValue && (int)RvaValue + 16 <= (int)FileSize)
                {
                    *(pSlot - 1) = 1;
                    *(_OWORD *)(pSlot + 3) = *(_OWORD *)&pFileBuffer[RvaValue];
                }
                pSlot += 12;
                --EntryCount;
            }
            while (EntryCount);
            IsReady = 1;
            GtWrite(GtCallbackField72, 1);
        }
        ExFree(pFileBuffer);
        if (IsReady == 1)
            FillExportEntrySlot((__int64)pExportTable);
    }
    return 1;
}
// BuildSyscallExportTable — 构建系统调用导出表（补全空壳）
// 对应原始驱动 0x140046AF4（211 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 ——
//   **静默失败型**：只置就绪位就报成功，调用方据此认为导出表已填充，实际表内容为空。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（40 行伪代码），按伪代码实现。
// 【逻辑】GtRead(GT 0x3DA) 取 ntoskrnl 基址 → ReadNtFileSyscall 读 nsiproxy.sys；
//   GtAlloc(GT 0x4466) 取导出表 → DispatchFindExportTableOffset 找导出表偏移
//   → ParseNtExportDir 修正重定位；
//   随后循环 28 项（步长 0x30）：取 +4 处 RVA，清零 +0，
//   若 RVA 有效且 RVA+16 <= 文件大小，则置 +0=1 并从文件缓冲拷 16 字节节头到 +0x10；
//   最后 GtWrite(GT 0x4280, 1) 置就绪位。
char BuildSyscallExportTable(void)
{
    __int64 NtoskrnlBase;
    __int64 *pExportTable;
    unsigned int *pIndexPtr;
    __int64 EntryCount;
    __int64 TargetRva;
    unsigned int FileSize = 0;
    char *pRawData = 0;

    NtoskrnlBase = GtRead(GtCallbackField78);
    if (NtoskrnlBase && ReadNtFileSyscall((_QWORD *)&pRawData, &FileSize))
    {
        pExportTable = GtAlloc(GtNtQueryVirtualMemoryFunc | 0x1100);
        if (DispatchFindExportTableOffset((__int64)pRawData, FileSize, (__int64)pExportTable) == 1
            && ParseNtExportDir((PUCHAR)pRawData, FileSize, (ULONG64)NtoskrnlBase, 0) == 1)
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
                    *(_OWORD *)(pIndexPtr + 3) = *(_OWORD *)&pRawData[TargetRva];
                }
                pIndexPtr += 12;
                --EntryCount;
            }
            while (EntryCount);
            GtWrite(GtCallbackField80, 1);
        }
        ExFree(pRawData);
    }
    return 1;
}
// InitShadowSyscallExportTable — 初始化 Shadow SSDT 导出表（补全空壳）
// 对应原始驱动 0x14003CF4C（231 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（44 行伪代码），按伪代码实现。
// 【逻辑】GtAlloc(GT 0xE60) 取导出表 → GtRead(GT 0x2D8) 取 ntoskrnl 基址；
//   ReadKbdClassSysFile 读 kbdclass.sys；
//   ParseShadowSyscallExportSections 填表 → ParseNtExportDir 修正重定位；
//   循环 28 项填 {+0=命中, +4=RVA, +8=地址, +0x10=16 字节节头}；
//   成功置就绪位(GT 0x2DA) 并 FillExportEntrySlot。
char InitShadowSyscallExportTable(void)
{
    char IsReady = 0;
    __int64 *pExportTable;
    __int64 NtoskrnlBase;
    unsigned int *pSlot;
    __int64 EntryCount;
    __int64 RvaValue;
    unsigned int FileSize = 0;
    char *pFileBuffer = 0;

    pExportTable = GtAlloc((GLOBAL_TABLE_INDEX)0xE60);
    NtoskrnlBase = GtRead(GtCallbackField13);
    if (NtoskrnlBase && ReadKbdClassSysFile((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseShadowSyscallExportSections((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, (ULONG64)NtoskrnlBase, 0) == 1)
        {
            pSlot = (unsigned int *)pExportTable + 1;
            EntryCount = 28;
            do
            {
                RvaValue = *pSlot;
                *(pSlot - 1) = 0;
                if ((_DWORD)RvaValue && (int)RvaValue + 16 <= (int)FileSize)
                {
                    *(pSlot - 1) = 1;
                    *(_OWORD *)(pSlot + 3) = *(_OWORD *)&pFileBuffer[RvaValue];
                }
                pSlot += 12;
                --EntryCount;
            }
            while (EntryCount);
            IsReady = 1;
            GtWrite(GtCallbackField15, 1);
        }
        ExFree(pFileBuffer);
        if (IsReady == 1)
            FillExportEntrySlot((__int64)pExportTable);
    }
    return 1;
}
// InitWin32kSyscallTable — 初始化 Win32k 系统调用表（补全空壳）
// 对应原始驱动 0x140053F04（231 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（44 行伪代码），按伪代码实现。
// 【逻辑】GtAlloc(GT 0x1A54) 取表 → GtRead(GT 0x322) 取 win32k 节基址；
//   ReadWin32kDriverFile 读 win32k 驱动文件；
//   ParseWin32kSyscallStubs 填表 → ParseNtExportDir 修正重定位；
//   循环 28 项填 {+0=命中, +4=RVA, +8=地址, +0x10=16 字节节头}；
//   成功置就绪位(GT 0x324) 并 FillExportEntrySlot。
char InitWin32kSyscallTable(void)
{
    char Result = 0;
    __int64 *pSyscallTable;
    __int64 SectionBase;
    unsigned int *pExportEntry;
    __int64 EntryCount;
    __int64 FuncRva;
    unsigned int FileSize = 0;
    char *pFileBuffer = 0;

    pSyscallTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1A54);
    SectionBase = GtRead(GtCallbackField81);
    if (SectionBase && ReadWin32kDriverFile((_QWORD *)&pFileBuffer, &FileSize))
    {
        if (ParseWin32kSyscallStubs((__int64)pFileBuffer, FileSize, (__int64)pSyscallTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, (ULONG64)SectionBase, 0) == 1)
        {
            pExportEntry = (unsigned int *)pSyscallTable + 1;
            EntryCount = 28;
            do
            {
                FuncRva = *pExportEntry;
                *(pExportEntry - 1) = 0;
                if ((_DWORD)FuncRva && (int)FuncRva + 16 <= (int)FileSize)
                {
                    *(pExportEntry - 1) = 1;
                    *(_OWORD *)(pExportEntry + 3) = *(_OWORD *)&pFileBuffer[FuncRva];
                }
                pExportEntry += 12;
                --EntryCount;
            }
            while (EntryCount);
            Result = 1;
            GtWrite(GtCallbackField83, 1);
        }
        ExFree(pFileBuffer);
        if (Result == 1)
            FillExportEntrySlot((__int64)pSyscallTable);
    }
    return 1;
}
// ParseSyscallTableExportDir — 解析系统调用表导出目录（补全空壳）
// 对应原始驱动 0x1400865C8（200 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（30 行伪代码），按伪代码实现。
// 【逻辑】GtRead(GT 0x8AE) 取 WDF 库模块基址；非 0 且 ReadWdfLibraryModule
//   成功读入文件后，依次调用 7 个解析/收集函数：
//     FindSyscallTableDescriptor → BuildExportSectionMapping
//     → ParseSyscallTableDataSection → ParseSyscallTableSections
//     → 若 ParseNtExportDir 成功，再调
//       CollectSyscallEntries4 → CollectTwoSyscallTables → CollectSyscallExportEntries
//   最后 ExFree 文件缓冲。
// 【说明】本函数是"系统调用表导出族"的顶层枢纽，此前因 7 个被调用方全部缺失
//   而无法实现；本轮补齐后得以忠实转写。
void ParseSyscallTableExportDir(void)
{
    __int64 WdfModuleBase;
    unsigned int FileSize = 0;
    void *pFileBuffer = 0;

    WdfModuleBase = GtRead((GLOBAL_TABLE_INDEX)0x8AE);
    if (WdfModuleBase && ReadWdfLibraryModule((_QWORD *)&pFileBuffer, &FileSize))
    {
        FindSyscallTableDescriptor((__int64)pFileBuffer, FileSize, WdfModuleBase);
        BuildExportSectionMapping((__int64)pFileBuffer, FileSize);
        ParseSyscallTableDataSection((__int64)pFileBuffer, FileSize, WdfModuleBase);
        ParseSyscallTableSections((__int64)pFileBuffer, FileSize, WdfModuleBase);
        if (ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, (ULONG64)WdfModuleBase, 0) == 1)
        {
            CollectSyscallEntries4((__int64)pFileBuffer, FileSize, WdfModuleBase);
            CollectTwoSyscallTables((__int64)pFileBuffer, FileSize, WdfModuleBase);
            CollectSyscallExportEntries((__int64)pFileBuffer, FileSize, WdfModuleBase);
        }
        ExFree(pFileBuffer);
    }
}
// InitDiskQueryExportTable — 初始化磁盘查询导出表（补全空壳）
// 对应原始驱动 0x140048B08（439 字节）
// 【⚠ 修正记录 2026-10-08】原为 `GtWrite(就绪位,1); return 1;` 空壳 —— 静默失败型。
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（80 行伪代码），按伪代码实现。
// 【逻辑】GtRead(GT 0x192) 取磁盘驱动基址 → GtAlloc(GT 0x1B02) 取导出表；
//   ReadNtFileDiskInfo 读磁盘驱动文件；
//   按构建号 0x1770 分两路：
//     >= 0x1770 → ParseNtSectionHeaders2(fb, size, base, table)（Win8+ 路径）
//     <  0x1770 → 用 ParsePESectionHeaders 查 ntoskrnl.exe 的 IofCompleteRequest
//                 写到 GT 0x2B1，再调 ParseExportDirForDiskInfo（Win7 路径）
//   两条路径均须 ParseNtExportDir 成功，然后循环 28 项填
//   {+0=命中, +4=RVA, +8=地址, +0x10=16 字节节头}，并置就绪位(GT 0x191)；
//   最后（构建号 >= 0x1770 且就绪位已置时）FillExportEntrySlot。
char InitDiskQueryExportTable(void)
{
    __int64 DiskImageBase;
    __int64 *ExportTablePtr;
    __int64 ExportTable;
    char ParseResult;
    unsigned int *EntryPtr;
    __int64 EntryCount;
    __int64 FuncRva;
    unsigned int FileSize = 0;
    char *FileBuffer = 0;
    unsigned int FuncAddr = 0;

    // 【修正 2026-10-16】原始 0x140048B2B 为 `mov ecx,192h; call GtRead`（GT[0x192]=402）。
    //   原写 `GtEprocessField136 | 0x100`：该宏被重映射为 GtObCallbackEntry2(0x188)，
    //   或上 0x100 仍是 392 ≠ 402，属真实取错槽。
    DiskImageBase = GtRead(GtDiskImageBase);
    ExportTablePtr = GtAlloc((GLOBAL_TABLE_INDEX)0x1B02);
    ExportTable = (__int64)ExportTablePtr;
    if (!DiskImageBase || !ExportTablePtr)
        return 0;

    if (ReadNtFileDiskInfo((void **)&FileBuffer, &FileSize))
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            ParseResult = ParseNtSectionHeaders2((__int64)FileBuffer, FileSize, DiskImageBase, ExportTable);
        }
        else
        {
            WCHAR ModuleName[16];
            char FuncName[24];
            wcscpy(ModuleName, L"ntoskrnl.exe");
            strcpy(FuncName, "IofCompleteRequest");
            if (ParsePESectionHeaders((__int64)FileBuffer, FileSize, (__int64)ModuleName,
                                      (unsigned __int8 *)FuncName, &FuncAddr) == 1)
                GtWrite((GLOBAL_TABLE_INDEX)0x2B1, DiskImageBase + FuncAddr);
            ParseResult = ParseExportDirForDiskInfo((__int64)FileBuffer, FileSize, DiskImageBase, ExportTable);
        }
        if (ParseResult == 1 &&
            ParseNtExportDir((PUCHAR)FileBuffer, FileSize, (ULONG64)DiskImageBase, 0) == 1)
        {
            EntryPtr = (unsigned int *)(ExportTable + 4);
            EntryCount = 28;
            do
            {
                FuncRva = *EntryPtr;
                *(EntryPtr - 1) = 0;
                if ((_DWORD)FuncRva && (int)FuncRva + 16 <= (int)FileSize)
                {
                    *(EntryPtr - 1) = 1;
                    *(_OWORD *)(EntryPtr + 3) = *(_OWORD *)&FileBuffer[FuncRva];
                }
                EntryPtr += 12;
                --EntryCount;
            }
            while (EntryCount);
            GtWrite((GLOBAL_TABLE_INDEX)0x191, 1);
        }
        ExFree(FileBuffer);
    }
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        if ((unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x191))
            return (char)FillExportEntrySlot(ExportTable);
    }
    return 0;
}
char ParsePESectionHeaders(__int64 PeBase, unsigned int PeSize, __int64 SectionName, unsigned __int8 *NameToMatch, unsigned int *OutOffset)
{
    __int64 PeHeaderRva = *(int *)(PeBase + 60);
    unsigned int ImageSize = PeSize;
    char Result = 0;
    unsigned int SectionTableRva = *(unsigned int *)(PeHeaderRva + PeBase + 144);
    unsigned int SectionCount = *(unsigned int *)(PeHeaderRva + PeBase + 148);

    if (SectionTableRva < ImageSize
        && SectionTableRva + 20 < ImageSize
        && SectionCount < ImageSize
        && SectionCount + SectionTableRva < ImageSize)
    {
        unsigned int *SectionEntry = (unsigned int *)(SectionTableRva + PeBase);
        int Remaining = (int)(ImageSize - SectionTableRva);

        // 遍历节表，查找名称匹配的节
        while (Remaining >= 0x14)
        {
            __int64 Entry4 = SectionEntry[4];
            if (!Entry4 || (unsigned int)Entry4 >= ImageSize || Entry4 + 8 > ImageSize)
                return Result;
            __int64 Entry3 = SectionEntry[3];
            if ((unsigned int)Entry3 > ImageSize)
                return Result;
            if (StringCompareCaseInsensitiveV2(SectionName, Entry3 + PeBase) == 0)
                break;
            SectionEntry += 5;
            Remaining -= 0x14;
        }
        if (Remaining < 0x14)
            return Result;

        // 确定数据列表基址：使用原始数据指针或虚拟地址
        __int64 RawDataRva = *SectionEntry;
        char IsLinkedSection = 0;
        __int64 *pDataList;
        int DataListRemaining = 0;

        if (RawDataRva && (unsigned int)RawDataRva < ImageSize && RawDataRva + 8 <= ImageSize)
        {
            pDataList = (__int64 *)(RawDataRva + PeBase);
            IsLinkedSection = 1;
            DataListRemaining = (int)(ImageSize - (unsigned int)RawDataRva);
        }
        else
        {
            __int64 VirtualRva = SectionEntry[4];
            pDataList = (__int64 *)(VirtualRva + PeBase);
            IsLinkedSection = 0;
            DataListRemaining = (int)(ImageSize - (unsigned int)VirtualRva);
        }

        // 遍历数据列表，查找名称匹配的条目
        while (1)
        {
            if (DataListRemaining < 8)
                return Result;
            __int64 EntryValue = *pDataList;
            if (!EntryValue)
                return Result;
            if (EntryValue > 0
                && (ULONG64)EntryValue < ImageSize
                && (ULONG64)EntryValue + 4 < ImageSize)
            {
                // 逐字节比较 NameToMatch 与 EntryValue + PeBase + 2 处的字符串
                unsigned __int8 *pCmp = NameToMatch;
                __int64 Delta = EntryValue + PeBase + 2 - (__int64)NameToMatch;
                int CmpResult = 0;
                unsigned __int8 Ch;
                do
                {
                    Ch = pCmp[Delta];
                    CmpResult = *pCmp - Ch;
                    if (CmpResult)
                        break;
                    ++pCmp;
                } while (Ch);
                if (!CmpResult)
                    break;
            }
            ++pDataList;
            DataListRemaining -= 8;
        }

        if (!IsLinkedSection)
        {
            *OutOffset = (unsigned int)((__int64)pDataList - PeBase);
            return 1;
        }
        else
        {
            unsigned int AdjOffset = (unsigned int)((__int64)pDataList - PeBase)
                + SectionEntry[4] - (unsigned int)RawDataRva;
            if (AdjOffset
                && AdjOffset < ImageSize
                && (unsigned __int64)AdjOffset + 8 <= ImageSize)
            {
                *OutOffset = AdjOffset;
                return 1;
            }
        }
    }
    return Result;
}
__int64 BuildExportIndexTable(
    __int64 PeBase,
    unsigned int PeSize,
    _BYTE *OutTable,
    unsigned int MaxEntries,
    unsigned char (__fastcall *FilterFunc)(__int64))
{
    unsigned int EntryCount = 0;

    // 清零输出表（每条目 12 字节，仅清标志字节）
    if (MaxEntries)
    {
        for (unsigned int i = 0; i < MaxEntries; i++)
            OutTable[12 * i] = 0;
    }

    /* 【⚠ 重大修正 2026-10-16】原实现把 IMAGE_EXPORT_DIRECTORY 的字段整体读错位了一步：
         把 +0x20(AddressOfNames) 当作"序数表"、把 +0x24(AddressOfNameOrdinals) 当作"名字表"，
         于是对**函数机器码**求哈希（应为对**函数名**求哈希），写入的偏移值也是错的。
       结果是索引表与 InitSyscallNumberTable 预计算的"名字哈希"永不匹配 →
       BuildHookTable 填不出 GT[0x4158+1] 等 rva 槽（实测 GT[0x4159]=0，而原始为 0x66EDC0）→
       FindNtOpenThreadTargetWin8 立即返回 0 → InitAllHookSubsystems 置 Success=0 → sc start 错误 31。
       下列偏移均按原始 sub_140005610 反汇编逐条核对：
         +0x18 NumberOfNames        +0x14 NumberOfFunctions
         +0x1C AddressOfFunctions   +0x20 AddressOfNames   +0x24 AddressOfNameOrdinals
       循环语义（原始）：遍历名字表取 NameRva → 由序数表取 OrdinalIndex →
       AddressOfFunctions[OrdinalIndex] 得函数 RVA → 对名字串求哈希 →
       条目 = {1, hash(名字), 函数 RVA}。 */
    __int64 PeHeader = *(int *)(PeBase + 60);
    unsigned int ExportDirRva = *(unsigned int *)(PeHeader + PeBase + 136);   // 0x88
    unsigned int ExportDirSize = *(unsigned int *)(PeHeader + PeBase + 140);  // 0x8C
    unsigned int ExportDirEnd = ExportDirRva + ExportDirSize;

    if (ExportDirRva < PeSize && ExportDirRva + 40 < PeSize
        && ExportDirSize < PeSize && ExportDirEnd < PeSize)
    {
        unsigned int NumberOfNames = *(unsigned int *)(ExportDirRva + PeBase + 0x18);
        unsigned int NumberOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 0x14);

        if (MaxEntries == NumberOfNames)
        {
            unsigned int AddressOfNames = *(unsigned int *)(ExportDirRva + PeBase + 0x20);
            if (AddressOfNames >= ExportDirRva)
            {
                unsigned int AddressOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 0x1C);
                unsigned int AddressOfNameOrdinals = *(unsigned int *)(ExportDirRva + PeBase + 0x24);

                if (4 * NumberOfNames + AddressOfNames < ExportDirEnd
                    && 4 * NumberOfNames < ExportDirSize
                    && AddressOfNameOrdinals >= ExportDirRva
                    && AddressOfNameOrdinals + 2 * NumberOfNames < ExportDirEnd
                    && AddressOfFunctions >= ExportDirRva
                    && AddressOfFunctions + 4 * NumberOfFunctions < ExportDirEnd
                    && 4 * NumberOfFunctions < ExportDirSize)
                {
                    unsigned int *pNameTable = (unsigned int *)(PeBase + AddressOfNames);
                    unsigned __int16 *pOrdinalTable = (unsigned __int16 *)(PeBase + AddressOfNameOrdinals);
                    __int64 FuncTableBase = PeBase + AddressOfFunctions;
                    unsigned int Remaining = NumberOfNames;

                    if (Remaining)
                    {
                        do
                        {
                            unsigned int NameRva = *pNameTable;
                            if (NameRva >= ExportDirRva && NameRva < ExportDirEnd)
                            {
                                unsigned __int16 OrdinalIndex = *pOrdinalTable;
                                if (OrdinalIndex < NumberOfFunctions)
                                {
                                    unsigned int FuncRva = *(unsigned int *)(FuncTableBase + 4LL * OrdinalIndex);
                                    if (FuncRva < PeSize
                                        && (FuncRva < ExportDirRva || FuncRva >= ExportDirEnd))
                                    {
                                        char *pName = (char *)(PeBase + NameRva);
                                        if (!FilterFunc || FilterFunc((__int64)pName) == 1)
                                        {
                                            unsigned int HashValue = (unsigned int)Sha1HashToDword(pName);
                                            OutTable[12 * EntryCount] = 1;
                                            *(unsigned int *)&OutTable[12 * EntryCount + 4] = HashValue;
                                            *(unsigned int *)&OutTable[12 * EntryCount + 8] = FuncRva;
                                            EntryCount++;
                                        }
                                    }
                                }
                            }
                            pNameTable++;
                            pOrdinalTable++;
                        } while (--Remaining);
                    }
                }
            }
        }
    }
    return EntryCount;
}
__int64 ScanKernelModulePESections(void)
{
    __int64 ImageBase = GtRead(GtEprocessField22);
    unsigned int ImageSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int TargetOffset1 = (unsigned int)GtRead(GtKernelDataSectionScanTarget1);
    unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    unsigned int TargetValue = 0;

    if (BuildNumber >= 0x2800)
        TargetValue = (unsigned int)GtRead(GtKernelDataSectionScanTarget3);
    else
        TargetValue = (unsigned int)GtRead(GtKernelDataSectionScanTarget2);

    if (!ImageBase || !ImageSize || !TargetOffset1 || !TargetValue
        || TargetOffset1 >= ImageSize || !NtoskrnlBase)
        return 0;

    // 从 TargetOffset1 + ImageBase 开始扫描 ImageSize - TargetOffset1 字节
    unsigned int ScanBase = (unsigned int)ImageBase + TargetOffset1;
    unsigned int ScanSize = ImageSize - TargetOffset1;

    __int64 Context[9];
    _DWORD SectionEntry[72];
    InitPESectionReadContext(ScanBase, ScanSize, 2, 0, -1, 0, 0, (__int64)&Context);

    // 第一阶段：查找类型 0x558 节区，匹配目标偏移
    unsigned int i;
    for (i = 0; i < 0x100; i++)
    {
            *(ULONG64 *)((PUCHAR)&Context + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
            break;
        unsigned int EntryBase = SectionEntry[0];
        __int64 EntryTypePtr = Context[5];
        unsigned int CurrentEnd = EntryBase + (unsigned int)SectionEntry[10];
        Context[5] = EntryTypePtr + EntryBase;

        if (*(unsigned __int16 *)(EntryTypePtr + 6) == 0x558
            && (*(__int64 *)((char *)SectionEntry + 0x80) & 0x4000000) != 0
            && SectionEntry[10])
        {
            unsigned int Result = CurrentEnd - TargetOffset1;
            if (Result == TargetValue)
                break;
        }
    }

    // 第二阶段：查找类型 0x512 节区，写入内核数据节区偏移
    for (i = 0; i < 0x50; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
            break;
        unsigned int EntryBase = SectionEntry[0];
        __int64 EntryTypePtr = Context[5];
        unsigned int CurrentEnd = EntryBase + (unsigned int)SectionEntry[9];
        Context[5] = EntryTypePtr + EntryBase;

        if (*(unsigned __int16 *)(EntryTypePtr + 6) == 0x512
            && *(unsigned __int64 *)((char *)SectionEntry + 0x80) == 0x40000
            && SectionEntry[9])
        {
            unsigned int Result = CurrentEnd - TargetOffset1;
            if (Result && Result < ImageSize)
            {
                GtWrite(GtKernelDataField21, Result);
                GtWrite(GtKernelDataField22, NtoskrnlBase + Result);
                return 1;
            }
        }
    }

    return 0;
}
char FillExportEntrySlot(__int64 pOutputTable)
{
    char Result = 0;
    unsigned int KernelDataOffset = (unsigned int)GtRead(GtKernelDataField21);
    if (!KernelDataOffset)
    {
        ScanKernelModulePESections();
        KernelDataOffset = (unsigned int)GtRead(GtKernelDataField21);
    }
    __int64 KernelDataBase = GtRead(GtEprocessField66);
    unsigned int KernelDataSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    if (KernelDataOffset && KernelDataBase && KernelDataSize && NtoskrnlBase
        && KernelDataOffset + 32 <= KernelDataSize)
    {
        __int64 pEntry = pOutputTable + 4;
        __int64 EntryCount = 28;
        do
        {
            if (!*(unsigned int *)pEntry)
            {
                *((unsigned int *)pEntry - 1) = 1;
                *(unsigned int *)pEntry = KernelDataOffset;
                *(_QWORD *)(pEntry + 4) = KernelDataOffset + NtoskrnlBase;
                *(_OWORD *)(pEntry + 12) = *(_OWORD *)(KernelDataOffset + KernelDataBase);
                *(_OWORD *)(pEntry + 28) = *(_OWORD *)(KernelDataOffset + KernelDataBase + 16);
            }
            pEntry += 48;
            EntryCount--;
        } while (EntryCount);
        return 1;
    }
    return Result;
}
char BuildSsdtHookTableWin10(void)
{
    __int64 HalImageBase = GtRead(GtEprocessField22);
    unsigned int HalImageSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    __int64 NtoskrnlBaseCopy = NtoskrnlBase;
    if (HalImageBase && HalImageSize && NtoskrnlBase)
    {
        if (!GtRead(GtEprocessModuleListOffset | GtEprocessField23))
        {
            unsigned int HalExportEntryCount = (unsigned int)GtRead(GtTotalSize | GtEprocessField112 | 0x400);
            if (HalExportEntryCount)
                FindHalDataSectionOffset(HalImageBase, HalImageSize, HalExportEntryCount, NtoskrnlBaseCopy);
        }
        if (!GtRead(GtEprocessField96 | 0x800))
            FindHalInitSystemExport(HalImageBase, HalImageSize, NtoskrnlBaseCopy);
        NtoskrnlBase = GtRead(GtEprocessModuleListOffset | GtEprocessField25);
        if (!NtoskrnlBase)
            BuildHalExportTable(HalImageBase, HalImageSize, NtoskrnlBaseCopy);
    }
    return (char)NtoskrnlBase;
}
void BuildSsdtHookTableLegacy(void)
{
    __int64 NtoskrnlBase = GtRead(GtEprocessField76);
    if (NtoskrnlBase)
    {
        void *FileBuffer = NULL;
        unsigned int FileSize = 0;
        if (ReadNtFileForHookTable((_QWORD *)&FileBuffer, &FileSize))
        {
            if (!GtRead(GtEprocessModuleEntryCount | GtEprocessField22))
                FindHalInitializeProcessorExport((__int64)FileBuffer, FileSize);
            unsigned int HalExportEntryCount = (unsigned int)GtRead(GtEprocessModuleEntryCount | GtEprocessField22);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0
                && HalExportEntryCount
                && !GtRead(GtEprocessModuleListOffset | GtEprocessField23))
            {
                FindHalDataSectionOffset((__int64)FileBuffer, FileSize, HalExportEntryCount, NtoskrnlBase);
            }
            if (!GtRead(GtEprocessField96 | 0x800))
                FindHalInitSystemExport((__int64)FileBuffer, FileSize, NtoskrnlBase);
            if (!GtRead(GtEprocessModuleListOffset | GtEprocessField25))
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0xA28)
                    FindHalExportTableLegacy((__int64)FileBuffer, FileSize);
                else
                    BuildHalExportTable((__int64)FileBuffer, FileSize, NtoskrnlBase);
            }
            ExFree(FileBuffer);
        }
    }
}
char FindNdisDeregisterProtocolExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisDeregisterProtocol");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField14, (unsigned int)Value);
            GtWrite(GtEprocessExtField15, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisFRegisterFilterDriverExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisFRegisterFilterDriver");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField17, (unsigned int)Value);
            GtWrite(GtEprocessExtField18, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisIMInitializeDeviceInstanceEx(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        WORD NameBuf[20];
        strcpy((char *)NameBuf, "NdisIMInitializeDeviceInstanceEx");
        *((UCHAR *)&NameBuf[16] + 1) = 0;
        NameBuf[17] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField20, (unsigned int)Value);
            GtWrite(GtEprocessExtField21, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisIfDeregisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisIfDeregisterInterface");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField42, (unsigned int)Value);
            GtWrite(GtEprocessExtField43, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisIfDeregisterProviderExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisIfDeregisterProvider");
        *((UCHAR *)&NameBuf[12] + 1) = 0;
        NameBuf[13] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField36, (unsigned int)Value);
            GtWrite(GtEprocessExtField37, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
__int16 FindNdisExportsBySectionScan(__int64 ImageBase, unsigned int ImageSize)
{
    char Found = 0;
    unsigned int NdisOffset = (unsigned int)GtRead(GtEprocessExtField38);
    if (!NdisOffset)
    {
        FindNdisIfRegisterInterfaceExport(ImageBase, ImageSize);
        NdisOffset = (unsigned int)GtRead(GtEprocessExtField38);
    }
    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 SectionBaseCopy = SectionBase;
    if (SectionBase && NdisOffset && NdisOffset < ImageSize)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            PE_DECODE_CONTEXT ReadContext; __int64 CumulativeSize = 0;   // 拆开：前者为 0x48 字节解码上下文
            _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
            int FieldValue = 0, EntryField = 0, EntrySize = 0;
            __int64 SectionChar = 0, SectionAlignment = 0, EntryDataPtr = 0;
            unsigned int EntryCumulSize = 0;

            InitPESectionReadContext(ImageBase + NdisOffset, ImageSize - NdisOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            int LoopIndex = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                int SectionEnd = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1368)
                {
                    if (FieldValue)
                    {
                        unsigned int TargetRva = (unsigned int)(SectionEnd + FieldValue - ImageBase);
                        if (TargetRva && TargetRva < ImageSize)
                        {
                            NdisOffset = (unsigned int)(SectionEnd + FieldValue - ImageBase);
                            break;
                        }
                    }
                }
                if (++LoopIndex >= 0xA)
                    break;
            }
        }
        int VersionOffset = (GtRead(GtWindowsBuildNumber) == 16299) + 1;
        PE_DECODE_CONTEXT DecodeContext; __int64 v19b = 0;   // DecodeContext 为 0x48 字节解码上下文（原 __int64 仅 8 字节）
        _DWORD v20b[112];
        int v21b = 0, v23b = 0, v24b = 0;
        __int64 v22b = 0, v25b = 0, v27b = 0;
        unsigned int v26b = 0;

        InitPESectionReadContext(ImageBase + NdisOffset, ImageSize - NdisOffset, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        unsigned int InnerOffset = 0;
        int InnerLoop = 0;
        while (1)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, v20b))
                return 0;
            int InnerEnd = (int)(v26b + v19b);
            v19b += v26b;
            __int16 SectionType = *(_WORD *)(v27b + 6);
            if (SectionType == 1349)
                return 0;
            if (SectionType == 1298 && v25b == 0x40000 && v22b == 64)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x23F0 && v23b == 1
                    || (unsigned int)GtRead(GtWindowsBuildNumber) == 9600 && v23b == 5
                    || (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
                {
                    if (v19b + v24b - ImageBase && (int)v19b + v24b - (int)ImageBase < (int)ImageSize)
                        InnerOffset = (unsigned int)(v19b + v24b - ImageBase);
                }
            }
            __int16 SectionType2 = *(_WORD *)(v27b + 6);
            if (SectionType2 == 1368)
                goto LABEL_46;
            if ((unsigned __int16)(SectionType2 - 1139) <= 1u)
                break;
            if (Found == 1)
            {
                if (SectionType2 == 1296 && v25b == 0x40000 && v22b == 64)
                {
                    if (InnerEnd + v24b - ImageBase && (unsigned int)(InnerEnd + v24b - ImageBase) < ImageSize && !--VersionOffset)
                    {
                        GtWrite(GtEprocessExtField41, SectionBaseCopy + (unsigned int)(InnerEnd + v24b - ImageBase));
                        return 0;
                    }
                }
            }
LABEL_47:
            if (++InnerLoop >= 0xC8)
                return 0;
        }
        if (InnerOffset && !Found)
        {
            GtWrite(GtEprocessExtField40, SectionBaseCopy + InnerOffset);
            Found = 1;
        }
LABEL_46:
        InnerOffset = 0;
        goto LABEL_47;
    }
    return 0;
}
__int64 FindNdisExportsBySectionScanV2(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead(GtEprocessExtField32);
    if (!Found)
    {
        FindNdisIfRegisterProviderExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead(GtEprocessExtField32);
    }
    __int64 SectionBase = GtRead(GtEprocessExtField11);
    if (SectionBase && Found && Found < ImageSize)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        {
            PE_DECODE_CONTEXT DecodeContext; __int64 CumulativeSize2 = 0;   // DecodeContext 为 0x48 字节解码上下文
            _DWORD SectionInfo[112];
            __int64 CumulativeSize = 0, SectionChar = 0, EntrySize = 0;
            int RvaOffset = 0;
            unsigned int FieldValue = 0, EntryField = 0;

            InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
            char SectionBaseCopy = 0;
            int LoopIndex = 0;
            while (1)
            {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)SectionInfo + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                    return 0;
                int SectionEnd = (int)(EntryField + CumulativeSize2);
                CumulativeSize2 += EntryField;
                __int16 TargetRva = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);
                if (TargetRva == 1296 && CumulativeSize == 64 && RvaOffset == 8 && SectionChar == 64)
                {
                    SectionBaseCopy = 1;
                }
                else if (SectionBaseCopy == 1)
                {
                    if (TargetRva == 1368)
                    {
                        Found = (unsigned int)(SectionEnd + SectionInfo[14] - ImageBase);
                        break;
                    }
                }
                if (++LoopIndex >= 0x64)
                    return 0;
            }
        }
        if (Found && Found < ImageSize)
        {
            PE_DECODE_CONTEXT DecodeContext2; __int64 EntryBase2 = 0;   // DecodeContext2 为 0x48 字节解码上下文
            _DWORD ReadEntry2[112];
            __int64 EntrySize2 = 0, SectionType2 = 0, SectionInfoPtr2 = 0;
            int SectionChar2 = 0;
            unsigned int FieldValue2 = 0, EntryDataPtr2 = 0;

            InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext2);
            unsigned int InnerFound = 0;
            char InnerLoop = 0;
            int InnerEnd = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext2, ReadEntry2))
                    return 0;
                int SectionType = (int)(EntryDataPtr2 + EntryBase2);
                EntryBase2 += EntryDataPtr2;
                __int16 SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)ReadEntry2 + 0x118) + 6);
                if (SectionType2 == 1349)
                    return 0;
                if (SectionType2 == 1298 && SectionType2 == 0x40000 && EntrySize2 == 64 && SectionChar2 == 1
                    && SectionType + FieldValue2 - ImageBase && SectionType + FieldValue2 - (unsigned int)ImageBase < ImageSize)
                {
                    InnerFound = (unsigned int)(SectionType + FieldValue2 - ImageBase);
                }
                if (SectionType2 == 1368)
                    goto LABEL_43;
                if ((unsigned __int16)(SectionType2 - 1139) <= 1u)
                    break;
                if (InnerLoop == 1 && SectionType2 == 0x40000 && EntrySize2 == 64)
                {
                    unsigned int result = (unsigned int)(SectionType + FieldValue2 - ImageBase);
                    if (result && result < ImageSize)
                        return GtWrite(GtEprocessExtField35, SectionBase + result);
                }
LABEL_44:
                if (++InnerEnd >= 0xC8)
                    return 0;
            }
            if (InnerFound && !InnerLoop)
            {
                GtWrite(GtEprocessExtField34, SectionBase + InnerFound);
                InnerLoop = 1;
            }
LABEL_43:
            InnerFound = 0;
            goto LABEL_44;
        }
    }
    return 0;
}
char FindNdisIfRegisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisIfRegisterInterface");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField38, (unsigned int)Value);
            GtWrite(GtEprocessExtField39, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisIfRegisterProviderExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisIfRegisterProvider");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField32, (unsigned int)Value);
            GtWrite(GtEprocessExtField33, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisMGetOffloadHandlersExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisMGetOffloadHandlers");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField44, (unsigned int)Value);
            GtWrite(GtEprocessExtField45, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char FindNdisMRegisterMiniportDriverExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[32];
        strcpy(NameBuf, "NdisMRegisterMiniportDriver");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1)
        {
            if ((unsigned int)Value && (unsigned int)Value < ImageSize)
            {
                GtWrite(GtEprocessExtField25, (unsigned int)Value);
                GtWrite(GtEprocessExtField26, NdisSectionBase + (unsigned int)Value);
                return 1;
            }
        }
        else
        {
            unsigned int MiniportOffset = (unsigned int)GtRead(GtEprocessExtField23);
            if (MiniportOffset || (FindNdisMRegisterMiniportExport(ImageBase, ImageSize), (MiniportOffset = (unsigned int)GtRead(GtEprocessExtField23)) != 0))
                ParseNdisMiniportDriverName(ImageBase, ImageSize, MiniportOffset);
        }
    }
    return Result;
}
char FindNdisGetVersionExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    unsigned int ExportOffset = 0;
    if (GtRead(GtEprocessExtField11))
    {
        char NameBuf[16];
        strcpy(NameBuf, "NdisGetVersion");
        NameBuf[15] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, &ExportOffset) == 1 && ExportOffset && ExportOffset < ImageSize && ExportOffset + 5 < ImageSize)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB)
                return ParseNdisGetVersionSection(ExportOffset, ImageBase, ImageSize);
            GtWrite(GtEprocessExtField13, *(unsigned int *)(ExportOffset + ImageBase + 1));
            return 1;
        }
    }
    return Result;
}
char FindKernelRdataSection(__int64 ImageBase, unsigned int ImageSize)
{
    char SectionName[8];
    __int64 ImageSizeVar = ImageSize;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        strcpy(SectionName, ".rdata");
        SectionName[7] = 0;
    }
    else
    {
        strcpy(SectionName, ".data");
        *(_WORD *)&SectionName[6] = 0;
    }
    unsigned int PESectionByName = (unsigned int)FindPESectionByName((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
    unsigned int SectionBaseCopy = (unsigned int)FindPESectionByNameReturnVa((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
    if (PESectionByName && SectionBaseCopy && PESectionByName < (unsigned int)ImageSizeVar)
    {
        _QWORD *ExportOffset = (_QWORD *)(PESectionByName + ImageBase);
        __int64 LoopIndex = *(_QWORD *)(*(int *)(ImageBase + 60) + ImageBase + 48);
        if (SectionBaseCopy >= 0x100000)
            SectionBaseCopy = 0x100000;
        __int64 SectionEnd = (SectionBaseCopy + PESectionByName >= (unsigned int)ImageSizeVar) ? (ImageBase + ImageSizeVar) : (ImageBase + PESectionByName + SectionBaseCopy);
        __int64 TargetRva = SectionEnd - 72;
        while ((unsigned __int64)ExportOffset < (unsigned __int64)TargetRva)
        {
            if (*ExportOffset == 65793 && !ExportOffset[2] && ExportOffset[3] == 65795 && !ExportOffset[5] && ExportOffset[6] == 65796)
            {
                __int64 TargetRva2 = ExportOffset[1];
                __int64 SectionType = ImageSizeVar + LoopIndex;
                if (TargetRva2 > LoopIndex && TargetRva2 < SectionType)
                {
                    __int64 SectionBase = ExportOffset[4];
                    if (SectionBase > LoopIndex && SectionBase < SectionType)
                    {
                        SectionBase = ExportOffset[7];
                        if (SectionBase > LoopIndex && SectionBase < SectionType)
                        {
                            unsigned int SectionType2 = (unsigned int)(__int64)ExportOffset - (unsigned int)ImageBase;
                            if (SectionType2 && SectionType2 < (unsigned int)ImageSizeVar)
                            {
                                __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
                                if (NdisSectionBase)
                                {
                                    GtWrite(GtEprocessExtField56, SectionType2 + NdisSectionBase);
                                    _QWORD *SectionType3 = (_QWORD *)(SectionType2 + ImageBase);
                                    _QWORD *FieldValue = SectionType3;
                                    if ((unsigned __int64)SectionType3 < (unsigned __int64)TargetRva)
                                    {
                                        __int64 FieldValue2 = ImageSizeVar + LoopIndex;
                                        do
                                        {
                                            if (*FieldValue > 0xFD010111)
                                                break;
                                            __int64 ReadContext = FieldValue[1];
                                            if (ReadContext && (ReadContext <= LoopIndex || ReadContext >= FieldValue2))
                                                break;
                                            if (!ReadContext && !FieldValue[2])
                                                break;
                                            __int64 CumulativeSize = FieldValue[2];
                                            if (CumulativeSize && (CumulativeSize <= LoopIndex || CumulativeSize >= FieldValue2))
                                                break;
                                            FieldValue += 3;
                                        } while ((unsigned __int64)FieldValue < (unsigned __int64)TargetRva);
                                    }
                                    unsigned int SectionEntry = (unsigned int)(__int64)FieldValue - (unsigned int)(__int64)SectionType3;
                                    if (SectionEntry - 1 <= 0xFFE)
                                    {
                                        AdjustRelocationOffsets(SectionType3, SectionEntry, (int)LoopIndex);
                                        GtWrite(GtEprocessExtField57, SectionEntry);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ++ExportOffset;
        }
    }
    return 0;
}
char FindNdisRegisterTdiCallBackExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 NdisSectionBase = GtRead(GtEprocessExtField11);
    if (NdisSectionBase)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisRegisterTdiCallBack");
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField28, (unsigned int)Value);
            GtWrite(GtEprocessExtField29, NdisSectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char ParseNtKernelDataOffsets(__int64 ImageBase, unsigned int ImageSize)
{
    char Size = 0;
    unsigned int Result = (unsigned int)GtRead(GtEprocessExtField44);
    if (!Result)
    {
        FindNdisMGetOffloadHandlersExport(ImageBase, ImageSize);
        Result = (unsigned int)GtRead(GtEprocessExtField44);
    }
    __int64 OffloadOffset = GtRead(GtEprocessExtField11);
    if (OffloadOffset && Result && Result < ImageSize)
    {
        __int64 SectionBase = *(_QWORD *)(*(int *)(ImageBase + 60) + ImageBase + 48);
        PE_DECODE_CONTEXT ReadContext; __int64 CumulativeSize = 0;   // 拆开：前者为 0x48 字节解码上下文
        _DWORD SectionEntry[112];           // 描述符：原 [20] 仅 80 字节
        __int64 SectionChar = 0, SectionAlignment = 0, EntryDataPtr = 0;
        __int64 Value = 0;
        unsigned int EntryCumulSize = 0;

        InitPESectionReadContext(ImageBase + Result, ImageSize - Result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int i = 0; i < 0x1E; ++i)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            int SectionIndex = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            __int16 SectionOffset = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (SectionOffset == 1349)
                break;
            if (SectionOffset == 1298 && SectionAlignment == 0x40000)
            {
                if ((_DWORD)Value && SectionChar == 64)
                {
                    unsigned int SectionType = (unsigned int)(SectionIndex + (unsigned int)Value - ImageBase);
                    if (SectionType && SectionType < ImageSize)
                    {
                        __int64 TargetRva = SectionType;
                        GtWrite(GtEprocessExtField46, SectionType);
                        GtWrite(GtEprocessExtField47, TargetRva + OffloadOffset);
                        GtWrite(GtEprocessExtField48, (unsigned int)Value);
                        GtWrite(GtEprocessExtField49, OffloadOffset + (unsigned int)(CumulativeSize - ImageBase - 4));
                        if (TargetRva + 56 < ImageSize)
                        {
                            if (*(_QWORD *)(TargetRva + ImageBase + 8) > (unsigned __int64)SectionBase)
                            {
                                unsigned int TargetOffset = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 8) - SectionBase);
                                if (ImageSize > TargetOffset)
                                    GtWrite(GtEprocessExtField50, OffloadOffset + TargetOffset);
                            }
                            if (*(_QWORD *)(TargetRva + ImageBase + 16) > (unsigned __int64)SectionBase)
                            {
                                unsigned int FieldOffset1 = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 16) - SectionBase);
                                if (ImageSize > FieldOffset1)
                                    GtWrite(GtEprocessExtField51, OffloadOffset + FieldOffset1);
                            }
                            if (*(_QWORD *)(TargetRva + ImageBase + 24) > (unsigned __int64)SectionBase)
                            {
                                unsigned int FieldOffset2 = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 24) - SectionBase);
                                if (ImageSize > FieldOffset2)
                                    GtWrite(GtEprocessExtField52, OffloadOffset + FieldOffset2);
                            }
                            if (*(_QWORD *)(TargetRva + ImageBase + 32) > (unsigned __int64)SectionBase)
                            {
                                unsigned int FieldOffset3 = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 32) - SectionBase);
                                if (ImageSize > FieldOffset3)
                                    GtWrite(GtEprocessExtField53, OffloadOffset + FieldOffset3);
                            }
                            if (*(_QWORD *)(TargetRva + ImageBase + 40) > (unsigned __int64)SectionBase)
                            {
                                unsigned int FieldOffset4 = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 40) - SectionBase);
                                if (ImageSize > FieldOffset4)
                                    GtWrite(GtEprocessExtField54, OffloadOffset + FieldOffset4);
                            }
                            if (*(_QWORD *)(TargetRva + ImageBase + 48) > (unsigned __int64)SectionBase)
                            {
                                unsigned int FieldOffset5 = (unsigned int)(*(_DWORD *)(TargetRva + ImageBase + 48) - SectionBase);
                                if (ImageSize > FieldOffset5)
                                    GtWrite(GtEprocessExtField55, OffloadOffset + FieldOffset5);
                            }
                            return 1;
                        }
                        return Size;
                    }
                }
            }
        }
    }
    return Size;
}
__int16 ScanTextSectionPattern(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead(GtEprocessExtField14);
    if (!Found)
    {
        FindNdisDeregisterProtocolExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead(GtEprocessExtField14);
    }
    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 LoopIndex = SectionBase;
    if (SectionBase && Found && Found < ImageSize)
    {
        PE_DECODE_CONTEXT DecodeContext; __int64 FieldValue2 = 0;   // DecodeContext 实为 0x48 字节解码上下文（名字错位；累加的是 FieldValue2）
        _DWORD SectionInfo[112];
        int RvaOffset = 0;
        __int64 CumulativeSize = 0, SectionChar = 0, EntrySize = 0;
        unsigned int EntryField = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        char SectionEnd = 0;
        for (unsigned int i = 0; i < 0x64; ++i)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                break;
            int TargetRva2 = (int)(EntryField + FieldValue2);
            FieldValue2 += EntryField;
            __int16 SectionType = *(_WORD *)(EntrySize + 6);
            if ((unsigned __int16)(SectionType - 1139) <= 1u)
            {
                SectionEnd = 1;
            }
            else if (SectionEnd == 1)
            {
                if (SectionType == 1296 && SectionChar == 0x40000)
                {
                    if (RvaOffset && CumulativeSize == 64)
                    {
                        unsigned int SectionType2 = (unsigned int)(TargetRva2 + RvaOffset - ImageBase);
                        if (SectionType2 && SectionType2 < ImageSize)
                        {
                            GtWrite(GtEprocessExtField16, LoopIndex + SectionType2);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
__int64 ScanDataSectionPattern(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead(GtEprocessExtField28);
    if (!Found)
    {
        FindNdisRegisterTdiCallBackExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead(GtEprocessExtField28);
    }
    __int64 LoopIndex = GtRead(GtEprocessExtField11);
    if (LoopIndex && Found && Found < ImageSize)
    {
        PE_DECODE_CONTEXT DecodeContext; __int64 FieldValue2 = 0;   // DecodeContext 实为 0x48 字节解码上下文（名字错位；累加的是 FieldValue2）
        _DWORD SectionInfo[112];
        int CumulativeSize = 0;
        __int64 RvaOffset = 0, EntryField = 0, SectionAlignment = 0;
        unsigned int EntrySize = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        unsigned int SectionEnd = 0;
        unsigned int TargetRva = 0;
        for (unsigned int i = 0; i < 0x32; ++i)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)SectionInfo + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                break;
            int SectionType = (int)(EntrySize + FieldValue2);
            FieldValue2 += EntrySize;
            __int16 SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);
            if (SectionType2 == 1349)
                break;
            if (SectionType2 == 1294 && RvaOffset == 0x40000 && EntryField == 64)
            {
                unsigned int result = (unsigned int)(SectionType + CumulativeSize - ImageBase);
                if (SectionType + CumulativeSize - (int)ImageBase)
                {
                    if (result < ImageSize)
                    {
                        if (SectionEnd)
                        {
                            TargetRva = (unsigned int)(SectionType + CumulativeSize - ImageBase);
                            break;
                        }
                        SectionEnd = (unsigned int)(SectionType + CumulativeSize - ImageBase);
                    }
                }
            }
        }
        if (SectionEnd && TargetRva)
        {
            GtWrite(GtEprocessExtField30, LoopIndex + SectionEnd);
            return GtWrite(GtEprocessExtField31, LoopIndex + TargetRva);
        }
    }
    return 0;
}
__int16 ScanInitSectionPattern(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead(GtEprocessExtField25);
    if (!Found)
    {
        FindNdisMRegisterMiniportDriverExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead(GtEprocessExtField25);
    }
    __int64 ExportOffset = GtRead(GtEprocessExtField11);
    __int64 FieldValue = ExportOffset;
    if (ExportOffset && Found && Found < ImageSize)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            PE_DECODE_CONTEXT ReadContext; __int64 CumulativeSize = 0;   // 拆开：前者为 0x48 字节解码上下文
            _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
            int SectionChar = 0, EntryField = 0, SectionAlignment = 0;
            __int64 EntrySize = 0, EntryCumulSize = 0, SectionInfoPtr = 0;
            unsigned int EntryDataPtr = 0;

            InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            int SectionBase = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            {
                *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                int LoopIndex = (int)(EntryDataPtr + CumulativeSize);
                CumulativeSize += EntryDataPtr;
                if ((unsigned __int16)(*(_WORD *)(SectionInfoPtr + 6) - 1368) <= 1u)
                {
                    if (SectionChar)
                    {
                        unsigned int SectionEnd = (unsigned int)(LoopIndex + SectionChar - ImageBase);
                        if (SectionEnd && SectionEnd < ImageSize)
                        {
                            Found = (unsigned int)(LoopIndex + SectionChar - ImageBase);
                            break;
                        }
                    }
                }
                if (++SectionBase >= 5)
                    break;
            }
        }
        PE_DECODE_CONTEXT DecodeContext2; __int64 EntryBase2 = 0;   // DecodeContext2 为 0x48 字节解码上下文
        _DWORD ReadEntry2[112];
        int SectionChar2 = 0, FieldValue2 = 0, FieldValue3 = 0;
        __int64 EntrySize2 = 0, SectionType2 = 0, SectionInfoPtr2 = 0;
        unsigned int EntryDataPtr2 = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext2);
        int TargetRva = 0;
        int SectionType = 0;
        for (unsigned int i = 0; i < 0x3E8; ++i)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext2, ReadEntry2))
                break;
            int SectionType3 = (int)(EntryDataPtr2 + EntryBase2);
            EntryBase2 += EntryDataPtr2;
            __int16 FieldValue2 = *(_WORD *)(SectionInfoPtr2 + 6);
            if ((unsigned __int16)(FieldValue2 - 1139) <= 1u)
            {
                TargetRva = 0;
                SectionType = 0;
            }
            else
            {
                if (FieldValue2 == 1296)
                {
                    if (SectionType2 == 0x40000 && FieldValue3 && EntrySize2 == 64)
                    {
                        if (TargetRva)
                        {
                            if (!SectionType)
                                SectionType = (unsigned int)(SectionType3 + FieldValue3 - ImageBase);
                        }
                        else
                        {
                            TargetRva = (unsigned int)(SectionType3 + FieldValue3 - ImageBase);
                        }
                    }
                }
                else if (EntrySize2 == 0x40000)
                {
                    if (FieldValue2 && SectionType2 == 64)
                    {
                        unsigned int rva = (unsigned int)(SectionType3 + FieldValue2 - ImageBase);
                        if (rva && rva < ImageSize && (TargetRva == (int)rva || SectionType == (int)rva))
                        {
                            GtWrite(GtEprocessExtField27, FieldValue + rva);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
__int16 ScanPageSectionPattern(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead(GtEprocessExtField17);
    if (!Found)
    {
        FindNdisFRegisterFilterDriverExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead(GtEprocessExtField17);
    }
    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 LoopIndex = SectionBase;
    if (SectionBase && Found && Found < ImageSize)
    {
        PE_DECODE_CONTEXT DecodeContext; __int64 FieldValue2 = 0;   // DecodeContext 实为 0x48 字节解码上下文（名字错位；累加的是 FieldValue2）
        _DWORD SectionInfo[112];
        int CumulativeSize = 0, SectionChar = 0;
        __int64 RvaOffset = 0, EntryField = 0, SectionAlignment = 0;
        unsigned int EntrySize = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        int SectionEnd = 0;
        for (unsigned int i = 0; i < 0x3E8; ++i)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                break;
            int TargetRva2 = (int)(EntrySize + FieldValue2);
            FieldValue2 += EntrySize;
            __int16 SectionType = *(_WORD *)(SectionAlignment + 6);
            if ((unsigned __int16)(SectionType - 1139) <= 1u)
            {
                SectionEnd = 0;
            }
            else
            {
                if (SectionType == 1296)
                {
                    if (EntryField == 0x40000 && SectionChar && RvaOffset == 64)
                        SectionEnd = (unsigned int)(TargetRva2 + SectionChar - ImageBase);
                }
                else if (RvaOffset == 0x40000)
                {
                    if (CumulativeSize && EntryField == 64)
                    {
                        unsigned int rva = (unsigned int)(TargetRva2 + CumulativeSize - ImageBase);
                        if (rva && rva < ImageSize && (int)rva == SectionEnd)
                        {
                            GtWrite(GtEprocessExtField19, LoopIndex + rva);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}
char FindTdiDeregisterPnpExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 SectionBase = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (SectionBase)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "TdiDeregisterPnPHandlers");
        *((UCHAR *)&NameBuf[12] + 1) = 0;
        NameBuf[13] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessField02 | 0x800, (unsigned int)Value);
            GtWrite(GtEprocessField03 | 0x800, SectionBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
__int64 ParseKernelDataSectionRelocs(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Found = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)2052);
    if (!Found)
    {
        FindDllInitExport(ImageBase, ImageSize);
        Found = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)2052);
    }
    __int64 SectionBase = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (SectionBase && Found && Found < ImageSize)
    {
        PE_DECODE_CONTEXT DecodeContext; __int64 SectionEntry = 0;   // DecodeContext 实为 0x48 字节解码上下文（名字错位，累加的是 SectionEntry）
        _DWORD FieldValue[112];
        unsigned int SectionChar = 0, EntrySizeField = 0;
        __int64 EntryField = 0, SectionAlignment = 0, EntryDataPtr = 0, SectionInfoPtr = 0;
        int EntrySize = 0, EntryCumulSize = 0;
        unsigned int ReadContext = 0;
        char SectionType3 = 0;
        int SectionType4 = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        int SectionBaseCopy = 0;
        unsigned int LoopIndex = 0;
        unsigned int SectionEnd = 0;
        do
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, FieldValue))
                return 0;
            int TargetRva = (int)(EntrySizeField + SectionEntry);
            SectionEntry += EntrySizeField;
            int InnerFound = *(unsigned __int16 *)(SectionInfoPtr + 6);
            if (InnerFound == 1349)
                return 0;
            if (ReadContext >= 4 || SectionBaseCopy || InnerFound != 1069)
            {
                // continue to next checks
            }
            else
            {
                if (EntryField == 0x40000 && SectionChar && EntryDataPtr == 0x1000000000LL && !SectionAlignment)
                {
                    unsigned int result = (unsigned int)(TargetRva + SectionChar - ImageBase);
                    if (result && result < ImageSize)
                    {
                        LoopIndex = (unsigned int)(TargetRva + SectionChar - ImageBase);
                        InnerFound = 1139;
                        SectionType3 = 1;
                    }
                }
            }
            if (InnerFound == 1298 && EntryDataPtr == 0x40000 && EntryCumulSize && EntryField == 64)
            {
                if (EntrySize == 1)
                {
                    LoopIndex = (unsigned int)(TargetRva + EntryCumulSize - ImageBase);
                    if (LoopIndex >= ImageSize)
                        LoopIndex = 0;
                }
                else if (EntrySize == 2)
                {
                    unsigned int result = (unsigned int)(TargetRva + EntryCumulSize - ImageBase);
                    SectionEnd = result < ImageSize ? result : 0;
                }
            }
            if (SectionType4 == 1 && InnerFound == 1298)
            {
                if (EntryDataPtr == 0x40000 && EntryCumulSize && EntryField == 64)
                {
                    unsigned int InnerEnd = (unsigned int)(TargetRva + EntryCumulSize - ImageBase);
                    if (InnerEnd && InnerEnd < ImageSize)
                    {
                        if (SectionType3 != 1 && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x2580)
                        {
                            int SectionType = 2056;
                            if (!GtRead((enum _GLOBAL_TABLE_INDEX)2056))
                                GtWrite((enum _GLOBAL_TABLE_INDEX)SectionType, SectionBase + InnerEnd);
                            else if (!GtRead(GtPathBuffer03 | 0x800))
                                GtWrite(GtPathBuffer03 | 0x800, SectionBase + InnerEnd);
                            else if (!GtRead(GtSymlinkBuffer | 0x800))
                                GtWrite(GtSymlinkBuffer | 0x800, SectionBase + InnerEnd);
                        }
                        else
                        {
                            if (!GtRead(GtPathBuffer03 | 0x800))
                                GtWrite(GtPathBuffer03 | 0x800, SectionBase + InnerEnd);
                            else if (!GtRead((enum _GLOBAL_TABLE_INDEX)2056))
                                GtWrite((enum _GLOBAL_TABLE_INDEX)2056, SectionBase + InnerEnd);
                            else if (!GtRead(GtSymlinkBuffer | 0x800))
                                GtWrite(GtSymlinkBuffer | 0x800, SectionBase + InnerEnd);
                        }
                    }
                }
                SectionBaseCopy = 1;
                goto LABEL_42;
            }
            SectionBaseCopy = SectionType4;
            if ((unsigned int)(InnerFound - 1139) <= 1)
            {
                if (SectionType4)
                {
                    if (LoopIndex && SectionEnd)
                    {
                        GtWrite(GtEprocessOffsetBase | 0x800, SectionBase + LoopIndex);
                        return GtWrite(GtEprocessField01 | 0x800, SectionBase + SectionEnd);
                    }
                }
                else if (LoopIndex)
                {
                    GtWrite(GtPathBuffer02 | 0x800, SectionBase + LoopIndex);
                }
                SectionBaseCopy = SectionType4 + 1;
                LoopIndex = 0;
                SectionEnd = 0;
                ++SectionType4;
            }
LABEL_42:
            ++ReadContext;
        } while (ReadContext < 0x50);
    }
    return 0;
}
char ReadNtoskrnlFileToBuffer(void **pBuffer, unsigned int *pBufferSize)
{
    char Result = 0;
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
    EncodedPath[14] = 6357084;
    EncodedPath[15] = 7340131;
    EncodedPath[16] = 3014761;
    EncodedPath[17] = 7929971;
    EncodedPath[18] = 115;
    void *Src = NULL;
    ULONG MaxCount = 0;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, &MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, pBufferSize) == 1;
        ExFree(Src);
    }
    return Result;
}
char ReadNtoskrnlFileToBuffer3(void **pBuffer, unsigned int *pBufferSize)
{
    char Result = 0;
    int EncodedPath[16];
    int ExtraPart1 = 0, ExtraPart2 = 0;
    _QWORD ExtraPart3[3];

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
    EncodedPath[14] = 6357084;
    EncodedPath[15] = 6357108;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        ExtraPart1 = 7274608;
        ExtraPart2 = 7602290;
        *(ULONG *)&ExtraPart3[0] = 7536686;
        *(_QWORD *)((char *)ExtraPart3 + 4) = 7536761;
    }
    else
    {
        ExtraPart1 = 6881392;
        ExtraPart2 = 7536686;
        ExtraPart3[0] = 7536761;
    }
    void *Src = NULL;
    ULONG MaxCount = 0;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, &MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, pBufferSize) == 1;
        ExFree(Src);
    }
    return Result;
}
bool ReadNtFileForSsdtTargets2(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    char Result = 0;
    int EncodedPath[24];
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
    EncodedPath[15] = 6357100;
    EncodedPath[16] = 7536755;
    EncodedPath[17] = 7209072;
    EncodedPath[18] = 3014768;
    EncodedPath[19] = 7929971;
    EncodedPath[20] = 115;
    void *pRawData = NULL;
    ULONG RawDataSize = 0;
    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &pRawData, &RawDataSize, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)RawDataSize, (PUCHAR *)pFileBuffer, pFileSize) == 1;
        ExFree(pRawData);
    }
    return Result;
}
char ParseNtHeaders(unsigned __int16 *SectionName, unsigned int SectionNameLength)
{
    char Result = 0;
    if (SectionNameLength >= 0x18)
    {
        int SectionName = 7602286;
        int SectionName2 = 7471211;
        int SectionName3 = 7077998;
        int SectionName4 = 7340141;
        int SectionName5 = 6619182;
        __int64 SectionName6 = 6619256;
        if (!(unsigned int)StringCompare3Way((__int64)&SectionName, (unsigned __int16 *)&SectionName, 0xCu))
            return 1;
        SectionName = 7602286;
        SectionName2 = 7536751;
        SectionName3 = 7471211;
        SectionName4 = 7077998;
        SectionName5 = 6619182;
        SectionName6 = 6619256;
        if (!(unsigned int)StringCompare3Way((__int64)&SectionName, (unsigned __int16 *)&SectionName, 0xCu))
            return 1;
        SectionName = 7602286;
        SectionName2 = 7471211;
        SectionName3 = 7077998;
        SectionName4 = 6357104;
        SectionName5 = 6619182;
        SectionName6 = 6619256;
        if ((unsigned int)StringCompare3Way((__int64)&SectionName, (unsigned __int16 *)&SectionName, 0xCu))
        {
            SectionName = 7602286;
            SectionName2 = 7471211;
            SectionName3 = 6357104;
            SectionName4 = 7340141;
            SectionName5 = 6619182;
            SectionName6 = 6619256;
            return (unsigned int)StringCompare3Way((__int64)&SectionName, (unsigned __int16 *)&SectionName, 0xCu) == 0;
        }
        else
        {
            return 1;
        }
    }
    return Result;
}
__int16 ParseNtKernelDataSections(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int InitDevOffset = (unsigned int)GtRead(GtEprocessExtField20);
    if (!InitDevOffset)
    {
        FindNdisIMInitializeDeviceInstanceEx(ImageBase, ImageSize);
        InitDevOffset = (unsigned int)GtRead(GtEprocessExtField20);
    }
    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 FoundMarker = SectionBase;
    if (SectionBase && InitDevOffset && InitDevOffset < ImageSize)
    {
        PE_DECODE_CONTEXT ReadContext; __int64 CumulativeSize = 0;   // 拆开：前者为 0x48 字节解码上下文
        _DWORD SectionEntry[112];           // 描述符：原 [8] 仅 32 字节
        char SectionFlags = 0;
        int EntrySize = 0;
        __int64 SectionChar = 0;
        int EntryField = 0;
        int EntrySize2 = 0;
        __int64 SectionAlignment = 0;
        unsigned int EntryCumulSize = 0;
        __int64 EntryDataPtr = 0;
        int SectionType = 0;

        InitPESectionReadContext(ImageBase + InitDevOffset, ImageSize - InitDevOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        char SectionIndex = 0;
        unsigned int SectionOffset = 0;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        {
            // Win10 19041+ 路径：找类型 1296+1368 组合
            while (SectionOffset < 0x64)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                SectionType = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                __int16 SectionType2 = *(_WORD *)(EntryDataPtr + 6);
                if (SectionType2 == 1296 && SectionChar == 64 && (SectionFlags & 8) != 0 && SectionAlignment == 0x20000 && EntrySize2 == 392)
                {
                    SectionIndex = 1;
                }
                else if (SectionIndex == 1 && SectionType2 == 1368)
                {
                    goto LABEL_SCAN;
                }
                ++SectionOffset;
            }
        }
        else
        {
            // 旧版路径：找 bound import(1139/1140)+1368 组合
            while (SectionOffset < 0x64)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                SectionType = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                __int16 InnerFound = *(_WORD *)(EntryDataPtr + 6);
                if ((unsigned __int16)(InnerFound - 1139) <= 1u)
                {
                    SectionIndex = 1;
                }
                else if (SectionIndex == 1 && InnerFound == 1368)
                {
                    goto LABEL_SCAN;
                }
                ++SectionOffset;
            }
        }
        return 0;

    char InnerLoopIndex = 0;
    unsigned int InnerSectionOffset = 0;

LABEL_SCAN:
    InnerSectionOffset = 0;
        SectionBase = SectionType + EntrySize - ImageBase;
        if ((_DWORD)SectionBase && (unsigned int)SectionBase < ImageSize)
        {
            InitPESectionReadContext(ImageBase + (unsigned int)SectionBase, ImageSize - (unsigned int)SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                int InnerSectionType = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                __int16 SectionTypeId = *(_WORD *)(EntryDataPtr + 6);
                if (SectionTypeId == 1298)
                {
                    // 数据节区：检查是否为目标
                    if (SectionAlignment == 0x40000 && EntrySize2 && SectionChar == 64 && EntryField == 1)
                    {
                        if (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                        {
                            if ((unsigned __int16)(*(_WORD *)(EntryDataPtr + 6) - 1139) <= 1u)
                            {
                                InnerLoopIndex = 1;
                                CumulativeSize += EntryCumulSize;
                            }
                        }
                    }
                }
                else if (InnerLoopIndex == 1)
                {
                    // 已标记，检查后续代码节区
                    if (SectionTypeId == 1296 && SectionAlignment == 0x40000 && EntrySize2 && SectionChar == 64)
                    {
                        SectionBase = InnerSectionType + EntrySize2 - ImageBase;
                        if ((_DWORD)SectionBase && (unsigned int)SectionBase < ImageSize)
                        {
                            GtWrite(GtEprocessExtField22, FoundMarker + (unsigned int)SectionBase);
                            return (__int16)SectionBase;
                        }
                    }
                }
                if (++InnerSectionOffset >= 0xC8)
                    break;
            }
        }
    }
    return (__int16)SectionBase;
}
char ParseNtHeadersForSsdtTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 OutputTable = pOutputTable;
    char Result = 0;
    __int64 NtoskrnlBase = GtRead(GtCallbackField47);
    if (NtoskrnlBase)
    {
        unsigned int OptHeaderSize = *(unsigned int *)(*(int *)(ImageBase + 60) + ImageBase + 40);
        if (OptHeaderSize < ImageSize && (int)OptHeaderSize + 4096 < (int)ImageSize)
        {
            char FoundInitSection = 0;
            PE_DECODE_CONTEXT DecodeContext; __int64 EntryBase = 0;   // DecodeContext 为 0x48 字节解码上下文
            _DWORD ReadEntry[112];
            char SectionFlags = 0;
            int EntryField = 0;
            __int64 EntrySize = 0;
            int SectionChar = 0, FieldValue = 0;
            __int64 SectionAlignment = 0;
            unsigned int EntryDataSize = 0;
            __int64 SectionInfoPtr = 0;

            InitPESectionReadContext(ImageBase + OptHeaderSize, 4096, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
            unsigned int SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, ReadEntry))
            {
                *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)ReadEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                unsigned int SectionEnd = (unsigned int)(EntryDataSize + EntryBase);
                EntryBase += EntryDataSize;
                __int16 SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)ReadEntry + 0x118) + 6);
                if (SectionType == 1369)
                {
                    unsigned int TargetRva = (unsigned int)(SectionEnd + EntryField - ImageBase);
                    if (TargetRva && TargetRva < ImageSize)
                    {
                        OptHeaderSize = TargetRva;
                        break;
                    }
                }
                else if (SectionType == 1296 && EntrySize == 64 && SectionChar == 1)
                {
                    FoundInitSection = 1;
                }
                else if (SectionType == 1368)
                {
                    if (FoundInitSection == 1)
                    {
                        unsigned int TargetRva = (unsigned int)(SectionEnd + EntryField - ImageBase);
                        if (TargetRva && TargetRva < ImageSize)
                        {
                            OptHeaderSize = TargetRva;
                            break;
                        }
                    }
                    FoundInitSection = 0;
                }
                if (++SectionIndex >= 0x14)
                    break;
            }
            OutputTable = pOutputTable;
        }
        if (OptHeaderSize && OptHeaderSize < ImageSize && (int)OptHeaderSize + 4096 < (int)ImageSize)
        {
            PE_DECODE_CONTEXT DecodeContext2; __int64 EntryBase2 = 0;   // DecodeContext2 为 0x48 字节解码上下文
            _DWORD ReadEntry2[112];
            char SectionFlags2 = 0;
            int EntryField2 = 0;
            __int64 EntrySize2 = 0;
            int SectionChar2 = 0, FieldValue2 = 0;
            __int64 SectionAlignment2 = 0;
            unsigned int EntryDataSize2 = 0;
            __int64 SectionInfoPtr2 = 0;

            InitPESectionReadContext(ImageBase + OptHeaderSize, 4096, 2, 0, -1, 0, 0, (__int64)&DecodeContext2);
            unsigned int TargetRva2 = 0;
            unsigned int ScanIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext2, ReadEntry2))
            {
                *(ULONG64 *)((PUCHAR)&DecodeContext2 + 0x08) += *(unsigned int *)((PUCHAR)ReadEntry2 + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                unsigned int SectionEnd2 = (unsigned int)(EntryDataSize2 + EntryBase2);
                EntryBase2 += EntryDataSize2;
                __int16 SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)ReadEntry2 + 0x118) + 6);
                if (SectionType2 == 1298 && SectionAlignment2 == 0x40000 && FieldValue2 && EntrySize2 == 64 && !SectionChar2)
                    TargetRva2 = (unsigned int)(SectionEnd2 + FieldValue2 - ImageBase);
                if (SectionType2 == 1327 && (SectionFlags2 & 0x10) != 0 && TargetRva2)
                {
                    _QWORD *pTableEntry = (_QWORD *)(OutputTable + 8);
                    __int64 EntryCount = 28;
                    do
                    {
                        *((_DWORD *)pTableEntry - 1) = TargetRva2;
                        *pTableEntry = NtoskrnlBase + TargetRva2;
                        pTableEntry += 6;
                        --EntryCount;
                    } while (EntryCount);
                    return 1;
                }
                if (++ScanIndex >= 0x1F4)
                    return Result;
            }
        }
    }
    return Result;
}
char ParseNtHeadersForSsdtTargets2(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    char Result = 0;
    char FoundFlag = 0;
    __int64 SectionBase = GtRead(GtFsFilterExportTable);
    if (SectionBase)
    {
        char ExportName[16];
        strcpy(ExportName, "ClassInitialize");
        unsigned int ExportRva = (unsigned int)FindExportByNameInPeBody((PUCHAR)ImageBase, ImageSize, (PCHAR)ExportName, 0);
        if (ExportRva && ExportRva < ImageSize && ExportRva + 4096 < ImageSize)
        {
            PE_DECODE_CONTEXT DecodeContext; __int64 ContextOffset = 0;   // DecodeContext 为 0x48 字节解码上下文
            _DWORD SectionEntry[72];
            int EntryOffset = 0, EntrySize = 0, EntryIndex = 0, TypeField1 = 0, TypeField2 = 0, RvaField = 0;
            __int64 Flags = 0;
            int IndexField = 0, ExtraFlags = 0;
            unsigned int EntrySize2 = 0;
            __int64 TypePtr = 0;
            _DWORD Dst[16];

            InitPESectionReadContext(ImageBase + ExportRva, 4096, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
            memset(Dst, 0, sizeof(Dst));
            char SectionReady = 0;
            unsigned int LoopCount = 0;
            unsigned int FieldOffset = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 904 : 912;
            do
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionEntry))
                    return Result;
                int CurrentRva = (int)(EntrySize2 + ContextOffset);
                ContextOffset += EntrySize2;
                __int16 TypeValue = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (TypeValue == 1349)
                    return FoundFlag;
                int SizeValue = EntrySize;
                if (TypeValue == 1139 || TypeValue == 1368)
                {
                    memset(Dst, 0, sizeof(Dst));
                }
                else if (TypeValue == 1340
                    && FieldOffset == (unsigned int)TypeField1
                    && !TypeField2
                    && SectionEntry[2] == 1
                    && Flags == 0x800000
                    && EntrySize == 32
                    && EntryIndex == 8)
                {
                    SectionReady = 1;
                    goto LABEL_20;
                }
                if (SectionReady != 1)
                    goto LABEL_43;
LABEL_20:
                if (TypeValue == 1298 && Flags == 0x40000)
                {
                    if (RvaField && EntrySize == 64)
                    {
                        unsigned int RvaValue = CurrentRva + RvaField - (int)ImageBase;
                        if (RvaValue && RvaValue < ImageSize)
                            Dst[EntryIndex] = RvaValue;
                    }
                }
                if (TypeValue != 1294
                    || (*(_QWORD *)&SizeValue & 0x14000LL) == 0
                    || (SizeValue & 0x40) == 0
                    || (ExtraFlags & 0xF) == 4
                    || EntryIndex == 5
                    || Flags != 64)
                {
                    goto LABEL_43;
                }
                if ((unsigned int)(EntryOffset - 112) > 0xD8 || (EntryOffset & 7) != 0)
                {
                    Result = FoundFlag;
                    if (EntryOffset == 96 && FoundFlag == 1 && !*(_DWORD *)(pOutputTable + 1348))
                    {
                        unsigned int FirstEntryRva = (unsigned int)Dst[IndexField];
                        *(_DWORD *)(pOutputTable + 1348) = FirstEntryRva;
                        *(_QWORD *)(pOutputTable + 1352) = SectionBase + FirstEntryRva;
                    }
                    goto LABEL_44;
                }
                unsigned int SlotIndex = (unsigned int)(EntryOffset - 112) >> 3;
                if (SlotIndex > 0x1B)
                    goto LABEL_43;
                unsigned int TargetRva = Dst[IndexField];
                if (TargetRva == 0)
                    goto LABEL_43;
                __int64 EntrySlot = 6 * SlotIndex;
                if (*(_DWORD *)(pOutputTable + 8 * EntrySlot + 4))
                    goto LABEL_43;
                Result = 1;
                *(_DWORD *)(pOutputTable + 8 * EntrySlot + 4) = TargetRva;
                FoundFlag = 1;
                *(_QWORD *)(pOutputTable + 8 * EntrySlot + 8) = SectionBase + TargetRva;
LABEL_43:
LABEL_44:
                ++LoopCount;
            } while (LoopCount < 0x3E8);
        }
    }
    return Result;
}
char ParseAtaPortInitForHookTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 CallbackBase = GtRead(GtCallbackField42);
    if (!CallbackBase)
        return 0;

    WORD FuncName[16];
    strcpy((char *)FuncName, "AtaPortInitialize");
    FuncName[9] = 0;

    __int64 AtaPortBase = FindExportByNameInPeBody((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, 0);
    if (!AtaPortBase)
        return 0;

    // 第一遍扫描：在 AtaPortInitialize 函数体内查找 bound import 和 1368 节区模式
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0
        && (unsigned int)AtaPortBase < ImageSize
        && (int)AtaPortBase + 4096 < (int)ImageSize)
    {
        __int64 Context[9];
        _DWORD Entry[112];
        char FoundBoundImport = 0;
        char FoundPush = 0;
        int CallCount = 0;
        int ScanIndex = 0;

        InitPESectionReadContext(ImageBase + (unsigned int)AtaPortBase, 4096, 2, 0, -1, 0, 0, (__int64)Context);

        while (!(unsigned int)ReadPESectionEntry((PUCHAR)Context, Entry))
        {
            *(ULONG64 *)((PUCHAR)Context + 0x08) += *(unsigned int *)((PUCHAR)Entry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            unsigned int EntrySize = Entry[15];
            __int64 EntryBase = Context[1];
            int SectionEnd = (int)(EntrySize + EntryBase);
            Context[1] += EntrySize;
            __int16 SectionType = *(_WORD *)(Context[6] + 6);

            if (SectionType == 1349)
                break;
            if (SectionType == 1139)
            {
                FoundBoundImport = 1;
            }
            else if (SectionType == 1368 && FoundBoundImport == 1)
            {
                if (++CallCount == 2 || (CallCount == 1 && FoundPush == 1))
                {
                    __int64 NewBase = SectionEnd + Entry[14] - ImageBase;
                    if (!NewBase || (unsigned int)NewBase >= ImageSize)
                        return 0;
                    AtaPortBase = NewBase;
                    goto LABEL_SCAN;
                }
            }
            else if (SectionType == 232 && FoundBoundImport == 1)
            {
                FoundPush = 1;
            }
            if ((unsigned int)++ScanIndex >= 0x64)
                return 0;
        }
        return 0;
    }

LABEL_SCAN:
    // 第二遍扫描：填充输出表
    if (!(_DWORD)AtaPortBase || (unsigned int)AtaPortBase >= ImageSize || (int)AtaPortBase + 4096 >= (int)ImageSize)
        return 0;

    {
        __int64 Context[9];
        _DWORD Entry[112];
        _DWORD Dst[16];
        unsigned int LoopIndex = 0;
        char TableBuilt = 0;

        InitPESectionReadContext(ImageBase + (unsigned int)AtaPortBase, 4096, 2, 0, -1, 0, 0, (__int64)Context);
        memset(Dst, 0, sizeof(Dst));

        do
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)Context, Entry))
                break;

            unsigned int EntrySize = Entry[15];
            __int64 EntryBase = Context[1];
            int SectionEnd = (int)(EntrySize + EntryBase);
            Context[1] += EntrySize;
            __int16 SectionType = *(_WORD *)(Context[6] + 6);

            if (SectionType == 1349)
                break;

            int SectionFlags = Entry[8];
            // 数据节区：记录目标 RVA
            if (SectionType == 1298 && Context[4] == 0x40000)
            {
                if (Entry[10] && Entry[8] == 64)
                {
                    unsigned int TargetRva = (unsigned int)(SectionEnd + Entry[10] - ImageBase);
                    if (TargetRva && TargetRva < ImageSize)
                        Dst[Entry[9]] = TargetRva;
                }
            }
            // bound import 标记：重置 Dst
            if (SectionType == 1139)
                memset(Dst, 0, sizeof(Dst));

            // 代码节区：检查是否为目标
            if (SectionType == 1294
                && (*(__int64 *)&SectionFlags & 0x14000) != 0
                && (SectionFlags & 0x40) != 0
                && (Entry[13] & 0xF) != 4
                && Context[4] == 64
                && (unsigned int)(Entry[7] - 112) <= 0xD8
                && (Entry[7] & 7) == 0)
            {
                unsigned int TableSlot = (unsigned int)(Entry[7] - 112) >> 3;
                if (TableSlot <= 0x1B)
                {
                    unsigned int RelocRva = Dst[Entry[12]];
                    if (RelocRva && !*(_DWORD *)(pOutputTable + 48 * TableSlot + 4))
                    {
                        TableBuilt = 1;
                        *(_DWORD *)(pOutputTable + 48 * TableSlot + 4) = RelocRva;
                        *(_QWORD *)(pOutputTable + 48 * TableSlot + 8) = CallbackBase + RelocRva;
                    }
                }
            }
            ++LoopIndex;
        } while (LoopIndex < 0x1F4);

        return TableBuilt;
    }
}
__int64 ScanProcessPESectionsV2(void)
{
    __int64 TargetProcess = GtRead(0x61);
    __int64 CurrentProcess = (__int64)IoGetCurrentProcess();
    KAPC_STATE ApcState;

    if (TargetProcess != CurrentProcess && TargetProcess)
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    __int64 SectionBase = GtRead(0x63);
    __int64 SectionSize = GtRead(0x20);
    __int64 NtoskrnlBase = GtRead(0x21);
    __int64 NtoskrnlSize = GtRead(3);

    if (SectionBase && SectionSize && (unsigned int)NtoskrnlBase && NtoskrnlSize)
    {
        __int64 Context[9];
        _DWORD SectionEntry[72];
        char FoundFlag = 0;
        __int64 EntryBase = 0;
        unsigned int EntrySize = 0;
        __int64 EntryTypePtr = 0;

        InitPESectionReadContext(SectionBase, (unsigned int)SectionSize, 2, 0, -1, 0, 0, (__int64)&Context);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            *(ULONG64 *)((PUCHAR)&Context + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
                break;
            unsigned int CurrentEnd = EntrySize + (unsigned int)EntryBase;
            EntryBase += EntrySize;
            __int16 TypeValue = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (TypeValue == 0x42A && (*(char *)((char *)SectionEntry + 0x20) & 4) != 0)
            {
                FoundFlag = 1;
            }
            else if (FoundFlag == 1)
            {
                if (TypeValue == 0x558 && (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0)
                {
                    int SizeVal = SectionEntry[14];
                    if (SizeVal)
                    {
                        unsigned int ResultOff = CurrentEnd + SizeVal - (unsigned int)SectionSize;
                        if (ResultOff && ResultOff < (unsigned int)SectionSize)
                        {
                            GtWrite(0x64, NtoskrnlBase + ResultOff);
                        }
                    }
                }
            }
        }
    }

    if (TargetProcess && TargetProcess != CurrentProcess)
        KeUnstackDetachProcess(&ApcState);

    return 0;
}
__int64 InitHookFunctionTable(void)
{
    // 从汇编分析：附加到目标进程，扫描 PE 节区
    // 查找类型 0x48E(1166) 节区，然后找类型 0x558(1368) 节区
    // 写入 GT[0x23F](575) = KiInsertQueueApc 函数地址
    // 【修正 2026-10-16】按原始 GT 读序（_gtseq 提取）修正：
    //   0x61(GtCurrentEprocess=97) → 0x41CB → 0x20(PE缓冲基址) → 0x21(PE大小) → 写 0x23F。
    //   原实现首读 GtEprocessField61(=71)、并误用 GtEprocessExtField11(=0x361)，
    //   差分报 gt_index_mismatch（原始首读 97，我方 71）。
    __int64 TargetProcess = GtRead(GtCurrentEprocess);          // 0x61 = 97
    __int64 CurrentProcess = (__int64)IoGetCurrentProcess();
    KAPC_STATE ApcState;

    if (TargetProcess != CurrentProcess && TargetProcess)
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    __int64 SectionBase = GtRead(GtSyscallHash16843);           // 0x41CB = 16843
    __int64 SectionSize = GtRead(GtNtoskrnlPeFileBase);         // 0x20 = 32
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlPeFileSize);        // 0x21 = 33
    __int64 NtoskrnlSize = (__int64)(ULONG)GtRead(GtNtoskrnlPeFileSize);  // 0x21（第二次）

    if (SectionBase && SectionSize && (unsigned int)NtoskrnlBase && NtoskrnlSize)
    {
        __int64 Context[9];
        _DWORD SectionEntry[72];
        char FoundFlag = 0;
        __int64 EntryBase = 0;
        unsigned int EntrySize = 0;
        __int64 EntryTypePtr = 0;

        InitPESectionReadContext(SectionBase, (unsigned int)SectionSize, 2, 0, -1, 0, 0, (__int64)&Context);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            *(ULONG64 *)((PUCHAR)&Context + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
                break;
            unsigned int CurrentEnd = EntrySize + (unsigned int)EntryBase;
            EntryBase += EntrySize;
            __int16 TypeValue = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (TypeValue == 0x48E && (*(char *)((char *)SectionEntry + 0x20) & 4) != 0)
            {
                FoundFlag = 1;
            }
            else if (FoundFlag == 1)
            {
                if (TypeValue == 0x558 && (*(__int64 *)((char *)SectionEntry + 0x80) & 0x4000000) != 0)
                {
                    int SizeVal = SectionEntry[10];
                    if (SizeVal)
                    {
                        unsigned int ResultOff = CurrentEnd + SizeVal - (unsigned int)SectionSize;
                        if (ResultOff && ResultOff < (unsigned int)SectionSize)
                        {
                            GtWrite(GtKiInsertQueueApcFunc, NtoskrnlBase + ResultOff);
                        }
                    }
                }
            }
        }
    }

    if (TargetProcess && TargetProcess != CurrentProcess)
        KeUnstackDetachProcess(&ApcState);

    return 0;
}
char __fastcall RelocateExportAddresses(void *Src, size_t MaxCount, int BaseDelta)
{
    __int64 CountCopy = (unsigned int)MaxCount;
    char Result = 0;
    unsigned int AllocSize = (unsigned int)(__int64)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtPspExitNormalApcAddr | 0x800));
    if (AllocSize - (unsigned int)(__int64)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField27)) >= (unsigned int)CountCopy)
    {
        __int64 *Dest = GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField27));
        memmove(Dest, Src, (unsigned int)CountCopy);
        __int64 *EndPtr = (__int64 *)((char *)Dest + CountCopy - 8);
        while (++Dest <= EndPtr)
        {
            if (*Dest)
                *Dest = (unsigned int)(*(_DWORD *)Dest - BaseDelta);
        }
        return 1;
    }
    return Result;
}
char __fastcall AdjustRelocationOffsets(void *Src, size_t MaxCount, int BaseDelta)
{
    __int64 CountCopy = (unsigned int)MaxCount;
    char Result = 0;
    unsigned int BufferSize = (unsigned int)(__int64)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessExtField58 | 0x400));
    if (BufferSize - (unsigned int)(__int64)GtAlloc((enum _GLOBAL_TABLE_INDEX)GtEprocessExtField58) >= (unsigned int)CountCopy)
    {
        __int64 *Dest = GtAlloc((enum _GLOBAL_TABLE_INDEX)GtEprocessExtField58);
        memmove(Dest, Src, (unsigned int)CountCopy);
        if (Dest <= (__int64 *)((char *)Dest + CountCopy - 24))
        {
            __int64 *EntryPtr = Dest + 2;
            unsigned __int64 EntryCount = (CountCopy - 24) / 0x18 + 1;
            do
            {
                if (*(EntryPtr - 1))
                    *(EntryPtr - 1) = (unsigned int)(*((_DWORD *)EntryPtr - 2) - BaseDelta);
                if (*EntryPtr)
                    *EntryPtr = (unsigned int)(*(_DWORD *)EntryPtr - BaseDelta);
                EntryPtr += 3;
                --EntryCount;
            } while (EntryCount);
        }
        return 1;
    }
    return Result;
}
char __fastcall FindHalInitSystemExport(__int64 ImageBase, unsigned int ImageSize, __int64 HalBase)
{
    char Result = 0;
    __int64 Value = 0;
    if (ImageBase && ImageSize && HalBase)
    {
        WORD FuncName[8];
        strcpy((char *)FuncName, "HalInitSystem");
        FuncName[7] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, (PULONG)&Value) == 1
            && (_DWORD)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessField96 | 0x800), (unsigned int)Value);
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtModuleBuffer | 0x800), HalBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char __fastcall FindHalInitializeProcessorExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 HalBase = GtRead(GtEprocessField76);
    if (HalBase)
    {
        char FuncName[40];
        strcpy(FuncName, "HalInitializeProcessor");
        FuncName[23] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, FuncName, (PULONG)&Value) == 1
            && (_DWORD)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleEntryCount | GtEprocessField22), (unsigned int)Value);
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField22), HalBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char __fastcall FindHalDataSectionOffset(__int64 ImageBase, unsigned int ImageSize, unsigned int SectionOffset, __int64 HalBase)
{
    char Result = 0;
    if (HalBase && SectionOffset && SectionOffset < ImageSize)
    {
        PE_DECODE_CONTEXT ReadContext;   // 0x48 字节解码上下文（原 __int64[8] 仅 64 字节）
        _DWORD SectionEntry[72];
        __int64 CumulativeSize = 0;
        unsigned int Phase1Result = 0;
        int EntrySize = 0;
        int EntrySize2 = 0;
        __int64 SectionFlags = 0;
        unsigned int EntryCumulSize = 0;
        __int64 EntryDataPtr = 0;

        // 阶段 1：查找子类型 1369 或 1368 的条目定位基址
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int Phase1Index = 0; Phase1Index < 0x1E; Phase1Index++)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                return Result;
            int CurrentOffset = EntryCumulSize + (unsigned int)CumulativeSize;
            CumulativeSize += EntryCumulSize;
            if (*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1369)
            {
                if (EntrySize)
                {
                    Phase1Result = (unsigned int)(CurrentOffset + EntrySize - ImageBase);
                    break;
                }
            }
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB && *(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && EntrySize)
            {
                Phase1Result = (unsigned int)(CumulativeSize + EntrySize - ImageBase);
                break;
            }
        }

        // 阶段 2：搜索子类型 1298 的条目
        if (Phase1Result && Phase1Result < ImageSize)
        {
            InitPESectionReadContext(ImageBase + Phase1Result, ImageSize - Phase1Result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            CumulativeSize = 0;
            for (int Phase2Index = 0; Phase2Index < 0x64; Phase2Index++)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    return Result;
                int Phase2Current = EntryCumulSize + (unsigned int)CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1298 && SectionFlags == 0x40000)
                {
                    if (EntrySize2 && EntryCumulSize == 64)
                    {
                        unsigned int Phase2Match = (unsigned int)(Phase2Current + EntrySize2 - ImageBase);
                        if (Phase2Match && Phase2Match < ImageSize)
                        {
                            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField23), HalBase + Phase2Match);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return Result;
}
char __fastcall FindHalExportTableLegacy(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 HalExportAddr = GtRead(GtEprocessField76);
    if (HalExportAddr)
    {
        unsigned int SectionOffset = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField96 | 0x800));
        if (!SectionOffset)
        {
            FindHalInitSystemExport(ImageBase, ImageSize, HalExportAddr);
            SectionOffset = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField96 | 0x800));
        }
        if (SectionOffset && SectionOffset < ImageSize)
        {
            unsigned __int64 BufferEnd = ImageSize + ImageBase;
            unsigned __int64 NtImageBase = *(_QWORD *)(*(int *)(ImageBase + 60) + ImageBase + 48);
            unsigned __int8 *ScanPos = (unsigned __int8 *)(ImageBase + SectionOffset);
            for (int OuterIndex = 0; OuterIndex < 0x96; OuterIndex++)
            {
                _WORD DecodeResult[24];
                if (!DecodeUnicodeChar(ScanPos, BufferEnd, DecodeResult))
                    break;
                ScanPos += *(unsigned int *)((char *)DecodeResult + 24);
                int TokenValue = *(int *)(*(__int64 *)((char *)DecodeResult + 40));
                int TokenFlag = *(int *)((char *)DecodeResult + 12);
                int TokenAddress = *(int *)((char *)DecodeResult + 16);
                if (TokenValue == 4280 && TokenFlag == 56 && TokenAddress && TokenAddress > (int)NtImageBase && (int)ImageSize > TokenAddress - (int)NtImageBase)
                {
                    unsigned int FoundOffset = TokenAddress - (int)NtImageBase;
                    if (TokenAddress != (int)NtImageBase && FoundOffset < ImageSize)
                    {
                        unsigned __int8 *InnerScanPos = (unsigned __int8 *)(ImageBase + FoundOffset);
                        for (int InnerIndex = 0; InnerIndex < 0x64; InnerIndex++)
                        {
                            if (!DecodeUnicodeChar(InnerScanPos, BufferEnd, DecodeResult))
                                break;
                            InnerScanPos += *(unsigned int *)((char *)DecodeResult + 24);
                            if (*(int *)(*(__int64 *)((char *)DecodeResult + 40)) == 4280 && *(int *)((char *)DecodeResult + 16) == 1212238880)
                            {
                                int MatchV17 = *(int *)((char *)DecodeResult + 12);
                                if (MatchV17 && MatchV17 > (int)NtImageBase)
                                {
                                    unsigned int MatchOffset = MatchV17 - (int)NtImageBase;
                                    if ((unsigned int)ImageSize > (unsigned int)MatchV17 - (int)NtImageBase && MatchOffset && MatchOffset < ImageSize)
                                    {
                                        GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField25), HalExportAddr + MatchOffset);
                                        return 1;
                                    }
                                }
                            }
                            if (InnerIndex >= 0x63)
                                return Result;
                        }
                    }
                    return Result;
                }
            }
        }
    }
    return Result;
}
char __fastcall BuildHalExportTable(__int64 ImageBase, unsigned int ImageSize, __int64 HalBase)
{
    char Result = 0;
    unsigned int SectionRva = 0;
    unsigned int SectionVa = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
    {
        char SectionName[8];
        strcpy(SectionName, ".rdata");
        SectionName[7] = 0;
        SectionVa = (unsigned int)FindPESectionByName((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
        SectionRva = (unsigned int)FindPESectionByNameReturnVa((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
        if (SectionRva >= 0x100000)
            SectionRva = 0x100000;
    }
    else
    {
        char SectionName[8];
        strcpy(SectionName, ".data");
        *(_WORD *)&SectionName[6] = 0;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            SectionVa = 200;
            SectionRva = ImageSize;
        }
        else
        {
            SectionVa = (unsigned int)FindPESectionByName((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
            SectionRva = (unsigned int)FindPESectionByNameReturnVa((__int64)ImageBase, (unsigned int)ImageSize, (__int64)SectionName);
            if (SectionRva >= 0x100000)
                SectionRva = 0x100000;
        }
    }

    if (SectionVa && SectionRva && SectionVa < ImageSize && HalBase)
    {
        unsigned __int64 ImageBaseAddr = *(_QWORD *)(*(int *)(ImageBase + 60) + ImageBase + 48);
        _QWORD *SectionPtr = (_QWORD *)(SectionVa + ImageBase);
        unsigned __int64 ScanEnd;
        if (SectionRva + SectionVa >= ImageSize)
            ScanEnd = ImageBase + ImageSize;
        else
            ScanEnd = ImageBase + SectionVa + (unsigned __int64)SectionRva;
        unsigned __int64 ScanLimit = ScanEnd - 72;

        while ((unsigned __int64)SectionPtr < ScanLimit)
        {
            unsigned __int64 ResultVal = *SectionPtr & 0xFFFFFF00FFFFFFFFuLL;
            if (ResultVal == 1212238880)
            {
                SectionPtr++;
                if (*SectionPtr > ImageBaseAddr)
                {
                    unsigned __int64 ImageEndAddr = ImageSize + ImageBaseAddr;
                    if (*SectionPtr < ImageSize + ImageBaseAddr)
                    {
                        ResultVal = SectionPtr[2];
                        if (ResultVal > ImageBaseAddr && ResultVal < ImageEndAddr)
                        {
                            ResultVal = SectionPtr[3];
                            if (ResultVal > ImageBaseAddr && ResultVal < ImageEndAddr)
                            {
                                unsigned int ExportOffset = (unsigned int)(__int64)SectionPtr - (unsigned int)ImageBase - 8;
                                if (ExportOffset && ExportOffset < ImageSize)
                                {
                                    __int64 ExportOffsetCopy = ExportOffset;
                                    GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField25), ExportOffset + HalBase);
                                    unsigned __int64 *ExportTablePtr = (unsigned __int64 *)(ExportOffsetCopy + ImageBase);
                                    unsigned __int64 *EntryPtr;

                                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
                                    {
                                        EntryPtr = ExportTablePtr + 19;
                                    }
                                    else
                                    {
                                        EntryPtr = ExportTablePtr + 4;
                                        while ((unsigned __int64)EntryPtr < ScanLimit)
                                        {
                                            ResultVal = *EntryPtr;
                                            if (*EntryPtr <= ImageBaseAddr)
                                                break;
                                            if (ResultVal >= ImageSize + ImageBaseAddr)
                                                break;
                                            EntryPtr++;
                                        }
                                    }
                                    if ((unsigned __int64)EntryPtr < ScanLimit)
                                    {
                                        unsigned int EntryCount = (unsigned int)(__int64)EntryPtr - (unsigned int)(__int64)ExportTablePtr;
                                        if (EntryCount - 1 <= 0xFFE)
                                        {
                                            if (RelocateExportAddresses(ExportTablePtr, EntryCount, (int)ImageBaseAddr) == 1)
                                                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField26), EntryCount);
                                        }
                                    }
                                    return (char)ResultVal;
                                }
                            }
                        }
                    }
                }
                SectionPtr++;
            }
            else
            {
                SectionPtr++;
            }
        }
    }
    return Result;
}
char __fastcall FindDllInitExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 ModuleLoadBase = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (ModuleLoadBase)
    {
        WORD FuncName[8];
        strcpy((char *)FuncName, "DllInitialize");
        FuncName[7] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, (PULONG)&Value) == 1
            || (strcpy((char *)FuncName, "TdiInitialize"),
                FuncName[7] = 0,
                LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, (PULONG)&Value) == 1))
        {
            if ((_DWORD)Value && (unsigned int)Value < ImageSize)
            {
                GtWrite((enum _GLOBAL_TABLE_INDEX)2052, (unsigned int)Value);
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtPathBuffer01 | 0x800), ModuleLoadBase + (unsigned int)Value);
                return 1;
            }
        }
    }
    return Result;
}
char __fastcall FindNdisMRegisterMiniportExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 ModuleAddress = GtRead(GtEprocessExtField11);
    if (ModuleAddress)
    {
        WORD FuncName[12];
        strcpy((char *)FuncName, "NdisMRegisterMiniport");
        FuncName[11] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, (PULONG)&Value) == 1
            && (_DWORD)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField23, (unsigned int)Value);
            GtWrite(GtEprocessExtField24, ModuleAddress + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}
char __fastcall ParseNdisMiniportDriverName(__int64 ImageBase, unsigned int ImageSize, unsigned int Offset)
{
    __int64 ImageEnd = ImageSize;
    __int64 ModuleAddress = GtRead(GtEprocessExtField11);
    char Result = 0;
    if (ModuleAddress && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770 && Offset && Offset < ImageSize)
    {
        unsigned __int8 *ScanPos = (unsigned __int8 *)(ImageBase + Offset);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            _WORD DecodeResult[24];
            if (!DecodeUnicodeChar(ScanPos, ImageBase + ImageEnd, DecodeResult))
                break;
            ScanPos += *(unsigned int *)((char *)DecodeResult + 24);
            if (*(int *)(*(__int64 *)((char *)DecodeResult + 40)) == 4275)
                break;
            if (*(int *)(*(__int64 *)((char *)DecodeResult + 40)) == 4301)
            {
                unsigned int NameOffset = *(int *)((char *)DecodeResult + 12) + (unsigned int)(ScanPos - (unsigned __int8 *)ImageBase);
                if (NameOffset && NameOffset < ImageSize)
                {
                    GtWrite(GtEprocessExtField25, NameOffset);
                    GtWrite(GtEprocessExtField26, NameOffset + ModuleAddress);
                    return 1;
                }
                return Result;
            }
        }
    }
    return Result;
}
char __fastcall ParseNdisGetVersionSection(unsigned int Rva, __int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    if (Rva && Rva < ImageSize)
    {
        PE_DECODE_CONTEXT ReadContext;   // 0x48 字节解码上下文（原 __int64[8] 仅 64 字节）
        _DWORD SectionEntry[72];
        __int64 CumulativeSize = 0;
        unsigned int Value = 0;
        int Value_4 = 0;
        unsigned int EntryCumulSize = 0;
        __int64 EntryDataPtr = 0;

        InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            CumulativeSize += EntryCumulSize;
            __int16 TypeValue = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (TypeValue == 1349)
                break;
            if ((unsigned __int16)(TypeValue - 1340) <= 7u && SectionEntry[2] == 1 && Value > 0x60000 && !Value_4)
            {
                GtWrite(GtEprocessExtField13, Value);
                return 1;
            }
        }
    }
    return Result;
}
bool __fastcall ReadNtFileForHookTable(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    bool Result = 0;
    void *RawDataBuffer = NULL;
    size_t RawDataSize = 0;
    int EncodedPath[13];
    __int64 EncodedPathExtra = 0;

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
    EncodedPath[10] = 6815836;
    EncodedPath[11] = 7077985;
    EncodedPath[12] = 6553646;
    EncodedPathExtra = 7077996;

    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &RawDataBuffer, (ULONG *)&RawDataSize, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)RawDataBuffer, (ULONG)RawDataSize, (PUCHAR *)pFileBuffer, pFileSize) == 1;
        ExFree(RawDataBuffer);
    }
    return Result;
}// ============================================================
void BuildHookTable(void)
{
    __int64 ImageBase = 0;
    __int64 ExportDirVa = 0;
    unsigned int ExportDirSize = 0;
    unsigned int ExportCount = 0;
    void *ExportRva;

    ImageBase = GtRead(GtNtoskrnlModuleBase);
    ExportDirVa = GtRead(GtEprocessField22);
    ExportDirSize = (unsigned int)GtRead(GtEprocessField23);
    if (ImageBase && ExportDirVa && ExportDirSize)
    {
        ExportCount = (unsigned int)GetExportDirSize(ExportDirVa, ExportDirSize);
        if (ExportCount)
        {
            ExportRva = ExAlloc(PagedPool, 12LL * ExportCount);
            if (ExportRva)
            {
                if ((unsigned int)BuildExportIndexTable(ExportDirVa, ExportDirSize, ExportRva, ExportCount, 0))
                {
                    for (enum _GLOBAL_TABLE_INDEX TableIndex = GtSyscallHashTable; (unsigned int)TableIndex < (GtTotalSize | GtEprocessField114 | 0x400); TableIndex = (enum _GLOBAL_TABLE_INDEX)((int)TableIndex + 3))
                    {
                        int FuncAddress = (int)GtRead(TableIndex);
                        unsigned int ExportOffset = (unsigned int)LookupExportFuncAddr((__int64)ExportRva, ExportCount, FuncAddress);
                        if (ExportOffset)
                        {
                            __int64 ExportAddress = ExportOffset;
                            GtWrite((enum _GLOBAL_TABLE_INDEX)((int)TableIndex + 1), ExportOffset);
                            GtWrite((enum _GLOBAL_TABLE_INDEX)((int)TableIndex + 2), ExportAddress + ImageBase);
                        }
                    }
                }
                ExFree(ExportRva);
            }
        }
    }
}
__int64 InitHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtInitHookSyscallPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x32; ++LoopIndex)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1298 && FieldValue == 0x40000)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)ImageBase;
                    if ((_DWORD)result && (unsigned int)result < ImageSize)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite(GtInitHookSyscallOffset, (unsigned int)result);
                        return GtWrite(GtInitHookSyscallAddress, TargetOffset + BaseAddress);
                    }
                }
            }
        }
    }
    return result;
}
__int64 InstallHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return FindHookTargetInExportWin8(ImageBase, ImageSize, UnusedParam, BaseAddress);
    else
        return FindHookTargetInExportWin7(ImageBase, ImageSize, UnusedParam, BaseAddress);
}
__int64 FindHookTargetInExportWin7(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    /* 【重写 2026-10-19】旧实现把描述符内的槽另立为 `= 0` 且从不赋值的独立局部
       → 全部判据恒假，GT[0x4F]/[0x416E]/[0x416F] 永不写入。
       描述符偏移由 desc_offsets.py 从原始栈偏移换算（描述符基址 rbp-0x70）：
         [rbp+0xa8]→+0x118（类型指针）  [rbp+0x18]→+0x88   [rbp]→+0x70
         [rbp-0x20]→+0x50                [rbp-0x30]→+0x40   [rbp+8]→+0x78
       逐条对照 0x14001C58C–0x14001C729 重写：
         循环 0x100 次；类型 0x545 直接结束；读指针在读取之后推进
         支 A（0x14001C64B..）：类型 0x430 且 (+0x88 & 0x1000000000) 且 ([rbp]==0，即 +0x70==0)
             且 (+0x50 的 bit16)、+0x40 < ImageSize、+0x50 & 0x40、+0x50 & 2、!（+0x50 & 4）
             → 首次：写 GT[0x416E]=+0x40、GT[0x416F]=+0x40+BaseAddress，置 FoundMatch；
               再次：写 GT[0x4F]=BaseAddress + +0x40
         支 B（0x14001C6B3..）：类型 0x512 且 (+0x50 & 0x40) 且 (+0x88 & 0x40)
             且 (+0x88 的 bit16) 且 FoundMatch → 写 GT[0x4F]=BaseAddress + +0x78 */
    char FoundMatch = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];

    /* 原始 0x14001C5BB：入口读 GT[0x416B]，须非 0 且 < ImageSize */
    unsigned int SectionOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x416B);
    if (!SectionOffset || SectionOffset >= ImageSize)
        return 0;

    InitPESectionReadContext(ImageBase + SectionOffset, (ULONG)(ImageSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            return 0;

        /* 原始 0x14001C627/62D：读指针 += Entry[0xF0]（在读取之后） */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

        __int16 SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
        if (SectionType == 0x545)
            return 0;

        ULONG64 ExtraField  = *(ULONG64 *)((PUCHAR)SectionEntry + 0x88);
        ULONG64 FieldValue  = *(ULONG64 *)((PUCHAR)SectionEntry + 0x50);
        ULONG   FieldValue2 = *(ULONG   *)((PUCHAR)SectionEntry + 0x40);
        ULONG64 ZeroField   = *(ULONG64 *)((PUCHAR)SectionEntry + 0x70);
        ULONG   OtherField  = *(ULONG   *)((PUCHAR)SectionEntry + 0x78);

        if (SectionType == 0x430 &&
            (ExtraField & 0x1000000000LL) != 0 &&
            ZeroField == 0 &&
            (FieldValue & 0x10000) != 0 &&
            FieldValue2 < ImageSize &&
            (FieldValue & 0x40) != 0 &&
            (FieldValue & 2) != 0 &&
            (FieldValue & 4) == 0)
        {
            if (FoundMatch)
                return GtWrite((GLOBAL_TABLE_INDEX)0x4F, BaseAddress + FieldValue2);

            GtWrite((GLOBAL_TABLE_INDEX)0x416E, FieldValue2);
            GtWrite((GLOBAL_TABLE_INDEX)0x416F, FieldValue2 + BaseAddress);
            FoundMatch = 1;
        }
        else if (SectionType == 0x512 &&
                 (FieldValue & 0x40) != 0 &&
                 (ExtraField & 0x40) != 0 &&
                 (ExtraField & 0x10000) != 0 &&
                 FoundMatch == 1)
        {
            if (OtherField && OtherField < ImageSize)
                return GtWrite((GLOBAL_TABLE_INDEX)0x4F, BaseAddress + OtherField);
        }
    }
    return 0;
}

__int64 FindHookTargetInExportWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    /* 【重写 2026-10-19】旧实现把描述符内的槽另立为 `=0` 且从不赋值的独立局部，
       且入口宏语义不定 → GT[0x4F]/[0x416E]/[0x416F] 永不写入。
       描述符偏移（desc_offsets.py 换算，基址 rbp-0x70）：
         [rbp+0xa8]→+0x118  [rbp+0x18]→+0x88  [rbp]→+0x70
         [rbp-0x20]→+0x50   [rbp-0x30]→+0x40
       逐条对照 0x14001C72C–0x14001C8A5：
         入口 GT[0x416B]；循环 0x100；读指针在读取之后推进
         构建号 < 0x55F0 时，类型 0x545 立即结束（0x14001C7ED/F4）
         支 A：类型 0x430 且 (+0x88 & 0x1000000000) 且 +0x70 == 0        （0x14001C807..826）
         支 B：类型 0x4DB 且 +0x88 == 0x40                                （0x14001C828..837）
         二者落到同一判据：+0x50 == 0x40000（0x14001C839）
             Candidate = +0x40 - ImageBase + 读指针（0x14001C843..849）
             Candidate > 0x20 且 < ImageSize（0x14001C84D/852）
             若已有首次命中且计数 < 0xA（0x14001C857/85C）→
                 GT[0x416E] = 首次 + 0；GT[0x416F] = 首次 + BaseAddress；
                 GT[0x4F]   = BaseAddress + (Candidate - 0x20)；结束
             否则 首次 = Candidate - 0x20、计数 = 0（0x14001C861/865）；未命中则计数++ */
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    unsigned int FirstMatchOffset = 0;
    unsigned int CountField = 0;

    unsigned int SectionOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x416B);
    if (!SectionOffset || SectionOffset >= ImageSize)
        return 0;

    InitPESectionReadContext(ImageBase + SectionOffset, (ULONG)(ImageSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;

        /* 原始 0x14001C7D1/7DC：读指针 += Entry[0xF0]（读取之后） */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

        __int16 SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x55F0 && SectionType == 0x545)
            break;

        ULONG64 ExtraField = *(ULONG64 *)((PUCHAR)SectionEntry + 0x88);
        ULONG64 ZeroField  = *(ULONG64 *)((PUCHAR)SectionEntry + 0x70);
        ULONG64 FieldValue = *(ULONG64 *)((PUCHAR)SectionEntry + 0x50);
        ULONG   FieldValue2 = *(ULONG  *)((PUCHAR)SectionEntry + 0x40);

        int BranchA = (SectionType == 0x430 && (ExtraField & 0x1000000000LL) != 0 && ZeroField == 0);
        int BranchB = (SectionType == 0x4DB && ExtraField == 0x40);

        if ((BranchA || BranchB) && FieldValue == 0x40000)
        {
            unsigned int Candidate = FieldValue2 - (unsigned int)ImageBase
                                   + (unsigned int)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08);
            if (Candidate > 0x20 && Candidate < ImageSize)
            {
                if (FirstMatchOffset && CountField < 0xA)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x416E, FirstMatchOffset);
                    GtWrite((GLOBAL_TABLE_INDEX)0x416F, FirstMatchOffset + BaseAddress);
                    return GtWrite((GLOBAL_TABLE_INDEX)0x4F, BaseAddress + (Candidate - 0x20));
                }
                FirstMatchOffset = Candidate - 0x20;
                CountField = 0;
            }
            else
            {
                ++CountField;
            }
        }
        else
        {
            ++CountField;
        }
    }
    return 0;
}

__int64 EnableHookProtection(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;

    result = GtRead(GtWindowsBuildNumber);
    if ((unsigned int)result >= 0x1DB0)
        return FindHookTargetDataSection(ImageBase, ImageSize, UnusedParam, BaseAddress);
    return result;
}
__int64 DisableHookProtection(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    /* 【修正 2026-10-19】同族缺陷：EntryFlags/FieldValue/FieldFlags/SectionSize 旧为
       `= 0` 且从不赋值 → 两轮判据恒假 → GT[0x817]/[0x818] 永不写入。
       逐条对照 0x14001CC4C 修正字段绑定：
         第一轮：GT 入口 0x42D9；+0xF0 推进；类型指针 +0x118（`[rbp+0xa8]`）取 [+6]；
                 判 +0x558（0x14001CCF0 `edx=0x558`）；命中取 +0x38（`[rbp-0x38]`）
                 → SectionOffset = 读指针 + (+0x38 - ImageBase)
         第二轮：类型 0x510 或 0x4D7；+0x50 == 0x40000；+0x10（`[rbp+8]`）非 0
                 → TargetOffset = +0x10 - ImageBase + 读指针
                 → 第 1 次命中写 GT[0x817]、第 2 次写 GT[0x818]=BaseAddress+TargetOffset */
    __int64 EntryFlags;
    __int64 FieldValue;
    unsigned int FieldFlags;
    unsigned int SectionSize;

    result = GtRead((GLOBAL_TABLE_INDEX)0x42D9);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        /* 【修正 2026-10-19】原始 0x14001CC89 `mov rbx,rax`：SectionOffset **初值就是
           GT[0x42D9]**，第一段未命中 0x558 时直接沿用该值作第二段起点。
           旧实现让它从 0 开始，第一段不命中就整体跳过第二段 → GT[0x817]/[0x818] 永不写。 */
        SectionOffset = (unsigned int)result;
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;

            /* 原始 0x14001CCE5..CCFF：先取 Entry[0xF0] 累加到读指针，再取类型 */
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 0x558)
            {
                FieldValue = *(unsigned int *)((PUCHAR)SectionEntry + 0x38);
                if (FieldValue)
                {
                    SectionOffset = (unsigned int)(FieldValue - (unsigned int)ImageBase
                                   + (unsigned int)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                    break;
                }
            }
        }
        if (SectionOffset && SectionOffset < ImageSize)
        {
            InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            int MatchCount = 0;
            for (unsigned int i = 0; i < 0x64; ++i)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;

                *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

                __int16 SubType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (SubType != 0x510 && SubType != 0x4D7)
                    continue;

                if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) != 0x40000)   /* [rbp+0x18] → +0x88 */
                    continue;

                FieldFlags = *(unsigned int *)((PUCHAR)SectionEntry + 0x78); /* [rbp+8] → +0x78 */
                if (!FieldFlags)
                    continue;

                unsigned int TargetOffset = (unsigned int)(FieldFlags - (unsigned int)ImageBase
                                             + (unsigned int)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                if (!TargetOffset || TargetOffset >= ImageSize)
                    continue;

                if (++MatchCount == 1)
                {
                    GtWrite(GtDisableHookProtectionAddr1, BaseAddress + TargetOffset);
                }
                else if (MatchCount == 2)
                {
                    return GtWrite(GtDisableHookProtectionAddr2, BaseAddress + TargetOffset);
                }
            }
        }
    }
    return 0;
}
__int64 FindNtOpenThreadTargetWin7(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    /* 【修正 2026-10-16】CumulativeSize 即上下文读指针（原始 ctx+0x08）：由 += 条目[0xF0] 推进 */
    _DWORD SectionEntry[72];
    /* 【修正 2026-10-16】同 FindNtOpenThreadTargetWin8：SectionDataPtr 是描述符 +0x118，
       由 ReadPESectionEntry 填充；原声明为独立局部且从不赋值 → 恒 0 → 扫描永不匹配。 */
#define SectionDataPtr PE_DESC_SECTION_DATA(SectionEntry)

    Result = 0;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField79 | 0x100);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        SectionBase = ImageBase + SectionOffset;
        GtWrite(GtEprocessField28, 0);
        InitPESectionReadContext(SectionBase, (ULONG)(ImageSize + ImageBase - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x46; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                return Result;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && LoopIndex > 6)
            {
                unsigned int TargetOffset = (unsigned int)(ReadContext.ReadPtr + *(_DWORD *)(ReadContext.ReadPtr - 4) - ImageBase);
                if (TargetOffset < MaxOffset)
                    return BaseAddress + TargetOffset;
                return Result;
            }
            ReadContext.ReadPtr += SectionEntry[60];
        }
    }
    return Result;
}
#undef SectionDataPtr
__int64 FindNtOpenThreadTargetWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    /* 【修正 2026-10-16】CumulativeSize 即上下文读指针（原始 ctx+0x08）：由 += 条目[0xF0] 推进 */
    _DWORD SectionEntry[72];
    /* 【修正 2026-10-16】下述"字段"不是独立局部变量：原始把它们**别名**到 SectionEntry
       （0x120 字节指令描述符）的对应偏移，由 ReadPESectionEntry 就地填充。原实现声明为
       独立局部且**从不赋值**（恒为 0）→ 节区扫描永远不匹配 → 本函数返回 0 →
       InitAllHookSubsystems 置 Success=0 → sc start 报错误 31。
       偏移见 PE_INSN_DESCRIPTOR（inc/XPCHunterDrv.h），由原始 sub_14001D300 反汇编逐条推出。 */
#define EntrySize      PE_DESC_ENTRY_SIZE(SectionEntry)
#define FieldValue     PE_DESC_FIELD_VALUE(SectionEntry)
#define FieldSize      PE_DESC_FIELD_SIZE(SectionEntry)
#define FieldValue2    PE_DESC_FIELD_VALUE2(SectionEntry)
#define SectionSize    PE_DESC_SECTION_SIZE(SectionEntry)
#define SectionDataPtr PE_DESC_SECTION_DATA(SectionEntry)

    Result = 0;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField79 | 0x100);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        SectionBase = ImageBase + SectionOffset;
        GtWrite(GtEprocessField28, 0);
        InitPESectionReadContext(SectionBase, (ULONG)(ImageBase + ImageSize - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x46; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                return Result;
            int MatchSize = (int)(SectionSize + ReadContext.ReadPtr);
            ReadContext.ReadPtr += SectionSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && (FieldValue & 0x4000000) != 0)
            {
                if (EntrySize)
                {
                    unsigned int TargetOffset = (unsigned int)(MatchSize + EntrySize - ImageBase);
                    if (TargetOffset && TargetOffset < ImageSize)
                    {
                        ReadContext.ReadPtr = 0;
                        InitPESectionReadContext(ImageBase + TargetOffset, ImageSize - TargetOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
                        for (int LoopIndex2 = 0; LoopIndex2 < 0x46; ++LoopIndex2)
                        {
                            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                                return Result;
                            int MatchSize2 = (int)(SectionSize + ReadContext.ReadPtr);
                            ReadContext.ReadPtr += SectionSize;
                            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1296 && (FieldValue2 & 0x40000) != 0)
                            {
                                unsigned int TargetOffset2 = (unsigned int)(MatchSize2 + FieldSize - ImageBase);
                                if (TargetOffset2 && TargetOffset2 < MaxOffset)
                                    return BaseAddress + TargetOffset2;
                                return Result;
                            }
                        }
                        return Result;
                    }
                }
            }
        }
    }
    return Result;
}
#undef EntrySize
#undef FieldValue
#undef FieldSize
#undef FieldValue2
#undef SectionSize
#undef SectionDataPtr
__int64 UninstallHookSyscall(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 TargetOffset = 0;
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    TargetOffset = 0;
    result = GtRead(GtUninstallHookSyscallPeOffset);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;

            /* 【修正 2026-10-17】原 0x14001C95C..0x14001C9AD：
                 eax = Entry[0xF0]（本条消费长度）
                 rcx = ctx.ReadPtr，随后 **ctx.ReadPtr += eax**（读完即推进）
                 type = *(WORD*)(Entry[0x118] + 6)
               旧实现把 EntryFlags/FieldValue/SectionSize 声明为**从不赋值的普通局部**
               （恒 0）→ 0x558 分支永不成立 → TargetOffset 恒 0 →
               0x545 分支因 `TargetOffset==0` 直接返回，GT[0x2B6]/[0x2B7] 永不写入
               （活体 diff 实测该两槽缺失）。现按原始逐条取值。 */
            ReadContext.ReadPtr += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

            __int16 SubType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (SubType == 0x545)                                     /* 0x14001C97C */
                break;                                                /* → 跳到写块 */
            if (SubType == 0x558                                        /* 0x14001C986 */
                && (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0
                && *(unsigned int *)((PUCHAR)SectionEntry + 0x38) != 0)
            {
                /* ebx = Entry[0x38] - ImageBase + ctx.ReadPtr（原始用推进后的 ReadPtr） */
                TargetOffset = (__int64)((unsigned int)(*(unsigned int *)((PUCHAR)SectionEntry + 0x38)
                                        - (unsigned int)ImageBase
                                        + (unsigned int)ReadContext.ReadPtr));
            }
        }

        /* 写块 0x14001C9B8：仅当 type==0x545 跳出且 TargetOffset 合法时写 0x2B6/0x2B7。
           原始写完后**不 return**，直接落到函数尾（对调用方等价，但更贴合原序）。 */
        {
            __int16 LastSubType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (LastSubType == 0x545 && (unsigned int)TargetOffset != 0
                && (unsigned int)TargetOffset < ImageSize)
            {
                GtWrite(GtUninstallHookResultOffset, TargetOffset);
                GtWrite(GtUninstallHookResultAddr, TargetOffset + BaseAddress);
            }
        }
    }
    return result;
}
char BuildJmpPatchStub(int PatchBase, __int64 TargetAddress, __int64 StubBuffer, unsigned int BufferSize, int Flags)
{
    if (BufferSize >= 0xD && *(_BYTE *)TargetAddress == 72 && *(_BYTE *)(TargetAddress + 1) == 0xFF && *(_BYTE *)(TargetAddress + 2) == 0x37 && *(_BYTE *)(TargetAddress + 7) == 0xCC && *(_BYTE *)(TargetAddress + 8) == 0xCC)
    {
        int OriginalOffset = *(_DWORD *)(TargetAddress + 3);
        *(_WORD *)StubBuffer = 0x8BFF; // -29876
        *(_BYTE *)(StubBuffer + 2) = 21;
        *(_BYTE *)(StubBuffer + 7) = 0xE9; // -23
        *(_DWORD *)(StubBuffer + 3) = OriginalOffset;
        __int64 DisableHookAddr = GtRead(GtDisableHookProtectionAddr1 | 0x100);
        if (DisableHookAddr && Flags)
            *(_DWORD *)(StubBuffer + 8) = Flags + (int)DisableHookAddr - PatchBase - 12;
        else
            *(_DWORD *)(StubBuffer + 8) = 0;
        *(_BYTE *)(StubBuffer + 12) = 0xCC;
        return 1;
    }
    return 0;
}
char InstallSsdtHookForThreadProtect(__int64 pInputEntry)
{
    char Result = 0;
    void (__fastcall *pInitFunc)(_BYTE *, _DWORD *);
    int (__fastcall *pDecodeFunc)(_BYTE *, __int64, _QWORD);
    void (*pCleanupFunc)(void);
    __int64 pSectionBase;
    _DWORD DecodedName[6];
    _BYTE EncodedName[16];
    int SuffixEncoded = 0;
    __int64 SuffixDecoded = 0;
    int Terminator = 0;
    int ActionType = 0;
    __int64 pInitResult;
    __int64 TargetAddress = 0;
    __int64 NewFuncAddr = 0;

    Result = 0;
    pInitFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    pDecodeFunc = (int (__fastcall *)(_BYTE *, __int64, _QWORD))GtRead(GtIoCreateFileFunc);
    pCleanupFunc = (void (*)(void))GtRead(GtCloseHandleFunc);
    pSectionBase = GtRead(GtDriverObjectListHead);
    if (pInitFunc && pDecodeFunc && pCleanupFunc && pSectionBase)
    {
        ActionType = *(_DWORD *)(pInputEntry + 36);
        DecodedName[0] = 4587612;
        DecodedName[1] = 7077993;
        DecodedName[2] = 5439589;
        DecodedName[3] = 7536761;
        DecodedName[4] = 6619252;
        DecodedName[5] = 6029421;
        Terminator = 0;
        if (ActionType == 2)
        {
            SuffixEncoded = 7602254;
            SuffixDecoded = 7536742;
        }
        else if (ActionType == 1)
        {
            SuffixEncoded = 7864421;
            SuffixDecoded = 0x7400610066LL;
        }
        else if (ActionType == 0)
        {
            SuffixEncoded = 6357062;
            SuffixDecoded = 0x61006600740073LL;
            Terminator = 116;
        }
        pInitFunc(EncodedName, DecodedName);
        if (pDecodeFunc(EncodedName, 64, 0) >= 0)
        {
            pInitResult = 0; // [rsp+40h]
            if (pInitResult)
            {
                if (*(_BYTE *)pInputEntry)
                {
                    __int64 pContextBase = *(_QWORD *)(pInitResult + 80);
                    if (!pContextBase)
                        goto LABEL_CLEANUP;
                    if (MmIsAddressValid(*(PVOID *)(pInitResult + 80)) != 1)
                        goto LABEL_CLEANUP;
                    if (MmIsAddressValid((PVOID)(pContextBase + 223)) != 1)
                        goto LABEL_CLEANUP;
                    unsigned int TargetFuncAddr = *(unsigned int *)(pInputEntry + 8);
                    if (TargetFuncAddr >= 0x1B)
                        goto LABEL_CLEANUP;
                    NewFuncAddr = *(_QWORD *)(pInputEntry + 16);
                    TargetAddress = pContextBase + 8 + 8 * TargetFuncAddr;
                }
                else
                {
                    NewFuncAddr = *(_QWORD *)(pInputEntry + 16);
                    if (!NewFuncAddr)
                        goto LABEL_CLEANUP;
                    unsigned int EntryIndex = *(unsigned int *)(pInputEntry + 8);
                    if (EntryIndex > 0x1B)
                        goto LABEL_CLEANUP;
                    TargetAddress = pInitResult + 8 * EntryIndex + 112;
                }
                WritePhysicalMemoryQword(TargetAddress, NewFuncAddr);
LABEL_CLEANUP:
                pCleanupFunc();
                return 1;
            }
        }
    }
    return Result;
}
__int64 HookSyscallNtCreateProcess(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtNtCreateProcessPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1296 && FieldValue == 0x40000)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)ImageBase;
                    if ((_DWORD)result && (unsigned int)result < ImageSize)
                        return GtWrite(GtNtCreateProcessResultAddr, BaseAddress + (unsigned int)result);
                }
            }
        }
    }
    return result;
}
__int64 HookSyscallNtCreateThread(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    /* 下列 6 个"字段"由描述符 SectionEntry 逐轮填充（见循环内注释），不再初始化为 0 */
    __int64 FieldValue;
    int EntryFlags;
    int SectionSize;
    __int64 FieldValue2;
    unsigned int SectionSize2;
    __int64 SectionDataPtr;

    SectionOffset = (unsigned int)GtRead(GtNtCreateThreadPeSectionOffset);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            /* 【重大修正 2026-10-17】以下 6 个"局部变量"在原始驱动里**就是描述符 SectionEntry
               数组内的字段**（原始反汇编 0x14001CF34：SectionSize2=+0xF0、SectionDataPtr=+0x118、
               FieldValue=+0x50、EntryFlags=+0x58、SectionSize=+0x78、FieldValue2=+0x88）。
               旧移植把它们另立为初始化为 0 的独立局部且从不赋值，MSVC/LTCG 据此把
               `*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成**绝对地址 [6]** —— 实机加载即 0x7E 蓝屏。
               现改为每次读取后从描述符取字段（与原始一致）。 */
            SectionSize2   = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            SectionDataPtr = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
            FieldValue     = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x58);
            SectionSize    = *(int *)((PUCHAR)SectionEntry + 0x78);
            FieldValue2    = *(__int64 *)((PUCHAR)SectionEntry + 0x88);
            int MatchSize = (int)(SectionSize2 + CumulativeSize);
            CumulativeSize += SectionSize2;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1245 && FieldValue == 64 && EntryFlags == 1 && FieldValue2 == 0x40000)
            {
                if (SectionSize)
                {
                    unsigned int TargetOffset = (unsigned int)(MatchSize + SectionSize - ImageBase);
                    if (TargetOffset && TargetOffset < ImageSize)
                    {
                        __int64 ResultAddress = BaseAddress + TargetOffset;
                        GtWrite(GtNtCreateThreadResultAddr, ResultAddress);
                        if (!ResultAddress)
                            break;
                        return GtWrite(GtNtCreateThreadHookSuccess, 0);
                    }
                }
            }
        }
    }
    return GtWrite(GtNtCreateThreadHookSuccess, 1);
}
__int64 HookSyscallNtOpenProcess(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    /* 【修正 2026-10-19】同族缺陷：EntryFlags/SectionSize 旧为 `=0` 且从不赋值
       → 判据恒假 → GT[0x909]/[0x90A] 永不写入。
       逐条对照 0x14001D074（描述符基址 rsp+0x90，偏移经 desc_offsets.py 换算）：
         入口 GT[0x439F]（0x14001D098）；循环 0x14 次；读指针在读取之后推进
         类型指针 +0x118（0x14001D115）取 [+6]，判 == 0x558
         命中取 +0x38（0x14001D128）
         TargetOffset = +0x38 - ImageBase + 读指针
         非 0 且 < ImageSize 时：GT[0x909]=TargetOffset、GT[0x90A]=TargetOffset+BaseAddress */
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];

    unsigned int SectionOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x439F);
    if (!SectionOffset || SectionOffset >= ImageSize)
        return 0;

    InitPESectionReadContext(ImageBase + SectionOffset, (ULONG)(ImageSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;

        /* 原始 0x14001D101/112/11D：读指针 += Entry[0xF0]（读取之后） */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

        if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 0x558)
        {
            ULONG FieldValue = *(ULONG *)((PUCHAR)SectionEntry + 0x38);
            if (FieldValue)
            {
                unsigned int TargetOffset = FieldValue - (unsigned int)ImageBase
                                          + (unsigned int)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08);
                if (TargetOffset && TargetOffset < ImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x909, (ULONG64)TargetOffset);
                    return GtWrite((GLOBAL_TABLE_INDEX)0x90A, (ULONG64)TargetOffset + BaseAddress);
                }
            }
        }
    }
    return 0;
}
__int64 HookSyscallNtOpenThread(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        return FindNtOpenThreadTargetWin8(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset);
    else
        return FindNtOpenThreadTargetWin7(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset);
}
__int64 HookSyscallNtOpenKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    unsigned int ResultValue = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    /* 【修正 2026-10-19】旧实现把描述符内的槽另立为 `= 0` 且从不赋值的独立局部
       → 所有条件恒假 → GT[0x63] 永不写入。已按 desc_offsets.py 从原始栈偏移换算
       描述符偏移（基址 rbp-0x70）：[rbp+0x18]→+0x88、[rbp]→+0x70、
       [rbp-0x20]→+0x50、[rbp-0x30]→+0x40、[rbp-0x38]→+0x38、[rbp+0xa8]→+0x118。
       输出：命中写 GT[0x63] = BaseAddress + 目标；收尾恒写 GT[0x68] = 结果值。 */

    ResultValue = -1;
    SectionOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x41BC);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;

            /* 原始 0x14001D55F..570：先取 Entry[0xF0] 累加到读指针，再取字段 */
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

            /* 描述符偏移由 desc_offsets.py 从原始 [rbp±X] 换算（描述符基址 rbp-0x70）：
                 [rbp+0xa8]→+0x118（类型指针）  [rbp+0x18]→+0x88  [rbp]→+0x70
                 [rbp-0x20]→+0x50                [rbp-0x30]→+0x40  [rbp-0x38]→+0x38
               原始 0x14001D568/577/57E：if ((D+0x88 & 0x80000) && D+0x70 == 0x10
                                            && (D+0x50 & 0x10000)) → 结果 = D+0x40 */
            if ((*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) & 0x80000) != 0 &&
                *(ULONG64 *)((PUCHAR)SectionEntry + 0x70) == 0x10 &&
                (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x10000) != 0)
            {
                ResultValue = *(unsigned int *)((PUCHAR)SectionEntry + 0x40);
            }
            /* 原始 0x14001D58D/59E/A8：类型 ∈ {0x558,0x559}（type-0x558 <= 1）
               且 (D+0x50 & 0x4000000)；目标 = D+0x38 - ImageBase + 读指针 */
            else if ((unsigned __int16)(*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) - 0x558) <= 1u &&
                     (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0)
            {
                unsigned int TargetOffset = (unsigned int)(*(unsigned int *)((PUCHAR)SectionEntry + 0x38)
                                             - (unsigned int)ImageBase
                                             + (unsigned int)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                if (TargetOffset && TargetOffset < ImageSize)
                    GtWrite((GLOBAL_TABLE_INDEX)0x63, BaseAddress + TargetOffset);
                break;
            }
        }
    }
    return GtWrite((GLOBAL_TABLE_INDEX)0x68, ResultValue);
}
__int64 HookSyscallNtOpenKeyEx(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int ResultValue = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char FieldValue = 0;
    int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ResultValue = -1;
    SectionOffset = (unsigned int)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField59);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += SectionSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((FieldValue & 0x40) != 0 && !EntryFlags && (FieldValue2 & 0x4000) != 0 && FieldFlags && (FieldValue2 & 0x40) != 0)
            {
                ResultValue = FieldFlags;
                return GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, ResultValue);
            }
        }
    }
    return GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, ResultValue);
}
__int64 HookSyscallNtCreateKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    /* 【修正 2026-10-17】下列"字段"在原始里就是描述符 SectionEntry 的偏移：
         FieldValue  -> +0x50   FieldFlags -> +0x78
         FieldValue2 -> +0x88   EntryFlags -> +0x58（原 `cmp [rsp+0xE8],0`）
         SectionSize -> +0xF0（本条消费长度）
       旧移植把它们另立为 `= 0` 的独立局部且**从不赋值** → MSVC/LTCG 折叠掉条件，
       0x510 分支恒不成立 → GT[0x875]/[0x876] 永不写入（活体 diff 实测缺失）。 */
    result = GtRead(GtTotalSize | GtPathBuffer04 | 0x400);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;

            /* 原始 0x14001D799..0x14001D7B0：先取本条长度并**推进读指针**，再判类型 */
            {
                unsigned int Consumed = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
                CumulativeSize += Consumed;
                ReadContext.ReadPtr += Consumed;
            }

            __int16 SubType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (SubType == 0x545)                                   /* 0x14001D7BE */
                break;
            if (SubType == 0x510                                      /* 0x14001D7C3 */
                && (*(unsigned char *)((PUCHAR)SectionEntry + 0x50) & 0x20) != 0
                && *(unsigned int *)((PUCHAR)SectionEntry + 0x58) == 0
                && (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) & 0x40000) != 0)
            {
                /* 0x14001D7EF：eax = Entry[0x78]（FieldFlags）
                   0x14001D7FA..0x14001D802：v = eax - ImageBase + ctx.ReadPtr；
                   若 v == 0 或 v >= ImageSize 则跳到下一轮 */
                unsigned int v = (unsigned int)(*(unsigned int *)((PUCHAR)SectionEntry + 0x78)
                                                - (unsigned int)ImageBase
                                                + (unsigned int)ReadContext.ReadPtr);
                if (v && v < ImageSize)
                {
                    GtWrite(GtEprocessModuleListOffset | GtPsExitSpecialApcAddr, v);        /* 0x875 */
                    return GtWrite(GtEprocessModuleListOffset | GtExFreeCallBackAddr, v + BaseAddress); /* 0x876 */
                }
            }
        }
    }
    return result;
}
__declspec(noinline) __int64 HookSyscallNtDeleteKey(unsigned __int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    /* 【重写 2026-10-19】旧实现字段偏移/判据多处不符 → GT[0x34E] 永不写入。
       逐条对照 0x14001D850（描述符基址 rsp+0x90，偏移由 desc_offsets.py 换算）：
         入口 GT[0x4393]（0x14001D874）；循环 0x14 次；读指针在读取之后推进
         类型指针 +0x118（0x14001D8FD）取 [+6]
           类型 0x48E → 置 FoundFlag 并继续（0x14001D90E/918）
           类型 0x512 且 (+0x88 & 0x40000) 且 FoundFlag（0x14001D91D..939）
         目标 = [+0x78]（0x14001D93B `movsxd rax,[rsp+0x108]`）+ 读指针（0x14001D943）
         目标 > ImageBase 且 < ImageBase+ImageSize 时
           GT[0x34E] = 目标 + BaseAddress - ImageBase（0x14001D950..95C） */
    char FoundFlag = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];

    unsigned int SectionOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x4393);
    if (!SectionOffset || SectionOffset >= ImageSize)
        return 0;

    /* 【修正 2026-10-19】原始 0x14001D898..8AB 的窗口是
           end = min(ImageBase+ImageSize, SectionStart + 0x1000)   （0x14001D8A1 cmova）
       旧实现直接用 `ImageSize - SectionOffset`（无 0x1000 上限），
       解码会扫过远超原始的字节流 → 类型序列不同 → GT[0x34E] 不写。 */
    {
        ULONG64 SectionStart = ImageBase + SectionOffset;
        ULONG64 BufferEnd    = ImageBase + (ULONG64)ImageSize;
        ULONG64 WindowEnd    = SectionStart + 0x1000;
        if (WindowEnd > BufferEnd) WindowEnd = BufferEnd;
        InitPESectionReadContext((__int64)SectionStart, (ULONG)(WindowEnd - SectionStart),
                                 2, 0, -1, 0, 0, (__int64)&ReadContext);
    }

    /* 【修正 2026-10-19】原始**没有轮次上限**：循环头 0x14001D8D8 无计数器比较，
       所有 continue 都跳回该处，唯一出口是 ReadPESectionEntry 返回非 0
       （0x14001D8EC jne 0x14001D961）。旧实现 `< 0x14` 会在命中 0x48E/0x512
       之前就退出（实测原始要 153 轮才见到 0x48E）→ GT[0x34E] 永不写。 */
    for (;;)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;

        /* 原始 0x14001D8EE/8FA/905：读指针 += Entry[0xF0]（读取之后） */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);

        __int16 SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x48E)
        {
            FoundFlag = 1;
        }
        else if (SectionType == 0x512 &&
                 (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) & 0x40000) != 0 &&
                 FoundFlag)
        {
            unsigned __int64 TargetAddress = (unsigned int)(*(int *)((PUCHAR)SectionEntry + 0x78))
                                           + *(ULONG64 *)((PUCHAR)&ReadContext + 0x08);
            if (TargetAddress > ImageBase && TargetAddress < ImageBase + (unsigned __int64)ImageSize)
                return GtWrite((GLOBAL_TABLE_INDEX)0x34E,
                               (__int64)(TargetAddress + BaseAddress - ImageBase));
        }
    }
    return 0;
}
__int64 HookSyscallNtDeleteValueKey(unsigned __int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Value[3];

    Value[0] = 0;
    Value[1] = 0;
    Value[2] = 0;
    if ((unsigned int)GtRead(GtEprocessField28) == 1)
    {
        FindDeleteValueKeyTarget(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset, Value);
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
    {
        ScanRegValueBodyForRef(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset, Value);
    }
    else
    {
        GetDeleteValueKeyCtx(Value);
    }
    return GtWrite(GtEprocessField60, Value[0]);
}
__int64 HookSyscallNtSetValueKey(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Value = 0;
    __int64 ResultArray[2];

    Value = 0;
    ResultArray[0] = 0;
    ResultArray[1] = 0;
    if ((unsigned int)GtRead(GtEprocessField28) == 1)
    {
        FindSetValueKeyTargets(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset, &Value, ResultArray);
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
    {
        FindSetValueKeyTarget(ImageBase, ImageSize, UnusedParam, BaseAddress, MaxOffset, &Value, ResultArray);
    }
    else
    {
        GetSetValueKeyCtx(&Value, ResultArray);
    }
    GtWrite(GtEprocessField58, Value);
    return GtWrite(GtEprocessField59, ResultArray[0]);
}
__int16 HookSyscallNtRenameKey(__int64 TargetAddress, unsigned int Flags, __int64 Context, unsigned __int64 MaxOffset)
{
    unsigned int Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
    {
        Result = (unsigned int)GtRead(GtWindowsBuildNumber);
        if (Result < 0x4563)
            return (__int16)FindNtRenameKeyTarget(TargetAddress, Flags, Context, MaxOffset);
    }
    else
    {
        return (__int16)FindRenameKeyTargetEx(TargetAddress, Flags, Context, MaxOffset);
    }
    return (__int16)Result;
}
__int64 HookSyscallNtCreateFile(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    __int64 Result = 0;
    Result = GtRead(GtNtCreateFileSyscallOffset);
    if ((_DWORD)Result)
    {
        Result = ResolveSyscallToAddress((unsigned int)Result);
        if ((_DWORD)Result && (unsigned int)Result < TargetSize)
        {
            unsigned int SyscallOffset = (unsigned int)Result;
            GtWrite(GtNtCreateFileSyscallResult, (unsigned int)Result);
            GtWrite(GtNtCreateFileSyscallAddress, SyscallOffset + RelocBase);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
            {
                Result = GtRead(GtWindowsBuildNumber);
                if ((unsigned int)Result < 0x2800)
                    return ResolveCreateFileRelocs(TargetBase, TargetSize, Context, RelocBase);
            }
            else
            {
                return FixCreateFileRelocs(TargetBase, TargetSize, Context, RelocBase);
            }
        }
    }
    return Result;
}
__int64 HookSyscallNtOpenFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField118 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField36, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField36, ResultOffset);
}
__int64 HookSyscallNtReadFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField130 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField43, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField43, ResultOffset);
}
__int64 HookSyscallNtWriteFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    int MatchOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    int EntrySize = 0;
    __int64 SectionType = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    MatchOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtNtWriteFilePeSectionOffset);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
            {
                if (MatchOffset != -1)
                    ResultOffset = MatchOffset;
                return GtWrite(GtEprocessField34, ResultOffset);
            }
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0)
            {
                MatchOffset = EntrySize;
            }
        }
    }
    return GtWrite(GtEprocessField34, ResultOffset);
}
__int64 HookSyscallNtClose(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField124 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField38, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField38, ResultOffset);
}
__int64 HookSyscallNtDuplicateObject(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtNtDuplicateObjectPeSectionOffset);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField37, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField37, ResultOffset);
}
__int64 HookSyscallNtQuerySystemInfo(unsigned __int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    /* 对应原始驱动 sub_14001FF5C（0x140 字节）。反汇编逐条核对（desc_offsets 确认
       描述符基址 = rbp-0x70，下列偏移均相对描述符）：
         0x14001FF86  GT[0x4393]（节区偏移）非零且 < TargetSize，否则整个函数返回
         0x14001FFA1..FFBF  窗口终点 = min(Base+Size, ScanStart+0x1000)（cmova）
         0x14001FFEC..FFF5  解码循环：**先** ReadPESectionEntry，**后**推进 +0xF0
         0x140020020..038   类型 0x50E 且 +0x50 bit14 且 +0x40 == 0x10 → FoundMarker=1
         0x140020044..05E   类型 0x510 且 FoundMarker==1 且 +0x88 bit18 且 +0x50 == 0x40
         0x140020060..06F   候选 = (int)+0x78 + 读指针；须在 (TargetBase, BufferEnd) 内
         0x14002007D..081   GT[0x2D3] = 候选 + (RelocBase - TargetBase)
       旧实现三处偏差：推进在解码前（首轮读垃圾）、判据字段全是「声明后从不赋值」
       的局部（恒 0）、候选用 CumulativeSize+EntrySize 而非 (int)+0x78 + 读指针。 */
    __int64 Result;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    ULONG64 BufferEnd;
    ULONG64 ScanStart;
    ULONG64 ScanEnd;
    char FoundMarker = 0;

    Result = GtRead(GtNtDeleteKeyPeSectionOffset);              /* 0x14001FF86 */
    if ((unsigned int)Result == 0 || (unsigned int)Result >= TargetSize)
        return Result;

    BufferEnd = TargetBase + (ULONG64)TargetSize;              /* 0x14001FFAC add r14,rdi */
    ScanStart = TargetBase + (unsigned int)Result;             /* 0x14001FFAF add rcx,rdi */
    ScanEnd   = ScanStart + 0x1000;                            /* 0x14001FFB5 */
    if (BufferEnd < ScanEnd) ScanEnd = BufferEnd;              /* 0x14001FFBF cmova */

    InitPESectionReadContext((__int64)ScanStart, (ULONG)(ScanEnd - ScanStart),
                             2, 0, -1, 0, 0, (__int64)&ReadContext);
    for (;;)
    {
        USHORT Type;
        ULONG64 ReadPtr;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry) != 0)
            break;                                             /* 0x14001FFFC jne → 收尾 */
        ReadPtr = *(ULONG64 *)((PUCHAR)&ReadContext + 0x08)
                + (ULONG64)*(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) = ReadPtr;   /* 0x14002000D..017 */

        Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
        if (Type == 0x50E)                                     /* 0x140020020..03D */
        {
            if ((*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000) != 0 &&
                *(ULONG *)((PUCHAR)SectionEntry + 0x40) == 0x10)
                FoundMarker = 1;
            continue;
        }
        if (Type != 0x510)                                     /* 0x14002003F..047 */
            continue;
        if (FoundMarker != 1)                                  /* 0x140020049..04D */
            continue;
        if ((*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) & 0x40000) == 0 ||   /* 0x14002004F..057 */
            *(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40)              /* 0x140020059..05E */
            continue;

        {
            /* 0x140020060: movsxd rax,dword[rbp+8] → +0x78；符号扩展后加读指针 */
            LONG64 Candidate = (LONG64)*(int *)((PUCHAR)SectionEntry + 0x78) + (LONG64)ReadPtr;
            if ((ULONG64)Candidate <= TargetBase)              /* 0x140020067 jbe */
                continue;
            if ((ULONG64)Candidate >= BufferEnd)               /* 0x14002006F jae */
                continue;
            /* 0x140020075 sub rbx,rdi；0x14002007D lea rdx,[rax+rbx] */
            return GtWrite(GtCallbackField08,
                           (__int64)((ULONG64)Candidate + ((ULONG64)RelocBase - TargetBase)));
        }
    }
    return Result;
}
__int64 HookSyscallNtQueryInformationProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType2 = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtNtCreateThreadPeSectionOffset | GtEprocessField20);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            __int16 SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (SectionType == 1349)
                break;
            if (SectionType == 1296 && (SectionFlags & 0x40) != 0 && (SectionType2 & 0x14000) != 0 && EntrySize)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField35 | 0x800, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField35 | 0x800, ResultOffset);
}
__int64 HookSyscallNtSetInformationProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField112 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField33, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField33, ResultOffset);
}
__int64 HookSyscallNtQueryInformationThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField82 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if (((SectionFlags & 8) != 0 && !EntryFlags || (SectionFlags & 0x20) != 0 && !EntryFlags) && (SectionType & 0x10000) != 0 && EntrySize)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtSdstServiceCount, ResultOffset);
            }
        }
    }
    return GtWrite(GtSdstServiceCount, ResultOffset);
}
__int64 HookSyscallNtSetInformationThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtPeSectionEndVa3 | 0x100);   /* 【修正 2026-10-16】原写 GtEprocessField115(=0x73) 得 0x4173（哈希槽），原始为 0x417D */
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 8) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField35, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField35, ResultOffset);
}
__int64 HookSyscallNtSuspendProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtPeCodeDataSectionVa | 0x100);   /* 【修正 2026-10-16】原写 GtEprocessField109(=0x6D) 得 0x416D（哈希槽），原始为 0x4177 */
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField32, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField32, ResultOffset);
}
__int64 HookSyscallNtResumeProcess(void)
{
    int BaseOffset = 0;
    int ResultOffset = 0;

    BaseOffset = (int)GtRead(GtEprocessField32);
    if (BaseOffset == -1)
        goto LABEL_SET;
    ResultOffset = BaseOffset - 8;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2195)
        ResultOffset -= 8;
    if (ResultOffset < 0)
LABEL_SET:
        ResultOffset = -1;
    return GtWrite(GtEprocessField31, (unsigned int)ResultOffset);
}
__int64 HookSyscallNtSuspendThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField136 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField51, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField51, ResultOffset);
}
__int64 HookSyscallNtResumeThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField139 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtProcessOffset, ResultOffset);
            }
        }
    }
    return GtWrite(GtProcessOffset, ResultOffset);
}
__int64 HookSyscallNtOpenProcessToken(__int64 TargetAddress, unsigned int TargetSize)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4F7C)
        return FindOpenProcessTokenTarget(TargetAddress, TargetSize);
    else
        return FindOpenProcessTokenOffset(TargetAddress, TargetSize);
}
__int64 HookSyscallNtOpenThreadToken(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField106 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtEprocessField30, ResultOffset);
            }
        }
    }
    return GtWrite(GtEprocessField30, ResultOffset);
}
__int64 HookSyscallNtCreateToken(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    int EntryField = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = (unsigned int)GtRead(GtNtWriteFilePeSectionOffset | GtPathBuffer02);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1349)
                break;
            if ((SectionFlags & 0x40) != 0 && !EntryFlags && (SectionType & 0x10000) != 0 && EntrySize && (SectionType & 0x40) != 0 && EntryField == 1)
            {
                ResultOffset = EntrySize;
                return GtWrite(GtProcessEprocess, ResultOffset);
            }
        }
    }
    return GtWrite(GtProcessEprocess, ResultOffset);
}
__int64 HookSyscallNtLoadDriver(__int64 TargetBase, signed int TargetSize, __int64 Context, __int64 RelocBase)
{
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    signed int EntrySize = 0;
    __int64 SectionFlags = 0;
    signed int EntrySize2 = 0;
    __int64 SectionType2 = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;
    unsigned int SectionOffset1 = 0;
    unsigned int SectionOffset2 = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x3FAB)
    {
        SectionOffset1 = (unsigned int)GtRead(GtTotalSize | GtKernelDataField44 | GtPathBuffer00);
        SectionOffset2 = (unsigned int)GtRead(GtTotalSize | GtEprocessExtField58 | GtPathBuffer02);
        if (SectionOffset1 && SectionOffset1 < (unsigned int)TargetSize)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(TargetBase + SectionOffset1, TargetSize - SectionOffset1, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (int Phase1Index = 0; Phase1Index < 0xA; ++Phase1Index)
            {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                int CurrentOffset1 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1141 && (SectionFlags & 0x40000) != 0 && EntrySize < TargetSize)
                {
                    unsigned int MatchOffset1 = (unsigned int)(CurrentOffset1 + EntrySize - TargetBase);
                    if (MatchOffset1 && MatchOffset1 < (unsigned int)TargetSize)
                    {
                        __int64 Phase1Result = MatchOffset1;
                        GtWrite(GtKernelDataField33, MatchOffset1);
                        GtWrite(GtKernelDataField34, Phase1Result + RelocBase);
                    }
                    break;
                }
            }
        }
        if (SectionOffset2 && SectionOffset2 < (unsigned int)TargetSize)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(TargetBase + SectionOffset2, TargetSize - SectionOffset2, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (int Phase2Index = 0; Phase2Index < 0xA; ++Phase2Index)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                int CurrentOffset2 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1296 && (SectionFlags & 0x40) != 0 && (SectionType2 & 0x40000) != 0 && EntrySize2 < TargetSize)
                {
                    unsigned int MatchOffset2 = (unsigned int)(CurrentOffset2 + EntrySize2 - TargetBase);
                    if (MatchOffset2 && MatchOffset2 < (unsigned int)TargetSize)
                    {
                        __int64 Phase2Result = MatchOffset2;
                        GtWrite(GtCallbackField104, MatchOffset2);
                        GtWrite(GtCallbackField105, Phase2Result + RelocBase);
                    }
                    break;
                }
            }
        }
    }
    GtWrite(GtKernelDataField23, 0);
    GtWrite(GtIopfCompleteRequestAddr, 0);
    GtWrite(GtCallbackField106, 0);
    return GtWrite(GtIopfCallDriverAddr, 0);
}

// =========================================================================
// ParseSyscallFileExportSections — 解析系统调用驱动文件的导出节区
// 对应原始驱动 0x14003D7F4（819 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（130 行伪代码），按伪代码实现。
// 【参数】PeBase = 文件缓冲；PeSize = 文件大小；OutTable = 0x30 字节/项的输出表
// 【描述符字段（与同族解析器一致，已由权威映射核对）】
//   +0x38 段1 RVA 字段 / +0x40 1294 槽偏移 / +0x50 ==64 判据 / +0x58 Dst 写索引
//   +0x78 1298 RVA / +0x88 Flags / +0x90 Dst 读索引 / +0xDC ExtraFlags
//   +0xF0 指令长度 / +0x118 类型指针
// 【与同族（ParseCallbackFunctionSections 等）的差异】
//   1) 本函数的 SectionBase 来自 GtRead(GT 0x317)，不是参数；
//   2) 段2 多一个 **槽早退** 机制：首次命中后开始计数，超过 0x28 即跳出
//      （即最多填 40 个槽位）；
//   3) 命中时不检查 OutTable 槽是否已占用之外的额外条件，返回 IsReady。
// =========================================================================
char __fastcall ParseSyscallFileExportSections(__int64 PeBase, unsigned int PeSize, __int64 OutTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 InitSectionRva;
    char FoundFlag;
    int ScanCount;
    char SlotFound;
    int SlotCount;
    PE_DECODE_CONTEXT PESectionContext;
    __int64 ContextOffset = 0;
    _DWORD SectionEntry[112];
    __int64 SectionBase;
    char IsReady = 0;

    PeOffset = *(int *)(PeBase + 60);
    SectionBase = GtRead(GtCallbackField70);
    if (!SectionBase)
        return Result;

    InitSectionRva = *(unsigned int *)(PeOffset + PeBase + 40);
    if ((unsigned int)InitSectionRva >= PeSize)
        return Result;
    if ((int)InitSectionRva + 4096 >= (int)PeSize)
        return Result;

    // ---- 段 1：定位目标节（上限 0x14）----
    FoundFlag = 0;
    InitPESectionReadContext(PeBase + InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    ScanCount = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
    {
        *(ULONG64 *)((PUCHAR)&PESectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
        ULONG CurrentRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
        ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 TypeValue = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        ULONG TargetRva;

        if (TypeValue == 1369)
        {
            TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)PeBase;
            if (TargetRva && TargetRva < PeSize)
            {
                InitSectionRva = TargetRva;
                break;
            }
        }
        else if (TypeValue == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            FoundFlag = 1;
        }
        else if (TypeValue == 1368)
        {
            if (FoundFlag == 1)
            {
                TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)PeBase;
                if (TargetRva && TargetRva < PeSize)
                {
                    InitSectionRva = TargetRva;
                    break;
                }
            }
            FoundFlag = 0;
        }
        if ((unsigned int)++ScanCount >= 0x14)
            break;
    }

    if ((unsigned int)InitSectionRva >= PeSize)
        return Result;
    if ((int)InitSectionRva + 4096 >= (int)PeSize)
        return Result;

    // ---- 段 2：填表（上限 0x3E8；首次命中后槽计数超 0x28 早退）----
    {
        _DWORD Dst[16];
        InitPESectionReadContext(PeBase + (unsigned int)InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
        memset(Dst, 0, sizeof(Dst));
        SlotFound = 0;
        SlotCount = 0;

        for (ULONG i = 0; i < 0x3E8; i++)
        {
            *(ULONG64 *)((PUCHAR)&PESectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            __int16 TypeValue2;
            ULONG SizeValue;
            ULONG RvaField;
            ULONG FlagsField;
            ULONG IndexField;
            ULONG ExtraFlags;
            ULONG EntryOffsetVal;

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
                break;

            {
                ULONG EntryRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
                ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);

                if (SlotFound == 1 && (unsigned int)++SlotCount > 0x28)
                    break;

                SizeValue     = *(ULONG *)((char *)SectionEntry + 0x50);
                TypeValue2    = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
                RvaField      = *(ULONG *)((char *)SectionEntry + 0x78);
                FlagsField    = *(ULONG *)((char *)SectionEntry + 0x88);
                IndexField    = *(ULONG *)((char *)SectionEntry + 0x90);
                ExtraFlags    = *(ULONG *)((char *)SectionEntry + 0xDC);
                EntryOffsetVal= *(ULONG *)((char *)SectionEntry + 0x40);

                if (TypeValue2 == 1298 && FlagsField == 0x40000)
                {
                    if (RvaField && SizeValue == 64)
                    {
                        ULONG v = EntryRva + RvaField - (ULONG)PeBase;
                        if (v && v < PeSize)
                            Dst[*(ULONG *)((char *)SectionEntry + 0x58)] = v;
                    }
                }
                if (TypeValue2 == 1139)
                    memset(Dst, 0, sizeof(Dst));

                if (TypeValue2 == 1294 &&
                    (SizeValue & 0x14000) && (SizeValue & 0x40) &&
                    (ExtraFlags & 0xF) != 4 && FlagsField == 64 &&
                    (EntryOffsetVal - 112) <= 0xD8 && (EntryOffsetVal & 7) == 0)
                {
                    ULONG SlotIndex = (EntryOffsetVal - 112) >> 3;
                    if (SlotIndex <= 0x1B)
                    {
                        ULONG DstRva = Dst[IndexField];
                        if (DstRva && !*(_DWORD *)(OutTable + 48 * SlotIndex + 4))
                        {
                            SlotFound = 1;
                            *(_DWORD *)(OutTable + 48 * SlotIndex + 4) = DstRva;
                            IsReady = 1;
                            *(_QWORD *)(OutTable + 48 * SlotIndex + 8) = SectionBase + DstRva;
                        }
                    }
                }
            }
        }
        return IsReady;
    }
}

// =========================================================================
// ParseShadowSyscallExportSections — 解析 Shadow SSDT 导出节区
// 对应原始驱动 0x14003D034（781 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（130 行伪代码），按伪代码实现。
// 【与 ParseNtFileForCallbackContext **完全同构**（逐句对比确认）】
//   同一两段扫描（段1 上限 0x14 定位目标节；段2 上限 0x3E8 填槽）、
//   同样的类型码 1369/1296/1368/1298/1349/1139/1294、
//   同样的 1349 提前 break、同样的槽步长 48、同样的 Dst 索引与判据。
//   唯一差异：NtoskrnlBase 取自 GtCallbackField13（回调上下文版取复合名）。
// 【参数】pFileBuffer / FileSize / pExportTable（0x30 字节/项）
// 【描述符字段】与本会话确立的权威映射一致：
//   +0x38 段1 RVA / +0x40 1294 槽偏移 / +0x50 ==64 / +0x58 Dst 写索引
//   +0x78 1298 RVA / +0x88 Flags / +0x90 Dst 读索引 / +0xDC ExtraFlags
//   +0xF0 指令长度 / +0x118 类型指针
// =========================================================================
char __fastcall ParseShadowSyscallExportSections(__int64 pFileBuffer, unsigned int FileSize, __int64 pExportTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 NtoskrnlBase;
    ULONG CurrentRva;
    char IsTargetSection = 0;
    int SectionIndex;
    PE_DECODE_CONTEXT SectionContext;
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD SlotAddresses[16];

    PeOffset = *(int *)(pFileBuffer + 60);
    NtoskrnlBase = GtRead(GtCallbackField13);
    if (!NtoskrnlBase)
        return Result;

    CurrentRva = *(ULONG *)(PeOffset + pFileBuffer + 40);
    if (CurrentRva >= FileSize || (int)CurrentRva + 4096 >= (int)FileSize)
        return Result;

    // ---- 段 1：定位目标节（上限 0x14）----
    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
        ULONG ComputedOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        ULONG SectionRva;

        if (SectionType == 1369)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
            if (SectionRva && SectionRva < FileSize)
            {
                CurrentRva = SectionRva;
                break;
            }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            IsTargetSection = 1;
        }
        else if (SectionType == 1368)
        {
            if (IsTargetSection == 1)
            {
                SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
                if (SectionRva && SectionRva < FileSize)
                {
                    CurrentRva = SectionRva;
                    break;
                }
            }
            IsTargetSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14)
            break;
    }

    if (CurrentRva >= FileSize || (int)CurrentRva + 4096 >= (int)FileSize)
        return Result;

    // ---- 段 2：填槽（上限 0x3E8，遇 1349 提前结束）----
    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    memset(SlotAddresses, 0, sizeof(SlotAddresses));

    for (ULONG SectionIndex2 = 0; SectionIndex2 < 0x3E8; SectionIndex2++)
    {
        ULONG ComputedOffset2;
        __int16 SectionType2;
        ULONG SectionFlags;
        ULONG FieldValueSize;
        ULONG FieldFlags;
        ULONG FieldMiscFlags;
        ULONG FieldOffset;
        ULONG SectionDataSize;
        ULONG SlotFieldIndex;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;

        ComputedOffset2 = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        if (SectionType2 == 1349)
            break;

        FieldValueSize   = *(ULONG *)((char *)SectionEntry + 0x50);
        SectionFlags     = *(ULONG *)((char *)SectionEntry + 0x50);
        FieldFlags       = *(ULONG *)((char *)SectionEntry + 0x88);
        FieldMiscFlags   = *(ULONG *)((char *)SectionEntry + 0xDC);
        FieldOffset      = *(ULONG *)((char *)SectionEntry + 0x40);
        SectionDataSize  = *(ULONG *)((char *)SectionEntry + 0x78);
        SlotFieldIndex   = *(ULONG *)((char *)SectionEntry + 0x90);

        if (SectionType2 == 1298 && FieldFlags == 0x40000)
        {
            if (SectionDataSize && FieldValueSize == 64)
            {
                ULONG EntryRva = ComputedOffset2 + SectionDataSize - (ULONG)pFileBuffer;
                if (EntryRva && EntryRva < FileSize)
                    SlotAddresses[*(ULONG *)((char *)SectionEntry + 0x58)] = EntryRva;
            }
        }
        if (SectionType2 == 1139)
            memset(SlotAddresses, 0, sizeof(SlotAddresses));

        if (SectionType2 == 1294 &&
            (SectionFlags & 0x14000) && (SectionFlags & 0x40) &&
            (FieldMiscFlags & 0xF) != 4 && FieldFlags == 64 &&
            (FieldOffset - 112) <= 0xD8 && (FieldOffset & 7) == 0)
        {
            ULONG SlotIndex = (FieldOffset - 112) >> 3;
            if (SlotIndex <= 0x1B)
            {
                ULONG TargetRva = SlotAddresses[SlotFieldIndex];
                if (TargetRva && !*(_DWORD *)(pExportTable + 48 * SlotIndex + 4))
                {
                    Result = 1;
                    *(_DWORD *)(pExportTable + 48 * SlotIndex + 4) = TargetRva;
                    *(_QWORD *)(pExportTable + 48 * SlotIndex + 8) = NtoskrnlBase + TargetRva;
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// ParseStorPortExportSections — 解析 StorPort 驱动文件的导出节区
// 对应原始驱动 0x140050774（842 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写，
//   并用 capstone 原始字节复核栈帧与字段偏移（见下）。
// 【调用者】ParseStorPortExportDir（0x140050578）在 ReadDiskPortDriverFile 读到
//   storport.sys 后调用本函数填 0x30 字节/项的导出表；成功后再调
//   ParseNtExportDir 做重定位、循环 29 项回填节头。
// 【GT 依据】寄存器跟踪提取：只读 0x309（GtCallbackField59 = storport.sys 基址）。
// 【参数】PeBase = 文件缓冲；PeSize = 文件大小；pExportTable = 0x30 字节/项输出表。
// 【字段映射】栈帧定案：上下文 = [rsp+50h]（+0x08 读指针 = [rsp+58h]），
//   描述符 = [rsp+A0h]（0x120 字节，对齐后）。故描述符字段为
//   +0x38 +0x40 +0x50 +0x58 +0x78 +0x88 +0xF0 +0x118（与同族解析器一致）。
//   ① IDA 栈帧：v26=[rsp+E0h]=+0x40（1294 槽偏移字段）、v27=[rsp+F0h]=+0x50、
//      v28=[rsp+F8h]=+0x58、v29=[rsp+118h]=+0x78、v30=[rsp+128h]=+0x88、
//      v31=[rsp+130h]=+0x90、v32=[rsp+17Ch]=+0xDC、v33=[rsp+190h]=+0xF0、
//      v34=[rsp+1B8h]=+0x118。
//   ② capstone：`cmp qword ptr [rbp-0x10], 0x40`（+0x50）、
//      `cmp qword ptr [rbp+0x28], 0x40000`（+0x88）、
//      `mov eax, dword ptr [rbp+0x7c]`（+0xDC）、
//      `mov r8d, dword ptr [rbp+rax*4+0xe0]`（Dst 数组，基址 = rbp+0xE0）。
// 【算法】三段：
//   段 1（上限 0x12C）：读条目；类型 1296 且 字段+0x50==64 时连续计数 v8，
//     一旦 >= 4 则 v9=1；非 1296 时 v8=0，且若 v9==1：类型 1368 → 由
//     字段+0x38（v25[14] = 描述符 +0x38）算 RVA(v13) 并进入段 2；否则 v9=0；
//   段 2（上限 0xC8）：读条目；类型 1349 → break；v17 = 字段+0x50；
//     类型 1298 且 字段+0x88==0x40000 且 字段+0x78 非零 且 字段+0x50==64 →
//       算 RVA(v18) 存 Dst[字段+0x90]；
//     类型 1139 或 1368 → 清空 Dst；
//     类型 1294 且 (v17 & 0x14000) 且 (v17 & 0x40) 且 (字段+0xDC & 0xF)!=4
//       且 字段+0x88==64 且 (字段+0x40-112)<=0xD8 且 (字段+0x40 & 7)==0 →
//       槽索引 = (字段+0x40-112)>>3；若 <= 0x1B 且 Dst[字段+0x90] 非零
//       且 pExportTable 对应槽 +4 为空 → 置已用、写 +4=RVA、+8=基址+RVA，
//       Result=1。
// 【返回值】Result（0 未命中；1 命中至少一项）。
// =========================================================================
char __fastcall ParseStorPortExportSections(__int64 PeBase, unsigned int PeSize, __int64 pExportTable)
{
    char    Result = 0;
    __int64 StorportBase;
    ULONG   ExportRva;
    int     RunCount;           // v8：类型 1296 连续计数
    char    Armed;              // v9：连续计数 >= 4 后的置位标志
    int     OuterCount;         // v10：段 1 循环计数
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];         // 描述符：0x120 字节
    _DWORD  Dst[16];            // 段 2 的中间槽数组
    char    NameBuf[32];

    StorportBase = (__int64)GtRead(GtCallbackField59);            // 0x1400507B9（0x309）
    if (!StorportBase)
        return Result;

    strcpy(NameBuf, "StorPortInitialize");                        // 0x1400507D6
    NameBuf[19] = 0;                                              // 0x1400507FE

    ExportRva = (ULONG)FindExportByNameInPeBody((PUCHAR)PeBase, PeSize,
                                                NameBuf, 0);      // 0x140050808
    if (!ExportRva)                                               // 0x140050811
        return Result;
    if (ExportRva >= PeSize || ExportRva + 4096 >= PeSize)        // 0x140050827
        return Result;

    /* ---- 段 1（0x14005085F）：定位第 4 个连续 1296 之后的 1368 ---- */
    InitPESectionReadContext(PeBase + ExportRva, 4096,             // 0x14005085F
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    RunCount = 0;                                                 // 0x140050864
    Armed = 0;                                                    // 0x140050866
    for (OuterCount = 0; ; )                                      // 0x140050869
    {
        USHORT Type;
        ULONG  Len, Cumul, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14005087C
            break;

        Len   = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14005088D
        Ctx.ReadPtr += Len;                                       // 0x140050897
        Type  = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14005089C
        F38   = *(ULONG *)((PUCHAR)Entry + 0x38);

        if (Type == 1296 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64)    // 0x1400508AF
        {
            if ((ULONG)(++RunCount) >= 4)                         // 0x1400508B6
                Armed = 1;                                        // 0x1400508BC
        }
        else
        {
            RunCount = 0;                                         // 0x1400508C4
            if (Armed == 1)                                       // 0x1400508CA
            {
                if (Type == 1368)                                 // 0x1400508D8
                {
                    ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;   // 0x1400508E4
                    if (r < PeSize)                               // 0x1400508E8
                    {
                        if (r && r + 4096 < PeSize)               // 0x1400508FE
                        {
                            /* ---- 段 2（0x140050936）：填导出表 ---- */
                            ULONG i;

                            InitPESectionReadContext(PeBase + r, 4096,    // 0x140050936
                                                     2, 0, -1, 0, 0, (__int64)&Ctx);
                            memset(Dst, 0, sizeof(Dst));          // 0x140050948
                            for (i = 0; i < 0xC8; ++i)            // 0x14005094D
                            {
                                USHORT T2;
                                ULONG  L2, C2, F40, F50, F58, F78, F90, FDC, F88;

                                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))  // 0x140050959
                                    break;

                                L2  = *(ULONG *)((PUCHAR)Entry + 0xF0);
                                C2  = L2 + (ULONG)Ctx.ReadPtr;    // 0x140050971
                                Ctx.ReadPtr += L2;                // 0x14005097B
                                T2  = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x140050980
                                if (T2 == 0x545)                  // 0x14005098C（1349）
                                    break;
                                F50 = *(ULONG *)((PUCHAR)Entry + 0x50);   // 0x140050992（v17 = v27）
                                F88 = *(ULONG *)((PUCHAR)Entry + 0x88);   // v30
                                F78 = *(ULONG *)((PUCHAR)Entry + 0x78);   // 0x1400509A8（v29）
                                F58 = *(ULONG *)((PUCHAR)Entry + 0x58);   // v28：1298 的 Dst 写索引
                                F90 = *(ULONG *)((PUCHAR)Entry + 0x90);   // v31：1294 的 Dst 读索引
                                F40 = *(ULONG *)((PUCHAR)Entry + 0x40);   // 0x140050A1C（v26）
                                FDC = *(ULONG *)((PUCHAR)Entry + 0xDC);   // 0x140050A0B（v32）

                                if (T2 == 1298 && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000)  // 0x1400509A8
                                {
                                    if (*(ULONG *)((PUCHAR)Entry + 0x78))          // 0x1400509AF（v29）
                                    {
                                        if (F50 == 64)                     // 0x1400509B5（v27）
                                        {
                                            ULONG r2 = C2 + F78 - (ULONG)(ULONG_PTR)PeBase;  // 0x1400509BA
                                            if (r2 && r2 < PeSize)         // 0x1400509BC/9C0
                                                Dst[F58] = r2;             // 0x1400509C5（Dst[v28]）
                                        }
                                    }
                                }
                                if (T2 == 1139 || T2 == 1368)                  // 0x1400509DE
                                    memset(Dst, 0, sizeof(Dst));               // 0x1400509ED

                                if (T2 == 1294                                    // 0x140050A2F（v26 见下）
                                    && (F50 & 0x14000) != 0                       // v17 & 0x14000
                                    && (F50 & 0x40) != 0
                                    && (FDC & 0xF) != 4
                                    && F88 == 64
                                    && (unsigned int)(F40 - 112) <= 0xD8
                                    && (F40 & 7) == 0)
                                {
                                    ULONG SlotIndex = (F40 - 112) >> 3;       // 0x140050A31
                                    if (SlotIndex <= 0x1B)                    // 0x140050A37
                                    {
                                        ULONG TargetRva = Dst[F90];           // 0x140050A3C
                                        if (TargetRva)                        // 0x140050A47
                                        {
                                            if (!*(_DWORD *)(pExportTable + 48 * SlotIndex + 4))  // 0x140050A50
                                            {
                                                Result = 1;                   // 0x140050A5B
                                                *(_DWORD *)(pExportTable + 48 * SlotIndex + 4) = TargetRva;   // 0x140050A5E
                                                *(_QWORD *)(pExportTable + 48 * SlotIndex + 8) =
                                                    StorportBase + TargetRva;                    // 0x140050A68
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        return Result;                            // 0x140050A77
                    }
                }
                else
                {
                    Armed = 0;                                    // 0x140050AAA
                }
            }
        }
        if ((ULONG)(++OuterCount) >= 0x12C)                       // 0x140050AB7
            return Result;
    }

    return Result;                                                // 0x140050A80
}

// =========================================================================
// ParseWin32kSyscallStubs — 解析 win32k.sys 的系统调用桩
// 对应原始驱动 0x140053B2C（819 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（130 行伪代码），按伪代码实现。
// 【与 ParseSyscallFileExportSections 同构，差异两处】
//   1) SectionBase 取自 GtRead(GtCallbackField81)（不是 GtCallbackField70）；
//   2) 段2 的上限是 0xC8（非 0x3E8），槽早退上限同为 0x28。
// 【参数】FileBuffer / FileSize / pOutputTable（0x30 字节/项）
// 【描述符字段】同权威映射：
//   +0x38 段1 RVA / +0x40 1294 槽偏移 / +0x50 ==64 / +0x58 Dst 写索引
//   +0x78 1298 RVA / +0x88 Flags / +0x90 Dst 读索引 / +0xDC ExtraFlags
//   +0xF0 指令长度 / +0x118 类型指针
// =========================================================================
char __fastcall ParseWin32kSyscallStubs(__int64 FileBuffer, unsigned int FileSize, __int64 pOutputTable)
{
    __int64 PeHeaderOffset;
    char Result = 0;
    __int64 SectionDataRva;
    char FoundSectionEnd;
    int SectionIndex;
    char HasReset;
    int ResetCount;
    char HasValidEntry = 0;
    __int64 SectionBase;
    PE_DECODE_CONTEXT Context;
    __int64 Accumulated = 0;
    _DWORD SectionEntry[112];
    _DWORD Dst[16];

    PeHeaderOffset = *(int *)(FileBuffer + 60);
    SectionBase = GtRead(GtCallbackField81);
    if (!SectionBase)
        return Result;

    SectionDataRva = *(unsigned int *)(PeHeaderOffset + FileBuffer + 40);
    if ((unsigned int)SectionDataRva >= FileSize || (int)SectionDataRva + 4096 >= (int)FileSize)
        return Result;

    // ---- 段 1：定位目标节（上限 0x14）----
    FoundSectionEnd = 0;
    InitPESectionReadContext(FileBuffer + SectionDataRva, 4096, 2, 0, -1, 0, 0, (__int64)&Context);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&Context, (PULONG)SectionEntry))
    {
        *(ULONG64 *)((PUCHAR)&Context + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
        ULONG SectionOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)Accumulated;
        Accumulated += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        ULONG TargetRva;

        if (SectionType == 1369)
        {
            TargetRva = SectionOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)FileBuffer;
            if (TargetRva && TargetRva < FileSize)
            {
                SectionDataRva = TargetRva;
                break;
            }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            FoundSectionEnd = 1;
        }
        else if (SectionType == 1368)
        {
            if (FoundSectionEnd == 1)
            {
                TargetRva = SectionOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)FileBuffer;
                if (TargetRva && TargetRva < FileSize)
                {
                    SectionDataRva = TargetRva;
                    break;
                }
            }
            FoundSectionEnd = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14)
            break;
    }

    if ((unsigned int)SectionDataRva >= FileSize || (int)SectionDataRva + 4096 >= (int)FileSize)
        return Result;

    // ---- 段 2：填表（上限 0xC8；首次命中后槽计数超 0x28 早退）----
    InitPESectionReadContext(FileBuffer + (unsigned int)SectionDataRva, 4096, 2, 0, -1, 0, 0, (__int64)&Context);
    memset(Dst, 0, sizeof(Dst));
    HasReset = 0;
    ResetCount = 0;

    for (ULONG LoopIndex = 0; LoopIndex < 0xC8; LoopIndex++)
    {
            *(ULONG64 *)((PUCHAR)&Context + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        ULONG EntryOffset;
        ULONG SectionFlags;
        __int16 EntryType;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&Context, (PULONG)SectionEntry))
            break;

        EntryOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)Accumulated;
        Accumulated += *(ULONG *)((char *)SectionEntry + 0xF0);
        if (HasReset == 1 && (unsigned int)++ResetCount > 0x28)
            break;

        SectionFlags = *(ULONG *)((char *)SectionEntry + 0x50);
        EntryType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (EntryType == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            ULONG RvaField = *(ULONG *)((char *)SectionEntry + 0x78);
            if (RvaField && *(ULONG *)((char *)SectionEntry + 0x50) == 64)
            {
                ULONG FuncRva = EntryOffset + RvaField - (ULONG)FileBuffer;
                if (FuncRva && FuncRva < FileSize)
                    Dst[*(ULONG *)((char *)SectionEntry + 0x58)] = FuncRva;
            }
        }
        if (EntryType == 1139)
            memset(Dst, 0, sizeof(Dst));

        if (EntryType == 1294 &&
            (SectionFlags & 0x14000) && (SectionFlags & 0x40) &&
            (*(ULONG *)((char *)SectionEntry + 0xDC) & 0xF) != 4 &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
            (*(ULONG *)((char *)SectionEntry + 0x40) - 112) <= 0xD8 &&
            (*(ULONG *)((char *)SectionEntry + 0x40) & 7) == 0)
        {
            ULONG ServiceIndex = (*(ULONG *)((char *)SectionEntry + 0x40) - 112) >> 3;
            if (ServiceIndex <= 0x1B)
            {
                ULONG StubRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                if (StubRva && !*(_DWORD *)(pOutputTable + 48 * ServiceIndex + 4))
                {
                    HasReset = 1;
                    *(_DWORD *)(pOutputTable + 48 * ServiceIndex + 4) = StubRva;
                    HasValidEntry = 1;
                    *(_QWORD *)(pOutputTable + 48 * ServiceIndex + 8) = SectionBase + StubRva;
                }
            }
        }
    }
    return HasValidEntry;
}