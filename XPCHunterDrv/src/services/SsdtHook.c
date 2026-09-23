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

// OpenTcpIpDriverSection — 打开 tcpip.sys 驱动节区
// 对应原始驱动 sub_1400537FC
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
char ParseStorPortExportDir(void)
{
    // 在原始驱动中，ParseStorPortExportDir 实际调用 GetDiskDriverSection 并初始化
    // 这里标记 GT 索引为就绪
    GtWrite(GtCallbackField61, 1);
    return 1;
}
char ParseSyscallFileExportDir(void)
{
    GtWrite(GtCallbackField72, 1);
    return 1;
}
char BuildSyscallExportTable(void)
{
    GtWrite(GtCallbackField80, 1);
    return 1;
}
char InitShadowSyscallExportTable(void)
{
    GtWrite(GtCallbackField15, 1);
    return 1;
}
char InitWin32kSyscallTable(void)
{
    GtWrite(GtCallbackField83, 1);
    return 1;
}
char ParseSyscallTableExportDir(void)
{
    GtWrite(GtDisableHookProtectionAddr2 | GtEprocessField157, 1);
    return 1;
}
char InitDiskQueryExportTable(void)
{
    GtWrite(GtEprocessField135 | 0x100, 1);
    return 1;
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

    // 清零输出表
    if (MaxEntries)
    {
        for (unsigned int i = 0; i < MaxEntries; i++)
            OutTable[12 * i] = 0;
    }

    __int64 PeHeader = *(int *)(PeBase + 60);
    unsigned int ExportDirRva = *(unsigned int *)(PeHeader + PeBase + 136);
    unsigned int ExportDirSize = *(unsigned int *)(PeHeader + PeBase + 140);
    unsigned int AddressOfNames = *(unsigned int *)(PeHeader + PeBase + 140);
    unsigned int AddressOfOrdinals = AddressOfNames + ExportDirSize;

    if (ExportDirRva < PeSize && ExportDirRva + 40 < PeSize
        && ExportDirSize < PeSize && AddressOfOrdinals < PeSize)
    {
        unsigned int NumberOfNames = *(unsigned int *)(ExportDirRva + PeBase + 24);
        unsigned int NumberOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 20);
        unsigned int AddressOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 28);
        unsigned int AddressOfNameOrdinals = *(unsigned int *)(ExportDirRva + PeBase + 32);
        unsigned int AddressOfNamePointers = *(unsigned int *)(ExportDirRva + PeBase + 36);

        if (MaxEntries == NumberOfNames
            && AddressOfFunctions >= ExportDirRva
            && AddressOfFunctions + 4 * NumberOfNames < AddressOfOrdinals
            && 4 * NumberOfNames < ExportDirSize
            && AddressOfNameOrdinals >= ExportDirRva
            && AddressOfNameOrdinals + 2 * NumberOfNames < AddressOfOrdinals
            && AddressOfNamePointers >= ExportDirRva
            && AddressOfNamePointers + 4 * NumberOfFunctions < AddressOfOrdinals
            && 4 * NumberOfFunctions < ExportDirSize)
        {
            unsigned int *pFuncTable = (unsigned int *)(PeBase + AddressOfFunctions);
            unsigned __int16 *pOrdTable = (unsigned __int16 *)(PeBase + AddressOfNameOrdinals);
            __int64 NameTableBase = PeBase + AddressOfNamePointers;

            if (NumberOfNames)
            {
                do
                {
                    unsigned int FuncRva = *pFuncTable;
                    if (FuncRva >= ExportDirRva && FuncRva < AddressOfOrdinals)
                    {
                        unsigned __int16 OrdinalIndex = *pOrdTable;
                        if (OrdinalIndex < NumberOfFunctions)
                        {
                            unsigned int NameRva = *(unsigned int *)(NameTableBase + 4LL * OrdinalIndex);
                            if (NameRva < PeSize && (NameRva < ExportDirRva || NameRva >= AddressOfOrdinals))
                            {
                                char *pName = (char *)(PeBase + FuncRva);
                                if (!FilterFunc || FilterFunc(PeBase + FuncRva) == 1)
                                {
                                    unsigned int HashValue = (unsigned int)Sha1HashToDword(pName);
                                    OutTable[12 * EntryCount] = 1;
                                    *(unsigned int *)&OutTable[12 * EntryCount + 4] = HashValue;
                                    *(unsigned int *)&OutTable[12 * EntryCount + 8] = NameRva;
                                    EntryCount++;
                                }
                            }
                        }
                    }
                    pFuncTable++;
                    pOrdTable++;
                } while (--NumberOfNames);
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
            int SectionEntry = 0;
            unsigned int FieldValue = 0, EntryField = 0;

            InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
            char SectionBaseCopy = 0;
            int LoopIndex = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                    return 0;
                int SectionEnd = (int)(EntryField + CumulativeSize2);
                CumulativeSize2 += EntryField;
                __int16 TargetRva = *(_WORD *)(EntrySize + 6);
                if (TargetRva == 1296 && CumulativeSize == 64 && SectionEntry == 8 && SectionChar == 64)
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
                __int16 SectionType2 = *(_WORD *)(SectionInfoPtr2 + 6);
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
    unsigned int PESectionByName = (unsigned int)FindPESectionByName((PUCHAR)ImageBase, (PCHAR)SectionName);
    unsigned int SectionBaseCopy = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)ImageBase, (PCHAR)SectionName);
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
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            int SectionIndex = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            __int16 SectionOffset = *(_WORD *)(EntryDataPtr + 6);
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
        int SectionEntry = 0;
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
                    if (SectionEntry && CumulativeSize == 64)
                    {
                        unsigned int SectionType2 = (unsigned int)(TargetRva2 + SectionEntry - ImageBase);
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
        __int64 SectionEntry = 0, EntryField = 0, SectionAlignment = 0;
        unsigned int EntrySize = 0;

        InitPESectionReadContext(ImageBase + Found, ImageSize - Found, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        unsigned int SectionEnd = 0;
        unsigned int TargetRva = 0;
        for (unsigned int i = 0; i < 0x32; ++i)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionInfo))
                break;
            int SectionType = (int)(EntrySize + FieldValue2);
            FieldValue2 += EntrySize;
            __int16 SectionType2 = *(_WORD *)(SectionAlignment + 6);
            if (SectionType2 == 1349)
                break;
            if (SectionType2 == 1294 && SectionEntry == 0x40000 && EntryField == 64)
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
        __int64 SectionEntry = 0, EntryField = 0, SectionAlignment = 0;
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
                    if (EntryField == 0x40000 && SectionChar && SectionEntry == 64)
                        SectionEnd = (unsigned int)(TargetRva2 + SectionChar - ImageBase);
                }
                else if (SectionEntry == 0x40000)
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
                unsigned int SectionEnd = (unsigned int)(EntryDataSize + EntryBase);
                EntryBase += EntryDataSize;
                __int16 SectionType = *(_WORD *)(SectionInfoPtr + 6);
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
                unsigned int SectionEnd2 = (unsigned int)(EntryDataSize2 + EntryBase2);
                EntryBase2 += EntryDataSize2;
                __int16 SectionType2 = *(_WORD *)(SectionInfoPtr2 + 6);
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
                __int16 TypeValue = *(_WORD *)(TypePtr + 6);
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
            if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
                break;
            unsigned int CurrentEnd = EntrySize + (unsigned int)EntryBase;
            EntryBase += EntrySize;
            __int16 TypeValue = *(_WORD *)(EntryTypePtr + 6);

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
    __int64 TargetProcess = GtRead(GtEprocessField61);
    __int64 CurrentProcess = (__int64)IoGetCurrentProcess();
    KAPC_STATE ApcState;

    if (TargetProcess != CurrentProcess && TargetProcess)
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 SectionSize = GtRead(GtEprocessField21);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    __int64 NtoskrnlSize = GtRead(GtNtoskrnlImageSize);

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
            if (ReadPESectionEntry((PUCHAR)&Context, SectionEntry))
                break;
            unsigned int CurrentEnd = EntrySize + (unsigned int)EntryBase;
            EntryBase += EntrySize;
            __int16 TypeValue = *(_WORD *)(EntryTypePtr + 6);

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
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                return Result;
            int CurrentOffset = EntryCumulSize + (unsigned int)CumulativeSize;
            CumulativeSize += EntryCumulSize;
            if (*(WORD *)(EntryDataPtr + 6) == 1369)
            {
                if (EntrySize)
                {
                    Phase1Result = (unsigned int)(CurrentOffset + EntrySize - ImageBase);
                    break;
                }
            }
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB && *(WORD *)(EntryDataPtr + 6) == 1368 && EntrySize)
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
                if (*(WORD *)(EntryDataPtr + 6) == 1298 && SectionFlags == 0x40000)
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
        SectionVa = (unsigned int)FindPESectionByName((PUCHAR)ImageBase, SectionName);
        SectionRva = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)ImageBase, SectionName);
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
            SectionVa = (unsigned int)FindPESectionByName((PUCHAR)ImageBase, SectionName);
            SectionRva = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)ImageBase, SectionName);
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
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            CumulativeSize += EntryCumulSize;
            __int16 TypeValue = *(__int16 *)(EntryDataPtr + 6);
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
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1298 && FieldValue == 0x40000)
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
    char FoundMatch = 0;
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 Value = 0;
    __int64 FieldValue = 0;
    __int64 ExtraField = 0;
    unsigned int CumulativeFlags = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    FoundMatch = 0;
    result = GtRead(GtFindHookTargetPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                return result;
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
                return result;
            if (SubType == 1072 && (FieldValue2 & 0x1000000000LL) != 0 && !ExtraField)
            {
                if ((FieldValue & 0x10000) != 0 && (unsigned int)Value < ImageSize && (FieldValue & 0x40) != 0 && (FieldValue & 2) != 0 && (FieldValue & 4) == 0)
                {
                    if (FoundMatch)
                    {
                        return GtWrite(GtEprocessField69, BaseAddress + (unsigned int)Value);
                    }
                    unsigned int TargetOffset = (unsigned int)Value;
                    GtWrite(GtFindHookTargetFirstMatchOffset2, (unsigned int)Value);
                    result = GtWrite(GtFindHookTargetFirstMatchAddr2, TargetOffset + BaseAddress);
                    FoundMatch = 1;
                }
            }
            else if (SubType == 1298 && (FieldValue & 0x40) != 0 && (FieldValue2 & 0x40) != 0 && (FieldValue2 & 0x10000) != 0 && FoundMatch == 1)
            {
                if (CumulativeFlags && CumulativeFlags < ImageSize)
                {
                    return GtWrite(GtEprocessField69, BaseAddress + CumulativeFlags);
                }
            }
        }
    }
    return result;
}
__int64 FindHookTargetInExportWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 FieldValue = 0;
    __int64 ExtraField = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtFindHookTargetPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        unsigned int CountField = 0;
        __int64 FirstMatchOffset = 0;
        for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            CumulativeSize += SectionSize;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x55F0)
            {
                if (*(_WORD *)(SectionDataPtr + 6) == 1349)
                    break;
            }
            if (((*(_WORD *)(SectionDataPtr + 6) == 1072 && (FieldValue2 & 0x1000000000LL) != 0 && !ExtraField) || (*(_WORD *)(SectionDataPtr + 6) == 1243 && FieldValue2 == 64)) && FieldValue == 0x40000)
            {
                unsigned int MatchOffset = (unsigned int)(CumulativeSize + SectionEntry[16] - ImageBase);
                if (MatchOffset > 0x20 && MatchOffset < ImageSize)
                {
                    if ((_DWORD)FirstMatchOffset && CountField < 0xA)
                    {
                        GtWrite(GtFindHookTargetFirstMatchOffset2, (unsigned int)FirstMatchOffset);
                        GtWrite(GtFindHookTargetFirstMatchAddr2, FirstMatchOffset + BaseAddress);
                        return GtWrite(GtEprocessField69, BaseAddress + MatchOffset - 32);
                    }
                    FirstMatchOffset = MatchOffset - 32;
                    CountField = 0;
                }
            }
            else
            {
                ++CountField;
            }
        }
    }
    return result;
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
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtDisableHookProtectionPeOffset);
    SectionOffset = (unsigned int)result;
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368)
            {
                if (EntryFlags)
                {
                    result = EntryFlags - (unsigned int)ImageBase;
                    SectionOffset = MatchSize + (unsigned int)result;
                    break;
                }
            }
        }
        if (SectionOffset && SectionOffset < ImageSize)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            int MatchCount = 0;
            for (unsigned int i = 0; i < 0x64; ++i)
            {
                result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                if ((_DWORD)result)
                    break;
                int MatchSize2 = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
                if (SubType != 1296 && SubType != 1239)
                    continue;
                if (FieldValue == 0x40000 && FieldFlags)
                {
                    result = MatchSize2 + FieldFlags - (unsigned int)ImageBase;
                    if ((_DWORD)result && (unsigned int)result < ImageSize)
                    {
                        ++MatchCount;
                        __int64 ResultAddress = BaseAddress + (unsigned int)result;
                        if (MatchCount == 1)
                        {
                            result = GtWrite(GtDisableHookProtectionAddr1, ResultAddress);
                        }
                        else if (MatchCount == 2)
                        {
                            return GtWrite(GtDisableHookProtectionAddr2, ResultAddress);
                        }
                    }
                }
            }
        }
    }
    return result;
}
__int64 FindNtOpenThreadTargetWin7(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 SectionDataPtr = 0;

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
            if (*(_WORD *)(SectionDataPtr + 6) == 1368 && LoopIndex > 6)
            {
                unsigned int TargetOffset = (unsigned int)(CumulativeSize + *(_DWORD *)(CumulativeSize - 4) - ImageBase);
                if (TargetOffset < MaxOffset)
                    return BaseAddress + TargetOffset;
                return Result;
            }
            CumulativeSize += SectionEntry[60];
        }
    }
    return Result;
}
__int64 FindNtOpenThreadTargetWin8(__int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress, unsigned int MaxOffset)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    int EntrySize = 0;
    __int64 FieldValue = 0;
    int FieldSize = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

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
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368 && (FieldValue & 0x4000000) != 0)
            {
                if (EntrySize)
                {
                    unsigned int TargetOffset = (unsigned int)(MatchSize + EntrySize - ImageBase);
                    if (TargetOffset && TargetOffset < ImageSize)
                    {
                        CumulativeSize = 0;
                        InitPESectionReadContext(ImageBase + TargetOffset, ImageSize - TargetOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
                        for (int LoopIndex2 = 0; LoopIndex2 < 0x46; ++LoopIndex2)
                        {
                            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                                return Result;
                            int MatchSize2 = (int)(SectionSize + CumulativeSize);
                            CumulativeSize += SectionSize;
                            if (*(_WORD *)(SectionDataPtr + 6) == 1296 && (FieldValue2 & 0x40000) != 0)
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
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
            {
                if ((_DWORD)TargetOffset && (unsigned int)TargetOffset < ImageSize)
                {
                    GtWrite(GtKernelDataField36, TargetOffset);
                    return GtWrite(GtKernelDataField37, TargetOffset + BaseAddress);
                }
                return result;
            }
            if (SubType == 1368 && (FieldValue & 0x4000000) != 0)
            {
                if (EntryFlags)
                    TargetOffset = MatchSize + EntryFlags - (unsigned int)ImageBase;
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
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1296 && FieldValue == 0x40000)
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
    __int64 FieldValue = 0;
    int EntryFlags = 0;
    int SectionSize = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize2 = 0;
    __int64 SectionDataPtr = 0;

    SectionOffset = (unsigned int)GtRead(GtNtCreateThreadPeSectionOffset);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            int MatchSize = (int)(SectionSize2 + CumulativeSize);
            CumulativeSize += SectionSize2;
            if (*(_WORD *)(SectionDataPtr + 6) == 1245 && FieldValue == 64 && EntryFlags == 1 && FieldValue2 == 0x40000)
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
    __int64 result;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtNtDeleteKeyPeSectionOffset | GtEprocessField02);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)ImageBase;
                    if ((_DWORD)result && (unsigned int)result < ImageSize)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite((enum _GLOBAL_TABLE_INDEX)2313, (unsigned int)result);
                        return GtWrite((enum _GLOBAL_TABLE_INDEX)2314, TargetOffset + BaseAddress);
                    }
                }
            }
        }
    }
    return result;
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
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 FieldValue = 0;
    __int64 FieldValue2 = 0;
    __int64 FieldValue3 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ResultValue = -1;
    SectionOffset = (unsigned int)GtRead(GtNtOpenKeyPeSectionOffset);
    if (SectionOffset && SectionOffset < ImageSize)
    {
        InitPESectionReadContext(ImageBase + SectionOffset, ImageSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            if ((FieldValue3 & 0x80000) != 0 && FieldValue2 == 16 && (FieldValue & 0x10000) != 0)
            {
                ResultValue = SectionEntry[16];
            }
            else if ((unsigned __int16)(*(_WORD *)(SectionDataPtr + 6) - 1368) <= 1u && (FieldValue & 0x4000000) != 0)
            {
                unsigned int TargetOffset = (unsigned int)(MatchSize + SectionEntry[14] - ImageBase);
                if (TargetOffset && TargetOffset < ImageSize)
                    GtWrite(GtPspTerminateThreadAddr, BaseAddress + TargetOffset);
                return GtWrite(GtEprocessField94, ResultValue);
            }
        }
        return GtWrite(GtEprocessField94, ResultValue);
    }
    return GtWrite(GtEprocessField94, ResultValue);
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
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1349)
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
    char FieldValue = 0;
    int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtTotalSize | GtPathBuffer04 | 0x400);
    if ((_DWORD)result && (unsigned int)result < ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)result, (ULONG)(ImageSize - result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296 && (FieldValue & 0x20) != 0 && !EntryFlags && (FieldValue2 & 0x40000) != 0)
            {
                if (FieldFlags)
                {
                    result = MatchSize + FieldFlags - (unsigned int)ImageBase;
                    if ((_DWORD)result && (unsigned int)result < ImageSize)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite(GtEprocessModuleListOffset | GtPsExitSpecialApcAddr, (unsigned int)result);
                        return GtWrite(GtEprocessModuleListOffset | GtExFreeCallBackAddr, TargetOffset + BaseAddress);
                    }
                }
            }
        }
    }
    return result;
}
__int64 HookSyscallNtDeleteKey(unsigned __int64 ImageBase, unsigned int ImageSize, __int64 UnusedParam, __int64 BaseAddress)
{
    __int64 MatchOffset = 0;
    char FoundFlag = 0;
    __int64 result;
    unsigned __int64 EndAddress;
    __int64 SectionBase = 0;
    int SectionEnd = 0;
    PE_DECODE_CONTEXT ReadContext;   // 0x48 字节解码上下文（原 char[8] 仅 8 字节）
    __int64 CumulativeSize2 = 0;
    char SectionEntry[448];                 // 描述符：原 [120] 仅 120 字节
    int EntrySize = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ImageSize = ImageSize;
    FoundFlag = 0;
    result = GtRead(GtNtDeleteKeyPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < (unsigned int)ImageSize)
    {
        EndAddress = ImageBase + ImageSize;
        SectionBase = ImageBase + (unsigned int)result;
        SectionEnd = (int)EndAddress;
        if (EndAddress > (unsigned __int64)(SectionBase + 4096))
            SectionEnd = (int)(SectionBase + 4096);
        InitPESectionReadContext(SectionBase, (ULONG)(SectionEnd - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (1)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
            if ((_DWORD)result)
                break;
            __int64 CumulativeSize = SectionSize + CumulativeSize2;
            CumulativeSize2 = CumulativeSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1166)
            {
                FoundFlag = 1;
            }
            else if (SubType == 1298 && (FieldValue & 0x40000) != 0 && FoundFlag == 1)
            {
                unsigned __int64 TargetAddress = CumulativeSize + EntrySize;
                if (TargetAddress > ImageBase && TargetAddress < EndAddress)
                    return GtWrite(GtCallbackField120, TargetAddress + BaseAddress - ImageBase);
            }
        }
    }
    return result;
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
    __int64 TargetSizeCopy = 0;
    char FoundMarker = 0;
    __int64 Result = 0;
    unsigned __int64 BufferEnd;
    __int64 ScanStart = 0;
    int ScanEnd = 0;
    PE_DECODE_CONTEXT ReadContext;   // 0x48 字节解码上下文（原 char[8] 仅 8 字节）
    __int64 TotalCumulSize = 0;
    char SectionEntry[448];                 // 描述符：原 [64] 仅 64 字节
    int EntryFlags = 0;
    __int64 SectionFlags = 0;
    int EntrySize = 0;
    __int64 SectionType2 = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    TargetSizeCopy = TargetSize;
    FoundMarker = 0;
    Result = GtRead(GtNtDeleteKeyPeSectionOffset);
    if ((_DWORD)Result && (unsigned int)Result < (unsigned int)TargetSizeCopy)
    {
        BufferEnd = TargetBase + TargetSizeCopy;
        ScanStart = TargetBase + (unsigned int)Result;
        ScanEnd = (int)BufferEnd;
        if (BufferEnd > (unsigned __int64)(ScanStart + 4096))
            ScanEnd = (int)(ScanStart + 4096);
        InitPESectionReadContext(ScanStart, (ULONG)(ScanEnd - ScanStart), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (1)
        {
            Result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
            if ((_DWORD)Result)
                break;
            __int64 CumulativeSize = EntryCumulSize + TotalCumulSize;
            TotalCumulSize = CumulativeSize;
            __int16 SectionType = *(_WORD *)(EntryDataPtr + 6);
            if (SectionType == 1294 && (SectionFlags & 0x4000) != 0 && EntryFlags == 16)
            {
                FoundMarker = 1;
            }
            else if (SectionType == 1296 && FoundMarker == 1 && (SectionType2 & 0x40000) != 0 && SectionFlags == 64)
            {
                unsigned __int64 MatchAddress = CumulativeSize + EntrySize;
                if (MatchAddress > TargetBase && MatchAddress < BufferEnd)
                    return GtWrite(GtCallbackField08, MatchAddress + RelocBase - TargetBase);
            }
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
            CumulativeSize += EntryCumulSize;
            __int16 SectionType = *(_WORD *)(EntryDataPtr + 6);
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField115 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
    SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField109 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1349)
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
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                int CurrentOffset1 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1141 && (SectionFlags & 0x40000) != 0 && EntrySize < TargetSize)
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
                if (*(_WORD *)(EntryDataPtr + 6) == 1296 && (SectionFlags & 0x40) != 0 && (SectionType2 & 0x40000) != 0 && EntrySize2 < TargetSize)
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
