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
void ParseStorPortExportDir(void);
char ParseSyscallFileExportDir(void);
char BuildSyscallExportTable(void);
char InitShadowSyscallExportTable(void);
char InitWin32kSyscallTable(void);
// ParseSyscallTableExportDir 声明见头文件（返回类型 void）
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

// InitSdstTable — 初始化 SSDT 表
// 对应原始驱动 sub_140003C3C
// 遍历内核模块链表定位 ntoskrnl.exe，写入路径到全局表
char InitSdstTable(void)
{
    char Success = 0;
    ULONG64 NtoskrnlBase;
    ULONG64 NtBuildNumber;
    ULONG64 NtBuildNumberCopy;
    ULONG64 *ModuleListHead;
    ULONG64 CurrentEntry;
    ULONG64 NtBuildNumberPtr;
    ULONG64 ModuleBase;
    ULONG64 ModuleEnd;
    void *NtImageName;
    ULONG NameLengthRemaining;
    int NameLength = 0;
    int NameIndex = 0;
    WORD *Offset;
    ULONG NameLenCopy;
    __int64 *FileNameLength;
    ULONG64 *FileNameBuffer;
    ULONG64 ModuleListHead2;
    ULONG64 CurrentEntry2;
    WORD ModuleBase2;
    ULONG64 NameLen2;
    __int64 ImageName2 = 0;
    int HalfNameLen = 0;
    int SearchIndex = 0;
    int NameLen2Copy = 0;
    ULONG64 Offset2;
    ULONG64 SearchOffset;
    ULONG SectionName;
    __int64 *FileNameLen2;
    int NameLen2CopySave = 0;
    ULONG64 Value;

    Success = 0;
    NtoskrnlBase = GtRead(GtDriverObject);
    NtBuildNumber = GtRead(GtNtBuildNumber);
    NtBuildNumberCopy = NtBuildNumber;
    if (!NtoskrnlBase || !NtBuildNumber)
        return Success;

    ModuleListHead = *(ULONG64 **)(NtoskrnlBase + 40);
    CurrentEntry = *ModuleListHead;

    GtWrite(GtPathBuffer00, 0x7300790053005CLL);
    GtWrite(GtPathBuffer01, 0x52006D00650074LL);
    GtWrite(GtPathBuffer02, 0x5C0074006F006FLL);
    GtWrite(GtPathBuffer03, 0x74007300790073LL);
    GtWrite(GtPathBuffer04, 0x320033006D0065LL);

    if (ModuleListHead != (ULONG64 *)CurrentEntry)
    {
        // 【⚠ 修正记录 2026-10-15】原写 `&NtBuildNumber`（**栈局部**的地址），
            //   而原始是取该值本身 —— 即 `nt!NtBuildNumber` 符号的**内核地址**
            //   （GT[0] 存的正是这个地址，见 InitGtCore）。后者才可能落在
            //   ntoskrnl 模块区间内；栈地址永远不在，故区间判断恒失败
            //   → Success=0 → DriverEntry 返回 0xC0000001 → 实机错误 31。
            NtBuildNumberPtr = NtBuildNumber;
        while (CurrentEntry > (ULONG64)MmSystemRangeStart)
        {
            ModuleBase = *(ULONG64 *)(CurrentEntry + 48);
            ModuleEnd = ModuleBase + *(ULONG *)(CurrentEntry + 64);

            if (ModuleBase > (ULONG64)MmSystemRangeStart &&
                ModuleEnd > (ULONG64)MmSystemRangeStart &&
                NtBuildNumberCopy > ModuleBase &&
                NtBuildNumberCopy < ModuleEnd &&
                NtBuildNumberPtr > ModuleBase &&
                NtBuildNumberPtr < ModuleEnd &&
                ModuleBase < 0xFFFFF88000000000ULL &&
                *(WORD *)(CurrentEntry + 72) > 4)
            {
                NtImageName = *(void **)(CurrentEntry + 80);
                if (NtImageName)
                {
                    if (CheckMemoryValid(NtImageName) == 1 &&
                        CheckMemoryValid((void *)(*(ULONG64 *)(CurrentEntry + 80) - 1 + *(WORD *)(CurrentEntry + 72))) == 1)
                    {
                        NameLengthRemaining = *(WORD *)(CurrentEntry + 72);
                        NameLength = (NameLengthRemaining >> 1) - 1;
                        if (NameLength >= 0)
                        {
                            NameIndex = 2 * NameLength;
                            Offset = (WORD *)(*(ULONG64 *)(CurrentEntry + 80) + 2LL * NameLength);
                            while (1)
                            {
                                if (*Offset == L'\\')
                                {
                                    NameLenCopy = NameLengthRemaining - NameIndex;
                                    if (NameLengthRemaining - NameIndex < 0xAE)
                                        break;
                                }
                                NameIndex -= 2;
                                Offset--;
                                if (--NameLength < 0)
                                    goto LABEL_24;
                            }
                            GtWrite(GtNtoskrnlImageSize, *(ULONG *)(CurrentEntry + 64));
                            GtWrite(GtNtoskrnlModuleBase, ModuleBase);
                            FileNameLength = GtAlloc(GtSymlinkBuffer);
                            memset(FileNameLength, 0, 0xB0);
                            memmove(FileNameLength, (const void *)(*(ULONG64 *)(CurrentEntry + 80) + 2LL * NameLength), NameLenCopy);
                            Success = 1;
                        }
LABEL_24:
                        if (Success == 1)
                            break;
                    }
                    // 【⚠ 修正记录 2026-10-15】原写 `&NtBuildNumber`（**栈局部**的地址），
            //   而原始是取该值本身 —— 即 `nt!NtBuildNumber` 符号的**内核地址**
            //   （GT[0] 存的正是这个地址，见 InitGtCore）。后者才可能落在
            //   ntoskrnl 模块区间内；栈地址永远不在，故区间判断恒失败
            //   → Success=0 → DriverEntry 返回 0xC0000001 → 实机错误 31。
            NtBuildNumberPtr = NtBuildNumber;
                }
            }
            CurrentEntry = *(ULONG64 *)CurrentEntry;
            if (ModuleListHead == (ULONG64 *)CurrentEntry)
                break;
        }
        if (Success)
            return Success;
    }

    FileNameBuffer = *(ULONG64 **)(NtoskrnlBase + 40);
    ModuleListHead2 = *FileNameBuffer;

LABEL_46:
    if (FileNameBuffer != (ULONG64 *)ModuleListHead2 && ModuleListHead2 > (ULONG64)MmSystemRangeStart)
    {
        CurrentEntry2 = *(ULONG64 *)(ModuleListHead2 + 48);
        Value = CurrentEntry2;
        if (CurrentEntry2 <= (ULONG64)MmSystemRangeStart)
            goto LABEL_45;
        if (CurrentEntry2 + *(ULONG *)(ModuleListHead2 + 64) <= (ULONG64)MmSystemRangeStart)
            goto LABEL_45;
        ModuleBase2 = *(WORD *)(ModuleListHead2 + 72);
        if (ModuleBase2 < 0x18)
            goto LABEL_45;
        NameLen2 = *(ULONG64 *)(ModuleListHead2 + 80);
        if (NameLen2 <= (ULONG64)MmSystemRangeStart)
            goto LABEL_45;
        ImageName2 = ModuleBase2 >> 1;
        if (*(WORD *)(NameLen2 + 2 * ImageName2 - 2) == L'\\')
            goto LABEL_45;
        HalfNameLen = (int)ImageName2 - 1;
        if (HalfNameLen < 0)
            goto LABEL_44;
        SearchIndex = ModuleBase2 >> 1;
        NameLen2Copy = 2 * HalfNameLen;
        NameLen2CopySave = SearchIndex;
        Offset2 = 2LL * HalfNameLen;
        while (1)
        {
            SearchOffset = *(ULONG64 *)(ModuleListHead2 + 80);
            if (*(WORD *)(Offset2 + SearchOffset) == L'\\' &&
                ParseNtHeaders((WORD *)(SearchOffset + 2LL * SearchIndex), 2 * ((int)ImageName2 - HalfNameLen) - 2))
            {
                SectionName = *(WORD *)(ModuleListHead2 + 72) - NameLen2Copy;
                if (SectionName < 0xAE)
                {
                    GtWrite(GtNtoskrnlImageSize, *(ULONG *)(ModuleListHead2 + 64));
                    GtWrite(GtNtoskrnlModuleBase, Value);
                    FileNameLen2 = GtAlloc(GtSymlinkBuffer);
                    memset(FileNameLen2, 0, 0xB0);
                    memmove(FileNameLen2, (const void *)(*(ULONG64 *)(ModuleListHead2 + 80) + 2LL * HalfNameLen), SectionName);
                    Success = 1;
LABEL_44:
                    if (Success != 1)
                    {
LABEL_45:
                        ModuleListHead2 = *(ULONG64 *)ModuleListHead2;
                        goto LABEL_46;
                    }
                    return Success;
                }
                SearchIndex = NameLen2CopySave;
            }
            SearchIndex--;
            NameLen2Copy -= 2;
            Offset2 -= 2;
            HalfNameLen--;
            NameLen2CopySave = SearchIndex;
            if (HalfNameLen < 0)
                goto LABEL_44;
        }
    }
    return Success;
}

// LookupExportFuncAddr — 在导出索引表中查找函数地址
// 对应原始驱动 sub_140005448
__int64 LookupExportFuncAddr(__int64 ExportIndexTable, unsigned int EntryCount, int HashValue)
{
    ULONG Index;
    __int64 TableEntry = 0;

    for (Index = 0; Index < EntryCount; Index++)
    {
        TableEntry = ExportIndexTable + 12LL * Index;
        if (*(UCHAR *)TableEntry == 1 && HashValue == *(ULONG *)(TableEntry + 4))
            return *(unsigned int *)(TableEntry + 8);
    }
    return 0;
}

// GetExportDirSize — 获取导出目录中的函数数量
// 对应原始驱动 sub_140005800
__int64 GetExportDirSize(__int64 PeBase, unsigned int PeSize)
{
    ULONG PeHeaderRva;
    ULONG ExportDirRva, ExportDirSize, ExportDirEnd;
    ULONG AddressOfFunctions, NumberOfFunctions;
    ULONG FuncTableSize;
    ULONG AddressOfNames, AddressOfOrdinals;

    PeHeaderRva = *(int *)(PeBase + 60);
    ExportDirRva = *(unsigned int *)(PeHeaderRva + PeBase + 136);
    ExportDirSize = *(unsigned int *)(PeHeaderRva + PeBase + 140);
    ExportDirEnd = ExportDirSize + ExportDirRva;

    if (ExportDirRva >= PeSize || ExportDirRva + 40 >= PeSize ||
        ExportDirSize >= PeSize || ExportDirEnd >= PeSize)
        return 0;

    AddressOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 32);
    NumberOfFunctions = *(unsigned int *)(ExportDirRva + PeBase + 24);

    if ((ULONG)AddressOfFunctions < ExportDirRva)
        return 0;

    FuncTableSize = 4 * NumberOfFunctions;
    if (FuncTableSize + AddressOfFunctions >= ExportDirEnd || FuncTableSize >= ExportDirSize)
        return 0;

    AddressOfNames = *(unsigned int *)(ExportDirRva + PeBase + 36);
    if ((ULONG)AddressOfNames < ExportDirRva || AddressOfNames + 2 * NumberOfFunctions >= ExportDirEnd)
        return 0;

    AddressOfOrdinals = *(unsigned int *)(ExportDirRva + PeBase + 28);
    if ((ULONG)AddressOfOrdinals < ExportDirRva ||
        AddressOfOrdinals + 4 * *(unsigned int *)(ExportDirRva + PeBase + 20) >= ExportDirEnd)
        return 0;

    return NumberOfFunctions;
}

// CheckSsdtHookIntegrity — 检查 SSDT Hook 完整性
// 对应原始驱动 sub_1400050DC
char CheckSsdtHookIntegrity(ULONG64 ProcessId, ULONG64 BufferSize, _DWORD *OutputBuffer, int OutputSize)
{
    char Result = 0;
    UCHAR IsMatch;
    __int64 ExportDirVa = 0;
    ULONG ExportDirSize;
    __int64 NtoskrnlBase = 0;
    ULONG ModuleSize;
    __int64 EncryptionKey = 0;

    Result = 0;
    IsMatch = 0;
    ExportDirVa = GtRead(GtEprocessField22);
    ExportDirSize = (ULONG)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    ModuleSize = (ULONG)GtRead(GtNtoskrnlImageSize);

    if (ExportDirVa && ExportDirSize && NtoskrnlBase && ModuleSize >= 0x1001)
        IsMatch = ComparePeHeaders(NtoskrnlBase, ModuleSize, ExportDirVa, ExportDirSize);

    if (ProcessId > (ULONG64)MmSystemRangeStart)
    {
        EncryptionKey = GtRead(GtEncryptionKey);
        GtWrite(GtEncryptionKey, EncryptionKey + 2);
    }

    if (OutputBuffer && (ULONG64)OutputBuffer < MmUserProbeAddress &&
        OutputSize == 4 && (ULONG64)(OutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, 4, 1);
        *OutputBuffer = IsMatch;
        Result = 1;
    }

    GtWrite(GtCallbackField54, 1);
    return Result;
}

// InitSyscallNumberTable — 初始化系统调用编号表
// 对应原始驱动 sub_140003FC4
__int64 InitSyscallNumberTable(void)
{
    /* 原始 sub_140003FC4：向 0x4158/0x415B 起、**步长 3** 的槽位写入 267 个预计算哈希值。
       布局为 [hash, rva, addr] 三元组，BuildHookTable 以 TableIndex += 3 迭代读取。
       【修正 2026-10-16】原实现自第 4 项起按 +1 递增（16734,16735,16738,16739,16740…），
       与原始的 +3 步长不符 —— 实测致 InitAllHookSubsystems 失败、sc start 报错误 31。 */
    GtWrite(GtSyscallHashEntry00, 0x989BCA3ELL);   /* GT[16731] */
    GtWrite(GtSyscallHashTable, 0x496CD1FE);       /* GT[16728] */
    GtWrite(16734, 0xB1A0E87FLL);
    GtWrite(16737, 0xC355DD31LL);
    GtWrite(16740, 0x52E5A42ALL);
    GtWrite(16743, 0x75F00B29LL);
    GtWrite(16746, 0x8F528242LL);
    GtWrite(16749, 0xFC7D413ELL);
    GtWrite(16752, 0x23A86046LL);
    GtWrite(16755, 0x2539715LL);
    GtWrite(16758, 0x1C710C25LL);
    GtWrite(16761, 0x596508BCLL);
    GtWrite(16776, 0xD26E0788LL);
    GtWrite(16764, 0xE5156335LL);
    GtWrite(16767, 0xE9FBCEFELL);
    GtWrite(16770, 0x664D70BFLL);
    GtWrite(16773, 0x6B871234LL);
    GtWrite(16779, 0xC4FAD3EBLL);
    GtWrite(16782, 0xDE4DCCC1LL);
    GtWrite(16785, 0xACD04BF3LL);
    GtWrite(16788, 0x9D4CCB0FLL);
    GtWrite(16791, 0xEC0A1287LL);
    GtWrite(16794, 0x575B969BLL);
    GtWrite(16797, 0x6BCD42A9LL);
    GtWrite(16800, 0xDAA023CBLL);
    GtWrite(16803, 0x11443CA9LL);
    GtWrite(16806, 0xA00702AALL);
    GtWrite(16809, 0xCBF1F891LL);
    GtWrite(16812, 0xECB7091ELL);
    GtWrite(16815, 0xBEA5E2EFLL);
    GtWrite(16818, 0x6B84188ALL);
    GtWrite(16821, 0x764B6D26LL);
    GtWrite(16824, 0x3E171C0DLL);
    GtWrite(16827, 0xA3CCAA67LL);
    GtWrite(16830, 0xDA519BA5LL);
    GtWrite(16833, 0x60E6A55ELL);
    GtWrite(16836, 0x30617C1ALL);
    GtWrite(16839, 0xC833258DLL);
    GtWrite(16842, 0xF91CE2EBLL);
    GtWrite(16845, 0xC3089EADLL);
    GtWrite(16848, 0xC880FC5ELL);
    GtWrite(16851, 0x71CF9A3ELL);
    GtWrite(16854, 0xFA330EA1LL);
    GtWrite(16857, 0xFA58CDC2LL);
    GtWrite(16860, 0x208580CBLL);
    GtWrite(16863, 0x67228994LL);
    GtWrite(16866, 0xCE61BFBBLL);
    GtWrite(16869, 0xEA6C46EFLL);
    GtWrite(16872, 0x3EC6D380LL);
    GtWrite(16875, 0xEB9830DDLL);
    GtWrite(16878, 0x4C641018LL);
    GtWrite(16881, 0x54EF05BALL);
    GtWrite(16884, 0x182C7ABDLL);
    GtWrite(16887, 0x38EA43CALL);
    GtWrite(16890, 0x816AD2F7LL);
    GtWrite(16893, 0xD52ADA4FLL);
    GtWrite(16896, 0xD849C233LL);
    GtWrite(16899, 0x31269C70LL);
    GtWrite(16902, 0x1AD07B46LL);
    GtWrite(16905, 0x2B5D4521LL);
    GtWrite(16908, 0x81D58D91LL);
    GtWrite(16911, 0x3A404733LL);
    GtWrite(16914, 0x8B02D8A2LL);
    GtWrite(16917, 0xAB3962CALL);
    GtWrite(16920, 0x24E8CC0DLL);
    GtWrite(16923, 0xC9422A37LL);
    GtWrite(16926, 0x48E31E12LL);
    GtWrite(16929, 0x9FF33383LL);
    GtWrite(16932, 0x15809667LL);
    GtWrite(16935, 0xEAAECD9CLL);
    GtWrite(16938, 0x9848CEABLL);
    GtWrite(16941, 0xFE213B95LL);
    GtWrite(16944, 0x88ED5CF4LL);
    GtWrite(16950, 0xFC040A43LL);
    GtWrite(16947, 0x8B5DD16LL);
    GtWrite(16953, 0x5345AC25LL);
    GtWrite(16956, 0x79352A4ELL);
    GtWrite(16959, 0xFCD830C4LL);
    GtWrite(16962, 0x238B926ALL);
    GtWrite(16965, 0x49733B00LL);
    GtWrite(16968, 0x99A62677LL);
    GtWrite(16971, 0xFFA82CDDLL);
    GtWrite(16974, 0x63B8D286LL);
    GtWrite(16977, 0x20AF640DLL);
    GtWrite(16980, 0x7BE9C3C8LL);
    GtWrite(16983, 0xBD01010ELL);
    GtWrite(16986, 0xA9724E39LL);
    GtWrite(16989, 0xDBA019E9LL);
    GtWrite(16992, 0xCFA77882LL);
    GtWrite(16995, 0x7158131LL);
    GtWrite(16998, 0x10E77406LL);
    GtWrite(17001, 0x1B0386BDLL);
    GtWrite(17004, 0xDFF75FDLL);
    GtWrite(17007, 0xB96DAD76LL);
    GtWrite(17010, 0x618521A8LL);
    GtWrite(17013, 0x6371DEF8LL);
    GtWrite(17016, 0x59FA3B98LL);
    GtWrite(17019, 0x777A6033LL);
    GtWrite(17022, 0xBB1A0857LL);
    GtWrite(17025, 0x4354588BLL);
    GtWrite(17028, 0x38145A3FLL);
    GtWrite(17031, 0xC28E0472LL);
    GtWrite(17034, 0x358E312DLL);
    GtWrite(17037, 0xCA66CD85LL);
    GtWrite(17040, 0xD2F1242FLL);
    GtWrite(17043, 0xA0752995LL);
    GtWrite(17046, 0xFDF9BD5ELL);
    GtWrite(17049, 0xA733E150LL);
    GtWrite(17052, 0xC6C1CD2ELL);
    GtWrite(17055, 0x29291EBLL);
    GtWrite(17058, 0xE8E050DBLL);
    GtWrite(17061, 0x5F3DBEB9LL);
    GtWrite(17064, 0x969C12BCLL);
    GtWrite(17067, 0x9BED0DAFLL);
    GtWrite(17070, 0xEEECBAE0LL);
    GtWrite(17073, 0x4910DB26LL);
    GtWrite(17076, 0x5612B523LL);
    GtWrite(17079, 0x32BD224FLL);
    GtWrite(17082, 0x8E429199LL);
    GtWrite(17085, 0x360B8B54LL);
    GtWrite(17088, 0x2F4FC27CLL);
    GtWrite(17091, 0xE1E1D2DALL);
    GtWrite(17094, 0x8DB049F3LL);
    GtWrite(17097, 0x8F30256BLL);
    GtWrite(17100, 0x34FDB1E5LL);
    GtWrite(17103, 0xF3C88A38LL);
    GtWrite(17106, 0x9792A2EDLL);
    GtWrite(17109, 0x3E6F0E31LL);
    GtWrite(17112, 0x111FD9C8LL);
    GtWrite(17115, 0x339A9A9LL);
    GtWrite(17118, 0x992020AALL);
    GtWrite(17121, 0xA10EA60ELL);
    GtWrite(17124, 0xDA4DAD8BLL);
    GtWrite(17127, 0xB585B522LL);
    GtWrite(17130, 0x9DE46039LL);
    GtWrite(17133, 0xBB05D4F7LL);
    GtWrite(17136, 0xA608DEB3LL);
    GtWrite(17139, 0x50AE9DEFLL);
    GtWrite(17142, 0xE0A4EF2ALL);
    GtWrite(17145, 0x194066FFLL);
    GtWrite(17148, 0x2B71C596LL);
    GtWrite(17151, 0x3A8B0535LL);
    GtWrite(17154, 0x7AD36E07LL);
    GtWrite(17157, 0x82384FFBLL);
    GtWrite(17160, 0x3DAF80F0LL);
    GtWrite(17163, 0xFDED2BE9LL);
    GtWrite(17166, 0xA01EE269LL);
    GtWrite(17169, 0x3CD816BALL);
    GtWrite(17172, 0x2A61C490LL);
    GtWrite(17175, 0xED7F4056LL);
    GtWrite(17178, 0x7329A919LL);
    GtWrite(17181, 0xE39F0C9CLL);
    GtWrite(17184, 0xEDDFEBDCLL);
    GtWrite(17187, 0x21F8F209LL);
    GtWrite(17190, 0x5D00C553LL);
    GtWrite(17193, 0xDCE054DALL);
    GtWrite(17196, 0xFC21AC4BLL);
    GtWrite(17199, 0xC5F7E0A4LL);
    GtWrite(17202, 0x890EDED3LL);
    GtWrite(17205, 0x43B0B0BLL);
    GtWrite(17208, 0xA23A41C8LL);
    GtWrite(17211, 0xCB14C8BCLL);
    GtWrite(17214, 0xE4966561LL);
    GtWrite(17217, 0x377015DCLL);
    GtWrite(17220, 0x9759743FLL);
    GtWrite(17223, 0x800DD1D7LL);
    GtWrite(17226, 0xDC8DDD66LL);
    GtWrite(17229, 0x7CCC51A6LL);
    GtWrite(17232, 0x45472F9ALL);
    GtWrite(17235, 0xE4F18F9ELL);
    GtWrite(17238, 0x15248FA8LL);
    GtWrite(17241, 0x1A3DF1B9LL);
    GtWrite(17244, 0x33CFA96ALL);
    GtWrite(17247, 0x9827428ELL);
    GtWrite(17250, 0xA75FF87ELL);
    GtWrite(17253, 0xD46EB408LL);
    GtWrite(17256, 0xBE14E0ELL);
    GtWrite(17259, 0xF4BEB0E7LL);
    GtWrite(17262, 0xBF1F0717LL);
    GtWrite(17265, 0x50C6C12DLL);
    GtWrite(17268, 0x1EC6A264LL);
    GtWrite(17271, 0xAA7C5725LL);
    GtWrite(17274, 0xB70A870CLL);
    GtWrite(17277, 0x3B7D89D4LL);
    GtWrite(17280, 0x8D50A0AELL);
    GtWrite(17283, 0x84038C18LL);
    GtWrite(17286, 0xF8B5849LL);
    GtWrite(17289, 0x3036CD1LL);
    GtWrite(17292, 0x987E412ELL);
    GtWrite(17295, 0xC3CEBE73LL);
    GtWrite(17298, 0x50DC4713LL);
    GtWrite(17301, 0x3251EF0CLL);
    GtWrite(17304, 0x5E1BD2E2LL);
    GtWrite(17307, 0x56AA7C37LL);
    GtWrite(17310, 0xB24B8190LL);
    GtWrite(17313, 0x4A7F8887LL);
    GtWrite(17316, 0xC3C7B2BCLL);
    GtWrite(17319, 0x5BD2F5B3LL);
    GtWrite(17322, 0xC5B63056LL);
    GtWrite(17325, 0xD776C56ELL);
    GtWrite(17328, 0x2B4D9430LL);
    GtWrite(17331, 0x36A1CFALL);
    GtWrite(17334, 0xD0C8B9D6LL);
    GtWrite(17337, 0xDE817CA7LL);
    GtWrite(17340, 0x860F92A7LL);
    GtWrite(17343, 0x13F4E81ALL);
    GtWrite(17346, 0xB71F96F8LL);
    GtWrite(17349, 0xCAC90F43LL);
    GtWrite(17352, 0xAC4060D8LL);
    GtWrite(17355, 0x45EF5633LL);
    GtWrite(17358, 0x4F959E7BLL);
    GtWrite(17361, 0xDEAF455ALL);
    GtWrite(17364, 0x9B7605DBLL);
    GtWrite(17367, 0xD5831992LL);
    GtWrite(17370, 0x5503C59BLL);
    GtWrite(17373, 0xA72F480FLL);
    GtWrite(17376, 0x9758E074LL);
    GtWrite(17379, 0x71BF7B31LL);
    GtWrite(17382, 0x6A3981EDLL);
    GtWrite(17385, 0xD105A851LL);
    GtWrite(17388, 0x64E4BA3LL);
    GtWrite(17391, 0xC936E5EDLL);
    GtWrite(17394, 0x5F35B1C2LL);
    GtWrite(17397, 0xDCB2E1E3LL);
    GtWrite(17400, 0xB025F852LL);
    GtWrite(17403, 0x794E760ALL);
    GtWrite(17406, 0x5D235F88LL);
    GtWrite(17409, 0x9EA7F1F5LL);
    GtWrite(17412, 0x24D734D8LL);
    GtWrite(17415, 0xA566F83BLL);
    GtWrite(17418, 0x4E1F61C1LL);
    GtWrite(17421, 0xF7CDF83CLL);
    GtWrite(17424, 0x785354C2LL);
    GtWrite(17427, 0x9CBC0C9BLL);
    GtWrite(17430, 0xE631A4C8LL);
    GtWrite(17433, 0x65EC3CC0LL);
    GtWrite(17436, 0x3D4F55A8LL);
    GtWrite(17439, 0x6D5F0FE9LL);
    GtWrite(17442, 0x2A0A82C4LL);
    GtWrite(17445, 0xFCDF4688LL);
    GtWrite(17448, 0x4F42A0FALL);
    GtWrite(17451, 0x81841CC1LL);
    GtWrite(17454, 0xDBB9C6A6LL);
    GtWrite(17457, 0xC71BEBD9LL);
    GtWrite(17460, 0x6AD0955ELL);
    GtWrite(17463, 0xD2000F15LL);
    GtWrite(17466, 0x96BF3A00LL);
    GtWrite(17469, 0xAE45EF20LL);
    GtWrite(17472, 0xD6834DE1LL);
    GtWrite(17475, 0x8A0D538LL);
    GtWrite(17478, 0x80850FDLL);
    GtWrite(17481, 0xF94A9B37LL);
    GtWrite(17484, 0x7891546ELL);
    GtWrite(17487, 0x661F49E4LL);
    GtWrite(17490, 0x712D18E5LL);
    GtWrite(17493, 0x35519062LL);
    GtWrite(17496, 0x66D9753CLL);
    GtWrite(17499, 0xFF67D295LL);
    GtWrite(17502, 0x37D8864CLL);
    GtWrite(17505, 0xB26A3E6ALL);
    GtWrite(17508, 0x9BAF4E6DLL);
    GtWrite(17511, 0x7BE5DB30LL);
    GtWrite(17514, 0xA8D092A5LL);
    GtWrite(17517, 0x3FC0CB8LL);
    GtWrite(17520, 0x3F7AA351LL);
    GtWrite(17523, 0x537EB693LL);
    GtWrite(17526, 0x6A2E832CLL);
    return GtWrite(GtSyscallHashEntryEnd, 3407524183LL);
}

// ScanPESectionPatterns — 扫描 PE 节区模式
// 对应原始驱动 sub_140079DE4
bool ScanPESectionPatterns(_BYTE *Pattern, char *TargetData, int DataSize, char UsePESection)
{
    char Result = 0;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节；名字错误另行改名）
    __int64 SectionEntry = 0;
    _DWORD SectionChar[20];
    __int64 EntryField = 0;
    int EntrySize = 0;
    __int64 SectionAlignment = 0;
    ULONG EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;
    char TargetRva = 0;
    __int64 SectionType2 = 0;
    // 5 字节 NOP 指令模板 (0F 1F 44 00 00)
    _BYTE NopPattern[5] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

    SectionEntry = 0;
    TargetRva = 0;
    SectionType2 = 0;

    if ((ULONG)(DataSize - 12) > 0x27F3) return Result;
    if (UsePESection == 1)
    {
        InitPESectionReadContext((__int64)Pattern, DataSize, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        if (ReadPESectionEntry((unsigned char *)&DecodeContext, SectionChar)) return Result;

        while (1)
        {
            int TargetRva2 = (int)(EntryCumulSize + (ULONG)SectionEntry);
            SectionEntry += EntryCumulSize;
            short SectionType = *(WORD *)(*(ULONG64 *)((PUCHAR)SectionChar + 0x118) + 6);
            if (SectionType == 1139 && EntryCumulSize == 7) { TargetRva = 1; }
            else
            {
                if (SectionType == 239 && EntryCumulSize == 5 && TargetRva == 1)
                {
                    SectionType2 = (ULONG)(TargetRva2 - (__int64)Pattern - 12);
                    goto CheckFound;
                }
                TargetRva = 0;
            }
            if (ReadPESectionEntry((unsigned char *)&DecodeContext, SectionChar)) return Result;
        }
    }
    else
    {
        for (SectionType2 = 0; (ULONG)SectionType2 <= (ULONG)(DataSize - 12); SectionType2++)
        {
            if (Pattern[SectionType2] == 0x48 && Pattern[(ULONG)(SectionType2 + 1)] == 0xFF &&
                Pattern[(ULONG)(SectionType2 + 2)] == 0x21 &&
                !MemoryCompare((__int64)&Pattern[(ULONG)SectionType2 + 7], (char *)NopPattern, 5))
                goto CheckFound;
        }
        return Result;
    }

CheckFound:
    Result = 1;
    if (TargetData)
    {
        Result = 0;
        if (SectionType2 && MemoryCompare((__int64)Pattern, (char *)TargetData, (ULONG)SectionType2)) return Result;
        InitPESectionReadContext((__int64)&TargetData[(ULONG)SectionType2], 12, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        if (!ReadPESectionEntry((unsigned char *)&DecodeContext, SectionChar) && *(WORD *)(*(ULONG64 *)((PUCHAR)SectionChar + 0x118) + 6) == 1296 && EntryCumulSize == 7 &&
            EntryField == 64 && SectionAlignment == 0x40000)
        {
            if (EntrySize && *(ULONG *)&Pattern[(ULONG)SectionType2 + 3] == EntrySize)
            {
                SectionEntry += 7;
                if (!ReadPESectionEntry((unsigned char *)&DecodeContext, SectionChar) && *(WORD *)(*(ULONG64 *)((PUCHAR)SectionChar + 0x118) + 6) == 1368)
                    return EntryCumulSize == 5;
            }
        }
    }
    return Result;
}

// ScanPESectionPatternsEx — 扩展版 PE 节区特征码扫描（两种模式匹配算法）
// 对应原始驱动 0x14007A048（600 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 D_need_review（源码中此前完全缺失）。
// 【与 ScanPESectionPatterns(0x14007B4B0 族) 的差异（逐条比对）】
//   本函数（Ex）与普通版结构同型，但**常量不同**，故是两个独立函数：
//     标记节区类型：Ex = 1141(0x475)/长度7、1356(0x54C)/长度1、计数阈值 5
//                   普通版 = 1139/长度7、239/长度5
//     线性特征：    Ex = `48 FF 25` + 其后 +7 处 != 5×0xCC（int3 填充）
//                   普通版 = `48 FF 21` + 其后 +7 处 == 0F 1F 44 00 00（NOP）
//     收尾比对类型：Ex = 1296/1369，普通版 = 1296/1368
// 【入参】PeBuffer=PE 缓冲；PatternBuffer=参照缓冲（可空）；BufferSize；UsePESectionParser
char __fastcall ScanPESectionPatternsEx(_BYTE *PeBuffer, char *PatternBuffer,
                                        int BufferSize, char UsePESectionParser)
{
    ULONG   MaxSearchSize = (ULONG)(BufferSize - 12);
    char    Result = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）
    ULONG   CurOfs;
    char    FoundMarker;
    int     PatternCount;
    ULONG64 MatchOffset;
    _BYTE  *p;
    __int64 EntryFieldAt40, EntryFieldAt50, EntryFieldAt88;

    // 5 字节 int3 填充模板（原始 byte_14008CAA0 = CC CC CC CC CC）
    _BYTE Int3Pad[5] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };

    EntryFieldAt40 = 0; EntryFieldAt50 = 0; EntryFieldAt88 = 0;

    if (MaxSearchSize > 0x27F3)                                        // 0x14007A08A
        return Result;

    if (UsePESectionParser == 1)                                      // 0x14007A099
    {
        InitPESectionReadContext((__int64)PeBuffer, (ULONG)BufferSize,
                                 2, 0, -1, 0, 0, (__int64)&Ctx);       // 0x14007A0C6
    L_LABEL4:                                                         // 0x14007A0CB
        FoundMarker = 0;
        PatternCount = 0;
        while (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))        // 0x14007A0E1
        {
            *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(unsigned int *)((PUCHAR)Entry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            USHORT Type;
            ULONG  EntryLen = *(ULONG *)((PUCHAR)Entry + 0xF0);

            CurOfs = EntryLen + (ULONG)Ctx.ReadPtr;                    // 0x14007A0F9
            Ctx.ReadPtr += EntryLen;                                   // 0x14007A0FC

            Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14007A101

            if (Type == 0x475 && EntryLen == 7)                        // 0x14007A112
            {
                FoundMarker = 1;                                       // 0x14007A114
            }
            else
            {
                if (Type != 0x54C || EntryLen != 1)                    // 0x14007A12A
                    goto L_LABEL4;
                ++PatternCount;                                        // 0x14007A12C
                if ((ULONG)PatternCount >= 5 && FoundMarker == 1)      // 0x14007A12F/135
                {
                    Result = 1;                                        // 0x14007A13C
                    MatchOffset = (ULONG)(CurOfs - (ULONG)(ULONG_PTR)PeBuffer - 12);  // 0x14007A142
                    goto L_LABEL22;                                    // 0x14007A145
                }
                goto L_LABEL4;
            }
        }
        return Result;
    }

    // ---- 线性特征搜索分支（0x14007A147） ----
    for (MatchOffset = 0, p = PeBuffer; ; ++p)                         // 0x14007A149
    {
        if (*p == 0x48                                                 // 0x14007A14C
            && PeBuffer[(ULONG)MatchOffset + 1] == 0xFF                // 0x14007A158
            && PeBuffer[(ULONG)MatchOffset + 2] == 0x25                // 0x14007A15E
            && MemoryCompare((__int64)&PeBuffer[(ULONG)MatchOffset + 7],
                             (char *)Int3Pad, 5u) != 0)                // 0x14007A16A
            break;
        MatchOffset = (ULONG)(MatchOffset + 1);                        // 0x14007A18C
        if ((ULONG)MatchOffset > MaxSearchSize)                        // 0x14007A18F
            return Result;
    }
    Result = 1;                                                        // 0x14007A19A

L_LABEL22:                                                             // 0x14007A1A0
    if (PatternBuffer)                                                 // 0x14007A1A6
    {
        Result = 0;                                                    // 0x14007A1AC
        if ((ULONG)MatchOffset == 0                                    // 0x14007A1BC
            || MemoryCompare((__int64)PeBuffer, PatternBuffer,
                             (unsigned int)MatchOffset) == 0)
        {
            InitPESectionReadContext((__int64)&PatternBuffer[MatchOffset], 12,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);   // 0x14007A1F3
            if (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)        // 0x14007A234
                && *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6) == 1296
                && *(ULONG *)((PUCHAR)Entry + 0xF0) == 7
                && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64            // EntryField (v18)
                && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)   // SectionAlignment (v20)
            {
                EntryFieldAt40 = *(ULONG *)((PUCHAR)Entry + 0x40);      // EntrySize (v19)
                if (EntryFieldAt40)                                    // 0x14007A23B
                {
                    if (*(ULONG *)&PeBuffer[MatchOffset + 3] == (ULONG)EntryFieldAt40)  // 0x14007A241
                    {
                        Ctx.ReadPtr += 7;                              // 0x14007A243
                        if (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)   // 0x14007A26B
                            && *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6) == 1369)
                            return (*(ULONG *)((PUCHAR)Entry + 0xF0) == 5) ? 1 : 0;  // 0x14007A278
                    }
                }
            }
        }
    }
    (void)EntryFieldAt50; (void)EntryFieldAt88;
    return Result;                                                     // 0x14007A27F
}

// ValidatePeHeaderSignature — 校验 PE 头签名（DOS 的 MZ 与 NT 的 ）
// 对应原始驱动 0x14007A2DC（74 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（伪代码见下），按伪代码 1:1 转写。
// 【逻辑】Buffer 非空 且 BufferSize > 0x40 且 *(WORD*)Buffer == 0x5A4D('MZ')
//   → e_lfanew = *(int*)(Buffer+0x3C)；要求 e_lfanew < BufferSize
//     且 e_lfanew+24 < BufferSize → 返回 (*(DWORD*)(Buffer+e_lfanew) == 0x4550)
//   （0x4550 即 PE 签名的前 4 字节）；否则返回 0。
char __fastcall ValidatePeHeaderSignature(__int64 Buffer, unsigned int BufferSize)
{
    char Result = 0;

    if (!Buffer)
        return Result;
    if (BufferSize > 0x40 && *(USHORT *)Buffer == 0x5A4D)          // 'MZ'
    {
        __int64 e_lfanew = *(int *)(Buffer + 60);                  // [Buffer+0x3C]
        if ((unsigned int)e_lfanew < BufferSize
            && (unsigned __int64)(unsigned int)e_lfanew + 24 < BufferSize)
            return (*(ULONG *)(e_lfanew + Buffer) == 0x4550) ? 1 : 0;   // PE signature
    }
    return Result;
}

// InitKernelRoutineTable — 初始化内核例程表
// 对应原始驱动 sub_14000C8CC
// 分配例程表，填充 PsExitSpecialApc、ExFreeCallBack 等关键内核例程地址
_QWORD *InitKernelRoutineTable(void)
{
    _QWORD *NtImageBase;
    int NtBaseInt = 0;
    _QWORD *RoutineTable;
    __int64 PsExitSpecialApcAddr = 0, ExFreeCallBackAddr = 0, PspExitNormalApcAddr = 0;
    __int64 PspExitThreadAddr = 0, PspTerminateThreadAddr = 0, KiFastCallEntryAddr = 0;
    __int64 KiInsertQueueApcAddr = 0, IopfCallDriverAddr = 0, IopfCompleteRequestAddr = 0;
    WORD NameBuffer[20];

    NtImageBase = (_QWORD *)GtRead(GtNtoskrnlModuleBase);
    NtBaseInt = (int)(LONG_PTR)NtImageBase;
    if (!NtImageBase) return NtImageBase;

    RoutineTable = ExAlloc(PagedPool, 0x318);
    if (!RoutineTable) return NtImageBase;

    memset(RoutineTable, 0, 0x318);

    // PsExitSpecialApc
    PsExitSpecialApcAddr = GtRead(GtPsExitSpecialApcAddr);
    RoutineTable[10] = PsExitSpecialApcAddr;
    if (PsExitSpecialApcAddr)
    {
        *((int *)RoutineTable + 18) = (int)(PsExitSpecialApcAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "PsExitSpecialApc");
        StringCopy((UCHAR *)RoutineTable + 4, (__int64)NameBuffer, 0x40);
    }

    // ExFreeCallBack
    ExFreeCallBackAddr = GtRead(GtExFreeCallBackAddr);
    RoutineTable[21] = ExFreeCallBackAddr;
    if (ExFreeCallBackAddr)
    {
        *((int *)RoutineTable + 40) = (int)(ExFreeCallBackAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "ExFreeCallBack");
        StringCopy((UCHAR *)RoutineTable + 92, (__int64)NameBuffer, 0x40);
    }

    // PspExitNormalApc
    PspExitNormalApcAddr = GtRead(GtPspExitNormalApcAddr);
    RoutineTable[32] = PspExitNormalApcAddr;
    if (PspExitNormalApcAddr)
    {
        *((int *)RoutineTable + 62) = (int)(PspExitNormalApcAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "PspExitNormalApc");
        StringCopy((UCHAR *)RoutineTable + 180, (__int64)NameBuffer, 0x40);
    }

    // PspExitThread
    PspExitThreadAddr = GtRead(GtPspExitThreadAddr);
    RoutineTable[43] = PspExitThreadAddr;
    if (!PspExitThreadAddr)
    {
        ScanProcessPESectionsV2();
        RoutineTable[43] = GtRead(GtPspExitThreadAddr);
    }
    if (RoutineTable[43])
    {
        *((int *)RoutineTable + 84) = *((int *)RoutineTable + 86) - NtBaseInt;
        strcpy((char *)NameBuffer, "PspExitThread");
        StringCopy((UCHAR *)RoutineTable + 268, (__int64)NameBuffer, 0x40);
    }

    // PspTerminateThreadByPointer
    PspTerminateThreadAddr = GtRead(GtPspTerminateThreadAddr);
    RoutineTable[54] = PspTerminateThreadAddr;
    if (PspTerminateThreadAddr)
    {
        *((int *)RoutineTable + 106) = (int)(PspTerminateThreadAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "PspTerminateThreadByPointer");
        StringCopy((UCHAR *)RoutineTable + 356, (__int64)NameBuffer, 0x40);
    }

    // KiFastCallEntry
    KiFastCallEntryAddr = GtRead(GtKiFastCallEntryAddr);
    RoutineTable[65] = KiFastCallEntryAddr;
    if (KiFastCallEntryAddr)
    {
        *((int *)RoutineTable + 128) = (int)(KiFastCallEntryAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "KiFastCallEntry");
        StringCopy((UCHAR *)RoutineTable + 444, (__int64)NameBuffer, 0x40);
    }

    // KiInsertQueueApc
    KiInsertQueueApcAddr = GtRead(GtKiInsertQueueApcFunc);
    RoutineTable[76] = KiInsertQueueApcAddr;
    if (!KiInsertQueueApcAddr)
    {
        InitHookFunctionTable();
        RoutineTable[76] = GtRead(GtKiInsertQueueApcFunc);
    }
    if (RoutineTable[76])
    {
        *((int *)RoutineTable + 150) = *((int *)RoutineTable + 152) - NtBaseInt;
        strcpy((char *)NameBuffer, "KiInsertQueueApc");
        StringCopy((UCHAR *)RoutineTable + 532, (__int64)NameBuffer, 0x40);
    }

    // IopfCallDriver
    IopfCallDriverAddr = GtRead(GtIopfCallDriverAddr);
    RoutineTable[87] = IopfCallDriverAddr;
    if (IopfCallDriverAddr)
    {
        *((int *)RoutineTable + 172) = (int)(IopfCallDriverAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "IopfCallDriver");
        StringCopy((UCHAR *)RoutineTable + 620, (__int64)NameBuffer, 0x40);
    }

    // IopfCompleteRequest
    IopfCompleteRequestAddr = GtRead(GtIopfCompleteRequestAddr);
    RoutineTable[98] = IopfCompleteRequestAddr;
    if (IopfCompleteRequestAddr)
    {
        *((int *)RoutineTable + 194) = (int)(IopfCompleteRequestAddr - NtBaseInt);
        strcpy((char *)NameBuffer, "IopfCompleteRequest");
        StringCopy((UCHAR *)RoutineTable + 708, (__int64)NameBuffer, 0x40);
    }

    GtWrite(GtKernelRoutineTableCount, 9);
    return (_QWORD *)GtWrite(GtKernelRoutineTable, (__int64)RoutineTable);
}

// ReadNtoskrnlFile — 从磁盘读取 ntoskrnl.exe 文件
// 对应原始驱动 sub_1400051F0
// 解析 PE 头，分配缓冲区，调用 ParseNtExportDir 构建导出表索引
// 【⚠ 重大修正 2026-10-16】原实现在成功路径上**无条件 ExFree(Src)**，而原始是把
//   `Src` 写入 GT[GtEprocessField22]（槽 32）后**刻意保留**（生命周期内不释放），
//   只释放 RawFileData。悬空指针随即被 BuildHookTable 取出并传给 GetExportDirSize，
//   读 [Src+0x3C] 时页面已回收/未映射 → BSOD 0x50（Arg1 为页对齐的池地址）。
//   原始控制流（LABEL_10 只 ExFree(RawFileData)）：成功时 Src 与展开缓冲均保留。
char ReadNtoskrnlFile(void)
{
    char Success = 0;
    WORD *FileBufferPtr;
    __int64 NtoskrnlBase = 0;
    int *ImageBuffer;
    char *PeSignature;
    ULONG OptHeaderOffset;
    char *NtHeaders;
    __int64 SectionHeader = 0, SectionHeadersEnd = 0;
    size_t FileSize = 0;        /* 展开后镜像大小（ReadNtFileToBuffer 出参） */
    size_t RawFileSize = 0;     /* 原始文件大小（ReadFileRawData 出参） */
    void *Src = NULL, *RawFileData = NULL;

    FileBufferPtr = (WORD *)GtAlloc(GtPathBuffer00);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);

    if (!*(ULONG64 *)FileBufferPtr || !NtoskrnlBase)
        return Success;
    if (ReadFileRawData(FileBufferPtr, &RawFileData, (ULONG *)&RawFileSize, 1))
        return Success;

    if (ReadNtFileToBuffer((PUCHAR)RawFileData, (ULONG)RawFileSize, (PUCHAR *)&Src, (PULONG)&FileSize) == 1)
    {
        ImageBuffer = ExAlloc(PagedPool, (ULONG)(FileSize + 256));
        if (ImageBuffer)
        {
            memmove(ImageBuffer, Src, (ULONG)FileSize);
            memset((char *)ImageBuffer + (ULONG)FileSize, 0, 0x100);

            if (ParseNtExportDir((PUCHAR)ImageBuffer, (ULONG)FileSize, NtoskrnlBase, 0) == 1)
            {
                GtWrite(GtEprocessField22, (__int64)Src);
                GtWrite(GtEprocessField23, (ULONG)FileSize);
                PeSignature = (char *)Src + *((int *)Src + 15);
                OptHeaderOffset = *((WORD *)PeSignature + 3);
                NtHeaders = &PeSignature[*((WORD *)PeSignature + 10)];
                GtWrite(GtEprocessField24, (__int64)PeSignature);
                GtWrite(GtEprocessField25, OptHeaderOffset);
                GtWrite(GtEprocessField26, (__int64)(NtHeaders + 24));
                GtWrite(GtEprocessField66, (__int64)ImageBuffer);
                SectionHeader = (__int64)ImageBuffer + ImageBuffer[15];
                SectionHeadersEnd = *(WORD *)(SectionHeader + 20) + SectionHeader + 24;
                GtWrite(GtEprocessField67, SectionHeader);
                GtWrite(GtEprocessField68, SectionHeadersEnd);
                Success = 1;
                /* 成功：Src 与 ImageBuffer 保留（槽 32/66 引用），只释放原始文件缓冲 */
                ExFree(RawFileData);
                return Success;
            }
            ExFree(ImageBuffer);
        }
        ExFree(Src);
    }

    ExFree(RawFileData);
    return Success;
}

// CleanupNtoskrnlFile — 清理 ntoskrnl 文件数据
// 对应原始驱动 sub_140005374
// 返回 ntoskrnl 导出目录缓冲区指针
__int64 CleanupNtoskrnlFile(void)
{
    void *ExportDirBuffer;
    void *result;
    void *NtImageBuffer;

    ExportDirBuffer = (void *)GtRead(GtEprocessField22);
    result = (void *)GtRead(GtEprocessField66);
    NtImageBuffer = result;
    if (ExportDirBuffer)
    {
        ExFree(ExportDirBuffer);
        result = (void *)GtWrite(GtEprocessField22, 0);
    }
    if (NtImageBuffer)
    {
        ExFree(NtImageBuffer);
        return (__int64)(ULONG_PTR)GtWrite(GtEprocessField66, 0);
    }
    return (__int64)result;
}

// InitSdstServiceCount — 初始化 SSDT 服务计数
// 对应原始驱动 sub_140021004
__int64 InitSdstServiceCount(void)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    if (BuildNumber == 2195)
        return GtWrite(GtSdstServiceCount, 308);
    if (BuildNumber == 2600)
        return GtWrite(GtSdstServiceCount, 320);
    if (BuildNumber == 3790)
        return GtWrite(GtSdstServiceCount, 277);
    if (BuildNumber >= 0x1770 && BuildNumber <= 0x1772)
        return GtWrite(GtSdstServiceCount, 231);
    if (BuildNumber >= 0x1DB0 && BuildNumber <= 0x1DB1)
        return GtWrite(GtSdstServiceCount, 502);
    if (BuildNumber == 9200 || BuildNumber == 9600 || BuildNumber >= 0x2800)
        return GtWrite(GtSdstServiceCount, 562);

    return 0;
}

// IsExportForwarder — 检查导出条目是否为转发器
// 对应原始驱动 sub_140006198
// 检测导出标志位第 25 位
char IsExportForwarder(PUCHAR ExportEntry)
{
    return (*(PULONG)(ExportEntry + 36) >> 25) & 1;
}

// CheckExportEntryFlags — 检查导出条目标志位
// 对应原始驱动 sub_1400061A4
// 检测 0x20000020 标志
char CheckExportEntryFlags(PUCHAR ExportEntry)
{
    return (*(PULONG)(ExportEntry + 36) & 0x20000020) != 0;
}

// GetExportEntrySignBit — 获取导出条目符号位
// 对应原始驱动 sub_1400061B0
// 返回最高位（第 31 位）
char GetExportEntrySignBit(PUCHAR ExportEntry)
{
    return *(PULONG)(ExportEntry + 36) >> 31;
}

// LookupExportByName — 按名称查找导出函数
// 对应原始驱动 sub_140005AC8
// 遍历 PE 导出目录的名称表，比较字符串，返回地址 RVA
char LookupExportByName(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, PULONG OutRva)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    PULONG AddressOfFunctions;
    PULONG AddressOfNames;
    PWORD AddressOfNameOrdinals;
    ULONG ExportDirRva, ExportDirSize;
    ULONG EndRva;
    ULONG FuncTableBase, NameTableBase, OrdinalTableBase;
    ULONG i;
    PUCHAR FuncNamePtr;
    int Cmp = 0;
    PULONG NameArrayEntry;
    WORD NameIndex;
    ULONG FuncRva;

    DosHeader = (PIMAGE_DOS_HEADER)PeBase;
    if (PeSize < sizeof(IMAGE_DOS_HEADER))
        return 0;

    NtHeaders = (PIMAGE_NT_HEADERS)(PeBase + DosHeader->e_lfanew);
    if ((ULONG_PTR)(NtHeaders + 1) > (ULONG_PTR)PeBase + PeSize)
        return 0;

    ExportDirRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExportDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    EndRva = ExportDirRva + ExportDirSize;

    if (ExportDirRva >= PeSize || ExportDirRva + 40 >= PeSize ||
        ExportDirSize >= PeSize || EndRva >= PeSize)
        return 0;

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)(PeBase + ExportDirRva);
    AddressOfFunctions = (PULONG)(PeBase + ExportDir->AddressOfFunctions);
    AddressOfNames = (PULONG)(PeBase + ExportDir->AddressOfNames);
    AddressOfNameOrdinals = (PWORD)(PeBase + ExportDir->AddressOfNameOrdinals);

    if (ExportDir->AddressOfFunctions < ExportDirRva ||
        ExportDir->AddressOfNames < ExportDirRva ||
        ExportDir->AddressOfNameOrdinals < ExportDirRva)
        return 0;

    FuncTableBase = ExportDir->AddressOfFunctions;
    NameTableBase = ExportDir->AddressOfNames;
    OrdinalTableBase = ExportDir->AddressOfNameOrdinals;

    if (4ULL * ExportDir->NumberOfFunctions + FuncTableBase > EndRva ||
        2ULL * ExportDir->NumberOfFunctions + NameTableBase > EndRva ||
        4ULL * ExportDir->NumberOfNames + OrdinalTableBase > EndRva)
        return 0;

    NameArrayEntry = AddressOfNames;
    for (i = 0; i < ExportDir->NumberOfNames; i++)
    {
        ULONG NameRva = *NameArrayEntry;
        if (NameRva >= ExportDirRva && NameRva < EndRva)
        {
            FuncNamePtr = PeBase + NameRva;
            Cmp = strcmp((const char *)FuncNamePtr, FuncName);
            if (Cmp == 0)
            {
                NameIndex = AddressOfNameOrdinals[i];
                if (NameIndex < ExportDir->NumberOfFunctions)
                {
                    FuncRva = AddressOfFunctions[NameIndex];
                    if (FuncRva < PeSize)
                    {
                        *OutRva = FuncRva;
                        return 1;
                    }
                }
            }
        }
        NameArrayEntry++;
    }
    return 0;
}

// FindPESectionByNameLocal — 按名称查找 PE 节
// 对应原始驱动 sub_140005C28
// 遍历节表，返回匹配节名的节在文件中的偏移
static __int64 FindPESectionByNameLocal(PUCHAR PeBase, PCHAR SectionName)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    WORD SectionCount;
    WORD i;

    DosHeader = (PIMAGE_DOS_HEADER)PeBase;
    NtHeaders = (PIMAGE_NT_HEADERS)(PeBase + DosHeader->e_lfanew);
    SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    SectionCount = NtHeaders->FileHeader.NumberOfSections;

    for (i = 0; i < SectionCount; i++)
    {
        if (strncmp((const char *)SectionHeader[i].Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return SectionHeader[i].PointerToRawData;
    }
    return 0;
}

// FindPESectionByNameReturnVaLocal — 按名称查找 PE 节返回 VA
// 对应原始驱动 sub_140005CB4
// 遍历节表，返回匹配节名的虚拟地址
static __int64 FindPESectionByNameReturnVaLocal(PUCHAR PeBase, PCHAR SectionName)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    WORD SectionCount;
    WORD i;

    DosHeader = (PIMAGE_DOS_HEADER)PeBase;
    NtHeaders = (PIMAGE_NT_HEADERS)(PeBase + DosHeader->e_lfanew);
    SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    SectionCount = NtHeaders->FileHeader.NumberOfSections;

    for (i = 0; i < SectionCount; i++)
    {
        if (strncmp((const char *)SectionHeader[i].Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return SectionHeader[i].VirtualAddress;
    }
    return 0;
}

// ReadNtFileToBuffer — 读取 PE 文件到缓冲区
// 对应原始驱动 sub_140005D4C
// 解析 PE 头，对齐节区，分配缓冲区并拷贝所有节数据
// ReadNtFileToBuffer — 读取 PE 文件到缓冲区（0x140005D4C，699 字节）
// 【⚠ 修正记录 2026-10-16】原实现把三个 OptionalHeader 字段**用错**：
//   原始字段映射（由 IDA 反编译 + 偏移反推双重确认）：
//     v8 = Src + e_lfanew（PE 签名处），v8[6..] 即 OptionalHeader 的 DWORD 数组
//     v16 = v8[14] = OptionalHeader+0x20 = **SectionAlignment**（作 VA 对齐掩码）
//     v15 = v8[15] = OptionalHeader+0x24 = **FileAlignment**（作 Raw 对齐掩码）
//     v17 = v8[20] = OptionalHeader+0x38 = **SizeOfImage**
//     v14 = v8[21] = OptionalHeader+0x3C = **SizeOfHeaders**
//   我方原实现：只取了 SectionAlignment/SizeOfImage/SizeOfHeaders 三者，
//   **完全漏掉 FileAlignment**，并把 SizeOfImage/SizeOfHeaders 的用途混淆，
//   导致节校验与展开逻辑与原始不一致 → 实机 ReadNtoskrnlFile 因此返回失败
//   （sc start 错误 31）。
// 【实机定位】用跨编译单元探针（保持产物 644096 字节健康）逐段二分：
//   跳过 ReadNtoskrnlFile 调用 → RUNNING；令其入口 return 1 → RUNNING；
//   让其走内部流程则失败；把各失败点打上不同 NTSTATUS 后 SCM 报
//   err 34 = 0xC0000013 = 本函数(ReadNtFileToBuffer) 的失败标记。
// 【语义】解析 PE：校验 DOS/NT 签名与节表边界，用 SectionAlignment 对齐各节 VA、
//   用 FileAlignment 对齐 SizeOfRawData，按边界调整节尺寸，
//   然后 ExAlloc(对齐后镜像大小+256)、memset 清零、拷头、逐节 memmove 展开。
// 【返回值】1 = 成功（*OutBuffer/*OutSize 有效）；0 = 失败。
char ReadNtFileToBuffer(PUCHAR Src, ULONG MaxCount, PUCHAR *OutBuffer, PULONG OutSize)
{
    ULONG  SrcSize = MaxCount;          // v4
    char   Result = 0;                  // v5
    PUCHAR pBase = Src;                 // v6
    ULONG  eLfanew;                     // v7
    ULONG *pNt;                         // v8
    ULONG  SectionCount;                // v9
    ULONG  OptSize;                     // v10
    PUCHAR pSection0;                   // v11
    PUCHAR pSectionLast;                // v12
    ULONG  HeaderEnd;                   // v13
    ULONG  SizeOfHeaders;               // v14 = v8[21]
    ULONG  FileAlignment;               // v15 = v8[15]
    ULONG  SectionAlignment;            // v16 = v8[14]
    ULONG  SizeOfImage;                 // v17 = v8[20]
    ULONG  VaMask, RawMask;             // v19 / v22
    ULONG  ImageLimit;                  // v20
    ULONG  i;                           // v23
    PUCHAR pSect;                       // v24
    PUCHAR Buffer;                      // v34/v35

    /* ① 长度与 DOS 签名（原始：`(MaxCount-513) <= 0x6FFFFDFE && *(WORD*)Src == 0x5A4D`） */
    if ((ULONG)(SrcSize - 513) > 0x6FFFFDFE || *(WORD *)pBase != IMAGE_DOS_SIGNATURE)
        return Result;

    eLfanew = *(ULONG *)(pBase + 0x3C);                              // Src[15]
    if (eLfanew >= SrcSize || (unsigned __int64)eLfanew + 24 >= SrcSize)
        return Result;

    pNt = (ULONG *)(pBase + eLfanew);                                // v8
    SectionCount  = *(WORD *)(pBase + eLfanew + 6);                  // v9  = FileHeader.NumberOfSections
    OptSize       = *(WORD *)(pBase + eLfanew + 20);                 // v10 = FileHeader.SizeOfOptionalHeader
    pSection0     = pBase + eLfanew + OptSize + 24;                  // v11 = 第一个节表项
    pSectionLast  = pSection0 + 40 * SectionCount - 40;              // v12
    HeaderEnd     = eLfanew + 40 * SectionCount + OptSize + 24;      // v13

    if (*pNt != IMAGE_NT_SIGNATURE || (SectionCount - 1) > 0x4E ||
        HeaderEnd >= SrcSize || OptSize >= SrcSize)
        return Result;

    SectionAlignment = pNt[14];   // OptionalHeader + 0x20
    FileAlignment    = pNt[15];   // OptionalHeader + 0x24
    SizeOfImage      = pNt[20];   // OptionalHeader + 0x38
    SizeOfHeaders    = pNt[21];   // OptionalHeader + 0x3C

    /* 【修正 2026-10-16】原写 `HeaderEnd > SizeOfImage`（v8[20]），原始是与
       **SizeOfHeaders**（v8[21]）比较：`v13 <= v14`。两者是不同的 OptionalHeader 字段。 */
    if (HeaderEnd > SizeOfHeaders || FileAlignment > 0x10000 || SectionAlignment > 0x10000)
        return Result;

    VaMask  = SectionAlignment - 1;                                  // v19
    RawMask = FileAlignment - 1;                                     // v22
    ImageLimit = ~VaMask & (VaMask + SizeOfImage);                   // v20：SizeOfImage 按 SectionAlignment 上对齐

    /* 末节表项 +0x0C = VirtualAddress(v18)、+0x08 = VirtualSize(v21)：
       原始要求 v18 <= ImageLimit 且 v21 < ImageLimit 且 v18+v21 <= ImageLimit
       （均取 uint32，故此处的 > / >= 与原始 <= / < 等价）。 */
    {
        ULONG LastVa       = *((ULONG *)pSectionLast + 3);           // v18 = 末节 VirtualAddress
        ULONG LastVirtSize = *((ULONG *)pSectionLast + 2);           // v21 = 末节 VirtualSize
        if (LastVa > ImageLimit
            || LastVirtSize >= ImageLimit
            || LastVa + LastVirtSize > ImageLimit)
        {
            return Result;
        }
    }
    if (RawMask > VaMask)
        return Result;

    /* ② 逐节校验并**就地改写** PointerToRawData 与 SizeOfRawData 为按 FileAlignment 对齐值
       （原始 sub_140005D4C 的循环：v24 指向节表 +0x14(PointerToRawData)）
       【修正 2026-10-16】原实现有三处与原始不符：
         ① 误把对齐值写回 VirtualSize(+0x08) —— 原始从不改 VirtualSize；
         ② 非末节用"前一节"比较 —— 原始比较的是**下一节** VirtualAddress(v24[8])；
         ③ 未把对齐后的 PointerToRawData 写回。
       三者叠加导致 i>=1 时几乎必然 break → i<SectionCount → 返回 0 → 实机错误 31。 */
    i = 0;
    pSect = pSection0;
    if (SectionCount)
    {
        do
        {
            ULONG Va     = *(ULONG *)(pSect + 0x0C);   // v26 = VirtualAddress
            ULONG RawPtr;                              // v27 = PointerToRawData
            ULONG RawSize;                             // v28 = SizeOfRawData

            if (Va > ImageLimit || (Va & VaMask) != 0)
                break;

            RawPtr  = *(ULONG *)(pSect + 0x14);
            if (RawPtr > SrcSize)
                break;

            RawSize = *(ULONG *)(pSect + 0x10);
            if (RawSize > SrcSize || RawSize + RawPtr > SrcSize)
                break;

            if (pSect != pSectionLast)
            {
                ULONG NextVa = *(ULONG *)(pSect + 40 + 0x0C);
                if (Va > NextVa || Va + *(ULONG *)(pSect + 0x08) > NextVa)
                    break;
            }

            {
                ULONG AlignedPtr  = ~RawMask & RawPtr;             // v31
                ULONG AlignedSize = ~RawMask & (RawMask + RawSize); // v32
                *(ULONG *)(pSect + 0x14) = AlignedPtr;
                *(ULONG *)(pSect + 0x10) = AlignedSize;
                if (AlignedPtr > SrcSize || (int)AlignedSize < 0)
                    break;
                if (AlignedSize > SrcSize - AlignedPtr)
                    AlignedSize = SrcSize - AlignedPtr;
                *(ULONG *)(pSect + 0x10) = AlignedSize;

                if (pSect == pSectionLast)
                {
                    if (AlignedSize > ImageLimit - Va)
                        AlignedSize = ImageLimit - Va;
                    *(ULONG *)(pSect + 0x10) = AlignedSize;
                }
                else if (AlignedSize > *(ULONG *)(pSect + 40 + 0x0C) - Va)
                    break;
            }

            ++i;
            pSect += 40;
        } while (i < SectionCount);

        if (i < SectionCount)
            return Result;
    }

    /* ③ 分配按 SectionAlignment 对齐的镜像缓冲，清零后拷头、逐节展开 */
    Buffer = (PUCHAR)ExAlloc(PagedPool, ImageLimit + 256);
    if (!Buffer)
        return Result;

    memset(Buffer, 0, ImageLimit + 256);

    {
        ULONG HeaderSize = SizeOfHeaders;
        if (SrcSize < HeaderSize)
            HeaderSize = SrcSize;
        memmove(Buffer, pBase, HeaderSize);
    }

    /* 原始：每节拷贝长度 = min(VirtualSize(+0x08), SizeOfRawData(+0x10))，
       目标偏移 = VirtualAddress(+0x0C)，源偏移 = PointerToRawData(+0x14)。
       【修正 2026-10-16】原实现只用了 SizeOfRawData，未与 VirtualSize 取小值。 */
    for (i = 0; i < SectionCount; i++)
    {
        PUCHAR p = pSection0 + 40 * i;
        ULONG VirtSize = *(ULONG *)(p + 0x08);
        ULONG RawSize  = *(ULONG *)(p + 0x10);
        ULONG CopySize = (VirtSize < RawSize) ? VirtSize : RawSize;
        memmove(Buffer + *(ULONG *)(p + 0x0C),
                pBase   + *(ULONG *)(p + 0x14),
                CopySize);
    }

    Result = 1;
    *OutBuffer = Buffer;
    *OutSize = ImageLimit;
    return Result;
}

// ParseNtExportDir — 解析 PE 导出目录的重定位
// 对应原始驱动 sub_140006008
// 遍历基址重定位块，根据节偏移修正导出函数地址
// 注意：参数 3 (ImageBase) 和 4 (Flags) 在当前实现中不使用，保留以匹配调用约定
char ParseNtExportDir(PUCHAR ImageBase, ULONG ExportDirSize, ULONG64 ImageBaseUnused, int Flags)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION CurrentBlock;
    ULONG SizeOfBlock;
    PWORD RelocEntry;
    ULONG EntryCount;
    ULONG i;
    ULONG PageRva;
    ULONG RelocType;
    ULONG Offset;
    ULONG_PTR Delta;
    ULONG VirtualAddress;
    ULONG EndOffset;

    UNREFERENCED_PARAMETER(ImageBaseUnused);
    UNREFERENCED_PARAMETER(Flags);

    if (ExportDirSize == 0)
        return 1;

    DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    NtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);

    VirtualAddress = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    SizeOfBlock = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (VirtualAddress >= ExportDirSize || VirtualAddress + 8 >= ExportDirSize ||
        SizeOfBlock >= ExportDirSize || VirtualAddress + SizeOfBlock > ExportDirSize)
        return 0;

    Delta = (ULONG_PTR)ImageBase - NtHeaders->OptionalHeader.ImageBase;
    EndOffset = VirtualAddress + SizeOfBlock;
    CurrentBlock = (PIMAGE_BASE_RELOCATION)(ImageBase + VirtualAddress);

    while ((ULONG_PTR)(CurrentBlock + 1) <= (ULONG_PTR)ImageBase + EndOffset)
    {
        PageRva = CurrentBlock->VirtualAddress;
        SizeOfBlock = CurrentBlock->SizeOfBlock;

        if (PageRva >= ExportDirSize || SizeOfBlock > ExportDirSize || SizeOfBlock <= 8)
            break;

        if ((PUCHAR)CurrentBlock + SizeOfBlock > ImageBase + EndOffset)
            break;

        EntryCount = (SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        RelocEntry = (PWORD)(CurrentBlock + 1);

        for (i = 0; i < EntryCount; i++)
        {
            ULONG Entry = RelocEntry[i];
            RelocType = Entry >> 12;
            Offset = Entry & 0xFFF;

            if (Offset + PageRva + sizeof(ULONG) > ExportDirSize)
                break;

            if (RelocType == IMAGE_REL_BASED_HIGHLOW)
            {
                *(PULONG)(ImageBase + PageRva + Offset) += (ULONG)Delta;
            }
            else if (RelocType == IMAGE_REL_BASED_DIR64)
            {
                *(PULONG64)(ImageBase + PageRva + Offset) += Delta;
            }
        }

        if (i < EntryCount)
            break;

        CurrentBlock = (PIMAGE_BASE_RELOCATION)((PUCHAR)CurrentBlock + SizeOfBlock);
    }

    return 1;
}

// 对应原始驱动 sub_140005484
// 遍历导出名称表，比较字符串，返回对应 RVA。支持 32/64 位 PE。
__int64 FindExportByNameInPeBody(PUCHAR PeBase, ULONG PeSize, PCHAR FuncName, int Is64Bit)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_NT_HEADERS32 NtHeaders32;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG ExportDirRva, ExportDirSize, EndRva;
    ULONG FuncRva, NameRva;
    ULONG FuncTableBase, NameTableBase, OrdinalTableBase;
    ULONG NumberOfFunctions, NumberOfNames;
    ULONG i;
    PULONG NameArrayEntry, FuncArrayEntry;
    PWORD OrdinalEntry;
    WORD Ordinal;
    PUCHAR NamePtr;
    int Cmp = 0;

    DosHeader = (PIMAGE_DOS_HEADER)PeBase;
    if (PeSize < sizeof(IMAGE_DOS_HEADER))
        return 0;

    if (Is64Bit == 1)
    {
        NtHeaders = (PIMAGE_NT_HEADERS)(PeBase + DosHeader->e_lfanew);
        ExportDirRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    else
    {
        NtHeaders32 = (PIMAGE_NT_HEADERS32)(PeBase + DosHeader->e_lfanew);
        ExportDirRva = NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ExportDirSize = NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    EndRva = ExportDirRva + ExportDirSize;

    if (ExportDirRva >= PeSize || ExportDirRva + 40 >= PeSize ||
        ExportDirSize >= PeSize || EndRva >= PeSize)
        return 0;

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)(PeBase + ExportDirRva);
    NumberOfFunctions = ExportDir->NumberOfFunctions;
    NumberOfNames = ExportDir->NumberOfNames;
    FuncTableBase = ExportDir->AddressOfFunctions;
    NameTableBase = ExportDir->AddressOfNames;
    OrdinalTableBase = ExportDir->AddressOfNameOrdinals;

    if (FuncTableBase < ExportDirRva || NameTableBase < ExportDirRva || OrdinalTableBase < ExportDirRva)
        return 0;

    if (4ULL * NumberOfFunctions + FuncTableBase > EndRva ||
        2ULL * NumberOfNames + NameTableBase > EndRva ||
        4ULL * NumberOfNames + OrdinalTableBase > EndRva)
        return 0;

    NameArrayEntry = (PULONG)(PeBase + NameTableBase);
    FuncArrayEntry = (PULONG)(PeBase + FuncTableBase);
    OrdinalEntry = (PWORD)(PeBase + OrdinalTableBase);

    for (i = 0; i < NumberOfNames; i++)
    {
        NameRva = NameArrayEntry[i];
        if (NameRva >= ExportDirRva && NameRva < EndRva)
        {
            NamePtr = PeBase + NameRva;
            Cmp = strcmp((const char *)NamePtr, FuncName);
            if (Cmp == 0)
            {
                Ordinal = OrdinalEntry[i];
                if (Ordinal < NumberOfFunctions)
                {
                    FuncRva = FuncArrayEntry[Ordinal];
                    if (FuncRva < PeSize && (FuncRva < ExportDirRva || FuncRva >= EndRva))
                        return FuncRva;
                }
            }
        }
    }
    return 0;
}

// InitPESectionReadContext 已移至 PEDecoder.c

// ============================================================
// SSDT 命令处理函数实现
// ============================================================

// CmdInitSsdtTable — 初始化 SSDT 表
// 对应原始驱动 sub_140060A68
__int64 CmdInitSsdtTable(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, int BufferSize)
{
    char Result = 0;
    if (!(unsigned int)GtRead(GtEprocessExtField13))
        InitKernelDataSectionTable();
    if (!(unsigned int)GtRead(GtEprocessExtField13)
        && OutputBuffer
        && BufferSize == 4
        && (unsigned __int64)OutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(OutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, 4u, 4u);
        *OutputBuffer = 0;
        return 1;
    }
    return Result;
}

// CmdEnumSyscallEntries — 枚举系统调用条目
// 对应原始驱动 sub_1400538C8
__int64 CmdEnumSyscallEntries(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        TableReady = (int)GtRead(GtEprocessField135 | 0x100);
        if (!TableReady)
        {
            InitDiskQueryExportTable();
            TableReady = (int)GtRead(GtEprocessField135 | 0x100);
        }
        if (EnumSyscallTable7((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopySyscallTable7((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSyscallHookEntries((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSystemHook — 安装系统钩子
// 对应原始驱动 sub_1400539FC
__int64 CmdInstallSystemHook(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = WriteTcpIpSyscallEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumShadowSyscallEntries — 枚举 Shadow SSDT 条目
// 对应原始驱动 sub_14003D464
__int64 CmdEnumShadowSyscallEntries(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int IsReady = 0;

    if (pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        IsReady = (int)GtRead(GtCallbackField15);
        if (!IsReady)
        {
            InitShadowSyscallExportTable();
            IsReady = (int)GtRead(GtCallbackField15);
        }
        if (EnumShadowSyscallTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopyShadowSyscallTable((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallShadowHook — 安装 Shadow SSDT 钩子
// 对应原始驱动 sub_14003D6C4
__int64 CmdInstallShadowHook(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = WriteShadowSyscallEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable2 — 枚举系统调用表 2
// 对应原始驱动 sub_1400338A0
__int64 CmdEnumSyscallTable2(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1400
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1400) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x578u, 1u);
        memset(pOutputBuffer, 0, 0x578u);
        TableReady = (int)GtRead(GtCallbackField37);
        if (!TableReady)
        {
            BuildSsdtHookTargets2();
            TableReady = (int)GtRead(GtCallbackField37);
        }
        if (EnumSsdtFunctionTable2((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopySsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable((__int64)(pOutputBuffer + 8)) == 1)
                {
                    if (*((_QWORD *)pOutputBuffer + 171))
                    {
                        if (*((_DWORD *)pOutputBuffer + 339))
                            pOutputBuffer[1] = 1;
                    }
                    else
                    {
                        *((_QWORD *)pOutputBuffer + 170) = 0;
                    }
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook2 — 安装系统调用钩子 2
// 对应原始驱动 sub_140033B38
__int64 CmdInstallSyscallHook2(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = SetSyscallHookEntry2((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable3 — 枚举系统调用表 3
// 对应原始驱动 sub_140032D40
__int64 CmdEnumSyscallTable3(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int HookTableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1864
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1864) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x748u, 1u);
        memset(pOutputBuffer, 0, 0x748u);
        HookTableReady = (int)GtRead(GtCallbackField44);
        if (!HookTableReady)
        {
            BuildSsdtHookTargets3();
            HookTableReady = (int)GtRead(GtCallbackField44);
        }
        if (InitContextTableFromSyscallBase((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (HookTableReady)
            {
                if (CopySsdtHookTargetTable3((__int64)(pOutputBuffer + 8)) == 1
                    && ResolveContextTableMemory((__int64)(pOutputBuffer + 8)) == 1)
                {
                    if (*((_DWORD *)pOutputBuffer + 451))
                        pOutputBuffer[1] = 1;
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook3 — 安装系统调用钩子 3（64字节输入）
// 对应原始驱动 sub_140032FE0
__int64 CmdInstallSyscallHook3(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData[2];

    if (pInputBuffer
        && InputSize == 64
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 64) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x40u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = InstallSsdtHookEntry3((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart)
            {
                PatchResult = 0;
                if (MmIsAddressValid(TargetAddress) == 1
                    && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 31LL)) == 1)
                {
                    PatchData[0] = *(_OWORD *)(pInputBuffer + 26);
                    PatchData[1] = *(_OWORD *)(pInputBuffer + 42);
                    PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), PatchData, 0x20u, 0, 0);
                }
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable4 — 枚举系统调用表 4
// 对应原始驱动 sub_1400316E0
__int64 CmdEnumSyscallTable4(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int HookTableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        HookTableReady = (int)GtRead(GtCallbackField49);
        if (!HookTableReady)
        {
            BuildSsdtHookTargets4();
            HookTableReady = (int)GtRead(GtCallbackField49);
        }
        if (EnumSsdtFunctionTable4((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (HookTableReady)
            {
                if (CopySsdtHookTargetTable((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook4 — 安装系统调用钩子 4
// 对应原始驱动 sub_140031934
__int64 CmdInstallSyscallHook4(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    void *TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = InstallSsdtHookEntry4((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            TargetAddress = (void *)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress)
            {
                PatchResult = 0;
                if (MmIsAddressValid(TargetAddress) == 1
                    && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
                {
                    PatchData = *(_OWORD *)(pInputBuffer + 26);
                    PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
                }
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable5 — 枚举系统调用表 5 (StorPort)
// 对应原始驱动 sub_140050AC0
__int64 CmdEnumSyscallTable5(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1400
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1400) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x578u, 1u);
        memset(pOutputBuffer, 0, 0x578u);
        TableReady = (int)GtRead(GtCallbackField61);
        if (!TableReady)
        {
            ParseStorPortExportDir();
            TableReady = (int)GtRead(GtCallbackField61);
        }
        if (FillSyscallTableInfo((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (DuplicateSyscallTableEntries((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable((__int64)(pOutputBuffer + 8)) == 1)
                {
                    if (*((_DWORD *)pOutputBuffer + 339))
                        pOutputBuffer[1] = 1;
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook5 — 安装系统调用钩子 5
// 对应原始驱动 sub_140050D64
__int64 CmdInstallSyscallHook5(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char SyscallTableEntry = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        SyscallTableEntry = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            SyscallTableEntry = GetSyscallTableEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return SyscallTableEntry & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable6 — 枚举系统调用表 6
// 对应原始驱动 sub_14003DD2C
__int64 CmdEnumSyscallTable6(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int IsReady = 0;

    if (pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        IsReady = (int)GtRead(GtCallbackField72);
        if (!IsReady)
        {
            ParseSyscallFileExportDir();
            IsReady = (int)GtRead(GtCallbackField72);
        }
        if (EnumSyscallTable6((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopySyscallTableEntryArray((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook6 — 安装系统调用钩子 6
// 对应原始驱动 sub_14003DF8C
__int64 CmdInstallSyscallHook6(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char IsHookReady = 0;
    char IsPatchReady = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        IsHookReady = 1;
        IsPatchReady = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            IsHookReady = SetSyscallHookEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            IsPatchReady = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                IsPatchReady = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return IsHookReady & IsPatchReady;
    }
    return Result;
}

// CmdEnumSyscallTable7 — 枚举系统调用表 7 (TCP/IP)
// 对应原始驱动 sub_140046C2C
__int64 CmdEnumSyscallTable7(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int IsReady = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770
        && pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        IsReady = (int)GtRead(GtCallbackField80);
        if (!IsReady)
        {
            BuildSyscallExportTable();
            IsReady = (int)GtRead(GtCallbackField80);
        }
        if (InitSyscallExportEntryArray((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopySyscallExportEntries((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook7 — 安装系统调用钩子 7
// 对应原始驱动 sub_140046EA4
__int64 CmdInstallSyscallHook7(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char IsContextSet = 0;
    char IsBufferWritten = 0;
    PVOID pTargetAddress;
    _OWORD BufferData;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770
        && pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        IsContextSet = 1;
        IsBufferWritten = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            IsContextSet = WriteSyscallContextEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            IsBufferWritten = 0;
            pTargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (pTargetAddress > MmSystemRangeStart
                && MmIsAddressValid(pTargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                BufferData = *(_OWORD *)(pInputBuffer + 26);
                IsBufferWritten = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &BufferData, 0x10u, 0, 0);
            }
        }
        return IsContextSet & IsBufferWritten;
    }
    return Result;
}

// CmdEnumSyscallTable8 — 枚举系统调用表 8 (Win32k)
// 对应原始驱动 sub_140054050
__int64 CmdEnumSyscallTable8(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableReady = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770
        && pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        TableReady = (int)GtRead(GtCallbackField83);
        if (!TableReady)
        {
            InitWin32kSyscallTable();
            TableReady = (int)GtRead(GtCallbackField83);
        }
        if (CopyWin32kServiceTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (DuplicateSyscallTableOutput((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook8 — 安装系统调用钩子 8 (Win32k)
// 对应原始驱动 sub_1400542B4
__int64 CmdInstallSyscallHook8(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    PVOID TargetAddress;
    _OWORD PatchData;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770
        && pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = SetWin32kServiceTableEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart
                && MmIsAddressValid(TargetAddress) == 1
                && MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumSyscallTable9 — 枚举系统调用表 9
// 对应原始驱动 sub_1400869C0
__int64 CmdEnumSyscallTable9(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableReady = 0;

    if (pOutputBuffer
        && OutputSize == 1352
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548u, 1u);
        memset(pOutputBuffer, 0, 0x548u);
        TableReady = (int)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField157);
        if (!TableReady)
        {
            ParseSyscallTableExportDir();
            TableReady = (int)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField157);
        }
        if (CopySyscallTableEntries((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopySyscallTableToBuffer((__int64)(pOutputBuffer + 8)) == 1
                    && ValidateSyscallTableEntries((__int64)(pOutputBuffer + 8)) == 1)
                    *pOutputBuffer = 1;
            }
        }
    }
    return Result;
}

// CmdInstallSyscallHook9 — 安装系统调用钩子 9
// 对应原始驱动 sub_14008719C
__int64 CmdInstallSyscallHook9(char *pInputBuffer, int InputSize)
{
    char Result = 0;
    char HookResult = 0;
    char PatchResult = 0;
    _OWORD PatchData;

    if (pInputBuffer
        && InputSize == 48
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = WriteWdfSyscallHook((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            if (CheckMemoryValid(*((void **)pInputBuffer + 1)) == 1
                && CheckMemoryValid((void *)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10u, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdGetSsdtTableInfo — 获取 SSDT 表信息
// 对应原始驱动 sub_140067DBC
__int64 CmdGetSsdtTableInfo(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    __int64 TdiExportTable = 0;
    __int64 TdiRelocTable = 0;
    __int64 DataSectionOffset = 0;
    _QWORD *KernelDataSection;
    __int64 DataSectionField = 0;

    if (!GtRead(GtEprocessField01 | 0x800))
        InitTdiExportAndRelocTable();
    TdiExportTable = GtRead(GtEprocessOffsetBase | 0x800);
    TdiRelocTable = GtRead(GtEprocessField01 | 0x800);
    if (TdiExportTable && TdiRelocTable)
    {
        if (!GtRead(GtEprocessExtField31))
            InitKernelDataSectionTable();
        KernelDataSection = (_QWORD *)GtRead(GtEprocessExtField30);
        DataSectionField = GtRead(GtEprocessExtField31);
        if (KernelDataSection
            && DataSectionField
            && pOutputBuffer
            && OutputSize == 48
            && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
            && (unsigned __int64)(pOutputBuffer + 6) < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, 0x30u, 8u);
            memset(pOutputBuffer, 0, 0x30u);
            pOutputBuffer[2] = TdiExportTable;
            pOutputBuffer[3] = TdiRelocTable;
            pOutputBuffer[4] = *KernelDataSection;
            pOutputBuffer[5] = *(_QWORD *)DataSectionField;
            return 1;
        }
    }
    return Result;
}

// CmdRestoreSsdtTable — 恢复 SSDT 表
// 对应原始驱动 sub_140068054
__int64 CmdRestoreSsdtTable(void)
{
    char Result = 0;
    __int64 TdiExportTable = 0;
    __int64 TdiRelocTable = 0;
    _QWORD *KernelDataSection;
    _QWORD *DataSectionField;

    if (!GtRead(GtEprocessField01 | 0x800))
        InitTdiExportAndRelocTable();
    TdiExportTable = GtRead(GtEprocessOffsetBase | 0x800);
    TdiRelocTable = GtRead(GtEprocessField01 | 0x800);
    if (TdiExportTable && TdiRelocTable)
    {
        if (!GtRead(GtEprocessExtField31))
            InitKernelDataSectionTable();
        KernelDataSection = (_QWORD *)GtRead(GtEprocessExtField30);
        DataSectionField = (_QWORD *)GtRead(GtEprocessExtField31);
        if (KernelDataSection && DataSectionField)
        {
            *KernelDataSection = TdiExportTable;
            Result = 1;
            *DataSectionField = TdiRelocTable;
        }
    }
    return Result;
}

// CmdQuerySsdtDetails — 查询 SSDT 详细信息
// 对应原始驱动 sub_140067428
__int64 CmdQuerySsdtDetails(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableCount = 0;
    _QWORD *ServiceTableBase;
    int ServiceTableCount = 0;
    unsigned int *ServiceTableLimit;
    __int64 ServiceTableArray[6];

    if (!(unsigned int)GtRead(GtEprocessExtField46))
        InitKernelDataSectionTable();
    TableCount = (int)GtRead(GtEprocessExtField46);
    ServiceTableBase = (_QWORD *)GtRead(GtEprocessExtField47);
    ServiceTableCount = (int)GtRead(GtEprocessExtField48);
    ServiceTableLimit = (unsigned int *)GtRead(GtEprocessExtField49);
    ServiceTableArray[0] = GtRead(GtEprocessExtField50);
    ServiceTableArray[1] = GtRead(GtEprocessExtField51);
    ServiceTableArray[2] = GtRead(GtEprocessExtField52);
    ServiceTableArray[3] = GtRead(GtEprocessExtField53);
    ServiceTableArray[4] = GtRead(GtEprocessExtField54);
    ServiceTableArray[5] = GtRead(GtEprocessExtField55);

    if (TableCount
        && ServiceTableBase
        && ServiceTableCount
        && ServiceTableLimit
        && ServiceTableArray[0]
        && ServiceTableArray[1]
        && ServiceTableArray[2]
        && ServiceTableArray[3]
        && ServiceTableArray[4]
        && ServiceTableArray[5]
        && pOutputBuffer
        && OutputSize == 176
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 22) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0xB0u, 8u);
        memset(pOutputBuffer, 0, 0xB0u);
        *(_DWORD *)pOutputBuffer = 7;
        pOutputBuffer[1] = (_QWORD)ServiceTableBase;
        pOutputBuffer[2] = (_QWORD)((char *)ServiceTableLimit + *ServiceTableLimit + 4);
        pOutputBuffer[4] = ServiceTableArray[0];
        pOutputBuffer[5] = ServiceTableBase[1];
        pOutputBuffer[7] = ServiceTableArray[1];
        pOutputBuffer[8] = ServiceTableBase[2];
        pOutputBuffer[10] = ServiceTableArray[2];
        pOutputBuffer[11] = ServiceTableBase[3];
        pOutputBuffer[13] = ServiceTableArray[3];
        pOutputBuffer[14] = ServiceTableBase[4];
        pOutputBuffer[16] = ServiceTableArray[4];
        pOutputBuffer[17] = ServiceTableBase[5];
        pOutputBuffer[19] = ServiceTableArray[5];
        pOutputBuffer[20] = ServiceTableBase[6];
        return 1;
    }
    return Result;
}

// CmdSetSsdtEntry — 设置 SSDT 条目
// 对应原始驱动 sub_140067664
__int64 CmdSetSsdtEntry(_DWORD *pInputBuffer, int InputSize)
{
    char Result = 0;
    int TableCount = 0;
    __int64 ServiceTableBase = 0;
    int ServiceTableCount = 0;
    unsigned __int64 ServiceTableLimit;
    __int64 ServiceTableArray[6];
    unsigned __int64 TargetAddress;
    __int64 NewValue = 0;

    if (!(unsigned int)GtRead(GtEprocessExtField46))
        InitKernelDataSectionTable();
    TableCount = (int)GtRead(GtEprocessExtField46);
    ServiceTableBase = GtRead(GtEprocessExtField47);
    ServiceTableCount = (int)GtRead(GtEprocessExtField48);
    ServiceTableLimit = GtRead(GtEprocessExtField49);
    ServiceTableArray[0] = GtRead(GtEprocessExtField50);
    ServiceTableArray[1] = GtRead(GtEprocessExtField51);
    ServiceTableArray[2] = GtRead(GtEprocessExtField52);
    ServiceTableArray[3] = GtRead(GtEprocessExtField53);
    ServiceTableArray[4] = GtRead(GtEprocessExtField54);
    ServiceTableArray[5] = GtRead(GtEprocessExtField55);

    if (TableCount
        && ServiceTableBase
        && ServiceTableCount
        && ServiceTableLimit
        && ServiceTableArray[0]
        && ServiceTableArray[1]
        && ServiceTableArray[2]
        && ServiceTableArray[3]
        && ServiceTableArray[4]
        && ServiceTableArray[5]
        && pInputBuffer
        && InputSize == 4
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 4u, 4u);
        Result = 1;
        switch (*pInputBuffer)
        {
        case 0:
            return WritePhysicalMemoryBuffer((unsigned __int64)ServiceTableLimit, &ServiceTableCount, 4u, 0, 0) != 0;
        case 1:
            TargetAddress = ServiceTableBase + 8;
            NewValue = ServiceTableArray[0];
            break;
        case 2:
            TargetAddress = ServiceTableBase + 16;
            NewValue = ServiceTableArray[1];
            break;
        case 3:
            TargetAddress = ServiceTableBase + 24;
            NewValue = ServiceTableArray[2];
            break;
        case 4:
            TargetAddress = ServiceTableBase + 32;
            NewValue = ServiceTableArray[3];
            break;
        case 5:
            TargetAddress = ServiceTableBase + 40;
            NewValue = ServiceTableArray[4];
            break;
        case 6:
            TargetAddress = ServiceTableBase + 48;
            NewValue = ServiceTableArray[5];
            break;
        default:
            return 0;
        }
        WritePhysicalMemoryQword(TargetAddress, NewValue);
    }
    return Result;
}

// CmdReadExportDirectory — 读取导出目录
// 对应原始驱动 sub_1400608E4
__int64 CmdReadExportDirectory(__int64 InputBuffer, __int64 InputSize, char *OutputBuffer, unsigned int BufferSize)
{
    SIZE_T Size = BufferSize;
    char Result = 0;
    const void *ExportDirData;
    unsigned int ExportDirSize = 0;
    __int64 KernelBase = 0;
    char *pEntry;

    if (!GtRead(GtEprocessExtField56))
        InitKernelDataSectionTable();
    ExportDirData = (const void *)GtRead(GtEprocessExtField56);
    GtAlloc(GtEprocessExtField58);
    ExportDirSize = (unsigned int)GtRead(GtEprocessExtField57);
    KernelBase = GtRead(GtEprocessExtField11);

    if (KernelBase
        && ExportDirData
        && ExportDirSize
        && (unsigned int)Size > 2 * ExportDirSize
        && Size >= 2 * (unsigned __int64)ExportDirSize + 48
        && OutputBuffer
        && (unsigned __int64)OutputBuffer < MmUserProbeAddress
        && (unsigned __int64)&OutputBuffer[Size] < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, (unsigned int)Size, 8u);
        memset(OutputBuffer, 0, (unsigned int)Size);
        memmove(OutputBuffer, ExportDirData, ExportDirSize);
        pEntry = &OutputBuffer[Size >> 1];
        memmove(pEntry, ExportDirData, ExportDirSize);
        while ((unsigned __int64)pEntry <= (unsigned __int64)&pEntry[ExportDirSize - 24])
        {
            if (*((_QWORD *)pEntry + 1))
                *((_QWORD *)pEntry + 1) = KernelBase + *((unsigned int *)pEntry + 2);
            if (*((_QWORD *)pEntry + 2))
                *((_QWORD *)pEntry + 2) = KernelBase + *((unsigned int *)pEntry + 4);
            pEntry += 24;
        }
        return 1;
    }
    return Result;
}

// CmdUpdateExportEntry — 更新导出条目
// 对应原始驱动 sub_140060AF4
__int64 CmdUpdateExportEntry(__int64 *pInputBuffer, int InputSize)
{
    char Result = 0;
    __int64 AddressValue1 = 0;
    __int64 AddressValue2 = 0;
    _QWORD *ExportDirData;
    unsigned int ExportDirSize = 0;
    __int64 *pExportEntryTable;
    __int64 KernelBase = 0;
    unsigned __int64 pEnd;
    unsigned __int64 pDataEnd;

    if (!GtRead(GtEprocessExtField56))
        InitKernelDataSectionTable();
    ExportDirData = (_QWORD *)GtRead(GtEprocessExtField56);
    ExportDirSize = (unsigned int)GtRead(GtEprocessExtField57);
    pExportEntryTable = GtAlloc(GtEprocessExtField58);
    KernelBase = GtRead(GtEprocessExtField11);

    if (KernelBase
        && ExportDirData
        && ExportDirSize
        && pInputBuffer
        && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8u, 8u);
        __int64 SearchValue = *pInputBuffer;
        pEnd = (unsigned __int64)pExportEntryTable + ExportDirSize - 24;
        while ((unsigned __int64)pExportEntryTable <= pEnd)
        {
            if (*pExportEntryTable == SearchValue)
            {
                if (pExportEntryTable[1])
                    AddressValue1 = KernelBase + *((unsigned int *)pExportEntryTable + 2);
                if (pExportEntryTable[2])
                    AddressValue2 = KernelBase + *((unsigned int *)pExportEntryTable + 4);
                break;
            }
            pExportEntryTable += 3;
        }
        pDataEnd = (unsigned __int64)ExportDirData + ExportDirSize - 24;
        while ((unsigned __int64)ExportDirData <= pDataEnd)
        {
            if (*ExportDirData == SearchValue)
            {
                WritePhysicalMemoryQword((unsigned __int64)(ExportDirData + 1), AddressValue1);
                WritePhysicalMemoryQword((unsigned __int64)(ExportDirData + 2), AddressValue2);
                return 1;
            }
            ExportDirData += 3;
        }
    }
    return Result;
}

// CmdRestoreExportTable — 恢复导出表
// 对应原始驱动 sub_140060C68
__int64 CmdRestoreExportTable(void)
{
    char Result = 0;
    unsigned __int64 ExportDirData;
    unsigned int ExportDirSize = 0;
    __int64 *pExportEntryTable;
    __int64 KernelBase = 0;

    if (!GtRead(GtEprocessExtField56))
        InitKernelDataSectionTable();
    ExportDirData = GtRead(GtEprocessExtField56);
    ExportDirSize = (unsigned int)GtRead(GtEprocessExtField57);
    pExportEntryTable = GtAlloc(GtEprocessExtField58);
    KernelBase = GtRead(GtEprocessExtField11);

    if (KernelBase && ExportDirData && ExportDirSize)
    {
        unsigned __int64 EndAddr = ExportDirSize + ExportDirData - 24;
        if (ExportDirData <= EndAddr)
        {
            _QWORD *pTableEntry = pExportEntryTable + 2;
            unsigned __int64 pDataCur = ExportDirData + 16;
            __int64 TableToDataDelta = ExportDirData - (_QWORD)pExportEntryTable;

            do
            {
                WritePhysicalMemoryQword((unsigned __int64)pTableEntry + TableToDataDelta - 16, *(pTableEntry - 2));
                __int64 Value1 = 0;
                if (*(pTableEntry - 1))
                    Value1 = KernelBase + *((unsigned int *)pTableEntry - 2);
                WritePhysicalMemoryQword(pDataCur - 8, Value1);
                __int64 Value2 = 0;
                if (*pTableEntry)
                    Value2 = KernelBase + *(unsigned int *)pTableEntry;
                WritePhysicalMemoryQword(pDataCur, Value2);
                pTableEntry += 3;
                pDataCur += 24;
            }
            while ((unsigned __int64)pTableEntry + TableToDataDelta - 16 <= EndAddr);
        }
        return 1;
    }
    return Result;
}

// CmdReadSsdtEntryTable — 读取 SSDT 条目表
// 对应原始驱动 sub_140028E60
__int64 CmdReadSsdtEntryTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
{
    unsigned __int64 OutputSize = OutputBufferSize;
    char Result = 0;
    unsigned __int64 SsdtBase;
    unsigned int SsdtCount = 0;
    unsigned __int64 NtBase;
    unsigned int NtImageBase = 0;
    unsigned __int64 NtEndAddr;

    SsdtBase = GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField187 | GtEprocessField06 | 0x100);
    SsdtCount = (unsigned int)GtRead(GtEprocessField94 | 0x800);
    NtBase = GtRead(GtNtoskrnlModuleBase);
    NtImageBase = (unsigned int)GtRead(GtNtoskrnlImageSize);

    if (SsdtBase && SsdtCount)
    {
        if (SsdtBase > (unsigned __int64)MmSystemRangeStart && SsdtCount < 0x100 && SsdtBase > NtBase)
        {
            NtEndAddr = NtImageBase + NtBase;
            if (SsdtBase < NtEndAddr
                && 8LL * SsdtCount + SsdtBase + 8 < NtEndAddr
                && pOutputBuffer
                && OutputSize >= 8 * (unsigned __int64)(SsdtCount - 1) + 16
                && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
            {
                ProbeForWrite(pOutputBuffer, (unsigned int)OutputSize, 8u);
                memset(pOutputBuffer, 0, (unsigned int)OutputSize);
                pOutputBuffer[1] = SsdtCount;
                *pOutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
                memmove(pOutputBuffer + 2, (const void *)(SsdtBase + 8), 8LL * SsdtCount);
                return 1;
            }
        }
    }
    return Result;
}

// CmdReadSsdtEntryTableEx — 读取 SSDT 条目表（扩展版）
// 对应原始驱动 sub_140029020
__int64 CmdReadSsdtEntryTableEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
{
    unsigned __int64 OutputSize = OutputBufferSize;
    char Result = 0;
    unsigned __int64 SsdtBase;
    unsigned int SsdtCount = 0;
    unsigned __int64 NtBase;
    unsigned int NtImageSize = 0;
    unsigned __int64 NtEndAddr;

    SsdtBase = GtRead((enum _GLOBAL_TABLE_INDEX)17408);
    SsdtCount = (unsigned int)GtRead(GtEprocessField95 | 0x800);
    NtBase = GtRead(GtNtoskrnlModuleBase);
    NtImageSize = (unsigned int)GtRead(GtNtoskrnlImageSize);

    if (SsdtBase && SsdtCount)
    {
        if (SsdtBase > (unsigned __int64)MmSystemRangeStart && SsdtCount < 0x100 && SsdtBase > NtBase)
        {
            NtEndAddr = NtImageSize + NtBase;
            if (SsdtBase < NtEndAddr
                && 8LL * SsdtCount + SsdtBase + 8 < NtEndAddr
                && pOutputBuffer
                && OutputSize >= 8 * (unsigned __int64)(SsdtCount - 1) + 16
                && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
            {
                ProbeForWrite(pOutputBuffer, (unsigned int)OutputSize, 8u);
                memset(pOutputBuffer, 0, (unsigned int)OutputSize);
                pOutputBuffer[1] = SsdtCount;
                *pOutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
                memmove(pOutputBuffer + 2, (const void *)(SsdtBase + 8), 8LL * SsdtCount);
                return 1;
            }
        }
    }
    return Result;
}

// CmdDispatchSsdtByVersion — SSDT 按版本分发
// 对应原始驱动 sub_140028B18
__int64 CmdDispatchSsdtByVersion(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0xA28)
        return BuildSsdtEntryTableLegacy(TargetBase, TargetSize, OutputBuffer, BufferSize);
    else
        return BuildSsdtEntryTableEx(TargetBase, TargetSize, OutputBuffer, BufferSize);
}

// CmdFixSsdtEntryAddress — 修复 SSDT 条目地址
// 对应原始驱动 sub_1400295B8
__int64 CmdFixSsdtEntryAddress(unsigned int *pSyscallIndex, int FieldSize)
{
    char Result = 0;
    unsigned __int64 SsdtHookTableBase;
    unsigned int SsdtHookTableSize = 0;
    __int64 *pSsdtHookEntryTable;
    unsigned int EntryCount = 0;
    unsigned __int64 SsdtBase;
    unsigned __int64 SsdtEndAddr;
    unsigned int SsdtSize = 0;
    unsigned __int64 SsdtBaseAndSize[6];

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28 && GetSsdtBaseAndSize((__int64 *)SsdtBaseAndSize, &SsdtSize))
    {
        if (!GtRead(GtEprocessModuleListOffset | GtEprocessField25))
            BuildInitSsdtHookTable();
        SsdtHookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField25);
        SsdtHookTableSize = (unsigned int)GtRead(GtEprocessModuleListOffset | GtEprocessField26);
        pSsdtHookEntryTable = GtAlloc(GtEprocessModuleListOffset | GtEprocessField27);
        if (SsdtHookTableBase && SsdtHookTableSize > 8
            && SsdtHookTableBase > (unsigned __int64)MmSystemRangeStart
            && SsdtHookTableSize < 0x1000)
        {
            EntryCount = (SsdtHookTableSize - 8) >> 3;
            SsdtBase = SsdtBaseAndSize[0];
            if (SsdtHookTableBase > SsdtBase)
            {
                SsdtEndAddr = SsdtSize + SsdtBase;
                if (SsdtHookTableBase < SsdtEndAddr && SsdtHookTableBase + SsdtHookTableSize < SsdtEndAddr
                    && EntryCount && pSyscallIndex && FieldSize == 4
                    && (unsigned __int64)pSyscallIndex < MmUserProbeAddress
                    && (unsigned __int64)(pSyscallIndex + 1) < MmUserProbeAddress)
                {
                    ProbeForRead(pSyscallIndex, 4u, 4u);
                    ULONG SyscallIndex = *pSyscallIndex;
                    if (SyscallIndex < EntryCount)
                    {
                        if (pSsdtHookEntryTable[SyscallIndex + 1])
                            WritePhysicalMemoryQword(
                                SsdtHookTableBase + 8 * (SyscallIndex + 1),
                                SsdtBase + LODWORD(pSsdtHookEntryTable[SyscallIndex + 1]));
                        return 1;
                    }
                }
            }
        }
    }
    return Result;
}

// CmdEnumSsdtEntryTable — 枚举 SSDT Hook 条目表
// 对应原始驱动 sub_14002916C
__int64 CmdEnumSsdtEntryTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
{
    SIZE_T OutputBufferSizeCopy = OutputBufferSize;
    unsigned int EntryIndex = 0;
    unsigned __int64 HookTableBase;
    unsigned int HookTableCount = 0;
    unsigned __int64 SsdtEndAddr;
    _DWORD SsdtRange[3];
    unsigned __int64 SsdtBaseAndSize[3];

    if (!GtRead(GtEprocessModuleListOffset | GtEprocessField23))
        BuildInitSsdtHookTable();
    HookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField23);
    HookTableCount = (unsigned int)GtRead(GtEprocessModuleListOffset | GtEprocessField24);
    if (GetSsdtBaseAndSize((__int64 *)SsdtBaseAndSize, SsdtRange))
    {
        if (HookTableBase && HookTableBase > (unsigned __int64)MmSystemRangeStart && HookTableCount)
        {
            if (HookTableBase > SsdtBaseAndSize[0])
            {
                SsdtEndAddr = SsdtRange[0] + SsdtBaseAndSize[0];
                if (HookTableBase < SsdtEndAddr
                    && HookTableBase + 16LL * HookTableCount < SsdtEndAddr
                    && pOutputBuffer
                    && OutputBufferSizeCopy >= 8 * (unsigned __int64)(HookTableCount - 1) + 16
                    && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                    && (unsigned __int64)pOutputBuffer + OutputBufferSizeCopy < MmUserProbeAddress)
                {
                    ProbeForWrite(pOutputBuffer, (unsigned int)OutputBufferSizeCopy, 8u);
                    memset(pOutputBuffer, 0, (unsigned int)OutputBufferSizeCopy);
                    pOutputBuffer[1] = HookTableCount;
                    *pOutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
                    for (EntryIndex = 0; EntryIndex < HookTableCount; EntryIndex++)
                        *(_QWORD *)&pOutputBuffer[2 * EntryIndex + 2] = *(_QWORD *)(HookTableBase + 16LL * EntryIndex);
                    return 1;
                }
            }
        }
    }
    return 0;
}

// DispatchFindExportTableOffset — 查找导出表偏移分发函数
// 构建号 > 0x23F0 时调用 FindExportTableOffsetV2，否则调用 V1
// 对应原始驱动 sub_140046444
char __fastcall DispatchFindExportTableOffset(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
        return FindExportTableOffsetV2(ImageBase, ImageSize, pOutputTable);
    else
        return FindExportTableOffsetV1(ImageBase, ImageSize, pOutputTable);
}

// FindExportTableOffsetV1 — 查找导出表偏移 V1 版本
// 两阶段 PE 节区扫描：先找 Type 1369 标记获取节区偏移，再找 Type 1298 导出节区，检查 Type 1327 确认，填充 28 项导出表
// 对应原始驱动 sub_140046490
char __fastcall FindExportTableOffsetV1(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 PeOffset = *(int *)(ImageBase + 60);
    char Result = 0;
    __int64 NtoskrnlBase = GtRead(GtCallbackField78);
    __int64 SectionDirRva;
    int SectionIndex;
    int ComputedOffset;
    unsigned int SectionRva;
    unsigned int ExportDirRva;
    int EntryIndex;
    int ComputedOffset2;
    __int16 SectionType;
    _QWORD *pExportSlot;
    __int64 EntryCount;
    char SectionContext[0x198];
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];           // 描述符：原 [8] 仅 32 字节
    char SectionFlags;
    int SectionDataSize;
    __int64 SectionCharacteristics;
    int FieldFlags;
    int RawDataSize;
    __int64 SectionAlignment;
    unsigned int SectionFileOffset;
    __int64 pSectionEntryBase;

    if (NtoskrnlBase)
    {
        SectionDirRva = *(unsigned int *)(PeOffset + ImageBase + 40);
        if ((unsigned int)SectionDirRva < ImageSize)
        {
            if ((unsigned int)SectionDirRva + 4096 < ImageSize)
            {
                InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)SectionContext);
                SectionIndex = 0;
                while (!(unsigned int)ReadPESectionEntry(SectionContext, SectionEntry))
                {
                    *(ULONG64 *)((PUCHAR)SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                    ComputedOffset = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1369)
                    {
                        if (SectionDataSize)
                        {
                            SectionRva = ComputedOffset + SectionDataSize - (unsigned int)ImageBase;
                            if (SectionRva && SectionRva < ImageSize)
                            {
                                LODWORD_LV(SectionDirRva) = ComputedOffset + SectionDataSize - (unsigned int)ImageBase;
                                break;
                            }
                        }
                    }
                    if ((unsigned int)++SectionIndex >= 0x1E)
                        break;
                }
            }
            if ((unsigned int)SectionDirRva < ImageSize && (unsigned int)SectionDirRva + 4096 < ImageSize)
            {
                InitPESectionReadContext(ImageBase + (unsigned int)SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)SectionContext);
                ExportDirRva = 0;
                EntryIndex = 0;
                while (!(unsigned int)ReadPESectionEntry(SectionContext, SectionEntry))
                {
                    *(ULONG64 *)((PUCHAR)SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                    ComputedOffset2 = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                    if (SectionType == 1298 && SectionAlignment == 0x40000 && RawDataSize && SectionCharacteristics == 64 && !FieldFlags)
                    {
                        ExportDirRva = ComputedOffset2 + RawDataSize - (unsigned int)ImageBase;
                        if (ExportDirRva >= ImageSize)
                            ExportDirRva = 0;
                    }
                    else if (SectionType == 1327 && (SectionFlags & 0x10) != 0 && ExportDirRva)
                    {
                        pExportSlot = (_QWORD *)(pOutputTable + 8);
                        EntryCount = 28;
                        do
                        {
                            *((_DWORD *)pExportSlot - 1) = ExportDirRva;
                            *pExportSlot = NtoskrnlBase + ExportDirRva;
                            pExportSlot += 6;
                            --EntryCount;
                        } while (EntryCount);
                        return 1;
                    }
                    if ((unsigned int)++EntryIndex >= 0x1F4)
                        return Result;
                }
            }
        }
    }
    return Result;
}

// FindExportTableOffsetV2 — 查找导出表偏移 V2 版本（Win10+）
// 三阶段 PE 节区扫描：Phase1 找 Type 1369/1296/1368 组合标记，Phase2 找 Type 1298 数据节区偏移，Phase3 扫描最多 0x96 项填充 28 项导出表
// 对应原始驱动 sub_1400466BC
char __fastcall FindExportTableOffsetV2(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 PeOffset = *(int *)(ImageBase + 60);
    char Result = 0;
    __int64 NtoskrnlBase = GtRead(GtCallbackField78);
    __int64 SectionDirRva;
    char IsTargetSection;
    int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int SectionRva;
    char IsDataSection;
    int EntryIndex;
    int ComputedOffset2;
    __int16 SectionType2;
    unsigned int SectionRva2;
    unsigned int InitSectionCount;
    int ScanIndex;
    int ComputedOffset3;
    __int16 SectionType3;
    unsigned int ExportDirRva;
    __int64 EntryCount;
    _QWORD *pExportSlot;
    char SectionContext[0x198];
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    int SectionDataSize;
    __int64 SectionCharacteristics;
    int FieldFlags;
    int RawDataSize;
    __int64 SectionAlignment;
    unsigned int SectionFileOffset;
    __int64 pSectionEntryBase;

    if (NtoskrnlBase)
    {
        SectionDirRva = *(unsigned int *)(PeOffset + ImageBase + 40);
        if ((unsigned int)SectionDirRva < ImageSize)
        {
            if ((unsigned int)SectionDirRva + 4096 < ImageSize)
            {
                IsTargetSection = 0;
                InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)SectionContext);
                SectionIndex = 0;
                while (!(unsigned int)ReadPESectionEntry(SectionContext, SectionEntry))
                {
                    *(ULONG64 *)((PUCHAR)SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                    ComputedOffset = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                    if (SectionType == 1369)
                    {
                        SectionRva = ComputedOffset + SectionDataSize - (unsigned int)ImageBase;
                        if (SectionRva && SectionRva < ImageSize)
                        {
                            LODWORD_LV(SectionDirRva) = SectionRva;
                            break;
                        }
                    }
                    else if (SectionType == 1296 && SectionCharacteristics == 64 && FieldFlags == 1)
                    {
                        IsTargetSection = 1;
                    }
                    else if (SectionType == 1368)
                    {
                        if (IsTargetSection == 1)
                        {
                            SectionRva = ComputedOffset + SectionDataSize - (unsigned int)ImageBase;
                            if (SectionRva && SectionRva < ImageSize)
                            {
                                LODWORD_LV(SectionDirRva) = SectionRva;
                                break;
                            }
                        }
                        IsTargetSection = 0;
                    }
                    if ((unsigned int)++SectionIndex >= 0x14)
                        break;
                }
            }
            if ((unsigned int)SectionDirRva < ImageSize)
            {
                if ((unsigned int)SectionDirRva + 4096 < ImageSize)
                {
                    IsDataSection = 0;
                    InitPESectionReadContext(ImageBase + (unsigned int)SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)SectionContext);
                    EntryIndex = 0;
                    while (!(unsigned int)ReadPESectionEntry(SectionContext, SectionEntry))
                    {
                        *(ULONG64 *)((PUCHAR)SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                        ComputedOffset2 = SectionFileOffset + (int)AccumulatedOffset;
                        AccumulatedOffset += SectionFileOffset;
                        SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                        if (SectionType2 == 1298 && SectionAlignment == 0x40000 && RawDataSize && SectionCharacteristics == 64)
                            IsDataSection = 1;
                        if (SectionType2 == 1368)
                        {
                            if (SectionDataSize && IsDataSection == 1)
                            {
                                SectionRva2 = ComputedOffset2 + SectionDataSize - (unsigned int)ImageBase;
                                if (SectionRva2 && SectionRva2 < ImageSize)
                                {
                                    LODWORD_LV(SectionDirRva) = ComputedOffset2 + SectionDataSize - (unsigned int)ImageBase;
                                    break;
                                }
                            }
                        }
                        if ((unsigned int)++EntryIndex >= 0x14)
                            break;
                    }
                }
                if ((unsigned int)SectionDirRva < ImageSize && (unsigned int)SectionDirRva + 4096 < ImageSize)
                {
                    InitPESectionReadContext(ImageBase + (unsigned int)SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)SectionContext);
                    InitSectionCount = 0;
                    ScanIndex = 0;
                    while (!(unsigned int)ReadPESectionEntry(SectionContext, SectionEntry))
                    {
                        *(ULONG64 *)((PUCHAR)SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
                        ComputedOffset3 = SectionFileOffset + (int)AccumulatedOffset;
                        AccumulatedOffset += SectionFileOffset;
                        SectionType3 = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                        if ((unsigned __int16)(SectionType3 - 1139) <= 1u)
                        {
                            ++InitSectionCount;
                        }
                        else if (InitSectionCount >= 3 && SectionType3 == 1298 && SectionAlignment == 0x40000)
                        {
                            if (RawDataSize && SectionCharacteristics == 64)
                            {
                                ExportDirRva = ComputedOffset3 + RawDataSize - (unsigned int)ImageBase;
                                if (ExportDirRva && ExportDirRva < ImageSize)
                                {
                                    EntryCount = 28;
                                    pExportSlot = (_QWORD *)(pOutputTable + 8);
                                    do
                                    {
                                        *((_DWORD *)pExportSlot - 1) = ExportDirRva;
                                        *pExportSlot = NtoskrnlBase + ExportDirRva;
                                        pExportSlot += 6;
                                        --EntryCount;
                                    } while (EntryCount);
                                    return 1;
                                }
                            }
                        }
                        if ((unsigned int)++ScanIndex >= 0x96)
                            return Result;
                    }
                }
            }
        }
    }
    return Result;
}

// DispatchStorPortIoControl — 分发 StorPort IO 控制
// 将 StorPort 函数表通过原子 16 字节交换写入全局表分配的缓冲区
// 对应原始驱动 sub_14007CFDC
char __fastcall DispatchStorPortIoControl(_OWORD *FunctionTable)
{
    char Result = 0;
    __int64 *pBuffer;

    if ((unsigned int)GtRead(GtCallbackField49))
    {
        pBuffer = GtAlloc(GtEprocessField108 | 0x1000);
        return AtomicExchange16Bytes((__int64)(pBuffer + 90), FunctionTable);
    }
    return Result;
}
