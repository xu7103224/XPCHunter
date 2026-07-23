// SSDT.c — SSDT Hook 引擎
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"

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
char ReadNtFileForSsdtTargets2(void **pFileBuffer, unsigned int *pFileSize);
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
    ULONG ImageBase;
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
        NtBuildNumberPtr = (ULONG64)&NtBuildNumber;
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
                    NtBuildNumberPtr = (ULONG64)&NtBuildNumber;
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
                ImageBase = *(WORD *)(ModuleListHead2 + 72) - NameLen2Copy;
                if (ImageBase < 0xAE)
                {
                    GtWrite(GtNtoskrnlImageSize, *(ULONG *)(ModuleListHead2 + 64));
                    GtWrite(GtNtoskrnlModuleBase, Value);
                    FileNameLen2 = GtAlloc(GtSymlinkBuffer);
                    memset(FileNameLen2, 0, 0xB0);
                    memmove(FileNameLen2, (const void *)(*(ULONG64 *)(ModuleListHead2 + 80) + 2LL * HalfNameLen), ImageBase);
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
    // 写入预计算哈希值到全局表索引 0x415B-0x4479
    // 全部哈希值从原始驱动逐字复刻
    GtWrite(GtSyscallHashEntry00, 2560346686LL);
    GtWrite(GtSyscallHashTable, 1231868414);
    GtWrite(16734, 2980112511LL);
    GtWrite(16735, 3277184305LL);
    GtWrite(16738, 1390781482);
    GtWrite(16739, 1978665769);
    GtWrite(16740, 2404549186LL);
    GtWrite(16741, 4236067134LL);
    GtWrite(16742, 598237254);
    GtWrite(16743, 39032597);
    GtWrite(16744, 477170725);
    GtWrite(16745, 1499793596);
    GtWrite(16746, 3530426248LL);
    GtWrite(16747, 3843384117LL);
    GtWrite(16748, 3925593854LL);
    GtWrite(16749, 1716351167);
    GtWrite(16750, 1804014132);
    GtWrite(16751, 3304772587LL);
    GtWrite(16752, 3729640641LL);
    GtWrite(16753, 2899332083LL);
    GtWrite(16754, 2639055631LL);
    GtWrite(16755, 3960083079LL);
    GtWrite(16756, 1465620123);
    GtWrite(16757, 1808614057);
    GtWrite(16758, 3667928011LL);
    GtWrite(16759, 289684649);
    GtWrite(16760, 2684813994LL);
    GtWrite(16761, 3421632657LL);
    GtWrite(16762, 3971418398LL);
    GtWrite(16763, 3198542575LL);
    GtWrite(16764, 1803819146);
    GtWrite(16765, 1984654630);
    GtWrite(16766, 1041701901);
    GtWrite(16767, 2748099175LL);
    GtWrite(16768, 3662781349LL);
    GtWrite(16769, 1625728350);
    GtWrite(16770, 811695130);
    GtWrite(16771, 3358795149LL);
    GtWrite(16772, 4179419883LL);
    GtWrite(16773, 3272122029LL);
    GtWrite(16774, 3363896414LL);
    GtWrite(16775, 1909430846);
    GtWrite(16776, 4197650081LL);
    GtWrite(16777, 4200123842LL);
    GtWrite(16778, 545620171);
    GtWrite(16779, 1730316692);
    GtWrite(16780, 3462512571LL);
    GtWrite(16781, 3932964591LL);
    GtWrite(16782, 1053217664);
    GtWrite(16783, 3952619741LL);
    GtWrite(16784, 1281626136);
    GtWrite(16785, 1424950714);
    GtWrite(16786, 405568189);
    GtWrite(16787, 954876874);
    GtWrite(16788, 2171261687LL);
    GtWrite(16789, 3576355407LL);
    GtWrite(16790, 3628712499LL);
    GtWrite(16791, 824614000);
    GtWrite(16792, 449870662);
    GtWrite(16793, 727532833);
    GtWrite(16794, 2178256273LL);
    GtWrite(16795, 977291059);
    GtWrite(16796, 2332219554LL);
    GtWrite(16797, 2872664778LL);
    GtWrite(16798, 619236365);
    GtWrite(16799, 3376556599LL);
    GtWrite(16800, 1222843922);
    GtWrite(16801, 2683515779LL);
    GtWrite(16802, 360748647);
    GtWrite(16803, 3937324444LL);
    GtWrite(16804, 2554908331LL);
    GtWrite(16805, 4263590805LL);
    GtWrite(16806, 2297257204LL);
    GtWrite(16807, 4228123203LL);
    GtWrite(16808, 146136342);
    GtWrite(16809, 1397074981);
    GtWrite(16810, 2033527374);
    GtWrite(16811, 4242026692LL);
    GtWrite(16812, 596349546);
    GtWrite(16813, 1232288512);
    GtWrite(16814, 2577802871LL);
    GtWrite(16815, 4289211613LL);
    GtWrite(16816, 1673056902);
    GtWrite(16817, 548365325);
    GtWrite(16818, 2078917576);
    GtWrite(16819, 3170959630LL);
    GtWrite(16820, 2842840633LL);
    GtWrite(16821, 3684702697LL);
    GtWrite(16822, 3483859074LL);
    GtWrite(16823, 118849841);
    GtWrite(16824, 283603974);
    GtWrite(16825, 453215933);
    GtWrite(16826, 234845693);
    GtWrite(16827, 3110972790LL);
    GtWrite(16828, 1636114856);
    GtWrite(16829, 1668407032);
    GtWrite(16830, 1509571480);
    GtWrite(16831, 2004508723);
    GtWrite(16832, 3139045463LL);
    GtWrite(16833, 1129601163);
    GtWrite(16834, 940857919);
    GtWrite(16835, 3264087154LL);
    GtWrite(16836, 898511149);
    GtWrite(16837, 3395734917LL);
    GtWrite(16838, 3539018799LL);
    GtWrite(16839, 2692032917LL);
    GtWrite(16840, 4261002590LL);
    GtWrite(16841, 2805195088LL);
    GtWrite(16842, 3334589742LL);
    GtWrite(16843, 43160043);
    GtWrite(16844, 3907014875LL);
    GtWrite(16845, 1597882041);
    GtWrite(16846, 2526810812LL);
    GtWrite(16847, 2616004015LL);
    GtWrite(16848, 4008491744LL);
    GtWrite(16849, 1225841446);
    GtWrite(16850, 1444066595);
    GtWrite(16851, 851255887);
    GtWrite(16852, 2386727321LL);
    GtWrite(16853, 906726228);
    GtWrite(16854, 793756284);
    GtWrite(16855, 3789673178LL);
    GtWrite(16856, 2377140723LL);
    GtWrite(16857, 2402297195LL);
    GtWrite(16858, 889041381);
    GtWrite(16859, 4090006072LL);
    GtWrite(16860, 2542969581LL);
    GtWrite(16861, 1047465521);
    GtWrite(16862, 287300040);
    GtWrite(16863, 54110633);
    GtWrite(16864, 2569019562LL);
    GtWrite(16865, 2702091790LL);
    GtWrite(16866, 3662523787LL);
    GtWrite(16867, 3045438754LL);
    GtWrite(16868, 2648989753LL);
    GtWrite(16869, 3137721591LL);
    GtWrite(16870, 2785599155LL);
    GtWrite(16871, 1353620975);
    GtWrite(16872, 3768905514LL);
    GtWrite(16873, 423651071);
    GtWrite(16874, 728876438);
    GtWrite(16875, 982189365);
    GtWrite(16876, 2060676615);
    GtWrite(16877, 2184728571LL);
    GtWrite(16878, 1034911984);
    GtWrite(16879, 4260178921LL);
    GtWrite(16880, 2686378601LL);
    GtWrite(16881, 1020794554);
    GtWrite(16882, 711050384);
    GtWrite(16883, 3984539734LL);
    GtWrite(16884, 1932110105);
    GtWrite(16885, 3818851484LL);
    GtWrite(16886, 3990875100LL);
    GtWrite(16887, 569963017);
    GtWrite(16888, 1560331603);
    GtWrite(16889, 3705689306LL);
    GtWrite(16890, 4230065227LL);
    GtWrite(16891, 3321356452LL);
    GtWrite(16892, 2299453139LL);
    GtWrite(16893, 70978315);
    GtWrite(16894, 2721726920LL);
    GtWrite(16895, 3407136956LL);
    GtWrite(16896, 3835061601LL);
    GtWrite(16897, 930092508);
    GtWrite(16898, 2539222079LL);
    GtWrite(16899, 2148389335LL);
    GtWrite(16900, 3700284774LL);
    GtWrite(16901, 2093765030);
    GtWrite(16902, 1162293146);
    GtWrite(16903, 3841036190LL);
    GtWrite(16904, 354717608);
    GtWrite(16905, 440267193);
    GtWrite(16906, 869247338);
    GtWrite(16907, 2552709774LL);
    GtWrite(16908, 2808084606LL);
    GtWrite(16909, 3564024840LL);
    GtWrite(16910, 199314958);
    GtWrite(16911, 4106137831LL);
    GtWrite(16912, 3206481687LL);
    GtWrite(16913, 1355202861);
    GtWrite(16914, 516334180);
    GtWrite(16915, 2860275493LL);
    GtWrite(16916, 3070920460LL);
    GtWrite(16917, 998083028);
    GtWrite(16918, 2370871470LL);
    GtWrite(16919, 2214824984LL);
    GtWrite(16920, 260790345);
    GtWrite(16921, 50556113);
    GtWrite(16922, 2558411054LL);
    GtWrite(16923, 3285106291LL);
    GtWrite(16924, 1356613395);
    GtWrite(16925, 844230412);
    GtWrite(16926, 1578881762);
    GtWrite(16927, 1454013495);
    GtWrite(16928, 2991292816LL);
    GtWrite(16929, 1249872007);
    GtWrite(16930, 3284644540LL);
    GtWrite(16931, 1540552115);
    GtWrite(16932, 3317051478LL);
    GtWrite(16933, 3614885230LL);
    GtWrite(16934, 726504496);
    GtWrite(16935, 57285882);
    GtWrite(16936, 3502815702LL);
    GtWrite(16937, 3733028007LL);
    GtWrite(16938, 2249167527LL);
    GtWrite(16939, 334817306);
    GtWrite(16940, 3072300792LL);
    GtWrite(16941, 3402174275LL);
    GtWrite(16942, 2889900248LL);
    GtWrite(16943, 1173313075);
    GtWrite(16944, 1335205499);
    GtWrite(16945, 3736028506LL);
    GtWrite(16946, 2608203227LL);
    GtWrite(16947, 3582138770LL);
    GtWrite(16948, 1426310555);
    GtWrite(16949, 2804893711LL);
    GtWrite(16950, 2539184244LL);
    GtWrite(16951, 1908374321);
    GtWrite(16952, 1782153709);
    GtWrite(16953, 3506808913LL);
    GtWrite(16954, 105794467);
    GtWrite(16955, 3375818221LL);
    GtWrite(16956, 1597354434);
    GtWrite(16957, 3702710755LL);
    GtWrite(16958, 2955278418LL);
    GtWrite(16959, 2035185162);
    GtWrite(16960, 1562599304);
    GtWrite(16961, 2661806581LL);
    GtWrite(16962, 618083544);
    GtWrite(16963, 2774988859LL);
    GtWrite(16964, 1310679489);
    GtWrite(16965, 4157470780LL);
    GtWrite(16966, 2018727106);
    GtWrite(16967, 2629569691LL);
    GtWrite(16968, 3862013128LL);
    GtWrite(16969, 1709980864);
    GtWrite(16970, 1028609448);
    GtWrite(16971, 1834946537);
    GtWrite(16972, 705331908);
    GtWrite(16973, 4242491016LL);
    GtWrite(16974, 1329766650);
    GtWrite(16975, 2172918977LL);
    GtWrite(16976, 3686385318LL);
    GtWrite(16977, 3340495833LL);
    GtWrite(16978, 1792054622);
    GtWrite(16979, 3523219221LL);
    GtWrite(16980, 2529114624LL);
    GtWrite(16981, 2923818784LL);
    GtWrite(16982, 3598929377LL);
    GtWrite(16983, 144758072);
    GtWrite(16984, 134762749);
    GtWrite(16985, 4182416183LL);
    GtWrite(16986, 2022790254);
    GtWrite(16987, 1713326564);
    GtWrite(16988, 1898780901);
    GtWrite(16989, 894537826);
    GtWrite(16990, 1725527356);
    GtWrite(16991, 4284994197LL);
    GtWrite(16992, 936937036);
    GtWrite(16993, 2993307242LL);
    GtWrite(16994, 2611957357LL);
    GtWrite(16995, 2078661424);
    GtWrite(16996, 2832241317LL);
    GtWrite(16997, 66849976);
    GtWrite(16998, 1065001809);
    GtWrite(16999, 1400813203);
    GtWrite(17000, 1781433132);
    return GtWrite(GtSyscallHashEntryEnd, 3407524183LL);
}

// ScanPESectionPatterns — 扫描 PE 节区模式
// 对应原始驱动 sub_140079DE4
bool ScanPESectionPatterns(_BYTE *Pattern, char *TargetData, int DataSize, char UsePESection)
{
    char Result = 0;
    __int64 v14 = 0;
    __int64 v15 = 0;
    _DWORD v16[20];
    __int64 v17 = 0;
    int v18 = 0;
    __int64 v19 = 0;
    ULONG v20 = 0;
    __int64 v21 = 0;
    char v8 = 0;
    __int64 v11 = 0;
    // 5 字节 NOP 指令模板 (0F 1F 44 00 00)
    _BYTE NopPattern[5] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };

    v15 = 0;
    v8 = 0;
    v11 = 0;

    if ((ULONG)(DataSize - 12) > 0x27F3) return Result;
    if (UsePESection == 1)
    {
        InitPESectionReadContext((__int64)Pattern, DataSize, 2, 0, -1, 0, 0, (__int64)&v14);
        if (ReadPESectionEntry((unsigned char *)&v14, v16)) return Result;

        while (1)
        {
            int v9 = (int)(v20 + (ULONG)v15);
            v15 += v20;
            short v10 = *(WORD *)(v21 + 6);
            if (v10 == 1139 && v20 == 7) { v8 = 1; }
            else
            {
                if (v10 == 239 && v20 == 5 && v8 == 1)
                {
                    v11 = (ULONG)(v9 - (__int64)Pattern - 12);
                    goto CheckFound;
                }
                v8 = 0;
            }
            if (ReadPESectionEntry((unsigned char *)&v14, v16)) return Result;
        }
    }
    else
    {
        for (v11 = 0; (ULONG)v11 <= (ULONG)(DataSize - 12); v11++)
        {
            if (Pattern[v11] == 0x48 && Pattern[(ULONG)(v11 + 1)] == 0xFF &&
                Pattern[(ULONG)(v11 + 2)] == 0x21 &&
                !MemoryCompare((__int64)&Pattern[(ULONG)v11 + 7], (char *)NopPattern, 5))
                goto CheckFound;
        }
        return Result;
    }

CheckFound:
    Result = 1;
    if (TargetData)
    {
        Result = 0;
        if (v11 && MemoryCompare((__int64)Pattern, (char *)TargetData, (ULONG)v11)) return Result;
        InitPESectionReadContext((__int64)&TargetData[(ULONG)v11], 12, 2, 0, -1, 0, 0, (__int64)&v14);
        if (!ReadPESectionEntry((unsigned char *)&v14, v16) && *(WORD *)(v21 + 6) == 1296 && v20 == 7 &&
            v17 == 64 && v19 == 0x40000)
        {
            if (v18 && *(ULONG *)&Pattern[(ULONG)v11 + 3] == v18)
            {
                v15 += 7;
                if (!ReadPESectionEntry((unsigned char *)&v14, v16) && *(WORD *)(v21 + 6) == 1368)
                    return v20 == 5;
            }
        }
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
char ReadNtoskrnlFile(void)
{
    char Success = 0;
    WORD *FileBufferPtr;
    __int64 NtoskrnlBase = 0, v3 = 0;
    int *ImageBuffer, *v5;
    char *PeSignature;
    ULONG OptHeaderOffset;
    char *NtHeaders;
    __int64 SectionHeader = 0, v10 = 0;
    size_t FileSize, v13;
    void *Src, *v15;

    FileBufferPtr = (WORD *)GtAlloc(GtPathBuffer00);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    v3 = NtoskrnlBase;

    if (!*(ULONG64 *)FileBufferPtr || !NtoskrnlBase)
        return Success;
    if (ReadFileRawData(FileBufferPtr, &v15, (ULONG *)&v13, 1))
        return Success;
    if (ReadNtFileToBuffer((PUCHAR)v15, (ULONG)v13, (PUCHAR *)&Src, (PULONG)&FileSize) != 1)
    {
        ExFree(v15);
        return Success;
    }

    ImageBuffer = ExAlloc(PagedPool, (ULONG)(FileSize + 256));
    v5 = ImageBuffer;
    if (!ImageBuffer)
    {
        ExFree(Src);
        ExFree(v15);
        return Success;
    }

    memmove(ImageBuffer, Src, (ULONG)FileSize);
    memset((char *)v5 + (ULONG)FileSize, 0, 0x100);

    if (ParseNtExportDir((PUCHAR)v5, (ULONG)FileSize, v3, 0) == 1)
    {
        GtWrite(GtEprocessField22, (__int64)Src);
        GtWrite(GtEprocessField23, (ULONG)FileSize);
        PeSignature = (char *)Src + *((int *)Src + 15);
        OptHeaderOffset = *((WORD *)PeSignature + 3);
        NtHeaders = &PeSignature[*((WORD *)PeSignature + 10)];
        GtWrite(GtEprocessField24, (__int64)PeSignature);
        GtWrite(GtEprocessField25, OptHeaderOffset);
        GtWrite(GtEprocessField26, (__int64)(NtHeaders + 24));
        GtWrite(GtEprocessField66, (__int64)v5);
        SectionHeader = (__int64)v5 + v5[15];
        v10 = *(WORD *)(SectionHeader + 20) + SectionHeader + 24;
        GtWrite(GtEprocessField67, SectionHeader);
        GtWrite(GtEprocessField68, v10);
        Success = 1;
    }
    else
        ExFree(v5);

    ExFree(Src);
    ExFree(v15);
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
        return (void *)(ULONG_PTR)GtWrite(GtEprocessField66, 0);
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

// FindPESectionByName — 按名称查找 PE 节
// 对应原始驱动 sub_140005C28
// 遍历节表，返回匹配节名的节在文件中的偏移
__int64 FindPESectionByName(PUCHAR PeBase, PCHAR SectionName)
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

// FindPESectionByNameReturnVa — 按名称查找 PE 节返回 VA
// 对应原始驱动 sub_140005CB4
// 遍历节表，返回匹配节名的虚拟地址
__int64 FindPESectionByNameReturnVa(PUCHAR PeBase, PCHAR SectionName)
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
char ReadNtFileToBuffer(PUCHAR Src, ULONG MaxCount, PUCHAR *OutBuffer, PULONG OutSize)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    PIMAGE_SECTION_HEADER LastSection;
    ULONG SectionAlignment, SizeOfImage, SizeOfHeaders;
    ULONG AlignedImageSize;
    ULONG i;
    WORD SectionCount;
    ULONG Va, RawSize, VirtSize;
    ULONG AlignMask;
    PUCHAR Buffer;
    char Result = 0;
    ULONG AlignedRawSize;
    ULONG TotalHeaderEnd;
    PIMAGE_SECTION_HEADER Sect;

    Result = 0;
    if (MaxCount < 0x201 || *(PWORD)Src != IMAGE_DOS_SIGNATURE)
        return Result;

    DosHeader = (PIMAGE_DOS_HEADER)Src;
    if (DosHeader->e_lfanew >= MaxCount || DosHeader->e_lfanew + 24 >= MaxCount)
        return Result;

    NtHeaders = (PIMAGE_NT_HEADERS)(Src + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return Result;

    SectionCount = NtHeaders->FileHeader.NumberOfSections;
    if (SectionCount > 79)
        return Result;

    SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
    SectionAlignment = NtHeaders->OptionalHeader.SectionAlignment;
    SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;
    SizeOfHeaders = NtHeaders->OptionalHeader.SizeOfHeaders;

    TotalHeaderEnd = (ULONG)((PUCHAR)(SectionHeader + SectionCount) - Src);
    if (TotalHeaderEnd > SizeOfImage)
        SizeOfImage = TotalHeaderEnd;

    if (SizeOfImage > 0x10000 || SizeOfHeaders > 0x10000)
        return Result;

    if (SectionAlignment > 0x10000)
        return Result;

    AlignMask = SectionAlignment - 1;
    AlignedImageSize = ~AlignMask & (AlignMask + SizeOfImage);

    // Validate and adjust section alignment
    if (SectionCount > 0)
    {
        for (i = 0; i < SectionCount; i++)
        {
            Sect = &SectionHeader[i];
            Va = Sect->VirtualAddress;
            if (Va > AlignedImageSize || (Va & AlignMask))
                break;

            RawSize = Sect->SizeOfRawData;
            if (RawSize > MaxCount)
                break;

            VirtSize = Sect->Misc.VirtualSize;
            if (VirtSize > MaxCount || VirtSize + RawSize > MaxCount)
                break;

            // Check no overlap with previous section
            if (i > 0)
            {
                PIMAGE_SECTION_HEADER PrevSect = &SectionHeader[i - 1];
                if (Va > PrevSect->VirtualAddress + PrevSect->SizeOfRawData ||
                    Va + VirtSize > PrevSect->VirtualAddress + PrevSect->SizeOfRawData)
                    break;
            }

            // Align SizeOfRawData
            AlignedRawSize = ~AlignMask & (RawSize + AlignMask);
            if (AlignedRawSize > MaxCount)
            {
                ULONG AdjustedSize = RawSize;
                if (AlignedRawSize > MaxCount - AlignedRawSize)
                    AdjustedSize = MaxCount - AlignedRawSize;
                Sect->SizeOfRawData = AdjustedSize;
            }
            else
            {
                Sect->SizeOfRawData = AlignedRawSize;
            }

            // Align VirtualSize
            ULONG AlignedVirtSize = ~AlignMask & (VirtSize + AlignMask);
            if (i == 0)
            {
                if (AlignedVirtSize > AlignedImageSize - Va)
                    AlignedVirtSize = AlignedImageSize - Va;
                Sect->Misc.VirtualSize = AlignedVirtSize;
            }
            else
            {
                PIMAGE_SECTION_HEADER PrevSect = &SectionHeader[i - 1];
                if (AlignedVirtSize > PrevSect->VirtualAddress + PrevSect->SizeOfRawData - Va)
                    break;
                Sect->Misc.VirtualSize = AlignedVirtSize;
            }
        }

        if (i < SectionCount)
            return Result;
    }

    // Allocate aligned buffer and copy PE data
    Buffer = (PUCHAR)ExAlloc(PagedPool, AlignedImageSize + 256);
    if (!Buffer)
        return Result;

    memset(Buffer, 0, AlignedImageSize + 256);

    // Copy headers
    ULONG HeaderSize = SizeOfHeaders;
    if (MaxCount < HeaderSize)
        HeaderSize = MaxCount;
    memmove(Buffer, Src, HeaderSize);

    // Copy section data
    for (i = 0; i < SectionCount; i++)
    {
        Sect = &SectionHeader[i];
        memmove(Buffer + Sect->VirtualAddress, Src + Sect->PointerToRawData, Sect->SizeOfRawData);
    }

    Result = 1;
    *OutBuffer = Buffer;
    *OutSize = AlignedImageSize;
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
    ULONG SizeOfImage;
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
__int64 CmdInitSsdtTable(__int64 a1, __int64 a2, _DWORD *OutputBuffer, int BufferSize)
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
__int64 CmdEnumSyscallEntries(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        TableReady = GtRead(GtEprocessField135 | 0x100);
        if (!TableReady)
        {
            InitDiskQueryExportTable();
            TableReady = GtRead(GtEprocessField135 | 0x100);
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
__int64 CmdEnumShadowSyscallEntries(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        IsReady = GtRead(GtCallbackField15);
        if (!IsReady)
        {
            InitShadowSyscallExportTable();
            IsReady = GtRead(GtCallbackField15);
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
__int64 CmdEnumSyscallTable2(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        TableReady = GtRead(GtCallbackField37);
        if (!TableReady)
        {
            BuildSsdtHookTargets2();
            TableReady = GtRead(GtCallbackField37);
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
__int64 CmdEnumSyscallTable3(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        HookTableReady = GtRead(GtCallbackField44);
        if (!HookTableReady)
        {
            BuildSsdtHookTargets3();
            HookTableReady = GtRead(GtCallbackField44);
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
__int64 CmdEnumSyscallTable4(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        HookTableReady = GtRead(GtCallbackField49);
        if (!HookTableReady)
        {
            BuildSsdtHookTargets4();
            HookTableReady = GtRead(GtCallbackField49);
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
__int64 CmdEnumSyscallTable5(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        TableReady = GtRead(GtCallbackField61);
        if (!TableReady)
        {
            ParseStorPortExportDir();
            TableReady = GtRead(GtCallbackField61);
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
__int64 CmdEnumSyscallTable6(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        IsReady = GtRead(GtCallbackField72);
        if (!IsReady)
        {
            ParseSyscallFileExportDir();
            IsReady = GtRead(GtCallbackField72);
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
__int64 CmdEnumSyscallTable7(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        IsReady = GtRead(GtCallbackField80);
        if (!IsReady)
        {
            BuildSyscallExportTable();
            IsReady = GtRead(GtCallbackField80);
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
__int64 CmdEnumSyscallTable8(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        TableReady = GtRead(GtCallbackField83);
        if (!TableReady)
        {
            InitWin32kSyscallTable();
            TableReady = GtRead(GtCallbackField83);
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
__int64 CmdEnumSyscallTable9(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
        TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField157);
        if (!TableReady)
        {
            ParseSyscallTableExportDir();
            TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField157);
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
__int64 CmdGetSsdtTableInfo(__int64 a1, __int64 a2, _QWORD *pOutputBuffer, int OutputSize)
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
__int64 CmdQuerySsdtDetails(__int64 a1, __int64 a2, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    int TableCount = 0;
    _QWORD *ServiceTableBase;
    int ServiceTableCount = 0;
    unsigned int *ServiceTableLimit;
    __int64 ServiceTableArray[6];
    __int64 ServiceTableCounts[6];

    if (!(unsigned int)GtRead(GtEprocessExtField46))
        InitKernelDataSectionTable();
    TableCount = GtRead(GtEprocessExtField46);
    ServiceTableBase = (_QWORD *)GtRead(GtEprocessExtField47);
    ServiceTableCount = GtRead(GtEprocessExtField48);
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
        pOutputBuffer[1] = ServiceTableBase;
        pOutputBuffer[2] = (char *)ServiceTableLimit + *ServiceTableLimit + 4;
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
    __int64 ServiceTableCounts[6];
    unsigned __int64 TargetAddress;
    __int64 NewValue = 0;

    if (!(unsigned int)GtRead(GtEprocessExtField46))
        InitKernelDataSectionTable();
    TableCount = GtRead(GtEprocessExtField46);
    ServiceTableBase = GtRead(GtEprocessExtField47);
    ServiceTableCount = GtRead(GtEprocessExtField48);
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
            return WritePhysicalMemoryBuffer((void *)ServiceTableLimit, &ServiceTableCount, 4u, 0, 0) != 0;
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
__int64 CmdReadExportDirectory(__int64 a1, __int64 a2, char *OutputBuffer, unsigned int BufferSize)
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
    ExportDirSize = GtRead(GtEprocessExtField57);
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
    ExportDirSize = GtRead(GtEprocessExtField57);
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
    ExportDirSize = GtRead(GtEprocessExtField57);
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
__int64 CmdReadSsdtEntryTable(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
{
    unsigned __int64 OutputSize = OutputBufferSize;
    char Result = 0;
    unsigned __int64 SsdtBase;
    unsigned int SsdtCount = 0;
    unsigned __int64 NtBase;
    unsigned int NtImageBase = 0;
    unsigned __int64 NtEndAddr;

    SsdtBase = GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField187 | GtEprocessField06 | 0x100);
    SsdtCount = GtRead(GtEprocessField94 | 0x800);
    NtBase = GtRead(GtNtoskrnlModuleBase);
    NtImageBase = GtRead(GtNtoskrnlImageSize);

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
                *pOutputBuffer = GtRead(GtWindowsBuildNumber);
                memmove(pOutputBuffer + 2, (const void *)(SsdtBase + 8), 8LL * SsdtCount);
                return 1;
            }
        }
    }
    return Result;
}

// CmdReadSsdtEntryTableEx — 读取 SSDT 条目表（扩展版）
// 对应原始驱动 sub_140029020
__int64 CmdReadSsdtEntryTableEx(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
{
    unsigned __int64 OutputSize = OutputBufferSize;
    char Result = 0;
    unsigned __int64 SsdtBase;
    unsigned int SsdtCount = 0;
    unsigned __int64 NtBase;
    unsigned int NtImageSize = 0;
    unsigned __int64 NtEndAddr;

    SsdtBase = GtRead((enum _GLOBAL_TABLE_INDEX)17408);
    SsdtCount = GtRead(GtEprocessField95 | 0x800);
    NtBase = GtRead(GtNtoskrnlModuleBase);
    NtImageSize = GtRead(GtNtoskrnlImageSize);

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
                *pOutputBuffer = GtRead(GtWindowsBuildNumber);
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
        SsdtHookTableSize = GtRead(GtEprocessModuleListOffset | GtEprocessField26);
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
__int64 CmdEnumSsdtEntryTable(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, unsigned int OutputBufferSize)
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
    HookTableCount = GtRead(GtEprocessModuleListOffset | GtEprocessField24);
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
                    *pOutputBuffer = GtRead(GtWindowsBuildNumber);
                    for (EntryIndex = 0; EntryIndex < HookTableCount; EntryIndex++)
                        *(_QWORD *)&pOutputBuffer[2 * EntryIndex + 2] = *(_QWORD *)(HookTableBase + 16LL * EntryIndex);
                    return 1;
                }
            }
        }
    }
    return 0;
}

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
__int64 OpenTcpIpDriverSection(void)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 6488148; EncodedPath[5] = 6881392;
    EncodedPath[6] = 112;     EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// OpenKbdClassDriverSection — 打开 kbdclass.sys 驱动节区
// 对应原始驱动 sub_14003D388
__int64 OpenKbdClassDriverSection(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 6422603; EncodedPath[5] = 4391012;
    EncodedPath[6] = 6357100; EncodedPath[7] = 7536755;
    EncodedPath[8] = 0;       EncodedPath[9] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// GetSsdtFunctionBase2 — 获取 SSDT 函数基址 2
// 对应原始驱动 sub_14003383C
__int64 GetSsdtFunctionBase2(void)
{
    _DWORD EncodedName[8];
    EncodedName[0] = 4456540; EncodedName[1] = 6881394;
    EncodedName[2] = 6619254; EncodedName[3] = 6029426;
    EncodedName[4] = 6881348; EncodedName[5] = 7012467;
    EncodedName[6] = 0;       EncodedName[7] = 0;
    return OpenFileSection((__int64)EncodedName);
}

// DecryptDiskDeviceContextStr — 解密磁盘设备上下文字符串
// 对应原始驱动 sub_140032ACC
__int64 DecryptDiskDeviceContextStr(void)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 7602241; EncodedPath[5] = 7340129;
    EncodedPath[6] = 105;     EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// GetSsdtFunctionBase4 — 获取 SSDT 函数基址 4
// 对应原始驱动 sub_1400314B0
__int64 GetSsdtFunctionBase4(void)
{
    _DWORD EncodedName[8];
    EncodedName[0] = 4456540; EncodedName[1] = 6881394;
    EncodedName[2] = 6619254; EncodedName[3] = 6029426;
    EncodedName[4] = 6488129; EncodedName[5] = 6881392;
    EncodedName[6] = 0;       EncodedName[7] = 0;
    return OpenFileSection((__int64)EncodedName);
}

// FindDiskDriverModule — 查找磁盘驱动模块
// 对应原始驱动 sub_140050E94
_QWORD *FindDiskDriverModule(void)
{
    _QWORD *Result = 0;
    __int64 v1 = 0;
    enum _GLOBAL_TABLE_INDEX v2;
    unsigned __int64 v3;
    unsigned int v4 = 0;
    unsigned __int64 v5;
    __int64 ObjectTypeDir = 0;
    __int64 v7 = 0;
    __int64 v8 = 0;
    _QWORD *v9;
    unsigned __int64 v10;
    unsigned __int64 v11;
    int v12 = 0;
    unsigned __int64 *i;
    unsigned __int64 v14;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        v1 = GtRead(GtCallbackField59);
        v2 = GtCallbackField60;
    }
    else
    {
        v1 = GtRead(GtCallbackField57);
        v2 = GtCallbackField58;
    }
    v3 = v1;
    v4 = GtRead(v2);
    if (v3 && v4)
    {
        v5 = v3 + v4;
        if (v5 > v3)
        {
            ObjectTypeDir = QueryObjectTypeDirectoryPath();
            if (ObjectTypeDir)
            {
                v7 = *(_QWORD *)(ObjectTypeDir + 312);
                if (v7)
                {
                    v8 = *(_QWORD *)(v7 + 48);
                    if (v8)
                    {
                        v9 = *(_QWORD **)(v8 + 8);
                        if (v9)
                        {
                            v10 = v9[12];
                            if (v10 < v3 || v10 >= v5)
                            {
                                v11 = v9[13];
                                if (v11 < v3 || v11 >= v5)
                                {
                                    v12 = 0;
                                    for (i = v9 + 14; ; i++)
                                    {
                                        v14 = *i;
                                        if (*i)
                                        {
                                            if (v14 >= v3 && v14 < v5)
                                                break;
                                        }
                                        if ((unsigned int)++v12 >= 0x1B)
                                            return (_QWORD *)Result;
                                    }
                                }
                            }
                            return v9;
                        }
                    }
                }
            }
        }
    }
    return (_QWORD *)Result;
}

// GetDiskDriverSection — 获取磁盘驱动节区
// 对应原始驱动 sub_1400504D4
_QWORD *GetDiskDriverSection(void)
{
    _QWORD *Result;
    _DWORD EncodedPath[6];
    int v2 = 0, v3 = 0, v4 = 0, v5 = 0, v6 = 0;

    Result = FindDiskDriverModule();
    if (!Result)
    {
        EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
        EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            v6 = 0;
            v2 = 7536748;
            v3 = 6226025;
            v4 = 6488179;
            v5 = 6881395;
        }
        else
        {
            v5 = 0;
            v2 = 7929971;
            v3 = 7143533;
            v4 = 6881392;
        }
        EncodedPath[4] = v2; EncodedPath[5] = v3;
        return (_QWORD *)OpenFileSection((__int64)EncodedPath);
    }
    return Result;
}

// OpenMountMgrDriverSection — 打开 mountmgr.sys 驱动节区
// 对应原始驱动 sub_14003DB6C
__int64 OpenMountMgrDriverSection(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 7274605; EncodedPath[5] = 4391029;
    EncodedPath[6] = 6357100; EncodedPath[7] = 7536755;
    EncodedPath[8] = 0;       EncodedPath[9] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// BuildSyscallDriverPath — 构建系统调用驱动路径
// 对应原始驱动 sub_140046A80
__int64 BuildSyscallDriverPath(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 7536750; EncodedPath[5] = 7340137;
    EncodedPath[6] = 7274610; EncodedPath[7] = 7929976;
    EncodedPath[8] = 0;       EncodedPath[9] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// OpenWin32kSection — 打开 win32k.sys 驱动节区
// 对应原始驱动 sub_140053EA4
__int64 OpenWin32kSection(void)
{
    _DWORD EncodedPath[6];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553716; EncodedPath[5] = 120;
    return OpenFileSection((__int64)EncodedPath);
}

// OpenWdfDriverSection — 打开 WDF 驱动节区
// 对应原始驱动 sub_1400864EC
__int64 OpenWdfDriverSection(void)
{
    _DWORD EncodedPath[10];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553719; EncodedPath[5] = 3145830;
    EncodedPath[6] = 3145777; EncodedPath[7] = 3145776;
    EncodedPath[8] = 0;       EncodedPath[9] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// ---- 9 个 Hook 条目写入函数 ----

// WriteTcpIpSyscallEntry — 写入 TCP/IP 系统调用条目
// 对应原始驱动 sub_1400539B8
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

// WriteShadowSyscallEntry — 写入 Shadow SSDT 条目
// 对应原始驱动 sub_14003D680
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

// SetSyscallHookEntry2 — 设置系统调用钩子条目 2
// 对应原始驱动 sub_140033AE8
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

// InstallSsdtHookEntry3 — 安装 SSDT Hook 条目 3
// 对应原始驱动 sub_140032F90
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

// InstallSsdtHookEntry4 — 安装 SSDT Hook 条目 4
// 对应原始驱动 sub_1400318F0
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

// GetSyscallTableEntry — 获取系统调用表条目
// 对应原始驱动 sub_140050D14
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

// SetSyscallHookEntry — 设置系统调用钩子条目
// 对应原始驱动 sub_14003DF48
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

// WriteSyscallContextEntry — 写入系统调用上下文条目
// 对应原始驱动 sub_140046E60
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

// SetWin32kServiceTableEntry — 设置 Win32k 服务表条目
// 对应原始驱动 sub_140054270
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

// WriteWdfSyscallHook — 写入 WDF 系统调用钩子
// 对应原始驱动 sub_140087158
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

// ---- 枚举/复制/验证函数 ----

// EnumSsdtFunctionTable2 — 枚举 SSDT 函数表 2
// 对应原始驱动 sub_1400335F4
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

// InitContextTableFromSyscallBase — 从系统调用基址初始化上下文表
// 对应原始驱动 sub_140032A70
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

// EnumSsdtFunctionTable4 — 枚举 SSDT 函数表 4
// 对应原始驱动 sub_14003146C
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

// CopySsdtHookTargetTable2 — 复制 SSDT Hook 目标表 2
// 对应原始驱动 sub_1400337D0
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

// CopySsdtHookTargetTable3 — 复制 SSDT Hook 目标表 3
// 对应原始驱动 sub_140032CCC
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

// CopySsdtHookTargetTable — 复制 SSDT Hook 目标表
// 对应原始驱动 sub_14003167C
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

// ValidateSsdtHookTargetTable — 验证 SSDT Hook 目标表
// 对应原始驱动 sub_140033118
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

// ValidateSsdtHookTargetTable2 — 验证 SSDT Hook 目标表 2
// 对应原始驱动 sub_140035A18
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

// ResolveContextTableMemory — 解析上下文表内存
// 对应原始驱动 sub_140032594
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

// ---- 初始化表函数 ----

// ReadKernelExportDirFile — 读取内核导出目录文件
// 对应原始驱动 sub_140066898
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

    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ReadSystemDriverFile — 读取系统驱动文件
// 对应原始驱动 sub_140067F3C
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

    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)OutBuffer, OutSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// InitKernelDataSectionTable — 初始化内核数据节区表
// 对应原始驱动 sub_140066650
void InitKernelDataSectionTable(void)
{
    unsigned int FileSize = 0;
    void *pFileBuffer = NULL;

    if (ReadKernelExportDirFile(&pFileBuffer, &FileSize))
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

// InitTdiExportAndRelocTable — 初始化 TDI 导出和重定位表
// 对应原始驱动 sub_140067EDC
void InitTdiExportAndRelocTable(void)
{
    unsigned int FileSize = 0;
    void *pFileBuffer = NULL;

    if (ReadSystemDriverFile(&pFileBuffer, &FileSize))
    {
        if (!GtRead(GtEprocessField01 | 0x800))
            ParseKernelDataSectionRelocs((__int64)pFileBuffer, FileSize);
        if (!GtRead(GtEprocessField02 | 0x800))
            FindTdiDeregisterPnpExport((__int64)pFileBuffer, FileSize);
        ExFree(pFileBuffer);
    }
}

// GetSsdtBaseAndSize — 获取 SSDT 基址和大小
// 对应原始驱动 sub_140028FAC
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
    *pOutSize = GtRead(SizeIndex);
    if (*pOutBase)
        return *pOutSize != 0;
    return 0;
}

// BuildInitSsdtHookTable — 构建初始化 SSDT Hook 表
// 对应原始驱动 sub_1400292CC
void BuildInitSsdtHookTable(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        BuildSsdtHookTableWin10();
    else
        BuildSsdtHookTableLegacy();
}

// BuildSsdtHookTargets2 — 构建 SSDT Hook 目标表 2
// 对应原始驱动 sub_140033650
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

    if (SectionBase && ReadNtFileForSsdtTargets2(&pFileBuffer, &FileSize))
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
            && ParseNtExportDir((__int64)pFileBuffer, FileSize, SectionBase, 0) == 1)
        {
            unsigned int *pRvaEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 29;
            do
            {
                __int64 TargetRva = *pRvaEntry;
                *(pRvaEntry - 1) = 0;
                if ((_DWORD)TargetRva && (int)TargetRva + 16 <= FileSize)
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

// BuildSsdtHookTargets3 — 构建 SSDT Hook 目标表 3
// 对应原始驱动 sub_140032B34
void BuildSsdtHookTargets3(void)
{
    char Result = 0;
    __int64 *pTargetTable = GtAlloc(GtFltUnregisterFilterOffset | GtDebugPortOffset | 0x400);
    unsigned int BuildNumber = GtRead(GtWindowsBuildNumber);
    enum _GLOBAL_TABLE_INDEX BaseIndex = GtCallbackField40;
    char *pFileBuffer;
    unsigned int FileSize = 0;
    unsigned int FuncOffset = 0;
    _WORD v12[8];
    char v13[24];

    if (BuildNumber >= 0x1770)
        BaseIndex = GtCallbackField42;
    __int64 NtoskrnlBase = GtRead(BaseIndex);
    if (NtoskrnlBase && ReadNtoskrnlFileToBuffer3(&pFileBuffer, &FileSize))
    {
        strcpy((char *)v12, "ntoskrnl.exe");
        HIBYTE_LV(v12[6]) = 0;
        v12[7] = 0;
        strcpy(v13, "IofCompleteRequest");
        v13[19] = 0;
        if (ParsePESectionHeaders((__int64)pFileBuffer, FileSize, (__int64)v12, (unsigned __int8 *)v13, &FuncOffset) == 1)
            GtWrite(GtCallbackField45, NtoskrnlBase + FuncOffset);
        if (ParseAtaPortInitForHookTargets((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1
            && ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
        {
            unsigned int *pEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 29;
            do
            {
                __int64 FuncRva = *pEntry;
                *(pEntry - 1) = 0;
                if ((_DWORD)FuncRva && (int)FuncRva + 32 <= FileSize)
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

// BuildSsdtHookTargets4 — 构建 SSDT Hook 目标 4
// 对应原始驱动 sub_140031514
void BuildSsdtHookTargets4(void)
{
    __int64 NtoskrnlBase = GtRead(GtCallbackField47);
    char *pFileBuffer;
    unsigned int FileSize = 0;
    unsigned int FuncOffset = 0;
    _WORD v8[8];
    char v9[24];

    if (NtoskrnlBase && ReadNtoskrnlFileToBuffer(&pFileBuffer, &FileSize))
    {
        HIBYTE_LV(v8[6]) = 0;
        v8[7] = 0;
        strcpy((char *)v8, "ntoskrnl.exe");
        strcpy(v9, "IofCompleteRequest");
        v9[19] = 0;
        if (ParsePESectionHeaders((__int64)pFileBuffer, FileSize, (__int64)v8, (unsigned __int8 *)v9, &FuncOffset) == 1)
            GtWrite(GtCallbackField50, NtoskrnlBase + FuncOffset);
        __int64 *pTargetTable = GtAlloc(GtEprocessField108 | 0x1000);
        if (ParseNtHeadersForSsdtTargets((__int64)pFileBuffer, FileSize, (__int64)pTargetTable) == 1
            && ParseNtExportDir((__int64)pFileBuffer, FileSize, NtoskrnlBase, 0) == 1)
        {
            unsigned int *pEntry = (unsigned int *)pTargetTable + 1;
            __int64 EntryCount = 28;
            do
            {
                __int64 FuncRva = *pEntry;
                *(pEntry - 1) = 0;
                if ((_DWORD)FuncRva)
                {
                    if ((int)FuncRva + 16 <= FileSize)
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

// BuildSsdtEntryTableLegacy — 构建 SSDT 条目表（旧版）
// 对应原始驱动 sub_140028B18 (CmdDispatchSsdtByVersion 的旧版分支)
char BuildSsdtEntryTableLegacy(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    // 简单封装：调用 BuildInitSsdtHookTable 初始化，然后输出到用户缓冲区
    if (!GtRead(GtEprocessModuleListOffset | GtEprocessField23))
        BuildInitSsdtHookTable();
    __int64 HookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField23);
    unsigned int HookTableCount = GtRead(GtEprocessModuleListOffset | GtEprocessField24);

    if (HookTableBase && HookTableBase > (unsigned __int64)MmSystemRangeStart && HookTableCount
        && OutputBuffer && BufferSize >= 8 * (unsigned __int64)(HookTableCount - 1) + 16
        && (unsigned __int64)OutputBuffer < MmUserProbeAddress
        && (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, BufferSize, 8u);
        memset(OutputBuffer, 0, BufferSize);
        OutputBuffer[1] = HookTableCount;
        *OutputBuffer = GtRead(GtWindowsBuildNumber);
        for (unsigned int Index = 0; Index < HookTableCount; Index++)
            *(_QWORD *)&OutputBuffer[2 * Index + 2] = *(_QWORD *)(HookTableBase + 16LL * Index);
        return 1;
    }
    return 0;
}

// BuildSsdtEntryTableEx — 构建 SSDT 条目表（扩展版）
// 对应原始驱动 sub_140028CF8
char BuildSsdtEntryTableEx(__int64 TargetBase, unsigned int TargetSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!GtRead(GtEprocessModuleListOffset | GtEprocessField25))
        BuildInitSsdtHookTable();
    __int64 HookTableBase = GtRead(GtEprocessModuleListOffset | GtEprocessField25);
    unsigned int HookTableSize = GtRead(GtEprocessModuleListOffset | GtEprocessField26);

    if (HookTableBase && HookTableSize > 8
        && HookTableBase > (unsigned __int64)MmSystemRangeStart && HookTableSize < 0x1000)
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
                *OutputBuffer = GtRead(GtWindowsBuildNumber);
                for (unsigned int Index = 0; Index < EntryCount; Index++)
                    *(_QWORD *)&OutputBuffer[2 * Index + 2] = *(_QWORD *)(HookTableBase + 8LL * (Index + 1));
                return 1;
            }
        }
    }
    return 0;
}

// ---- 以下为 SSDT 表枚举/复制/验证函数（由各 CmdEnumSyscallTableX 调用） ----
// 这些函数在原始驱动中位于不同地址，这里统一实现

// EnumSyscallTable7 — 枚举系统调用表 7 (TCP/IP)
// 对应原始驱动 sub_140046C2C 内部调用
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

// EnumShadowSyscallTable — 枚举 Shadow SSDT 表
// 对应原始驱动 sub_14003D464 内部调用
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

// FillSyscallTableInfo — 填充系统调用表信息
// 对应原始驱动 sub_140050AC0 内部调用
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

// EnumSyscallTable6 — 枚举系统调用表 6
// 对应原始驱动 sub_14003DD2C 内部调用
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

// InitSyscallExportEntryArray — 初始化系统调用导出条目数组
// 对应原始驱动 sub_140046C2C 内部调用
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

// CopySyscallTable7 — 复制系统调用表 7
// 对应原始驱动 sub_140046C2C 内部调用
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

// CopyShadowSyscallTable — 复制 Shadow SSDT 表
// 对应原始驱动 sub_14003D464 内部调用
char CopyShadowSyscallTable(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}

// CopySyscallTableEntryArray — 复制系统调用表条目数组
// 对应原始驱动 sub_14003DD2C 内部调用
char CopySyscallTableEntryArray(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}

// CopySyscallExportEntries — 复制系统调用导出条目
// 对应原始驱动 sub_140046C2C 内部调用
char CopySyscallExportEntries(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}

// DuplicateSyscallTableEntries — 复制系统调用表条目
// 对应原始驱动 sub_140050AC0 内部调用
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

// DuplicateSyscallTableOutput — 复制系统调用表输出
// 对应原始驱动 sub_140054050 内部调用
char DuplicateSyscallTableOutput(__int64 pSourceTable)
{
    return DuplicateSyscallTableEntries(pSourceTable);
}

// CopyWin32kServiceTable — 复制 Win32k 服务表
// 对应原始驱动 sub_140054050 内部调用
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

// CopySyscallTableEntries — 复制系统调用表条目
// 对应原始驱动 sub_1400869C0 内部调用
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

// CopySyscallTableToBuffer — 复制系统调用表到缓冲区
// 对应原始驱动 sub_1400869C0 内部调用
char CopySyscallTableToBuffer(__int64 pSourceTable)
{
    return CopySyscallTable7(pSourceTable);
}

// ValidateSyscallHookEntries — 验证系统调用钩子条目
// 对应原始驱动 sub_140046C2C 内部调用
char ValidateSyscallHookEntries(__int64 pTargetTable)
{
    return ValidateSsdtHookTargetTable(pTargetTable);
}

// ValidateSyscallTableEntries — 验证系统调用表条目
// 对应原始驱动 sub_1400869C0 内部调用
char ValidateSyscallTableEntries(__int64 pTargetTable)
{
    return ValidateSsdtHookTargetTable2(pTargetTable);
}

// ParseStorPortExportDir — 解析 StorPort 导出目录
// 对应原始驱动 sub_140050AC0 内部调用
char ParseStorPortExportDir(void)
{
    // 在原始驱动中，ParseStorPortExportDir 实际调用 GetDiskDriverSection 并初始化
    // 这里标记 GT 索引为就绪
    GtWrite(GtCallbackField61, 1);
    return 1;
}

// ParseSyscallFileExportDir — 解析系统调用文件导出目录
// 对应原始驱动 sub_14003DD2C 内部调用
char ParseSyscallFileExportDir(void)
{
    GtWrite(GtCallbackField72, 1);
    return 1;
}

// BuildSyscallExportTable — 构建系统调用导出表
// 对应原始驱动 sub_140046C2C 内部调用
char BuildSyscallExportTable(void)
{
    GtWrite(GtCallbackField80, 1);
    return 1;
}

// InitShadowSyscallExportTable — 初始化 Shadow SSDT 导出表
// 对应原始驱动 sub_14003D464 内部调用
char InitShadowSyscallExportTable(void)
{
    GtWrite(GtCallbackField15, 1);
    return 1;
}

// InitWin32kSyscallTable — 初始化 Win32k 系统调用表
// 对应原始驱动 sub_140054050 内部调用
char InitWin32kSyscallTable(void)
{
    GtWrite(GtCallbackField83, 1);
    return 1;
}

// ParseSyscallTableExportDir — 解析系统调用表导出目录
// 对应原始驱动 sub_1400869C0 内部调用
char ParseSyscallTableExportDir(void)
{
    GtWrite(GtDisableHookProtectionAddr2 | GtEprocessField157, 1);
    return 1;
}

// InitDiskQueryExportTable — 初始化磁盘查询导出表
// 对应原始驱动 sub_1400538C8 内部调用
char InitDiskQueryExportTable(void)
{
    GtWrite(GtEprocessField135 | 0x100, 1);
    return 1;
}

// ===================================================================
// PE 头解析函数
// ===================================================================

// ParseNtHeaders — 解析 NT 文件头类型
// 对应原始驱动 sub_140004F80

// ParsePESectionHeaders — 解析 PE 节头表。遍历节表查找指定名称的节，返回该节的节头偏移。
// 对应原始驱动 sub_1400058A4
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
        int Remaining = ImageSize - SectionTableRva;

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
            DataListRemaining = ImageSize - (unsigned int)RawDataRva;
        }
        else
        {
            __int64 VirtualRva = SectionEntry[4];
            pDataList = (__int64 *)(VirtualRva + PeBase);
            IsLinkedSection = 0;
            DataListRemaining = ImageSize - (unsigned int)VirtualRva;
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

// BuildExportIndexTable — 构建导出索引表
// 对应原始驱动 sub_140005610
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
                                    unsigned int HashValue = Sha1HashToDword(pName);
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

// ===================================================================
// 导出条目填充函数
// ===================================================================

// ScanKernelModulePESections — 扫描内核模块 PE 节区，查找内核数据节区偏移
// 对应原始驱动 sub_14007870C
__int64 ScanKernelModulePESections(void)
{
    __int64 ImageBase = GtRead(GtEprocessField22);
    unsigned int ImageSize = GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int TargetOffset1 = (unsigned int)GtRead(GtKernelDataSectionScanTarget1);
    unsigned int BuildNumber = GtRead(GtWindowsBuildNumber);
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

    __int64 Context[8];
    _DWORD SectionEntry[72];
    InitPESectionReadContext(ScanBase, ScanSize, 2, 0, -1, 0, 0, (__int64)&Context);

    // 第一阶段：查找类型 0x558 节区，匹配目标偏移
    unsigned int i;
    for (i = 0; i < 0x100; i++)
    {
        if (ReadPESectionEntry(&Context, SectionEntry))
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
        if (ReadPESectionEntry(&Context, SectionEntry))
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

// FillExportEntrySlot — 填充导出条目槽
// 对应原始驱动 sub_14007A9EC
char FillExportEntrySlot(__int64 pOutputTable)
{
    char Result = 0;
    unsigned int KernelDataOffset = GtRead(GtKernelDataField21);
    if (!KernelDataOffset)
    {
        ScanKernelModulePESections();
        KernelDataOffset = GtRead(GtKernelDataField21);
    }
    __int64 KernelDataBase = GtRead(GtEprocessField66);
    unsigned int KernelDataSize = GtRead(GtEprocessField23);
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

// ===================================================================
// NDIS 导出查找函数（通过名称查找 NDIS 导出函数）
// ===================================================================

// BuildSsdtHookTableWin10 — 构建 SSDT Hook 表（Win10）
// 对应原始驱动 sub_1400292F4
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

// BuildSsdtHookTableLegacy — 构建 SSDT Hook 表（旧版）
// 对应原始驱动 sub_1400293B0
void BuildSsdtHookTableLegacy(void)
{
    __int64 NtoskrnlBase = GtRead(GtEprocessField76);
    if (NtoskrnlBase)
    {
        void *FileBuffer = NULL;
        unsigned int FileSize = 0;
        if (ReadNtFileForHookTable(&FileBuffer, &FileSize))
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

// FindNdisDeregisterProtocolExport — 查找 NdisDeregisterProtocol 导出
// 对应原始驱动 sub_140060E38
char FindNdisDeregisterProtocolExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisDeregisterProtocol");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField14, (unsigned int)Value);
            GtWrite(GtEprocessExtField15, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisFRegisterFilterDriverExport — 查找 NdisFRegisterFilterDriver 导出
// 对应原始驱动 sub_140060F04
char FindNdisFRegisterFilterDriverExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisFRegisterFilterDriver");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField17, (unsigned int)Value);
            GtWrite(GtEprocessExtField18, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisIMInitializeDeviceInstanceEx — 查找 NdisIMInitializeDeviceInstanceEx 导出
// 对应原始驱动 sub_140060FD8
char FindNdisIMInitializeDeviceInstanceEx(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        WORD NameBuf[20];
        strcpy((char *)NameBuf, "NdisIMInitializeDeviceInstanceEx");
        *((UCHAR *)&NameBuf[16] + 1) = 0;
        NameBuf[17] = 0;
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField20, (unsigned int)Value);
            GtWrite(GtEprocessExtField21, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisIfDeregisterInterfaceExport — 查找 NdisIfDeregisterInterface 导出
// 对应原始驱动 sub_140061140
char FindNdisIfDeregisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisIfDeregisterInterface");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField42, (unsigned int)Value);
            GtWrite(GtEprocessExtField43, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisIfDeregisterProviderExport — 查找 NdisIfDeregisterProvider 导出
// 对应原始驱动 sub_1400611E0
char FindNdisIfDeregisterProviderExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "NdisIfDeregisterProvider");
        *((UCHAR *)&NameBuf[12] + 1) = 0;
        NameBuf[13] = 0;
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField36, (unsigned int)Value);
            GtWrite(GtEprocessExtField37, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisExportsBySectionScan — 通过节区扫描查找 NDIS 导出
// 对应原始驱动 sub_140061254
__int16 FindNdisExportsBySectionScan(__int64 a1, unsigned int a2)
{
    char v4 = 0;
    unsigned int v5 = GtRead(GtEprocessExtField38);
    if (!v5)
    {
        FindNdisIfRegisterInterfaceExport(a1, a2);
        v5 = GtRead(GtEprocessExtField38);
    }
    __int64 v6 = GtRead(GtEprocessExtField11);
    __int64 v7 = v6;
    if (v6 && v5 && v5 < a2)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            __int64 v18 = 0, v19 = 0;
            _DWORD v20[14];
            int v21 = 0, v23 = 0, v24 = 0;
            __int64 v22 = 0, v25 = 0, v27 = 0;
            unsigned int v26 = 0;

            InitPESectionReadContext(a1 + v5, a2 - v5, 2, 0, -1, 0, 0, (__int64)&v18);
            int v8 = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry(&v18, v20))
                    break;
                int v9 = v26 + v19;
                v19 += v26;
                if (*(_WORD *)(v27 + 6) == 1368)
                {
                    if (v21)
                    {
                        unsigned int v10 = v9 + v21 - a1;
                        if (v10 && v10 < a2)
                        {
                            v5 = v9 + v21 - a1;
                            break;
                        }
                    }
                }
                if (++v8 >= 0xA)
                    break;
            }
        }
        int v11 = (GtRead(GtWindowsBuildNumber) == 16299) + 1;
        __int64 v18b = 0, v19b = 0;
        _DWORD v20b[14];
        int v21b = 0, v23b = 0, v24b = 0;
        __int64 v22b = 0, v25b = 0, v27b = 0;
        unsigned int v26b = 0;

        InitPESectionReadContext(a1 + v5, a2 - v5, 2, 0, -1, 0, 0, (__int64)&v18b);
        unsigned int v12 = 0;
        int v13 = 0;
        while (1)
        {
            if ((unsigned int)ReadPESectionEntry(&v18b, v20b))
                return 0;
            int v14 = v26b + v19b;
            v19b += v26b;
            __int16 v15 = *(_WORD *)(v27b + 6);
            if (v15 == 1349)
                return 0;
            if (v15 == 1298 && v25b == 0x40000 && v22b == 64)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x23F0 && v23b == 1
                    || (unsigned int)GtRead(GtWindowsBuildNumber) == 9600 && v23b == 5
                    || (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
                {
                    if (v19b + v24b - a1 && (int)v19b + v24b - (int)a1 < (int)a2)
                        v12 = v19b + v24b - a1;
                }
            }
            __int16 v16 = *(_WORD *)(v27b + 6);
            if (v16 == 1368)
                goto LABEL_46;
            if ((unsigned __int16)(v16 - 1139) <= 1u)
                break;
            if (v4 == 1)
            {
                if (v16 == 1296 && v25b == 0x40000 && v22b == 64)
                {
                    if (v14 + v24b - a1 && (unsigned int)(v14 + v24b - a1) < a2 && !--v11)
                    {
                        GtWrite(GtEprocessExtField41, v7 + (unsigned int)(v14 + v24b - a1));
                        return 0;
                    }
                }
            }
LABEL_47:
            if (++v13 >= 0xC8)
                return 0;
        }
        if (v12 && !v4)
        {
            GtWrite(GtEprocessExtField40, v7 + v12);
            v4 = 1;
        }
LABEL_46:
        v12 = 0;
        goto LABEL_47;
    }
    return 0;
}

// FindNdisExportsBySectionScanV2 — 通过节区扫描查找 NDIS 导出 V2
// 对应原始驱动 sub_140061554
__int64 FindNdisExportsBySectionScanV2(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead(GtEprocessExtField32);
    if (!v4)
    {
        FindNdisIfRegisterProviderExport(a1, a2);
        v4 = GtRead(GtEprocessExtField32);
    }
    __int64 v6 = GtRead(GtEprocessExtField11);
    if (v6 && v4 && v4 < a2)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        {
            __int64 v16 = 0, v17 = 0;
            _DWORD v18[20];
            __int64 v19 = 0, v22 = 0, v24 = 0;
            int v20 = 0;
            unsigned int v21 = 0, v23 = 0;

            InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v16);
            char v7 = 0;
            int v8 = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry(&v16, v18))
                    return 0;
                int v9 = v23 + v17;
                v17 += v23;
                __int16 v10 = *(_WORD *)(v24 + 6);
                if (v10 == 1296 && v19 == 64 && v20 == 8 && v22 == 64)
                {
                    v7 = 1;
                }
                else if (v7 == 1)
                {
                    if (v10 == 1368)
                    {
                        v4 = v9 + v18[14] - a1;
                        break;
                    }
                }
                if (++v8 >= 0x64)
                    return 0;
            }
        }
        if (v4 && v4 < a2)
        {
            __int64 v16b = 0, v17b = 0;
            _DWORD v18b[20];
            __int64 v19b = 0, v22b = 0, v24b = 0;
            int v20b = 0;
            unsigned int v21b = 0, v23b = 0;

            InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v16b);
            unsigned int v11 = 0;
            char v12 = 0;
            int v13 = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry(&v16b, v18b))
                    return 0;
                int v14 = v23b + v17b;
                v17b += v23b;
                __int16 v15 = *(_WORD *)(v24b + 6);
                if (v15 == 1349)
                    return 0;
                if (v15 == 1298 && v22b == 0x40000 && v19b == 64 && v20b == 1
                    && v14 + v21b - a1 && v14 + v21b - (unsigned int)a1 < a2)
                {
                    v11 = v14 + v21b - a1;
                }
                if (v15 == 1368)
                    goto LABEL_43;
                if ((unsigned __int16)(v15 - 1139) <= 1u)
                    break;
                if (v12 == 1 && v22b == 0x40000 && v19b == 64)
                {
                    unsigned int result = v14 + v21b - a1;
                    if (result && result < a2)
                        return GtWrite(GtEprocessExtField35, v6 + result);
                }
LABEL_44:
                if (++v13 >= 0xC8)
                    return 0;
            }
            if (v11 && !v12)
            {
                GtWrite(GtEprocessExtField34, v6 + v11);
                v12 = 1;
            }
LABEL_43:
            v11 = 0;
            goto LABEL_44;
        }
    }
    return 0;
}

// FindNdisIfRegisterInterfaceExport — 查找 NdisIfRegisterInterface 导出
// 对应原始驱动 sub_140061814
char FindNdisIfRegisterInterfaceExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisIfRegisterInterface");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField38, (unsigned int)Value);
            GtWrite(GtEprocessExtField39, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisIfRegisterProviderExport — 查找 NdisIfRegisterProvider 导出
// 对应原始驱动 sub_1400618E0
char FindNdisIfRegisterProviderExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisIfRegisterProvider");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField32, (unsigned int)Value);
            GtWrite(GtEprocessExtField33, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisMGetOffloadHandlersExport — 查找 NdisMGetOffloadHandlers 导出
// 对应原始驱动 sub_1400619AC
char FindNdisMGetOffloadHandlersExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisMGetOffloadHandlers");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField44, (unsigned int)Value);
            GtWrite(GtEprocessExtField45, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// FindNdisMRegisterMiniportDriverExport — 查找 NdisMRegisterMiniportDriver 导出
// 对应原始驱动 sub_140061B44
char FindNdisMRegisterMiniportDriverExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[32];
        strcpy(NameBuf, "NdisMRegisterMiniportDriver");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1)
        {
            if ((unsigned int)Value && (unsigned int)Value < ImageSize)
            {
                GtWrite(GtEprocessExtField25, (unsigned int)Value);
                GtWrite(GtEprocessExtField26, v5 + (unsigned int)Value);
                return 1;
            }
        }
        else
        {
            unsigned int v6 = GtRead(GtEprocessExtField23);
            if (v6 || (FindNdisMRegisterMiniportExport(ImageBase, ImageSize), (v6 = GtRead(GtEprocessExtField23)) != 0))
                ParseNdisMiniportDriverName(ImageBase, ImageSize, v6);
        }
    }
    return Result;
}

// FindNdisGetVersionExport — 查找 NdisGetVersion 导出
// 对应原始驱动 sub_140062090
char FindNdisGetVersionExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    unsigned int v6 = 0;
    if (GtRead(GtEprocessExtField11))
    {
        char NameBuf[16];
        strcpy(NameBuf, "NdisGetVersion");
        NameBuf[15] = 0;
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, &v6) == 1 && v6 && v6 < ImageSize && v6 + 5 < ImageSize)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB)
                return ParseNdisGetVersionSection(v6, ImageBase, ImageSize);
            GtWrite(GtEprocessExtField13, *(unsigned int *)(v6 + ImageBase + 1));
            return 1;
        }
    }
    return Result;
}

// FindKernelRdataSection — 查找内核 .rdata 节区
// 对应原始驱动 sub_140062278
char FindKernelRdataSection(__int64 a1, unsigned int a2)
{
    char SectionName[8];
    __int64 v3 = a2;
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
    unsigned int PESectionByName = (unsigned int)FindPESectionByName(a1, v3, (__int64)SectionName);
    unsigned int v6 = (unsigned int)FindPESectionByNameReturnVa(a1, v3, (__int64)SectionName);
    if (PESectionByName && v6 && PESectionByName < (unsigned int)v3)
    {
        _QWORD *v7 = (_QWORD *)(PESectionByName + a1);
        __int64 v8 = *(_QWORD *)(*(int *)(a1 + 60) + a1 + 48);
        if (v6 >= 0x100000)
            v6 = 0x100000;
        __int64 v9 = (v6 + PESectionByName >= (unsigned int)v3) ? (a1 + v3) : (a1 + PESectionByName + v6);
        __int64 v10 = v9 - 72;
        while ((unsigned __int64)v7 < v10)
        {
            if (*v7 == 65793 && !v7[2] && v7[3] == 65795 && !v7[5] && v7[6] == 65796)
            {
                __int64 v11 = v7[1];
                __int64 v12 = v3 + v8;
                if (v11 > v8 && v11 < v12)
                {
                    __int64 v5 = v7[4];
                    if (v5 > v8 && v5 < v12)
                    {
                        v5 = v7[7];
                        if (v5 > v8 && v5 < v12)
                        {
                            unsigned int v13 = (_DWORD)v7 - a1;
                            if (v13 && v13 < (unsigned int)v3)
                            {
                                __int64 v5b = GtRead(GtEprocessExtField11);
                                if (v5b)
                                {
                                    GtWrite(GtEprocessExtField56, v13 + v5b);
                                    _QWORD *v14 = (_QWORD *)(v13 + a1);
                                    _QWORD *v15 = v14;
                                    if ((unsigned __int64)v14 < v10)
                                    {
                                        __int64 v16 = v3 + v8;
                                        do
                                        {
                                            if (*v15 > 0xFD010111)
                                                break;
                                            __int64 v17 = v15[1];
                                            if (v17 && (v17 <= v8 || v17 >= v16))
                                                break;
                                            if (!v17 && !v15[2])
                                                break;
                                            __int64 v18 = v15[2];
                                            if (v18 && (v18 <= v8 || v18 >= v16))
                                                break;
                                            v15 += 3;
                                        } while ((unsigned __int64)v15 < v10);
                                    }
                                    unsigned int v19 = (_DWORD)v15 - (_DWORD)v14;
                                    if (v19 - 1 <= 0xFFE)
                                    {
                                        AdjustRelocationOffsets(v14, v19, v8);
                                        GtWrite(GtEprocessExtField57, v19);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ++v7;
        }
    }
    return 0;
}

// FindNdisRegisterTdiCallBackExport — 查找 NdisRegisterTdiCallBack 导出
// 对应原始驱动 sub_140061D3C
char FindNdisRegisterTdiCallBackExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        char NameBuf[24];
        strcpy(NameBuf, "NdisRegisterTdiCallBack");
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField28, (unsigned int)Value);
            GtWrite(GtEprocessExtField29, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// ParseNtKernelDataOffsets — 解析 NT 内核数据偏移
// 对应原始驱动 sub_140061E08
char ParseNtKernelDataOffsets(__int64 a1, unsigned int a2)
{
    char v4 = 0;
    unsigned int v5 = GtRead(GtEprocessExtField44);
    if (!v5)
    {
        FindNdisMGetOffloadHandlersExport(a1, a2);
        v5 = GtRead(GtEprocessExtField44);
    }
    __int64 v6 = GtRead(GtEprocessExtField11);
    if (v6 && v5 && v5 < a2)
    {
        __int64 v7 = *(_QWORD *)(*(int *)(a1 + 60) + a1 + 48);
        __int64 v20 = 0, v21 = 0;
        _DWORD v22[20];
        __int64 v23 = 0, v25 = 0, v27 = 0;
        __int64 Value = 0;
        unsigned int v26 = 0;

        InitPESectionReadContext(a1 + v5, a2 - v5, 2, 0, -1, 0, 0, (__int64)&v20);
        for (unsigned int i = 0; i < 0x1E; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v20, v22))
                break;
            int v9 = v26 + v21;
            v21 += v26;
            __int16 v10 = *(_WORD *)(v27 + 6);
            if (v10 == 1349)
                break;
            if (v10 == 1298 && v25 == 0x40000)
            {
                if ((_DWORD)Value && v23 == 64)
                {
                    unsigned int v11 = v9 + (unsigned int)Value - a1;
                    if (v11 && v11 < a2)
                    {
                        __int64 v12 = v11;
                        GtWrite(GtEprocessExtField46, v11);
                        GtWrite(GtEprocessExtField47, v12 + v6);
                        GtWrite(GtEprocessExtField48, (unsigned int)Value);
                        GtWrite(GtEprocessExtField49, v6 + (unsigned int)(v21 - a1 - 4));
                        if (v12 + 56 < a2)
                        {
                            if (*(_QWORD *)(v12 + a1 + 8) > v7)
                            {
                                unsigned int v13 = *(_DWORD *)(v12 + a1 + 8) - v7;
                                if (a2 > v13)
                                    GtWrite(GtEprocessExtField50, v6 + v13);
                            }
                            if (*(_QWORD *)(v12 + a1 + 16) > v7)
                            {
                                unsigned int v14 = *(_DWORD *)(v12 + a1 + 16) - v7;
                                if (a2 > v14)
                                    GtWrite(GtEprocessExtField51, v6 + v14);
                            }
                            if (*(_QWORD *)(v12 + a1 + 24) > v7)
                            {
                                unsigned int v15 = *(_DWORD *)(v12 + a1 + 24) - v7;
                                if (a2 > v15)
                                    GtWrite(GtEprocessExtField52, v6 + v15);
                            }
                            if (*(_QWORD *)(v12 + a1 + 32) > v7)
                            {
                                unsigned int v16 = *(_DWORD *)(v12 + a1 + 32) - v7;
                                if (a2 > v16)
                                    GtWrite(GtEprocessExtField53, v6 + v16);
                            }
                            if (*(_QWORD *)(v12 + a1 + 40) > v7)
                            {
                                unsigned int v17 = *(_DWORD *)(v12 + a1 + 40) - v7;
                                if (a2 > v17)
                                    GtWrite(GtEprocessExtField54, v6 + v17);
                            }
                            if (*(_QWORD *)(v12 + a1 + 48) > v7)
                            {
                                unsigned int v18 = *(_DWORD *)(v12 + a1 + 48) - v7;
                                if (a2 > v18)
                                    GtWrite(GtEprocessExtField55, v6 + v18);
                            }
                            return 1;
                        }
                        return v4;
                    }
                }
            }
        }
    }
    return v4;
}

// ScanTextSectionPattern — 扫描 .text 节区模式
// 对应原始驱动 sub_140062BD0
__int16 ScanTextSectionPattern(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead(GtEprocessExtField14);
    if (!v4)
    {
        FindNdisDeregisterProtocolExport(a1, a2);
        v4 = GtRead(GtEprocessExtField14);
    }
    __int64 v5 = GtRead(GtEprocessExtField11);
    __int64 v6 = v5;
    if (v5 && v4 && v4 < a2)
    {
        __int64 v12 = 0, v13 = 0;
        _DWORD v14[20];
        int v16 = 0;
        __int64 v15 = 0, v17 = 0, v19 = 0;
        unsigned int v18 = 0;

        InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v12);
        char v7 = 0;
        for (unsigned int i = 0; i < 0x64; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v12, v14))
                break;
            int v9 = v18 + v13;
            v13 += v18;
            __int16 v10 = *(_WORD *)(v19 + 6);
            if ((unsigned __int16)(v10 - 1139) <= 1u)
            {
                v7 = 1;
            }
            else if (v7 == 1)
            {
                if (v10 == 1296 && v17 == 0x40000)
                {
                    if (v16 && v15 == 64)
                    {
                        unsigned int v11 = v9 + v16 - a1;
                        if (v11 && v11 < a2)
                        {
                            GtWrite(GtEprocessExtField16, v6 + v11);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// ScanDataSectionPattern — 扫描 .data 节区模式
// 对应原始驱动 sub_140062D50
__int64 ScanDataSectionPattern(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead(GtEprocessExtField28);
    if (!v4)
    {
        FindNdisRegisterTdiCallBackExport(a1, a2);
        v4 = GtRead(GtEprocessExtField28);
    }
    __int64 v6 = GtRead(GtEprocessExtField11);
    if (v6 && v4 && v4 < a2)
    {
        __int64 v12 = 0, v13 = 0;
        _DWORD v14[16];
        int v15 = 0;
        __int64 v16 = 0, v18 = 0, v20 = 0;
        unsigned int v19 = 0;

        InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v12);
        unsigned int v7 = 0;
        unsigned int v8 = 0;
        for (unsigned int i = 0; i < 0x32; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v12, v14))
                break;
            int v10 = v19 + v13;
            v13 += v19;
            __int16 v11 = *(_WORD *)(v20 + 6);
            if (v11 == 1349)
                break;
            if (v11 == 1294 && v16 == 0x40000 && v18 == 64)
            {
                unsigned int result = v10 + v15 - a1;
                if (v10 + v15 - (int)a1)
                {
                    if (result < a2)
                    {
                        if (v7)
                        {
                            v8 = v10 + v15 - a1;
                            break;
                        }
                        v7 = v10 + v15 - a1;
                    }
                }
            }
        }
        if (v7 && v8)
        {
            GtWrite(GtEprocessExtField30, v6 + v7);
            return GtWrite(GtEprocessExtField31, v6 + v8);
        }
    }
    return 0;
}

// ScanInitSectionPattern — 扫描 INIT 节区模式
// 对应原始驱动 sub_140062604
__int16 ScanInitSectionPattern(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead(GtEprocessExtField25);
    if (!v4)
    {
        FindNdisMRegisterMiniportDriverExport(a1, a2);
        v4 = GtRead(GtEprocessExtField25);
    }
    __int64 v5 = GtRead(GtEprocessExtField11);
    __int64 v6 = v5;
    if (v5 && v4 && v4 < a2)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            __int64 v16 = 0, v17 = 0;
            _DWORD v18[14];
            int v19 = 0, v20 = 0, v22 = 0;
            __int64 v21 = 0, v23 = 0, v25 = 0;
            unsigned int v24 = 0;

            InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v16);
            int v7 = 0;
            while (!(unsigned int)ReadPESectionEntry(&v16, v18))
            {
                int v8 = v24 + v17;
                v17 += v24;
                if ((unsigned __int16)(*(_WORD *)(v25 + 6) - 1368) <= 1u)
                {
                    if (v19)
                    {
                        unsigned int v9 = v8 + v19 - a1;
                        if (v9 && v9 < a2)
                        {
                            v4 = v8 + v19 - a1;
                            break;
                        }
                    }
                }
                if (++v7 >= 5)
                    break;
            }
        }
        __int64 v16b = 0, v17b = 0;
        _DWORD v18b[14];
        int v19b = 0, v20b = 0, v22b = 0;
        __int64 v21b = 0, v23b = 0, v25b = 0;
        unsigned int v24b = 0;

        InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v16b);
        int v10 = 0;
        int v11 = 0;
        for (unsigned int i = 0; i < 0x3E8; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v16b, v18b))
                break;
            int v13 = v24b + v17b;
            v17b += v24b;
            __int16 v14 = *(_WORD *)(v25b + 6);
            if ((unsigned __int16)(v14 - 1139) <= 1u)
            {
                v10 = 0;
                v11 = 0;
            }
            else
            {
                if (v14 == 1296)
                {
                    if (v23b == 0x40000 && v22b && v21b == 64)
                    {
                        if (v10)
                        {
                            if (!v11)
                                v11 = v13 + v22b - a1;
                        }
                        else
                        {
                            v10 = v13 + v22b - a1;
                        }
                    }
                }
                else if (v21b == 0x40000)
                {
                    if (v20b && v23b == 64)
                    {
                        unsigned int rva = v13 + v20b - a1;
                        if (rva && rva < a2 && (v10 == (int)rva || v11 == (int)rva))
                        {
                            GtWrite(GtEprocessExtField27, v6 + rva);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// ScanPageSectionPattern — 扫描 .page 节区模式
// 对应原始驱动 sub_140062458
__int16 ScanPageSectionPattern(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead(GtEprocessExtField17);
    if (!v4)
    {
        FindNdisFRegisterFilterDriverExport(a1, a2);
        v4 = GtRead(GtEprocessExtField17);
    }
    __int64 v5 = GtRead(GtEprocessExtField11);
    __int64 v6 = v5;
    if (v5 && v4 && v4 < a2)
    {
        __int64 v12 = 0, v13 = 0;
        _DWORD v14[16];
        int v15 = 0, v17 = 0;
        __int64 v16 = 0, v18 = 0, v20 = 0;
        unsigned int v19 = 0;

        InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v12);
        int v7 = 0;
        for (unsigned int i = 0; i < 0x3E8; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v12, v14))
                break;
            int v9 = v19 + v13;
            v13 += v19;
            __int16 v10 = *(_WORD *)(v20 + 6);
            if ((unsigned __int16)(v10 - 1139) <= 1u)
            {
                v7 = 0;
            }
            else
            {
                if (v10 == 1296)
                {
                    if (v18 == 0x40000 && v17 && v16 == 64)
                        v7 = v9 + v17 - a1;
                }
                else if (v16 == 0x40000)
                {
                    if (v15 && v18 == 64)
                    {
                        unsigned int rva = v9 + v15 - a1;
                        if (rva && rva < a2 && (int)rva == v7)
                        {
                            GtWrite(GtEprocessExtField19, v6 + rva);
                            return 0;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// FindTdiDeregisterPnpExport — 查找 TdiDeregisterPnPHandlers 导出
// 对应原始驱动 sub_140067CF0
char FindTdiDeregisterPnpExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (v5)
    {
        WORD NameBuf[16];
        strcpy((char *)NameBuf, "TdiDeregisterPnPHandlers");
        *((UCHAR *)&NameBuf[12] + 1) = 0;
        NameBuf[13] = 0;
        if (LookupExportByName(ImageBase, ImageSize, (__int64)NameBuf, (unsigned int *)&Value) == 1
            && (unsigned int)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessField02 | 0x800, (unsigned int)Value);
            GtWrite(GtEprocessField03 | 0x800, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// ParseKernelDataSectionRelocs — 解析内核数据节区重定位
// 对应原始驱动 sub_140067984
__int64 ParseKernelDataSectionRelocs(__int64 a1, unsigned int a2)
{
    unsigned int v4 = GtRead((enum _GLOBAL_TABLE_INDEX)2052);
    if (!v4)
    {
        FindDllInitExport(a1, a2);
        v4 = GtRead((enum _GLOBAL_TABLE_INDEX)2052);
    }
    __int64 v6 = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (v6 && v4 && v4 < a2)
    {
        __int64 v19 = 0, v20 = 0;
        _DWORD v21[16];
        unsigned int v22 = 0, v28 = 0;
        __int64 v23 = 0, v25 = 0, v27 = 0, v29 = 0;
        int v24 = 0, v26 = 0;
        unsigned int v18 = 0;
        char v16 = 0;
        int v17 = 0;

        InitPESectionReadContext(a1 + v4, a2 - v4, 2, 0, -1, 0, 0, (__int64)&v19);
        int v7 = 0;
        unsigned int v8 = 0;
        unsigned int v9 = 0;
        do
        {
            if ((unsigned int)ReadPESectionEntry(&v19, v21))
                return 0;
            int v10 = v28 + v20;
            v20 += v28;
            int v11 = *(unsigned __int16 *)(v29 + 6);
            if (v11 == 1349)
                return 0;
            if (v18 >= 4 || v7 || v11 != 1069)
            {
                // continue to next checks
            }
            else
            {
                if (v23 == 0x40000 && v22 && v27 == 0x1000000000LL && !v25)
                {
                    unsigned int result = v10 + v22 - a1;
                    if (result && result < a2)
                    {
                        v8 = v10 + v22 - a1;
                        v11 = 1139;
                        v16 = 1;
                    }
                }
            }
            if (v11 == 1298 && v27 == 0x40000 && v26 && v23 == 64)
            {
                if (v24 == 1)
                {
                    v8 = v10 + v26 - a1;
                    if (v8 >= a2)
                        v8 = 0;
                }
                else if (v24 == 2)
                {
                    unsigned int result = v10 + v26 - a1;
                    v9 = result < a2 ? result : 0;
                }
            }
            if (v17 == 1 && v11 == 1298)
            {
                if (v27 == 0x40000 && v26 && v23 == 64)
                {
                    unsigned int v13 = v10 + v26 - a1;
                    if (v13 && v13 < a2)
                    {
                        if (v16 != 1 && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x2580)
                        {
                            int v14 = 2056;
                            if (!GtRead((enum _GLOBAL_TABLE_INDEX)2056))
                                GtWrite((enum _GLOBAL_TABLE_INDEX)v14, v6 + v13);
                            else if (!GtRead(GtPathBuffer03 | 0x800))
                                GtWrite(GtPathBuffer03 | 0x800, v6 + v13);
                            else if (!GtRead(GtSymlinkBuffer | 0x800))
                                GtWrite(GtSymlinkBuffer | 0x800, v6 + v13);
                        }
                        else
                        {
                            if (!GtRead(GtPathBuffer03 | 0x800))
                                GtWrite(GtPathBuffer03 | 0x800, v6 + v13);
                            else if (!GtRead((enum _GLOBAL_TABLE_INDEX)2056))
                                GtWrite((enum _GLOBAL_TABLE_INDEX)2056, v6 + v13);
                            else if (!GtRead(GtSymlinkBuffer | 0x800))
                                GtWrite(GtSymlinkBuffer | 0x800, v6 + v13);
                        }
                    }
                }
                v7 = 1;
                goto LABEL_42;
            }
            v7 = v17;
            if ((unsigned int)(v11 - 1139) <= 1)
            {
                if (v17)
                {
                    if (v8 && v9)
                    {
                        GtWrite(GtEprocessOffsetBase | 0x800, v6 + v8);
                        return GtWrite(GtEprocessField01 | 0x800, v6 + v9);
                    }
                }
                else if (v8)
                {
                    GtWrite(GtPathBuffer02 | 0x800, v6 + v8);
                }
                v7 = v17 + 1;
                v8 = 0;
                v9 = 0;
                ++v17;
            }
LABEL_42:
            ++v18;
        } while (v18 < 0x50);
    }
    return 0;
}

// ReadNtoskrnlFileToBuffer — 读取 ntoskrnl 文件到缓冲区
// 对应原始驱动 sub_1400317D0
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
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, &MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, pBufferSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ReadNtoskrnlFileToBuffer3 — 读取 ntoskrnl 文件到缓冲区 3
// 对应原始驱动 sub_140032E40
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
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, &MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)pBuffer, pBufferSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ReadNtFileForSsdtTargets2 — 读取 ntoskrnl 文件用于 SSDT 目标 2
// 对应原始驱动 sub_1400339BC
char ReadNtFileForSsdtTargets2(void **pFileBuffer, unsigned int *pFileSize)
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
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &pRawData, &RawDataSize, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)RawDataSize, (PUCHAR *)pFileBuffer, pFileSize) == 1;
        ExFree(pRawData);
    }
    return Result;
}

// ParseNtHeaders — 解析 NT 文件头类型
// 对应原始驱动 sub_140004F80
char ParseNtHeaders(unsigned __int16 *a1, unsigned int SectionNameLength)
{
    char Result = 0;
    if (SectionNameLength >= 0x18)
    {
        int SectionName = 7602286;
        int v6 = 7471211;
        int v7 = 7077998;
        int v8 = 7340141;
        int v9 = 6619182;
        __int64 v10 = 6619256;
        if (!(unsigned int)StringCompare3Way((__int64)&SectionName, a1, 0xCu))
            return 1;
        SectionName = 7602286;
        v6 = 7536751;
        v7 = 7471211;
        v8 = 7077998;
        v9 = 6619182;
        v10 = 6619256;
        if (!(unsigned int)StringCompare3Way((__int64)&SectionName, a1, 0xCu))
            return 1;
        SectionName = 7602286;
        v6 = 7471211;
        v7 = 7077998;
        v8 = 6357104;
        v9 = 6619182;
        v10 = 6619256;
        if ((unsigned int)StringCompare3Way((__int64)&SectionName, a1, 0xCu))
        {
            SectionName = 7602286;
            v6 = 7471211;
            v7 = 6357104;
            v8 = 7340141;
            v9 = 6619182;
            v10 = 6619256;
            return (unsigned int)StringCompare3Way((__int64)&SectionName, a1, 0xCu) == 0;
        }
        else
        {
            return 1;
        }
    }
    return Result;
}

// ParseNtKernelDataSections — 解析 NT 内核数据节区
// 对应原始驱动 sub_140062884
__int16 ParseNtKernelDataSections(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int v4 = GtRead(GtEprocessExtField20);
    if (!v4)
    {
        FindNdisIMInitializeDeviceInstanceEx(ImageBase, ImageSize);
        v4 = GtRead(GtEprocessExtField20);
    }
    __int64 v5 = GtRead(GtEprocessExtField11);
    __int64 v6 = v5;
    if (v5 && v4 && v4 < ImageSize)
    {
        __int64 v18 = 0, v19 = 0;
        _DWORD v20[8];
        char v21 = 0;
        int v22 = 0;
        __int64 v23 = 0;
        int v24 = 0;
        int v25 = 0;
        __int64 v26 = 0;
        unsigned int v27 = 0;
        __int64 v28 = 0;
        int v9 = 0;

        InitPESectionReadContext(ImageBase + v4, ImageSize - v4, 2, 0, -1, 0, 0, (__int64)&v18);
        char v7 = 0;
        unsigned int v8 = 0;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        {
            // Win10 19041+ 路径：找类型 1296+1368 组合
            while (v8 < 0x64)
            {
                if ((unsigned int)ReadPESectionEntry(&v18, v20))
                    break;
                v9 = v27 + v19;
                v19 += v27;
                __int16 v15 = *(_WORD *)(v28 + 6);
                if (v15 == 1296 && v23 == 64 && (v21 & 8) != 0 && v26 == 0x20000 && v25 == 392)
                {
                    v7 = 1;
                }
                else if (v7 == 1 && v15 == 1368)
                {
                    goto LABEL_SCAN;
                }
                ++v8;
            }
        }
        else
        {
            // 旧版路径：找 bound import(1139/1140)+1368 组合
            while (v8 < 0x64)
            {
                if ((unsigned int)ReadPESectionEntry(&v18, v20))
                    break;
                v9 = v27 + v19;
                v19 += v27;
                __int16 v10 = *(_WORD *)(v28 + 6);
                if ((unsigned __int16)(v10 - 1139) <= 1u)
                {
                    v7 = 1;
                }
                else if (v7 == 1 && v10 == 1368)
                {
                    goto LABEL_SCAN;
                }
                ++v8;
            }
        }
        return 0;

    char v11 = 0;
    unsigned int v12 = 0;

LABEL_SCAN:
    v12 = 0;
        v5 = v9 + v22 - ImageBase;
        if ((_DWORD)v5 && (unsigned int)v5 < ImageSize)
        {
            InitPESectionReadContext(ImageBase + (unsigned int)v5, ImageSize - (unsigned int)v5, 2, 0, -1, 0, 0, (__int64)&v18);
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry(&v18, v20))
                    break;
                int v13 = v27 + v19;
                v19 += v27;
                __int16 v14 = *(_WORD *)(v28 + 6);
                if (v14 == 1298)
                {
                    // 数据节区：检查是否为目标
                    if (v26 == 0x40000 && v25 && v23 == 64 && v24 == 1)
                    {
                        if (!(unsigned int)ReadPESectionEntry(&v18, v20))
                        {
                            if ((unsigned __int16)(*(_WORD *)(v28 + 6) - 1139) <= 1u)
                            {
                                v11 = 1;
                                v19 += v27;
                            }
                        }
                    }
                }
                else if (v11 == 1)
                {
                    // 已标记，检查后续代码节区
                    if (v14 == 1296 && v26 == 0x40000 && v25 && v23 == 64)
                    {
                        v5 = v13 + v25 - ImageBase;
                        if ((_DWORD)v5 && (unsigned int)v5 < ImageSize)
                        {
                            GtWrite(GtEprocessExtField22, v6 + (unsigned int)v5);
                            return v5;
                        }
                    }
                }
                if (++v12 >= 0xC8)
                    break;
            }
        }
    }
    return v5;
}

// ===================================================================
// 复杂 PE 节区扫描函数
// ===================================================================

// ParseNtHeadersForSsdtTargets — 解析 NT 头查找 SSDT 目标
// 对应原始驱动 sub_1400311E4
char ParseNtHeadersForSsdtTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 OutputTable = pOutputTable;
    char Result = 0;
    __int64 NtoskrnlBase = GtRead(GtCallbackField47);
    if (NtoskrnlBase)
    {
        unsigned int OptHeaderSize = *(unsigned int *)(*(int *)(ImageBase + 60) + ImageBase + 40);
        if (OptHeaderSize < ImageSize && (int)OptHeaderSize + 4096 < ImageSize)
        {
            char FoundInitSection = 0;
            __int64 v22 = 0, v23 = 0;
            _DWORD v24[8];
            char v25 = 0;
            int v26 = 0;
            __int64 v27 = 0;
            int v28 = 0, v29 = 0;
            __int64 v30 = 0;
            unsigned int v31 = 0;
            __int64 v32 = 0;

            InitPESectionReadContext(ImageBase + OptHeaderSize, 4096, 2, 0, -1, 0, 0, (__int64)&v22);
            unsigned int SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry(&v22, v24))
            {
                unsigned int SectionEnd = v31 + v23;
                v23 += v31;
                __int16 SectionType = *(_WORD *)(v32 + 6);
                if (SectionType == 1369)
                {
                    unsigned int TargetRva = SectionEnd + v26 - ImageBase;
                    if (TargetRva && TargetRva < ImageSize)
                    {
                        OptHeaderSize = TargetRva;
                        break;
                    }
                }
                else if (SectionType == 1296 && v27 == 64 && v28 == 1)
                {
                    FoundInitSection = 1;
                }
                else if (SectionType == 1368)
                {
                    if (FoundInitSection == 1)
                    {
                        unsigned int TargetRva = SectionEnd + v26 - ImageBase;
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
        if (OptHeaderSize && OptHeaderSize < ImageSize && (int)OptHeaderSize + 4096 < ImageSize)
        {
            __int64 v22b = 0, v23b = 0;
            _DWORD v24b[8];
            char v25b = 0;
            int v26b = 0;
            __int64 v27b = 0;
            int v28b = 0, v29b = 0;
            __int64 v30b = 0;
            unsigned int v31b = 0;
            __int64 v32b = 0;

            InitPESectionReadContext(ImageBase + OptHeaderSize, 4096, 2, 0, -1, 0, 0, (__int64)&v22b);
            unsigned int TargetRva2 = 0;
            unsigned int ScanIndex = 0;
            while (!(unsigned int)ReadPESectionEntry(&v22b, v24b))
            {
                unsigned int SectionEnd2 = v31b + v23b;
                v23b += v31b;
                __int16 SectionType2 = *(_WORD *)(v32b + 6);
                if (SectionType2 == 1298 && v30b == 0x40000 && v29b && v27b == 64 && !v28b)
                    TargetRva2 = SectionEnd2 + v29b - ImageBase;
                if (SectionType2 == 1327 && (v25b & 0x10) != 0 && TargetRva2)
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

// ParseNtHeadersForSsdtTargets2 — 解析 NT 头查找 SSDT 目标 2
// 对应原始驱动 sub_1400332C4
char ParseNtHeadersForSsdtTargets2(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    char Result = 0;
    char FoundFlag = 0;
    __int64 SectionBase = GtRead(GtFsFilterExportTable);
    if (SectionBase)
    {
        char ExportName[16];
        strcpy(ExportName, "ClassInitialize");
        unsigned int ExportRva = (unsigned int)FindExportByNameInPeBody(ImageBase, ImageSize, (__int64)ExportName, 0);
        if (ExportRva && ExportRva < ImageSize && ExportRva + 4096 < ImageSize)
        {
            __int64 PESectionContext = 0, ContextOffset = 0;
            _DWORD SectionEntry[72];
            int EntryOffset = 0, EntrySize = 0, EntryIndex = 0, TypeField1 = 0, TypeField2 = 0, RvaField = 0;
            __int64 Flags = 0;
            int IndexField = 0, ExtraFlags = 0;
            unsigned int EntrySize2 = 0;
            __int64 TypePtr = 0;
            _DWORD Dst[16];

            InitPESectionReadContext(ImageBase + ExportRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
            memset(Dst, 0, sizeof(Dst));
            char SectionReady = 0;
            unsigned int LoopCount = 0;
            unsigned int FieldOffset = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 904 : 912;
            do
            {
                if ((unsigned int)ReadPESectionEntry(&PESectionContext, SectionEntry))
                    return Result;
                int CurrentRva = EntrySize2 + ContextOffset;
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

// ParseAtaPortInitForHookTargets — 解析 AtaPort 初始化查找 Hook 目标
// 对应原始驱动 sub_1400326CC
char ParseAtaPortInitForHookTargets(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 v23 = GtRead(GtCallbackField42);
    if (!v23)
        return 0;

    WORD FuncName[16];
    strcpy((char *)FuncName, "AtaPortInitialize");
    FuncName[9] = 0;

    __int64 AtaPortBase = FindExportByNameInPeBody(ImageBase, ImageSize, (char *)FuncName, 0);
    if (!AtaPortBase)
        return 0;

    // 第一遍扫描：在 AtaPortInitialize 函数体内查找 bound import 和 1368 节区模式
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0
        && (unsigned int)AtaPortBase < ImageSize
        && (int)AtaPortBase + 4096 < ImageSize)
    {
        __int64 Context[8];
        _DWORD Entry[16];
        char FoundBoundImport = 0;
        char FoundPush = 0;
        int CallCount = 0;
        int ScanIndex = 0;

        InitPESectionReadContext(ImageBase + (unsigned int)AtaPortBase, 4096, 2, 0, -1, 0, 0, (__int64)Context);

        while (!(unsigned int)ReadPESectionEntry(Context, Entry))
        {
            unsigned int EntrySize = Entry[15];
            __int64 EntryBase = Context[1];
            int SectionEnd = EntrySize + EntryBase;
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
    if (!(_DWORD)AtaPortBase || (unsigned int)AtaPortBase >= ImageSize || (int)AtaPortBase + 4096 >= ImageSize)
        return 0;

    {
        __int64 Context[8];
        _DWORD Entry[16];
        _DWORD Dst[16];
        unsigned int LoopIndex = 0;
        char TableBuilt = 0;

        InitPESectionReadContext(ImageBase + (unsigned int)AtaPortBase, 4096, 2, 0, -1, 0, 0, (__int64)Context);
        memset(Dst, 0, sizeof(Dst));

        do
        {
            if ((unsigned int)ReadPESectionEntry(Context, Entry))
                break;

            unsigned int EntrySize = Entry[15];
            __int64 EntryBase = Context[1];
            int SectionEnd = EntrySize + EntryBase;
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
                    unsigned int TargetRva = SectionEnd + Entry[10] - ImageBase;
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
                        *(_QWORD *)(pOutputTable + 48 * TableSlot + 8) = v23 + RelocRva;
                    }
                }
            }
            ++LoopIndex;
        } while (LoopIndex < 0x1F4);

        return TableBuilt;
    }
}

// ===================================================================
// 无法反编译的函数（从汇编分析实现）
// ===================================================================

// QueryObjectTypeDirectoryPath — 查询对象类型目录路径
// 对应原始驱动 sub_140079654（Hex-Rays 无法反编译，从汇编分析）

// ScanProcessPESectionsV2 — 扫描进程 PE 节区 V2
// 对应原始驱动 sub_14007FB40（Hex-Rays 无法反编译，从汇编分析）
// 与 InitHookFunctionTable 结构类似，但使用不同的全局表索引
__int64 ScanProcessPESectionsV2(void)
{
    __int64 TargetProcess = GtRead(0x61);
    __int64 CurrentProcess = IoGetCurrentProcess();
    KAPC_STATE ApcState;

    if (TargetProcess != CurrentProcess && TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    __int64 SectionBase = GtRead(0x63);
    __int64 SectionSize = GtRead(0x20);
    __int64 NtoskrnlBase = GtRead(0x21);
    __int64 NtoskrnlSize = GtRead(3);

    if (SectionBase && SectionSize && (unsigned int)NtoskrnlBase && NtoskrnlSize)
    {
        __int64 Context[8];
        _DWORD SectionEntry[72];
        char FoundFlag = 0;
        __int64 EntryBase = 0;
        unsigned int EntrySize = 0;
        __int64 EntryTypePtr = 0;

        InitPESectionReadContext(SectionBase, (unsigned int)SectionSize, 2, 0, -1, 0, 0, (__int64)&Context);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            if (ReadPESectionEntry(&Context, SectionEntry))
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

// InitHookFunctionTable — 初始化 Hook 函数表
// 对应原始驱动 sub_14007F4B8（Hex-Rays 无法反编译，从汇编分析）
__int64 InitHookFunctionTable(void)
{
    // 从汇编分析：附加到目标进程，扫描 PE 节区
    // 查找类型 0x48E(1166) 节区，然后找类型 0x558(1368) 节区
    // 写入 GT[0x23F](575) = KiInsertQueueApc 函数地址
    __int64 TargetProcess = GtRead(GtEprocessField61);
    __int64 CurrentProcess = IoGetCurrentProcess();
    KAPC_STATE ApcState;

    if (TargetProcess != CurrentProcess && TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    __int64 SectionBase = GtRead(GtEprocessExtField11);
    __int64 SectionSize = GtRead(GtEprocessField21);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    __int64 NtoskrnlSize = GtRead(GtNtoskrnlImageSize);

    if (SectionBase && SectionSize && (unsigned int)NtoskrnlBase && NtoskrnlSize)
    {
        __int64 Context[8];
        _DWORD SectionEntry[72];
        char FoundFlag = 0;
        __int64 EntryBase = 0;
        unsigned int EntrySize = 0;
        __int64 EntryTypePtr = 0;

        InitPESectionReadContext(SectionBase, (unsigned int)SectionSize, 2, 0, -1, 0, 0, (__int64)&Context);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            if (ReadPESectionEntry(&Context, SectionEntry))
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

// ============================================================
// 以下函数从 SSDT.c 前向声明中引用，在文件末尾实现
// ============================================================

// RelocateExportAddresses — 重定位导出地址
// 对应原始驱动 sub_14002839C
// 分配内存（GtAlloc 0x790/0x390），复制导出表到分配的内存，遍历每个 QWORD 减去基址差量进行重定位修正
char __fastcall RelocateExportAddresses(void *Src, size_t MaxCount, int BaseDelta)
{
    __int64 CountCopy = (unsigned int)MaxCount;
    char Result = 0;
    unsigned int AllocSize = (unsigned int)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtPspExitNormalApcAddr | 0x800));
    if (AllocSize - (unsigned int)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField27)) >= (unsigned int)CountCopy)
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

// AdjustRelocationOffsets — 调整重定位偏移
// 对应原始驱动 sub_140060D70
// 将 Src 中的 24 字节每项的导出条目复制到 GT 912 缓冲区，将每个条目中的地址偏移减去 BaseDelta(基址修正值)
char __fastcall AdjustRelocationOffsets(void *Src, size_t MaxCount, int BaseDelta)
{
    __int64 CountCopy = (unsigned int)MaxCount;
    char Result = 0;
    unsigned int BufferSize = (unsigned int)GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtEprocessExtField58 | 0x400));
    if (BufferSize - (unsigned int)GtAlloc((enum _GLOBAL_TABLE_INDEX)GtEprocessExtField58) >= (unsigned int)CountCopy)
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

// FindHalInitSystemExport — 查找 HalInitSystem 导出
// 对应原始驱动 sub_1400287C4
// 通过名称查找 HAL.DLL 的 HalInitSystem 导出函数 RVA，写入全局表 0x86A 和 0x86B
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

// FindHalInitializeProcessorExport — 查找 HalInitializeProcessor 导出
// 对应原始驱动 sub_14002886C
// 通过名称查找 HAL.DLL 的 HalInitializeProcessor 导出函数 RVA，写入全局表 0x82F 和 0x830
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

// FindHalDataSectionOffset — 查找 HAL 数据节区偏移
// 对应原始驱动 sub_140028934
// 两阶段扫描：阶段 1 搜索子类型 1369 或 1368 的条目定位基址，阶段 2 搜索子类型 1298（类型 0x40000，标志 64）的条目，计算地址写入全局表 0x831
char __fastcall FindHalDataSectionOffset(__int64 ImageBase, unsigned int ImageSize, unsigned int SectionOffset, __int64 HalBase)
{
    char Result = 0;
    if (HalBase && SectionOffset && SectionOffset < ImageSize)
    {
        __int64 ReadContext[8];
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
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                return Result;
            int CurrentOffset = EntryCumulSize + (unsigned int)CumulativeSize;
            CumulativeSize += EntryCumulSize;
            if (*(WORD *)(EntryDataPtr + 6) == 1369)
            {
                if (EntrySize)
                {
                    Phase1Result = CurrentOffset + EntrySize - ImageBase;
                    break;
                }
            }
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3FAB && *(WORD *)(EntryDataPtr + 6) == 1368 && EntrySize)
            {
                Phase1Result = CumulativeSize + EntrySize - ImageBase;
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
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    return Result;
                int Phase2Current = EntryCumulSize + (unsigned int)CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(WORD *)(EntryDataPtr + 6) == 1298 && SectionFlags == 0x40000)
                {
                    if (EntrySize2 && EntryCumulSize == 64)
                    {
                        unsigned int Phase2Match = Phase2Current + EntrySize2 - ImageBase;
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

// FindHalExportTableLegacy — 查找 HAL 导出表（旧版）
// 对应原始驱动 sub_140028648
// 读取全局表索引 86 获取 HAL 基址，调用 FindHalInitSystemExport 定位，然后使用 DecodeUnicodeChar 解码 Unicode 标记流搜索标记 4280，匹配偏移值 1212238880，计算导出地址写入全局表 0x833
char __fastcall FindHalExportTableLegacy(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 HalExportAddr = GtRead(GtEprocessField76);
    if (HalExportAddr)
    {
        unsigned int SectionOffset = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField96 | 0x800));
        if (!SectionOffset)
        {
            FindHalInitSystemExport(ImageBase, ImageSize, HalExportAddr);
            SectionOffset = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField96 | 0x800));
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
                int v17 = *(int *)((char *)DecodeResult + 12);
                int v18 = *(int *)((char *)DecodeResult + 16);
                if (TokenValue == 4280 && v17 == 56 && v18 && v18 > (int)NtImageBase && (int)ImageSize > v18 - (int)NtImageBase)
                {
                    unsigned int FoundOffset = v18 - (int)NtImageBase;
                    if (v18 != (int)NtImageBase && FoundOffset < ImageSize)
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

// BuildHalExportTable — 构建 HAL 导出表
// 对应原始驱动 sub_140028434
// 根据版本选择 .rdata 或 .data 节区，在节区中扫描 Magic 值 0x484C4C42（"BLLH"）定位 HAL 导出表，调用 RelocateExportAddresses 重定位地址，写入全局表 0x833 和 0x834
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
                                unsigned int ExportOffset = (_DWORD)SectionPtr - (int)ImageBase - 8;
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
                                        unsigned int EntryCount = (_DWORD)EntryPtr - (_DWORD)ExportTablePtr;
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

// FindDllInitExport — 查找 DLL 初始化导出
// 对应原始驱动 sub_140067890
// 优先查找 "DllInitialize"，若失败则查找 "TdiInitialize"，将找到的偏移写入 GT 2052(0x804)，地址写入 GT 2053(0x805)
char __fastcall FindDllInitExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead((enum _GLOBAL_TABLE_INDEX)2050);
    if (v5)
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
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtPathBuffer01 | 0x800), v5 + (unsigned int)Value);
                return 1;
            }
        }
    }
    return Result;
}

// FindNdisMRegisterMiniportExport — 查找 NdisMRegisterMiniport 导出函数
// 对应原始驱动 sub_140061A78
// 通过名称查找 "NdisMRegisterMiniport" 导出函数，将偏移写入 GT 877，地址写入 GT 878
char __fastcall FindNdisMRegisterMiniportExport(__int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    __int64 Value = 0;
    __int64 v5 = GtRead(GtEprocessExtField11);
    if (v5)
    {
        WORD FuncName[12];
        strcpy((char *)FuncName, "NdisMRegisterMiniport");
        FuncName[11] = 0;
        if (LookupExportByName((PUCHAR)ImageBase, ImageSize, (PCHAR)FuncName, (PULONG)&Value) == 1
            && (_DWORD)Value && (unsigned int)Value < ImageSize)
        {
            GtWrite(GtEprocessExtField23, (unsigned int)Value);
            GtWrite(GtEprocessExtField24, v5 + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// ParseNdisMiniportDriverName — 解析 NDIS 微型端口驱动名称
// 对应原始驱动 sub_140061C54
// 在 ndis.sys 镜像中逐字节解码 Unicode 字符，找到匹配的驱动名称模式，将偏移写入 GT 879，地址写入 GT 880
char __fastcall ParseNdisMiniportDriverName(__int64 ImageBase, unsigned int ImageSize, unsigned int Offset)
{
    __int64 v5 = ImageSize;
    __int64 v7 = GtRead(GtEprocessExtField11);
    char Result = 0;
    if (v7 && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770 && Offset && Offset < ImageSize)
    {
        unsigned __int8 *ScanPos = (unsigned __int8 *)(ImageBase + Offset);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            _WORD DecodeResult[24];
            if (!DecodeUnicodeChar(ScanPos, ImageBase + v5, DecodeResult))
                break;
            ScanPos += *(unsigned int *)((char *)DecodeResult + 24);
            if (*(int *)(*(__int64 *)((char *)DecodeResult + 40)) == 4275)
                break;
            if (*(int *)(*(__int64 *)((char *)DecodeResult + 40)) == 4301)
            {
                unsigned int v10 = *(int *)((char *)DecodeResult + 12) + (unsigned int)(ScanPos - (unsigned __int8 *)ImageBase);
                if (v10 && v10 < ImageSize)
                {
                    GtWrite(GtEprocessExtField25, v10);
                    GtWrite(GtEprocessExtField26, v10 + v7);
                    return 1;
                }
                return Result;
            }
        }
    }
    return Result;
}

// ParseNdisGetVersionSection — 解析 NDIS 获取版本节区
// 对应原始驱动 sub_140062170
// 在 ndis.sys 的 NdisGetVersion 函数附近遍历 PE 节区，查找类型为 1340-1347 且特征匹配的节区，将其版本值写入 GT 867
char __fastcall ParseNdisGetVersionSection(unsigned int Rva, __int64 ImageBase, unsigned int ImageSize)
{
    char Result = 0;
    if (Rva && Rva < ImageSize)
    {
        __int64 ReadContext[8];
        _DWORD SectionEntry[72];
        __int64 CumulativeSize = 0;
        unsigned int Value = 0;
        int Value_4 = 0;
        unsigned int EntryCumulSize = 0;
        __int64 EntryDataPtr = 0;

        InitPESectionReadContext(ImageBase + Rva, ImageSize - Rva, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int i = 0; i < 0x64; i++)
        {
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// ReadNtFileForHookTable — 读取 ntoskrnl 文件用于 Hook 表构建
// 对应原始驱动 sub_1400294B8
// 使用编码的 DWORD 数组（加密路径）调用 ReadFileRawData 解码并读取 ntoskrnl.exe 文件内容，然后调用 ReadNtFileToBuffer 解析为 PE 缓冲区
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
// Hook 系统调用基础设施函数
// ============================================================

// BuildHookTable — 构建 Hook 表
// 对应原始驱动 sub_140003B3C
// 遍历系统调用哈希表，通过导出索引表查找每个哈希对应的函数地址，写入全局表
void BuildHookTable(void)
{
    __int64 ImageBase = 0;
    __int64 ExportDirVa = 0;
    unsigned int ExportDirSize = 0;
    unsigned int ExportCount = 0;
    void *ExportRva;

    ImageBase = GtRead(GtNtoskrnlModuleBase);
    ExportDirVa = GtRead(GtEprocessField22);
    ExportDirSize = GtRead(GtEprocessField23);
    if (ImageBase && ExportDirVa && ExportDirSize)
    {
        ExportCount = GetExportDirSize(ExportDirVa, ExportDirSize);
        if (ExportCount)
        {
            ExportRva = ExAlloc(PagedPool, 12LL * ExportCount);
            if (ExportRva)
            {
                if ((unsigned int)BuildExportIndexTable(ExportDirVa, ExportDirSize, ExportRva, ExportCount, 0))
                {
                    for (enum _GLOBAL_TABLE_INDEX TableIndex = GtSyscallHashTable; (unsigned int)TableIndex < (GtTotalSize | GtEprocessField114 | 0x400); TableIndex = (enum _GLOBAL_TABLE_INDEX)((int)TableIndex + 3))
                    {
                        int FuncAddress = GtRead(TableIndex);
                        unsigned int ExportOffset = LookupExportFuncAddr((__int64)ExportRva, ExportCount, FuncAddress);
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

// InitHookSyscall — 初始化 Hook 系统调用
// 对应原始驱动 sub_14001C408
// 扫描 PE 节区，查找类型 1298(0x514) 且标志 0x40000 的条目，计算偏移并写入全局表
__int64 InitHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtInitHookSyscallPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x32; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1298 && FieldValue == 0x40000)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)a1;
                    if ((_DWORD)result && (unsigned int)result < a2)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite(GtInitHookSyscallOffset, (unsigned int)result);
                        return GtWrite(GtInitHookSyscallAddress, TargetOffset + a4);
                    }
                }
            }
        }
    }
    return result;
}

// 前向声明
__int64 FindHookTargetInExportWin7(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);
__int64 FindHookTargetInExportWin8(__int64 a1, unsigned int a2, __int64 a3, __int64 a4);

// InstallHookSyscall — 安装 Hook 系统调用
// 对应原始驱动 sub_14001C528
// 根据 Windows 构建号选择导出查找方式（Win7 或 Win8+）
__int64 InstallHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return FindHookTargetInExportWin8(a1, a2, a3, a4);
    else
        return FindHookTargetInExportWin7(a1, a2, a3, a4);
}

// FindHookTargetInExportWin7 — 在 Win7 导出中查找 Hook 目标
// 对应原始驱动 sub_14001C58C
// 扫描 PE 节区，匹配子类型 1072 或 1298 的条目，计算偏移写入全局表
__int64 FindHookTargetInExportWin7(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    char FoundMatch = 0;
    __int64 result;
    __int64 ReadContext = 0;
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
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                return result;
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
                return result;
            if (SubType == 1072 && (FieldValue2 & 0x1000000000LL) != 0 && !ExtraField)
            {
                if ((FieldValue & 0x10000) != 0 && (unsigned int)Value < a2 && (FieldValue & 0x40) != 0 && (FieldValue & 2) != 0 && (FieldValue & 4) == 0)
                {
                    if (FoundMatch)
                    {
                        return GtWrite(GtEprocessField69, a4 + (unsigned int)Value);
                    }
                    unsigned int TargetOffset = (unsigned int)Value;
                    GtWrite(GtFindHookTargetFirstMatchOffset2, (unsigned int)Value);
                    result = GtWrite(GtFindHookTargetFirstMatchAddr2, TargetOffset + a4);
                    FoundMatch = 1;
                }
            }
            else if (SubType == 1298 && (FieldValue & 0x40) != 0 && (FieldValue2 & 0x40) != 0 && (FieldValue2 & 0x10000) != 0 && FoundMatch == 1)
            {
                if (CumulativeFlags && CumulativeFlags < a2)
                {
                    return GtWrite(GtEprocessField69, a4 + CumulativeFlags);
                }
            }
        }
    }
    return result;
}

// FindHookTargetInExportWin8 — 在 Win8+ 导出中查找 Hook 目标
// 对应原始驱动 sub_14001C72C
// 扫描 PE 节区，匹配子类型 1072/1243 的条目，计算偏移写入全局表
__int64 FindHookTargetInExportWin8(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 FieldValue = 0;
    __int64 ExtraField = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtFindHookTargetPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        unsigned int CountField = 0;
        __int64 FirstMatchOffset = 0;
        for (unsigned int LoopIndex = 0; LoopIndex < 0x100; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
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
                unsigned int MatchOffset = CumulativeSize + SectionEntry[16] - a1;
                if (MatchOffset > 0x20 && MatchOffset < a2)
                {
                    if ((_DWORD)FirstMatchOffset && CountField < 0xA)
                    {
                        GtWrite(GtFindHookTargetFirstMatchOffset2, (unsigned int)FirstMatchOffset);
                        GtWrite(GtFindHookTargetFirstMatchAddr2, FirstMatchOffset + a4);
                        return GtWrite(GtEprocessField69, a4 + MatchOffset - 32);
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

// EnableHookProtection — 启用 Hook 保护
// 对应原始驱动 sub_14001C9FC
// 根据 Windows 构建号选择数据节区查找方式
__int64 EnableHookProtection(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;

    result = GtRead(GtWindowsBuildNumber);
    if ((unsigned int)result >= 0x1DB0)
        return FindHookTargetDataSection(a1, a2, a3, a4);
    return result;
}

// DisableHookProtection — 禁用 Hook 保护
// 对应原始驱动 sub_14001CC4C
// 两阶段扫描：先查找子类型 1368 定位偏移，再扫描子类型 1296/1239 计算目标地址
__int64 DisableHookProtection(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtDisableHookProtectionPeOffset);
    SectionOffset = (unsigned int)result;
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368)
            {
                if (EntryFlags)
                {
                    result = EntryFlags - (unsigned int)a1;
                    SectionOffset = MatchSize + (unsigned int)result;
                    break;
                }
            }
        }
        if (SectionOffset && SectionOffset < a2)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(a1 + SectionOffset, a2 - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            int MatchCount = 0;
            for (unsigned int i = 0; i < 0x64; ++i)
            {
                result = ReadPESectionEntry(&ReadContext, SectionEntry);
                if ((_DWORD)result)
                    break;
                int MatchSize2 = SectionSize + CumulativeSize;
                CumulativeSize += SectionSize;
                __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
                if (SubType != 1296 && SubType != 1239)
                    continue;
                if (FieldValue == 0x40000 && FieldFlags)
                {
                    result = MatchSize2 + FieldFlags - (unsigned int)a1;
                    if ((_DWORD)result && (unsigned int)result < a2)
                    {
                        ++MatchCount;
                        __int64 ResultAddress = a4 + (unsigned int)result;
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

// FindNtOpenThreadTargetWin7 — 查找 NtOpenThread Hook 目标（Win7）
// 对应原始驱动 sub_14001D1EC
// 扫描 PE 节区，查找子类型 1368 条目，计算偏移返回
__int64 FindNtOpenThreadTargetWin7(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 SectionDataPtr = 0;

    Result = 0;
    SectionOffset = GtRead(GtTotalSize | GtEprocessField79 | 0x100);
    if (SectionOffset && SectionOffset < a2)
    {
        SectionBase = a1 + SectionOffset;
        GtWrite(GtEprocessField28, 0);
        InitPESectionReadContext(SectionBase, a2 + a1 - SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x46; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                return Result;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368 && LoopIndex > 6)
            {
                unsigned int TargetOffset = CumulativeSize + *(_DWORD *)(CumulativeSize - 4) - a1;
                if (TargetOffset < a5)
                    return a4 + TargetOffset;
                return Result;
            }
            CumulativeSize += SectionEntry[60];
        }
    }
    return Result;
}

// FindNtOpenThreadTargetWin8 — 查找 NtOpenThread Hook 目标（Win8+）
// 对应原始驱动 sub_14001D300
// 两阶段扫描：先查找子类型 1368 条目定位偏移，再扫描子类型 1296 计算目标地址
__int64 FindNtOpenThreadTargetWin8(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5)
{
    __int64 Result = 0;
    unsigned int SectionOffset = 0;
    __int64 SectionBase = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    int EntrySize = 0;
    __int64 FieldValue = 0;
    int FieldSize = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    Result = 0;
    SectionOffset = GtRead(GtTotalSize | GtEprocessField79 | 0x100);
    if (SectionOffset && SectionOffset < a2)
    {
        SectionBase = a1 + SectionOffset;
        GtWrite(GtEprocessField28, 0);
        InitPESectionReadContext(SectionBase, a1 + a2 - SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x46; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                return Result;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368 && (FieldValue & 0x4000000) != 0)
            {
                if (EntrySize)
                {
                    unsigned int TargetOffset = MatchSize + EntrySize - a1;
                    if (TargetOffset && TargetOffset < a2)
                    {
                        CumulativeSize = 0;
                        InitPESectionReadContext(a1 + TargetOffset, a2 - TargetOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
                        for (int LoopIndex2 = 0; LoopIndex2 < 0x46; ++LoopIndex2)
                        {
                            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                                return Result;
                            int MatchSize2 = SectionSize + CumulativeSize;
                            CumulativeSize += SectionSize;
                            if (*(_WORD *)(SectionDataPtr + 6) == 1296 && (FieldValue2 & 0x40000) != 0)
                            {
                                unsigned int TargetOffset2 = MatchSize2 + FieldSize - a1;
                                if (TargetOffset2 && TargetOffset2 < a5)
                                    return a4 + TargetOffset2;
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

// UninstallHookSyscall — 卸载 Hook 系统调用
// 对应原始驱动 sub_14001C8D0
// 扫描 PE 节区，查找子类型 1368 计算偏移，遇到子类型 1349 时写入全局表
__int64 UninstallHookSyscall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 TargetOffset = 0;
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    TargetOffset = 0;
    result = GtRead(GtUninstallHookSyscallPeOffset);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
            {
                if ((_DWORD)TargetOffset && (unsigned int)TargetOffset < a2)
                {
                    GtWrite(GtKernelDataField36, TargetOffset);
                    return GtWrite(GtKernelDataField37, TargetOffset + a4);
                }
                return result;
            }
            if (SubType == 1368 && (FieldValue & 0x4000000) != 0)
            {
                if (EntryFlags)
                    TargetOffset = MatchSize + EntryFlags - (unsigned int)a1;
            }
        }
    }
    return result;
}

// BuildJmpPatchStub — 构建跳转修补桩
// 对应原始驱动 sub_14008280C
// 检查目标代码是否为 jmp qword ptr [rdi] 模式，构建跳转桩
char BuildJmpPatchStub(int a1, __int64 a2, __int64 a3, unsigned int a4, int a5)
{
    if (a4 >= 0xD && *(_BYTE *)a2 == 72 && *(_BYTE *)(a2 + 1) == 0xFF && *(_BYTE *)(a2 + 2) == 0x37 && *(_BYTE *)(a2 + 7) == 0xCC && *(_BYTE *)(a2 + 8) == 0xCC)
    {
        int v8 = *(_DWORD *)(a2 + 3);
        *(_WORD *)a3 = 0x8BFF; // -29876
        *(_BYTE *)(a3 + 2) = 21;
        *(_BYTE *)(a3 + 7) = 0xE9; // -23
        *(_DWORD *)(a3 + 3) = v8;
        __int64 v9 = GtRead(GtDisableHookProtectionAddr1 | 0x100);
        if (v9 && a5)
            *(_DWORD *)(a3 + 8) = a5 + (int)v9 - a1 - 12;
        else
            *(_DWORD *)(a3 + 8) = 0;
        *(_BYTE *)(a3 + 12) = 0xCC;
        return 1;
    }
    return 0;
}

// InstallSsdtHookForThreadProtect — 安装 SSDT Hook 用于线程保护
// 对应原始驱动 sub_140035730
// 解码驱动名称，打开设备，根据输入条目类型写入 SSDT 表项
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

// ============================================================
// HookSyscallNt* 系列函数 — 系统调用 Hook 入口
// ============================================================

// HookSyscallNtCreateProcess — Hook NtCreateProcess 系统调用
// 对应原始驱动 sub_14001CE20
// 扫描 PE 节区，查找类型 1296(0x510) 且标志 0x40000 的条目，计算目标地址写入全局表
__int64 HookSyscallNtCreateProcess(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtNtCreateProcessPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1296 && FieldValue == 0x40000)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)a1;
                    if ((_DWORD)result && (unsigned int)result < a2)
                        return GtWrite(GtNtCreateProcessResultAddr, a4 + (unsigned int)result);
                }
            }
        }
    }
    return result;
}

// HookSyscallNtCreateThread — Hook NtCreateThread 系统调用
// 对应原始驱动 sub_14001CF34
// 扫描 PE 节区，匹配子类型 1245 的条目，计算目标地址写入全局表
__int64 HookSyscallNtCreateThread(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 FieldValue = 0;
    int EntryFlags = 0;
    int SectionSize = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize2 = 0;
    __int64 SectionDataPtr = 0;

    SectionOffset = GtRead(GtNtCreateThreadPeSectionOffset);
    if (SectionOffset && SectionOffset < a2)
    {
        InitPESectionReadContext(a1 + SectionOffset, a2 - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                break;
            int MatchSize = SectionSize2 + CumulativeSize;
            CumulativeSize += SectionSize2;
            if (*(_WORD *)(SectionDataPtr + 6) == 1245 && FieldValue == 64 && EntryFlags == 1 && FieldValue2 == 0x40000)
            {
                if (SectionSize)
                {
                    unsigned int TargetOffset = MatchSize + SectionSize - a1;
                    if (TargetOffset && TargetOffset < a2)
                    {
                        __int64 ResultAddress = a4 + TargetOffset;
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

// HookSyscallNtOpenProcess — Hook NtOpenProcess 系统调用
// 对应原始驱动 sub_14001D074
// 扫描 PE 节区，查找子类型 1368 的条目，计算目标地址写入全局表
__int64 HookSyscallNtOpenProcess(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    unsigned int EntryFlags = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtNtDeleteKeyPeSectionOffset | GtEprocessField02);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if (*(_WORD *)(SectionDataPtr + 6) == 1368)
            {
                if (EntryFlags)
                {
                    result = MatchSize + EntryFlags - (unsigned int)a1;
                    if ((_DWORD)result && (unsigned int)result < a2)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite((enum _GLOBAL_TABLE_INDEX)2313, (unsigned int)result);
                        return GtWrite((enum _GLOBAL_TABLE_INDEX)2314, TargetOffset + a4);
                    }
                }
            }
        }
    }
    return result;
}

// HookSyscallNtOpenThread — Hook NtOpenThread 系统调用
// 对应原始驱动 sub_14001D188
// 根据 Windows 构建号选择查找方式（Win7 或 Win8+）
__int64 HookSyscallNtOpenThread(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        return FindNtOpenThreadTargetWin8(a1, a2, a3, a4, a5);
    else
        return FindNtOpenThreadTargetWin7(a1, a2, a3, a4, a5);
}

// HookSyscallNtOpenKey — Hook NtOpenKey 系统调用
// 对应原始驱动 sub_14001D4C0
// 扫描 PE 节区，匹配特定标志组合的条目，计算偏移写入全局表
__int64 HookSyscallNtOpenKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    unsigned int ResultValue = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    __int64 FieldValue = 0;
    __int64 FieldValue2 = 0;
    __int64 FieldValue3 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ResultValue = -1;
    SectionOffset = GtRead(GtNtOpenKeyPeSectionOffset);
    if (SectionOffset && SectionOffset < a2)
    {
        InitPESectionReadContext(a1 + SectionOffset, a2 - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            if ((FieldValue3 & 0x80000) != 0 && FieldValue2 == 16 && (FieldValue & 0x10000) != 0)
            {
                ResultValue = SectionEntry[16];
            }
            else if ((unsigned __int16)(*(_WORD *)(SectionDataPtr + 6) - 1368) <= 1u && (FieldValue & 0x4000000) != 0)
            {
                unsigned int TargetOffset = MatchSize + SectionEntry[14] - a1;
                if (TargetOffset && TargetOffset < a2)
                    GtWrite(GtPspTerminateThreadAddr, a4 + TargetOffset);
                return GtWrite(GtEprocessField94, ResultValue);
            }
        }
        return GtWrite(GtEprocessField94, ResultValue);
    }
    return GtWrite(GtEprocessField94, ResultValue);
}

// HookSyscallNtOpenKeyEx — Hook NtOpenKeyEx 系统调用
// 对应原始驱动 sub_14001D608
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果值
__int64 HookSyscallNtOpenKeyEx(__int64 a1, unsigned int a2)
{
    unsigned int ResultValue = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char FieldValue = 0;
    int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ResultValue = -1;
    SectionOffset = GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField59);
    if (SectionOffset && SectionOffset < a2)
    {
        InitPESectionReadContext(a1 + SectionOffset, a2 - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtCreateKey — Hook NtCreateKey 系统调用
// 对应原始驱动 sub_14001D708
// 扫描 PE 节区，匹配子类型 1296 的条目，计算偏移写入全局表
__int64 HookSyscallNtCreateKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 result;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char FieldValue = 0;
    int EntryFlags = 0;
    unsigned int FieldFlags = 0;
    __int64 FieldValue2 = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    result = GtRead(GtTotalSize | GtPathBuffer04 | 0x400);
    if ((_DWORD)result && (unsigned int)result < a2)
    {
        InitPESectionReadContext(a1 + (unsigned int)result, a2 - result, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (unsigned int LoopIndex = 0; LoopIndex < 0x14; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            int MatchSize = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            __int16 SubType = *(_WORD *)(SectionDataPtr + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296 && (FieldValue & 0x20) != 0 && !EntryFlags && (FieldValue2 & 0x40000) != 0)
            {
                if (FieldFlags)
                {
                    result = MatchSize + FieldFlags - (unsigned int)a1;
                    if ((_DWORD)result && (unsigned int)result < a2)
                    {
                        unsigned int TargetOffset = (unsigned int)result;
                        GtWrite(GtEprocessModuleListOffset | GtPsExitSpecialApcAddr, (unsigned int)result);
                        return GtWrite(GtEprocessModuleListOffset | GtExFreeCallBackAddr, TargetOffset + a4);
                    }
                }
            }
        }
    }
    return result;
}

// HookSyscallNtDeleteKey — Hook NtDeleteKey 系统调用
// 对应原始驱动 sub_14001D850
// 在 PE 节区中查找子类型 1166 标记后跟子类型 1298 的条目，计算目标地址
__int64 HookSyscallNtDeleteKey(unsigned __int64 a1, unsigned int a2, __int64 a3, __int64 a4)
{
    __int64 ImageSize = 0;
    char FoundFlag = 0;
    __int64 result;
    unsigned __int64 EndAddress;
    __int64 SectionBase = 0;
    int SectionEnd = 0;
    char ReadContext[8];
    __int64 CumulativeSize2 = 0;
    char SectionEntry[120];
    int EntrySize = 0;
    __int64 FieldValue = 0;
    unsigned int SectionSize = 0;
    __int64 SectionDataPtr = 0;

    ImageSize = a2;
    FoundFlag = 0;
    result = GtRead(GtNtDeleteKeyPeSectionOffset);
    if ((_DWORD)result && (unsigned int)result < (unsigned int)ImageSize)
    {
        EndAddress = a1 + ImageSize;
        SectionBase = a1 + (unsigned int)result;
        SectionEnd = (int)EndAddress;
        if (EndAddress > SectionBase + 4096)
            SectionEnd = SectionBase + 4096;
        InitPESectionReadContext(SectionBase, SectionEnd - SectionBase, 2, 0, -1, 0, 0, (__int64)ReadContext);
        while (1)
        {
            result = ReadPESectionEntry((__int64 *)ReadContext, SectionEntry);
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
                if (TargetAddress > a1 && TargetAddress < EndAddress)
                    return GtWrite(GtCallbackField120, TargetAddress + a4 - a1);
            }
        }
    }
    return result;
}

// HookSyscallNtDeleteValueKey — Hook NtDeleteValueKey 系统调用
// 对应原始驱动 sub_14001D984
// 根据构建版本选择不同的查找方式，写入结果值
__int64 HookSyscallNtDeleteValueKey(unsigned __int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5)
{
    __int64 Value[3];

    Value[0] = 0;
    Value[1] = 0;
    Value[2] = 0;
    if ((unsigned int)GtRead(GtEprocessField28) == 1)
    {
        FindDeleteValueKeyTarget(a1, a2, a3, a4, a5, Value);
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
    {
        ScanRegValueBodyForRef(a1, a2, a3, a4, a5, Value);
    }
    else
    {
        GetDeleteValueKeyCtx(Value);
    }
    return GtWrite(GtEprocessField60, Value[0]);
}

// HookSyscallNtSetValueKey — Hook NtSetValueKey 系统调用
// 对应原始驱动 sub_14001DCC0
// 根据构建版本选择不同的查找方式，写入结果值
__int64 HookSyscallNtSetValueKey(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, unsigned int a5)
{
    __int64 Value = 0;
    __int64 v11[2];

    Value = 0;
    v11[0] = 0;
    v11[1] = 0;
    if ((unsigned int)GtRead(GtEprocessField28) == 1)
    {
        FindSetValueKeyTargets(a1, a2, a3, a4, a5, &Value, v11);
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
    {
        FindSetValueKeyTarget(a1, a2, a3, a4, a5, &Value, v11);
    }
    else
    {
        GetSetValueKeyCtx(&Value, v11);
    }
    GtWrite(GtEprocessField58, Value);
    return GtWrite(GtEprocessField59, v11[0]);
}

// HookSyscallNtRenameKey — Hook NtRenameKey 系统调用
// 对应原始驱动 sub_14001DFBC
// 根据 Windows 构建号选择重命名键目标查找方式
__int16 HookSyscallNtRenameKey(__int64 TargetAddress, unsigned int Flags, __int64 Context, unsigned __int64 MaxOffset)
{
    unsigned int Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
    {
        Result = GtRead(GtWindowsBuildNumber);
        if (Result < 0x4563)
            return (__int16)FindNtRenameKeyTarget(TargetAddress, Flags, Context, MaxOffset);
    }
    else
    {
        return (__int16)FindRenameKeyTargetEx(TargetAddress, Flags, Context, MaxOffset);
    }
    return (__int16)Result;
}

// HookSyscallNtCreateFile — Hook NtCreateFile 系统调用
// 对应原始驱动 sub_14001E5BC
// 解析系统调用号到地址，根据构建版本选择重定位方式
__int64 HookSyscallNtCreateFile(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    __int64 Result = 0;
    Result = GtRead(GtNtCreateFileSyscallOffset);
    if ((_DWORD)Result)
    {
        Result = ResolveSyscallToAddress(Result);
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

// HookSyscallNtOpenFile — Hook NtOpenFile 系统调用
// 对应原始驱动 sub_14001E688
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtOpenFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField118 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtReadFile — Hook NtReadFile 系统调用
// 对应原始驱动 sub_14001E78C
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtReadFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField130 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtWriteFile — Hook NtWriteFile 系统调用
// 对应原始驱动 sub_14001E890
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtWriteFile(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    int MatchOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtNtWriteFilePeSectionOffset);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtClose — Hook NtClose 系统调用
// 对应原始驱动 sub_14001ED98
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtClose(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField124 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtDuplicateObject — Hook NtDuplicateObject 系统调用
// 对应原始驱动 sub_14001EE9C
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtDuplicateObject(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtNtDuplicateObjectPeSectionOffset);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtQuerySystemInfo — Hook NtQuerySystemInformation 系统调用
// 对应原始驱动 sub_14001FF5C
// 扫描 PE 节区，查找子类型 1294 标记后跟子类型 1296 的条目，计算目标地址
__int64 HookSyscallNtQuerySystemInfo(unsigned __int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    __int64 TargetSizeCopy = 0;
    char FoundMarker = 0;
    __int64 Result = 0;
    unsigned __int64 BufferEnd;
    __int64 ScanStart = 0;
    int ScanEnd = 0;
    char ReadContext[8];
    __int64 TotalCumulSize = 0;
    char SectionEntry[64];
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
        if (BufferEnd > ScanStart + 4096)
            ScanEnd = ScanStart + 4096;
        InitPESectionReadContext(ScanStart, ScanEnd - ScanStart, 2, 0, -1, 0, 0, (__int64)ReadContext);
        while (1)
        {
            Result = ReadPESectionEntry((__int64 *)ReadContext, SectionEntry);
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

// HookSyscallNtQueryInformationProcess — Hook NtQueryInformationProcess 系统调用
// 对应原始驱动 sub_1400200A4
// 扫描 PE 节区，匹配子类型 1296 的条目，写入结果偏移
__int64 HookSyscallNtQueryInformationProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType2 = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = GtRead(GtNtCreateThreadPeSectionOffset | GtEprocessField20);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtSetInformationProcess — Hook NtSetInformationProcess 系统调用
// 对应原始驱动 sub_1400201A4
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtSetInformationProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField112 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtQueryInformationThread — Hook NtQueryInformationThread 系统调用
// 对应原始驱动 sub_1400202A8
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtQueryInformationThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    char SectionFlags = 0;
    int EntryFlags = 0;
    unsigned int EntrySize = 0;
    __int64 SectionType = 0;
    unsigned int EntryCumulSize = 0;
    __int64 EntryDataPtr = 0;

    ResultOffset = -1;
    SectionOffset = GtRead(GtTotalSize | GtEprocessField82 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtSetInformationThread — Hook NtSetInformationThread 系统调用
// 对应原始驱动 sub_1400203AC
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtSetInformationThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField115 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtSuspendProcess — Hook NtSuspendProcess 系统调用
// 对应原始驱动 sub_1400204B0
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtSuspendProcess(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField109 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtResumeProcess — Hook NtResumeProcess 系统调用
// 对应原始驱动 sub_1400205B4
// 从 GtEprocessField32 取值并偏移计算，根据构建号调整
__int64 HookSyscallNtResumeProcess(void)
{
    int BaseOffset = 0;
    int ResultOffset = 0;

    BaseOffset = GtRead(GtEprocessField32);
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

// HookSyscallNtSuspendThread — Hook NtSuspendThread 系统调用
// 对应原始驱动 sub_1400205F8
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtSuspendThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField136 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtResumeThread — Hook NtResumeThread 系统调用
// 对应原始驱动 sub_1400206FC
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtResumeThread(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField139 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtOpenProcessToken — Hook NtOpenProcessToken 系统调用
// 对应原始驱动 sub_140020800
// 根据 Windows 构建号选择查找方式
__int64 HookSyscallNtOpenProcessToken(__int64 TargetAddress, unsigned int TargetSize)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4F7C)
        return FindOpenProcessTokenTarget(TargetAddress, TargetSize);
    else
        return FindOpenProcessTokenOffset(TargetAddress, TargetSize);
}

// HookSyscallNtOpenThreadToken — Hook NtOpenThreadToken 系统调用
// 对应原始驱动 sub_140020BC4
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtOpenThreadToken(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtTotalSize | GtEprocessField106 | 0x100);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtCreateToken — Hook NtCreateToken 系统调用
// 对应原始驱动 sub_140020CC8
// 扫描 PE 节区，匹配特定标志组合的条目，写入结果偏移
__int64 HookSyscallNtCreateToken(__int64 TargetBase, unsigned int TargetSize)
{
    unsigned int ResultOffset = 0;
    unsigned int SectionOffset = 0;
    __int64 ReadContext = 0;
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
    SectionOffset = GtRead(GtNtWriteFilePeSectionOffset | GtPathBuffer02);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
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

// HookSyscallNtLoadDriver — Hook NtLoadDriver 系统调用
// 对应原始驱动 sub_140020DCC
// 两阶段扫描定位偏移，根据构建版本判断是否执行
__int64 HookSyscallNtLoadDriver(__int64 TargetBase, signed int TargetSize, __int64 Context, __int64 RelocBase)
{
    __int64 ReadContext = 0;
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
        SectionOffset1 = GtRead(GtTotalSize | GtKernelDataField44 | GtPathBuffer00);
        SectionOffset2 = GtRead(GtTotalSize | GtEprocessExtField58 | GtPathBuffer02);
        if (SectionOffset1 && SectionOffset1 < TargetSize)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(TargetBase + SectionOffset1, TargetSize - SectionOffset1, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (int Phase1Index = 0; Phase1Index < 0xA; ++Phase1Index)
            {
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    break;
                int CurrentOffset1 = EntryCumulSize + CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1141 && (SectionFlags & 0x40000) != 0 && EntrySize < TargetSize)
                {
                    unsigned int MatchOffset1 = CurrentOffset1 + EntrySize - TargetBase;
                    if (MatchOffset1 && MatchOffset1 < TargetSize)
                    {
                        __int64 Phase1Result = MatchOffset1;
                        GtWrite(GtKernelDataField33, MatchOffset1);
                        GtWrite(GtKernelDataField34, Phase1Result + RelocBase);
                    }
                    break;
                }
            }
        }
        if (SectionOffset2 && SectionOffset2 < TargetSize)
        {
            CumulativeSize = 0;
            InitPESectionReadContext(TargetBase + SectionOffset2, TargetSize - SectionOffset2, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (int Phase2Index = 0; Phase2Index < 0xA; ++Phase2Index)
            {
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    break;
                int CurrentOffset2 = EntryCumulSize + CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1296 && (SectionFlags & 0x40) != 0 && (SectionType2 & 0x40000) != 0 && EntrySize2 < TargetSize)
                {
                    unsigned int MatchOffset2 = CurrentOffset2 + EntrySize2 - TargetBase;
                    if (MatchOffset2 && MatchOffset2 < TargetSize)
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
    unsigned int v3;
    v3 = MaxCount;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return ParseServiceTableWin8(Src, v3);
    return ParseServiceTableWin7(Src, v3);
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
    if (CheckValidFunc && pListHead && CheckValidFunc(pListHead))
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
    if (CheckValidFunc && pListHead && CheckValidFunc(pListHead))
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
    unsigned int v2 = 0x1000000;
    __int64 v3 = GtRead(GtEprocessField22);
    unsigned int v4 = GtRead(GtEprocessField23);
    unsigned int v5 = GtRead(TypeIndex);
    __int64 v8;
    __int64 v9;
    _DWORD v10[70];
    __int64 v11;
    int i;

    if (v3 && v4 && v5 && v5 < v4 && (unsigned __int64)v5 + 5 <= v4)
    {
        InitPESectionReadContext(v5 + v3, v4 - v5, 2, 0, -1, 0, 0, (__int64)&v8);
        for (i = 0; i < 0x10; i++)
        {
            if ((unsigned int)ReadPESectionEntry(&v8, v10))
                break;
            v9 += v10[60];
            if (*(_WORD *)(v11 + 6) == 1340 && (*(_QWORD *)&v10[34] & 0x800000LL) != 0 && !v10[29])
                return v10[28];
        }
    }
    return v2;
}

// VerifyServiceTableDriverFile — 验证服务表驱动文件：比较内存中的驱动镜像与磁盘文件 PE 头是否一致
char __fastcall VerifyServiceTableDriverFile(__int64 DiskBuffer, unsigned int DiskSize)
{
    __int64 KernelBase;
    unsigned int KernelSize;

    KernelBase = GtRead(GtKernelModuleBase);
    KernelSize = GtRead(GtEprocessField71);
    if (KernelBase && KernelSize && DiskBuffer && DiskSize && KernelSize > 0x1000)
    {
        if (ComparePeHeaders(KernelBase, KernelSize, DiskBuffer, DiskSize) == 1)
            return GtWrite(GtCallbackField53, 1);
    }
    return 0;
}

// ResolveKernelModuleFunctionAddrs — 解析内核模块函数地址
__int64 ResolveKernelModuleFunctionAddrs(void)
{
    __int64 v0;
    unsigned int v1;
    __int64 v2;
    unsigned int v4;
    unsigned int v5;

    v0 = GtRead(GtEprocessField22);
    v1 = GtRead(GtEprocessField23);
    v2 = GtRead(GtNtoskrnlModuleBase);
    v4 = GtRead(GtWin32kServiceEntryCount);
    if (v0 && v1 && v2 && v4)
    {
        v5 = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField189 | GtEprocessField06 | 0x100));
        if (v5 && v5 < v4)
        {
            v5 = ResolveSyscallToAddress(v5);
            if (v5 && v5 < v1)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField55), v2 + v5);
        }
        v5 = GtRead((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField06 | 0x100));
        if (v5 && v5 < v4)
        {
            v5 = ResolveSyscallToAddress(v5);
            if (v5 && v5 < v1)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField10 | 0x100), v2 + v5);
        }
        v5 = GtRead((enum _GLOBAL_TABLE_INDEX)(GtSubsystemConfigBase | GtEprocessField07 | 0x100));
        if (v5 && v5 < v4)
        {
            v5 = ResolveSyscallToAddress(v5);
            if (v5 && v5 < v1)
                GtWrite((enum _GLOBAL_TABLE_INDEX)(GtKiFastCallEntryAddr | GtEprocessField06), v2 + v5);
        }
        v5 = GtRead((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField54));
        if (v5 && v5 < v4)
        {
            v5 = ResolveSyscallToAddress(v5);
            if (v5 && v5 < v1)
                return GtWrite((enum _GLOBAL_TABLE_INDEX)(GtNtQuerySystemInformationFunc | GtEprocessField58), v2 + v5);
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
            TableIndex = GtRead(GtCallbackField55);
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
        TableEntryCount = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr1 | GtEprocessField150));
        SyscallTable = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField151));
        AllocIndex = (enum _GLOBAL_TABLE_INDEX)(GtEprocessField154 | 0x2100);
    }
    else
    {
        if (!(unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField152)))
            ParseSyscallTableExportDir();
        TableEntryCount = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField152));
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
    __int64 AllocFlag;
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
                ExportTableSize = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize | 0x100));
                ExportTableSizeCopy = ExportTableSize;
                if (ExportIndexTable && ExportTableSize)
                {
                    HashValue = Sha1HashToDword(AnsiBuffer);
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
    KernelSize = GtRead(GtEprocessField23);
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
                    *((_DWORD *)pCurrentEntry - 2) = RvaOffset;
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

    if (GtRead(GtDisableHookProtectionAddr1 | 0x100) && ReadRawFileToBuffer(&pFileBuffer, &FileSize))
    {
        ExportDirSize = GetExportDirSize((__int64)pFileBuffer, FileSize);
        if (ExportDirSize)
        {
            pIndexTable = ExAlloc(PagedPool, 12LL * ExportDirSize);
            if (pIndexTable)
            {
                TableEntryCount = BuildExportIndexTable((__int64)pFileBuffer, FileSize, pIndexTable, ExportDirSize, (unsigned __int8 (__fastcall *)(__int64))CheckStringPrefixNt);
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

    if (ReadNtOsKrnlFile(&Src, (unsigned int *)&MaxCount))
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
        Result = ReadNtFileToBuffer((int *)Src, (unsigned int)MaxCount, pBuffer, pSize) == 1;
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
        if (ReadNtFileToBuffer((int *)Src, (unsigned int)MaxCount, pBuffer, pSize) == 1)
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

    Result = GtRead(GtNtCreateThreadHookSuccess | GtEprocessField06);
    if (!Result)
    {
        NtoskrnlBase = GtRead(GtNtoskrnlFileBase);
        Result = GtRead(GtDisableHookProtectionAddr1 | GtEprocessField182 | GtEprocessField22);
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
            FindSsdtTableAddresses((__int64)pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
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
            ResolveSsdtTablePointerEx((__int64)pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
        else
            ResolveSsdtTablePointer((__int64)pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
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
            ResolveSsdtTablePointer((__int64)pScanPos, SectionEnd, &Value, &SsdtOffsetOut);
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
    __int64 ReadContext;
    __int64 CumulSize;
    _DWORD SectionEntry[20];
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
    InitPESectionReadContext(SectionBase, TargetSize + SectionOffset - SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    for (LoopIndex = 0; LoopIndex < 5; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
            break;
        CurrentOffset = EntryDataPtr + CumulSize;
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
    __int64 SectionContext;
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
        SectionContext = 0;
        InitPESectionReadContext(
            (PUCHAR)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (PUCHAR)&SectionContext);

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
                && CharOffset - (int)FuncAddress < NtImageSize)
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
    char v25[8];
    __int64 v26;
    _DWORD v27[8];
    int v28;
    int v29;
    int v30;
    __int64 v31;
    int v32;
    int v33;
    __int64 v34;
    unsigned int v35;
    __int64 v36;

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
            (PUCHAR)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (PUCHAR)v25);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)v25, v27))
        {
            ComputedOffset = v35 + (int)v26;
            v26 += v35;

            if ((unsigned __int16)(*(_WORD *)(v36 + 6) - 1368) <= 2u)
            {
                if (v29)
                {
                    SubSectionRva = (unsigned int)(ComputedOffset + v29 - (int)NtImageBase);
                    if (SubSectionRva && SubSectionRva < NtImageSize)
                    {
                        FieldIndex = 0;
                        FieldAddress = 0;
                        InitPESectionReadContext(
                            (PUCHAR)(NtImageBase + (unsigned int)(ComputedOffset + v29 - (int)NtImageBase)),
                            SectionEnd - (ComputedOffset + v29),
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (PUCHAR)v25);

                        FieldCount = 0;
                        while (!(unsigned int)ReadPESectionEntry((PUCHAR)v25, v27))
                        {
                            ComputedOffset2 = v35 + (int)v26;
                            v26 += v35;
                            SectionType2 = *(_WORD *)(v36 + 6);

                            if (SectionType2 == 1298 && v34 == 0x40000 && v33 && v31 == 64)
                            {
                                TableRva = (unsigned int)(ComputedOffset2 + v33 - (int)NtImageBase);
                                if ((_DWORD)TableRva && (unsigned int)TableRva < NtImageSize && !*pSsdtTable)
                                    *pSsdtTable = NtoskrnlImageBase + TableRva;
                            }
                            else if ((SectionType2 == 1065 && v31 == 0x40000 && (v28 & 4) != 0 && v34 == 0x400000000LL && v32 == -1)
                                  || (SectionType2 == 1201 && v31 == 0x40000 && (v28 & 4) != 0 && v34 == 32)
                                  || (SectionType2 == 1137 && v31 == 0x40000 && (v28 & 4) != 0))
                            {
                                OffsetRva = (unsigned int)(ComputedOffset2 + v30 - (int)NtImageBase);
                                if (OffsetRva && OffsetRva < NtImageSize)
                                {
                                    FieldIndex = FieldCount;
                                    FieldAddress = NtoskrnlImageBase + OffsetRva;
                                }
                            }
                            else if (SectionType2 == 1324
                                  && v32 == 2
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
    __int64 SectionReadContext;
    __int64 RootTableOffsetAccum;
    _DWORD SectionEntry[8];
    char FieldFlagsByte;
    int FieldValue;
    __int64 FieldFileOffset;
    int FieldCount;
    int FieldFlags;
    __int64 TableFieldFlags;
    unsigned int SectionEntrySize;
    __int64 v31;

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
            (PUCHAR)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (PUCHAR)&SectionReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry(&SectionReadContext, SectionEntry))
        {
            pSectionEntryBase = v31;
            SectionFileOffset = FieldFileOffset;
            ComputedOffset = SectionEntrySize + (int)RootTableOffsetAccum;
            RootTableOffsetAccum += SectionEntrySize;

            if (*(_WORD *)(v31 + 6) == 1298 && TableFieldFlags == 0x40000)
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
    __int64 SectionReadContext;
    __int64 RootOffsetAccum;
    _DWORD SectionEntry[8];
    char FieldFlagsByte;
    int SubSectionFieldCount;
    int OffsetFieldValue;
    __int64 FieldFileOffset;
    int OffsetFieldCount;
    int FieldFlags;
    __int64 TableFieldFlags;
    unsigned int SectionEntrySize;
    __int64 v35;

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
            (PUCHAR)pSectionData,
            SectionEnd - (int)pSectionData,
            2,
            0,
            -1,
            0,
            0,
            (PUCHAR)&SectionReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry(&SectionReadContext, SectionEntry))
        {
            ComputedOffset = SectionEntrySize + (int)RootOffsetAccum;
            RootOffsetAccum += SectionEntrySize;

            if ((unsigned __int16)(*(_WORD *)(v35 + 6) - 1368) <= 2u)
            {
                if (SubSectionFieldCount)
                {
                    SubSectionRva = (unsigned int)(ComputedOffset + SubSectionFieldCount - (int)NtImageBase);
                    if (SubSectionRva && SubSectionRva < NtImageSize)
                    {
                        InitPESectionReadContext(
                            (PUCHAR)(NtImageBase + (unsigned int)(ComputedOffset + SubSectionFieldCount - (int)NtImageBase)),
                            SectionEnd - (ComputedOffset + SubSectionFieldCount),
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (PUCHAR)&SectionReadContext);

                        FieldIndex = 0;
                        while (!(unsigned int)ReadPESectionEntry(&SectionReadContext, SectionEntry))
                        {
                            pSectionEntryBase = v35;
                            SectionFileOffset = FieldFileOffset;
                            ComputedOffset2 = SectionEntrySize + (int)RootOffsetAccum;
                            RootOffsetAccum += SectionEntrySize;

                            if (*(_WORD *)(v35 + 6) == 1298 && TableFieldFlags == 0x40000)
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
    if (LookupExportByName(PeBase, PeSize, (__int64)FuncNameBuffer, &ExportOffset) == 1 && ExportOffset)
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
            if (ParseNtExportDir((__int64)pBuffer, FileSize, KernelBase, 0) == 1)
            {
                unsigned int ExportIndex = GtRead(201 | GtEprocessField22);
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
    if (!PeBase || !PeSize || PeBase < (unsigned __int64)MmSystemRangeStart)
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

    InitPESectionReadContext((PUCHAR)TargetAddress + PeScanBaseOffset, TargetSize - PeScanBaseOffset, 3, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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

    InitPESectionReadContext((PUCHAR)TargetAddress + PeScanBaseOffset, TargetSize - PeScanBaseOffset, 3, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
                    InitPESectionReadContext((PUCHAR)TargetAddress + Offset, TargetSize - Offset, 3, (LONG64)&PeContext, -1, 0, 0, (PUCHAR)&EntryBuffer);
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
