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
    PE_DECODE_CONTEXT CumulativeSize;   // 0x48 字节解码上下文（原 __int64 仅 8 字节；名字错误另行改名）
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
        InitPESectionReadContext((__int64)Pattern, DataSize, 2, 0, -1, 0, 0, (__int64)&CumulativeSize);
        if (ReadPESectionEntry((unsigned char *)&CumulativeSize, SectionChar)) return Result;

        while (1)
        {
            int TargetRva2 = (int)(EntryCumulSize + (ULONG)SectionEntry);
            SectionEntry += EntryCumulSize;
            short SectionType = *(WORD *)(EntryDataPtr + 6);
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
            if (ReadPESectionEntry((unsigned char *)&CumulativeSize, SectionChar)) return Result;
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
        InitPESectionReadContext((__int64)&TargetData[(ULONG)SectionType2], 12, 2, 0, -1, 0, 0, (__int64)&CumulativeSize);
        if (!ReadPESectionEntry((unsigned char *)&CumulativeSize, SectionChar) && *(WORD *)(EntryDataPtr + 6) == 1296 && EntryCumulSize == 7 &&
            EntryField == 64 && SectionAlignment == 0x40000)
        {
            if (EntrySize && *(ULONG *)&Pattern[(ULONG)SectionType2 + 3] == EntrySize)
            {
                SectionEntry += 7;
                if (!ReadPESectionEntry((unsigned char *)&CumulativeSize, SectionChar) && *(WORD *)(EntryDataPtr + 6) == 1368)
                    return EntryCumulSize == 5;
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
    __int64 NtoskrnlBase = 0;
    int *ImageBuffer, *ImageBufferEnd;
    char *PeSignature;
    ULONG OptHeaderOffset;
    char *NtHeaders;
    __int64 SectionHeader = 0, SectionHeadersEnd = 0;
    size_t FileSize;
    void *Src, *FileBuffer;

    FileBufferPtr = (WORD *)GtAlloc(GtPathBuffer00);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlBase = NtoskrnlBase;

    if (!*(ULONG64 *)FileBufferPtr || !NtoskrnlBase)
        return Success;
    if (ReadFileRawData(FileBufferPtr, &FileBuffer, (ULONG *)&FileSize, 1))
        return Success;
    if (ReadNtFileToBuffer((PUCHAR)FileBuffer, (ULONG)FileSize, (PUCHAR *)&Src, (PULONG)&FileSize) != 1)
    {
        ExFree(FileBuffer);
        return Success;
    }

    ImageBuffer = ExAlloc(PagedPool, (ULONG)(FileSize + 256));
    ImageBufferEnd = ImageBuffer;
    if (!ImageBuffer)
    {
        ExFree(Src);
        ExFree(FileBuffer);
        return Success;
    }

    memmove(ImageBuffer, Src, (ULONG)FileSize);
    memset((char *)ImageBufferEnd + (ULONG)FileSize, 0, 0x100);

    if (ParseNtExportDir((PUCHAR)ImageBufferEnd, (ULONG)FileSize, NtoskrnlBase, 0) == 1)
    {
        GtWrite(GtEprocessField22, (__int64)Src);
        GtWrite(GtEprocessField23, (ULONG)FileSize);
        PeSignature = (char *)Src + *((int *)Src + 15);
        OptHeaderOffset = *((WORD *)PeSignature + 3);
        NtHeaders = &PeSignature[*((WORD *)PeSignature + 10)];
        GtWrite(GtEprocessField24, (__int64)PeSignature);
        GtWrite(GtEprocessField25, OptHeaderOffset);
        GtWrite(GtEprocessField26, (__int64)(NtHeaders + 24));
        GtWrite(GtEprocessField66, (__int64)ImageBufferEnd);
        SectionHeader = (__int64)ImageBufferEnd + ImageBufferEnd[15];
        SectionHeadersEnd = *(WORD *)(SectionHeader + 20) + SectionHeader + 24;
        GtWrite(GtEprocessField67, SectionHeader);
        GtWrite(GtEprocessField68, SectionHeadersEnd);
        Success = 1;
    }
    else
        ExFree(ImageBufferEnd);

    ExFree(Src);
    ExFree(FileBuffer);
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
    if ((ULONG)DosHeader->e_lfanew >= MaxCount || (ULONG)DosHeader->e_lfanew + 24 >= MaxCount)
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
                    ComputedOffset = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    if (*(_WORD *)(pSectionEntryBase + 6) == 1369)
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
                    ComputedOffset2 = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    SectionType = *(_WORD *)(pSectionEntryBase + 6);
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
                    ComputedOffset = SectionFileOffset + (int)AccumulatedOffset;
                    AccumulatedOffset += SectionFileOffset;
                    SectionType = *(_WORD *)(pSectionEntryBase + 6);
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
                        ComputedOffset2 = SectionFileOffset + (int)AccumulatedOffset;
                        AccumulatedOffset += SectionFileOffset;
                        SectionType2 = *(_WORD *)(pSectionEntryBase + 6);
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
                        ComputedOffset3 = SectionFileOffset + (int)AccumulatedOffset;
                        AccumulatedOffset += SectionFileOffset;
                        SectionType3 = *(_WORD *)(pSectionEntryBase + 6);
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
