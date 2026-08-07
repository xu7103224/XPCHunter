// DriverSection.c — 驱动节区打开（从 SsdtHook.c 拆分）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：打开 tcpip/磁盘/键盘/挂载点/win32k/wdf 等驱动文件节区

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
__int64 GetSsdtFunctionBase2(void)
{
    _DWORD EncodedName[8];
    EncodedName[0] = 4456540; EncodedName[1] = 6881394;
    EncodedName[2] = 6619254; EncodedName[3] = 6029426;
    EncodedName[4] = 6881348; EncodedName[5] = 7012467;
    EncodedName[6] = 0;       EncodedName[7] = 0;
    return OpenFileSection((__int64)EncodedName);
}
__int64 DecryptDiskDeviceContextStr(void)
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 7602241; EncodedPath[5] = 7340129;
    EncodedPath[6] = 105;     EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}
__int64 GetSsdtFunctionBase4(void)
{
    _DWORD EncodedName[8];
    EncodedName[0] = 4456540; EncodedName[1] = 6881394;
    EncodedName[2] = 6619254; EncodedName[3] = 6029426;
    EncodedName[4] = 6488129; EncodedName[5] = 6881392;
    EncodedName[6] = 0;       EncodedName[7] = 0;
    return OpenFileSection((__int64)EncodedName);
}
_QWORD *FindDiskDriverModule(void)
{
    _QWORD *Result = 0;
    __int64 ModuleStart = 0;
    enum _GLOBAL_TABLE_INDEX ModuleSizeIdx;
    unsigned __int64 ModuleBase;
    unsigned int ModuleSize = 0;
    unsigned __int64 ModuleEnd;
    __int64 ObjectTypeDir = 0;
    __int64 TypeDirBody = 0;
    __int64 ObjectEntry = 0;
    _QWORD *DiskModule = 0;
    unsigned __int64 StartAddr;
    unsigned __int64 EndAddr;
    int EntryIndex = 0;
    unsigned __int64 *i;
    unsigned __int64 DriverAddr;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        ModuleStart = GtRead(GtCallbackField59);
        ModuleSizeIdx = GtCallbackField60;
    }
    else
    {
        ModuleStart = GtRead(GtCallbackField57);
        ModuleSizeIdx = GtCallbackField58;
    }
    ModuleBase = ModuleStart;
    ModuleSize = GtRead(ModuleSizeIdx);
    if (ModuleBase && ModuleSize)
    {
        ModuleEnd = ModuleBase + ModuleSize;
        if (ModuleEnd > ModuleBase)
        {
            ObjectTypeDir = QueryObjectTypeDirectoryPath();
            if (ObjectTypeDir)
            {
                TypeDirBody = *(_QWORD *)(ObjectTypeDir + 312);
                if (TypeDirBody)
                {
                    ObjectEntry = *(_QWORD *)(TypeDirBody + 48);
                    if (ObjectEntry)
                    {
                        DiskModule = *(_QWORD **)(ObjectEntry + 8);
                        if (DiskModule)
                        {
                            StartAddr = DiskModule[12];
                            if (StartAddr < ModuleBase || StartAddr >= ModuleEnd)
                            {
                                EndAddr = DiskModule[13];
                                if (EndAddr < ModuleBase || EndAddr >= ModuleEnd)
                                {
                                    EntryIndex = 0;
                                    for (i = DiskModule + 14; ; i++)
                                    {
                                        DriverAddr = *i;
                                        if (*i)
                                        {
                                            if (DriverAddr >= ModuleBase && DriverAddr < ModuleEnd)
                                                break;
                                        }
                                        if ((unsigned int)++EntryIndex >= 0x1B)
                                            return (_QWORD *)Result;
                                    }
                                }
                            }
                            return DiskModule;
                        }
                    }
                }
            }
        }
    }
    return (_QWORD *)Result;
}
_QWORD *GetDiskDriverSection(void)
{
    _QWORD *Result;
    _DWORD EncodedPath[6];
    int PathDword4 = 0, PathDword5 = 0, PathDword6 = 0, DummyDword = 0, PathDword7 = 0;

    Result = FindDiskDriverModule();
    if (!Result)
    {
        EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
        EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            PathDword7 = 0;
            PathDword4 = 7536748;
            PathDword5 = 6226025;
            PathDword6 = 6488179;
            DummyDword = 6881395;
        }
        else
        {
            DummyDword = 0;
            PathDword4 = 7929971;
            PathDword5 = 7143533;
            PathDword6 = 6881392;
        }
        EncodedPath[4] = PathDword4; EncodedPath[5] = PathDword5;
        return (_QWORD *)OpenFileSection((__int64)EncodedPath);
    }
    return Result;
}
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
__int64 OpenWin32kSection(void)
{
    _DWORD EncodedPath[6];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254; EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553716; EncodedPath[5] = 120;
    return OpenFileSection((__int64)EncodedPath);
}
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
