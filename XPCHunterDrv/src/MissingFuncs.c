// MissingFuncs.c — 暂未分配到各源文件的函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "..\inc\XPCHunterDrv.h"

// C4700 抑制：各种函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
#include <intrin.h>

// 前向声明 — 定义在 Protocol.c 中
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// 前向声明 — 内部辅助函数
extern char OpenDeviceTarget(__int64 EncodedPath, __int64 *pDeviceHandle, __int64 *pDeviceObjectHandle);
extern __int64 GetDeviceObjectFromContext(__int64 DeviceHandle);
extern char GetDiskDriverInfo(char State, void *pBuffer, __int64 *pFuncTable);
extern char SetDiskDriverInfo(char State, char Flags, void *pBuffer);
extern char FindPeSectionByType0x510(__int64 Base, unsigned int Size, int SectionType, unsigned int SectionFlags);
extern char FindPeSectionByTypeRsrc(__int64 Buffer, unsigned int Size, __int64 Address);
extern char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
extern void QueryProcessModuleFilePath(__int64 ProcessId, __int64 Address, _WORD *pBuffer, unsigned int MaxLen);
extern __int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex);
extern __int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex);
extern __int64 ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern char BuildFsFilterDriverPath1(void);
extern char BuildFsFilterDriverPath2(void);
extern __int64 ReadWriteKernelMemory(void);

// =======================================================================
// 简单函数实现
// =======================================================================

// j_GetCurrentFiber — 跳转到 GetCurrentFiber
// 对应原始驱动 sub_14007A5F0
void *j_GetCurrentFiber(void)
{
    return GetCurrentFiber();
}

// =======================================================================
// 中等复杂度函数实现
// =======================================================================
// ParseServiceTableWin7 — 解析服务表（Win7 版）
// 对应原始驱动 sub_140051434
char ParseServiceTableWin7(char *Src, size_t MaxCount)
{
    char Result;
    unsigned int ServiceCount;
    _DWORD *ServiceTable;
    _DWORD *ServiceTableCopy;
    unsigned __int64 ImageBase;
    unsigned int Win32kServiceTable;
    unsigned __int64 TableSize;
    char *ServiceTablePtr;
    unsigned int EntryIndex;
    _DWORD *CurrentEntry;
    unsigned __int64 FuncAddr;

    Result = 0;
    VerifyServiceTableDriverFile((__int64)Src, MaxCount);
    ServiceCount = GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        if (!(unsigned int)GtRead(GtCallbackField53))
        {
            ServiceTable = (_DWORD *)ExAlloc(PagedPool, 4LL * ServiceCount);
            ServiceTableCopy = ServiceTable;
            if (ServiceTable)
            {
                memset(ServiceTable, 0, 4LL * ServiceCount);
                ImageBase = *(_QWORD *)&Src[*((int *)Src + 15) + 48];
                Win32kServiceTable = FindWin32kServiceTable((__int64)Src, (unsigned int)MaxCount);
                if (!Win32kServiceTable)
                    goto LABEL_FREE;
                if (Win32kServiceTable >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                TableSize = 8LL * ServiceCount;
                if (TableSize >= (unsigned int)MaxCount || Win32kServiceTable + TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                ServiceTablePtr = &Src[Win32kServiceTable];
                if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600)
                {
                    FuncAddr = *(_QWORD *)&ServiceTablePtr[8 * (ServiceCount - 1)];
                    if (FuncAddr <= ImageBase || (unsigned int)MaxCount + ImageBase <= FuncAddr)
                    {
                        --ServiceCount;
                        GtWrite(GtEprocessField57, ServiceCount);
                        GtWrite(GtEncryptionKeyByte | GtPathBuffer04, (unsigned int)(GtRead(GtEncryptionKeyByte | GtPathBuffer04) - 1));
                    }
                }
                EntryIndex = 0;
                if (ServiceCount)
                {
                    CurrentEntry = ServiceTableCopy;
                    do
                    {
                        FuncAddr = *(_QWORD *)ServiceTablePtr;
                        if (*(_QWORD *)ServiceTablePtr <= ImageBase || (unsigned int)MaxCount + ImageBase <= FuncAddr)
                            break;
                        ++EntryIndex;
                        ServiceTablePtr += 8;
                        *CurrentEntry++ = FuncAddr - ImageBase;
                    } while (EntryIndex < ServiceCount);
                    if (EntryIndex < ServiceCount)
                        goto LABEL_FREE;
                }
                if (ParseServiceTableExportEntry(Src, (unsigned int)MaxCount, (__int64)ServiceTableCopy) == 1)
                {
                    GtWrite(GtIrpBufferSize | GtEprocessField14, (__int64)ServiceTableCopy);
                    return 1;
                }
                else
                {
LABEL_FREE:
                    ExFree(ServiceTableCopy);
                }
            }
        }
    }
    return Result;
}

// ParseServiceTableWin8 — 解析服务表（Win8+ 版）
// 对应原始驱动 sub_14005132C
char ParseServiceTableWin8(char *Src, size_t MaxCount)
{
    char Result;
    unsigned int ServiceCount;
    unsigned __int64 TableSize;
    unsigned int *ServiceTable;
    unsigned int *ServiceTableCopy;
    unsigned int Win32kServiceTable;
    unsigned int EntryIndex;
    unsigned int *CurrentEntry;
    char *ServiceTablePtr;
    unsigned int FuncValue;

    Result = 0;
    VerifyServiceTableDriverFile((__int64)Src, MaxCount);
    ServiceCount = GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        if (!(unsigned int)GtRead(GtCallbackField53))
        {
            TableSize = 4LL * ServiceCount;
            ServiceTable = (unsigned int *)ExAlloc(PagedPool, TableSize);
            ServiceTableCopy = ServiceTable;
            if (ServiceTable)
            {
                memset(ServiceTable, 0, 4LL * ServiceCount);
                Win32kServiceTable = FindWin32kServiceTable((__int64)Src, (unsigned int)MaxCount);
                if (!Win32kServiceTable)
                    goto LABEL_FREE;
                if (Win32kServiceTable >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                if (TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                if (Win32kServiceTable + TableSize >= (unsigned int)MaxCount)
                    goto LABEL_FREE;
                EntryIndex = 0;
                CurrentEntry = ServiceTableCopy;
                ServiceTablePtr = (char *)(&Src[Win32kServiceTable] - (char *)ServiceTableCopy);
                do
                {
                    FuncValue = *(unsigned int *)((char *)CurrentEntry + (__int64)ServiceTablePtr);
                    if (!FuncValue)
                        break;
                    if ((unsigned int)MaxCount <= FuncValue)
                        break;
                    ++EntryIndex;
                    *CurrentEntry++ = FuncValue;
                } while (EntryIndex < ServiceCount);
                if (EntryIndex >= ServiceCount && ParseServiceTableExportEntry(Src, (unsigned int)MaxCount, (__int64)ServiceTableCopy) == 1)
                {
                    GtWrite(GtIrpBufferSize | GtEprocessField14, (__int64)ServiceTableCopy);
                    return 1;
                }
                else
                {
LABEL_FREE:
                    ExFree(ServiceTableCopy);
                }
            }
        }
    }
    return Result;
}

// FindHookTargetDataSection — 查找 Hook 目标数据节区
// 对应原始驱动 sub_14001CA5C
__int64 FindHookTargetDataSection(__int64 ModuleBase, unsigned int ModuleSize, __int64 Context, __int64 RelocBase)
{
    __int64 result;
    int EndAddress;
    __int64 SectionBase;
    int SectionIndex;
    int MatchSize;
    unsigned int TargetOffset;
    unsigned int LoopIndex;
    int MatchSize2;
    __int16 SubType;
    __int64 ResultAddress;
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    int EntryCharacteristics;
    __int64 FieldValue;
    unsigned int EntryFlags;
    __int64 FieldValue2;
    int EntrySize;
    unsigned int SectionSize;
    __int64 SectionDataPtr;

    result = GtRead(GtFindHookTargetDataPeOffset);
    if ((_DWORD)result && (unsigned int)result < ModuleSize)
    {
        EndAddress = ModuleBase + ModuleSize;
        SectionBase = ModuleBase + (unsigned int)result;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            InitPESectionReadContext(SectionBase, EndAddress - SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            SectionIndex = 0;
            while (1)
            {
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    goto LABEL_13;
                MatchSize = SectionSize + CumulativeSize;
                CumulativeSize += SectionSize;
                if (*(_WORD *)(SectionDataPtr + 6) == 1368)
                {
                    if (EntryCharacteristics)
                        break;
                }
                if ((unsigned int)++SectionIndex >= 7)
                    goto LABEL_13;
            }
            TargetOffset = MatchSize + EntryCharacteristics - ModuleBase;
            if (TargetOffset && TargetOffset < ModuleSize)
                SectionBase = ModuleBase + TargetOffset;
        }
LABEL_13:
        InitPESectionReadContext(SectionBase, EndAddress - SectionBase, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (LoopIndex = 0; LoopIndex < 0xC8; ++LoopIndex)
        {
            result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)result)
                return result;
            MatchSize2 = SectionSize + CumulativeSize;
            CumulativeSize += SectionSize;
            SubType = *(_WORD *)(SectionDataPtr + 6);
            result = EntryFlags;
            if (SubType == 1298 && FieldValue2 == 0x40000 && EntryFlags)
            {
                result = MatchSize2 + EntryFlags - (unsigned int)ModuleBase;
                if ((_DWORD)result && (unsigned int)result < ModuleSize)
                {
                    ResultAddress = RelocBase + (unsigned int)result;
                    return GtWrite(GtCallbackField00, ResultAddress);
                }
            }
            else if (SubType == 1296
                && FieldValue2 == 65607
                && EntryFlags
                && EntrySize == 8
                && FieldValue == 64
                && EntryFlags < ModuleSize)
            {
                ResultAddress = RelocBase + EntryFlags;
                return GtWrite(GtCallbackField00, ResultAddress);
            }
        }
    }
    return result;
}
// 链接存根函数（待从 IDA 反编译实现）
// =======================================================================
// BuildDevicePath — 构建设备路径
// 读取 GT 0x4220(QueryObjectNameFunc) 的函数指针，查询系统对象目录信息，
// 匹配系统根类型对应的设备条目，提取磁盘/分区索引并写入 Buffer
// 对应原始驱动 sub_140047DFC
char BuildDevicePath(char *Buffer, unsigned int BufferSize)
{
    char Result;
    _DWORD *pInfoBuffer;
    _DWORD *pCurrentEntry;
    unsigned int InfoEntryCount;
    unsigned int LoopIndex;
    unsigned int NameByteLen;
    _WORD *pOutputPos;
    _WORD PathBuffer[8];
    _WORD ObjectName[0x28];
    _WORD *pNameBuffer;
    _DWORD NameSize;
    __int64 QueryObjectNameFunc;
    unsigned int SystemRootType;

    Result = 0;
    QueryObjectNameFunc = GtRead(0x4220);
    if (!QueryObjectNameFunc)
        return Result;
    SystemRootType = (unsigned int)GtRead(0x60);
    if (!SystemRootType)
    {
        BuildSystemRootPath();
        SystemRootType = (unsigned int)GtRead(0x60);
        if (!SystemRootType)
            return Result;
    }
    if (BufferSize < 0xC)
        return Result;
    *(_DWORD *)Buffer = 0;
    pOutputPos = (_WORD *)(Buffer + 4);
    // 构建 L"\\Device\\RawIp" 路径前缀
    PathBuffer[0] = 0x5C;   // L'\\'
    PathBuffer[1] = 0x44;   // L'D'
    PathBuffer[2] = 0x65;   // L'e'
    PathBuffer[3] = 0x76;   // L'v'
    PathBuffer[4] = 0x69;   // L'i'
    PathBuffer[5] = 0x63;   // L'c'
    PathBuffer[6] = 0x65;   // L'e'
    PathBuffer[7] = 0;
    NameByteLen = GetStringLength(PathBuffer) * 2;
    // 查询系统对象信息
    pInfoBuffer = (_DWORD *)AllocExBufferAndQuerySystemInfo(0x10);
    if (!pInfoBuffer)
        return Result;
    InfoEntryCount = *pInfoBuffer;
    if (InfoEntryCount)
    {
        pCurrentEntry = pInfoBuffer + 4;
        for (LoopIndex = 0; LoopIndex < InfoEntryCount; ++LoopIndex)
        {
            if (*((unsigned __int8 *)pCurrentEntry + 4) == SystemRootType)
            {
                __int64 ObjectAddr = *(_QWORD *)pCurrentEntry;
                if (ObjectAddr && ObjectAddr > (unsigned __int64)MmSystemRangeStart)
                {
                    ObjectName[0] = 0;
                    pNameBuffer = ObjectName;
                    NameSize = 0x50;
                    if (!((int (__fastcall *)(__int64, _WORD *, _DWORD *, _WORD **, _BYTE))QueryObjectNameFunc)(
                            ObjectAddr, ObjectName, &NameSize, &pNameBuffer, 0))
                    {
                        if (pNameBuffer == ObjectName + 8 && *ObjectName == NameByteLen)
                        {
                            if (!MemoryCompare((__int64)PathBuffer, (char *)ObjectName, NameByteLen))
                            {
                                *pOutputPos++ = *(_WORD *)pCurrentEntry;
                                *(_DWORD *)pOutputPos = *(_DWORD *)(pCurrentEntry + 1);
                                pOutputPos += 2;
                                ++*(_DWORD *)Buffer;
                            }
                        }
                    }
                }
            }
            pCurrentEntry += 6;
        }
    }
    ExFree(pInfoBuffer);
    return 1;
}

// ComparePeModuleSignature — 比较 PE 模块签名
// 比较模块的前13字节签名，用于识别特定驱动模块
// 对应原始驱动 sub_14008296C
char ComparePeModuleSignature(char *pSignature1, __int64 Signature2, unsigned int SignatureSize)
{
    char Result;

    Result = 0;
    if (SignatureSize >= 0xD)
    {
        if ((unsigned int)MemoryCompare(Signature2, pSignature1, 0xDu))
        {
            if (!(unsigned int)MemoryCompare(Signature2, pSignature1, 8u))
                return pSignature1[12] == *(_BYTE *)(Signature2 + 12);
        }
        else
        {
            return 1;
        }
    }
    return Result;
}

// FindExportInFileByName — 按名称查找文件中的导出函数
// 查找 "ClassSpinDownPowerHandler" 在文件系统过滤器驱动中的导出地址
// 对应原始驱动 sub_14000E584
char FindExportInFileByName(__int64 PeBase, unsigned int PeSize, __int64 OutEntry)
{
    char Result;
    __int64 ExportTableBase;
    unsigned int ExportByNameInPeBody;
    _WORD FuncNameBuffer[16];

    Result = 0;
    ExportTableBase = GtRead(GtFsFilterExportTable);
    if (ExportTableBase)
    {
        strcpy((char *)FuncNameBuffer, "ClassSpinDownPowerHandler");
        FuncNameBuffer[13] = 0;
        ExportByNameInPeBody = FindExportByNameInPeBody(PeBase, PeSize, (__int64)FuncNameBuffer, 0);
        if (ExportByNameInPeBody)
        {
            if (ExportByNameInPeBody < PeSize)
            {
                *(_DWORD *)(OutEntry + 4) = ExportByNameInPeBody;
                Result = 1;
                *(_QWORD *)(OutEntry + 8) = ExportTableBase + ExportByNameInPeBody;
            }
        }
    }
    return Result;
}
// FixCreateFileRelocs — 修复创建文件重定位
// 读取全局表索引，在 PE 节区中搜索匹配条目定位三个目标，搜索重定位偏移写入全局表
// 对应原始驱动 sub_14001E044
__int64 FixCreateFileRelocs(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    int Target1;
    int Target2;
    int Target3;
    __int64 Result;
    unsigned int LoopIndex1;
    int Offset1;
    unsigned int i;
    int Offset2;
    unsigned int LoopIndex2;
    int Offset3;
    unsigned int j;
    unsigned int FirstRelocOffset;
    unsigned int SecondRelocOffset;
    unsigned int LoopIndex3;
    int CurrentOffset;
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    unsigned int EntrySize;
    int EntryFlags;
    __int64 SectionFlags;
    unsigned int SectionSize;
    __int64 SectionType;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    Target1 = GtRead(GtNtWriteFilePeSectionOffset | GtObjectTypeField08);
    Target2 = GtRead(GtTotalSize | GtObjectTypeField18);
    Target3 = GtRead(GtTotalSize | GtEprocessField187 | 0x100);
    Result = GtRead(GtNtCreateFileSyscallResult);
    if (Target1 && Target2 && Target3 && (_DWORD)Result && (unsigned int)Result < TargetSize)
    {
        InitPESectionReadContext(
            TargetBase + (unsigned int)Result,
            TargetSize - (unsigned int)Result,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);
        for (LoopIndex1 = 0; LoopIndex1 < 0x3E8; ++LoopIndex1)
        {
            Result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                break;
            Offset1 = EntryCumulSize + CumulativeSize;
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
            {
                if (EntrySize)
                {
                    Result = Offset1 + EntrySize - (unsigned int)TargetBase;
                    if (Target1 == (_DWORD)Result)
                    {
                        Target1 = 0;
                        break;
                    }
                }
            }
        }
        if (!Target1)
        {
            for (i = 0; i < 0x3E8; ++i)
            {
                Result = ReadPESectionEntry(&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
                Offset2 = EntryCumulSize + CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
                {
                    if (EntrySize)
                    {
                        Result = Offset2 + EntrySize - (unsigned int)TargetBase;
                        if (Target2 == (_DWORD)Result)
                        {
                            Target2 = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (!Target2)
        {
            for (LoopIndex2 = 0; LoopIndex2 < 0x64; ++LoopIndex2)
            {
                Result = ReadPESectionEntry(&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
                Offset3 = EntryCumulSize + CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
                {
                    if (EntrySize)
                    {
                        Result = Offset3 + EntrySize - (unsigned int)TargetBase;
                        if (Target3 == (_DWORD)Result)
                        {
                            Target3 = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (!Target3)
        {
            for (j = 0; j < 0x1E; ++j)
            {
                Result = ReadPESectionEntry(&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1294
                    && (SectionFlags & 0x40000) != 0
                    && EntryFlags
                    && (SectionType & 0x40) != 0)
                {
                    FirstRelocOffset = 0;
                    SecondRelocOffset = 0;
                    for (LoopIndex3 = 0; LoopIndex3 < 0x1E; ++LoopIndex3)
                    {
                        Result = ReadPESectionEntry(&ReadContext, SectionEntry);
                        if ((_DWORD)Result)
                            break;
                        CurrentOffset = EntryCumulSize + CumulativeSize;
                        CumulativeSize += EntryCumulSize;
                        if (SectionType == 0x40000)
                        {
                            if (SectionSize)
                            {
                                if ((SectionFlags & 0x20) == 0 || FirstRelocOffset)
                                {
                                    if ((SectionFlags & 0x40) != 0 && FirstRelocOffset)
                                    {
                                        SecondRelocOffset = CurrentOffset + SectionSize - (unsigned int)TargetBase;
                                        break;
                                    }
                                }
                                else
                                {
                                    FirstRelocOffset = CurrentOffset + SectionSize - (unsigned int)TargetBase;
                                }
                            }
                        }
                    }
                    if (FirstRelocOffset && SecondRelocOffset)
                    {
                        GtWrite(GtCallbackField116, RelocBase + SecondRelocOffset);
                        return GtWrite(GtCallbackField117, RelocBase + FirstRelocOffset);
                    }
                    return Result;
                }
            }
        }
    }
    return Result;
}



// ParseNtExportFunctions — 解析 NT 导出函数
// 读取 ntoskrnl 导出表，扫描 PE 节区条目匹配 0xFE/0x558/0x430/0x4DB/0x512/0x53D 等类型
// 查找 MSR 相关导出地址并写入全局表 0x813/0x815
// 对应原始驱动 sub_14002A644
__int64 ParseNtExportFunctions(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    __int64 SectionAlignment;
    int SectionType;
    __int64 MiscInfo;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    int MiscInfo2;
    __int64 Result;
    int Phase1Offset;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    char HasDiscardable;
    char HasCodeSection;
    char Found418;
    char MsrFlag1;
    char MsrFlag2;
    int SavedEntryCount;
    __int64 NtoskrnlBase;
    unsigned int ImageBase;
    unsigned int ImageSize;
    unsigned int DataDirRva;
    __int64 PeContext;
    char EntryBuffer[80];
    __int64 PeFileData;

    Result = 0;
    NtoskrnlBase = GtRead(3);
    ImageBase = (unsigned int)GtRead(0x22);
    ImageSize = (unsigned int)GtRead(0x20);
    DataDirRva = (unsigned int)GtRead(0x21);
    if (!NtoskrnlBase || !ImageBase || !ImageSize || !DataDirRva)
        return Result;
    PeFileData = *(__int64 *)(ImageBase + 0x28);
    if (!PeFileData || (unsigned int)PeFileData >= DataDirRva)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((char *)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, &PeContext, -1, 0, 0, 0);
    HasDiscardable = 0;
    HasCodeSection = 0;
    Found418 = 0;
    MsrFlag1 = 0;
    MsrFlag2 = 0;
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment & 0x4000000)
            {
                FieldValue = *(int *)&EntryBuffer[0x20];
                if (FieldValue && HasDiscardable == 1)
                {
                    int Offset = FieldValue - (int)ImageSize + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < DataDirRva)
                    {
                        Phase1Offset = Offset;
                        break;
                    }
                }
            }
        }
        ++Phase1Count;
    }
    HasDiscardable = 0;
    HasCodeSection = 0;
    MsrFlag1 = 0;
    MsrFlag2 = 0;
    memset(Dst, 0, sizeof(Dst));
    LoopIndex = 0;
    SavedEntryCount = 0;
    PeContext = 0;
    InitPESectionReadContext((char *)(ImageSize + Phase1Offset), DataDirRva + ImageSize - (ImageSize + Phase1Offset), 2, &PeContext, -1, 0, 0, 0);
    while (LoopIndex < 0x1F4)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (!HasCodeSection)
        {
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x430)
            {
                if (!HasDiscardable)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment & 0x4000)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                        {
                            if (CumulativeSize == 0x400000000LL)
                            {
                                MiscInfo = *(__int64 *)&EntryBuffer[0x30 + 0x10];
                                if (MiscInfo == 0)
                                    HasCodeSection = 1;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DB)
            {
                if (!HasDiscardable)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment & 0x4000)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                        {
                            if (CumulativeSize == 0x20)
                                HasCodeSection = 1;
                        }
                    }
                }
            }
            else
            {
                if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
                    HasDiscardable = 1;
            }
        }
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
        {
            if (Phase1Offset && (unsigned int)Phase1Offset < DataDirRva)
            {
                if (MsrFlag1 == 0)
                    GtWrite(0x813, NtoskrnlBase + Phase1Offset);
                else if (MsrFlag2 != 0)
                    GtWrite(0x815, NtoskrnlBase + Phase1Offset);
                if (GtRead(0x813) && GtRead(0x815))
                    return Result;
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
        {
            if (CumulativeSize == 0x40000)
            {
                EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                if (EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(int *)&EntryBuffer[0x18];
                        if ((SectionType & 0xFFFFFFFD) == 0)
                        {
                            Phase1Offset = EntrySize - (int)ImageSize + (int)CumulativeSize;
                        }
                    }
                }
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x53D)
        {
            if (CumulativeSize == 0x800000)
            {
                MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                if (MiscInfo == 0xC0000083)
                    MsrFlag1 = 1;
                else if (MiscInfo == 0xC0000082)
                    MsrFlag2 = 1;
            }
        }
        else if (HasCodeSection)
        {
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(int *)&EntryBuffer[0x18];
                        if (SectionType < 0x10)
                        {
                            Dst[SectionType] = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            if (ReadPESectionEntry(&PeContext, EntryBuffer))
                                return Result;
                            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
                            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
                            CumulativeSize += SectionSize;
                            SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
                            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
                            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512 &&
                                CumulativeSize == 0x40000 && EntrySize)
                            {
                                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                if (SectionAlignment == 0x40)
                                    Dst[SectionType] = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x418)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x80000)
                    {
                        MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                        if (MiscInfo == 0)
                        {
                            Found418 = 1;
                            int Offset = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < DataDirRva)
                            {
                                if (!*(char *)(NtoskrnlBase + Offset))
                                    HasCodeSection = 0;
                                else
                                {
                                    if (GtRead(0x90D))
                                    {
                                        void *Fiber = j_GetCurrentFiber();
                                        if (Fiber)
                                            HasCodeSection = (*(char *)(GtRead(0x90D) + (__int64)Fiber) == 1) ? 2 : 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DA)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x90D))
                    {
                        if (EntrySize)
                        {
                            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                            if (SectionAlignment == 0x10041)
                            {
                                if (Found418)
                                    Dst[0] = SavedEntryCount;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x13E)
            {
                if (Dst[1] == 1)
                {
                    if (SavedEntryCount >= Dst[0] + 5)
                    {
                        if (HasCodeSection == 1)
                        {
                            FieldValue = *(int *)&EntryBuffer[0x20];
                            int Offset = FieldValue - (int)ImageSize + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < DataDirRva)
                            {
                                __int64 CheckAddr = NtoskrnlBase + Offset;
                                __int64 CurrentCumulative = CumulativeSize;
                                if (CheckAddr > CurrentCumulative || CheckAddr + 0x100 <= CurrentCumulative)
                                {
                                    if (CurrentCumulative > CheckAddr || CurrentCumulative + 0x100 <= CheckAddr)
                                    {
                                        if (ParseNtDataSectionRelocs(Dst, NtoskrnlBase, ImageSize, DataDirRva))
                                            HasCodeSection = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
            {
                if (SectionAlignment == 0x40 && CumulativeSize == 0x40)
                {
                    /* match */
                }
            }
        }
        ++LoopIndex;
    }
    return Result;
}

// ParseNtExportFunctionsV2 — 解析 NT 导出函数 V2
// 使用索引 0x22 获取数据目录，扫描 0xFE/0x558/0x4D7 等类型，写入全局表 0x813/0x815
// 对应原始驱动 sub_14002AD88
__int64 ParseNtExportFunctionsV2(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    __int64 SectionAlignment;
    int SectionType;
    __int64 MiscInfo;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    __int64 Result;
    int Phase1Offset;
    int Phase1Type;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    char HasDiscardable;
    char HasCodeSection;
    int DstIndex;
    unsigned int SavedEntryCount;
    __int64 NtoskrnlBase;
    unsigned int ImageBase;
    unsigned int DataDirRva;
    unsigned int ImageSize;
    __int64 PeContext;
    char EntryBuffer[80];
    __int64 PeFileData;

    Result = 0;
    NtoskrnlBase = GtRead(3);
    ImageBase = (unsigned int)GtRead(0x22);
    DataDirRva = (unsigned int)GtRead(0x20);
    ImageSize = (unsigned int)GtRead(0x21);
    if (!NtoskrnlBase || !ImageBase || !DataDirRva || !ImageSize)
        return Result;
    PeFileData = *(__int64 *)(ImageBase + 0x28);
    if (!PeFileData || (unsigned int)PeFileData >= ImageSize)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((char *)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, &PeContext, -1, 0, 0, 0);
    HasDiscardable = 0;
    Phase1Offset = 0;
    Phase1Type = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
            break;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment & 0x4000000)
            {
                FieldValue = *(int *)&EntryBuffer[0x20];
                if (FieldValue && HasDiscardable == 1)
                {
                    int Offset = FieldValue - (int)DataDirRva + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < ImageSize)
                    {
                        Phase1Offset = Offset;
                        Phase1Type = Phase1Count;
                    }
                }
            }
        }
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4D7)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment == 0x20 && CumulativeSize == 0x20)
            {
                SectionType = *(int *)&EntryBuffer[0x18];
                if (SectionType == 1)
                {
                    if (*(int *)&EntryBuffer[0x10] == 1 && Phase1Type && Phase1Type + 10 > Phase1Count)
                        break;
                }
            }
        }
        ++Phase1Count;
    }
    if (!Phase1Offset)
        return Result;
    memset(Dst, 0, sizeof(Dst));
    Phase1Count = 0;
    PeContext = 0;
    InitPESectionReadContext((char *)(DataDirRva + Phase1Offset), ImageSize + DataDirRva - (DataDirRva + Phase1Offset), 2, &PeContext, -1, 0, 0, 0);
    HasCodeSection = 0;
    HasDiscardable = 0;
    LoopIndex = 0;
    SavedEntryCount = 0;
    while (LoopIndex < 0x1F4)
    {
        if (ReadPESectionEntry(&PeContext, EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (!HasCodeSection)
        {
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x430)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment & 0x4000)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                    {
                        if (CumulativeSize == 0x400000000LL)
                        {
                            MiscInfo = *(__int64 *)&EntryBuffer[0x40];
                            if (MiscInfo == 0)
                                HasCodeSection = 1;
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DB)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment & 0x4000)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                    {
                        if (CumulativeSize == 0x20)
                            HasCodeSection = 1;
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment == 0x20 && (CumulativeSize & 0x4000))
                {
                    if (*(unsigned int *)&EntryBuffer[0x20] == (unsigned int)GtRead(0x80E))
                        HasCodeSection = 1;
                }
            }
        }
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
        {
            if (Phase1Offset && (unsigned int)Phase1Offset < ImageSize)
            {
                if (HasDiscardable == 0)
                    GtWrite(0x813, NtoskrnlBase + Phase1Offset);
                else
                    GtWrite(0x815, NtoskrnlBase + Phase1Offset);
                if (GtRead(0x813) && GtRead(0x815))
                    return Result;
            }
        }
        else if (HasCodeSection)
        {
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize)
                    {
                        SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                        if (SectionAlignment == 0x40)
                        {
                            SectionType = *(int *)&EntryBuffer[0x18];
                            if (SectionType < 0x10)
                            {
                                Dst[SectionType] = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                                if (ReadPESectionEntry(&PeContext, EntryBuffer))
                                    return Result;
                                SectionSize = *(unsigned int *)&EntryBuffer[0x38];
                                CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
                                CumulativeSize += SectionSize;
                                SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
                                *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
                                if (*(unsigned short *)(SectionDataPtr + 6) == 0x512 &&
                                    CumulativeSize == 0x40000 && EntrySize)
                                {
                                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                    if (SectionAlignment == 0x40)
                                        Dst[SectionType] = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x418)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize && CumulativeSize == 0x80000)
                    {
                        MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                        if (MiscInfo == 0)
                        {
                            int Offset = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize)
                            {
                                if (!*(char *)(NtoskrnlBase + Offset))
                                    Phase1Count = 0;
                                else
                                {
                                    if (GtRead(0x90D))
                                    {
                                        void *Fiber = j_GetCurrentFiber();
                                        if (Fiber)
                                            Phase1Count = (*(char *)(GtRead(0x90D) + (__int64)Fiber) == 1) ? 2 : 1;
                                    }
                                }
                                HasCodeSection = 0;
                                HasDiscardable = 0;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DA)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x90D))
                        {
                            if (EntrySize)
                            {
                                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                if (SectionAlignment == 0x10041)
                                {
                                    DstIndex = 1;
                                    if (HasDiscardable)
                                        Dst[0] = SavedEntryCount;
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment == 0x40 && CumulativeSize == 0x40)
                {
                    SectionType = *(int *)&EntryBuffer[0x18];
                    if (SectionType == 2)
                    {
                        if (Dst[Dst[0x10]])
                            Phase1Offset = Dst[Dst[0x10]];
                    }
                }
            }
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x53D)
            {
                if (CumulativeSize == 0x800000)
                {
                    MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                    if (MiscInfo == 0xC0000083)
                        Phase1Type = 0;
                    else if (MiscInfo == 0xC0000082)
                        Phase1Type = 1;
                }
            }
        }
        ++SavedEntryCount;
        if (LoopIndex == 0)
            HasDiscardable = 0;
        ++LoopIndex;
    }
    return Result;
}

// ParseNtImageSections2 — 解析 NT 映像节区 V2
// 通过 PE 节区扫描匹配 EntryType 1369/1296+64+1/1368 查找 Init 节区，然后扫描 0x1F4 条目匹配 1298（可重定位基址）和 1294（函数入口），填充上下文表（15476）和目标表（15650），共 28 条目
// 对应原始驱动 sub_140031A58
char ParseNtImageSections2(__int64 PeBase, unsigned int PeSize)
{
    unsigned int SectionRva;
    char TableBuilt;
    __int64 FileSize;
    __int64 NtoskrnlBase;
    unsigned int OptHeaderSize;
    char FoundInitSection;
    int SectionIndex;
    int SectionEnd;
    __int16 SectionType;
    unsigned int TargetRva;
    unsigned int TargetRva2;
    char FoundRelocSection;
    unsigned int LoopIndex;
    int SectionEnd2;
    __int16 SectionType2;
    unsigned int RelocRva;
    __int64 EntryIndex;
    unsigned int RelocBaseRva;
    __int64 TableSlot;
    __int64 FieldAddr;
    __int64 FieldOffset;
    _QWORD *pTargetEntry;
    __int64 EntryCount;
    unsigned __int64 *pFieldSrc;
    __int64 FieldRva;
    __int64 FillCount;
    char *pFillEntry;
    char TableBuilt2;
    unsigned int RelocRva2;
    __int64 NtoskrnlBase2;
    __int64 *pContextTable;
    __int64 *pTargetTable;
    unsigned __int64 ImageNtHeader;
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    int FieldValue;
    int FieldValue2;
    __int64 SectionCharacteristics;
    unsigned int SectionEntryIndex;
    int FieldValueB;
    __int64 SectionDataPtr;
    int EntryIndex2;
    int FieldValueC;
    unsigned int SectionSize;
    __int64 SectionDataPtr2;
    _DWORD Dst[16];

    SectionRva = 0;
    TableBuilt = 0;
    TableBuilt2 = 0;
    FileSize = PeSize;
    NtoskrnlBase2 = GtRead(GtFltPeSectionOfs8 | GtEprocessField54);
    pContextTable = GtAlloc(GtEprocessModuleListOffset | GtPspExitThreadAddr | 0x3400);
    pTargetTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)15650);
    if (NtoskrnlBase2)
    {
        OptHeaderSize = *(unsigned int *)(*(int *)(PeBase + 60) + PeBase + 40);
        ImageNtHeader = *(_QWORD *)(*(int *)(PeBase + 60) + PeBase + 48);
        if ((unsigned int)OptHeaderSize < (unsigned int)FileSize)
        {
            FoundInitSection = 0;
            InitPESectionReadContext(PeBase + OptHeaderSize, FileSize - OptHeaderSize, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
            {
                SectionEnd = SectionSize + CumulativeSize;
                CumulativeSize += SectionSize;
                SectionType = *(_WORD *)(SectionDataPtr2 + 6);
                if (SectionType == 1369)
                {
                    TargetRva = SectionEnd + FieldValue - PeBase;
                    if (TargetRva && TargetRva < (unsigned int)FileSize)
                        goto LABEL_8;
                }
                else if (SectionType == 1296 && SectionCharacteristics == 64 && SectionEntryIndex == 1)
                {
                    FoundInitSection = 1;
                }
                else if (SectionType == 1368)
                {
                    if (FoundInitSection == 1)
                    {
                        TargetRva = SectionEnd + FieldValue - PeBase;
                        if (TargetRva && TargetRva < (unsigned int)FileSize)
                        {
LABEL_8:
                            OptHeaderSize = TargetRva;
                            break;
                        }
                    }
                    FoundInitSection = 0;
                }
                if ((unsigned int)++SectionIndex >= 0x14)
                    break;
            }
        }
        if (OptHeaderSize && (unsigned int)OptHeaderSize < (unsigned int)FileSize)
        {
            InitPESectionReadContext(
                PeBase + (unsigned int)OptHeaderSize,
                FileSize - OptHeaderSize,
                2, 0, -1, 0, 0,
                (__int64)&ReadContext);
            memset(Dst, 0, sizeof(Dst));
            RelocRva2 = 0;
            TargetRva2 = 0;
            FoundRelocSection = 0;
            for (LoopIndex = 0; LoopIndex < 0x1F4; ++LoopIndex)
            {
                if ((unsigned int)ReadPESectionEntry(&ReadContext, SectionEntry))
                    break;
                SectionEnd2 = SectionSize + CumulativeSize;
                CumulativeSize += SectionSize;
                SectionType2 = *(_WORD *)(SectionDataPtr2 + 6);
                if (SectionType2 == 1298 && SectionDataPtr == 0x40000 && FieldValueB && SectionCharacteristics == 64)
                {
                    RelocRva = SectionEnd2 + FieldValueB - PeBase;
                    if (RelocRva && RelocRva < (unsigned int)FileSize && SectionEntryIndex < 0x10)
                    {
                        SectionRva = RelocRva2;
                        RelocRva2 = SectionEnd2 + FieldValueB - PeBase;
                        Dst[SectionEntryIndex] = RelocRva;
                    }
                }
                else if (SectionType2 == 1294 && (SectionCharacteristics & 0x14000) != 0 && (SectionCharacteristics & 0x40) != 0 && (FieldValueC & 0xF) != 4 && SectionDataPtr == 64)
                {
                    if ((unsigned int)(FieldValue2 - 112) > 0xD8 || (FieldValue2 & 7) != 0)
                    {
                        if (FieldValue2 == 80)
                        {
                            FieldAddr = (unsigned int)Dst[EntryIndex2];
                            if ((_DWORD)FieldAddr)
                            {
                                if ((unsigned int)FieldAddr < (unsigned int)FileSize)
                                {
                                    FieldOffset = (unsigned int)FieldAddr;
                                    if (FieldAddr + 224 <= FileSize)
                                    {
                                        pTargetEntry = pTargetTable + 1;
                                        EntryCount = 27;
                                        pFieldSrc = (unsigned __int64 *)(PeBase + FieldOffset + 8);
                                        do
                                        {
                                            if (*pFieldSrc > ImageNtHeader)
                                            {
                                                FieldRva = (unsigned int)*pFieldSrc - (unsigned int)ImageNtHeader;
                                                if ((unsigned int)FileSize > (unsigned int)FieldRva)
                                                {
                                                    *((_DWORD *)pTargetEntry - 1) = FieldRva;
                                                    *pTargetEntry = NtoskrnlBase2 + FieldRva;
                                                }
                                            }
                                            ++pFieldSrc;
                                            pTargetEntry += 6;
                                            --EntryCount;
                                        } while (EntryCount);
                                        TableBuilt = TableBuilt2;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        if (!FoundRelocSection)
                        {
                            TargetRva2 = SectionRva;
                            FoundRelocSection = 1;
                        }
                        EntryIndex = (unsigned int)(FieldValue2 - 112) >> 3;
                        if ((unsigned int)EntryIndex <= 0x1B)
                        {
                            RelocBaseRva = Dst[EntryIndex2];
                            if (RelocBaseRva)
                            {
                                TableSlot = 6 * EntryIndex;
                                if (!HIDWORD(pContextTable[TableSlot]))
                                {
                                    TableBuilt = 1;
                                    ((ULONG *)&pContextTable[TableSlot])[1] = (ULONG)RelocBaseRva;
                                    TableBuilt2 = 1;
                                    pContextTable[TableSlot + 1] = NtoskrnlBase2 + RelocBaseRva;
                                }
                            }
                        }
                    }
                }
            }
            if (TableBuilt == 1 && TargetRva2)
            {
                FillCount = 28;
                pFillEntry = (char *)pContextTable + 4;
                do
                {
                    if (!*(_DWORD *)pFillEntry)
                    {
                        *(_DWORD *)pFillEntry = TargetRva2;
                        *(_QWORD *)(pFillEntry + 4) = NtoskrnlBase2 + TargetRva2;
                    }
                    pFillEntry += 48;
                    --FillCount;
                } while (FillCount);
                return TableBuilt2;
            }
        }
    }
    return TableBuilt;
}

// QueryDiskInfoAta — 查询 ATA 磁盘信息
// 打开目标磁盘设备，发送 ATA IDENTIFY 命令获取磁盘标识信息，解析分区表数据，输出 52 字节每分区的磁盘信息结构
// 对应原始驱动 sub_140047FDC
char QueryDiskInfoAta(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    char Result;
    __int64 (__fastcall *SendDeviceIoControl)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    void (__fastcall *WaitForEvent)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD);
    __int64 CloseDeviceHandle;
    __int64 CloseHandle;
    __int64 DeviceObjectFromContext;
    __int64 IrpPtr;
    ULONG_PTR IrpResult;
    __int64 IrpStackLocation;
    char DiskDriverInfo;
    int IoStatus;
    unsigned int IdentifyBufferSize;
    _WORD *IdentifyBuffer;
    __int64 (__fastcall *IrpPtr2)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    __int64 IrpStackLocation2;
    char DiskDriverInfo2;
    int IoStatus2;
    unsigned __int64 PartitionCount;
    _WORD *SrcEntry;
    char *DstEntry;
    __int64 RemainingEntries;
    int TempValue;
    int WaitFlag;
    char DiskDriverInfo1;
    char RestoreFlag2;
    char RestoreFlag1;
    char RestoreFlag3;
    __int64 DeviceHandle;
    __int64 (__fastcall *DiskDriverInfoTable)(__int64, ULONG_PTR, __int64);
    __int64 (__fastcall *SendDeviceIoControl2)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    unsigned int OutputBufferSizeCopy;
    int IoStatusBlock;
    unsigned __int64 DataTransferSize;
    __int64 DeviceObjectHandle;
    void (__fastcall *CloseDeviceHandleFunc)(__int64);
    void (__fastcall *CloseHandleFunc)(__int64);
    struct _KEVENT Event;
    _DWORD Dst[10];
    _DWORD AtaOutputBuffer[16];
    _DWORD EncodedDevicePath[6];
    _OWORD DiskDriverInfoBuffer;

    OutputBufferSizeCopy = BufferSize;
    Result = 0;
    SendDeviceIoControl = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    SendDeviceIoControl2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    WaitForEvent = (void (__fastcall *)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField06);
    CloseDeviceHandle = GtRead(GtCloseHandleFunc);
    CloseDeviceHandleFunc = (void (__fastcall *)(__int64))CloseDeviceHandle;
    CloseHandle = GtRead(GtExFreePoolFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandle;
    if (SendDeviceIoControl && WaitForEvent && CloseDeviceHandle && CloseHandle)
    {
        EncodedDevicePath[0] = 4456540;
        EncodedDevicePath[1] = 7733349;
        EncodedDevicePath[2] = 6488169;
        EncodedDevicePath[3] = 6029413;
        EncodedDevicePath[4] = 6488148;
        EncodedDevicePath[5] = 112;
        if (OpenDeviceTarget((__int64)EncodedDevicePath, (__int64)&DeviceHandle, &DeviceObjectHandle) == 1)
        {
            memset(Dst, 0, sizeof(Dst));
            Dst[0] = 1024;
            Dst[2] = 512;
            Dst[3] = 256;
            Dst[4] = 1;
            DeviceObjectFromContext = GetDeviceObjectFromContext(DeviceHandle);
            if (DeviceObjectFromContext)
            {
                KeInitializeEvent(&Event, NotificationEvent, 0);
                memset(AtaOutputBuffer, 0, 0x3Cu);
                IrpPtr = SendDeviceIoControl(1179651, DeviceObjectFromContext, Dst, 40, AtaOutputBuffer, 60u, 0, &Event, &IoStatusBlock);
                IrpResult = IrpPtr;
                if (IrpPtr)
                {
                    IrpStackLocation = *(_QWORD *)(IrpPtr + 184);
                    *(_QWORD *)(IrpStackLocation - 32) = DeviceObjectFromContext;
                    *(_QWORD *)(IrpStackLocation - 24) = DeviceHandle;
                    DiskDriverInfo = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, &DiskDriverInfoTable);
                    DiskDriverInfo1 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                    RestoreFlag1 = SwapDiskIrpFunctionPointer();
                    IoStatus = AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, IrpResult);
                    SetDiskDriverInfo(DiskDriverInfo, 0, &DiskDriverInfoBuffer);
                    if (IoStatus == 259)
                    {
                        WaitForEvent(&Event, 0, 0, 0, 0);
                        IoStatus = IoStatusBlock;
                    }
                    if (DiskDriverInfo1 == 1)
                        WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                    RestoreDiskIrpFunctionPointer(RestoreFlag1);
                    if (!IoStatus)
                    {
                        IdentifyBufferSize = 24 * (AtaOutputBuffer[14] + 16);
                        IdentifyBuffer = ExAlloc(PagedPool, IdentifyBufferSize);
                        if (IdentifyBuffer)
                        {
                            Dst[4] = 258;
                            KeInitializeEvent(&Event, NotificationEvent, 0);
                            WaitFlag = 0;
                            IrpPtr2 = SendDeviceIoControl2(1179651, DeviceObjectFromContext, Dst, 40, IdentifyBuffer, IdentifyBufferSize, WaitFlag, &Event, &IoStatusBlock);
                            SendDeviceIoControl2 = IrpPtr2;
                            if (IrpPtr2)
                            {
                                IrpStackLocation2 = *((_QWORD *)IrpPtr2 + 23);
                                *(_QWORD *)(IrpStackLocation2 - 32) = DeviceObjectFromContext;
                                *(_QWORD *)(IrpStackLocation2 - 24) = DeviceHandle;
                                DiskDriverInfo2 = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, &DiskDriverInfoTable);
                                RestoreFlag3 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                                RestoreFlag2 = SwapDiskIrpFunctionPointer();
                                IoStatus2 = AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, (ULONG_PTR)SendDeviceIoControl2);
                                SetDiskDriverInfo(DiskDriverInfo2, 0, &DiskDriverInfoBuffer);
                                if (IoStatus2 == 259)
                                {
                                    WaitForEvent(&Event, 0, 0, 0, 0);
                                    IoStatus2 = IoStatusBlock;
                                }
                                if (RestoreFlag3 == 1)
                                    WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                                RestoreDiskIrpFunctionPointer(RestoreFlag2);
                                if (!IoStatus2)
                                {
                                    PartitionCount = DataTransferSize / 0x18;
                                    *OutSize = (unsigned int)(DataTransferSize / 0x18) ? 52 * ((unsigned int)(DataTransferSize / 0x18) - 1) + 56 : 56;
                                    if (OutputBufferSizeCopy >= *OutSize)
                                    {
                                        memset(Buffer, 0, *OutSize);
                                        *(unsigned int *)Buffer = PartitionCount;
                                        if ((_DWORD)PartitionCount)
                                        {
                                            SrcEntry = IdentifyBuffer + 8;
                                            DstEntry = Buffer + 8;
                                            RemainingEntries = (unsigned int)PartitionCount;
                                            do
                                            {
                                                *((_DWORD *)DstEntry - 1) = *((_DWORD *)SrcEntry - 4);
                                                *(_WORD *)DstEntry = *(SrcEntry - 4);
                                                DstEntry += 52;
                                                *((_WORD *)DstEntry - 25) = *SrcEntry;
                                                TempValue = *((_DWORD *)SrcEntry - 3);
                                                SrcEntry += 12;
                                                *((_DWORD *)DstEntry - 12) = TempValue;
                                                *((_DWORD *)DstEntry - 11) = *((_DWORD *)SrcEntry - 7);
                                                *((_WORD *)DstEntry - 20) = *(SrcEntry - 15);
                                                TempValue = *(SrcEntry - 11);
                                                *((_QWORD *)DstEntry - 2) = 0;
                                                *((_WORD *)DstEntry - 19) = TempValue;
                                                *((_DWORD *)DstEntry - 2) = *((_DWORD *)SrcEntry - 5) | 0x80000000;
                                                --RemainingEntries;
                                            } while (RemainingEntries);
                                        }
                                        Result = 1;
                                    }
                                }
                            }
                            ExFree(IdentifyBuffer);
                        }
                    }
                }
            }
            CloseDeviceHandleFunc(DeviceHandle);
            CloseHandleFunc(DeviceObjectHandle);
        }
    }
    return Result;
}
// QuerySystemInfoPart1 — 查询系统信息第一部分
// 调用 QuerySystemInfoAllocateBuffers 查询系统信息类 1，根据构建号选择条目大小（12/16/20），遍历条目填充 52 字节每项的输出缓冲区
// 对应原始驱动 sub_140049270
char QuerySystemInfoPart1(_DWORD *OutputBuffer, unsigned int OutputBufferSize, _DWORD *pOutputSize)
{
    char Result;
    unsigned __int64 BufferSize;
    __int64 *QueryParam;
    unsigned int EntrySize;
    unsigned int EntryCount;
    _DWORD *NameBuffer;
    void *ExtBuffer;
    char *BaseBuffer;
    void *NameBufferCopy;
    unsigned int LoopIndex;
    char *CurrentEntry;
    int ExtData;
    _DWORD *ExtBufferPtr;
    char *BaseBufferPtr;
    unsigned int ActualEntryCount;
    _DWORD *NameBufferPtr;

    Result = 0;
    BufferSize = OutputBufferSize;
    if (OutputBufferSize >= 0x38)
    {
        *OutputBuffer = 0;
        *pOutputSize = 56;
        QueryParam = GtAlloc(GtNtQuerySystemInformationFunc | GtDriverObject);
        GtWrite(GtNtQuerySystemInformationFunc | GtDriverObject, 0x100000018LL);
        GtWrite(GtEprocessField146 | 0x100, 0x11D49B1AEB004A03LL);
        GtWrite(GtEprocessField147 | 0x100, 0xBC59770450002391uLL);
        EntrySize = GtRead(GtWindowsBuildNumber) < 0x55F0
            ? (GtRead(GtWindowsBuildNumber) < 0x1DB1 ? 12 : 16)
            : 20;
        if (!QuerySystemInfoAllocateBuffers(
                1u,
                (__int64)QueryParam,
                3,
                (__int64 *)&BaseBufferPtr,
                56,
                0,
                0,
                (__int64 *)&NameBufferPtr,
                EntrySize,
                &ExtBufferPtr,
                32,
                &ActualEntryCount))
        {
            EntryCount = ActualEntryCount;
            NameBuffer = NameBufferPtr;
            ExtBuffer = ExtBufferPtr;
            BaseBuffer = BaseBufferPtr;
            NameBufferCopy = NameBufferPtr;
            if (ActualEntryCount)
            {
                LoopIndex = 0;
                CurrentEntry = BaseBufferPtr + 32;
                NameBufferPtr = ExtBufferPtr + 3;
                do
                {
                    if (*OutputBuffer)
                    {
                        if (BufferSize < (unsigned int)*pOutputSize + 52)
                            break;
                        *pOutputSize = (unsigned int)*pOutputSize + 52;
                    }
                    {
                        __int64 EntryIndex = (unsigned int)*OutputBuffer;
                        if (*((_WORD *)CurrentEntry - 16) == 23)
                        {
                            *(_OWORD *)&OutputBuffer[13 * EntryIndex + 3] = *(_OWORD *)(CurrentEntry - 24);
                            *(_OWORD *)&OutputBuffer[13 * *OutputBuffer + 7] = *(_OWORD *)(CurrentEntry + 4);
                            OutputBuffer[13 * *OutputBuffer + 13] &= ~0x80000000;
                        }
                        else
                        {
                            OutputBuffer[13 * EntryIndex + 3] = *((_DWORD *)CurrentEntry - 7);
                            OutputBuffer[13 * *OutputBuffer + 4] = *(_DWORD *)CurrentEntry;
                            OutputBuffer[13 * *OutputBuffer + 13] |= 0x80000000;
                        }
                    }
                    ++LoopIndex;
                    CurrentEntry += 56;
                    OutputBuffer[13 * *OutputBuffer + 1] = *NameBuffer;
                    *((_WORD *)&OutputBuffer[13 * *OutputBuffer + 2]) = *((_WORD *)CurrentEntry - 43);
                    *((_WORD *)&OutputBuffer[13 * *OutputBuffer + 2] + 1) = *((_WORD *)CurrentEntry - 29);
                    OutputBuffer[13 * *OutputBuffer + 11] = *((_DWORD *)CurrentEntry - 16);
                    OutputBuffer[13 * *OutputBuffer + 12] = *((_DWORD *)CurrentEntry - 9);
                    {
                        __int64 EntryIndex2 = (unsigned int)*OutputBuffer;
                        ExtData = *NameBufferPtr;
                        NameBufferPtr += 8;
                        NameBuffer = (_DWORD *)((char *)NameBuffer + EntrySize);
                        OutputBuffer[13 * EntryIndex2 + 13] ^= (OutputBuffer[13 * EntryIndex2 + 13] ^ ExtData) & 0x7FFFFFFF;
                    }
                    ++*OutputBuffer;
                } while (LoopIndex < EntryCount);
                Result = 1;
            }
            FreeAllocatedBuffers(BaseBuffer, 0, NameBufferCopy, ExtBuffer);
        }
    }
    return Result;
}

// QuerySystemInfoPart2 — 查询系统信息第二部分
// 分配 411 字节查询参数，调用 QuerySystemInfoAllocateBuffers 查询系统信息类 1 数据，遍历条目填充 24 字节每项的输出缓冲区
// 对应原始驱动 sub_1400494E8
char QuerySystemInfoPart2(_DWORD *OutputBuffer, unsigned int OutputBufferSize, _DWORD *pOutputSize)
{
    char Result;
    unsigned __int64 BufferSize;
    __int64 *QueryParam;
    unsigned int EntryCount;
    _DWORD *NameBuffer;
    void *BaseBuffer;
    void *NameBufferCopy;
    unsigned int LoopIndex;
    _OWORD *CurrentEntry;
    int ExtData;
    __int64 BaseBufferArray[7];
    unsigned int ActualEntryCount;
    _DWORD *NameBufferPtr;

    Result = 0;
    BufferSize = OutputBufferSize;
    if (OutputBufferSize >= 0x1C)
    {
        *OutputBuffer = 0;
        *pOutputSize = 28;
        QueryParam = GtAlloc(GtNtQuerySystemInformationFunc | GtDriverObject);
        GtWrite(GtNtQuerySystemInformationFunc | GtDriverObject, 0x100000018LL);
        GtWrite(GtEprocessField146 | 0x100, 0x11D49B1AEB004A02LL);
        GtWrite(GtEprocessField147 | 0x100, 0xBC59770450002391uLL);
        if (!QuerySystemInfoAllocateBuffers(
                1u,
                (__int64)QueryParam,
                1,
                BaseBufferArray,
                28,
                0,
                0,
                0,
                0,
                &NameBufferPtr,
                32,
                &ActualEntryCount))
        {
            EntryCount = ActualEntryCount;
            NameBuffer = NameBufferPtr;
            BaseBuffer = (void *)BaseBufferArray[0];
            NameBufferCopy = NameBufferPtr;
            if (ActualEntryCount)
            {
                LoopIndex = 0;
                CurrentEntry = (_OWORD *)(BaseBufferArray[0] + 8);
                do
                {
                    if (*OutputBuffer)
                    {
                        if (BufferSize < (unsigned int)*pOutputSize + 24)
                            break;
                        *pOutputSize = (unsigned int)*pOutputSize + 24;
                    }
                    {
                        __int64 EntryIndex = (unsigned int)*OutputBuffer;
                        if (*((_WORD *)CurrentEntry - 4) == 23)
                        {
                            *(_OWORD *)&OutputBuffer[6 * EntryIndex + 1] = *CurrentEntry;
                            OutputBuffer[6 * *OutputBuffer + 6] &= ~0x80000000;
                        }
                        else
                        {
                            OutputBuffer[6 * EntryIndex + 1] = *((_DWORD *)CurrentEntry - 1);
                            OutputBuffer[6 * *OutputBuffer + 6] |= 0x80000000;
                        }
                    }
                    ++LoopIndex;
                    CurrentEntry = (_OWORD *)((char *)CurrentEntry + 28);
                    *((_WORD *)&OutputBuffer[6 * *OutputBuffer + 5]) = *((_WORD *)CurrentEntry - 17);
                    {
                        __int64 EntryIndex2 = (unsigned int)*OutputBuffer + 1LL;
                        ExtData = *NameBuffer ^ OutputBuffer[6 * EntryIndex2];
                        NameBuffer += 8;
                        OutputBuffer[6 * EntryIndex2] ^= ExtData & 0x7FFFFFFF;
                    }
                    ++*OutputBuffer;
                } while (LoopIndex < EntryCount);
                Result = 1;
            }
            FreeAllocatedBuffers(BaseBuffer, 0, 0, NameBufferCopy);
        }
    }
    return Result;
}
// RemoveFromModuleLinkedList — 从模块链表中移除指定条目
// 从 GT 索引（ListType==1 时 GtEprocessField123，否则 GtEprocessField122）获取链表头，
// 遍历双向链表，找到匹配 pTargetEntry 的节点后，ObfDereferenceObject 再摘除并 ExFreePoolWithTag('IoRi')
// 对应原始驱动 sub_140045A38
char RemoveFromModuleLinkedList(PVOID *pTargetEntry, char ListType)
{
    char Result;
    enum _GLOBAL_TABLE_INDEX GtIndex;
    PVOID **pListHead;
    PVOID **pSentinel;
    PVOID *pCurrentNode;
    int IterationCount;

    Result = 0;
    GtIndex = GtDisableHookProtectionAddr2 | GtEprocessField123;
    if (ListType != 1)
        GtIndex = GtDisableHookProtectionAddr2 | GtEprocessField122;
    pListHead = (PVOID **)GtRead(GtIndex);
    pSentinel = pListHead;
    if (pListHead && MmIsAddressValid(pListHead) == 1)
    {
        pCurrentNode = *pSentinel;
        IterationCount = 0;
        while (pCurrentNode != (PVOID *)pSentinel)
        {
            if (pCurrentNode <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrentNode) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrentNode == pTargetEntry)
            {
                if (MmIsAddressValid(*pCurrentNode) == 1)
                {
                    PVOID *pPrevEntry;
                    PVOID **pNextEntry;

                    ObfDereferenceObject(pTargetEntry[2]);
                    pPrevEntry = (PVOID *)*pCurrentNode;
                    pNextEntry = (PVOID **)pCurrentNode[1];
                    pPrevEntry[1] = pNextEntry;
                    *pNextEntry = pPrevEntry;
                    ExFreePoolWithTag(pTargetEntry, 0x69526F49u);
                    return 1;
                }
                return Result;
            }
            pCurrentNode = (PVOID *)*pCurrentNode;
        }
    }
    return Result;
}

// RemoveObjectFromLinkedList — 从对象链表中移除（Win10+）
// 使用 GT 16859 验证函数，遍历 0x7F 个桶，在每个桶中线性搜索匹配句柄的条目，
// 通过 Next 指针（+40 偏移）重新链接实现移除
// 对应原始驱动 sub_140036F9C
char RemoveObjectFromLinkedList(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int BucketIndex;
    unsigned int EntryCount;
    _QWORD *pEntry;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (BucketIndex = 0; BucketIndex < 0x7F; ++BucketIndex)
        {
            EntryCount = 0;
            pEntry = pObjectTable;
            if (*pObjectTable)
            {
                while (ValidateFunc(*pEntry) && EntryCount <= 0x10000)
                {
                    CurrentEntry = *pEntry;
                    if (TargetHandle == *pEntry)
                    {
                        Success = 1;
                        *pEntry = *(_QWORD *)(CurrentEntry + 40);
                        break;
                    }
                    pEntry = (_QWORD *)(CurrentEntry + 40);
                    ++EntryCount;
                    if (!*(_QWORD *)(CurrentEntry + 40))
                        break;
                }
            }
            if (Success == 1)
                break;
            ++pObjectTable;
        }
    }
    return Success;
}

// RemoveObjectFromLinkedListLegacy — 从对象链表中移除（旧版 Win8）
// 使用 GT 16859 验证函数，遍历 0x7F 个桶，通过 Next 指针（+32 偏移）重新链接实现移除
// 与 Win10+ 版本区别在于 Next 指针偏移为 32 而非 40
// 对应原始驱动 sub_140037204
char RemoveObjectFromLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int BucketIndex;
    unsigned int EntryCount;
    _QWORD *pEntry;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (BucketIndex = 0; BucketIndex < 0x7F; ++BucketIndex)
        {
            EntryCount = 0;
            pEntry = pObjectTable;
            if (*pObjectTable)
            {
                while (ValidateFunc(*pEntry) && EntryCount <= 0x10000)
                {
                    CurrentEntry = *pEntry;
                    if (TargetHandle == *pEntry)
                    {
                        Success = 1;
                        *pEntry = *(_QWORD *)(CurrentEntry + 32);
                        break;
                    }
                    pEntry = (_QWORD *)(CurrentEntry + 32);
                    ++EntryCount;
                    if (!*(_QWORD *)(CurrentEntry + 32))
                        break;
                }
            }
            if (Success == 1)
                break;
            ++pObjectTable;
        }
    }
    return Success;
}

// RemoveObjectSingleLinkedListLegacy — 从单链表中移除（旧版 Win7）
// 使用 GT 16859 验证函数，遍历单链表（Next 在 +32 偏移），匹配句柄后通过重新链接移除
// 对应原始驱动 sub_14003746C
char RemoveObjectSingleLinkedListLegacy(_QWORD *pObjectTable, __int64 TargetHandle)
{
    char Success;
    unsigned __int8 (__fastcall *pValidateFunc)(_QWORD);
    unsigned __int8 (__fastcall *ValidateFunc)(_QWORD);
    unsigned int EntryIndex;
    __int64 CurrentEntry;

    Success = 0;
    pValidateFunc = (unsigned __int8 (__fastcall *)(_QWORD))GtRead(GtObjectTypeCheckFlag);
    ValidateFunc = pValidateFunc;
    if (pValidateFunc && pObjectTable && pValidateFunc(pObjectTable))
    {
        for (EntryIndex = 0; *pObjectTable && ValidateFunc(*pObjectTable) && EntryIndex <= 0x10000; ++EntryIndex)
        {
            CurrentEntry = *pObjectTable;
            if (TargetHandle == *pObjectTable)
            {
                Success = 1;
                *pObjectTable = *(_QWORD *)(CurrentEntry + 32);
                return Success;
            }
            pObjectTable = (_QWORD *)(CurrentEntry + 32);
        }
    }
    return Success;
}

// ResolveCreateFileRelocs — 解析 CreateFile 重定位（Win8 方案）
// 读取全局表索引 840 和 17305 获取偏移，遍历 PE 节区匹配子类型 1368 的目标，进入次级扫描搜索子类型 0x40000 的条目提取重定位偏移，写入全局表 0x34A 和 0x34B
// 对应原始驱动 sub_14001E340
__int64 ResolveCreateFileRelocs(__int64 TargetBase, ULONG TargetSize, __int64 Context, __int64 RelocBase)
{
    unsigned int SectionOffset;
    __int64 Result;
    int TargetOffset;
    char FoundFirstMatch;
    char FoundSecondStage;
    int LoopIndex;
    int CurrentOffset;
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    int EntrySize;
    __int64 SectionFlags;
    unsigned int SectionSize;
    int EntryField1;
    int EntryField2;
    unsigned int EntrySizeInner;
    __int64 SectionTypeInner;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    SectionOffset = GtRead(GtNtCreateFileSyscallResult);
    Result = GtRead(GtNtWriteFilePeSectionOffset | GtObjectTypeField08);
    TargetOffset = Result;
    if (SectionOffset && SectionOffset < TargetSize && (_DWORD)Result && (unsigned int)Result < TargetSize)
    {
        InitPESectionReadContext(
            TargetBase + SectionOffset,
            TargetSize - SectionOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);
        FoundFirstMatch = 0;
        FoundSecondStage = 0;
        LoopIndex = 0;
        while (1)
        {
            Result = ReadPESectionEntry(&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                return Result;
            CurrentOffset = EntryCumulSize + CumulativeSize;
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) != 1368 || (SectionFlags & 0x4000000) == 0 || !EntrySize)
            {
                if (*(_WORD *)(EntryDataPtr + 6) == 1066 && (SectionTypeInner & 0x200000000LL) != 0)
                {
                    Result = 1;
                    if (EntryField2 == 16 && FoundFirstMatch == 1)
                        FoundSecondStage = 1;
                    goto NEXT_ITER;
                }
                Result = 1;
                goto NEXT_ITER;
            }
            Result = (unsigned int)(CurrentOffset + EntrySize - TargetBase);
            if ((_DWORD)Result != TargetOffset)
            {
                if (FoundSecondStage == 1)
                {
                    if ((_DWORD)Result && (unsigned int)Result < TargetSize)
                    {
                        InitPESectionReadContext(
                            TargetBase + (unsigned int)Result,
                            TargetSize - Result,
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (__int64)&ReadContext);
                        {
                            char FoundInnerResult;
                            unsigned int InnerRelocOffset;
                            int InnerLoopIndex;
                            int InnerCurrentOffset;

                            FoundInnerResult = 0;
                            InnerRelocOffset = 0;
                            InnerLoopIndex = 0;
                            while (1)
                            {
                                Result = ReadPESectionEntry(&ReadContext, SectionEntry);
                                if ((_DWORD)Result)
                                    break;
                                InnerCurrentOffset = EntryCumulSize + CumulativeSize;
                                CumulativeSize += EntryCumulSize;
                                if (SectionTypeInner == 0x40000 && (Result = EntrySizeInner) != 0)
                                {
                                    InnerRelocOffset = InnerCurrentOffset + EntrySizeInner - TargetBase;
                                }
                                else if (EntryField1 == 8)
                                {
                                    if (InnerRelocOffset)
                                    {
                                        if (InnerRelocOffset < TargetSize)
                                        {
                                            Result = GtWrite(GtCallbackField116, RelocBase + InnerRelocOffset);
                                            FoundInnerResult = 1;
                                        }
                                    }
                                }
                                else
                                {
                                    Result = 1;
                                    if (FoundInnerResult == 1 && SectionFlags == 0x40000)
                                    {
                                        Result = SectionSize;
                                        if (SectionSize)
                                        {
                                            Result = InnerCurrentOffset + SectionSize - (unsigned int)TargetBase;
                                            if ((_DWORD)Result)
                                            {
                                                if ((unsigned int)Result < TargetSize)
                                                    return GtWrite(GtCallbackField117, RelocBase + (unsigned int)Result);
                                            }
                                        }
                                    }
                                }
                                if ((unsigned int)++InnerLoopIndex >= 0x12C)
                                    return Result;
                            }
                        }
                    }
                    return Result;
                }
                Result = 1;
                goto NEXT_ITER;
            }
            Result = 1;
            FoundFirstMatch = 1;
NEXT_ITER:
            if ((unsigned int)++LoopIndex >= 0x3E8)
                return Result;
        }
    }
    return Result;
}

// ParseNtImageSections2 — 解析 NT 映像节区 V2

// SendAtaScsiCommand — 发送 ATA/SCSI 命令
// 打开 SCSI 设备，分配 IRP 发送 SCSI INQUIRY 命令，获取 SCSI 设备列表，输出 24 字节每设备的 SCSI 信息结构
// 对应原始驱动 sub_140048CC0
char SendAtaScsiCommand(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    char Result;
    __int64 (__fastcall *SendDeviceIoControl)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    void (__fastcall *WaitForEvent)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD);
    __int64 CloseDeviceHandle;
    __int64 CloseHandle;
    __int64 DeviceObjectFromContext;
    __int64 IrpPtr;
    ULONG_PTR IrpResult;
    __int64 IrpStackLocation;
    char DiskDriverInfo;
    int IoStatus;
    unsigned int ScsiBufferSize;
    char *ScsiBuffer;
    __int64 (__fastcall *IrpPtr2)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    __int64 IrpStackLocation2;
    char DiskDriverInfo2;
    int IoStatus2;
    unsigned __int64 ScsiDeviceCount;
    char *SrcEntry;
    char *DstEntry;
    __int64 RemainingEntries;
    int TempValue;
    int WaitFlag;
    char DiskDriverInfo1;
    char RestoreFlag2;
    char RestoreFlag1;
    char RestoreFlag3;
    __int64 DeviceHandle;
    __int64 (__fastcall *DiskDriverInfoTable)(__int64, ULONG_PTR, __int64);
    __int64 (__fastcall *SendDeviceIoControl2)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    unsigned int OutputBufferSizeCopy;
    int IoStatusBlock;
    unsigned __int64 DataTransferSize;
    __int64 DeviceObjectHandle;
    void (__fastcall *CloseDeviceHandleFunc)(__int64);
    struct _KEVENT Event;
    void (__fastcall *CloseHandleFunc)(__int64);
    _QWORD ScsiOutputBuffer[2];
    int ScsiStatus;
    _DWORD Dst[10];
    _DWORD EncodedDevicePath[6];
    _OWORD DiskDriverInfoBuffer;

    OutputBufferSizeCopy = BufferSize;
    Result = 0;
    SendDeviceIoControl = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    SendDeviceIoControl2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    WaitForEvent = (void (__fastcall *)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField06);
    CloseDeviceHandle = GtRead(GtCloseHandleFunc);
    CloseDeviceHandleFunc = (void (__fastcall *)(__int64))CloseDeviceHandle;
    CloseHandle = GtRead(GtExFreePoolFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandle;
    if (SendDeviceIoControl && WaitForEvent && CloseDeviceHandle && CloseHandle)
    {
        EncodedDevicePath[0] = 4456540;
        EncodedDevicePath[1] = 7733349;
        EncodedDevicePath[2] = 6488169;
        EncodedDevicePath[3] = 6029413;
        EncodedDevicePath[4] = 6553685;
        EncodedDevicePath[5] = 112;
        if (OpenDeviceTarget((__int64)EncodedDevicePath, (__int64)&DeviceHandle, &DeviceObjectHandle) == 1)
        {
            memset(Dst, 0, sizeof(Dst));
            Dst[0] = 1025;
            Dst[2] = 512;
            Dst[3] = 256;
            Dst[4] = 1;
            DeviceObjectFromContext = GetDeviceObjectFromContext(DeviceHandle);
            if (DeviceObjectFromContext)
            {
                KeInitializeEvent(&Event, NotificationEvent, 0);
                ScsiOutputBuffer[0] = 0;
                ScsiOutputBuffer[1] = 0;
                ScsiStatus = 0;
                IrpPtr = SendDeviceIoControl(1179651, DeviceObjectFromContext, Dst, 40, (char *)ScsiOutputBuffer, 20u, 0, &Event, &IoStatusBlock);
                IrpResult = IrpPtr;
                if (IrpPtr)
                {
                    IrpStackLocation = *(_QWORD *)(IrpPtr + 184);
                    *(_QWORD *)(IrpStackLocation - 32) = DeviceObjectFromContext;
                    *(_QWORD *)(IrpStackLocation - 24) = DeviceHandle;
                    DiskDriverInfo = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, &DiskDriverInfoTable);
                    DiskDriverInfo1 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                    RestoreFlag1 = SwapDiskIrpFunctionPointer();
                    IoStatus = AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, IrpResult);
                    SetDiskDriverInfo(DiskDriverInfo, 0, &DiskDriverInfoBuffer);
                    if (IoStatus == 259)
                    {
                        WaitForEvent(&Event, 0, 0, 0, 0);
                        IoStatus = IoStatusBlock;
                    }
                    if (DiskDriverInfo1 == 1)
                        WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                    RestoreDiskIrpFunctionPointer(RestoreFlag1);
                    if (!IoStatus)
                    {
                        ScsiBufferSize = 12 * (ScsiStatus + 16);
                        ScsiBuffer = (char *)ExAlloc(PagedPool, ScsiBufferSize);
                        if (ScsiBuffer)
                        {
                            Dst[4] = 258;
                            KeInitializeEvent(&Event, NotificationEvent, 0);
                            WaitFlag = 0;
                            IrpPtr2 = SendDeviceIoControl2(1179651, DeviceObjectFromContext, Dst, 40, ScsiBuffer, ScsiBufferSize, WaitFlag, &Event, &IoStatusBlock);
                            SendDeviceIoControl2 = IrpPtr2;
                            if (IrpPtr2)
                            {
                                IrpStackLocation2 = *((_QWORD *)IrpPtr2 + 23);
                                *(_QWORD *)(IrpStackLocation2 - 32) = DeviceObjectFromContext;
                                *(_QWORD *)(IrpStackLocation2 - 24) = DeviceHandle;
                                DiskDriverInfo2 = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, &DiskDriverInfoTable);
                                RestoreFlag3 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                                RestoreFlag2 = SwapDiskIrpFunctionPointer();
                                IoStatus2 = AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, (ULONG_PTR)SendDeviceIoControl2);
                                SetDiskDriverInfo(DiskDriverInfo2, 0, &DiskDriverInfoBuffer);
                                if (IoStatus2 == 259)
                                {
                                    WaitForEvent(&Event, 0, 0, 0, 0);
                                    IoStatus2 = IoStatusBlock;
                                }
                                if (RestoreFlag3 == 1)
                                    WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                                RestoreDiskIrpFunctionPointer(RestoreFlag2);
                                if (!IoStatus2)
                                {
                                    ScsiDeviceCount = DataTransferSize / 0xC;
                                    *OutSize = (unsigned int)(DataTransferSize / 0xC) ? 24 * ((unsigned int)(DataTransferSize / 0xC) - 1) + 28 : 28;
                                    if (OutputBufferSizeCopy >= *OutSize)
                                    {
                                        memset(Buffer, 0, *OutSize);
                                        *(unsigned int *)Buffer = ScsiDeviceCount;
                                        if ((_DWORD)ScsiDeviceCount)
                                        {
                                            SrcEntry = ScsiBuffer + 4;
                                            DstEntry = Buffer + 8;
                                            RemainingEntries = (unsigned int)ScsiDeviceCount;
                                            do
                                            {
                                                *((_DWORD *)DstEntry - 1) = *((_DWORD *)SrcEntry - 1);
                                                *(_WORD *)DstEntry = *((_WORD *)SrcEntry + 1);
                                                DstEntry += 24;
                                                *((_WORD *)DstEntry - 6) = *(_WORD *)SrcEntry;
                                                TempValue = *((_DWORD *)SrcEntry + 1);
                                                SrcEntry += 12;
                                                *((_DWORD *)DstEntry - 2) = TempValue | 0x80000000;
                                                --RemainingEntries;
                                            } while (RemainingEntries);
                                        }
                                        Result = 1;
                                    }
                                }
                            }
                            ExFree(ScsiBuffer);
                        }
                    }
                }
            }
            CloseDeviceHandleFunc(DeviceHandle);
            CloseHandleFunc(DeviceObjectHandle);
        }
    }
    return Result;
}


// =======================================================================
// 新增函数实现（从 IDA 反编译）
// =======================================================================

// MiniFilterStreamHandleCleanup — Minifilter 流句柄清理
// 对应原始驱动 sub_14001AE7C
char MiniFilterStreamHandleCleanup(PRKPROCESS PROCESS, __int64 CallbackContext, ULONG64 ContextFlag, __int64 BaseOffset, __int64 (*CallbackFunc)(void))
{
    ULONG64 ProtectedBase;
    __int64 SystemRootForThread;
    int CallbackResult;
    int IsSuccess;
    int CallbackResult2;

    MiniFilterOpLockPre(PROCESS, CallbackContext, ContextFlag, 0);
    if (CheckProtectedEntry((__int64)PROCESS))
    {
        ProtectedBase = GtRead(GtEprocessModuleListOffset | GtDriverObject);
        if (ProtectedBase
            || BaseOffset
            && (SystemRootForThread = GetSystemRootForThread(PROCESS)) != 0
            && (ProtectedBase = SystemRootForThread + BaseOffset,
                GtWrite(GtEprocessModuleListOffset | GtDriverObject, SystemRootForThread + BaseOffset),
                ProtectedBase))
        {
            MiniFilterOpLockPre(PROCESS, CallbackContext, ProtectedBase, 1);
        }
    }
    MiniFilterOpLockPost(PROCESS, 0, CallbackContext);
    MiniFilterOpLockPost(PROCESS, 1, CallbackContext);
    GtRead(GtEprocessField28);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        {
            IsSuccess = CallbackResult2;
            return IsSuccess >= 0;
        }
        CallbackResult = InvokeCallbackWithZeroArg(
            (__int64)PROCESS,
            CallbackContext,
            0,
            (__int64(__fastcall *)(__int64, __int64, __int64, ULONG64))CallbackFunc);
    }
    else
    {
        CallbackResult = InvokeNullCallback(
            (__int64)PROCESS,
            CallbackContext,
            0,
            (__int64(*)(void))CallbackFunc);
    }
    IsSuccess = CallbackResult;
    return IsSuccess >= 0;
}
// ParseDriverInitSection — 解析驱动初始化节区
// 对应原始驱动 sub_140087580
void ParseDriverInitSection(__int64 PeBuffer, unsigned int PeSize, __int64 RelocBase)
{
    int LoopIndex;
    unsigned int ExportByNameInPeBody;
    __int64 ExportOffset;
    unsigned int PESectionByName;
    unsigned int PESectionByNameReturnVa;
    unsigned int SectionEnd;
    int SectionEnd2;
    unsigned int TargetRva;
    int LoopIndex2;
    int SectionEnd3;
    __int16 SectionType;
    unsigned int RelocRva;
    unsigned int EntryIndex;
    int SectionEnd4;
    __int64 BaseOffset;
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    int FieldValue;
    int FieldValue2;
    __int64 SectionCharacteristics;
    int FieldValue3;
    int FieldValue4;
    __int64 SectionFlags;
    unsigned int EntryCount;
    unsigned int SectionSize;
    __int64 SectionDataPtr;
    _QWORD FuncNameBuffer[2];
    _DWORD Dst[16];

    if (!RelocBase)
        return;

    LoopIndex = 0;
    strcpy((char *)FuncNameBuffer, "DllInitialize");
    FuncNameBuffer[1] = 0;
    ExportByNameInPeBody = FindExportByNameInPeBody((PUCHAR)PeBuffer, PeSize, (char *)FuncNameBuffer, 0);
    ExportOffset = ExportByNameInPeBody;
    if (!ExportByNameInPeBody)
        return;
    if (ExportByNameInPeBody >= PeSize || ExportByNameInPeBody + 4096 >= PeSize)
        return;

    FuncNameBuffer[0] = 1414090313;  // "INIT" as DWORD
    PESectionByName = FindPESectionByName((PUCHAR)PeBuffer, PeSize, (char *)FuncNameBuffer);
    PESectionByNameReturnVa = FindPESectionByNameReturnVa((PUCHAR)PeBuffer, PeSize, (char *)FuncNameBuffer);
    if (!PESectionByName || !PESectionByNameReturnVa)
        return;
    if (PESectionByName >= PeSize || PESectionByNameReturnVa >= PeSize)
        return;

    SectionEnd = PESectionByNameReturnVa + PESectionByName;
    if (SectionEnd >= PeSize)
        return;

    InitPESectionReadContext((PUCHAR)(PeBuffer + ExportOffset), 4096, 2, 0, -1, 0, 0, (PUCHAR)&ReadContext);
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
    {
        SectionEnd2 = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;
        if ((unsigned __int16)(*(_WORD *)(SectionDataPtr + 6) - 1368) <= 1u)
        {
            if (FieldValue)
            {
                TargetRva = SectionEnd2 + FieldValue - PeBuffer;
                if (TargetRva && TargetRva < PeSize && (PESectionByName > TargetRva || TargetRva >= SectionEnd))
                {
                    ExportOffset = TargetRva;
                    break;
                }
            }
        }
        if ((unsigned int)++LoopIndex >= 0x14)
            break;
    }

    if ((unsigned int)ExportOffset < PeSize && (int)ExportOffset + 4096 < PeSize)
    {
        InitPESectionReadContext((PUCHAR)(PeBuffer + (unsigned int)ExportOffset), 4096, 2, 0, -1, 0, 0, (PUCHAR)&ReadContext);
        memset(Dst, 0, sizeof(Dst));
        LoopIndex2 = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            SectionEnd3 = SectionSize + (int)CumulativeSize;
            CumulativeSize += SectionSize;
            SectionType = *(_WORD *)(SectionDataPtr + 6);
            if (SectionType == 1298 && SectionFlags == 0x40000)
            {
                if (FieldValue4 && SectionCharacteristics == 64)
                {
                    RelocRva = SectionEnd3 + FieldValue4 - PeBuffer;
                    if (RelocRva && RelocRva < PeSize)
                        Dst[FieldValue3] = RelocRva;
                }
            }
            if (SectionType == 1294 && SectionCharacteristics == 0x40000)
            {
                if (FieldValue2 && SectionFlags == 64 && EntryCount < 0x10)
                {
                    EntryIndex = SectionEnd3 + FieldValue2 - PeBuffer;
                    if (EntryIndex && EntryIndex < PeSize)
                    {
                        SectionEnd4 = Dst[EntryCount];
                        if (SectionEnd4 && EntryIndex == (unsigned int)SectionEnd4)
                        {
                            BaseOffset = EntryIndex;
                            GtWrite(GtFltPeSectionOfs6 | GtEprocessField22, EntryIndex);
                            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr6 | GtEprocessField22), BaseOffset + RelocBase);
                            return;
                        }
                    }
                }
            }
            if ((unsigned int)++LoopIndex2 >= 0x12C)
                return;
        }
    }
}
// =======================================================================
// 新增函数实现（从 IDA 反编译）
// =======================================================================

// KernelNotifyRoutine — 内核通知例程
// 对应原始驱动 sub_140019CFC
// 调用 MiniFilterTeardownRoutine 转发通知，IsAddOperation=1
__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 1);
}

// KernelNotifyRoutineEx — 内核通知例程扩展
// 对应原始驱动 sub_140019D04
// 调用 MiniFilterTeardownRoutine 转发通知，IsAddOperation=0
__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 0);
}

// PowerCallbackRoutine — 电源回调处理例程
// 对应原始驱动 sub_140011240
// 从内核地址读取数据到用户缓冲区，按页映射内存，通过 ReadObjectNameFromCallback 或 ReadNameFunc 读取对象名称，逐页拷贝
__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize)
{
    char Success;
    __int64 MapMemoryFunc;
    __int64 MapFunc;
    __int64 ZeroFunc;
    __int64 ReadNameFunc;
    __int64 UnmapFunc;
    __int64 FreeFunc;
    __int64 FreeFunc2;
    volatile void *TargetBuffer;
    unsigned int ReadSize;
    unsigned __int64 CurrentAddress;
    unsigned __int64 RemainingSize;
    char *OutputPtr;
    unsigned int PageRemainder;
    unsigned int BytesCopied;
    char PageSuccess;
    __int64 MappedMemory;
    __int64 MappedBuffer;
    __int64 MappedBuffer2;
    __int64 ObjectNameFromCallback;
    char CopySuccess;
    __int64 (__fastcall *ReadNameFuncTyped)(__int64, _QWORD, __int64);
    __int64 (__fastcall *MapMemoryFuncTyped)(unsigned __int64, __int64, _QWORD, _QWORD, _QWORD);
    void (__fastcall *UnmapFuncTyped)(__int64, __int64);
    void (__fastcall *MapFuncTyped)(__int64);
    void (__fastcall *FreeFuncTyped)(__int64);
    void (__fastcall *ZeroFuncTyped)(__int64, _QWORD, _QWORD);
    void (__fastcall *FreeFunc2Typed)(__int64);
    int SizeCopy;

    Success = 0;
    if (InputBuffer)
    {
        if (BufferSize == 24
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 3) < MmUserProbeAddress)
        {
            MapMemoryFunc = GtRead(GtAllocPhysPagesFunc);
            MapFunc = GtRead(GtMapPhysPagesFunc);
            MapFuncTyped = (void (__fastcall *)(__int64))MapFunc;
            ZeroFunc = GtRead(GtZeroPagesFunc);
            ZeroFuncTyped = (void (__fastcall *)(__int64, _QWORD, _QWORD))ZeroFunc;
            ReadNameFunc = GtRead(GtMapMemoryFunc);
            ReadNameFuncTyped = (__int64 (__fastcall *)(__int64, _QWORD, __int64))ReadNameFunc;
            UnmapFunc = GtRead(GtUnmapMemoryFunc);
            UnmapFuncTyped = (void (__fastcall *)(__int64, __int64))UnmapFunc;
            FreeFunc = GtRead(GtFreeMemoryFunc);
            FreeFuncTyped = (void (__fastcall *)(__int64))FreeFunc;
            FreeFunc2 = GtRead(GtFreePagesFunc);
            FreeFunc2Typed = (void (__fastcall *)(__int64))FreeFunc2;
            if (MapMemoryFunc && MapFunc && ZeroFunc && ReadNameFunc && UnmapFunc && FreeFunc && FreeFunc2)
            {
                ProbeForRead(InputBuffer, 0x18u, 4u);
                TargetBuffer = InputBuffer[2];
                if (TargetBuffer)
                {
                    ReadSize = *((_DWORD *)InputBuffer + 2);
                    if (ReadSize)
                    {
                        if (ReadSize < (unsigned __int64)MmSystemRangeStart
                            && *InputBuffer >= MmSystemRangeStart
                            && (char *)*InputBuffer + ReadSize >= MmSystemRangeStart
                            && (unsigned __int64)TargetBuffer < MmUserProbeAddress
                            && (unsigned __int64)TargetBuffer + ReadSize < MmUserProbeAddress)
                        {
                            ProbeForWrite(TargetBuffer, ReadSize, 1u);
                            CurrentAddress = (unsigned __int64)*InputBuffer;
                            RemainingSize = *((unsigned int *)InputBuffer + 2);
                            SizeCopy = *((_DWORD *)InputBuffer + 2);
                            OutputPtr = (char *)InputBuffer[2];
                            if (*InputBuffer >= MmSystemRangeStart
                                && RemainingSize < (unsigned __int64)MmSystemRangeStart
                                && CurrentAddress + (unsigned int)RemainingSize > (unsigned __int64)MmSystemRangeStart)
                            {
                                PageRemainder = 4096 - (CurrentAddress & 0xFFF);
                                BytesCopied = 0;
                                while (BytesCopied < (unsigned int)RemainingSize)
                                {
                                    if ((unsigned int)RemainingSize - BytesCopied < PageRemainder)
                                        PageRemainder = RemainingSize - BytesCopied;
                                    PageSuccess = 0;
                                    CopySuccess = 0;
                                    if (CheckMemoryValid((void *)CurrentAddress) == 1)
                                    {
                                        MappedMemory = MapMemoryFuncTyped(CurrentAddress & 0xFFFFFFFFFFFFF000uLL, 4096, 0, 0, 0);
                                        if (MappedMemory)
                                        {
                                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
                                            {
                                                ZeroFuncTyped(MappedMemory, 0, 0);
                                                ObjectNameFromCallback = ReadObjectNameFromCallback(
                                                    MappedMemory,
                                                    16,
                                                    ReadNameFuncTyped);
                                                if (ObjectNameFromCallback)
                                                {
                                                    memmove(
                                                        OutputPtr,
                                                        (const void *)(ObjectNameFromCallback + (CurrentAddress & 0xFFF)),
                                                        PageRemainder);
                                                    Success = 1;
                                                    CopySuccess = 1;
                                                }
                                                FreeFuncTyped(MappedMemory);
                                            }
                                            else
                                            {
                                                MapFuncTyped(MappedMemory);
                                                MappedBuffer = ReadNameFuncTyped(MappedMemory, 0, 1);
                                                MappedBuffer2 = MappedBuffer;
                                                if (MappedBuffer)
                                                {
                                                    memmove(
                                                        OutputPtr,
                                                        (const void *)(MappedBuffer + (CurrentAddress & 0xFFF)),
                                                        PageRemainder);
                                                    Success = 1;
                                                    CopySuccess = 1;
                                                    UnmapFuncTyped(MappedBuffer2, MappedMemory);
                                                }
                                            }
                                            FreeFunc2Typed(MappedMemory);
                                            PageSuccess = CopySuccess;
                                        }
                                    }
                                    if (!PageSuccess)
                                        memset(OutputPtr, 0, PageRemainder);
                                    if (BytesCopied)
                                        PageRemainder = 4096;
                                    BytesCopied += 4096;
                                    CurrentAddress += PageRemainder;
                                    OutputPtr += PageRemainder;
                                    LODWORD_LV(RemainingSize) = SizeCopy;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}

// PowerCallbackUnregister — 卸载电源回调
// 对应原始驱动 sub_140011630
// 将指定进程的源缓冲区数据拷贝到目标缓冲区，使用 KeStackAttachProcess 附加到目标进程上下文后执行内存操作
__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize)
{
    char Success;
    HANDLE ProcessHandle;
    unsigned int TargetSize;
    HANDLE TargetBufferVal;
    PVOID SourceBuffer;
    NTSTATUS AllocStatus;
    int LookupStatus;
    const void *SourcePtr;
    unsigned int BufferSizeCopy;
    void *TargetPtr;
    PEPROCESS Process;
    unsigned int SizeVal;
    HANDLE TargetHandle;
    HANDLE *InputBufferPtr;
    HANDLE SourceHandle;
    PRKPROCESS ProcessObject;
    struct _KAPC_STATE ApcState;

    Success = 0;
    Process = 0;
    if (InputBuffer)
    {
        if (BufferSize == 40
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 5) < MmUserProbeAddress)
        {
            ProbeForRead(InputBuffer, 0x28u, 4u);
            InputBufferPtr = InputBuffer;
            if (*InputBuffer)
            {
                if (InputBuffer[1])
                {
                    ProcessHandle = InputBuffer[4];
                    if (ProcessHandle)
                    {
                        TargetSize = *((_DWORD *)InputBuffer + 6);
                        if (TargetSize)
                        {
                            TargetBufferVal = InputBuffer[2];
                            if (TargetBufferVal)
                            {
                                if (TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)TargetBufferVal < MmUserProbeAddress
                                    && (unsigned __int64)TargetBufferVal + TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)ProcessHandle < MmUserProbeAddress
                                    && (unsigned __int64)ProcessHandle + TargetSize < MmUserProbeAddress)
                                {
                                    ProbeForWrite(ProcessHandle, TargetSize, 1u);
                                    SourceBuffer = ExAlloc(NonPagedPool, *((unsigned int *)InputBuffer + 6));
                                    if (SourceBuffer)
                                    {
                                        AllocStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
                                        LookupStatus = AllocStatus;
                                        if (!InputBuffer[1] && AllocStatus >= 0)
                                            InputBuffer[1] = Process;
                                        if (ValidateProcessObject((struct _KPROCESS *)InputBuffer[1], 0) == 1)
                                        {
                                            ProcessObject = (PRKPROCESS)InputBuffer[1];
                                            SourceHandle = InputBuffer[2];
                                            SourcePtr = SourceHandle;
                                            SizeVal = *((_DWORD *)InputBuffer + 6);
                                            BufferSizeCopy = SizeVal;
                                            TargetHandle = InputBuffer[4];
                                            TargetPtr = TargetHandle;
                                            KeStackAttachProcess(ProcessObject, &ApcState);
                                            memset(SourceBuffer, 0, BufferSizeCopy);
                                            memmove(SourceBuffer, SourcePtr, BufferSizeCopy);
                                            Success = 1;
                                            KeUnstackDetachProcess(&ApcState);
                                            memmove(TargetPtr, SourceBuffer, BufferSizeCopy);
                                        }
                                        if (LookupStatus >= 0)
                                            ObfDereferenceObject(Process);
                                        ExFree(SourceBuffer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}

// ShutdownCallbackUnregister — 卸载关机回调
// 对应原始驱动 sub_1400118F4
// 将目标缓冲区的数据写入到指定进程的源地址，使用 WritePhysicalMemoryBuffer 进行物理内存写入
__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize)
{
    bool Success;
    PRKPROCESS TargetBuffer;
    unsigned int TargetSize;
    PRKPROCESS SourceBuffer;
    PVOID AllocBuffer;
    NTSTATUS LookupStatus;
    int Status;
    PRKPROCESS SourcePtr;
    unsigned int BufferSizeCopy;
    PEPROCESS Process;
    PVOID AllocBufferPtr;
    unsigned int SizeVal;
    PRKPROCESS SourceBufferPtr;
    PRKPROCESS TargetBufferPtr;
    PRKPROCESS ProcessObject;
    struct _KAPC_STATE ApcState;

    Success = 0;
    Process = 0;
    if (InputBuffer)
    {
        if (BufferSize == 40
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 5) < MmUserProbeAddress)
        {
            AllocBufferPtr = 0;
            ProbeForRead(InputBuffer, 0x28u, 4u);
            if (*InputBuffer)
            {
                if (InputBuffer[1])
                {
                    TargetBuffer = InputBuffer[4];
                    if (TargetBuffer)
                    {
                        TargetSize = *((_DWORD *)InputBuffer + 6);
                        if (TargetSize)
                        {
                            SourceBuffer = InputBuffer[2];
                            if (SourceBuffer)
                            {
                                if (TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)SourceBuffer < MmUserProbeAddress
                                    && (unsigned __int64)SourceBuffer + TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)TargetBuffer < MmUserProbeAddress
                                    && (unsigned __int64)TargetBuffer + TargetSize < MmUserProbeAddress)
                                {
                                    ProbeForRead(TargetBuffer, TargetSize, 1u);
                                    AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)InputBuffer + 6));
                                    AllocBufferPtr = AllocBuffer;
                                    if (AllocBuffer)
                                    {
                                        LookupStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
                                        Status = LookupStatus;
                                        if (!InputBuffer[1] && LookupStatus >= 0)
                                            InputBuffer[1] = Process;
                                        if (ValidateProcessObject(InputBuffer[1], 0) == 1)
                                        {
                                            ProcessObject = InputBuffer[1];
                                            SourceBufferPtr = InputBuffer[2];
                                            SourcePtr = SourceBufferPtr;
                                            BufferSizeCopy = *((_DWORD *)InputBuffer + 6);
                                            SizeVal = BufferSizeCopy;
                                            TargetBufferPtr = InputBuffer[4];
                                            memmove(AllocBuffer, TargetBufferPtr, BufferSizeCopy);
                                            KeStackAttachProcess(InputBuffer[1], &ApcState);
                                            ProbeForRead(SourcePtr, BufferSizeCopy, 1u);
                                            Success = WritePhysicalMemoryBuffer(
                                                (unsigned __int64)SourcePtr,
                                                AllocBuffer,
                                                BufferSizeCopy,
                                                1,
                                                0) == 1;
                                            KeUnstackDetachProcess(&ApcState);
                                        }
                                        if (Status >= 0)
                                            ObfDereferenceObject(Process);
                                        ExFree(AllocBuffer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}

// EnumKernelModules — 枚举内核模块
// 对应原始驱动 sub_1400669B8
// 读取 GT 895(NDIS 节区扫描结果)获取内核模块链表头，遍历内核模块结构链表
// 根据 GT 867(构建号)选择不同结构偏移映射：<0x60028 使用旧版偏移，>=0x60028 使用新版偏移
// 每项输出 156 个 DWORD(624 字节)，含模块基址、大小、标志、名称字符串等
char EnumKernelModules(__int64 UnusedParam1, __int64 UnusedParam2, _DWORD *pOutputBuffer, unsigned int BufferSize)
{
    SIZE_T RemainingSize;
    char Result;
    _QWORD *pModuleListHead;
    unsigned int BuildNumber;
    unsigned __int64 MaxCount;
    _QWORD *pCurrentEntry;
    PVOID MinAddress;
    unsigned int ModuleIndex;
    unsigned __int64 EntryOffset;
    unsigned __int16 NameLength;
    __int64 OutputIndex;
    _OWORD *pOutputEntry;
    _OWORD *pSrcEntry;
    __int64 CopyCount;
    unsigned __int64 EntryOffset2;
    unsigned __int64 EntryOffset3;
    unsigned __int64 EntryOffset4;
    unsigned __int16 NameLength2;
    __int64 OutputIndex2;
    _OWORD *pOutputEntry2;
    _OWORD *pSrcEntry2;
    __int64 CopyCount2;
    unsigned __int64 EntryOffset5;
    unsigned __int16 NameLength3;
    __int64 OutputIndex3;
    _OWORD *pOutputEntry3;
    _OWORD *pSrcEntry3;
    __int64 CopyCount3;

    RemainingSize = BufferSize;
    Result = 0;
    pModuleListHead = (_QWORD *)GtRead(GtEprocessExtField41);
    if (!pModuleListHead)
    {
        InitKernelDataSectionTable();
        pModuleListHead = (_QWORD *)GtRead(GtEprocessExtField41);
    }
    BuildNumber = GtRead(GtEprocessExtField13);
    if (pModuleListHead
        && pModuleListHead > MmSystemRangeStart
        && BuildNumber >= 0x60000
        && pOutputBuffer
        && (unsigned int)RemainingSize >= 0x278
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + RemainingSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, RemainingSize, 4u);
        memset(pOutputBuffer, 0, RemainingSize);
        MaxCount = (RemainingSize - 632) / 0x270 + 1;
        *(_DWORD *)pOutputBuffer = 0;
        pCurrentEntry = (_QWORD *)*pModuleListHead;
        MinAddress = MmSystemRangeStart;
        if (*pModuleListHead > (unsigned __int64)MmSystemRangeStart && pCurrentEntry != pModuleListHead)
        {
            ModuleIndex = 0;
            if (BuildNumber >= 0x60028)
            {
                EntryOffset3 = (unsigned __int64)(pCurrentEntry - 154);
                if (BuildNumber >= 0x60053)
                {
                    while (ModuleIndex < 0x1000 && EntryOffset3 > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset3) == 1 && (_DWORD)MaxCount)
                    {
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset3;
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset3 + 560);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset3 + 1120);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset3 + 1216);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset3 + 528);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset3 + 532);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset3 + 536);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset3 + 564);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset3 + 1220);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset3 + 1224);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset3 + 1192);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset3 + 1112);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset3 + 4);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset3 + 1320);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset3 + 1328);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset3 + 540);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset3 + 580);
                        NameLength3 = *(_WORD *)(EntryOffset3 + 8);
                        OutputIndex3 = (unsigned int)*(_DWORD *)pOutputBuffer;
                        if (NameLength3 >= 0x200u)
                        {
                            pOutputEntry3 = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex3))[24];
                            pSrcEntry3 = (_OWORD *)(EntryOffset3 + 10);
                            CopyCount3 = 4;
                            do
                            {
                                *pOutputEntry3 = *pSrcEntry3;
                                pOutputEntry3[1] = pSrcEntry3[1];
                                pOutputEntry3[2] = pSrcEntry3[2];
                                pOutputEntry3[3] = pSrcEntry3[3];
                                pOutputEntry3[4] = pSrcEntry3[4];
                                pOutputEntry3[5] = pSrcEntry3[5];
                                pOutputEntry3[6] = pSrcEntry3[6];
                                pOutputEntry3 += 8;
                                *(pOutputEntry3 - 1) = pSrcEntry3[7];
                                pSrcEntry3 += 8;
                                --CopyCount3;
                            }
                            while (CopyCount3);
                        }
                        else
                        {
                            memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex3 + 24], (const void *)(EntryOffset3 + 10), NameLength3);
                        }
                        ++*(_DWORD *)pOutputBuffer;
                        LODWORD_LV(MaxCount) = MaxCount - 1;
                        EntryOffset5 = *(_QWORD *)(EntryOffset3 + 1232);
                        if ((_QWORD *)EntryOffset5 == pModuleListHead)
                            break;
                        MinAddress = MmSystemRangeStart;
                        if (EntryOffset5 <= (unsigned __int64)MmSystemRangeStart)
                            break;
                        EntryOffset3 = EntryOffset5 - 1232;
                        ++ModuleIndex;
                    }
                }
                else
                {
                    while (ModuleIndex < 0x1000 && EntryOffset3 > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset3) == 1 && (_DWORD)MaxCount)
                    {
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset3;
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset3 + 560);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset3 + 1120);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset3 + 1216);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset3 + 528);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset3 + 532);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset3 + 536);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset3 + 564);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset3 + 1220);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset3 + 1224);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset3 + 1192);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset3 + 1112);
                        ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset3 + 4);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset3 + 1320);
                        *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset3 + 1328);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset3 + 540);
                        *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset3 + 580);
                        NameLength2 = *(_WORD *)(EntryOffset3 + 8);
                        OutputIndex2 = (unsigned int)*(_DWORD *)pOutputBuffer;
                        if (NameLength2 >= 0x200u)
                        {
                            pOutputEntry2 = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex2))[24];
                            pSrcEntry2 = (_OWORD *)(EntryOffset3 + 10);
                            CopyCount2 = 4;
                            do
                            {
                                *pOutputEntry2 = *pSrcEntry2;
                                pOutputEntry2[1] = pSrcEntry2[1];
                                pOutputEntry2[2] = pSrcEntry2[2];
                                pOutputEntry2[3] = pSrcEntry2[3];
                                pOutputEntry2[4] = pSrcEntry2[4];
                                pOutputEntry2[5] = pSrcEntry2[5];
                                pOutputEntry2[6] = pSrcEntry2[6];
                                pOutputEntry2 += 8;
                                *(pOutputEntry2 - 1) = pSrcEntry2[7];
                                pSrcEntry2 += 8;
                                --CopyCount2;
                            }
                            while (CopyCount2);
                        }
                        else
                        {
                            memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex2 + 24], (const void *)(EntryOffset3 + 10), NameLength2);
                        }
                        ++*(_DWORD *)pOutputBuffer;
                        LODWORD_LV(MaxCount) = MaxCount - 1;
                        EntryOffset4 = *(_QWORD *)(EntryOffset3 + 1232);
                        if ((_QWORD *)EntryOffset4 == pModuleListHead)
                            break;
                        MinAddress = MmSystemRangeStart;
                        if (EntryOffset4 <= (unsigned __int64)MmSystemRangeStart)
                            break;
                        EntryOffset3 = EntryOffset4 - 1232;
                        ++ModuleIndex;
                    }
                }
            }
            else
            {
                EntryOffset = (unsigned __int64)(pCurrentEntry - 1);
                while (ModuleIndex < 0x1000 && EntryOffset > (unsigned __int64)MinAddress && CheckMemoryValid((void *)EntryOffset) == 1 && (_DWORD)MaxCount)
                {
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 2] = EntryOffset;
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 4] = *(_DWORD *)(EntryOffset + 708);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 5] = *(_DWORD *)(EntryOffset + 1264);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 6] = *(unsigned __int8 *)(EntryOffset + 1360);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 7] = *(_DWORD *)(EntryOffset + 676);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 8] = *(_DWORD *)(EntryOffset + 680);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 9] = *(_DWORD *)(EntryOffset + 684);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 10] = *(_DWORD *)(EntryOffset + 712);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 11] = *(_DWORD *)(EntryOffset + 1364);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 12] = *(_DWORD *)(EntryOffset + 1368);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 13] = *(_DWORD *)(EntryOffset + 1336);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 14] = *(_DWORD *)(EntryOffset + 1256);
                    ((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 23] = *(_DWORD *)(EntryOffset + 152);
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 154] = *(_QWORD *)(EntryOffset + 96);
                    *(_QWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 156] = *(_QWORD *)(EntryOffset + 104);
                    *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 15] = *(_OWORD *)(EntryOffset + 688);
                    *(_OWORD *)&((_DWORD *)pOutputBuffer)[156 * *(_DWORD *)pOutputBuffer + 19] = *(_OWORD *)(EntryOffset + 724);
                    NameLength = *(_WORD *)(EntryOffset + 156);
                    OutputIndex = (unsigned int)*(_DWORD *)pOutputBuffer;
                    if (NameLength >= 0x200u)
                    {
                        pOutputEntry = &((_OWORD *)((_DWORD *)pOutputBuffer + 156 * OutputIndex))[24];
                        pSrcEntry = (_OWORD *)(EntryOffset + 158);
                        CopyCount = 4;
                        do
                        {
                            *pOutputEntry = *pSrcEntry;
                            pOutputEntry[1] = pSrcEntry[1];
                            pOutputEntry[2] = pSrcEntry[2];
                            pOutputEntry[3] = pSrcEntry[3];
                            pOutputEntry[4] = pSrcEntry[4];
                            pOutputEntry[5] = pSrcEntry[5];
                            pOutputEntry[6] = pSrcEntry[6];
                            pOutputEntry += 8;
                            *(pOutputEntry - 1) = pSrcEntry[7];
                            pSrcEntry += 8;
                            --CopyCount;
                        }
                        while (CopyCount);
                    }
                    else
                    {
                        memmove(&((_DWORD *)pOutputBuffer)[156 * OutputIndex + 24], (const void *)(EntryOffset + 158), NameLength);
                    }
                    ++*(_DWORD *)pOutputBuffer;
                    LODWORD_LV(MaxCount) = MaxCount - 1;
                    EntryOffset2 = *(_QWORD *)(EntryOffset + 8);
                    if ((_QWORD *)EntryOffset2 == pModuleListHead)
                        break;
                    MinAddress = MmSystemRangeStart;
                    if (EntryOffset2 <= (unsigned __int64)MmSystemRangeStart)
                        break;
                    EntryOffset = EntryOffset2 - 8;
                    ++ModuleIndex;
                }
            }
        }
        return *(_DWORD *)pOutputBuffer != 0;
    }
    return Result;
}

// =======================================================================
// 以下函数已移至其他源文件实现（此处仅保留注释）：
// FindKernelDataSectionOffsetWin7 — SSDT.c
// FindKernelDataSectionOffsetWin10 — SSDT.c
// FindKernelDataSectionPair — SSDT.c
// DispatchParseNtExportSectionsV2 — SystemInfo.c
// ValidateIoPortSection — SystemInfo.c
// ParseNtExportSectionsV4 — SystemInfo.c
// ReadIdtr — SystemInfo.c
// FindPESectionByIndex — ModuleMgmt.c
// FindSsdtOffsetInNtFile — SSDT.c
// =======================================================================
