// Minifilter.c — 文件系统 Minifilter
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"

// 全局变量声明
extern KMUTEX g_Mutex;
extern volatile PVOID g_Pointer;

// 前向声明 — 这些函数在被定义之前已被调用
__int64 (__fastcall *__fastcall FsFilterCreateCallback(__int64 FilterContext))(__int64);
__int64 MiniFilterTeardownRoutine(void *NameBuffer, size_t BufferSize, char IsAddOperation);
void ParseMiniFilterRegSections(void);
__int64 EnumMiniFilterVolumeList(_QWORD **ListHead, __int64 GuidValue, __int64 OutputBuffer, _DWORD *EntryCount);
__int64 OpenAndWaitMiniFilterFile(__int64 ContextBlock);
__int64 CopyServiceTableFromSection(__int64 OutputTable);
__int64 CopyWin32kServiceTableFromFilter(__int64 OutputTable);
__int64 CopyServiceTableWithFilter(__int64 SourceTable);
__int64 CopyServiceTablePartial(__int64 SourceTable);
__int64 ResolveContextMemoryBlocks(__int64 pContextTable, unsigned int EntryCount);

// InitMiniFilterDriver — 初始化 Minifilter 驱动
// 对应原始驱动 sub_140011F6C
// 解析注册表获取 Minifilter 信息，遍历列表枚举卷信息
bool InitMiniFilterDriver(__int64 Reserved, __int64 Reserved2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG64 BufferSizeCopy;
    bool Result;
    _QWORD **ListHead1, **ListHead2, **ListHead3, **ListHead4Ptr;
    __int64 ListHead4;
    ULONG64 RemainingCount;
    int CountBefore1, CountBefore2, CountBefore3;
    int CurrentCount;
    bool HasItems;
    int GuidHigh;
    __int64 GuidLow;
    int GuidFlag;

    BufferSizeCopy = BufferSize;
    Result = 0;

    if (!GtRead(2074))
        ParseMiniFilterRegSections();

    ListHead1 = (_QWORD **)GtRead(2074);
    ListHead2 = (_QWORD **)GtRead(2176 | 0x100);
    ListHead3 = (_QWORD **)GtRead(2177 | 0x100);
    ListHead4 = GtRead(2073);
    ListHead4Ptr = (_QWORD **)ListHead4;

    if ((!ListHead1 && !ListHead2 && !ListHead3 && !ListHead4) ||
        !OutputBuffer || (ULONG)BufferSizeCopy < 0x130 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSizeCopy >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, (ULONG)BufferSizeCopy, 1);
    memset(OutputBuffer, 0, (ULONG)BufferSizeCopy);
    *OutputBuffer = 0;

    RemainingCount = (BufferSizeCopy - 304) / 0x128 + 1;
    CurrentCount = (int)RemainingCount;

    if (ListHead3)
    {
        GuidHigh = 6881348;
        GuidLow = 7012467;
        EnumMiniFilterVolumeList(ListHead3, (__int64)&GuidHigh,
            (__int64)&OutputBuffer[74 * *OutputBuffer + 2], &CurrentCount);
        CountBefore1 = (int)RemainingCount;
        RemainingCount = CurrentCount;
        *OutputBuffer += CountBefore1 - CurrentCount;
    }

    if (ListHead1)
    {
        GuidHigh = 6619214;
        GuidLow = 0x72006F00770074LL;
        GuidFlag = 107;
        EnumMiniFilterVolumeList(ListHead1, (__int64)&GuidHigh,
            (__int64)&OutputBuffer[74 * *OutputBuffer + 2], &CurrentCount);
        CountBefore2 = (int)RemainingCount;
        RemainingCount = CurrentCount;
        *OutputBuffer += CountBefore2 - CurrentCount;
    }

    if (ListHead2)
    {
        GuidHigh = 6553667;
        GuidLow = 0x6D006F0052LL;
        EnumMiniFilterVolumeList(ListHead2, (__int64)&GuidHigh,
            (__int64)&OutputBuffer[74 * *OutputBuffer + 2], &CurrentCount);
        CountBefore3 = (int)RemainingCount;
        RemainingCount = CurrentCount;
        *OutputBuffer += CountBefore3 - CurrentCount;
    }

    if (ListHead4Ptr)
    {
        GuidHigh = 6357076;
        GuidLow = 6619248;
        EnumMiniFilterVolumeList(ListHead4Ptr, (__int64)&GuidHigh,
            (__int64)&OutputBuffer[74 * *OutputBuffer + 2], &CurrentCount);
        *OutputBuffer += (int)RemainingCount - CurrentCount;
    }

    Result = *OutputBuffer != 0;
    HasItems = Result;
    return Result;
}

// MiniFilterInstanceSetup — Minifilter 实例安装回调
// 对应原始驱动 sub_1400129CC
NTSTATUS MiniFilterInstanceSetup(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags)
{
    return STATUS_SUCCESS;
}

// MiniFilterInstanceQuery — Minifilter 实例查询回调
// 对应原始驱动 sub_140012B78
NTSTATUS MiniFilterInstanceQuery(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_FLAGS Flags)
{
    return STATUS_SUCCESS;
}

// MiniFilterTeardownRoutine — Minifilter 拆卸回调
// 对应原始驱动 sub_140019BA0
__int64 MiniFilterTeardownRoutine(void *NameBuffer, size_t BufferSize, char IsAddOperation)
{
    if (!NameBuffer || (ULONG)BufferSize <= 2 || (BufferSize & 1) != 0)
        return 0;

    if ((ULONG64)NameBuffer >= MmUserProbeAddress ||
        (ULONG64)NameBuffer + (ULONG)BufferSize >= MmUserProbeAddress)
        return 0;

    PVOID PoolBuffer = ExAllocatePool(PagedPool, (ULONG)BufferSize + 2);
    if (!PoolBuffer)
        return 0;

    ProbeForRead(NameBuffer, (ULONG)BufferSize, 2);
    memmove(PoolBuffer, NameBuffer, BufferSize);
    *((WORD *)PoolBuffer + (BufferSize >> 1)) = 0;

    if (IsAddOperation == 1)
    {
        MiniFilterNotifyRoutine((wchar_t *)PoolBuffer, BufferSize >> 1);
    }
    else
    {
        _QWORD *ListEntry;
        KeWaitForSingleObject(&g_Mutex, Executive, 0, 0, 0);
        for (ListEntry = &g_Pointer; *ListEntry; ListEntry = (_QWORD *)*ListEntry)
        {
            if (!_wcsicmp((const wchar_t *)*ListEntry + 6, (const wchar_t *)PoolBuffer))
            {
                *ListEntry = *(_QWORD *)*ListEntry;
                break;
            }
        }
        KeReleaseMutex(&g_Mutex, 0);
    }

    ExFreePoolWithTag(PoolBuffer, 0);
    return 1;
}

// MiniFilterFilterUnload — Minifilter 卸载回调
// 对应原始驱动 sub_140019EA0
__int64 *MiniFilterFilterUnload(__int64 ProcessId, __int64 BaseAddress, char IsAddOperation)
{
    return NULL;
}

// MiniFilterNotifyRoutine — Minifilter 通知例程
// 对应原始驱动 sub_140019AD8
__int64 MiniFilterNotifyRoutine(wchar_t *Name, ULONG NameLength)
{
    return 1;
}

// MiniFilterPreCreate — 预处理创建
// 对应原始驱动 sub_140014078
NTSTATUS MiniFilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// MiniFilterPostCreate — 后处理创建
// 对应原始驱动 sub_1400142A8
// 遍历 PE 节表定位 PostCreate 相关的数据节偏移
ULONG64 MiniFilterPostCreate(void)
{
    __int64 PeBase = GtRead(GtEprocessField22);
    ULONG PeSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG64 result = GtRead(0x4160);
    ULONG64 SectionAddr = result;

    if (!PeBase || !PeSize || !NtImageBase || result <= NtImageBase) return result;

    ULONG SectionOffset = (ULONG)(result - NtImageBase);
    if (SectionOffset >= PeSize) return result;
    if (SectionAddr != SectionOffset + NtImageBase) return result;

    __int64 ReadContext;
    __int64 VirtualSize = 0;
    _DWORD SectionInfo[14];
    ULONG DataSectionSize;
    __int64 SectionFlags2;
    ULONG SubType;
    int Characteristics;
    ULONG RawSize;
    __int64 SectionName;

    InitPESectionReadContext(PeBase + SectionOffset, PeSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ULONG InitSectionIndex = 0, PageSectionIndex = 0, SectionCount = 0;
    char FoundPostCreate = 0;

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry(&ReadContext, SectionInfo)) break;

        int SectionSize = RawSize + (int)VirtualSize;
        VirtualSize += RawSize;
        short SectionFlags = *(WORD *)(SectionName + 6);

        if (SectionFlags == 1298 && SectionFlags2 == 64 && Characteristics == 4)
        {
            switch (SubType)
            {
            case 2: InitSectionIndex = i; break;
            case 9: PageSectionIndex = i; break;
            case 1:
                if ((InitSectionIndex && InitSectionIndex + 1 == i) ||
                    (PageSectionIndex && PageSectionIndex + 3 == i))
                    FoundPostCreate = 1;
                break;
            }
        }
        else if (FoundPostCreate == 1 && SectionFlags == 1368 && (SectionFlags2 & 0x4000000) != 0)
        {
            if (DataSectionSize && ++SectionCount == 2)
            {
                result = SectionSize + DataSectionSize - (ULONG)PeBase;
                if ((ULONG)result && (ULONG)result < PeSize)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x41C, NtImageBase + (ULONG)result);
                return result;
            }
        }
    }
    return result;
}

// MiniFilterPreRead — 预读取
// 对应原始驱动 sub_1400144A8
// 遍历 PE 节表查找 PreRead 相关节
ULONG64 MiniFilterPreRead(void)
{
    __int64 PeBase = GtRead(GtEprocessField22);
    ULONG PeSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG SectionIdx1 = (ULONG)GtRead(17299 | 2);
    ULONG SectionIdx2 = (ULONG)GtRead(16765);
    ULONG SectionIdx3 = (ULONG)GtRead(16778);
    ULONG64 result = GtRead(0x4160);
    ULONG64 SectionAddr = result;

    if (!PeBase || !PeSize || !NtImageBase || !SectionIdx1 || !SectionIdx2 || result <= NtImageBase) return result;
    if ((ULONG)(result - NtImageBase) >= PeSize) return result;
    ULONG SectionOffset = (ULONG)(result - NtImageBase);
    result += NtImageBase;
    if (SectionAddr != result) return result;

    __int64 ReadContext;
    __int64 VirtualSize = 0;
    _DWORD SectionInfo[14];
    ULONG DataSectionSize, RawSize;
    int FieldValue;
    __int64 SectionFlags2, SectionDataPtr, SectionName;

    InitPESectionReadContext(SectionOffset + PeBase, PeSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ULONG TargetSection = 0;

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry(&ReadContext, SectionInfo)) break;
        int SectionSize = RawSize + (int)VirtualSize;
        VirtualSize += RawSize;
        short SectionFlags = *(WORD *)(SectionName + 6);

        if (SectionFlags == 1072 && FieldValue && SectionFlags2 == 0x40000 && !SectionDataPtr)
        {
            if (TargetSection && SectionIdx1 != TargetSection && SectionIdx2 != TargetSection && SectionIdx3 != TargetSection)
                return GtWrite((GLOBAL_TABLE_INDEX)0x41C, NtImageBase + TargetSection);
        }
        else if (SectionFlags == 1368 && (SectionFlags2 & 0x4000000) != 0)
        {
            if (DataSectionSize)
            {
                result = SectionSize + DataSectionSize - (ULONG)PeBase;
                if ((ULONG)result && (ULONG)result < PeSize)
                    TargetSection = SectionSize + DataSectionSize - PeBase;
            }
        }
    }
    return result;
}

// MiniFilterPostRead — 后读取
// 对应原始驱动 sub_1400146D4
// 遍历 PE 节表定位 PostRead 数据节偏移
ULONG64 MiniFilterPostRead(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    ULONG KernelSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG64 result = GtRead(0x4161);
    ULONG64 TargetAddress = result;

    if (!KernelBase || !KernelSize || !NtImageBase || result <= NtImageBase) return result;
    ULONG ImageOffset = (ULONG)(result - NtImageBase);
    if (ImageOffset >= KernelSize) return result;
    result = ImageOffset + NtImageBase;
    if (TargetAddress != result) return result;

    __int64 ReadContext;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    ULONG FieldValue, SectionSize;
    __int64 EntryFlags;
    ULONG SubType;
    int EntryCharacteristics;
    __int64 SectionDataPtr;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ULONG Type2SectionIndex = 0, Type9SectionIndex = 0, MatchCount = 0;
    char FoundFlag = 0;

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry(&ReadContext, SectionEntry)) break;
        int CalculatedSize = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;
        short SectionFlags = *(WORD *)(SectionDataPtr + 6);

        if (SectionFlags == 1298 && EntryFlags == 64 && EntryCharacteristics == 4)
        {
            switch (SubType)
            {
            case 2: Type2SectionIndex = i; break;
            case 9: Type9SectionIndex = i; break;
            case 1:
                if ((Type2SectionIndex && Type2SectionIndex + 1 == i) ||
                    (Type9SectionIndex && Type9SectionIndex + 3 == i))
                    FoundFlag = 1;
                break;
            }
        }
        else if (FoundFlag == 1 && SectionFlags == 1368 && (EntryFlags & 0x4000000) != 0)
        {
            if (FieldValue && ++MatchCount == 2)
            {
                result = CalculatedSize + FieldValue - (ULONG)KernelBase;
                if ((ULONG)result && (ULONG)result < KernelSize)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x41D, NtImageBase + (ULONG)result);
                return result;
            }
        }
    }
    return result;
}

// MiniFilterPreWrite — 预写入
// 对应原始驱动 sub_1400148D4
// 遍历 PE 节表查找 PreWrite 相关节
__int64 MiniFilterPreWrite(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    ULONG KernelSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG ExistingPreWriteOffset = (ULONG)GtRead(16754);
    ULONG64 TargetAddress = GtRead(0x4161);
    __int64 result = GtRead(16756);
    ULONG ExistingPostWriteOffset = (ULONG)result;

    if (!KernelBase || !KernelSize || !NtImageBase || !ExistingPreWriteOffset ||
        TargetAddress <= NtImageBase || !result) return result;
    if ((ULONG)(TargetAddress - NtImageBase) >= KernelSize) return result;
    ULONG ImageOffset = (ULONG)(TargetAddress - NtImageBase);
    result += NtImageBase;
    if (TargetAddress != result) return result;

    __int64 ReadContext;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    ULONG FieldValue, SectionSize;
    __int64 EntryFlags;
    __int64 SectionDataPtr;
    char FoundMatchFlag = 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry(&ReadContext, SectionEntry)) break;
        int CalculatedSize = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;
        short SectionFlags = *(WORD *)(SectionDataPtr + 6);

        if (SectionFlags == 483 && EntryFlags == 65601)
            FoundMatchFlag = 1;
        else if (SectionFlags == 1368 && (EntryFlags & 0x4000000) != 0)
        {
            if (FieldValue)
            {
                result = CalculatedSize + FieldValue - (ULONG)KernelBase;
                if ((ULONG)result && (ULONG)result < KernelSize &&
                    FoundMatchFlag == 1 &&
                    (ULONG)result != ExistingPreWriteOffset &&
                    (ULONG)result != ExistingPostWriteOffset)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x41D, NtImageBase + (ULONG)result);
                FoundMatchFlag = 0;
            }
        }
    }
    return result;
}

// MiniFilterPostWrite — 后写入
// 对应原始驱动 sub_140014D08
// 遍历 PE 节表查找 PostWrite 相关节
__int64 MiniFilterPostWrite(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    ULONG KernelSize = (ULONG)GtRead(GtEprocessField23);
    __int64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    __int64 SectionOffset = (int)ScanFileForPeSectionInfo();
    ULONG ExistingPostWriteOffset1 = (ULONG)GtRead(17299 | 2);
    __int64 result = GtRead(16765);
    ULONG ExistingPostWriteOffset2 = (ULONG)result;

    if (!KernelBase || !KernelSize || !NtImageBase || (int)SectionOffset <= 0 ||
        (ULONG)SectionOffset >= KernelSize || !ExistingPostWriteOffset1 || !result) return result;

    __int64 PeHeaderDataDir = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 48);
    __int64 ReadContext;
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    ULONG FieldValue, SectionSize;
    __int64 EntryFlags, SectionCharacteristics, SectionDataPtr;
    ULONG SubType;
    __int64 SavedSectionOffset = 0;

    InitPESectionReadContext(SectionOffset + KernelBase, KernelSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x100; i++)
    {
        if (ReadPESectionEntry(&ReadContext, SectionEntry)) break;
        int CalculatedSize = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;

        if (*(WORD *)(SectionDataPtr + 6) == 1368 && (EntryFlags & 0x4000000) != 0 && (result = FieldValue) != 0)
        {
            result = CalculatedSize + FieldValue - (ULONG)KernelBase;
            if (((ULONG)result == ExistingPostWriteOffset1 || (ULONG)result == ExistingPostWriteOffset2) &&
                SavedSectionOffset && (ULONG)SavedSectionOffset < KernelSize)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x424, SavedSectionOffset + PeHeaderDataDir);
                return GtWrite((GLOBAL_TABLE_INDEX)0x41E, SavedSectionOffset + NtImageBase);
            }
        }
        else if (SectionCharacteristics == 0x40000 && SubType)
            SavedSectionOffset = CalculatedSize + SubType - (ULONG)KernelBase;
    }
    return result;
}

// MiniFilterPreCleanup — 预清理
// 对应原始驱动 sub_140014EE4
NTSTATUS MiniFilterPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// MiniFilterPreClose — 预关闭
// 对应原始驱动 sub_1400152D4
NTSTATUS MiniFilterPreClose(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// MiniFilterPreDirEnum — 预目录枚举
// 对应原始驱动 sub_140015A48
NTSTATUS MiniFilterPreDirEnum(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// MiniFilterPreSetInfo — 预设置信息
// 对应原始驱动 sub_140015F34
NTSTATUS MiniFilterPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// MiniFilterPreRename — 预重命名
// 对应原始驱动 sub_140017938
__int64 MiniFilterPreRename(__int64 Unknown, __int64 Unknown2, _BYTE *OutputBuffer, int OutputBufferSize)
{
    char Result = 0;
    int HasFilterTable;

    if (!OutputBuffer || OutputBufferSize != 2648 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(OutputBuffer + 2648) >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, 0xA58, 1);
    memset(OutputBuffer, 0, 0xA58);

    HasFilterTable = (int)GtRead(GtFsFilterTableReady);
    if (!HasFilterTable)
    {
        InitFsFilterExportTable();
        HasFilterTable = (int)GtRead(GtFsFilterTableReady);
    }

    if (CopyServiceTableFromSection((__int64)(OutputBuffer + 8)) == 1)
    {
        *(WORD *)OutputBuffer |= 1;
        Result = 1;
        if (HasFilterTable)
        {
            if (CopyServiceTableWithFilter((__int64)(OutputBuffer + 8)) == 1 &&
                ResolveContextMemoryBlocks((__int64)(OutputBuffer + 8), 0x1C) == 1)
                OutputBuffer[2] = 1;
        }
    }

    if (CopyWin32kServiceTableFromFilter((__int64)(OutputBuffer + 1352)) == 1)
    {
        *(WORD *)OutputBuffer |= 2;
        Result = 1;
        if ((ULONG)GtRead(GtWin32kFilterTableReady))
        {
            if (CopyServiceTablePartial((__int64)(OutputBuffer + 1352)) == 1 &&
                ResolveContextMemoryBlocks((__int64)(OutputBuffer + 1352), 0x1B) == 1)
                OutputBuffer[3] = 1;
        }
    }

    return Result;
}

// MiniFilterPreDelete — 预删除
// 对应原始驱动 sub_1400177B4
__int64 MiniFilterPreDelete(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize)
{
    ULONG64 BufferSize = OutputBufferSize;
    ULONG Result = 0;
    __int64 ServiceTable1, ServiceTable2, FltMgrBase;
    ULONG EntryCount;

    if (!GtRead(GtFsFilterTableReady))
        InitFsFilterExportTable();

    ServiceTable1 = GtRead(GtFltPeSectionAddr3);
    ServiceTable2 = GtRead(GtFltPeSectionAddr8);
    FltMgrBase = GtRead(GtFltmgrBase);

    if (!ServiceTable1 || !ServiceTable2 || !FltMgrBase)
        return 0;

    EntryCount = (ULONG)GtRead(GtWindowsBuildNumber) < 0x3AD7 ? 12 : 14;

    if (!OutputBuffer || BufferSize < 32 * EntryCount + 40)
        return 0;

    if ((ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;

    __int64 SectionObject = OpenWin32kSysSection();
    if (!SectionObject)
        return 0;

    ULONG64 SectionBase = *(_QWORD *)(SectionObject + 48);
    if (!SectionBase || SectionBase <= (ULONG64)MmSystemRangeStart)
        return 0;

    ULONG64 ServiceArray = *(_QWORD *)(SectionBase + 48);
    if (!ServiceArray || ServiceArray <= (ULONG64)MmSystemRangeStart)
        return 0;

    ProbeForWrite(OutputBuffer, OutputBufferSize, 8);
    memset(OutputBuffer, 0, OutputBufferSize);
    *OutputBuffer = EntryCount;

    while (Result < EntryCount)
    {
        __int64 OffsetValue = 8 * Result;
        OutputBuffer[OffsetValue + 2] = Result;
        __int64 ServiceFuncPtr = (Result & 1) ? ServiceTable2 : ServiceTable1;
        *(__int64 *)&OutputBuffer[OffsetValue + 4] = ServiceFuncPtr;
        *(__int64 *)&OutputBuffer[OffsetValue + 6] = *(__int64 *)(ServiceArray + 8 * Result + 8);
        Result++;
    }

    return 1;
}

// MiniFilterPreHardLink — 预硬链接
// 对应原始驱动 sub_140017A90
__int64 MiniFilterPreHardLink(__int64 Unknown1, __int64 Unknown2, __int64 *OutputBuffer, unsigned int OutputBufferSize)
{
    ULONG64 BufferSize = OutputBufferSize;
    char Result = 0;
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG ModuleInfoSize = (ULONG)GtRead(GtNtoskrnlImageSize);
    ULONG64 *ExecSectionBase = (ULONG64 *)GtRead(GtPeExecutableSectionBase);
    __int64 FltMgrBase, TempVar, ServiceTableAddr1, ServiceTableAddr2, BaseAddr;
    __int64 TableValue1, TableValue2, TableValue3, TableValue4;
    __int64 FltMgrBaseCopy, FileVersion;
    ULONG64 v14, v15;
    ULONG v16;
    __int64 v17;

    if (!ExecSectionBase)
    {
        FindPeExecutableSection();
        ExecSectionBase = (ULONG64 *)GtRead(GtPeExecutableSectionBase);
    }
    FltMgrBaseCopy = GtRead(GtFltmgrBase);
    FltMgrBase = GtRead(GtFltPeSectionAddr3);
    TempVar = GtRead(GtFltPeSectionOfs8);
    if (!FltMgrBase && !TempVar)
        InitFsFilterExportTable();
    ServiceTableAddr1 = GtRead(GtFltPeSectionAddr3);
    TableValue1 = GtRead(GtFltPeSectionAddr4);
    TableValue2 = GtRead(GtFltPeSectionAddr5);
    TableValue3 = GtRead(GtFltPeSectionAddr6);
    TableValue4 = GtRead(GtFltPeSectionAddr7);
    ServiceTableAddr2 = GtRead(GtFltPeSectionAddr8);
    BaseAddr = GtRead(GtFltPeSectionAddr0);
    FileVersion = BaseAddr;

    if (!ExecSectionBase || !FltMgrBaseCopy || !BaseAddr ||
        (!ServiceTableAddr1 && !ServiceTableAddr2) ||
        (ULONG64)ExecSectionBase <= NtImageBase)
        return Result;

    v14 = ModuleInfoSize + NtImageBase;
    if ((ULONG64)ExecSectionBase >= v14 || (ULONG64)(ExecSectionBase + 6) >= v14 ||
        !OutputBuffer || (ULONG)BufferSize < 0x70 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, BufferSize, 8);
    memset(OutputBuffer, 0, BufferSize);
    *OutputBuffer = FileVersion;
    v15 = *ExecSectionBase;
    OutputBuffer[1] = *ExecSectionBase;

    if (!v15 || v15 <= (ULONG64)MmSystemRangeStart)
        return 1;

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        OutputBuffer[12] = ServiceTableAddr2;
        OutputBuffer[13] = *(__int64 *)OutputBuffer[1];
    }
    else
    {
        v16 = (ULONG)GtRead(GtWindowsBuildNumber);
        OutputBuffer[2] = ServiceTableAddr1;
        OutputBuffer[3] = *(__int64 *)OutputBuffer[1];
        if (v16 >= 0x4A61)
        {
            OutputBuffer[12] = ServiceTableAddr2;
            OutputBuffer[13] = *(__int64 *)(OutputBuffer[1] + 8);
            OutputBuffer[4] = TableValue1;
            OutputBuffer[5] = *(__int64 *)(OutputBuffer[1] + 16);
            OutputBuffer[6] = TableValue2;
            OutputBuffer[7] = *(__int64 *)(OutputBuffer[1] + 24);
            OutputBuffer[8] = TableValue3;
            OutputBuffer[9] = *(__int64 *)(OutputBuffer[1] + 32);
            OutputBuffer[10] = TableValue4;
            v17 = *(__int64 *)(OutputBuffer[1] + 40);
        }
        else
        {
            OutputBuffer[4] = TableValue1;
            OutputBuffer[5] = *(__int64 *)(OutputBuffer[1] + 8);
            OutputBuffer[6] = TableValue2;
            OutputBuffer[7] = *(__int64 *)(OutputBuffer[1] + 16);
            OutputBuffer[8] = TableValue3;
            OutputBuffer[9] = *(__int64 *)(OutputBuffer[1] + 24);
            OutputBuffer[10] = TableValue4;
            v17 = *(__int64 *)(OutputBuffer[1] + 32);
        }
        OutputBuffer[11] = v17;
    }
    return 1;
}

// MiniFilterPreAcquire — 预获取
// 对应原始驱动 sub_140017D94
// 遍历过滤器上下文链表，收集上下文信息到输出缓冲区
__int64 MiniFilterPreAcquire(__int64 Unknown1, __int64 Unknown2, unsigned int *OutputBuffer, unsigned int OutputBufferSize)
{
    ULONG64 BufferSize = OutputBufferSize;
    char Result = 0;
    ULONG64 *ContextListHead;
    ULONG StructSize;
    unsigned int *OutputEntry;
    ULONG64 CurrentEntry;
    ULONG LoopIndex;
    ULONG64 ContextBlock;
    _QWORD *SubListHead, *SubListHeadCopy, *SubListEntry;
    ULONG SubLoopIndex;
    _QWORD *SubContextBlock, *NameArray;
    ULONG NameIndex;
    __int64 EntryTypeCount;
    ULONG OutputSize;
    ULONG ContextSize;
    int MainLoopCount, SubLoopCount;
    ULONG StructSizeCopy;
    ULONG64 *NextEntryPtr;

    ContextListHead = (ULONG64 *)GtRead(GtFltEnumerateFilterDataSection);
    if (!ContextListHead)
    {
        InitFsFilterExportTable();
        ContextListHead = (ULONG64 *)GtRead(GtFltEnumerateFilterDataSection);
    }

    if (!ContextListHead || (ULONG64)ContextListHead <= (ULONG64)MmSystemRangeStart ||
        !OutputBuffer || (ULONG)BufferSize < 0x90 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, BufferSize, 4);
    memset(OutputBuffer, 0, BufferSize);

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x2800)
    {
        if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x23F0)
        {
            if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1770)
                ContextSize = 68;
            else
                ContextSize = 82;
        }
        else
            ContextSize = 84;
    }
    else
        ContextSize = 86;

    StructSize = (ULONG)GtRead(GtWindowsBuildNumber) < 0x1770 ? 1344 : 1920;
    StructSizeCopy = StructSize;
    OutputEntry = OutputBuffer + 2;
    CurrentEntry = *ContextListHead;
    NextEntryPtr = (ULONG64 *)*ContextListHead;

    for (MainLoopCount = 0; MainLoopCount < 0x1000; MainLoopCount++)
    {
        if ((ULONG64 *)CurrentEntry == ContextListHead)
            break;
        if (CurrentEntry <= (ULONG64)MmSystemRangeStart)
            break;
        if ((ULONG)BufferSize < 0x90)
            break;

        ContextBlock = CurrentEntry - 8;
        if (CheckMemoryValid((void *)(CurrentEntry - 8)) != 1 ||
            CheckMemoryValid((void *)(ContextBlock + StructSize - 1)) != 1)
            break;

        SubListHead = (_QWORD *)(ContextBlock + 176);
        SubListHeadCopy = SubListHead;
        SubListEntry = *(_QWORD **)(ContextBlock + 176);

        for (SubLoopCount = 0; SubLoopCount < 0x1000; SubLoopCount++)
        {
            if (SubListEntry == SubListHead || !SubListEntry ||
                SubListEntry <= (ULONG64)MmSystemRangeStart)
                break;

            SubContextBlock = SubListEntry - 2;
            if (CheckMemoryValid(SubListEntry - 2) != 1 ||
                CheckMemoryValid((char *)&SubContextBlock[ContextSize - 1] + 7) != 1 ||
                (ULONG)BufferSize < 0x90)
                break;

            OutputEntry[1] = 0;

            if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x2800)
            {
                if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x23F0)
                {
                    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1770)
                    {
                        *((__int64 *)OutputEntry + 1) = (__int64)SubContextBlock;
                        *((__int64 *)OutputEntry + 2) = SubContextBlock[28];
                        *((__int64 *)OutputEntry + 3) = SubContextBlock[29];
                        *((__int64 *)OutputEntry + 4) = SubContextBlock[30];
                        *((__int64 *)OutputEntry + 5) = SubContextBlock[31];
                        *((__int64 *)OutputEntry + 6) = SubContextBlock[32];
                        *((__int64 *)OutputEntry + 7) = SubContextBlock[42];
                        *((__int64 *)OutputEntry + 8) = SubContextBlock[43];
                        *((__int64 *)OutputEntry + 9) = SubContextBlock[44];
                        *((__int64 *)OutputEntry + 11) = SubContextBlock[46];
                        NameArray = (_QWORD *)SubContextBlock[45];
                    }
                    else
                    {
                        *((__int64 *)OutputEntry + 1) = (__int64)SubContextBlock;
                        *((__int64 *)OutputEntry + 2) = SubContextBlock[30];
                        *((__int64 *)OutputEntry + 3) = SubContextBlock[31];
                        *((__int64 *)OutputEntry + 4) = SubContextBlock[32];
                        *((__int64 *)OutputEntry + 5) = SubContextBlock[33];
                        *((__int64 *)OutputEntry + 6) = SubContextBlock[34];
                        *((__int64 *)OutputEntry + 7) = SubContextBlock[44];
                        *((__int64 *)OutputEntry + 8) = SubContextBlock[45];
                        *((__int64 *)OutputEntry + 9) = SubContextBlock[47];
                        *((__int64 *)OutputEntry + 10) = SubContextBlock[48];
                        *((__int64 *)OutputEntry + 11) = SubContextBlock[50];
                        *((__int64 *)OutputEntry + 13) = SubContextBlock[46];
                        NameArray = (_QWORD *)SubContextBlock[49];
                    }
                }
                else
                {
                    *((__int64 *)OutputEntry + 1) = (__int64)SubContextBlock;
                    *((__int64 *)OutputEntry + 2) = SubContextBlock[30];
                    *((__int64 *)OutputEntry + 3) = SubContextBlock[31];
                    *((__int64 *)OutputEntry + 4) = SubContextBlock[32];
                    *((__int64 *)OutputEntry + 5) = SubContextBlock[33];
                    *((__int64 *)OutputEntry + 6) = SubContextBlock[34];
                    *((__int64 *)OutputEntry + 7) = SubContextBlock[45];
                    *((__int64 *)OutputEntry + 8) = SubContextBlock[46];
                    *((__int64 *)OutputEntry + 9) = SubContextBlock[48];
                    *((__int64 *)OutputEntry + 10) = SubContextBlock[49];
                    *((__int64 *)OutputEntry + 11) = SubContextBlock[52];
                    *((__int64 *)OutputEntry + 12) = SubContextBlock[50];
                    *((__int64 *)OutputEntry + 13) = SubContextBlock[47];
                    NameArray = (_QWORD *)SubContextBlock[51];
                }
            }
            else
            {
                *((__int64 *)OutputEntry + 1) = (__int64)SubContextBlock;
                *((__int64 *)OutputEntry + 2) = SubContextBlock[32];
                *((__int64 *)OutputEntry + 3) = SubContextBlock[33];
                *((__int64 *)OutputEntry + 4) = SubContextBlock[34];
                *((__int64 *)OutputEntry + 5) = SubContextBlock[35];
                *((__int64 *)OutputEntry + 6) = SubContextBlock[36];
                *((__int64 *)OutputEntry + 7) = SubContextBlock[47];
                *((__int64 *)OutputEntry + 8) = SubContextBlock[48];
                *((__int64 *)OutputEntry + 9) = SubContextBlock[50];
                *((__int64 *)OutputEntry + 10) = SubContextBlock[51];
                *((__int64 *)OutputEntry + 11) = SubContextBlock[54];
                *((__int64 *)OutputEntry + 12) = SubContextBlock[52];
                *((__int64 *)OutputEntry + 13) = SubContextBlock[49];
                NameArray = (_QWORD *)SubContextBlock[53];
            }

            if (NameArray && (ULONG64)NameArray > (ULONG64)MmSystemRangeStart)
            {
                for (NameIndex = 0; NameIndex < 0x1000; NameIndex++)
                {
                    if ((ULONG64)NameArray <= *(ULONG64 *)MmSystemRangeStart)
                        break;
                    if (CheckMemoryValid(NameArray) != 1 ||
                        CheckMemoryValid((char *)NameArray + 31) != 1)
                        break;
                    EntryTypeCount = OutputEntry[1];
                    if ((ULONG)BufferSize < 24 * (EntryTypeCount + 6) || *(UCHAR *)NameArray == 0x80)
                        break;
                    OutputEntry[6 * EntryTypeCount + 28] = *(UCHAR *)NameArray;
                    *(__int64 *)&OutputEntry[6 * OutputEntry[1] + 30] = NameArray[1];
                    *(__int64 *)&OutputEntry[6 * OutputEntry[1]++ + 32] = NameArray[2];
                    NameArray += 4;
                }
            }

            OutputSize = OutputEntry[1];
            *OutputEntry = OutputSize <= 1 ? 136 : 24 * (OutputSize - 1) + 136;
            BufferSize = BufferSize - *OutputEntry;
            ++*OutputBuffer;
            OutputEntry = (unsigned int *)((char *)OutputEntry + *OutputEntry);
            Result = 1;
            SubListEntry = (_QWORD *)*SubListEntry;
        }
        CurrentEntry = *NextEntryPtr;
        NextEntryPtr = (ULONG64 *)*NextEntryPtr;
    }
    return Result;
}

// MiniFilterPreFlush — 预刷新
// 对应原始驱动 sub_140018794
__int64 MiniFilterPreFlush(unsigned int *OutputBuffer, int BufferSize)
{
    char Result = 0;
    __int64 ServiceTable1, ServiceTable2, FltMgrBase;
    ULONG EntryCount;
    __int64 SectionObject;
    ULONG64 SectionBase, ServiceArray;
    ULONG ServiceIndex;

    if (!GtRead(GtFltPeSectionAddr1))
        InitFsFilterExportTable();

    ServiceTable1 = GtRead(GtFltPeSectionAddr1);
    ServiceTable2 = GtRead(GtFltPeSectionAddr2);
    FltMgrBase = GtRead(GtFltmgrBase);

    if (!ServiceTable1 || !ServiceTable2 || !FltMgrBase)
        return Result;

    EntryCount = (ULONG)GtRead(GtWindowsBuildNumber) < 0x3AD7 ? 12 : 14;

    if (!OutputBuffer || BufferSize != 4 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(OutputBuffer + 1) >= MmUserProbeAddress)
        return Result;

    SectionObject = OpenWin32kSysSection();
    if (!SectionObject) return Result;

    SectionBase = *(_QWORD *)(SectionObject + 48);
    if (!SectionBase || SectionBase <= (ULONG64)MmSystemRangeStart)
        return Result;

    ServiceArray = *(_QWORD *)(SectionBase + 48);
    if (!ServiceArray || ServiceArray <= (ULONG64)MmSystemRangeStart)
        return Result;

    ProbeForRead(OutputBuffer, 4, 4);
    ServiceIndex = *OutputBuffer;
    if ((ULONG)ServiceIndex < EntryCount)
    {
        if ((ServiceIndex & 1) != 0)
            *(_QWORD *)(ServiceArray + 8 * ServiceIndex + 8) = ServiceTable2;
        else
            *(_QWORD *)(ServiceArray + 8 * ServiceIndex + 8) = ServiceTable1;
    }
    return 1;
}

// MiniFilterPreShutdown — 预关机
// 对应原始驱动 sub_1400188D8
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize)
{
    return 0;
}

// StoreVolumeMountCallback — 存储卷挂载回调
// 对应原始驱动 sub_140018C84
__int64 StoreVolumeMountCallback(__int64 CallbackData)
{
    char Result;
    __int64 SectionObject;
    __int64 ServiceTablePtr;
    __int64 ServiceFunc;
    __int64 EntryIndex, SlotIndex, EntryIndexVal;

    Result = 0;
    SectionObject = OpenWin32kSysSection();
    ServiceTablePtr = SectionObject;
    if (!SectionObject)
        return Result;

    if (*(UCHAR *)CallbackData)
    {
        ServiceTablePtr = *(__int64 *)(SectionObject + 80);
        if (!ServiceTablePtr)
            return Result;
        if (MmIsAddressValid(*(PVOID *)(SectionObject + 80)) != 1 ||
            MmIsAddressValid((PVOID)(ServiceTablePtr + 223)) != 1)
            return Result;
        EntryIndexVal = *(ULONG *)(CallbackData + 8);
        if ((ULONG)EntryIndexVal >= 0x1B)
            return Result;
        ServiceFunc = *(__int64 *)(CallbackData + 16);
        SlotIndex = EntryIndexVal + 1;
        goto WriteSlot;
    }

    ServiceFunc = *(__int64 *)(CallbackData + 16);
    if (!ServiceFunc)
        return Result;
    EntryIndex = *(ULONG *)(CallbackData + 8);
    if ((ULONG)EntryIndex > 0x1B)
        return Result;
    SlotIndex = EntryIndex + 14;

WriteSlot:
    WritePhysicalMemoryQword(ServiceTablePtr + 8 * SlotIndex, ServiceFunc);
    return 1;
}

// MiniFilterPreVolumeMount — 预卷挂载
// 对应原始驱动 sub_140018D14
__int64 MiniFilterPreVolumeMount(char *InputBuffer, int BufferSize)
{
    char Result = 0;
    char StoreResult, WriteResult;
    void *TargetPtr;
    _OWORD BufferData;

    if (!InputBuffer || BufferSize != 56 ||
        (ULONG64)InputBuffer >= MmUserProbeAddress ||
        (ULONG64)(InputBuffer + 56) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(InputBuffer, 0x38, 1);
    StoreResult = 1;
    WriteResult = 1;

    if (InputBuffer[32] == 1)
        StoreResult = StoreVolumeMountCallback((__int64)InputBuffer);

    if (InputBuffer[33] == 1)
    {
        WriteResult = 0;
        TargetPtr = (void *)*((__int64 *)InputBuffer + 2);
        if (TargetPtr &&
            MmIsAddressValid(TargetPtr) == 1 &&
            MmIsAddressValid((PVOID)(*((__int64 *)InputBuffer + 2) + 15)) == 1)
        {
            BufferData = *(_OWORD *)(InputBuffer + 34);
            WriteResult = WritePhysicalMemoryBuffer(*((__int64 *)InputBuffer + 2), &BufferData, 0x10, 0, 0);
        }
    }

    return StoreResult & WriteResult;
}

// MiniFilterPreVolumeDismount — 预卷卸载
// 对应原始驱动 sub_140018EA0
__int64 MiniFilterPreVolumeDismount(void)
{
    return 0;
}

// MiniFilterCommPortDisconnect — 通信端口断开
// 对应原始驱动 sub_140019400
__int64 MiniFilterCommPortDisconnect(void)
{
    if (!GtRead(GtCommPortCallbackReady))
        return 1;
    if (UnregisterCommPortCallback())
    {
        GtWrite(GtCommPortCallbackReady, 0);
        return 1;
    }
    return 0;
}

// MiniFilterCommPortCleanup — 通信端口清理
// 对应原始驱动 sub_1400198D8
__int64 MiniFilterCommPortCleanup(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
    if (!OutputBuffer || BufferSize != 4)
        return 0;
    if ((ULONG64)OutputBuffer >= MmUserProbeAddress || (ULONG64)(OutputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, 4, 4);
    *OutputBuffer = (ULONG)GtRead(GtCommPortCallbackReady);
    return 1;
}

// MiniFilterCommPortConnect — 通信端口连接
// 对应原始驱动 sub_140019784
void MiniFilterCommPortConnect(void)
{
}

// MiniFilterCommPortReplyDone — 通信端口回复完成
// 对应原始驱动 sub_140019938
__int64 MiniFilterCommPortReplyDone(void)
{
    return 1;
}

// MiniFilterNormalizeName — 文件名规范化
// 对应原始驱动 sub_140019DD8
__int64 MiniFilterNormalizeName(void)
{
    return 1;
}

// MiniFilterContextCleanup — 上下文清理
// 对应原始驱动 sub_140019A78
VOID MiniFilterContextCleanup(PVOID *Data, FLT_CONTEXT_TYPE ContextType, FLT_CONTEXT_CLEANUP_FLAGS Flags)
{
}

// MiniFilterFormatFileName — 格式化文件名
// 对应原始驱动 sub_14001A030
__int64 MiniFilterFormatFileName(void)
{
    if (!GtRead(GtMiniFilterFormatNameReady))
    {
        void (__fastcall *RegisterCallback)(__int64 *(__fastcall *)(__int64, __int64, char), __int64);
        RegisterCallback = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char), __int64))GtRead(16808);
        if (RegisterCallback)
        {
            RegisterCallback(MiniFilterNormalizeName, 1);
            GtWrite(GtMiniFilterFormatNameReady, 0);
            return 1;
        }
    }
    return 0;
}

// MiniFilterGenerateFileName — 生成文件名
// 对应原始驱动 sub_14001A0A0
__int64 MiniFilterGenerateFileName(void)
{
    if (!GtRead(GtMiniFilterFormatNameReady))
    {
        void (__fastcall *RegisterCallback)(__int64 *(__fastcall *)(__int64, __int64, char), __int64);
        RegisterCallback = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char), __int64))GtRead(16808);
        if (RegisterCallback)
        {
            RegisterCallback(MiniFilterNormalizeName, 0);
            GtWrite(GtMiniFilterFormatNameReady, 1);
            return 1;
        }
    }
    return 0;
}

// CleanupMiniFilter — 清理 Minifilter 通知链表
// 对应原始驱动 sub_140019D0C
LONG CleanupMiniFilter(void)
{
    _QWORD *CurrentEntry, *NextEntry;

    KeWaitForSingleObject(&g_Mutex, Executive, 0, 0, 0);
    CurrentEntry = (_QWORD *)g_Pointer;
    while (CurrentEntry)
    {
        NextEntry = (_QWORD *)*CurrentEntry;
        ExFreePoolWithTag(CurrentEntry, 0);
        CurrentEntry = NextEntry;
    }
    g_Pointer = 0;
    return KeReleaseMutex(&g_Mutex, 0);
}

// AcquireMiniFilterMutex — 获取 Minifilter 互斥锁
// 对应原始驱动 sub_14007182C
void AcquireMiniFilterMutex(void)
{
    KeWaitForSingleObject(&g_Mutex, Executive, 0, 0, 0);
}

// AcquireMiniFilterMutexEx — 获取 Minifilter 互斥锁（扩展）
// 对应原始驱动 sub_140071874
void AcquireMiniFilterMutexEx(void)
{
    KeWaitForSingleObject(&g_Mutex, Executive, 0, 0, 0);
}

// InitFsFilterExportTable — 初始化文件系统过滤器导出表
// 对应原始驱动 sub_14001763C
void InitFsFilterExportTable(void)
{
}

// OpenWin32kSysSection — 打开 Win32k 系统节
// 对应原始驱动 sub_1400174F8
__int64 OpenWin32kSysSection(void)
{
    return 0;
}

// UnregisterCommPortCallback — 取消注册通信端口回调
// 对应原始驱动 sub_140019A0C
__int64 UnregisterCommPortCallback(void)
{
    return 0;
}

// CheckProtectedEntry — 检查受保护条目
// 对应原始驱动 sub_14007A2A0
__int64 CheckProtectedEntry(__int64 Entry)
{
    return 0;
}

// MiniFilterPreRelease — 预释放
// 对应原始驱动 sub_1400184B8
__int64 MiniFilterPreRelease(_QWORD **ContextPtr, int ContextSize)
{
    char Result = 0;
    ULONG64 ContextListHead;
    _QWORD *ContextEntry;
    ULONG StructSize;
    ULONG64 FileObject;

    ContextListHead = GtRead(GtFltUnregisterFilterAddr);
    if (!ContextListHead)
    {
        InitFsFilterExportTable();
        ContextListHead = GtRead(GtFltUnregisterFilterAddr);
    }

    if (ContextListHead <= (ULONG64)MmSystemRangeStart)
        return Result;

    if (!ContextPtr || ContextSize != 8 ||
        (ULONG64)ContextPtr >= MmUserProbeAddress ||
        (ULONG64)(ContextPtr + 1) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(ContextPtr, 8, 8);
    ContextEntry = *ContextPtr;
    if (ContextEntry <= (ULONG64)MmSystemRangeStart)
        return Result;

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x2800)
    {
        if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x23F0)
        {
            if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1770)
                StructSize = 68;
            else
                StructSize = 82;
        }
        else
            StructSize = 84;
    }
    else
        StructSize = 86;

    if (CheckMemoryValid(ContextEntry) != 1 ||
        CheckMemoryValid((char *)&ContextEntry[StructSize - 1] + 7) != 1 ||
        ContextEntry[2] <= (ULONG64)MmSystemRangeStart ||
        ContextEntry[3] <= (ULONG64)MmSystemRangeStart)
        return Result;

    FileObject = ((ULONG)GtRead(GtWindowsBuildNumber) > 0x2580) ? ContextEntry[6] : ContextEntry[4];
    if (FileObject > (ULONG64)MmSystemRangeStart)
        return OpenAndWaitMiniFilterFile((__int64)ContextEntry) == 1;

    return Result;
}

// MiniFilterCommPortSend — 通信端口发送（桩函数）
NTSTATUS MiniFilterCommPortSend(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterCommPortRecv — 通信端口接收（桩函数）
NTSTATUS MiniFilterCommPortRecv(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterCommPortReply — 通信端口回复（桩函数）
NTSTATUS MiniFilterCommPortReply(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterFormatFileNameWithPath — 格式化文件名带路径（桩函数）
__int64 MiniFilterFormatFileNameWithPath(void)
{
    return 0;
}

// MiniFilterFormatFileNameWithContext — 格式化文件名带上下文（桩函数）
__int64 MiniFilterFormatFileNameWithContext(void)
{
    return 0;
}

// MiniFilterFormatFileNameEx — 格式化文件名扩展（桩函数）
__int64 MiniFilterFormatFileNameEx(void)
{
    return 0;
}

// MiniFilterFormatFileNameWithPathEx — 格式化文件名带路径扩展（桩函数）
__int64 MiniFilterFormatFileNameWithPathEx(void)
{
    return 0;
}

// MiniFilterQueryIdleRoutine — 查询空闲例程（桩函数）
NTSTATUS MiniFilterQueryIdleRoutine(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterNotifyRoutineEx — 通知例程扩展（桩函数）
NTSTATUS MiniFilterNotifyRoutineEx(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterActiveRoutine — 激活例程（桩函数）
NTSTATUS MiniFilterActiveRoutine(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterNotifyRoutineEx2 — 通知例程扩展2（桩函数）
NTSTATUS MiniFilterNotifyRoutineEx2(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterStreamHandle — 流句柄（桩函数）
NTSTATUS MiniFilterStreamHandle(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterPreFastIo — 快速IO预处理（桩函数）
NTSTATUS MiniFilterPreFastIo(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterPostFastIo — 快速IO后处理（桩函数）
NTSTATUS MiniFilterPostFastIo(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForModWrite — 获取修改写入（桩函数）
NTSTATUS MiniFilterAcquireForModWrite(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterReleaseForModWrite — 释放修改写入（桩函数）
NTSTATUS MiniFilterReleaseForModWrite(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForCcFlush — 获取缓存管理器刷新（桩函数）
NTSTATUS MiniFilterAcquireForCcFlush(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterReleaseForCcFlush — 释放缓存管理器刷新（桩函数）
NTSTATUS MiniFilterReleaseForCcFlush(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForSectionSync — 获取节同步（桩函数）
NTSTATUS MiniFilterAcquireForSectionSync(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterServerContext — 服务器上下文（桩函数）
NTSTATUS MiniFilterServerContext(void)
{
    return STATUS_SUCCESS;
}

// MiniFilterClientContext — 客户端上下文（桩函数）
NTSTATUS MiniFilterClientContext(void)
{
    return STATUS_SUCCESS;
}

// CopyServiceTableFromSection — 从节复制服务表
// 对应原始驱动 sub_1400174B4
// 打开 win32k.sys 文件节，从偏移 112 处读取服务表指针，复制 0x1C 个服务表条目到输出缓冲区（每条目 48 字节）
__int64 CopyServiceTableFromSection(__int64 OutputTable)
{
    ULONG EntryIndex;
    __int64 SectionObject;
    _QWORD *ServiceTablePtr;

    EntryIndex = 0;
    SectionObject = OpenWin32kSysSection();
    if (SectionObject)
    {
        ServiceTablePtr = (_QWORD *)(SectionObject + 112);
        do
        {
            *(_DWORD *)OutputTable = EntryIndex++;
            *(_QWORD *)(OutputTable + 16) = *ServiceTablePtr;
            OutputTable += 48;
            ++ServiceTablePtr;
        } while (EntryIndex <= 0x1B);
        return 1;
    }
    return 0;
}

// CopyWin32kServiceTableFromFilter — 从 Minifilter 复制 Win32k 服务表
// 对应原始驱动 sub_14001743C
// 打开 win32k.sys 文件节，从偏移 80 处读取服务表指针，复制前 0x1B 个服务表条目到输出缓冲区（每条目 48 字节）
__int64 CopyWin32kServiceTableFromFilter(__int64 OutputTable)
{
    ULONG EntryIndex;
    __int64 SectionObject;
    __int64 ServiceTablePtr;
    _QWORD *ServiceEntry;

    EntryIndex = 0;
    SectionObject = OpenWin32kSysSection();
    if (SectionObject)
    {
        ServiceTablePtr = *(_QWORD *)(SectionObject + 80);
        if (ServiceTablePtr)
        {
            if (MmIsAddressValid(*(PVOID *)(SectionObject + 80)) == 1 &&
                MmIsAddressValid((PVOID)(ServiceTablePtr + 223)) == 1)
            {
                ServiceEntry = (_QWORD *)(ServiceTablePtr + 8);
                do
                {
                    *(_DWORD *)OutputTable = EntryIndex++;
                    *(_QWORD *)(OutputTable + 16) = *ServiceEntry;
                    OutputTable += 48;
                    ++ServiceEntry;
                } while (EntryIndex < 0x1B);
                return 1;
            }
        }
    }
    return 0;
}

// CopyServiceTableWithFilter — 带过滤复制服务表
// 对应原始驱动 sub_140017574
// 从 GtAlloc 分配的缓冲区复制 28 个服务表条目，过滤条件为条目索引==1 且值非零
__int64 CopyServiceTableWithFilter(__int64 SourceTable)
{
    char Result;
    __int64 *AllocBuffer;
    __int64 EntryCount;
    char *SourceEntry;
    __int64 OffsetDelta;

    Result = 0;
    AllocBuffer = GtAlloc(GtFltPeSectionOfs1 | GtObjectTypeField27 | 0x1400);
    EntryCount = 28;
    SourceEntry = (char *)AllocBuffer + 4;
    OffsetDelta = SourceTable - (_QWORD)AllocBuffer;
    do
    {
        *(_DWORD *)&SourceEntry[OffsetDelta] = *(_DWORD *)SourceEntry;
        if (*(_DWORD *)SourceEntry && *((_DWORD *)SourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&SourceEntry[OffsetDelta + 4] = *(_QWORD *)(SourceEntry + 4);
            *(_OWORD *)&SourceEntry[OffsetDelta + 22] = *(_OWORD *)(SourceEntry + 12);
        }
        SourceEntry += 48;
        --EntryCount;
    } while (EntryCount);
    return Result;
}

// CopyServiceTablePartial — 部分复制服务表
// 对应原始驱动 sub_1400175D8
// 从 GtAlloc 分配的缓冲区复制 27 个服务表条目，过滤条件为条目索引==1 且值非零
__int64 CopyServiceTablePartial(__int64 SourceTable)
{
    char Result;
    __int64 *AllocBuffer;
    __int64 EntryCount;
    char *SourceEntry;
    __int64 OffsetDelta;

    Result = 0;
    AllocBuffer = GtAlloc(GtInitHookSyscallAddress | GtObjectTypeField35 | 0x1400);
    EntryCount = 27;
    SourceEntry = (char *)AllocBuffer + 4;
    OffsetDelta = SourceTable - (_QWORD)AllocBuffer;
    do
    {
        *(_DWORD *)&SourceEntry[OffsetDelta] = *(_DWORD *)SourceEntry;
        if (*(_DWORD *)SourceEntry && *((_DWORD *)SourceEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&SourceEntry[OffsetDelta + 4] = *(_QWORD *)(SourceEntry + 4);
            *(_OWORD *)&SourceEntry[OffsetDelta + 22] = *(_OWORD *)(SourceEntry + 12);
        }
        SourceEntry += 48;
        --EntryCount;
    } while (EntryCount);
    return Result;
}

// ResolveContextMemoryBlocks — 解析上下文内存块
// 对应原始驱动 sub_140039120
// 遍历指定数量的条目，比较函数地址与原始地址，若不同则标记为已修改。对每条目验证地址有效后比较原始字节，若被 Hook 则标记并保存原始地址
__int64 ResolveContextMemoryBlocks(__int64 pContextTable, unsigned int EntryCount)
{
    __int64 pEntryScan;
    __int64 ScanCount;
    ULONG EntryIndex;
    __int64 pEntry;
    UCHAR ByteIndex;
    __int64 TranslatedAddress;

    if (EntryCount)
    {
        pEntryScan = pContextTable + 8;
        ScanCount = EntryCount;
        do
        {
            if (*(_QWORD *)pEntryScan && *(_QWORD *)pEntryScan != *(_QWORD *)(pEntryScan + 8))
                *(_BYTE *)(pEntryScan + 16) = 1;
            pEntryScan += 48;
            --ScanCount;
        } while (ScanCount);
    }

    EntryIndex = 0;
    if (EntryCount)
    {
        pEntry = pContextTable + 8;
        do
        {
            if (*(_QWORD *)pEntry)
            {
                if (MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + 15)) == 1)
                {
                    if ((unsigned int)MemoryCompare(*(_QWORD *)pEntry, (char *)(48 * EntryIndex + pContextTable + 26), 0x10u))
                    {
                        *(_BYTE *)(pEntry + 17) = 1;
                        if (*(_BYTE *)(pEntry + 16) == 0)
                        {
                            for (ByteIndex = 0; ByteIndex < 0x10; ++ByteIndex)
                            {
                                if (!MmIsAddressValid((PVOID)(*(_QWORD *)pEntry + ByteIndex)))
                                    break;
                            }
                            if (ByteIndex && ReturnFalseStub() == 1)
                                *(_QWORD *)(pEntry + 8) = TranslatedAddress;
                        }
                    }
                }
            }
            EntryIndex = (ULONG)(EntryIndex + 1);
            pEntry += 48;
        } while ((unsigned int)EntryIndex < EntryCount);
    }
    return 1;
}

// EnumMiniFilterVolumeList — 枚举 Minifilter 卷列表
// 对应原始驱动 sub_1400121D4
// 遍历链表条目，检查内存有效性，解析对象头获取名称，将过滤卷信息写入输出缓冲区，每个条目 296 字节
__int64 EnumMiniFilterVolumeList(
    _QWORD **ListHead,
    __int64 GuidValue,
    __int64 OutputBuffer,
    _DWORD *EntryCount)
{
    __int64 GuidValueCopy;
    char Result;
    _QWORD **CurrentEntry;
    ULONG LoopIndex;
    _QWORD **EntryStruct;
    __int64 NameLength;
    char *NameBuffer;
    __int64 AltNameLength;
    char *AltNameBuffer;
    unsigned __int16 *HeaderInfo;

    GuidValueCopy = GuidValue;
    Result = 0;
    if (*EntryCount)
    {
        CurrentEntry = (_QWORD **)*ListHead;
        for (LoopIndex = 0; LoopIndex < 0x1000; ++LoopIndex)
        {
            if (CurrentEntry == ListHead)
                break;
            if ((ULONG64)CurrentEntry <= (ULONG64)MmSystemRangeStart)
                break;
            EntryStruct = CurrentEntry - 10;
            if ((ULONG64)(CurrentEntry - 10) <= (ULONG64)MmSystemRangeStart)
                break;
            if (CheckMemoryValid(CurrentEntry - 10) != 1)
                break;

            *(_QWORD *)OutputBuffer = EntryStruct;
            *(_QWORD *)(OutputBuffer + 8) = EntryStruct[1];
            WStringCopyN((_WORD *)(OutputBuffer + 16), GuidValueCopy, 0xAu);
            *(_DWORD *)(OutputBuffer + 34) = 0;
            *(_WORD *)(OutputBuffer + 164) = 0;

            if (ResolveObjectHeaderPointer((__int64)(CurrentEntry - 10), &HeaderInfo) == 1)
            {
                NameLength = *HeaderInfo;
                NameBuffer = (char *)*((_QWORD *)HeaderInfo + 1);
                if (NameBuffer)
                {
                    if ((unsigned int)NameLength > 0x80)
                        NameLength = 128;
                    if ((unsigned int)NameLength > 2 &&
                        CheckMemoryValid(*((void **)HeaderInfo + 1)) == 1 &&
                        CheckMemoryValid(&NameBuffer[NameLength - 1]) == 1)
                    {
                        memmove((void *)(OutputBuffer + 36), NameBuffer, (unsigned int)NameLength);
                        *(_WORD *)(OutputBuffer + 162) = 0;
                    }
                }
            }

            if (ResolveObjectHeaderPointer(*(_QWORD *)(OutputBuffer + 8), &HeaderInfo) == 1)
            {
                AltNameLength = *(unsigned __int16 *)(HeaderInfo + 56);
                AltNameBuffer = *(char **)(HeaderInfo + 64);
                if (AltNameBuffer)
                {
                    if ((unsigned int)AltNameLength > 0x80)
                        AltNameLength = 128;
                    if ((unsigned int)AltNameLength > 2 &&
                        CheckMemoryValid(AltNameBuffer) == 1 &&
                        CheckMemoryValid(&AltNameBuffer[AltNameLength - 1]) == 1)
                    {
                        memmove((void *)(OutputBuffer + 164), AltNameBuffer, (unsigned int)AltNameLength);
                        *(_WORD *)(OutputBuffer + 290) = 0;
                    }
                }
            }

            OutputBuffer += 296;
            if (*EntryCount == 1)
                break;
            --(*EntryCount);
            CurrentEntry = (_QWORD **)*CurrentEntry;
            GuidValueCopy = GuidValue;
        }
    }
    return Result;
}

// OpenAndWaitMiniFilterFile — 打开并等待 Minifilter 文件
// 对应原始驱动 sub_140018664
// 使用 GtRead 获取的函数指针创建文件、查询信息、等待操作完成
__int64 OpenAndWaitMiniFilterFile(__int64 ContextBlock)
{
    char Result;
    int (__fastcall *CreateFileFunc)(HANDLE *, _QWORD, int *, _QWORD, _QWORD, __int64 (__fastcall *(__fastcall *)(__int64))(__int64), __int64);
    int (__fastcall *QueryInfoFunc)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD);
    void (__fastcall *WaitFunc)(__int64, _QWORD, _QWORD, __int64, __int64 *);
    void (__fastcall *CloseFunc)(__int64);
    __int64 Alertable;
    int ObjAttr;
    __int64 Attr2;
    __int64 Attr3;
    int CreateOptions;
    _OWORD ObjAttrZero;
    __int64 FileInfo;
    HANDLE Handle;
    __int64 Timeout;

    Result = 0;
    CreateFileFunc = (int (__fastcall *)(HANDLE *, _QWORD, int *, _QWORD, _QWORD, __int64 (__fastcall *(__fastcall *)(__int64))(__int64), __int64))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField182 | GtEprocessField06);
    QueryInfoFunc = (int (__fastcall *)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD))GtRead(GtNtFsControlFileFunc);
    WaitFunc = (void (__fastcall *)(__int64, _QWORD, _QWORD, __int64, __int64 *))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField42);
    CloseFunc = (void (__fastcall *)(__int64))GtRead(GtCloseHandleFunc);

    if (CreateFileFunc)
    {
        if (GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField42))
        {
            if (QueryInfoFunc)
            {
                if (WaitFunc)
                {
                    if (CloseFunc)
                    {
                        memset(&ObjAttrZero, 0, sizeof(ObjAttrZero));
                        ObjAttr = 48;
                        Attr2 = 0;
                        CreateOptions = 512;
                        Attr3 = 0;
                        if (CreateFileFunc(&Handle, 0, &ObjAttr, 0, 0, FsFilterCreateCallback, ContextBlock) >= 0)
                        {
                            if (QueryInfoFunc(Handle, 0x1FFFFF, 0, 0, &FileInfo, 0) >= 0)
                            {
                                Alertable = 1;
                                Timeout = -30000000;
                                WaitFunc(FileInfo, 0, 0, (char)Alertable, &Timeout);
                                CloseFunc(FileInfo);
                            }
                            ZwClose(Handle);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// ParseMiniFilterRegSections — 解析 Minifilter 注册表节
// 对应原始驱动 sub_140011B80
// 读取注册表中 Minifilter 相关的 Sections 信息，解析 GUID 和驱动列表头，初始化四个列表指针（ListHead1-4）存入全局表
void ParseMiniFilterRegSections(void)
{
    __int64 PeFileBase;
    __int64 PeFileSize;
    __int64 NtoskrnlBase;
    __int64 SectionTarget1;
    __int64 SectionTarget2;
    __int64 SectionTarget3;
    ULONG CumulativeSize;
    _DWORD PeSectionEntry[14];
    ULONG FieldValue;
    __int64 SectionDataPtr;
    __int64 ReadContext;
    __int64 SectionFlags;
    ULONG SectionRawSize;
    ULONG ListHead1, ListHead2, ListHead3, ListHead4;
    ULONG SectionIndex;
    ULONG MatchCount;
    ULONG FoundCount;
    ULONG Phase2MatchCount;
    char Phase1Done;
    ULONG SavedValue1, SavedValue2, SavedValue3, SavedValue4;
    ULONG CalculatedOffset;

    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    SectionTarget1 = GtRead(0x435D);
    SectionTarget2 = GtRead(0x4426);
    SectionTarget3 = GtRead(0x4465);

    ListHead1 = 0;
    ListHead2 = 0;
    ListHead3 = 0;
    ListHead4 = 0;
    CumulativeSize = 0;
    Phase1Done = 0;
    SavedValue1 = 0;
    SavedValue2 = 0;
    SavedValue3 = 0;
    SavedValue4 = 0;
    FoundCount = 0;
    MatchCount = 0;

    if (!PeFileBase || !PeFileSize || !NtoskrnlBase ||
        !SectionTarget1 || !SectionTarget2 || !SectionTarget3)
        return;

    if ((ULONG)SectionTarget2 >= (ULONG)PeFileSize)
        return;

    // Phase 1: 扫描 PE 节区，查找 0x558 标记的节
    InitPESectionReadContext(
        (ULONG)SectionTarget2 + PeFileBase,
        (ULONG)PeFileSize - (ULONG)SectionTarget2,
        2, 0, -1, 0, 0, (__int64)&ReadContext);

    CumulativeSize = 0;
    for (SectionIndex = 0; SectionIndex < 0x1E; SectionIndex++)
    {
        if (ReadPESectionEntry(&ReadContext, PeSectionEntry))
            break;

        SectionRawSize = PeSectionEntry[11];
        CumulativeSize += SectionRawSize;

        // 从 SectionDataPtr 获取 section flags
        SectionDataPtr = *(__int64 *)&PeSectionEntry[12];
        SectionFlags = *(WORD *)(SectionDataPtr + 6);

        if (SectionFlags == 0x558)
        {
            CalculatedOffset = PeSectionEntry[9] - (ULONG)PeFileBase + CumulativeSize;
            if (CalculatedOffset == (ULONG)SectionTarget3)
                FoundCount++;
            else if (CalculatedOffset == (ULONG)SectionTarget2)
                SavedValue1 = (ULONG)SectionTarget2;
            else if (!SavedValue1)
                SavedValue1 = CalculatedOffset;
        }
    }

    // Phase 2: 扫描 0x512 标记的节
    InitPESectionReadContext(
        (ULONG)SectionTarget2 + PeFileBase,
        (ULONG)PeFileSize - (ULONG)SectionTarget2,
        2, 0, -1, 0, 0, (__int64)&ReadContext);

    CumulativeSize = 0;
    MatchCount = 0;

    for (SectionIndex = 0; SectionIndex < 0xC8; SectionIndex++)
    {
        if (ReadPESectionEntry(&ReadContext, PeSectionEntry))
            return;

        SectionRawSize = PeSectionEntry[11];
        CumulativeSize += SectionRawSize;

        SectionDataPtr = *(__int64 *)&PeSectionEntry[12];
        SectionFlags = *(WORD *)(SectionDataPtr + 6);

        if (SectionFlags == 0x558)
        {
            CalculatedOffset = PeSectionEntry[9] - (ULONG)PeFileBase + CumulativeSize;
            if (CalculatedOffset == (ULONG)SectionTarget1)
            {
                MatchCount++;
                if (MatchCount >= 3 && ListHead1 && ListHead2 && ListHead3 && ListHead4)
                    goto WriteResults;
            }
        }

        if (SectionFlags == 0x512)
        {
            if (*(__int64 *)&PeSectionEntry[7] == 0x40000 &&
                PeSectionEntry[10] != 0 &&
                *(__int64 *)&PeSectionEntry[4] == 0x40 &&
                *(_DWORD *)&PeSectionEntry[6] == 1)
            {
                CalculatedOffset = PeSectionEntry[9] - (ULONG)PeFileBase + CumulativeSize;
                if (CalculatedOffset != 0 && (ULONG)CalculatedOffset < (ULONG)PeFileSize)
                {
                    ListHead1 = ListHead2;
                    ListHead2 = ListHead3;
                    ListHead3 = ListHead4;
                    ListHead4 = CalculatedOffset + (ULONG)NtoskrnlBase;
                }
            }
        }
    }

    // Phase 3: 如果 FoundCount (阶段1中匹配 0x558 且值==SectionTarget3 的计数) > 0, 重新扫描
    if (FoundCount > 0)
    {
        InitPESectionReadContext(
            (ULONG)SectionTarget2 + PeFileBase,
            (ULONG)PeFileSize - (ULONG)SectionTarget2,
            2, 0, -1, 0, 0, (__int64)&ReadContext);

        CumulativeSize = 0;
        MatchCount = 0;
        ListHead1 = 0;
        ListHead2 = 0;
        ListHead3 = 0;
        ListHead4 = 0;
        SavedValue1 = 0;
        SavedValue2 = 0;
        SavedValue3 = 0;
        SavedValue4 = 0;

        for (SectionIndex = 0; SectionIndex < 0xC8; SectionIndex++)
        {
            if (ReadPESectionEntry(&ReadContext, PeSectionEntry))
                return;

            SectionRawSize = PeSectionEntry[11];
            CumulativeSize += SectionRawSize;

            SectionDataPtr = *(__int64 *)&PeSectionEntry[12];
            SectionFlags = *(WORD *)(SectionDataPtr + 6);

            if (SectionFlags == 0x512)
            {
                if (*(__int64 *)&PeSectionEntry[7] == 0x40000 &&
                    PeSectionEntry[10] != 0 &&
                    *(__int64 *)&PeSectionEntry[4] == 0x40 &&
                    *(_DWORD *)&PeSectionEntry[6] == 1)
                {
                    CalculatedOffset = PeSectionEntry[9] - (ULONG)PeFileBase + CumulativeSize;
                    if (CalculatedOffset != 0 && (ULONG)CalculatedOffset < (ULONG)PeFileSize)
                    {
                        SavedValue1 = SavedValue2;
                        SavedValue2 = SavedValue3;
                        SavedValue3 = SavedValue4;
                        SavedValue4 = CalculatedOffset + (ULONG)NtoskrnlBase;
                    }
                }
            }

            if (SectionFlags == 0x558)
            {
                CalculatedOffset = PeSectionEntry[9] - (ULONG)PeFileBase + CumulativeSize;
                if (CalculatedOffset == (ULONG)SectionTarget1)
                {
                    MatchCount++;
                    if (MatchCount >= 3 && SavedValue1 && SavedValue2 && SavedValue3 && SavedValue4)
                    {
                        ListHead1 = SavedValue1;
                        ListHead2 = SavedValue2;
                        ListHead3 = SavedValue3;
                        ListHead4 = SavedValue4;
                        goto WriteResults;
                    }
                    MatchCount = 0;
                }
            }
        }
    }

WriteResults:
    GtWrite((GLOBAL_TABLE_INDEX)0x89F, ListHead1);
    GtWrite((GLOBAL_TABLE_INDEX)0x8A0, ListHead2);
    GtWrite((GLOBAL_TABLE_INDEX)0x8A1, ListHead3);
    GtWrite((GLOBAL_TABLE_INDEX)0x89E, ListHead4);
}

// CheckMemoryValid was moved to MemoryOps.c

// FsFilterCreateCallback — 文件系统过滤器创建回调
// 对应原始驱动 sub_140018E28
// 读取创建文件函数和 FltUnregisterFilter 函数指针，调用后返回
__int64 (__fastcall *__fastcall FsFilterCreateCallback(__int64 FilterContext))(__int64)
{
    __int64 (__fastcall *(__fastcall *CreateFileFunc)(_QWORD))(__int64);
    __int64 (__fastcall *result)(__int64);

    CreateFileFunc = (__int64 (__fastcall *(__fastcall *)(_QWORD))(__int64))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField42);
    result = (__int64 (__fastcall *)(__int64))GtRead(GtFltUnregisterFilterAddr);
    if (FilterContext && result)
        result = (__int64 (__fastcall *)(__int64))result(FilterContext);
    if (CreateFileFunc)
        return CreateFileFunc(0);
    return result;
}
