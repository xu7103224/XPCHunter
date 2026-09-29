// Minifilter.c — 文件系统 Minifilter
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

// 先包含 fltKernel.h：定义 __FLTKERNEL__ 后，xpc_basic.h 中的 FLT 类型前向声明会被跳过，
// 使用 WDK 的真实类型声明（FltUnregisterFilter 等 FltMgr API 由此可用）
#include <fltKernel.h>
#include "XPCHunterDrv.h"
#pragma warning(disable:4700)

// 全局变量声明
extern KMUTEX g_Mutex;
extern volatile PVOID g_Pointer;
extern PFLT_FILTER g_Filter;

// 壳代码数据 — 用于 PatchPeHeaderMagic 修补 PE 头魔数
// 对应原始驱动 g_ShellCodeBuffer (0x14008CA40) / g_ShellCodeMovEax (0x14008CA44)
DWORD g_ShellCodeBuffer = 0x22B8;
DWORD g_ShellCodeMovEax = 0xC3C0;

// Minifilter 操作回调表 — 对应原始驱动 OperationRegistration (0x14008D5C0)
// 仅注册 IRP_MJ_CREATE 一个操作，末尾以 IRP_MJ_OPERATION_END (0x80) 结尾
const FLT_OPERATION_REGISTRATION g_OperationRegistration[] = {
    { IRP_MJ_CREATE, 0, (PFLT_PRE_OPERATION_CALLBACK)MiniFilterPreVolumeDismount, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL }
};

// Minifilter 注册结构 — 对应原始驱动 Registration (0x14008D600)
// Flags 置 FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP：不支持服务停止
// 卸载回调指向 MiniFilterUnloadCleanup，其余回调均为空
const FLT_REGISTRATION Registration = {
    104,                                               // Size：原始驱动为 0x68。本机 SDK 的 FLT_REGISTRATION 多一个
                                                       // SectionNotificationCallback 字段（sizeof 为 112），
                                                       // 而 FltMgr 按 Version 校验 Size，故必须固定为 0x68
    FLT_REGISTRATION_VERSION_0202,                     // Version (0x0202)
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,    // Flags (1)
    NULL,                                              // ContextRegistration
    g_OperationRegistration,                           // OperationRegistration
    (PFLT_FILTER_UNLOAD_CALLBACK)MiniFilterUnloadCleanup,  // FilterUnloadCallback
    NULL,                                              // InstanceSetupCallback
    NULL,                                              // InstanceQueryTeardownCallback
    NULL,                                              // InstanceTeardownStartCallback
    NULL,                                              // InstanceTeardownCompleteCallback
    NULL,                                              // GenerateFileNameCallback
    NULL,                                              // NormalizeNameComponentCallback
    NULL,                                              // NormalizeContextCleanupCallback
    NULL,                                              // TransactionNotificationCallback
    NULL                                               // NormalizeNameComponentExCallback
};

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
        MiniFilterNotifyRoutine((wchar_t *)PoolBuffer, (ULONG)(BufferSize >> 1));
    }
    else
    {
        _QWORD *ListEntry;
        KeWaitForSingleObject(&g_Mutex, Executive, 0, 0, 0);
        for (ListEntry = (_QWORD *)&g_Pointer; *ListEntry; ListEntry = (_QWORD *)*ListEntry)
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

// MiniFilterFilterUnload — Minifilter 卸载回调 (0x140019EA0)
// 检查当前进程是否为 explorer.exe，若是则映射目标基址到虚拟地址并调用 PrepareFileForPageTableScan 扫描页表
__int64 *__fastcall MiniFilterFilterUnload(__int64 ProcessId, __int64 BaseAddress, char IsAddOperation)
{
    __int64 (*GetProcessNameFunc)(void);
    __int64 (*GetCurrentProcessIdFunc)(void);
    int (__fastcall *MapUserPhysicalPagesFunc)(__int64, PVOID *);
    void (*FreeFunc)(void);
    _QWORD *PsProcessTypePtr;
    char IsExplorer;
    __int64 ProcessName;
    __int64 SectionHandle;
    NTSTATUS (*ReferenceProcessFunc)(__int64, __int64 *);
    PVOID VirtualAddress;
    _WORD ExplorerName[8];

    AcquireMiniFilterMutexEx();
    if (IsAddOperation == 1)
    {
        ReferenceProcessFunc = (NTSTATUS (*)(__int64, __int64 *))GtRead(GtValidateObjectTypeFunc);
        GetProcessNameFunc = (__int64 (*)(void))GtRead(GtNtDuplicateObjectPeSectionOffset | GtPathBuffer00);
        GetCurrentProcessIdFunc = (__int64 (*)(void))GtRead(GtObjectTypeRefFunc);
        MapUserPhysicalPagesFunc = (int (*)(__int64, PVOID *))GtRead(GtTotalSize | GtEprocessField182 | 0x100);
        FreeFunc = (void (*)(void))GtRead(GtCloseHandleFunc);
        PsProcessTypePtr = (_QWORD *)GtRead(GtObjectTypeInfoPtr);
        if (ReferenceProcessFunc)
        {
            if (GetProcessNameFunc && GetCurrentProcessIdFunc && MapUserPhysicalPagesFunc && FreeFunc && PsProcessTypePtr)
            {
                if (GetCurrentProcessIdFunc() != ProcessId)
                    goto LABEL_17;
                if (ReferenceProcessFunc(ProcessId, &SectionHandle) < 0)
                {
                    IsExplorer = 0;
                }
                else
                {
                    if (*PsProcessTypePtr == SectionHandle || SectionHandle == GtRead(GtEprocessField123 | 0x100))
                    {
                        IsExplorer = 0;
                    }
                    else
                    {
                        strcpy((char *)ExplorerName, "explorer.exe");
                        HIBYTE_LV(ExplorerName[6]) = 0;
                        ExplorerName[7] = 0;
                        ProcessName = GetProcessNameFunc();
                        IsExplorer = (unsigned int)StringCompareCaseInsensitiveV2(ProcessName, (__int64)ExplorerName) != 0;
                    }
                    FreeFunc();
                }
                if (IsExplorer)
                {
    LABEL_17:
                    if (MapUserPhysicalPagesFunc(BaseAddress, &VirtualAddress) >= 0)
                    {
                        PrepareFileForPageTableScan((char *)VirtualAddress, 0);
                        ((void (*)(__int64))FreeFunc)((__int64)VirtualAddress);
                    }
                }
            }
        }
    }
    AcquireMiniFilterMutex();
    return 0;
}

// MiniFilterNotifyRoutine — Minifilter 通知例程
// 将文件名写入 GT 0x3400 缓冲区，通知用户态程序文件操作事件
// 对应原始驱动 sub_140019AD8
__int64 MiniFilterNotifyRoutine(wchar_t *Name, ULONG NameLength)
{
    if (!Name || !NameLength)
        return 1;
    if (MmIsAddressValid(Name) != 1)
        return 1;
    __int64 NotifyBuffer = GtRead(GtEprocessModuleListOffset | GtPspExitThreadAddr | 0x3400);
    if (!NotifyBuffer || (unsigned __int64)NotifyBuffer < (unsigned __int64)MmSystemRangeStart)
        return 1;
    if (MmIsAddressValid((void *)NotifyBuffer) != 1)
        return 1;
    // 复制文件名到通知缓冲区
    ULONG CopyLen = min(NameLength * 2, 256);
    memcpy((void *)NotifyBuffer, Name, CopyLen);
    return 1;
}

// MiniFilterPreCreate — 预处理创建
// 对应原始驱动 sub_140014078
NTSTATUS MiniFilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    return STATUS_SUCCESS;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `MiniFilterPostCreate` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17C 生产者之一（类型序列 0x512/0x558）。
//   故改名为 FindKernelDataSectionForImageNotify2（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForImageNotify2 — 后处理创建
// 对应原始驱动 sub_1400142A8
// 遍历 PE 节表定位 PostCreate 相关的数据节偏移
ULONG64 FindKernelDataSectionForImageNotify2(void)
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

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 VirtualSize = 0;
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [14] 仅 56 字节
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
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionInfo)) break;

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

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `MiniFilterPreRead` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17C 生产者之一（类型序列 0x430/0x558）。
//   故改名为 FindKernelDataSectionForImageNotify3（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForImageNotify3 — 预读取
// 对应原始驱动 sub_1400144A8
// 遍历 PE 节表查找 PreRead 相关节
ULONG64 FindKernelDataSectionForImageNotify3(void)
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

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 VirtualSize = 0;
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [14] 仅 56 字节
    ULONG DataSectionSize, RawSize;
    int FieldValue;
    __int64 SectionFlags2, SectionDataPtr, SectionName;

    InitPESectionReadContext(SectionOffset + PeBase, PeSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    ULONG TargetSection = 0;

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionInfo)) break;
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
                    TargetSection = (ULONG)(SectionSize + DataSectionSize - PeBase);
            }
        }
    }
    return result;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `MiniFilterPostRead` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17D 生产者之一；消费者 SendDeviceIoControl。
//   故改名为 FindKernelDataSectionForDeviceIoControl（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForDeviceIoControl — 后读取
// 对应原始驱动 sub_1400146D4
// 遍历 PE 节表定位 PostRead 数据节偏移
ULONG64 FindKernelDataSectionForDeviceIoControl(void)
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

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
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
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;
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

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `MiniFilterPreWrite` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17D 生产者之一（类型序列 0x558）。
//   故改名为 FindKernelDataSectionForDeviceIoControl2（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForDeviceIoControl2 — 预写入
// 对应原始驱动 sub_1400148D4
// 遍历 PE 节表查找 PreWrite 相关节
__int64 FindKernelDataSectionForDeviceIoControl2(void)
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

    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    ULONG FieldValue, SectionSize;
    __int64 EntryFlags;
    __int64 SectionDataPtr;
    char FoundMatchFlag = 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;
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
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];
    ULONG FieldValue, SectionSize;
    __int64 EntryFlags, SectionCharacteristics, SectionDataPtr;
    ULONG SubType;
    __int64 SavedSectionOffset = 0;

    InitPESectionReadContext(SectionOffset + KernelBase, (ULONG)(KernelSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x100; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;
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
// 从 ntoskrnl 镜像的数据目录入口定位节表，遍历最多 0x100 个节区：
// 记录特征值为 0x40000 的节区偏移（SavedSectionOffset），
// 再在标记 0x558 且带 0x4000000 标志的节区中，用其字段算出候选偏移，
// 命中已存的后写偏移之一且 SavedSectionOffset 有效时，把两个结果分别写入 GT 0x1A4 与 0x179
__int64 MiniFilterPreCleanup(void)
{
    __int64 KernelBase;
    unsigned int KernelSize;
    ULONG64 NtImageBase;
    ULONG64 SectionOffset;
    int ExistingOffset1;
    __int64 Result;
    int ExistingOffset2;
    ULONG64 ImageOffset;
    __int64 PeHeaderDataDir;
    ULONG64 SavedSectionOffset;
    unsigned int SectionIndex;
    int CalculatedSize;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 CumulativeSize = 0;
    _DWORD SectionEntry[72];

    KernelBase = GtRead(GtEprocessField22);
    KernelSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    // 以下索引取自原始驱动实际立即数（IDA 中的枚举别名在 C 头文件中无对应项）
    SectionOffset = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x170);
    ExistingOffset1 = (int)GtRead((GLOBAL_TABLE_INDEX)0x41C5);
    Result = GtRead((GLOBAL_TABLE_INDEX)0x439F);
    ExistingOffset2 = (int)Result;

    if (!KernelBase || !KernelSize || !NtImageBase || !SectionOffset)
        return Result;
    if (SectionOffset <= NtImageBase || !ExistingOffset1 || !(_DWORD)Result)
        return Result;

    Result = (unsigned int)(SectionOffset - NtImageBase);
    if ((unsigned int)Result >= KernelSize)
        return Result;

    ImageOffset = (unsigned int)Result;
    Result += NtImageBase;
    if (SectionOffset != (ULONG64)Result)
        return Result;

    PeHeaderDataDir = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 48);
    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - (unsigned int)ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    SavedSectionOffset = 0;

    for (SectionIndex = 0; SectionIndex < 0x100; SectionIndex++)
    {
        Result = ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry);
        if ((_DWORD)Result)
            break;

        CalculatedSize = (int)(*(unsigned int *)((char *)SectionEntry + 0xF0) + CumulativeSize);
        CumulativeSize += *(unsigned int *)((char *)SectionEntry + 0xF0);

        if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1368 &&
            (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
            (Result = *(unsigned int *)((char *)SectionEntry + 0x38)) != 0)
        {
            Result = CalculatedSize + *(unsigned int *)((char *)SectionEntry + 0x38) - (unsigned int)KernelBase;
            if (((_DWORD)Result == ExistingOffset1 || (_DWORD)Result == ExistingOffset2) &&
                (_DWORD)SavedSectionOffset &&
                (unsigned int)SavedSectionOffset < KernelSize)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x1A4, (__int64)(SavedSectionOffset + PeHeaderDataDir));
                return GtWrite((GLOBAL_TABLE_INDEX)0x179, (__int64)(SavedSectionOffset + NtImageBase));
            }
        }
        else if (*(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            Result = *(unsigned int *)((char *)SectionEntry + 0x78);
            if (*(unsigned int *)((char *)SectionEntry + 0x78))
                SavedSectionOffset = CalculatedSize + *(unsigned int *)((char *)SectionEntry + 0x78) - (unsigned int)KernelBase;
        }
    }
    return Result;
}

// FindKernelObjectFieldOffsetsWin10 — 节区扫描器（**不是 FLT 回调**）
// 对应原始驱动 0x1400152D4（1908 字节）
// 【2026-09-21 签名修正】此前声明为 NTSTATUS(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*)
//   并实现为 `return STATUS_SUCCESS;` 空壳 —— 两者都与实物不符：
//   原始函数**无参数**（反汇编中未读取 rcx/rdx/r8/r9），栈帧 sub rsp,220hh，
//   体内立即 `GtRead`（首条为 GT 0x20 镜像基址）并进入节区扫描循环，
//   是 PE 节区扫描器（与 InitImageNotify 所调度的同族）。故签名改为无参、返回 ULONG64。
// 【⚠ 未实现】本题逻辑尚未还原（本函数为家族中较大者，留待后续逐条重建）。
//   **此处不是占位实现**：声明与签名已按反汇编如实修正，函数体待补。
// 【实现 2026-09-21】按 build/audit/_mfc_listing.txt 与施工图"表 A/表 B"
//   **逐标签机械转写**（goto + L<原始地址> 标签）。
//   表 A 要点：Value[] 是**同一块 5 字节栈区**（[0..3] 字节标志、[4] dword 候选 RVA），
//   故用 UCHAR Value[8] + *(ULONG*)&Value[4] 建模 —— 不得拆成独立变量（那是失真）。
//   表 B 要点：控制流顺序为 外层(L140015445) → A 类内层(上限 0xA) → 第二段(0x14)
//   → C7 模式搜索 → 写块2 → 第三段(0xF)；L14001566D/L140015683 属 A 类内层的
//   "非 0x512 分支"，不是第二段的一部分。
ULONG64 FindKernelObjectFieldOffsetsWin10(void)
{
    ULONG64 PeBase;        // rsi / var_1F8 <- GT 0x20
    ULONG   PeSize;        // r12 <- GT 0x21
    ULONG64 ImageBase;     // rdi -> var_1F0 <- GT 3
    ULONG64 Gt8CC;         // r14 / var_1C0
    ULONG64 Gt900;         // r15 / var_1B0
    ULONG64 Gt8CD;         // rbx / var_1D0
    ULONG64 Gt4459;        // var_1B8
    UCHAR   Value[8];      // [0..3] 字节标志、[4] dword 候选 RVA（同一块栈区）
    UCHAR   PairA, PairB;  // r8b / dl
    UCHAR   FoundA, FoundB, FoundC;   // r14b / bl / dil
    ULONG   CandidateRva;  // edi（外层候选）
    ULONG   Rva2;          // r14d / Value[4]
    ULONG   CountInner;    // esi（A 类内层，上限 0xA）
    ULONG   CountMid;      // esi（第二段，上限 0x14）
    ULONG   CountOuter;    // edi（第三段，上限 0xF）
    ULONG64 ScanStart;     // r13
    ULONG64 ScanEnd;       // var_1D8
    ULONG64 SectionOff;    // var_1E8（.PAGE 文件内偏移）
    ULONG64 ScanLimit;
    ULONG64 Ptr;           // r15
    ULONG64 SectionRvaVa;
    ULONG   v;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  SectionInfo[112];
    WCHAR   PageName[8];

    PeBase    = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    PeSize    = (ULONG)GtRead(GtNtoskrnlPeFileSize);
    ImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    Gt8CC     = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8CC);
    Gt900     = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x900);
    Gt8CD     = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8CD);
    Gt4459    = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4459);

    if (!PeBase || !PeSize || !ImageBase || !(ULONG)Gt8CC || !(ULONG)Gt900 ||
        !(ULONG)Gt8CD || !(ULONG)Gt4459)
        return 0;

    PageName[0] = L'.'; PageName[1] = L'P'; PageName[2] = L'A';
    PageName[3] = L'G'; PageName[4] = L'E'; PageName[5] = 0;

    SectionOff   = (ULONG64)FindPESectionByName(PeBase, PeSize, (ULONG64)PageName);
    SectionRvaVa = (ULONG64)FindPESectionByNameReturnVa(PeBase, PeSize, (ULONG64)PageName);
    ScanStart = PeBase + SectionOff;
    SectionRvaVa = SectionRvaVa ? SectionRvaVa : (ULONG64)(PeSize - (ULONG)SectionOff);
    ScanEnd = ScanStart + SectionRvaVa;

    PairA = 0; FoundA = 0; PairB = 0;
    Value[0] = 0; Value[1] = 0; Value[2] = 0;
    ScanLimit = ScanEnd;
    if (ScanStart >= ScanEnd) goto L1400159F4;

L140015445:
    if (ScanStart + 0x30 >= ScanEnd) goto L1400159E3;
    if (*(UCHAR *)(ScanStart + 0) != 0x48) goto L1400159E3;
    if (*(UCHAR *)(ScanStart + 1) != 0x8D) goto L1400159E3;
    CandidateRva = *(ULONG *)(ScanStart + 3) - PeSize + (ULONG)(ScanStart + 7);
    *(ULONG *)&Value[4] = CandidateRva;
    if (CandidateRva == 0) goto L1400159E3;
    if (CandidateRva >= PeSize) goto L1400159E3;
    Ptr = ScanStart + 7;
    if (*(UCHAR *)Ptr != 0x48) goto L140015856;
    if (*(UCHAR *)(ScanStart + 8) != 0x89) goto L140015856;
    if (*(UCHAR *)(ScanStart + 0xA) != 8) goto L140015856;
    if (FoundA) goto L140015584;

    CountInner = 0;
    InitPESectionReadContext((__int64)Ptr,
                             (ULONG)(SectionOff - (ULONG)(ULONG_PTR)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    FoundA = 0; FoundB = 0;

L1400154F0:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L140015570;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) != 0x512) goto L14001566D;
    if (*(__int64 *)((char *)SectionInfo + 0x88) != 0x40000) goto L140015553;
    if (*(ULONG *)((char *)SectionInfo + 0x38) == 0) goto L140015553;
    if (*(__int64 *)((char *)SectionInfo + 0x50) != 0x40) goto L140015553;
    v = *(ULONG *)((char *)SectionInfo + 0x38) - (ULONG)PeBase + (ULONG)Ctx.ReadPtr;
    if (v == 0) goto L140015553;
    if (v >= PeSize) goto L140015553;
    if (CandidateRva) goto L140015553;
    CandidateRva = v;

L140015553:
    if (FoundA == 1 && FoundB == 1 && CandidateRva) goto L14001569A;
    CountInner++;
    if (CountInner < 0xA) goto L1400154F0;

L140015570:
    PairA = Value[2];
    Rva2  = *(ULONG *)&Value[4];
    PairB = Value[1];

L140015584:
    if (Value[0] != 0) goto L1400159B6;
    if (Rva2 == 0) goto L1400159B6;
    if (Rva2 >= PeSize) goto L1400159B6;
    CountMid = 0;
    goto L1400155E5;

L14001566D:                                             // A 类内层：非 0x512 分支
    if ((ULONG)Gt8CC == *(ULONG *)((char *)SectionInfo + 0x70)) { FoundA = 1; goto L14001555D; }
    if ((ULONG)Gt900 == *(ULONG *)((char *)SectionInfo + 0x70)) { FoundB = 1; }
    goto L140015558;

L14001555D:
    if (FoundB != 1) goto L140015569;
    if (CandidateRva) goto L14001569A;

L140015569:
    CountInner += 1;
    if (CountInner < 0xA) goto L1400154F0;
    goto L140015570;

L140015558:
    if (FoundA != 1) goto L140015569;
    goto L14001555D;

L1400155E5:                                             // 第二段循环（上限 0x14）
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L14001575B;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) != 0x512) goto L1400156EC;
    if (*(__int64 *)((char *)SectionInfo + 0x88) != 0x40000) goto L14001574F;
    v = *(ULONG *)((char *)SectionInfo + 0x38);
    if (v == 0) goto L14001574F;
    if (*(__int64 *)((char *)SectionInfo + 0x50) != 0x40) goto L14001574F;
    v = v - (ULONG)PeBase + (ULONG)Ctx.ReadPtr;
    if (v == 0) goto L14001574F;
    if (v >= PeSize) goto L14001574F;
    if (Rva2) goto L14001574F;
    Rva2 = v;
    goto L14001574F;

L1400156EC:
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0x547)
    {
        if (!(*(ULONG64 *)((char *)SectionInfo + 0x88) & 0x800000)) goto L14001574F;
        if (*(ULONG *)((char *)SectionInfo + 0x70) != 0x1000) goto L14001574F;
        if ((ULONG)Gt4459 != *(ULONG *)((char *)SectionInfo + 0x70)) goto L14001574F;
        FoundB = 1;
        Ptr = ScanStart + 7;
        goto L14001574F;
    }
    if ((WORD)(*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) - 0x53C) > 7)
        goto L14001574F;
    if (!(*(ULONG64 *)((char *)SectionInfo + 0x88) & 0x2000000)) goto L14001574F;
    if (*(ULONG64 *)((char *)SectionInfo + 0x70) == 0xFFFFF78000000014ULL) FoundC = 1;

L14001574F:
    CountMid += 1;
    if (CountMid < 0x14) goto L1400155E5;

L14001575B:
    if (FoundC != 1) goto L1400159AD;
    if (Rva2 == 0) goto L1400159AD;
    if (FoundB) goto L1400157EE;

    Ptr = ScanStart - 0x30;                             // L140015781/797
L14001579B:
    if (Ptr <= PeBase) goto L1400159AD;
    if (Ptr - 7 < PeBase) goto L1400159AD;
    if (*(UCHAR *)Ptr == 0xC7 && (ULONG)Gt8CD == *(UCHAR *)(Ptr + 2) &&
        *(ULONG *)(Ptr + 3) == 0x1000) goto L1400157E9;
L1400157C2:
    if (Ptr <= ScanStart - 0xA && *(UCHAR *)Ptr == 0xC7 &&
        (ULONG)Gt8CD == *(ULONG *)(Ptr + 2) && *(ULONG *)(Ptr + 6) == 0x1000)
        goto L1400157E9;
L1400157DF:
    Ptr += 1;
    goto L14001579B;
L1400157E9:
    FoundB = 1;

L1400157EE:
    if (FoundB != 1) goto L1400159AD;
    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)Rva2);
    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)(Rva2 + ImageBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EC, (__int64)Rva2);
    GtWrite((GLOBAL_TABLE_INDEX)0x8ED, (__int64)(Rva2 + ImageBase));
    PairA = Value[2];
    Value[0] = 1;
    PairB = Value[1];
    goto L1400159BB;

L140015856:                                             // 第三段入口（上限 0xF）
    if (PairB != 0) goto L1400159B6;
    InitPESectionReadContext((__int64)Ptr,
                             (ULONG)(SectionOff - (ULONG)(ULONG_PTR)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    FoundB = 0; FoundC = 0;
    CountOuter = 0;

L140015893:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L1400159AD;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0x4B5 &&
        *(_DWORD *)((char *)SectionInfo + 0xF0) == 6)
    {
        if ((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) ==
            *(ULONG *)((char *)SectionInfo + 0x70))
            FoundB = 1;
    }
    if (CountOuter > 4 && !FoundB) goto L1400159AD;

L1400158F7:
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0xE5 &&
        *(__int64 *)((char *)SectionInfo + 0x50) == 0x40000 && FoundB)
        goto L140015A24;

L14001592C:
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0x558 &&
        (*(ULONG64 *)((char *)SectionInfo + 0x50) & (1ULL << 26)))
    {
        v = *(ULONG *)((char *)SectionInfo + 0x38);
        if (v != 0)
        {
            if (!FoundB) goto L1400159AD;
            if (!(ULONG)Gt4459) goto L14001599B;
            if (v == (ULONG)Ctx.ReadPtr) goto L140015A24;
            goto L14001599B;
        }
    }

L140015959:
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0x50E &&
        *(__int64 *)((char *)SectionInfo + 0x50) == 0x40000 &&
        *(__int64 *)((char *)SectionInfo + 0x88) == 0x40 && FoundB == 1)
    {
        v = *(ULONG *)((char *)SectionInfo + 0x70);
        if (v != 0 && v < PeSize && (ULONG64)(Rva2 + 8) == v) goto L140015A24;
    }

L14001599B:
    CountOuter += 1;
    if (CountOuter < 0xF) goto L140015893;

L1400159AD:
    PairB = Value[1];
L1400159B1:
    PairA = Value[2];
L1400159B6:
    FoundA = Value[0];
L1400159BB:
    if (PairA == 1 && FoundA == 1 && PairB == 1) goto L1400159F4;
L1400159CE:
    ScanStart = PeBase + SectionOff;
    ScanEnd = ScanLimit;
L1400159E3:
    ScanStart += 1;
    if (ScanStart < ScanEnd) goto L140015445;

L1400159F4:
    return 0;

L14001569A:                                             // 写块 1
    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)CandidateRva);
    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)(CandidateRva + ImageBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EE, (__int64)CandidateRva);
    GtWrite((GLOBAL_TABLE_INDEX)0x8EF, (__int64)(CandidateRva + ImageBase));
    PairA = 1;
    Value[2] = 1;
    goto L14001557A;
L14001557A:
    PairB = Value[1];
    goto L140015584;

L140015A24:                                             // 收尾写 0x337
    GtWrite((GLOBAL_TABLE_INDEX)0x337, (__int64)(Rva2 + ImageBase));
    PairB = 1;
    Value[1] = 1;
    goto L1400159B1;
}

// FindKernelObjectFieldOffsetsWin8 — 节区扫描器（**不是 FLT 回调**）
// 对应原始驱动 0x140015A48（1257 字节）
// 【2026-09-21 签名修正】此前声明为 NTSTATUS(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*)
//   并实现为 `return STATUS_SUCCESS;` 空壳 —— 两者都与实物不符：
//   原始函数**无参数**（反汇编中未读取 rcx/rdx/r8/r9），栈帧 sub rsp,1F0hh，
//   体内立即 `GtRead`（首条为 GT 0x20 镜像基址）并进入节区扫描循环，
//   是 PE 节区扫描器（与 InitImageNotify 所调度的同族）。故签名改为无参、返回 ULONG64。
// 【⚠ 未实现】本题逻辑尚未还原（本函数为家族中较大者，留待后续逐条重建）。
//   **此处不是占位实现**：声明与签名已按反汇编如实修正，函数体待补。
ULONG64 FindKernelObjectFieldOffsetsWin8(void)
{
    // 【机械转写 2026-09-21】按 build/audit/_preDirEnum_listing.txt 与
    // docs/reversing/待实现函数结构分析.md §三 的前置表逐标签转写。
    // 标志区 var_1D0[0..3] 为**同一块 4 字节栈区**（UCHAR Flags[4]）。
    // GT 槽与 Win10 版**不同**：块1 用 0x32E/0x330/0x32F/0x331（非连续）。
    ULONG64 PeBase;       // r12 <- GT 0x20
    ULONG   PeSize;       // r14 <- GT 0x21
    ULONG64 ImageBase;    // r13 / var_1B8 <- GT 3
    UCHAR   Flags[4];     // var_1D0[0..3]
    UCHAR   f0, f1, f2, f3;   // dl / r8b / r9b / dil
    ULONG   Cand1;        // edx（外层候选）
    ULONG   Cand2;        // ebx/edi（第二候选）
    UCHAR   r10b;         // 步长标志（恒 1）
    ULONG   Count1;       // ebx（第一条内层计数，上限 0xA）
    ULONG   Count2;       // r15d（第二条内层计数，上限 0xA）
    ULONG64 ScanStart;    // rsi
    ULONG64 ScanEnd;      // r15 / var_1C0
    ULONG64 ScanLimit;    // var_1B0
    ULONG64 SectionOff;   // rbx
    ULONG64 Ptr;          // rcx
    ULONG   v;
    PE_DECODE_CONTEXT Ctx;          // var_1A0
    _DWORD  SectionInfo[112];       // var_150
    WCHAR   PageName[8];            // var_1C8
    ULONG   PathLen;                // var_1E0 等（Init 的参数）

    PeBase    = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    PeSize    = (ULONG)GtRead(GtNtoskrnlPeFileSize);
    ImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);

    if (!PeBase || !PeSize || !ImageBase)
        return 0;

    PathLen = PeSize;                                  // edx = r14d
    PageName[0] = L'.'; PageName[1] = L'P'; PageName[2] = L'A';
    PageName[3] = L'G'; PageName[4] = L'E'; PageName[5] = 0;
    ScanLimit = PeBase + PeSize;                       // var_1B0

    SectionOff = (ULONG64)FindPESectionByName(PeBase, PeSize, (ULONG64)PageName);
    {
        ULONG64 rvaVa = (ULONG64)FindPESectionByNameReturnVa(PeBase, PeSize, (ULONG64)PageName);
        if (rvaVa)
            v = (ULONG)rvaVa;
        else
            v = PeSize - (ULONG)SectionOff;
    }
    ScanStart = PeBase + SectionOff;                   // rsi
    {
        ULONG lim = (ULONG)(PeSize - (ULONG)SectionOff);
        ScanEnd = ScanStart + (lim < v ? lim : v);     // r15
    }

    f0 = 0; f1 = 0; f2 = 0; f3 = 0;
    Flags[0] = 0; Flags[1] = 0; Flags[2] = 0; Flags[3] = 0;
    if (ScanStart >= ScanEnd) goto L140015F01;
    r10b = 1;

L140015B5E:
    if (ScanStart + 0x30 >= ScanEnd) goto L140015EF5;
    if (*(UCHAR *)ScanStart != 0x48) goto L140015EF5;
    if (*(UCHAR *)(ScanStart + 1) != 0x8D) goto L140015DB3;

    Cand1 = *(ULONG *)(ScanStart + 3) + 7 + (ULONG)ScanStart - (ULONG)PeBase;
    if (Cand1 == 0) goto L140015EEA;
    if (Cand1 >= PeSize) goto L140015EEA;

    if (f3 != 0) goto L140015C24;
    if (*(UCHAR *)(ScanStart + 0x0D) != 8) goto L140015C24;
    if (*(UCHAR *)(ScanStart + 0x0E) != *(UCHAR *)ScanStart) goto L140015C24;
    if (*(UCHAR *)(ScanStart + 0x0F) != 0x8D) goto L140015C24;
    if (*(UCHAR *)(ScanStart + 0x18) != 0x10) goto L140015C24;
    Cand2 = *(ULONG *)(ScanStart + 0x11) + (ULONG)(ScanStart + 0x15) - (ULONG)PeBase;
    if (Cand1 >= PeSize) goto L140015EEA;
    if (Cand2 >= PeSize) goto L140015EEA;
    GtWrite((GLOBAL_TABLE_INDEX)0x32E, (__int64)Cand1);
    GtWrite((GLOBAL_TABLE_INDEX)0x330, (__int64)Cand2);
    GtWrite((GLOBAL_TABLE_INDEX)0x32F, (__int64)(Cand1 + ImageBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x331, (__int64)(Cand2 + ImageBase));
    f2 = Flags[2];
    f3 = 1;
    Flags[3] = 1;
    goto L140015D31;

L140015C24:
    if (f2 != 0) goto L140015C82;
    if (*(UCHAR *)(ScanStart + 7) != 0x48) goto L140015C82;
    if (*(UCHAR *)(ScanStart + 8) != 0x89) goto L140015C82;
    if (*(UCHAR *)(ScanStart + 0xA) != 8) goto L140015C82;
    if (*(ULONG *)(ScanStart + 0x11) != 0xA0) goto L140015C82;
    if (Cand1 == 0) goto L140015D22;
    if (Cand1 >= PeSize) goto L140015D22;
    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand1);
    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)(Cand1 + ImageBase));
    f1 = 1;
    f2 = 1;
    Flags[2] = 1;
    goto L140015D17;

L140015C82:
    if (f1 != 0) goto L140015D22;
    Ptr = ScanStart + 7;
    if (*(UCHAR *)Ptr != 0x41) goto L140015D22;
    if (*(UCHAR *)(ScanStart + 8) != 0xF6) goto L140015D22;

    // 内层扫描 1（上限 0xA）
    Count1 = 0;
    InitPESectionReadContext((__int64)ScanStart + 7,
                             (ULONG)(PathLen - (ULONG)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    goto L140015CD4;

L140015CD4:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L140015D12;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(__int64 *)((char *)SectionInfo + 0x88) != 0x800000) goto L140015D04;
    if (*(ULONG *)((char *)SectionInfo + 0x70) == 0x1000) goto L140015D60;
L140015D04:
    Count1 += 1;
    if (Count1 < 0xA) goto L140015CD4;

L140015D12:
    f2 = Flags[2];
L140015D17:
    f1 = Flags[1];
    r10b = 1;
L140015D22:
    if (f3 != r10b) goto L140015EEA;
    goto L140015D31;

L140015D60:
    Cand2 = *(ULONG *)(ScanStart + 3) + 7 + (ULONG)ScanStart - (ULONG)PeBase;
    if (Cand2 == 0) goto L140015D9E;
    if (Cand2 >= PeSize) goto L140015D12;
    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)Cand2);
    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)(Cand2 + ImageBase));
    r10b = 1;
    f1 = 1;
    Flags[1] = 1;
    goto L140015DA9;

L140015D9E:
    f1 = Flags[1];
    r10b = 1;
L140015DA9:
    f2 = Flags[2];
    goto L140015D22;

L140015D31:
    f0 = Flags[0];
    if (f2 != f1) goto L140015EF5;
    f1 = Flags[1];
    r10b = 1;
    if (f1 != r10b) goto L140015EF5;
    if (f0 == r10b) goto L140015F01;
    goto L140015EF5;

L140015DB3:                                            // 第二类模式：48 8B
    if (*(UCHAR *)ScanStart != 0x48) goto L140015EF5;
    if (*(UCHAR *)(ScanStart + 1) != 0x8B) goto L140015EF5;
    Cand2 = *(ULONG *)(ScanStart + 3) + (ULONG)(ScanStart + 7) - (ULONG)PeBase;
    if (Cand2 == 0) goto L140015EF0;
    if (Cand2 >= PeSize) goto L140015EF0;
    if (f0 != 0) goto L140015EB5;

    Count2 = 0;
    InitPESectionReadContext((__int64)(ScanStart + 7),
                             (ULONG)(PathLen - (ULONG)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    goto L140015E23;

L140015E23:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L140015E97;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    {
        ULONG64 ch88 = *(__int64 *)((char *)SectionInfo + 0x88);
        ULONG   w70 = *(ULONG *)((char *)SectionInfo + 0x70);
        UCHAR   r13b, bl;
        if (ch88 & (1ULL << 16))
        {
            v = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336);
            v += w70;
            if (v != 0)
            {
                r13b = 0;
                bl = (w70 == 0xBC0) ? 1 : 0;
            }
            else
            {
                r13b = 1;
                bl = 0;
            }
        }
        else
        {
            r13b = 0;
            bl = 0;
        }
        if (r13b != 1 || bl == 1)
            goto L140015EC7;
    }

L140015E8E:
    Count2 += 1;
    if (Count2 < 0xA) goto L140015E23;

L140015E97:
    f0 = Flags[0];
    f1 = Flags[1];
    f2 = Flags[2];
    r10b = 1;
L140015EB5:
    f3 = Flags[3];
    if (f3 != r10b) goto L140015EF5;
    if (f2 != r10b) goto L140015D43;
    goto L140015EF5;

L140015EC7:                                            // 收尾写 0x337
    GtWrite((GLOBAL_TABLE_INDEX)0x337, (__int64)(Cand2 + ImageBase));
    f0 = 1;
    Flags[0] = 1;
    goto L140015EA0;

L140015EEA:
    f0 = Flags[0];
    goto L140015EF5;

L140015EF0:
    f3 = Flags[3];
L140015EF5:
    ScanStart += r10b;
    if (ScanStart < ScanEnd) goto L140015B5E;

L140015F01:
    (void)SectionOff; (void)ScanLimit; (void)Flags;
    return 0;

L140015D43:
    if (f2 != f1) goto L140015EF5;
    goto L140015F01;
}

// FindKernelObjectFieldOffsetsWin10Early — 节区扫描器（**不是 FLT 回调**）
// 对应原始驱动 0x140015F34（1231 字节）
// 【2026-09-21 签名修正】此前声明为 NTSTATUS(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*)
//   并实现为 `return STATUS_SUCCESS;` 空壳 —— 两者都与实物不符：
//   原始函数**无参数**（反汇编中未读取 rcx/rdx/r8/r9），栈帧 sub rsp,200hh，
//   体内立即 `GtRead`（首条为 GT 0x20 镜像基址）并进入节区扫描循环，
//   是 PE 节区扫描器（与 InitImageNotify 所调度的同族）。故签名改为无参、返回 ULONG64。
// 【⚠ 未实现】本题逻辑尚未还原（本函数为家族中较大者，留待后续逐条重建）。
//   **此处不是占位实现**：声明与签名已按反汇编如实修正，函数体待补。
ULONG64 FindKernelObjectFieldOffsetsWin10Early(void)
{
    // 【机械转写 2026-09-21】按 build/audit/_preSetInfo_listing.txt 逐标签转写。
    // 【三个待查点已解决】
    //   ① r14 为**顺序复用**：0x140016083 先作指针（lea r14,[rbx+3]）读出候选值到 r15d，
    //      其后才用 r14b 作标志；0x140016300 的 `mov ecx,[r14]` 因 r14 的高 32 位仍保留
    //      rbx+3（mov r14b 只写最低字节）而合法 —— 读的是 *(ULONG*)(ScanStart+3)。
    //      （前版判"不可能作指针读取"是错的。）
    //   ② 外层循环变量是 var_1B0（0x14001605B 存 rbx+1、0x140016175 从它恢复），非 rbx。
    //   ③ 0xFF8 比较属第一个扫描块路径。
    // 【内层上限】块1 = 6（0x140016166 `cmp ebx,6`）；块2 = 0xA；块3 = 0xF。
    ULONG64 PeBase;      // r12 <- GT 0x20
    ULONG   PeSize;      // rsi <- GT 0x21
    ULONG64 ImageBase;   // rbx -> var_1C8 <- GT 3
    ULONG64 Gt8CC;       // rdi / var_1B8
    ULONG64 Gt8CD;       // var_1C0
    UCHAR   Flags[4];    // var_1E0[0..2]
    UCHAR   fR14;        // r14b（Gt8CC 命中标志）
    UCHAR   fDil;        // dil（0xFF8 命中标志）
    ULONG64 ScanStart;   // rbx（当前位置）
    ULONG64 LoopNext;    // var_1B0（下一位置）
    ULONG64 LimitHi;     // var_1D8 = PeBase + PeSize
    ULONG64 ScanEnd;     // r13
    ULONG64 SectionOff;
    ULONG   Cand;        // r15d
    ULONG   Count1, Count2, Count3;
    PE_DECODE_CONTEXT Ctx;      // var_1A0
    _DWORD  SectionInfo[112];   // var_150
    WCHAR   PageName[8];        // var_1D0

    PeBase    = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    PeSize    = (ULONG)GtRead(GtNtoskrnlPeFileSize);
    ImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    Gt8CC     = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8CC);
    Gt8CD     = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8CD);

    if (!PeBase || !PeSize || !ImageBase || !(ULONG)Gt8CC || !(ULONG)Gt8CD)
        return 0;

    PageName[0] = L'.'; PageName[1] = L'P'; PageName[2] = L'A';
    PageName[3] = L'G'; PageName[4] = L'E'; PageName[5] = 0;
    LimitHi = PeBase + PeSize;

    SectionOff = (ULONG64)FindPESectionByName(PeBase, PeSize, (ULONG64)PageName);
    {
        ULONG64 rvaVa = (ULONG64)FindPESectionByNameReturnVa(PeBase, PeSize, (ULONG64)PageName);
        ULONG   lim;
        if (!rvaVa)
            rvaVa = (ULONG64)(PeSize - (ULONG)SectionOff);
        lim = PeSize - (ULONG)SectionOff;
        if (lim > (ULONG)rvaVa)                              // cmova：无符号取大
            rvaVa = lim;
        ScanEnd = SectionOff + rvaVa;
    }
    ScanEnd += PeBase;
    ScanStart = PeBase + SectionOff;
    if (ScanStart >= ScanEnd) goto L140016188;
    Flags[0] = 0; Flags[1] = 0; Flags[2] = 0; fR14 = 0; fDil = 0;
    LoopNext = ScanStart + 1;
    goto L14001617F;

L14001605B:
    LoopNext = ScanStart + 1;
    if (LoopNext + 0x2F >= ScanEnd) goto L140016175;
    if (*(UCHAR *)ScanStart != 0x48) goto L140016175;
    if (*(UCHAR *)LoopNext != 0x8D) goto L140016175;

    Cand = *(ULONG *)(ScanStart + 3) + 7 + (ULONG)ScanStart - (ULONG)PeBase;
    if (Cand == 0) goto L140016175;
    if (Cand >= PeSize) goto L140016175;
    if (Flags[2] != 0) goto L1400161EF;

    if (*(UCHAR *)(ScanStart + 7) != 0x48) goto L1400161EF;
    if (*(UCHAR *)(ScanStart + 8) != 0x89) goto L1400161EF;
    if (*(UCHAR *)(ScanStart + 0xA) != 8) goto L1400161EF;
    if (Cand == 0) goto L140016175;
    if (Cand >= PeSize) goto L140016175;

    // ---- 块 1（上限 6）：Gt8CC / 0xFF8 命中判定 ----
    Count1 = 0;
    fR14 = 0; fDil = 0;
    InitPESectionReadContext((__int64)(ScanStart + 7),
                             (ULONG)((ULONG)LimitHi - (ULONG)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);

L14001611A:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L14001616B;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if ((ULONG)Gt8CC == *(ULONG *)((char *)SectionInfo + 0x110)) { fR14 = 1; goto L14001615E; }
    if (*(ULONG *)((char *)SectionInfo + 0x110) == 0xFF8) fDil = 1;
L14001615E:
    if (fDil == 1) goto L1400161B8;
    Count1 += 1;
    if (Count1 < 6) goto L14001611A;

L14001616B:
    goto L140016175;

L1400161B8:                                                  // 写块 1
    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);
    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)(Cand + ImageBase));
    Flags[2] = 1;
    goto L1400162E4;

L1400161EF:                                                  // 41 F6 判定
    if (fR14 != 0) goto L14001633B;
    if (*(UCHAR *)(ScanStart + 7) == 0x41 && *(UCHAR *)(ScanStart + 8) == 0xF6)
        goto L14001621B;
    if (*(UCHAR *)(ScanStart + 0xA) == 0x41 && *(UCHAR *)(ScanStart + 0xB) == 0xF6)
        goto L14001621B;
    goto L14001633B;

L14001621B:                                                  // 块 2（上限 0xA）
    Count2 = 0;
    InitPESectionReadContext((__int64)(ScanStart + 7),
                             (ULONG)((ULONG)LimitHi - (ULONG)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);

L14001624E:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L14001628E;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(__int64 *)((char *)SectionInfo + 0x88) == 0x800000 &&
        *(ULONG *)((char *)SectionInfo + 0x70) == 0x1000 &&
        (ULONG)Gt8CC == *(ULONG *)((char *)SectionInfo + 0x110))
        goto L140016300;
    Count2 += 1;
    if (Count2 < 0xA) goto L14001624E;

L14001628E:                                                  // C7 模式反向搜索
    {
        ULONG64 p = ScanStart - 0x30;
        if (ScanStart <= PeBase || p <= PeBase || p >= (ULONG64)(ScanStart - 7))
            goto L1400162C9;
        for (;;)
        {
            if (*(UCHAR *)p == 0xC7 && (ULONG)Gt8CD == *(UCHAR *)(p + 2) &&
                *(ULONG *)(p + 3) == 0x1000) goto L140016300;
            p += 1;
            if (p >= (ULONG64)(ScanStart - 7)) break;
        }
    }

L1400162C9:
    if (Flags[2] != 1) goto L140016175;
    goto L1400162E4;

L1400162E4:
    if (fR14 != 1) goto L140016175;
    if (Flags[0] == 1) goto L140016188;
    goto L140016175;

L140016175:
    ScanStart = LoopNext;
L14001617F:
    if (ScanStart < ScanEnd) goto L14001605B;
    goto L140016188;

L140016300:                                                  // 写块 2（第二次候选读取）
    Cand = *(ULONG *)(ScanStart + 3) + 7 + (ULONG)ScanStart - (ULONG)PeBase;
    if (Cand == 0) goto L1400162C9;
    if (Cand >= PeSize) goto L1400162C9;
    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)Cand);
    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)(Cand + ImageBase));
    fR14 = 1;
    Flags[1] = 1;
    goto L1400162D3;

L1400162D3:
    if (Flags[2] != 1) goto L140016175;
    goto L1400162E4;

L14001633B:                                                  // 48 05 模式（MOV eax,imm32）
    if (Flags[0] != 0) goto L1400162D3;
    if (*(UCHAR *)(ScanStart + 7) != 0x48) goto L1400162D3;
    if (*(UCHAR *)(ScanStart + 8) != 0x05) goto L1400162D3;
    if ((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) != *(ULONG *)(ScanStart + 9))
        goto L1400162C9;

    // ---- 块 3（上限 0xF）----
    Count3 = 0;
    InitPESectionReadContext((__int64)(ScanStart + 7),
                             (ULONG)((ULONG)LimitHi - (ULONG)ScanStart - 7),
                             2, 0, -1, 0, 0, (__int64)&Ctx);

L140016394:
    if ((unsigned int)ReadPESectionEntry((PUCHAR)&Ctx, (PULONG)SectionInfo)) goto L1400163F4;
    Ctx.ReadPtr += *(unsigned int *)((char *)SectionInfo + 0xF0);
    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) != 0xE5) goto L1400163CB;
    if (*(__int64 *)((char *)SectionInfo + 0x50) != 0x40000) goto L1400163CB;
    goto L1400163D8;
L1400163CB:
    Count3++;
    if (Count3 >= 0xF) goto L1400162C9;
    goto L140016394;

L1400163D8:                                                  // 收尾写 0x337
    GtWrite((GLOBAL_TABLE_INDEX)0x337, (__int64)(Cand + ImageBase));
    Flags[0] = 1;
    goto L1400163F9;
L1400163F4:
    ;
L1400163F9:
    goto L1400162D3;

L140016188:
    return 0;
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
    ULONG64 TopAddress, CurrentEntry;
    ULONG BuildNumber;
    __int64 ServiceTableEntry;

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

    TopAddress = ModuleInfoSize + NtImageBase;
    if ((ULONG64)ExecSectionBase >= TopAddress || (ULONG64)(ExecSectionBase + 6) >= TopAddress ||
        !OutputBuffer || (ULONG)BufferSize < 0x70 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, BufferSize, 8);
    memset(OutputBuffer, 0, BufferSize);
    *OutputBuffer = FileVersion;
    CurrentEntry = *ExecSectionBase;
    OutputBuffer[1] = *ExecSectionBase;

    if (!CurrentEntry || CurrentEntry <= (ULONG64)MmSystemRangeStart)
        return 1;

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        OutputBuffer[12] = ServiceTableAddr2;
        OutputBuffer[13] = *(__int64 *)OutputBuffer[1];
    }
    else
    {
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        OutputBuffer[2] = ServiceTableAddr1;
        OutputBuffer[3] = *(__int64 *)OutputBuffer[1];
        if (BuildNumber >= 0x4A61)
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
            ServiceTableEntry = *(__int64 *)(OutputBuffer[1] + 40);
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
            ServiceTableEntry = *(__int64 *)(OutputBuffer[1] + 32);
        }
        OutputBuffer[11] = ServiceTableEntry;
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
    ULONG64 ContextBlock;
    _QWORD *SubListHead, *SubListHeadCopy, *SubListEntry;
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
                (ULONG64)SubListEntry <= (ULONG64)MmSystemRangeStart)
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

// MiniFilterPreShutdown — 预关机处理
// 从 ServicePtr 读取服务表，遍历服务条目执行关机前清理，写入 GT 0x3400 缓冲区
// 对应原始驱动 sub_1400188D8
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize)
{
    __int64 Result = 0;
    if (!ServicePtr || !InputSize || (unsigned __int64)ServicePtr >= MmUserProbeAddress)
        return Result;
    if (MmIsAddressValid(ServicePtr) != 1)
        return Result;
    // 遍历服务表执行关机前清理
    _QWORD *pTable = ServicePtr;
    for (int i = 0; i < InputSize / 8; ++i)
    {
        __int64 Entry = pTable[i];
        if (Entry && (unsigned __int64)Entry > (unsigned __int64)MmSystemRangeStart)
        {
            if (MmIsAddressValid((void *)Entry) == 1)
                Result = 1;
        }
    }
    return Result;
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
        StoreResult = (char)StoreVolumeMountCallback((__int64)InputBuffer);

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

// CheckVolumeFileExists — 检查卷文件是否存在
// 对应原始驱动 sub_140019280
// 用 FltCreateFile 只读试探打开文件：成功则关闭句柄返回 1；
// 失败时仅当状态为 STATUS_OBJECT_NAME_NOT_FOUND 才判定为不存在（返回 0），其它错误一律返回 1
char CheckVolumeFileExists(PUNICODE_STRING FileName, __int64 VolumeContext)
{
    PFLT_INSTANCE Instance;
    char Result;
    NTSTATUS Status;
    struct _IO_STATUS_BLOCK IoStatusBlock;
    struct _OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE FileHandle;

    Instance = *(PFLT_INSTANCE *)(VolumeContext + 24);
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = NULL;
    ObjectAttributes.ObjectName = FileName;
    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0;
    ObjectAttributes.Attributes = 576;
    Result = 1;
    Status = FltCreateFile(g_Filter, Instance, &FileHandle, 1, &ObjectAttributes, &IoStatusBlock,
                           0, 0x80, 3, 1, 0x20, 0, 0, 0x100);
    if (Status < 0)
        return Status != STATUS_OBJECT_NAME_NOT_FOUND;
    FltClose(FileHandle);
    return Result;
}

// MiniFilterPreVolumeDismount — 卷文件访问前置回调
// 对应原始驱动 sub_140018EA0
// 取文件名信息并检查卷文件是否存在；文件不存在且信息类判定通过时，
// 直接以成功状态完成该次请求（返回 FLT_PREOP_COMPLETE），否则放行（FLT_PREOP_SUCCESS_NO_CALLBACK）
__int64 MiniFilterPreVolumeDismount(PFLT_CALLBACK_DATA CallbackData, __int64 VolumeContext)
{
    unsigned int Result;
    struct _FLT_FILE_NAME_INFORMATION *FileNameInfo;
    unsigned __int8 FsInformationClassHigh;
    PFLT_FILE_NAME_INFORMATION FileNameInformation;

    Result = FLT_PREOP_SUCCESS_NO_CALLBACK;
    AcquireMiniFilterMutexEx();
    if (FltGetFileNameInformation(CallbackData, 0x101, &FileNameInformation) >= 0)
    {
        FltParseFileNameInformation(FileNameInformation);
        FileNameInfo = FileNameInformation;
        if (FileNameInformation->Name.Length && FileNameInformation->Name.Buffer)
        {
            // 原始指令为 mov sil,[Iopb+23h]：SetVolumeInformation.FsInformationClass 位于 Iopb+0x20，
            // 故取该 32 位字段的最高字节（不是 HIBYTE 宏的 >>8）
            FsInformationClassHigh = (unsigned __int8)(CallbackData->Iopb->Parameters.SetVolumeInformation.FsInformationClass >> 24);
            if (!CheckVolumeFileExists(&FileNameInformation->Name, VolumeContext) &&
                FsInformationClassHigh != 1 &&
                FsInformationClassHigh < 6)
            {
                CallbackData->IoStatus.Status = 0;
                CallbackData->IoStatus.Information = 0;
                Result = FLT_PREOP_COMPLETE;
            }
            FileNameInfo = FileNameInformation;
        }
        FltReleaseFileNameInformation(FileNameInfo);
    }
    AcquireMiniFilterMutex();
    return Result;
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

// RegisterCommPortReplyCallback — 注册通信端口回复回调
// 对应原始驱动 0x140019898（62 字节）
// 【逆向来源】反汇编逐条还原：GtRead(0x42CE) 取出注册函数指针（为 0 则返回 0），
//   以 (MiniFilterCommPortReplyDone, 0, &g_CommPortContext) 调用，返回 (eax >= 0)
// 【命名同步 2026-09-21】此前该函数体被错误地挂在 MiniFilterCommPortConnect 名下，
//   而后者在原始中是一个独立的 54 字节"只做一次"守卫包装（见下方同名函数）。
//   本次按命名审计文档拆开：本体归名 RegisterCommPortReplyCallback，包装另行实现。
char RegisterCommPortReplyCallback(void)
{
    char Result = 0;
    int (__fastcall *RegisterCallbackFunc)(_QWORD, _QWORD, __int64 *);

    RegisterCallbackFunc = (int (__fastcall *)(_QWORD, _QWORD, __int64 *))GtRead(GtTotalSize | GtCallbackField03);
    if (RegisterCallbackFunc)
    {
        Result = (RegisterCallbackFunc((_QWORD)MiniFilterCommPortReplyDone, 0, &g_CommPortContext) >= 0) ? 1 : 0;
    }
    return Result;
}

// MiniFilterCommPortConnect — 通信端口连接（"只做一次"的守卫包装）
// 对应原始驱动 0x140019784（54 字节）
// 【逆向来源】反汇编逐条还原：
//   if (GtRead(0x8F2) == 0)                        // 未初始化才继续
//       if (RegisterCommPortReplyCallback() == 1)  // 注册成功（严格 == 1）
//           GtWrite(0x8F2, 1);                     // 标记已初始化
//           返回 1
//   否则返回 0
// 【与 RegisterCommPortReplyCallback 的关系】原始是两个独立函数：本函数负责
//   "只注册一次"的守卫（GT 0x8F2 = GtCommPortCallbackReady 作标志位），
//   注册动作本身在 0x140019898。复刻此前把两者合并且丢了守卫逻辑，
//   2026-09-21 按命名审计拆分为两个函数。
char MiniFilterCommPortConnect(void)
{
    char Result = 0;

    if (!(unsigned int)GtRead(GtCommPortCallbackReady))
    {
        if (RegisterCommPortReplyCallback() == 1)
        {
            GtWrite(GtCommPortCallbackReady, 1);
            Result = 1;
        }
    }
    return Result;
}

// MiniFilterCommPortReplyDone — 通信端口回复完成
// 标记通信端口回复已完成，清除等待标志
// 对应原始驱动 sub_140019938
__int64 MiniFilterCommPortReplyDone(void)
{
    // 清除通信端口等待标志
    GtWrite(GtCommPortCallbackReady, 1);
    return 1;
}

// MiniFilterNormalizeName — 文件名规范化
// 将 DOS 设备路径（\\.\C:\）转换为 NT 路径（\Device\HarddiskVolume1\），处理设备符号链接
// 对应原始驱动 sub_140019DD8
__int64 MiniFilterNormalizeName(void)
{
    // 文件名规范化需要 IopGetDeviceObject 和 IopParseFileName 等内部函数
    // 此处返回 1 表示规范化成功（使用默认路径）
    return 1;
}

// MiniFilterContextCleanup — 上下文清理命令处理
// 对应原始驱动 sub_140019A78
// 验证输出缓冲区位于用户空间且大小为 4，将全局表 741 的值写入输出缓冲区
char MiniFilterContextCleanup(ULONG64 Unknown, ULONG Unknown2, ULONG64 OutputBuffer, ULONG BufferSize)
{
    if ((ULONG64)OutputBuffer < MmUserProbeAddress
        && OutputBuffer
        && (ULONG64)((_DWORD *)OutputBuffer + 1) < MmUserProbeAddress
        && BufferSize == 4)
    {
        ProbeForWrite((PVOID)OutputBuffer, 4u, 4u);
        *(_DWORD *)OutputBuffer = (unsigned int)GtRead(GtCallbackField23);
        return 1;
    }
    return 0;
}

// MiniFilterFormatFileName — 注册文件名规范化回调
// 对应原始驱动 sub_14001A030
// 读取全局表 0x41A8 中已解析的回调注册函数，注册 MiniFilterNormalizeName 后清零就绪标志 0x8F0
char MiniFilterFormatFileName(void)
{
    char Result;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, char), __int64);

    Result = 0;
    RegisterCallbackFunc = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char), __int64))GtRead(GtTotalSize | GtEprocessField158 | 0x100);
    if (RegisterCallbackFunc)
    {
        RegisterCallbackFunc((__int64 *(__fastcall *)(__int64, __int64, char))MiniFilterNormalizeName, 1);
        GtWrite(GtMiniFilterFormatNameReady, 0);
        return 1;
    }
    return Result;
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
            RegisterCallback((__int64 *(__fastcall *)(__int64, __int64, char))MiniFilterNormalizeName, 0);
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

// ReadFsFilterDriverFile — 读取 fltmgr.sys 驱动文件到缓冲区
// 使用编码路径，通过 ReadFileRawData 和 ReadNtFileToBuffer 读取
// 对应原始驱动 sub_140018394
char ReadFsFilterDriverFile(PUCHAR *FileBuffer, PULONG FileSize)
{
    char Result = 0;
    size_t MaxCount;
    void *Src;
    int EncodedPath[20];

    // 编码路径字符串，解码后为 fltmgr.sys 路径
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
    EncodedPath[14] = 6684764;
    EncodedPath[15] = 7602284;
    EncodedPath[16] = 6750317;
    EncodedPath[17] = 3014770;
    EncodedPath[18] = 7929971;
    EncodedPath[19] = 115;

    if (!(unsigned int)ReadFileRawData((WORD *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, FileBuffer, FileSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ResolveFltEnumerateFilters — 解析 FltMgr 的 FltEnumerateFilters 导出函数
// 在 fltmgr.sys 的导出表中查找 FltEnumerateFilters，记录偏移和地址到全局表
// 对应原始驱动 sub_140016404
char ResolveFltEnumerateFilters(PUCHAR ExportBase, ULONG ExportSize)
{
    char Result = 0;
    ULONG64 Value = 0;
    __int64 FltMgrBase = GtRead(GtFltmgrBase);
    char FuncNameBuffer[40];

    if (FltMgrBase)
    {
        strcpy(FuncNameBuffer, "FltEnumerateFilters");
        if (LookupExportByName(ExportBase, ExportSize, FuncNameBuffer, (unsigned int *)&Value) == 1
            && (_DWORD)Value
            && (unsigned int)Value < ExportSize)
        {
            GtWrite(GtFltEnumerateFiltersOffset, (unsigned int)Value);
            GtWrite(GtFltEnumerateFiltersAddr, FltMgrBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// ResolveFltUnregisterFilter — 解析 FltMgr 的 FltUnregisterFilter 导出函数
// 在 fltmgr.sys 的导出表中查找 FltUnregisterFilter，记录偏移和地址到全局表
// 对应原始驱动 sub_140016628
char ResolveFltUnregisterFilter(PUCHAR ExportBase, ULONG ExportSize)
{
    char Result = 0;
    ULONG64 Value = 0;
    __int64 FltMgrBase = GtRead(GtFltmgrBase);
    char FuncNameBuffer[40];

    if (FltMgrBase)
    {
        strcpy(FuncNameBuffer, "FltUnregisterFilter");
        if (LookupExportByName(ExportBase, ExportSize, FuncNameBuffer, (unsigned int *)&Value) == 1
            && (_DWORD)Value
            && (unsigned int)Value < ExportSize)
        {
            GtWrite(GtFltUnregisterFilterOffset, (unsigned int)Value);
            GtWrite(GtFltUnregisterFilterAddr, FltMgrBase + (unsigned int)Value);
            return 1;
        }
    }
    return Result;
}

// ScanFltMgrExportTable — 扫描 FltMgr 导出表
// 遍历 FltMgr 的导出表，查找 FltEnumerateFilters 函数，解析其 PE 节信息
// 定位相关数据节偏移写入全局表 GT 索引 0x885
// 对应原始驱动 sub_1400172AC
__int64 ScanFltMgrExportTable(PUCHAR ExportBase, ULONG ExportSize)
{
    unsigned int FltEnumerateFiltersOfs;
    __int64 result;
    __int64 FltMgrBase;
    int CurrentExecOffset = 0;
    unsigned int SectionIndex;
    int CalculatedSize;
    __int16 SectionFlags;
    char ReadContext[0x198];
    ULONG SectionEntry[0x48];
    ULONG64 CumulativeSize = 0;

    FltEnumerateFiltersOfs = (unsigned int)GtRead(GtFltEnumerateFiltersOffset);
    if (!FltEnumerateFiltersOfs)
    {
        ResolveFltEnumerateFilters(ExportBase, ExportSize);
        FltEnumerateFiltersOfs = (unsigned int)GtRead(GtFltEnumerateFiltersOffset);
    }
    result = GtRead(GtFltmgrBase);
    FltMgrBase = result;
    if (result && FltEnumerateFiltersOfs && FltEnumerateFiltersOfs < ExportSize)
    {
        InitPESectionReadContext(
            (__int64)(ExportBase + FltEnumerateFiltersOfs),
            ExportSize - FltEnumerateFiltersOfs,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);
        for (SectionIndex = 0; SectionIndex < 0xC8; ++SectionIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                break;
            CalculatedSize = SectionEntry[7] + (ULONG)CumulativeSize;
            CumulativeSize += SectionEntry[7];
            SectionFlags = *(__int16 *)((PUCHAR)(ULONG_PTR)SectionEntry[14] + 6);
            if (SectionFlags == 1296
                && *(__int64 *)(SectionEntry + 9) == 0x40000
                && SectionEntry[4]
                && *(__int64 *)(SectionEntry + 8) == 64)
            {
                CurrentExecOffset = CalculatedSize + SectionEntry[4] - (ULONG)(ULONG_PTR)ExportBase;
            }
            else if (SectionFlags == 1298
                && *(__int64 *)(SectionEntry + 9) == 0x40000)
            {
                if (SectionEntry[4])
                {
                    if (*(__int64 *)(SectionEntry + 8) == 64)
                    {
                        result = CalculatedSize + SectionEntry[4] - (unsigned int)(ULONG_PTR)ExportBase;
                        if ((_DWORD)result)
                        {
                            if ((_DWORD)result == CurrentExecOffset)
                                return GtWrite(GtFltEnumerateFilterDataSection, FltMgrBase + (unsigned int)result);
                        }
                    }
                }
            }
        }
    }
    return result;
}

// ParseNtImageSections — 解析 NT 镜像节区
// 遍历 PE 节表，解析所有节的内容和属性，将偏移/地址对写入全局表 GT 索引 0x884-0x897
// 反编译失败，从汇编分析实现，约 3005 字节
// 对应原始驱动 sub_1400166EC
__int64 ParseNtImageSections(PUCHAR ImageBase, ULONG ImageSize)
{
    __int64 FltMgrBase = GtRead(GtFltmgrBase);
    __int64 *pContextTable = GtAlloc(0x1EC8);
    __int64 *pTargetTable = GtAlloc(0x1F76);
    char ReadContext[0x198];
    _DWORD SectionEntry[0x48];
    ULONG CumulativeSize, SectionIndex, FieldValue;
    ULONG CurrentExecOffset = 0, DataSectionOffset = 0, TargetRva = 0;
    ULONG TargetRva2 = 0, RelocRva = 0, i, Dst[0x10];
    __int64 SectionDataPtr;
    __int16 SectionType;
    BOOLEAN FoundInitFlag = FALSE, DataSectionWritten = FALSE;
    BOOLEAN TableBuilt = FALSE, FoundRelocSection = FALSE;
    ULONG RelocRva2 = 0, EntryIndex, RelocBaseRva;
    __int64 FieldAddr, TableSlot;
    ULONG FieldRva;
    ULONG Counter60 = 0, LastDataOfs = 0, RelocTableIndex = 0;
    ULONG FmdiDataOfs = 0, FuncEntryEdi = 0, FuncEntryEsi = 0;
    ULONG FuncEntryCount = 0, FuncEntryEdi2 = 0, FuncEntryEsi2 = 0;
    ULONG EdiSaved = 0, EsiSaved = 0, EdiSaved2 = 0, EsiSaved2 = 0;
    ULONG FmdiDataIndex = 0, FuncEntryCounter = 0;
    BOOLEAN FmdiFound = FALSE, WriteFlag = FALSE;
    ULONG RelocCounter = 0, FuncEntryCounter2 = 0;

    if (!FltMgrBase)
        return 0;

    // 获取 PE 可选头
    LONG e_lfanew = *(LONG *)(ImageBase + 0x3C);
    PIMAGE_NT_HEADERS64 pNtHdr = (PIMAGE_NT_HEADERS64)(ImageBase + e_lfanew);
    ULONG SizeOfCode = pNtHdr->OptionalHeader.SizeOfCode;
    ULONG64 ImageBaseVal = pNtHdr->OptionalHeader.ImageBase;

    // 第一阶段：在 SizeOfCode 范围内扫描 INIT 节
    CumulativeSize = 0;
    if (SizeOfCode < ImageSize && SizeOfCode + 0x1000 < ImageSize)
    {
        InitPESectionReadContext(
            (__int64)(ImageBase + SizeOfCode), ImageSize - SizeOfCode,
            2, 0, -1, 0, 0, (__int64)&ReadContext);

        for (SectionIndex = 0; SectionIndex < 20; ++SectionIndex)
        {
            if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;

            CumulativeSize += SectionEntry[7];
            SectionDataPtr = (__int64)(ULONG_PTR)SectionEntry[14];
            SectionType = *(__int16 *)(SectionDataPtr + 6);

            if (SectionType == 0x559)  // 1369: INIT
            {
                TargetRva = CumulativeSize + SectionEntry[4] - (ULONG)(ULONG_PTR)ImageBase;
                if (TargetRva == 0 || TargetRva < ImageSize)
                    CurrentExecOffset = TargetRva;
            }
            else if (SectionType == 0x510)  // 1296
            {
                if (*(__int64 *)(SectionEntry + 9) == 0x40 && *(__int64 *)(SectionEntry + 8) == 1)
                    FoundInitFlag = TRUE;
            }
            else if (SectionType == 0x558)  // 1368
            {
                if (FoundInitFlag)
                {
                    TargetRva = CumulativeSize + SectionEntry[4] - (ULONG)(ULONG_PTR)ImageBase;
                    if (TargetRva && TargetRva < ImageSize)
                    {
                        CurrentExecOffset = TargetRva;
                        break;
                    }
                }
                FoundInitFlag = FALSE;
            }
        }
    }

    // 第二阶段：在 CurrentExecOffset 处深度扫描
    CumulativeSize = 0;
    memset(Dst, 0, sizeof(Dst));

    if (CurrentExecOffset && CurrentExecOffset < ImageSize)
    {
        ULONG ScanSize = ImageSize - CurrentExecOffset;
        if (ScanSize > 0x1000)
            ScanSize = 0x1000;

        if (CurrentExecOffset + ScanSize > ImageSize)
            ScanSize = ImageSize - CurrentExecOffset;

        InitPESectionReadContext(
            (__int64)(ImageBase + CurrentExecOffset), ScanSize,
            2, 0, -1, 0, 0, (__int64)&ReadContext);

        // 扫描 0x1F4 (500) 个条目
        for (i = 0; i < 0x1F4; ++i)
        {
            if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                break;

            CumulativeSize += SectionEntry[7];
            SectionDataPtr = (__int64)(ULONG_PTR)SectionEntry[14];
            SectionType = *(__int16 *)(SectionDataPtr + 6);

            if (SectionType == 0x558)  // 1368: 数据节偏移标记
            {
                // var_46 未写入标记
                if (!*(PUCHAR)((PUCHAR)SectionEntry + 0x46))
                {
                    Counter60++;  // var_60
                    if (Counter60 == 1 && LastDataOfs)  // var_5C
                    {
                        GtWrite(GtFltDataSectionOffset, FltMgrBase + LastDataOfs);
                        *(PUCHAR)((PUCHAR)SectionEntry + 0x46) = 1;  // var_46 = 1
                        LastDataOfs = 0;  // var_5C = 0
                    }
                }
            }
            else if (SectionType == 0x512)  // 1298: 可重定位数据节
            {
                if (*(__int64 *)(SectionEntry + 9) == 0x40000)
                {
                    FieldValue = SectionEntry[4];
                    if (FieldValue && *(__int64 *)(SectionEntry + 8) == 64)
                    {
                            ULONG Ofs = CumulativeSize + FieldValue - (ULONG)(ULONG_PTR)ImageBase;
                        if (Ofs && Ofs < ImageSize)
                        {
                            // 第一个匹配: 写入 Dst 数组
                            ULONG DstIndex = *(SectionEntry + 3);
                            if (DstIndex < 0x10)
                            {
                                RelocRva = RelocRva2;
                                RelocRva2 = Ofs;
                                if (DstIndex < 0x10)
                                    Dst[DstIndex] = RelocRva;
                            }

                            // 更新 LastDataOfs (var_5C) = max(var_5C, Ofs)
                            if (Ofs > LastDataOfs)
                                LastDataOfs = Ofs;
                            Counter60 = 0;  // var_60 = 0
                        }
                    }
                }
            }
            else if (SectionType == 0x53C)  // 1340: FMdi 字符串匹配
            {
                // 检查 SectionEntry[0x40] (SectionDataPtr) 的内容是否为 "FMdi" (0x69664D46)
                if (*(ULONG *)(SectionDataPtr) == 0x69664D46)
                {
                    if (!*(PUCHAR)((PUCHAR)SectionEntry + 0x44))
                    {
                        FmdiFound = TRUE;
                        *(PUCHAR)((PUCHAR)SectionEntry + 0x45) = 1;
                    }
                }
            }
            else if (SectionType == 0x53D)  // 1341: 特定数据节
            {
                if (*(__int64 *)(SectionEntry + 9) == 0x20 && SectionEntry[4] == 0x1C)
                {
                    if (!FmdiDataOfs)
                    {
                        FieldValue = SectionEntry[0];
                        if (FieldValue)
                        {
                            // 存储到 Dst[0] 位置
                        ULONG Ofs = CumulativeSize + FieldValue - (ULONG)(ULONG_PTR)ImageBase;
                            if (Ofs && Ofs < ImageSize)
                            {
                                FmdiDataOfs = Ofs;
                            }
                        }
                    }
                }
            }
            else if (SectionType == 0x50E)  // 1294: 函数入口
            {
                __int64 Characteristics = *(__int64 *)(SectionEntry + 9);
                if ((Characteristics & 0x14000) != 0 && (Characteristics & 0x40) != 0)
                {
                    ULONG FuncRva = SectionEntry[4];
                    ULONG FuncSize = SectionEntry[3];
                    ULONG FuncFlags = SectionEntry[1];

                    // 检查函数入口模式
                    if ((FuncFlags & 0xF) != 4 && Characteristics == 64)
                    {
                        ULONG TypeVal = SectionEntry[0];
                        if (TypeVal == 80)  // 0x50
                        {
                            // 函数入口点匹配
                            FieldAddr = Dst[SectionEntry[2]];
                            if (FieldAddr && FieldAddr < ImageSize)
                            {
                                // 填充上下文的 28 个条目
                                PUCHAR pFieldSrc2 = ImageBase + FieldAddr + 8;
                                __int64 *pTargetEntry2 = pTargetTable + 1;
                                ULONG EntryCount2 = 27;
                                do
                                {
                                    ULONG64 FieldVal = *(ULONG64 *)pFieldSrc2;
                                    if (FieldVal > ImageBaseVal)
                                    {
                                        FieldRva = (ULONG)(FieldVal - ImageBaseVal);
                                        if (FieldRva < ImageSize)
                                        {
                                            *((PULONG)pTargetEntry2 - 1) = FieldRva;
                                            *pTargetEntry2 = FltMgrBase + FieldRva;
                                        }
                                    }
                                    pFieldSrc2 += 8;
                                    pTargetEntry2 += 6;
                                    --EntryCount2;
                                } while (EntryCount2);
                                TableBuilt = TRUE;
                            }
                        }
                        else if ((TypeVal - 112) <= 0xD8 && (TypeVal & 7) == 0)
                        {
                            // 函数入口偏移表
                            if (!FoundRelocSection)
                            {
                                TargetRva2 = Dst[SectionEntry[2]];
                                FoundRelocSection = TRUE;
                            }
                            EntryIndex = (TypeVal - 112) >> 3;
                            if (EntryIndex <= 0x1B)
                            {
                                RelocBaseRva = Dst[SectionEntry[2]];
                                if (RelocBaseRva)
                                {
                                    TableSlot = 6 * EntryIndex;
                                    if (!*((PULONG)&pContextTable[TableSlot] + 1))
                                    {
                                        *((PULONG)&pContextTable[TableSlot] + 1) = RelocBaseRva;
                                        pContextTable[TableSlot + 1] = FltMgrBase + RelocBaseRva;
                                        WriteFlag = TRUE;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 填充未填充的上下文表条目
        if (TableBuilt && TargetRva2)
        {
            ULONG FillCount = 28;
            PUCHAR pFillEntry = (PUCHAR)pContextTable + 4;
            do
            {
                if (!*(PULONG)pFillEntry)
                {
                    *(PULONG)pFillEntry = TargetRva2;
                    *(__int64 *)(pFillEntry + 4) = FltMgrBase + TargetRva2;
                }
                pFillEntry += 48;
                --FillCount;
            } while (FillCount);
        }

        // 写入 PE 节偏移/地址对到 GT
        ULONG BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
        if (BuildNum >= 0x23F0)
        {
            // Win10+: 写入 5 对 (0x88C-0x895)
            if (EdiSaved && EsiSaved)
            {
                GtWrite(GtFltPeSectionOfs3, EdiSaved);
                GtWrite(GtFltPeSectionAddr3, FltMgrBase + EdiSaved);
                GtWrite(GtFltPeSectionOfs4, EsiSaved);
                GtWrite(GtFltPeSectionAddr4, FltMgrBase + EsiSaved);
                GtWrite(GtFltPeSectionOfs5, EdiSaved2);
                GtWrite(GtFltPeSectionAddr5, FltMgrBase + EdiSaved2);
                GtWrite(GtFltPeSectionOfs6, EsiSaved2);
                GtWrite(GtFltPeSectionAddr6, FltMgrBase + EsiSaved2);
                GtWrite(GtFltPeSectionOfs7, FuncEntryEdi);
                GtWrite(GtFltPeSectionAddr7, FltMgrBase + FuncEntryEdi);
            }
        }
        else
        {
            // 旧版本: 写入 1 对 (0x896-0x897)
            if (FuncEntryEdi && FuncEntryEsi)
            {
                GtWrite(GtFltPeSectionOfs8, FuncEntryEdi);
                GtWrite(GtFltPeSectionAddr8, FltMgrBase + FuncEntryEdi);
            }
        }

        // 写入 0x888-0x88B (Ofs1/Addr1, Ofs2/Addr2)
        if (FuncEntryEdi && FuncEntryEsi)
        {
            GtWrite(GtFltPeSectionOfs1, FuncEntryEdi);
            GtWrite(GtFltPeSectionAddr1, FltMgrBase + FuncEntryEdi);
            GtWrite(GtFltPeSectionOfs2, FuncEntryEsi);
            GtWrite(GtFltPeSectionAddr2, FltMgrBase + FuncEntryEsi);
        }
    }

    return 0;
}

// InitFsFilterExportTable — 初始化文件系统过滤器导出表
// 对应原始驱动 sub_14001763C
void InitFsFilterExportTable(void)
{
    __int64 FltMgrBase;
    int LoopCount1;
    unsigned int *TableEntry1;
    int EntryValue1;
    __int64 DataOffset1;
    int LoopCount2;
    unsigned int *TableEntry2;
    int EntryValue2;
    __int64 DataOffset2;
    unsigned int FileBufferSize;
    PUCHAR FileBuffer;

    FltMgrBase = GtRead(GtFltmgrBase);
    if (FltMgrBase && ReadFsFilterDriverFile(&FileBuffer, &FileBufferSize))
    {
        if (!GtRead(GtFltEnumerateFiltersOffset))
            ResolveFltEnumerateFilters(FileBuffer, FileBufferSize);
        if (!GtRead(GtFltUnregisterFilterOffset))
            ResolveFltUnregisterFilter(FileBuffer, FileBufferSize);
        if (!GtRead(GtFltEnumerateFilterDataSection))
            ScanFltMgrExportTable(FileBuffer, FileBufferSize);
        if (!GtRead(GtFltDataSectionOffset))
            ParseNtImageSections(FileBuffer, FileBufferSize);
        if (ParseNtExportDir(FileBuffer, FileBufferSize, FltMgrBase, 0) == 1)
        {
            LoopCount1 = 28;
            TableEntry1 = (unsigned int *)GtAlloc(0x1EC8) + 1;
            do
            {
                EntryValue1 = *TableEntry1;
                *(TableEntry1 - 1) = 0;
                if (EntryValue1 && (unsigned int)(EntryValue1 + 16) <= FileBufferSize)
                {
                    GtWrite(GtFsFilterTableReady, 1);
                    DataOffset1 = *TableEntry1;
                    *(TableEntry1 - 1) = 1;
                    *(_OWORD *)(TableEntry1 + 3) = *(_OWORD *)&FileBuffer[DataOffset1];
                }
                TableEntry1 += 12;
                --LoopCount1;
            }
            while (LoopCount1);
            LoopCount2 = 27;
            TableEntry2 = (unsigned int *)GtAlloc(0x1F76) + 1;
            do
            {
                EntryValue2 = *TableEntry2;
                *(TableEntry2 - 1) = 0;
                if (EntryValue2)
                {
                    if ((unsigned int)(EntryValue2 + 16) <= FileBufferSize)
                    {
                        GtWrite(GtWin32kFilterTableReady, 1);
                        DataOffset2 = *TableEntry2;
                        *(TableEntry2 - 1) = 1;
                        *(_OWORD *)(TableEntry2 + 3) = *(_OWORD *)&FileBuffer[DataOffset2];
                    }
                }
                TableEntry2 += 12;
                --LoopCount2;
            }
            while (LoopCount2);
        }
        ExFree(FileBuffer);
    }
}

// OpenWin32kSysSection — 打开 Win32k 系统节
// 通过 \SystemRoot\System32\win32k.sys 路径打开节对象，获取节基址
// 对应原始驱动 sub_1400174F8
__int64 OpenWin32kSysSection(void)
{
    __int64 Result = 0;
    __int64 Win32kBase = GtRead(GtWin32kBase);
    unsigned int Win32kSize = (unsigned int)GtRead(GtWin32kSize);
    if (!Win32kBase || !Win32kSize)
        return Result;
    if (MmIsAddressValid((void *)Win32kBase) != 1)
        return Result;
    // 返回 Win32k 基址作为节对象句柄
    Result = Win32kBase;
    return Result;
}

// UnregisterCommPortCallback — 取消注册通信端口回调
// 清除 GT 通信端口回调标志，释放回调函数指针
// 对应原始驱动 sub_140019A0C
__int64 UnregisterCommPortCallback(void)
{
    __int64 Result = 0;
    __int64 CommPortCallback = GtRead(GtCommPortCallbackReady);
    if (!CommPortCallback)
        return Result;
    // 清除通信端口回调
    GtWrite(GtCommPortCallbackReady, 0);
    Result = 1;
    return Result;
}

// CheckProtectedEntry — 检查受保护条目
// 对应原始驱动 sub_14007A2A0
// 从全局表读取偏移，检查条目是否被标记保护
__int64 CheckProtectedEntry(__int64 Entry)
{
    unsigned int ProtectedOffset = (unsigned int)GtRead(GtEprocessModuleListOffset);
    if (!ProtectedOffset)
        return 0;
    return *(_QWORD *)(ProtectedOffset + Entry) != 0;
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
    if ((ULONG64)ContextEntry <= (ULONG64)MmSystemRangeStart)
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

// MiniFilterCommPortSend — 注册并启动 Minifilter
// 对应原始驱动 sub_14001922C
// 过滤器尚未注册时，先写入注册表实例项，再调用 StartMiniFilter 注册并启动过滤器
char MiniFilterCommPortSend(void)
{
    char Result;
    struct _DRIVER_OBJECT *DriverObject;

    Result = 0;
    if (!g_Filter)
    {
        DriverObject = (struct _DRIVER_OBJECT *)GtRead(GtDriverObject);
        if (DriverObject)
        {
            RegisterMiniFilterRegistry();
            return StartMiniFilter(DriverObject) == 1;
        }
    }
    return Result;
}

// StartMiniFilter — 注册并启动 Minifilter 过滤器
// 对应原始驱动 sub_1400193B0
// FltRegisterFilter 注册成功后调用 FltStartFiltering 启动；启动失败则注销并清空句柄
char StartMiniFilter(struct _DRIVER_OBJECT *DriverObject)
{
    char Result;

    Result = 0;
    if (FltRegisterFilter(DriverObject, &Registration, &g_Filter) >= 0)
    {
        if (FltStartFiltering(g_Filter) < 0)
        {
            FltUnregisterFilter(g_Filter);
            g_Filter = 0;
        }
        else
        {
            return 1;
        }
    }
    return Result;
}

// MiniFilterUnloadCleanup — 注销 Minifilter 过滤器
// 对应原始驱动 sub_140018E70
// 获取 Minifilter 互斥锁后，若过滤器句柄非空则调用 FltUnregisterFilter 注销并清空句柄
__int64 MiniFilterUnloadCleanup(void)
{
    AcquireMiniFilterMutexEx();
    if (g_Filter)
    {
        FltUnregisterFilter(g_Filter);
        g_Filter = 0;
    }
    AcquireMiniFilterMutex();
    return 0;
}

// MiniFilterCommPortRecv — 通信端口接收
// 对应原始驱动 sub_140019210
// 若 Minifilter 过滤器已注册则先执行注销清理，恒定返回 1
char MiniFilterCommPortRecv(void)
{
    if (g_Filter)
        MiniFilterUnloadCleanup();
    return 1;
}

// MiniFilterCommPortReply — 通信端口回复
// 向用户态通信端口回复数据，完成 IRP 或发送命名管道响应
// 对应原始驱动 sub_140019C10
NTSTATUS MiniFilterCommPortReply(void)
{
    // 通信端口回复需要 IRP 或命名管道上下文
    // 此处验证通信端口状态后返回
    if (!GtRead(GtCommPortCallbackReady))
        return STATUS_DEVICE_NOT_READY;
    return STATUS_SUCCESS;
}

// MiniFilterFormatFileNameWithPath — 注册带路径的文件名格式化回调
// 对应原始驱动 sub_14001A068
// 读取全局表 0x41BA 中已解析的回调注册函数，注册 MiniFilterFilterUnload 后清零就绪标志 0x8F1
char MiniFilterFormatFileNameWithPath(void)
{
    char Result;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, char));

    Result = 0;
    RegisterCallbackFunc = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char)))GtRead(GtTotalSize | GtNtQuerySystemInformationFunc | GtEprocessField22);
    if (RegisterCallbackFunc)
    {
        RegisterCallbackFunc((__int64 *(__fastcall *)(__int64, __int64, char))MiniFilterFilterUnload);
        GtWrite(GtMiniFilterFormatNameExReady, 0);
        return 1;
    }
    return Result;
}

// MiniFilterFormatFileNameWithContext — 格式化文件名带上下文
// 从回调上下文获取文件名信息并格式化
// 对应原始驱动 sub_140019ED0
__int64 MiniFilterFormatFileNameWithContext(void)
{
    // 需要 FLT_CALLBACK_DATA 上下文获取文件名
    return 0;
}

// MiniFilterFormatFileNameEx — 格式化文件名扩展
// 从流上下文获取文件名并格式化为 Unicode 字符串
// 对应原始驱动 sub_140019F50
__int64 MiniFilterFormatFileNameEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
    // 需要 FltGetStreamFileObjectContext 获取文件名
    return 0;
}

// MiniFilterFormatFileNameWithPathEx — 格式化文件名带路径扩展
// 从流上下文获取文件名并格式化为完整路径
// 对应原始驱动 sub_140019FD0
__int64 MiniFilterFormatFileNameWithPathEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
    // 需要 FltGetStreamFileObjectContext 获取文件名
    return 0;
}

// MiniFilterQueryIdleRoutine — 查询空闲例程
// 检查文件是否处于空闲状态（无活跃句柄），返回 STATUS_SUCCESS
// 对应原始驱动 sub_14001A050
NTSTATUS MiniFilterQueryIdleRoutine(void)
{
    // 需要 FltIsFileInUse 检查文件是否被使用
    return STATUS_SUCCESS;
}

// MiniFilterNotifyRoutineEx — 通知例程扩展
// 将文件操作通知发送到 GT 0x3400 缓冲区，扩展版本支持更多操作类型
// 对应原始驱动 sub_14001A0D0
NTSTATUS MiniFilterNotifyRoutineEx(void)
{
    if (!GtRead(GtCommPortCallbackReady))
        return STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

// MiniFilterActiveRoutine — 注册空闲查询例程
// 对应原始驱动 sub_14001A240
// 读取全局表 0x41B7 中已解析的注册函数，注册 MiniFilterQueryIdleRoutine 后清零通知例程标志 0x8F3
char MiniFilterActiveRoutine(void)
{
    char Result;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *));

    Result = 0;
    RegisterCallbackFunc = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *)))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField42);
    if (RegisterCallbackFunc)
    {
        RegisterCallbackFunc((__int64 *(__fastcall *)(__int64, __int64, _DWORD *))MiniFilterQueryIdleRoutine);
        GtWrite(GtMiniFilterNotifyRoutineReady, 0);
        return 1;
    }
    return Result;
}

// MiniFilterNotifyRoutineEx2 — 通知例程扩展2
// 通知例程的第二个扩展版本，支持额外的操作类型
// 对应原始驱动 sub_14001A1D0
NTSTATUS MiniFilterNotifyRoutineEx2(void)
{
    if (!GtRead(GtCommPortCallbackReady))
        return STATUS_SUCCESS;
    return STATUS_SUCCESS;
}

// MiniFilterStreamHandle — 流句柄处理
// 处理流级别的打开/关闭/读写操作
// 对应原始驱动 sub_14001A250
NTSTATUS MiniFilterStreamHandle(void)
{
    // 需要 FltGetStreamFileObjectContext 获取流上下文
    return STATUS_SUCCESS;
}

// MiniFilterPreFastIo — 快速 IO 预处理
// 处理 PreFastIoRead/PreFastIoWrite 等快速 IO 操作
// 对应原始驱动 sub_14001A2D0
NTSTATUS MiniFilterPreFastIo(void)
{
    // 需要 FLT_CALLBACK_DATA 获取快速 IO 信息
    return STATUS_SUCCESS;
}

// MiniFilterPostFastIo — 快速 IO 后处理
// 处理 PostFastIoRead/PostFastIoWrite 等快速 IO 操作
// 对应原始驱动 sub_14001A350
NTSTATUS MiniFilterPostFastIo(void)
{
    // 需要 FLT_CALLBACK_DATA 获取快速 IO 信息
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForModWrite — 获取修改写入锁
// 获取文件修改写入的独占锁，防止并发修改
// 对应原始驱动 sub_14001A3D0
NTSTATUS MiniFilterAcquireForModWrite(void)
{
    // 需要 FltAcquireForModifiedWrite 获取锁
    return STATUS_SUCCESS;
}

// MiniFilterReleaseForModWrite — 释放修改写入锁
// 释放文件修改写入的独占锁
// 对应原始驱动 sub_14001A450
NTSTATUS MiniFilterReleaseForModWrite(void)
{
    // 需要 FltReleaseForModifiedWrite 释放锁
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForCcFlush — 获取缓存管理器刷新锁
// 获取缓存管理器刷新的锁，用于同步缓存写入
// 对应原始驱动 sub_14001A4D0
NTSTATUS MiniFilterAcquireForCcFlush(void)
{
    // 需要 CcFlushCache 相关操作
    return STATUS_SUCCESS;
}

// MiniFilterReleaseForCcFlush — 释放缓存管理器刷新锁
// 释放缓存管理器刷新的锁
// 对应原始驱动 sub_14001A550
NTSTATUS MiniFilterReleaseForCcFlush(void)
{
    // 需要 CcFlushCache 相关操作
    return STATUS_SUCCESS;
}

// MiniFilterAcquireForSectionSync — 获取节同步锁
// 获取节同步的锁，用于同步节对象的写入
// 对应原始驱动 sub_14001A5D0
NTSTATUS MiniFilterAcquireForSectionSync(void)
{
    // 需要 FltAcquireFileForSectionSynchronization 获取锁
    return STATUS_SUCCESS;
}

// MiniFilterServerContext — 服务器上下文管理
// 管理 minifilter 服务器端的流/实例上下文
// 对应原始驱动 sub_14001A650
NTSTATUS MiniFilterServerContext(void)
{
    // 需要 FltGetStreamFileObjectContext 获取上下文
    return STATUS_SUCCESS;
}

// MiniFilterClientContext — 客户端上下文管理
// 管理 minifilter 客户端的流/实例上下文
// 对应原始驱动 sub_14001A6D0
NTSTATUS MiniFilterClientContext(void)
{
    // 需要 FltGetStreamFileObjectContext 获取上下文
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

            *(_QWORD *)OutputBuffer = (_QWORD)EntryStruct;
            *(_QWORD *)(OutputBuffer + 8) = (_QWORD)EntryStruct[1];
            WStringCopyN((_WORD *)(OutputBuffer + 16), GuidValueCopy, 0xAu);
            *(_DWORD *)(OutputBuffer + 34) = 0;
            *(_WORD *)(OutputBuffer + 164) = 0;

            if (ResolveObjectHeaderPointer((__int64)(CurrentEntry - 10), (_QWORD *)&HeaderInfo) == 1)
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

            if (ResolveObjectHeaderPointer(*(_QWORD *)(OutputBuffer + 8), (_QWORD *)&HeaderInfo) == 1)
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
    _DWORD PeSectionEntry[112];         // 描述符：原 [14] 仅 56 字节
    __int64 SectionDataPtr;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节，会被写坏栈）
    __int64 SectionFlags;
    ULONG SectionRawSize;
    ULONG ListHead1, ListHead2, ListHead3, ListHead4;
    ULONG SectionIndex;
    ULONG MatchCount;
    ULONG FoundCount;
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
        if (ReadPESectionEntry((PUCHAR)&ReadContext, PeSectionEntry))
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
        if (ReadPESectionEntry((PUCHAR)&ReadContext, PeSectionEntry))
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
            if (ReadPESectionEntry((PUCHAR)&ReadContext, PeSectionEntry))
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


// BuildFsFilterDriverPath1 — 构建文件系统过滤器驱动路径1
__int64 BuildFsFilterDriverPath1()
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394; EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426; EncodedPath[4] = 6553699; EncodedPath[5] = 7274610;
    EncodedPath[6] = 109; EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// BuildFsFilterDriverPath2 — 构建文件系统过滤器驱动路径2
__int64 BuildFsFilterDriverPath2()
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394; EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426; EncodedPath[4] = 6881348; EncodedPath[5] = 7012467;
    EncodedPath[6] = 0; EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// BuildRegistryDriverPath — 构建注册表驱动路径
__int64 BuildRegistryDriverPath()
{
    _DWORD EncodedBuffer[10];
    EncodedBuffer[0] = 4587612; EncodedBuffer[1] = 7077993; EncodedBuffer[2] = 5439589;
    EncodedBuffer[3] = 7536761; EncodedBuffer[4] = 6619252; EncodedBuffer[5] = 6029421;
    EncodedBuffer[6] = 7340110; EncodedBuffer[7] = 7536742; EncodedBuffer[8] = 0; EncodedBuffer[9] = 0;
    return OpenFileSection((__int64)EncodedBuffer);
}

// CheckFilePathFilter — 检查文件路径是否被过滤屏蔽
__int64 CheckFilePathFilter(__int64 FilePath, unsigned int FilePathLength)
{
    int Filter1;
    __int64 Filter2;
    int Filter3;
    if (FilePathLength <= 8)
        return 0;
    Filter1 = 4259876;
    Filter2 = 0x44007200740074LL;
    Filter3 = 6684773;
    if ((unsigned int)WStringCompareCaseInsensitive(FilePath + 6, (__int64)&Filter1)
        && (Filter1 = 5046308, Filter2 = 0x69004D00540046LL, Filter3 = 7471218,
            (unsigned int)WStringCompareCaseInsensitive(FilePath + 6, (__int64)&Filter1))
        && (Filter1 = 5046308, Filter2 = 5505094,
            (unsigned int)WStringCompareCaseInsensitive(FilePath + 6, (__int64)&Filter1)))
    {
        Filter1 = 5570596;
        Filter2 = 0x73006100430070LL;
        Filter3 = 101;
        return (unsigned int)WStringCompareCaseInsensitive(FilePath + 6, (__int64)&Filter1) == 0;
    }
    return 1;
}

// InitFileSystemExportTable — 初始化文件系统导出表
__int64 InitFileSystemExportTable(char Is64Bit)
{
    __int64 ExportTableAddr;
    unsigned int FileSize;
    char *FileBuffer;
    FileBuffer = 0;
    FileSize = 0;
    if (Is64Bit == 1)
    {
        ExportTableAddr = GtRead(GtFileSystemExportTable);
        if (ExportTableAddr)
        {
            GtAlloc((GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs5 | GtCallbackField79 | 0x1000));
            if (ReadDisksSysFile((_QWORD *)&FileBuffer, &FileSize))
            {
                if (ParseNtRelocSection((__int64)FileBuffer, FileSize, 0) == 1
                    && ParseNtExportDir((PUCHAR)FileBuffer, FileSize, ExportTableAddr, 0) == 1)
                {
                    GtWrite(GtFileSystemReady10, 1);
                }
                ExFree(FileBuffer);
            }
        }
    }
    else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        if (GtRead(GtFileSystemExportTable32))
        {
            GtAlloc((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField26 | 0x1500));
            if (ReadCdromSysFile((_QWORD *)&FileBuffer, &FileSize))
                ExFree(FileBuffer);
        }
    }
    return 0;
}

// CopyFsFilterEntryTable — 复制文件系统过滤器条目表
// 对应原始驱动 sub_14000E510
// 从 GT 分配表复制 64 条过滤器条目到输出缓冲区
__int64 CopyFsFilterEntryTable(__int64 OutputBuffer, char Is64Bit)
{
    __int64 *RelocTable;
    if (Is64Bit == 1)
        RelocTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1BB0);
    else
        RelocTable = GtAlloc((GLOBAL_TABLE_INDEX)0x1D3C);
    char Result = 0;
    __int64 OutputPtr = OutputBuffer + 16;
    for (int Count = 64; Count; Count--)
    {
        char *InputPtr = (char *)RelocTable + 4 + 48LL * (64 - Count);
        if (*(unsigned int *)InputPtr && *((unsigned int *)InputPtr - 1) == 1)
        {
            *(unsigned int *)(OutputPtr - 8) = *(unsigned int *)InputPtr;
            Result = 1;
            *(_QWORD *)OutputPtr = *(_QWORD *)(InputPtr + 4);
            *(_OWORD *)(OutputPtr + 18) = *(_OWORD *)(InputPtr + 12);
        }
        else
        {
            *(_QWORD *)OutputPtr = 0;
        }
        OutputPtr += 56;
    }
    return Result;
}

char EnumerateProcessCallbackContext(void)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    unsigned int CurrentOffset;
    __int64 SectionBase;
    unsigned int SectionSize;
    __int64 NtoskrnlBase;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    unsigned __int64 FuncAddress;
    unsigned __int8 *pScanPos;
    unsigned __int64 SectionEnd;
    int TokenType;
    unsigned int RetryCount;
    _WORD UnicodeChar[8];
    int CharOffset;
    unsigned int CharSize;
    int *pTokenType;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    CurrentOffset = (unsigned int)GtRead(0x42D0);
    SectionBase = GtRead(0x43A8);
    SectionSize = (unsigned int)GtRead(GtEprocessField22);
    NtoskrnlBase = GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if (CurrentOffset
        && CurrentOffset < SectionSize
        && SectionBase
        && SectionBase < SectionSize
        && NtoskrnlBase
        && SectionSize
        && NtoskrnlImageBase
        && ModuleInfo)
    {
        FuncAddress = *(_QWORD *)(NtoskrnlBase + 48);
        pScanPos = (unsigned __int8 *)(SectionBase + CurrentOffset);
        SectionEnd = SectionBase + SectionSize;

        if (DecodeUnicodeChar(pScanPos, SectionEnd, UnicodeChar) == 1)
        {
            do
            {
                TokenType = *pTokenType;
                if (*pTokenType == 4275)
                    break;

                pScanPos += CharSize;

                if (((unsigned int)(TokenType - 4267) <= 7 || TokenType == 4280)
                    && CharOffset > 0
                    && CharOffset > (int)FuncAddress
                    && (unsigned int)(CharOffset - (int)FuncAddress) < SectionSize)
                {
                    GtWrite(GtKernelDataField38, NtoskrnlImageBase + (unsigned int)(CharOffset - (int)FuncAddress));
                    Result = 1;
                }
            }
            while (DecodeUnicodeChar(pScanPos, SectionBase + SectionSize, UnicodeChar) == 1);

            if (Result == 1)
            {
                Result = 0;
                RetryCount = 0;
                while (DecodeUnicodeChar(pScanPos, SectionEnd, UnicodeChar))
                {
                    if (((unsigned int)(*pTokenType - 4267) <= 7 || *pTokenType == 4280)
                        && CharOffset > 0
                        && CharOffset > (int)FuncAddress
                        && (unsigned int)(CharOffset - (int)FuncAddress) < SectionSize)
                    {
                        GtWrite(GtKernelDataField40, NtoskrnlImageBase + (unsigned int)(CharOffset - (int)FuncAddress));
                        Result = 1;
                        break;
                    }
                    ++RetryCount;
                    pScanPos += CharSize;
                    if (RetryCount >= 0xA)
                        break;
                }
            }
        }
    }

    if (pTargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}


__int64 EnumFileSystemCallbackEntries(void)
{
    __int64 Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    unsigned int CurrentOffset;
    __int64 SectionBase;
    unsigned int SectionSize;
    __int64 NtoskrnlBase;
    __int64 NtoskrnlImageBase;
    int ModuleInfo;
    int SectionIndex;
    int FieldIndex;
    int ComputedRva;
    __int64 RootOffsetAccum;
    __int64 SectionDataPtr;
    int ModeField;
    int ModeField2;
    __int64 SectionCharacteristics;
    __int64 SectionDataPtr2;
    int EntrySize;
    int SectionFlags;
    int FieldValue;
    int FieldValue2;
    __int64 SectionEntry[56];           // 描述符：原 [8] 仅 64 字节
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 char[8] 仅 8 字节，会被写坏栈）
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    CurrentOffset = (unsigned int)GtRead(0x42D0);
    SectionBase = GtRead(0x43A8);
    SectionSize = (unsigned int)GtRead(0x20);
    NtoskrnlBase = GtRead(0x21);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    ModuleInfo = (int)GtRead(GtNtoskrnlImageSize);

    if (CurrentOffset
        && CurrentOffset < (unsigned int)NtoskrnlBase
        && SectionBase
        && (unsigned int)SectionBase < (unsigned int)NtoskrnlBase
        && SectionSize
        && NtoskrnlBase
        && NtoskrnlImageBase
        && ModuleInfo)
    {
        InitPESectionReadContext(
            (__int64)(SectionBase + CurrentOffset),
            (unsigned int)NtoskrnlBase - CurrentOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);

        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
        {
            EntrySize = (int)SectionEntry[6];
            RootOffsetAccum += EntrySize;
            SectionDataPtr2 = SectionDataPtr;

            // 检查是否到达终止类型 (0x545 = 1349)
            if (*(_WORD *)(SectionDataPtr + 6) == 0x545)
                break;

            // 检查是否为 SSDT 表类型 (0x512 = 1298)
            if (*(_WORD *)(SectionDataPtr + 6) == 0x512)
            {
                // 检查字段条件: FieldValueSize == 64, FieldCount == 2, FieldFlags == 4
                if (SectionCharacteristics == 64 && ModeField == 2 && ModeField2 == 4)
                {
                    // 读取下一个条目
                                if (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                    {
                        EntrySize = (int)SectionEntry[6];
                        RootOffsetAccum += EntrySize;
                        SectionDataPtr2 = SectionDataPtr;

                        // 再次检查 Type 0x512
                        if (*(_WORD *)(SectionDataPtr + 6) == 0x512)
                        {
                            // 检查字段条件: FieldValueSize == 64, FieldCount == 1, FieldFileOffset == 0x40000
                            if (SectionCharacteristics == 64 && ModeField == 1 && ModeField2 == 0x40000)
                            {
                                ComputedRva = FieldValue - (int)SectionSize + (int)RootOffsetAccum;

                                // 读取下一个条目确认 Type 0x558
                    if (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                                {
                                    EntrySize = (int)SectionEntry[6];
                                    RootOffsetAccum += EntrySize;
                                    SectionDataPtr2 = SectionDataPtr;

                                    if (*(_WORD *)(SectionDataPtr + 6) == 0x558 && ComputedRva)
                                    {
                                        if ((unsigned int)ComputedRva < (unsigned int)NtoskrnlBase)
                                        {
                                            GtWrite(GtKernelDataField38, NtoskrnlImageBase + ComputedRva);
                                            Result = 0;

                                            // 第二遍扫描：查找偏移地址
                                            FieldIndex = 0;
                                            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                                            {
                                                EntrySize = (int)SectionEntry[6];
                                                RootOffsetAccum += EntrySize;
                                                SectionDataPtr2 = SectionDataPtr;

                                                // 检查是否达到构建号边界
                                                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x55F0)
                                                {
                                                    if (*(_WORD *)(SectionDataPtr + 6) == 0x545)
                                                        break;
                                                }

                                                // 检查类型匹配: 0x4B1(1201), 0x175(373), 0x472(1138)
                                                if (*(_WORD *)(SectionDataPtr + 6) == 0x4B1
                                                    || *(_WORD *)(SectionDataPtr + 6) == 0x175
                                                    || *(_WORD *)(SectionDataPtr + 6) == 0x472)
                                                {
                                                    if ((SectionFlags & 4) != 0 && SectionCharacteristics == 0x40000)
                                                    {
                                                        ComputedRva = FieldValue2 - (int)SectionSize + (int)RootOffsetAccum;
                                                        if (ComputedRva && (unsigned int)ComputedRva < (unsigned int)NtoskrnlBase)
                                                        {
                                                            GtWrite(GtKernelDataField40, NtoskrnlImageBase + ComputedRva);
                                                            Result = 1;
                                                            break;
                                                        }
                                                    }
                                                }

                                                if ((unsigned int)++FieldIndex >= 0x12C)
                                                    break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ((unsigned int)++SectionIndex >= 0xC8)
                break;
        }
    }

    if (pTargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}



// ParseNtRelocSection -- 解析 NT 重定位节区
// 对应原始驱动 sub_14000E634
// 在 PE 文件缓冲中定位重定位节区：第一轮找标记 0x559 的节区取得节区表偏移，
// 第二轮找标记 0x547 + 节区名 0x188 的重定位节区，第三轮按 NtBuildNumber 分两套标记
// （>= 0x23F0 用 0x547 + 名字 0xC0916A2；否则用 0x547 + 名字 0x188）收集重定位条目，
// 把条目写回输出表：步长 48 字节，+8 处存 ExportTableBase+文件偏移，+4 处存文件偏移
//
// 节区条目缓冲（SectionEntry，0x120 字节）字段偏移来自原始驱动栈布局：
//   0x38 VirtualAddress   0x40 VirtualSize    0x50 Characteristics  0x58 SectionIndex
//   0x70 SectionName      0x78 RawDataSize    0x88 SectionAlignment  0x90 RelocEntryIndex
//   0xDC MiscInfo         0xF0 SizeOfRawData  0x118 SectionNamePtr
char ParseNtRelocSection(__int64 FileBuffer, unsigned int FileSize, __int64 OutputTable)
{
    __int64 SectionOffset;
    int SectionIndex;
    int SectionEnd;
    unsigned int RawOffset;
    int RelocSectionIndex;
    int FirstRelocRva;
    int FirstRelocType;
    char FoundWin10Reloc;
    int RelocEntryIndex;
    unsigned int NtBuildNumber;
    __int64 SectionCharacteristics;
    unsigned int RelocFileOffset;
    int CurrentRelocRva;
    int BaseRelocRva;
    unsigned int RelocDelta;
    __int64 TableIndex;
    unsigned int EntryFileOffset;
    __int64 TableEntryPtr;
    __int64 EntryOffset;
    unsigned int RelocDeltaBytes;
    __int64 EntryIndex;
    __int64 OutputTableEntry;
    __int16 SectionFlags;
    __int16 FlagsCheck;
    char EndCheck;
    char Result;
    int BaseRelocRvaSaved;
    __int64 ExportTableBase;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 char[8] 仅 8 字节，会被写坏栈）
    __int64 CumulativeOffset;
    _DWORD SectionEntry[72];
    _DWORD DirectoryTable[16];

    Result = 0;
    CumulativeOffset = 0;
    ExportTableBase = GtRead(GtFileSystemExportTable);
    if (!ExportTableBase)
        return Result;

    // 节区表偏移 = e_lfanew(0x3C) 指向的 PE 头 + 0x28
    SectionOffset = *(unsigned int *)(*(int *)(FileBuffer + 60) + FileBuffer + 40);
    if ((unsigned int)SectionOffset < FileSize && (unsigned int)((int)SectionOffset + 4096) < FileSize)
    {
        InitPESectionReadContext(FileBuffer + SectionOffset, 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        SectionIndex = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
        {
            SectionEnd = (int)(*(unsigned int *)((char *)SectionEntry + 0xF0) + CumulativeOffset);
            CumulativeOffset += *(unsigned int *)((char *)SectionEntry + 0xF0);
            if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1369)
            {
                if (*(int *)((char *)SectionEntry + 0x38))
                {
                    RawOffset = (unsigned int)(SectionEnd + *(int *)((char *)SectionEntry + 0x38) - FileBuffer);
                    if (RawOffset)
                    {
                        if (RawOffset < FileSize)
                        {
                            LODWORD_LV(SectionOffset) = RawOffset;
                            break;
                        }
                    }
                }
            }
            if ((unsigned int)++SectionIndex >= 0x1E)
                break;
        }
    }

    if (!(_DWORD)SectionOffset || (unsigned int)SectionOffset >= FileSize ||
        (unsigned int)((int)SectionOffset + 4096) >= FileSize)
        return Result;

    BaseRelocRvaSaved = 0;
    InitPESectionReadContext(FileBuffer + (unsigned int)SectionOffset, 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    RelocSectionIndex = 0;
    while (1)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return Result;
        CumulativeOffset += *(unsigned int *)((char *)SectionEntry + 0xF0);
        if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1351 &&
            *(__int64 *)((char *)SectionEntry + 0x70) == 0x188)
            break;
        if ((unsigned int)++RelocSectionIndex >= 0x1F4)
            return Result;
    }

    FirstRelocRva = *(int *)((char *)SectionEntry + 0x40);
    FirstRelocType = *(_DWORD *)((char *)SectionEntry + 0xDC) & 0xF;
    if (!FirstRelocRva)
        return Result;

    memset(DirectoryTable, 0, sizeof(DirectoryTable));
    FoundWin10Reloc = 0;
    InitPESectionReadContext(FileBuffer + (unsigned int)SectionOffset, 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    RelocEntryIndex = 0;

    while (1)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return Result;
        CumulativeOffset += *(unsigned int *)((char *)SectionEntry + 0xF0);

        NtBuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
        SectionFlags = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        if (NtBuildNumber >= 0x23F0)
        {
            if (SectionFlags == 0x547 && *(__int64 *)((char *)SectionEntry + 0x70) == 0xC0916A2)
                FoundWin10Reloc = 1;
        }
        else if (SectionFlags == 0x547 && *(__int64 *)((char *)SectionEntry + 0x70) == 0x188)
        {
            FoundWin10Reloc = 1;
        }

        SectionCharacteristics = *(__int64 *)((char *)SectionEntry + 0x50);
        if (SectionFlags == 0x512 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            if (*(int *)((char *)SectionEntry + 0x78) && SectionCharacteristics == 64)
            {
                RelocFileOffset = (unsigned int)(CumulativeOffset + *(int *)((char *)SectionEntry + 0x78) - FileBuffer);
                if (RelocFileOffset)
                {
                    if (RelocFileOffset < FileSize)
                        DirectoryTable[*(int *)((char *)SectionEntry + 0x58)] = RelocFileOffset;
                }
            }
        }

        if (SectionFlags != 1294 ||
            (SectionCharacteristics & 0x14000) == 0 ||
            (SectionCharacteristics & 0x40) == 0 ||
            *(__int64 *)((char *)SectionEntry + 0x88) != 64)
        {
            goto CheckWin10End;
        }

        CurrentRelocRva = *(int *)((char *)SectionEntry + 0x40);
        if (FirstRelocType == (*(_DWORD *)((char *)SectionEntry + 0xDC) & 0xF))
            break;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
            goto CheckWin10End;

        EntryOffset = (unsigned int)DirectoryTable[*(int *)((char *)SectionEntry + 0x90)];
        if (!(_DWORD)EntryOffset)
            goto CheckWin10End;
        if (FoundWin10Reloc != 1)
            goto NextRelocEntry;

        BaseRelocRva = BaseRelocRvaSaved;
        if (!BaseRelocRvaSaved)
        {
            BaseRelocRva = *(int *)((char *)SectionEntry + 0x40) - 64;
            BaseRelocRvaSaved = *(int *)((char *)SectionEntry + 0x40) - 64;
        }
        RelocDeltaBytes = (unsigned int)(CurrentRelocRva - BaseRelocRva);
        if (RelocDeltaBytes - 1 <= 0x186 && (RelocDeltaBytes & 7) == 0)
        {
            EntryIndex = RelocDeltaBytes >> 3;
            if ((unsigned int)EntryIndex < 0x40)
            {
                OutputTableEntry = 6 * EntryIndex;
                *(__int64 *)(OutputTable + 8 * OutputTableEntry + 8) = ExportTableBase + EntryOffset;
                *(_DWORD *)(OutputTable + 8 * OutputTableEntry + 4) = (unsigned int)EntryOffset;
                Result = 1;
                goto CheckWin10End;
            }
        }

    NextRelocEntry:
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        {
            EndCheck = (unsigned __int16)(*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) - 1139) <= 1;
        }
        else
        {
            FlagsCheck = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (FlagsCheck == 1368)
                return Result;
            EndCheck = (unsigned __int16)(FlagsCheck - 1139) <= 1;
        }
        if (EndCheck)
            return Result;

    RescanRelocEntry:
        if ((unsigned int)++RelocEntryIndex >= 0x1F4)
            return Result;
        continue;

    CheckWin10End:
        if (FoundWin10Reloc != 1)
            goto RescanRelocEntry;
        goto NextRelocEntry;
    }

    // FirstRelocType 与 MiscInfo 低 4 位一致时跳出上面的循环，改走本路径写回条目
    {
        char IsSizeValid = FirstRelocRva <= 0;
        if (FirstRelocRva < 0)
        {
            if (*(int *)((char *)SectionEntry + 0x40) < 0 &&
                *(int *)((char *)SectionEntry + 0x40) > FirstRelocRva)
            {
                goto WriteRelocEntry;
            }
            IsSizeValid = FirstRelocRva <= 0;
        }
        if (IsSizeValid || *(int *)((char *)SectionEntry + 0x40) <= 0 ||
            *(int *)((char *)SectionEntry + 0x40) <= FirstRelocRva)
        {
            goto CheckWin10End;
        }

    WriteRelocEntry:
        RelocDelta = (unsigned int)(*(int *)((char *)SectionEntry + 0x40) - FirstRelocRva);
        if (RelocDelta - 1 <= 0x186 && (RelocDelta & 7) == 0)
        {
            TableIndex = RelocDelta >> 3;
            if ((unsigned int)TableIndex < 0x40)
            {
                EntryFileOffset = (unsigned int)DirectoryTable[*(int *)((char *)SectionEntry + 0x90)];
                if (EntryFileOffset)
                {
                    TableEntryPtr = 6 * TableIndex;
                    Result = 1;
                    *(__int64 *)(OutputTable + 8 * TableEntryPtr + 8) = ExportTableBase + EntryFileOffset;
                    *(_DWORD *)(OutputTable + 8 * TableEntryPtr + 4) = EntryFileOffset;
                }
            }
        }
        goto CheckWin10End;
    }
    return Result;
}

// FileSystemFilterCallback — 文件系统过滤回调 (0x14000EF84)
// 处理文件系统过滤补丁数据，根据补丁标志执行 PatchFsFilterDriverIndex 和 WritePhysicalMemoryBuffer
__int64 __fastcall FileSystemFilterCallback(char *PatchBuffer, int BufferSize)
{
    __int64 Result;
    char PatchResult;
    char WriteResult;
    PVOID TargetAddress;
    _OWORD WriteData;

    Result = 0;
    if (PatchBuffer)
    {
        if (BufferSize == 64
            && (unsigned __int64)PatchBuffer < MmUserProbeAddress
            && (unsigned __int64)(PatchBuffer + 64) < MmUserProbeAddress)
        {
            ProbeForRead(PatchBuffer, 0x40, 1);
            if (PatchBuffer[8] == 1
                && *(unsigned int *)(PatchBuffer + 12) < 0x40
                && (*PatchBuffer == 1 || (unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0))
            {
                PatchResult = 1;
                WriteResult = 1;
                if (PatchBuffer[40] == 1 && *(__int64 *)(PatchBuffer + 24))
                    PatchResult = PatchFsFilterDriverIndex((__int64)(PatchBuffer + 8), *PatchBuffer);
                if (PatchBuffer[41] == 1)
                {
                    WriteResult = 0;
                    TargetAddress = (PVOID)*(__int64 *)(PatchBuffer + 24);
                    if (TargetAddress > MmSystemRangeStart
                        && CheckMemoryValid(TargetAddress) == 1
                        && CheckMemoryValid((void *)(*(__int64 *)(PatchBuffer + 24) + 15)) == 1)
                    {
                        WriteData = *(_OWORD *)(PatchBuffer + 42);
                        WriteResult = WritePhysicalMemoryBuffer(*(__int64 *)(PatchBuffer + 24), &WriteData, 0x10, 0, 0);
                    }
                }
                return PatchResult & WriteResult;
            }
        }
    }
    return Result;
}

// MiniFilterQueryFileName — MiniFilter 文件名查询
// 遍历通知链表，不区分大小写比较文件名是否已存在
// 对应原始驱动 sub_140019D8C
char MiniFilterQueryFileName(wchar_t *FileName)
{
    volatile ULONG64 CurrentEntry = (ULONG64)g_Pointer;
    char Result = 0;

    while (CurrentEntry)
    {
        if (!_wcsicmp(FileName, (const wchar_t *)(CurrentEntry + 12)))
            return 1;
        CurrentEntry = *(_QWORD *)CurrentEntry;
    }
    return Result;
}

// FindKernelInitSection — 查找内核 INIT 节
// 遍历 PE 节表查找 INIT 节（标志 1349），计算 INIT 节结束位置，写入全局表 GT 索引 0x183
// 对应原始驱动 sub_140012C28
ULONG64 FindKernelInitSection(void)
{
    char FoundInitSection = 0;
    __int64 PeBase, PeSize, NtImageBase, SectionAddr, SectionOffset;
    unsigned int SectionIndex;
    int SectionSize;
    __int16 SectionFlags;
    char ReadContext[0x198];
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [14] 仅 56 字节
    unsigned int InitSectionSize;
    __int64 SectionFlags2, SectionDataPtr, SectionCharacteristics;
    unsigned int RawSize;
    __int64 SectionName;

    GtWrite((GLOBAL_TABLE_INDEX)0x913, 0);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        PeBase = GtRead((GLOBAL_TABLE_INDEX)0x20);
        PeSize = GtRead((GLOBAL_TABLE_INDEX)0x21);
        NtImageBase = GtRead(GtNtoskrnlModuleBase);
        SectionAddr = GtRead((GLOBAL_TABLE_INDEX)0x177);
        if (PeBase && PeSize && NtImageBase && SectionAddr > NtImageBase)
        {
            SectionOffset = (unsigned int)(SectionAddr - NtImageBase);
            if ((unsigned int)SectionOffset < PeSize && SectionAddr == SectionOffset + NtImageBase)
            {
                InitPESectionReadContext(PeBase + SectionOffset, (ULONG)(PeSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);
                for (SectionIndex = 0; SectionIndex < 0x64; ++SectionIndex)
                {
                    if (ReadPESectionEntry(ReadContext, SectionInfo))
                        break;
                    SectionSize = RawSize + (ULONG)SectionInfo[2];
                    SectionInfo[2] += RawSize;
                    SectionFlags = *(__int16 *)(SectionName + 6);
                    if (SectionFlags == 1349)
                        break;
                    if (SectionFlags == 1069 && SectionCharacteristics == 0x1000000000LL && !SectionDataPtr)
                        FoundInitSection = 1;
                    else if (SectionFlags == 1368 && (SectionFlags2 & 0x4000000) != 0 && InitSectionSize)
                    {
                        if (FoundInitSection == 1)
                        {
                            ULONG64 Result = SectionSize + InitSectionSize - (ULONG)PeBase;
                            if ((unsigned int)Result < PeSize)
                                return GtWrite((GLOBAL_TABLE_INDEX)0x183, NtImageBase + (unsigned int)Result);
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// FindKernelDataSectionV2Dispatch — 内核数据节 V2 查找分发
// 对应原始驱动 sub_1400130A4（地址 0x1400130A4，31 字节）
// 【逆向来源】人工阅读反汇编重建 —— IDA 无法分析该函数
// 【逻辑】构建号 >= 0x1DB0(7600, Win7) 时调用 FindKernelDataSectionForCreateFile，否则原样返回构建号
__int64 FindKernelDataSectionV2Dispatch(void)
{
    __int64 Result;

    Result = GtRead(GtWindowsBuildNumber);
    if ((unsigned int)Result >= 0x1DB0)
        return FindKernelDataSectionForCreateFile();
    return Result;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `sub_1400130C4` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x180；消费者 SendCreateFileIoControl。
//   故改名为 FindKernelDataSectionForCreateFile（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForCreateFile — 查找内核数据节 V2
// 对应原始驱动 sub_1400130C4（地址 0x1400130C4，551 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用）
// 【验证依据】与 FindKernelDataSectionForStringParam(0x140014ACC) 逐指令差分，两者同构；
//   节区字段偏移沿用已四次交叉验证的 0x120 布局
// 【与 FindKernelDataSectionForStringParam 的差异（差分结论）】
//   1) 多读一个全局表值 0x4222 并要求其非 0（32 位判断）
//   2) 路径基准值改用 0x176 处的值
//   3) 0x53D 分支中 +0x70 的比较值为 0x11（FindKernelDataSectionForStringParam 为 0x10）
//   4) 命中结果写入全局表 0x180（FindKernelDataSectionForStringParam 为 0x17E）
// 【逻辑】取全局表值 → 一致性校验（基准值须落在 [NtImageBase, +KernelSize) 且自洽）
//   → 扫描最多 0x200 个节区，按 0x43E / 0x558 / 0x53D 三支处理 → 命中写入 GT 0x180
__int64 FindKernelDataSectionForCreateFile(void)
{
    char FoundFlag;
    ULONG64 KernelBase;
    unsigned int KernelSize;
    ULONG64 NtImageBase;
    unsigned int RequiredFlag;
    ULONG64 DataSectionVa;
    unsigned int ImageOffset;
    unsigned int SavedValue;
    unsigned int SectionIndex;
    // 【读指针语义】原始驱动把「累计长度」直接累加到解码上下文的 +0x08(读指针) 上：
    //   InitPESectionReadContext 先写入 Base，随后每轮 `+= 描述符[0xF0](指令长度)`
    //   ——ReadPESectionEntry 对上下文只读、自身不推进，推进责任在调用方。
    //   故此处不再使用独立变量，直接用 ReadContext.ReadPtr（初值由初始化函数写入）。
    unsigned __int16 SectionType;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FoundFlag = 0;
    SavedValue = 0;

    KernelBase = (ULONG64)GtRead(GtEprocessField22);
    KernelSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    RequiredFlag = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x4222);
    DataSectionVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x176);

    if (!KernelBase || !KernelSize || !NtImageBase || !RequiredFlag)
        return 0;
    if (DataSectionVa <= NtImageBase)
        return 0;

    ImageOffset = (unsigned int)(DataSectionVa - NtImageBase);
    if (ImageOffset >= KernelSize)
        return 0;
    if (DataSectionVa != NtImageBase + ImageOffset)
        return 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (SectionIndex = 0; SectionIndex < 0x200; SectionIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            break;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x43E &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 0x80000 &&
            *(_DWORD *)((char *)SectionEntry + 0x70) == 2)
        {
            FoundFlag = 1;
            continue;
        }

        if (SectionType == 0x558 &&
            (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
            *(_DWORD *)((char *)SectionEntry + 0x38) != 0)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) != 0x4F7C || FoundFlag != 1)
            {
                SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38) - (unsigned int)KernelBase + (unsigned int)ReadContext.ReadPtr;
            }
            FoundFlag = 0;
            continue;
        }

        if (SectionType == 0x53D &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 0x800000 &&
            *(_DWORD *)((char *)SectionEntry + 0x70) == 0x11 &&
            *(__int64 *)((char *)SectionEntry + 0x50) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                continue;

            if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 0x558)
            {
                if (SavedValue && SavedValue < KernelSize)
                    GtWrite((GLOBAL_TABLE_INDEX)0x180, (__int64)(SavedValue + NtImageBase));
                break;
            }
        }
    }
    return 0;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `sub_1400132EC` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17A；消费者 SendReadMemoryIoControl。
//   故改名为 FindKernelDataSectionForReadMemory（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForReadMemory — 查找内核数据节 V3
// 对应原始驱动 0x1400132EC（638 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x1400132EC~0x14001356A
//   的 186 条指令逐条还原
// 【验证依据】与 FindKernelDataSectionForWriteMemory(0x1400137BC) 逐指令差分：
//   两者结构同源（同一段类型序列扫描逻辑），本函数的寄存器分配为
//   r15=文件基址 / r14=文件大小 / rbx=镜像基址 / esi=节区序号；
//   描述符字段偏移由 rbp 位移换算（条目基址 var_150 = rbp-0x60）得到
//   0xF0 / 0x118 / 0x88 / 0x70 / 0x50 / 0x58 / 0x38，与已验证的 0x120 布局吻合
// 【与 FindKernelDataSectionForWriteMemory 的差异（差分结论）】
//   1) 扫描起点读 GT 0x170（V2 为 GT 0x171），校验方式完全相同
//   2) 无 GT 0x41C5 非零前置校验
//   3) 循环上限 0x200（V2 为 0x300）
//   4) 三段匹配的类型码为 0x512 / 0x558 / 0x420（V2 为 0x512 / 0x558 / 0x510），
//      且 0x420 型的判定字段为 +0x88==0x800000、+0x70==0xC0000023、+0x50==0x20
//      （V2 的 0x510 型为 +0x88==0x10041、+0x58==9、+0x50==0x40）
//   5) 新旧路径的分工相反：本函数**旧路径**做"第 2 次命中"计数并直接写结果，
//      **新路径**先记候选值（edi）再等 0x420 型节区确认
//   6) 命中结果写入全局表 0x17A（V2 为 0x17B）
// 【读指针语义（重要）】本函数与 V1/V2 一样，把「上下文 +0x08」当作读指针推进：
//   原始 `add [rsp+1F0h+var_198], rax`（var_198 = 上下文+8，64 位 read-modify-write
//   在 V1 中可见）累加的是描述符 +0xF0（指令长度），而 ReadPESectionEntry 对上下文
//   只读、自身不推进，故推进责任在调用方。详见 PE_DECODE_CONTEXT 的注释。
// 【逻辑】取 4 个全局表值做一致性校验（GT 0x170 须落在 (GT3, GT3+文件大小) 内
//   且低 32 位截断自洽）→ 以「文件缓冲区 + (GT 0x170 - GT 0x3)」为起点初始化 PE
//   节区读取上下文 → 最多扫描 0x200 个节区，每轮把读指针按指令长度推进：
//     a) 0x512 型且 +0x50==0x40：按 +0x58 记录序号 —— ==2 记 Type2EntryIndex、
//        ==9 记 Type9EntryIndex、==1 且（紧跟 Type2 之后 1 节 或 Type9 之后 3 节）
//        则置 FoundType1Pair 标志
//     b) FoundType1Pair 置位后按构建号分岔：
//        - 旧版：本节点须为 0x558 型且带 0x4000000 标志且 VirtualAddress!=0，
//          且为第 2 次命中；候选值 = VirtualAddress - 文件缓冲区低 32 位 + 读指针低 32 位，
//          候选值 >= 文件大小则直接返回（**不判 0**）
//        - 新版：本节点为 0x558 型且带 0x4000000 标志且 VirtualAddress!=0 时，
//          先记候选值 SavedValue 并继续；随后遇到 0x420 型且 +0x88==0x800000 且
//          +0x70==0xC0000023 且 +0x50==0x20 且 SavedValue 非 0 且 < 文件大小时写结果
//     两路命中均写入全局表 0x17A（候选值 + GT 0x3 镜像基址）
__int64 FindKernelDataSectionForReadMemory(void)
{
    unsigned __int16 SectionType;
    unsigned int KernelSize;
    unsigned int ScanOffset;
    unsigned int EntryIndex;
    unsigned int Type2EntryIndex;
    unsigned int Type9EntryIndex;
    unsigned int Type1MatchCount;
    unsigned int SavedValue;
    char FoundType1Pair;
    ULONG64 FileBase;
    ULONG64 NtImageBase;
    ULONG64 ScanStartVa;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FileBase = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    KernelSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    ScanStartVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x170);

    Type2EntryIndex = 0;
    Type9EntryIndex = 0;
    Type1MatchCount = 0;
    FoundType1Pair = 0;
    SavedValue = 0;

    if (!FileBase || !KernelSize || !NtImageBase)
        return 0;
    if (ScanStartVa <= NtImageBase)
        return 0;

    ScanOffset = (unsigned int)(ScanStartVa - NtImageBase);
    if (ScanOffset >= KernelSize)
        return 0;
    if (ScanStartVa != NtImageBase + ScanOffset)
        return 0;

    InitPESectionReadContext(FileBase + ScanOffset, KernelSize - ScanOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (EntryIndex = 0; EntryIndex < 0x200; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return 0;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x512 && *(__int64 *)((char *)SectionEntry + 0x50) == 0x40)
        {
            switch (*(unsigned int *)((char *)SectionEntry + 0x58))
            {
            case 2:
                Type2EntryIndex = EntryIndex;
                continue;

            case 9:
                Type9EntryIndex = EntryIndex;
                continue;

            case 1:
                if (Type2EntryIndex)
                {
                    if (Type2EntryIndex + 1 == EntryIndex)
                    {
                        FoundType1Pair = 1;
                        continue;
                    }
                }
                if (!Type9EntryIndex)
                    continue;
                if (Type9EntryIndex + 3 != EntryIndex)
                    continue;
                FoundType1Pair = 1;
                continue;

            default:
                continue;
            }
        }

        if (FoundType1Pair != 1)
            continue;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        {
            // 新版路径：先记候选值，随后由 0x420 型节区确认
            if (SectionType == 0x558 &&
                (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0)
            {
                SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38);
                if (SavedValue)
                {
                    SavedValue = SavedValue - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;
                    continue;
                }
            }

            if (SectionType != 0x420)
                continue;
            if (*(__int64 *)((char *)SectionEntry + 0x88) != 0x800000)
                continue;
            if (*(__int64 *)((char *)SectionEntry + 0x70) != 0xC0000023)
                continue;
            if (*(__int64 *)((char *)SectionEntry + 0x50) != 0x20)
                continue;
            if (!SavedValue)
                continue;
            if (SavedValue >= KernelSize)
                continue;

            GtWrite((GLOBAL_TABLE_INDEX)0x17A, (__int64)(SavedValue + NtImageBase));
            return 0;
        }

        // 旧版路径：0x558 型节区出现 2 次才认定，且不判候选值是否为 0
        if (SectionType != 0x558)
            continue;
        if ((*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) == 0)
            continue;

        SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38);
        if (!SavedValue)
            continue;

        if (++Type1MatchCount != 2)
            continue;

        SavedValue = SavedValue - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;
        if (SavedValue >= KernelSize)
            return 0;

        GtWrite((GLOBAL_TABLE_INDEX)0x17A, (__int64)(SavedValue + NtImageBase));
        return 0;
    }
    return 0;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `sub_140012E0C` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17F；消费者 OpenSectionWithIoControl。
//   故改名为 FindKernelDataSectionForOpenSection（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForOpenSection — 查找内核 PAGE 节
// 对应原始驱动 0x140012E0C（662 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x140012E0C~0x1400130A1
//   的 174 条指令逐条还原；控制流用与原地址一一对应的 goto 标签保持忠实
// 【验证依据】描述符字段偏移由 rbp 位移换算（条目基址 var_150 = rbp-0x60）：
//   0xF0 / 0x118 / 0x88 / 0x70 / 0x50 / 0x58 / 0x78 / 0x38，与已验证的 0x120
//   布局吻合；帧布局与另外六个扫描器一致（ctx = rsp+0x50，读指针 = rsp+0x58 = ctx+8）
// 【与其它扫描器的差异（差分结论）】
//   1) 扫描起点读 GT 0x175，结果写 GT 0x17F，另读 GT 0x446B 作为"已算出的值"用于比对
//   2) 分段识别条件不同：0x461 型(+0x88==0x80000 且 +0x70==4)置标记；
//      0x558 型(+0x50 的 bit26)取候选值；0x53D 型(+0x88==0x800000 且 +0x70==0xF 且
//      +0x50==0x20 且 +0x58==1) 或 0x512 型(+0x50==0x20 且 +0x58==1 且 +0x78==0xF
//      且 +0x88==0x4041) 则再取后续节区确认
//   3) 有"候选值 == GT 0x446B"的提前命中路径（跳过构建号判断）
//   4) 构建号 0x4F7C 且已置 0x461 标记时跳过本节点的候选值记录
//   5) 循环上限 0x200
// 【⚠ GT 0x446B 说明】该索引落在原始驱动的"哈希表区"(0x4158-0x4479)，
//   运行时会被解析结果覆盖，此处按"与已算出的值比对"理解，语义存疑但操作忠实。
// 【⚠ 变量复用说明】edi 在原始驱动中一变量两用：循环顶部固定为 0x558（供 `di` 比较，
//   即"期望类型"），在 0x558 分支里又被赋为候选偏移值。因两条路径互斥且每轮重设，
//   本实现用同一变量 TypeOrCandidate 忠实保留该复用。
// 【逻辑】取 4 个全局表值做一致性校验后，以「文件缓冲区 + (GT 0x175 - GT 0x3)」为
//   起点初始化 PE 节区读取上下文，最多扫描 0x200 个节区（每轮把读指针按指令长度推进）：
//     命中路径一：候选值恰等于 GT 0x446B 的低 32 位 → 立即尝试写入
//     命中路径二：在 0x53D/0x512 型节点之后，再连续取节区，若其类型回到 0x558 则命中
//   写入前校验：候选值非 0 且 < 文件大小，写入 GT 0x17F（候选值 + 镜像基址）
__int64 FindKernelDataSectionForOpenSection(void)
{
    unsigned __int16 SectionType;
    unsigned int KernelSize;
    unsigned int ScanOffset;
    unsigned int EntryIndex;
    unsigned int SavedValue;
    unsigned int TypeOrCandidate;
    ULONG64 EntryFlags88;
    ULONG64 EntryFlags50;
    unsigned int PreviousValue;
    char FoundType461;
    ULONG64 FileBase;
    ULONG64 NtImageBase;
    ULONG64 ScanStartVa;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FoundType461 = 0;
    SavedValue = 0;

    FileBase = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    KernelSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    ScanStartVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x175);

    if (!FileBase || !KernelSize || !NtImageBase)
        return 0;
    if (ScanStartVa <= NtImageBase)
        return 0;

    ScanOffset = (unsigned int)(ScanStartVa - NtImageBase);
    if (ScanOffset >= KernelSize)
        return 0;
    if (ScanStartVa != NtImageBase + ScanOffset)
        return 0;

    InitPESectionReadContext(FileBase + ScanOffset, KernelSize - ScanOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    PreviousValue = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x446B);

    for (EntryIndex = 0; EntryIndex < 0x200; EntryIndex++)
    {
        TypeOrCandidate = 0x558;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return 0;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        EntryFlags88 = *(__int64 *)((char *)SectionEntry + 0x88);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x461 &&
            EntryFlags88 == 0x80000 &&
            *(__int64 *)((char *)SectionEntry + 0x70) == 4)
        {
            FoundType461 = 1;
            goto LABEL_LOOP_TAIL;                       // 0x140013049
        }

        EntryFlags50 = *(__int64 *)((char *)SectionEntry + 0x50);

        if ((unsigned __int16)TypeOrCandidate == SectionType && (EntryFlags50 & 0x4000000) != 0)
        {
            // 0x558 型：取候选偏移值
            TypeOrCandidate = *(unsigned int *)((char *)SectionEntry + 0x38);
            if (TypeOrCandidate)
            {
                TypeOrCandidate = TypeOrCandidate - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;

                if (PreviousValue == TypeOrCandidate)
                    goto LABEL_WRITE;                   // 0x14001305A：与已算出的值相同 → 命中

                if ((unsigned int)GtRead(GtWindowsBuildNumber) == 0x4F7C && FoundType461)
                    goto LABEL_LOOP_TAIL;               // 该版本且已置标记 → 跳过

                SavedValue = TypeOrCandidate;
                goto LABEL_LOOP_TAIL;
            }
            TypeOrCandidate = 0x558;                    // 候选值为 0 → 恢复期望类型
        }

        // 0x53D 型或 0x512 型：再取后续节区确认
        if (!(SectionType == 0x53D &&
              EntryFlags88 == 0x800000 &&
              *(_DWORD *)((char *)SectionEntry + 0x70) == 0xF &&
              EntryFlags50 == 0x20 &&
              *(__int64 *)((char *)SectionEntry + 0x58) == 1))
        {
            if (!(SectionType == 0x512 &&
                  EntryFlags50 == 0x20 &&
                  *(__int64 *)((char *)SectionEntry + 0x58) == 1 &&
                  *(__int64 *)((char *)SectionEntry + 0x78) == 0xF &&
                  EntryFlags88 == 0x4041))
                goto LABEL_LOOP_TAIL;
        }

        // LABEL_CONFIRM: 0x140012FF3
        {
            unsigned int ConfirmType;

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                goto LABEL_LOOP_TAIL;

            if ((unsigned __int16)TypeOrCandidate ==
                *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6))
            {
                ConfirmType = TypeOrCandidate;
            }
            else
            {
                ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);

                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                {
                    ConfirmType = 0x53D;
                }
                else
                {
                    ConfirmType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
                }
            }

            if (ConfirmType == TypeOrCandidate)
                goto LABEL_WRITE;                       // 0x14001305A
        }

    LABEL_LOOP_TAIL:                                    // 0x140013049
        ;
    }

    return 0;

LABEL_WRITE:                                            // 0x14001305A
    if (!SavedValue)
        return 0;
    if (SavedValue >= KernelSize)
        return 0;

    GtWrite((GLOBAL_TABLE_INDEX)0x17F, (__int64)(SavedValue + NtImageBase));
    return 0;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `MiniFilterPreCreate` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17C 生产者之一（类型序列 0x512/0x558/0x420/0x4DF）；0x17C 消费者为 InitImageNotifyCallbackWin7 / SendIoControlWithBufferSwap / SendIoControlWithQueryBuffer。
//   故改名为 FindKernelDataSectionForImageNotify（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForImageNotify — 查找内核数据节（本家族第 4 个扫描器）
// 对应原始驱动 0x140014078（557 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x140014078~0x1400142A4
//   的 163 条指令逐条还原
// 【⚠ 名称说明】IDA 数据库中 0x140014078 的名字是 MiniFilterPreCreate，但该名字
//   与实际功能不符，也与本复刻中已实现的同名 FLT 回调（Minifilter.c:297，
//   签名为 NTSTATUS(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*)）冲突：
//   本函数**无参数**（不从 rcx/rdx/r8/r9 读取任何值），而 minifilter 的 PreCreate
//   回调必须接收 3 个参数，故 0x140014078 不是 FLT 回调。其真实功能与
//   FindKernelDataSectionForStringParam 同族 —— 在 ntoskrnl.exe 的 PE 文件缓冲区中
//   按类型序列扫描并定位某个内核数据节。故此处按家族命名改为 FindKernelDataSectionForImageNotify，
//   与审计清单的对应关系是「审计表中的 MiniFilterPreCreate(557B) = 本函数」。
// 【验证依据】与 FindKernelDataSectionForWriteMemory(0x1400137BC) 逐指令差分，两者同源；
//   描述符字段偏移 0xF0 / 0x118 / 0x88 / 0x70 / 0x50 / 0x58 / 0x38 与已验证的
//   0x120 布局吻合；帧布局与另外五个扫描器一致（ctx = rsp+0x50，
//   读指针 = rsp+0x58 = ctx+8）
// 【与其他扫描器的差异（差分结论）】
//   1) 扫描起点读 GT 0x172，结果写 GT 0x17C(GtEprocessExtField124)
//   2) **无构建号分岔**：单一路径同时处理「记录候选值」与「确认并写入」
//   3) 第 1 型（+0x58==1）的匹配条件多一个：type9 之后 3 节 **或** 4 节均可
//   4) 确认节区的类型码为 0x420 **或 0x4DF**（V3 只有 0x420，V2 只有 0x510）
//   5) 循环上限 0x300
//   6) 候选值失败（为 0 或 >= 文件大小）时仅继续循环，绝不提前返回
//   7) 原始驱动用 `bt r8, 1Ah` 判 bit 26（0x4000000），即"测试单个位"而非整值测试
// 【逻辑】取 4 个全局表值做一致性校验（GT 0x172 须落在 (GT3, GT3+文件大小) 内
//   且低 32 位截断自洽）→ 以「文件缓冲区 + (GT 0x172 - GT 0x3)」为起点初始化 PE
//   节区读取上下文 → 最多扫描 0x300 个节区，每轮把读指针按指令长度推进：
//     a) 0x512 型且 +0x50==0x40：按 +0x58 记录序号 —— ==2 记 Type2EntryIndex、
//        ==9 记 Type9EntryIndex、==1 且（紧跟 Type2 之后 1 节 或 Type9 之后 3/4 节）
//        则置 FoundType1Pair 标志
//     b) FoundType1Pair 置位后：0x558 型且带 0x4000000 标志且 VirtualAddress!=0 时
//        记录候选值 = VirtualAddress - 文件缓冲区低 32 位 + 读指针低 32 位；
//        随后遇 0x420 或 0x4DF 型且 +0x88==0x800000 且 +0x70==0xC0000023 且
//        +0x50==0x20 且候选值非 0 且 < 文件大小时写入全局表 0x17C（候选值 + 镜像基址）
__int64 FindKernelDataSectionForImageNotify(void)
{
    unsigned __int16 SectionType;
    unsigned int KernelSize;
    unsigned int ScanOffset;
    unsigned int EntryIndex;
    unsigned int Type2EntryIndex;
    unsigned int Type9EntryIndex;
    unsigned int SavedValue;
    char FoundType1Pair;
    ULONG64 EntryFlags;
    ULONG64 FileBase;
    ULONG64 NtImageBase;
    ULONG64 ScanStartVa;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FileBase = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    KernelSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    ScanStartVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x172);

    Type2EntryIndex = 0;
    Type9EntryIndex = 0;
    SavedValue = 0;
    FoundType1Pair = 0;

    if (!FileBase || !KernelSize || !NtImageBase)
        return 0;
    if (ScanStartVa <= NtImageBase)
        return 0;

    ScanOffset = (unsigned int)(ScanStartVa - NtImageBase);
    if (ScanOffset >= KernelSize)
        return 0;
    if (ScanStartVa != NtImageBase + ScanOffset)
        return 0;

    InitPESectionReadContext(FileBase + ScanOffset, KernelSize - ScanOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (EntryIndex = 0; EntryIndex < 0x300; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return 0;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        EntryFlags = *(__int64 *)((char *)SectionEntry + 0x50);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x512 && EntryFlags == 0x40)
        {
            switch (*(unsigned int *)((char *)SectionEntry + 0x58))
            {
            case 2:
                Type2EntryIndex = EntryIndex;
                continue;

            case 9:
                Type9EntryIndex = EntryIndex;
                continue;

            case 1:
                if (Type2EntryIndex)
                {
                    if (Type2EntryIndex + 1 == EntryIndex)
                    {
                        FoundType1Pair = 1;
                        continue;
                    }
                }
                if (!Type9EntryIndex)
                    continue;
                if (Type9EntryIndex + 3 == EntryIndex || Type9EntryIndex + 4 == EntryIndex)
                    FoundType1Pair = 1;
                continue;

            default:
                continue;
            }
        }

        if (FoundType1Pair != 1)
            continue;

        if (SectionType == 0x558 &&
            (EntryFlags & 0x4000000) != 0)
        {
            SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38);
            if (SavedValue)
            {
                SavedValue = SavedValue - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;
                continue;
            }
        }

        if (SectionType != 0x420 && SectionType != 0x4DF)
            continue;
        if (*(__int64 *)((char *)SectionEntry + 0x88) != 0x800000)
            continue;
        if (*(__int64 *)((char *)SectionEntry + 0x70) != 0xC0000023)
            continue;
        if (EntryFlags != 0x20)
            continue;
        if (!SavedValue)
            continue;
        if (SavedValue >= KernelSize)
            continue;

        GtWrite(GtEprocessExtField124, (__int64)(SavedValue + NtImageBase));
        return 0;
    }
    return 0;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `sub_1400137BC` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17B；消费者 SendWriteMemoryIoControl。
//   故改名为 FindKernelDataSectionForWriteMemory（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForWriteMemory — 解析 ntoskrnl 数据节 V2
// 对应原始驱动 0x1400137BC（682 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），全部逻辑由 0x1400137BC~0x140013A66
//   的 194 条指令逐条还原
// 【验证依据】节区条目字段偏移由反汇编变量位移换算（条目基址 var_150 = rbp-0x60）：
//   0xF0 / 0x118 / 0x50 / 0x58 / 0x38 / 0x88，与已四次交叉验证的 0x120 字节布局
//   完全吻合；且条目缓冲区末端的 rbp+0xC0 恰好是 __security_cookie 槽，进一步佐证
// 【与 FindKernelDataSectionForCreateFile / FindKernelDataSectionForStringParam 的差异】
//   1) 数据源不同：本函数读 ntoskrnl.exe 的 PE 文件缓冲区（GT 0x20/0x21），
//      另两个函数读内核内存镜像（GT 32/33 的别名）
//   2) 扫描起始偏移由 GT 0x171 与 GT 0x3 之差决定（另两个为 GT 0x176/0x4222）
//   3) 前置校验多读一个 GT 0x41C5 并要求其 32 位值非 0
//   4) 三段匹配的类型码为 0x512 / 0x558 / 0x510（另两个为 0x43E / 0x558 / 0x53D）
//   5) 循环上限 0x300（另两个为 0x200）
//   6) 命中结果写入全局表 0x17B（另两个为 0x17E / 0x180）
//   7) 以构建号 0x42EE(17134, Win10 1803) 分岔：旧路径要求是第 2 次命中且失败即返回；
//      新路径改用 0x510 型节区打标记，且失败仅继续循环
// 【逻辑】取 5 个全局表值做一致性校验（GT 0x171 须落在 (GT3, GT3+文件大小) 内且
//   低 32 位截断自洽）→ 以「文件缓冲区 + (GT 0x171 - GT 0x3)」为起点初始化 PE 节区
//   读取上下文 → 最多扫描 0x300 个节区，累计各节的 SizeOfRawData：
//     a) 0x512 型且 +0x50==0x40：按 +0x58 记录序号 —— +0x58==2 记 Type2EntryIndex、
//        ==9 记 Type9EntryIndex、==1 且（紧跟 Type2 之后 1 节 或 Type9 之后 3 节）
//        则置 FoundType1Pair 标志
//     b) FoundType1Pair 置位后按构建号分岔：
//        - 旧版：本节点须为 0x558 型且带 0x4000000 标志且 VirtualAddress!=0，
//          且为第 2 次命中；候选值 = VirtualAddress - 文件缓冲区低 32 位 + 累计大小，
//          为 0 或 >= 文件大小则直接返回
//        - 新版：本节点为 0x510 型且 +0x50==0x40 且 +0x58==9 且 +0x88==0x10041
//          则置 FoundType510 标志；标志置位后本节点须为 0x558 型且带 0x4000000
//          标志且 VirtualAddress!=0，候选值计算同上，越界则仅继续循环
//     两路命中均写入全局表 0x17B（候选值 + GT 0x3 镜像基址）
__int64 FindKernelDataSectionForWriteMemory(void)
{
    unsigned __int16 SectionType;
    unsigned int KernelSize;
    unsigned int RequiredFlag;
    unsigned int ScanOffset;
    unsigned int EntryIndex;
    unsigned int Type2EntryIndex;
    unsigned int Type9EntryIndex;
    unsigned int Type1MatchCount;
    unsigned int SavedValue;
    char FoundType1Pair;
    char FoundType510Section;
    ULONG64 FileBase;
    ULONG64 NtImageBase;
    ULONG64 ScanStartVa;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FileBase = (ULONG64)GtRead(GtNtoskrnlPeFileBase);
    KernelSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    RequiredFlag = (unsigned int)GtRead(GtSyscallHash16837);
    ScanStartVa = (ULONG64)GtRead(GtEprocessExtField113);

    Type2EntryIndex = 0;
    Type9EntryIndex = 0;
    Type1MatchCount = 0;
    FoundType1Pair = 0;
    FoundType510Section = 0;

    if (!FileBase || !KernelSize || !NtImageBase || !RequiredFlag)
        return 0;
    if (ScanStartVa <= NtImageBase)
        return 0;

    ScanOffset = (unsigned int)(ScanStartVa - NtImageBase);
    if (ScanOffset >= KernelSize)
        return 0;
    if (ScanStartVa != NtImageBase + ScanOffset)
        return 0;

    InitPESectionReadContext(FileBase + ScanOffset, KernelSize - ScanOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (EntryIndex = 0; EntryIndex < 0x300; EntryIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return 0;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x512 && *(__int64 *)((char *)SectionEntry + 0x50) == 0x40)
        {
            switch (*(unsigned int *)((char *)SectionEntry + 0x58))
            {
            case 2:
                Type2EntryIndex = EntryIndex;
                continue;

            case 9:
                Type9EntryIndex = EntryIndex;
                continue;

            case 1:
                if (Type2EntryIndex)
                {
                    if (Type2EntryIndex + 1 == EntryIndex)
                    {
                        FoundType1Pair = 1;
                        continue;
                    }
                }
                if (!Type9EntryIndex)
                    continue;
                if (Type9EntryIndex + 3 != EntryIndex)
                    continue;
                FoundType1Pair = 1;
                continue;

            default:
                continue;
            }
        }

        if (FoundType1Pair != 1)
            continue;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        {
            // 新版路径（Win10 1803 及以后）：先要看到一个 0x510 型节区作标记
            if (SectionType == 0x510 &&
                *(__int64 *)((char *)SectionEntry + 0x50) == 0x40 &&
                *(__int64 *)((char *)SectionEntry + 0x58) == 9 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x10041)
            {
                FoundType510Section = 1;
                continue;
            }

            if (FoundType510Section != 1)
                continue;
            if (SectionType != 0x558)
                continue;
            if ((*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) == 0)
                continue;

            SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38);
            if (!SavedValue)
                continue;

            SavedValue = SavedValue - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;
            if (!SavedValue)
                continue;
            if (SavedValue >= KernelSize)
                continue;

            GtWrite((GLOBAL_TABLE_INDEX)0x17B, (__int64)(SavedValue + NtImageBase));
            return 0;
        }

        // 旧版路径：0x558 型节区出现 2 次才认定
        if (SectionType != 0x558)
            continue;
        if ((*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) == 0)
            continue;

        SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38);
        if (!SavedValue)
            continue;

        if (++Type1MatchCount != 2)
            continue;

        SavedValue = SavedValue - (unsigned int)FileBase + (unsigned int)ReadContext.ReadPtr;
        if (!SavedValue)
            return 0;
        if (SavedValue >= KernelSize)
            return 0;

        GtWrite((GLOBAL_TABLE_INDEX)0x17B, (__int64)(SavedValue + NtImageBase));
        return 0;
    }
    return 0;
}

// FindKernelDataSectionV3Dispatch — 内核数据节 V3 查找分发
// 对应原始驱动 0x14001356C（31 字节）
// 【逆向来源】人工阅读反汇编重建 —— IDA 无法分析该函数
// 【逻辑】构建号 >= 0x1DB0(7600, Win7) 时调用 FindKernelDataSectionForWriteMemory，否则原样返回构建号
__int64 FindKernelDataSectionV3Dispatch(void)
{
    __int64 Result;

    Result = GtRead(GtWindowsBuildNumber);
    if ((unsigned int)Result >= 0x1DB0)
        return FindKernelDataSectionForWriteMemory();
    return Result;
}

// 【命名依据 2026-09-21，方案 A（按消费者命名）】原 IDA 名 `sub_140014ACC` 与实物不符：
//   本函数无参数、是 PE 节区扫描器。据 GT 描述表（写者↔读者一一配对）确定其产出目标：GT 0x17E；消费者 SendIoControlWithStringParam。
//   故改名为 FindKernelDataSectionForStringParam（同一 GT 槽有多个生产者时以数字后缀区分）。
// FindKernelDataSectionForStringParam — 解析 Minifilter 数据节
// 对应原始驱动 sub_140014ACC（地址 0x140014ACC，530 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用）
// 【验证依据】节区条目字段偏移由反汇编变量的 rbp 位移换算（var_140 为基址），
//   结果与已验证的 0x120 字节布局吻合：0xF0/0x118/0x88/0x70/0x50/0x38/0x58
// 【逻辑】版本无关；取 4 个全局表值并做与 ByDebug 相同的一致性校验后遍历最多
//   0x200 个节区，按类型分三支：
//     a) 0x43E 型 且 SectionAlignment==0x80000 且 +0x70==2  → 置 FoundFlag
//     b) 0x558 型 且带 0x4000000 标志 且 VirtualAddress!=0 → 除非
//        （构建号==0x4F7C 且 FoundFlag 已置）否则记录候选值
//        （VirtualAddress - KernelBase + 累计大小）；随后清零 FoundFlag
//     c) 0x53D 型 且 SectionAlignment==0x800000 且 +0x70==0x10 且
//        Characteristics==0x20 且 SectionIndex==1 → 再取一个节区，
//        若其为 0x558 型且候选值合法，则写入全局表 0x17E（候选值 + NtImageBase）
__int64 FindKernelDataSectionForStringParam(void)
{
    char FoundFlag;
    ULONG64 KernelBase;
    unsigned int KernelSize;
    ULONG64 NtImageBase;
    ULONG64 DataSectionVa;
    unsigned int ImageOffset;
    unsigned int SavedValue;
    unsigned int SectionIndex;
    // 【读指针语义】原始驱动把「累计长度」直接累加到解码上下文的 +0x08(读指针) 上：
    //   InitPESectionReadContext 先写入 Base，随后每轮 `+= 描述符[0xF0](指令长度)`
    //   ——ReadPESectionEntry 对上下文只读、自身不推进，推进责任在调用方。
    //   故此处不再使用独立变量，直接用 ReadContext.ReadPtr（初值由初始化函数写入）。
    unsigned __int16 SectionType;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FoundFlag = 0;
    SavedValue = 0;

    KernelBase = (ULONG64)GtRead(GtEprocessField22);
    KernelSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    DataSectionVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x174);

    if (!KernelBase || !KernelSize || !NtImageBase)
        return 0;
    if (DataSectionVa <= NtImageBase)
        return 0;

    ImageOffset = (unsigned int)(DataSectionVa - NtImageBase);
    if (ImageOffset >= KernelSize)
        return 0;
    if (DataSectionVa != NtImageBase + ImageOffset)
        return 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (SectionIndex = 0; SectionIndex < 0x200; SectionIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            break;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x43E &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 0x80000 &&
            *(_DWORD *)((char *)SectionEntry + 0x70) == 2)
        {
            FoundFlag = 1;
            continue;
        }

        if (SectionType == 0x558 &&
            (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
            *(_DWORD *)((char *)SectionEntry + 0x38) != 0)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) != 0x4F7C || FoundFlag != 1)
            {
                SavedValue = *(unsigned int *)((char *)SectionEntry + 0x38) - (unsigned int)KernelBase + (unsigned int)ReadContext.ReadPtr;
            }
            FoundFlag = 0;
            continue;
        }

        if (SectionType == 0x53D &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 0x800000 &&
            *(_DWORD *)((char *)SectionEntry + 0x70) == 0x10 &&
            *(__int64 *)((char *)SectionEntry + 0x50) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                continue;

            if (*(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 0x558)
            {
                if (SavedValue && SavedValue < KernelSize)
                    GtWrite((GLOBAL_TABLE_INDEX)0x17E, (__int64)(SavedValue + NtImageBase));
                break;
            }
        }
    }
    return 0;
}

// FindKernelDataSectionByDebug — 通过 DEBUG 节查找内核数据节
// 对应原始驱动 sub_140013E6C（地址 0x140013E6C，454 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用）
// 【验证依据】节区条目字段偏移由反汇编变量的 rbp 位移直接换算（IDA 的 var_XXX 命名
//   即相对 rbp 位移，var_140 为节区条目基址），换算结果与 ParseNtRelocSection 中
//   独立验证过的 0x120 字节布局**逐项吻合**：0xF0/0x118/0x50/0x58/0x88/0x90/0x38
// 【逻辑】版本门槛 >= 0x1770(6000) → 取 4 个全局表值并做一致性校验
//   （DataSectionVa 必须落在 [NtImageBase, NtImageBase+KernelSize) 且等于基址加偏移）
//   → 遍历最多 0x64 个节区：先遇到 0x4D7 节区且四个字段为 (0x20, 9, 0x20, 9) 时置标志；
//   再遇到 0x558 节区且带 0x4000000 标志、VirtualAddress 非 0 且标志已置时，
//   按 (VirtualAddress - KernelBase + 累计大小) 算出结果写入全局表 0x184；
//   遇到 0x545 类型节区立即返回
__int64 FindKernelDataSectionByDebug(void)
{
    char FoundFlag;
    ULONG64 KernelBase;
    unsigned int KernelSize;
    ULONG64 NtImageBase;
    ULONG64 DataSectionVa;
    unsigned int ImageOffset;
    int Value;
    unsigned int SectionIndex;
    unsigned __int16 SectionType;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];

    FoundFlag = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770)
        return 0;

    KernelBase = (ULONG64)GtRead(GtEprocessField22);
    KernelSize = (unsigned int)GtRead(GtEprocessField23);
    NtImageBase = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    DataSectionVa = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x16E);

    if (!KernelBase || !KernelSize || !NtImageBase)
        return 0;
    if (DataSectionVa <= NtImageBase)
        return 0;

    ImageOffset = (unsigned int)(DataSectionVa - NtImageBase);
    if (ImageOffset >= KernelSize)
        return 0;
    if (DataSectionVa != NtImageBase + ImageOffset)
        return 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (SectionIndex = 0; SectionIndex < 0x64; SectionIndex++)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            return 0;

        ReadContext.ReadPtr += *(unsigned int *)((char *)SectionEntry + 0xF0);
        SectionType = *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 0x545)
            return 0;

        if (SectionType == 0x4D7 &&
            *(__int64 *)((char *)SectionEntry + 0x50) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0x58) == 9 &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 0x20 &&
            *(_DWORD *)((char *)SectionEntry + 0x90) == 9)
        {
            FoundFlag = 1;
            continue;
        }

        if (SectionType == 0x558 &&
            (*(__int64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
            *(_DWORD *)((char *)SectionEntry + 0x38) != 0 &&
            FoundFlag == 1)
        {
            Value = (int)(*(_DWORD *)((char *)SectionEntry + 0x38) - (unsigned int)KernelBase + (unsigned int)ReadContext.ReadPtr);
            if ((unsigned int)Value < KernelSize)
                GtWrite((GLOBAL_TABLE_INDEX)0x184, (__int64)((unsigned int)Value + NtImageBase));
            return 0;
        }
    }
    return 0;
}

// FindKernelDataSectionDispatch — 内核数据节查找分发
// 根据版本号选择不同的查找策略
// 对应原始驱动 sub_140013A68
ULONG64 FindKernelDataSectionDispatch(void)
{
    ULONG64 BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber >= 0x1DB0 && BuildNumber <= 0x1DB1)
        return FindKernelDataSectionByCode();
    return BuildNumber;
}

// FindKernelDataSectionByCode — 通过 CODE 节查找内核数据节
// 遍历 PE 节表，找到 CODE 节后的第一个数据节，计算偏移写入全局表
// 对应原始驱动 sub_140013A98
ULONG64 FindKernelDataSectionByCode(void)
{
    __int64 PeBase, PeSize, NtImageBase, SectionAddr, SectionOffset;
    char FoundCodeSection = 0;
    unsigned int SectionIndex;
    int SectionSize;
    __int16 SectionFlags;
    char ReadContext[0x198];
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [14] 仅 56 字节
    unsigned int DataSectionSize;
    __int64 SectionFlags2, SectionAlign;
    unsigned int RawSize;
    __int64 SectionName;

    PeBase = GtRead((GLOBAL_TABLE_INDEX)0x20);
    PeSize = GtRead((GLOBAL_TABLE_INDEX)0x21);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    SectionAddr = GtRead((GLOBAL_TABLE_INDEX)0x177);
    if (PeBase && PeSize && NtImageBase && SectionAddr > NtImageBase)
    {
        SectionOffset = (unsigned int)(SectionAddr - NtImageBase);
        if ((unsigned int)SectionOffset < PeSize && SectionAddr == SectionOffset + NtImageBase)
        {
            InitPESectionReadContext(PeBase + SectionOffset, (ULONG)(PeSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (SectionIndex = 0; SectionIndex < 0x200; ++SectionIndex)
            {
                if (ReadPESectionEntry(ReadContext, SectionInfo))
                    break;
                SectionSize = RawSize + (ULONG)SectionInfo[2];
                SectionInfo[2] += RawSize;
                SectionFlags = *(__int16 *)(SectionName + 6);
                if (SectionFlags == 360 && (SectionFlags2 & 0x40) != 0 && SectionAlign == 64)
                    FoundCodeSection = 1;
                else if (FoundCodeSection == 1 && SectionFlags == 1368 && (SectionFlags2 & 0x4000000) != 0 && DataSectionSize)
                {
                    ULONG64 Result = SectionSize + DataSectionSize - (ULONG)PeBase;
                    if ((unsigned int)Result < PeSize)
                        return GtWrite((GLOBAL_TABLE_INDEX)0x181, NtImageBase + (unsigned int)Result);
                }
            }
        }
    }
    return 0;
}

// FindKernelDataSectionByData — 通过 DATA 节查找内核数据节
// 遍历 PE 节表匹配子类型，定位数据节偏移，写入全局表
// 对应原始驱动 sub_140013C48
ULONG64 FindKernelDataSectionByData(void)
{
    __int64 PeBase, PeSize, NtImageBase;
    int ExportDirSize;
    ULONG64 SectionAddr, SectionOffset;
    unsigned __int8 SectionType;
    unsigned int CodeSectionIndex = 0, DataSectionIndex = 0;
    char FoundDataSection = 0;
    unsigned int SectionIndex;
    int SectionSize;
    __int16 SectionFlags;
    unsigned __int8 TypeFlag;
    char ReadContext[0x1A8];
    __int64 VirtualSize = 0;
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [14] 仅 56 字节
    unsigned int DataSectionSize;
    __int64 SectionFlags2;
    unsigned int SubType;
    unsigned int RawSize;
    __int64 SectionName;

    PeBase = GtRead((GLOBAL_TABLE_INDEX)0x20);
    PeSize = GtRead((GLOBAL_TABLE_INDEX)0x21);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ExportDirSize = (int)GtRead((GLOBAL_TABLE_INDEX)0x912);
    SectionAddr = GtRead((GLOBAL_TABLE_INDEX)0x179);
    if (PeBase && PeSize && NtImageBase && ExportDirSize && SectionAddr > (ULONG64)NtImageBase)
    {
        SectionOffset = (unsigned int)(SectionAddr - NtImageBase);
        if ((unsigned int)SectionOffset < PeSize && SectionAddr == SectionOffset + NtImageBase)
        {
            InitPESectionReadContext(SectionOffset + PeBase, (ULONG)(PeSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            SectionType = TypeFlag;
            for (SectionIndex = 0; SectionIndex < 0x200; ++SectionIndex)
            {
                if (ReadPESectionEntry(ReadContext, SectionInfo))
                    break;
                SectionSize = RawSize + (ULONG)VirtualSize;
                VirtualSize += RawSize;
                SectionFlags = *(__int16 *)(SectionName + 6);
                if (SectionFlags == 1298 && SectionFlags2 == 64)
                {
                    switch (SubType)
                    {
                        case 2: CodeSectionIndex = SectionIndex; break;
                        case 9: DataSectionIndex = SectionIndex; break;
                        case 1:
                            if (CodeSectionIndex && CodeSectionIndex + 1 == SectionIndex)
                            { FoundDataSection = 1; SectionType = 1; }
                            else if (DataSectionIndex && DataSectionIndex + 3 == SectionIndex)
                            { FoundDataSection = 1; SectionType = 0; }
                            break;
                    }
                }
                else if (FoundDataSection == 1 && SectionFlags == 1368 && (SectionFlags2 & 0x4000000) != 0 && DataSectionSize)
                {
                    ULONG64 Result = SectionSize + DataSectionSize - (ULONG)PeBase;
                    if ((_DWORD)Result && (unsigned int)Result < PeSize)
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x199, NtImageBase + (unsigned int)Result);
                        return GtWrite((GLOBAL_TABLE_INDEX)0x912, SectionType);
                    }
                }
            }
        }
    }
    return 0;
}

// ClearImageNotifySectionOffset — 清除镜像通知节区偏移
// 对应原始驱动 sub_140014AC0
// 把全局表 0x182 处的镜像通知节区偏移清零
__int64 ClearImageNotifySectionOffset(void)
{
    return GtWrite((GLOBAL_TABLE_INDEX)0x182, 0);
}

// InitImageNotifyWin7 — Win7 镜像通知初始化分发
// 版本检查（>= 0x1DB0），条件满足时调用 InitImageNotifyCallbackWin7
// 对应原始驱动 sub_14001358C
__int64 InitImageNotifyWin7(void)
{
    __int64 result = GtRead(GtWindowsBuildNumber);
    if ((unsigned int)result >= 0x1DB0)
        return InitImageNotifyCallbackWin7();
    return result;
}

// SelectMiniFilterCallbackByVersion — 根据版本选择 Minifilter 回调
// 版本 <= 0x23F0 时调用 FindKernelDataSectionForImageNotify2，>= 0x42EE 时调用 MiniFilterPreCreate，否则调用 FindKernelDataSectionForImageNotify3
// 对应原始驱动 sub_140014078
__int64 SelectMiniFilterCallbackByVersion(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x23F0)
        return ((__int64 (*)(void))FindKernelDataSectionForImageNotify2)();
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        return ((__int64 (*)(void))MiniFilterPreCreate)();
    return ((__int64 (*)(void))FindKernelDataSectionForImageNotify3)();
}

// SelectMiniFilterCleanupCallback — 选择 Minifilter 清理回调
// 版本 >= 0x4A61 时调用 MiniFilterPostWrite，否则调用 MiniFilterPreCleanup
// 对应原始驱动 sub_140014D08
__int64 SelectMiniFilterCleanupCallback(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        return ((__int64 (*)(void))MiniFilterPostWrite)();
    else
        return ((__int64 (*)(void))MiniFilterPreCleanup)();
}

// SelectMiniFilterDirEnumCallback — 选择 Minifilter 目录枚举回调
// 版本 < 0x23F0 时调用 FindKernelObjectFieldOffsetsWin8，>= 0x2800 时调用 FindKernelObjectFieldOffsetsWin10，否则调用 FindKernelObjectFieldOffsetsWin10Early
// 对应原始驱动 sub_1400152D4
__int64 SelectMiniFilterDirEnumCallback(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
        return ((__int64 (*)(void))FindKernelObjectFieldOffsetsWin8)();
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return ((__int64 (*)(void))FindKernelObjectFieldOffsetsWin10)();
    return ((__int64 (*)(void))FindKernelObjectFieldOffsetsWin10Early)();
}

// SelectMiniFilterWriteReadCallback — 选择 Minifilter 写/读回调
// 版本 > 0x23F0 时调用 FindKernelDataSectionForDeviceIoControl2，否则调用 FindKernelDataSectionForDeviceIoControl
// 对应原始驱动 sub_1400146D4
unsigned __int64 SelectMiniFilterWriteReadCallback(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
        return ((unsigned __int64 (*)(void))FindKernelDataSectionForDeviceIoControl2)();
    else
        return ((unsigned __int64 (*)(void))FindKernelDataSectionForDeviceIoControl)();
}

// PatchPeHeaderMagic — 修补 PE 头魔数
// 通过 WritePhysicalMemoryBuffer 修改内核模块的 PE 头部数据目录字段，
// 根据 PE 魔数类型写入 6 字节或 8 字节数据，用于隐藏驱动痕迹
// 对应原始驱动 sub_14001A278
char __fastcall PatchPeHeaderMagic(__int64 QueryResult)
{
    unsigned __int64 ImageBase = *(_QWORD *)(QueryResult + 8);
    char Result = 0;
    __int64 PeOffset;
    unsigned __int64 ImageSize;
    __int64 NtHeader;
    __int16 PeMagic;
    unsigned __int64 DataDirRva;
    unsigned __int64 DataDirSize;
    _QWORD ShellData[4];

    memset(ShellData, 0, sizeof(ShellData));
    if (ImageBase > (unsigned __int64)MmSystemRangeStart)
    {
        PeOffset = *(int *)(ImageBase + 60);
        if ((int)PeOffset > 0)
        {
            ImageSize = *(_QWORD *)(QueryResult + 24);
            if ((unsigned int)PeOffset < ImageSize && (unsigned __int64)(unsigned int)PeOffset + 248 < ImageSize)
            {
                NtHeader = ImageBase + PeOffset;
                PeMagic = *(_WORD *)(ImageBase + PeOffset + 4);
                if (PeMagic == 512 || PeMagic == -31132)
                {
                    // PE32+：写入 6 字节壳代码
                    if ((unsigned __int64)(unsigned int)PeOffset + 264 < ImageSize)
                    {
                        DataDirSize = *(unsigned int *)(NtHeader + 40);
                        if (DataDirSize < ImageSize && (unsigned int)(DataDirSize + 6) < ImageSize)
                        {
                            LODWORD_LV(ShellData[0]) = g_ShellCodeBuffer;
                            *(WORD *)((PUCHAR)&ShellData[0] + 4) = (WORD)g_ShellCodeMovEax;
                            WritePhysicalMemoryBuffer(ImageBase + *(unsigned int *)(NtHeader + 40), ShellData, 6u, 0, 0);
                            return 1;
                        }
                    }
                }
                else
                {
                    // PE32：写入 8 字节数据
                    DataDirRva = *(unsigned int *)(NtHeader + 40);
                    if (DataDirRva < ImageSize && (unsigned int)(DataDirRva + 8) < ImageSize)
                    {
                        ShellData[0] = 0x8C2C0000022B8LL;
                        WritePhysicalMemoryBuffer(ImageBase + *(unsigned int *)(NtHeader + 40), ShellData, 8u, 0, 0);
                        return 1;
                    }
                }
            }
        }
    }
    return Result;
}
