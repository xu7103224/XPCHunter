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

    // 【GT 索引修正 2026-10-13】以下四个索引原先全部写错
    //   （我方 0x81A/0x980/0x981/0x819，原始 0x89F/0x8A0/0x8A1/0x89E）。
    //   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
    //   原始读 0x89F 而我方读 0x81A；逐条反汇编核对确认原始读序为
    //   0x89F(懒初始化) / 0x8A0 / 0x8A1 / 0x89E。
    //   原始汇编：`mov r14d,0x89f` → GtRead → test → 为空则 call 0x140011B80
    //   → 再 GtRead(0x89F) 存入 r13；随后 0x8A0→r15、0x8A1→r12、0x89E→r14。
    if (!GtRead((GLOBAL_TABLE_INDEX)0x89F))                   // 0x140011FA3
        ParseMiniFilterRegSections();                          // 0x140011FAD

    ListHead1 = (_QWORD **)GtRead((GLOBAL_TABLE_INDEX)0x89F);  // 0x140011FB5（r13）
    ListHead2 = (_QWORD **)GtRead((GLOBAL_TABLE_INDEX)0x8A0);  // 0x140011FC2（r15）
    ListHead3 = (_QWORD **)GtRead((GLOBAL_TABLE_INDEX)0x8A1);  // 0x140011FCF（r12）
    ListHead4 = GtRead((GLOBAL_TABLE_INDEX)0x89E);             // 0x140011FDC（r14）
    ListHead4Ptr = (_QWORD **)ListHead4;

    if ((!ListHead1 && !ListHead2 && !ListHead3 && !ListHead4) ||  // 0x140011FE4~1FF6
        !OutputBuffer || (ULONG)BufferSizeCopy < 0x130 ||          // 0x140011FFC/2005
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


// =========================================================================
// RemoveMiniFilterContextNode — 从上下文链表中摘除匹配节点
// 对应原始驱动 0x140012A80（247 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（45 行伪代码），按伪代码实现。
// 【参数】ContextNode = 含 { 链表基址偏移, 目标值 } 的 16 字节结构
// 【逻辑】取 GT 0x41DB（校验函数/标志，须非 0）与 GT 0x360（上下文链表偏移）；
//   链表头 = (void**)(偏移 + ContextNode[0])，须内存有效；
//   从 *链表头 起遍历（上限 0x10000，且要求节点 > MmSystemRangeStart 且
//   节点与 +63 处均内存有效）：
//     若 节点[5] 或 节点[6] == ContextNode[1] → 命中：
//       取 Prev=*节点、Next=节点[1]，摘链（Prev[1]=Next、*Next=Prev），返回 1；
//     否则节点 = *节点 继续；
//   未命中返回 0。
// =========================================================================
// 对应原始驱动 0x140012A80（247 字节）
char __fastcall RemoveMiniFilterContextNode(_QWORD *ContextNode)
{
    char Result = 0;
    __int64 ValidateFlag;
    unsigned int ContextOffset;
    __int64 ContextOffsetVal;
    void **ListHead;
    _QWORD *CurrentNode;
    int NodeIndex = 0;
    __int64 TargetValue;
    _QWORD *PrevNode;
    _QWORD *NextNode;

    // 【⚠ 回退 2026-10-13】此处曾被一次针对 InitMiniFilterDriver 的批量替换误改
    //   （该批次的文本模式与本函数相同，导致误命中）。本函数原始索引就是
    //   0x41DB 与 0x360，见原始 0x140012A80 反汇编：
    //     `mov ecx,0x41db; call GtRead` → 校验标志
    //     `mov ecx,0x360;  call GtRead` → 上下文链表偏移
    ValidateFlag = GtRead((GLOBAL_TABLE_INDEX)0x41DB);          // 校验标志
    ContextOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x360);   // 上下文链表偏移
    if (!ValidateFlag || !ContextOffset)
        return Result;

    ContextOffsetVal = ContextOffset;
    ListHead = (void **)(ContextOffset + *ContextNode);
    if (CheckMemoryValid(ListHead) != 1)
        return Result;

    CurrentNode = *ListHead;
    while (CurrentNode &&
           CurrentNode != (_QWORD *)(ContextOffsetVal + *ContextNode) &&
           CurrentNode > (_QWORD *)MmSystemRangeStart &&
           CheckMemoryValid(CurrentNode) == 1 &&
           CheckMemoryValid((char *)CurrentNode + 63) == 1)
    {
        TargetValue = ContextNode[1];
        if (CurrentNode[5] == TargetValue || CurrentNode[6] == TargetValue)
        {
            if (CheckMemoryValid((void *)*CurrentNode) == 1)
            {
                PrevNode = (_QWORD *)*CurrentNode;
                NextNode = (_QWORD *)CurrentNode[1];
                Result = 1;
                PrevNode[1] = (__int64)NextNode;
                *NextNode = (__int64)PrevNode;
            }
            return Result;
        }
        CurrentNode = (_QWORD *)*CurrentNode;
        if ((unsigned int)++NodeIndex >= 0x10000)
            return Result;
    }
    return Result;
}

// =========================================================================
// MiniFilterInstanceQuery — Minifilter 实例查询回调（补全空壳）
// 对应原始驱动 0x140012B78（175 字节）
// 【⚠ 修正记录 2026-10-08】原名 `CmdRemoveFilterContextNode`、注释称
//   "Minifilter 实例查询回调" —— 名字与实物不符（功能对，名字错）。
//   原始 IDA 名是 MiniFilterInstanceQuery。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（22 行伪代码），按伪代码实现。
// 【参数】InputBuffer = 16 字节输入（含两个内核指针）；BufferSize 须 == 16
// 【逻辑】校验输入缓冲位于用户空间且大小为 16 → ProbeForRead 后读出两个 QWORD；
//   两者都须 > MmSystemRangeStart 且构建号 >= 0x1771；
//   然后转调 RemoveMiniFilterContextNode（传读出的 16 字节）并返回其结果是否为 1。
// 对应原始驱动 0x140012B78（175 字节）
bool __fastcall MiniFilterInstanceQuery(_OWORD *InputBuffer, int BufferSize)
{
    char Result = 0;
    _QWORD ContextPair[2];      // 与 _OWORD 同为 16 字节，但可按 QWORD 访问（_OWORD 不可直接转整数）

    if (!InputBuffer)
        return Result;
    if (BufferSize != 16)
        return Result;
    if ((unsigned __int64)InputBuffer >= MmUserProbeAddress)
        return Result;
    if ((unsigned __int64)(InputBuffer + 1) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(InputBuffer, 0x10u, 1u);
    ContextPair[0] = *(_QWORD *)InputBuffer;
    ContextPair[1] = *((_QWORD *)InputBuffer + 1);
    if (ContextPair[0] > (unsigned __int64)MmSystemRangeStart &&
        ContextPair[1] > (unsigned __int64)MmSystemRangeStart &&
        (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1771)
    {
        return RemoveMiniFilterContextNode(ContextPair) == 1;
    }
    return Result;
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
                    if (*PsProcessTypePtr == SectionHandle || SectionHandle == GtRead((GLOBAL_TABLE_INDEX)0x185))
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
// 【注意】0x140014078 在 IDA 中被命名为 MiniFilterPreCreate，但它**无参数**、
//   实际是 PE 节区扫描器，已作为 FindKernelDataSectionForImageNotify 在下方实现
//   （见「命名说明」）。本函数是真正的 FLT 回调占位，保持桩实现。
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
// 【修正 2026-10-19】旧实现读的 `SectionName`/`SectionFlags2`/`RawSize`/`Characteristics`
//   全是**声明后从不赋值**的局部（初值 0），`*(WORD *)(SectionName + 6)` 被折叠成
//   绝对地址 `[6]` → 实机 DriverEntry 直接 0x50 PAGE_FAULT。
//   逐条对照 0x1400142A8 重写：类型指针取描述符 +0x118（原始 0x1400143B0
//   `mov rax,[rsp+0x1a8]`），类型 = `[rax+6]`；其余字段 +0x50/+0x58/+0x38
//   （原始 0x1400143CB `[rsp+0xe0]`、0x1400143D6 `[rsp+0x120]`、0x14001443A `[rsp+0xc8]`）。
ULONG64 FindKernelDataSectionForImageNotify2(void)
{
    __int64 PeBase = GtRead(GtEprocessField22);
    ULONG PeSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG64 result = GtRead((GLOBAL_TABLE_INDEX)0x172);
    ULONG64 SectionAddr = result;

    if (!PeBase || !PeSize || !NtImageBase || result <= NtImageBase) return result;

    ULONG SectionOffset = (ULONG)(result - NtImageBase);
    if (SectionOffset >= PeSize) return result;
    if (SectionAddr != SectionOffset + NtImageBase) return result;

    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionInfo[112];
    char FoundPostCreate = 0;
    ULONG InitSectionIndex = 0, PageSectionIndex = 0, MatchCount = 0;

    InitPESectionReadContext(PeBase + SectionOffset, PeSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionInfo)) break;

        /* 原始 0x1400143B0..B8：先取 Entry[0xF0] 累加到读指针，再取类型 */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += SectionInfo[0x3C];   /* +0xF0 */

        short SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);

        if (SectionType == 0x512)
        {
            if (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) == 0x40 &&      /* +0x50 == 64 */
                *(ULONG *)((PUCHAR)SectionInfo + 0x90) == 4)             /* +0x90 == 4  */
            {
                ULONG SubType = *(ULONG *)((PUCHAR)SectionInfo + 0x58);  /* +0x58 */
                if (SubType == 2) InitSectionIndex = i;
                else if (SubType == 9) PageSectionIndex = i;
                else if (SubType == 1)
                {
                    if ((InitSectionIndex && InitSectionIndex + 1 == i) ||
                        (PageSectionIndex && PageSectionIndex + 3 == i))
                        FoundPostCreate = 1;
                }
            }
        }
        else if (FoundPostCreate == 1 &&
                 SectionType == 0x558 &&
                 (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x4000000) != 0)
        {
            ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionInfo + 0x38);   /* +0x38 */
            if (DataSectionSize && ++MatchCount == 2)
            {
                result = (ULONG)(DataSectionSize - (ULONG)PeBase
                                 + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                if ((ULONG)result && (ULONG)result < PeSize)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x17C, NtImageBase + (ULONG)result);
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
// 【修正 2026-10-19】同族缺陷：旧实现读的 `SectionName`/`SectionFlags2`/`RawSize`/
//   `FieldValue`/`SectionDataPtr` 均为**从不赋值**的局部 → `[SectionName+6]` 折叠为 `[6]`
//   → 0x50 崩溃。逐条对照 0x1400144A8 重写：
//     类型指针 +0x118（0x1400145DC `[rsp+0x1a8]`），类型 = [rax+6]（0x1400145E9）
//     +0x38（0x1400145F7 `[rsp+0xd0]`）、+0x50（0x140014601 `[rsp+0xe0]`==0x40000）
//     +0x70（0x14001460F `[rsp+0x100]`==0）、末支 +0x50&0x4000000、+0x38（0x140014685 `[rsp+0xc8]`）
//   新偏移 = +0x38（当轮） - PeBase + 读指针，且 < PeSize 时写 GT[0x17C]（0x14001462F `ecx=0x17c`）。
ULONG64 FindKernelDataSectionForImageNotify3(void)
{
    __int64 PeBase = GtRead(GtEprocessField22);
    ULONG PeSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG SectionIdx1 = (ULONG)GtRead(0x439F);
    ULONG SectionIdx2 = (ULONG)GtRead(0x41C5);
    ULONG SectionIdx3 = (ULONG)GtRead(0x4444);
    ULONG64 result = GtRead((GLOBAL_TABLE_INDEX)0x172);
    ULONG64 SectionAddr = result;

    if (!PeBase || !PeSize || !NtImageBase || !SectionIdx1 || !SectionIdx2 ||
        !SectionIdx3 || result <= NtImageBase) return result;
    if ((ULONG)(result - NtImageBase) >= PeSize) return result;
    ULONG SectionOffset = (ULONG)(result - NtImageBase);
    if (SectionAddr != (ULONG64)SectionOffset + NtImageBase) return result;

    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionInfo[112];
    ULONG TargetSection = 0;

    InitPESectionReadContext(PeBase + SectionOffset, PeSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionInfo)) break;

        /* 原始 0x1400145CD..E4：先取 Entry[0xF0] 累加到读指针，再取类型 */
        ULONG RawSize = *(ULONG *)((PUCHAR)SectionInfo + 0xF0);
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += RawSize;

        short SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);

        if (SectionType == 0x430 &&
            *(ULONG *)((PUCHAR)SectionInfo + 0x40) != 0 &&      /* [rsp+0xd0] → +0x40 */
            *(ULONG64 *)((PUCHAR)SectionInfo + 0x50) == 0x40000 &&
            *(ULONG64 *)((PUCHAR)SectionInfo + 0x70) == 0)
        {
            if (TargetSection &&
                SectionIdx1 != TargetSection &&
                SectionIdx2 != TargetSection &&
                SectionIdx3 != TargetSection)
                return GtWrite((GLOBAL_TABLE_INDEX)0x17C, NtImageBase + TargetSection);
        }
        else if (SectionType == 0x558 &&
                 (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x4000000) != 0)
        {
            ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionInfo + 0x38);
            if (DataSectionSize)
            {
                ULONG Candidate = DataSectionSize - (ULONG)PeBase
                                + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08);
                if (Candidate && Candidate < PeSize)
                    TargetSection = Candidate;
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
// 【修正 2026-10-19】同族缺陷：旧实现读的 `SectionDataPtr`/`SectionSize`/`EntryFlags`/
//   `EntryCharacteristics` 均为从不赋值的局部 → `[SectionDataPtr+6]` 折叠为 `[6]` → 0x50。
//   逐条对照 0x1400146D4 重写（与 sub_1400142A8 同构，仅 GT 入口 0x173 / 出口 0x17D）：
//     类型指针 +0x118（0x1400147DC `[rsp+0x1a8]`）、+0x50（0x1400147F7 `[rsp+0xe0]`）
//     +0x90（0x140014802 `[rsp+0x120]`）、+0x58（0x14001480C `[rsp+0xe8]`）
//     末支 +0x50&0x4000000、+0x38（0x140014866 `[rsp+0xc8]`）
ULONG64 FindKernelDataSectionForDeviceIoControl(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    ULONG KernelSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG64 result = GtRead((GLOBAL_TABLE_INDEX)0x173);
    ULONG64 TargetAddress = result;

    if (!KernelBase || !KernelSize || !NtImageBase || result <= NtImageBase) return result;
    ULONG ImageOffset = (ULONG)(result - NtImageBase);
    if (ImageOffset >= KernelSize) return result;
    if (TargetAddress != (ULONG64)ImageOffset + NtImageBase) return result;

    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    ULONG Type2SectionIndex = 0, Type9SectionIndex = 0, MatchCount = 0;
    char FoundFlag = 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;

        /* 原始 0x1400147CD..E4：先取 Entry[0xF0] 累加到读指针，再取类型 */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);

        short SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x512)
        {
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) == 0x40 &&
                *(ULONG *)((PUCHAR)SectionEntry + 0x90) == 4)
            {
                ULONG SubType = *(ULONG *)((PUCHAR)SectionEntry + 0x58);
                if (SubType == 2) Type2SectionIndex = i;
                else if (SubType == 9) Type9SectionIndex = i;
                else if (SubType == 1)
                {
                    if ((Type2SectionIndex && Type2SectionIndex + 1 == i) ||
                        (Type9SectionIndex && Type9SectionIndex + 3 == i))
                        FoundFlag = 1;
                }
            }
        }
        else if (FoundFlag == 1 &&
                 SectionType == 0x558 &&
                 (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0)
        {
            ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionEntry + 0x38);
            if (DataSectionSize && ++MatchCount == 2)
            {
                result = (ULONG)(DataSectionSize - (ULONG)KernelBase
                                 + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                if ((ULONG)result && (ULONG)result < KernelSize)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x17D, NtImageBase + (ULONG)result);
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
// 【修正 2026-10-19】同族缺陷：`SectionSize`/`EntryFlags`/`FieldValue` 均为从不赋值的
//   局部 → 判据恒假/恒真，且 `[SectionEntry+0xF0]` 在**首轮**读的是未初始化内存（推进顺序也错）。
//   逐条对照 0x1400148D4 重写：
//     入口 GT：0x443E / 0x173 / 0x444A（0x14001492A/937/944）
//     类型指针 +0x118（0x140014A01 `[rsp+0x1a8]`）、+0x50 == 0x10041（0x140014A1C）
//     末支 +0x50&0x4000000、+0x38（0x140014A47 `[rsp+0xc8]`）；与既有 Pre/Post 偏移比对
//     结果写 GT[0x17D]（0x140014A81 `ecx=0x17d`）。读指针在**读取之后**推进。
__int64 FindKernelDataSectionForDeviceIoControl2(void)
{
    __int64 KernelBase = GtRead(GtEprocessField22);
    ULONG KernelSize = (ULONG)GtRead(GtEprocessField23);
    ULONG64 NtImageBase = GtRead(GtNtoskrnlModuleBase);
    ULONG ExistingPreWriteOffset = (ULONG)GtRead(0x443E);
    ULONG64 TargetAddress = GtRead((GLOBAL_TABLE_INDEX)0x173);
    __int64 result = GtRead(0x444A);
    ULONG ExistingPostWriteOffset = (ULONG)result;

    if (!KernelBase || !KernelSize || !NtImageBase || !ExistingPreWriteOffset ||
        TargetAddress <= NtImageBase || !result) return result;
    if ((ULONG)(TargetAddress - NtImageBase) >= KernelSize) return result;
    ULONG ImageOffset = (ULONG)(TargetAddress - NtImageBase);
    if (TargetAddress != (ULONG64)ImageOffset + NtImageBase) return result;

    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    char FoundMatchFlag = 0;

    InitPESectionReadContext(KernelBase + ImageOffset, KernelSize - ImageOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x200; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;

        /* 原始 0x1400149F2..A09：先取 Entry[0xF0] 累加到读指针，再取类型 */
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);

        short SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x1E3 &&
            *(ULONG64 *)((PUCHAR)SectionEntry + 0x50) == 0x10041)
        {
            FoundMatchFlag = 1;
        }
        else if (SectionType == 0x558 &&
                 (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0)
        {
            ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionEntry + 0x38);
            if (DataSectionSize)
            {
                result = (ULONG)(DataSectionSize - (ULONG)KernelBase
                                 + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08));
                if ((ULONG)result && (ULONG)result < KernelSize &&
                    FoundMatchFlag == 1 &&
                    (ULONG)result != ExistingPreWriteOffset &&
                    (ULONG)result != ExistingPostWriteOffset)
                    return GtWrite((GLOBAL_TABLE_INDEX)0x17D, NtImageBase + (ULONG)result);
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
    ULONG ExistingPostWriteOffset1 = (ULONG)GtRead(0x439F);
    __int64 result = GtRead(0x41C5);
    ULONG ExistingPostWriteOffset2 = (ULONG)result;

    if (!KernelBase || !KernelSize || !NtImageBase || (int)SectionOffset <= 0 ||
        (ULONG)SectionOffset >= KernelSize || !ExistingPostWriteOffset1 || !(ULONG)result) return result;

    /* 原始 0x140014DBD..DC7：
           movsxd rax,dword [rbp+3Ch]      ; e_lfanew
           mov r13,[rax+rbp+30h]           ; PE32+ OptionalHeader.ImageBase
       即 r13 = 文件头里记录的**首选映像基址**（ntoskrnl 为 0x140000000），
       而不是驱动自身的加载基址。 */
    __int64 PeImageBase = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 48);
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];
    __int64 SavedSectionOffset = 0;

    InitPESectionReadContext(SectionOffset + KernelBase, (ULONG)(KernelSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);

    for (ULONG i = 0; i < 0x100; i++)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry)) break;

        /* 原始 0x140014E11..E2D：先取 Entry[0xF0] 累加到读指针，再取类型 */
        ULONG SectionSize = *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += SectionSize;

        short SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 0x558 &&                              /* 0x140014E1D */
            (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0 &&   /* [rsp+0xe0] */
            *(ULONG *)((PUCHAR)SectionEntry + 0x38) != 0)         /* [rsp+0xc8] */
        {
            ULONG Candidate = *(ULONG *)((PUCHAR)SectionEntry + 0x38)
                            - (ULONG)KernelBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08);   /* [rsp+0x48] */
            if ((Candidate == ExistingPostWriteOffset1 || Candidate == ExistingPostWriteOffset2) &&
                SavedSectionOffset && (ULONG)SavedSectionOffset < KernelSize)
            {
                /* 原始 0x140014E67..E7E：写 GT[0x1A4]=Saved+ImageBase、GT[0x179]=Saved+NtBase */
                GtWrite((GLOBAL_TABLE_INDEX)0x1A4, SavedSectionOffset + PeImageBase);
                return GtWrite((GLOBAL_TABLE_INDEX)0x179, SavedSectionOffset + NtImageBase);
            }
        }
        else if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) == 0x40000 &&   /* [rsp+0x118] */
                 *(ULONG *)((PUCHAR)SectionEntry + 0x78) != 0)             /* [rsp+0x108] */
        {
            /* 【修正 2026-10-19】原始 0x140014ECC..ED1：
                   mov ebx,[rsp+var_E0]   ; entry+0x78
                   add ebx,ecx            ; + 读指针低 32 位
               这里 **不减 PeBase**（与主路径 0x140014E51 的 `sub eax,ebp` 不同）。
               旧实现多减了一个 KernelBase，导致保存的偏移永远对不上。 */
            SavedSectionOffset = *(ULONG *)((PUCHAR)SectionEntry + 0x78)
                               + (ULONG)*(ULONG64 *)((PUCHAR)&ReadContext + 0x08);
        }
    }
    return result;
}

// MiniFilterPreCleanup — 预清理
// 对应原始驱动 sub_140014EE4
// 从 ntoskrnl 镜像的数据目录入口定位节表，遍历最多 0x100 个节区：
// 记录特征值为 0x40000 的节区偏移（SavedSectionOffset），
// 再在标记 0x558 且带 0x4000000 标志的节区中，用其字段算出候选偏移，
// 命中已存的后写偏移之一且 SavedSectionOffset 有效时，把两个结果分别写入 GT 0x1A4 与 0x179
// ============================================================
// MiniFilterPreClose — 关闭前扫描器
// 对应原始驱动 sub_1400152D4（1908 字节 / 486 条指令）
// 【重写 2026-10-19】寄存器级机械转写。旧实现（同日早些时候）经反汇编复核有 5 处偏差：
//   1) 扫描基址：原始 `Base = (Raw < PeSize) ? Raw : 0`（Raw 取自
//      FindPESectionByName 的返回值，0x1400153E9 sbb + 0x1400153EE and）；
//      旧代码误用 ReturnVa 比较。
//   2) 解码窗口：原始 `(ULONG)PeEnd - (ULONG)r13 - 7`（0x1400154B6..4DB），
//      备用支路则是 `edi - (ULONG)r13 - 7`（0x14001585E..882）。旧代码两处都不对。
//   3) 块 A 的类型判据比较描述符 +0x40（0x140015671/68A），旧代码误作 +0x70。
//   4) 备用 `48 8B` 支路（0x140015856..9A7，类型 0x4B5/0xE5/0x558/0x50E 与回扫）整体缺失。
//   5) 写块 2 的上游条件（回扫命中 ebx / 0x547 标志）缺失，导致 GT[0x334]/[0x335]/
//      [0x8EC]/[0x8ED] 永不落盘。
// 原码在 8/16/32/64 位别名间反复切换并复用寄存器（rsi 既作 PeBase 又作块 A 计数器；
// r14d 既作 Cand 又作两个 Alt 候选与标志字节；r13 在块 B 内被改写为 PeBase 后
// 再从 [rsp+0x78] 恢复），故此处按「寄存器 = 变量」建模、窄写用掩码，以求位级一致。
// 标签名保留原始地址，便于逐槽核对。
// 写入槽位：写块 1（0x14001569A）GT[0x332]/[0x333]/[0x8EE]/[0x8EF]
//           写块 2（0x1400157FB）GT[0x334]/[0x335]/[0x8EC]/[0x8ED]
//           尾写 （0x140015A24）GT[0x337]
__int64 MiniFilterPreClose(void)
{
    /* 寄存器级转写。原码寄存器复用严重，故按「寄存器 = 变量」建模：
         rsi   = PeBase（同时在块 A 内当 0..0xA 的计数器）
         r12d  = PeSize
         rdi   = 块 A/B 的 AltCand；全宽 rdi 另承载 PeEnd
         r13   = 扫描游标（[rsp+0x78] 备份）
         r15   = r13+7（块 B 中被复用为步进 1）
         r14d  = Cand（[rsp+0x44]），块内改写为 Alt 候选与标志字节
         ebx   = Base / Alt2 候选 / 标志
       窄写一律用掩码模拟，以求位级一致。标签名 = 原始地址。 */
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* rsi   0x14001530B */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* r12d  0x140015315 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* [rsp+0x50] */
    const ULONG   v8CC   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CC);    /* [rbp-0x80] */
    const ULONG   v900   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x900);    /* [rbp-0x70] */
    const ULONG   v8CD   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CD);    /* [rsp+0x70] */
    const ULONG   v4459  = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4459);   /* [rbp-0x78] */

    ULONG64 PeEnd = 0;          /* [rsp+0x58] = PeBase + PeSize */
    ULONG64 End   = 0;          /* [rsp+0x68] = 扫描终点 */
    ULONG64 r13   = 0;          /* 扫描游标 */
    ULONG64 r15   = 0;          /* r13 + 7，或块 B 的步进 */
    ULONG   r14d  = 0;          /* Cand / Alt / 标志字节 */
    ULONG   edi   = 0;          /* 块 A/B 的 AltCand；循环尾恢复为 (u32)PeEnd */
    ULONG   esi   = 0;
    ULONG   ebx   = 0;
    UCHAR   dl = 0, r8b = 0;
    UCHAR   f40 = 0, f41 = 0, f42 = 0;    /* [rsp+0x40]/[41]/[42] */
    ULONG   Cand = 0;           /* [rsp+0x44] */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase) return 0;    /* 0x14001537E..397 */
    if (!v8CC || !v900 || !v8CD) return 0;          /* 0x140015399..3AD */

    PeEnd = PeBase + (ULONG64)PeSize;               /* 0x1400153B3 add rdi,rsi */
    edi   = PeSize;                                 /* mov edi,r12d，随后 add rdi,rsi */
    {
        char  Name[8];                              /* [rsp+0x60] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;         /* 0x1400153C4 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;               /* 0x1400153D1 "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;           /* sbb/and 0x1400153E9..3EE */
        ebx  = Base;                                /* 0x1400153EB */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;            /* 0x1400153F9..3FE */
        Avail = PeSize - Base;                      /* 0x140015407 */
        Len = (Va > Avail) ? Avail : Va;            /* cmova 0x14001540E */
        r13 = PeBase + (ULONG64)Base;               /* 0x140015403 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;/* 0x140015422 / 42E */
    }
    f42 = 0; f40 = 0; f41 = 0;                      /* 0x14001541D / 425 / 42A */
    dl = 0; r8b = 0; r14d = 0;                      /* 0x140015416 / 413 / 419 */
    if (r13 >= End) return 0;                       /* 0x140015436..439 */

L_140015445:                                        /* ===== 主循环体（0x140015445） ===== */
    if (r13 + 0x30 >= End) goto L_1400159E3;
    if (*(UCHAR *)r13 != 0x48) goto L_1400159E3;
    if (*(UCHAR *)(r13 + 1) != 0x8D) goto L_1400159E3;
    /* 0x140015468..475：Cand = (u32)(r13+7) + (*(u32*)(r13+3) - (u32)PeBase) */
    Cand = (ULONG)(r13 + 7) + (*(ULONG *)(r13 + 3) - (ULONG)PeBase);
    r14d = Cand;                                    /* 0x140015475 [rsp+0x44] 备份 */
    if (Cand == 0 || Cand >= PeSize) goto L_1400159E3;
    r15 = r13 + 7;
    if (*(UCHAR *)r15 != 0x48) goto L_140015856;    /* 0x14001548D..491 */
    if (*(UCHAR *)(r13 + 8) != 0x89) goto L_140015856;
    if (*(UCHAR *)(r13 + 0xA) != 8)  goto L_140015856;
    if (r8b != 0) goto L_140015584;                 /* 0x1400154AD..4B0 */

    /* ===== 块 A（0x1400154B6..56E）：最多 0xA 轮 ===== */
    edi = 0;                                        /* 0x1400154BA xor edi,edi */
    r14d &= 0xFFFFFF00u;                            /* 0x1400154E4 xor r14b,r14b */
    ebx  &= 0xFFFFFF00u;                            /* 0x1400154E7 xor bl,bl */
    InitPESectionReadContext((__int64)r15, (ULONG)PeEnd - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    esi = 0;                                        /* 0x1400154EE xor esi,esi */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_140015570;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            if (ty == 0x512)                                    /* 0x140015528..551 */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x78) != 0 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40)
                {
                    ULONG c = *(ULONG *)((PUCHAR)Entry + 0x78) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (c != 0 && c < PeSize && edi == 0) edi = c;
                }
            }
            else if (*(ULONG *)((PUCHAR)Entry + 0x40) == v8CC)  /* 0x14001566D..67E */
            {
                r14d = 1;
                goto L_14001555D;
            }
            else                                                /* 0x140015683..695 */
            {
                UCHAR lo = (UCHAR)ebx;      /* movzx ebx,bl */
                ebx = (*(ULONG *)((PUCHAR)Entry + 0x40) == v900) ? 1u : (ULONG)lo;
                goto L_140015558;
            }
        }
        /* 类型非 0x512 且两分支均未命中时不会到达此处；为对齐原始 0x140015553 */
L_140015553:
        if ((UCHAR)r14d != 1) goto L_140015569;
        if ((UCHAR)ebx  != 1) goto L_140015569;
        if (edi != 0) goto L_14001569A;
        goto L_140015569;
L_140015558:
        if ((UCHAR)r14d != 1) goto L_140015569;
L_14001555D:
        if ((UCHAR)ebx != 1) goto L_140015569;
        if (edi != 0) goto L_14001569A;
L_140015569:
        esi += 1;                                    /* 0x140015569..56E */
        if (esi < 0xA) continue;
        goto L_140015570;
    }

L_140015570:                                        /* 0x140015570..57A */
    r8b  = f42;
    dl   = f41;
    r14d = Cand;                                    /* 0x140015575 mov r14d,[rsp+0x44] */

L_140015584:                                        /* 0x140015584 */
    if (f40 != 0) goto L_1400159B6;                 /* 0x140015584..589 */
    if (r14d == 0 || r14d >= PeSize) goto L_1400159B6;  /* 0x14001558F..59B */

    /* ===== 块 B（0x1400155A1..755）：最多 0x14 轮 ===== */
    r14d = 0;                                       /* 0x1400155A5 xor r14d,r14d */
    ebx  &= 0xFFFFFF00u;                            /* 0x1400155D0 xor bl,bl */
    edi  &= 0xFFFFFF00u;                            /* 0x1400155D2 xor dil,dil */
    InitPESectionReadContext((__int64)r15, (ULONG)PeEnd - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    esi = 0;                                        /* 0x1400155DF xor esi,esi */
    r15 = 1;                                        /* 0x1400155E1 lea r15d,[r14+1] */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_14001575B;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            if (ty == 0x512)                                    /* 0x140015624..668 */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x78) != 0 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40)
                {
                    ULONG c = *(ULONG *)((PUCHAR)Entry + 0x78) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (c != 0 && c < PeSize && r14d == 0) r14d = c;
                }
            }
            else if (ty == 0x547)                               /* 0x1400156EC..71B */
            {
                if ((*(ULONG64 *)((PUCHAR)Entry + 0x88) & 0x800000) != 0 &&
                    *(ULONG *)((PUCHAR)Entry + 0x70) == 0x1000 &&
                    *(ULONG *)((PUCHAR)Entry + 0x40) == v8CD)
                {
                    ebx = 1;
                    r15 = 1;
                }
            }
            else if ((USHORT)(ty - 0x53C) <= 7)                 /* 0x14001571D..74B */
            {
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x2000000 &&
                    *(ULONG64 *)((PUCHAR)Entry + 0x70) == 0xFFFFF78000000014ull)
                {
                    UCHAR lo = (UCHAR)edi;   /* movzx edi,dil */
                    edi = (r15 == 0) ? (ULONG)lo : (ULONG)r15;   /* cmove edi,r15d */
                }
            }
        }
        esi += (ULONG)r15;                                  /* 0x14001574F */
        if (esi < 0x14) continue;
        break;
    }

L_14001575B:                                        /* 0x14001575B */
    if ((UCHAR)edi != 1) goto L_1400159AD;          /* 0x140015761 cmp dil,1 */
    if (r14d == 0) goto L_1400159AD;                /* 0x14001576F */
    if ((UCHAR)ebx != 0) goto L_1400157EE;          /* 0x140015778 */
    {   /* 回扫 `C7`：rcx 自 (r13-0x30) 递增至 (r13-7)（0x140015781..7E9） */
        PUCHAR rcx = (PUCHAR)r13 - 0x30;
        PUCHAR hi  = (PUCHAR)(r13 - 7);
        if (r13 <= PeBase) goto L_1400159AD;        /* 0x140015785..788 */
        if ((ULONG64)rcx <= PeBase) goto L_1400159AD;/* 0x14001578E..791 */
        for (;;)
        {
            UCHAR dv;
            if (rcx > hi) goto L_1400159AD;         /* 0x14001579B..79E */
            dv = *rcx;
            if (dv == 0xC7 && (ULONG)rcx[2] == v8CD && *(ULONG *)(rcx + 3) == 0x1000)
                break;                              /* 0x1400157AB..7C0 */
            if (rcx <= (PUCHAR)(r13 - 0xA) && dv == 0xC7 &&
                *(ULONG *)(rcx + 2) == v8CD && *(ULONG *)(rcx + 6) == 0x1000)
                break;                              /* 0x1400157C2..7DD */
            rcx += 1;                               /* 0x1400157DF..7E7 */
        }
        ebx = 1;                                    /* 0x1400157E9 */
    }
L_1400157EE:                                        /* 0x1400157EE */
    if ((UCHAR)ebx != 1) goto L_1400159AD;
    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)Cand);              /* 0x1400157FB */
    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)Cand + NtBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EC, (__int64)(ULONG64)r14d);
    GtWrite((GLOBAL_TABLE_INDEX)0x8ED, (__int64)((ULONG64)r14d + NtBase));
    r8b  = f42;                                     /* 0x14001583C */
    dl   = 1;                                       /* 0x140015841 */
    r14d = (r14d & 0xFFFFFF00u) | 1u;               /* 0x140015846 mov r14b,dl */
    f40  = 1;                                       /* 0x140015849 */
    dl   = f41;                                     /* 0x14001584D */
    goto L_1400159BB;

L_14001569A:                                        /* ===== 写块 1（0x14001569A..6E7） ===== */
    r14d = Cand;                                    /* 0x14001569A mov r14d,[rsp+0x44] */
    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);              /* 0x14001569F */
    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase));
    GtWrite((GLOBAL_TABLE_INDEX)0x8EE, (__int64)(ULONG64)edi);
    GtWrite((GLOBAL_TABLE_INDEX)0x8EF, (__int64)((ULONG64)edi + NtBase));
    r8b = 1;                                        /* 0x1400156E0 mov r8b,dl */
    f42 = 1;                                        /* 0x1400156E3 */
    dl  = f41;                                      /* 0x1400156E7 */
    goto L_140015584;

L_140015856:                                        /* ===== 备用支路（0x140015856..9A7） ===== */
    if (dl != 0) goto L_1400159B6;                  /* 0x140015856..858 */
    /* 0x14001585E..882：窗口 = edi - (u32)r13 - 7（edi 此处 = PeSize） */
    InitPESectionReadContext((__int64)r15, edi - (ULONG)r13 - 7u,
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    ebx &= 0xFFFFFF00u;                             /* 0x140015880 xor bl,bl */
    edi  = 0;                                       /* 0x140015891 xor edi,edi */
    for (;;)
    {
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto L_1400159AD;
        *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
        {
            USHORT ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
            /* 0x1400158C5..8F0：0x4B5 且 [F0]==6 → ebx = (GT[0x336] == +0x70) */
            if (ty == 0x4B5 && *(ULONG *)((PUCHAR)Entry + 0xF0) == 6)
            {
                UCHAR lo = (UCHAR)ebx;
                ebx = ((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) ==
                       *(ULONG *)((PUCHAR)Entry + 0x70)) ? 1u : (ULONG)lo;
            }
            if (edi > 4 && (UCHAR)ebx == 0) goto L_1400159AD;   /* 0x1400158F7..8FE */
            if (ty == 0xE5 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000 &&
                (UCHAR)ebx == 1)
                goto L_140015A24;                               /* 0x14001590C..926 */
            if (ty == 0x558 &&                                  /* 0x14001592C..957 */
                (*(ULONG64 *)((PUCHAR)Entry + 0x50) & 0x4000000) != 0 &&
                *(ULONG *)((PUCHAR)Entry + 0x38) != 0)
            {
                if ((UCHAR)ebx == 0) goto L_1400159AD;
                if (v4459 != 0)
                {
                    ULONG a = *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)PeBase
                            + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                    if (v4459 == a) goto L_140015A24;
                }
            }
            else if (ty == 0x50E &&                             /* 0x140015959..995 */
                     *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000 &&
                     *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40 &&
                     (UCHAR)ebx == 1)
            {
                ULONG a = *(ULONG *)((PUCHAR)Entry + 0x40) - (ULONG)PeBase
                        + (ULONG)*(ULONG64 *)((PUCHAR)&Ctx + 0x08);
                if (a != 0 && a < PeSize && (ULONG64)r14d + 8 == (ULONG64)a)
                    goto L_140015A24;
            }
        }
        edi += 1;                                            /* 0x14001599B..9A7 */
        if (edi >= 0xF) goto L_1400159AD;
    }

L_140015A24:                                        /* 尾写（0x140015A24） */
    GtWrite((GLOBAL_TABLE_INDEX)0x337, (__int64)((ULONG64)r14d + NtBase));
    dl  = 1;                                        /* 0x140015A3C mov dl,r8b */
    f41 = 1;                                        /* 0x140015A3F */
    goto L_1400159B1;

L_1400159AD:                                        /* 0x1400159AD */
    dl  = f41;
    r8b = f42;
L_1400159B1:
L_1400159B6:                                        /* 0x1400159B6 */
    r14d = (r14d & 0xFFFFFF00u) | (ULONG)f40;       /* mov r14b,[rsp+0x40] */
L_1400159BB:                                        /* 完成闸门（0x1400159BB） */
    if (r8b == 1 && (UCHAR)r14d == 1 && dl == 1) return 0;
L_1400159CE:                                        /* 前进（0x1400159CE..9EE） */
    /* 0x1400159D3/9D8：每轮从栈槽恢复 rcx=End、rdi=PeEnd、r9d=7。
       缺 rdi 的恢复会让备用支路用到块 A/B 残留的计数器值（窗口过小 → 不触发 0x337）。 */
    edi = (ULONG)PeEnd;
    r13 += 1;
    if (r13 < End) goto L_140015445;
    return 0;
L_1400159E3:
    goto L_1400159CE;
}


// MiniFilterPreCleanup — 预清理回调（build < 0x4A61 走这里，本机 18362 即是）
// 对应原始驱动 0x140014EE4（0x1F9 字节 / 69 条指令）
// 【重写 2026-10-20】旧实现 5 处偏差，逐条对照反汇编修正：
//   1) 读指针推进时机错：原始在 ReadPESectionEntry **之后**才 `add rcx,rax`
//      （0x14001500E..02A），旧代码放在解码之前，首轮用未初始化描述符推进。
//   2) 累计量语义错：原始直接用 ctx+0x08（读指针）作基，旧代码另设 CumulativeSize。
//   3) 0x40000 支路减基数错：原始 0x1400150CB..0D0 是
//      `mov ebx,eax; sub ebx,r14d; add ebx,ecx` —— **要减 PeBase**，
//      与 PostWrite 的同名支路不同（那里不减）。旧代码减了但基数是 CumulativeSize。
//   4) 命中判据顺序错：原始先比 r12d(GT[0x439F]) 再比 r15d(GT[0x41C5])，
//      且 0x179/0x1A4 的写入值分别用 r13（PE 头 ImageBase）与 rdi（GT[3]）。
//   5) 描述符数组大小：0x120 字节 = 72 个 DWORD（旧注释写 112 是错的）。
// 寄存器映射（保留原名便于核对）：
//   r14=PeBase(GT[0x20])  esi=PeSize(GT[0x21])  rdi=NtImageBase(GT[3])
//   rbx=SectionAddr(GT[0x170])  r12d=GT[0x439F]  r15d=GT[0x41C5]
//   r13=PE 可选头 ImageBase（e_lfanew+0x30）  ebp=轮次  ebx=SavedSectionOffset
// 对应原始驱动 0x140014EE4（509 字节）
__int64 MiniFilterPreCleanup(void)
{
    ULONG64 PeBase;
    ULONG   PeSize;
    ULONG64 NtImageBase;
    ULONG64 SectionAddr;
    ULONG   ExistingOffset1;
    ULONG   ExistingOffset2;
    ULONG   Offset;
    ULONG64 PeImageBase;
    ULONG64 SavedSectionOffset;
    ULONG   SectionIndex;
    ULONG   Result;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[72];        /* 0x120 字节描述符 */

    PeBase       = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* r14  */
    PeSize       = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* esi  */
    NtImageBase  = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* rdi  */
    SectionAddr  = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x170);  /* rbx  */
    ExistingOffset1 = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x439F);/* r12d */
    ExistingOffset2 = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41C5);/* r15d */
    Result = ExistingOffset2;

    /* 0x140014F63..F9A：六道守卫 */
    if (!PeBase || !PeSize || !NtImageBase || !SectionAddr) return Result;
    if (SectionAddr <= NtImageBase) return Result;
    if (!ExistingOffset1 || !ExistingOffset2) return Result;

    /* 0x140014FA0..FB4：Offset = (u32)(SectionAddr - NtImageBase)，
       要求 Offset < PeSize 且 SectionAddr == Offset + NtImageBase（32 位回绕形式） */
    Offset = (ULONG)(SectionAddr - NtImageBase);
    if (Offset >= PeSize) return Result;
    if (SectionAddr != (ULONG64)Offset + NtImageBase) return Result;

    /* 0x140014FBA..FC4：r13 = PE 可选头 ImageBase；rcx = PeBase + Offset */
    PeImageBase = *(ULONG64 *)(*(int *)(PeBase + 0x3C) + PeBase + 0x30);

    InitPESectionReadContext((__int64)(PeBase + Offset),
                             (ULONG)(PeSize - Offset),
                             2, 0, -1, 0, 0, (__int64)&ReadContext); /* 0x140014FEF */

    SavedSectionOffset = 0;                                   /* 0x140014FF4 xor ebx,ebx */
    for (SectionIndex = 0; SectionIndex < 0x100; SectionIndex++)  /* 0x140014FF6 xor ebp,ebp */
    {
        ULONG64 ReadPtr;
        USHORT  Type;
        ULONG   Cand;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry) != 0)
            break;                                            /* 0x14001500C jnz 收尾 */

        /* 0x14001500E..02A：先推进读指针，再判类型 */
        ReadPtr = *(ULONG64 *)((PUCHAR)&ReadContext + 0x08)
                + (ULONG64)*(ULONG *)((PUCHAR)SectionEntry + 0xF0);
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) = ReadPtr;

        Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (Type == 0x558 &&                                    /* 0x14001502F */
            (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) & 0x4000000) != 0 &&  /* 0x140015035 */
            *(ULONG *)((PUCHAR)SectionEntry + 0x38) != 0)       /* 0x140015043 */
        {
            Cand = *(ULONG *)((PUCHAR)SectionEntry + 0x38) - (ULONG)PeBase
                 + (ULONG)ReadPtr;                              /* 0x14001504E..051 */
            if (Cand == ExistingOffset1 || Cand == ExistingOffset2)
            {
                if (SavedSectionOffset && (ULONG)SavedSectionOffset < PeSize)
                {
                    /* 0x140015065..07C：0x1A4 = Saved + PE.ImageBase；0x179 = Saved + GT[3] */
                    GtWrite((GLOBAL_TABLE_INDEX)0x1A4, (__int64)(SavedSectionOffset + PeImageBase));
                    return GtWrite((GLOBAL_TABLE_INDEX)0x179, (__int64)(SavedSectionOffset + NtImageBase));
                }
            }
        }
        else if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) == 0x40000 &&   /* 0x1400150B2 */
                 *(ULONG *)((PUCHAR)SectionEntry + 0x78) != 0)             /* 0x1400150C0 */
        {
            /* 0x1400150CB..0D0：ebx = 字段 - PeBase + 读指针（此处**要减** PeBase） */
            SavedSectionOffset = (ULONG64)(*(ULONG *)((PUCHAR)SectionEntry + 0x78)
                                           - (ULONG)PeBase
                                           + (ULONG)ReadPtr);
        }
    }
    return Result;
}

// ============================================================
// Minifilter 缺失族（L2-3）—— 上下文枚举依赖链
//
// 拓扑：MiniFilterInstanceSetup → OpenMiniFilterVolumeFile
//       → EnumMiniFilterContextList
// 三者依次在 _FINAL_GAP.json 中均为 A_definite_missing，必须成链实现。
// 以下按原始反汇编逐条转写，代码内标注 `L_<地址>`。
// ============================================================

// EnumMiniFilterContextList — 枚举对象类型条目、按类型分组并填表
// 对应原始驱动 0x140012620（938 字节）
// 【帧定基】`mov rax,rsp` → 存 4 个实参到 home（[rax+8]=rcx, [rax+0x10]=edx,
//   [rax+0x18]=r8, [rax+0x20]=r9）→ push 8 个寄存器(0x40) → `sub rsp,0x68`
//   故 rsp = 入口 rsp - 0xA8，rax = rsp + 0xA8。实参槽（由 rax 换算）：
//     [rsp+0xB0] = rcx = OutArray   （输出数组基址）
//     [rsp+0xB8] = edx = MaxEntries （条目上限，调用方传 0x20000）
//     [rsp+0xC0] = r8  = OutCount   （输出计数指针，命中时 +1）
//     [rsp+0xC8] = r9  = Limit      （输出边界，用于越界校验）
//   —— 与调用方 OpenMiniFilterVolumeFile 的
//      `EnumMiniFilterContextList(Buf, 0x20000, OutStruct, OutStruct+OutSize)` 完全一致。
// 【算法】取 GT 0x41DB / 0x360，任一为 0 即返回；要求 MaxEntries > 1；
//   沿 OutArray[0] 起的对象列表最多走 0x25 项：
//     用 CheckMemoryValid 校验对象 → 按构建号取对象类型（<=0x1772 取 [obj-0x20]，
//     否则 CheckObjectTypeFlagWrapper(obj-0x30)）→ 遍历该对象的上下文链（首项 [obj]，后继 [node]）：
//       · 类型相同 → 追加到 OutArray[++Written]；
//       · 否则 FindContextEntry 尝试合并，未合并则用 SkipContextEntries 取条目位并
//         ValidateAddressWithSize 校验后填 {节点, 名字截断 0x40 字节, 字段计数}，
//         再逐条把 (Cur+0x10, Cur+0x28, Cur+0x30) 三个字段拷入表尾；
//         若本条目无子项则不动 OutCount，有则 +1。
// 对应原始驱动 0x140012620（938 字节）
void EnumMiniFilterContextList(__int64 OutArray, ULONG MaxEntries,
                               ULONG *OutCount, ULONG64 Limit)
{
    __int64 ObjList;              // rbp = rcx（OutArray 起点，逐轮 +8）
    ULONG   OuterIdx;             // ebx
    ULONG   InnerIdx;             // edx
    ULONG64 R12;                  // Written（初值 -1）
    ULONG64 R15;                  // Written 的 64 位伴随（OutArray 索引）
    __int64 ObjEntry;             // rdi
    ULONG64 Cur;                  // 当前对象
    ULONG64 TypeA;                // 参照类型
    ULONG64 EntryBase;            // 条目位（SkipContextEntries 结果）
    UCHAR   Done;                 // [rsp+0x20]

    ULONG64 G41DB = (ULONG64)GtRead(GtObjectTypeCheckFlag);        // 0x140012651
    ULONG64 G360  = (ULONG64)GtRead(GtEprocessExtField10);         // 0x140012668

    Done = 0;

    if (!G41DB || !G360)                                     // 0x140012672/67B
        return;
    if ((int)MaxEntries <= 1)                                // 0x140012687
        return;

    ObjList = OutArray;
    ObjEntry = *(__int64 *)ObjList;                          // 0x140012690 [rbp]
    R12 = (ULONG64)-1;                                       // 0x140012694
    R15 = R12;
    OuterIdx = 0;
    InnerIdx = 0;

    if (!ObjEntry)                                           // 0x1400126A8
        return;

L_OUTER:                                                     // 0x1400126B4
    if (CheckMemoryValid((void *)ObjEntry) != 1)              // 0x1400126BA（原始 bl=1）
        return;
    if (OuterIdx >= 0x100000)                                // 0x1400126C8
        return;

    // 参照类型（0x1400126D4~6F4）
    if ((ULONG)GtRead(GtWindowsBuildNumber) <= 0x1772)
        TypeA = *(ULONG64 *)(ObjEntry - 0x20);
    else
        TypeA = (UCHAR)CheckObjectTypeFlagWrapper(ObjEntry - 0x30);

    EntryBase = (ULONG64)SkipContextEntries((_DWORD *)OutArray);   // 0x140012703
    Cur = *(ULONG64 *)ObjEntry;                              // 0x140012710
    InnerIdx = 0;

    if (!Cur)                                                // 0x14001271E
        goto L_OUTER_NEXT;

L_INNER:                                                     // 0x140012727
    if ((ULONG64)EntryBase >= Limit)                         // 0x140012727 cmp rsi,[rsp+0xc8]
        goto L_INNER_END;
    if (InnerIdx >= 0x10000)                                 // 0x140012735
        goto L_INNER_END;

    {
        ULONG64 CtxHdr = *(ULONG64 *)(Cur + 8);              // 0x140012741
        ULONG64 NodeType;

        if ((ULONG)GtRead(GtWindowsBuildNumber) <= 0x1772)   // 0x140012745~75A
            NodeType = *(ULONG64 *)(CtxHdr - 0x20);
        else
            NodeType = (UCHAR)CheckObjectTypeFlagWrapper(CtxHdr - 0x30);

        if (TypeA == NodeType)                               // 0x14001276B
        {
            // 类型相同 → 追加到 OutArray[++Written]（0x14001276D~79B）
            ULONG CapMinus1 = MaxEntries - 1;
            if ((int)R12 < (int)CapMinus1)
            {
                ++R12;
                ++R15;
                ((ULONG64 *)(ULONG_PTR)OutArray)[R15] = CtxHdr;
            }
        }
        else
        {
            // 0x1400127A0：先尝试合并
            if (FindContextEntry((__int64)CtxHdr, (_DWORD *)OutArray) != 0)  // 0x1400123C8
                goto L_INNER_NEXT;

            // 0x1400127B3：取新条目位并做边界检查（OutArray 作为游标推进）
            EntryBase = (ULONG64)SkipContextEntries((_DWORD *)OutArray);
            if (EntryBase + 0x68 >= Limit)                   // 0x1400127BE/7C2
            {
                Done = 1;
                goto L_OUTER_NEXT;
            }

            *(ULONG64 *)EntryBase = CtxHdr;                  // 0x1400127D2
            *(USHORT *)(EntryBase + 8) = 0;                  // 0x1400127D8

            // 0x1400127DC：取名字并截断拷贝（至多 0x40 字节）
            {
                __int64 Name = (__int64)ValidateAddressWithSize((char *)CtxHdr);  // 0x1400798F8
                if (Name)
                {
                    ULONG n = *(USHORT *)Name;
                    if (n > 1)                               // 0x1400127EE
                    {
                        ULONG64 Src = *(ULONG64 *)(Name + 8);
                        if ((UCHAR)CheckMemoryValid((void *)Src) != 0        // 0x1400127FD
                            && (UCHAR)CheckMemoryValid((void *)(Src - 1)) != 0)  // 0x140012813
                        {
                            ULONG cp = (n < 0x40) ? n : 0x40;    // 0x140012828 cmova
                            memmove((void *)(EntryBase + 8), (void *)Src, cp);  // 0x140012836
                            *(USHORT *)(EntryBase + 8 + ((ULONG64)cp >> 1) * 2) = 0;  // 0x140012840
                        }
                    }
                }
                *(ULONG *)(EntryBase + 0x4C) = 0;            // 0x14001284A
            }

            // 0x14001284D：遍历子链（Sub = CtxHdr + G360）
            {
                ULONG64 Sub = (ULONG64)CtxHdr + G360;        // 0x140012853
                if (CheckMemoryValid((void *)Sub) == 1)      // 0x14001285C
                {
                    ULONG64 S = *(ULONG64 *)Sub;             // 0x14001286A
                    ULONG   cnt = 0;

                    while (S && S != Sub)                    // 0x14001287B/884
                    {
                        ULONG64 need;
                        ULONG   idx;
                        ULONG64 slot;

                        idx = *(ULONG *)(EntryBase + 0x4C);  // 0x140012889
                        need = EntryBase + ((ULONG64)idx * 3 + 0xD) * 8;
                        if (need > Limit) break;             // 0x140012898

                        if (CheckMemoryValid((void *)S) != 1) break;               // 0x1400128A3
                        if (CheckMemoryValid((void *)(S + 0x3F)) != 1) break;      // 0x1400128B4

                        ++cnt;                               // 0x1400128C1
                        idx = *(ULONG *)(EntryBase + 0x4C);
                        slot = (ULONG64)idx * 3;
                        *(ULONG  *)(EntryBase + slot * 8 + 0x50)    = *(ULONG  *)(S + 0x10); // 0x1400128CB
                        *(ULONG64*)(EntryBase + slot * 8 + 0x58)    = *(ULONG64*)(S + 0x28); // 0x1400128DA
                        *(ULONG64*)(EntryBase + (slot + 4) * 8)     = *(ULONG64*)(S + 0x30); // 0x1400128EE
                        ++*(ULONG *)(EntryBase + 0x4C);      // 0x1400128F2
                        S = *(ULONG64 *)S;                   // 0x1400128F6
                        if (cnt >= 0x10000) break;           // 0x1400128F9
                    }
                }
            }

            // 0x14001290F：本条目产出了子项才递增 OutCount
            if (*(ULONG *)(EntryBase + 0x4C) != 0)           // 0x140012919
                ++*OutCount;                                 // 0x14001291E
        }

    L_INNER_NEXT:                                            // 0x140012926
        Cur = *(ULONG64 *)Cur;                               // 0x14001292F
        ++InnerIdx;                                          // 0x140012932
        if (Cur)
            goto L_INNER;                                    // 0x140012942
    }

L_INNER_END:                                                 // 0x140012950
L_OUTER_NEXT:                                                // 0x140012954
    if (Done == 1)                                           // 0x14001295D/95F
        return;
    ++OuterIdx;                                              // 0x140012961
    ObjList += 8;                                            // 0x140012963
    ObjEntry = *(__int64 *)ObjList;                          // 隐含：rdi += 8 后重取
    if (OuterIdx >= 0x25)                                    // 0x140012970 cmp ebx,25h
        return;
    if (!ObjEntry)                                           // 0x1400129B0
        return;
    goto L_OUTER;
}

// OpenMiniFilterVolumeFile — 打开 L"\ObjectTypes" 并枚举过滤器上下文
// 对应原始驱动 0x14001241C（515 字节）
// 【帧定基】存 rbx/rsi 到 [rsp+0x10/0x18] → push rdi,r12,r13,r14,r15(0x28) → sub rsp,0xC0
// 【算法】取 5 个 GT 函数指针（0x421D 打开 / 0x4238 查询 / 0x41C6 初始化 /
//   0x4223 关闭 / 0x4334 释放），任一为 0 则整体跳过；
//   构造 UNICODE_STRING L"\ObjectTypes"（栈 rsp+0x98）→ FnOpen(&Handle, &Name)
//   → 布置 OBJECT_ATTRIBUTES{rsp+0x68=0x30, rsp+0x80=0x240, rsp+0x78=&Name}
//   → FnQuery(&QueryOut, 1, &Attr)，非负则 FnInit(Handle, 0xF000F, 0, 0, &QueryOut)，
//   非负则 ExAlloc(1, 0x100000) 取缓冲、写入查询结果、调 EnumMiniFilterContextList
//   → ExFree 缓冲 → FnClose(查询结果) → FnFree(句柄)。恒返回 0。
// 对应原始驱动 0x14001241C（515 字节）
UCHAR OpenMiniFilterVolumeFile(__int64 OutStruct, ULONG OutSize)
{
    __int64 FnOpen, FnQuery, FnInit, FnClose, FnFree;
    UCHAR   Name[32];
    UCHAR   ObjAttr[0x30];
    ULONG64 Handle;
    ULONG64 QueryOut;
    ULONG64 Buf;

    FnOpen  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x421D);   // 0x140012453
    FnQuery = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4238);   // 0x140012460
    FnInit  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x41C6);   // 0x14001246D
    FnClose = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4223);   // 0x14001247A
    FnFree  = (__int64)GtRead(GtExFreePoolFunc);             // 0x14001248C ecx=0x4334

    if (!FnOpen || !FnQuery || !FnInit || !FnClose || !FnFree)   // 0x140012499~4C0
        return 0;

    // L"\ObjectTypes"（0x1400124C6~508）
    memset(Name, 0, sizeof(Name));
    *(ULONG *)&Name[0]  = 0x4F005C;      // \\O
    *(ULONG *)&Name[4]  = 0x6A0062;      // bj
    *(ULONG *)&Name[8]  = 0x630065;      // ec
    *(ULONG *)&Name[12] = 0x540074;      // tT
    *(ULONG *)&Name[16] = 0x700079;      // yp
    *(ULONG *)&Name[20] = 0x730065;      // es

    ((void(__fastcall *)(ULONG64 *, void *))FnOpen)(&Handle, Name);   // 0x14001251D

    // OBJECT_ATTRIBUTES（0x140012520~546）
    memset(ObjAttr, 0, 0x28);
    *(ULONG   *)&ObjAttr[0x00] = 0x30;                                  // Length
    *(ULONG64 *)&ObjAttr[0x10] = (ULONG64)(ULONG_PTR)Name;              // ObjectName
    *(ULONG   *)&ObjAttr[0x18] = 0x240;                                 // Attributes

    if ((int)((__int64(__fastcall *)(ULONG64 *, ULONG, void *))FnQuery)(
            &QueryOut, 1, ObjAttr) < 0)                     // 0x140012562/565/567
        return 0;

    if ((int)((__int64(__fastcall *)(ULONG64, ULONG, ULONG, ULONG, ULONG64 *))FnInit)(
            Handle, 0xF000F, 0, 0, &QueryOut) < 0)          // 0x14001258D/591
        goto L_CLOSE_HANDLE;

    Buf = (ULONG64)ExAlloc(1, 0x100000);                    // 0x14001259B（rcx=1, edx=0x100000）
    if (!Buf)                                               // 0x1400125A8
        goto L_FREE_QUERY;

    *(ULONG64 *)Buf = QueryOut;                             // 0x1400125B2

    EnumMiniFilterContextList((__int64)Buf, 0x20000,         // 0x1400125C4
                              (ULONG *)OutStruct, (ULONG64)(OutStruct + OutSize));

    ExFree((void *)Buf);                                    // 0x1400125DD

L_FREE_QUERY:
    ((void(__fastcall *)(ULONG64))FnClose)(QueryOut);       // 0x1400125E7
L_CLOSE_HANDLE:
    ((void(__fastcall *)(ULONG64))FnFree)(Handle);          // 0x1400125EE
    return 0;                                               // 0x1400125F0 xor al,al
}

// MiniFilterInstanceSetup — FLT 实例安装回调：校验用户缓冲并按构建号分发
// 对应原始驱动 0x1400129CC（179 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return STATUS_SUCCESS;` 空壳。
char MiniFilterInstanceSetup(void *FltFilter, void *Instance, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;

    (void)FltFilter; (void)Instance;

    if (!Buffer)                                             // 0x1400129ED
        return Result;
    if (BufferSize <= 0x70)                                  // 0x1400129F2
        return Result;
    if ((ULONG64)Buffer >= MmUserProbeAddress)               // 0x1400129F7/2A01
        return Result;
    if ((ULONG64)Buffer + BufferSize >= MmUserProbeAddress)  // 0x140012A06/0A0A
        return Result;

    ProbeForWrite(Buffer, BufferSize, 1);                    // 0x140012A1B
    memset(Buffer, 0, BufferSize);                           // 0x140012A29
    *(ULONG *)Buffer = 0;                                    // 0x140012A2E

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1771)        // 0x140012A30/3A
        return Result;

    OpenMiniFilterVolumeFile((__int64)Buffer, BufferSize);   // 0x140012A46

    Result = (*(ULONG *)Buffer != 0) ? 1 : 0;                // 0x140012A4E cmovne
    return Result;
}

// MiniFilterPreFastIo — 快速 IO 预处理：校验用户缓冲并按结构尺寸分发枚举
// 对应原始驱动 0x14001B2B4（176 字节）
// 【逆向来源】人工阅读反汇编逐条转写 —— 原实现是 `return STATUS_SUCCESS;` 空壳。
// 【要点】用魔数 0xA41A41A41A41A41B 实现无符号除法：
//   条目数 = (BufferSize - 0x278) / 0x278 + 1。
// 对应原始驱动 0x14001B2B4（176 字节）
char MiniFilterPreFastIo(void *Filter, void *CallbackData, void *Buffer, ULONG BufferSize)
{
    UCHAR Result = 0;
    ULONG64 T, Entries;

    (void)Filter; (void)CallbackData;

    if (!Buffer)                                             // 0x14001B2C8
        return Result;
    if (BufferSize < 0x278)                                  // 0x14001B2D1
        return Result;
    if ((ULONG64)Buffer >= MmUserProbeAddress)               // 0x14001B2DA/2E4
        return Result;
    if ((ULONG64)Buffer + BufferSize >= MmUserProbeAddress)  // 0x14001B2EC/2F0
        return Result;

    ProbeForWrite(Buffer, BufferSize, 8);                    // 0x14001B2FE
    memset(Buffer, 0, BufferSize);                           // 0x14001B30C
    *(ULONG *)Buffer = 0;                                    // 0x14001B311

    // 原始汇编用魔数 0xA41A41A41A41A41B 实现无符号除法（mul 取高半），
    // 数学上等价于 T / 0x278；此处直接写除法以免 __int128（本工程 MSVC/LTCG 不支持）。
    T = (ULONG64)BufferSize - 0x278;                         // 0x14001B313
    Entries = (T / 0x278) + 1;                               // 0x14001B31A~335

    if (EnumerateAleEndpointLayers((_DWORD *)Buffer, (__int64)Buffer + 8, (int)Entries))  // 0x14001B33F
        Result = 1;                                          // 0x14001B344
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
    if (Ptr <= ScanStart - 0xA && *(UCHAR *)Ptr == 0xC7 &&
        (ULONG)Gt8CD == *(ULONG *)(Ptr + 2) && *(ULONG *)(Ptr + 6) == 0x1000)
        goto L1400157E9;
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

    if (*(WORD *)(*(__int64 *)((char *)SectionInfo + 0x118) + 6) == 0xE5 &&
        *(__int64 *)((char *)SectionInfo + 0x50) == 0x40000 && FoundB)
        goto L140015A24;

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
    /* 【修正 2026-10-17】原始 0x1400159CE..0x1400159DD 只是从栈上恢复 rsi/rcx/rdi
       （循环体用的 PeBase、ScanEnd 上限、SectionOff 局部），紧接着就是 `inc r13`。
       **原始并不重置 ScanStart**。旧代码在此多了
       `ScanStart = PeBase + SectionOff;`（外加 `ScanEnd = ScanLimit;`），
       等于每轮都把扫描游标拨回节区起点，外层 `++ScanStart` 只能走到 offset+1，
       于是无限循环。实机症状：DriverEntry 在 FindKernelObjectFieldOffsetsWin10
       内死转（kd 栈顶 rtZ9+0x309d6），sc start 永不返回。 */
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
L140015EA0:
    ;
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

    // 【GT 索引修正 2026-10-13】三个索引原写为
    //   GtFsFilterTableReady(0x898) / GtFltPeSectionAddr3(0x88D) / GtFltPeSectionAddr8(0x897)，
    //   原始实为 **0x889 / 0x88B / 0x87E**。
    //   依据（原始 0x1400177B4 逐条）：
    //     `mov edi,0x889`（0x1400177D9）→ GtRead → 空则 call 0x14001763C
    //     → 再 GtRead(0x889) 存入 r13
    //     → `mov ecx,0x88B`（0x1400177F9）存入 r12
    //     → `mov ecx,0x87E`（0x140017806）存入 rax
    //   三者齐备后读 0x914（构建号）并 `cmp eax,0x3AD7; sbb; and -2; add 0xE`
    //   → EntryCount = (构建号 < 0x3AD7) ? 12 : 14。
    if (!GtRead((GLOBAL_TABLE_INDEX)0x889))                   // 0x1400177DE（懒初始化）
        InitFsFilterExportTable();                             // 0x1400177EA

    ServiceTable1 = GtRead((GLOBAL_TABLE_INDEX)0x889);         // 0x1400177EF（r13）
    ServiceTable2 = GtRead((GLOBAL_TABLE_INDEX)0x88B);         // 0x1400177FE（r12）
    FltMgrBase = GtRead((GLOBAL_TABLE_INDEX)0x87E);            // 0x14001780B（rax）

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

// MiniFilterPreShutdown — FltMgr 关机前指针修补（0x1400188D8）
// 对应原始驱动 0x1400188D8（937 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：一段通用的
//   "遍历 ServicePtr 数组、检查每项是否为有效内核地址"的循环，
//   与原始函数体毫无关系。注释称"从 ServicePtr 读取服务表，遍历服务条目
//   执行关机前清理"亦不符。
//   发现方式：静态 GT 核查工具 `_gtwrites2.py` 报该函数原始读
//   {3,2,0x89A,0x87E,0x88D,0x896,0x88F,0x891,0x893,0x895,0x897,0x887,0x914}
//   而我方一个都没有；逐条反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写（IDA 无伪代码）。
// 【语义】把 FltMgr 各 PE 节里指向某个"旧指针值"的槽原位替换为新指针，
//   属 minifilter 卸载/关机时的指针修正（与 GtFltmgrBase 系列 GT 配合）。
// 【原始汇编骨架】
//   ① 读 GT 3 → [rsp+0x50]（模块基址）；读 GT 2 → [rsp+0x58]（模块大小）；
//   ② r14 = GT 0x89A；若为 0 → call 0x1400164C8 后重读 0x89A。
//      0x89A = 待替换的"旧指针值"。
//   ③ [rsp+0x48] = GT 0x87E（FltMgr 基址）
//   ④ r15d = 0x88D；rbx = GT 0x88D；同时读 GT (0x88D+9)=0x896；
//      若两者都为 0 → call 0x14001763C（初始化 FltMgr 节表），随后重读 0x88D → r12。
//   ⑤ 依次读 0x88F/[+0x28]、0x891/[+0x30]、0x893/[+0x38]、0x895/[+0x40]、
//      0x897 → r15、0x887 → r13。（六个 FltMgr 节地址）
//   ⑥ 前置校验：r14 非 0；[rsp+0x48] 非 0；r13 非 0；r12 或 r15 至少一个非 0；
//      r14 落在 (Gt3, Gt3+Gt2) 区间内且 r14+8 仍 < 上界；
//      rsi(第 1 参) 非 0 且位于 MmUserProbeAddress 之下（含 +8）；
//      第 2 参（[rsp+0x98]）必须等于 8。
//   ⑦ ProbeForRead(rsi, 8, 8)；目标值 = *(rsi)（预期是被替换的旧指针）；
//      要求该值 > MmSystemRangeStart。
//   ⑧ rbx = *(r14)；若 rbx == 目标值 → 直接 `xchg [r14], r13`（换成 0x887 节地址）
//      并成功返回。
//   ⑨ 否则按构建号分支（0x914）：
//        < 0x23F0            → 只补 1 处：若 *rbx == 目标值 且 r15 非 0 → 写 r15
//        >= 0x4A61           → 补 6 处：偏移 0/8/0x10/0x18/0x20/0x28 分别尝试
//                              用 r12/r15/[+0x28]/[+0x30]/[+0x38] 替换
//        否则(0x23F0..0x4A60) → 补 5 处：偏移 0/8/0x10/0x18/0x20
//   ⑩ 每次替换 = WritePhysicalMemoryQword(槽地址, 新值)（0x140083180），
//      成功则置标志 dil=1。
//   ⑪ 返回 dil。
__int64 MiniFilterPreShutdown(_QWORD *ServicePtr, int InputSize)
{
    char    Result = 0;                 // dil
    __int64 ModuleBase;                 // [rsp+0x50] = GT 3
    ULONG   ModuleSize;                 // [rsp+0x58] = GT 2
    __int64 OldValue;                   // r14 = GT 0x89A
    __int64 FltMgrBase;                 // [rsp+0x48] = GT 0x87E
    __int64 Sect88D;                    // rbx / r12
    __int64 Sect896;
    __int64 Sect88F, Sect891, Sect893, Sect895, Sect897, Sect887;
    __int64 Expected;                   // rsi 解引用所得
    __int64 Cur;                        // rbx
    ULONG   Build;
    ULONG64 ProbeLimit;
    __int64 i;

    /* ① 模块基址/大小 */
    ModuleBase = GtRead((GLOBAL_TABLE_INDEX)3);              // 0x140018902
    ModuleSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)2);       // 0x140018911

    /* ② 旧指针值（懒初始化） */
    OldValue = GtRead((GLOBAL_TABLE_INDEX)0x89A);            // 0x140018922
    if (!OldValue)                                           // 0x14001892A
    {
        FindPeExecutableSection();                           // 0x14001892F（call 0x1400164C8）
        OldValue = GtRead((GLOBAL_TABLE_INDEX)0x89A);        // 0x140018936
    }

    /* ③ FltMgr 基址 */
    FltMgrBase = GtRead((GLOBAL_TABLE_INDEX)0x87E);          // 0x140018943

    /* ④ 0x88D 节地址（两者皆空则先初始化） */
    Sect88D = GtRead((GLOBAL_TABLE_INDEX)0x88D);             // 0x140018956
    Sect896 = GtRead((GLOBAL_TABLE_INDEX)0x896);             // 0x140018962（0x88D+9）
    if (!Sect88D && !Sect896)                                // 0x140018967/96C
        InitFsFilterExportTable();                           // 0x140018971（call 0x14001763C）
    Sect88D = GtRead((GLOBAL_TABLE_INDEX)0x88D);             // 0x140018979（r12）

    /* ⑤ 六个 FltMgr 节地址 */
    Sect88F = GtRead((GLOBAL_TABLE_INDEX)0x88F);             // 0x140018986
    Sect891 = GtRead((GLOBAL_TABLE_INDEX)0x891);             // 0x140018995
    Sect893 = GtRead((GLOBAL_TABLE_INDEX)0x893);             // 0x1400189A4
    Sect895 = GtRead((GLOBAL_TABLE_INDEX)0x895);             // 0x1400189B3
    Sect897 = GtRead((GLOBAL_TABLE_INDEX)0x897);             // 0x1400189C2（r15）
    Sect887 = GtRead((GLOBAL_TABLE_INDEX)0x887);             // 0x1400189CF（r13）

    /* ⑥ 前置校验 */
    if (!OldValue || !FltMgrBase || !Sect887)                // 0x1400189D7 / 9E0 / 9EC
        return Result;
    if (!Sect88D && !Sect897)                                // 0x1400189F5/9FA
        return Result;
    if ((ULONG64)OldValue <= (ULONG64)ModuleBase)            // 0x140018A03/0A08
        return Result;
    if ((ULONG64)OldValue >= (ULONG64)ModuleBase + ModuleSize)   // 0x140018A11/0A15/0A18
        return Result;
    if ((ULONG64)OldValue + 8 >= (ULONG64)ModuleBase + ModuleSize)  // 0x140018A21/0A25
        return Result;
    if (!ServicePtr || InputSize != 8)                       // 0x140018A2E / A3C
        return Result;
    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;             // 0x140018A49/0A50
    if ((ULONG64)ServicePtr >= ProbeLimit                    // 0x140018A53
        || (ULONG64)ServicePtr + 8 >= ProbeLimit)            // 0x140018A5C
        return Result;

    /* ⑦ 读取预期旧值 */
    ProbeForRead((PVOID)ServicePtr, 8, 8);                   // 0x140018A6F
    Expected = *(__int64 *)ServicePtr;                       // 0x140018A75
    if ((ULONG64)Expected <= *(ULONG64 *)MmSystemRangeStart)  // 0x140018A7D/0A84/0A87
        return Result;

    /* ⑧ 首槽特判 */
    Cur = *(__int64 *)OldValue;                              // 0x140018A90
    if (Cur == Expected)                                     // 0x140018A93
    {
        *(__int64 *)OldValue = Sect887;                      // 0x140018A98（xchg [r14], r13）
        return 1;
    }
    if (!Cur || (ULONG64)Cur <= *(ULONG64 *)MmSystemRangeStart)  // 0x140018AA0 / AA9
        return Result;
    if (((ULONG64)Cur & 7) != 0)                             // 0x140018AB2
        return Result;

    /* ⑨ 按构建号决定要补几处 */
    Build = (ULONG)GtRead(GtWindowsBuildNumber);             // 0x140018AC4（0x914）

    if (Build >= 0x23F0 && Build < 0x4A61)                   // 0x140018AC9 / ADC
    {
        /* 5 处：偏移 0/8/0x10/0x18/0x20 */
        struct { ULONG Off; __int64 Val; } slots[5] = {
            { 0x00, Sect88D }, { 0x08, Sect897 }, { 0x10, Sect88F },
            { 0x18, Sect891 }, { 0x20, Sect893 }
        };
        for (i = 0; i < 5; ++i)                              // 0x140018AF1..0x140018B8B
        {
            __int64 *p = (__int64 *)(Cur + slots[i].Off);
            if (Expected == *p && slots[i].Val)
            {
                WritePhysicalMemoryQword((unsigned __int64)p, slots[i].Val);   // 0x140018AF7 等
                Result = 1;
            }
            (void)p;
        }
    }
    else if (Build >= 0x4A61)                                // 0x140018AE1
    {
        /* 6 处：偏移 0/8/0x10/0x18/0x20/0x28 */
        struct { ULONG Off; __int64 Val; } slots[6] = {
            { 0x00, Sect88D }, { 0x08, Sect897 }, { 0x10, Sect88F },
            { 0x18, Sect891 }, { 0x20, Sect893 }, { 0x28, Sect895 }
        };
        for (i = 0; i < 6; ++i)                              // 0x140018B90..0x140018C34
        {
            __int64 *p = (__int64 *)(Cur + slots[i].Off);
            if (Expected == *p && slots[i].Val)
            {
                WritePhysicalMemoryQword((unsigned __int64)p, slots[i].Val);
                Result = 1;
            }
        }
    }
    else
    {
        /* 构建号 < 0x23F0：只补首槽 */
        if (Expected == *(__int64 *)Cur && Sect897)          // 0x140018C3D / C42
        {
            WritePhysicalMemoryQword((unsigned __int64)Cur, Sect897);   // 0x140018C4D
            Result = 1;
        }
    }

    return Result;                                           // 0x140018C64
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
// 对应原始驱动 0x140019898（62 字节）
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

// CmdCreateFileForPathAdd — 文件名规范化
// 将 DOS 设备路径（\\.\C:\）转换为 NT 路径（\Device\HarddiskVolume1\），处理设备符号链接
// 对应原始驱动 sub_140019DD8
__int64 *__fastcall CmdCreateFileForPathAdd(__int64 Unknown, __int64 FilePath, char IsAddOperation)
{
    // 【补全空壳 2026-09-29】对应原始驱动 0x140019DD8（199 字节），可反编译（46 行伪码）
    // 【⚠ 修正记录】此前是空壳 `return 1;`，注释称"需要 IopGetDeviceObject 和
    //   IopParseFileName 等内部函数" —— 该判断**错误**。伪代码签名
    //   `f(Unknown, FilePath, IsAddOperation)`：实为"**添加操作**时通过创建文件对象
    //   来设置路径信息"，只用三个 GT 函数指针，无需任何内部函数。
    // 【GT 索引（反汇编实测）】0x432E=创建文件函数、0x41CF=设置信息函数、0x4334=关闭函数
    // 【逻辑】先加互斥锁；若 IsAddOperation == 1 且三个函数指针齐备，构造参数块
    //   （[0]=FilePath、+0x10=48、+0x28=512）调创建函数 → 成功后设置信息(句柄,0) →
    //   关闭句柄；最后释放互斥锁并返回其值。
    int (__fastcall *CreateFileFunc)(__int64 *, __int64, int *, _QWORD *);
    void (__fastcall *SetInfoFunc)(__int64, _QWORD);
    __int64 CloseFuncPtr;
    void (__fastcall *CloseFunc)(__int64);
    _QWORD v10[2];
    int v11;
    __int64 v12;
    __int64 v13;
    int v14;
    _OWORD v15;
    __int64 v16;

    AcquireMiniFilterMutexEx();

    if (IsAddOperation == 1)
    {
        CreateFileFunc = (int (__fastcall *)(__int64 *, __int64, int *, _QWORD *))
            GtRead((GLOBAL_TABLE_INDEX)0x432E);
        SetInfoFunc = (void (__fastcall *)(__int64, _QWORD))
            GtRead((GLOBAL_TABLE_INDEX)0x41CF);
        CloseFuncPtr = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4334);
        CloseFunc = (void (__fastcall *)(__int64))CloseFuncPtr;

        if (CreateFileFunc && SetInfoFunc && CloseFuncPtr)
        {
            v10[1] = 0;
            v12 = 0;
            v13 = 0;
            RtlZeroMemory(&v15, sizeof(v15));
            v10[0] = FilePath;
            v11 = 48;
            v14 = 512;
            if (CreateFileFunc(&v16, 1, &v11, v10) >= 0)
            {
                SetInfoFunc(v16, 0);
                CloseFunc(v16);
            }
        }
    }
    AcquireMiniFilterMutex();
    return (__int64 *)0;   // AcquireMiniFilterMutex 为 void，原函数返回其值
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

// RegisterFormatNameCallback — 注册文件名规范化回调
// 对应原始驱动 sub_14001A030
// 读取全局表 0x41A8 中已解析的回调注册函数，注册 CmdCreateFileForPathAdd 后清零就绪标志 0x8F0
char RegisterFormatNameCallback(void)
{
    char Result;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, char), __int64);

    Result = 0;
    RegisterCallbackFunc = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char), __int64))GtRead(GtTotalSize | GtEprocessField158 | 0x100);
    if (RegisterCallbackFunc)
    {
        RegisterCallbackFunc((__int64 *(__fastcall *)(__int64, __int64, char))CmdCreateFileForPathAdd, 1);
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
            RegisterCallback((__int64 *(__fastcall *)(__int64, __int64, char))CmdCreateFileForPathAdd, 0);
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

#define GT_NOINLINE __declspec(noinline)

// AcquireMiniFilterMutex — 获取 Minifilter 互斥锁
// 对应原始驱动 0x14007182C（72 字节）
// 【⚠ 修正记录 2026-10-13】原实现为 `KeWaitForSingleObject(&g_Mutex,Executive,0,0,0);`
//   —— 与原驱动无关。原始实现在 0x4274/0x4277 两个全局表槽里取出**函数指针**，
//   再以 GtAlloc(0x1FB)（全局互斥体）为参数间接调用其中一个。
//   发现方式：windows-driver-emulation skill 逐函数差分时，原始侧读到 GT 0x4274
//   而我方侧为 0（函数被内联且语义不同）；逐条反汇编核对后确认。
// 【原始汇编】0x14007182C：
//   rbx = GtRead(0x4274)        ; 取函数指针 A
//   rdi = GtRead(0x4277)        ; 取函数指针 B
//   rax = GtAlloc(0x1FB)        ; 全局互斥体
//   if (rbx && rdi) rdi(rax)    ; 本函数调 B
// 【说明】本函数与 AcquireMiniFilterMutexEx 结构完全相同，唯一差异是**调用哪一个**：
//   本函数 `call rdi`（0x4277），Ex 版 `call rbx`（0x4274）。
//   两槽的语义应为「取锁/放锁」一对，槽名待考，故此处以裸索引标注。
// 对应原始驱动 0x14007182C（72 字节）
GT_NOINLINE void AcquireMiniFilterMutex(void)
{
    __int64 FuncA = GtRead((GLOBAL_TABLE_INDEX)0x4274);   // 0x140071836
    __int64 FuncB = GtRead((GLOBAL_TABLE_INDEX)0x4277);   // 0x140071848
    __int64 Mutex = (__int64)GtAlloc(GtGlobalMutex);      // 0x140071855（0x1FB）

    if (FuncA && FuncB)                                   // 0x14007185A/85F
    {
        ((void (__fastcall *)(__int64))FuncB)(Mutex);     // 0x140071867（call rdi）
    }
}

// AcquireMiniFilterMutexEx — 获取 Minifilter 互斥锁（扩展）
// 对应原始驱动 0x140071874（72 字节）
// 【⚠ 修正记录 2026-10-13】同 AcquireMiniFilterMutex：原实现是
//   `KeWaitForSingleObject(...)` 的伪造版，且因函数体简单被 LTCG 内联消除，
//   导致 7 处调用点全部退化为"间接调用一个从未定义的导入桩"。
// 【原始汇编】0x140071874：与 0x14007182C 逐指令相同，仅最后调用不同——
//   `if (rbx && rdi) rbx(rax)`（call rbx = 调 0x4274 处的指针）。
GT_NOINLINE void AcquireMiniFilterMutexEx(void)
{
    __int64 FuncA = GtRead((GLOBAL_TABLE_INDEX)0x4274);   // 0x14007187E
    __int64 FuncB = GtRead((GLOBAL_TABLE_INDEX)0x4277);   // 0x140071890
    __int64 Mutex = (__int64)GtAlloc(GtGlobalMutex);      // 0x14007189D（0x1FB）

    if (FuncA && FuncB)                                   // 0x1400718A2/8A7
    {
        ((void (__fastcall *)(__int64))FuncA)(Mutex);     // 0x1400718AF（call rbx）
    }
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
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
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

// ParseNtImageSections — 解析 NT/fltmgr 镜像节区并填充全局表
// 对应原始驱动 0x1400166EC（3005 字节 / 807 条指令）
// 【逆向来源】人工阅读 capstone + IDA 反汇编**逐条转写** —— IDA `decompile` 返回 None
//   （属 91 个不可反编译函数之一，已复验），故走"读反汇编 → 按寄存器/栈槽归属转写"。
//   代码内以 `L_<原始地址>` 标注各基本块，便于逐块回查。
//
// 【帧定基（原始序言）】
//   mov rax,rsp → push rbp,r12,r13,r14,r15(0x28) → lea rbp,[rax-0x168] → sub rsp,0x240
//   故 rbp = 入口 rsp - 0x168，rbp = rsp + 0x100。
//   - 节区描述符（ReadPESectionEntry 输出，0x120 字节）基址 = rbp-0x30，即 desc+N ≡ rbp+(N-0x30)
//   - PE_DECODE_CONTEXT（0x48 字节）基址 = rbp-0x80
//   - 读取上下文 +0x08（读指针）= [rbp-0x78]，由主循环按 desc+0xF0（指令长度）推进
//   - Dst[0x10]（ULONG）基址 = rbp+0xF0（= 描述符 +0x120 之后）
//   【11 处锚点自洽】desc+0x50/0x58/0x70/0x74/0x78/0x88/0x90/0xD8/0xDC/0xF0/0x118
//   分别对应 [rbp+0x20/0x28/0x40/0x44/0x48/0x58/0x60/0xA8/0xAC/0xC0/0xE8]，
//   反解基址全部 = rbp-0x30 —— 描述符布局与 ReadPESectionEntry 的 0x120 字节定义一致。
//
// 【rsp 内联槽（非叶帧；按函数内自洽 + 角色命名）】
//   +0x40 CtxTableVal  +0x44 Flag44(0x42A)  +0x45 Flag45(FMdi)  +0x46 Flag46(数据节偏移已写)
//   +0x48 SavedEsi     +0x4C CtxDupVal      +0x50 SavedEsi2
//   +0x54 SkipCount    +0x58 Flag58         +0x5C DataSectionOfs
//   +0x60 Counter60    +0x64 IterCount      +0x68 SavedEbx
//   +0x70 MainTable(=GtAlloc 0x1EC8)        +0x78 FillTable(=GtAlloc 0x1F76)
//
// 【闭环自校验】本函数 0x14001672E 读 GtFltmgrBase(0x87E) 作模块基址，该槽由本函数之前的
//   InitFltmgrBase 系列写入（DriverStartup: 先探 fltmgr → 再解析节区），属完整初始化链成员。

#define DSC32(o)  (*(ULONG   *)(Desc + (o)))
#define DSC64(o)  (*(ULONG64 *)(Desc + (o)))

// 对应原始驱动 0x1400166EC（3005 字节）
__int64 ParseNtImageSections(PUCHAR ImageBase, ULONG ImageSize)
{
    UCHAR  DescBuf[0x120];          // rbp-0x30：节区描述符
    PUCHAR Desc = DescBuf;
    ULONG  CumulativeSize;          // rbp-0x78：= 读取上下文 +0x08（读指针）
    PE_DECODE_CONTEXT ReadContext;  // rbp-0x80：PE 读取上下文（0x48 字节）
    ULONG  Dst[0x10];               // rbp+0xF0

    ULONG  CtxTableVal;             // +0x40
    ULONG  Flag44;                  // +0x44
    ULONG  Flag45;                  // +0x45
    ULONG  Flag46;                  // +0x46
    ULONG  SavedEsi;                // +0x48
    ULONG  CtxDupVal;               // +0x4C
    ULONG  SavedEsi2;               // +0x50
    ULONG  SkipCount;               // +0x54
    ULONG  Flag58;                  // +0x58
    ULONG  DataSectionOfs;          // +0x5C
    ULONG  Counter60;               // +0x60
    ULONG  IterCount;               // +0x64
    ULONG  SavedEbx;                // +0x68
    __int64 MainTable;              // +0x70 = GtAlloc(0x1EC8)
    __int64 FillTable;              // +0x78 = GtAlloc(0x1F76)

    __int64 FltMgrBase;             // r13
    __int64 ImageBaseVal;           // r15：可选头优先基址
    ULONG  ChunkBase;               // ebx：阶段 1 求出的扫描起点
    ULONG  EntryPoint;              // ebx：AddressOfEntryPoint
    ULONG  SectionType;             // ecx / r8w
    ULONG  Ofs;                     // ecx：候选偏移
    ULONG  BuildNumber;
    ULONG  ScanIndex;
    ULONG  i;
    ULONG  t;
    UCHAR  InitSeen;                // dil：阶段 1 的 0x510 命中标志
    ULONG64 Val64;                  // 无符号比较（对应 cmp/jbe/jae）
    __int64 Row;

    memset(&ReadContext, 0, sizeof(ReadContext));
    RtlZeroMemory(Dst, sizeof(Dst));
    CumulativeSize = 0;
    ChunkBase = 0;
    InitSeen = 0;

    FltMgrBase = GtRead(GtFltmgrBase);                          // 0x14001672E  ecx=0x87E
    MainTable  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1EC8);  // 0x14001673B
    FillTable  = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0x1F76);  // 0x14001674A

    if (!FltMgrBase)                                            // 0x140016757
        return 0;

    // PE 头：AddressOfEntryPoint(NT+0x28) 与 ImageBase(NT+0x30)
    // 【关键】原始读的是 AddressOfEntryPoint，**不是 SizeOfCode**（0x140016761）。
    Row = (__int64)(ImageBase + *(LONG *)(ImageBase + 0x3C));
    EntryPoint   = *(ULONG *)(Row + 0x28);
    ImageBaseVal = *(__int64 *)(Row + 0x30);

    // ===== 阶段 1：在 AddressOfEntryPoint 处扫 INIT(0x559) 定 ChunkBase =====
    if (EntryPoint < ImageSize && EntryPoint + 0x1000 < ImageSize)   // 0x14001676B/77A
    {
        InitPESectionReadContext(
            (__int64)(ImageBase + EntryPoint),
            ImageSize - ((ULONG)(ULONG_PTR)ImageBase + EntryPoint) + 0x1000 + EntryPoint,
            2, 0, -1, 0, 0, (__int64)&ReadContext);             // 0x1400167B8

        for (ScanIndex = 0; ScanIndex < 20; ++ScanIndex)        // 0x1400167BF  cmp esi,14h
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)&Desc + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc))   // 0x1400167C7
                break;

            CumulativeSize += DSC32(0xF0);                      // 0x1400167D4/DE
            SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);      // 0x1400167EC
            Ofs = (ULONG)ImageBaseVal + CumulativeSize;         // 0x1400167FA
            Ofs -= (ULONG)(ULONG_PTR)ImageBase;

            if (SectionType == 0x559)                           // 0x1400167F5
            {
                if (Ofs != 0 && Ofs < ImageSize)                // 0x140016802/807
                    ChunkBase = Ofs;                            // 0x14001685E
            }
            else if (SectionType == 0x510)                      // 0x140016824
            {
                if (DSC64(0x50) == 0x40UL && DSC32(0x58) == 1)  // 0x140016829/830
                    InitSeen = 1;                               // 0x140016836
            }
            else if (SectionType == 0x558)                      // 0x140016840
            {
                if (InitSeen == 1)                              // 0x140016845
                {
                    if (Ofs != 0 && Ofs < ImageSize)            // 0x14001684A~857
                    {
                        ChunkBase = Ofs;
                        break;                                  // 0x14001685E
                    }
                    InitSeen = 0;                               // 0x140016859
                }
                else
                {
                    InitSeen = 0;
                }
            }
        }
    }

    if (!ChunkBase || ChunkBase >= ImageSize || ChunkBase + 0x1000 >= ImageSize)
        return 0;                                               // 0x140016862/86B/87A

    // ===== 阶段 2 =====
    memset(Dst, 0, sizeof(Dst));                                // 0x1400168E1
    CtxTableVal = 0;  Flag44 = 0;  Flag45 = 0;  Flag46 = 0;     // 0x1400168D3~906
    SavedEsi = 0;     SavedEsi2 = 0;  CtxDupVal = 0;
    SkipCount = 0;    Flag58 = 0;     DataSectionOfs = 0;
    Counter60 = 0;    IterCount = 0;  SavedEbx = 0;
    CumulativeSize = 0;

    InitPESectionReadContext(
        (__int64)(ImageBase + ChunkBase),
        ImageSize - ((ULONG)(ULONG_PTR)ImageBase + ChunkBase) + 0x1000 + ChunkBase,
        2, 0, -1, 0, 0, (__int64)&ReadContext);                 // 0x1400168B3

    for (;;)
    {
        if (ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)Desc))   // L_190A  0x140016912
            return 0;

        CumulativeSize += DSC32(0xF0);                          // 0x140016925
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016930

        // ---- 0x558：数据节偏移登记（写 0x884） ----
        if (SectionType == 0x558)                               // 0x140016939
        {
            if (Flag46 == 0)                                    // 0x14001693E
            {
                ++Counter60;                                    // 0x140016952
                if (Counter60 == 1 && DataSectionOfs != 0)      // 0x140016958/960
                {
                    GtWrite(GtFltDataSectionOffset,
                            DataSectionOfs + FltMgrBase);       // 0x14001696D  0x884
                    Flag46 = 1;                                 // 0x140016978
                }
            }
            DataSectionOfs = 0;                                 // 0x14001697D
        }
        // ---- 0x512：候选偏移登记 ----
        else if (SectionType == 0x512                           // 0x140016984
                 && DSC64(0x88) == 0x40000UL && DSC32(0x78) != 0
                 && DSC64(0x50) == 0x40UL && DSC32(0x58) == 1)  // 0x14001698E~AE
        {
            t = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;  // 0x1400169B0
            if (t != 0)                                         // 0x1400169B6
            {
                if (t < ImageSize)                              // 0x1400169BC
                    DataSectionOfs = t;                         // 0x1400169BF cmovb
            }
            Counter60 = 0;                                      // 0x1400169C8
        }

        if (IterCount >= 0x32)                                  // 0x1400169CC
            goto L_1DBF;

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x1400169DC
        if (BuildNumber >= 0x4A61)                              // 0x1400169ED
            goto L_1A9B;

        // ---------- build < 0x4A61 ----------
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x1400169F3
        if (SectionType == 0x42A && DSC64(0x50) == 1)           // 0x1400169FC/0A06
        {
            Flag44 = 1;                                         // 0x140016A0C
            goto L_17222;                                       // 0x140016A10
        }
        if (SectionType == 0x50E && DSC64(0x50) == 0x40000UL    // 0x140016A1B~30
            && DSC64(0x88) == 0x20UL)
        {
            Flag44 = 1;                                         // 0x140016A32
            goto L_17222;                                       // 0x140016A3C
        }
        if (Flag44 == 1)                                        // 0x140016A41
        {
            if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
                && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL
                && DSC32(0x58) == 1)                            // 0x140016A4B~80
            {
                Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
                if (Ofs != 0 && Ofs < ImageSize)                // 0x140016A88/8D
                {
                    if (SavedEbx == 0)                          // 0x140016A8F
                    {
                        SavedEbx = Ofs;                         // 0x140016A93
                        CtxTableVal = Ofs;                      // 0x140016A95
                    }
                    else
                    {
                        goto L_1B05;                            // 0x140016A91
                    }
                }
            }
        }
        goto L_1AFD;                                            // 0x140016AFD

    L_1A9B:                                                     // build >= 0x4A61
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016A9B
        if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
            && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL
            && DSC32(0x58) == 1)                                // 0x140016AA4~C9
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
            if (Ofs != 0 && Ofs < ImageSize)                    // 0x140016AD1/D6
                SavedEbx = Ofs;                                 // 0x140016AD8
            goto L_1AFD;
        }
        if ((USHORT)(SectionType - 0x473) <= 1)                 // 0x140016ADE~EE
        {
            CtxTableVal = SavedEbx;                             // 0x140016AF6 cmovne + 0x140016AF9
        }

    L_1AFD:
        if (SavedEbx == 0)                                      // 0x140016AFD
            goto L_1DBF;

    L_1B05:
        if (GtRead(GtFltPeSectionOfs0) != 0)                    // 0x140016B0A  0x886
            goto L_1DBF;

        GtWrite(GtFltPeSectionOfs0,  SavedEbx);                 // 0x140016B21
        GtWrite(GtFltPeSectionAddr0, FltMgrBase + SavedEbx);    // 0x140016B2F

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140016B3B
        if (BuildNumber < 0x23F0)                               // 0x140016B40
            goto L_1D7F;

        if ((ULONG)(SavedEbx + 0x30) >= ImageSize)              // 0x140016B4F
            goto L_1DBF;

        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140016B5A
        if (BuildNumber >= 0x4A61)                              // 0x140016B68
            goto L_1C76;

        // 0x23F0 <= build < 0x4A61：偏移 0/8/0x10/0x18/0x20 → 0x88C,0x88E,0x890,0x892,0x894
        // (0x140016B5F..0x140016C34，五段展开)
        Val64 = *(__int64 *)(ImageBase + SavedEbx);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs3, Ofs);  GtWrite(GtFltPeSectionAddr3, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 8);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs4, Ofs);  GtWrite(GtFltPeSectionAddr4, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x10);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs5, Ofs);  GtWrite(GtFltPeSectionAddr5, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x18);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs6, Ofs);  GtWrite(GtFltPeSectionAddr6, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x20);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs7, Ofs);  GtWrite(GtFltPeSectionAddr7, FltMgrBase + Ofs);
        }
        goto L_1DBF;                                            // 0x140016C6D

    L_1C76:                                                     // build >= 0x4A61
        // 偏移 0/8/0x10/0x18/0x20/0x28 → 0x88C,0x896,0x88E,0x890,0x892,0x894
        Val64 = *(__int64 *)(ImageBase + SavedEbx);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs3, Ofs);  GtWrite(GtFltPeSectionAddr3, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 8);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs8, Ofs);  GtWrite(GtFltPeSectionAddr8, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x10);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs4, Ofs);  GtWrite(GtFltPeSectionAddr4, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x18);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs5, Ofs);  GtWrite(GtFltPeSectionAddr5, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x20);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs6, Ofs);  GtWrite(GtFltPeSectionAddr6, FltMgrBase + Ofs);
        }
        Val64 = *(__int64 *)(ImageBase + SavedEbx + 0x28);
        if (Val64 > (ULONG64)ImageBaseVal && Val64 < (ULONG64)(ImageBaseVal + ImageSize))
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs7, Ofs);  GtWrite(GtFltPeSectionAddr7, FltMgrBase + Ofs);
        }
        goto L_1DBF;                                            // 0x140016C6D

    L_1D7F:                                                     // build < 0x23F0
        if ((ULONG)(SavedEbx + 8) >= ImageSize)                 // 0x140016D83
            goto L_1DBF;
        Val64 = *(__int64 *)(ImageBase + SavedEbx);             // 0x140016D88
        if (Val64 > (ULONG64)ImageBaseVal
            && Val64 < (ULONG64)(ImageBaseVal + ImageSize))     // 0x140016D8C~98
        {
            Ofs = (ULONG)(Val64 - (ULONG64)ImageBaseVal);
            GtWrite(GtFltPeSectionOfs8, Ofs);                   // 0x140016DA8  0x896
            GtWrite(GtFltPeSectionAddr8, FltMgrBase + Ofs);     // 0x140016DB6  0x897
        }

    // ===== 0x53C / 0x473 / 0x50E / 0x53D 段 =====
    L_1DBF:                                                     // 0x140016DBF
        SectionType = *(USHORT *)((__int64)DSC64(0x118) + 6);   // 0x140016DC6
        if (SectionType == 0x53C                                 // 0x140016DD0
            && DSC32(0x70) == 0x69664D46UL                       // "FMdi"
            && DSC32(0x74) == 0)                                 // 0x140016DE1/DE7
        {
            Flag45 = 1;                                          // 0x140016DF6
            // 落到 SkipCount 判定
        }
        else if ((USHORT)(SectionType - 0x473) <= 1)             // 0x140016EF9~F0D
        {
            if (Flag45 == 1)                                     // 0x140016F13~F21
                SkipCount = 1;
        }

        if (SkipCount != 0)                                      // 0x140016DFE
            goto L_1700C;

        // ---------- SkipCount == 0 主体 ----------
        // 0x512 → Dst 填
        if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL     // 0x140016E06~27
            && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL)
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;  // 0x140016E2B
            if (Ofs != 0 && Ofs < ImageSize)                     // 0x140016E2F/34
            {
                i = DSC32(0x58);                                 // 0x140016E36
                if (i < 0x10)                                    // 0x140016E39
                    Dst[i] = Ofs;                                // 0x140016E3E
            }
        }

        // 0x50E → 以 Dst[desc+0x90] 填 MainTable 的 28 组（步长 0x30）
        if (SectionType == 0x50E                                 // 0x140016E58
            && (DSC32(0xD8) & 0x300) == 0x100                    // 0x140016E62~71
            && DSC32(0x40) == 0x70                               // 0x140016E7C
            && (DSC32(0xDC) & 0x300) == 0x300                    // 0x140016E85~8A
            && DSC64(0x88) == 0x40UL                             // 0x140016E93
            && DSC32(0x90) < 0x10)                               // 0x140016E9E
        {
            if (CtxDupVal == 0)                                  // 0x140016EA8
            {
                Ofs = Dst[DSC32(0x90)];                          // 0x140016EB3
                CtxDupVal = Ofs;                                 // 0x140016EBB
                if (Ofs != 0 && Ofs < ImageSize)                 // 0x140016EBF/CB
                {
                    Row = MainTable + 4;                         // 0x140016ED0
                    for (i = 0x1C; i != 0; --i)                  // 0x140016EE1 循环 28 次
                    {
                        *(ULONG *)Row = Ofs;                     // 0x140016EE1
                        *(__int64 *)(Row + 4) = FltMgrBase + Ofs;// 0x140016EE4
                        Row += 0x30;
                    }
                }
            }
            SavedEbx = CtxTableVal;                              // 0x140016EF0
            goto L_17222;
        }

        // 0x53D → 以 desc+0xF0 填 MainTable 的 28 组
        if (SectionType == 0x53D                                 // 0x140016F2A
            && DSC64(0x50) == 0x20UL                             // 0x140016F35
            && DSC64(0x70) == 0x1CUL                             // 0x140016F3C
            && CtxDupVal == 0)                                   // 0x140016F43
        {
            Ofs = DSC32(0xF0);                                   // 0x140016F4A
            CtxDupVal = Ofs;                                     // 0x140016F51
            if (Ofs != 0 && Ofs < ImageSize)                     // 0x140016F56/F5B
            {
                Row = MainTable + 4;                             // 0x140016F60
                for (i = 0x1C; i != 0; --i)                      // 0x140016F72 循环 28 次
                {
                    *(ULONG *)Row = Ofs;
                    *(__int64 *)(Row + 4) = FltMgrBase + Ofs;
                    Row += 0x30;
                }
            }
            SavedEbx = CtxTableVal;                              // 0x140016F82
            goto L_16A36;
        }

        // 0x50E → MainTable 行槽回填（槽非零且等于 CtxDupVal 时才写）
        if (SectionType == 0x50E                                 // 0x140016F8B
            && (DSC64(0x50) & 0x14000UL)                         // 0x140016F91/95
            && (DSC64(0x50) & 0x40UL)                            // 0x140016F9D
            && (DSC32(0xDC) & 0xF) != 4                          // 0x140016FA1~A7
            && DSC64(0x88) == 0x40UL                             // 0x140016FA9
            && (DSC32(0x40) - 0x70) <= 0xD8                      // 0x140016FB0~B9
            && (DSC32(0x40) & 7) == 0                            // 0x140016FBB~C0
            && ((DSC32(0x40) - 0x70) >> 3) <= 0x1B)              // 0x140016FC2~C8
        {
            Ofs = Dst[DSC32(0x90)];                              // 0x140016FCA
            if (Ofs != 0)                                        // 0x140016FD2
            {
                i = (DSC32(0x40) - 0x70) >> 3;                   // 0x140016FC2
                Row = MainTable + 0x30 * i;                      // 0x140016FDB~DF
                if (*(ULONG *)(Row + 4) != 0)                    // 0x140016FE2
                {
                    if (*(ULONG *)(Row + 4) == CtxDupVal)        // 0x140016FEF
                    {
                        *(ULONG *)(Row + 4)   = Ofs;             // 0x140016FFD
                        *(__int64 *)(Row + 8) = FltMgrBase + Ofs;// 0x140017002
                    }
                }
                goto L_17222;
            }
        }
        SavedEbx = CtxTableVal;                                  // 0x140016F82
        goto L_17222;

    L_1700C:                                                     // SkipCount != 0   0x14001700C
        if (Flag58 == 0)                                         // 0x140017010
        {
            // 0x512 → Dst 填
            if (SectionType == 0x512 && DSC64(0x88) == 0x40000UL
                && DSC32(0x78) != 0 && DSC64(0x50) == 0x40UL)    // 0x140017018~39
            {
                Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize;
                if (Ofs != 0 && Ofs < ImageSize)                 // 0x140017041/47
                {
                    i = DSC32(0x58);
                    if (i < 0x10)                                // 0x140017053
                        Dst[i] = Ofs;                            // 0x140017058
                }
            }
            // 0x50E → 填 FillTable（无条件写）
            if (SectionType == 0x50E                              // 0x140017061
                && (DSC64(0x50) & 0x14000UL)                      // 0x14001706C
                && (DSC64(0x50) & 0x40UL)                         // 0x140017078
                && (DSC32(0xDC) & 0xF) != 4                       // 0x140017082~87
                && DSC64(0x88) == 0x40UL                          // 0x140017089
                && (DSC32(0x40) - 8) <= 0xB8                      // 0x140017090~9C
                && (DSC32(0x40) & 7) == 0                         // 0x14001709E~A3
                && ((DSC32(0x40) - 8) >> 3) < 0x1B)               // 0x1400170A5~AB
            {
                Ofs = Dst[DSC32(0x90)];                           // 0x1400170AD/B0
                if (Ofs != 0)                                     // 0x1400170B7
                {
                    i = (DSC32(0x40) - 8) >> 3;
                    Row = FillTable + 0x30 * i;                   // 0x1400170BB~C8
                    *(ULONG *)(Row + 4)   = Ofs;                  // 0x1400170CB
                    *(__int64 *)(Row + 8) = FltMgrBase + Ofs;     // 0x1400170D0
                }
            }
        }

        // ---- 版本标志：决定 Flag58 ----
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);        // 0x1400170DA
        if (BuildNumber >= 0x4A61)                                // 0x1400170EB
        {
            if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x50E    // 0x14001712B
                && (DSC64(0x50) & 0x10000UL) == 0x10000UL         // 0x140017131
                && (DSC64(0x50) & 0x40UL) == 0x40UL)              // 0x14001713B
            {
                if (DSC64(0x88) == 0x40UL)                        // 0x140017141
                    Flag58 = (DSC32(0x40) == 0xB8) ? 1 : 0;       // 0x14001714E cmove
                else
                    Flag58 = 0;                                   // 0x140017164
            }
            else
            {
                Flag58 = 0;
            }
        }
        else
        {
            if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x547)  // 0x1400170F2
            {
                BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
                Flag58 = (BuildNumber >= 0x3AD7)
                         ? ((DSC64(0x70) == 0x78UL) ? 1 : 0)      // 0x14001711F
                         : ((DSC64(0x70) == 0x68UL) ? 1 : 0);     // 0x14001710F
            }
            else
            {
                Flag58 = 0;                                       // 0x14001715E
            }
        }

        if (Flag58 != 1)                                          // 0x140017164
            goto L_16EF0;

        // ---- Flag58 == 1：登记 0x888 / 0x88A 候选 ----
        if (*(USHORT *)((__int64)DSC64(0x118) + 6) == 0x512       // 0x14001717D
            && DSC64(0x88) == 0x40000UL && DSC32(0x78) != 0
            && DSC64(0x50) == 0x40UL)                             // 0x14001718C~95
        {
            Ofs = DSC32(0x78) - (ULONG)(ULONG_PTR)ImageBase + CumulativeSize; // 0x140017197
            if (Ofs != 0 && Ofs < ImageSize)                      // 0x14001719D/A2
            {
                BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
                if (BuildNumber >= 0x4A61 && BuildNumber <= 0x4F7C)   // 0x1400171AE/BF
                {
                    if (SavedEsi == 0)                            // 0x1400171C6
                    {
                        if (Dst[1] != 0)                          // 0x1400171CA
                            SavedEsi = Dst[1];                    // 0x1400171D2
                    }
                    if (SavedEsi2 == 0)                           // 0x1400171D9
                        SavedEsi2 = Ofs;                          // 0x1400171DD
                }
                else if (BuildNumber >= 0x4A61)                   // 0x1400171E5
                {
                    if (SavedEsi == 0)
                        SavedEsi = Ofs;                           // 0x1400171E9
                }
                else                                              // 0x1400171F1
                {
                    if (SavedEsi == 0)
                        SavedEsi = Ofs;
                    else if (SavedEsi2 == 0 && Ofs != SavedEsi)   // 0x1400171F5
                        SavedEsi2 = Ofs;                          // 0x1400171F7
                }
            }
        }

    L_16EF0:                                                      // 0x140016EF0
        SavedEbx = CtxTableVal;
        goto L_17222;

    L_16A36:                                                      // 0x140016A36
        goto L_17222;

    L_17222:                                                      // 0x14001721F / 0x140017222
        ++IterCount;                                              // 0x140017226
        if (IterCount >= 0x1F4)                                   // 0x14001722D
            return 0;

        // 0x1400171FE：类型为 0x473/0x474 时收尾写 0x888 / 0x88A
        if ((USHORT)(*(USHORT *)((__int64)DSC64(0x118) + 6) - 0x473) <= 1)  // 0x140017209
        {
            if (SavedEsi2 != 0 && SavedEsi != 0)                  // 0x14001723B/23F
            {
                GtWrite(GtFltPeSectionOfs1,  SavedEsi);           // 0x14001724A  0x888
                GtWrite(GtFltPeSectionAddr1, FltMgrBase + SavedEsi);
                GtWrite(GtFltPeSectionOfs2,  SavedEsi2);          // 0x140017266  0x88A
                GtWrite(GtFltPeSectionAddr2, FltMgrBase + SavedEsi2);
            }
            return 0;
        }
        SavedEbx = CtxTableVal;                                   // 0x14001721B
    }
}
#undef DSC32
#undef DSC64

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
// OpenWin32kSysSection — 打开 win32k 的节对象
// 对应原始驱动 0x1400174F8（124 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：读 GtWin32kBase / GtWin32kSize
//   做有效性检查后直接返回基址。注释称"返回 Win32k 基址作为节对象句柄"，
//   与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始读 GT 0x421D（= GtRtlInitUnicodeStringFunc）而我方读 0x80F；
//   逐条反汇编核对后确认（原始函数体里根本没有 GtRead）。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x1400174F8（全部指令）：
//   sub rsp,0x58 ; 存入 stack cookie
//   [rsp+0x44] = 0                          ; 第 5 个栈参 = 0
//   rcx = [rsp+0x20]                        ; 指向待构造的 Unicode 缓冲
//   依次写入 9 个 DWORD，拼出 L"\FileSystem\FltMgr"（18 个字符）：
//     0x46005C 0x6C0069 0x530065 0x730079 0x650074
//     0x5C006D 0x6C0046 0x4D0074 0x720067
//   call 0x140078F48                        ; = OpenFileSection(缓冲)
//   校验 stack cookie ; add rsp,0x58 ; ret
// 【说明】本函数**不访问全局表**：差分里看到的 GT 0x421D 读
//   发生在被调用的 OpenFileSection（0x140078F48）内部——
//   后者开头即读 0x421D/0x421A/0x4223/0x4160 四个函数指针槽
//   （= GtRtlInitUnicodeStringFunc / GtIoCreateFileFunc /
//      GtCloseHandleFunc / GtDriverObjectListHead，枚举值已逐一核对吻合）。
// 【返回值】OpenFileSection 的返回值（文件节对象句柄；失败为 0）。
// 对应原始驱动 0x1400174F8（124 字节）
__int64 OpenWin32kSysSection(void)
{
    WCHAR PathBuffer[20];

    // L"\FileSystem\FltMgr" —— 与原始驱动逐 DWORD 一致（9 个 DWORD = 18 字符）
    PathBuffer[0] = 0x005C; PathBuffer[1] = 0x0046;   // backslash,F
    PathBuffer[2] = 0x0069; PathBuffer[3] = 0x006C;   // il
    PathBuffer[4] = 0x0065; PathBuffer[5] = 0x0053;   // eS
    PathBuffer[6] = 0x0079; PathBuffer[7] = 0x0073;   // ys
    PathBuffer[8] = 0x0074; PathBuffer[9] = 0x0065;   // te
    PathBuffer[10] = 0x006D; PathBuffer[11] = 0x005C; // m,backslash
    PathBuffer[12] = 0x0046; PathBuffer[13] = 0x006C; // F,l
    PathBuffer[14] = 0x0074; PathBuffer[15] = 0x004D; // tM
    PathBuffer[16] = 0x0067; PathBuffer[17] = 0x0072; // gr
    PathBuffer[18] = 0;                               // 结尾（原始 [rsp+0x44]=0）

    return OpenFileSection((__int64)PathBuffer);      // 0x14001755D
}

// UnregisterCommPortCallback — 取消注册通信端口回调
// 对应原始驱动 0x140019A0C（53 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：
//   读 GtCommPortCallbackReady(=0x8F2) 后置 0 返回 1。与原始无关。
//   发现方式：差分报原始读 GT **0x42D1**（函数指针槽）。
// 【原始逻辑】取 GT 0x42D1 的函数指针，若非 0 则
//   以 `*（某个内核对象，见 rip+0xB39EE）` 为参数调用它；
//   返回值 >= 0 则置 1（`cmovns`）。
//   本函数**不写入任何 GT**。
// 对应原始驱动 0x140019A0C（53 字节）
__int64 UnregisterCommPortCallback(void)
{
    char Result = 0;
    __int64 (*Callback)(void *);
    void   *Argument;

    Callback = (__int64 (*)(void *))GtRead((GLOBAL_TABLE_INDEX)0x42D1);   // 0x140019A19
    if (!Callback)                                                        // 0x140019A1E
        return Result;

    Argument = &g_CommPortContext;                                        // 0x140019A23（rip+0xB39EE → g_CommPortContext）
    if (Callback(Argument) >= 0)                                          // 0x140019A2A/36（cmovns）
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

// MiniFilterCommPortReply — 通信端口回复（0x140019344）
// 对应原始驱动 0x140019344（105 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：
//     `if (!GtRead(GtCommPortCallbackReady)) return STATUS_DEVICE_NOT_READY; return STATUS_SUCCESS;`
//   注释称"需要 IRP 或命名管道上下文"，与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始不读任何 GT 而我方读 0x8F2；反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x140019344：
//   rdi = r8（用户缓冲）；bl = 0（结果）
//   rcx = *MmUserProbeAddress
//   ① r8 >= rcx        → 返回 0     ; 越界
//   ② r8 == 0          → 返回 0     ; 空指针
//   ③ r8+4 >= rcx      → 返回 0     ; 4 字节写入会越界
//   ④ r9d != 4         → 返回 0     ; 输入长度必须为 4
//   ProbeForWrite(r8, 4, 4)          ; 校验可写
//   ⑤ *rdi = (*(volatile ULONG64*)0x1400A84D9 != 0)   ; 注意：直接读绝对地址
//   返回 1
// 【说明】第 ⑤ 步读的 **不是** GT 表，而是绝对地址 0x1400A84D9
//   （反汇编 `cmp qword ptr [rip+0x8f151], rbx`，rbx=0），
//   这是原驱动自己的一个全局标志，不经过 GtRead —— 故运行时 GT 序列为空。
__int64 MiniFilterCommPortReply(__int64 Address, __int64 Length, _DWORD *Output, int OutputSize)
{
    char   Result = 0;
    ULONG64 ProbeLimit;

    _DWORD *OutPtr = (_DWORD *)Address;               // rdi = r8（原始把 r8 视作输出缓冲）

    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;      // rcx = *MmUserProbeAddress
    if ((unsigned __int64)Address >= ProbeLimit        // 0x140019361
        || Address == 0                                // 0x140019366
        || (unsigned __int64)Address + 4 >= ProbeLimit  // 0x14001936F
        || OutputSize != 4)                            // 0x140019377
        return 0;

    ProbeForWrite((PVOID)Address, 4, 4);               // 0x140019382

    *OutPtr = (*(volatile ULONG64 *)0x1400A84D9 != 0) ? 1 : 0;   // 0x140019388/38F/392
    Result = 1;                                        // 0x140019394
    return Result;
}

// RegisterFormatPathCallback — 注册带路径的文件名格式化回调
// 对应原始驱动 sub_14001A068
// 读取全局表 0x41BA 中已解析的回调注册函数，注册 MiniFilterFilterUnload 后清零就绪标志 0x8F1
char RegisterFormatPathCallback(void)
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

// MiniFilterFormatFileNameWithContext — 注册 MiniFilter 回调（补全空壳）
// 对应原始驱动 0x14001A0E8（69 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（18 行伪代码），按伪代码实现
// 【⚠ 修正记录】此前注释写"需要 FLT_CALLBACK_DATA 上下文获取文件名，无法实现" ——
//   该判断**错误**：伪代码显示本函数**无参数**，实际是"一次性注册回调"：
//   若 GT (GtMiniFilterFormatNameExReady) 未置位，则取注册函数指针
//   (GtTotalSize|GtEprocessField155|0x100) 注册 MiniFilterFilterUnload，然后置位并返回 1。
// 【命名说明】名字与实际功能（注册回调）不符，与 MiniFilterCommPortConnect 同族；
//   改名归入命名轮，此处先按伪代码补全实现。
// 对应原始驱动 0x14001A0E8（69 字节）
__int64 MiniFilterFormatFileNameWithContext(void)
{
    char Result = 0;
    void (__fastcall *RegisterFunc)(__int64 *(__fastcall *)(__int64, __int64, char));

    if (!(unsigned int)GtRead(GtMiniFilterFormatNameExReady))
    {
        RegisterFunc = (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, char)))
            GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField155 | 0x100));
        if (RegisterFunc)
        {
            RegisterFunc(MiniFilterFilterUnload);
            GtWrite(GtMiniFilterFormatNameExReady, 1);
            return 1;
        }
    }
    return Result;
}

// MiniFilterFormatFileNameEx — 查询"文件名格式化就绪"标志（补全空壳）
// 对应原始驱动 0x14001A130（110 字节）
// 【逆向来源】⚠ 可反编译（17 行伪代码）
// 【⚠ 修正记录】此前注释写"需要 FltGetStreamFileObjectContext 获取文件名" —— **错误**。
//   实际：校验输出缓冲可写且 BufferSize == 4 → ProbeForWrite
//   → 把 GT (GtMiniFilterFormatNameReady) 是否非 0 作为结果写回输出缓冲 → 返回 1。
// 对应原始驱动 0x14001A130（110 字节）
__int64 MiniFilterFormatFileNameEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
    int Result = 0;

    if ((unsigned __int64)OutputBuffer < MmUserProbeAddress && OutputBuffer &&
        (unsigned __int64)OutputBuffer + 1 < MmUserProbeAddress && BufferSize == 4)
    {
        ProbeForWrite(OutputBuffer, 4u, 4u);
        Result = (int)((unsigned int)GtRead(GtMiniFilterFormatNameReady) != 0);
        *OutputBuffer = Result;
        Result = 1;
    }
    return Result;
}

// MiniFilterNormalizeName — 规范化对象名并解除只读映射
// 对应原始驱动 0x140019DD8（199 字节）
// 【逆向来源】人工阅读 capstone 反汇编**逐条转写** —— IDA `decompile` 返回 None
//   （属 91 个不可反编译函数之一），故走"读反汇编 → 按寄存器/栈槽归属转写"。
//   本函数此前在源码中**完全缺失**（被 _FINAL_GAP.json 误归为"占位"）。
// 【帧定基】`mov rbp,rsp`（标准帧）→ push rbp,rdi,r14 → `sub rsp,0x60`
//   故 rbp = 推送 rbp 后的 rsp；形参 arg_38 位于 [rbp+0x38]。
// 【算法】
//   1) AcquireMiniFilterMutexEx()（0x140071874）取互斥；
//   2) 若第 3 参（bl = r8b）== 1：
//        取 3 个函数指针 —— GtRead(0x432E)、GtRead(0x41CF)、GtRead(0x4334)；
//        任一为 0 则跳过整段；
//        否则在栈上布置 { [rbp-0x30]=0x30, [rbp-0x18]=0x200, 其余槽清零 }，
//        以 (rcx=[rbp+0x38], edx=1, r8=[rbp-0x30], r9=[rbp-0x40]) 调 FnQuery(0x432E)；
//        返回非负则调用 FnUnmap(0x41CF)(查询结果, 0) 卸载，再 FnFree(0x4334)(结果) 释放；
//   3) AcquireMiniFilterMutex()（0x14007182C）释放互斥。
void MiniFilterNormalizeName(__int64 Param1, __int64 Object, UCHAR DoNormalize)
{
    __int64 FnQuery;                 // 0x432E
    __int64 FnUnmap;                 // 0x41CF
    __int64 FnFree;                  // 0x4334
    ULONG64 QueryOut;                // [rbp+0x38]
    UCHAR   Req[0x48];               // [rbp-0x40..]：请求结构

    (void)Param1; (void)Object;

    AcquireMiniFilterMutexEx();                              // 0x140019DF3

    if (DoNormalize == 1)                                    // 0x140019DF8
    {
        FnQuery = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x432E);   // 0x140019E06
        FnUnmap = (__int64)GtRead(GtSyscallHash16847);           // 0x140019E13  ecx=0x41CF
        FnFree  = (__int64)GtRead(GtExFreePoolFunc);             // 0x140019E20  ecx=0x4334

        if (FnQuery && FnUnmap && FnFree)                    // 0x140019E28~E35
        {
            // 清空请求结构（0x140019E37~E49）
            memset(Req, 0, 0x28);                            // [rbp-0x38] / [rbp-0x28] / [rbp-0x20]
            *(ULONG64 *)&Req[0x28] = 0;                      // [rbp-0x10]

            QueryOut = 0;                                    // 0x140019E37 [rbp+0x38]
            *(ULONG *)&Req[0x08] = 0x30;                     // 0x140019E63 [rbp-0x30]
            *(ULONG *)&Req[0x20] = 0x200;                    // 0x140019E6A [rbp-0x18]

            // 0x140019E71：rcx=&QueryOut, edx=1, r8=&Req[0x08], r9=&Req[0x00]
            if ((int)((__int64(__fastcall *)(ULONG64 *, ULONG, void *, void *))FnQuery)(
                    &QueryOut, 1, &Req[0x08], &Req[0x00]) >= 0)      // test eax,eax / js
            {
                ((void(__fastcall *)(ULONG64, __int64))FnUnmap)(QueryOut, 0);  // 0x140019E7D
                ((void(__fastcall *)(ULONG64))FnFree)(QueryOut);               // 0x140019E83
            }
        }
    }

    AcquireMiniFilterMutex();                                // 0x140019E85
}

// MiniFilterFormatFileNameWithPath — 装格式化文件名回调并清零就绪标志
// 对应原始驱动 0x14001A068（54 字节）
// 【逆向来源】同上（人工逐条转写）。源码中此前完全缺失。
// 【算法】取函数指针 GtRead(0x41BA)；非空则调用它并向 GT 0x8F1 写 0；返回是否成功。
UCHAR MiniFilterFormatFileNameWithPath(void)
{
    ULONG64 Fn = (ULONG64)GtRead(GtSyscallHash16826);        // 0x14001A06E  ecx=0x41BA
    UCHAR Result = 0;

    if (Fn)                                                  // 0x14001A07A
    {
        // 0x14001A07F `lea rcx,[rip-0x1E6]` 即本函数地址（作回调注册参数）
        ((void(__fastcall *)(void *))Fn)((void *)MiniFilterFormatFileNameWithPath);
        GtWrite(GtMiniFilterFormatNameExReady, 0);           // 0x14001A08F  ecx=0x8F1
        Result = 1;                                          // 0x14001A094
    }
    return Result;
}


// MiniFilterFormatFileNameWithPathEx — 查询"扩展格式化就绪"标志（补全空壳）
// 对应原始驱动 0x14001A1A0（110 字节）
// 【逆向来源】⚠ 可反编译（22 行伪代码）
// 【⚠ 修正记录】此前注释写"需要 FltGetStreamFileObjectContext 获取文件名" —— **错误**。
//   与 MiniFilterFormatFileNameEx 同构，只是查询的 GT 槽不同
//   （GtMiniFilterFormatNameExReady = 0x8F1）。
// 对应原始驱动 0x14001A1A0（110 字节）
__int64 MiniFilterFormatFileNameWithPathEx(__int64 Unknown, __int64 Unknown2, _DWORD *OutputBuffer, int BufferSize)
{
    int Result = 0;

    if ((unsigned __int64)OutputBuffer < MmUserProbeAddress && OutputBuffer &&
        (unsigned __int64)OutputBuffer + 1 < MmUserProbeAddress && BufferSize == 4)
    {
        ProbeForWrite(OutputBuffer, 4u, 4u);
        Result = (int)((unsigned int)GtRead(GtMiniFilterFormatNameExReady) != 0);
        *OutputBuffer = Result;
        Result = 1;
    }
    return Result;
}

// MiniFilterQueryIdleRoutine — 空闲查询例程（补全空壳）
// 对应原始驱动 0x14001A210（48 字节）
// 【⚠ 修正记录 2026-10-08】原名 `CmdPatchPeHeaderOnFlag`、注释称"检查文件是否
//   处于空闲状态，需要 FltIsFileInUse" —— **名字与描述均与实物不符**。
//   原始 IDA 名是 `MiniFilterQueryIdleRoutine`，实际功能是
//   "取互斥量 → 若标志位 0x100 置位且 IRQL < 2 则 PatchPeHeaderMagic"。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（6 行伪代码），按伪代码实现。
// 【参数】3 个（回调注册的上下文/缓冲/标志）
// 【逻辑】AcquireMiniFilterMutexEx() 取互斥；
//   若 (*a3 & 0x100) 且 KeGetCurrentIrql() < 2（PASSIVE_LEVEL 或 APC_LEVEL）
//   → PatchPeHeaderMagic((__int64)a3)；
//   返回 AcquireMiniFilterMutex() 的结果（释放互斥并返回其返回值）。
// 对应原始驱动 0x14001A210（48 字节）
__int64 *MiniFilterQueryIdleRoutine(__int64 a1, __int64 a2, _DWORD *a3)
{
    AcquireMiniFilterMutexEx();
    if ((*a3 & 0x100) != 0 && KeGetCurrentIrql() < 2u)
        PatchPeHeaderMagic((__int64)a3);
    AcquireMiniFilterMutex();
    // 原始反汇编的尾调用是 `return AcquireMiniFilterMutex();`，但复刻中该函数
    // 的返回类型是 void（见头文件），故此处调用后返回 0 —— 功能等价（调用方
    // RegisterCallbackFunc 不使用该返回值）。差异已记录。
    return 0;
}

// RegisterFilterUnloadCallback — 注册过滤卸载回调（0x14001A39C）
// 对应原始驱动 0x14001A39C（69 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：
//     `if (!GtRead(GtCommPortCallbackReady)) return STATUS_SUCCESS; return ...;`
//   —— 读错索引（0x8F2 而非 0x8F3），且两个分支返回同一常量，
//   等于什么都不做。注释"将文件操作通知发送到 GT 0x3400 缓冲区"与实物无关。
//   发现方式：windows-driver-emulation skill 逐函数差分，运行时观测到
//   原始读 GT 0x8F3 而我方读 0x8F2；反汇编核对后确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001A39C：
//   0x14001A3A2  ecx = 0x8F3 ; GtRead        ; 已注册标志
//   0x14001A3AE  test eax,eax ; jne 返回 0    ; 已注册则直接返回 0（不做重复注册）
//   0x14001A3B2  ecx = 0x41AB ; GtRead        ; 取注册函数指针
//   0x14001A3BC  test rax,rax ; je 返回 0     ; 未解析到则返回 0
//   0x14001A3C1  lea rcx,[rip-0x1B8]          ; -> 0x14001A210 (MiniFilterQueryIdleRoutine)
//   0x14001A3C8  call rax                     ; 注册该回调
//   0x14001A3CA  edx = 1 ; ecx = 0x8F3 ; GtWrite  ; 置已注册标志 = 1
//   0x14001A3D7  bl = 1                       ; 返回 1
// 【说明】本函数与 MiniFilterActiveRoutine（0x14001A240）是配对的一对：
//   本函数**注册**回调并置标志位 1；后者**注销**回调并清标志位 0。
//   两者读的是同一个指针槽（0x41AB）与同一个标志槽（0x8F3）。
//   0x41AB 在枚举里被误标为 GtSyscallHash16811，语义实为
//   "回调注册函数指针"，故此处以裸索引 + 注释书写。
NTSTATUS RegisterFilterUnloadCallback(void)
{
    char Result = 0;
    void (__fastcall *RegisterCallbackFunc)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *));

    if ((ULONG)GtRead(GtMiniFilterNotifyRoutineReady) == 0)       // 0x14001A3A2/3AE（0x8F3）
    {
        RegisterCallbackFunc =
            (void (__fastcall *)(__int64 *(__fastcall *)(__int64, __int64, _DWORD *)))
            GtRead((GLOBAL_TABLE_INDEX)0x41AB);                   // 0x14001A3B2
        if (RegisterCallbackFunc)                                 // 0x14001A3BC
        {
            RegisterCallbackFunc(
                (__int64 *(__fastcall *)(__int64, __int64, _DWORD *))
                MiniFilterQueryIdleRoutine);                      // 0x14001A3C8（lea rcx,[rip-0x1B8]）
            GtWrite(GtMiniFilterNotifyRoutineReady, 1);            // 0x14001A3CD/3D2（0x8F3 = 1）
            Result = 1;                                           // 0x14001A3D7
        }
    }
    return Result;
}

// MiniFilterActiveRoutine — 注册空闲查询例程
// 对应原始驱动 sub_14001A240
// 读取全局表 0x41B7 中已解析的注册函数，注册 CmdPatchPeHeaderOnFlag 后清零通知例程标志 0x8F3
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

// MiniFilterNotifyRoutineEx2 — Minifilter 通知例程（扩展 2，0x14001A3E4）
// 对应原始驱动 0x14001A3E4（110 字节）
// 【⚠ 修正记录 2026-10-13】原为**伪造实现**：只读 GT 0x8F2 后 `xor eax,eax`。
//   发现方式同上（逐函数差分：原始读 0x8F3，我方读 0x8F2 且不返回值）。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001A3E4：与 0x140019344 同构，仅末段不同——
//   校验（越界/空/加4越界/长度!=4）→ ProbeForWrite(r8,4,4)
//   → 读 GT **0x8F3**（`mov ecx,0x8F3; call GtRead`）
//   → *rdi = (GT 值 != 0)；返回 1。
// 【与 MiniFilterCommPortReply 的差异】本函数读的是 GT 表索引 0x8F3
//   （经 GtRead），而前者读的是绝对地址 0x1400A84D9。两者结果都写入 *r8。
__int64 MiniFilterNotifyRoutineEx2(__int64 Address, __int64 Length, _DWORD *Output, int OutputSize)
{
    char   Result = 0;
    ULONG64 ProbeLimit;

    _DWORD *OutPtr = (_DWORD *)Address;               // rdi = r8

    ProbeLimit = *(ULONG64 *)MmUserProbeAddress;
    if ((unsigned __int64)Address >= ProbeLimit        // 0x14001A401
        || Address == 0                                // 0x14001A406
        || (unsigned __int64)Address + 4 >= ProbeLimit  // 0x14001A40F
        || OutputSize != 4)                            // 0x14001A417
        return 0;

    ProbeForWrite((PVOID)Address, 4, 4);               // 0x14001A422

    *OutPtr = ((ULONG)GtRead(GtMiniFilterNotifyRoutineReady) != 0) ? 1 : 0;  // 0x14001A428/434/437（0x8F3）
    Result = 1;                                        // 0x14001A439
    return Result;
}

// CmdHandleStreamProcessInput — 流句柄操作处理器（补全空壳）
// 对应原始驱动 0x14001AB5C（289 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（43 行伪代码），按伪代码实现
// 【⚠ 修正记录两处】① 此前注释写"对应 sub_14001A250"，而该地址**在原始中不存在**
//   （已用 _xrefs 与函数清单双向核实）—— 正确地址是 0x14001AB5C；
//   ② 此前是空壳 `return STATUS_SUCCESS;` 且注释称"需要 FltGetStreamFileObjectContext
//   获取流上下文"—— 该判断**错误**。伪代码签名 `bool f(__m128i *Address, int a2)`：
//   实为**输入缓冲处理器**（校验 40 字节输入 → 解析 ProcessId/EPROCESS/流上下文 →
//   PsLookupProcessByProcessId → ValidateProcessObject → 调 MiniFilterStreamHandleEx）。
bool CmdHandleStreamProcessInput(void *Address, int InputSize)
{
    bool Result = 0;
    _OWORD InputData;
    _OWORD StreamData;
    struct _KPROCESS *TargetProcess;
    NTSTATUS Status;
    int Status2;
    PEPROCESS Process = NULL;
    __int64 StreamContext;

    if (Address && InputSize == 40 &&
        (unsigned __int64)Address < MmUserProbeAddress &&
        ((unsigned __int64)Address + 40) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x28u, 4u);
        InputData = *(_OWORD *)Address;
        StreamData = *((_OWORD *)Address + 1);
        StreamContext = *((__int64 *)Address + 4);

        TargetProcess = (struct _KPROCESS *)(*(unsigned __int64 *)((char *)&InputData + 8));
        Status = PsLookupProcessByProcessId((HANDLE)(*(unsigned __int64 *)&InputData), &Process);
        Status2 = Status;
        if (!TargetProcess && Status >= 0)
            TargetProcess = Process;

        if (ValidateProcessObject(TargetProcess, 0) == 1 &&
            (*(unsigned __int64 *)&StreamData) < MmUserProbeAddress &&
            (*(unsigned __int64 *)((char *)&StreamData + 8)) < MmUserProbeAddress)
        {
            Result = MiniFilterStreamHandleEx(TargetProcess,
                *(unsigned __int64 *)&StreamData, (*(unsigned __int64 *)((char *)&StreamData + 8)), StreamContext);
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}


// CmdInitFwpsDispatchTables — 建立 Fwps 分发表副本（0x14001BC08）
// 对应原始驱动 0x14001BC08（316 字节）
// 【⚠ 修正记录 2026-10-13】原实现漏掉了**全部全局表访问**：
//   原稿直接校验输出缓冲后调用 EnumerateAleEndpointLayers。原始函数
//   先读 GT 0x800（懒初始化，为空则 call 0x14001BE80）与 GT 0x801，
//   再以这两个值为指针做内存校验，然后拷贝到用户缓冲。
//   发现方式：windows-driver-emulation skill 逐函数差分——原始读 0x800，
//   我方读 0 个；逐条反汇编核对确认。
// 【逆向来源】人工阅读 capstone 反汇编逐条转写。
// 【原始汇编】0x14001BC08（按语义分四段）：
//   段 1（取全局表）：
//     `mov edi,0x800; call GtRead`；为空 → `call 0x14001BE80`；
//     再 `GtRead(0x800)` → r14；`GtRead(0x801)` → edi；
//     要求 r14 非 0 且 edi 非 0。
//   段 2（校验 r14 指向的结构）：
//     要求 r14 > MmSystemRangeStart、edi < 0x100；
//     r14 = *(ULONG64*)r14；要求 r14 > MmSystemRangeStart；
//     CheckMemoryValid(r14, 1) 必须返回 1（0x140059BC4）；
//     CheckMemoryValid(r14 - 1 + edi*8, 1) 必须返回 1。
//   段 3（校验用户输出缓冲）：
//     要求 r8(输出) 非 0；edi >= 1 且 大小 >= (edi-1)*8 + 0x10；
//     输出 < MmUserProbeAddress 且 输出+大小 < MmUserProbeAddress。
//   段 4（拷贝并返回）：
//     ProbeForWrite(输出, 大小, 8)；
//     memset(输出, 0, 大小)；
//     *(ULONG*)输出 = edi；
//     memmove(输出 + 8, r14, edi * 8)；
//     返回 1。
// 【返回值】1 = 成功；0 = 任一校验失败。
char CmdInitFwpsDispatchTables(__int64 Reserved1, __int64 Reserved2,
                               _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char    Result = 0;
    ULONG64 TablePtr;      // r14：GT 0x800
    ULONG   EntryCount;    // edi：GT 0x801
    ULONG64 RangeStart;

    /* ---- 段 1：取全局表（0x800 懒初始化，0x801 为条目数）---- */
    if (!GtRead((GLOBAL_TABLE_INDEX)0x800))                   // 0x14001BC30
        InitFwpsDispatchTables();                              // 0x14001BC3A

    TablePtr   = GtRead((GLOBAL_TABLE_INDEX)0x800);            // 0x14001BC41（r14）
    EntryCount = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x801);     // 0x14001BC4E（edi）

    if (!TablePtr || !EntryCount)                              // 0x14001BC56 / BC5F
        return Result;

    /* ---- 段 2：校验 TablePtr 指向的结构 ---- */
    RangeStart = *(ULONG64 *)MmSystemRangeStart;               // 0x14001BC67/6E
    if (TablePtr <= RangeStart                                 // 0x14001BC71
        || EntryCount >= 0x100)                                // 0x14001BC7A
        return Result;                                         // 0x14001BD28

    TablePtr = *(ULONG64 *)TablePtr;                           // 0x14001BC86
    if (TablePtr <= RangeStart)                                // 0x14001BC8C
        return Result;

    if ((char)CheckMemoryValid((void *)TablePtr) != 1)              // 0x14001BC97
        return Result;
    if ((char)CheckMemoryValid((void *)(TablePtr - 1 + (ULONG64)EntryCount * 8)) != 1)  // 0x14001BCB4
        return Result;

    /* ---- 段 3：校验用户输出缓冲 ---- */
    if (!OutputBuffer)                                         // 0x14001BCBD
        goto L_DONE;
    if ((ULONG64)BufferSize < (ULONG64)(EntryCount - 1) * 8 + 0x10)   // 0x14001BCC5/CCD
        goto L_DONE;
    if ((ULONG64)OutputBuffer >= *(ULONG64 *)MmUserProbeAddress)      // 0x14001BCD9/CDC
        goto L_DONE;
    if ((ULONG64)OutputBuffer + BufferSize >= *(ULONG64 *)MmUserProbeAddress)  // 0x14001BCE5
        goto L_DONE;

    /* ---- 段 4：拷贝 ---- */
    ProbeForWrite(OutputBuffer, BufferSize, 8);                // 0x14001BCF6
    memset(OutputBuffer, 0, BufferSize);                       // 0x14001BD04
    *OutputBuffer = EntryCount;                                // 0x14001BD09
    memmove(OutputBuffer + 2, (const void *)TablePtr,          // 0x14001BD15
            (ULONG64)EntryCount * 8);
    Result = 1;                                                // 0x14001BD1A

L_DONE:
    return Result;                                             // 0x14001BD28
}

// =========================================================================
// FindFwpsTcpIpDispatchTableStr — 按导出名查找 TcpIp 调度表
// 对应原始驱动 0x14001B600（300 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（28 行伪代码），按伪代码实现。
// 【逻辑】GtRead(GT 0x7F8) 取 fwpkclnt 模块基址；非 0 时
//   依次尝试两个导出名 "FwpsTcpIpDispatchTableAndGlobalsSet0" /
//   "FwpsTcpIpDispatchTableSet0"（前者失败才试后者）；
//   命中且 RVA 有效（< 模块大小）→
//   GtWrite(GT 0x7FA, RVA) 与 GtWrite(GT 0x7FB, 基址 + RVA)，返回 1。
// =========================================================================
// 对应原始驱动 0x14001B600（300 字节）
char __fastcall FindFwpsTcpIpDispatchTableStr(__int64 ModuleBase, unsigned int ModuleSize)
{
    char Result = 0;
    __int64 FwpsBase;
    unsigned int Value = 0;
    char FuncName[48];

    FwpsBase = GtRead(GtFwpsModuleBase);
    if (!FwpsBase)
        return Result;

    strcpy(FuncName, "FwpsTcpIpDispatchTableAndGlobalsSet0");
    if (LookupExportByName((PUCHAR)ModuleBase, ModuleSize, FuncName, &Value) == 1 ||
        (strcpy(FuncName, "FwpsTcpIpDispatchTableSet0"),
         LookupExportByName((PUCHAR)ModuleBase, ModuleSize, FuncName, &Value) == 1))
    {
        if (Value && Value < ModuleSize)
        {
            GtWrite(GtFwpsTcpIpOffset, Value);            // GT 0x7FA
            GtWrite(GtFwpsTcpIpAddress, FwpsBase + Value);  // GT 0x7FB
            return 1;
        }
    }
    return Result;
}

// =========================================================================
// FindFwpsL2DispatchTable — 按导出名查找 L2 调度表
// 对应原始驱动 0x14001B520（224 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（22 行伪代码），按伪代码实现。
// 【逻辑】与上者同构，但只尝试一个导出名 "FwpsL2DispatchTableAndGlobalsSet0"，
//   命中写 GtWrite(GT 0x7FE, RVA) 与 GtWrite(GT 0x7FF, 基址 + RVA)。
// =========================================================================
// 对应原始驱动 0x14001B520（224 字节）
char __fastcall FindFwpsL2DispatchTable(__int64 ModuleBase, unsigned int ModuleSize)
{
    char Result = 0;
    __int64 FwpsBase;
    unsigned int Value = 0;
    char FuncName[48];

    FwpsBase = GtRead(GtFwpsModuleBase);
    if (!FwpsBase)
        return Result;

    strcpy(FuncName, "FwpsL2DispatchTableAndGlobalsSet0");
    if (LookupExportByName((PUCHAR)ModuleBase, ModuleSize, FuncName, &Value) == 1 &&
        Value && Value < ModuleSize)
    {
        GtWrite(GtFwpsL2Offset, Value);                 // GT 0x7FE
        GtWrite(GtFwpsL2Address, FwpsBase + Value);     // GT 0x7FF
        return 1;
    }
    return Result;
}

// =========================================================================
// FindFwpsTcpIpDispatchTable — 扫描节区查找 TcpIp 调度表（按构建号两路）
// 对应原始驱动 0x14001B990（629 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（80 行伪代码），按伪代码实现。
// 【逻辑】GT 0x7FA 为 TcpIp 调度表 RVA；若为 0 先调
//   FindFwpsTcpIpDispatchTableStr 补找。随后从该 RVA 起扫节区（上限 0x64）：
//   ● 构建号 > 0x23F0 路径：遇 1296 且 +0x88==0x40000 且 +0x50!=0 且 +0x70==64
//     → 算出 RVA；条目数按构建号 < 0x295A 取 42、否则取 44；
//     写 GT 0x7FC（基址+RVA）与 GT 0x7FD（条目数）。
//   ● 构建号 <= 0x23F0 路径：先记 1296（+0x88==0x40000、+0x50!=0、+0x70==64、
//     +0x58==1）的首个匹配为 FirstMatchOffset；再遇 1340（+0x58==1、+0xDC==0）
//     且 +0x50 >= 8 → 写 GT 0x7FC 与 GT 0x7FD（= +0x50 >> 3）。
//   两路都遇 1349 提前结束。
// =========================================================================
// 对应原始驱动 0x14001B990（629 字节）
char __fastcall FindFwpsTcpIpDispatchTable(__int64 a1, unsigned int a2)
{
    char Result = 0;
    unsigned int TcpIpExportOffset;
    __int64 FwpsBase;
    __int64 CumulativeSize = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];

    TcpIpExportOffset = (unsigned int)GtRead(GtFwpsTcpIpOffset);
    if (!TcpIpExportOffset)
    {
        FindFwpsTcpIpDispatchTableStr(a1, a2);
        TcpIpExportOffset = (unsigned int)GtRead(GtFwpsTcpIpOffset);
    }
    FwpsBase = GtRead(GtFwpsModuleBase);
    if (!FwpsBase || !TcpIpExportOffset || TcpIpExportOffset >= a2)
        return Result;

    InitPESectionReadContext(a1 + TcpIpExportOffset, a2 - TcpIpExportOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; LoopIndex++)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            ULONG MatchSize;
            __int16 SubType;
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                break;
            MatchSize = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)CumulativeSize;
            CumulativeSize += *(ULONG *)((char *)SectionEntry + 0xF0);
            SubType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(ULONG *)((char *)SectionEntry + 0x50) && *(__int64 *)((char *)SectionEntry + 0x70) == 64)
            {
                ULONG MatchOffset = MatchSize + *(ULONG *)((char *)SectionEntry + 0x50) - (ULONG)a1;
                if (MatchOffset && MatchOffset < a2)
                {
                    unsigned int EntryCount = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x295A ? 42 : 44;
                    GtWrite(GtFwpsTcpIpTableAddr, FwpsBase + MatchOffset);   // GT 0x7FC
                    GtWrite(GtFwpsTcpIpEntryCount, EntryCount);              // GT 0x7FD
                    return 1;
                }
            }
        }
    }
    else
    {
        unsigned int FirstMatchOffset = 0;
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; LoopIndex++)
        {
            ULONG MatchSize;
            __int16 SubType;
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                break;
            MatchSize = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)CumulativeSize;
            CumulativeSize += *(ULONG *)((char *)SectionEntry + 0xF0);
            SubType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296)
            {
                if (*(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                    *(ULONG *)((char *)SectionEntry + 0x50) &&
                    *(__int64 *)((char *)SectionEntry + 0x70) == 64 &&
                    *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
                {
                    ULONG MatchOffset = MatchSize + *(ULONG *)((char *)SectionEntry + 0x50) - (ULONG)a1;
                    if (MatchOffset && MatchOffset < a2 && !FirstMatchOffset)
                        FirstMatchOffset = MatchOffset;
                }
            }
            else if (SubType == 1340 && SectionEntry[2] == 1 &&
                     *(_DWORD *)((char *)SectionEntry + 0xDC) == 0)
            {
                ULONG EntrySize = *(ULONG *)((char *)SectionEntry + 0x50);
                if (EntrySize >= 8)
                {
                    GtWrite(GtFwpsTcpIpTableAddr, FwpsBase + FirstMatchOffset);  // GT 0x7FC
                    GtWrite(GtFwpsTcpIpEntryCount, EntrySize >> 3);              // GT 0x7FD
                    return 1;
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// ============================================================
// "按导出名查找并把 (偏移, 地址) 写入 GT 对" 家族（L2-1，14 个）
//
// 本族 14 个函数**结构完全同构**（各 183~300 字节），统一模板：
//   ① v5 = GtRead(GtEprocessField151|0x100)  → 模块基址（0x1A1），为 0 即返回 0；
//   ② strcpy(名字缓冲, L"<导出名>")；
//   ③ LookupExportByName(a1, a2, 名字, &Value) == 1 && Value != 0 && Value < a2
//   ④ GtWrite(<偏移槽>, Value); GtWrite(<地址槽>, v5 + Value); return 1；
//   否则返回 0。
//
// 【逆向来源】全部**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写。
// 【GT 索引】均为源码枚举未命名区间（0x7B8..0x7E1），故以裸索引书写并附原始语义注释。
// ============================================================


// FindWfpStartStreamShimExport — 按名查找 WfpStartStreamShim 导出并登记 (偏移, 地址) 到 GT 0x7c1/0x7c2
// 对应原始驱动 0x140069bcc
char __fastcall FindWfpStartStreamShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStartStreamShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c1, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c2, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindWfpStopStreamShimExport — 按名查找 WfpStopStreamShim 导出并登记 (偏移, 地址) 到 GT 0x7c3/0x7c4
// 对应原始驱动 0x140069c90
char __fastcall FindWfpStopStreamShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStopStreamShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c3, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c4, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindWfpStartMacShimExport — 按名查找 WfpStartMacShim 导出并登记 (偏移, 地址) 到 GT 0x7d1/0x7d2
// 对应原始驱动 0x140069998
char __fastcall FindWfpStartMacShimExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpStartMacShim");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d1, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d2, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdGetOffloadEpochExport — 按名查找 KfdGetOffloadEpoch 导出并登记 (偏移, 地址) 到 GT 0x7b8/0x7b9
// 对应原始驱动 0x140068458
char __fastcall FindKfdGetOffloadEpochExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdGetOffloadEpoch");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7b8, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7b9, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdGetRefCalloutExport — 按名查找 KfdGetRefCallout 导出并登记 (偏移, 地址) 到 GT 0x7da/0x7db
// 对应原始驱动 0x14006851c
char __fastcall FindKfdGetRefCalloutExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdGetRefCallout");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7da, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7db, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdDeleteCalloutEntryExport — 按名查找 KfdDeleteCalloutEntry 导出并登记 (偏移, 地址) 到 GT 0x7de/0x7df
// 对应原始驱动 0x140068260
char __fastcall FindKfdDeleteCalloutEntryExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdDeleteCalloutEntry");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7de, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7df, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdUnregisterCalloutEntryExport — 按名查找 KfdUnregisterCalloutEntry 导出并登记 (偏移, 地址) 到 GT 0x7e0/0x7e1
// 对应原始驱动 0x1400686fc
char __fastcall FindKfdUnregisterCalloutEntryExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdUnregisterCalloutEntry");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7e0, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7e1, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdDeregisterLayerCallbackExport — 按名查找 KfdDeregisterLayerChangeCallback 导出并登记 (偏移, 地址) 到 GT 0x7be/0x7bf
// 对应原始驱动 0x14006832c
char __fastcall FindKfdDeregisterLayerCallbackExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdDeregisterLayerChangeCallback");
    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) != 1)
    {
        strcpy(NameBuf, "KfdDeregisterLayerEventNotify");
        if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) != 1)
            return Result;
    }

    if (Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7be, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7bf, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindKfdRegisterLayerCallbackExport — 按名查找 KfdRegisterLayerChangeCallback 导出并登记 (偏移, 地址) 到 GT 0x7bc/0x7bd
// 对应原始驱动 0x1400685d8
char __fastcall FindKfdRegisterLayerCallbackExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "KfdRegisterLayerChangeCallback");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7bc, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7bd, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiGetModuleHandle — 按名查找 NsiGetModuleHandle 导出并登记 (偏移, 地址) 到 GT 0x7ca/0x7cb
// 对应原始驱动 0x140069000
char __fastcall FindNsiGetModuleHandle(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiGetModuleHandle");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7ca, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7cb, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNmrRegisterProviderExport — 按名查找 NmrRegisterProvider 导出并登记 (偏移, 地址) 到 GT 0x7d7/0x7d8
// 对应原始驱动 0x1400689f8
char __fastcall FindNmrRegisterProviderExport(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NmrRegisterProvider");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d7, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d8, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiDeregisterChangeNotificationEx — 按名查找 NsiDeregisterChangeNotificationEx 导出并登记 (偏移, 地址) 到 GT 0x7c8/0x7c9
// 对应原始驱动 0x140068e4c
char __fastcall FindNsiDeregisterChangeNotificationEx(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiDeregisterChangeNotificationEx");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7c8, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7c9, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindNsiDeregisterLegacyHandler — 按名查找 NsiDeregisterLegacyHandler 导出并登记 (偏移, 地址) 到 GT 0x7ce/0x7cf
// 对应原始驱动 0x140068f2c
char __fastcall FindNsiDeregisterLegacyHandler(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "NsiDeregisterLegacyHandler");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7ce, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7cf, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindSetWfpDeviceObject — 按名查找 SetWfpDeviceObject 导出并登记 (偏移, 地址) 到 GT 0x7d4/0x7d5
// 对应原始驱动 0x1400696c0
char __fastcall FindSetWfpDeviceObject(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "SetWfpDeviceObject");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7d4, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7d5, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}


// FindWfpNblInfoDispatchTableClear — 按名查找 WfpNblInfoDispatchTableClear 导出并登记到 GT 0x7B2/0x7B3
// 对应原始驱动 0x1400698C4（211 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，与本文件已实现的 14 个 Find* 族同构。
char __fastcall FindWfpNblInfoDispatchTableClear(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    __int64 ModuleBase;
    ULONG   Value = 0;
    char    NameBuf[32];

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // GtEprocessField151|0x100
    if (!ModuleBase)
        return Result;

    strcpy(NameBuf, "WfpNblInfoDispatchTableClear");

    if (LookupExportByName((PUCHAR)PeBase, PeSize, NameBuf, &Value) == 1
        && Value != 0 && Value < PeSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x7B2, (__int64)Value);
        GtWrite((GLOBAL_TABLE_INDEX)0x7B3, ModuleBase + (__int64)Value);
        return 1;
    }
    return Result;
}

// ScanWfpDeviceObjectSection — 扫描 WFP 设备对象节区（类型 1294）
// 对应原始驱动 0x140069784（319 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【算法】先取 GT 0x7D4（SetWfpDeviceObject 的导出偏移）；为 0 则调
//   FindSetWfpDeviceObject 再取一次，仍为 0 即返回 0；要求 < PeSize →
//   以 (PeBase+偏移, PeSize-偏移) 初始化节区上下文，最多扫 0x14 条：
//     · 类型 1349(0x545) → 结束；
//     · 类型 1294(0x50E) 且 (字段+0x88 & 0x10000) 且 (字段+0x40 != 0)
//       且 字段+0x50 == 64 且 字段+0x8C == 1 → 写 GT 0x7D6 = 字段+0x40，返回 1。
// 对应原始驱动 0x140069784（319 字节）
char __fastcall ScanWfpDeviceObjectSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    ULONG   i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D4);
    if (!Offset)                                                  // 0x1400697B4
    {
        FindSetWfpDeviceObject(PeBase, PeSize);                   // 0x1400697C7
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D4);
        if (!Offset)
            return Result;
    }
    if (Offset >= PeSize)                                         // 0x1400697DB
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006980B
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x14; ++i)                                    // 0x140069810
    {
        USHORT Type;
        ULONG  Len;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006981F
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Ctx.ReadPtr += Len;                                       // 0x14006982F

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x14006983C
        if (Type == 0x545)                                        // 0x140069848
            break;

        if (Type == 0x50E                                          // 0x14006987E
            && (*(ULONG64 *)((PUCHAR)Entry + 0x88) & 0x10000ULL) != 0
            && *(ULONG *)((PUCHAR)Entry + 0x40) != 0
            && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64
            && *(ULONG *)((PUCHAR)Entry + 0x8C) == 1)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x7D6,                          // 0x140069895
                    *(__int64 *)((PUCHAR)Entry + 0x40));   // 注意：原为 (unsigned int)Value
            return 1;
        }
    }
    return Result;                                                // 0x14006989E
}


// ScanWfpMacShimSections — 扫描 WFP Mac Shim 数据节区（类型 1294 / characteristics 0x40000）
// 对应原始驱动 0x140069A50（379 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【算法】取 GT 0x7D3；为 0 则调 FindWfpStartMacShimExport 再取；
//   再取 GT 0x1A1 作模块基址；要求 基址 与 偏移 均非 0 且 偏移 < PeSize →
//   以 (PeBase+偏移, PeSize-偏移) 初始化上下文，最多扫 0x1E 条：
//     类型 0x545 结束；类型 0x50E 且 字段+0x88 == 0x40000 且 字段+0x40 非零
//     且 字段+0x50 == 64 且 字段+0x8C == 1 → 算 RVA = 累计 + 字段+0x40 - PeBase，
//     非 0 且 < PeSize 时写 GT 0x7D3 = 基址 + RVA，返回 1。
// 对应原始驱动 0x140069A50（379 字节）
char __fastcall ScanWfpMacShimSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    // 【索引依据】原始序言 `mov ebp,7D1h; mov ecx,ebp` → 首读 0x7D1（配对 Find* 的
    //   导出偏移槽）；命中后写的是 0x7D3（本函数自己的结果槽）。两者不同，不可混用。
    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D1);             // 0x140069A85
    if (!Offset)
    {
        FindWfpStartMacShimExport(PeBase, PeSize);                // 0x140069A96
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D1);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140069AAE
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140069AC4
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x140069AF6
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x1E; ++i)                                    // 0x140069AFB
    {
        USHORT Type;
        ULONG  Len;
        ULONG  Cumul;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x140069B0A
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069B23
        Ctx.ReadPtr += Len;                                       // 0x140069B2E

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069B33
        if (Type == 0x545)                                        // 0x140069B3F
            break;

        if (Type == 0x50E                                          // 0x140069B57
            && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)
        {
            ULONG v15 = *(ULONG *)((PUCHAR)Entry + 0x40);          // v15
            if (v15                                                // 0x140069B62
                && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64        // v17
                && *(ULONG *)((PUCHAR)Entry + 0x8C) == 1)          // v18
            {
                ULONG Rva = Cumul + v15 - (ULONG)(ULONG_PTR)PeBase;   // 0x140069B7C
                if (Rva && Rva < PeSize)                          // 0x140069B7E/82
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x7D3,            // 0x140069B9A
                            ModuleBase + (__int64)Rva);
                    return 1;
                }
            }
        }
    }
    return Result;                                                // 0x140069BA3
}

// ScanNsiDeregisterDataSection — 扫描 NSI 注销数据节区（类型 360 / characteristics 0x40000）
// 对应原始驱动 0x1400690C4（369 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【算法】取 GT 0x7D0；为 0 则调 FindNsiDeregisterLegacyHandler 再取；
//   再取 GT 0x1A1 作模块基址；要求均满足后初始化上下文，最多扫 0x1E 条：
//     类型 0x545 结束；类型 360(0x168) 且 字段+0x88 == 0x40000 且 字段+0x40 非零
//     且 字段+0x50 == 64 → 写 GT 0x7D0 = 基址 + RVA，返回 1。
// 对应原始驱动 0x1400690C4（369 字节）
char __fastcall ScanNsiDeregisterDataSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    // 【索引依据】原始序言 `mov ecx,7CEh` → 首读 0x7CE（配对 Find* 的导出偏移槽）；
    //   命中后写 0x7D0（本函数的结果槽）。
    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CE);             // 0x1400690FE
    if (!Offset)
    {
        FindNsiDeregisterLegacyHandler(PeBase, PeSize);           // 0x14006910A
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CE);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140069122
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140069138
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006916A
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x1E; ++i)                                    // 0x14006916F
    {
        USHORT Type;
        ULONG  Len;
        ULONG  Cumul;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006917E
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069197
        Ctx.ReadPtr += Len;                                       // 0x1400691A2

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400691A7
        if (Type == 0x545)                                        // 0x1400691B3
            break;

        if (Type == 360                                            // 0x1400691CB
            && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)
        {
            ULONG v15 = *(ULONG *)((PUCHAR)Entry + 0x40);
            if (v15 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64)   // 0x1400691D6/1E1
            {
                ULONG Rva = Cumul + v15 - (ULONG)(ULONG_PTR)PeBase;    // 0x1400691E6
                if (Rva && Rva < PeSize)                          // 0x1400691E8/1EC
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x7D0,            // 0x140069204
                            ModuleBase + (__int64)Rva);
                    return 1;
                }
            }
        }
    }
    return Result;                                                // 0x14006920D
}


// ScanKernelDataPartitionSection — 扫描内核数据分区节区（类型 1296 两阶段匹配）
// 对应原始驱动 0x140069504（443 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【和同族 Scan*Section 的差异】本函数是**两阶段**匹配：
//   阶段 1：类型 1296 且 字段+0x88 == 0x40000 且 字段+0x40 非零 且 字段+0x50 == 64
//           → 记录候选 RVA(累计+字段+0x40-PeBase) 与 字段+0x8C（须尚未记录）；
//   阶段 2：类型 1296 且 (字段+0x88 & 0x10000) 非零 且 (int)字段+0x40 > 0
//           且 字段+0x50 == 32 且 已有候选 且 字段+0x8C == 阶段 1 记录的字段+0x8C
//           → 写 GT 0x7BA = 字段+0x40、GT 0x7BB = 基址+候选RVA，返回 1。
// 【注】`v14`（IDArbp-C0 处的 dword）在反汇编里于循环前取自描述符自身字段
//   （0x1400695BB `mov r13d,[rsp+0x40]`），与后文 v19(字段+0x8C) 同一来源位置。
char __fastcall ScanKernelDataPartitionSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   SavedOfs = 0;         // v8：阶段 1 记录的候选 RVA
    ULONG   SavedField = 0;       // v7：阶段 1 记录的 字段+0x8C
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    // 【索引依据】配对 Find 写的是 0x7B8(偏移)/0x7B9(地址)；本函数读的是 **0x7B8**（偏移）。
    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B8);            // 0x140069549
    if (!Offset)
    {
        FindKfdGetOffloadEpochExport(PeBase, PeSize);             // 0x140069555
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B8);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006956E
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140069584
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x1400695B6
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    SavedField = 0;                                               // 0x1400695BB（取自描述符字段区）
    SavedOfs = 0;

    for (i = 0; i < 0x1E; ++i)                                    // 0x1400695C2
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F40, F8C;
        ULONG64 F50, F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x1400695CE
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x1400695E6
        Ctx.ReadPtr += Len;                                       // 0x1400695F0

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400695F5
        if (Type == 0x545)                                        // 0x140069601
            break;

        F40 = *(ULONG *)((PUCHAR)Entry + 0x40);
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
        F8C = *(ULONG *)((PUCHAR)Entry + 0x8C);

        if (Type == 0x510)                                        // 0x140069614（1296）
        {
            if (F88 == 0x40000ULL && F40 != 0 && F50 == 64)        // 0x140069629
            {
                ULONG Rva = Cumul + F40 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006962B
                if (Rva && Rva < PeSize && !SavedOfs)              // 0x140069630/632/636
                {
                    SavedField = F8C;                              // 0x14006963A
                    SavedOfs = Rva;                                // 0x14006963E
                }
            }
            else if ((F88 & 0x10000ULL) != 0 && (int)F40 > 0       // 0x140069665
                && F50 == 32 && SavedOfs && SavedField == F8C)
            {
                // 【顺序依据】原始 0x14006967D 先写 0x7BB（= F40），
                //   0x14006968C 后写 0x7BA（= 基址 + 候选 RVA）。逐条核对过调用序。
                GtWrite((GLOBAL_TABLE_INDEX)0x7BB, (__int64)F40);          // 0x14006967D
                GtWrite((GLOBAL_TABLE_INDEX)0x7BA,
                        ModuleBase + (__int64)SavedOfs);                   // 0x14006968C
                return 1;
            }
        }
    }
    return Result;                                                // 0x140069695
}

// ScanNsiGetModuleDataSection — 双层嵌套扫描 NSI GetModule 数据节区
// 对应原始驱动 0x140069238（715 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】原始序言 `mov ecx,7CAh`（GT 调用序经寄存器跟踪提取）：
//   首读 0x7CA（配对 Find* 的导出偏移槽）→ 再读 0x1A1（模块基址）
//   → 命中写 0x7CC / 0x7CD（本函数的结果槽）。
// 【字段映射】描述符仍为 0x120 布局：+0x38 +0x40 +0x50 +0x58 +0x70 +0x78 +0x88 +0xF0 +0x118。
// 【算法】外层（上限 0x1E）：类型 1334 且 字段+0x70 == 1 → 置标记；
//   类型 0x558 且 标记已置 → 由 字段+0x38 算 RVA，合法则进入内层。
//   内层（上限 0x64）：类型 0x558 → 置标记2；其余分支按 1243 / 1298 / 其它 分流，
//   记录两个候选 RVA 并在两者相符时写 GT 0x7CC/0x7CD（= 基址 + 各候选），返回 1。
// 对应原始驱动 0x140069238（715 字节）
char __fastcall ScanNsiGetModuleDataSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i, j;
    UCHAR   Mark1 = 0;            // v7（外层标记）
    UCHAR   Mark2 = 0;            // v12（内层标记）
    ULONG   Cand1 = 0;            // v13：候选1
    ULONG   Cand2 = 0;            // v14：候选2
    ULONG   Cand2Saved = 0;       // v20：候选2 的上次值
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CA);            // 0x14006927D
    if (!Offset)
    {
        FindNsiGetModuleHandle(PeBase, PeSize);                   // 0x140069289
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7CA);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x1400692A2
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x1400692B8
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x1400692EE
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; ; )                                               // 0x140069308（外层 while）
    {
        USHORT Type;
        ULONG  Len, Cumul;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069319
        Ctx.ReadPtr += Len;                                       // 0x140069323
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069328

        if (Type == 1334 && *(ULONG64 *)((PUCHAR)Entry + 0x70) == 1)   // 0x14006933B
        {
            Mark1 = 1;                                            // 0x14006933D
        }
        else if (Type == 0x558 && Mark1 == 1)                     // 0x140069350
        {
            ULONG Rva = Cumul + *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)(ULONG_PTR)PeBase;
            if (Rva && Rva < PeSize)                              // 0x140069358 / 35A / 35E
            {
                InitPESectionReadContext(PeBase + Rva, PeSize - Rva,   // 0x140069399
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                Mark2 = 0; Cand1 = 0; Cand2 = 0; Cand2Saved = 0;

                for (j = 0; ; )                                   // 0x1400693BE（内层 while）
                {
                    USHORT T2;
                    ULONG  L2, C2;

                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
                        return Result;

                    L2 = *(ULONG *)((PUCHAR)Entry + 0xF0);
                    C2 = L2 + (ULONG)Ctx.ReadPtr;                 // 0x1400693CF
                    Ctx.ReadPtr += L2;                            // 0x1400693D9
                    T2 = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400693DE

                    if (T2 == 0x558)                              // 0x1400693EA
                    {
                        Mark2 = 1;                                // 0x1400693EC
                    }
                    else if (T2 != 1298 || Mark2)                 // 0x1400693FE
                    {
                        if (T2 == 1243)                           // 0x14006943B
                        {
                            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000ULL)   // 0x140069445
                            {
                                if (*(ULONG *)((PUCHAR)Entry + 0x40) != 0)          // 0x14006944C
                                {
                                    if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 64    // 0x140069459
                                        && Mark2 == 1 && Cand1)
                                    {
                                        ULONG v14 = C2 + *(ULONG *)((PUCHAR)Entry + 0x40)
                                                    - (ULONG)(ULONG_PTR)PeBase;   // 0x140069463
                                        if (v14 && v14 < PeSize)                      // 0x140069465/469
                                        {
                                            GtWrite((GLOBAL_TABLE_INDEX)0x7CC,
                                                    ModuleBase + (__int64)Cand1);   // LABEL_49
                                            GtWrite((GLOBAL_TABLE_INDEX)0x7CD,
                                                    ModuleBase + (__int64)v14);
                                            return 1;
                                        }
                                    }
                                }
                                Cand2 = Cand2Saved;                   // 0x14006946B
                            }
                        }
                        else if (Mark2 == 1
                                 && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL
                                 && *(ULONG *)((PUCHAR)Entry + 0x78) != 0
                                 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 64)     // 0x14006949F
                        {
                            ULONG v18 = C2 + *(ULONG *)((PUCHAR)Entry + 0x78)
                                        - (ULONG)(ULONG_PTR)PeBase;               // 0x1400694A4
                            if (v18 == Cand2 && v18)                              // 0x1400694AC
                            {
                                GtWrite((GLOBAL_TABLE_INDEX)0x7CC,
                                        ModuleBase + (__int64)Cand1);             // LABEL_49
                                GtWrite((GLOBAL_TABLE_INDEX)0x7CD,
                                        ModuleBase + (__int64)Cand2);
                                return 1;
                            }
                            Cand2 = Cand2Saved = v18;                   // 0x1400694AE / 4B0
                        }
                    }
                    else if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)  // 0x140069408
                    {
                        if (*(ULONG *)((PUCHAR)Entry + 0x78) != 0)               // 0x14006940F
                        {
                            if (*(ULONG64 *)((PUCHAR)Entry + 0x50) == 64
                                && *(ULONG *)((PUCHAR)Entry + 0x58) == 1)            // 0x14006941C
                            {
                                ULONG v17 = C2 + *(ULONG *)((PUCHAR)Entry + 0x78)
                                            - (ULONG)(ULONG_PTR)PeBase;          // 0x140069421
                                if (v17 && v17 < PeSize && !Cand1)                   // 0x140069423 / 42C
                                    Cand1 = v17;                                     // 0x14006942E
                            }
                        }
                    }

                    if ((ULONG)(++j) >= 0x64)                                 // 0x14006947C
                        return Result;
                }
            }
        }

        if ((ULONG)(++i) >= 0x1E)                                     // 0x140069365
            return Result;
    }
    return Result;                                                    // 0x1400694D9
}

// ScanKfdDriverSections — 扫描 KFD 驱动节区（类型 1296/1298/1049 三段确认）
// 对应原始驱动 0x1400687D0（550 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取的调用序：首读 0x7BE（配对 Find* 的导出偏移槽）
//   → 0x1A1（模块基址）→ 循环内两处 GtRead(0x7BA) 作比对 → 命中写 0x7C0。
// 【算法】
//   ① Offset = GtRead(0x7BE)；为 0 → FindKfdDeregisterLayerCallbackExport 后再取；
//   ② ModuleBase = GtRead(0x1A1)；三者齐备且 Offset < PeSize → 初始化上下文；
//   ③ 循环上限 0x64；每轮：类型 0x558 时计数器 +1，> 1 即返回 0（只允许一次）；
//      类型 0x510(1296) 且 字段+0x88==0x40000 且 字段+0x78!=0 且 字段+0x50==64
//        → 记候选 RVA(v9) 与 字段+0x8C(v8)（须尚未记录）；
//      类型 1298 且 (字段+0x88 & 0x10000) 且 (int)字段+0x78 > 0 且 字段+0x50==64
//        → 若 候选非0 且 (基址+候选) == GtRead(0x7BA) 且 v8 == 字段+0x78
//          → 写 GT 0x7C0 = 字段+0x78，返回 1；
//      类型 1049 且 字段+0x50==64 且 字段+0x88==0x2000000 且 候选非0
//        且 (基址+候选) == GtRead(0x7BA) 且 v8 == 字段+0x40
//        → 写 GT 0x7C0 = 字段+0x40，返回 1。
// 对应原始驱动 0x1400687D0（550 字节）
char __fastcall ScanKfdDriverSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Count558 = 0;         // v5
    ULONG64 SavedField = 0;       // v8（候选对应的 字段+0x8C / 字段+0x40）
    ULONG   SavedRva = 0;         // v9
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7BE);            // 0x14006881D
    if (!Offset)
    {
        FindKfdDeregisterLayerCallbackExport(PeBase, PeSize);     // 0x140068829
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7BE);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140068842
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140068858
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006888A
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x64; ++i)                                    // 0x140068896
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F40, F78, F8C; ULONG64 F50, F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x1400688A2
            return Result;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x1400688BA
        Ctx.ReadPtr += Len;                                       // 0x1400688C4

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400688C9
        if (Type == 0x558 && (ULONG)(++Count558) > 1)             // 0x1400688DE
            return Result;

        F40 = *(ULONG *)((PUCHAR)Entry + 0x40);
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
        F8C = *(ULONG *)((PUCHAR)Entry + 0x8C);

        if (Type == 0x510 && F88 == 0x40000ULL && F78 != 0 && F50 == 64)   // 0x14006890C
        {
            ULONG Rva = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;   // 0x140068912
            if (Rva && Rva < PeSize && !SavedRva)                 // 0x140068924
            {
                SavedField = F8C;                                 // 0x14006892A
                SavedRva = Rva;                                   // 0x14006892E
            }
        }
        else if (Type == 1298 && (F88 & 0x10000ULL) != 0          // 0x14006894B
                 && (int)F78 > 0 && F50 == 64)
        {
            if (SavedRva                                          // 0x14006896C
                && (ULONG64)(ModuleBase + (__int64)SavedRva)
                       == (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x7BA)
                && SavedField == (ULONG64)F78)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7C0, (__int64)F78);      // LABEL_35
                return 1;
            }
        }
        else if (Type == 1049 && F50 == 64 && F88 == 0x2000000ULL // 0x1400689AB
                 && SavedRva
                 && (ULONG64)(ModuleBase + (__int64)SavedRva)
                        == (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x7BA)
                 && SavedField == (ULONG64)F40)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x7C0, (__int64)F40);      // LABEL_35
            return 1;
        }
    }
    return Result;                                                // 0x1400689CC
}

// ScanWfpStreamShimSections — 扫描 WFP Stream Shim 节区（多类型组合，写 3 个 GT）
// 对应原始驱动 0x14006A508（652 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7C1（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7C5 / 0x7C6 / 0x7C7（本函数的三个结果槽）。
// 【字段映射】描述符 0x120 布局；本函数用到 +0x40(v22) +0x70(v23) +0x78(v24)
//   +0x80(v25) +0xF0 +0x118。初值 v6 = 0xFFFFFFFF（-1，用于求"最小偏移"）。
// 【算法】循环（上限 0x64，末尾计数 v17）：
//   · 类型 1349(0x545) → 若 v7(计数) 与 v9 均非 0 且 v6 落在 (0,0xFFFFFFFE] 内，
//       写 GT 0x7C5 = v7、GT 0x7C6 = 基址+v6、GT 0x7C7 = 基址+v9，返回 1；
//       否则返回 0；
//   · 类型 1139/1140 → v8 = v15 = 1（bound import 标志）
//   · 类型 0x558    → ++v16
//   · 类型 1294(0x50E) 且 v16==1 且 !v8 且 字段+0x70==0x40000
//       且 字段+0x40!=0 且 字段+0x80==64 → 算 RVA，合法则 ++v7 并更新最小 v6
//   · 类型 1351(0x547) 且 v8==1 且 字段+0x70==0x40000
//       且 字段+0x40!=0 且 字段+0x80==0x800000 且 字段+0x78==1 → 算 RVA，
//       合法且 (构建号 >= 0x585D 或 v9==0) 时 v9 = RVA；随后 v8 = v15
// 对应原始驱动 0x14006A508（652 字节）
char __fastcall ScanWfpStreamShimSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   MinRva = 0xFFFFFFFF;  // v6：1294 的最小偏移
    ULONG   Cnt1294 = 0;          // v7
    UCHAR   BoundMark = 0;        // v8
    UCHAR   BoundSaved = 0;       // v15
    ULONG   Rva1351 = 0;          // v9
    ULONG   Cnt558 = 0;           // v16
    ULONG   Iter = 0;             // v17
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7C1);            // 0x14006A54D
    if (!Offset)
    {
        FindWfpStartStreamShimExport(PeBase, PeSize);             // 0x14006A559
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7C1);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006A572
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x14006A58A
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006A5C0
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (;;)                                                      // 0x14006A5EA
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F40, F70, F78; ULONG64 F80;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14006A5FB
        Ctx.ReadPtr += Len;                                       // 0x14006A605

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x14006A60A

        if (Type == 0x545)                                        // 0x14006A616
        {
            if (Cnt1294 && (MinRva - 1) <= 0xFFFFFFFD && Rva1351)  // 0x14006A72F
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7C5, (__int64)Cnt1294);      // 0x14006A739
                GtWrite((GLOBAL_TABLE_INDEX)0x7C6,
                        ModuleBase + (__int64)MinRva);                     // 0x14006A74E
                GtWrite((GLOBAL_TABLE_INDEX)0x7C7,
                        ModuleBase + (__int64)Rva1351);                    // 0x14006A75E
                return 1;
            }
            return Result;                                        // 0x14006A763
        }

        F40 = *(ULONG *)((PUCHAR)Entry + 0x40);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F80 = *(ULONG64 *)((PUCHAR)Entry + 0x80);

        if ((USHORT)(Type - 1139) <= 1)                           // 0x14006A633
        {
            BoundMark = 1;                                        // 0x14006A714
            BoundSaved = 1;                                       // 0x14006A717
        }
        else if (Type == 0x558)                                   // 0x14006A641
        {
            ++Cnt558;                                             // 0x14006A643
        }
        else if (Type == 0x50E)                                   // 0x14006A655
        {
            if (Cnt558 == 1 && !BoundMark && F70 == 0x40000)      // 0x14006A673
            {
                if (F40 != 0 && F80 == 64)                        // 0x14006A67E / 685
                {
                    ULONG Rva = Cumul + F40 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A68A
                    if (Rva && Rva < PeSize)                      // 0x14006A68C / 690
                    {
                        ++Cnt1294;                                // 0x14006A692
                        if (Rva < MinRva)                         // 0x14006A698
                            MinRva = Rva;                         // 0x14006A69A
                    }
                }
            }
        }
        else if (Type == 0x547 && BoundMark == 1 && F70 == 0x40000)   // 0x14006A6B6
        {
            if (F40 != 0 && F80 == 0x800000ULL && F78 == 1)       // 0x14006A6BD / 6CD
            {
                ULONG Rva = Cumul + F40 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A6D2
                if (Rva && Rva < PeSize                            // 0x14006A6D4 / 6F4
                    && ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x585D || !Rva1351))
                    Rva1351 = Rva;                                // 0x14006A6F6
            }
            BoundMark = BoundSaved;                               // 0x14006A6F9
        }

        if ((ULONG)(++Iter) >= 0x64)                              // 0x14006A70C
            return Result;
    }
    return Result;                                                // 0x14006A76A
}

// ScanWfpNblInfoSections — 扫描 WFP NBL Info 节区（类型 1298 两段组合）
// 对应原始驱动 0x14006A794（468 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7B2（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7B4 / 0x7B5 / 0x7B6（本函数的三个结果槽）。
// 【#define 展开】原伪代码里的复合表达式对应：
//   GtMsrvTokenTable|GtEprocessField134 = 0x7B2（配对 Find 的偏移槽）
//   GtEprocessField151|0x100            = 0x1A1（模块基址）
//   GtMsrvTebTable|GtEprocessField134   = 0x7B4（本函数结果槽 1）
//   GtMsrvTebTable|GtEprocessField135   = 0x7B5（本函数结果槽 2）
//   GtMsrvTebTable|GtEprocessField136   = 0x7B6（本函数结果槽 3）
// 【算法】取 GT 0x7B2；为 0 则调 FindWfpNblInfoDispatchTableClear 再取；
//   取 GT 0x1A1 作基址；三者齐备且偏移 < PeSize → 初始化上下文；
//   循环上限 0x1E：类型 1349(0x545) 结束；
//     类型 1298(0x512) 两段：
//       (a) 字段+0x70==32 且 字段+0x74==8 且 (int)字段+0x78 > 0
//           → v7 = 字段+0x78 >> 3（条目计数）
//       (b) 字段+0x88==0x40000 且 字段+0x78 != 0 且 字段+0x70==64 且 字段+0x74==1
//           → 算 RVA，非 0 且 < PeSize 且 v8==0 时 v8 = RVA；
//     每轮末尾若 v7 与 v8 均非 0 → 写 GT 0x7B4=v8、0x7B5=基址+v8、0x7B6=v7，返回 1。
// 对应原始驱动 0x14006A794（468 字节）
char __fastcall ScanWfpNblInfoSections(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Cnt = 0;              // v7
    ULONG   Rva = 0;              // v8
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B2);            // 0x14006A7D2
    if (!Offset)
    {
        FindWfpNblInfoDispatchTableClear(PeBase, PeSize);         // 0x14006A7DE
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7B2);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006A7F6
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x14006A80C
        return Result;

    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006A83E
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x1E; ++i)                                    // 0x14006A847
    {
        USHORT Type;
        ULONG  Len, Cumul;
        ULONG  F70, F74, F78;
        ULONG64 F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006A857
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14006A870
        Ctx.ReadPtr += Len;                                       // 0x14006A87B

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x14006A880
        if (Type == 0x545)                                        // 0x14006A88C
            break;

        if (Type == 0x512)                                        // 0x14006A89A
        {
            F70 = *(ULONG *)((PUCHAR)Entry + 0x70);
            F74 = *(ULONG *)((PUCHAR)Entry + 0x74);
            F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
            F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

            if (F70 == 32 && F74 == 8 && (int)F78 > 0)            // 0x14006A8BA
            {
                Cnt = F78 >> 3;                                   // 0x14006A8BE
            }
            else if (F88 == 0x40000ULL)                           // 0x14006A8CF
            {
                if (F78 != 0 && F70 == 64 && F74 == 1)            // 0x14006A8D3 / 8E8
                {
                    ULONG r = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A8ED
                    if (r && r < PeSize && !Rva)                  // 0x14006A8EF / 8F7
                        Rva = r;
                }
            }
        }

        if (Cnt && Rva)                                           // 0x14006A900
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x7B4, (__int64)Rva);          // 0x14006A919
            GtWrite((GLOBAL_TABLE_INDEX)0x7B5,
                    ModuleBase + (__int64)Rva);                        // 0x14006A927
            GtWrite((GLOBAL_TABLE_INDEX)0x7B6, (__int64)Cnt);          // 0x14006A933
            return 1;                                              // 0x14006A938
        }
    }
    return Result;                                                 // 0x14006A93C
}


// ScanKernelMemoryDataSection — 四层嵌套扫描内核内存数据节区
// 对应原始驱动 0x140068ABC（912 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7D7（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7D9（本函数结果槽）。
// 【字段映射】描述符 0x120 布局；用到 +0x38(v29) +0x50(v30) +0x58(v31)
//   +0x70(v32) +0x78(v33) +0x88(v34) +0xF0(v35) +0x118(v36)。
// 【算法】四层嵌套（层级由 类型序列 1341→1368 / 1298→1368 / 1332..1347→1368 / 1298 驱动）：
//   L1（上限 0x64）：类型 1341(0x53D) 且 字段+0x70==2 → 置标记；
//       类型 1368(0x558) 且 标记已置 → 由 字段+0x38 算 RVA(v8)，合法则 break；
//   L2（上限 0x64）：类型 1298(0x512) 且 字段+0x78!=0 且 字段+0x50==64
//       且 字段+0x58==8 → 置标记2；类型 0x558 且 标记2 → 算 RVA(v16) 进入 L3；
//   L3（上限 0x64）：类型 1332..1347 且 字段+0x70==1 → 置标记3；
//       类型 0x558 且 标记3 → 算 RVA(v21) 进入 L4；
//   L4（上限 0x1E）：类型 1298 且 字段+0x88==0x40000 且 字段+0x78!=0
//       且 字段+0x50==64 → 算 RVA(v24)，合法则写 GT 0x7D9 = 基址 + v24，返回 1。
// 对应原始驱动 0x140068ABC（912 字节）
char __fastcall ScanKernelMemoryDataSection(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Rva1 = 0;             // v8
    ULONG   Rva2 = 0;             // v16
    ULONG   Rva3 = 0;             // v21
    UCHAR   M1 = 0, M2 = 0, M3 = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D7);            // 0x140068B01
    if (!Offset)
    {
        FindNmrRegisterProviderExport(PeBase, PeSize);            // 0x140068B0D
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7D7);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140068B26
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140068B3C
        return Result;

    /* ---- L1：1341(字段+0x70==2) → 1368 ---- */
    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x140068B6E
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068B8B
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F70;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068B98
        Ctx.ReadPtr += Len;                                       // 0x140068BA2
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068BA7
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);

        if (Type == 0x53D && F70 == 2)                            // 0x140068BBA
        {
            M1 = 1;                                               // 0x140068BBC
        }
        else if (Type == 0x558 && M1 == 1)                        // 0x140068BDD
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
            if (r && r < PeSize)                                  // 0x140068BDD 内联判据
            {
                Rva1 = r;                                         // 0x140068BEA
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068BE6
            break;
    }

    if (!Rva1 || Rva1 >= PeSize)                                  // 0x140068BF6
        return Result;

    /* ---- L2：1298(字段+0x78/0x50/0x58) → 1368 ---- */
    InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,        // 0x140068C28
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068C48
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F58, F78;
        ULONG64 F50;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068C59
        Ctx.ReadPtr += Len;                                       // 0x140068C63
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068C68
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F58 = *(ULONG *)((PUCHAR)Entry + 0x58);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);

        if (Type == 0x512 && F78 != 0 && F50 == 64 && F58 == 8)    // 0x140068C82
        {
            M2 = 1;                                               // 0x140068C84
        }
        else if (Type == 0x558 && M2 == 1)                        // 0x140068C99
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068CA1
            if (r && r < PeSize)                                  // 0x140068CA3 / CA7
            {
                Rva2 = r;
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068CB4
            return Result;
    }

    if (!Rva2 || Rva2 >= PeSize)                                  // 0x140068CC1
        return Result;

    /* ---- L3：1332..1347(字段+0x70==1) → 1368 ---- */
    InitPESectionReadContext(PeBase + Rva2, PeSize - Rva2,        // 0x140068CF3
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )                                               // 0x140068D0D
    {
        USHORT Type;
        ULONG  Len, Cumul, F38, F70;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068D24
        Ctx.ReadPtr += Len;                                       // 0x140068D2E
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068D33
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F70 = *(ULONG *)((PUCHAR)Entry + 0x70);

        if ((USHORT)(Type - 1332) <= 0xF && F70 == 1)             // 0x140068D49
        {
            M3 = 1;                                               // 0x140068D4B
        }
        else if (Type == 0x558 && M3 == 1)                        // 0x140068D5A
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068D62
            if (r && r < PeSize)                                  // 0x140068D64 / D68
            {
                Rva3 = r;
                break;
            }
        }
        if ((ULONG)(++i) >= 0x64)                                 // 0x140068D6F
            return Result;
    }

    if (!Rva3 || Rva3 >= PeSize)                                  // 0x140068D68
        return Result;

    /* ---- L4：1298(字段+0x88==0x40000 等) → 写 GT ---- */
    InitPESectionReadContext(PeBase + Rva3, PeSize - Rva3,        // 0x140068DA3
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; i < 0x1E; ++i)                                    // 0x140068DC0
    {
        USHORT Type;
        ULONG  Len, Cumul, F78;
        ULONG64 F50, F88;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
            return Result;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140068DCD
        Ctx.ReadPtr += Len;                                       // 0x140068DD7
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140068DDE
        F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 0x512 && F88 == 0x40000ULL                    // 0x140068DEB
            && F78 != 0 && F50 == 64)                             // 0x140068DF2 / DF9
        {
            ULONG r = Cumul + F78 - (ULONG)(ULONG_PTR)PeBase;      // 0x140068DFE
            if (r && r < PeSize)                                  // 0x140068E00 / E04
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x7D9,                 // 0x140068E19
                        ModuleBase + (__int64)r);
                return 1;                                         // 0x140068E1E
            }
        }
    }
    return Result;                                                 // 0x140068E22
}

// ScanKfdDriverSectionV2 — 四层嵌套扫描 KFD 驱动节区（V2）
// 对应原始驱动 0x140069D54（982 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取：首读 0x7DA（配对 Find* 的偏移槽）→ 0x1A1（基址）；
//   命中写 0x7DC / 0x7DD（本函数的两个结果槽）。
// 【字段映射】描述符 0x120 布局；用到 +0x08 +0x20(byte) +0x38 +0x50 +0x58
//   +0x70 +0x78 +0x88 +0xF0 +0x118。
//   【⚠ 更正】原稿把 flags 字节写成 +0xA0、把 ==1 判别字段写成 +0x0C，均错。
//   依据（两种独立方法一致）：① IDA 栈帧 var_140=[rsp+B0h]、var_158=[rsp+98h]，
//   而描述符起点 = [rsp+90h]，故 rbp-0x50 = 描述符 +0x20、rbp-0x68 = +0x08；
//   ② capstone 原始字节：`test byte ptr [rbp-0x50], 4`（=+0x20）、
//   `cmp dword ptr [rbp-0x68], 1`（=+0x08）。
// 【算法】四层（每层"先找 0x558 算 RVA，再按类型+条件推进"）：
//   L1（上限 0x64）：类型 1349 直接返回 0；类型 0x558 且 RVA 合法 → v7；
//   L2（上限 0x64）：类型 0x558 → 记 v12；否则若
//       (类型 1065 且 (字段+0x20 & 4) 且 字段+0x88==0x400000000 且 字段+0x70==1)
//       或 (类型 1137 且 (字段+0x20 & 4))，且 v12 合法 → v11 = v12，break；
//   L3（上限 0x64）：类型 1245 且 字段+0x08==1 → 若 字段+0x58==1 且
//       (字段+0x88 & 0x10000) 且 (int)字段+0x78 > 0 且 !v16 → v16 = 字段+0x78；
//       类型 1277 或 318 且 v16 非零 → 由 字段+0x38 算 RVA(v20) 进入 L4；
//   L4（上限 0x1E）：类型 1296(0x510) 且 字段+0x88==0x40000 且 字段+0x78!=0
//       且 字段+0x50==64 且 !字段+0x58 → 算 RVA(v23)，合法则
//       写 GT 0x7DC = v16、GT 0x7DD = 基址 + v23，返回 1。
// 对应原始驱动 0x140069D54（982 字节）
char __fastcall ScanKfdDriverSectionV2(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   i;
    ULONG   Rva1 = 0, Rva2 = 0, Save = 0, Rva3 = 0;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);            // 0x140069D99
    if (!Offset)
    {
        FindKfdGetRefCalloutExport(PeBase, PeSize);               // 0x140069DA5
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x140069DBE
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x140069DD4
        return Result;

    /* ---- L1（0x140069E26）：找 0x558 ---- */
    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x140069E06
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F38;
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069E33
        Ctx.ReadPtr += Len;                                       // 0x140069E3D
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069E42
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);

        if (Type == 0x545)                                        // 0x140069E4E
            return Result;
        if (Type == 0x558)                                        // 0x140069E66
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
            if (r && r < PeSize) { Rva1 = r; break; }              // 0x140069E73
        }
        if ((ULONG)(++i) >= 0x64) break;                          // 0x140069E6F
    }

    if (!Rva1 || Rva1 >= PeSize)                                  // 0x140069E82
        return Result;

    /* ---- L2（0x140069ECE）：1368 → 1065/1137 ---- */
    InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,        // 0x140069EB4
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F70, F78; ULONG64 F88; UCHAR A20;
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) break;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069EDF
        Ctx.ReadPtr += Len;                                       // 0x140069EE9
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069EEE
        F70  = *(ULONG *)((PUCHAR)Entry + 0x70);
        F78  = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88  = *(ULONG64 *)((PUCHAR)Entry + 0x88);
        A20  = *(UCHAR *)((PUCHAR)Entry + 0x20);

        if (Type == 0x558)                                        // 0x140069EFA
        {
            Rva2 = Cumul + *(ULONG *)((PUCHAR)Entry + 0x38) - (ULONG)(ULONG_PTR)PeBase;
        }
        else if (((Type == 1065 && (A20 & 4) != 0 && F88 == 0x400000000ULL && F70 == 1)
                  || (Type == 1137 && (A20 & 4) != 0))            // 0x140069F42
                 && Rva2 && Rva2 < PeSize)
        {
            Save = Rva2;                                          // 0x140069F52
            break;
        }
        if ((ULONG)(++i) >= 0x64) break;                          // 0x140069F4B
    }

    if (!Save || Save >= PeSize)                                  // 0x140069F64
        return Result;

    /* ---- L3（0x140069FB2）：1245 / 1277 / 318 ---- */
    InitPESectionReadContext(PeBase + Save, PeSize - Save,        // 0x140069F9B
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; ; )
    {
        USHORT Type; ULONG Len, Cumul, F38, F58, F78; ULONG64 F88;
        // 【修正 2026-10-15】此处原误写为 break —— 跳出 L3 循环后直接落到函数末尾，缺 return
        //   （LTCG 重编译报 C4715）。原始 0x14006A086 为 `jnz loc_14006A0FE`，
        //   而 loc_14006A0FE = `mov al, bl`（bl 恒为 0），语义等价于 return 0。
        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry)) return Result;
        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x140069FC3
        Ctx.ReadPtr += Len;                                       // 0x140069FCD
        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x140069FD2
        F38 = *(ULONG *)((PUCHAR)Entry + 0x38);
        F58 = *(ULONG *)((PUCHAR)Entry + 0x58);
        F78 = *(ULONG *)((PUCHAR)Entry + 0x78);
        F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 1245 && *(ULONG *)((PUCHAR)Entry + 0x08) == 1)// 0x140069FE4
        {
            if (F58 == 1 && (F88 & 0x10000ULL) != 0
                && (int)F78 > 0 && !Rva3)                          // 0x140069FFE
                Rva3 = F78;                                        // 0x14006A000
        }
        else if ((Type == 1277 && Rva3) || (Type == 318 && Rva3))  // 0x14006A022
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;      // 0x14006A02A
            if (r && r < PeSize)                                  // 0x14006A02C / 030
            {
                /* ---- L4（0x14006A086）：1296 ---- */
                InitPESectionReadContext(PeBase + r, PeSize - r,   // 0x14006A06E
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (ULONG k = 0; k < 0x1E; ++k)                  // 0x14006A0DC
                {
                    USHORT T4; ULONG L4, C4, F58b, F78b; ULONG64 F50b, F88b;
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))
                        return Result;

                    L4 = *(ULONG *)((PUCHAR)Entry + 0xF0);
                    C4 = L4 + (ULONG)Ctx.ReadPtr;                 // 0x14006A098
                    Ctx.ReadPtr += L4;                            // 0x14006A0A2
                    T4   = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);
                    F50b = *(ULONG64 *)((PUCHAR)Entry + 0x50);
                    F58b = *(ULONG *)((PUCHAR)Entry + 0x58);
                    F78b = *(ULONG *)((PUCHAR)Entry + 0x78);
                    F88b = *(ULONG64 *)((PUCHAR)Entry + 0x88);

                    if (T4 == 0x510 && F88b == 0x40000ULL          // 0x14006A0B5
                        && F78b != 0 && F50b == 64 && !F58b)       // 0x14006A0BC / 0C8
                    {
                        ULONG r3 = C4 + F78b - (ULONG)(ULONG_PTR)PeBase;   // 0x14006A0CD
                        if (r3 && r3 < PeSize)                     // 0x14006A0CF / 0D3
                        {
                            GtWrite((GLOBAL_TABLE_INDEX)0x7DC, (__int64)Rva3);      // 0x14006A0E8
                            GtWrite((GLOBAL_TABLE_INDEX)0x7DD,
                                    ModuleBase + (__int64)r3);                      // 0x14006A0F7
                            return 1;
                        }
                    }
                }
                return Result;                                    // 0x14006A086
            }
        }
        if ((ULONG)(++i) >= 0x64) return Result;                  // 0x14006A037
    }
}

// ScanKfdDriverSectionV3 — 四层嵌套扫描 KFD 驱动节区（V3，增强版）
// 对应原始驱动 0x14006A12C（986 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写，并逐条与
//   capstone 原始字节核对（见下方【字段映射】的两种独立证据）。
// 【GT 依据】寄存器跟踪提取的调用序：
//   读 0x7DA（配对 FindKfdGetRefCalloutExport 的偏移槽；为 0 时先调用它再读）
//   → 读 0x1A1（KFD 驱动模块基址）→ 读 0x914 三次（Windows 构建号，做版本分支）；
//   命中写 0x7DC / 0x7DD（本函数的两个结果槽，同 V2）。
// 【字段映射】栈帧定案：上下文 = [rsp+40h]（v24，0x48 字节，ReadPtr 即 +0x08=v25），
//   指令描述符 = [rsp+90h]（v26，0x120 字节）。故描述符字段为
//   +0x08(==1 判别) +0x38 +0x50 +0x58 +0x78 +0x88 +0xF0(指令长度) +0x118(类型指针)。
//   ① IDA 栈帧：var_158=[rsp+98h]=+0x08、var_110=[rsp+E0h]=+0x50、
//      var_D8=[rsp+118h]=+0x88、var_E8=[rsp+108h]=+0x78、var_108=[rsp+E8h]=+0x58、
//      var_128=[rsp+C8h]=+0x38、var_70=[rsp+180h]=+0xF0、var_48=[rsp+1A8h]=+0x118。
//   ② capstone 原始字节：`cmp dword ptr [rbp-0x68], 1`（=+0x08）、
//      `cmp qword ptr [rbp-0x20], 0x20`（=+0x50）、`test qword ptr [rbp+0x18], 0x10000`
//      （=+0x88）、`mov edi, dword ptr [rbp+0x8]`（=+0x78）、
//      `cmp dword ptr [rbp-0x18], ebx`（=+0x58，与 0 比较）。
// 【与 V2 的差异】① L2 仅在第 2 个 1368 才推进（`++v11 == 2`），循环上限 0x32；
//   ② L2 整体受构建号分支门控（Win10 19041-20270 即 0x4A61..0x4F7C，或 >=22621
//      即 0x585D）；③ L3 的 1245 分支用 字段+0x50==32（V2 用 +0x58==1），且不写
//      GT；④ 其余层次与 V2 同构（L1 上限 0x64、L3 上限 0x64、L4 上限 0x1E）。
// 【算法】四层：
//   L1（上限 0x64）：类型 1349 → break；类型 1368 且 RVA 合法 → v7，break；
//   L2（门控，上限 0x32）：类型 1349 → 直接返回 0；类型 1368 且这是第 2 个
//       且 RVA 合法 → v7，break；
//   L3（上限 0x64）：类型 1245 且 字段+0x08==1 → 若 字段+0x50==32 且
//       (字段+0x88 & 0x10000) 且 (int)字段+0x78 > 0 且 !v15 → v15 = 字段+0x78；
//       类型 1277 或 318 且 v15 非零 → 由 字段+0x38 算 RVA(v19) 进入 L4；
//   L4（上限 0x1E）：类型 1296(0x510) 且 字段+0x88==0x40000 且 字段+0x78!=0
//       且 字段+0x50==64 且 !字段+0x58 → 算 RVA(v22)，合法则
//       写 GT 0x7DC = v15、GT 0x7DD = 基址 + v22，返回 1。
// 【返回值】0（未命中）；1（命中）；L2 读条目失败路径返回 0。
// 对应原始驱动 0x14006A12C（986 字节）
char __fastcall ScanKfdDriverSectionV3(__int64 PeBase, unsigned int PeSize)
{
    char    Result = 0;
    ULONG   Offset;
    __int64 ModuleBase;
    ULONG   BuildNumber;
    ULONG   Rva1 = 0, Rva2 = 0, Rva3 = 0;
    ULONG   i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];          // 描述符：0x120 字节（ReadPESectionEntry 写 0x120）

    Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);            // 0x14006A171
    if (!Offset)
    {
        FindKfdGetRefCalloutExport(PeBase, PeSize);               // 0x14006A17D
        Offset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x7DA);        // 0x14006A18A
    }

    ModuleBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x1A1);      // 0x14006A196
    if (!ModuleBase || !Offset || Offset >= PeSize)               // 0x14006A1AC
        return Result;

    /* ---- L1（0x14006A1DE）：找 1368 ---- */
    InitPESectionReadContext(PeBase + Offset, PeSize - Offset,    // 0x14006A1DE
                             2, 0, -1, 0, 0, (__int64)&Ctx);
    for (i = 0; i < 0x64; ++i)                                    // 0x14006A1E5
    {
        USHORT Type;
        ULONG  Len, Cumul, F38;

        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))       // 0x14006A1F7
            break;

        Len   = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                         // 0x14006A20B
        Ctx.ReadPtr += Len;                                       // 0x14006A215
        Type  = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006A21A
        F38   = *(ULONG *)((PUCHAR)Entry + 0x38);

        if (Type == 0x545)                                        // 0x14006A226（1349）
            break;
        if (Type == 0x558)                                        // 0x14006A23A（1368）
        {
            ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
            if (r && r < PeSize) { Rva1 = r; break; }             // 0x14006A247
        }
    }

    /* ---- L2（0x14006A2BC）：仅特定构建号，取第 2 个 1368 ---- */
    // 原始条件对 GT 0x914 连读三次（寄存器跟踪序可见三连读），此处保持同序。
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);            // 0x14006A28A
    if (((BuildNumber >= 0x4A61 && (ULONG)GtRead(GtWindowsBuildNumber) <= 0x4F7C)
         || (ULONG)GtRead(GtWindowsBuildNumber) >= 0x585D)
        && Rva1 && Rva1 < PeSize)                                 // 0x14006A2BC
    {
        int Seen1368 = 0;
        int Count32  = 0;

        InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,    // 0x14006A2BC
                                 2, 0, -1, 0, 0, (__int64)&Ctx);
        Rva1 = 0;                                                 // 0x14006A2C1
        while (!(ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))    // 0x14006A2D9
        {
            *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(unsigned int *)((PUCHAR)Entry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            USHORT Type;
            ULONG  Len, Cumul, F38;

            Len   = *(ULONG *)((PUCHAR)Entry + 0xF0);
            Cumul = Len + (ULONG)Ctx.ReadPtr;                     // 0x14006A2E6
            Ctx.ReadPtr += Len;                                   // 0x14006A2F0
            Type  = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006A2F5
            F38   = *(ULONG *)((PUCHAR)Entry + 0x38);

            if (Type == 0x545)                                    // 0x14006A301
                return Result;                                    // 注意：是 return 而非 break
            if (Type == 0x558 && ++Seen1368 == 2)                 // 0x14006A326
            {
                ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;
                if (r && r < PeSize) { Rva1 = r; break; }         // 0x14006A333
            }
            if ((ULONG)(++Count32) >= 0x32)                       // 0x14006A32F
                break;
        }
    }

    /* ---- L3（0x14006A377）：1245 / 1277 / 318 ---- */
    Rva3 = 0;                                                     // 0x14006A335（v15）
    if (Rva1 && Rva1 < PeSize)                                    // 0x14006A342
    {
        InitPESectionReadContext(PeBase + Rva1, PeSize - Rva1,    // 0x14006A377
                                 2, 0, -1, 0, 0, (__int64)&Ctx);
        for (i = 0; ; )                                           // 0x14006A37C（v16，上限 0x64）
        {
            USHORT Type;
            ULONG  Len, Cumul, F38;

            if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))   // 0x14006A38E
                break;

            Len   = *(ULONG *)((PUCHAR)Entry + 0xF0);
            Cumul = Len + (ULONG)Ctx.ReadPtr;                     // 0x14006A39F
            Ctx.ReadPtr += Len;                                   // 0x14006A3A9
            Type  = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);  // 0x14006A3AE
            F38   = *(ULONG *)((PUCHAR)Entry + 0x38);

            if (Type == 1245 && *(ULONG *)((PUCHAR)Entry + 0x08) == 1)   // 0x14006A3BC/3C0
            {
                ULONG64 F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
                ULONG64 F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
                ULONG   F78 = *(ULONG *)((PUCHAR)Entry + 0x78);

                if (F50 == 32 && (F88 & 0x10000ULL) != 0
                    && (int)F78 > 0 && !Rva3)                     // 0x14006A3C2..3DB
                    Rva3 = F78;                                   // 0x14006A3DD
            }
            else if ((Type == 1277 && Rva3) || (Type == 318 && Rva3))    // 0x14006A3FF
            {
                ULONG r = Cumul + F38 - (ULONG)(ULONG_PTR)PeBase;     // 0x14006A407
                if (r && r < PeSize)                                  // 0x14006A409/40D
                {
                    /* ---- L4（0x14006A44A）：1296 ---- */
                    ULONG k;

                    InitPESectionReadContext(PeBase + r, PeSize - r, // 0x14006A44A
                                             2, 0, -1, 0, 0, (__int64)&Ctx);
                    for (k = 0; ; )                               // 0x14006A44F（v20，上限 0x1E）
                    {
                        USHORT T4;
                        ULONG  L4, C4;

                        if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry))  // 0x14006A462
                            return Result;

                        L4 = *(ULONG *)((PUCHAR)Entry + 0xF0);
                        C4 = L4 + (ULONG)Ctx.ReadPtr;             // 0x14006A474
                        Ctx.ReadPtr += L4;                        // 0x14006A47E
                        T4 = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);

                        if (T4 == 0x510                             // 0x14006A491（1296）
                            && *(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x40000ULL)
                        {
                            ULONG64 F50 = *(ULONG64 *)((PUCHAR)Entry + 0x50);
                            ULONG   F58 = *(ULONG *)((PUCHAR)Entry + 0x58);
                            ULONG   F78 = *(ULONG *)((PUCHAR)Entry + 0x78);

                            if (F78)                              // 0x14006A493/498（v30）
                            {
                                if (F50 == 64 && !F58)            // 0x14006A49A/4A1
                                {
                                    ULONG r3 = C4 + F78 - (ULONG)(ULONG_PTR)PeBase;  // 0x14006A4A6
                                    if (r3 && r3 < PeSize)        // 0x14006A4AB/4AF
                                    {
                                        GtWrite((GLOBAL_TABLE_INDEX)0x7DC, (__int64)Rva3);       // 0x14006A4C4
                                        GtWrite((GLOBAL_TABLE_INDEX)0x7DD,
                                                ModuleBase + (__int64)r3);                   // 0x14006A4D3
                                        return 1;                 // 0x14006A4D8
                                    }
                                }
                            }
                        }
                        if ((ULONG)(++k) >= 0x1E)                 // 0x14006A4B1/4B4/4B8
                            return Result;
                    }
                    return Result;                                // 0x14006A462（读条目失败退出）
                }
            }
            if ((ULONG)(++i) >= 0x64)                             // 0x14006A40F/411/414
                return Result;
        }
    }

    return Result;                                                // 0x14006A4DC
}

// FindWin32kSectionByType — 按节区类型 1298 查找 Win32k 数据节区
// 对应原始驱动 0x1400888FC（356 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪提取的调用序：
//   读 0x20（GtEprocessField22 = Win32k 映像基址）
//   读 0x21（GtEprocessField23 = Win32k 映像大小）
//   读 0x21 复用为循环边界比较；
//   读 0x4348（GtTotalSize|GtNtCreateFileSyscallResult = 节区起始偏移）
//   命中写 0x31A（GtCallbackField73 = 结果槽）。
// 【算法】四个 GT 值齐备且 偏移 < 大小 → 以 (基址+偏移, 大小-偏移) 初始化上下文；
//   循环上限 0x64：类型 1298(0x512) 且 字段+0x88 == 0x40000 且 字段+0x40 非零
//   且 字段+0x50 == 64 → 算 RVA = 累计 + 字段+0x40 - 基址，非 0 且 < 大小 →
//   写 GT 0x31A = ntoskrnl 模块基址 + RVA。
// 【返回值】伪代码里是 `result`（读条目失败时为 ReadPESectionEntry 的返回值，
//   命中时为 GtWrite 的返回值）。此处按项目惯例以 __int64 返回同一表达式。
// 对应原始驱动 0x1400888FC（356 字节）
__int64 FindWin32kSectionByType(void)
{
    __int64  Win32kBase;         // v0 = GtRead(0x20)
    ULONG    Win32kSize;         // v1 = GtRead(0x21)
    __int64  NtoskrnlBase;       // v2 = GtRead(3)
    __int64  result;             // = GtRead(0x4348)
    ULONG    i;
    PE_DECODE_CONTEXT Ctx;
    _DWORD   Entry[112];         // 描述符：原 [20] 仅 80 字节（ReadPESectionEntry 写 0x120）

    Win32kBase   = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x20);      // 0x140088934（GtEprocessField22=32）
    Win32kSize   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);        // 0x140088941（GtEprocessField23=33）
    NtoskrnlBase = (__int64)GtRead(GtNtoskrnlModuleBase);          // 0x14008894E（3）
    result       = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4348);    // 0x140088951

    if (!Win32kBase || !Win32kSize || !NtoskrnlBase                 // 0x14008897A
        || (ULONG)result == 0 || (ULONG)result >= Win32kSize)
        return result;

    InitPESectionReadContext(Win32kBase + (ULONG)result,           // 0x1400889AD
                             Win32kSize - (ULONG)result,
                             2, 0, -1, 0, 0, (__int64)&Ctx);

    for (i = 0; i < 0x64; ++i)                                     // 0x1400889B2
    {
        USHORT Type;
        ULONG  Len, Cumul, F40;
        ULONG64 F50, F88;

        result = (__int64)ReadPESectionEntry((PUCHAR)&Ctx, Entry);  // 0x1400889C1
        if ((ULONG)result != 0)                                     // 0x1400889C8
            break;

        Len = *(ULONG *)((PUCHAR)Entry + 0xF0);
        Cumul = Len + (ULONG)Ctx.ReadPtr;                          // 0x1400889DB
        Ctx.ReadPtr += Len;                                        // 0x1400889E6

        Type = *(USHORT *)((*(ULONG64 *)((PUCHAR)Entry + 0x118)) + 6);   // 0x1400889DE
        F40  = *(ULONG *)((PUCHAR)Entry + 0x40);
        F50  = *(ULONG64 *)((PUCHAR)Entry + 0x50);
        F88  = *(ULONG64 *)((PUCHAR)Entry + 0x88);

        if (Type == 0x512 && F88 == 0x40000ULL)                    // 0x1400889FD
        {
            if (F40 != 0                                            // 0x140088A08
                && F50 == 64)                                       // 0x140088A13
            {
                ULONG r = Cumul + F40 - (ULONG)(ULONG_PTR)Win32kBase;   // 0x140088A17
                if (r && r < Win32kSize)                            // 0x140088A19 / A1D
                {
                    return (__int64)GtWrite(GtCallbackField73,      // 0x140088A32
                                            NtoskrnlBase + (__int64)r);
                }
            }
        }
    }
    return result;                                                  // 0x140088A37
}

// OpenFileQueryInfo — 打开文件对象并查询其基本信息
// 对应原始驱动 0x140019678（265 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】寄存器跟踪 + 逐字节提取：
//   读 0x41F3（ZwCreateFile 族函数指针）
//   读 0x4208（ZwQueryInformationFile 族函数指针）
//   读 0x4334（GtExFreePoolFunc，此处用作句柄关闭函数）
// 【结构】v12 起是 OBJECT_ATTRIBUTES 形态的 {Length=48, RootDir=0, Name=FilePath,
//   Attributes=576(0x240)}；v17[32] 为输出信息缓冲（32 字节），v11 为 IO_STATUS。
// 【返回值】Result 初值 1；只有走到"打开成功"分支才被赋值为
//   (查询结果 != STATUS_OBJECT_NAME_NOT_FOUND(0xC0000034))，
//   即"打开失败 / 函数指针缺失"都返回 1（原始如此，非笔误）。
// 对应原始驱动 0x140019678（265 字节）
char __fastcall OpenFileQueryInfo(__int64 FilePath, __int64 Context)
{
    char     Result = 1;
    __int64  CreateFileFunc;
    __int64  QueryInfoFunc;
    __int64  CloseFunc;
    __int64  Handle = 0;             // v10
    UCHAR    IoStatus[8];            // v11
    UCHAR    ObjAttr[0x30];          // v12 起：Length/RootDir/Name/Attributes
    UCHAR    InfoBuf[32];            // v17
    int      QueryStatus;

    CreateFileFunc = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x41F3);   // 0x1400196B3
    QueryInfoFunc  = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4208);   // 0x1400196C0
    CloseFunc      = (__int64)GtRead(GtExFreePoolFunc);             // 0x1400196CD（0x4334）

    if (!CreateFileFunc || !QueryInfoFunc || !CloseFunc)            // 0x1400196DB~6E5
        return Result;

    // 0x1400196F6~711：布置 OBJECT_ATTRIBUTES（Length=48、Attributes=0x240、ObjectName=FilePath）
    *(ULONG *)&ObjAttr[0x00] = 48;                                  // v12
    *(ULONG64 *)&ObjAttr[0x08] = 0;                                 // v13（RootDirectory）
    *(ULONG64 *)&ObjAttr[0x10] = FilePath;                          // v14（ObjectName）
    *(ULONG *)&ObjAttr[0x18] = 576;                                 // v15（Attributes = 0x240）

    if ((int)((__int64(__fastcall *)(__int64 *, __int64, void *))CreateFileFunc)(
            &Handle, 1, ObjAttr) >= 0)                              // 0x14001971A
    {
        QueryStatus = (int)((__int64(__fastcall *)(__int64, __int64, __int64,
                                                  void *, int, void *))QueryInfoFunc)(
            Handle, Context, 0, InfoBuf, 32, IoStatus);             // 0x14001974D
        Result = (QueryStatus != (int)0xC0000034) ? 1 : 0;          // STATUS_OBJECT_NAME_NOT_FOUND
        ((void(__fastcall *)(__int64))CloseFunc)(Handle);            // 0x140019751
    }
    return Result;                                                  // 0x140019755
}

// QueryAllocFilePath — 查询文件对象名并按需分配缓冲返回完整路径
// 对应原始驱动 0x1400197BC（220 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【GT 依据】逐字节提取：读 0x4220（ObQueryNameString 族函数指针）。
// 【算法】先以 (FileObject,0,0,&Size) 调查询函数，期望返回 STATUS_BUFFER_TOO_SMALL
//   (0xC0000023) 且 Size+100 无溢出 → ExAlloc(PagedPool, Size+100)；
//   再以 (FileObject, buf, Size+32, &Size) 查询，成功且
//   buf[1](OBJECT_NAME_INFORMATION.NameBuffer) == buf+2（即名字紧跟结构体）
//   且 (WORD)buf == Size+16 <= Size+32 且 (UINT)(WORD)buf < Size+32 →
//   在名字末尾补 NUL 并返回该缓冲；否则 ExFree 后返回 0。
// 对应原始驱动 0x1400197BC（220 字节）
_QWORD *__fastcall QueryAllocFilePath(__int64 FileObject)
{
    __int64  Result = 0;
    __int64  QueryNameFunc;
    _QWORD  *NameBuffer;
    ULONG    RequiredSize = 0;
    int      Status;

    QueryNameFunc = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4220);    // 0x1400197DA
    if (!FileObject || !QueryNameFunc)                              // 0x1400197E5 / 7EE
        return (_QWORD *)Result;

    Status = (int)((__int64(__fastcall *)(__int64, __int64, __int64, ULONG *))QueryNameFunc)(
        FileObject, 0, 0, &RequiredSize);                           // 0x140019801
    if (Status != (int)0xC0000023)                                  // 0x140019813
        return (_QWORD *)Result;
    if ((ULONG64)RequiredSize + 100 <= (ULONG64)RequiredSize)       // 溢出保护
        return (_QWORD *)Result;

    NameBuffer = (_QWORD *)ExAlloc(1 /*PagedPool*/, RequiredSize + 100);   // 0x14001981A
    if (!NameBuffer)                                                // 0x140019825
        return (_QWORD *)Result;

    Status = (int)((__int64(__fastcall *)(__int64, _QWORD *, __int64, ULONG *))QueryNameFunc)(
        FileObject, NameBuffer, (__int64)RequiredSize + 32, &RequiredSize);   // 0x140019869
    if (Status >= 0)
    {
        _QWORD *NameInfo = (_QWORD *)NameBuffer[1];
        ULONG64 BufferSize = *(USHORT *)NameBuffer;
        if (NameBuffer + 2 == NameInfo                                  // 0x140019869
            && BufferSize + 16 <= (ULONG64)RequiredSize + 32
            && (ULONG)BufferSize < RequiredSize + 32)
        {
            *((WORD *)NameInfo + (BufferSize >> 1)) = 0;                // 0x14001986E
            return NameBuffer;                                          // 0x140019873
        }
    }
    ExFree(NameBuffer);                                             // 0x14001987B
    return (_QWORD *)Result;                                        // 0x140019880
}

// CheckCommPortFilePathExists — 拼接/规范化通信端口文件路径并检查其是否存在
// 对应原始驱动 0x140019438（362 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
// 【入参结构】FilePathInfo 是含两个元素的指针数组：
//   FilePathInfo[0] = 指向 UNICODE_STRING 的指针（*FilePathInfo = 该 UNICODE_STRING 首址，
//     其 +0x00 是 Length(字节数)、+0x08 是 Buffer）
//   FilePathInfo[1] = 文件对象（供 QueryAllocFilePath 查询其完整路径）
// 【逻辑】
//   ① 取 UNICODE_STRING 的 Length；< 2 直接返回 0；
//   ② 若 名字缓冲首字符 == L'\\'(92)（已是完整路径）：
//        ExAlloc(PagedPool, Length+4) → memmove(名字, Length) → 末尾补 NUL；
//   ③ 否则（相对路径）：QueryAllocFilePath(FilePathInfo[1]) 取目录完整路径，
//        总长 = 目录长 + 名字长 + 10；溢出三重检查通过后 ExAlloc(PagedPool, 总长) →
//        memmove(目录, 目录长) → 在目录末尾写 L'\\' → memmove(名字, 名字长) → 末尾补 NUL；
//        随后 ExFree(目录缓冲)；
//   ④ 若拼出完整路径：Result = (OpenFileCheckExists(路径) == 0)，再 ExFree(路径)。
// 对应原始驱动 0x140019438（362 字节）
bool __fastcall CheckCommPortFilePathExists(unsigned __int16 **FilePathInfo)
{
    unsigned __int16 *NameStruct;
    bool    Result = 0;
    USHORT  NameLen;
    _WORD  *FullPath = 0;
    const void **DirPath;
    int     DirLen, TotalLen;

    NameStruct = *FilePathInfo;                                     // 0x140019455
    NameLen    = *NameStruct;                                       // 0x14001945D（UNICODE_STRING.Length）
    if (NameLen < 2)                                                // 0x140019468
        return Result;

    if (*(WORD *)(*((_WORD **)NameStruct + 1)) == 92)               // 0x14001947C（L'\\'，即 +0x08 = Buffer）
    {
        /* ---- 已是完整路径：直接复制 ---- */
        FullPath = (_WORD *)ExAlloc(1 /*PagedPool*/, (ULONG64)NameLen + 4);   // 0x14001948C
        if (!FullPath)                                              // 0x140019497
            return Result;

        memmove(FullPath, *((const void **)NameStruct + 1), NameLen);        // 0x1400194AB
        FullPath[(ULONG64)NameLen >> 1] = 0;                        // 0x1400194B9
    }
    else
    {
        /* ---- 相对路径：取目录全路径后拼接 ---- */
        DirPath = (const void **)QueryAllocFilePath((__int64)FilePathInfo[1]);   // 0x1400194C6
        if (!DirPath)                                               // 0x1400194D1
            return Result;

        DirLen   = *(USHORT *)DirPath;                              // 0x1400194E3（目录 UNICODE_STRING.Length）
        TotalLen = DirLen + NameLen + 10;                           // 0x1400194EB
        if (TotalLen > DirLen && TotalLen > NameLen                  // 0x1400194FA（三重溢出检查）
            && TotalLen > DirLen + NameLen)
        {
            FullPath = (_WORD *)ExAlloc(1 /*PagedPool*/, (ULONG64)TotalLen);   // 0x140019502
            if (FullPath)                                           // 0x14001950D
            {
                memmove(FullPath, DirPath[1], *(USHORT *)DirPath);            // 0x14001951B
                *(WORD *)((char *)FullPath + *(USHORT *)DirPath) = 92;        // 0x140019524（L'\\'）
                memmove((char *)FullPath + *(USHORT *)DirPath + 2,            // 0x14001953E
                        *((const void **)NameStruct + 1), NameLen);
                FullPath[(ULONG64)(NameLen + *(USHORT *)DirPath + 2) >> 1] = 0;   // 0x140019557
            }
        }
        ExFree((void *)DirPath);                                    // 0x14001955E
    }

    if (FullPath)                                                   // 0x140019566
    {
        Result = (OpenFileCheckExists((__int64)FullPath) == 0) ? 1 : 0;   // 0x140019578
        ExFree(FullPath);                                           // 0x14001957C
    }
    return Result;                                                  // 0x140019581
}

// FindFwpsDispatchTableWin8 — 扫描节区查找 Win8 Fwps 调度表
// 对应原始驱动 0x14001B72C（611 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（80 行伪代码），按伪代码实现。
// 【逻辑】与 FindFwpsTcpIpDispatchTable 同构（同样按构建号 0x23F0 分两路），
//   差异：入口 RVA 取 GT 0x7FE（L2 调度表，为 0 则先调 FindFwpsL2DispatchTable）；
//   写入目标是 GT 0x800（基址+RVA）与 GT 0x801（条目数）；
//   高版本路径的条目数**固定为 12**；低版本路径为 +0x50 >> 3。
// =========================================================================
// 对应原始驱动 0x14001B72C（611 字节）
char __fastcall FindFwpsDispatchTableWin8(__int64 a1, unsigned int a2)
{
    char Result = 0;
    unsigned int L2ExportOffset;
    __int64 FwpsBase;
    __int64 CumulativeSize = 0;
    PE_DECODE_CONTEXT ReadContext;
    _DWORD SectionEntry[112];

    L2ExportOffset = (unsigned int)GtRead(GtFwpsL2Offset);
    if (!L2ExportOffset)
    {
        FindFwpsL2DispatchTable(a1, a2);
        L2ExportOffset = (unsigned int)GtRead(GtFwpsL2Offset);
    }
    FwpsBase = GtRead(GtFwpsModuleBase);
    if (!FwpsBase || !L2ExportOffset || L2ExportOffset >= a2)
        return Result;

    InitPESectionReadContext(a1 + L2ExportOffset, a2 - L2ExportOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; LoopIndex++)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            ULONG MatchSize;
            __int16 SubType;
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                break;
            MatchSize = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)CumulativeSize;
            CumulativeSize += *(ULONG *)((char *)SectionEntry + 0xF0);
            SubType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(ULONG *)((char *)SectionEntry + 0x50) && *(__int64 *)((char *)SectionEntry + 0x70) == 64)
            {
                ULONG MatchOffset = MatchSize + *(ULONG *)((char *)SectionEntry + 0x50) - (ULONG)a1;
                if (MatchOffset && MatchOffset < a2)
                {
                    GtWrite(GtFwpsDispatchTableBase, FwpsBase + MatchOffset);   // GT 0x800
                    GtWrite(GtFwpsDispatchTableCount, 12);                      // GT 0x801
                    return 1;
                }
            }
        }
    }
    else
    {
        unsigned int FirstMatchOffset = 0;
        for (unsigned int LoopIndex = 0; LoopIndex < 0x64; LoopIndex++)
        {
            ULONG MatchSize;
            __int16 SubType;
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                break;
            MatchSize = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)CumulativeSize;
            CumulativeSize += *(ULONG *)((char *)SectionEntry + 0xF0);
            SubType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SubType == 1349)
                break;
            if (SubType == 1296)
            {
                if (*(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                    *(ULONG *)((char *)SectionEntry + 0x50) &&
                    *(__int64 *)((char *)SectionEntry + 0x70) == 64 &&
                    *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
                {
                    ULONG MatchOffset = MatchSize + *(ULONG *)((char *)SectionEntry + 0x50) - (ULONG)a1;
                    if (MatchOffset && MatchOffset < a2 && !FirstMatchOffset)
                        FirstMatchOffset = MatchOffset;
                }
            }
            else if (SubType == 1340 && SectionEntry[2] == 1 &&
                     *(_DWORD *)((char *)SectionEntry + 0xDC) == 0)
            {
                ULONG EntrySize = *(ULONG *)((char *)SectionEntry + 0x50);
                if (EntrySize >= 8)
                {
                    GtWrite(GtFwpsDispatchTableBase, FwpsBase + FirstMatchOffset);  // GT 0x800
                    GtWrite(GtFwpsDispatchTableCount, EntrySize >> 3);              // GT 0x801
                    return 1;
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// InitFwpsDispatchTables — 初始化 Fwps 调度表（4 个 Find 的调度者）
// 对应原始驱动 0x14001BE80（200 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（18 行伪代码），按伪代码实现。
// 【逻辑】ReadNtoskrnlNlsFile 读 fwpkclnt.sys；
//   对四个槽**各自"未填充才查找"**：
//     GT 0x7FA 为空 → FindFwpsTcpIpDispatchTableStr
//     GT 0x7FC 为空 → FindFwpsTcpIpDispatchTable
//     GT 0x7FE 为空 → FindFwpsL2DispatchTable
//     GT 0x800 为空 → FindFwpsDispatchTableWin8
//   最后 ExFree 文件缓冲。
// =========================================================================
// 对应原始驱动 0x14001BE80（154 字节）
void InitFwpsDispatchTables(void)
{
    unsigned int FileSize = 0;
    void *FileBuffer = 0;

    if (ReadNtoskrnlNlsFile((_QWORD *)&FileBuffer, &FileSize))
    {
        if (!GtRead(GtFwpsTcpIpOffset))
            FindFwpsTcpIpDispatchTableStr((__int64)FileBuffer, FileSize);
        if (!GtRead(GtFwpsTcpIpTableAddr))
            FindFwpsTcpIpDispatchTable((__int64)FileBuffer, FileSize);
        if (!GtRead(GtFwpsL2Offset))
            FindFwpsL2DispatchTable((__int64)FileBuffer, FileSize);
        if (!GtRead(GtFwpsDispatchTableBase))
            FindFwpsDispatchTableWin8((__int64)FileBuffer, FileSize);
        ExFree(FileBuffer);
    }
}
// MiniFilterAcquireForModWrite — 获取修改写调度表（补全空壳）
// 对应原始驱动 0x14001BD44（316 字节）
// 【⚠ 修正记录 2026-10-08】原名 `CmdInitFwpsDispatchTables2`、注释称"获取文件修改
//   写入的独占锁，需要 FltAcquireForModifiedWrite" —— **名字与描述均与实物不符**。
//   原始 IDA 名是 `MiniFilterAcquireForModWrite`，实际功能是
//   "把 Fwps 修改写调度表复制到用户输出缓冲区"。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（47 行伪代码），按伪代码实现。
// 【参数】FilterObject / CallbackData（未使用）/ OutputBuffer / BufferSize
// 【逻辑】GT 0x7FC 为空则先调 InitFwpsDispatchTables 补齐；
//   取 GT 0x7FC（表指针，须 > MmSystemRangeStart）与 GT 0x7FD（条目数，< 0x100）；
//   取 *TablePtr 为表数据，须有效且 CheckMemoryValid(&TableData[8*EntryCount-1]) 通过；
//   输出缓冲须非空、大小 >= 8*(EntryCount-1)+16、位于用户空间；
//   ProbeForWrite + 清零后：*OutputBuffer = EntryCount，
//   memmove(OutputBuffer+2, TableData, 8*EntryCount) —— 即把表项数组拷到 +8 处。
// 对应原始驱动 0x14001BD44（316 字节）
char __fastcall MiniFilterAcquireForModWrite(__int64 FilterObject, __int64 CallbackData,
                                            unsigned int *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    void **TablePtr;
    unsigned int TableCount;
    unsigned int EntryCount;
    char *TableData;

    if (!GtRead(GtFwpsTcpIpTableAddr))
        InitFwpsDispatchTables();

    TablePtr = (void **)GtRead(GtFwpsTcpIpTableAddr);      // GT 0x7FC
    TableCount = (unsigned int)GtRead(GtFwpsTcpIpEntryCount); // GT 0x7FD
    EntryCount = TableCount;

    if (!TablePtr || !TableCount)
        return Result;
    if (TablePtr <= (void **)MmSystemRangeStart || TableCount >= 0x100)
        return Result;

    TableData = (char *)*TablePtr;
    if (TableData <= (char *)MmSystemRangeStart)
        return Result;
    if (CheckMemoryValid(TableData) != 1)
        return Result;
    if (CheckMemoryValid(&TableData[8 * EntryCount - 1]) != 1)
        return Result;
    if (!OutputBuffer)
        return Result;
    if (BufferSize < 8 * (unsigned __int64)(EntryCount - 1) + 16)
        return Result;
    if ((unsigned __int64)OutputBuffer >= MmUserProbeAddress)
        return Result;
    if ((unsigned __int64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, BufferSize, 8u);
    memset(OutputBuffer, 0, BufferSize);
    *OutputBuffer = EntryCount;
    memmove(OutputBuffer + 2, TableData, 8LL * EntryCount);
    return 1;
}

// CmdCollectGdtrEntries — 记录 GDTR 信息到上下文缓冲（补全空壳）
// 对应原始驱动 0x14001C048（229 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（20 行伪代码）
// 【⚠ 修正记录两处】① 注释地址 sub_14001A450 **在原始中不存在**（已核实），
//   正确为 0x14001C048；② 注释称"需要 FltReleaseForModifiedWrite 释放锁" —— **错误**。
//   伪代码签名 `char f(int ProcessorNumber, unsigned int **ContextBuffer)`：
//   实为**读取 GDTR 并把 GDT 信息追加写入上下文缓冲**（形似处理器/GDT 操作，
//   与"ModWrite 回调"无关 —— 见待实现文档 §7.3 的命名问题）。
// 【逻辑】ReadGdtr 取 GDTR；按 `16389 * *ContextBuffer` 算条目索引，
//   越界（`索引*4 + 65560 > 缓冲容量`）则返回 0；否则写入处理器号、
//   GDTR 值（10 字节）、段选择子（GDTR 低 16 位 >> 3）、并把 GDT 表数据 memmove 进去，
//   最后把条目计数 `*ContextBuffer` 加 1；返回 1。
char CmdCollectGdtrEntries(int ProcessorNumber, unsigned int **ContextBuffer)
{
    char Result = 1;
    _DWORD *EntryPtr;
    __int64 EntryIndex;
    _OWORD GdtrValue;

    ReadGdtr(&GdtrValue);

    EntryPtr = (_DWORD *)*ContextBuffer;
    EntryIndex = 16389LL * **ContextBuffer;
    if ((unsigned __int64)(EntryIndex * 4 + 65560) > (unsigned __int64)*((unsigned int *)ContextBuffer + 2))
        return 0;

    EntryPtr[EntryIndex + 1] = ProcessorNumber;
    *(_OWORD *)&EntryPtr[16389 * *EntryPtr + 2] = GdtrValue;
    EntryPtr[16389 * *EntryPtr + 5] = (unsigned __int64)(*(unsigned short *)&GdtrValue) >> 3;
    memmove(&EntryPtr[16389 * *EntryPtr + 6], *(const void **)((char *)&GdtrValue + 2),
            (unsigned int)(*(unsigned short *)&GdtrValue));
    ++*EntryPtr;
    return Result;
}

// CmdClearGdtPresentBit — 清除指定 GDT 选择子的 Present 位（补全空壳）
// 对应原始驱动 0x14001C130（129 字节）
// 【逆向来源】⚠ 可反编译（24 行伪代码）
// 【⚠ 修正记录】注释称"需要 CcFlushCache 相关操作" —— **错误**。实为 GDT 操作用例：
//   若处理器号匹配，ReadGdtr 取 GDTR 并与上下文 +4 处 10 字节比较（MemoryCompare）；
//   相同且上下文 +16 的选择子索引 < GDTR 限值>>3 时，
//   **清除该 GDT 条目（基址 + 8*索引 + 4）的 Present 位（0x8000）**，并置上下文 +20 = 1；
//   返回 0（"已处理当前处理器"）。
char CmdClearGdtPresentBit(int ProcessorNumber, __int64 ContextBuffer)
{
    char Result = 1;
    __int64 SelectorIndex;
    unsigned __int16 GdtrValue;
    __int64 GdtrBase;

    if (ProcessorNumber == *(_DWORD *)ContextBuffer)
    {
        ReadGdtr(&GdtrValue);
        if (!(unsigned int)MemoryCompare((__int64)&GdtrValue, (char *)(ContextBuffer + 4), 0xAu))
        {
            SelectorIndex = *(unsigned int *)(ContextBuffer + 16);
            if ((unsigned int)SelectorIndex < (unsigned int)(*(unsigned short *)&GdtrValue >> 3))
            {
                *(_WORD *)(GdtrBase + 8 * SelectorIndex + 4) &= ~0x8000u;
                *(_BYTE *)(ContextBuffer + 20) = 1;
            }
        }
        return 0;
    }
    return Result;
}

// ForEachProcessor 回调适配（原始直接传函数名，复刻中声明形参不同故加 thunk）
static __int64 CmdClearGdtPresentBitThunk(__int64 a, __int64 b)
{ return (__int64)CmdClearGdtPresentBit((int)a, b); }
static __int64 CmdCollectGdtrEntriesThunk(__int64 a, __int64 b)
{ return (__int64)CmdCollectGdtrEntries((int)a, (unsigned int **)b); }

// CmdForEachCpuClearGdtBit — 遍历处理器执行 GDT 清理（补全空壳）
// 对应原始驱动 0x14001C1B4（192 字节）
// 【逆向来源】⚠ 可反编译（22 行伪代码）
// 【⚠ 修正记录】注释称"需要 CcFlushCache 相关操作" —— **错误**。实为：
//   校验 20 字节输入可读 → ProbeForRead → 复制上下文 → ForEachProcessor 对每个
//   处理器调 CmdClearGdtPresentBit → 返回"成功标志是否为 1"。
bool CmdForEachCpuClearGdtBit(void *Address, int ContextSize)
{
    bool Result = 0;
    _OWORD ContextData;
    int FlagsValue;
    char SuccessFlag;

    if (Address && ContextSize == 20 &&
        (unsigned __int64)Address < MmUserProbeAddress &&
        (unsigned __int64)Address + 20 < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x14u, 1u);
        ContextData = *(_OWORD *)Address;
        FlagsValue = *((_DWORD *)Address + 4);
        SuccessFlag = 0;
        ForEachProcessor(CmdClearGdtPresentBitThunk,
                         (__int64)&ContextData);
        return SuccessFlag == 1;
    }
    return Result;
}

// CmdCollectAllCpuGdtEntries — 收集各处理器 GDT 条目（补全空壳）
// 对应原始驱动 0x14001C274（181 字节）
// 【逆向来源】⚠ 可反编译（26 行伪代码）
// 【⚠ 修正记录】注释称"需要 FltAcquireFileForSectionSynchronization 获取锁" —— **错误**。
//   实为：要求输出缓冲 ≥ 0x10018 且位于用户空间 → ProbeForWrite → 清零 →
//   ForEachProcessor 对每个处理器调 CmdCollectGdtrEntries（把该处理器 GDTR/GDT
//   条目追加写入输出缓冲）→ 返回"输出缓冲首 DWORD 是否非 0"。
bool CmdCollectAllCpuGdtEntries(__int64 FilterObject, __int64 CallbackData,
                                    _DWORD *OutputBuffer, unsigned int BufferSize)
{
    bool Result = 0;
    _DWORD *ContextPtr;
    unsigned int ContextSize;

    if (OutputBuffer && BufferSize >= 0x10018 &&
        (unsigned __int64)OutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)OutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(OutputBuffer, BufferSize, 1u);
        memset(OutputBuffer, 0, BufferSize);
        *OutputBuffer = 0;
        ContextSize = BufferSize;
        ContextPtr = OutputBuffer;
        ForEachProcessor(CmdCollectGdtrEntriesThunk,
                         (__int64)&ContextPtr);
        return *OutputBuffer != 0;
    }
    return Result;
}

// MiniFilterServerContext — 服务器上下文标志回调（补全空壳）
// 对应原始驱动 0x140019A44（23 字节）
// 【⚠ 修正记录 2026-10-08】原为无参 `return STATUS_SUCCESS;` 空壳 ——
//   既丢了返回值语义（原始返回 1），也漏掉了唯一动作 GtWrite。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（4 行伪代码），按伪代码实现。
// 【逻辑】GtWrite(GT 0x2E5, 0) —— 向该标志槽写 0（"服务器侧"），返回 1。
// 对应原始驱动 0x140019A44（23 字节）
char MiniFilterServerContext(void)
{
    GtWrite(GtCallbackField23, 0);
    return 1;
}

// MiniFilterClientContext — 客户端上下文标志回调（补全空壳）
// 对应原始驱动 0x140019A5C（26 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（4 行伪代码），按伪代码实现。
// 【逻辑】GtWrite(GT 0x2E5, 1) —— 向同一标志槽写 1（"客户端侧"），返回 1。
//   与 MiniFilterServerContext 构成 0/1 配对，用于区分当前处理侧。
// 对应原始驱动 0x140019A5C（26 字节）
char MiniFilterClientContext(void)
{
    GtWrite(GtCallbackField23, 1);
    return 1;
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
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)PeSectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&ReadContext, PeSectionEntry))
            break;

        SectionRawSize = PeSectionEntry[11];
        CumulativeSize += SectionRawSize;

        // 从 SectionDataPtr 获取 section flags
        SectionDataPtr = *(__int64 *)&PeSectionEntry[12];
        SectionFlags = *(WORD *)(*(ULONG64 *)((PUCHAR)PeSectionEntry + 0x118) + 6);

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
        SectionFlags = *(WORD *)(*(ULONG64 *)((PUCHAR)PeSectionEntry + 0x118) + 6);

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
            SectionFlags = *(WORD *)(*(ULONG64 *)((PUCHAR)PeSectionEntry + 0x118) + 6);

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
// 对应原始驱动 0x14000DBC0（103 字节）
__int64 BuildFsFilterDriverPath1()
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394; EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426; EncodedPath[4] = 6553699; EncodedPath[5] = 7274610;
    EncodedPath[6] = 109; EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// BuildFsFilterDriverPath2 — 构建文件系统过滤器驱动路径2
// 对应原始驱动 0x14000EADC（100 字节）
__int64 BuildFsFilterDriverPath2()
{
    _DWORD EncodedPath[8];
    EncodedPath[0] = 4456540; EncodedPath[1] = 6881394; EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426; EncodedPath[4] = 6881348; EncodedPath[5] = 7012467;
    EncodedPath[6] = 0; EncodedPath[7] = 0;
    return OpenFileSection((__int64)EncodedPath);
}

// BuildRegistryDriverPath — 构建注册表驱动路径
// 对应原始驱动 0x140045EE4（116 字节）
__int64 BuildRegistryDriverPath()
{
    _DWORD EncodedBuffer[10];
    EncodedBuffer[0] = 4587612; EncodedBuffer[1] = 7077993; EncodedBuffer[2] = 5439589;
    EncodedBuffer[3] = 7536761; EncodedBuffer[4] = 6619252; EncodedBuffer[5] = 6029421;
    EncodedBuffer[6] = 7340110; EncodedBuffer[7] = 7536742; EncodedBuffer[8] = 0; EncodedBuffer[9] = 0;
    return OpenFileSection((__int64)EncodedBuffer);
}

// CheckFilePathFilter — 检查文件路径是否被过滤屏蔽
// 对应原始驱动 0x14002D1E8（258 字节）
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
// 对应原始驱动 0x14000E24C（340 字节）
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

// 对应原始驱动 0x14003EAA8（809 字节）
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


// EnumerateProcessCallbackContext — 枚举进程回调节区（原 0x14003EAA8，809 字节）
// 【逆向来源】IDA 反编译失败，按反汇编逐条重建（含 0x14003EAA8~0x14003EDD1 全量）
// 【⚠ 重大修正 2026-10-17】旧移植版有 6 个局部变量（SectionDataPtr / SectionCharacteristics /
//   ModeField / ModeField2 / FieldValue / FieldValue2 / SectionFlags）**声明后从未赋值**，
//   MSVC/LTCG 据此把 `*(WORD *)(SectionDataPtr + 6)` 折叠成**绝对地址 [6]**：
//   实机加载即 0x7E 蓝屏，故障指令 `cmp word ptr [6], si`（我方镜像 RVA 0x11E92）。
//   现全部改为**直接读描述符字段**（与原始一致）：
//     +0xF0 → 本条消耗长度      +0x118 → 类型结构体指针（+6 为类型号）
//     +0x50 → 与 0x40 / 0x40000 比较   +0x58 → 与 2 / 1 比较
//     +0x90 → 与 4 比较         +0x88 → 与 0x40000 比较
//     +0x78 → 第一段 RVA 基值   +0x40 → 第二段 RVA 基值
//     +0x28 → 按位测试 bit2
//   另修正两处：EntrySize 应取 +0xF0（旧版误取 +0x30，即操作数 0 记录）；
//   构建号判断方向（原始为 `Loaded < 0x55F0` 时才检查 0x545 结束）。
// 【GT】0x61=当前 EPROCESS、0x42D0=CurrentOffset、0x43A8=SectionBase、0x20=SectionSize、
//   0x21=NtoskrnlBase、3=NtoskrnlImageBase、0x914=构建号、写 0x2B8 / 0x2BA。
// 对应原始驱动 0x14003EE40（541 字节）
__int64 EnumFileSystemCallbackEntries(void)
{
    __int64 Result;
    struct _KPROCESS *TargetProcess;
    struct _KPROCESS *pTargetProcess;
    ULONG    CurrentOffset;
    ULONG64  SectionBase;
    ULONG    SectionSize;
    ULONG64  NtoskrnlBase;
    ULONG64  NtoskrnlImageBase;
    ULONG    SectionIndex;
    ULONG    FieldIndex;
    ULONG    ComputedRva;
    ULONG64  RootOffsetAccum;
    ULONG64  TypePtr;
    USHORT   Type;
    __int64  SectionEntry[56];          // 描述符：0x120 字节
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节读取上下文
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)GtCurrentEprocess);
    pTargetProcess = TargetProcess;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    CurrentOffset     = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x42D0);
    SectionBase       = GtRead((GLOBAL_TABLE_INDEX)0x43A8);
    SectionSize       = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x20);
    NtoskrnlBase      = GtRead((GLOBAL_TABLE_INDEX)0x21);
    NtoskrnlImageBase = GtRead((GLOBAL_TABLE_INDEX)GtNtoskrnlModuleBase);

    if (CurrentOffset
        && CurrentOffset < (ULONG)NtoskrnlBase
        && SectionBase
        && (ULONG)SectionBase < (ULONG)NtoskrnlBase
        && SectionSize
        && NtoskrnlBase
        && NtoskrnlImageBase)
    {
        InitPESectionReadContext(
            (__int64)(SectionBase + CurrentOffset),
            (ULONG)NtoskrnlBase - CurrentOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);

        RootOffsetAccum = 0;

        // 第一层：最多 0xC8(200) 轮
        for (SectionIndex = 0; SectionIndex < 0xC8; ++SectionIndex)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                break;

            RootOffsetAccum += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
            TypePtr = *(ULONG64 *)((PUCHAR)SectionEntry + 0x118);
            Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

            if (Type == 0x545)                                    // 1349：结束
                break;
            if (Type != 0x512)                                    // 非 1298：下一轮
                continue;
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40)
                continue;
            if (*(ULONG *)((PUCHAR)SectionEntry + 0x58) != 2)
                continue;
            if (*(ULONG *)((PUCHAR)SectionEntry + 0x90) != 4)
                continue;

            // 第二层条目
            if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                continue;
            RootOffsetAccum += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
            TypePtr = *(ULONG64 *)((PUCHAR)SectionEntry + 0x118);
            if (*(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) != 0x512)
                continue;
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40)
                continue;
            if (*(ULONG *)((PUCHAR)SectionEntry + 0x58) != 1)
                continue;
            if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x88) != 0x40000)
                continue;

            ComputedRva = *(ULONG *)((PUCHAR)SectionEntry + 0x78)
                        - SectionSize + (ULONG)RootOffsetAccum;

            // 第三层条目：确认类型 0x558，之后才校验算出的 RVA
            if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                continue;
            RootOffsetAccum += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
            if (*(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) != 0x558)
                continue;
            if (!ComputedRva || ComputedRva >= (ULONG)NtoskrnlBase)
                continue;

            GtWrite((GLOBAL_TABLE_INDEX)GtKernelDataField38, NtoskrnlImageBase + ComputedRva);
            Result = 0;

            // 第三层：最多 0x12C(300) 轮
            for (FieldIndex = 0; FieldIndex < 0x12C; ++FieldIndex)
            {
                ULONG Loaded;
                ULONG Rva2;

                if ((ULONG)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
                    break;

                RootOffsetAccum += *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
                Loaded = (ULONG)GtRead((GLOBAL_TABLE_INDEX)GtWindowsBuildNumber);
                TypePtr = *(ULONG64 *)((PUCHAR)SectionEntry + 0x118);

                // 原始：Load < 0x55F0 时才把 0x545 当作结束标记
                if (Loaded < 0x55F0 && *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 0x545)
                    break;

                Type = *(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (Type != 0x4B1 && Type != 0x175 && Type != 0x472)
                    continue;
                if ((*(UCHAR *)((PUCHAR)SectionEntry + 0x28) & 4) == 0)
                    continue;
                if (*(ULONG64 *)((PUCHAR)SectionEntry + 0x50) != 0x40000)
                    continue;

                Rva2 = *(ULONG *)((PUCHAR)SectionEntry + 0x40)
                     - SectionSize + (ULONG)RootOffsetAccum;
                if (!Rva2 || Rva2 >= (ULONG)NtoskrnlBase)
                    continue;

                GtWrite((GLOBAL_TABLE_INDEX)GtKernelDataField40, NtoskrnlImageBase + Rva2);
                Result = 1;
                break;
            }

            break;      // 原始：第三层结束即结束第一层
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
// 对应原始驱动 0x14000E634（1190 字节）
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
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
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
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
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
// 【修正 2026-10-19】旧实现读的 `SectionName` 是个**声明后从不赋值**的局部
//   （初值 0），于是 `*(__int16 *)(SectionName + 6)` 被折叠成绝对地址 `[6]`
//   → 实机 DriverEntry 里直接 **0x50 PAGE_FAULT**（本次验收抓到的 bugcheck：
//   rtZ19+0x3bbdd `movzx eax,word ptr [rax+6]`，rax=0）。
//   原始 0x140012D46 是 `mov rax,[rsp+0x1a8]`（描述符 +0x118 = 类型表项指针），
//   随后 `movzx edx,word ptr [rax+6]` 取类型。旧实现另有三处字段读取亦错位：
//     SectionSize 应为 +0xF0（原始 0x140012D37 `mov eax,[rsp+0x180]`）
//     SectionCharacteristics 应为 +0x118（原始 0x140012D75 `[rsp+0x118]`）
//     SectionDataPtr 应为 +0x70（原始 0x140012D7F `[rsp+0x100]`）
//     InitSectionSize 应为 +0x38（原始 0x140012DA7 `mov eax,[rsp+0xc8]`）
//     SectionFlags2（0x558 判据）应为 +0x50（原始 0x140012D99 `[rsp+0xe0]`）
//   逐条对照 0x140012C28–0x140012DEA 重写。
ULONG64 FindKernelInitSection(void)
{
    char FoundInitSection = 0;
    __int64 PeBase, PeSize, NtImageBase, SectionAddr, SectionOffset;
    unsigned int SectionIndex;
    __int16 SectionType;
    char ReadContext[0x198];
    _DWORD SectionInfo[112];            // 描述符：ReadPESectionEntry 会写 0x120 字节

    GtWrite((GLOBAL_TABLE_INDEX)0x913, 0);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        PeBase = GtRead((GLOBAL_TABLE_INDEX)0x20);
        PeSize = GtRead((GLOBAL_TABLE_INDEX)0x21);
        NtImageBase = GtRead(GtNtoskrnlModuleBase);
        SectionAddr = GtRead((GLOBAL_TABLE_INDEX)0x16F);
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

                    /* 原始 0x140012D37..D4E：先取 Entry[0xF0]（描述符 +0xF0），
                       累加到读指针（ReadContext+0x08）后再取类型。 */
                    *(ULONG64 *)(ReadContext + 0x08) += SectionInfo[0x3C];   /* +0xF0 */

                    SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);

                    if (SectionType == 0x545)                 /* 0x140012D57 */
                        break;

                    if (SectionType == 0x42D)                 /* 0x140012D61 */
                    {
                        if (*(ULONG64 *)((PUCHAR)SectionInfo + 0x88) == 0x1000000000LL &&
                            *(ULONG64 *)((PUCHAR)SectionInfo + 0x70) == 0)
                            FoundInitSection = 1;
                    }
                    else if (SectionType == 0x558)            /* 0x140012D8F */
                    {
                        unsigned int InitSectionSize = SectionInfo[0x0E];   /* +0x38 */
                        if ((*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x4000000) != 0 &&
                            InitSectionSize != 0 &&
                            FoundInitSection == 1)
                        {
                            /* 原始 0x140012DC4：eax = InitSectionSize - PeBase(低32)
                               + 新读指针(低32)；< PeSize 则写 GT[0x183]。 */
                            ULONG Result = InitSectionSize - (ULONG)PeBase
                                         + (ULONG)*(ULONG64 *)(ReadContext + 0x08);
                            if (Result < PeSize)
                                return GtWrite((GLOBAL_TABLE_INDEX)0x183,
                                               NtImageBase + (ULONG64)Result);
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
                *(_DWORD *)((char *)SectionEntry + 0x58) == 9 &&
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
// 对应原始驱动 0x140013E6C（454 字节）
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
// 【修正 2026-10-19】同族缺陷：`SectionName`/`SectionFlags2`/`SectionAlign`/`RawSize`/
//   `DataSectionSize` 均为从不赋值的局部 → `[SectionName+6]` 折叠为 `[6]` → 0x50。
//   逐条对照 0x140013A98 重写：类型指针 +0x118（0x140013B94 `[rsp+0x1a8]`）、
//   +0x50 & 0x40（0x140013BAF `test byte [rsp+0xe0],0x40`）、+0x88 == 0x40
//   （0x140013BB9 `[rsp+0x118]`）、+0x50&0x4000000、+0x38（0x140013BE7 `[rsp+0xc8]`）、
//   结果写 GT[0x181]（0x140013C0B `ecx=0x181`）。
ULONG64 FindKernelDataSectionByCode(void)
{
    __int64 PeBase, PeSize, NtImageBase, SectionAddr, SectionOffset;
    char FoundCodeSection = 0;
    unsigned int SectionIndex;
    char ReadContext[0x198];
    _DWORD SectionInfo[112];

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

                /* 原始 0x140013B85..B9C：先取 Entry[0xF0] 累加到读指针，再取类型 */
                *(ULONG64 *)(ReadContext + 0x08) += *(ULONG *)((PUCHAR)SectionInfo + 0xF0);

                __int16 SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);

                if (SectionType == 0x168)
                {
                    if ((*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x40) != 0 &&
                        *(ULONG64 *)((PUCHAR)SectionInfo + 0x88) == 0x40)
                        FoundCodeSection = 1;
                }
                else if (FoundCodeSection == 1 &&
                         SectionType == 0x558 &&
                         (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x4000000) != 0)
                {
                    ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionInfo + 0x38);
                    ULONG Result = DataSectionSize - (ULONG)PeBase
                                 + (ULONG)*(ULONG64 *)(ReadContext + 0x08);
                    if (Result && Result < PeSize)
                        return GtWrite((GLOBAL_TABLE_INDEX)0x181, NtImageBase + (ULONG64)Result);
                }
            }
        }
    }
    return 0;
}

// FindKernelDataSectionByData — 通过 DATA 节查找内核数据节
// 遍历 PE 节表匹配子类型，定位数据节偏移，写入全局表
// 对应原始驱动 sub_140013C48
// 【修正 2026-10-19】同族缺陷：`SectionName`/`SectionFlags2`/`RawSize`/`DataSectionSize`/
//   `TypeFlag` 均为从不赋值的局部 → `[SectionName+6]` 折叠为 `[6]` → 0x50。
//   逐条对照 0x140013C48 重写：
//     类型指针 = 描述符 +0x118（0x140013D68 `mov rax,[rsp+0x1b8]`），类型 = [rax+6]
//     首支 +0x50 == 0x40（0x140013D83 `[rsp+0xf0]`）、+0x58（0x140013D8E `[rsp+0xf8]`）
//     末支 +0x50&0x4000000、+0x38（0x140013DF6 `[rsp+0xd8]`）
//     结果写 GT[0x197]（0x140013E1D `ecx=0x197`）、再写 GT[0x912] = bpl（0x140013E2E）
//   其中 bpl 由「Code 节 +1」置 1、「Data 节 +3」置 0（0x140013DBB/DD0/DD3）。
ULONG64 FindKernelDataSectionByData(void)
{
    __int64 PeBase, PeSize, NtImageBase;
    int ExportDirSize;
    ULONG64 SectionAddr, SectionOffset;
    unsigned int CodeSectionIndex = 0, DataSectionIndex = 0;
    char FoundDataSection = 0;
    unsigned int SectionIndex;
    unsigned __int8 TypeFlag = 0;
    char ReadContext[0x1A8];
    _DWORD SectionInfo[112];

    PeBase = GtRead((GLOBAL_TABLE_INDEX)0x20);
    PeSize = GtRead((GLOBAL_TABLE_INDEX)0x21);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);
    /* 【修正 2026-10-19】入口 GT 索引错误。原始 sub_140013C48 读取顺序
       （0x140013C79..CDF）：
         0x20 → r13 (PeBase)
         0x21 → rsi (PeSize)
         3    → rdi (NtImageBase)
         0x41C5 → rbx（守卫：非零；0x140013CA2）
         0x171  → rcx/rax（守卫：> NtImageBase；0x140013CAF）
       旧代码误用 0x912 与 0x179 —— 那正是本函数**输出**的槽，
       于是首次运行时两者为 0 → 整个函数被守卫挡掉 → 永远不写 0x197/0x912。 */
    ExportDirSize = (int)GtRead((GLOBAL_TABLE_INDEX)0x41C5);
    SectionAddr = GtRead((GLOBAL_TABLE_INDEX)0x171);
    if (PeBase && PeSize && NtImageBase && ExportDirSize && SectionAddr > (ULONG64)NtImageBase)
    {
        SectionOffset = (unsigned int)(SectionAddr - NtImageBase);
        if ((unsigned int)SectionOffset < PeSize && SectionAddr == SectionOffset + NtImageBase)
        {
            InitPESectionReadContext(SectionOffset + PeBase, (ULONG)(PeSize - SectionOffset), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (SectionIndex = 0; SectionIndex < 0x200; ++SectionIndex)
            {
                if (ReadPESectionEntry(ReadContext, SectionInfo))
                    break;

                /* 原始 0x140013D59..D70：先取 Entry[0xF0] 累加到读指针，再取类型 */
                *(ULONG64 *)(ReadContext + 0x08) += *(ULONG *)((PUCHAR)SectionInfo + 0xF0);

                __int16 SectionType2 = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionInfo + 0x118) + 6);

                if (SectionType2 == 0x512)
                {
                    if (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) == 0x40)
                    {
                        ULONG SubType = *(ULONG *)((PUCHAR)SectionInfo + 0x58);
                        if (SubType == 2) CodeSectionIndex = SectionIndex;
                        else if (SubType == 9) DataSectionIndex = SectionIndex;
                        else if (SubType == 1)
                        {
                            if (CodeSectionIndex && CodeSectionIndex + 1 == SectionIndex)
                            {
                                FoundDataSection = 1;
                                TypeFlag = 1;
                            }
                            else if (DataSectionIndex && DataSectionIndex + 3 == SectionIndex)
                            {
                                FoundDataSection = 1;
                                TypeFlag = 0;
                            }
                        }
                    }
                }
                else if (FoundDataSection == 1 &&
                         SectionType2 == 0x558 &&
                         (*(ULONG64 *)((PUCHAR)SectionInfo + 0x50) & 0x4000000) != 0)
                {
                    ULONG DataSectionSize = *(ULONG *)((PUCHAR)SectionInfo + 0x38);
                    ULONG Result = DataSectionSize - (ULONG)PeBase
                                 + (ULONG)*(ULONG64 *)(ReadContext + 0x08);
                    if (Result && Result < PeSize)
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x197, NtImageBase + (ULONG64)Result);
                        return GtWrite((GLOBAL_TABLE_INDEX)0x912, (__int64)TypeFlag);
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
// 对应原始驱动 sub_140014034（65 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x140014078 —— 那是**被调用的
//   MiniFilterPreCreate** 的地址，不是本函数自身。本函数真实地址是 0x140014034。
__int64 SelectMiniFilterCallbackByVersion(void)
{
    /* 【修正 2026-10-19】原始 0x140014034 的三个分支都是 **tail-call jmp**：
         build <= 0x23F0      → jmp 0x1400142A8  （= FindKernelDataSectionForImageNotify2）
         build >= 0x42EE      → jmp 0x140014078  （= FindKernelDataSectionForImageNotify
                                                  —— 「MiniFilterPreCreate」是 IDA 的错名，
                                                     该函数无参数、是 PE 节区扫描器，产出 GT[0x17C]）
         否则                 → jmp 0x1400144A8  （= FindKernelDataSectionForImageNotify3）
       旧代码在 build>=0x42EE 分支调的是**同名的 FLT 回调桩 MiniFilterPreCreate**（return
       STATUS_SUCCESS）→ GT[0x17C] 永不写入。本机 build 19045 = 0x4A65 正落在该分支。 */
    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x23F0)
        return ((__int64 (*)(void))FindKernelDataSectionForImageNotify2)();
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        return ((__int64 (*)(void))FindKernelDataSectionForImageNotify)();
    return ((__int64 (*)(void))FindKernelDataSectionForImageNotify3)();
}

// SelectMiniFilterCleanupCallback — 选择 Minifilter 清理回调
// 版本 >= 0x4A61 时调用 MiniFilterPostWrite，否则调用 MiniFilterPreCleanup
// 对应原始驱动 sub_140014CE0（65 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x140014D08（0x28 偏移差），已按 IDA 函数表更正。
__int64 SelectMiniFilterCleanupCallback(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4A61)
        return ((__int64 (*)(void))MiniFilterPostWrite)();
    else
        return ((__int64 (*)(void))MiniFilterPreCleanup)();
}

// SelectMiniFilterDirEnumCallback — 选择 Minifilter 目录枚举回调
// 版本 < 0x23F0 时调用 FindKernelObjectFieldOffsetsWin8，>= 0x2800 时调用 FindKernelObjectFieldOffsetsWin10，否则调用 FindKernelObjectFieldOffsetsWin10Early
// 对应原始驱动 sub_1400150E4（65 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x1400152D4 —— 那是**被调用的
//   FindKernelObjectFieldOffsetsWin10** 的地址，本函数真实地址是 0x1400150E4。
__int64 SelectMiniFilterDirEnumCallback(void)
{
    /* 【修正 2026-10-19】原始 sub_1400150E4 的三个分支都是 **tail-call jmp**：
         build <  0x23F0 → jmp 0x140015A48 = MiniFilterPreDirEnum
         build <  0x2800 → jmp 0x140015F34 = MiniFilterPreSetInfo
         否则            → jmp 0x1400152D4 = MiniFilterPreClose
       旧代码错调 FindKernelObjectFieldOffsetsWin8/Win10/Win10Early —— 那三个是
       **EPROCESS 偏移初始化器**，与目录枚举回调毫无关系（原注释已指出
       "0x1400152D4 是被调用者的地址"，但被误当成另一个函数）。
       本机 build 19045 ≥ 0x2800 → 应走 MiniFilterPreClose。 */
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
        return ((__int64 (*)(void))MiniFilterPreDirEnum)();
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x2800)
        return ((__int64 (*)(void))MiniFilterPreSetInfo)();
    return ((__int64 (*)(void))MiniFilterPreClose)();
}

// ============================================================
// MiniFilterPreDirEnum — 目录枚举前扫描器
// 对应原始驱动 sub_140015A48（1257 字节 / 331 条指令）
// 【新实现 2026-10-19】此前是安全占位（return 0）。逐条对照 0x140015A48 重建。
//
// 入口守卫仅 3 项：GT[0x20]（PE 缓冲）、GT[0x21]（大小）、GT[3]（内核基址）
//   （0x140015AAB..AC0）—— 与 PreClose 不同，本函数**不读** 0x8CC/0x900/0x8CD/0x4459。
// 窗口（0x140015AC6..B4F）：与 PreClose 同款 ".PAGE" 定位：
//   Base=(Raw<PeSize)?Raw:0（sbb/and 0x140015AF9..AFE）；
//   Va=ReturnVa，为 0 时取 PeSize-Base；Len=min(Va, PeSize-Base)（cmova 0x140015B1C）。
//   扫描游标 rsi=PeBase+Base，终点 r15=PeBase+Base+Len。
// 主循环（0x140015B5E..EFB）：rsi+0x30>=End 或 *rsi!=0x48 → 前进一字节；再按 rsi[1] 分派：
//   · rsi[1]==0x8D（0x140015B79）
//       Cand = (u32)(rsi+7) + (*(u32*)(rsi+3) - (u32)PeBase)（0x140015B7F..B8A）
//       Cand==0 或 >=PeSize → 前进（0x140015B8C..B95）
//       A1（0x140015B9B..C1F）dil==0 且 rsi[0xD]==8 && rsi[0xE]==0x48 &&
//          rsi[0xF]==0x8D && rsi[0x18]==0x10：
//            Alt = (u32)(rsi+0x15) + (*(u32*)(rsi+0x11) - (u32)PeBase)
//            Alt>=PeSize → 前进；否则写
//            GT[0x32E]=Cand、GT[0x330]=Alt、GT[0x32F]=Cand+Gt[3]、GT[0x331]=Alt+Gt[3]
//            置 [rsp+0x43]=1（dil）→ 完成闸门（0x140015D31）
//       A2（0x140015C24..C7D）r9b==0 且 rsi[7]==0x48 && rsi[8]==0x89 &&
//          rsi[0xA]==8 && *(u32*)(rsi+0x11)==0xA0：
//            Cand 已保证有效，写 GT[0x332]=Cand、GT[0x333]=Cand+Gt[3]，
//            置 [rsp+0x42]=1（r9b）（0x140015C75..C78）→ 闸门（0x140015D17）
//       A3（0x140015C82..D12）r8b==0 且 rsi[7]==0x41 && rsi[8]==0xF6：
//            以 [rsi+7, PeEnd-rsi-7) 建上下文，最多 0xA 轮；
//            描述符 +0x88==0x800000 && +0x70==0x1000（0x140015CF1..D02）→ 命中：
//              重算 Cand（0x140015D60..D6B），有效则写
//              GT[0x334]=Cand、GT[0x335]=Cand+Gt[3]，置 [rsp+0x41]=1（r8b，0x140015D8E..D97）
//            未命中 → 闸门（0x140015D22）
//   · 否则若 rsi[0]==0x48 && rsi[1]==0x8B（0x140015DB3..DBF）：
//       edi = (u32)(rsi+7) + (*(u32*)(rsi+3) - (u32)PeBase)（0x140015DC5..DCE）
//       edi==0 或 >=PeSize → 前进；dl!=0 → 闸门
//       否则以 [rsi+7, PeEnd-rsi-7) 解码最多 0xA 轮（0x140015E23..E95）：
//         hit34 = (+0x88 的 bit16) && (GT[0x336] + 描述符+0x78) == 0（0x140015E40..E62）
//         hit35 = (+0x88 的 bit16) && 描述符+0x78 == 0xBC0（0x140015E6D..E85）
//         两者同时成立 → 写 GT[0x337]=edi+Gt[3]（0x140015ECE），置 [rsp+0x40]=1（dl）
// 完成闸门（0x140015D22 / D31 / D43 / EB5）：[0x43]==1 && [0x42]==1 && [0x41]==1 &&
//   [0x40]==1 → 收尾返回；否则前进下一字节。四标志跨字节持久。
// 写入槽位：0x32E/0x32F/0x330/0x331、0x332/0x333、0x334/0x335、0x337
// ============================================================
// 对应原始驱动 0x140015A48（1257 字节）
__int64 MiniFilterPreDirEnum(void)
{
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* r12  0x140015A7F */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* r14d 0x140015A91 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* r13  0x140015A9E */

    ULONG64 PeEnd = 0;          /* [rsp+0x60] */
    ULONG64 End   = 0;          /* r15 */
    ULONG64 rsi   = 0;          /* 扫描游标 */
    UCHAR   f43 = 0;            /* [rsp+0x43]（dil） */
    UCHAR   f42 = 0;            /* [rsp+0x42]（r9b） */
    UCHAR   f41 = 0;            /* [rsp+0x41]（r8b） */
    UCHAR   f40 = 0;            /* [rsp+0x40]（dl） */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase) return 0;        /* 0x140015AAB..AC0 */

    PeEnd = PeBase + (ULONG64)PeSize;                   /* 0x140015AC6..ADF */
    {
        char  Name[8];                                  /* [rsp+0x48] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;             /* 0x140015AD7 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;                   /* 0x140015AE4 "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;               /* 0x140015AF1..AFE */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;                /* 0x140015B0A..B11 */
        Avail = PeSize - Base;                          /* 0x140015B13..B1A */
        Len = (Va > Avail) ? Avail : Va;                /* cmova 0x140015B1C */
        rsi = PeBase + (ULONG64)Base;                   /* 0x140015B16 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;    /* 0x140015B2F..B4A */
    }
    f43 = 0; f42 = 0; f41 = 0; f40 = 0;                 /* 0x140015B21..B43 */
    if (rsi >= End) return 0;                           /* 0x140015B4F..B52 */

    for (;;)
    {
        ULONG Cand;

        if (rsi + 0x30 >= End) goto LD_ADV;              /* 0x140015B65 jae → 0x140015EF5 */
        if (*(UCHAR *)rsi != 0x48) goto LD_ADV;          /* 0x140015B6F jne → 0x140015EF5 */

        if (*(UCHAR *)(rsi + 1) == 0x8D)                /* 0x140015B75 */
        {
            Cand = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase); /* 0x140015B7F..B8A */
            if (Cand == 0 || Cand >= PeSize) goto LD_ADV;                    /* 0x140015B8C..B95 */

            /* A1（0x140015B9B..C1F） */
            if (f43 == 0 &&
                *(UCHAR *)(rsi + 0xD) == 8 && *(UCHAR *)(rsi + 0xE) == 0x48 &&
                *(UCHAR *)(rsi + 0xF) == 0x8D && *(UCHAR *)(rsi + 0x18) == 0x10)
            {
                ULONG Alt = (ULONG)(rsi + 0x15)
                          + (*(ULONG *)(rsi + 0x11) - (ULONG)PeBase);
                if (Alt >= PeSize) goto LD_ADV;                          /* 0x140015BCF..BD2 */
                GtWrite((GLOBAL_TABLE_INDEX)0x32E, (__int64)Cand);                      /* 0x140015BD8 */
                GtWrite((GLOBAL_TABLE_INDEX)0x330, (__int64)Alt);                       /* 0x140015BE6 */
                GtWrite((GLOBAL_TABLE_INDEX)0x32F, (__int64)((ULONG64)Cand + NtBase));  /* 0x140015BF4 */
                GtWrite((GLOBAL_TABLE_INDEX)0x331, (__int64)((ULONG64)Alt  + NtBase));  /* 0x140015C02 */
                f43 = 1;                                                /* 0x140015C17 mov dil,r8b */
                goto GATE;
            }
            /* A2（0x140015C24..C7D） */
            if (f42 == 0 && *(UCHAR *)(rsi + 7) == 0x48 && *(UCHAR *)(rsi + 8) == 0x89 &&
                *(UCHAR *)(rsi + 0xA) == 8 && *(ULONG *)(rsi + 0x11) == 0xA0)
            {
                GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);                      /* 0x140015C55 */
                GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase));  /* 0x140015C65 */
                f42 = 1;                                                    /* 0x140015C75 mov r9b,r8b */
                goto GATE;
            }
            /* A3（0x140015C82..D12） */
            if (f41 == 0 && *(UCHAR *)(rsi + 7) == 0x41 && *(UCHAR *)(rsi + 8) == 0xF6)
            {
                int Hit = 0;
                InitPESectionReadContext((__int64)(rsi + 7), (ULONG)PeEnd - (ULONG)rsi - 7u,
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (int k = 0; k < 0xA; ++k)                            /* 0x140015CD4..D10 */
                {
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                    *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                    if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x800000 &&  /* 0x140015CF1..D02 */
                        *(ULONG   *)((PUCHAR)Entry + 0x70) == 0x1000)
                    { Hit = 1; break; }
                }
                if (Hit)                                                     /* 0x140015D60..D97 */
                {
                    ULONG c = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase);
                    if (c != 0 && c < PeSize)
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)c);                      /* 0x140015D74 */
                        GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)c + NtBase));  /* 0x140015D84 */
                        f41 = 1;                                                 /* 0x140015D94 */
                    }
                }
                goto GATE;
            }
            goto GATE;
        }

        /* 0x140015DB3：rsi[1] != 0x8D */
        if (*(UCHAR *)(rsi + 1) != 0x8B) goto LD_ADV;                    /* 0x140015DBB..DBF */
        {
            ULONG Alt = (ULONG)(rsi + 7) + (*(ULONG *)(rsi + 3) - (ULONG)PeBase); /* 0x140015DC5..DCE */
            if (Alt == 0 || Alt >= PeSize) goto LD_ADV;                  /* 0x140015DD0..DD9 */
            if (f40 == 0)                                               /* 0x140015DDF..DE1 */
            {
                InitPESectionReadContext((__int64)(rsi + 7), (ULONG)PeEnd - (ULONG)rsi - 7u,
                                         2, 0, -1, 0, 0, (__int64)&Ctx);
                for (int k = 0; k < 0xA; ++k)                            /* 0x140015E23..E95 */
                {
                    ULONG64 F88;
                    UCHAR Hit34, Hit35;
                    if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                    *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                    F88 = *(ULONG64 *)((PUCHAR)Entry + 0x88);
                    /* hit34：bit16 置位且 (GT[0x336]+描述符+0x78)==0（0x140015E40..E62） */
                    Hit34 = ((F88 & 0x10000) != 0 &&
                             (ULONG)((ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336)
                                     + *(ULONG *)((PUCHAR)Entry + 0x78)) == 0) ? 1u : 0u;
                    /* hit35：bit16 置位且 描述符+0x78==0xBC0（0x140015E6D..E85） */
                    Hit35 = ((F88 & 0x10000) != 0 &&
                             *(ULONG *)((PUCHAR)Entry + 0x78) == 0xBC0) ? 1u : 0u;
                    if (Hit34 == 1 && Hit35 == 1)                            /* 0x140015E8A..E8C */
                    {
                        GtWrite((GLOBAL_TABLE_INDEX)0x337,                    /* 0x140015ECE */
                                (__int64)((ULONG64)Alt + NtBase));
                        f40 = 1;                                             /* 0x140015EE1..EE4 */
                        break;
                    }
                }
            }
        }
        goto GATE;

GATE:                                                    /* 0x140015D22 / D43 / EB5 */
        if (f43 == 1 && f42 == 1 && f41 == 1 && f40 == 1) return 0;     /* 0x140015D55 → 收尾 */
LD_ADV:                                                  /* 0x140015EF5..EFB */
        rsi += 1;
        if (rsi >= End) return 0;
    }
    return 0;
}

// ============================================================
// MiniFilterPreSetInfo — 设置信息前扫描器
// 对应原始驱动 sub_140015F34（1231 字节 / 317 条指令）
// 【新实现 2026-10-19】此前是安全占位（return 0）。逐条对照 0x140015F34 重建。
//
// 入口 5 项守卫（0x140015FB8..FDC）：GT[0x20]、GT[0x21]、GT[3]、GT[0x8CC]、GT[0x8CD]。
//   保存位置：GT[3]→[rsp+0x58]、GT[0x8CC]→[rsp+0x68]、GT[0x8CD]→[rsp+0x60]。
// 窗口（0x140015FE2..6056）：与 PreClose 同款 ".PAGE" 定位：
//   Base=(Raw<PeSize)?Raw:0；Va=ReturnVa，为 0 时取 PeSize-Base；Len=min(Va,PeSize-Base)；
//   PeEnd=PeBase+PeSize 存于 [rsp+0x48]；游标 rbx=PeBase+Base，终点 r13=PeBase+Base+Len。
//   注意 rbx 在块内被复用为「轮次计数器」，故进入每块前把 rbx+1 存入 [rsp+0x70]，
//   块末从该槽恢复（0x14001605F / 0x140016175）。
// 三块的衔接（按原始跳转）：
//   块 1 守卫失败（f42!=0 或 rbx[7..0xA] 非 `48 89 08`）→ 落块 2；块 1 执行但未写 → 下一字节。
//   块 2 守卫失败（f41!=0 或非 `41 F6` 形态）→ 落块 3；块 2 执行完（无论是否命中）→ 闸门。
//   块 3 守卫（f40==0 && rbx[7]==0x48 && rbx[8]==5 && GT[0x336]==*(u32*)(rbx+9)）→ 执行 → 闸门。
// 闸门（0x1400162D3..2F5）：f42==1 && f41==1 && f40==1 → return 0。
// 写入槽位：块 1 → 0x332/0x333；块 2 → 0x334/0x335；块 3 → 0x337
// ============================================================
__int64 MiniFilterPreSetInfo(void)
{
    const ULONG64 PeBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* r12  0x140015F6B */
    const ULONG   PeSize = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);     /* esi  0x140015F75 */
    const ULONG64 NtBase = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)3);      /* [rsp+0x58] 0x140015F8A */
    const ULONG   v8CC   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CC);    /* [rsp+0x68] 0x140015F9C */
    const ULONG   v8CD   = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8CD);    /* [rsp+0x60] 0x140015FAE */

    ULONG64 PeEnd = 0;          /* [rsp+0x48] = PeBase + PeSize */
    ULONG64 End   = 0;          /* r13 */
    ULONG64 rbx   = 0;          /* 扫描游标 */
    ULONG64 rdi   = 0;          /* rdi：低 32 位兼作窗口长度与「+0xFF8」标志 */
    UCHAR   f40 = 0;            /* [rsp+0x40] */
    UCHAR   f41 = 0;            /* [rsp+0x41] */
    UCHAR   f42 = 0;            /* [rsp+0x42] */
    PE_DECODE_CONTEXT Ctx;
    _DWORD  Entry[112];

    if (!PeBase || !PeSize || !NtBase || !v8CC || !v8CD) return 0;  /* 0x140015FB8..FDC */

    rdi   = (ULONG64)PeSize;                            /* 0x140015FE2 mov edi,esi */
    PeEnd = PeBase + (ULONG64)PeSize;                   /* 0x140015FEB add rdi,r12 */
    rdi   = PeEnd;                                      /* rdi 全宽 = PeEnd */
    {
        char  Name[8];                                  /* [rsp+0x50] ".PAGE" */
        ULONG Raw, Base, Va, Len, Avail;
        *(ULONG *)(Name + 0) = 0x4741502Eu;             /* 0x140015FF1 ".PAG" */
        *(ULONG *)(Name + 4) = 0x45u;                   /* 0x140015FFE "E"    */
        Raw = (ULONG)FindPESectionByName((__int64)PeBase, PeSize, (__int64)Name);
        Base = (Raw < PeSize) ? Raw : 0u;               /* 0x14001600B..19 */
        Va = (ULONG)FindPESectionByNameReturnVa((__int64)PeBase, PeSize, (__int64)Name);
        if (Va == 0) Va = PeSize - Base;                /* 0x140016022..28 */
        Avail = PeSize - Base;                          /* 0x14001602A..31 */
        Len = (Va > Avail) ? Avail : Va;                /* cmova 0x140016033..35 */
        End = PeBase + (ULONG64)Base + (ULONG64)Len;    /* 0x140016040..50 */
        rbx = PeBase + (ULONG64)Base;                   /* 0x140016053 */
    }
    f42 = 0; f41 = 0; f40 = 0;                          /* 0x14001602C / 43 / 4B */
    if (rbx >= End) return 0;                           /* 0x14001617F..182 */

    for (;;)                                            /* 循环条件 0x14001617F */
    {
        ULONG Cand;                                     /* r15d */

        if (rbx + 1 + 0x2F >= End) goto LD_NEXT;        /* 0x140016064..6B */
        if (*(UCHAR *)rbx != 0x48) goto LD_NEXT;        /* 0x140016071..74 */
        if (*(UCHAR *)(rbx + 1) != 0x8D) goto LD_NEXT;  /* 0x14001607A..7D */
        Cand = 7u + *(ULONG *)(rbx + 3) + (ULONG)rbx - (ULONG)PeBase;   /* 0x140016083..93 */
        if (Cand == 0 || Cand >= PeSize) goto LD_NEXT;  /* 0x140016096..9F */

        /* ===== 块 1（0x1400160A5..169）：`48 89 08` 双标志 ===== */
        if (f42 == 0 && *(UCHAR *)(rbx + 7) == 0x48 &&
            *(UCHAR *)(rbx + 8) == 0x89 && *(UCHAR *)(rbx + 0xA) == 8)
        {
            int   flagA = 0;                            /* r14b：desc+0x40 == GT[0x8CC] */
            int   wrote = 0;
            ULONG counter = 0;                          /* ebx（rbx 已备份到 [rsp+0x70]） */
            rdi = rdi & ~(ULONG64)0xFF;                 /* 0x140016110 xor dil,dil */
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)PeEnd - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            while (counter < 6)                         /* 0x14001611A..169 */
            {
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) goto LD_NEXT;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                if (*(ULONG *)((PUCHAR)Entry + 0x40) == v8CC)      /* 0x14001613B..148 */
                {
                    flagA = 1;
                }
                else
                {
                    rdi = rdi & 0xFFu;                             /* 0x140016151 movzx edi,dil */
                    if (*(ULONG *)((PUCHAR)Entry + 0x40) == 0xFF8)
                        rdi = 1;                                   /* 0x140016155 cmove edi,1 */
                    if (flagA != 1) goto LD_CB;                    /* 0x140016159..15C */
                }
                if ((UCHAR)rdi == 1)                               /* 0x14001615E..161 */
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x332, (__int64)Cand);                     /* 0x1400161BB */
                    GtWrite((GLOBAL_TABLE_INDEX)0x333, (__int64)((ULONG64)Cand + NtBase)); /* 0x1400161CD */
                    f42 = 1;                                       /* 0x1400161E5 */
                    wrote = 1;
                    break;
                }
LD_CB:
                counter += 1;                                  /* 0x140016163..166 */
            }
            if (!wrote) goto LD_NEXT;                          /* 0x14001616B */
            goto LD_GATE;                                      /* 0x1400161EA */
        }

        /* ===== 块 2（0x1400161EF..2CE）：`41 F6` 双形态 ===== */
        if (f41 == 0 &&
            ((*(UCHAR *)(rbx + 7) == 0x41 && *(UCHAR *)(rbx + 8) == 0xF6) ||
             (*(UCHAR *)(rbx + 0xA) == 0x41 && *(UCHAR *)(rbx + 0xB) == 0xF6)))
        {
            int hit = 0;
            /* 窗口长度取 edi（0x14001621B..243）；edi 可能已被块 1 改为 0/1 */
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)rdi - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            for (int k = 0; k < 0xA; ++k)                       /* 0x14001624E..28C */
            {
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                if (*(ULONG64 *)((PUCHAR)Entry + 0x88) == 0x800000 &&   /* 0x140016269..284 */
                    *(ULONG   *)((PUCHAR)Entry + 0x70) == 0x1000 &&
                    *(ULONG   *)((PUCHAR)Entry + 0x40) == v8CD)
                { hit = 1; break; }
            }
            if (!hit)                                           /* 回扫 `C7` 0x14001628E..2C7 */
            {
                PUCHAR rcx = (PUCHAR)rbx - 0x30;
                PUCHAR hi  = (PUCHAR)(rbx - 7);
                if (rbx > PeBase && (ULONG64)rcx > PeBase && rcx < hi)
                {
                    for (;;)
                    {
                        if (rcx >= hi) break;                   /* 0x1400162C4..2C7 */
                        if (rcx[0] == 0xC7 && (ULONG)rcx[2] == (v8CD & 0xFF) &&
                            *(ULONG *)(rcx + 3) == 0x1000)
                        { hit = 1; break; }                     /* 0x1400162AA..2BF */
                        rcx += 1;
                    }
                }
            }
            if (hit)                                            /* 0x140016300..32C */
            {
                ULONG c = *(ULONG *)(rbx + 3) + 7u + (ULONG)rbx - (ULONG)PeBase;
                if (c != 0 && c < PeSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x334, (__int64)c);                     /* 0x140016315 */
                    GtWrite((GLOBAL_TABLE_INDEX)0x335, (__int64)((ULONG64)c + NtBase)); /* 0x140016324 */
                    f41 = 1;                                                            /* 0x140016334 */
                }
            }
            goto LD_GATE;                                       /* 0x140016339 → 0x1400162CE */
        }

        /* ===== 块 3（0x14001633B..3FE）：`48 05` + GT[0x336] 比对 ===== */
        if (f40 == 0 && *(UCHAR *)(rbx + 7) == 0x48 && *(UCHAR *)(rbx + 8) == 5 &&
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x336) == *(ULONG *)(rbx + 9))   /* 0x14001633B..359 */
        {
            InitPESectionReadContext((__int64)(rbx + 7), (ULONG)PeEnd - (ULONG)rbx - 7u,
                                     2, 0, -1, 0, 0, (__int64)&Ctx);
            for (int k = 0; k < 0xF; ++k)                       /* 0x140016394..3D6 */
            {
                USHORT ty;
                if ((ULONG)ReadPESectionEntry((PUCHAR)&Ctx, Entry) != 0) break;
                *(ULONG64 *)((PUCHAR)&Ctx + 0x08) += *(ULONG *)((PUCHAR)Entry + 0xF0);
                ty = *(USHORT *)(*(ULONG64 *)((PUCHAR)Entry + 0x118) + 6);
                if (ty == 0xE5 && *(ULONG64 *)((PUCHAR)Entry + 0x50) == 0x40000)   /* 0x1400163BB..3C9 */
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x337,                         /* 0x1400163DB..3E5 */
                            (__int64)((ULONG64)Cand + NtBase));
                    f40 = 1;                                               /* 0x1400163ED */
                    break;
                }
            }
        }

LD_GATE:                                                        /* 0x1400162D3..2F5 */
        if (f42 == 1 && f41 == 1 && f40 == 1) return 0;         /* 0x1400162F2..2F5 */
LD_NEXT:                                                        /* 0x140016175..182 */
        /* 0x14001617A mov rdi,[rsp+0x48]：每轮恢复 rdi = PeEnd。
           缺此恢复会让第二块的解码窗口用到第一块残留的 edi（0/1），窗口为负。 */
        rdi = PeEnd;
        rbx += 1;
        if (rbx >= End) return 0;
    }
    return 0;
}
// SelectMiniFilterWriteReadCallback — 选择 Minifilter 写/读回调
// 版本 > 0x23F0 时调用 FindKernelDataSectionForDeviceIoControl2，否则调用 FindKernelDataSectionForDeviceIoControl
// 对应原始驱动 sub_1400146AC（65 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x1400146D4 —— 那是**被调用的
//   FindKernelDataSectionForDeviceIoControl** 的地址，本函数真实地址是 0x1400146AC。
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

// =========================================================================
// InitCallbackFunctionTable — 初始化回调函数表（按模式 0/1/2）
// 对应原始驱动 0x1400344BC（2359 字节，574 行反汇编）
// 【逆向来源】⚠ 人工阅读反汇编**逐条转写** —— IDA **确认无法反编译**
//   （`ida_hexrays.decompile` 返回 None，已复验），故走转写流程。
// 【参数】Mode = ecx（0 / 1 / 2）。调用方 InitCallbackFunctions（0x140033EE8）
//   按"结果槽是否已填"分别以模式 0 / 2 / 1 调用它。
// 【模式与文件系统的对应（由 ReadNtFileForCallbackTable 的路径表确定）】
//   模式 0 → fastfat.sys（FAT）  模式 1 → exfat.sys（exFAT）  模式 2 → ntfs.sys（NTFS）
// 【⚠ 三处文档错误更正（本轮逐条核对反汇编得出，原 docs §四 骨架有误）】
//   1) 原骨架写"按模式再取 0x2A1(模式1)/0x52(模式0)/0x54(模式2)"——正确；
//      但**该值不是文件大小，而是该模式的重定位基址**，随后作为
//      ParseCallback*Sections 的 SectionBase，并参与 `GtWrite(槽, 段偏移+基址)`。
//   2) 原骨架未区分 r13 与 r12：**r13 = Gt[0x421A]**（8 实参调用，IDB 名为
//      IoCreateFile 但实参形状与 ObjectMgmt.c 的 7 参用法不同，按本函数反汇编为准）、
//      **r12 = Gt[0x4223] = CloseHandle**（1 实参）；原骨架完全未提及这两次调用。
//   3) 原骨架写"名字串是 ntoskrnl.exe 与 IoCompleteRequest"——**部分正确**：
//      第一处是 `ParsePESectionHeaders(FileBuffer, FileSize, "ntoskrnl.exe",
//      "MmFlushImageSection", &OutOffset)`（原骨架漏了 MmFlushImageSection），
//      第二处才是 "IoCompleteRequest"；两个结果分别写进两族 GT 槽。
// 【两个填表循环的迭代数（原骨架写"0x1C 项 / 0x1B 项"）——实为混淆写法】
//   目标表的循环上限是 `Mode + {0x1C|0x1A|0x1B}`：三种模式**恒等于 0x1C**；
//   备用表上限是固定 0x1B。已在代码中按恒等值 0x1C / 0x1B 书写并注明。
// 【GT 槽】0x421D=RtlInitUnicodeString、0x421A=IoCreateFile 包装、0x4223=CloseHandle、
//   0x4160=驱动对象链表头（解引用后作第 5 实参）；
//   模式基址槽 0x52/0x54/0x2A1；段偏移槽 0x188/0x187/0x2A5 与 0x2AB/0x2AC/0x2AD；
//   结果槽 0x195+0x18F+0x8A3（模式0）/ 0x194+0x190+0x8A2（模式2）/ 0x2A3+0x2A4+0x8A4（模式1）。
// 【三段主体】仅分配槽、缓存表迭代数与解析函数不同：
//   模式 0：GtAlloc(0xA4C)/GtAlloc(0xAFA)，ParseCallbackFunctionSections(…,1)，
//           IoCreateFile("\FileSystem\Fastfat")
//   模式 2：GtAlloc(0xBA8)/GtAlloc(0xC56)，ParseCallbackContextSections(…)，
//           IoCreateFile("\FileSystem\Ntfs")
//   模式 1：GtAlloc(0xD04)/GtAlloc(0xDB2)，ParseCallbackFunctionSections(…,0)，
//           IoCreateFile("\FileSystem\exfat")
//   每个表项：取 +4 处 RVA → 清 +0 → 越界检查（RVA+0x10 <= FileSize）→
//   置 +0 命中标志 → 从 FileBuffer+RVA 拷 16 字节到 +0x10。
// 【后缀】ExFree(文件缓冲) → FillExportEntrySlot(目标表) →
//   取 GT 0x4C(映像缓冲)/0x21(PE 大小)/3(ntoskrnl 基址)，任一为 0 即返回；
//   按模式把 6 个一族回调地址槽填入**备用表**（槽内布局：+0=1、+4=槽值、
//   +8=槽值+基址、+0x10=16 字节节头副本；仅在 +4 尚为 0 时写）：
//   模式 2：仅 +0x300(0x442F) / +0x360(0x4432)
//   模式 1：+0x30(0x4429) +0x60(0x442C) +0x300 +0x360 +0x2D0(0x4435) +0x330(0x4438)
//   模式 0：+0x30 +0x60，然后**仅当构建号 >= 0x1772** 时再加 +0x300/+0x360/+0x2D0/+0x330
// 【返回值】原始函数 ret 前未显式设置 rax（返回值意外取自最后一条 call 的结果），
//   两个调用方（InitCallbackFunctions、MemoryOperation.c:809）均忽略该值；
//   此处显式返回 0 以消除不确定性，并如实记录该差异。
// =========================================================================
// 对应原始驱动 0x1400344BC（2359 字节）
ULONG64 InitCallbackFunctionTable(unsigned int Mode)
{
    __int64 FnRtlInitUnicodeString;
    __int64 FnCreateFile;
    __int64 FnCloseHandle;
    __int64 DriverListHead;
    __int64 RelocBase;
    __int64 FileBuffer = 0;
    unsigned int FileSize = 0;
    unsigned int SectionOffset = 0;
    __int64 pTargetTable = 0;
    __int64 pAlternateTable = 0;
    __int64 Handle = 0;
    int Result = 0;
    int IoStatus;
    WCHAR NameNtoskrnl[20];
    WCHAR NameMmFlush[24];
    WCHAR NameIoComplete[24];
    WCHAR FilePath[24];
    _BYTE UnicodeString[16];
    int i;

    FnRtlInitUnicodeString = GtRead(GtRtlInitUnicodeStringFunc);
    FnCreateFile           = GtRead(GtIoCreateFileFunc);
    FnCloseHandle          = GtRead(GtCloseHandleFunc);
    DriverListHead         = GtRead(GtDriverObjectListHead);

    if (!FnRtlInitUnicodeString || !FnCreateFile || !FnCloseHandle || !DriverListHead)
        return 0;

    // ---- 按模式取该模式的重定位基址（0x140034554~0x140034584）----
    if (Mode == 0)
        RelocBase = GtRead((GLOBAL_TABLE_INDEX)0x52);
    else if (Mode == 2)
        RelocBase = GtRead((GLOBAL_TABLE_INDEX)0x54);
    else if (Mode == 1)
        RelocBase = GtRead(GtKernelDataField15);        // 0x2A1
    else
        RelocBase = 0;
    if (!RelocBase)
        return 0;

    // ---- 按模式读取文件系统驱动（0x14003458A）----
    if (!ReadNtFileForCallbackTable((_QWORD *)&FileBuffer, &FileSize, (int)Mode))
        return 0;

    // ---- 节名查找 1：ntoskrnl.exe 内的 MmFlushImageSection（0x1400345A2~0x140034628）----
    SectionOffset = 0;
    wcscpy(NameNtoskrnl, L"ntoskrnl.exe");
    wcscpy(NameMmFlush, L"MmFlushImageSection");
    if (ParsePESectionHeaders(FileBuffer, FileSize, (__int64)NameNtoskrnl,
                              (unsigned __int8 *)NameMmFlush, &SectionOffset) == 1)
    {
        GLOBAL_TABLE_INDEX ResultIndex;
        if (Mode == 2)
            ResultIndex = (GLOBAL_TABLE_INDEX)0x187;
        else if (Mode == 0)
            ResultIndex = (GLOBAL_TABLE_INDEX)0x188;
        else
            ResultIndex = GtKernelDataField19;          // 0x2A5
        GtWrite(ResultIndex, SectionOffset + RelocBase);
    }

    // ---- 节名查找 2：ntoskrnl.exe 内的 IoCompleteRequest（0x14003462D~0x14003469F）----
    SectionOffset = 0;
    wcscpy(NameNtoskrnl, L"ntoskrnl.exe");
    wcscpy(NameIoComplete, L"IoCompleteRequest");
    if (ParsePESectionHeaders(FileBuffer, FileSize, (__int64)NameNtoskrnl,
                              (unsigned __int8 *)NameIoComplete, &SectionOffset) == 1)
    {
        GLOBAL_TABLE_INDEX ResultIndex;
        if (Mode == 2)
            ResultIndex = GtKernelDataField26;          // 0x2AC
        else if (Mode == 0)
            ResultIndex = GtKernelDataField25;          // 0x2AB
        else
            ResultIndex = GtKernelDataField27;          // 0x2AD
        GtWrite(ResultIndex, SectionOffset + RelocBase);
    }

    // ---- 三段主体（0x1400346D3 / 0x140034846 / 0x1400349A7）----
    if (Mode == 0)
    {
        pTargetTable    = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xA4C);
        pAlternateTable = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xAFA);

        if (ParseCallbackFunctionSections(FileBuffer, FileSize, RelocBase,
                                          pTargetTable, pAlternateTable, 1) != 1)
            goto L_FREE_FILE;
        if (ParseNtExportDir((PUCHAR)FileBuffer, FileSize, (ULONG64)RelocBase, 0) != 1)
            goto L_FREE_FILE;

        for (i = 0; i < 0x1C; i++)              // 恒为 0x1C（原写 Mode+0x1C）
        {
            unsigned int Rva = *(unsigned int *)(pTargetTable + 48 * i + 4);
            *(_DWORD *)(pTargetTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pTargetTable + 48 * i) = 1;
                memcpy((void *)(pTargetTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }
        for (i = 0; i < 0x1B; i++)
        {
            unsigned int Rva = *(unsigned int *)(pAlternateTable + 48 * i + 4);
            *(_DWORD *)(pAlternateTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pAlternateTable + 48 * i) = 1;
                memcpy((void *)(pAlternateTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }

        wcscpy(FilePath, L"\\FileSystem\\Fastfat");
        ((void(__fastcall *)(_BYTE *, WCHAR *))FnRtlInitUnicodeString)(UnicodeString, FilePath);
        IoStatus = (int)((__int64(__fastcall *)(_BYTE *, __int64, __int64, __int64, __int64,
                                               __int64, __int64, __int64 *))FnCreateFile)(
                     UnicodeString, 0x40, 0, 0, *(__int64 *)DriverListHead, 0, 0, &Handle);
        if (IoStatus < 0 || !Handle)
            goto L_FREE_FILE;
        Result = 1;
        ((void(__fastcall *)(__int64))FnCloseHandle)(Handle);

        GtWrite(GtSavedDeviceObject2, Handle);       // 0x195
        GtWrite((GLOBAL_TABLE_INDEX)0x18F, 1);
        GtWrite((GLOBAL_TABLE_INDEX)0x8A3, 1);
    }
    else if (Mode == 2)
    {
        pTargetTable    = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xBA8);
        pAlternateTable = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xC56);

        if (ParseCallbackContextSections(FileBuffer, FileSize, RelocBase,
                                         pTargetTable, pAlternateTable) != 1)
            goto L_FREE_FILE;
        if (ParseNtExportDir((PUCHAR)FileBuffer, FileSize, (ULONG64)RelocBase, 0) != 1)
            goto L_FREE_FILE;

        for (i = 0; i < 0x1C; i++)              // 恒为 0x1C（原写 Mode+0x1A）
        {
            unsigned int Rva = *(unsigned int *)(pTargetTable + 48 * i + 4);
            *(_DWORD *)(pTargetTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pTargetTable + 48 * i) = 1;
                memcpy((void *)(pTargetTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }
        for (i = 0; i < 0x1B; i++)
        {
            unsigned int Rva = *(unsigned int *)(pAlternateTable + 48 * i + 4);
            *(_DWORD *)(pAlternateTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pAlternateTable + 48 * i) = 1;
                memcpy((void *)(pAlternateTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }

        wcscpy(FilePath, L"\\FileSystem\\Ntfs");
        ((void(__fastcall *)(_BYTE *, WCHAR *))FnRtlInitUnicodeString)(UnicodeString, FilePath);
        IoStatus = (int)((__int64(__fastcall *)(_BYTE *, __int64, __int64, __int64, __int64,
                                               __int64, __int64, __int64 *))FnCreateFile)(
                     UnicodeString, 0x40, 0, 0, *(__int64 *)DriverListHead, 0, 0, &Handle);
        if (IoStatus < 0 || !Handle)
            goto L_FREE_FILE;
        Result = 1;
        ((void(__fastcall *)(__int64))FnCloseHandle)(Handle);

        GtWrite(GtSavedDeviceObject, Handle);        // 0x194
        GtWrite((GLOBAL_TABLE_INDEX)0x190, 1);
        GtWrite((GLOBAL_TABLE_INDEX)0x8A2, 1);
    }
    else if (Mode == 1)
    {
        pTargetTable    = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xD04);
        pAlternateTable = (__int64)GtAlloc((GLOBAL_TABLE_INDEX)0xDB2);

        if (ParseCallbackFunctionSections(FileBuffer, FileSize, RelocBase,
                                          pTargetTable, pAlternateTable, 0) != 1)
            goto L_FREE_FILE;
        if (ParseNtExportDir((PUCHAR)FileBuffer, FileSize, (ULONG64)RelocBase, 0) != 1)
            goto L_FREE_FILE;

        for (i = 0; i < 0x1C; i++)              // 恒为 0x1C（原写 Mode+0x1B）
        {
            unsigned int Rva = *(unsigned int *)(pTargetTable + 48 * i + 4);
            *(_DWORD *)(pTargetTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pTargetTable + 48 * i) = 1;
                memcpy((void *)(pTargetTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }
        for (i = 0; i < 0x1B; i++)
        {
            unsigned int Rva = *(unsigned int *)(pAlternateTable + 48 * i + 4);
            *(_DWORD *)(pAlternateTable + 48 * i) = 0;
            if (Rva && Rva + 0x10 <= FileSize)
            {
                *(_DWORD *)(pAlternateTable + 48 * i) = 1;
                memcpy((void *)(pAlternateTable + 48 * i + 0x10), (void *)(FileBuffer + Rva), 16);
            }
        }

        wcscpy(FilePath, L"\\FileSystem\\exfat");
        ((void(__fastcall *)(_BYTE *, WCHAR *))FnRtlInitUnicodeString)(UnicodeString, FilePath);
        IoStatus = (int)((__int64(__fastcall *)(_BYTE *, __int64, __int64, __int64, __int64,
                                               __int64, __int64, __int64 *))FnCreateFile)(
                     UnicodeString, 0x40, 0, 0, *(__int64 *)DriverListHead, 0, 0, &Handle);
        if (IoStatus < 0 || !Handle)
            goto L_FREE_FILE;
        Result = 1;
        ((void(__fastcall *)(__int64))FnCloseHandle)(Handle);

        GtWrite(GtSavedDeviceObject3, Handle);       // 0x2A3
        GtWrite(GtKernelDataField18, 1);             // 0x2A4
        GtWrite((GLOBAL_TABLE_INDEX)0x8A4, 1);
    }
    else
    {
        return 0;
    }

L_FREE_FILE:                                        // 0x140034B06
    ExFree((void *)FileBuffer);
    if (!Result)
        return 0;

    // ---- 后缀（0x140034B19~0x140034DC6）----
    FillExportEntrySlot(pTargetTable);
    {
        __int64 ImageBuffer  = GtRead(GtNtoskrnlImageBuffer);            // 0x4C
        unsigned int PeSize  = (unsigned int)GtRead(GtNtoskrnlPeFileSize); // 0x21
        __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);             // 3
        // 槽集合：{ 备用表偏移, 源 GT 索引 }
        unsigned int SlotOff[6];
        GLOBAL_TABLE_INDEX SlotGt[6];
        unsigned int SlotCount = 0;

        if (!ImageBuffer || !PeSize || !NtoskrnlBase)
            return 0;

        if (Mode == 2)
        {
            SlotOff[0] = 0x300; SlotGt[0] = (GLOBAL_TABLE_INDEX)0x442F;
            SlotOff[1] = 0x360; SlotGt[1] = (GLOBAL_TABLE_INDEX)0x4432;
            SlotCount = 2;
        }
        else if (Mode == 1)
        {
            SlotOff[0] = 0x30;  SlotGt[0] = (GLOBAL_TABLE_INDEX)0x4429;
            SlotOff[1] = 0x60;  SlotGt[1] = (GLOBAL_TABLE_INDEX)0x442C;
            SlotOff[2] = 0x300; SlotGt[2] = (GLOBAL_TABLE_INDEX)0x442F;
            SlotOff[3] = 0x360; SlotGt[3] = (GLOBAL_TABLE_INDEX)0x4432;
            SlotOff[4] = 0x2D0; SlotGt[4] = (GLOBAL_TABLE_INDEX)0x4435;
            SlotOff[5] = 0x330; SlotGt[5] = (GLOBAL_TABLE_INDEX)0x4438;
            SlotCount = 6;
        }
        else /* Mode == 0：前两个无条件，其余需构建号 >= 0x1772 */
        {
            SlotOff[0] = 0x30;  SlotGt[0] = (GLOBAL_TABLE_INDEX)0x4429;
            SlotOff[1] = 0x60;  SlotGt[1] = (GLOBAL_TABLE_INDEX)0x442C;
            SlotCount = 2;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1772)
            {
                SlotOff[2] = 0x300; SlotGt[2] = (GLOBAL_TABLE_INDEX)0x442F;
                SlotOff[3] = 0x360; SlotGt[3] = (GLOBAL_TABLE_INDEX)0x4432;
                SlotOff[4] = 0x2D0; SlotGt[4] = (GLOBAL_TABLE_INDEX)0x4435;
                SlotOff[5] = 0x330; SlotGt[5] = (GLOBAL_TABLE_INDEX)0x4438;
                SlotCount = 6;
            }
        }

        for (i = 0; i < (int)SlotCount; i++)
        {
            unsigned int Value = (unsigned int)GtRead(SlotGt[i]);
            unsigned int Off = SlotOff[i];
            if (Value && !*(_DWORD *)(pAlternateTable + Off + 4))
            {
                *(_DWORD *)(pAlternateTable + Off)     = 1;
                *(_DWORD *)(pAlternateTable + Off + 4) = Value;
                *(_QWORD *)(pAlternateTable + Off + 8) = NtoskrnlBase + Value;
                memcpy((void *)(pAlternateTable + Off + 0x10),
                       (void *)(ImageBuffer + Value), 16);
            }
        }
    }
    return 0;
}
// =========================================================================
// EnumerateAleEndpointLayer — 枚举单个 ALE 端点层
// 对应原始驱动 0x14001B090（427 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（47 行伪代码），故按伪代码实现。
// 【参数】FilePath = 层标识串（编码后的 DWORD 数组，见 EnumerateAleEndpointLayers）
//   OutCount = 已枚举条目计数（dword，即输出缓冲首 4 字节）
//   OutBuffer = 输出缓冲（每条目 0x270 字节）
//   MaxCount = 最大条目数
// 【逻辑】从 4 个 GT 槽取函数指针（RtlInitUnicodeString / IoCreateFile /
//   驱动对象链表头 / CloseHandle），任一为空即返回 0；
//   构造对象属性 → IoCreateFile(...,1<<6,...) → 失败或句柄为空则返回 0；
//   双层链表遍历：外层 = 句柄+8 起、步长 +0x10（层链）；
//   内层 = 层节点起、步长 +0x18（端点链），且仅在 MaxCount 非 0 时继续；
//   端点数据 = 内层节点+8；去重（FindAleEndpointDuplicate）后
//   复制（CopyAleEndpointEntry）成功才 ++计数、OutBuffer += 0x270、--MaxCount；
//   最后关闭句柄。
// 【⚠ 与消费者契约】调用方 CmdInitFwpsDispatchTables 传
//   (OutputBuffer, OutputBuffer+8, (Size-632)/0x270+1) —— 与形参一一对应：
//   OutCount=(dword*)OutputBuffer、OutBuffer=OutputBuffer+8、MaxCount=条目上限。
//   条目步长 0x270(=624) 与 CopyAleEndpointEntry 的写入范围（+0..+0x270）一致。
// =========================================================================
// 对应原始驱动 0x14001B090（427 字节）
__int64 EnumerateAleEndpointLayer(__int64 FilePath, _DWORD *OutCount, __int64 OutBuffer, int MaxCount)
{
    unsigned int ResultCount = 0;
    __int64 (*InitObjAttrFunc)(_BYTE *, __int64);
    __int64 (*CreateFileFunc)(_BYTE *, __int64, __int64, __int64, __int64, char, __int64, __int64 *, int);
    __int64 *ObjAttrPtr;
    __int64 CloseFunc;
    __int64 LayerEntry;
    __int64 i;
    __int64 EndpointData;
    __int64 FileHandle = 0;
    _BYTE ObjAttrBuffer[80];

    InitObjAttrFunc = (__int64 (*)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc  = (__int64 (*)(_BYTE *, __int64, __int64, __int64, __int64, char, __int64, __int64 *, int))GtRead(GtIoCreateFileFunc);
    ObjAttrPtr      = (__int64 *)GtRead(GtDriverObjectListHead);
    CloseFunc       = GtRead(GtCloseHandleFunc);

    if (!InitObjAttrFunc || !CreateFileFunc || !ObjAttrPtr || !CloseFunc)
        return ResultCount;

    InitObjAttrFunc(ObjAttrBuffer, FilePath);
    if (CreateFileFunc(ObjAttrBuffer, 64, 0, 0, *ObjAttrPtr, 0, 0, &FileHandle, 0) < 0)
        return ResultCount;
    if (!FileHandle)
        return ResultCount;

    for (LayerEntry = *(__int64 *)(FileHandle + 8); LayerEntry; LayerEntry = *(__int64 *)(LayerEntry + 16))
    {
        for (i = LayerEntry; i && MaxCount; i = *(__int64 *)(i + 24))
        {
            EndpointData = *(__int64 *)(i + 8);
            if (!FindAleEndpointDuplicate(EndpointData, OutCount) &&
                CopyAleEndpointEntry(OutBuffer, EndpointData) == 1)
            {
                ++*OutCount;
                OutBuffer += 624;
                --MaxCount;
                ++ResultCount;
            }
        }
    }

    ((void(__fastcall *)(__int64))CloseFunc)(FileHandle);
    return ResultCount;
}

// =========================================================================
// FindAleEndpointDuplicate — 在已枚举列表中查找重复的 ALE 端点
// 对应原始驱动 0x14001B4F4（41 字节）
// 【逆向来源】⚠ 可反编译（18 行伪代码），按伪代码实现。
// 【参数】EndpointData = 待查端点数据指针；EndpointList = 输出缓冲（首 dword 为计数）
// 【逻辑】计数为 0 直接返回 0；否则从 EndpointList+2（即 +8 字节）起、
//   步长 78 个 QWORD（= 0x270 字节，与条目步长一致）比较；命中返回 1，
//   遍历完计数次未命中返回 0。
// =========================================================================
// 对应原始驱动 0x14001B4F4（41 字节）
char FindAleEndpointDuplicate(__int64 EndpointData, _DWORD *EndpointList)
{
    unsigned int Count = *(unsigned int *)EndpointList;
    char Result = 0;
    int Index = 0;

    if (!Count)
        return Result;

    for (__int64 *p = (__int64 *)(EndpointList + 2); EndpointData != *p; p += 78)
    {
        if (++Index >= (int)Count)
            return Result;
    }
    return 1;
}

// =========================================================================
// CopyAleEndpointEntry — 复制 ALE 端点条目到输出缓冲
// 对应原始驱动 0x14001B364（399 字节）
// 【逆向来源】⚠ 可反编译（44 行伪代码），按伪代码实现。
// 【参数】OutputBuffer = 输出缓冲（本条目的起点）；EndpointEntry = 端点条目节点
// 【逻辑】EndpointEntry+0x30 取 EndpointData，须 > MmSystemRangeStart 且内存有效；
//   EndpointData[6] 取 EndpointInfo，须有效且 +103 处有效；
//   把 EndpointInfo[1..12] 共 12 个 QWORD 写入 OutputBuffer+528（步长 8），
//   OutputBuffer+616 收尾；OutputBuffer[0] = EndpointEntry；
//   名称长度 = *(WORD*)(EndpointEntry+0x38) >> 1（截到 0x103=259），
//   从 EndpointEntry+0x40 复制 2*长度 字节到 OutputBuffer+8，末尾补 0；
//   名称指针与末尾均须通过有效性检查。
// 【⚠ 缓冲区范围】写入区间 OutputBuffer+0..+0x270（8+259*2+... ≤ 624），
//   与调用方条目步长 0x270 吻合 —— 无越界。
// =========================================================================
// 对应原始驱动 0x14001B364（399 字节）
char CopyAleEndpointEntry(__int64 OutputBuffer, __int64 EndpointEntry)
{
    __int64 EndpointData;
    char Result = 0;
    __int64 EndpointInfo;
    __int64 LastQword;
    unsigned int NameLength;
    __int64 NamePtr;

    EndpointData = *(__int64 *)(EndpointEntry + 48);
    if (EndpointData <= (__int64)MmSystemRangeStart || CheckMemoryValid((void *)EndpointData) != 1)
        return Result;

    EndpointInfo = *(__int64 *)(EndpointData + 48);
    if (EndpointInfo <= (__int64)MmSystemRangeStart ||
        CheckMemoryValid((void *)EndpointInfo) != 1 ||
        CheckMemoryValid((void *)(EndpointInfo + 103)) != 1)
        return Result;

    Result = 1;
    *(__int64 *)(OutputBuffer + 528) = *(__int64 *)(EndpointInfo + 8);
    *(__int64 *)(OutputBuffer + 536) = *(__int64 *)(EndpointInfo + 16);
    *(__int64 *)(OutputBuffer + 544) = *(__int64 *)(EndpointInfo + 24);
    *(__int64 *)(OutputBuffer + 552) = *(__int64 *)(EndpointInfo + 32);
    *(__int64 *)(OutputBuffer + 560) = *(__int64 *)(EndpointInfo + 40);
    *(__int64 *)(OutputBuffer + 568) = *(__int64 *)(EndpointInfo + 48);
    *(__int64 *)(OutputBuffer + 576) = *(__int64 *)(EndpointInfo + 56);
    *(__int64 *)(OutputBuffer + 584) = *(__int64 *)(EndpointInfo + 64);
    *(__int64 *)(OutputBuffer + 592) = *(__int64 *)(EndpointInfo + 72);
    *(__int64 *)(OutputBuffer + 600) = *(__int64 *)(EndpointInfo + 80);
    *(__int64 *)(OutputBuffer + 608) = *(__int64 *)(EndpointInfo + 88);
    LastQword = *(__int64 *)(EndpointInfo + 96);
    *(__int64 *)OutputBuffer = EndpointEntry;
    *(__int64 *)(OutputBuffer + 616) = LastQword;

    NameLength = (unsigned int)(*(unsigned __int16 *)(EndpointEntry + 56) >> 1);
    *(_WORD *)(OutputBuffer + 8) = 0;
    NamePtr = *(__int64 *)(EndpointEntry + 64);
    if (NameLength > 0x103)
        NameLength = 259;
    if (NamePtr > (__int64)MmSystemRangeStart &&
        CheckMemoryValid((void *)NamePtr) == 1 &&
        CheckMemoryValid((void *)(*(__int64 *)(EndpointEntry + 64) - 2 + 2LL * NameLength)) == 1)
    {
        memmove((void *)(OutputBuffer + 8), (const void *)NamePtr, 2 * NameLength);
    }
    if (NameLength)
        *(_WORD *)(OutputBuffer + 2 * NameLength + 8) = 0;

    return Result;
}

// =========================================================================
// EnumerateAleEndpointLayers — 枚举全部 ALE 端点层
// 对应原始驱动 0x14001B23C（120 字节）
// 【逆向来源】⚠ 可反编译（12 行伪代码），按伪代码实现。
// 【⚠ 签名更正】原声明 `(void *OutputBuffer, __int64 SecondBuffer, unsigned __int64 EntryCount)`
//   与实物不符 —— 真实签名是 `(OutCount, OutBuffer, MaxCount)`（见反编译）：
//   本函数只是把 8 个编码后的层标识串打包成一个 16 项的 DWORD 数组
//   （实际写 8 项，其余为 0），然后转调 EnumerateAleEndpointLayer。
// 【层标识串】8 个 DWORD 是**编码后的宽字符路径**（与 ReadNtFileForCallbackTable 同法）。
//   逐字节解码结果为 `\FileSystem\RAW`（含结尾 NUL 共 16 字节）。
//   ⚠ 注意：本族函数名由 IDA 标为 "AleEndpointLayer"（ALE 端点层），但路径实为
//   `\FileSystem\RAW`（裸卷文件系统）—— 名字与实物不符，属 IDA 命名问题
//   （同 §7.3 记录的那类），此处如实保留 IDA 名并在注释中留档。
// =========================================================================
// 对应原始驱动 0x14001B23C（120 字节）
__int64 EnumerateAleEndpointLayers(_DWORD *OutCount, __int64 OutBuffer, int MaxCount)
{
    _DWORD LayerIds[16];

    LayerIds[0] = 4587612;
    LayerIds[1] = 7077993;
    LayerIds[2] = 5439589;
    LayerIds[3] = 7536761;
    LayerIds[4] = 6619252;
    LayerIds[5] = 6029421;
    LayerIds[6] = 4259922;
    LayerIds[7] = 87;
    LayerIds[8] = 0;
    LayerIds[9] = 0;
    LayerIds[10] = 0;
    LayerIds[11] = 0;
    LayerIds[12] = 0;
    LayerIds[13] = 0;
    LayerIds[14] = 0;
    LayerIds[15] = 0;

    return EnumerateAleEndpointLayer((__int64)LayerIds, OutCount, OutBuffer, MaxCount);
}
