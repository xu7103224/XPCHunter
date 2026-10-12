// MemoryOps.c — 内存操作
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"
// Forward declarations
void ExFree(void *Buffer);
UCHAR ReferenceObjectSafe(__int64 Object);
#include <ntdddisk.h>

// 前向声明（定义在 ThreadMgmt.c 中）
void EnumerateVadRecursiveV1(_QWORD *VirtualAddress, int Depth, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int MaxSize, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV2(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV2(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);

// 外部函数（定义在 SystemInfo.c 和 Utility.c 中）
__int32 AtomicWrite32NoWriteProtect(volatile __int32 *Target, __int32 Value);
__int64 AtomicWrite64NoWriteProtect(volatile __int64 *Target, __int64 Value);
ULONG64 CopyMemoryNoWriteProtect(void *Destination, const void *Source, ULONG Size);
unsigned int MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size);
char ResolveSyscallNumbers(void);

// WritePhysicalMemoryDword — 写物理内存 DWORD（直接 MmMapIoSpace 方式）
// 对应原始驱动 sub_1400833D0
void WritePhysicalMemoryDword(ULONG64 TargetAddress, ULONG Value)
{
    ULONG *MappedAddress;
    PHYSICAL_ADDRESS PhysicalAddr;

    PhysicalAddr.QuadPart = TargetAddress;
    MappedAddress = (ULONG *)MmMapIoSpace(PhysicalAddr, 4, MmNonCached);
    if (MappedAddress)
    {
        *MappedAddress = Value;
        MmUnmapIoSpace(MappedAddress, 4);
    }
}

// CheckAddressInPhysicalMemoryRange — 检查地址是否在物理内存范围内
// 对应原始驱动 sub_140078070
char CheckAddressInPhysicalMemoryRange(unsigned __int64 Address)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return CheckAddressInSystemModuleRange(Address);
    return 0;
}

// WritePhysicalMemory — 写入物理内存（通过 MDL 映射）
// 对应原始驱动 sub_1400831A4
char WritePhysicalMemory(unsigned __int64 TargetAddress, __int64 pWriteContext)
{
    char Success = 0;
    PMDL Mdl;
    char IsPhysicalRange;
    char *MappedSystemVa;
    unsigned __int8 CurrentIrql;
    volatile __int32 *pTarget;
    __int64 QwordValue;
    __int32 DwordValue;
    char *MappedVa;
    void *MappedBuffer;
    volatile __int32 *pExchangePtr;

    Mdl = IoAllocateMdl(
        (PVOID)(TargetAddress & 0xFFFFFFFFFFFFF000ui64),
        (*(_DWORD *)(pWriteContext + 4) + (TargetAddress & 0xFFF) + 4095) & 0xFFFFF000,
        0, 0, 0);
    if (Mdl)
    {
        if (TargetAddress < (unsigned __int64)MmSystemRangeStart)
        {
            MmBuildMdlForNonPagedPool(Mdl);
            Mdl->MdlFlags |= 1u;
            MappedVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, 1, MmCached, 0, 0, 0x10u);
            MappedBuffer = MappedVa;
            if (MappedVa)
            {
                pExchangePtr = (volatile __int32 *)&MappedVa[TargetAddress & 0xFFF];
                if (*(_BYTE *)pWriteContext)
                    InterlockedExchange(pExchangePtr, *(_DWORD *)(pWriteContext + 8));
                else
                    InterlockedExchange64((volatile __int64 *)pExchangePtr, *(_QWORD *)(pWriteContext + 8));
                MmUnmapLockedPages(MappedBuffer, Mdl);
                Success = 1;
            }
        }
        else
        {
            IsPhysicalRange = CheckAddressInPhysicalMemoryRange(TargetAddress);
            MmProbeAndLockPages(Mdl, 0, (LOCK_OPERATION)!IsPhysicalRange);
            if ((Mdl->MdlFlags & 5) != 0)
                MappedSystemVa = (char *)Mdl->MappedSystemVa;
            else
                MappedSystemVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, 0, MmCached, 0, 0, 0x10u);
            if (MappedSystemVa)
            {
                CurrentIrql = KeGetCurrentIrql();
                __writecr8(2u);
                pTarget = (volatile __int32 *)&MappedSystemVa[TargetAddress & 0xFFF];
                if (*(_BYTE *)pWriteContext)
                {
                    DwordValue = *(_DWORD *)(pWriteContext + 8);
                    if (IsPhysicalRange)
                        AtomicWrite32NoWriteProtect(pTarget, DwordValue);
                    else
                        InterlockedExchange(pTarget, DwordValue);
                }
                else
                {
                    QwordValue = *(_QWORD *)(pWriteContext + 8);
                    if (IsPhysicalRange)
                        AtomicWrite64NoWriteProtect((volatile __int64 *)pTarget, QwordValue);
                    else
                        InterlockedExchange64((volatile __int64 *)pTarget, QwordValue);
                }
                __writecr8(CurrentIrql);
                Success = 1;
            }
            MmUnlockPages(Mdl);
        }
        IoFreeMdl(Mdl);
    }
    return Success;
}

// WritePhysicalMemoryQword — 写入物理内存 QWORD（通过 MDL 映射）
// 对应原始驱动 sub_140083180
char WritePhysicalMemoryQword(unsigned __int64 TargetAddress, __int64 Value)
{
    struct {
        char Flag;
        int Size;
        __int64 WriteValue;
    } WriteContext;

    WriteContext.Flag = 0;
    WriteContext.Size = 8;
    WriteContext.WriteValue = Value;
    return WritePhysicalMemory(TargetAddress, (__int64)&WriteContext);
}

// WritePhysicalMemoryBuffer — 写入物理内存缓冲区（通过 MDL 映射）
// 对应原始驱动 sub_140082F3C
char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress, const void *SourceBuffer, unsigned int BufferSize, char ProcessorMode, void *pReadBack)
{
    char Success = 0;
    PMDL Mdl;
    char *MappedSystemVa;
    unsigned __int8 CurrentIrql;
    char *pWriteDest;
    char *MappedVa;
    char *MappedBuffer;
    char IsPhysicalRange;

    Mdl = IoAllocateMdl(
        (PVOID)(TargetAddress & 0xFFFFFFFFFFFFF000ui64),
        ((TargetAddress & 0xFFF) + BufferSize + 4095) & 0xFFFFF000,
        0, 0, 0);
    if (Mdl)
    {
        if (TargetAddress < (unsigned __int64)MmSystemRangeStart)
        {
            MmBuildMdlForNonPagedPool(Mdl);
            Mdl->MdlFlags |= 1u;
            MappedVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, ProcessorMode, MmCached, 0, 0, 0x10u);
            MappedBuffer = MappedVa;
            if (MappedVa)
            {
                if (pReadBack)
                    memmove(pReadBack, &MappedVa[TargetAddress & 0xFFF], BufferSize);
                memmove(&MappedBuffer[TargetAddress & 0xFFF], SourceBuffer, BufferSize);
                MmUnmapLockedPages(MappedBuffer, Mdl);
                Success = 1;
            }
        }
        else
        {
            IsPhysicalRange = CheckAddressInPhysicalMemoryRange(TargetAddress);
            MmProbeAndLockPages(Mdl, 0, (LOCK_OPERATION)!IsPhysicalRange);
            if ((Mdl->MdlFlags & 5) != 0)
                MappedSystemVa = (char *)Mdl->MappedSystemVa;
            else
                MappedSystemVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, 0, MmCached, 0, 0, 0x10u);
            if (MappedSystemVa)
            {
                CurrentIrql = KeGetCurrentIrql();
                __writecr8(2u);
                if (pReadBack)
                    memmove(pReadBack, &MappedSystemVa[TargetAddress & 0xFFF], BufferSize);
                pWriteDest = &MappedSystemVa[TargetAddress & 0xFFF];
                if (IsPhysicalRange)
                    CopyMemoryNoWriteProtect(pWriteDest, SourceBuffer, BufferSize);
                else
                    memmove(pWriteDest, SourceBuffer, BufferSize);
                __writecr8(CurrentIrql);
                Success = 1;
            }
            MmUnlockPages(Mdl);
        }
        IoFreeMdl(Mdl);
    }
    return Success;
}

// AtomicExchange16Bytes — 原子交换 16 字节
// 对应原始驱动 sub_140082CB0
// 通过 MDL 映射目标地址，提升 IRQL 到 2，原子交换 16 字节数据
char AtomicExchange16Bytes(__int64 Source, _OWORD *ExchangeData)
{
    char Result;
    char *TargetPtr;
    PMDL Mdl;
    char *MappedSystemVa, *MappedVa;
    UCHAR CurrentIrql;

    Result = 0;
    if (!*(_DWORD *)(Source + 4))
        return Result;
    if (*(_DWORD *)Source != 1)
        return Result;
    TargetPtr = *(char **)(Source + 8);
    if (!TargetPtr)
        return Result;
    if (!MemoryCompare(Source + 16, TargetPtr, 0x10))
        return Result;

    Mdl = IoAllocateMdl(
        (PVOID)((ULONG64)TargetPtr & 0xFFFFFFFFFFFFF000ULL),
        (((WORD)TargetPtr & 0xFFF) + 4111) & 0xFFFFF000,
        FALSE, FALSE, NULL);
    Mdl = Mdl;
    if (!Mdl)
        return Result;

    MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

    if ((Mdl->MdlFlags & 5) != 0)
        MappedSystemVa = (char *)Mdl->MappedSystemVa;
    else
        MappedSystemVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, 0x10);

    if (MappedSystemVa)
    {
        MappedVa = &MappedSystemVa[(WORD)TargetPtr & 0xFFF];
        CurrentIrql = KeGetCurrentIrql();
        __writecr8(2);
        *ExchangeData = *(_OWORD *)MappedVa;
        *(_OWORD *)MappedVa = *(_OWORD *)(Source + 16);
        Result = 1;
        __writecr8(CurrentIrql);
    }

    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    return Result;
}

// ReadObjectHeaderField — 读取对象头字段
// 对应原始驱动 sub_14006EA50

// ReadObjectHeaderCreateInfo — 读取对象头创建信息
// 对应原始驱动 sub_14006E960
__int64 ReadObjectHeaderCreateInfo(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField05), Flags);
}

// ReadObjectHeaderName — 读取对象头名称
// 对应原始驱动 sub_14006E990
__int64 ReadObjectHeaderName(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField06), Flags);
}

// ReadObjectHeaderType — 读取对象头类型
// 对应原始驱动 sub_14006E9C0
__int64 ReadObjectHeaderType(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField07), Flags);
}

// ReadObjectHeaderQuota — 读取对象头配额
// 对应原始驱动 sub_14006E9F0
__int64 ReadObjectHeaderQuota(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField08), Flags);
}

// ReadObjectHeaderHandle — 读取对象头句柄
// 对应原始驱动 sub_14006EA20
__int64 ReadObjectHeaderHandle(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField09), Flags);
}

// ReadObjectTypeOffset — 读取对象类型偏移
// 对应原始驱动 sub_14006EAE8
__int64 ReadObjectTypeOffset(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField08), Flags);
}

// ReadObjectBodyOffset — 读取对象体偏移
// 对应原始驱动 sub_14006EB18
__int64 ReadObjectBodyOffset(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField10), Flags);
}

// ReadWriteVirtualMemory — 读写虚拟内存通用函数
// 对应原始驱动 sub_1400716E0
bool ReadWriteVirtualMemory(__int64 Process, __int64 SrcAddr, __int64 DstAddr, unsigned int Size)
{
    bool Result = 0;
    __int64 (*pOpenProcessFunc)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *);
    ULONG ServiceCount;
    int (__fastcall *pAttachProcessFunc)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *);
    _QWORD *pServiceCount;
    __int64 FreeFuncAddr;
    void (__fastcall *pFreeFunc)(_QWORD);
    struct _KTHREAD *CurrentThread;
    char SavedByte;
    int CallResult;
    _BYTE ObjectAttrBuffer[8];
    _QWORD HandleBuffer[8];
    __int64 SrcAddrLocal = SrcAddr;
    __int64 DstAddrLocal = DstAddr;
    unsigned int CopySize = Size;

    pOpenProcessFunc = (__int64 (*)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *))GtRead(GtCallbackField07);
    if (!pOpenProcessFunc) { ResolveModuleBaseAddress(); pOpenProcessFunc = (__int64 (*)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *))GtRead(GtCallbackField07); }
    ServiceCount = (ULONG)GtRead(GtSdstServiceCount);
    pAttachProcessFunc = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *))GtRead(16735);
    pServiceCount = (_QWORD *)GtRead(16748);
    FreeFuncAddr = GtRead(GtExFreePoolFunc);
    pFreeFunc = (void (__fastcall *)(_QWORD))FreeFuncAddr;

    if (ServiceCount == (ULONG)-1 || !pAttachProcessFunc || !pServiceCount || !FreeFuncAddr || !pOpenProcessFunc) return Result;

    CurrentThread = KeGetCurrentThread();
    if (pAttachProcessFunc(Process, 512, 0, 0x10000000, *pServiceCount, 0, HandleBuffer) >= 0)
    {
        SavedByte = *((UCHAR *)CurrentThread + ServiceCount);
        *((UCHAR *)CurrentThread + ServiceCount) = 0;
        CallResult = (int)pOpenProcessFunc(HandleBuffer[0], &SrcAddrLocal, &DstAddrLocal, CopySize, ObjectAttrBuffer);
        *((UCHAR *)CurrentThread + ServiceCount) = SavedByte;
        Result = CallResult >= 0;
        pFreeFunc(HandleBuffer[0]);
    }

    return Result;
}

// CmdVirtualMemoryOp — 虚拟内存操作命令
// 对应原始驱动 sub_1400715C0
__int64 CmdVirtualMemoryOp(_OWORD *Address, int InputSize)
{
    bool Result = 0;
    NTSTATUS LookupStatus;
    struct _KPROCESS *TargetProcess, *pQueryFunc;
    PEPROCESS Process = NULL;
    _OWORD InputArgs;
    _OWORD MemoryArgs;
    __int64 OperationData;

    if (!Address || InputSize != 40 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 2) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x28, 4);
    InputArgs = Address[0];
    MemoryArgs = Address[1];
    OperationData = Address[2].qword[0];

    LookupStatus = PsLookupProcessByProcessId((HANDLE)InputArgs.qword[0], &Process);
    TargetProcess = (struct _KPROCESS *)Process;
    if (LookupStatus < 0) TargetProcess = NULL;
    Process = (PEPROCESS)TargetProcess;
    pQueryFunc = (struct _KPROCESS *)InputArgs.qword[1];
    if (!pQueryFunc) { if (LookupStatus >= 0) pQueryFunc = TargetProcess; }

    if (ValidateProcessObject(pQueryFunc, NULL) == 1 && MemoryArgs.qword[1])
        Result = ReadWriteVirtualMemory((__int64)pQueryFunc, MemoryArgs.qword[0], MemoryArgs.qword[1], (unsigned int)OperationData);

    if (Process) ObfDereferenceObject(Process);
    return Result;
}

// SwapKernelMemoryPointer — 交换内核内存指针
// 对应原始驱动 sub_1400759F8
__int64 *SwapKernelMemoryPointer(__int64 *pTarget)
{
    __int64 *pOldEntry = NULL;
    if (!GtRead(459)) AttachToProcessAndInitKernelMemory();
    ULONG Offset = (ULONG)GtRead(GtEprocessExtField01);
    __int64 NewValue = GtRead(16854);
    _QWORD *Result = (_QWORD *)GtRead(16854);
    if (Offset && NewValue && Result)
    {
        __int64 *ExchangeBuffer = (__int64 *)(*Result + Offset + (ULONG64)(ULONG)ReadObjectTypeOffsetByIndex());
        if (*ExchangeBuffer != NewValue) { *pTarget = *ExchangeBuffer; pOldEntry = ExchangeBuffer; *ExchangeBuffer = NewValue; }
    }
    return pOldEntry;
}

// CmdReadProcessMemoryEx — 读取进程内存扩展命令
// 对应原始驱动 sub_140071470
__int64 CmdReadProcessMemoryEx(_OWORD *Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    _OWORD Status;
    NTSTATUS SavedByte;
    struct _KPROCESS *ServiceCount, *AddressPair;
    PEPROCESS Process = NULL;
    _OWORD AddressPair2;

    if (!Address || InputSize != 16 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 1) >= MmUserProbeAddress ||
        !OutputBuffer || BufferSize <= 0x38 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x10, 4);
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    Status = *Address;
    AddressPair2 = Status;
    SavedByte = PsLookupProcessByProcessId((HANDLE)Status.qword[0], &Process);
    ServiceCount = (struct _KPROCESS *)Process;
    if (SavedByte < 0) ServiceCount = NULL;
    Process = (PEPROCESS)ServiceCount;
    AddressPair = (struct _KPROCESS *)Status.qword[1];
    if (!AddressPair) { if (SavedByte >= 0) AddressPair = ServiceCount; AddressPair2.qword[1] = (__int64)AddressPair; }
    if (ValidateProcessObject(AddressPair, NULL) == 1)
        Result = QueryProcessMemoryRegions((__int64)AddressPair, OutputBuffer, BufferSize);
    if (Process) ObfDereferenceObject(Process);
    return Result;
}

// QueryKernelMemoryByAddress — 按地址查询内核内存
// 对应原始驱动 sub_14006E930
__int64 QueryKernelMemoryByAddress(PVOID ***VirtualAddress, char Flags)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField04), Flags);
}
__int64 ReadObjectHeaderField(PVOID ***VirtualAddress, unsigned int FieldOffset, char DerefFirst)
{
    __int64 Result = 0;
    ULONG BaseOffset = (ULONG)GtRead(GtEprocessExtField01);

    if (!BaseOffset || !VirtualAddress || MmIsAddressValid(VirtualAddress) != 1)
        return Result;
    if (!DerefFirst) VirtualAddress = (PVOID ***)*VirtualAddress;
    if (!VirtualAddress || MmIsAddressValid(VirtualAddress) != 1) return Result;

    char *TargetAddr = (char *)VirtualAddress + BaseOffset + FieldOffset;
    if (MmIsAddressValid(TargetAddr) == 1) return *(__int64 *)TargetAddr;
    return Result;
}

// AttachToProcessAndInitKernelMemory — 附加到进程并初始化内核内存
// 对应原始驱动 sub_14006E7F8
__int64 AttachToProcessAndInitKernelMemory(void)
{
    struct _KPROCESS *TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    KAPC_STATE ApcState;

    if (IoGetCurrentProcess() == TargetProcess) TargetProcess = NULL;
    if (TargetProcess) KeStackAttachProcess(TargetProcess, &ApcState);
    InitKernelModuleSectionScan();
    if (TargetProcess) KeUnstackDetachProcess(&ApcState);
    return GtWrite((GLOBAL_TABLE_INDEX)459, 1);
}

// CmdWriteKernelMemoryRange — 写入内核内存范围
// 对应原始驱动 sub_14006C510
__int64 CmdWriteKernelMemoryRange(void)
{
    char Result = 0;
    ULONG HandleTableSize;
    _QWORD *HandleTablePtr;
    __int64 *TargetSlot;
    __int64 NtHandleEntry;

    if (!GtRead(2000)) InitKernelMemoryContext();
    HandleTableSize = (ULONG)GtRead(2000);
    HandleTablePtr = (_QWORD *)GtRead(1992);

    if (HandleTablePtr && (ULONG64)HandleTablePtr > (ULONG64)MmSystemRangeStart && HandleTableSize &&
        (HandleTableSize & 7) == 0 && *HandleTablePtr > (ULONG64)MmSystemRangeStart)
    {
        TargetSlot = (__int64 *)(*HandleTablePtr + HandleTableSize);
        if (CheckMemoryValid(TargetSlot) == 1)
        {
            NtHandleEntry = AllocateNtHandleEntry();
            if (NtHandleEntry)
            {
                *TargetSlot = NtHandleEntry;
                return 1;
            }
        }
    }
    return Result;
}

// CmdCallKernelMemoryFunction — 调用内核内存函数
// 对应原始驱动 sub_14006C42C
__int64 CmdCallKernelMemoryFunction(unsigned int *Address, int InputSize)
{
    char Result = 0;
    int (__fastcall *pOpenFunc)(ULONG64);

    ULONG BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    GLOBAL_TABLE_INDEX SavedByte = BuildNum >= 0x585D ? (GLOBAL_TABLE_INDEX)2017 : (GLOBAL_TABLE_INDEX)2015;

    if (!GtRead(SavedByte)) InitKernelMemoryContext();

    BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    GLOBAL_TABLE_INDEX CallResult = BuildNum >= 0x585D ? (GLOBAL_TABLE_INDEX)2017 : (GLOBAL_TABLE_INDEX)2015;
    pOpenFunc = (int (__fastcall *)(ULONG64))GtRead(CallResult);

    if (pOpenFunc && (char *)pOpenFunc > (char *)MmSystemRangeStart &&
        Address && InputSize == 4 &&
        (ULONG64)Address < MmUserProbeAddress &&
        (ULONG64)(Address + 1) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 4, 4);
        return pOpenFunc(*Address) >= 0;
    }

    return Result;
}

// AtomicWrite16Bytes — 原子写入 16 字节
// 对应原始驱动 sub_140082E14
// 通过 MDL 映射目标地址，提升 IRQL 到 2，原子写入 16 字节数据
char AtomicWrite16Bytes(ULONG64 Context, void *Buffer)
{
    char Result = 0;
    __int64 TargetAddress;
    struct _MDL *Mdl;
    char *MappedSystemVa;
    unsigned __int8 CurrentIrql;

    if (*(_DWORD *)(Context + 4))
    {
        if (*(_DWORD *)Context == 1)
        {
            TargetAddress = *(_QWORD *)(Context + 8);
            if (TargetAddress)
            {
                Mdl = IoAllocateMdl(
                    (PVOID)(TargetAddress & 0xFFFFFFFFFFFFF000uLL),
                    ((TargetAddress & 0xFFF) + 4111) & 0xFFFFF000,
                    0, 0, 0);
                if (Mdl)
                {
                    MmProbeAndLockPages(Mdl, 0, IoWriteAccess);
                    if ((Mdl->MdlFlags & 5) != 0)
                        MappedSystemVa = (char *)Mdl->MappedSystemVa;
                    else
                        MappedSystemVa = (char *)MmMapLockedPagesSpecifyCache(Mdl, 0, MmCached, 0, 0, 0x10u);
                    if (MappedSystemVa)
                    {
                        CurrentIrql = KeGetCurrentIrql();
                        __writecr8(2u);
                        *(_OWORD *)&MappedSystemVa[TargetAddress & 0xFFF] = *(_OWORD *)Buffer;
                        __writecr8(CurrentIrql);
                        Result = 1;
                    }
                    MmUnlockPages(Mdl);
                    IoFreeMdl(Mdl);
                }
            }
        }
    }
    return Result;
}

// EnumerateVadWithBufferV1 — 枚举 VAD 节点(V1)
// 对应原始驱动 sub_14004E71C
void EnumerateVadWithBufferV1(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    PVOID Buffer = ExAlloc(PagedPool, 0x800000);
    if (Buffer)
    {
        EnumerateVadIterativeV1(VirtualAddress, (__int64)Buffer, 0x100000, OutputBuffer, BufferSize);
        ExFree(Buffer);
    }
    else
        EnumerateVadRecursiveV1(VirtualAddress, 0, OutputBuffer, BufferSize);
}

// EnumVadMemoryRegions — 枚举 VAD 内存区域
// 对应原始驱动 sub_14004C65C
// 从 VAD 节点获取文件对象指针，填充 544 字节每项的内存区域条目
void EnumVadMemoryRegions(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG EntryIndex = *OutputBuffer;
    if ((ULONG)(544 * (int)EntryIndex + 552) > BufferSize) return;

    __int64 *pVadRoot = *(__int64 **)(VadNode + 72);
    if (!pVadRoot) return;
    if (MmIsAddressValid(*(PVOID *)(VadNode + 72)) != 1 ||
        MmIsAddressValid((char *)pVadRoot + 55) != 1) return;

    __int64 pVadNode = *pVadRoot;
    if (!pVadNode) return;
    if (MmIsAddressValid((PVOID)pVadNode) != 1 ||
        MmIsAddressValid((PVOID)(pVadNode + 119)) != 1) return;

    bool IsLargePage = (ULONG)GtRead(GtWindowsBuildNumber) < 0x47BA
        ? (*(_DWORD *)(VadNode + 48) & 0x38) == 56
        : (*(_DWORD *)(VadNode + 48) & 0x380) == 896;

    if ((*(UCHAR *)(pVadNode + 56) & 0xA0) != 0xA0 || !IsLargePage) return;

    WORD *pFileObject = (WORD *)(*(_QWORD *)(pVadNode + 64) & 0xFFFFFFFFFFFFFFF0ULL);
    if ((ULONG64)pFileObject <= (ULONG64)MmSystemRangeStart) return;
    if (MmIsAddressValid(pFileObject) != 1 || MmIsAddressValid((char *)pFileObject + 183) != 1) return;
    if (*pFileObject != 5 || ((pFileObject[1] - 184) & 0xFFDF) != 0) return;

    ULONG64 StartAddr = *(ULONG *)(VadNode + 24) + ((ULONG64)*(UCHAR *)(VadNode + 32) << 32);
    ULONG64 EndAddr = *(ULONG *)(VadNode + 28) + ((ULONG64)*(UCHAR *)(VadNode + 33) << 32);
    ULONG ThreadIndex;
    void *Src[2];
    ULONG NameLen, NameLength, CopyLength, StringLength, StringLength2;

    if (FindThreadEntry(OutputBuffer, StartAddr << 12, &ThreadIndex, (__int64)pFileObject) == 1)
    {
        if (EndAddr != StartAddr && QueryObjectNameString((ULONG64)pFileObject, (_QWORD *)Src, &NameLen) == 1)
        {
            __int64 EntryIndex = *OutputBuffer;
            __int64 BufferOffset = 136 * EntryIndex;
            LOBYTE_LV(OutputBuffer[BufferOffset + 2]) = 1;
            NameLength = NameLen;
            *(__int64 *)&OutputBuffer[BufferOffset + 8] = (__int64)pFileObject;
            *(__int64 *)&OutputBuffer[BufferOffset + 4] = StartAddr << 12;
            *(__int64 *)&OutputBuffer[BufferOffset + 6] = (EndAddr - StartAddr + 1) << 12;
            if (NameLength > 0x1FE) NameLength = 510;
            NameLen = NameLength;
            CopyLength = NameLength;
            memmove(&OutputBuffer[BufferOffset + 10], Src[0], NameLength);
            *((WORD *)&OutputBuffer[136 * EntryIndex + 10] + (CopyLength >> 1)) = 0;
            HIWORD_LV(OutputBuffer[BufferOffset + 137]) = 0;
            *OutputBuffer = (ULONG)(EntryIndex + 1);
            ExFree(Src[0]);
        }
    }
    else if (QueryObjectNameString((ULONG64)pFileObject, (_QWORD *)Src, &NameLen) == 1)
    {
        __int64 BufferOffset2 = 136 * ThreadIndex;
        HIWORD_LV(OutputBuffer[BufferOffset2 + 137]) = 0;
        ULONG StringLen = (ULONG)GetStringLength((_WORD *)&OutputBuffer[BufferOffset2 + 10]);
        if (2 * StringLen != NameLen ||
            StringCompare3Way((__int64)&OutputBuffer[BufferOffset2 + 10], (WORD *)Src[0], NameLen >> 1))
        {
            StringLength = (ULONG)GetStringLength((_WORD *)&OutputBuffer[BufferOffset2 + 10]);
            if (NameLen > 2 * (ULONG64)StringLength)
            {
                LOBYTE_LV(OutputBuffer[BufferOffset2 + 2]) = 1;
                StringLength2 = NameLen > 0x1FE ? 510 : NameLen;
                NameLen = StringLength2;
                memmove(&OutputBuffer[BufferOffset2 + 10], Src[0], StringLength2);
                *((WORD *)&OutputBuffer[136 * (ULONG)ThreadIndex + 10] + (NameLen >> 1)) = 0;
                HIWORD_LV(OutputBuffer[BufferOffset2 + 137]) = 0;
            }
        }
        ExFree(Src[0]);
    }
}
// ReadProcessMemoryBlock — 读取进程命令行
// 对应原始驱动 sub_14004B4DC
// 从 PEB 读取 CommandLine，去除引号和前后空格
char ReadProcessMemoryBlock(PRKPROCESS PROCESS, void *Dst, size_t Size)
{
    char Result = 0;
    ULONG PebOffset;
    ULONG64 *pPeb;
    ULONG64 PebAddr;
    UCHAR pEntryData;
    ULONG64 ProcessParams;
    WORD *CmdLinePtr, *TokenPtr;
    __int64 CmdLineLen;
    ULONG TokenCount;
    ULONG i, j, k;
    KAPC_STATE ApcState;

    PebOffset = (ULONG)GtRead(GtEprocessField33);
    if ((ULONG)Size < 2 || PebOffset == (ULONG)-1) return Result;

    pPeb = (ULONG64 *)((char *)PROCESS + PebOffset);
    if (MmIsAddressValid(pPeb) != 1) return Result;

    memset(Dst, 0, Size);
    PebAddr = *pPeb;
    pEntryData = ReferenceObjectSafe((__int64)PROCESS);
    KeStackAttachProcess(PROCESS, &ApcState);

    if (PebAddr && PebAddr < MmUserProbeAddress && PebAddr + 96 < MmUserProbeAddress)
    {
        ProcessParams = *(_QWORD *)(PebAddr + 32);
        if (ProcessParams < MmUserProbeAddress && ProcessParams + 1008 < MmUserProbeAddress)
        {
            CmdLinePtr = *(WORD **)(ProcessParams + 120);
            CmdLineLen = *(WORD *)(ProcessParams + 112);
            if (CmdLinePtr && (_DWORD)CmdLineLen && (ULONG64)CmdLinePtr < MmUserProbeAddress && (ULONG64)CmdLinePtr + CmdLineLen < MmUserProbeAddress)
            {
                if ((ULONG)CmdLineLen > (ULONG)Size) CmdLineLen = (ULONG)Size;
                TokenCount = (ULONG)CmdLineLen >> 1;
                if (TokenCount)
                {
                    TokenPtr = NULL;
                    if (*CmdLinePtr == L'"')
                    {
                        for (i = 1; i < TokenCount; i++)
                        {
                            if (CmdLinePtr[i] == L'"') { TokenPtr = &CmdLinePtr[i + 1]; TokenCount += -1 - i; break; }
                        }
                    }
                    if (!TokenPtr) TokenPtr = CmdLinePtr;

                    // Strip leading spaces
                    for (j = 0; j < TokenCount; j++)
                    {
                        if (TokenPtr[j] == L' ') { TokenPtr = &TokenPtr[j + 1]; TokenCount += -1 - j; if (j < TokenCount) goto CheckPath; break; }
                    }

CheckPath:
                    if (TokenCount && *TokenPtr == L'\\') TokenCount = 0;
                    if (TokenCount > 3 && TokenPtr[1] == L':' && TokenPtr[2] == L'\\') TokenCount = 0;

                    for (k = 1; k < TokenCount; k++) { if (TokenPtr[k] == L'.') goto CopyPath; }
CopyPath:
                    if (TokenCount) memmove(Dst, TokenPtr, 2 * TokenCount);
                    Result = 1;
                }
            }
        }
    }

    KeUnstackDetachProcess(&ApcState);
    if (pEntryData == 1) DereferenceObjectSafe((__int64)PROCESS);

    return Result;
}

// WriteProcessMemoryValue — 写入进程内存值
// 对应原始驱动 sub_140006F00
char WriteProcessMemoryValue(_QWORD *InputParams)
{
    ULONG64 TargetAddress;
    char IsWin32k;
    UCHAR ProcessRefed;
    KAPC_STATE ApcState;

    TargetAddress = InputParams[2];
    if (!TargetAddress || TargetAddress >= MmUserProbeAddress || TargetAddress + 8 >= MmUserProbeAddress)
        return 0;

    if ((ULONG)InputParams[6] >= (ULONG)GtRead(GtWin32kServiceCount))
        return 0;

    IsWin32k = (char)CheckProtectedEntry(*InputParams);
    ProcessRefed = ReferenceObjectSafe(*InputParams);
    KeStackAttachProcess((PRKPROCESS)*InputParams, &ApcState);

    if (IsWin32k)
        WritePhysicalMemoryDword(InputParams[2], *((ULONG *)InputParams + 8));
    else
        WritePhysicalMemoryQword(InputParams[2], InputParams[4]);

    KeUnstackDetachProcess(&ApcState);
    if (ProcessRefed == 1)
        DereferenceObjectSafe(*InputParams);

    return 1;
}

// ReadFileIntoBuffer — 读取文件到缓冲区
// 对应原始驱动 sub_14000BD24
// 从指定地址读取数据到缓冲区，支持跨进程读取
char ReadFileIntoBuffer(__int64 SrcAddress, unsigned int BufferSize, char *DstBuffer)
{
    char *DstBuffer2;
    char Result;
    struct _KPROCESS *TargetProcess;
    char IsSameProcess;
    __int64 NtBuildVer;
    __int64 NtImageBase;
    __int64 HalImageBase;
    struct _KPROCESS *TargetProcess2;
    char DiskSectorsWithAlloc;
    __int64 ReadFunc;
    unsigned int PageOffset;
    unsigned int BytesRead;
    __int64 MappedPage;
    __int64 MappedVa;
    __int64 MappedAddr;
    __int64 ObjectNameFromCallback;
    char ReadSuccess;
    __int64 Flags;
    char PageReadOk;
    char DataReadOk;
    char DiskReadDone;
    char *Dst;
    unsigned int TotalBytesRead;
    __int64 (__fastcall *MapMemoryFunc)(__int64, ULONG64, __int64);
    void (__fastcall *FreeMemoryFunc)(__int64);
    void (__fastcall *UnmapMemoryFunc)(__int64, __int64);
    __int64 (__fastcall *AllocPhysPages)(ULONG64, __int64, ULONG64, ULONG64, ULONG64);
    void (__fastcall *ZeroPagesFunc)(__int64, ULONG64, ULONG64);
    void (__fastcall *MapPhysPagesFunc)(__int64);
    void (__fastcall *FreePagesFunc)(__int64);
    KAPC_STATE ApcState;

    DstBuffer2 = DstBuffer;
    Dst = DstBuffer;
    Result = 0;
    DataReadOk = 0;
    TargetProcess = NULL;
    DiskReadDone = 0;
    IsSameProcess = 0;

    NtBuildVer = GtRead(GtKernelModuleBase);
    if (NtBuildVer)
        IsSameProcess = (NtBuildVer == SrcAddress);

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        if (IsSameProcess)
            goto LABEL_13;
        NtImageBase = GtRead(GtNtoskrnlFileBase);
        if (NtImageBase)
            IsSameProcess = (NtImageBase == SrcAddress);
        if (IsSameProcess)
            goto LABEL_13;
        HalImageBase = GtRead(GtHalModuleBase);
        if (HalImageBase)
            IsSameProcess = (HalImageBase == SrcAddress);
    }

    if (IsSameProcess)
    {
LABEL_13:
        DiskSectorsWithAlloc = (char)ReadDiskSectorsWithAlloc((__int64)&ApcState);
        DiskReadDone = (char)DiskSectorsWithAlloc;
        goto LABEL_15;
    }

    TargetProcess2 = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    TargetProcess = TargetProcess2;
    if (TargetProcess2)
        KeStackAttachProcess(TargetProcess2, &ApcState);
    DiskSectorsWithAlloc = 0;

LABEL_15:
    AllocPhysPages = (__int64 (__fastcall *)(ULONG64, __int64, ULONG64, ULONG64, ULONG64))GtRead(GtAllocPhysPagesFunc);
    MapPhysPagesFunc = (void (__fastcall *)(__int64))GtRead(GtMapPhysPagesFunc);
    ZeroPagesFunc = (void (__fastcall *)(__int64, ULONG64, ULONG64))GtRead(GtZeroPagesFunc);
    MapMemoryFunc = (__int64 (__fastcall *)(__int64, ULONG64, __int64))GtRead(GtMapMemoryFunc);
    UnmapMemoryFunc = (void (__fastcall *)(__int64, __int64))GtRead(GtUnmapMemoryFunc);
    FreeMemoryFunc = (void (__fastcall *)(__int64))GtRead(GtFreeMemoryFunc);
    ReadFunc = GtRead(GtFreePagesFunc);
    FreePagesFunc = (void (__fastcall *)(__int64))ReadFunc;

    if (SrcAddress && AllocPhysPages && MapPhysPagesFunc && ZeroPagesFunc &&
        MapMemoryFunc && UnmapMemoryFunc && FreeMemoryFunc && ReadFunc)
    {
        PageOffset = 4096 - (SrcAddress & 0xFFF);
        BytesRead = 0;

        while (1)
        {
            TotalBytesRead = BytesRead;
            if (BytesRead >= BufferSize)
            {
                DiskSectorsWithAlloc = DiskReadDone;
                break;
            }

            if (BufferSize - BytesRead < PageOffset)
                PageOffset = BufferSize - BytesRead;

            PageReadOk = 0;
            if (CheckMemoryValid((void *)SrcAddress) == 1)
            {
                MappedPage = AllocPhysPages(SrcAddress & 0xFFFFFFFFFFFFF000ULL, 4096, 0, 0, 0);
                if (MappedPage)
                {
                    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x42EE)
                    {
                        ZeroPagesFunc(MappedPage, 0, 0);
                        ObjectNameFromCallback = ReadObjectNameFromCallback(MappedPage, 16, MapMemoryFunc);
                        if (ObjectNameFromCallback)
                        {
                            memmove(Dst, (const void *)(ObjectNameFromCallback + (SrcAddress & 0xFFF)), PageOffset);
                            DataReadOk = 1;
                            PageReadOk = 1;
                        }
                        FreeMemoryFunc(MappedPage);
                    }
                    else
                    {
                        MapPhysPagesFunc(MappedPage);
                        Flags = 0;
                        MappedVa = ((__int64 (__fastcall *)(__int64, ULONG64, __int64, __int64, __int64, int))MapMemoryFunc)(MappedPage, 0, 1, 0, Flags, 16);
                        MappedAddr = MappedVa;
                        if (MappedVa)
                        {
                            memmove(Dst, (const void *)(MappedVa + (SrcAddress & 0xFFF)), PageOffset);
                            DataReadOk = 1;
                            PageReadOk = 1;
                            UnmapMemoryFunc(MappedAddr, MappedPage);
                        }
                    }
                    if (PageReadOk || MmIsAddressValid((PVOID)(PageOffset + SrcAddress - 1)) != 1)
                        Result = DataReadOk;
                    else
                    {
                        memmove(Dst, (const void *)SrcAddress, PageOffset);
                        Result = 1;
                        DataReadOk = 1;
                        PageReadOk = 1;
                    }
                    FreePagesFunc(MappedPage);
                    goto LABEL_40;
                }
                if (CheckMemoryValid((void *)(PageOffset + SrcAddress - 1)) != 1)
                    goto LABEL_40;
                DstBuffer2 = Dst;
                memmove(Dst, (const void *)SrcAddress, PageOffset);
                Result = 1;
                DataReadOk = 1;
                ReadSuccess = 1;
            }
            else
                ReadSuccess = 0;

LABEL_44:
            if (!ReadSuccess)
                memset(DstBuffer2, 0, PageOffset);
            PageOffset = 4096;
            BytesRead = TotalBytesRead + 4096;
            SrcAddress += 4096;
            DstBuffer2 += 4096;
            Dst = DstBuffer2;
            continue;

LABEL_40:
            DstBuffer2 = Dst;
            ReadSuccess = PageReadOk;
            goto LABEL_44;
        }
    }

    if (IsSameProcess)
    {
        if (DiskSectorsWithAlloc == 1)
            ReleaseDiskBuffer((__int64)&ApcState);
    }
    else if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}

// CheckMemoryValid — 检查内存地址是否有效
// 对应原始驱动 sub_140059BC4
BOOLEAN CheckMemoryValid(void *Address)
{
    if (GtRead(GtCallbackField54))
    {
        GtRead(GtCallbackField08);
        GtRead(GtCallbackField120);
        GtRead(GtCallbackField116);
        GtRead(GtCallbackField117);
    }
    return MmIsAddressValid(Address);
}

// ReferenceObjectSafe — 安全引用对象
// 对应原始驱动 sub_140077DF4
// 增加对象的引用计数，使用原子操作确保线程安全
UCHAR ReferenceObjectSafe(__int64 Object)
{
    UCHAR Result;
    int (__fastcall *RefFunc)(__int64);
    UCHAR (__fastcall *AtomicFunc)(volatile signed __int32 *);
    __int64 FuncParam;
    ULONG RefOffset;
    volatile signed __int32 *RefCount;
    ULONG CurrentRef;

    Result = 0;
    RefFunc = (int (__fastcall *)(__int64))GtRead(16944);
    FuncParam = GtRead(16960);

    if (RefFunc && FuncParam)
    {
        if (RefFunc(Object) >= 0)
            return 1;
    }
    else
    {
        AtomicFunc = (UCHAR (__fastcall *)(volatile signed __int32 *))GtRead(16916);
        FuncParam = GtRead(16909);
        RefOffset = (ULONG)GtRead(GtCallbackField77);

        if (AtomicFunc && FuncParam && RefOffset)
        {
            RefCount = (volatile signed __int32 *)(Object + RefOffset);
            if ((ULONG)GtRead(GtWindowsBuildNumber) != 2600)
            {
                CurrentRef = *RefCount & 0xFFFFFFFE;
                if (CurrentRef != _InterlockedCompareExchange(RefCount, CurrentRef + 2, CurrentRef))
                    return AtomicFunc(RefCount) != 0;
                return 1;
            }
            return AtomicFunc(RefCount);
        }
    }
    return Result;
}

// DereferenceObjectSafe — 安全解除引用
// 对应原始驱动 sub_140077ECC
void DereferenceObjectSafe(__int64 Object)
{
    int (__fastcall *DerefFunc)(__int64);
    UCHAR (__fastcall *AtomicFunc)(volatile signed __int32 *);
    __int64 FuncParam;
    ULONG RefOffset;
    volatile signed __int32 *RefCount;
    ULONG CurrentRef;

    DerefFunc = (int (__fastcall *)(__int64))GtRead(16944);
    FuncParam = GtRead(16960);

    if (DerefFunc && FuncParam)
    {
        DerefFunc(Object);
    }
    else
    {
        AtomicFunc = (UCHAR (__fastcall *)(volatile signed __int32 *))GtRead(16916);
        FuncParam = GtRead(16909);
        RefOffset = (ULONG)GtRead(GtCallbackField77);

        if (AtomicFunc && FuncParam && RefOffset)
        {
            RefCount = (volatile signed __int32 *)(Object + RefOffset);
            if ((ULONG)GtRead(GtWindowsBuildNumber) != 2600)
            {
                CurrentRef = *RefCount & 0xFFFFFFFE;
                if (CurrentRef == _InterlockedCompareExchange(RefCount, CurrentRef - 2, CurrentRef))
                    return;
            }
            AtomicFunc(RefCount);
        }
    }
}

// ResolvePointerSafe — 安全解析指针
// 对应原始驱动 sub_14007ACE8
char ResolvePointerSafe(_QWORD *Pointer, _QWORD *OutValue)
{
    if (!MmIsAddressValid(Pointer))
        return 0;
    *OutValue = *Pointer;
    return 1;
}

// ExAlloc — 分配内存（封装）
// 对应原始驱动 sub_140077A00
void *ExAlloc(ULONG PoolType, ULONG Size)
{
    return ExAllocatePoolWithTag((POOL_TYPE)PoolType, Size, 'XPHC');
}

// ExFree — 释放内存（封装）
// 对应原始驱动 sub_140077A34
void ExFree(void *Buffer)
{
    if (Buffer)
        ExFreePoolWithTag(Buffer, 'XPHC');
}

// CheckAddressInSystemModuleRange — 检查地址是否在系统模块范围内
// 对应原始驱动 sub_140077F64
// 检查地址是否在 ntoskrnl 或 hal 模块基址+大小范围内
char CheckAddressInSystemModuleRange(unsigned __int64 Address)
{
    char IsInRange;
    unsigned __int64 ModuleBase;
    __int64 ModuleSize;
    unsigned __int64 NtoskrnlFileBase;
    __int64 NtoskrnlFileSize;
    unsigned __int64 HalBase;
    __int64 HalSize;

    IsInRange = 0;
    ModuleBase = GtRead(GtKernelModuleBase);
    ModuleSize = GtRead(GtEprocessField71);
    if (ModuleBase && (_DWORD)ModuleSize)
    {
        if ((unsigned int)ModuleSize > 0x1405000)
            ModuleSize = 20971520;
        if (Address >= ModuleBase)
            IsInRange = Address < ModuleBase + ModuleSize;
    }
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800 && !IsInRange)
    {
        NtoskrnlFileBase = GtRead(GtNtoskrnlFileBase);
        NtoskrnlFileSize = GtRead(GtDisableHookProtectionAddr1);
        if (NtoskrnlFileBase && (_DWORD)NtoskrnlFileSize)
        {
            if ((unsigned int)NtoskrnlFileSize > 0x1405000)
                NtoskrnlFileSize = 20971520;
            if (Address >= NtoskrnlFileBase && Address < NtoskrnlFileBase + NtoskrnlFileSize)
                return 1;
        }
        HalBase = GtRead(GtHalModuleBase);
        HalSize = GtRead(GtMiniFilterFormatNameExReady);
        if (HalBase && (_DWORD)HalSize)
        {
            if ((unsigned int)HalSize > 0x1405000)
                HalSize = 20971520;
            if (Address >= HalBase && Address < HalBase + HalSize)
                return 1;
        }
    }
    return IsInRange;
}

// ResolveModuleBaseAddress — 解析模块基地址
// 对应原始驱动 sub_1400711A8
// 通过系统调用号解析地址并计算模块基址存储到全局表
__int64 ResolveModuleBaseAddress(void)
{
    __int64 Field22;
    unsigned int Field23;
    __int64 NtoskrnlBase;
    unsigned int ServiceEntryCount;
    __int64 CallbackField06;

    Field22 = GtRead(GtEprocessField22);
    Field23 = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    ServiceEntryCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    CallbackField06 = GtRead(GtCallbackField06);
    if (Field22 && Field23 && NtoskrnlBase && (_DWORD)CallbackField06)
    {
        if ((unsigned int)CallbackField06 < ServiceEntryCount)
        {
            CallbackField06 = ResolveSyscallToAddress((unsigned int)CallbackField06);
            if ((_DWORD)CallbackField06)
            {
                if ((unsigned int)CallbackField06 < Field23)
                    return GtWrite(GtCallbackField07, NtoskrnlBase + (unsigned int)CallbackField06);
            }
        }
    }
    return CallbackField06;
}

// ReadObjectTypeOffsetByIndex — 按索引读取对象类型偏移
// 对应原始驱动 sub_140070064
// 返回全局表中存储的对象句柄信息偏移值
__int64 ReadObjectTypeOffsetByIndex(void)
{
    return GtRead(GtEprocessExtField06);
}

// QueryProcessMemoryRegions — 查询进程内存区域信息
// 对应原始驱动 sub_140071244
// 遍历进程 VAD 树收集所有内存区域的基本信息
char QueryProcessMemoryRegions(__int64 ProcessId, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Success;
    __int64 (__fastcall *DuplicateObjectFunc)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *);
    _QWORD *NtQueryVirtualMemoryFunc;
    void (__fastcall *CloseHandleFunc)(__int64);
    int (__fastcall *QueryVirtualMemoryFunc)(__int64, ULONG64, _QWORD, void *, __int64, _BYTE *);
    struct _KTHREAD *CurrentThread;
    char SavedPreviousMode;
    ULONG64 CurrentAddress;
    unsigned int OutOffset;
    ULONG64 ProtectionInfo;
    ULONG64 AlignedEnd;
    __int64 Handle;
    /* 三个 16 字节的 VAD 条目信息缓冲区 */
    ULONG64 VadEntryInfo[2];
    ULONG64 VadEntryInfo2[2];
    ULONG64 VadEntryInfo3[2];

    Success = 0;
    *OutputBuffer = 0;
    CurrentAddress = GtRead(GtSdstServiceCount);
    DuplicateObjectFunc = (__int64 (__fastcall *)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset);
    NtQueryVirtualMemoryFunc = (_QWORD *)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
    CloseHandleFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    if (CurrentAddress != -1 && DuplicateObjectFunc && NtQueryVirtualMemoryFunc && CloseHandleFunc)
    {
        QueryVirtualMemoryFunc = (int (__fastcall *)(__int64, ULONG64, _QWORD, void *, __int64, _BYTE *))GtRead(GtKernelDataField03);
        if (!QueryVirtualMemoryFunc)
        {
            ResolveModuleEnumBase();
            QueryVirtualMemoryFunc = (int (__fastcall *)(__int64, ULONG64, _QWORD, void *, __int64, _BYTE *))GtRead(GtKernelDataField03);
        }
        if (QueryVirtualMemoryFunc)
        {
            CurrentThread = KeGetCurrentThread();
            Success = 0;
            if (DuplicateObjectFunc(ProcessId, 512, 0, 0x10000000, *NtQueryVirtualMemoryFunc, Success, &Handle) >= 0)
            {
                SavedPreviousMode = *((_BYTE *)CurrentThread + CurrentAddress);
                *((_BYTE *)CurrentThread + CurrentAddress) = 0;
                CurrentAddress = 0;
                OutOffset = 56;
                memset(VadEntryInfo, 0, sizeof(VadEntryInfo));
                while (CurrentAddress < MmUserProbeAddress &&
                       QueryVirtualMemoryFunc(Handle, CurrentAddress, 0, VadEntryInfo, 48, (_BYTE *)VadEntryInfo3 + 8) >= 0)
                {
                    ProtectionInfo = VadEntryInfo2[1];
                    if (VadEntryInfo2[1] < 0x1000u)
                        ProtectionInfo = 4096;
                    VadEntryInfo2[1] = ProtectionInfo;
                    AlignedEnd = VadEntryInfo[0] + ProtectionInfo;
                    CurrentAddress += 4096;
                    if (AlignedEnd >= CurrentAddress)
                        CurrentAddress = AlignedEnd;
                    if (OutOffset < BufferSize)
                    {
                        memcpy(OutputBuffer + 2, VadEntryInfo, sizeof(_OWORD));
                        memcpy(OutputBuffer + 6, VadEntryInfo2, sizeof(_OWORD));
                        memcpy(OutputBuffer + 10, VadEntryInfo3, sizeof(_OWORD));
                        OutOffset += 48;
                        OutputBuffer += 12;
                        ++*OutputBuffer;
                        Success = 1;
                    }
                }
                *((_BYTE *)CurrentThread + (ULONG64)GtRead(GtSdstServiceCount)) = SavedPreviousMode;
                CloseHandleFunc(Handle);
            }
        }
    }
    return Success;
}

// EnumerateVadWithBufferV2 — 枚举 VAD 节点(V2 版，Win7/8)
// 对应原始驱动 sub_14004E964
// 尝试分配 8MB 缓冲区用迭代方式遍历 VAD 树，失败则回退到递归方式
void EnumerateVadWithBufferV2(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    PVOID Buffer = ExAlloc(PagedPool, 0x800000);
    if (Buffer)
    {
        EnumerateVadIterativeV2(VirtualAddress, (__int64)Buffer, 0x100000, OutputBuffer, BufferSize);
        ExFree(Buffer);
    }
    else
    {
        EnumerateVadRecursiveV2(VirtualAddress, 0, OutputBuffer, BufferSize);
    }
}

// GetKernelVirtualAddressRange — 获取内核虚拟地址范围
// 对应原始驱动 sub_14007AD54
// 根据系统版本返回内核地址扫描起始和结束地址
unsigned __int64 GetKernelVirtualAddressRange(__int64 DriverObject, unsigned __int64 *pStartAddress, unsigned __int64 *pEndAddress)
{
    unsigned __int64 result;
    unsigned __int64 *pStartAddr;
    unsigned __int64 *pEndAddr;
    unsigned __int64 EndValue;
    unsigned __int64 StartValue;
    unsigned __int64 AlignedBase;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        pStartAddr = (unsigned __int64 *)GtRead(GtNtCreateThreadResultAddr);
        pEndAddr = (unsigned __int64 *)GtRead(GtNtCreateProcessResultAddr);
        if (pStartAddr && pEndAddr && (EndValue = *pEndAddr, StartValue = *pStartAddr, *pStartAddr > (unsigned __int64)MmSystemRangeStart) && EndValue > (unsigned __int64)MmSystemRangeStart && EndValue > StartValue)
        {
            *pStartAddress = StartValue;
            *pEndAddress = EndValue;
            result = *pStartAddress + 0x10000000;
            if (EndValue <= result)
                return result;
        }
        else if (DriverObject || (DriverObject = GtRead(GtDriverObject)) != 0)
        {
            AlignedBase = DriverObject & 0xFFFFFFFF00000000ULL;
            result = AlignedBase + 0x100000000LL;
            *pStartAddress = AlignedBase;
        }
        else
        {
            *pStartAddress = 0xFFFFFA8000000000ULL;
            result = 0xFFFFFA8100000000ULL;
        }
    }
    else
    {
        *pStartAddress = 0xFFFFFA8000000000ULL;
        result = 0xFFFFFA8020000000ULL;
    }
    *pEndAddress = result;
    return result;
}

// GetProcessVirtualizationContextFallback — 获取进程虚拟化上下文（回退版本）
// 对应原始驱动 sub_140049CD0
// 通过 Fiber 获取当前线程信息，构建进程虚拟化上下文条目

// QueryProcessVirtualization — 查询进程虚拟化状态
// 对应原始驱动 sub_140049F18
// 通过 ZwQueryInformationProcess 获取当前进程的虚拟化信息
__int64 (__fastcall *QueryProcessVirtualizationEx(void))(__int64)
{
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    __int16 TargetSessionId = (__int16)GtRead(GtEprocessField86);
    __int64 (__fastcall *pQueryFunc)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *) = (__int64 (__fastcall *)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtEprocessField54);
    _QWORD *pBuffer = (_QWORD *)GtRead(GtEprocessField58 | 0x100);
    __int64 (__fastcall *pFreeFunc)(__int64) = (__int64 (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    unsigned int EntryIndex = 0;
    __int64 (__fastcall *result)(__int64) = pFreeFunc;

    if (pQueryFunc && pBuffer && pFreeFunc)
    {
        char QueryFlags = 0;
        __int64 ReturnHandle;
        result = (__int64 (__fastcall *)(__int64))pQueryFunc(CurrentProcess, 512, 0, 0x80000000LL, *pBuffer, QueryFlags, &ReturnHandle);
        if ((int)(__int64)result >= 0)
        {
            __int16 *SystemInfo = (__int16 *)AllocExBufferAndQuerySystemInfo(0x10u);
            if (SystemInfo)
            {
                unsigned int EntryCount = *(_DWORD *)SystemInfo;
                if (EntryCount)
                {
                    __int16 *CurrentEntry = SystemInfo + 4;
                    while (CurrentEntry[3] != (_WORD)ReturnHandle || !CompareInt16Equal(*CurrentEntry, TargetSessionId))
                    {
                        ++EntryIndex;
                        CurrentEntry += 12;
                        if (EntryIndex >= EntryCount)
                            goto LABEL_13;
                    }
                    unsigned int SessionIdValue = LOBYTE_LV(SystemInfo[12 * EntryIndex + 6]);
                    GtWrite(GtEprocessField61, 1);
                    GtWrite(GtEprocessField62, SessionIdValue);
                }
LABEL_13:
                ExFree(SystemInfo);
            }
            return (__int64 (__fastcall *)(__int64))pFreeFunc(ReturnHandle);
        }
    }
    return result;
}

// InitKernelModuleSectionScan — 初始化内核模块节区扫描
// 对应原始驱动 sub_14006EB48
// 依次扫描各种类型的节区并记录结果到全局表

// ReadDiskSectorsWithAlloc — 分配并读取磁盘扇区
// 对应原始驱动 sub_14007AAD8
// 分配缓冲区后读取磁盘扇区数据
__int64 ReadDiskSectorsWithAlloc(__int64 BufferSize)
{
    char IsInitialized = 0;
    void (__fastcall *pCreateFunc)(__int64, __int64) = (void (__fastcall *)(__int64, __int64))GtRead(GtCreateObjectTypeFunc);
    __int64 CloseObjectTypeFunc = GtRead(GtCloseObjectTypeFunc);
    int (__fastcall *pValidateFunc)(_QWORD, __int64 *) = (int (__fastcall *)(_QWORD, __int64 *))GtRead(GtValidateObjectTypeFunc);
    __int64 pDeviceObject = GtRead(GtCloseHandleFunc);
    void (__fastcall *pCloseFunc)(__int64) = (void (__fastcall *)(__int64))pDeviceObject;

    if (pCreateFunc && CloseObjectTypeFunc && pValidateFunc && pCloseFunc)
    {
        unsigned int Result = (unsigned int)GtRead(GtCallbackField52);
        if (!Result)
        {
            unsigned int DiskSectors = ReadDiskSectors();
            Result = DiskSectors;
            if (!DiskSectors)
                return IsInitialized;
            GtWrite(GtCallbackField52, DiskSectors);
        }
        __int64 DiskObject;
        if (pValidateFunc(Result, &DiskObject) >= 0)
        {
            pCreateFunc(DiskObject, BufferSize);
            IsInitialized = 1;
            pCloseFunc(DiskObject);
        }
    }
    return IsInitialized;
}

// ReleaseDiskBuffer — 释放磁盘缓冲区
// 对应原始驱动 sub_14007ABA4
__int64 ReleaseDiskBuffer(__int64 DiskObject)
{
    char pEntry = 0;
    void (__fastcall *pCloseFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtCloseObjectTypeFunc);
    if (pCloseFunc)
    {
        pCloseFunc(DiskObject);
        return 1;
    }
    return pEntry;
}

// ResolveModuleEnumBase — 解析模块枚举基址
// 对应原始驱动 sub_140057924
// 从全局表读取 ntoskrnl 映射基址和大小，通过系统调用号解析模块枚举函数的地址
__int64 ResolveModuleEnumBase(void)
{
    __int64 NtImageBase = GtRead(GtEprocessField22);
    unsigned int NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int KernelBase = (unsigned int)GtRead(GtKernelDataField01);
    __int64 result = GtRead(GtWin32kServiceEntryCount);

    if (NtImageBase && NtImageSize && NtoskrnlModuleBase && KernelBase && KernelBase < (unsigned int)result)
    {
        result = ResolveSyscallToAddress(KernelBase);
        if ((_DWORD)result && (unsigned int)result < NtImageSize)
        {
            __int64 CumulativeSize = (unsigned int)result;
            GtWrite(GtKernelDataField02, (unsigned int)result);
            return GtWrite(GtKernelDataField03, CumulativeSize + NtoskrnlModuleBase);
        }
    }
    return result;
}

// ResolveSyscallToAddress — 通过系统调用号解析地址
// 对应原始驱动 sub_14007A5F8
// 在系统调用号表中查找对应的函数地址偏移
__int64 ResolveSyscallToAddress(unsigned int SyscallNumber)
{
    __int64 TargetSyscall = SyscallNumber;
    unsigned int NotResolved = 0;
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    __int64 ServiceTableBase = GtRead(GtEprocessField24);
    unsigned int NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    unsigned int SizeLimit = NtImageSize;

    if (ServiceCount && (_DWORD)TargetSyscall && (unsigned int)TargetSyscall < ServiceCount && ServiceTableBase && NtImageSize)
    {
        __int64 SyscallTable = GtRead(GtEprocessField88);
        if (SyscallTable || (ResolveSyscallNumbers(), (SyscallTable = GtRead(GtEprocessField88)) != 0))
        {
            unsigned __int64 EntryValue = *(_QWORD *)(SyscallTable + 8 * TargetSyscall);
            unsigned __int64 ServiceLimit = *(_QWORD *)(ServiceTableBase + 48);
            if (EntryValue > ServiceLimit && (unsigned int)((int)EntryValue - (int)ServiceLimit) < SizeLimit && EntryValue == ServiceLimit + (unsigned int)(EntryValue - ServiceLimit))
                return (unsigned int)(EntryValue - ServiceLimit);
        }
    }
    return NotResolved;
}

// AllocateNtHandleEntry — 分配 NT 句柄条目
// 对应原始驱动 sub_14006C34C
// 使用加密的路径数据解码后调用对象打开 API，分配 128 字节缓冲区

// ReadDiskSectors — 读取磁盘扇区
// 对应原始驱动 sub_140078A30
// 通过 GtRead 获取的函数指针打开物理磁盘设备，查询扇区计数
// 使用变通方式：直接通过 ZwCreateFile + NtFsControlFile 获取磁盘几何信息
unsigned int ReadDiskSectors(void)
{
    unsigned int Result = 0;
    ULONG BuildNumber;
    HANDLE Handle;
    IO_STATUS_BLOCK IoStatus;
    UNICODE_STRING ObjectName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    WCHAR DevicePath[32];
    DISK_GEOMETRY DiskGeometry;
    ULONG DriveIndex;
    int Status;
    int (__fastcall *pNtFsControlFunc)(HANDLE, ULONG, PVOID, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK);
    __int64 CloseHandleFunc;
    char IsDeviceOpened;

    pNtFsControlFunc = (int (__fastcall *)(HANDLE, ULONG, PVOID, ULONG, PVOID, ULONG, PIO_STATUS_BLOCK))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = GtRead(GtCloseHandleFunc);
    BuildNumber = (ULONG)GtRead(GtNtBuildNumber);

    if (!pNtFsControlFunc || !CloseHandleFunc)
        return 0;

    IsDeviceOpened = 0;

    // Try to open \\.\PhysicalDrive0, \\.\PhysicalDrive1, etc.
    for (DriveIndex = 0; DriveIndex < 32; DriveIndex++)
    {
        RtlStringCbPrintfW(DevicePath, sizeof(DevicePath), L"\\\\.\\PhysicalDrive%lu", DriveIndex);
        RtlInitUnicodeString(&ObjectName, DevicePath);
        InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        Status = ZwCreateFile(
            &Handle,
            GENERIC_READ | SYNCHRONIZE,
            &ObjectAttributes,
            &IoStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL,
            0);

        if (NT_SUCCESS(Status))
        {
            IsDeviceOpened = 1;

            // Query disk geometry
            Status = pNtFsControlFunc(
                Handle,
                0x70040,  // IOCTL_DISK_GET_DRIVE_GEOMETRY
                NULL, 0,
                &DiskGeometry, sizeof(DiskGeometry),
                &IoStatus);

            if (NT_SUCCESS(Status))
            {
                // Calculate total sectors
                ULONG64 TotalSectors = DiskGeometry.Cylinders.QuadPart *
                    DiskGeometry.TracksPerCylinder *
                    DiskGeometry.SectorsPerTrack;

                Result = (ULONG)TotalSectors;

                // On newer builds, adjust for sector size
                if (BuildNumber >= 0x1DB0)
                    Result = Result * (DiskGeometry.BytesPerSector / 512);
            }

            ((void (__fastcall *)(HANDLE))CloseHandleFunc)(Handle);
            break;
        }
    }

    return Result;
}

// CallKernelCleanupEntryV3 — 调用内核清理条目 V3
// 对应原始驱动 sub_14004267C
char CallKernelCleanupEntryV3(_QWORD *VirtualAddress)
{
    char Result = 0;
    void (__fastcall *pFreeFunc)(_QWORD, _QWORD);

    pFreeFunc = (void (__fastcall *)(_QWORD, _QWORD))GtRead(GtTotalSize | GtEprocessExtField05);
    if (pFreeFunc && MmIsAddressValid(VirtualAddress) == 1 && MmIsAddressValid((char *)VirtualAddress + 31) == 1)
    {
        pFreeFunc(VirtualAddress[2], VirtualAddress[3]);
        return 1;
    }
    return Result;
}

// ClearKernelMemoryPointer — 清除内核内存指针
// 对应原始驱动 sub_1400426E0
char ClearKernelMemoryPointer(void)
{
    _QWORD *pShadowSsdtTable = (_QWORD *)GtRead(GtEprocessField84);
    if (MmIsAddressValid(pShadowSsdtTable) == 1)
    {
        *pShadowSsdtTable = 0;
        return 1;
    }
    return 0;
}

// ResolveSyscallNumbers — 解析系统调用号
// 对应原始驱动 sub_140052BF4
char ResolveSyscallNumbers(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return FindSyscallNumbers();
    else
        return ResolveSyscallNumberTable();
}

// =========================================================================
// ResolveSyscallNumberTable — 解析系统调用号表（Win7/8 版本）
// 对应原始驱动 sub_140052C1C
// 在 ntoskrnl 的 .rdata 节区中搜索 NtAdjustPrivilegesToken 和
// NtAllocateVirtualMemory 的导出地址，找到系统调用号表并写入 GT 0x62
// =========================================================================
char ResolveSyscallNumberTable(void)
{
    char Result = 0;
    unsigned int KernelImageSize = (unsigned int)GtRead(GtEprocessField23);
    unsigned __int64 KernelImageBase = GtRead(GtEprocessField22);
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);

    if (!KernelImageBase || !KernelImageSize)
        return 0;

    // 查找 PE 节区
    unsigned int SectionType1 = (unsigned int)FindKernelPESectionByType(0x41D1);
    unsigned int SectionType2 = (unsigned int)FindKernelPESectionByType(0x41D4);

    if (!SectionType1 || SectionType1 >= ServiceCount || !SectionType2 || SectionType2 >= ServiceCount)
        return 0;

    // 计算 PE 可选头中的数据目录
    __int64 PeNtHeaders = *(int *)(KernelImageBase + 60) + KernelImageBase;
    __int64 ExportDirRva = *(_QWORD *)(PeNtHeaders + 0x48);

    // 查找 NtAdjustPrivilegesToken 和 NtAllocateVirtualMemory 的导出地址
    unsigned int AdjustPrivAddr = 0;
    unsigned int AllocVirAddr = 0;

    char Name1[] = "NtAdjustPrivilegesToken";
    char Name2[] = "NtLocalAllocVirtualMemory";

    if (LookupExportByName((PUCHAR)KernelImageBase, (ULONG)KernelImageSize, Name1, &AdjustPrivAddr) != 1)
        return 0;
    if (LookupExportByName((PUCHAR)KernelImageBase, (ULONG)KernelImageSize, Name2, &AllocVirAddr) != 1)
        return 0;

    // 确保两个地址不重叠 — 如果 SectionType2 比 SectionType1 小，交换
    unsigned int StartSection = SectionType1;
    unsigned int EndSection = SectionType2;
    unsigned int StartAddr = (unsigned int)(AdjustPrivAddr + ExportDirRva);
    unsigned int EndAddr = (unsigned int)(AllocVirAddr + ExportDirRva);

    if (EndSection < StartSection)
    {
        unsigned int tmp = StartSection;
        StartSection = EndSection;
        EndSection = tmp;
        tmp = StartAddr;
        StartAddr = EndAddr;
        EndAddr = tmp;
    }

    if (EndSection <= StartSection)
        return 0;

    // 查找 .rdata 节区
    char SectionName[] = ".rdata";
    SectionName[7] = 0;
    unsigned int RdataOffset = (unsigned int)((__int64 (__fastcall *)(unsigned __int64, unsigned int, char *))FindPESectionByName)(KernelImageBase, KernelImageSize, SectionName);
    unsigned int RdataVa = (unsigned int)((__int64 (__fastcall *)(unsigned __int64, unsigned int, char *))FindPESectionByNameReturnVa)(KernelImageBase, KernelImageSize, SectionName);

    if (!RdataOffset || RdataOffset >= KernelImageSize || !RdataVa || RdataVa >= KernelImageSize)
        return 0;

    if (RdataVa + RdataOffset > KernelImageSize)
        return 0;

    // 在 .rdata 中搜索匹配的导出地址
    unsigned int *RdataBase = (unsigned int *)(KernelImageBase + RdataOffset);
    unsigned __int64 RdataEnd = KernelImageBase + RdataOffset + RdataVa;

    unsigned int *ScanPtr = RdataBase;
    int Found = 0;

    while ((unsigned __int64)ScanPtr < RdataEnd)
    {
        if (*ScanPtr == StartAddr)
        {
            unsigned int *CheckPtr = &ScanPtr[EndSection - StartSection];
            if ((unsigned __int64)CheckPtr < RdataEnd && *CheckPtr == EndAddr)
            {
                unsigned int *TableBase = &ScanPtr[-(int)StartSection];
                if ((unsigned __int64)TableBase >= KernelImageBase + RdataOffset &&
                    (unsigned __int64)TableBase < RdataEnd &&
                    (unsigned __int64)&TableBase[ServiceCount] <= RdataEnd)
                {
                    // 找到系统调用号表
                    __int64 *SyscallTable = (__int64 *)ExAlloc(PagedPool, 8 * ServiceCount);
                    if (SyscallTable)
                    {
                        for (unsigned int i = 0; i < ServiceCount; i++)
                        {
                            SyscallTable[i] = ExportDirRva + TableBase[i];
                        }
                        GtWrite((enum _GLOBAL_TABLE_INDEX)0x62, (__int64)SyscallTable);
                        return 1;
                    }
                }
            }
        }
        ScanPtr++;
    }

    return Result;
}

// =========================================================================
// FindSyscallNumbers — 查找系统调用号（Win10+ 版本）
// 对应原始驱动 sub_140052FDC
// 通过特征码在 ntoskrnl 的 .rdata 中查找系统调用号表
// 搜索 NtAdjustPrivilegesToken 和 NtAllocateVirtualMemory 的导出地址
// 匹配后计算所有系统调用地址并写入 GT 0x62
// =========================================================================
char FindSyscallNumbers(void)
{
    char Result = 0;
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    unsigned __int64 KernelImageBase = GtRead(GtEprocessField22);
    unsigned int KernelImageSize = (unsigned int)GtRead(GtEprocessField23);

    if (!KernelImageBase || !KernelImageSize)
        return 0;

    unsigned int SectionType1 = (unsigned int)FindKernelPESectionByType(0x41D1);
    unsigned int SectionType2 = (unsigned int)FindKernelPESectionByType(0x41D2);

    if (!SectionType1 || SectionType1 >= ServiceCount || !SectionType2 || SectionType2 >= ServiceCount)
        return 0;

    __int64 ExportDirRva = *(_QWORD *)(*(int *)(KernelImageBase + 60) + KernelImageBase + 0x48);

    char Name1[] = "NtAdjustPrivilegesToken";
    char Name2[] = "NtAllocateVirtualMemory";

    unsigned int AdjustPrivAddr = 0;
    unsigned int AllocVirAddr = 0;

    if (LookupExportByName((PUCHAR)KernelImageBase, (ULONG)KernelImageSize, Name1, &AdjustPrivAddr) != 1)
        return 0;
    if (LookupExportByName((PUCHAR)KernelImageBase, (ULONG)KernelImageSize, Name2, &AllocVirAddr) != 1)
        return 0;

    // 确保两个地址不重叠
    if (SectionType2 < SectionType1)
    {
        unsigned int tmp = SectionType1;
        SectionType1 = SectionType2;
        SectionType2 = tmp;
        tmp = AdjustPrivAddr;
        AdjustPrivAddr = AllocVirAddr;
        AllocVirAddr = tmp;
    }

    if (SectionType2 <= SectionType1)
        return 0;

    // 查找 .rdata 节区
    char SectionName[] = ".rdata";
    SectionName[7] = 0;
    unsigned int RdataOffset = (unsigned int)((__int64 (__fastcall *)(unsigned __int64, unsigned int, char *))FindPESectionByName)(KernelImageBase, KernelImageSize, SectionName);
    unsigned int RdataVa = (unsigned int)((__int64 (__fastcall *)(unsigned __int64, unsigned int, char *))FindPESectionByNameReturnVa)(KernelImageBase, KernelImageSize, SectionName);

    if (!RdataOffset || RdataOffset >= KernelImageSize || !RdataVa || RdataVa >= KernelImageSize)
        return 0;

    if (RdataVa + RdataOffset > KernelImageSize)
        return 0;

    // 在 .rdata 中搜索匹配的导出地址
    unsigned int *RdataBase = (unsigned int *)(KernelImageBase + RdataOffset);
    unsigned __int64 RdataEnd = KernelImageBase + RdataOffset + RdataVa;

    unsigned int *ScanPtr = RdataBase;
    unsigned int AdjustWithBase = (unsigned int)(AdjustPrivAddr + ExportDirRva);
    unsigned int AllocWithBase = (unsigned int)(AllocVirAddr + ExportDirRva);

    while ((unsigned __int64)ScanPtr < RdataEnd)
    {
        if (*ScanPtr == AdjustWithBase)
        {
            unsigned int *CheckPtr = &ScanPtr[SectionType2 - SectionType1];
            if ((unsigned __int64)CheckPtr < RdataEnd && *CheckPtr == AllocWithBase)
            {
                unsigned int *TableBase = &ScanPtr[-(int)SectionType1];
                if ((unsigned __int64)TableBase >= KernelImageBase + RdataOffset &&
                    (unsigned __int64)TableBase < RdataEnd &&
                    (unsigned __int64)&TableBase[ServiceCount] <= RdataEnd)
                {
                    // 找到系统调用号表
                    __int64 *SyscallTable = (__int64 *)ExAlloc(PagedPool, 8 * ServiceCount);
                    if (SyscallTable)
                    {
                        for (unsigned int i = 0; i < ServiceCount; i++)
                        {
                            SyscallTable[i] = ExportDirRva + TableBase[i];
                        }
                        GtWrite((enum _GLOBAL_TABLE_INDEX)0x62, (__int64)SyscallTable);
                        return 1;
                    }
                }
            }
        }
        ScanPtr++;
    }

    return Result;
}


// ===== Functions moved from MissingFuncs.c =====

// ClearPageTableEntryFlags — 清除页表条目标志
void ClearPageTableEntryFlags(char *VirtualAddress)
{
    int Offset1, Offset2, Mask;
    int FlagOffset, FieldOffset, TypeOffset, ObjTypeCount;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB1)
    {
        Mask = 16;
        Offset1 = (int)GtRead(GtEprocessField94);
    }
    else
    {
        Offset1 = (int)GtRead((GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr1 | GtEprocessField86));
        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 7601) Mask = 0x2000;
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200) Mask = 4096;
        else
        {
            Mask = 1024;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600) Mask = 2048;
        }
    }
    Offset2 = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 64 : 32;
    FlagOffset = (int)GtRead(GtEprocessField53);
    FieldOffset = (int)GtRead(GtEprocessField94);
    TypeOffset = (int)GtRead(GtEprocessField95);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Offset1 != -1 && FlagOffset && FieldOffset != -1 && TypeOffset && ObjTypeCount)
    {
        if (MmIsAddressValid(VirtualAddress) && MmIsAddressValid(&VirtualAddress[ObjTypeCount - 1]))
        {
            *(_DWORD *)&VirtualAddress[Offset1] &= ~Mask;
            *(_DWORD *)&VirtualAddress[FieldOffset] &= ~Offset2 & 0xFFFFFFFE;
            if (VirtualAddress[FlagOffset] == 4) VirtualAddress[FlagOffset] = 0;
            *(_DWORD *)&VirtualAddress[TypeOffset] = 0;
        }
    }
    }

// ===== Functions moved from MissingFuncs.c =====

// ClearProcessPageTableFlags — 清除进程页表标志：遍历进程页目录，清除 PTE 中的保护标志
void ClearProcessPageTableFlags(struct _KPROCESS *Process)
{
    int FlagMask;
    unsigned int PteOffset;
    int PdeOffset;
    unsigned int PteOffset2;
    unsigned int PdeOffset2;
    int TableOffset;
    int TableOffset2;
    int PageSize;
    PVOID *pTableEntry;
    unsigned __int8 RefCount;
    _QWORD *pCurrentEntry;
    unsigned int EntryCount;
    unsigned __int64 ObjectAddr;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB1)
    {
        FlagMask = 16;
        PteOffset = (unsigned int)GtRead(GtEprocessField94);
    }
    else
    {
        PteOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr1 | GtEprocessField86));
        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 7601) FlagMask = 0x2000;
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200) FlagMask = 4096;
        else
        {
            FlagMask = 1024;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600) FlagMask = 2048;
        }
    }
    PageSize = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 64 : 32;
    PdeOffset = (int)GtRead(GtEprocessField41);
    PteOffset2 = (unsigned int)GtRead(GtEprocessField48);
    PdeOffset2 = (unsigned int)GtRead(GtEprocessField94);
    TableOffset = (int)GtRead(GtEprocessField53);
    TableOffset2 = (int)GtRead(GtEprocessField95);
    if (PdeOffset && PteOffset2 && PteOffset != -1 && PdeOffset2 != -1 && TableOffset && TableOffset2)
    {
        if (ValidateProcessObject(Process, 0) == 1)
        {
            pTableEntry = (PVOID *)((char *)Process + PdeOffset);
            RefCount = ReferenceObjectSafe((__int64)Process);
            if (MmIsAddressValid(pTableEntry) == 1)
            {
                pCurrentEntry = *pTableEntry;
                EntryCount = 0;
                if (*pTableEntry > MmSystemRangeStart)
                {
                    do
                    {
                        if ((PVOID *)pCurrentEntry == pTableEntry)
                            break;
                        if (EntryCount > 0x10000)
                            break;
                        if (MmIsAddressValid(pCurrentEntry) != 1)
                            break;
                        ObjectAddr = (unsigned __int64)pCurrentEntry - PteOffset2;
                        if (ValidateKernelObject(ObjectAddr, 0, 0, 0) != 1)
                            break;
                        ++EntryCount;
                        *(_DWORD *)(PteOffset + ObjectAddr) &= ~FlagMask;
                        *(_DWORD *)(PdeOffset2 + ObjectAddr) &= ~PageSize & 0xFFFFFFFE;
                        pCurrentEntry = (_QWORD *)*pCurrentEntry;
                    }
                    while ((unsigned __int64)pCurrentEntry > (unsigned __int64)MmSystemRangeStart);
                }
            }
            if (RefCount == 1)
                DereferenceObjectSafe((__int64)Process);
        }
    }
}
__int64 ReadWriteKernelMemory(void)
{
    // PE 节区读取上下文（约 0x170 字节）
    UCHAR SectionContext[0x170];
    // 节区条目信息缓冲区（0x120 字节，由 ReadPESectionEntry 填充）
    UCHAR SectionEntry[0x120];

    // 局部变量
    __int64 TargetProcess;           // Gt[0x61]: 目标进程 EPROCESS
    ULONG PeFileOffset;              // Gt[0x42E2]: ntoskrnl PE 文件偏移
    ULONG64 PeFileBase;              // Gt[0x20]: ntoskrnl PE 文件映射基址
    ULONG PeFileSize;                // Gt[0x21]: ntoskrnl PE 文件映射大小
    ULONG64 NtoskrnlBase;            // Gt[3]: ntoskrnl 模块基址
    ULONG NtoskrnlSize;              // Gt[2]: ntoskrnl 模块大小
    ULONG SectionIndex;              // 节区遍历索引
    ULONG BuildNumber;               // Gt[0x914]: Windows 构建号
    BOOLEAN Attached;                // 是否已附加到进程
    BOOLEAN Found;                   // 是否找到匹配
    struct _KAPC_STATE ApcState;            // APC 状态
    ULONG64 TargetAddress;           // 计算得到的目标地址
    ULONG PeSectionOffset;           // 从 SectionEntry 读取的偏移值
    ULONG64 AccumulatedOffset;       // 累积偏移（跨迭代保持）
    ULONG64 Type430Matched;          // Type 430/418 匹配标志（跨迭代保持）

    // 清零初始化
    Attached = FALSE;
    Found = FALSE;
    SectionIndex = 0;
    AccumulatedOffset = 0;
    Type430Matched = 0;

    // 读取目标进程指针，如果非空则附加到该进程
    TargetProcess = GtRead((GLOBAL_TABLE_INDEX)0x61);
    if (TargetProcess)
    {
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);
        Attached = TRUE;
    }

    // 读取 PE 相关数据
    PeFileOffset = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x42E2);
    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (ULONG)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlSize = (ULONG)GtRead(GtNtoskrnlImageSize);

    // 验证所有值有效
    if (!PeFileOffset ||
        PeFileOffset >= PeFileSize ||
        !PeFileBase ||
        !PeFileSize ||
        !NtoskrnlBase ||
        !NtoskrnlSize)
    {
        goto Cleanup;
    }

    // 初始化 PE 节区读取上下文
    RtlZeroMemory(SectionContext, sizeof(SectionContext));
    RtlZeroMemory(SectionEntry, sizeof(SectionEntry));

    InitPESectionReadContext(
        (__int64)(PeFileBase + (ULONG_PTR)PeFileOffset),
        PeFileSize - PeFileOffset,
        2,              // Mode: 64-bit PE
        0,              // a4
        -1,             // a5
        0,              // a6
        0,              // a7
        (__int64)SectionContext);

    // 遍历 PE 节区，最多 0xC8 个
    for (SectionIndex = 0; SectionIndex < 0xC8; SectionIndex++)
    {
        ULONG64 TypePtr;
        USHORT EntryType;

        // 读取下一个节区条目，如果失败则退出循环
        if ((ULONG)ReadPESectionEntry(SectionContext, (PULONG)SectionEntry))
        {
            break;
        }

        // SectionEntry + 0xF0: 偏移值，累加到累积偏移中
        PeSectionOffset = *(ULONG *)(SectionEntry + 0xF0);
        AccumulatedOffset += PeSectionOffset;

        // SectionEntry + 0x118: 指向类型结构体的指针
        // 该指针指向的偏移 +6 处为 WORD 类型值
        TypePtr = *(ULONG64 *)(SectionEntry + 0x118);
        EntryType = *(USHORT *)(TypePtr + 6);

        // 如果类型为 0x545，退出循环
        if (EntryType == 0x545)
        {
            break;
        }

        // 读取构建号，根据版本选择匹配模式
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

        // ============================================================
        // 根据构建号选择匹配模式
        // ============================================================

        if (BuildNumber < 0x23F0)
        {
            // ---- Win7/2008R2 及更早：使用 Type 0x50E ----
            if (EntryType != 0x50E)
            {
                continue;
            }

            // SectionEntry + 0x50: 必须为 0x40000
            if (*(ULONG64 *)(SectionEntry + 0x50) != 0x40000)
            {
                continue;
            }

            // SectionEntry + 0x88: 必须为 0x40
            if (*(ULONG64 *)(SectionEntry + 0x88) != 0x40)
            {
                continue;
            }

            // SectionEntry + 0x40: DWORD 偏移值
            // 计算：值 - PeFileOffset + AccumulatedOffset
            PeSectionOffset = *(ULONG *)(SectionEntry + 0x40);
            PeSectionOffset -= PeFileOffset;
            PeSectionOffset += (ULONG)AccumulatedOffset;

            if (!PeSectionOffset || PeSectionOffset >= PeFileSize)
            {
                continue;
            }

            // 直接写入 Gt[0x2BC]
            TargetAddress = (ULONG64)PeSectionOffset + NtoskrnlBase;
            GtWrite((GLOBAL_TABLE_INDEX)0x2BC, TargetAddress);
            Found = TRUE;
            break;
        }
        else if (BuildNumber < 0x2800)
        {
            // ---- Win8/8.1：使用 Type 0x512 ----
            if (EntryType != 0x512)
            {
                continue;
            }

            // SectionEntry + 0x88: 必须为 0x40000
            if (*(ULONG64 *)(SectionEntry + 0x88) != 0x40000)
            {
                continue;
            }

            // SectionEntry + 0x50: 必须为 0x40
            if (*(ULONG64 *)(SectionEntry + 0x50) != 0x40)
            {
                continue;
            }

            // SectionEntry + 0x78: DWORD 偏移值
            // 计算：值 - PeFileOffset + AccumulatedOffset
            PeSectionOffset = *(ULONG *)(SectionEntry + 0x78);
            PeSectionOffset -= PeFileOffset;
            PeSectionOffset += (ULONG)AccumulatedOffset;

            if (!PeSectionOffset || PeSectionOffset >= PeFileSize)
            {
                continue;
            }

            // 检查 Gt[0x82A] 是否已设置
            TargetAddress = (ULONG64)PeSectionOffset + NtoskrnlBase;
            if (GtRead((GLOBAL_TABLE_INDEX)0x82A))
            {
                // 已设置，写入 Gt[0x2BC] 并结束
                GtWrite((GLOBAL_TABLE_INDEX)0x2BC, TargetAddress);
                Found = TRUE;
                break;
            }
            else
            {
                // 未设置，写入 Gt[0x82A] 并继续循环
                GtWrite((GLOBAL_TABLE_INDEX)0x82A, TargetAddress);
                // 继续循环
            }
        }
        else if (BuildNumber < 0x585D)
        {
            // ---- Win10 早期版本（1507-1607）：Type 0x430 设置标志 + Type 0x512 完成匹配 ----
            // 先检查 Type 0x430，满足条件则设置 Type430Matched 标志
            // 后续迭代中遇到 Type 0x512 且标志已设置时完成匹配

            if (EntryType == 0x430)
            {
                // SectionEntry + 0x88: 必须为 0x400000000
                // SectionEntry + 0x70: 必须为 4
                // SectionEntry + 0x50: 必须为 0x20
                if (*(ULONG64 *)(SectionEntry + 0x88) == 0x400000000LL &&
                    *(ULONG64 *)(SectionEntry + 0x70) == 4 &&
                    *(ULONG64 *)(SectionEntry + 0x50) == 0x20)
                {
                    // 设置标志（一旦设置，跨迭代保持）
                    // 原始代码使用 cmovz 保持已有值，等效于：
                    // if (条件满足) Type430Matched = 1; else Type430Matched = Type430Matched;
                    // 但由于 Type430Matched 初始为 0，这里直接设置
                    Type430Matched = 1;
                }
            }

            // 检查 Type 0x512
            if (EntryType == 0x512)
            {
                // SectionEntry + 0x88: 必须为 0x40000
                // SectionEntry + 0x50: 必须为 0x40
                // Type430Matched 标志必须已设置
                if (*(ULONG64 *)(SectionEntry + 0x88) == 0x40000 &&
                    *(ULONG64 *)(SectionEntry + 0x50) == 0x40 &&
                    Type430Matched)
                {
                    // SectionEntry + 0x78: DWORD 偏移值
                    PeSectionOffset = *(ULONG *)(SectionEntry + 0x78);
                    PeSectionOffset -= PeFileOffset;
                    PeSectionOffset += (ULONG)AccumulatedOffset;

                    if (PeSectionOffset && PeSectionOffset < PeFileSize)
                    {
                        TargetAddress = (ULONG64)PeSectionOffset + NtoskrnlBase;
                        GtWrite((GLOBAL_TABLE_INDEX)0x2BC, TargetAddress);
                        Found = TRUE;
                        break;
                    }
                }
            }
        }
        else
        {
            // ---- Win10 1607+：Type 0x418 设置标志 + Type 0x512 完成匹配 ----
            // 先检查 Type 0x418，满足条件则设置 Type430Matched 标志
            // 后续迭代中遇到 Type 0x512 且标志已设置时完成匹配

            if (EntryType == 0x418)
            {
                // SectionEntry + 0x88: 必须为 0x80000
                // SectionEntry + 0x70: 必须为 0
                // SectionEntry + 0x50: 必须为 0x4041
                // SectionEntry + 0x40: 必须为 0x2C
                if (*(ULONG64 *)(SectionEntry + 0x88) == 0x80000 &&
                    *(ULONG64 *)(SectionEntry + 0x70) == 0 &&
                    *(ULONG64 *)(SectionEntry + 0x50) == 0x4041 &&
                    *(ULONG *)(SectionEntry + 0x40) == 0x2C)
                {
                    Type430Matched = 1;
                }
            }

            // 检查 Type 0x512
            if (EntryType == 0x512)
            {
                // SectionEntry + 0x88: 必须为 0x40000
                // SectionEntry + 0x50: 必须为 0x40
                // Type430Matched 标志必须已设置
                if (*(ULONG64 *)(SectionEntry + 0x88) == 0x40000 &&
                    *(ULONG64 *)(SectionEntry + 0x50) == 0x40 &&
                    Type430Matched)
                {
                    // SectionEntry + 0x78: DWORD 偏移值
                    PeSectionOffset = *(ULONG *)(SectionEntry + 0x78);
                    PeSectionOffset -= PeFileOffset;
                    PeSectionOffset += (ULONG)AccumulatedOffset;

                    if (PeSectionOffset && PeSectionOffset < PeFileSize)
                    {
                        TargetAddress = (ULONG64)PeSectionOffset + NtoskrnlBase;
                        GtWrite((GLOBAL_TABLE_INDEX)0x2BC, TargetAddress);
                        Found = TRUE;
                        break;
                    }
                }
            }
        }
    }

Cleanup:
    // 如果之前附加到进程，则分离
    if (Attached)
    {
        KeUnstackDetachProcess(&ApcState);
    }

    return Found ? 1 : 0;
}

// ScanProcessVadMemory — 扫描目标进程的 VAD 内存，定位进程对象在 VAD 中的地址
// 对应原始驱动 0x1400897E4（2707 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整，含地址注释），
//   故按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 A_definite_missing，源码中此前完全缺失。
//
// 【功能】对给定进程对象：取 VAD 根与结束地址，按**构建号**选择对应的 VAD 条目
//   结构布局，在 VAD 表区间内扫描匹配该进程对象的条目，取出其中记录的地址；
//   若结果小于 MmSystemRangeStart 则置 0；把
//   { 进程对象, 创建时间, [VAD 中查得的地址], 0 } 写入输出缓冲并递增计数。
//
// 【构建号分档（自伪代码逐个 if 提取）】
//   10240 / 10586 / 14393  → VAD 项从 +0x50 起、每项 0xA0 字节（步长 20 qword）
//   15063                  → 步长 15 qword
//   16299 / 17134 / 17763 / 18362 / 18363 → 步长 15 qword，且按 16299/17134/17763/其余 细分
//   197xx（0x4A61..0x4A65）→ 步长 15 qword（与 20348 共用同一组判定）
//   20348                  → 步长 15 qword
//   22000 / 22621 / 22631  → 步长 15 qword
char __fastcall ScanProcessVadMemory(unsigned __int64 ObjectAddress,
                                     _OWORD **ppOutputBuffer,
                                     _DWORD *pEntryCount)
{
    __int64 (__fastcall *FnGetProcess)(unsigned __int64);  // GtEprocessField140|GtTotalSize|0x100 (0x4196)
    __int64 KernelSize;          // GtNtoskrnlImageSize
    __int64 MinAddressPtr;       // GtEprocessField104|GtTotalSize|0x100 (0x4168)
    __int64 ObjectTypeCheckBase; // GtObjectTypeCheckFlag
    ULONG   VadRootOffset;       // GtEprocessField191 (201)
    ULONG   VadTableOffset;      // GtEprocessField193 (203)
    ULONG   CreateTimeOffset;    // GtProcessCreateTime (60)
    __int64 KernelBase;          // GtNtoskrnlModuleBase
    UCHAR   Result;              // 返回标志
    ULONG64 FoundAddress;
    __int64 TargetProcess;       // _KPROCESS*
    ULONG64 VadEndAddress;       // *(QWORD*)(VadRootOffset + ObjectAddress)
    __int64 *VadRoot;            // *(QWORD*)(VadTableOffset + ObjectAddress)
    UCHAR   IsReferenced;
    ULONG64 MinAddress;
    ULONG   Build;
    ULONG64 OutS1Lo, OutS1Hi, OutS2Lo, OutS2Hi;
    struct _KAPC_STATE ApcState;

    FnGetProcess        = (__int64 (__fastcall *)(unsigned __int64))GtRead((GLOBAL_TABLE_INDEX)0x4196);  // 0x140089826
    KernelBase          = (__int64)GtRead(GtNtoskrnlModuleBase);         // 0x140089835
    KernelSize          = (__int64)GtRead(GtNtoskrnlImageSize);          // 0x140089842
    MinAddressPtr       = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x4168);   // 0x14008984F
    ObjectTypeCheckBase = (__int64)GtRead(GtObjectTypeCheckFlag);        // 0x14008985E
    VadRootOffset       = (ULONG)GtRead(GtEprocessField191);             // 0x14008986B (201)
    VadTableOffset      = (ULONG)GtRead(GtEprocessField193);             // 0x140089878 (203)
    CreateTimeOffset    = (ULONG)GtRead(GtProcessCreateTime);            // 0x140089885 (60)

    if (!FnGetProcess || !KernelBase || !KernelSize || !MinAddressPtr      // 0x1400898D1
        || !ObjectTypeCheckBase || !VadRootOffset || !VadTableOffset
        || !CreateTimeOffset)
        return 0;

    Result = 1;
    if (!ObjectAddress || !ValidateKernelObject(ObjectAddress, 0, 0, 0))    // 0x1400898F4
        return Result;

    MinAddress = *(ULONG64 *)MinAddressPtr;                                 // [rbp-0xB8] 解引用

    OutS1Lo = ObjectAddress;                                                // 0x140089901
    OutS1Hi = 0;
    OutS2Lo = *(ULONG64 *)(CreateTimeOffset + ObjectAddress);               // 0x14008990C
    OutS2Hi = 0;                                                            // 0x140089919（DWORD2=0）
    FoundAddress = 0;                                                       // 0x140089911

    TargetProcess = FnGetProcess(ObjectAddress);                            // 0x140089925
    IsReferenced = (UCHAR)ReferenceObjectSafe(TargetProcess);               // 0x140089930
    KeStackAttachProcess((void *)TargetProcess, &ApcState);                 // 0x14008993C

    if ((UCHAR)CheckProcessObjectFlag(ObjectAddress) == 1)                  // 0x14008994C
    {
        VadEndAddress = *(ULONG64 *)(VadRootOffset + ObjectAddress);        // 0x140089954
        VadRoot = (__int64 *)(*(ULONG64 *)(VadTableOffset + ObjectAddress)); // 0x14008995B

        if (CheckMemoryValid((void *)(VadEndAddress - 1)) == 1              // 0x140089985
            && CheckMemoryValid(VadRoot) == 1)
        {
            Build = (ULONG)GtRead(GtWindowsBuildNumber);

            if (Build == 10240 || Build == 10586 || Build == 14393)          // 0x1400899C4
            {
                __int64 *p = VadRoot + 10;                                  // 0x14008A0F4
                if ((ULONG64)p < VadEndAddress)                             // 0x14008A0FB
                {
                    while ((ULONG64)(p + 20) <= VadEndAddress)              // 0x14008A11D
                    {
                        __int64 tag = *(p - 1);                             // 0x14008A123
                        if (tag == 128)                                     // 0x14008A12A
                        {
                            if (ObjectAddress == (ULONG64)*p)               // 0x14008A132
                            {
                                ULONG64 v33 = p[1], v16;
                                if (v33 > (ULONG64)MmSystemRangeStart     // 0x14008A148
                                    && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart)
                                {
                                    v16 = p[3];                         // 0x14008A14E
                                    if (v16 > (ULONG64)MmSystemRangeStart
                                        && v33 > v16 && v33 - v16 < 0x1000)   // 0x14008A162
                                    {
                                        FoundAddress = v16;             // LABEL_45
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                ULONG64 v34 = p[2];                     // 0x14008A16A
                                if ((ULONG64)*p == v34)                 // 0x14008A171
                                {
                                    ULONG64 v35 = p[1], v36;
                                    if (v35 > (ULONG64)MmSystemRangeStart
                                        && v34 > (ULONG64)MmSystemRangeStart)  // 0x14008A182
                                    {
                                        v36 = p[3];                     // 0x14008A184
                                        if (v36 > (ULONG64)MmSystemRangeStart
                                            && v35 > v36 && v35 - v36 < 0x1000)  // 0x14008A198
                                        {
                                            FoundAddress = p[3];        // 0x14008A1DC
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            __int64 v37 = *p;                               // 0x14008A19C
                            if (ObjectAddress == (ULONG64)*p
                                && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart)  // 0x14008A1AB
                            {
                                ULONG64 v38 = p[2];                         // 0x14008A1AD
                                if (v38 > (ULONG64)MmSystemRangeStart)      // 0x14008A1B4
                                {
                                    ULONG64 v39 = p[3];                     // 0x14008A1B6
                                    if (v39 > (ULONG64)MmSystemRangeStart
                                        && (tag == (__int64)v39 || v37 == (__int64)v39)
                                        && v37 != (__int64)v38)             // 0x14008A1CC
                                    {
                                        FoundAddress = *(ULONG64 *)(p - 1); // 0x14008A1E1
                                        break;
                                    }
                                }
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                  // 0x14008A1D5
                            break;
                    }
                }
            }
            else if (Build == 15063)                                        // 0x1400899D7
            {
                __int64 *p = VadRoot + 10;                                  // 0x1400899DD
                if ((ULONG64)p < VadEndAddress)
                {
                    while ((ULONG64)(p + 15) <= VadEndAddress)              // 0x1400899FD
                    {
                        if (*p == 128)                                      // 0x140089A09
                        {
                            ULONG64 v16 = *(ULONG64 *)(p - 1);              // 0x140089A0B
                            if (v16 > (ULONG64)MmSystemRangeStart)          // 0x140089A15
                            {
                                ULONG64 v17 = *(ULONG64 *)(p - 2);          // 0x140089A17
                                if (v17 > (ULONG64)MmSystemRangeStart)      // 0x140089A1E
                                {
                                    __int64 v18 = p[1];                     // 0x140089A20
                                    if (v17 == (ULONG64)v18 && v18 == p[3]) // 0x140089A2D
                                    {
                                        ULONG64 v19 = p[2];                 // 0x140089A2F
                                        if (v19 > v16 && v19 - v16 < 0x200) // 0x140089A42
                                        {
                                            FoundAddress = v16;             // LABEL_45
                                            break;
                                        }
                                    }
                                }
                            }
                            if (v16 == 0                                        // 0x140089A6B
                                && *(ULONG64 *)(p - 2) == 0
                                && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                                && ObjectAddress == (ULONG64)p[2])
                            {
                                FoundAddress = v16;                         // LABEL_45
                                break;
                            }
                        }
                        if ((*p & 0xFFFFFFFFFFFFFF7FULL) == 0                   // 0x140089A86
                            && *(ULONG64 *)(p - 3) == 0
                            && *(ULONG64 *)(p - 2) == 0
                            && p[8] == 0)
                        {
                            __int64 v20 = p[3];                                 // 0x140089A8C
                            if (ObjectAddress == (ULONG64)v20                  // 0x140089AB4
                                && v20 == p[12]
                                && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[6] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[11] > (ULONG64)MmSystemRangeStart)
                            {
                                FoundAddress = p[11];                       // 0x140089AD0
                                break;
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                      // 0x140089ABD
                            break;
                    }
                }
            }
            else
            {
                goto L_OTHER_BUILDS;
            }

            goto L_STORE_RESULT;
        }

        Result = 1;
        goto L_EPILOGUE;
    }
    goto L_EPILOGUE;

L_OTHER_BUILDS:                                                             // 0x140089B32 起
    if (Build == 16299 || Build == 17134 || Build == 17763
        || Build == 18362 || Build == 18363)
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089DBD
        Result = 1;
        if ((ULONG64)p < VadEndAddress)                                     // 0x140089DC9
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089DDC
            {
                ULONG   Inner = (ULONG)GtRead(GtWindowsBuildNumber);        // 0x140089DF1
                if (Inner == 16299)                                         // 0x140089DF1
                {
                    __int64 v23 = *p;                                       // 0x140089DF7
                    if (ObjectAddress == (ULONG64)*p && ObjectAddress == (ULONG64)p[1])  // 0x140089E03
                    {
                        if (*(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart  // 0x140089E2F
                            && p[3] == 0 && p[4] == 0
                            && (ULONG64)p[5] > (ULONG64)MmSystemRangeStart
                            && p[6] == 128 && p[8] == 0)
                        {
                            ULONG64 v25 = p[10];                            // 0x140089E35
                            if (v25 == (ULONG64)p[12]                        // 0x140089E48
                                && v25 > (ULONG64)MmSystemRangeStart
                                && (ULONG64)p[11] > (ULONG64)MmSystemRangeStart)
                            {
                                FoundAddress = p[11];                       // LABEL_211 0x14008A0C7
                                goto L_STORE_RESULT;
                            }
                        }
                    }
                    if (v23 == 128)                                         // 0x140089E5C
                    {
                        if (*(ULONG64 *)(p - 2) == 0 && *(ULONG64 *)(p - 3) == 0)  // 0x140089E64
                        {
                            ULONG64 base = *(ULONG64 *)MmSystemRangeStart;  // v24 = *MmSystemRangeStart
                            if (base < (ULONG64)p[1] && ObjectAddress == (ULONG64)p[2]
                                && (ULONG64)p[3] > base && (ULONG64)p[4] > base)   // 0x140089E83
                            {
                                FoundAddress = p[11];                       // LABEL_211
                                goto L_STORE_RESULT;
                            }
                            if (base < (ULONG64)p[1] && (ULONG64)p[4] > base
                                && (ULONG64)p[5] > base && ObjectAddress == (ULONG64)p[6]
                                && (ULONG64)p[7] > base)                    // 0x140089EBB
                            {
                                FoundAddress = p[5];                        // 0x14008A0D0
                                goto L_STORE_RESULT;
                            }
                        }
                    }
                    if ((v23 & 0xFFFFFFFFFFFF00FFULL) == 0 && *(ULONG64 *)(p - 1) == 0)  // 0x140089ED1
                    {
                        ULONG64 base = *(ULONG64 *)MmSystemRangeStart;
                        if (*(ULONG64 *)(p - 4) > base && *(ULONG64 *)(p - 3) > base
                            && (ULONG64)p[1] > base)                        // 0x140089EF6
                        {
                            ULONG64 v29 = p[2];                             // 0x140089EFC
                            if (v29 > base && (ULONG64)p[3] > base
                                && ObjectAddress == (ULONG64)p[4]
                                && (ULONG64)p[5] > base)                    // 0x140089F21
                            {
                                ULONG64 v30 = p[6];                         // 0x140089F27
                                if (v30 > base && (ULONG64)p[7] > base
                                    && (ULONG64)p[8] > base && v29 == v30)  // 0x140089F4B
                                {
                                    FoundAddress = p[3];                    // LABEL_213
                                    goto L_STORE_RESULT;
                                }
                            }
                        }
                    }
                }
                else if (Inner == 17134)                                    // 0x140089F65
                {
                    if (ObjectAddress == (ULONG64)*p)                       // 0x140089F74
                    {
                        if ((ULONG64)p[1] > (ULONG64)MmSystemRangeStart     // 0x140089FC8
                            && (p[2] & 0xFFFFFFFFFFFF00FFULL) == 0
                            && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 3) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                            && p[8] == 0
                            && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart)
                        {
                            FoundAddress = *(ULONG64 *)(p - 1);             // LABEL_215 0x14008A0EB
                            goto L_STORE_RESULT;
                        }
                        if (ObjectAddress == (ULONG64)*p                     // 0x14008A023
                            && ObjectAddress == (ULONG64)p[2]
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                            && *((ULONG *)p - 2) == 1
                            && p[3] == 128
                            && p[6] == 0
                            && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart)
                        {
                            FoundAddress = p[4];                            // 0x14008A0E2
                            goto L_STORE_RESULT;
                        }
                    }
                }
                else if (Inner == 17763)                                    // 0x14008A03D
                {
                    if (ObjectAddress == (ULONG64)*p                        // 0x14008A078
                        && ObjectAddress == (ULONG64)p[2]
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                        && *((ULONG *)p - 2) == 1
                        && (ULONG64)p[4] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 3) == 0
                        && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = p[3];                                // LABEL_213 0x14008A0D9
                        goto L_STORE_RESULT;
                    }
                }
                else                                                        // 18362/18363
                {
                    if (ObjectAddress == (ULONG64)*p                        // 0x14008A0B3
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 2) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 3) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 5) == 0
                        && (ULONG64)p[3] > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = *(ULONG64 *)(p - 1);                  // LABEL_215
                        goto L_STORE_RESULT;
                    }
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x14008A0BC
                    goto L_STORE_RESULT;
            }
        }
        goto L_STORE_RESULT;
    }
    else if (Build >= 0x4A61 && Build <= 0x4A65)                            // 0x140089B58
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089B5E
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089B79
            {
                if (ObjectAddress == (ULONG64)*p                            // 0x140089BE7
                    && (((ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 4) == 0 && *(ULONG64 *)(p - 6) == 0)
                        || (ObjectAddress == (ULONG64)*p
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                            && p[3] == 0
                            && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)))
                {
                    FoundAddress = p[1];                                    // LABEL_74 0x140089BFB
                    break;
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089BF0
                    break;
            }
        }
    }
    else if (Build == 20348)                                                // 0x140089C11
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089C17
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089C32
            {
                if (ObjectAddress == (ULONG64)*p                            // 0x140089CA0
                    && (((ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                         && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                         && *(ULONG64 *)(p - 4) == 0 && *(ULONG64 *)(p - 6) == 0)
                        || (ObjectAddress == (ULONG64)*p
                            && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                            && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                            && p[3] == 0
                            && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 4) == 0
                            && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                            && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)))
                {
                    FoundAddress = p[1];                                    // LABEL_74
                    break;
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089CAD
                    break;
            }
        }
    }
    else if (Build == 22000 || Build == 22621 || Build == 22631)            // 0x140089CE3
    {
        __int64 *p = VadRoot + 10;                                          // 0x140089CE9
        if ((ULONG64)p < VadEndAddress)
        {
            while ((ULONG64)(p + 15) <= VadEndAddress)                      // 0x140089D04
            {
                if (ObjectAddress == (ULONG64)*p)                           // 0x140089D13
                {
                    if ((ULONG64)p[1] > (ULONG64)MmSystemRangeStart         // 0x140089D4E
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[8] > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[9] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 4) == 0
                        && *(ULONG64 *)(p - 6) == 0
                        && (*(ULONG64 *)(p - 8) || *(ULONG64 *)(p - 9)
                            || *(ULONG64 *)(p - 10) || *(ULONG64 *)(p - 11)))
                    {
                        FoundAddress = *(ULONG64 *)(p - 3);                 // 0x140089DA2
                        Result = 1;
                        if (FoundAddress <= (ULONG64)MmSystemRangeStart)    // 0x140089DAE
                            FoundAddress = p[1];                            // 0x140089DB4
                        goto L_STORE_RESULT;
                    }
                    if (ObjectAddress == (ULONG64)*p                        // 0x140089D8A
                        && (ULONG64)p[1] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 1) > (ULONG64)MmSystemRangeStart
                        && (ULONG64)p[2] > (ULONG64)MmSystemRangeStart
                        && p[3] == 0
                        && (ULONG64)p[7] > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 4) == 0
                        && *(ULONG64 *)(p - 5) > (ULONG64)MmSystemRangeStart
                        && *(ULONG64 *)(p - 6) > (ULONG64)MmSystemRangeStart)
                    {
                        FoundAddress = p[1];                                // LABEL_74
                        break;
                    }
                }
                if ((ULONG64)++p >= VadEndAddress)                          // 0x140089D97
                    break;
            }
        }
    }

L_STORE_RESULT:
    Result = 1;                                                             // 0x14008A1E4
    if (FoundAddress < MinAddress)                                          // 0x14008A1F6
        FoundAddress = 0;
    OutS2Hi = FoundAddress;                                                 // 0x14008A1FA

L_EPILOGUE:                                                                 // 0x14008A206
    KeUnstackDetachProcess(&ApcState);
    if (IsReferenced == 1)                                                  // 0x14008A215
        DereferenceObjectSafe(TargetProcess);

    {
        ULONG64 *p = (ULONG64 *)*ppOutputBuffer;                            // 0x14008A225
        p[0] = OutS1Lo;                                                     // 0x14008A22D
        p[1] = OutS1Hi;
        p[2] = OutS2Lo;                                                     // 0x14008A235
        p[3] = OutS2Hi;
        *ppOutputBuffer += 2;                                               // 0x14008A239
        ++*pEntryCount;                                                     // 0x14008A242
    }
    return Result;                                                          // 0x14008A254
}

// ScanProcessVadForObjectTypes — 枚举进程并对匹配目标对象类型的进程扫描其 VAD 内存
// 对应原始驱动 0x14008A278（383 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整），按伪代码 1:1 转写。
//   该函数是 _FINAL_GAP.json 的 D_need_review（源码中此前完全缺失）。
// 【功能】分配 0x44610 字节缓冲 → 调 EnumProcessInformationWorker 取进程列表 →
//   逐个进程用"对象类型校验函数"验证（自身、+CallbackField76+7）、且
//   *(QWORD*)(proc + CallbackField76) 非零 → 在已输出条目中查重（按 proc 地址，
//   步长 4 qword 向前回扫，计数 pEntryCount）→ 未重复则调 ScanProcessVadMemory
//   继续扫描；其返回 0 则中断循环。最后释放缓冲。
void __fastcall ScanProcessVadForObjectTypes(_OWORD *OutputBuffer,
                                            int *pEntryCount,
                                            int MaxEntries)
{
    _OWORD *pOutputPos;
    UCHAR (__fastcall *pCheckObjectTypeFunc)(ULONG64);
    __int64 *pObjectTypeInfo;
    ULONG   EprocessField30;
    ULONG64 CallbackField76;
    ULONG64 *ProcessInfoBuffer;
    ULONG   ProcessCount;
    ULONG   ProcessIndex;
    ULONG64 ProcAddr;
    char    CtxByte[8];
    __int64 v19, v20;
    _OWORD *OutputCursor;
    int    *pCount;
    int     Max;

    (void)MaxEntries;
    OutputCursor = OutputBuffer;
    pCount = pEntryCount;
    Max = MaxEntries;

    pOutputPos = OutputBuffer;
    pCheckObjectTypeFunc = (UCHAR (__fastcall *)(ULONG64))GtRead(GtObjectTypeCheckFlag);
    if (!pCheckObjectTypeFunc)                                              // 0x14008A2AA
        return;

    pObjectTypeInfo = (__int64 *)GtRead(GtObjectTypeInfoPtr);               // 0x14008A2BF
    EprocessField30 = (ULONG)GtRead(GtEprocessField30);                      // 0x14008A2CC
    CallbackField76 = (ULONG64)GtRead(GtCallbackField76);                    // 0x14008A2CF

    if (!pObjectTypeInfo)                                                   // 0x14008A2DF
        return;
    if (EprocessField30 == 0xFFFFFFFF)                                      // 0x14008A2E8
        return;
    if ((ULONG)CallbackField76 == 0)                                        // 0x14008A2F0
        return;

    ProcessInfoBuffer = (ULONG64 *)ExAlloc(1 /*PagedPool*/, 0x44610);       // 0x14008A302
    if (!ProcessInfoBuffer)                                                 // 0x14008A312
        return;

    v20 = *pObjectTypeInfo;                                                 // 0x14008A320
    v19 = *(ULONG64 *)(EprocessField30 + v20);                              // 0x14008A32E
    CtxByte[0] = 1;                                                          // 0x14008A336

    if (EnumProcessInformationWorker(CtxByte, (__int64)ProcessInfoBuffer, 0x44610))  // 0x14008A33B
    {
        ProcessCount = *((ULONG *)ProcessInfoBuffer + 4);                    // 0x14008A348
        ProcessIndex = 0;
        if (ProcessCount)                                                    // 0x14008A351
        {
            ULONG64 *p = ProcessInfoBuffer + 4;                              // 0x14008A357
            ULONG64 Step = CallbackField76;                                  // 0x14008A35B

            do
            {
                ProcAddr = *p;                                               // 0x14008A363
                if (pCheckObjectTypeFunc(ProcAddr) == 1                      // 0x14008A380
                    && pCheckObjectTypeFunc(ProcAddr + Step + 7) == 1
                    && *(ULONG64 *)(ProcAddr + Step) != 0)
                {
                    ULONG64 *cur = (ULONG64 *)pOutputPos - 2;                // 0x14008A38F
                    int cnt = *pCount;                                       // 0x14008A393
                    if (cnt)
                    {
                        // 已在输出中的进程跳过（步长 4 qword 向前回扫）
                        while (*cur != ProcAddr)                             // 0x14008A39D
                        {
                            cur -= 4;                                        // 0x14008A39F
                            if (--cnt == 0)                                  // 0x14008A3A5
                                goto L_DO_SCAN;
                        }
                    }
                    else
                    {
                    L_DO_SCAN:                                               // 0x14008A3C4
                        if (!ScanProcessVadMemory(ProcAddr, &OutputCursor, (_DWORD *)pCount))
                            break;                                           // 0x14008A3C4
                        pOutputPos = OutputCursor;                           // 0x14008A3C6
                    }
                }
                ++ProcessIndex;                                              // 0x14008A3CE
                p += 7;                                                      // 0x14008A3D0
            } while (ProcessIndex < ProcessCount);                           // 0x14008A3D7
        }
    }

    ExFree(ProcessInfoBuffer);                                               // 0x14008A3E1
    (void)v19; (void)Max;
}

// ScanProcessVadTree — 扫描目标进程 VAD 树，按对象类型索引定位 VAD 记录地址
// 对应原始驱动 0x140088B74（1834 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
//   该函数是 _FINAL_GAP.json 的 A_definite_missing，源码中此前完全缺失。
//
// 【与 ScanProcessVadMemory(0x1400897E4) 的关系】同族：同样的 GT 前置校验、
//   ValidateKernelObject → ReferenceObjectSafe → KeStackAttachProcess 骨架、
//   以及同样的"输出 {进程对象, 创建时间, 地址, 对象类型索引} 并递增计数"收尾。
//   差异：本函数**多一个入参 ObjectTypeIndex**（写入 ResultStruct2 的第 2 个 DWORD，
//   即"类型索引"字段），且构建号分档更多（2600/7600-7601/9200/9600/3790/其他）。
char __fastcall ScanProcessVadTree(unsigned __int64 ObjectAddress,
                                   int ObjectTypeIndex,
                                   _OWORD **ppOutputBuffer,
                                   _DWORD *pEntryCount)
{
    __int64 (__fastcall *pGetProcessFunc)(unsigned __int64);
    ULONG64 KernelBase;
    ULONG   KernelSize;
    ULONG64 *pMinAddress;
    __int64 ObjectTypeCheckBase;
    ULONG   VadRootOffset;
    ULONG   VadTableOffset;
    ULONG   CreateTimeOffset;
    UCHAR   Result;
    ULONG64 FoundAddress;
    __int64 TargetProcess;
    ULONG64 VadEndAddress;
    ULONG   Build;
    UCHAR   IsReferenced;
    ULONG64 OutS1Lo, OutS1Hi, OutS2Lo, OutS2Hi;
    struct _KAPC_STATE ApcState;

    Result = 0;
    pGetProcessFunc = (__int64 (__fastcall *)(unsigned __int64))GtRead((GLOBAL_TABLE_INDEX)0x4196);
    KernelBase      = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    KernelSize      = (ULONG)GtRead(GtNtoskrnlImageSize);
    pMinAddress     = (ULONG64 *)GtRead((GLOBAL_TABLE_INDEX)0x4168);
    ObjectTypeCheckBase = (__int64)GtRead(GtObjectTypeCheckFlag);
    VadRootOffset   = (ULONG)GtRead(GtEprocessField191);
    VadTableOffset  = (ULONG)GtRead(GtEprocessField193);
    CreateTimeOffset= (ULONG)GtRead(GtProcessCreateTime);

    if (!pGetProcessFunc) return Result;
    if (!KernelBase) return Result;
    if (!KernelSize) return Result;
    if (!pMinAddress) return Result;
    if (!ObjectTypeCheckBase) return Result;
    if (!VadRootOffset) return Result;
    if (!VadTableOffset) return Result;
    if (!CreateTimeOffset) return Result;

    Result = 1;
    if (!ObjectAddress) return Result;
    if (!ValidateKernelObject(ObjectAddress, 0, 0, 0)) return Result;

    OutS1Lo = ObjectAddress;
    OutS1Hi = 0;
    OutS2Lo = *(ULONG64 *)(CreateTimeOffset + ObjectAddress);
    OutS2Hi = (ULONG64)(ULONG)ObjectTypeIndex;      // DWORD2(ResultStruct2) = ObjectTypeIndex
    FoundAddress = 0;

    TargetProcess = pGetProcessFunc(ObjectAddress);
    IsReferenced = (UCHAR)ReferenceObjectSafe(TargetProcess);
    KeStackAttachProcess((void *)TargetProcess, &ApcState);

    if (CheckProcessObjectFlag(ObjectAddress))
    {
        __int64 *VadRoot;
        VadEndAddress = *(ULONG64 *)(VadRootOffset + ObjectAddress);
        VadRoot = (__int64 *)(*(ULONG64 *)(VadTableOffset + ObjectAddress));

        if (CheckMemoryValid((void *)(VadEndAddress - 1)) == 1
            && CheckMemoryValid(VadRoot) == 1)
        {
            Build = (ULONG)GtRead(GtWindowsBuildNumber);

            if (Build == 2600)                                          // 0x140088D2F
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress; ++p)
                {
                    if ((ULONG64)(p + 12) > VadEndAddress)              // 0x140088D4B
                        break;
                    if (ObjectAddress == (ULONG64)*p && p[1] == 0)      // 0x140088D56
                    {
                        ULONG64 v18 = p[3];                             // 0x140088D5B
                        if (v18 > (ULONG64)VadRoot && v18 < VadEndAddress)   // 0x140088D67
                        {
                            ULONG64 v19 = p[4];                         // 0x140088D69
                            if (v19 > KernelBase && v19 < KernelBase + KernelSize)  // 0x140088D7C
                            {
                                FoundAddress = p[2];                    // LABEL_112
                                break;
                            }
                        }
                    }
                }
            }
            else if (Build == 7600 || Build == 7601)                    // 0x140088DA8
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress && (ULONG64)(p + 20) <= VadEndAddress; ++p)
                {
                    if ((ULONG)GtRead(GtWindowsBuildNumber) == 7600)    // 0x140089120
                    {
                        if (ObjectAddress == (ULONG64)*p)               // 0x140089129
                        {
                            ULONG64 v46 = p[7], v47 = p[8];             // 0x14008912F/133
                            if (v46 == v47 && v47 >= (ULONG64)MmSystemRangeStart)  // 0x14008914B
                            {
                                ULONG64 v48 = p[10];                    // 0x14008914D
                                ULONG64 v49 = KernelBase + KernelSize;  // 0x140089159
                                if (v48 > KernelBase && v48 < v49)      // 0x140089154/15F
                                {
                                    ULONG64 v50 = p[11];                // 0x140089161
                                    if (v50 > KernelBase && v50 < v49)  // 0x14008916D
                                    {
                                        FoundAddress = p[13];           // 0x14008920B
                                        break;
                                    }
                                }
                            }
                            if (p[5] >= (__int64)MmSystemRangeStart)    // 0x140089181
                            {
                                ULONG64 v51 = p[1];                     // 0x140089183
                                ULONG64 v52 = KernelBase + KernelSize;
                                if (v51 > KernelBase && v51 < v52)      // 0x14008918A/195
                                {
                                    ULONG64 v53 = p[2];                 // 0x140089197
                                    if (v53 > KernelBase && v53 < v52   // 0x1400891B3
                                        && v46 > (ULONG64)VadRoot && v46 < VadEndAddress
                                        && p[9] >= (__int64)MmSystemRangeStart)
                                    {
                                        FoundAddress = p[4];            // 0x140089211
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else if (p[1] == 0 && p[3] == 0)                    // 0x1400891BF
                    {
                        ULONG64 v54 = p[4];                             // 0x1400891C5
                        if (v54 >= (ULONG64)MmSystemRangeStart          // 0x1400891FD
                            && p[5] >= (__int64)MmSystemRangeStart
                            && p[6] == 1
                            && ObjectAddress == (ULONG64)p[9]
                            && p[10] >= (__int64)MmSystemRangeStart
                            && p[11] >= (__int64)MmSystemRangeStart
                            && p[18] == (__int64)v54)
                        {
                            FoundAddress = p[5];                        // LABEL_145
                            break;
                        }
                    }
                }
            }
            else if (Build == 9200)                                     // 0x140088DBA
            {
                __int64 *p = VadRoot + 10;
                if ((ULONG64)p < VadEndAddress)
                {
                    while ((ULONG64)(p + 20) <= VadEndAddress)          // 0x140088DDE
                    {
                        if (ObjectAddress == (ULONG64)*p && p[-1] == (__int64)-6000000000LL)  // 0x140088DF7
                        {
                            ULONG64 v21 = p[1];                             // 0x140088DF9
                            ULONG64 v22 = KernelBase + KernelSize;
                            if (v21 > KernelBase && v21 < v22)              // 0x140088E00/0C
                            {
                                ULONG64 v23 = p[2];                         // 0x140088E0E
                                if (v23 > KernelBase && v23 < v22)          // 0x140088E1A
                                {
                                    ULONG64 v24 = p[-2];                    // 0x140088E1C
                                    if (v24 > KernelBase && v24 < v22       // 0x140088E31
                                        && p[9] >= (__int64)MmSystemRangeStart)
                                    {
                                        FoundAddress = p[-6];               // 0x140088E42
                                        break;
                                    }
                                }
                            }
                        }
                        if ((ULONG64)++p >= VadEndAddress)                  // 0x140088E3A
                            break;
                    }
                }
            }
            else if (Build == 9600)                                     // 0x140088E57
            {
                __int64 *p = VadRoot + 10;
                for (; (ULONG64)p < VadEndAddress && (ULONG64)(p + 20) <= VadEndAddress; ++p)
                {
                    if (ObjectAddress != (ULONG64)*p)                       // 0x140088E7D
                        continue;

                    {
                        __int64 HookFlag = (__int64)GtRead(GtNtCreateThreadHookSuccess);  // 0x140088E88
                        ULONG64 v27 = p[1];                                 // 0x140088E8F
                        if (HookFlag)                                       // 0x140088E96
                        {
                            if (v27 > KernelBase && v27 < KernelBase + KernelSize)  // 0x140088EEF
                            {
                                __int64 v28 = p[2];                         // 0x140088EF1
                                if (v28 == 1)                               // 0x140088EF8
                                {
                                    if (p[3] > (__int64)MmSystemRangeStart
                                        && *p == p[4])                      // 0x140088F11
                                    {
                                        FoundAddress = p[3];                // 0x140088F92
                                        break;
                                    }
                                }
                                else if (v28 == 0 && p[3] == 0 && p[4] == 0  // 0x140088F3D
                                    && p[7] > (__int64)MmSystemRangeStart
                                    && *p == p[6])
                                {
                                    FoundAddress = p[7];                // 0x140088F9B
                                    break;
                                }
                            }
                            else if (v27 == 1 && p[6] == 0)                // 0x140088F46
                            {
                                __int64 v29 = *p;                          // 0x140088F4C
                                if (*p == p[3])                            // 0x140088F53
                                {
                                    ULONG64 v30 = p[5];                    // 0x140088F55
                                    if (v30 > (ULONG64)MmSystemRangeStart  // 0x140088F7A
                                        && (ULONG64)v29 != v30
                                        && ((v29 ^ (__int64)v30) & 0xFFFFFFFF00000000LL) != 0)
                                    {
                                        FoundAddress = p[5];               // LABEL_145
                                        break;
                                    }
                                }
                            }
                        }
                        else if (v27 > KernelBase                          // 0x140088ED5
                            && v27 < KernelBase + KernelSize
                            && p[2] > (__int64)MmSystemRangeStart
                            && p[3] == 2
                            && p[7] == 40)
                        {
                            FoundAddress = p[2];                        // 0x140088F89
                            break;
                        }
                    }
                }
            }
            else if (Build < 0x1770 || Build > 0x1772)                  // 0x140088FBE
            {
                ULONG   v36 = (ULONG)GtRead(GtWindowsBuildNumber);      // 0x140089033
                __int64 *p = VadRoot;
                if (v36 == 3790)                                        // 0x140089043
                {
                    for (; (ULONG64)p < VadEndAddress; ++p)
                    {
                        if ((ULONG64)(p + 12) > VadEndAddress)          // 0x140089059
                            break;
                        if (ObjectAddress == (ULONG64)*p && p[1] == 0)  // 0x140089064
                        {
                            ULONG64 v39 = p[7];                         // 0x140089069
                            if (v39 > (ULONG64)VadRoot && v39 < VadEndAddress)  // 0x140089075
                            {
                                ULONG64 v40 = p[8];                     // 0x140089077
                                if (v40 > KernelBase && v40 < KernelBase + KernelSize)  // 0x14008908A
                                {
                                    FoundAddress = p[6];                // 0x140089094
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    for (; (ULONG64)p < VadEndAddress; ++p)
                    {
                        if ((ULONG64)(p + 12) > VadEndAddress)          // 0x1400890B1
                            break;
                        if (ObjectAddress == (ULONG64)*p && p[1] == 0)  // 0x1400890BC
                        {
                            ULONG64 v43 = p[4];                         // 0x1400890C1
                            if (v43 > (ULONG64)VadRoot && v43 < VadEndAddress)  // 0x1400890CD
                            {
                                ULONG64 v44 = p[5];                     // 0x1400890CF
                                if (v44 > KernelBase && v44 < KernelBase + KernelSize)  // 0x1400890E2
                                {
                                    FoundAddress = p[2];                // LABEL_112
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            else                                                        // 0x1770..0x1772
            {
                __int64 *p = VadRoot;
                for (; (ULONG64)p < VadEndAddress; ++p)
                {
                    if ((ULONG64)(p + 12) > VadEndAddress)              // 0x140088FDA
                        break;
                    if (ObjectAddress == (ULONG64)*p && p[1] == 0)      // 0x140088FE5
                    {
                        ULONG64 v34 = p[10];                            // 0x140088FEA
                        if (v34 > (ULONG64)VadRoot && v34 < VadEndAddress)   // 0x140088FF6
                        {
                            ULONG64 v35 = p[11];                        // 0x140088FF8
                            if (v35 > KernelBase && v35 < KernelBase + KernelSize)  // 0x14008900B
                            {
                                FoundAddress = p[8];                    // 0x140089015
                                if (FoundAddress < (ULONG64)MmSystemRangeStart)  // 0x140089023
                                    FoundAddress = 0;
                                break;
                            }
                        }
                    }
                }
            }

            if (FoundAddress < *pMinAddress)                            // 0x140089226
                FoundAddress = 0;
            OutS2Hi = FoundAddress;                                     // 0x14008922A
        }
    }

    KeUnstackDetachProcess(&ApcState);                                 // 0x140089239
    if (IsReferenced == 1)                                             // 0x140089243
        DereferenceObjectSafe(TargetProcess);

    {
        ULONG64 *o = (ULONG64 *)*ppOutputBuffer;                       // 0x140089253
        o[0] = OutS1Lo; o[1] = OutS1Hi;
        o[2] = OutS2Lo; o[3] = OutS2Hi;
        *ppOutputBuffer += 2;                                          // 0x140089267
        ++*pEntryCount;                                                // 0x140089270
    }
    return Result;                                                     // 0x14008927B
}

// EnumProcessObjectTypes — 枚举进程对象类型表，逐类型遍历对象链并扫描 VAD 树
// 对应原始驱动 0x1400892A0（1346 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（伪代码完整且带地址注释），
//   按伪代码 1:1 转写（符合项目规则：可反编译者不手工逐条转写）。
// 【原型】原始是可变参（表, 类型数, 输出缓冲, 计数指针, 上限）；此处按实际用到的
//   5 个具名参数给出，与调用点 DispatchEnumObjectTypes 的实参一一对应。
// 【说明】原始在每个"候选对象"处都用同一段 inline 查重（输出游标 -2 起、步长 4 qword
//   向前回扫计数次），此处抽成文件内静态辅助 `VadEntryAlreadyStored` ——
//   它是对**同一段原始指令**的忠实提取（不含任何原始没有的语义），仅消除重复书写。
static BOOLEAN VadEntryAlreadyStored(const int *pEntryCount, _OWORD *pOutputStart, ULONG64 Value)
{
    int     n = *pEntryCount;
    _OWORD *cur = pOutputStart - 2;
    while (n)
    {
        if (*(ULONG64 *)cur == Value)
            return TRUE;
        cur -= 4;
        if (--n == 0)
            break;
    }
    return FALSE;
}

void __fastcall EnumProcessObjectTypes(_QWORD *pObjectTypeTable, unsigned int ObjectTypeCount,
                                       _OWORD *OutputBuffer, int *pEntryCount, int MaxEntries)
{
    UCHAR (__fastcall *pCheck)(ULONG64);
    ULONG   ObjectTypeCheckBase;
    ULONG   Build;
    ULONG   TypeIndex;

    pCheck = (UCHAR (__fastcall *)(ULONG64))GtRead(GtObjectTypeCheckFlag);   // 0x1400892D5
    ObjectTypeCheckBase = (ULONG)GtRead(GtCallbackField74);                  // 0x1400892DC

    if (!pCheck || !ObjectTypeCheckBase || !pObjectTypeTable                  // 0x140089301
        || pCheck((ULONG64)pObjectTypeTable) == 0)
        return;

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                             // 0x14008931E

    if (Build >= 0x23F0)
    {
        if (Build == 9200)                                                   // 0x1400893D3
        {
            for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)    // 0x1400893CF
            {
                _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[10 * (ULONG64)TypeIndex + 1];
                ULONG    guard = 0;
                _QWORD   *pObj = *pSlot;

                while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                       && MaxEntries && guard <= 0x10000)                    // 0x140089418
                {
                    ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;      // 0x140089427
                    if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                    {
                        if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                               &OutputBuffer, (_DWORD *)pEntryCount))
                        {
                            TypeIndex = ObjectTypeCount;                     // 0x140089464
                            break;
                        }
                    }
                    pObj = (_QWORD *)*pObj;                                  // 0x140089457
                    ++guard;
                }
                if (ObjectTypeCount == TypeIndex)                            // 0x140089468
                    break;
            }
        }
        else
        {
            for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)    // 0x14008947F
            {
                _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[88 * (ULONG64)TypeIndex + 1];
                ULONG    guard = 0;
                _QWORD   *pObj = *pSlot;

                while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                       && MaxEntries && guard <= 0x10000)                    // 0x1400894BD
                {
                    ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;      // 0x1400894CC
                    if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                    {
                        if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                               &OutputBuffer, (_DWORD *)pEntryCount))
                        {
                            TypeIndex = ObjectTypeCount;                     // 0x140089509
                            break;
                        }
                    }
                    pObj = (_QWORD *)*pObj;                                  // 0x1400894FC
                    ++guard;
                }
                if (ObjectTypeCount == TypeIndex)                            // 0x14008950D
                    break;
            }
        }
    }
    else
    {
        for (TypeIndex = 0; TypeIndex < ObjectTypeCount; ++TypeIndex)        // 0x140089328
        {
            _QWORD **pSlot = (_QWORD **)&pObjectTypeTable[11 * (ULONG64)TypeIndex + 1];
            ULONG    guard = 0;
            _QWORD   *pObj = *pSlot;

            while (pObj && pObj != (_QWORD *)pSlot && pCheck((ULONG64)pObj)
                   && MaxEntries && guard <= 0x10000)                        // 0x140089363
            {
                ULONG64 diff = (ULONG64)pObj - ObjectTypeCheckBase;          // 0x140089372
                if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, diff))
                {
                    if (!ScanProcessVadTree(diff, (int)TypeIndex,
                                           &OutputBuffer, (_DWORD *)pEntryCount))
                    {
                        TypeIndex = ObjectTypeCount;                         // 0x1400893AF
                        break;
                    }
                }
                pObj = (_QWORD *)*pObj;                                      // 0x1400893A2
                ++guard;
            }
            if (ObjectTypeCount == TypeIndex)                                // 0x1400893B3
                break;
        }
    }

    /* ---- 第二段：由进程列表反查类型槽 → 类型下标（0x140089528 起） ---- */
    {
        __int64 *pTypeInfo = (__int64 *)GtRead(GtObjectTypeInfoPtr);         // 0x140089528
        ULONG    EprocF30  = (ULONG)GtRead(GtEprocessField30);               // 0x140089535
        ULONG    CbF76     = (ULONG)GtRead(GtCallbackField76);               // 0x140089538
        ULONG64  Step      = CbF76;
        ULONG64 *ProcBuf;
        ULONG    ProcCount, ProcIdx;
        char     Ctx[8];

        if (!pTypeInfo) return;                                              // 0x140089544
        if (EprocF30 == 0xFFFFFFFF) return;                                  // 0x14008954D
        if (Step == 0) return;                                               // 0x140089555

        ProcBuf = (ULONG64 *)ExAlloc(1 /*PagedPool*/, 0x44610);              // 0x140089569
        if (!ProcBuf) return;

        Ctx[0] = 1;                                                          // 0x140089599
        if (EnumProcessInformationWorker(Ctx, (__int64)ProcBuf, 0x44610))     // 0x14008959D
        {
            ProcCount = *((ULONG *)ProcBuf + 4);                              // 0x1400895AA
            ProcIdx = 0;
            if (ProcCount)
            {
                ULONG64 *p = ProcBuf + 4;                                     // 0x1400895BA
                for (;;)
                {
                    ULONG64 ProcAddr = *p;                                    // 0x1400895C2

                    if (pCheck(ProcAddr) == 1                                 // 0x1400895E2
                        && pCheck(ProcAddr + Step + 7) == 1)
                    {
                        __int64 *SlotPtr = *(__int64 **)(Step + ProcAddr);    // 0x1400895E8
                        if (SlotPtr)                                          // 0x1400895EF
                        {
                            ULONG Inner = (ULONG)GtRead(GtWindowsBuildNumber);
                            int   TypeIdx = -1;

                            if (Inner >= 0x23F0)                              // 0x140089604
                            {
                                if (Inner == 9200)                            // 0x14008964E
                                {
                                    if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                    else if (SlotPtr == pObjectTypeTable + 10)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 20)      TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 30)      TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 40)      TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 50)      TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 60)      TypeIdx = 6;
                                }
                                else
                                {
                                    if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                    else if (SlotPtr == pObjectTypeTable + 88)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 176)     TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 264)     TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 352)     TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 440)     TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 528)     TypeIdx = 6;
                                    else if (SlotPtr == pObjectTypeTable + 90)      TypeIdx = 1;
                                    else if (SlotPtr == pObjectTypeTable + 180)     TypeIdx = 2;
                                    else if (SlotPtr == pObjectTypeTable + 270)     TypeIdx = 3;
                                    else if (SlotPtr == pObjectTypeTable + 360)     TypeIdx = 4;
                                    else if (SlotPtr == pObjectTypeTable + 450)     TypeIdx = 5;
                                    else if (SlotPtr == pObjectTypeTable + 540)     TypeIdx = 6;
                                }
                            }
                            else
                            {
                                if      (SlotPtr == pObjectTypeTable)           TypeIdx = 0;
                                else if (SlotPtr == pObjectTypeTable + 11)      TypeIdx = 1;
                                else if (SlotPtr == pObjectTypeTable + 22)      TypeIdx = 2;
                            }

                            if (TypeIdx >= 0)                                 // LABEL_100
                            {
                                if (!VadEntryAlreadyStored(pEntryCount, OutputBuffer, ProcAddr))
                                {
                                    if (!ScanProcessVadTree(ProcAddr, TypeIdx,
                                                           &OutputBuffer, (_DWORD *)pEntryCount))
                                        goto L_DONE;                      // LABEL_105
                                }
                            }
                        }
                    }

                    ++ProcIdx;                                                // 0x1400897AE
                    p += 7;                                                   // 0x1400897B1
                    if (ProcIdx >= ProcCount)                                 // 0x1400897B8
                        break;
                }
            }
        }

    L_DONE:
        ExFree(ProcBuf);                                                      // 0x1400897C2
    }
}

// DispatchEnumObjectTypes — 取当前进程对象类型表并按构建号选择枚举量后分发
// 对应原始驱动 0x14008A3F8（189 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译，按伪代码 1:1 转写。
void __fastcall DispatchEnumObjectTypes(__int64 OutputBuffer, __int64 pEntryCount, int MaxEntries)
{
    char   *CurrentFiber;
    int     FiberOffset;
    __int64 ProcessPtr;
    _QWORD *pObjectTypeTable;
    ULONG   Build;
    ULONG   EnumCount;

    CurrentFiber = (char *)j_GetCurrentFiber();                                  // 0x14008A41F
    FiberOffset = (int)GtRead((GLOBAL_TABLE_INDEX)(0x4000 | 0x01 | 0x100));      // Gt821|GtEprocessField02
    if (FiberOffset == -1)                                                       // 0x14008A42A
        return;

    ProcessPtr = *(ULONG64 *)&CurrentFiber[FiberOffset];                         // 0x14008A42F
    if (!ProcessPtr)                                                             // 0x14008A436
        return;

    pObjectTypeTable = (_QWORD *)(ProcessPtr + 192);                             // 0x14008A43D

    if ((ULONG)GtRead(GtWindowsBuildNumber) == 9600                              // 0x14008A46E
        && (ULONG64)pObjectTypeTable > (ULONG64)MmSystemRangeStart
        && ((ULONG64)pObjectTypeTable[2] <= (ULONG64)MmSystemRangeStart
            || (ULONG64)pObjectTypeTable[1] <= (ULONG64)MmSystemRangeStart
            || (ULONG64)*pObjectTypeTable >= (ULONG64)MmSystemRangeStart))
    {
        pObjectTypeTable = (_QWORD *)*pObjectTypeTable;                          // 0x14008A470
    }

    Build = (ULONG)GtRead(GtWindowsBuildNumber);                                 // 0x14008A478
    EnumCount = 7;                                                               // 0x14008A48A
    if (Build != 9200)                                                           // 0x14008A494
        EnumCount = 1;

    EnumProcessObjectTypes(pObjectTypeTable, EnumCount,                           // 0x14008A49B
                           (_OWORD *)OutputBuffer, (int *)pEntryCount, MaxEntries);
}
