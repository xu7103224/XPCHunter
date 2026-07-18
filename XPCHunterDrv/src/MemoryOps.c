// MemoryOps.c — 内存操作
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"
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
__int64 MemoryCompare(__int64 Buf1, char *Buf2, unsigned int Size);
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
    volatile __int32 *v14;

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
                v14 = (volatile __int32 *)&MappedVa[TargetAddress & 0xFFF];
                if (*(_BYTE *)pWriteContext)
                    InterlockedExchange(v14, *(_DWORD *)(pWriteContext + 8));
                else
                    InterlockedExchange64((volatile __int64 *)v14, *(_QWORD *)(pWriteContext + 8));
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
    PMDL Mdl, v7;
    char *MappedSystemVa, *v9;
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
    v7 = Mdl;
    if (!Mdl)
        return Result;

    MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);

    if ((v7->MdlFlags & 5) != 0)
        MappedSystemVa = (char *)v7->MappedSystemVa;
    else
        MappedSystemVa = (char *)MmMapLockedPagesSpecifyCache(v7, KernelMode, MmCached, NULL, FALSE, 0x10);

    if (MappedSystemVa)
    {
        v9 = &MappedSystemVa[(WORD)TargetPtr & 0xFFF];
        CurrentIrql = KeGetCurrentIrql();
        __writecr8(2);
        *ExchangeData = *(_OWORD *)v9;
        *(_OWORD *)v9 = *(_OWORD *)(Source + 16);
        Result = 1;
        __writecr8(CurrentIrql);
    }

    MmUnlockPages(v7);
    IoFreeMdl(v7);
    return Result;
}

// ReadObjectHeaderField — 读取对象头字段
// 对应原始驱动 sub_14006EA50

// ReadObjectHeaderCreateInfo — 读取对象头创建信息
// 对应原始驱动 sub_14006E960
__int64 ReadObjectHeaderCreateInfo(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField05), a2);
}

// ReadObjectHeaderName — 读取对象头名称
// 对应原始驱动 sub_14006E990
__int64 ReadObjectHeaderName(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField06), a2);
}

// ReadObjectHeaderType — 读取对象头类型
// 对应原始驱动 sub_14006E9C0
__int64 ReadObjectHeaderType(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField07), a2);
}

// ReadObjectHeaderQuota — 读取对象头配额
// 对应原始驱动 sub_14006E9F0
__int64 ReadObjectHeaderQuota(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField08), a2);
}

// ReadObjectHeaderHandle — 读取对象头句柄
// 对应原始驱动 sub_14006EA20
__int64 ReadObjectHeaderHandle(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField09), a2);
}

// ReadObjectTypeOffset — 读取对象类型偏移
// 对应原始驱动 sub_14006EAE8
__int64 ReadObjectTypeOffset(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField08), a2);
}

// ReadObjectBodyOffset — 读取对象体偏移
// 对应原始驱动 sub_14006EB18
__int64 ReadObjectBodyOffset(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField10), a2);
}

// ReadWriteVirtualMemory — 读写虚拟内存通用函数
// 对应原始驱动 sub_1400716E0
bool ReadWriteVirtualMemory(__int64 Process, __int64 SrcAddr, __int64 DstAddr, unsigned int Size)
{
    bool Result = 0;
    __int64 (*v6)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *);
    ULONG v7;
    int (__fastcall *v8)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *);
    _QWORD *v9;
    __int64 v10;
    void (__fastcall *v11)(_QWORD);
    struct _KTHREAD *CurrentThread;
    __int64 v13;
    char v14;
    int v15;
    _BYTE v17[8];
    _QWORD v18[8];
    __int64 v19 = SrcAddr;
    __int64 v20 = DstAddr;
    unsigned int v21 = Size;

    v6 = (__int64 (*)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *))GtRead(GtCallbackField07);
    if (!v6) { ResolveModuleBaseAddress(); v6 = (__int64 (*)(_QWORD, __int64 *, __int64 *, __int64, _BYTE *))GtRead(GtCallbackField07); }
    v7 = (ULONG)GtRead(GtSdstServiceCount);
    v8 = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *))GtRead(16735);
    v9 = (_QWORD *)GtRead(16748);
    v10 = GtRead(GtExFreePoolFunc);
    v11 = (void (__fastcall *)(_QWORD))v10;

    if (v7 == (ULONG)-1 || !v8 || !v9 || !v10 || !v6) return Result;

    CurrentThread = KeGetCurrentThread();
    if (v8(Process, 512, 0, 0x10000000, *v9, 0, v18) >= 0)
    {
        v14 = *((UCHAR *)CurrentThread + v7);
        *((UCHAR *)CurrentThread + v7) = 0;
        v15 = v6(v18[0], &v19, &v20, v21, v17);
        *((UCHAR *)CurrentThread + v7) = v14;
        Result = v15 >= 0;
        v11(v18[0]);
    }

    return Result;
}

// CmdVirtualMemoryOp — 虚拟内存操作命令
// 对应原始驱动 sub_1400715C0
__int64 CmdVirtualMemoryOp(_OWORD *Address, int InputSize)
{
    bool Result = 0;
    NTSTATUS v4;
    struct _KPROCESS *v5, *v6;
    PEPROCESS Process = NULL;
    _OWORD v9;
    _OWORD v11;
    __int64 v12;

    if (!Address || InputSize != 40 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 2) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x28, 4);
    v9 = Address[0];
    v11 = Address[1];
    v12 = Address[2].qword[0];

    v4 = PsLookupProcessByProcessId((HANDLE)v9.qword[0], &Process);
    v5 = (struct _KPROCESS *)Process;
    if (v4 < 0) v5 = NULL;
    Process = (PEPROCESS)v5;
    v6 = (struct _KPROCESS *)v9.qword[1];
    if (!v6) { if (v4 >= 0) v6 = v5; }

    if (ValidateProcessObject(v6, NULL) == 1 && v11.qword[1])
        Result = ReadWriteVirtualMemory((__int64)v6, v11.qword[0], v11.qword[1], v12);

    if (Process) ObfDereferenceObject(Process);
    return Result;
}

// SwapKernelMemoryPointer — 交换内核内存指针
// 对应原始驱动 sub_1400759F8
__int64 *SwapKernelMemoryPointer(__int64 *a1)
{
    __int64 *v2 = NULL;
    if (!GtRead(459)) AttachToProcessAndInitKernelMemory();
    ULONG v3 = (ULONG)GtRead(GtEprocessExtField01);
    __int64 v4 = GtRead(16854);
    _QWORD *v5 = (_QWORD *)GtRead(16854);
    if (v3 && v4 && v5)
    {
        __int64 *v6 = (__int64 *)(*v5 + v3 + (ULONG64)(ULONG)ReadObjectTypeOffsetByIndex());
        if (*v6 != v4) { *a1 = *v6; v2 = v6; *v6 = v4; }
    }
    return v2;
}

// CmdReadProcessMemoryEx — 读取进程内存扩展命令
// 对应原始驱动 sub_140071470
__int64 CmdReadProcessMemoryEx(_OWORD *Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    _OWORD v8;
    NTSTATUS v9;
    struct _KPROCESS *v10, *v11;
    PEPROCESS Process = NULL;
    _OWORD v14;

    if (!Address || InputSize != 16 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 1) >= MmUserProbeAddress ||
        !OutputBuffer || BufferSize <= 0x38 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x10, 4);
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    v8 = *Address;
    v14 = v8;
    v9 = PsLookupProcessByProcessId((HANDLE)v8.qword[0], &Process);
    v10 = (struct _KPROCESS *)Process;
    if (v9 < 0) v10 = NULL;
    Process = (PEPROCESS)v10;
    v11 = (struct _KPROCESS *)v8.qword[1];
    if (!v11) { if (v9 >= 0) v11 = v10; v14.qword[1] = (__int64)v11; }
    if (ValidateProcessObject(v11, NULL) == 1)
        Result = QueryProcessMemoryRegions((__int64)v11, OutputBuffer, BufferSize);
    if (Process) ObfDereferenceObject(Process);
    return Result;
}

// QueryKernelMemoryByAddress — 按地址查询内核内存
// 对应原始驱动 sub_14006E930
__int64 QueryKernelMemoryByAddress(PVOID ***VirtualAddress, char a2)
{
    return ReadObjectHeaderField(VirtualAddress, (ULONG)GtRead(GtEprocessExtField04), a2);
}
__int64 ReadObjectHeaderField(PVOID ***VirtualAddress, unsigned int FieldOffset, char DerefFirst)
{
    __int64 Result = 0;
    ULONG BaseOffset = (ULONG)GtRead(GtEprocessExtField01);

    if (!BaseOffset || !VirtualAddress || MmIsAddressValid(VirtualAddress) != 1)
        return Result;
    if (!DerefFirst) VirtualAddress = (PVOID ***)*VirtualAddress;
    if (!VirtualAddress || MmIsAddressValid(VirtualAddress) != 1) return Result;

    char *v8 = (char *)VirtualAddress + BaseOffset + FieldOffset;
    if (MmIsAddressValid(v8) == 1) return *(__int64 *)v8;
    return Result;
}

// AttachToProcessAndInitKernelMemory — 附加到进程并初始化内核内存
// 对应原始驱动 sub_14006E7F8
__int64 AttachToProcessAndInitKernelMemory(void)
{
    struct _KPROCESS *v0 = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    KAPC_STATE ApcState;

    if (IoGetCurrentProcess() == v0) v0 = NULL;
    if (v0) KeStackAttachProcess(v0, &ApcState);
    InitKernelModuleSectionScan();
    if (v0) KeUnstackDetachProcess(&ApcState);
    return GtWrite((GLOBAL_TABLE_INDEX)459, 1);
}

// CmdWriteKernelMemoryRange — 写入内核内存范围
// 对应原始驱动 sub_14006C510
__int64 CmdWriteKernelMemoryRange(void)
{
    char Result = 0;
    ULONG v1;
    _QWORD *v2;
    __int64 *v3;
    __int64 NtHandleEntry;

    if (!GtRead(2000)) InitKernelMemoryContext();
    v1 = (ULONG)GtRead(2000);
    v2 = (_QWORD *)GtRead(1992);

    if (v2 && (ULONG64)v2 > (ULONG64)MmSystemRangeStart && v1 &&
        (v1 & 7) == 0 && *v2 > (ULONG64)MmSystemRangeStart)
    {
        v3 = (__int64 *)(*v2 + v1);
        if (CheckMemoryValid(v3) == 1)
        {
            NtHandleEntry = AllocateNtHandleEntry();
            if (NtHandleEntry)
            {
                *v3 = NtHandleEntry;
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
    int (__fastcall *v9)(ULONG64);

    ULONG BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    GLOBAL_TABLE_INDEX v6 = BuildNum >= 0x585D ? (GLOBAL_TABLE_INDEX)2017 : (GLOBAL_TABLE_INDEX)2015;

    if (!GtRead(v6)) InitKernelMemoryContext();

    BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    GLOBAL_TABLE_INDEX v8 = BuildNum >= 0x585D ? (GLOBAL_TABLE_INDEX)2017 : (GLOBAL_TABLE_INDEX)2015;
    v9 = (int (__fastcall *)(ULONG64))GtRead(v8);

    if (v9 && (char *)v9 > (char *)MmSystemRangeStart &&
        Address && InputSize == 4 &&
        (ULONG64)Address < MmUserProbeAddress &&
        (ULONG64)(Address + 1) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 4, 4);
        return v9(*Address) >= 0;
    }

    return Result;
}

// AtomicWrite16Bytes — 原子写入 16 字节
// 对应原始驱动 sub_140082E14
void AtomicWrite16Bytes(ULONG64 TargetAddress, void *Buffer)
{
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
    if (544 * (int)EntryIndex + 552 > BufferSize) return;

    __int64 *v6 = *(__int64 **)(VadNode + 72);
    if (!v6) return;
    if (MmIsAddressValid(*(PVOID *)(VadNode + 72)) != 1 ||
        MmIsAddressValid((char *)v6 + 55) != 1) return;

    __int64 v7 = *v6;
    if (!v7) return;
    if (MmIsAddressValid((PVOID)v7) != 1 ||
        MmIsAddressValid((PVOID)(v7 + 119)) != 1) return;

    bool v8 = (ULONG)GtRead(GtWindowsBuildNumber) < 0x47BA
        ? (*(_DWORD *)(VadNode + 48) & 0x38) == 56
        : (*(_DWORD *)(VadNode + 48) & 0x380) == 896;

    if ((*(UCHAR *)(v7 + 56) & 0xA0) != 0xA0 || !v8) return;

    WORD *v9 = (WORD *)(*(_QWORD *)(v7 + 64) & 0xFFFFFFFFFFFFFFF0ULL);
    if ((ULONG64)v9 <= (ULONG64)MmSystemRangeStart) return;
    if (MmIsAddressValid(v9) != 1 || MmIsAddressValid((char *)v9 + 183) != 1) return;
    if (*v9 != 5 || ((v9[1] - 184) & 0xFFDF) != 0) return;

    ULONG64 StartAddr = *(ULONG *)(VadNode + 24) + ((ULONG64)*(UCHAR *)(VadNode + 32) << 32);
    ULONG64 EndAddr = *(ULONG *)(VadNode + 28) + ((ULONG64)*(UCHAR *)(VadNode + 33) << 32);
    ULONG v24;
    void *Src[2];
    ULONG v23, v15, v16, v20, v21;

    if (FindThreadEntry(OutputBuffer, StartAddr << 12, &v24, (__int64)v9) == 1)
    {
        if (EndAddr != StartAddr && QueryObjectNameString((ULONG64)v9, Src, &v23) == 1)
        {
            __int64 v13 = EntryIndex;
            __int64 v14 = 136 * EntryIndex;
            LOBYTE_LV(OutputBuffer[v14 + 2]) = 1;
            v15 = v23;
            *(__int64 *)&OutputBuffer[v14 + 8] = (__int64)v9;
            *(__int64 *)&OutputBuffer[v14 + 4] = StartAddr << 12;
            *(__int64 *)&OutputBuffer[v14 + 6] = (EndAddr - StartAddr + 1) << 12;
            if (v15 > 0x1FE) v15 = 510;
            v23 = v15;
            v16 = v15;
            memmove(&OutputBuffer[v14 + 10], Src[0], v15);
            *((WORD *)&OutputBuffer[136 * EntryIndex + 10] + (v16 >> 1)) = 0;
            HIWORD_LV(OutputBuffer[v14 + 137]) = 0;
            *OutputBuffer = (ULONG)(EntryIndex + 1);
            ExFree(Src[0]);
        }
    }
    else if (QueryObjectNameString((ULONG64)v9, Src, &v23) == 1)
    {
        __int64 v18 = 136 * v24;
        HIWORD_LV(OutputBuffer[v18 + 137]) = 0;
        ULONG StringLen = GetStringLength(&OutputBuffer[v18 + 10]);
        if (2 * StringLen != v23 ||
            StringCompare3Way((__int64)&OutputBuffer[v18 + 10], (WORD *)Src[0], v23 >> 1))
        {
            v20 = GetStringLength(&OutputBuffer[v18 + 10]);
            if (v23 > 2 * (ULONG64)v20)
            {
                LOBYTE_LV(OutputBuffer[v18 + 2]) = 1;
                v21 = v23 > 0x1FE ? 510 : v23;
                v23 = v21;
                memmove(&OutputBuffer[v18 + 10], Src[0], v21);
                *((WORD *)&OutputBuffer[136 * (ULONG)v24 + 10] + (v23 >> 1)) = 0;
                HIWORD_LV(OutputBuffer[v18 + 137]) = 0;
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
    UCHAR v10;
    ULONG64 v11;
    WORD *v12, *v15;
    __int64 v13;
    ULONG v14;
    ULONG i, j, k;
    KAPC_STATE ApcState;

    PebOffset = (ULONG)GtRead(GtEprocessField33);
    if ((ULONG)Size < 2 || PebOffset == (ULONG)-1) return Result;

    pPeb = (ULONG64 *)((char *)PROCESS + PebOffset);
    if (MmIsAddressValid(pPeb) != 1) return Result;

    memset(Dst, 0, Size);
    PebAddr = *pPeb;
    v10 = ReferenceObjectSafe((__int64)PROCESS);
    KeStackAttachProcess(PROCESS, &ApcState);

    if (PebAddr && PebAddr < MmUserProbeAddress && PebAddr + 96 < MmUserProbeAddress)
    {
        v11 = *(_QWORD *)(PebAddr + 32);
        if (v11 < MmUserProbeAddress && v11 + 1008 < MmUserProbeAddress)
        {
            v12 = *(WORD **)(v11 + 120);
            v13 = *(WORD *)(v11 + 112);
            if (v12 && (_DWORD)v13 && (ULONG64)v12 < MmUserProbeAddress && (ULONG64)v12 + v13 < MmUserProbeAddress)
            {
                if ((ULONG)v13 > (ULONG)Size) v13 = (ULONG)Size;
                v14 = (ULONG)v13 >> 1;
                if (v14)
                {
                    v15 = NULL;
                    if (*v12 == L'"')
                    {
                        for (i = 1; i < v14; i++)
                        {
                            if (v12[i] == L'"') { v15 = &v12[i + 1]; v14 += -1 - i; break; }
                        }
                    }
                    if (!v15) v15 = v12;

                    // Strip leading spaces
                    for (j = 0; j < v14; j++)
                    {
                        if (v15[j] == L' ') { v15 = &v15[j + 1]; v14 += -1 - j; if (j < v14) goto CheckPath; break; }
                    }

CheckPath:
                    if (v14 && *v15 == L'\\') v14 = 0;
                    if (v14 > 3 && v15[1] == L':' && v15[2] == L'\\') v14 = 0;

                    for (k = 1; k < v14; k++) { if (v15[k] == L'.') goto CopyPath; }
CopyPath:
                    if (v14) memmove(Dst, v15, 2 * v14);
                    Result = 1;
                }
            }
        }
    }

    KeUnstackDetachProcess(&ApcState);
    if (v10 == 1) DereferenceObjectSafe((__int64)PROCESS);

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

    IsWin32k = CheckProtectedEntry(*InputParams);
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
        DiskSectorsWithAlloc = ReadDiskSectorsWithAlloc((__int64)&ApcState);
        DiskReadDone = DiskSectorsWithAlloc;
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
                        MappedVa = MapMemoryFunc(MappedPage, 0, 1, 0, Flags, 16);
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
    Field23 = GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    ServiceEntryCount = GtRead(GtWin32kServiceEntryCount);
    CallbackField06 = GtRead(GtCallbackField06);
    if (Field22 && Field23 && NtoskrnlBase && (_DWORD)CallbackField06)
    {
        if ((unsigned int)CallbackField06 < ServiceEntryCount)
        {
            CallbackField06 = ResolveSyscallToAddress(CallbackField06);
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
    __int64 v20;
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
            if (DuplicateObjectFunc(ProcessId, 512, 0, 0x10000000, *NtQueryVirtualMemoryFunc, Success, &v20) >= 0)
            {
                SavedPreviousMode = *((_BYTE *)CurrentThread + CurrentAddress);
                *((_BYTE *)CurrentThread + CurrentAddress) = 0;
                CurrentAddress = 0;
                OutOffset = 56;
                memset(VadEntryInfo, 0, sizeof(VadEntryInfo));
                while (CurrentAddress < MmUserProbeAddress &&
                       QueryVirtualMemoryFunc(v20, CurrentAddress, 0, VadEntryInfo, 48, (_BYTE *)VadEntryInfo3 + 8) >= 0)
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
                CloseHandleFunc(v20);
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
unsigned __int64 GetKernelVirtualAddressRange(__int64 a1, unsigned __int64 *pStartAddress, unsigned __int64 *pEndAddress)
{
    unsigned __int64 result;
    unsigned __int64 *v7;
    unsigned __int64 *v8;
    unsigned __int64 v9;
    unsigned __int64 v10;
    unsigned __int64 v11;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        v7 = (unsigned __int64 *)GtRead(GtNtCreateThreadResultAddr);
        v8 = (unsigned __int64 *)GtRead(GtNtCreateProcessResultAddr);
        if (v7 && v8 && (v9 = *v8, v10 = *v7, *v7 > (unsigned __int64)MmSystemRangeStart) && v9 > (unsigned __int64)MmSystemRangeStart && v9 > v10)
        {
            *pStartAddress = v10;
            *pEndAddress = v9;
            result = *pStartAddress + 0x10000000;
            if (v9 <= result)
                return result;
        }
        else if (a1 || (a1 = GtRead(GtDriverObject)) != 0)
        {
            v11 = a1 & 0xFFFFFFFF00000000ULL;
            result = v11 + 0x100000000LL;
            *pStartAddress = v11;
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
    __int16 v1 = (__int16)GtRead(GtEprocessField86);
    __int64 (__fastcall *pQueryFunc)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *) = (__int64 (__fastcall *)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtEprocessField54);
    _QWORD *pBuffer = (_QWORD *)GtRead(GtEprocessField58 | 0x100);
    __int64 (__fastcall *pFreeFunc)(__int64) = (__int64 (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    unsigned int v5 = 0;
    __int64 (__fastcall *result)(__int64) = pFreeFunc;

    if (pQueryFunc && pBuffer && pFreeFunc)
    {
        char v12 = 0;
        __int64 v13;
        result = (__int64 (__fastcall *)(__int64))pQueryFunc(CurrentProcess, 512, 0, 0x80000000LL, *pBuffer, v12, &v13);
        if ((int)result >= 0)
        {
            __int16 *SystemInfo = (__int16 *)AllocExBufferAndQuerySystemInfo(0x10u);
            if (SystemInfo)
            {
                unsigned int v9 = *(_DWORD *)SystemInfo;
                if (v9)
                {
                    __int16 *v10 = SystemInfo + 4;
                    while (v10[3] != (_WORD)v13 || !CompareInt16Equal(*v10, v1))
                    {
                        ++v5;
                        v10 += 12;
                        if (v5 >= v9)
                            goto LABEL_13;
                    }
                    unsigned int v11 = LOBYTE_LV(SystemInfo[12 * v5 + 6]);
                    GtWrite(GtEprocessField61, 1);
                    GtWrite(GtEprocessField62, v11);
                }
LABEL_13:
                ExFree(SystemInfo);
            }
            return (__int64 (__fastcall *)(__int64))pFreeFunc(v13);
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
__int64 ReadDiskSectorsWithAlloc(__int64 a1)
{
    char v2 = 0;
    void (__fastcall *pCreateFunc)(__int64, __int64) = (void (__fastcall *)(__int64, __int64))GtRead(GtCreateObjectTypeFunc);
    __int64 v4 = GtRead(GtCloseObjectTypeFunc);
    int (__fastcall *pValidateFunc)(_QWORD, __int64 *) = (int (__fastcall *)(_QWORD, __int64 *))GtRead(GtValidateObjectTypeFunc);
    __int64 v6 = GtRead(GtCloseHandleFunc);
    void (__fastcall *pCloseFunc)(__int64) = (void (__fastcall *)(__int64))v6;

    if (pCreateFunc && v4 && pValidateFunc && pCloseFunc)
    {
        unsigned int v8 = GtRead(GtCallbackField52);
        if (!v8)
        {
            unsigned int DiskSectors = ReadDiskSectors();
            v8 = DiskSectors;
            if (!DiskSectors)
                return v2;
            GtWrite(GtCallbackField52, DiskSectors);
        }
        __int64 v11;
        if (pValidateFunc(v8, &v11) >= 0)
        {
            pCreateFunc(v11, a1);
            v2 = 1;
            pCloseFunc(v11);
        }
    }
    return v2;
}

// ReleaseDiskBuffer — 释放磁盘缓冲区
// 对应原始驱动 sub_14007ABA4
__int64 ReleaseDiskBuffer(__int64 a1)
{
    char v2 = 0;
    void (__fastcall *pCloseFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtCloseObjectTypeFunc);
    if (pCloseFunc)
    {
        pCloseFunc(a1);
        return 1;
    }
    return v2;
}

// ResolveModuleEnumBase — 解析模块枚举基址
// 对应原始驱动 sub_140057924
// 从全局表读取 ntoskrnl 映射基址和大小，通过系统调用号解析模块枚举函数的地址
__int64 ResolveModuleEnumBase(void)
{
    __int64 v0 = GtRead(GtEprocessField22);
    unsigned int v1 = GtRead(GtEprocessField23);
    __int64 v2 = GtRead(GtNtoskrnlModuleBase);
    unsigned int v3 = GtRead(GtKernelDataField01);
    __int64 result = GtRead(GtWin32kServiceEntryCount);

    if (v0 && v1 && v2 && v3 && v3 < (unsigned int)result)
    {
        result = ResolveSyscallToAddress(v3);
        if ((_DWORD)result && (unsigned int)result < v1)
        {
            __int64 v5 = (unsigned int)result;
            GtWrite(GtKernelDataField02, (unsigned int)result);
            return GtWrite(GtKernelDataField03, v5 + v2);
        }
    }
    return result;
}

// ResolveSyscallToAddress — 通过系统调用号解析地址
// 对应原始驱动 sub_14007A5F8
// 在系统调用号表中查找对应的函数地址偏移
__int64 ResolveSyscallToAddress(unsigned int SyscallNumber)
{
    __int64 v1 = SyscallNumber;
    unsigned int v2 = 0;
    unsigned int v3 = GtRead(GtWin32kServiceEntryCount);
    __int64 v4 = GtRead(GtEprocessField24);
    unsigned int v5 = GtRead(GtEprocessField23);
    unsigned int v6 = v5;

    if (v3 && (_DWORD)v1 && (unsigned int)v1 < v3 && v4 && v5)
    {
        __int64 v7 = GtRead(GtEprocessField88);
        if (v7 || (ResolveSyscallNumbers(), (v7 = GtRead(GtEprocessField88)) != 0))
        {
            unsigned __int64 v8 = *(_QWORD *)(v7 + 8 * v1);
            unsigned __int64 v9 = *(_QWORD *)(v4 + 48);
            if (v8 > v9 && (int)v8 - (int)v9 < v6 && v8 == v9 + (unsigned int)(v8 - v9))
                return (unsigned int)(v8 - v9);
        }
    }
    return v2;
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
    BuildNumber = GtRead(GtNtBuildNumber);

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
    unsigned int KernelImageSize = GtRead(GtEprocessField23);
    unsigned __int64 KernelImageBase = GtRead(GtEprocessField22);
    unsigned int ServiceCount = GtRead(GtWin32kServiceEntryCount);

    if (!KernelImageBase || !KernelImageSize)
        return 0;

    // 查找 PE 节区
    unsigned int SectionType1 = FindKernelPESectionByType(0x41D1);
    unsigned int SectionType2 = FindKernelPESectionByType(0x41D4);

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

    if (LookupExportByName(KernelImageBase, KernelImageSize, Name1, &AdjustPrivAddr) != 1)
        return 0;
    if (LookupExportByName(KernelImageBase, KernelImageSize, Name2, &AllocVirAddr) != 1)
        return 0;

    // 确保两个地址不重叠 — 如果 SectionType2 比 SectionType1 小，交换
    unsigned int StartSection = SectionType1;
    unsigned int EndSection = SectionType2;
    unsigned int StartAddr = AdjustPrivAddr + ExportDirRva;
    unsigned int EndAddr = AllocVirAddr + ExportDirRva;

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
    unsigned int RdataOffset = FindPESectionByName(KernelImageBase, KernelImageSize, SectionName);
    unsigned int RdataVa = FindPESectionByNameReturnVa(KernelImageBase, KernelImageSize, SectionName);

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
    unsigned int ServiceCount = GtRead(GtWin32kServiceEntryCount);
    unsigned __int64 KernelImageBase = GtRead(GtEprocessField22);
    unsigned int KernelImageSize = GtRead(GtEprocessField23);

    if (!KernelImageBase || !KernelImageSize)
        return 0;

    unsigned int SectionType1 = FindKernelPESectionByType(0x41D1);
    unsigned int SectionType2 = FindKernelPESectionByType(0x41D2);

    if (!SectionType1 || SectionType1 >= ServiceCount || !SectionType2 || SectionType2 >= ServiceCount)
        return 0;

    __int64 ExportDirRva = *(_QWORD *)(*(int *)(KernelImageBase + 60) + KernelImageBase + 0x48);

    char Name1[] = "NtAdjustPrivilegesToken";
    char Name2[] = "NtAllocateVirtualMemory";

    unsigned int AdjustPrivAddr = 0;
    unsigned int AllocVirAddr = 0;

    if (LookupExportByName(KernelImageBase, KernelImageSize, Name1, &AdjustPrivAddr) != 1)
        return 0;
    if (LookupExportByName(KernelImageBase, KernelImageSize, Name2, &AllocVirAddr) != 1)
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
    unsigned int RdataOffset = FindPESectionByName(KernelImageBase, KernelImageSize, SectionName);
    unsigned int RdataVa = FindPESectionByNameReturnVa(KernelImageBase, KernelImageSize, SectionName);

    if (!RdataOffset || RdataOffset >= KernelImageSize || !RdataVa || RdataVa >= KernelImageSize)
        return 0;

    if (RdataVa + RdataOffset > KernelImageSize)
        return 0;

    // 在 .rdata 中搜索匹配的导出地址
    unsigned int *RdataBase = (unsigned int *)(KernelImageBase + RdataOffset);
    unsigned __int64 RdataEnd = KernelImageBase + RdataOffset + RdataVa;

    unsigned int *ScanPtr = RdataBase;
    unsigned int AdjustWithBase = AdjustPrivAddr + ExportDirRva;
    unsigned int AllocWithBase = AllocVirAddr + ExportDirRva;

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
        Offset1 = GtRead(GtEprocessField94);
    }
    else
    {
        Offset1 = GtRead((GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr1 | GtEprocessField86));
        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 7601) Mask = 0x2000;
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200) Mask = 4096;
        else
        {
            Mask = 1024;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600) Mask = 2048;
        }
    }
    Offset2 = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 64 : 32;
    FlagOffset = GtRead(GtEprocessField53);
    FieldOffset = GtRead(GtEprocessField94);
    TypeOffset = GtRead(GtEprocessField95);
    ObjTypeCount = GtRead(GtObjectTypeCount);
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
        PteOffset = GtRead(GtEprocessField94);
    }
    else
    {
        PteOffset = GtRead((GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr1 | GtEprocessField86));
        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 7601) FlagMask = 0x2000;
        else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200) FlagMask = 4096;
        else
        {
            FlagMask = 1024;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600) FlagMask = 2048;
        }
    }
    PageSize = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0 ? 64 : 32;
    PdeOffset = GtRead(GtEprocessField41);
    PteOffset2 = GtRead(GtEprocessField48);
    PdeOffset2 = GtRead(GtEprocessField94);
    TableOffset = GtRead(GtEprocessField53);
    TableOffset2 = GtRead(GtEprocessField95);
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
                        if (pCurrentEntry == pTableEntry)
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
                    while (pCurrentEntry > MmSystemRangeStart);
                }
            }
            if (RefCount == 1)
                DereferenceObjectSafe((__int64)Process);
        }
    }
}