// Registry.c — 注册表保护
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"
#pragma warning(disable:4700)

// InitRegCallback — 初始化注册表回调
// 对应原始驱动 sub_14000A094
char InitRegCallback(void *OutputBuffer, int OutputSize, volatile void *UserBuffer, unsigned int UserBufferSize)
{
    int RefCount;

    RefCount = (int)GtRead(GtWin32kServiceTableVersion);
    GtWrite(GtWin32kServiceTableVersion, RefCount + 1);

    if (OutputSize != 552 || UserBufferSize < 0x218)
        return 0;

    if ((ULONG64)OutputBuffer >= MmUserProbeAddress || (ULONG64)OutputBuffer + 552 >= MmUserProbeAddress)
        return 0;

    if (!UserBuffer)
        return 0;

    if ((ULONG64)UserBuffer >= MmUserProbeAddress || (ULONG64)UserBuffer + UserBufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, 0x228, 1);
    ProbeForWrite(UserBuffer, UserBufferSize, 1);
    memset((void *)UserBuffer, 0, UserBufferSize);
    *((WORD *)OutputBuffer + 275) = 0;

    if (FindRegCallbackEntry((__int64)OutputBuffer) == 1)
    {
        if (UserBufferSize >= 0x98C)
            ParseNtKernelFile((__int64)OutputBuffer, (__int64)UserBuffer, UserBufferSize);
        FindExportEntryByName((char *)OutputBuffer);
        return 1;
    }

    return 0;
}

// FindRegCallbackEntry — 查找注册表回调条目
// 对应原始驱动 sub_14000A1A4
char FindRegCallbackEntry(__int64 RegEntry)
{
    _DWORD *CallbackList, *CallbackListPtr;
    ULONG EntryCount, EntryIndex;

    CallbackList = (_DWORD *)GtRead(GtModuleBuffer);
    if (!CallbackList)
        return 0;

    CallbackListPtr = CallbackList;
    EntryCount = *CallbackList;
    if (!EntryCount)
        return 0;

    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        _DWORD *Entry = CallbackListPtr + 138 * EntryIndex;
        if (*((__int64 *)Entry - 1) == *(__int64 *)(RegEntry + 24) &&
            *Entry == *(ULONG *)(RegEntry + 32) &&
            WStringCompare((__int64)(Entry + 11), (WORD *)(RegEntry + 36), 0x100) == 0)
            return 1;
    }

    return 0;
}

// InitRegNotify — 初始化注册表通知
// 对应原始驱动 sub_14000C1E0
char InitRegNotify(void)
{
    void *CallbackBuffer;
    ULONG EntryIndex;
    _QWORD *ListAllocation;

    CallbackBuffer = (void *)GtRead(GtModuleBuffer);
    if (CallbackBuffer)
    {
        ExFree(CallbackBuffer);
        GtWrite(GtModuleBuffer, 0);
    }

    GtWrite(GtWin32kServiceTableVersion, 0);

    ListAllocation = (_QWORD *)GtRead(0x415F);
    if (ListAllocation)
    {
        FreeListAllocation(ListAllocation);
        GtWrite(0x415F, 0);
    }

    for (EntryIndex = 0; EntryIndex < 0x100; EntryIndex++)
        GtWrite((GLOBAL_TABLE_INDEX)(EntryIndex + 109), 0);

    GtWrite(GtCallbackInitialized, 0);
    return 1;
}

// InitRegFilter — 初始化注册表过滤器
// 对应原始驱动 sub_14000C738
// 分配驱动对象缓冲区，枚举驱动对象，初始化注册表通知
char InitRegFilter(__int64 DeviceObject, __int64 Irp, _OWORD *OutputBuffer, int OutputSize)
{
    unsigned int Result;
    void *DriverObjectBuffer;
    void *TempBuffer;
    _OWORD *SourceDataPtr;
    __int64 QuadCount;

    Result = 0;
    DriverObjectBuffer = NULL;

    if (OutputSize != 552 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + 552 >= MmUserProbeAddress)
        return Result;

    if (!GtRead(GtCallbackInitialized))
    {
        InitRegNotify();
        GtWrite(GtCallbackInitialized, 1);

        TempBuffer = ExAlloc(PagedPool, 0x28910);
        DriverObjectBuffer = TempBuffer;
        if (TempBuffer)
        {
            memset(TempBuffer, 0, 0x28910);
            if (CmdEnumDriverObjects((unsigned int *)DriverObjectBuffer, 0x28910, 1, 0) == 1)
            {
                GtWrite(GtModuleBuffer, (__int64)DriverObjectBuffer);
                ((void (*)(void *))0x14000D2B8)(DriverObjectBuffer); // CPullPin::Process

                ULONG Index;
                for (Index = 0; Index < 0x100; Index++)
                    GtWrite((GLOBAL_TABLE_INDEX)(Index + 109), 0);
                Result = 1;
            }
            else
                ExFree(DriverObjectBuffer);
        }
    }

    if (Result == 1)
    {
        ProbeForWrite(OutputBuffer, 0x228, 2);
        SourceDataPtr = (_OWORD *)((char *)DriverObjectBuffer + 8);
        QuadCount = 4;
        do
        {
            *OutputBuffer = *SourceDataPtr;
            OutputBuffer[1] = SourceDataPtr[1];
            OutputBuffer[2] = SourceDataPtr[2];
            OutputBuffer[3] = SourceDataPtr[3];
            OutputBuffer[4] = SourceDataPtr[4];
            OutputBuffer[5] = SourceDataPtr[5];
            OutputBuffer[6] = SourceDataPtr[6];
            OutputBuffer += 8;
            *(OutputBuffer - 1) = SourceDataPtr[7];
            SourceDataPtr += 8;
            QuadCount--;
        } while (QuadCount);
        *OutputBuffer = *SourceDataPtr;
        OutputBuffer[1] = SourceDataPtr[1];
        *((__int64 *)OutputBuffer + 4) = *((__int64 *)SourceDataPtr + 4);
    }

    return Result;
}

// RegNotifyCallback — 向目标地址写入数据（补全空壳）
// 对应原始驱动 0x14000D0B0（518 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（84 行伪代码），按伪代码实现
// 【⚠ 修正记录】此前是空壳（`return STATUS_SUCCESS;` —— 把失败伪装成成功），
//   且名字与功能不符：本函数**不是注册表通知回调**，而是"**向指定内核地址
//   写数据**"的处理器（签名实为 `char f(void *Address, int InputSize)`）。
// 【逻辑】
//   1) 要求 InputSize == 24，且 Address 位于用户空间（含边界校验）
//   2) ProbeForRead(24 字节)；要求 Address[0]（目标地址）> MmSystemRangeStart，
//      Address[1]（大小）非 0 且 < MmUserProbeAddress，Address[2]（数据指针）合法
//   3) ProbeForRead 数据 → ExAlloc(NonPagedPool, 大小) → 把数据拷入内核缓冲
//   4) 按目标地址是否在系统模块范围二选一建立访问上下文：
//      - 是：ReadDiskSectorsWithAlloc(&ApcState)（磁盘分区路径）
//      - 否：取 GT 当前进程 → KeStackAttachProcess（若非本进程）
//   5) 校验目标地址与末字节有效后，用 WritePhysicalMemoryBuffer 写入
//   6) 按上述分支释放（ReleaseDiskBuffer / KeUnstackDetachProcess）→ ExFree
char RegNotifyCallback(void *Address, int InputSize)
{
    unsigned int DataSize;
    PVOID UserDataPtr;
    PVOID AllocBuffer;
    struct _KPROCESS *TargetProcess;
    char Result = 0;
    char DiskSectorsAllocated;
    char IsSystemModule;
    unsigned int CopySize;
    char *TargetAddress;
    struct _KPROCESS *AttachedProcess = 0;
    void *Buffer;
    KAPC_STATE ApcState;

    if (InputSize == 24)
    {
        __int64 *Addr = (__int64 *)Address;
        if (Addr && (unsigned __int64)Addr < MmUserProbeAddress &&
            (unsigned __int64)(Addr + 3) < MmUserProbeAddress)
        {
            ProbeForRead(Addr, 0x18u, 4u);
            if ((unsigned __int64)*Addr > (unsigned __int64)MmSystemRangeStart)
            {
                DataSize = *((_DWORD *)Addr + 2);
                if (DataSize && DataSize < (unsigned int)MmUserProbeAddress)
                {
                    UserDataPtr = (PVOID)Addr[2];
                    if (UserDataPtr && (unsigned __int64)UserDataPtr < MmUserProbeAddress &&
                        (unsigned __int64)UserDataPtr + DataSize < MmUserProbeAddress)
                    {
                        ProbeForRead(UserDataPtr, DataSize, 1u);
                        AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)Addr + 2));
                        Buffer = AllocBuffer;
                        if (AllocBuffer)
                        {
                            memmove(AllocBuffer, (PVOID)Addr[2], *((unsigned int *)Addr + 2));
                            TargetAddress = (char *)*Addr;
                            CopySize = *((_DWORD *)Addr + 2);
                            IsSystemModule = CheckAddressInSystemModuleRange((unsigned __int64)*Addr);
                            DiskSectorsAllocated = 0;

                            if (IsSystemModule)
                            {
                                DiskSectorsAllocated = (char)ReadDiskSectorsWithAlloc((__int64)&ApcState);
                            }
                            else
                            {
                                TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
                                if (IoGetCurrentProcess() == TargetProcess)
                                    TargetProcess = 0;
                                AttachedProcess = TargetProcess;
                                if (TargetProcess)
                                    KeStackAttachProcess(TargetProcess, &ApcState);
                            }

                            if (MmIsAddressValid(TargetAddress) == 1 &&
                                MmIsAddressValid(&TargetAddress[CopySize - 1]) == 1)
                                Result = WritePhysicalMemoryBuffer((unsigned __int64)TargetAddress,
                                                                   Buffer, CopySize, 0, 0);

                            if (IsSystemModule)
                            {
                                if (DiskSectorsAllocated == 1)
                                    ReleaseDiskBuffer((__int64)&ApcState);
                            }
                            else if (AttachedProcess)
                            {
                                KeUnstackDetachProcess(&ApcState);
                            }
                            ExFree(Buffer);
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// RegisterMiniFilterRegistry — 注册 Minifilter 注册表项
// 对应原始驱动 sub_140018F4C
// 在驱动注册表路径下创建 Instances 和 Instances\1 子键，设置 Altitude=315000、Flags=0 等标准 minifilter 注册表配置
void RegisterMiniFilterRegistry(void)
{
    const WCHAR *RegPath;
    WCHAR *RegPathBuffer;
    unsigned int StringLength;
    unsigned int PathLength;
    WCHAR *AllocBuffer;
    WCHAR *InstancePath;
    struct _UNICODE_STRING DestinationString;
    struct _OBJECT_ATTRIBUTES ObjectAttributes;
    int Data;
    void *KeyHandle;
    HANDLE Handle;

    RegPath = (const WCHAR *)GtRead(GtRegPathStringPtr);
    RegPathBuffer = (WCHAR *)RegPath;
    if (RegPath)
    {
        RtlInitUnicodeString(&DestinationString, RegPath);
        // 原始驱动以 16 字节清零 SecurityDescriptor + SecurityQualityOfService，此处逐字段等价展开
        ObjectAttributes.SecurityDescriptor = NULL;
        ObjectAttributes.SecurityQualityOfService = NULL;
        ObjectAttributes.ObjectName = &DestinationString;
        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0;
        ObjectAttributes.Attributes = 576;
        if (ZwCreateKey(&KeyHandle, 0xF003F, &ObjectAttributes, 0, 0, 0, 0) >= 0)
            ZwClose(KeyHandle);
        StringLength = (unsigned int)GetStringLength((_WORD *)RegPathBuffer);
        if (StringLength)
        {
            if (StringLength + 200 >= StringLength)
            {
                PathLength = 2 * StringLength;
                if (2 * StringLength > StringLength)
                {
                    AllocBuffer = (WCHAR *)ExAlloc(PagedPool, PathLength + 200);
                    InstancePath = AllocBuffer;
                    if (AllocBuffer)
                    {
                        memmove(AllocBuffer, RegPathBuffer, PathLength);
                        WStringCopy((__int16 *)&InstancePath[(unsigned __int64)PathLength >> 1], L"\\Instances");
                        RtlInitUnicodeString(&DestinationString, InstancePath);
                        ObjectAttributes.SecurityDescriptor = NULL;
                        ObjectAttributes.SecurityQualityOfService = NULL;
                        ObjectAttributes.ObjectName = &DestinationString;
                        ObjectAttributes.Length = 48;
                        ObjectAttributes.RootDirectory = 0;
                        ObjectAttributes.Attributes = 576;
                        if (ZwCreateKey(&KeyHandle, 0xF003F, &ObjectAttributes, 0, 0, 0, 0) >= 0)
                        {
                            RtlInitUnicodeString(&DestinationString, L"DefaultInstance");
                            if (ZwSetValueKey(KeyHandle, &DestinationString, 0, 1, L"1", 4) >= 0)
                            {
                                memmove(InstancePath, RegPathBuffer, PathLength);
                                WStringCopy((__int16 *)&InstancePath[(unsigned __int64)PathLength >> 1], L"\\Instances\\1");
                                RtlInitUnicodeString(&DestinationString, InstancePath);
                                ObjectAttributes.SecurityDescriptor = NULL;
                                ObjectAttributes.SecurityQualityOfService = NULL;
                                ObjectAttributes.ObjectName = &DestinationString;
                                ObjectAttributes.Length = 48;
                                ObjectAttributes.RootDirectory = 0;
                                ObjectAttributes.Attributes = 576;
                                if (ZwCreateKey(&Handle, 0xF003F, &ObjectAttributes, 0, 0, 0, 0) >= 0)
                                {
                                    RtlInitUnicodeString(&DestinationString, L"Altitude");
                                    ZwSetValueKey(Handle, &DestinationString, 0, 1, L"315000", 14);
                                    RtlInitUnicodeString(&DestinationString, L"Flags");
                                    Data = 0;
                                    ZwSetValueKey(Handle, &DestinationString, 0, 4, &Data, 4);
                                    ZwClose(Handle);
                                }
                            }
                            ZwClose(KeyHandle);
                        }
                        ExFree(InstancePath);
                    }
                }
            }
        }
    }
}

// InitRegistryCallback — 初始化注册表回调
// 对应原始驱动 sub_140010BF8
// 从输入缓冲区读取值，根据大小（2或4字节）存入输出缓冲区
ULONG64 InitRegistryCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *StateFlags, UCHAR *OutputBuffer)
{
    int CurrentOffset;
    ULONG *ValuePtr;
    __int64 ValueSize;
    ULONG64 Result;

    CurrentOffset = StateFlags[4];
    ValuePtr = (ULONG *)((ULONG)(StateFlags[1] + StateFlags[2] + StateFlags[3] + CurrentOffset + 1) + InputBuffer);
    StateFlags[4] = CurrentOffset + *OutputBuffer;
    ValueSize = *OutputBuffer;
    Result = (ULONG64)ValuePtr + ValueSize - 1;

    if (Result >= BufferSize)
    {
        *StateFlags |= 2;
        return Result;
    }

    Result = (ULONG)StateFlags[5];
    if (Result)
    {
        if (Result == 1)
        {
            if (*(UCHAR *)&ValueSize == 4)
                Result = *ValuePtr;
            else if (*(UCHAR *)&ValueSize == 2)
                Result = (ULONG)*(short *)ValuePtr;
            else
                goto Done;
            *((ULONG *)OutputBuffer + 5) = (ULONG)Result;
        }
    }
    else
    {
        if (*(UCHAR *)&ValueSize == 4)
        {
            Result = *ValuePtr;
            goto StoreResult;
        }
        if (*(UCHAR *)&ValueSize == 2)
            Result = (ULONG)*(short *)ValuePtr;
        else
            goto Done;

StoreResult:
        *((ULONG *)OutputBuffer + 4) = (ULONG)Result;
    }

Done:
    ++StateFlags[5];
    return Result;
}

// RegistryCallbackRoutine — 注册表回调例程
// 对应原始驱动 sub_140010C74
// 解析注册表回调数据，提取 16 位值到输出缓冲区偏移 16 或 20 处
ULONG64 RegistryCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, ULONG64 OutputBuffer)
{
    ULONG CurrentOffset;
    ULONG64 DataOffset;
    ULONG64 Result;

    CurrentOffset = StateFlags[4];
    DataOffset = (ULONG)(StateFlags[1] + StateFlags[2] + StateFlags[3] + CurrentOffset + 1);
    StateFlags[4] = CurrentOffset + 2;
    Result = DataOffset + InputBuffer + 1;

    if (Result >= BufferSize)
    {
        *StateFlags |= 2;
    }
    else
    {
        Result = StateFlags[5];
        if (Result == 0)
        {
            Result = (ULONG)*(SHORT *)(InputBuffer + DataOffset);
            *(PULONG)(OutputBuffer + 16) = (ULONG)Result;
        }
        else if (Result == 1)
        {
            Result = (ULONG)*(SHORT *)(InputBuffer + DataOffset);
            *(PULONG)(OutputBuffer + 20) = (ULONG)Result;
        }
        StateFlags[5]++;
    }

    return Result;
}

// FreeListAllocation — 释放链表分配
// 对应原始驱动 sub_1400575A0
// 遍历链表依次释放每个节点，直到链表为空
void FreeListAllocation(_QWORD *Allocation)
{
    _QWORD *CurrentEntry;

    if (Allocation)
    {
        do
        {
            CurrentEntry = (_QWORD *)Allocation[4];
            ExFree(Allocation);
            Allocation = CurrentEntry;
        } while (CurrentEntry);
    }
}

// CmdEnumDriverObjects — 枚举驱动对象命令处理函数
// 对应原始驱动 sub_14003A6E8
// 依次调用多个子枚举函数收集驱动列表、驱动对象、对象类型等信息
char CmdEnumDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize, char Flags, char Flags2)
{
    char Success;

    Success = 0;
    if (OutputSize > 0x230)
    {
        *pOutputBuffer = 0;
        EnumerateDriverList(pOutputBuffer, OutputSize);
        EnumerateDriverObjects(pOutputBuffer, OutputSize);
        EnumObjectTypeList(pOutputBuffer, OutputSize);
        EnumerateDriverObjectsEx(pOutputBuffer, OutputSize);
        EnumerateDriverObjectsFull(pOutputBuffer, OutputSize);
        if (!Flags && Flags2 == 1)
            EnumerateKernelModules(pOutputBuffer, OutputSize);
        if (*pOutputBuffer)
        {
            EnumerateDriverFiles(pOutputBuffer);
            return 1;
        }
    }
    return Success;
}

// ===== 注册表操作函数（从 MissingFuncs.c 移入） =====

// GetDeleteValueKeyCtx — 获取 DeleteValueKey 上下文
// 对应原始驱动 sub_14001DB00（63 字节）
__int64 GetDeleteValueKeyCtx(_QWORD *pContext)
{
    char *CurrentFiber;
    __int64 Offset;
    CurrentFiber = (char *)j_GetCurrentFiber();
    *pContext = 0;
    Offset = GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField130 | 0x100));
    if ((_DWORD)Offset && CurrentFiber) *pContext = (_QWORD)&CurrentFiber[(unsigned int)Offset];
    return Offset;
}

// GetSetValueKeyCtx — 获取 SetValueKey 上下文
// 对应原始驱动 sub_14001DEA4（80 字节）
__int64 GetSetValueKeyCtx(_QWORD *pContext, _QWORD *pResult)
{
    char *FiberBase;
    char *FiberBaseCopy;
    __int64 ContextOffset;

    FiberBase = (char *)j_GetCurrentFiber();
    *pContext = 0;
    *pResult = 0;
    FiberBaseCopy = FiberBase;
    ContextOffset = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField129 | 0x100));
    if ((_DWORD)ContextOffset && FiberBaseCopy)
        *pContext = (_QWORD)&FiberBaseCopy[(unsigned int)ContextOffset];
    return ContextOffset;
}

// FindDeleteValueKeyTarget — 查找 NtDeleteValueKey 的 Hook 目标
__int64 FindDeleteValueKeyTarget(__int64 Buffer, unsigned int BufferSize, __int64 Context, __int64 TargetBase, unsigned int TargetSize, __int64 *pResult)
{
    *pResult = 0;
    __int64 Offset = GtRead((GLOBAL_TABLE_INDEX)(GtNtWriteFilePeSectionOffset | GtEprocessField08));
    if ((_DWORD)Offset && (unsigned int)Offset < BufferSize && (unsigned int)((int)Offset + 4106) < BufferSize)
    {
        unsigned __int64 ScanPos = Buffer + (unsigned int)Offset;
        unsigned __int64 EndAddress = Buffer + BufferSize;
        unsigned __int64 ScanEnd = ScanPos + 4096;
        while (ScanPos < ScanEnd)
        {
            unsigned int Decoded = (unsigned int)DecodeUtf8Buffer((unsigned __int8 *)ScanPos, EndAddress);
            if (!Decoded)
                break;
            if (Decoded == 7 && (*(_DWORD *)ScanPos & 0xFFFFFF) == 0xCD048D && *(_BYTE *)(ScanPos + 7) == 57)
            {
                unsigned __int64 Delta = *(unsigned int *)(ScanPos + 3);
                if (Delta > *(_QWORD *)(Context + 48))
                {
                    unsigned int ResultOffset = (unsigned int)(Delta - *(_DWORD *)(Context + 48));
                    if (ResultOffset < TargetSize)
                        *pResult = TargetBase + ResultOffset;
                }
                return Decoded;
            }
            ScanPos += Decoded;
        }
    }
    return 0;
}

// FindSetValueKeyTargets — 查找 NtSetValueKey 的 Hook 目标（主方案）
__int64 FindSetValueKeyTargets(
    __int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    _QWORD *pResult1,
    __int64 *pResult2)
{
    __int64 ImageSize;
    __int64 result;
    unsigned __int64 ScanPos;
    unsigned __int64 EndAddress;
    unsigned __int64 ScanEnd;
    unsigned __int64 Delta1;
    unsigned __int64 BaseValue;
    unsigned __int64 Delta2;
    unsigned int ResultOffset1;
    unsigned int ResultOffset2;

    *pResult1 = 0;
    *pResult2 = 0;
    ImageSize = BufferSize;
    result = GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField142 | 0x100));
    if ((_DWORD)result && (unsigned int)result < (unsigned int)ImageSize && (unsigned int)((int)result + 4126) < (unsigned int)ImageSize)
    {
        ScanPos = Buffer + (unsigned int)result;
        EndAddress = Buffer + ImageSize;
        ScanEnd = ScanPos + 4096;
        while (ScanPos < ScanEnd)
        {
            result = DecodeUtf8Buffer((unsigned __int8 *)ScanPos, EndAddress);
            if (!(_DWORD)result)
                break;
            if ((_DWORD)result == 5
                && *(_BYTE *)ScanPos == 0xB9
                && *(_BYTE *)(ScanPos + 5) == 0x84
                && *(_BYTE *)(ScanPos + 24) == 0xB9)
            {
                Delta1 = *(unsigned int *)(ScanPos + 1);
                BaseValue = *(_QWORD *)(Context + 48);
                Delta2 = *(unsigned int *)(ScanPos + 25);
                if (Delta1 > BaseValue && Delta2 > BaseValue)
                {
                    ResultOffset1 = (unsigned int)(Delta1 - BaseValue);
                    ResultOffset2 = (unsigned int)(Delta2 - BaseValue);
                    if (ResultOffset1 < MaxDelta && ResultOffset2 < MaxDelta)
                    {
                        *pResult1 = BaseOffset + ResultOffset1;
                        result = BaseOffset + ResultOffset2;
                        *pResult2 = result;
                    }
                }
                return result;
            }
            result = (unsigned int)result;
            ScanPos += (unsigned int)result;
        }
    }
    return result;
}

// FindSetValueKeyTarget — 查找 NtSetValueKey 的 Hook 目标（备选方案）
__int64 FindSetValueKeyTarget(
    __int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    unsigned int MaxDelta,
    __int64 *pResultOffset,
    _QWORD *pResultOffset2)
{
    __int64 BufferSizeCopy;
    __int64 DecodedSize;
    unsigned __int64 ScanPos;
    unsigned __int64 BufferEnd;
    unsigned __int64 ScanEnd;
    unsigned __int64 FoundValue;
    unsigned int ValueDelta;

    *pResultOffset = 0;
    *pResultOffset2 = 0;
    BufferSizeCopy = BufferSize;
    DecodedSize = GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtNtQuerySystemInformationFunc | GtPathBuffer00));
    if ((_DWORD)DecodedSize
        && (unsigned int)DecodedSize < (unsigned int)BufferSizeCopy
        && (unsigned int)((int)DecodedSize + 4106) < (unsigned int)BufferSizeCopy)
    {
        ScanPos = Buffer + (unsigned int)DecodedSize;
        BufferEnd = Buffer + BufferSizeCopy;
        ScanEnd = ScanPos + 4096;
        while (ScanPos < ScanEnd)
        {
            DecodedSize = DecodeUtf8Buffer((unsigned __int8 *)ScanPos, BufferEnd);
            if (!(_DWORD)DecodedSize)
                break;
            if ((_DWORD)DecodedSize == 6 && *(_WORD *)ScanPos == 967 && *(_WORD *)(ScanPos + 6) == 17289)
            {
                FoundValue = *(unsigned int *)(ScanPos + 2);
                if (FoundValue > *(_QWORD *)(Context + 48))
                {
                    ValueDelta = (unsigned int)(FoundValue - *(_DWORD *)(Context + 48));
                    if (ValueDelta < MaxDelta)
                    {
                        DecodedSize = BaseOffset + ValueDelta;
                        *pResultOffset = DecodedSize;
                    }
                }
                return DecodedSize;
            }
            DecodedSize = (unsigned int)DecodedSize;
            ScanPos += (unsigned int)DecodedSize;
        }
    }
    return DecodedSize;
}

// FindNtRenameKeyTarget — 查找 NtRenameKey 目标
__int16 FindNtRenameKeyTarget(__int64 TargetBase, unsigned int TargetSize, __int64 Context, unsigned __int64 MaxOffset)
{
    char FoundMarker;
    char FoundMatch;
    unsigned int SectionOffset;
    unsigned int i;
    int CurrentOffset;
    __int16 SectionType;
    unsigned int MatchOffset;
    int FinalOffset;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [16] 仅 64 字节
    int EntryField;
    __int64 SectionFlags;
    __int64 Value;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    FoundMarker = 0;
    FoundMatch = 0;
    SectionOffset = (unsigned int)GtRead(GtNtCreateProcessPeSectionOffset);
    if (SectionOffset && SectionOffset < TargetSize)
    {
        InitPESectionReadContext(TargetBase + SectionOffset, TargetSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (i = 0; i < 0x3E8; ++i)
        {
            SectionOffset = (unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if (SectionOffset)
                return (__int16)SectionOffset;
            CurrentOffset = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            SectionType = *(_WORD *)(EntryDataPtr + 6);
            if ((unsigned __int16)(SectionType - 1340) <= 7u)
            {
                if (SectionFlags == 0x2000000 && (unsigned __int64)Value > MaxOffset)
                {
                    GtWrite((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtDriverObject), Value);
                    FoundMarker = 1;
                    if (FoundMatch == 1)
                        return (__int16)SectionOffset;
                }
            }
            else if (SectionType == 1245 && SectionFlags == 0x40000)
            {
                if (EntryField)
                {
                    MatchOffset = (unsigned int)(CurrentOffset + EntryField - TargetBase);
                    if (MatchOffset < TargetSize)
                    {
                        SectionOffset = (unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                        if (!SectionOffset)
                        {
                            CumulativeSize += EntryCumulSize;
                            if (*(_WORD *)(EntryDataPtr + 6) == 321)
                            {
                                if (SectionEntry[14])
                                {
                                    SectionOffset = (unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                                    if (!SectionOffset)
                                    {
                                        FinalOffset = (int)(EntryCumulSize + CumulativeSize);
                                        CumulativeSize += EntryCumulSize;
                                        if (*(_WORD *)(EntryDataPtr + 6) == 1072)
                                        {
                                            if (EntryField && SectionFlags == 0x40000 && !Value)
                                            {
                                                SectionOffset = (unsigned int)(FinalOffset + EntryField - TargetBase);
                                                if (SectionOffset && SectionOffset < TargetSize)
                                                {
                                                    GtWrite((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize), MaxOffset + SectionOffset);
                                                    GtWrite(GtCallbackField119, MaxOffset + MatchOffset);
                                                    FoundMatch = 1;
                                                    if (FoundMarker == 1)
                                                        return (__int16)SectionOffset;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return (__int16)SectionOffset;
}

// FindRenameKeyTargetEx — 查找 NtRenameKey 目标（旧版扩展）
__int64 FindRenameKeyTargetEx(
    __int64 TargetBase,
    unsigned int TargetSize,
    __int64 Context,
    __int64 RelocBase)
{
    char FoundFlag;
    unsigned int PhaseIndex;
    enum _GLOBAL_TABLE_INDEX GtIndex;
    __int64 Result;
    unsigned int i;
    int CurrentOffset;
    unsigned int MatchOffset;
    int FinalOffset;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [30] 仅 120 字节
    unsigned int EntrySize;
    __int64 SectionFlags;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    FoundFlag = 0;
    for (PhaseIndex = 0; PhaseIndex < 2; ++PhaseIndex)
    {
        GtIndex = (enum _GLOBAL_TABLE_INDEX)(GtNtDuplicateObjectPeSectionOffset | GtObjectTypeField02 | GtPathBuffer00);
        if (PhaseIndex)
            GtIndex = GtNtCreateProcessPeSectionOffset;
        Result = GtRead(GtIndex);
        if ((_DWORD)Result && (unsigned int)Result < TargetSize)
        {
            InitPESectionReadContext(TargetBase + (unsigned int)Result, (ULONG)(TargetSize - Result), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            for (i = 0; i < 0x3E8; ++i)
            {
                Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
                CurrentOffset = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1245 && SectionFlags == 0x40000)
                {
                    if (EntrySize)
                    {
                        MatchOffset = (unsigned int)(CurrentOffset + EntrySize - TargetBase);
                        if (MatchOffset < TargetSize)
                        {
                            Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                            if (!(_DWORD)Result)
                            {
                                CumulativeSize += EntryCumulSize;
                                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 321)
                                {
                                    if (SectionEntry[14])
                                    {
                                        Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                                        if (!(_DWORD)Result)
                                        {
                                            FinalOffset = (int)(EntryCumulSize + CumulativeSize);
                                            CumulativeSize += EntryCumulSize;
                                            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1296)
                                            {
                                                if (EntrySize && SectionFlags == 0x40000)
                                                {
                                                    Result = FinalOffset + EntrySize - (unsigned int)TargetBase;
                                                    if ((unsigned int)Result > 8 && (unsigned int)Result < TargetSize)
                                                    {
                                                        FoundFlag = 1;
                                                        GtWrite(GtCallbackField118, Result + RelocBase - 8);
                                                        Result = GtWrite(GtCallbackField119, RelocBase + MatchOffset);
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
                }
            }
        }
        if (FoundFlag == 1)
            break;
    }
    return Result;
}

// ScanRegValueBodyForRef — 扫描注册表值体查找引用
char ScanRegValueBodyForRef(
    unsigned __int64 Buffer,
    unsigned int BufferSize,
    __int64 Context,
    __int64 BaseOffset,
    int MaxDelta,
    __int64 *pResult)
{
    __int64 ImageSize;
    __int64 Result;
    unsigned __int8 *TargetPtr;
    unsigned __int8 *BodyStart;
    unsigned int ResultOffset;
    _WORD UnicodeBuf[6];
    int OffsetValue;
    int EntryFlags;
    unsigned int CharLen;
    _DWORD *TokenPtr;

    *pResult = 0;
    ImageSize = BufferSize;
    Result = GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField151 | 0x100));
    if ((_DWORD)Result && (unsigned int)Result < (unsigned int)ImageSize)
    {
        TargetPtr = 0;
        BodyStart = (unsigned __int8 *)(Buffer + (unsigned int)Result);
        while (1)
        {
            Result = DecodeUnicodeChar(BodyStart, Buffer + ImageSize, UnicodeBuf);
            if ((_BYTE)Result != 1)
                break;
            if (*TokenPtr == 4276)
                break;
            BodyStart += CharLen;
            if (*TokenPtr == 4279
                && EntryFlags == 1
                && DecodeUnicodeChar(BodyStart, Buffer + ImageSize, UnicodeBuf) == 1
                && *TokenPtr == 4301
                && OffsetValue < 0)
            {
                Result = (__int64)&BodyStart[OffsetValue];
                TargetPtr = (unsigned __int8 *)(Result + CharLen);
                break;
            }
        }
        if ((unsigned __int64)TargetPtr >= Buffer && (unsigned __int64)TargetPtr < Buffer + ImageSize)
        {
            while (1)
            {
                Result = DecodeUnicodeChar(TargetPtr, Buffer + ImageSize, UnicodeBuf);
                if ((_BYTE)Result != 1)
                    break;
                if (*TokenPtr == 4276)
                    break;
                TargetPtr += CharLen;
                if (*TokenPtr == 4737 && EntryFlags == 96 && DecodeUnicodeChar(TargetPtr, Buffer + ImageSize, UnicodeBuf) == 1)
                {
                    TargetPtr += CharLen;
                    if (DecodeUnicodeChar(TargetPtr, Buffer + ImageSize, UnicodeBuf) == 1)
                    {
                        if (*TokenPtr == 4224
                            && OffsetValue > 0
                            && (unsigned __int64)(unsigned int)OffsetValue > *(_QWORD *)(Context + 48))
                        {
                            ResultOffset = (unsigned int)(OffsetValue - *(_DWORD *)(Context + 48));
                            if (ResultOffset < (unsigned int)ImageSize)
                            {
                                Result = BaseOffset + ResultOffset;
                                *pResult = Result;
                            }
                            return (char)Result;
                        }
                    }
                }
            }
        }
    }
    return (char)Result;
}

// CopyRegistryContextEntryArray — 复制注册表上下文条目数组
// 对应原始驱动 sub_140046048
__int64 CopyRegistryContextEntryArray(__int64 pOutputTable)
{
    __int64 *pExportTable = GtAlloc(GtDisableHookProtectionAddr2|GtCallbackField50|0x3000);
    if (!pExportTable)
        return 0;
    __int64 pDestSlot = pOutputTable + 8;
    char *pSrcSlot = (char *)pExportTable + 4;
    char Result = 0;
    for (int EntryCount = 28; EntryCount; EntryCount--)
    {
        *(_DWORD *)(pDestSlot - 4) = *(_DWORD *)pSrcSlot;
        if (*(_DWORD *)pSrcSlot && *((_DWORD *)pSrcSlot - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)pDestSlot = *(_QWORD *)(pSrcSlot + 4);
            *(_OWORD *)(pDestSlot + 18) = *(_OWORD *)(pSrcSlot + 12);
            *(_OWORD *)(pDestSlot + 34) = *(_OWORD *)(pSrcSlot + 28);
        }
        pSrcSlot += 48;
        pDestSlot += 64;
    }
    return Result;
}


// RegistryOperationDispatch — 注册表操作分发
// 处理注册表操作请求：通过进程ID查找进程，初始化进程并查询注册表操作信息
// 对应原始驱动 sub_14007EA14 (CmdRegistryOperation)
__int64 RegistryOperationDispatch(void *InputBuffer, int BufferSize)
{
    char Result;
    NTSTATUS Status;
    int StatusCopy;
    struct _KPROCESS *TargetProcess;
    char Inited;
    PEPROCESS Process;
    __int64 InputCopy[2];

    Result = 0;
    if (BufferSize == 16
        && (unsigned __int64)InputBuffer < MmUserProbeAddress
        && (unsigned __int64)((char *)InputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(InputBuffer, 0x10u, 8u);
        InputCopy[0] = *(__int64 *)InputBuffer;
        InputCopy[1] = *((__int64 *)InputBuffer + 1);
        Status = PsLookupProcessByProcessId((HANDLE)InputCopy[0], &Process);
        StatusCopy = Status;
        TargetProcess = (struct _KPROCESS *)InputCopy[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
            InputCopy[1] = (__int64)TargetProcess;
        }
        if ((struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)0x185) != TargetProcess
            && ValidateProcessObject(TargetProcess, 0) == 1)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0xA28)
                Inited = (char)EnumProcessAndInitObjects((__int64)TargetProcess, 1);
            else
                Inited = InitProcessAndQueryInfo(TargetProcess, 1);
            Result = Inited;
        }
        if (StatusCopy >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}
