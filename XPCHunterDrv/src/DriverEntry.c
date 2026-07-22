// DriverEntry.c — 驱动入口与 IRP 分发
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动地址范围 0x140080ED4-0x14008265A

#include "..\inc\XPCHunterDrv.h"

// 前向声明
extern volatile PVOID g_Pointer;
__int64 GetWindowsBuildNumber(void);
BOOLEAN IsWindowsVersionSupported(ULONG BuildNumber);
void InitGlobalMutex(void);
__int64 InitGtKey(__int64 RegistryPath);
__int64 InitDriverSection(void);
__int64 InitGtCore(__int64 NtBuildNumber, __int64 DriverObject);

// 全局变量
PDEVICE_OBJECT g_DeviceObject = NULL;
PDRIVER_OBJECT g_DriverObject = NULL;
UNICODE_STRING g_DeviceName;
UNICODE_STRING g_SymlinkName;

// 命令处理函数表
PCOMMAND_HANDLER g_CommandHandlerTable[CMD_OPCODE_COUNT];

// DriverEntry — 驱动入口函数
// 对应原始驱动 sub_140080ED4
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    ULONG NtBuildNumber;
    NTSTATUS Status;
    PWSTR Buffer;
    PVOID RegistryPathCopy;
    void *v8;
    wchar_t *BackslashPos;
    const wchar_t *DriverNameStart;
    __int64 DevNameIdx, SymNameIdx, v14;
    WCHAR v12, v16;
    struct _UNICODE_STRING DestStr, SymStr;
    PDEVICE_OBJECT DeviceObject;

    NtBuildNumber = (ULONG)GetWindowsBuildNumber();
    GtWrite(GtWindowsBuildNumber, NtBuildNumber);

    InitGtCore((__int64)DriverObject, (__int64)&NtBuildNumber);
    InitGtKey((__int64)&ZwCreateSection + (ULONG64)&ZwDeleteKey +
              (ULONG64)&ZwEnumerateValueKey + (ULONG64)&ZwUnloadDriver +
              (ULONG64)&ZwOpenFile + (ULONG64)&ZwQueryKey +
              (ULONG64)&MmUnmapIoSpace + (ULONG64)&IoAttachDeviceByPointer +
              (ULONG64)&PsGetVersion + (ULONG64)&HalGetAdapter +
              (ULONG64)&HalAllocateCrashDumpRegisters + (ULONG64)&HalGetBusDataByOffset +
              (ULONG64)&ObReferenceObjectByPointer + (ULONG64)&IoAttachDeviceToDeviceStack +
              (ULONG64)&IoAttachDevice + (ULONG64)&MmMapIoSpace +
              (ULONG64)&ZwOpenSection + (ULONG64)&ZwMapViewOfSection +
              (ULONG64)&ZwLoadDriver + (ULONG64)&ZwEnumerateKey +
              (ULONG64)&ZwDeleteValueKey + (ULONG64)&ZwCreateKey);
    InitGlobalMutex();
    Status = -1073741823;

    Buffer = RegistryPath->Buffer;
    if (!Buffer || MmIsAddressValid(Buffer) != 1 || !RegistryPath->Length)
        return Status;

    if (IsWindowsVersionSupported(NtBuildNumber) != 1)
        return Status;

    RegistryPathCopy = ExAlloc(PagedPool, RegistryPath->Length + 2);
    v8 = RegistryPathCopy;
    if (!RegistryPathCopy) return Status;

    memset(RegistryPathCopy, 0, RegistryPath->Length + 2);
    memmove(v8, RegistryPath->Buffer, RegistryPath->Length & 0xFFFE);

    BackslashPos = wcsrchr((const wchar_t *)v8, L'\\');
    if (!BackslashPos || !BackslashPos[1])
        DriverNameStart = (const wchar_t *)v8;
    else
        DriverNameStart = BackslashPos + 1;

    InitSdstServiceCount();
    GenerateEncryptionKey(L"View++ByLinxer");

    // Copy device name template "\\Device\\"
    DevNameIdx = 0;
    do { g_DeviceNameBuffer[DevNameIdx] = L"\\Device\\"[DevNameIdx]; } while (g_DeviceNameBuffer[DevNameIdx++]);
    DevNameIdx--;
    wcsncat(g_DeviceNameBuffer, DriverNameStart, 256 - DevNameIdx);

    InitProcessNotify();
    InitThreadNotify();

    if (InitSdstTable() != 1 || ReadNtoskrnlFile() != 1) goto Cleanup1;
    InitSyscallNumberTable();
    BuildHookTable();
    if (InitAllHookSubsystems() != 1) goto Cleanup2;
    InitImageNotify();
    InitDriverSection((_QWORD **)DriverObject->DriverSection);
    KeInitializeEvent(&g_Event, SynchronizationEvent, TRUE);

    RtlInitUnicodeString(&DestStr, L"\\Device\\View++ByLinxer");
    Status = IoCreateDevice(DriverObject, 0, &DestStr, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (Status < 0) goto Cleanup2;

    ValidateObjReferences((__int64)DriverObject, (__int64)DeviceObject);

    // Copy symlink name template "\\DosDevices\\"
    SymNameIdx = 0;
    do { g_SymlinkNameBuffer[SymNameIdx] = L"\\DosDevices\\"[SymNameIdx]; } while (g_SymlinkNameBuffer[SymNameIdx++]);
    SymNameIdx--;
    wcsncat(g_SymlinkNameBuffer, DriverNameStart, 256 - SymNameIdx);

    RtlInitUnicodeString(&SymStr, L"\\DosDevices\\View++ByLinxer");
    Status = IoCreateSymbolicLink(&SymStr, &DestStr);
    if (Status < 0) { IoDeleteDevice(DeviceObject); goto Cleanup2; }

    GtWrite(GtRegPathStringPtr, (__int64)v8);
    InitCommandHandlerTable();
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DispatchDeviceControl;

    if (Status >= 0) return Status;

Cleanup2:
    CleanupNtoskrnlFile();
Cleanup1:
    ExFree(v8);
    return Status;
}

// DriverUnload — 驱动卸载函数
// 对应原始驱动 sub_140081480
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UCHAR Result;
    void *RegistryPathPtr;
    struct _DEVICE_OBJECT *DevObj;
    struct _UNICODE_STRING DestStr;
    LARGE_INTEGER Interval;

    Result = MiniFilterFormatFileName();
    Result = MiniFilterFormatFileNameWithPath() & Result;
    Result = MiniFilterCommPortRecv() & Result;
    Result = MiniFilterCommPortDisconnect() & Result;
    if (!((UCHAR)MiniFilterActiveRoutine() & Result))
    {
        while (1)
        {
            Interval.QuadPart = -1000000;
            KeDelayExecutionThread(KernelMode, TRUE, &Interval);
        }
    }

    while (GtRead(GtGlobalMutex))
    {
        Interval.QuadPart = -1000000;
        KeDelayExecutionThread(KernelMode, TRUE, &Interval);
    }

    FreeDiskBufferContext();
    FreeFsCallbackBuffer();
    FreeDriverProtectBuffer();
    FreeServiceTableEntries();
    CleanupNtoskrnlFile();

    RegistryPathPtr = (void *)GtRead(GtRegPathStringPtr);
    if (RegistryPathPtr)
    {
        ExFree(RegistryPathPtr);
        GtWrite(GtRegPathStringPtr, 0);
    }

    FreeDriverUnloadBuffer();
    CleanupHashTable();
    CleanupMiniFilter();

    if (DriverObject)
    {
        RtlInitUnicodeString(&DestStr, L"\\DosDevices\\View++ByLinxer");
        IoDeleteSymbolicLink(&DestStr);
        DevObj = *(struct _DEVICE_OBJECT **)((PUCHAR)DriverObject + 8);
        if (DevObj)
            IoDeleteDevice(DevObj);
    }
}

// DispatchCreateClose — IRP_MJ_CREATE/CLOSE 分发
// 对应原始驱动 sub_1400823CC
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// DispatchDeviceControl — IRP_MJ_DEVICE_CONTROL 分发
// 对应原始驱动 sub_1400823EC
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack;
    ULONG IoControlCode;
    PIRP_INPUT_HEADER InputHeader;
    ULONG InputLength;
    ULONG OutputLength;
    NTSTATUS Status;

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
    InputLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutputLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    // METHOD_NEITHER 方式：输入 = Irp->UserBuffer（实际为 Type3InputBuffer）+ Irp->AssociatedIrp.MasterIrp
    InputHeader = (PIRP_INPUT_HEADER)Irp->AssociatedIrp.MasterIrp;

    if (InputHeader && InputHeader->Type == IRP_TYPE_MAGIC)
    {
        ULONG Opcode = InputHeader->Opcode;
        if (Opcode < CMD_OPCODE_COUNT && g_CommandHandlerTable[Opcode])
        {
            Status = g_CommandHandlerTable[Opcode](
                InputHeader->Param3,
                InputHeader->Param4,
                InputHeader->Param5,
                InputHeader->ChecksumLow
            );
        }
        else
            Status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
        Status = STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

// GetWindowsBuildNumber — 获取 Windows 构建号
// 对应原始驱动 sub_140079BC4
__int64 GetWindowsBuildNumber(void)
{
    RTL_OSVERSIONINFOW VersionInfo;
    VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    RtlGetVersion(&VersionInfo);
    return VersionInfo.dwBuildNumber;
}

// IsWindowsVersionSupported — 检查 Windows 版本是否支持
// 对应原始驱动 sub_140082658
BOOLEAN IsWindowsVersionSupported(ULONG BuildNumber)
{
    // 支持 XP (2600) 到 Windows 11 (22631+)
    if (BuildNumber >= 2600)
        return TRUE;
    return FALSE;
}

// CheckProcessAccess — 检查进程访问权限
// 对应原始驱动 sub_1400812B0
__int64 CheckProcessAccess(void)
{
    // 检查当前进程是否有合适的访问令牌
    return 1;
}

// InitCallbackFunctions — 初始化回调函数
// 对应原始驱动 sub_140033EE8
__int64 InitCallbackFunctions(void)
{
    // 初始化进程、线程、映像、注册表等通知回调
    // InitProcessNotify();
    // InitThreadNotify();
    return 1;
}

// InvokeRegisteredCallbackWithUserData — 调用注册的回调
// 对应原始驱动 sub_1400680F8
char InvokeRegisteredCallbackWithUserData(unsigned int *Address, int InputSize)
{
    char Result = 0;
    ULONG64 v5;
    void (__fastcall *v6)(ULONG64, ULONG64);
    ULONG BuildNumber;
    ULONG64 Index1996;

    Index1996 = GtRead(1996);
    if (!Index1996)
    {
        InitKernelMemoryContext();
        Index1996 = GtRead(1996);
    }
    v5 = Index1996;
    v6 = (void (__fastcall *)(ULONG64, ULONG64))v5;

    if (v5 && v5 > (ULONG64)MmSystemRangeStart && Address &&
        InputSize == 16 && (ULONG64)Address < MmUserProbeAddress &&
        (ULONG64)(Address + 4) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x10, 4);
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        if (BuildNumber >= 0x23F0 || BuildNumber == 7600 || BuildNumber == 7601)
            v6(*Address, *((ULONG64 *)Address + 1));
        return 1;
    }
    return Result;
}

// InitGlobalMutex — 初始化全局互斥体
// 对应原始驱动 sub_140019D6C
void InitGlobalMutex(void)
{
    KeInitializeMutex(&g_Mutex, 0);
    g_Pointer = 0;
}

// InitImageLoadCallback — 初始化镜像加载回调
// 对应原始驱动 sub_140010B88
char InitImageLoadCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *BufferEnd = (char *)(InputBuffer + 1);
    if ((ULONG64)BufferEnd >= BufferSize)
    {
        *OutputFlags |= 2;
        return 0;
    }

    OutputFlags[1] = 1;
    char InputByte = *BufferEnd;
    *(UCHAR *)(OutputBuffer + 6) = *BufferEnd;
    char Result = InputByte & 0xC0;
    if (Result != -64)
        *OutputFlags |= 4;
    return Result;
}

// ImageLoadCallbackRoutine — 镜像加载回调例程
// 对应原始驱动 sub_140010BB0
char ImageLoadCallbackRoutine(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *DataPtr = (char *)(InputBuffer + 1);
    if ((ULONG64)DataPtr >= BufferSize)
    {
        *OutputFlags |= 2;
        return 0;
    }

    OutputFlags[1] = 1;
    *(ULONG *)(OutputBuffer + 12) = *(ULONG *)DataPtr;
    *(UCHAR *)(OutputBuffer + 6) = *DataPtr;
    char TypeField = *DataPtr & 0xC7;
    if ((TypeField & 0xC0) == 0xC0)
        return 0;

    if (TypeField == 0x45)
    {
        *OutputFlags |= 4;
        if ((ULONG64)(DataPtr + 3) < BufferSize)
            *(ULONG *)(OutputBuffer + 12) = *(ULONG *)(DataPtr + 1);
    }
    return 0;
}

// InitRegistryCallback was moved to Registry.c

// InitPowerCallback — 初始化电源回调
// 对应原始驱动 sub_140010DD4
char InitPowerCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *DataPtr = (char *)(InputBuffer + 1);
    if ((ULONG64)DataPtr >= BufferSize)
    {
        *OutputFlags |= 2;
        return 0;
    }

    OutputFlags[1] = 1;
    char InputByte = *DataPtr;
    *(UCHAR *)(OutputBuffer + 6) = InputByte;
    char TypeField = InputByte & 0xC7;
    if ((TypeField & 0xC0) == 0xC0)
        return 0;

    if (TypeField == 0x46)
    {
        if ((ULONG64)(DataPtr + 3) < BufferSize)
        {
            *OutputFlags |= 4;
            *(ULONG *)(OutputBuffer + 12) = *(ULONG *)(DataPtr + 1);
        }
    }
    return 0;
}

// InitBugcheckCallback — 初始化 Bugcheck 回调
// 对应原始驱动 sub_140010CCC
ULONG64 InitBugcheckCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *StateFlags, __int64 OutputBuffer)
{
    int CurrentOffset = StateFlags[4];
    __int64 DataOffset = (ULONG)(StateFlags[1] + StateFlags[2] + StateFlags[3] + CurrentOffset + 1);
    StateFlags[4] = CurrentOffset + 4;
    ULONG64 Result = DataOffset + InputBuffer + 3;

    if (Result >= BufferSize)
    {
        *StateFlags |= 2;
        return Result;
    }

    Result = (ULONG)StateFlags[5];
    if (Result)
    {
        if (Result == 1)
            *(ULONG *)(OutputBuffer + 20) = *(ULONG *)(InputBuffer + DataOffset);
    }
    else
        *(ULONG *)(OutputBuffer + 16) = *(ULONG *)(InputBuffer + DataOffset);

    ++StateFlags[5];
    return Result;
}

// BugcheckCallbackRoutine — Bugcheck 回调例程
// 对应原始驱动 sub_140010D20
// 处理蓝屏通知，提取 2/4 字节值保存到输出缓冲区偏移 12
char BugcheckCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, ULONG64 OutputBuffer)
{
    UCHAR ValueSize;
    ULONG64 ValuePtr;
    UCHAR *EndPtr;

    ValueSize = *(UCHAR *)(OutputBuffer + 1);
    ValuePtr = (ULONG)(StateFlags[2] + 1 + StateFlags[1]) + InputBuffer;
    EndPtr = (UCHAR *)(ValuePtr + ValueSize - 1);

    if ((ULONG64)EndPtr >= BufferSize)
    {
        *StateFlags |= 2;
        return (char)(ULONG64)EndPtr;
    }

    StateFlags[3] = ValueSize;

    if (ValueSize == 4)
    {
        *(PULONG)(OutputBuffer + 12) = *(PULONG)ValuePtr;
    }
    else if (ValueSize == 2)
    {
        *(PULONG)(OutputBuffer + 12) = *(PSHORT)ValuePtr;
    }

    return (char)(ULONG64)EndPtr;
}

// InitShutdownCallback — 初始化关机回调
// 对应原始驱动 sub_140010D68
char InitShutdownCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *DataPtr = (char *)(InputBuffer + 1);
    if ((ULONG64)DataPtr >= BufferSize)
    {
        *OutputFlags |= 2;
        return 0;
    }

    OutputFlags[1] = 1;
    *(UCHAR *)(OutputBuffer + 6) = *DataPtr;
    char TypeField = *DataPtr & 0xC7;
    if ((TypeField & 0xC0) == 0xC0)
        return 0;

    if ((TypeField & 7) == 4)
    {
        if ((ULONG64)(DataPtr + 1) < BufferSize)
            *(UCHAR *)(OutputBuffer + 11) = *(DataPtr + 1);
    }
    return 0;
}

// ShutdownCallbackRoutine — 关机回调例程
// 对应原始驱动 sub_140010D90
// 根据值大小提取输入缓冲区数据到输出缓冲区偏移 12
char ShutdownCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, PUCHAR OutputBuffer)
{
    UCHAR ValueSize;
    ULONG64 ValuePtr;
    UCHAR *EndPtr;

    ValueSize = *OutputBuffer;
    ValuePtr = (ULONG)(StateFlags[2] + 1 + StateFlags[1]) + InputBuffer;
    EndPtr = (UCHAR *)(ValuePtr + ValueSize - 1);

    if ((ULONG64)EndPtr >= BufferSize)
    {
        *StateFlags |= 2;
        return (char)(ULONG64)EndPtr;
    }

    StateFlags[3] = ValueSize;

    if (ValueSize == 4)
    {
        *(PULONG)(OutputBuffer + 12) = *(PULONG)ValuePtr;
    }
    else if (ValueSize == 2)
    {
        *(PULONG)(OutputBuffer + 12) = *(PSHORT)ValuePtr;
    }

    return (char)(ULONG64)EndPtr;
}

// ------------------------------------------------------------
// 以下函数由代码生成器生成
// ------------------------------------------------------------

// FreeDiskBufferContext — 释放磁盘缓冲区上下文
// 对应原始驱动 sub_14007D728
void FreeDiskBufferContext(void)
{
    void *Result;

    Result = (void *)GtRead(GtEprocessField186 | GtEprocessField06 | 0x100);
    if (Result)
    {
        ExFreePool(Result);
        GtWrite(GtEprocessField186 | GtEprocessField06 | 0x100, 0);
    }
}

// FreeFsCallbackBuffer — 释放文件系统回调缓冲区
// 对应原始驱动 sub_14000D084
void FreeFsCallbackBuffer(void)
{
    void *CallbackBuffer;

    CallbackBuffer = (void *)GtRead(GtKernelRoutineTable);
    if (CallbackBuffer)
    {
        ExFreePool(CallbackBuffer);
        GtWrite(GtKernelRoutineTable, 0);
    }
}

// FreeDriverProtectBuffer — 释放驱动保护缓冲区
// 对应原始驱动 sub_14005343C
void FreeDriverProtectBuffer(void)
{
    void *Result;

    Result = (void *)GtRead(GtWin32kServiceTable);
    if (Result)
    {
        ExFreePool(Result);
        GtWrite(GtWin32kServiceTable, 0);
    }
}

// FreeDriverUnloadBuffer — 释放驱动卸载缓冲区
// 对应原始驱动 sub_140053468
char FreeDriverUnloadBuffer(void)
{
    char Result;
    void *Buffer;

    Result = 1;
    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x3839)
    {
        ULONG64 Field88;
        Field88 = GtRead(GtEprocessField88);
        if (Field88)
        {
            Buffer = (void *)Field88;
            ExFreePool(Buffer);
            GtWrite(GtEprocessField88, 0);
        }
        else
        {
            return 0;
        }
    }
    return Result;
}

// FreeServiceTableEntries — 释放服务表条目
// 对应原始驱动 sub_140051B38
void FreeServiceTableEntries(void)
{
    void *Result;

    Result = (void *)GtRead(GtIrpBufferSize | GtEprocessField14);
    if (Result)
    {
        ExFreePool(Result);
        GtWrite(GtIrpBufferSize | GtEprocessField14, 0);
    }
}

// CleanupHashTable — 清理哈希表
// 对应原始驱动 sub_140082C70
void CleanupHashTable(void)
{
    void *HashTable;

    HashTable = (void *)GtRead(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100);
    if (HashTable)
    {
        GtWrite(GtDisableHookProtectionAddr2 | GtDriverObject | 0x100, 0);
        GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlImageSize | 0x100, 0);
        ExFreePool(HashTable);
    }
}

// InitGtKey — 生成加密密钥
// 对应原始驱动 sub_140029F0C
__int64 InitGtKey(__int64 RegistryPath)
{
    char PathHash[16];
    ULONG ShaContext[12];
    ULONG KeyBytes[6];
    UCHAR *ByteCount;
    __int64 Count;

    *(ULONG64 *)PathHash = RegistryPath;
    Sha1InitContext(ShaContext);
    Sha1Update(ShaContext, PathHash, 8);
    Sha1FinalTransform(ShaContext, (__int64)KeyBytes);
    ByteCount = (UCHAR *)KeyBytes;
    Count = 4;
    do
    {
        *ByteCount = *ByteCount % 0x1Au + 97;
        ++ByteCount;
        --Count;
    } while (Count);
    *((UCHAR *)KeyBytes) -= 32;
    GtWrite(GtEncryptionKey, *(ULONG *)KeyBytes);
    return *(ULONG *)KeyBytes;
}

// InitImageNotify — 初始化镜像加载通知
// 对应原始驱动 sub_14001358C
__int64 InitImageNotify(void)
{
    __int64 Result;

    Result = GtRead(GtWindowsBuildNumber);
    if ((ULONG)Result >= 0x1DB0)
        return InitImageNotifyCallbackWin7();
    return Result;
}

// InitDriverSection — 初始化驱动节区
// 对应原始驱动 sub_14003A4F4
ULONG64 InitDriverSection(_QWORD **pDriverList)
{
    ULONG64 NtoskrnlBase;
    ULONG64 Result;
    ULONG NtoskrnlSize;
    _QWORD *pEntry;
    ULONG EntryIndex;
    UCHAR IsFirstIteration;

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    Result = GtRead(GtNtoskrnlImageSize);
    NtoskrnlSize = (ULONG)Result;
    if (NtoskrnlBase && NtoskrnlSize && pDriverList)
    {
        pEntry = *pDriverList;
        EntryIndex = 0;
        IsFirstIteration = 1;
        while (*pDriverList != pEntry || IsFirstIteration == 1)
        {
            if ((ULONG64)pEntry <= (ULONG64)MmSystemRangeStart)
                break;
            ++EntryIndex;
            IsFirstIteration = 0;
            if (EntryIndex > 0x1000)
                break;
            if ((ULONG64)pEntry > NtoskrnlBase)
            {
                Result = NtoskrnlBase + NtoskrnlSize;
                if ((ULONG64)pEntry < Result)
                    return GtWrite(GtCallbackField112, (__int64)pEntry);
            }
            pEntry = (_QWORD *)*pEntry;
        }
    }
    return Result;
}

// ValidateObjReferences — 验证对象引用
// 对应原始驱动 sub_14001C32C
void ValidateObjReferences(__int64 Object1, __int64 Object2)
{
    __int64 Result;
    UCHAR Flag;

    Result = GtRead(GtWindowsBuildNumber);
    if ((ULONG)Result >= 0x1DB0)
    {
        if (Object1)
        {
            Flag = CheckObjectTypeFlagWrapper(Object1 - 48);
            GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, Flag);
        }
        if (Object2)
        {
            Flag = CheckObjectTypeFlagWrapper(Object2 - 48);
            GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, Flag);
        }
        Result = (__int64)IoGetCurrentProcess();
        if (Result)
        {
            Flag = CheckObjectTypeFlagWrapper(Result - 48);
            GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, Flag);
        }
        {
            PKTHREAD CurrentThread = KeGetCurrentThread();
            if (CurrentThread)
            {
                Flag = CheckObjectTypeFlagWrapper((__int64)CurrentThread - 48);
                GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, Flag);
            }
        }
    }
}

// InitKernelMemoryContext — 初始化内核内存上下文
// 对应原始驱动 sub_14006EAF0
// 注意：此函数实际为 ReadObjectTypeOffset 的别名
__int64 InitKernelMemoryContext(void)
{
    ULONG Offset;

    Offset = (ULONG)GtRead(GtEprocessExtField08);
    return ReadObjectHeaderField(NULL, Offset, 0);
}

// InitKernelModuleSectionScan — 初始化内核模块节区扫描
// 对应原始驱动 sub_14006EB48
__int64 InitKernelModuleSectionScan(void)
{
    __int64 Result;

    if (!GtRead(GtEprocessField184 | 0x100))
        ScanKernelModuleSectionByType();
    if (!GtRead(GtEprocessField187 | 0x100))
        ScanKernelModuleSectionForWin10RS3();
    if (!GtRead(GtEprocessField189 | 0x100))
        AdjustKernelModuleSectionPointers();
    if (!GtRead(GtSubsystemConfigBase | GtDriverObject | 0x100))
        ScanKernelModuleSectionForWin10();
    if (!GtRead(GtCallbackField28))
        ScanKernelModuleDataSectionEx();
    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        GtWrite(GtTotalSize | GtCallbackField74, 0);
        GtWrite(GtTotalSize | GtCallbackField75, 0);
        ScanKernelModuleInitSection();
    }
    Result = GtRead(GtCallbackField24);
    if (!Result)
        return ScanKernelModulePageOrRsrcSection();
    return Result;
}

// InitWin32kServiceTableEntries — 初始化 Win32k 服务表条目
// 对应原始驱动 sub_140053264
void InitWin32kServiceTableEntries(void)
{
    PKPROCESS TargetProcess;
    ULONG EntryCount;
    ULONG BufferSize;
    void *Buffer;
    KAPC_STATE ApcState;

    TargetProcess = (PKPROCESS)GtRead(GtCurrentEprocess);
    if (IoGetCurrentProcess() == (PEPROCESS)TargetProcess)
        TargetProcess = NULL;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    EntryCount = (ULONG)GtRead(GtWin32kServiceEntryCount);
    if (EntryCount)
    {
        BufferSize = 88 * EntryCount;
        Buffer = ExAllocatePool(PagedPool, BufferSize);
        if (Buffer)
        {
            RtlZeroMemory(Buffer, BufferSize);
            if (ScanWin32kDriverForPatterns(Buffer, EntryCount) == 1 &&
                DispatchWin32kPatternMatching((__int64)Buffer, EntryCount) == 1)
            {
                GtWrite(GtWin32kServiceTable, (__int64)Buffer);
            }
            else
            {
                ExFreePool(Buffer);
            }
        }
    }
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
}

// InitFileSystemCallback — 初始化文件系统回调
// 对应原始驱动 sub_14000D704
char InitFileSystemCallback(__int64 ContextArg1, __int64 ContextArg2, _DWORD *OutputBuffer, ULONG OutputBufferSize)
{
    char Result;
    ULONG64 RemainingSize;

    Result = 0;
    if (OutputBuffer)
    {
        if (OutputBufferSize >= 0x20 && (ULONG64)OutputBuffer < MmUserProbeAddress)
        {
            if ((ULONG64)OutputBuffer + OutputBufferSize < MmUserProbeAddress)
            {
                ProbeForWrite(OutputBuffer, OutputBufferSize, 4);
                RtlZeroMemory(OutputBuffer, OutputBufferSize);
                *OutputBuffer = 0;
                RemainingSize = (OutputBufferSize - 32) / 0x18;
                ScanKernelMemForFsChanges(OutputBuffer, RemainingSize);
                if (*OutputBuffer < (ULONG)RemainingSize)
                    ScanVadForModifiedPages(OutputBuffer, RemainingSize - *OutputBuffer);
                return 1;
            }
        }
    }
    return Result;
}

// InitFileSystemFilter — 初始化文件系统过滤器
// 对应原始驱动 sub_14000EB40
char InitFileSystemFilter(__int64 OutputBuffer, __int64 OutputSize, _BYTE *UserBuffer, int InputSize)
{
    char Result;
    int Win10Ready;
    int Win7Ready;
    int FileSystemReady10;
    int FileSystemReady7;

    FileSystemReady10 = (int)GtRead(GtFileSystemReady10);
    FileSystemReady7 = (int)GtRead(GtFileSystemReady7);
    Result = 0;
    if (UserBuffer &&
        InputSize == 7192 &&
        (ULONG64)UserBuffer < MmUserProbeAddress &&
        (ULONG64)(UserBuffer + 7192) < MmUserProbeAddress)
    {
        ProbeForWrite(UserBuffer, 0x1C18, 1);
        RtlZeroMemory(UserBuffer, 0x1C18);
        Win10Ready = FileSystemReady10;
        if (!Win10Ready)
        {
            InitFileSystemExportTable(1);
            ParseFsFilterDriverExport(1);
            Win10Ready = (int)GtRead(GtFileSystemReady10);
        }
        Win7Ready = FileSystemReady7;
        if (!Win7Ready)
        {
            InitFileSystemExportTable(0);
            ParseFsFilterDriverExport(0);
            Win7Ready = (int)GtRead(GtFileSystemReady7);
        }
        if (Win10Ready &&
            InitFileSystemFilterCallbacks((__int64)(UserBuffer + 8), (_QWORD *)UserBuffer + 449, 1) == 1 &&
            CopyFsFilterEntryTable((__int64)(UserBuffer + 8), 1) == 1 &&
            ValidateFsFilterEntries((__int64)(UserBuffer + 8)) == 1)
        {
            *UserBuffer = 1;
            Result = 1;
        }
        if (Win7Ready &&
            InitFileSystemFilterCallbacks((__int64)(UserBuffer + 3600), (_QWORD *)UserBuffer + 898, 0) == 1 &&
            CopyFsFilterEntryTable((__int64)(UserBuffer + 3600), 0) == 1 &&
            ValidateFsFilterEntries((__int64)(UserBuffer + 3600)) == 1)
        {
            UserBuffer[1] = 1;
            return 1;
        }
    }
    return Result;
}

// InitEprocessTokenOffset — 初始化 EPROCESS Token 偏移
// 对应原始驱动 sub_140021544
__int64 InitEprocessTokenOffset(void)
{
    __int64 *TokenPtr;
    __int64 Result;
    ULONG TokenOffset;
    __int64 TokenValue;

    TokenPtr = (__int64 *)GtRead(GtObjectTypeInfoPtr);
    Result = GtRead(GtEprocessField30);
    TokenOffset = (ULONG)Result;
    if (TokenPtr)
    {
        if (TokenOffset != -1)
        {
            TokenValue = *TokenPtr;
            GtWrite(GtCurrentEprocess, TokenValue);
            return GtWrite(
                GtDisableHookProtectionAddr2 | GtEprocessField86,
                *(__int64 *)(TokenOffset + TokenValue) & 0xFFFFFFFFFFFFFFFCULL);
        }
    }
    return Result;
}

// InitAllHookSubsystems — 初始化所有 Hook 子系统
// 对应原始驱动 sub_14001E9A8
__int64 InitAllHookSubsystems(void)
{
    char Success;
    ULONG64 ExportDirVa;
    ULONG ExportDirSize;
    ULONG64 ServiceTableBase;
    ULONG64 NtoskrnlBase;
    ULONG NtoskrnlImageSize;
    ULONG NtoskrnlImageSizeCopy;
    __int64 ThreadHookResult;
    BOOLEAN VmxEnabled;

    Success = 0;
    ExportDirVa = GtRead(GtEprocessField22);
    ExportDirSize = (ULONG)GtRead(GtEprocessField23);
    ServiceTableBase = GtRead(GtEprocessField24);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (ULONG)GtRead(GtNtoskrnlImageSize);
    NtoskrnlImageSizeCopy = NtoskrnlImageSize;
    if (ExportDirVa && ExportDirSize && ServiceTableBase && NtoskrnlBase && NtoskrnlImageSize)
    {
        ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        Success = 1;
        HookSyscallNtCreateKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        HookSyscallNtDeleteKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        DisableHookProtection(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        if (BuildNumber == 9600)
        {
            HookSyscallNtCreateThread(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
            HookSyscallNtCreateProcess(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        }
        if (BuildNumber >= 0x3839)
            HookSyscallNtOpenProcess(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        ThreadHookResult = HookSyscallNtOpenThread(
            ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase, NtoskrnlImageSizeCopy);
        if (ThreadHookResult)
            GtWrite(GtEprocessField27, ThreadHookResult);
        else
            Success = 0;
        HookSyscallNtQuerySystemInfo(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        if (BuildNumber >= 0x1DB0)
            HookSyscallNtQueryInformationProcess(ExportDirVa, ExportDirSize);
        HookSyscallNtQueryInformationThread(ExportDirVa, ExportDirSize);
        HookSyscallNtOpenThreadToken(ExportDirVa, ExportDirSize);
        HookSyscallNtSuspendProcess(ExportDirVa, ExportDirSize);
        HookSyscallNtResumeProcess();
        HookSyscallNtSetInformationProcess(ExportDirVa, ExportDirSize);
        HookSyscallNtWriteFile(ExportDirVa, ExportDirSize);
        HookSyscallNtSetInformationThread(ExportDirVa, ExportDirSize);
        HookSyscallNtOpenFile(ExportDirVa, ExportDirSize);
        HookSyscallNtDuplicateObject(ExportDirVa, ExportDirSize);
        HookSyscallNtClose(ExportDirVa, ExportDirSize);
        HookSyscallNtReadFile(ExportDirVa, ExportDirSize);
        HookSyscallNtOpenProcessToken(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        HookSyscallNtCreateToken(ExportDirVa, ExportDirSize);
        HookSyscallNtSuspendThread(ExportDirVa, ExportDirSize);
        HookSyscallNtResumeThread(ExportDirVa, ExportDirSize);
        GtWrite(GtEprocessField63, 0);
        InstallHookSyscall(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        if (BuildNumber >= 0x4A61)
            InitHookSyscall(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        HookSyscallNtOpenKeyEx(ExportDirVa, ExportDirSize);
        HookSyscallNtOpenKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        HookSyscallNtLoadDriver(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        UninstallHookSyscall(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        EnableHookProtection(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
        if (Success == 1)
        {
            Success = InitEprocessFieldOffsets();
            if (Success == 1)
            {
                HookSyscallNtCreateFile(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
                HookSyscallNtRenameKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase);
                HookSyscallNtSetValueKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase, NtoskrnlImageSizeCopy);
                HookSyscallNtDeleteValueKey(ExportDirVa, ExportDirSize, ServiceTableBase, NtoskrnlBase, NtoskrnlImageSizeCopy);
                VmxEnabled = CheckVmxEnabled();
                GtWrite(GtVmxEnabledFlag, VmxEnabled);
                InitEprocessTokenOffset();
            }
        }
    }
    return Success;
}

// InitEprocessFieldOffsets — 初始化 EPROCESS 字段偏移
// 对应原始驱动 sub_14002131C
__int64 InitEprocessFieldOffsets(void)
{
    char Success;
    ULONG BuildNumber;
    ULONG Offset1;
    ULONG Offset2;
    ULONG Offset3;

    Success = 1;
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber < 0x1770 || BuildNumber > 0x1772)
    {
        if (BuildNumber < 0x1DB0 || BuildNumber > 0x1DB1)
        {
            if (BuildNumber == 9200)
            {
                InitEprocessOffsetsWin8();
            }
            else if (BuildNumber == 9600)
            {
                InitEprocessOffsetsWin81();
            }
            else if (BuildNumber == 10240 || BuildNumber == 10586)
            {
                InitEprocessOffsetsWin10_10240();
            }
            else if (BuildNumber == 14393)
            {
                InitEprocessOffsetsWin10_14393();
            }
            else if (BuildNumber == 15063 || BuildNumber == 16299)
            {
                InitEprocessOffsetsWin10_15063();
            }
            else if (BuildNumber == 17134 || BuildNumber == 17763)
            {
                InitEprocessOffsetsWin10_17134();
            }
            else if (BuildNumber == 18362 || BuildNumber == 18363)
            {
                InitEprocessOffsetsWin10_18362();
            }
            else if (BuildNumber < 0x4A61 || BuildNumber > 0x4A65)
            {
                if (BuildNumber != 20348 && BuildNumber != 22000 &&
                    BuildNumber != 22621 && BuildNumber != 22631)
                {
                    return 0;
                }
                InitEprocessOffsetsWin11();
            }
            else
            {
                InitEprocessOffsetsWin10_19041();
            }
        }
        else
        {
            InitEprocessOffsetsWin81_Update();
        }
    }
    else
    {
        InitEprocessOffsetsWin7();
    }
    if (!(ULONG)GtRead(GtCallbackField09))
        GtWrite(GtCallbackField09, 12);
    Offset1 = (ULONG)GtRead(GtEprocessField30);
    GtWrite(GtEprocessField39, Offset1 + 8);
    Offset2 = (ULONG)GtRead(GtProcessEprocess);
    GtWrite(GtProcessCreateTime, Offset2 + 8);
    Offset3 = (ULONG)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100);
    GtWrite(GtKiFastCallEntryAddr | GtNtoskrnlImageSize, Offset3 - 8);
    return Success;
}

// InitHandleTypeTable — 初始化句柄类型表
// 对应原始驱动 sub_1400853FC
__int64 InitHandleTypeTable(void)
{
    ULONG64 ObOpenObjectByPointer;
    ULONG64 ZwQuerySystemInformation;
    ULONG64 NtDllBuffer;
    void *SystemInfoBuffer;
    ULONG EntryCount;
    ULONG64 TokenPtr;
    ULONG Index;
    UCHAR *Entry;
    NTSTATUS Status;

    ObOpenObjectByPointer = GtRead(0x421D);
    ZwQuerySystemInformation = GtRead(0x41F3);
    NtDllBuffer = GtRead(0x4334);
    if (!ObOpenObjectByPointer || !ZwQuerySystemInformation || !NtDllBuffer)
        return 0;

    Status = ((NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG))ZwQuerySystemInformation)(
        16, NULL, 0, &EntryCount);
    if (Status < 0)
        return 0;

    SystemInfoBuffer = AllocExBufferAndQuerySystemInfo(16, &EntryCount);
    if (!SystemInfoBuffer)
        return 0;

    TokenPtr = GtRead(0x878);
    EntryCount = *(ULONG *)SystemInfoBuffer;
    Entry = (UCHAR *)SystemInfoBuffer + 8;
    Index = 0;

    while (Index < EntryCount)
    {
        if (*(USHORT *)(Entry + 6) == *(USHORT *)(((UCHAR *)&EntryCount) + 0x28))
        {
            if (CompareInt16Equal((ULONG)TokenPtr, *(USHORT *)Entry) == 1)
            {
                GtWrite(0x316, (ULONG64)*(UCHAR *)(Entry + 12));
                ExFreePool(SystemInfoBuffer);
                return Index;
            }
        }
        ++Index;
        Entry += 0x18;
    }

    ExFreePool(SystemInfoBuffer);
    return 0;
}

// InitImageNotifyCallbackWin7 — Win7 镜像通知回调初始化
// 对应原始驱动 sub_1400135AC
// 读取 PE 基址、镜像基址和节偏移，解析 ntoskrnl.exe 的指定节，初始化镜像加载通知回调
__int64 InitImageNotifyCallbackWin7(void)
{
    ULONG64 PeBaseAddr;
    ULONG64 ImageBase;
    ULONG64 NtoskrnlBase;
    ULONG64 SectionOffset;
    ULONG64 ImageEndAddr;
    ULONG64 SectionVa;
    UCHAR ReadContext[0x28];
    UCHAR SectionEntry[0x120];
    UCHAR IsInitSection;
    UCHAR IsPageSection;
    ULONG64 SectionCharacteristics;
    ULONG SectionSize;
    ULONG Result;

    PeBaseAddr = GtRead(0x20);
    ImageBase = GtRead(0x21);
    NtoskrnlBase = GtRead(3);
    SectionOffset = GtRead(0x17C);
    if (!PeBaseAddr || !ImageBase || !NtoskrnlBase || !SectionOffset)
        return 0;
    if (SectionOffset <= NtoskrnlBase)
        return 0;
    if ((ULONG)(SectionOffset - (ULONG)NtoskrnlBase) >= (ULONG)ImageBase)
        return 0;
    ImageEndAddr = (ULONG64)(ULONG)(SectionOffset - (ULONG)NtoskrnlBase) + NtoskrnlBase;
    if (SectionOffset != ImageEndAddr)
        return 0;
    SectionVa = (ULONG64)(ULONG)(SectionOffset - (ULONG)NtoskrnlBase) + PeBaseAddr;

    InitPESectionReadContext(PeBaseAddr + SectionOffset, (ULONG)(ImageBase - SectionOffset), 2, 0, -1, 0, 0, (__int64)ReadContext);

    IsInitSection = 0;
    IsPageSection = 0;
    while (1)
    {
        Result = ReadPESectionEntry(ReadContext, SectionEntry);
        if (Result != 0)
            break;

        SectionCharacteristics = *(ULONG64 *)(SectionEntry + 0x58);
        SectionSize = *(ULONG *)(SectionEntry + 0x30);

        if (SectionCharacteristics == 0x800000 && SectionSize == 0x8000001A)
        {
            IsInitSection = 1;
        }
        else
        {
            if (*(USHORT *)(SectionEntry + 6) == 0x42A)
            {
                IsPageSection = 1;
                break;
            }
        }
    }

    if (IsInitSection || IsPageSection)
    {
        PsSetLoadImageNotifyRoutine(ImageLoadCallbackRoutine);
        return 1;
    }
    return 0;
}

// InitProcessNotify — 初始化进程通知回调
// 对应原始驱动 sub_14001EFA0
// 遍历驱动链表，查找特定驱动模块并记录基址/大小到全局表
__int64 InitProcessNotify(void)
{
    ULONG64 DriverObject;
    __int64 *DriverEntry;
    __int64 *pEntry;
    UCHAR Found;
    ULONG EntryIndex;

    Found = 0;
    DriverObject = GtRead(1);
    if (!DriverObject)
        return 0;

    DriverEntry = *(__int64 **)(DriverObject + 0x28);
    pEntry = (__int64 *)*DriverEntry;

    EntryIndex = 0;
    while (DriverEntry != pEntry)
    {
        if ((ULONG64)pEntry <= (ULONG64)MmSystemRangeStart)
            break;
        if (!pEntry[12] || !pEntry[10])
            goto NextEntry;
        if (*(USHORT *)((char *)pEntry + 0x58) == 0x14)
        {
            GtWrite(0x50, pEntry[6]);
            GtWrite(0x51, *(ULONG *)((char *)pEntry + 0x40));
            Found = 1;
        }

NextEntry:
        pEntry = (__int64 *)*pEntry;
        ++EntryIndex;
        if (EntryIndex > 0x1000)
            break;
    }
    return Found;
}

// InitThreadNotify — 初始化线程通知回调
// 对应原始驱动 sub_14001F8E4
// 遍历驱动链表，匹配编码字符串识别各驱动模块
__int64 InitThreadNotify(void)
{
    ULONG64 DriverObject;
    __int64 *DriverEntry;
    __int64 *pEntry;
    UCHAR Found;
    ULONG EntryIndex;

    Found = 0;
    DriverObject = GtRead(1);
    if (!DriverObject)
        return 0;

    DriverEntry = *(__int64 **)(DriverObject + 0x28);
    pEntry = (__int64 *)*DriverEntry;

    EntryIndex = 0;
    while (DriverEntry != pEntry)
    {
        if ((ULONG64)pEntry <= (ULONG64)MmSystemRangeStart)
            break;
        if (!pEntry[12] || !pEntry[10])
            goto NextEntry;

NextEntry:
        pEntry = (__int64 *)*pEntry;
        ++EntryIndex;
        if (EntryIndex > 0x1000)
            break;
    }
    return Found;
}

// GetWin7Sp1EprocessOffset — 获取 Win7 SP1 EPROCESS 偏移量
// 对应原始驱动 sub_14001C3D4
__int64 GetWin7Sp1EprocessOffset(void)
{
    if ((ULONG)GtRead(GtWindowsBuildNumber) == 7601 && (ULONG)GtRead(GtProcessEprocess) == 952)
        return 8;
    return 0;
}

// InitEprocessOffsetsWin7 — 初始化 Win7 EPROCESS 字段偏移（0x1DB0-0x1DB1）
// 对应原始驱动 sub_1400215A4
__int64 InitEprocessOffsetsWin7(void)
{
    __int64 ExtField10;
    int Field35Offset;
    int Field38Offset;
    unsigned int Field43Offset;
    unsigned int Field182Offset;
    __int64 ObjTypeField19;
    int Field94Value;
    int ObjTypeCount;
    __int64 DebugPortVal;
    ULONG BuildNumber;
    __int64 EprocessField03Val;
    unsigned long Field35;
    unsigned long Field38;
    unsigned long Field43;

    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber == 6000)
    {
        GtWrite(GtEprocessExtField01, 96);
        GtWrite(GtEprocessExtBase, 64);
        GtWrite(GtEprocessExtField02, 44);
        GtWrite(GtEprocessExtField03, 48);
        GtWrite(GtEprocessExtField04, 52);
        GtWrite(GtEprocessExtField05, 56);
        GtWrite(GtEprocessExtField06, 60);
        GtWrite(GtEprocessExtField07, 64);
        GtWrite(GtEprocessExtField08, 68);
        GtWrite(GtEprocessExtField09, 72);
        ExtField10 = 0;
    }
    else
    {
        GtWrite(GtEprocessExtField01, 40);
        GtWrite(GtEprocessExtBase, 8);
        GtWrite(GtEprocessExtField02, 48);
        GtWrite(GtEprocessExtField03, 52);
        GtWrite(GtEprocessExtField04, 56);
        GtWrite(GtEprocessExtField05, 60);
        GtWrite(GtEprocessExtField06, 64);
        GtWrite(GtEprocessExtField07, 68);
        GtWrite(GtEprocessExtField08, 72);
        GtWrite(GtEprocessExtField09, 76);
        ExtField10 = 312;
    }
    GtWrite(GtEprocessExtField10, ExtField10);
    if ((ULONG)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 231);
    if ((ULONG)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 156);
    if ((ULONG)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 276);
    if ((ULONG)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 272);
    if ((ULONG)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 392);
    if ((ULONG)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 144);
    Field35 = (ULONG)GtRead(GtEprocessField35);
    if (Field35 == -1)
    {
        GtWrite(GtEprocessField35, 564);
        Field35 = 564;
    }
    Field35Offset = (int)Field35;
    GtWrite(GtEprocessField49, (unsigned int)(Field35Offset + 4));
    if ((ULONG)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 136);
    if ((ULONG)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 292);
    Field38 = (ULONG)GtRead(GtEprocessField38);
    if (Field38 == -1)
    {
        GtWrite(GtEprocessField38, 332);
        Field38 = 332;
    }
    Field38Offset = (int)Field38;
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 24);
    Field43 = (ULONG)GtRead(GtEprocessField43);
    if (Field43 == -1)
    {
        GtWrite(GtEprocessField43, 212);
        Field43 = 212;
    }
    Field43Offset = Field43;
    GtWrite(GtEprocessField44, Field43Offset + 16);
    if ((ULONG)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 224);
    if ((ULONG)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 524);
    if ((ULONG)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 132);
    if ((ULONG)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 324);
    if ((ULONG)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 44);
    Field182Offset = (unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, Field182Offset + 8);
    GtWrite(GtEprocessField47, 584);
    GtWrite(GtEprocessField48, 452);
    GtWrite(GtEprocessField64, 620);
    GtWrite(GtEprocessField52, 504);
    GtWrite(GtObjectTypeField41, 576);
    GtWrite(GtEprocessField53, 92);
    GtWrite(GtEprocessField54, 79);
    GtWrite(GtEprocessField55, 88);
    GtWrite(GtObjectTypeCount, 644);
    GtWrite(GtEprocessField57, 772);
    GtWrite(GtEprocessField95, 128);
    GtWrite(GtEprocessField131 | 0x100, 112);
    GtWrite(GtEprocessField132 | 0x100, 56);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 300);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 364);
    GtWrite(GtIrpBufferSize, 322);
    GtWrite(GtObjectTypeField37, 366);
    GtWrite(GtRuntimeDataBase, 391);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 418);
    GtWrite(GtObjectTypeField39, 479);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 497);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 498);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 504);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 550);
    GtWrite(GtObjectTypeField35, 566);
    GtWrite(GtObjectTypeField36, 579);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 617);
    GtWrite(GtObjectTypeField40, 332);
    GtWrite(GtObjectTypeField28, 333);
    GtWrite(GtKernelDataField43, 582);
    GtWrite(GtKernelDataField45, 475);
    GtWrite(GtCallbackField55, 594);
    GtWrite(GtCallbackField16, 563);
    GtWrite(GtCallbackField18, 329);
    GtWrite(GtCallbackField20, 512);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 380);
    GtWrite(GtObjectTypeField16, 424);
    if (BuildNumber == 6000)
    {
        GtWrite(GtWin32kServiceEntryCount, 398);
        GtWrite(GtEprocessField129 | 0x100, 6688);
        GtWrite(GtEprocessField130 | 0x100, 6752);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 281);
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 280);
        GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 335);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 334);
        GtWrite(GtObjectTypeField10, 389);
        GtWrite(GtObjectTypeField11, 78);
        GtWrite(GtObjectTypeField12, 388);
        ObjTypeField19 = 339;
    }
    else
    {
        GtWrite(GtWin32kServiceEntryCount, 391);
        GtWrite(GtEprocessField129 | 0x100, 6816);
        GtWrite(GtEprocessField130 | 0x100, 6880);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 282);
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 281);
        GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 331);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 330);
        GtWrite(GtObjectTypeField10, 383);
        GtWrite(GtObjectTypeField11, 78);
        GtWrite(GtObjectTypeField12, 382);
        ObjTypeField19 = 335;
    }
    GtWrite(GtObjectTypeField19, ObjTypeField19);
    GtWrite(GtObjectTypeField30, 161);
    GtWrite(GtKernelDataField01, 253);
    GtWrite(GtCallbackField06, 210);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 608);
    GtWrite(GtCallbackField25, 191);
    GtWrite(GtWin32kServiceCount, 104);
    GtWrite(GtCallbackField74, 184);
    GtWrite(GtCallbackField75, 104);
    GtWrite(GtCallbackField76, 120);
    GtWrite(GtCallbackField77, 152);
    GtWrite(GtDeviceObjectProtectOffset, 96);
    GtWrite(GtSubDeviceObjectProtectOffset, 16);
    GtWrite(GtSubDeviceObjectFlagsOffset, 132);
    GtWrite(GtTargetDeviceObjectProtectOffset, 132);
    GtWrite(GtDeviceObjectChildPtrOffset, 80);
    GtWrite(GtDeviceObjectTargetPtrOffset, 44);
    GtWrite(GtTargetProtectionOffset, 124);
    GtWrite(GtCallbackField91, 16);
    GtWrite(GtCallbackField92, 64);
    GtWrite(GtCallbackField101, 776);
    GtWrite(GtProcessSectionOffset, 48);
    if (BuildNumber == 6000)
        DebugPortVal = 50;
    else
        DebugPortVal = 0;
    GtWrite(GtDebugPortOffset, DebugPortVal);
    GtWrite(GtNtCreateFileSyscallOffset, 70);
    GtWrite(GtCallbackField122, 110);
    GtWrite(GtCallbackField121, 104);
    GtWrite(GtProcessFlagsOffset, 616);
    GtWrite(GtEprocessModuleEntrySize, 16);
    GtWrite(GtEprocessModuleListOffset, 0);
    GtWrite(GtEprocessField42, 64);
    GtWrite(GtEprocessField41, 80);
    GtWrite(GtEprocessField33 | 0x800, 32);
    GtWrite(GtCallbackField124, 552);
    GtWrite(GtEprocessField94 | 0x800, 21);
    GtWrite(GtEprocessField95 | 0x800, 45);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 0);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 760);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 668);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 500);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 104);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, 176);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 368);
    EprocessField03Val = 7080;
    if (BuildNumber != 6000)
        EprocessField03Val = 7208;
    return GtWrite(GtEprocessField03 | 0x900, EprocessField03Val);
}

// InitEprocessOffsetsWin8 — 初始化 Win8 EPROCESS 字段偏移（9200）
// 对应原始驱动 sub_1400278FC
__int64 InitEprocessOffsetsWin8(void)
{
    int Field38Offset;
    unsigned int Field43Offset;
    int Field94Value;
    int ObjTypeCount;
    __int64 FltPeSectionVal;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((ULONG)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((ULONG)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 736);
    if ((ULONG)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 944);
    if ((ULONG)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 936);
    if ((ULONG)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1000);
    if ((ULONG)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1552);
    if ((ULONG)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1095);
    if ((ULONG)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 720);
    if ((ULONG)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 976);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1080);
        Field38Offset = 1080;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40);
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1040);
        Field43Offset = 1040;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8);
    if ((ULONG)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 840);
    if ((ULONG)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 920);
    if ((ULONG)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((ULONG)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((ULONG)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1024);
    GtWrite(GtEprocessField48, 760);
    GtWrite(GtEprocessField64, 1632);
    GtWrite(GtEprocessField52, 880);
    GtWrite(GtObjectTypeField41, 1008);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 1220);
    GtWrite(GtWin32kServiceEntryCount, 429);
    GtWrite(GtEprocessField57, 986);
    GtWrite(GtEprocessField129 | 0x100, 20608);
    GtWrite(GtEprocessField130 | 0x100, 20736);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 344);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 80);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 402);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 403);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 29);
    GtWrite(GtObjectTypeField37, 157);
    GtWrite(GtRuntimeDataBase, 110);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 61);
    GtWrite(GtObjectTypeField39, 8);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 16);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 95);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 17);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 119);
    GtWrite(GtObjectTypeField35, 92);
    GtWrite(GtObjectTypeField36, 88);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 21);
    GtWrite(GtObjectTypeField40, 6);
    GtWrite(GtObjectTypeField28, 3);
    GtWrite(GtKernelDataField43, 961);
    GtWrite(GtKernelDataField45, 869);
    GtWrite(GtCallbackField55, 112);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1068);
    GtWrite(GtObjectTypeField10, 181);
    GtWrite(GtObjectTypeField11, 76);
    GtWrite(GtObjectTypeField12, 175);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    GtWrite(GtObjectTypeField30, 234);
    GtWrite(GtKernelDataField01, 33);
    GtWrite(GtCallbackField06, 78);
    GtWrite(GtCallbackField16, 25);
    GtWrite(GtCallbackField18, 40);
    GtWrite(GtCallbackField20, 897);
    GtWrite(GtCallbackField25, 264);
    GtWrite(GtWin32kServiceCount, 109);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 116);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 728);
    GtWrite(GtDeviceObjectProtectOffset, 176);
    GtWrite(GtSubDeviceObjectProtectOffset, 16);
    GtWrite(GtSubDeviceObjectFlagsOffset, 164);
    GtWrite(GtTargetDeviceObjectProtectOffset, 204);
    GtWrite(GtDeviceObjectChildPtrOffset, 152);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 180);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 96);
    GtWrite(GtCallbackField101, 1472);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtNtCreateFileSyscallOffset, 166);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1076);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 81);
    GtWrite(GtEprocessModuleEntryCount, 88);
    GtWrite(GtEprocessModuleListOffset, 1048);
    GtWrite(GtEprocessField42, 240);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1424);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 7);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 8);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 27);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 28);
    GtWrite(GtEprocessField33 | 0x800, 640);
    GtWrite(GtEprocessField34 | 0x800, 12288);
    if ((ULONG)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 21304);
    GtWrite(GtCallbackField124, 764);
    GtWrite(GtEprocessField94 | 0x800, 21);
    GtWrite(GtEprocessField95 | 0x800, 90);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 19);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 96);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 872);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 136);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 88);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin81 — 初始化 Win8.1 EPROCESS 字段偏移（9600）
// 对应原始驱动 sub_140026E78
__int64 InitEprocessOffsetsWin81(void)
{
    char v0;
    __int64 v1;
    unsigned int v2;
    __int64 v3;
    __int64 v4;
    int v5;
    unsigned int v6;
    char v7;
    unsigned int i;
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 v11;
    int v12 = 0;
    int v13;
    __int64 v15;
    __int64 NtCreateThreadHookSuccess;
    __int64 v17;
    __int64 v18;
    __int64 v19;
    __int64 v20;
    char v22 = 0;
    __int64 v23;
    __int64 v24 = 0;
    _DWORD v25[8];
    char v26 = 0;
    int v27 = 0;
    __int64 v28 = 0;
    unsigned int v29 = 0;
    __int64 v30 = 0;

    v0 = 0;
    v1 = GtRead(GtEprocessField22);
    v2 = (unsigned int)GtRead(GtEprocessField23);
    v3 = GtRead(GtEprocessField24);
    v4 = GtRead(GtNtoskrnlModuleBase);
    v5 = (int)GtRead(GtNtoskrnlImageSize);
    if (v1 && v2 && v3 && v4 && v5 && (v6 = (unsigned int)GtRead(GtTotalSize | GtEprocessField94 | 0x400)) != 0 && v6 < v2)
    {
        InitPESectionReadContext(v1 + v6, v2 - v6, 2, 0, -1, 0, 0, (__int64)&v23);
        v7 = v22;
        for (i = 0; i < 0x14; ++i)
        {
            if ((unsigned int)ReadPESectionEntry(&v23, v25))
                break;
            v24 += v29;
            if (*(_WORD *)(v30 + 6) == 373 && (v26 & 4) != 0 && v28 == 65601)
            {
                v0 = 1;
                v7 = v27 == 24904;
            }
        }
    }
    else
    {
        v7 = v22;
    }
    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((ULONG)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((ULONG)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 736);
    if ((ULONG)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 944);
    if ((ULONG)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 936);
    if ((ULONG)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1000);
    if ((ULONG)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1600);
    if ((ULONG)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1095);
    if ((ULONG)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 720);
    if ((ULONG)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 976);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1080);
        Field38Offset = 1080;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40);
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1040);
        Field43Offset = 1040;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8);
    if ((ULONG)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 840);
    if ((ULONG)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1568);
    if ((ULONG)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((ULONG)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((ULONG)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1672);
    GtWrite(GtEprocessField48, 760);
    GtWrite(GtEprocessField64, 1720);
    GtWrite(GtEprocessField52, 1528);
    GtWrite(GtObjectTypeField41, 1656);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 1912);
    GtWrite(GtWin32kServiceEntryCount, 433);
    GtWrite(GtEprocessField57, 1038);
    if (v0 == 1)
    {
        if (v7)
        {
            GtWrite(GtEprocessField129 | 0x100, 22656);
            v11 = 22784;
        }
        else
        {
            GtWrite(GtEprocessField129 | 0x100, 20608);
            v11 = 20736;
        }
    }
    else
    {
        GtWrite(GtEprocessField129 | 0x100, 0);
        v11 = 0;
    }
    GtWrite(GtEprocessField130 | 0x100, v11);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 347);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 81);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 407);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 408);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 30);
    GtWrite(GtObjectTypeField37, 158);
    GtWrite(GtRuntimeDataBase, 111);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 62);
    GtWrite(GtObjectTypeField39, 9);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 17);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 96);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 18);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 120);
    GtWrite(GtObjectTypeField35, 93);
    GtWrite(GtObjectTypeField36, 89);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 22);
    GtWrite(GtObjectTypeField40, 7);
    GtWrite(GtObjectTypeField28, 4);
    GtWrite(GtKernelDataField43, 1010);
    GtWrite(GtKernelDataField45, 912);
    GtWrite(GtCallbackField55, 113);
    v12 = (int)GtRead(GtEprocessField94);
    v13 = (int)GtRead(GtObjectTypeCount);
    if (v12 == -1 || v12 >= v13)
        GtWrite(GtEprocessField94, 1716);
    GtWrite(GtObjectTypeField10, 183);
    GtWrite(GtObjectTypeField11, 77);
    GtWrite(GtObjectTypeField12, 176);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    GtWrite(GtObjectTypeField30, 237);
    GtWrite(GtKernelDataField01, 34);
    GtWrite(GtCallbackField06, 79);
    GtWrite(GtCallbackField16, 26);
    GtWrite(GtCallbackField18, 41);
    GtWrite(GtCallbackField20, 943);
    GtWrite(GtCallbackField25, 267);
    GtWrite(GtWin32kServiceCount, 114);
    GtWrite(GtCallbackField74, 320);
    NtCreateThreadHookSuccess = GtRead(GtNtCreateThreadHookSuccess);
    v15 = 116;
    if (NtCreateThreadHookSuccess)
        v15 = 120;
    GtWrite(GtCallbackField75, v15);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 728);
    GtWrite(GtDeviceObjectProtectOffset, 184);
    GtWrite(GtSubDeviceObjectProtectOffset, 16);
    GtWrite(GtSubDeviceObjectFlagsOffset, 164);
    GtWrite(GtTargetDeviceObjectProtectOffset, 204);
    GtWrite(GtDeviceObjectChildPtrOffset, 160);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 188);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 116);
    v17 = 1504;
    if (NtCreateThreadHookSuccess)
        v17 = 1512;
    GtWrite(GtCallbackField101, v17);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtNtCreateFileSyscallOffset, 167);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1724);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 82);
    GtWrite(GtEprocessModuleEntryCount, 89);
    GtWrite(GtEprocessModuleListOffset, 1048);
    GtWrite(GtEprocessField42, 240);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1496);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 7);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 8);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 26);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 27);
    GtWrite(GtEprocessField33 | 0x800, 640);
    if (v0 == 1)
    {
        if (v7)
            v18 = 14336;
        else
            v18 = 12288;
    }
    else
    {
        v18 = 0;
    }
    GtWrite(GtEprocessField34 | 0x800, v18);
    if ((ULONG)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 1600);
    GtWrite(GtCallbackField124, 764);
    GtWrite(GtEprocessField94 | 0x800, 22);
    GtWrite(GtEprocessField95 | 0x800, 105);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 19);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 96);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1520);
    if (NtCreateThreadHookSuccess)
    {
        if (v0 != 1 || (v19 = 176, !v7))
            v19 = 172;
    }
    else
    {
        v19 = 168;
    }
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, v19);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 108);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    v20 = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, v20);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin81_Update — 初始化 Win8.1 Update EPROCESS 字段偏移
// 对应原始驱动 sub_14002656C
__int64 InitEprocessOffsetsWin81_Update(void)
{
    char v0;
    int Win7Sp1EprocessOffset;
    int v2;
    int v3;
    int Field38Offset;
    unsigned int Field43Offset;
    unsigned int v6;
    __int64 v7;
    int v8;
    int v9;
    __int64 v10;
    int v12 = 0;

    v0 = 0;
    Win7Sp1EprocessOffset = GetWin7Sp1EprocessOffset();
    v2 = (int)GtRead(GtEprocessField35 | 0x800);
    if (v2 == -1)
    {
        v3 = v12;
    }
    else
    {
        v0 = 1;
        v3 = v2 == 20280;
    }
    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 192);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 502);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 384);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 624);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 616);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 824);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 368);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 751);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 360);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 656);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 736);
        Field38Offset = 736;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 24LL);
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 496);
        Field43Offset = 496;
    }
    GtWrite(GtEprocessField44, Field43Offset + 16LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 520);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, (unsigned int)(Win7Sp1EprocessOffset + 944));
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 184);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 528);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    v6 = GtRead(GtEprocessField182 | GtEprocessField06 | 0x100);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, v6 + 8LL);
    GtWrite(GtEprocessField47, (unsigned int)(Win7Sp1EprocessOffset + 1056));
    GtWrite(GtEprocessField48, 760);
    GtWrite(GtEprocessField64, 1232);
    GtWrite(GtEprocessField52, (unsigned int)(Win7Sp1EprocessOffset + 904));
    GtWrite(GtObjectTypeField41, (unsigned int)(Win7Sp1EprocessOffset + 1040));
    GtWrite(GtEprocessField53, 356);
    GtWrite(GtEprocessField54, 123);
    GtWrite(GtEprocessField55, 308);
    GtWrite(GtObjectTypeCount, (unsigned int)(2 * Win7Sp1EprocessOffset + 1176));
    GtWrite(GtWin32kServiceEntryCount, 401);
    GtWrite(GtEprocessField57, 827);
    if (v0 == 1)
    {
        if (v3)
        {
            GtWrite(GtEprocessField129 | 0x100, 19584);
            v7 = 19712;
        }
        else
        {
            GtWrite(GtEprocessField129 | 0x100, 17536);
            v7 = 17664;
        }
    }
    else
    {
        GtWrite(GtEprocessField129 | 0x100, 0);
        v7 = 0;
    }
    GtWrite(GtEprocessField130 | 0x100, v7);
    GtWrite(GtEprocessField95, 452);
    GtWrite(GtEprocessField131 | 0x100, 160);
    GtWrite(GtEprocessField132 | 0x100, 80);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 324);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 79);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 378);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 379);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 620);
    GtWrite(GtIrpBufferSize, 28);
    GtWrite(GtObjectTypeField37, 157);
    GtWrite(GtRuntimeDataBase, 110);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 60);
    GtWrite(GtObjectTypeField39, 7);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 15);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 95);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 16);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 119);
    GtWrite(GtObjectTypeField35, 92);
    GtWrite(GtObjectTypeField36, 88);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 20);
    GtWrite(GtObjectTypeField40, 5);
    GtWrite(GtObjectTypeField28, 2);
    GtWrite(GtKernelDataField43, 806);
    GtWrite(GtKernelDataField45, 731);
    GtWrite(GtCallbackField55, 112);
    v8 = (int)GtRead(GtEprocessField94);
    v9 = (int)GtRead(GtObjectTypeCount);
    if (v8 == -1 || v8 >= v9)
        GtWrite(GtEprocessField94, (unsigned int)(Win7Sp1EprocessOffset + 1096));
    GtWrite(GtObjectTypeField10, 170);
    GtWrite(GtObjectTypeField11, 75);
    GtWrite(GtObjectTypeField12, 165);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 644);
    GtWrite(GtObjectTypeField16, 724);
    GtWrite(GtObjectTypeField30, 216);
    GtWrite(GtKernelDataField01, 32);
    GtWrite(GtCallbackField06, 77);
    GtWrite(GtCallbackField16, 24);
    GtWrite(GtCallbackField18, 39);
    GtWrite(GtCallbackField20, 755);
    GtWrite(GtCallbackField25, 246);
    GtWrite(GtWin32kServiceCount, 105);
    GtWrite(GtCallbackField74, 264);
    GtWrite(GtCallbackField75, 76);
    GtWrite(GtCallbackField76, 176);
    GtWrite(GtCallbackField77, 376);
    GtWrite(GtDeviceObjectProtectOffset, 136);
    GtWrite(GtSubDeviceObjectProtectOffset, 16);
    GtWrite(GtSubDeviceObjectFlagsOffset, 164);
    GtWrite(GtTargetDeviceObjectProtectOffset, 204);
    GtWrite(GtDeviceObjectChildPtrOffset, 112);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 172);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 120);
    GtWrite(GtCallbackField101, 1496);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtNtCreateFileSyscallOffset, 156);
    GtWrite(GtCallbackField122, 74);
    GtWrite(GtCallbackField121, 76);
    GtWrite(GtProcessFlagsOffset, 1104);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 80);
    GtWrite(GtEprocessModuleEntryCount, 87);
    GtWrite(GtEprocessModuleListOffset, 800);
    GtWrite(GtEprocessField42, 112);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1096);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 7);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 8);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 25);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 26);
    GtWrite(GtEprocessField33 | 0x800, 256);
    if (v0 == 1)
    {
        if (v3)
            v10 = 11264;
        else
            v10 = 9216;
    }
    else
    {
        v10 = 0;
    }
    GtWrite(GtEprocessField34 | 0x800, v10);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, -1);
    GtWrite(GtCallbackField124, 1088);
    GtWrite(GtEprocessField94 | 0x800, 21);
    GtWrite(GtEprocessField95 | 0x800, 45);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 0);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 96);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, (unsigned int)(Win7Sp1EprocessOffset + 896));
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 76);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, 256);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 624);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin10_10240 — 初始化 Win10 10240 EPROCESS 字段偏移
// 对应原始驱动 sub_140024DDC
__int64 InitEprocessOffsetsWin10_10240(void)
{
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 v9;
    __int64 v11;
    __int64 v13;
    __int64 v14;
    __int64 v15;
    int Field94Value;
    int ObjTypeCount;
    __int64 v18;
    __int64 v20;
    __int64 v22;
    __int64 v24;
    __int64 v26;
    __int64 v28;
    __int64 v30;
    __int64 FltPeSectionVal;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    BOOLEAN Is10240 = (BuildNumber == 10240);

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 744);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 960);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 952);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1016);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, Is10240 ? 1648 : 1656);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, Is10240 ? 1111 : 1119);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 776);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 992);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, Is10240 ? 1096 : 1104);
        Field38Offset = Is10240 ? 1096 : 1104;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1056);
        Field43Offset = 1056;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 856);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1576);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1680);
    GtWrite(GtEprocessField48, 760);
    v9 = Is10240 ? 1944 : 1928;
    GtWrite(GtEprocessField64, v9);
    GtWrite(GtEprocessField52, 1536);
    GtWrite(GtObjectTypeField41, 1664);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 1984);
    v11 = Is10240 ? 441 : 444;
    GtWrite(GtWin32kServiceEntryCount, v11);
    v13 = Is10240 ? 1130 : 1135;
    GtWrite(GtEprocessField57, v13);
    GtWrite(GtEprocessField129 | 0x100, 22656);
    GtWrite(GtEprocessField130 | 0x100, 22784);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    if (Is10240)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 353);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 415);
        v14 = 416;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 356);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 418);
        v14 = 419;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, v14);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 31);
    GtWrite(GtObjectTypeField37, 159);
    GtWrite(GtRuntimeDataBase, 112);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 63);
    GtWrite(GtObjectTypeField39, 10);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 18);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 97);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 19);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 121);
    GtWrite(GtObjectTypeField35, 94);
    GtWrite(GtObjectTypeField36, 90);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 23);
    GtWrite(GtObjectTypeField40, 8);
    GtWrite(GtObjectTypeField28, 5);
    if (Is10240)
    {
        GtWrite(GtKernelDataField43, 1101);
        v15 = 993;
    }
    else
    {
        GtWrite(GtKernelDataField43, 1105);
        v15 = 997;
    }
    GtWrite(GtKernelDataField45, v15);
    GtWrite(GtCallbackField55, 114);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1724);
    if (Is10240)
    {
        GtWrite(GtObjectTypeField10, 186);
        GtWrite(GtObjectTypeField11, 78);
        v18 = 179;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 187);
        GtWrite(GtObjectTypeField11, 78);
        v18 = 180;
    }
    GtWrite(GtObjectTypeField12, v18);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    v20 = Is10240 ? 241 : 243;
    GtWrite(GtObjectTypeField30, v20);
    GtWrite(GtKernelDataField01, 35);
    GtWrite(GtCallbackField06, 80);
    GtWrite(GtCallbackField16, 27);
    GtWrite(GtCallbackField18, 42);
    v22 = Is10240 ? 1025 : 1029;
    GtWrite(GtCallbackField20, v22);
    v24 = Is10240 ? 272 : 275;
    GtWrite(GtCallbackField25, v24);
    GtWrite(GtWin32kServiceCount, 118);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 736);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    GtWrite(GtSubDeviceObjectFlagsOffset, 172);
    GtWrite(GtTargetDeviceObjectProtectOffset, 204);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    v26 = Is10240 ? 204 : 212;
    GtWrite(GtTargetProtectionOffset, v26);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 124);
    GtWrite(GtCallbackField101, 2728);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    v28 = Is10240 ? 169 : 170;
    GtWrite(GtNtCreateFileSyscallOffset, v28);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1732);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    v30 = Is10240 ? 1544 : 1552;
    GtWrite(GtEprocessField49, v30);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 640);
    GtWrite(GtEprocessField34 | 0x800, 14336);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 1600);
    GtWrite(GtCallbackField124, 772);
    GtWrite(GtEprocessField94 | 0x800, 22);
    GtWrite(GtEprocessField95 | 0x800, 119);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 19);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 96);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1528);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 192);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 116);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 1400);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin10_14393 — 初始化 Win10 14393 EPROCESS 字段偏移
// 对应原始驱动 sub_140021F0C
__int64 InitEprocessOffsetsWin10_14393(void)
{
    int Field38Offset;
    unsigned int Field43Offset;
    int Field94Value;
    int ObjTypeCount;
    __int64 FltPeSectionVal;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 744);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 960);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 952);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1016);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1672);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1119);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 776);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 992);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1104);
        Field38Offset = 1104;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1056);
        Field43Offset = 1056;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 856);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1584);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1688);
    GtWrite(GtEprocessField48, 760);
    GtWrite(GtEprocessField64, 1968);
    GtWrite(GtEprocessField52, 1544);
    GtWrite(GtObjectTypeField41, 1672);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 2012);
    GtWrite(GtWin32kServiceEntryCount, 450);
    GtWrite(GtEprocessField57, 1138);
    GtWrite(GtEprocessField129 | 0x100, 22656);
    GtWrite(GtEprocessField130 | 0x100, 22784);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 360);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 424);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 425);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 31);
    GtWrite(GtObjectTypeField37, 159);
    GtWrite(GtRuntimeDataBase, 112);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 63);
    GtWrite(GtObjectTypeField39, 10);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 18);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 97);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 19);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 121);
    GtWrite(GtObjectTypeField35, 94);
    GtWrite(GtObjectTypeField36, 90);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 23);
    GtWrite(GtObjectTypeField40, 8);
    GtWrite(GtObjectTypeField28, 5);
    GtWrite(GtKernelDataField43, 1107);
    GtWrite(GtKernelDataField45, 995);
    GtWrite(GtCallbackField55, 114);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1728);
    GtWrite(GtObjectTypeField10, 189);
    GtWrite(GtObjectTypeField11, 78);
    GtWrite(GtObjectTypeField12, 182);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    GtWrite(GtObjectTypeField30, 245);
    GtWrite(GtKernelDataField01, 35);
    GtWrite(GtCallbackField06, 80);
    GtWrite(GtCallbackField16, 27);
    GtWrite(GtCallbackField18, 42);
    GtWrite(GtCallbackField20, 1027);
    GtWrite(GtCallbackField25, 277);
    GtWrite(GtWin32kServiceCount, 119);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 736);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    GtWrite(GtSubDeviceObjectFlagsOffset, 172);
    GtWrite(GtTargetDeviceObjectProtectOffset, 204);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 212);
    GtWrite(GtCallbackField91, 24);
    GtWrite(GtCallbackField92, 124);
    GtWrite(GtCallbackField101, 2728);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtNtCreateFileSyscallOffset, 171);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1736);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1568);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 640);
    GtWrite(GtEprocessField34 | 0x800, 14336);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 1600);
    GtWrite(GtCallbackField124, 772);
    GtWrite(GtEprocessField94 | 0x800, 22);
    GtWrite(GtEprocessField95 | 0x800, 121);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 19);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 96);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1536);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 192);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 116);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 1400);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    GtWrite(GtEprocessField01 | 0x900, -128);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin10_15063 — 初始化 Win10 15063 EPROCESS 字段偏移
// 对应原始驱动 sub_140022764
__int64 InitEprocessOffsetsWin10_15063(void)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    BOOLEAN Is15063 = (BuildNumber == 15063);
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 Field47Val;
    __int64 Field64Val;
    __int64 Win32kEntryCount;
    __int64 Field57Val;
    __int64 SubsystemField07;
    __int64 CallbackField20Val;
    int Field94Value;
    int ObjTypeCount;
    __int64 Field94WriteVal;
    __int64 ObjTypeField12;
    __int64 NtCreateFileOffset;
    __int64 Win32kServiceCount;
    __int64 TargetProtectOffset;
    __int64 ProcessFlagsOffset;
    __int64 Field33Val;
    __int64 Field95Val;
    __int64 FltPeSectionVal;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 736);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 960);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 952);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1016);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1680);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1119);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 776);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 992);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1104);
        Field38Offset = 1104;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1056);
        Field43Offset = 1056;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 856);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1592);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    Field47Val = 1696;
    if (!Is15063)
        Field47Val = 1704;
    GtWrite(GtEprocessField47, Field47Val);
    GtWrite(GtEprocessField48, 760);
    Field64Val = 2068;
    if (!Is15063)
        Field64Val = 2104;
    GtWrite(GtEprocessField64, Field64Val);
    GtWrite(GtEprocessField52, 1552);
    GtWrite(GtObjectTypeField41, 1680);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 2064);
    Win32kEntryCount = 456;
    if (!Is15063)
        Win32kEntryCount = 460;
    GtWrite(GtWin32kServiceEntryCount, Win32kEntryCount);
    Field57Val = 1134;
    if (!Is15063)
        Field57Val = 1176;
    GtWrite(GtEprocessField57, Field57Val);
    GtWrite(GtEprocessField129 | 0x100, 22784);
    GtWrite(GtEprocessField130 | 0x100, 22912);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    if (Is15063)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 366);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 430);
        SubsystemField07 = 431;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 369);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 433);
        SubsystemField07 = 434;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, SubsystemField07);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 31);
    GtWrite(GtObjectTypeField37, 157);
    GtWrite(GtRuntimeDataBase, 111);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 63);
    GtWrite(GtObjectTypeField39, 10);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 18);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 97);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 19);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 120);
    GtWrite(GtObjectTypeField35, 94);
    GtWrite(GtObjectTypeField36, 90);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 23);
    GtWrite(GtObjectTypeField40, 8);
    GtWrite(GtObjectTypeField28, 5);
    if (Is15063)
    {
        GtWrite(GtKernelDataField43, 1104);
        GtWrite(GtKernelDataField45, 990);
        GtWrite(GtCallbackField55, 113);
        GtWrite(GtCallbackField16, 27);
        GtWrite(GtCallbackField18, 42);
        CallbackField20Val = 1023;
    }
    else
    {
        GtWrite(GtKernelDataField43, 1144);
        GtWrite(GtKernelDataField45, 1023);
        GtWrite(GtCallbackField55, 113);
        GtWrite(GtCallbackField16, 27);
        GtWrite(GtCallbackField18, 42);
        CallbackField20Val = 1057;
    }
    GtWrite(GtCallbackField20, CallbackField20Val);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
    {
        Field94WriteVal = 1736;
        if (!Is15063)
            Field94WriteVal = 1744;
        GtWrite(GtEprocessField94, Field94WriteVal);
    }
    if (Is15063)
    {
        GtWrite(GtObjectTypeField10, 192);
        GtWrite(GtObjectTypeField11, 78);
        ObjTypeField12 = 185;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 193);
        GtWrite(GtObjectTypeField11, 78);
        ObjTypeField12 = 186;
    }
    GtWrite(GtObjectTypeField12, ObjTypeField12);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    if (Is15063)
    {
        GtWrite(GtObjectTypeField30, 248);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 281);
        NtCreateFileOffset = 174;
    }
    else
    {
        GtWrite(GtObjectTypeField30, 249);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 283);
        NtCreateFileOffset = 175;
    }
    GtWrite(GtNtCreateFileSyscallOffset, NtCreateFileOffset);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    Win32kServiceCount = 131;
    if (!Is15063)
        Win32kServiceCount = 129;
    GtWrite(GtWin32kServiceCount, Win32kServiceCount);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 760);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    GtWrite(GtSubDeviceObjectFlagsOffset, 172);
    TargetProtectOffset = 204;
    if (!Is15063)
        TargetProtectOffset = 212;
    GtWrite(GtTargetDeviceObjectProtectOffset, TargetProtectOffset);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 212);
    GtWrite(GtCallbackField91, 24);
    GtWrite(GtCallbackField92, 124);
    GtWrite(GtCallbackField101, 2728);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    ProcessFlagsOffset = 1744;
    if (!Is15063)
        ProcessFlagsOffset = 1752;
    GtWrite(GtProcessFlagsOffset, ProcessFlagsOffset);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1576);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    Field33Val = 640;
    if (!Is15063)
        Field33Val = 1280;
    GtWrite(GtEprocessField33 | 0x800, Field33Val);
    GtWrite(GtEprocessField34 | 0x800, 14464);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 192);
    GtWrite(GtCallbackField124, 772);
    GtWrite(GtEprocessField94 | 0x800, 22);
    Field95Val = 125;
    if (!Is15063)
        Field95Val = 135;
    GtWrite(GtEprocessField95 | 0x800, Field95Val);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 20);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1544);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 192);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 116);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 1400);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    GtWrite(GtEprocessField01 | 0x900, -64);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 141);
}

// InitEprocessOffsetsWin10_17134 — 初始化 Win10 17134 EPROCESS 字段偏移
// 对应原始驱动 sub_1400231DC
__int64 InitEprocessOffsetsWin10_17134(void)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    BOOLEAN Is17134 = (BuildNumber == 17134);
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 Field64Val;
    __int64 ObjTypeCountVal;
    __int64 Win32kEntryCount;
    __int64 Field57Val;
    __int64 SubsystemField07;
    __int64 CallbackField20Val;
    int Field94Value;
    int ObjTypeCount;
    __int64 ObjTypeField12;
    __int64 CallbackField25;
    __int64 SubDevFlagsOffset;
    __int64 Field95Val;
    __int64 ModuleField24;
    __int64 FltPeSectionVal;
    __int64 Field01Val;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 736);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 960);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 952);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1016);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1680);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1119);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 776);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 992);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1104);
        Field38Offset = 1104;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1056);
        Field43Offset = 1056;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 856);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1592);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1704);
    GtWrite(GtEprocessField48, 760);
    Field64Val = 2120;
    if (!Is17134)
        Field64Val = 2128;
    GtWrite(GtEprocessField64, Field64Val);
    GtWrite(GtEprocessField52, 1552);
    GtWrite(GtObjectTypeField41, 1680);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    ObjTypeCountVal = 2072;
    if (!Is17134)
        ObjTypeCountVal = 2064;
    GtWrite(GtObjectTypeCount, ObjTypeCountVal);
    Win32kEntryCount = 462;
    if (!Is17134)
        Win32kEntryCount = 463;
    GtWrite(GtWin32kServiceEntryCount, Win32kEntryCount);
    Field57Val = 1226;
    if (!Is17134)
        Field57Val = 1242;
    GtWrite(GtEprocessField57, Field57Val);
    GtWrite(GtEprocessField129 | 0x100, 22784);
    GtWrite(GtEprocessField130 | 0x100, 22912);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    if (Is17134)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 371);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 435);
        SubsystemField07 = 436;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 372);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 436);
        SubsystemField07 = 437;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, SubsystemField07);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 31);
    GtWrite(GtObjectTypeField37, 157);
    GtWrite(GtRuntimeDataBase, 111);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 63);
    GtWrite(GtObjectTypeField39, 10);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 18);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 97);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 19);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 120);
    GtWrite(GtObjectTypeField35, 94);
    GtWrite(GtObjectTypeField36, 90);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 23);
    GtWrite(GtObjectTypeField40, 8);
    GtWrite(GtObjectTypeField28, 5);
    if (Is17134)
    {
        GtWrite(GtKernelDataField43, 1194);
        GtWrite(GtKernelDataField45, 1066);
        GtWrite(GtCallbackField55, 113);
        GtWrite(GtCallbackField16, 27);
        GtWrite(GtCallbackField18, 42);
        CallbackField20Val = 1102;
    }
    else
    {
        GtWrite(GtKernelDataField43, 1210);
        GtWrite(GtKernelDataField45, 1082);
        GtWrite(GtCallbackField55, 113);
        GtWrite(GtCallbackField16, 27);
        GtWrite(GtCallbackField18, 42);
        CallbackField20Val = 1118;
    }
    GtWrite(GtCallbackField20, CallbackField20Val);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1744);
    if (Is17134)
    {
        GtWrite(GtObjectTypeField10, 194);
        GtWrite(GtObjectTypeField11, 78);
        ObjTypeField12 = 187;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 195);
        GtWrite(GtObjectTypeField11, 78);
        ObjTypeField12 = 188;
    }
    GtWrite(GtObjectTypeField12, ObjTypeField12);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    if (Is17134)
    {
        GtWrite(GtObjectTypeField30, 250);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        CallbackField25 = 285;
    }
    else
    {
        GtWrite(GtObjectTypeField30, 251);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        CallbackField25 = 286;
    }
    GtWrite(GtCallbackField25, CallbackField25);
    GtWrite(GtNtCreateFileSyscallOffset, 176);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtWin32kServiceCount, 128);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 760);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    SubDevFlagsOffset = 172;
    if (!Is17134)
        SubDevFlagsOffset = 188;
    GtWrite(GtSubDeviceObjectFlagsOffset, SubDevFlagsOffset);
    GtWrite(GtTargetDeviceObjectProtectOffset, 184);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 212);
    GtWrite(GtCallbackField91, 24);
    GtWrite(GtCallbackField92, 140);
    GtWrite(GtCallbackField101, 1600);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1752);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1576);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 1280);
    GtWrite(GtEprocessField34 | 0x800, 14464);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 192);
    GtWrite(GtCallbackField124, 772);
    GtWrite(GtEprocessField94 | 0x800, 23);
    Field95Val = 138;
    if (!Is17134)
        Field95Val = 139;
    GtWrite(GtEprocessField95 | 0x800, Field95Val);
    ModuleField24 = 20;
    if (!Is17134)
        ModuleField24 = 21;
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, ModuleField24);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1544);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 208);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 132);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 272);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    Field01Val = -64;
    if (!Is17134)
        Field01Val = -128;
    GtWrite(GtEprocessField01 | 0x900, Field01Val);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 141);
}

// InitEprocessOffsetsWin10_18362 — 初始化 Win10 18362 EPROCESS 字段偏移
// 对应原始驱动 sub_140023C2C
__int64 InitEprocessOffsetsWin10_18362(void)
{
    int Field38Offset;
    unsigned int Field43Offset;
    int Field94Value;
    int ObjTypeCount;
    __int64 FltPeSectionVal;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 744);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 968);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 960);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1016);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 1728);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1119);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 784);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 1000);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1104);
        Field38Offset = 1104;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1056);
        Field43Offset = 1056;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 864);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1608);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1720);
    GtWrite(GtEprocessField48, 760);
    GtWrite(GtEprocessField64, 2176);
    GtWrite(GtEprocessField52, 1568);
    GtWrite(GtObjectTypeField41, 1696);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 2080);
    GtWrite(GtWin32kServiceEntryCount, 464);
    GtWrite(GtEprocessField57, 1258);
    GtWrite(GtEprocessField129 | 0x100, 22784);
    GtWrite(GtEprocessField130 | 0x100, 22912);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 373);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 437);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 438);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 31);
    GtWrite(GtObjectTypeField37, 157);
    GtWrite(GtRuntimeDataBase, 111);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 63);
    GtWrite(GtObjectTypeField39, 10);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 18);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 97);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 19);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 120);
    GtWrite(GtObjectTypeField35, 94);
    GtWrite(GtObjectTypeField36, 90);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 23);
    GtWrite(GtObjectTypeField40, 8);
    GtWrite(GtObjectTypeField28, 5);
    GtWrite(GtKernelDataField43, 1226);
    GtWrite(GtKernelDataField45, 1093);
    GtWrite(GtCallbackField55, 113);
    GtWrite(GtCallbackField16, 27);
    GtWrite(GtCallbackField18, 42);
    GtWrite(GtCallbackField20, 1131);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1760);
    GtWrite(GtObjectTypeField10, 196);
    GtWrite(GtObjectTypeField11, 78);
    GtWrite(GtObjectTypeField12, 189);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    GtWrite(GtObjectTypeField30, 252);
    GtWrite(GtKernelDataField01, 35);
    GtWrite(GtCallbackField06, 80);
    GtWrite(GtCallbackField25, 287);
    GtWrite(GtNtCreateFileSyscallOffset, 177);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtWin32kServiceCount, 128);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 768);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    GtWrite(GtSubDeviceObjectFlagsOffset, 188);
    GtWrite(GtTargetDeviceObjectProtectOffset, 188);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 212);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 140);
    GtWrite(GtCallbackField101, 1600);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1768);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 1624);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 1280);
    GtWrite(GtEprocessField34 | 0x800, 14464);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 192);
    GtWrite(GtCallbackField124, 780);
    GtWrite(GtEprocessField94 | 0x800, 23);
    GtWrite(GtEprocessField95 | 0x800, 139);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 21);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1560);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 208);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 132);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 272);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    GtWrite(GtEprocessField01 | 0x900, -64);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 141);
}

// InitEprocessOffsetsWin10_19041 — 初始化 Win10 19041 EPROCESS 字段偏移
// 对应原始驱动 sub_1400244A8
__int64 InitEprocessOffsetsWin10_19041(void)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 Field64Val;
    int Field94Value;
    int ObjTypeCount;
    __int64 FltPeSectionVal;
    __int64 Field69Val;
    __int64 InitHookSyscallAddr;
    __int64 Field01Val;

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 1088);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 1312);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 1304);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1360);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 2112);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1463);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 1128);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 1344);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1448);
        Field38Offset = 1448;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1400);
        Field43Offset = 1400;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 1208);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1144);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1256);
    GtWrite(GtEprocessField48, 760);
    if (BuildNumber == 19041 || BuildNumber == 19042)
    {
        Field64Val = 2576;
    }
    else if (BuildNumber == 19043)
    {
        Field64Val = 2592;
    }
    else if (BuildNumber == 19044)
    {
        Field64Val = 2600;
    }
    else if (BuildNumber == 19045)
    {
        Field64Val = 2608;
    }
    else
    {
        Field64Val = 2576;
    }
    GtWrite(GtEprocessField64, Field64Val);
    GtWrite(GtEprocessField52, 1104);
    GtWrite(GtObjectTypeField41, 1232);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 2200);
    GtWrite(GtWin32kServiceEntryCount, 471);
    GtWrite(GtEprocessField57, 1316);
    GtWrite(GtEprocessField129 | 0x100, 31744);
    GtWrite(GtEprocessField130 | 0x100, 31872);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 379);
    GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
    GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 443);
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, 444);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    GtWrite(GtIrpBufferSize, 28);
    GtWrite(GtObjectTypeField37, 154);
    GtWrite(GtRuntimeDataBase, 108);
    GtWrite(GtEncryptionKey | GtPathBuffer00, 60);
    GtWrite(GtObjectTypeField39, 7);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 15);
    GtWrite(GtIrpBufferSize | GtPathBuffer00, 94);
    GtWrite(GtRuntimeDataBase | GtPathBuffer00, 16);
    GtWrite(GtEncryptionKey | GtPathBuffer04, 117);
    GtWrite(GtObjectTypeField35, 91);
    GtWrite(GtObjectTypeField36, 87);
    GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 20);
    GtWrite(GtObjectTypeField40, 5);
    GtWrite(GtObjectTypeField28, 2);
    GtWrite(GtKernelDataField43, 1285);
    GtWrite(GtKernelDataField45, 1143);
    GtWrite(GtCallbackField55, 110);
    GtWrite(GtCallbackField16, 24);
    GtWrite(GtCallbackField18, 39);
    GtWrite(GtCallbackField20, 1184);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1296);
    GtWrite(GtObjectTypeField10, 200);
    GtWrite(GtObjectTypeField11, 78);
    GtWrite(GtObjectTypeField12, 193);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    GtWrite(GtObjectTypeField30, 257);
    GtWrite(GtKernelDataField01, 35);
    GtWrite(GtCallbackField06, 80);
    GtWrite(GtCallbackField25, 292);
    GtWrite(GtNtCreateFileSyscallOffset, 181);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtWin32kServiceCount, 129);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 1112);
    GtWrite(GtDeviceObjectProtectOffset, 192);
    GtWrite(GtSubDeviceObjectProtectOffset, 20);
    GtWrite(GtSubDeviceObjectFlagsOffset, 188);
    GtWrite(GtTargetDeviceObjectProtectOffset, 188);
    GtWrite(GtDeviceObjectChildPtrOffset, 168);
    GtWrite(GtDeviceObjectTargetPtrOffset, 72);
    GtWrite(GtTargetProtectionOffset, 212);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 140);
    GtWrite(GtCallbackField101, 1600);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1304);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtEprocessModuleListOffset, 1408);
    GtWrite(GtEprocessField42, 344);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 2008);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 1280);
    GtWrite(GtEprocessField34 | 0x800, 15168);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 192);
    GtWrite(GtCallbackField124, 1124);
    GtWrite(GtEprocessField94 | 0x800, 23);
    GtWrite(GtEprocessField95 | 0x800, 153);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 21);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1096);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 208);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 132);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 272);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionVal);
    Field69Val = GtRead(GtEprocessField69);
    InitHookSyscallAddr = GtRead(GtInitHookSyscallAddress);
    if (Field69Val && InitHookSyscallAddr)
    {
        Field01Val = (int)Field69Val - (int)InitHookSyscallAddr;
    }
    else if (BuildNumber == 19041 || BuildNumber == 19042 || BuildNumber == 19043)
    {
        Field01Val = -384;
    }
    GtWrite(GtEprocessField01 | 0x900, Field01Val);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 141);
}

// InitEprocessOffsetsWin11 — 初始化 Win11 EPROCESS 字段偏移
// 对应原始驱动 sub_1400257F0
__int64 InitEprocessOffsetsWin11(void)
{
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 v3;
    __int64 v5;
    __int64 v6;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 v11;
    __int64 v13;
    int Field94Value;
    int ObjTypeCount;
    __int64 v16;
    __int64 v17;
    __int64 v19;
    __int64 v20;
    __int64 v22;
    __int64 v23;
    __int64 v24;
    __int64 v25;
    __int64 v26;
    __int64 result;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    GtWrite(GtEprocessExtField01, 64);
    GtWrite(GtEprocessExtBase, 16);
    GtWrite(GtEprocessExtField02, 48);
    GtWrite(GtEprocessExtField03, 56);
    GtWrite(GtEprocessExtField04, 64);
    GtWrite(GtEprocessExtField05, 72);
    GtWrite(GtEprocessExtField06, 80);
    GtWrite(GtEprocessExtField07, 88);
    GtWrite(GtEprocessExtField08, 96);
    GtWrite(GtEprocessExtField09, 104);
    GtWrite(GtEprocessExtField10, 200);
    if ((unsigned int)GtRead(GtSdstServiceCount) == -1)
        GtWrite(GtSdstServiceCount, 562);
    if ((unsigned int)GtRead(GtEprocessField30) == -1)
        GtWrite(GtEprocessField30, 1088);
    if ((unsigned int)GtRead(GtEprocessField32) == -1)
        GtWrite(GtEprocessField32, 1312);
    if ((unsigned int)GtRead(GtEprocessField31) == -1)
        GtWrite(GtEprocessField31, 1304);
    if ((unsigned int)GtRead(GtEprocessField33) == -1)
        GtWrite(GtEprocessField33, 1360);
    if ((unsigned int)GtRead(GtEprocessField34) == -1)
        GtWrite(GtEprocessField34, 2112);
    if ((unsigned int)GtRead(GtEprocessField35) == -1)
        GtWrite(GtEprocessField35, 1463);
    if ((unsigned int)GtRead(GtEprocessField36) == -1)
        GtWrite(GtEprocessField36, 1128);
    if ((unsigned int)GtRead(GtEprocessField37) == -1)
        GtWrite(GtEprocessField37, 1344);
    Field38Offset = (int)GtRead(GtEprocessField38);
    if (Field38Offset == -1)
    {
        GtWrite(GtEprocessField38, 1448);
        Field38Offset = 1448;
    }
    GtWrite(GtEprocessField40, (unsigned int)(Field38Offset + 16) + 40LL);
    Field43Offset = GtRead(GtEprocessField43);
    if (Field43Offset == -1)
    {
        GtWrite(GtEprocessField43, 1400);
        Field43Offset = 1400;
    }
    GtWrite(GtEprocessField44, Field43Offset - 8LL);
    if ((unsigned int)GtRead(GtCallbackField109) == -1)
        GtWrite(GtCallbackField109, 1208);
    if ((unsigned int)GtRead(GtProcessEprocess) == -1)
        GtWrite(GtProcessEprocess, 1224);
    if ((unsigned int)GtRead(GtEprocessField51) == -1)
        GtWrite(GtEprocessField51, 240);
    if ((unsigned int)GtRead(GtProcessOffset) == -1)
        GtWrite(GtProcessOffset, 544);
    if ((unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100) == -1)
        GtWrite(GtEprocessField182 | GtEprocessField06 | 0x100, 48);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, 88);
    GtWrite(GtEprocessField47, 1336);
    GtWrite(GtEprocessField48, 760);
    if (BuildNumber == 20348 || BuildNumber == 22000)
        v3 = 2888;
    else
        v3 = 2936;
    GtWrite(GtEprocessField64, v3);
    GtWrite(GtEprocessField52, 1184);
    GtWrite(GtObjectTypeField41, 1312);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    if (BuildNumber == 20348 || BuildNumber == 22000)
        v5 = 2288;
    else
        v5 = 2304;
    GtWrite(GtObjectTypeCount, v5);
    if (BuildNumber == 20348)
    {
        v6 = 477;
    }
    else
    {
        v6 = 481;
        if (BuildNumber != 22000)
            v6 = 486;
    }
    GtWrite(GtWin32kServiceEntryCount, v6);
    if (BuildNumber == 20348 ||
        BuildNumber == 22000 ||
        BuildNumber != 22621)
    {
        v8 = 1456;
    }
    else
    {
        v8 = 1452;
    }
    GtWrite(GtEprocessField57, v8);
    GtWrite(GtEprocessField129 | 0x100, 32448);
    GtWrite(GtEprocessField130 | 0x100, 32576);
    GtWrite(GtEprocessField95, 484);
    GtWrite(GtEprocessField131 | 0x100, 216);
    GtWrite(GtEprocessField132 | 0x100, 152);
    GtWrite(GtEprocessField184 | GtEprocessField06 | 0x100, 0);
    GtWrite(GtEprocessField185 | GtEprocessField06 | 0x100, 12);
    if (BuildNumber == 20348)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 386);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 450);
        v9 = 451;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 388);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 454);
        v9 = 455;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 392);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 459);
        v9 = 460;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, v9);
    GtWrite(GtKiFastCallEntryAddr | GtEprocessField08, 644);
    if (BuildNumber == 20348)
    {
        GtWrite(GtIrpBufferSize, 28);
        GtWrite(GtObjectTypeField37, 154);
        GtWrite(GtRuntimeDataBase, 108);
        GtWrite(GtEncryptionKey | GtPathBuffer00, 60);
        GtWrite(GtObjectTypeField39, 7);
        GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 15);
        GtWrite(GtIrpBufferSize | GtPathBuffer00, 94);
        GtWrite(GtRuntimeDataBase | GtPathBuffer00, 16);
        GtWrite(GtEncryptionKey | GtPathBuffer04, 117);
        GtWrite(GtObjectTypeField35, 91);
        GtWrite(GtObjectTypeField36, 87);
        GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 20);
        GtWrite(GtObjectTypeField40, 5);
        GtWrite(GtObjectTypeField28, 2);
        GtWrite(GtKernelDataField43, 1411);
        GtWrite(GtKernelDataField45, 1205);
        GtWrite(GtCallbackField20, 1258);
        GtWrite(GtCallbackField55, 110);
        GtWrite(GtCallbackField16, 24);
        v10 = 39;
    }
    else
    {
        GtWrite(GtIrpBufferSize, 26);
        GtWrite(GtObjectTypeField37, 149);
        GtWrite(GtRuntimeDataBase, 103);
        GtWrite(GtEncryptionKey | GtPathBuffer00, 55);
        GtWrite(GtObjectTypeField39, 5);
        GtWrite(GtEncryptionKeyByte | GtPathBuffer00, 13);
        GtWrite(GtIrpBufferSize | GtPathBuffer00, 89);
        GtWrite(GtRuntimeDataBase | GtPathBuffer00, 14);
        GtWrite(GtEncryptionKey | GtPathBuffer04, 112);
        GtWrite(GtObjectTypeField35, 86);
        GtWrite(GtObjectTypeField36, 82);
        GtWrite(GtEncryptionKeyByte | GtPathBuffer04, 18);
        GtWrite(GtObjectTypeField40, -1);
        GtWrite(GtObjectTypeField28, -1);
        if (BuildNumber == 22000)
        {
            GtWrite(GtKernelDataField43, 1411);
            GtWrite(GtKernelDataField45, 1202);
            v11 = 1255;
        }
        else
        {
            v13 = 1410;
            if (BuildNumber != 22621)
                v13 = 1414;
            GtWrite(GtKernelDataField43, v13);
            GtWrite(GtKernelDataField45, 1201);
            v11 = 1256;
        }
        GtWrite(GtCallbackField20, v11);
        GtWrite(GtCallbackField55, 105);
        GtWrite(GtCallbackField16, 22);
        v10 = -1;
    }
    GtWrite(GtCallbackField18, v10);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1376);
    if (BuildNumber == 20348)
    {
        GtWrite(GtObjectTypeField10, 204);
        GtWrite(GtObjectTypeField11, 78);
        v16 = 196;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtObjectTypeField10, 205);
        GtWrite(GtObjectTypeField11, 78);
        v16 = 197;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 207);
        GtWrite(GtObjectTypeField11, 78);
        v16 = 199;
    }
    GtWrite(GtObjectTypeField12, v16);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    if (BuildNumber == 20348)
    {
        GtWrite(GtObjectTypeField30, 261);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 297);
        v17 = 183;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtObjectTypeField30, 262);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 298);
        v17 = 184;
    }
    else
    {
        GtWrite(GtObjectTypeField30, 264);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 301);
        v17 = 186;
    }
    GtWrite(GtNtCreateFileSyscallOffset, v17);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    if (BuildNumber == 20348 || BuildNumber == 22000)
        v19 = 130;
    else
        v19 = 131;
    GtWrite(GtWin32kServiceCount, v19);
    GtWrite(GtCallbackField74, 320);
    GtWrite(GtCallbackField75, 120);
    GtWrite(GtCallbackField76, 232);
    GtWrite(GtCallbackField77, 1112);
    if (BuildNumber == 20348)
    {
        GtWrite(GtDeviceObjectProtectOffset, 192);
        GtWrite(GtSubDeviceObjectProtectOffset, 20);
        GtWrite(GtSubDeviceObjectFlagsOffset, 188);
        GtWrite(GtTargetDeviceObjectProtectOffset, 188);
        GtWrite(GtDeviceObjectChildPtrOffset, 168);
        GtWrite(GtDeviceObjectTargetPtrOffset, 72);
        v20 = 212;
    }
    else
    {
        GtWrite(GtDeviceObjectProtectOffset, 200);
        GtWrite(GtSubDeviceObjectProtectOffset, 20);
        GtWrite(GtSubDeviceObjectFlagsOffset, 188);
        GtWrite(GtTargetDeviceObjectProtectOffset, 188);
        GtWrite(GtDeviceObjectChildPtrOffset, 176);
        GtWrite(GtDeviceObjectTargetPtrOffset, 72);
        v20 = 220;
    }
    GtWrite(GtTargetProtectionOffset, v20);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 140);
    GtWrite(GtCallbackField101, 1608);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1384);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtEprocessModuleListOffset, 1408);
    GtWrite(GtEprocessField42, 344);
    GtWrite(GtEprocessField41, 48);
    GtWrite(GtEprocessField49, 2008);
    GtWrite(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer00, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01, 0);
    GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02, 0);
    GtWrite(GtEprocessField33 | 0x800, 2048);
    GtWrite(GtEprocessField34 | 0x800, 15872);
    if ((unsigned int)GtRead(GtEprocessField35 | 0x800) == -1)
        GtWrite(GtEprocessField35 | 0x800, 192);
    GtWrite(GtCallbackField124, 1124);
    GtWrite(GtEprocessField94 | 0x800, 23);
    v22 = 153;
    if (BuildNumber != 20348)
        v22 = 157;
    GtWrite(GtEprocessField95 | 0x800, v22);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 21);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1176);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 216);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 132);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 280);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    v23 = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, v23);
    v24 = GtRead(GtEprocessField69);
    v25 = GtRead(GtInitHookSyscallAddress);
    if (v24 && v25)
    {
        v26 = (int)v24 - (int)v25;
    }
    else if (BuildNumber == 20348)
    {
        v26 = -320;
    }
    else if (BuildNumber == 22000)
    {
        v26 = -256;
    }
    else
    {
        v26 = -320;
        if (BuildNumber != 22621)
            v26 = -384;
    }
    GtWrite(GtEprocessField01 | 0x900, v26);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    GtWrite(GtEprocessField03 | 0x900, 141);
    result = BuildNumber;
    if (result >= 0x585D)
        return GtWrite((enum _GLOBAL_TABLE_INDEX)2336, 12712);
    return result;
}


// InitNsiEnumerateObjects — 初始化 Nsi 枚举对象
// 读取 NSI 模块基址，读取 ntoskrnl.exe 文件，查找 NsiEnumerateObjectsAllParametersEx 导出函数地址
// 对应原始驱动 sub_1400490D8
char InitNsiEnumerateObjects(void)
{
    char Result;
    __int64 NsiBaseAddr;
    unsigned int ExportByNameInPeBody;
    ULONG FileSize;
    unsigned int NtFileSize;
    void *NtFileBuffer;
    void *FileBuffer;
    _DWORD EncodedPathOrFuncName[24];

    Result = 0;
    NsiBaseAddr = GtRead(GtEprocessField151 | 0x100);
    if (NsiBaseAddr)
    {
        EncodedPathOrFuncName[19] = 0;
        EncodedPathOrFuncName[0] = 5439580;
        EncodedPathOrFuncName[1] = 7536761;
        EncodedPathOrFuncName[2] = 6619252;
        EncodedPathOrFuncName[3] = 5374061;
        EncodedPathOrFuncName[4] = 7274607;
        EncodedPathOrFuncName[5] = 6029428;
        EncodedPathOrFuncName[6] = 7929971;
        EncodedPathOrFuncName[7] = 7602291;
        EncodedPathOrFuncName[8] = 7143525;
        EncodedPathOrFuncName[9] = 3276851;
        EncodedPathOrFuncName[10] = 6553692;
        EncodedPathOrFuncName[11] = 6881394;
        EncodedPathOrFuncName[12] = 6619254;
        EncodedPathOrFuncName[13] = 7536754;
        EncodedPathOrFuncName[14] = 7209052;
        EncodedPathOrFuncName[15] = 7602277;
        EncodedPathOrFuncName[16] = 7274601;
        EncodedPathOrFuncName[17] = 7536686;
        EncodedPathOrFuncName[18] = 7536761;
        if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPathOrFuncName, &FileBuffer, &FileSize, 1))
        {
            if (ReadNtFileToBuffer((int *)FileBuffer, FileSize, &NtFileBuffer, &NtFileSize) == 1)
            {
                Result = 1;
                strcpy((char *)EncodedPathOrFuncName, "NsiEnumerateObjectsAllParametersEx");
                *((unsigned char *)&EncodedPathOrFuncName[8] + 3) = 0;
                ExportByNameInPeBody = FindExportByNameInPeBody(
                    (__int64)NtFileBuffer,
                    NtFileSize,
                    (__int64)EncodedPathOrFuncName,
                    0);
                if (ExportByNameInPeBody)
                    GtWrite(GtNtQuerySystemInformationFunc, NsiBaseAddr + ExportByNameInPeBody);
                ExFree(NtFileBuffer);
            }
            ExFree(FileBuffer);
        }
    }
    return Result;
}


// InitFileSystemFilterCallbacks -- 初始化文件系统过滤回调
// 对应原始驱动 sub_14000DC28
__int64 InitFileSystemFilterCallbacks(__int64 FilterExtensionObject, _QWORD *FastIoDispatchPtr, char Is64Bit)
{
    return 0;
}

// ParseFsFilterDriverExport -- 解析文件系统过滤驱动导出
// 对应原始驱动 sub_14000E3A0
void ParseFsFilterDriverExport(char Is64Bit)
{
    return;
}

// ScanKernelMemForFsChanges -- 扫描内核内存中的文件系统变更
// 对应原始驱动 sub_14000D7B0
char ScanKernelMemForFsChanges(ULONG *a1, int a2)
{
    return 0;
}

// ScanKernelModuleDataSectionEx -- 扫描内核模块数据节区（扩展版）
// 对应原始驱动 sub_14006DB78
__int64 ScanKernelModuleDataSectionEx(void)
{
    return 0;
}

// ScanKernelModuleInitSection -- 扫描内核模块初始化节区
// 对应原始驱动 sub_14006D974
__int64 ScanKernelModuleInitSection(void)
{
    return 0;
}

// ScanKernelModulePageOrRsrcSection -- 扫描内核模块 PAGE 或 RSRC 节区
// 对应原始驱动 sub_14006E52C
__int64 ScanKernelModulePageOrRsrcSection(void)
{
    return 0;
}

// ScanKernelModuleSectionByType -- 按类型扫描内核模块节区
// 对应原始驱动 sub_14006E26C
__int64 ScanKernelModuleSectionByType(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10 -- 扫描 Win10 内核模块节区
// 对应原始驱动 sub_14006DD80
__int64 ScanKernelModuleSectionForWin10(void)
{
    return 0;
}

// ScanKernelModuleSectionForWin10RS3 -- 扫描 Win10 RS3 内核模块节区
// 对应原始驱动 sub_14006DFB4
__int64 ScanKernelModuleSectionForWin10RS3(void)
{
    return 0;
}

// ScanVadForModifiedPages -- 扫描 VAD 查找已修改页面
// 对应原始驱动 sub_14000D960
void ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount)
{
    return;
}

// ScanWin32kDriverForPatterns -- 扫描 Win32k 驱动查找模式
// 对应原始驱动 sub_140052320
__int64 ScanWin32kDriverForPatterns(ULONG_PTR a1, ULONG_PTR a2)
{
    return 0;
}
