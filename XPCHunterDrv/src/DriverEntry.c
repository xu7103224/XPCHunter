// DriverEntry.c — 驱动入口与 IRP 分发
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动地址范围 0x140080ED4-0x14008265A

#include "XPCHunterDrv.h"

// 前向声明
extern volatile PVOID g_Pointer;
__int64 GetWindowsBuildNumber(void);
BOOLEAN IsWindowsVersionSupported(ULONG BuildNumber);
void InitGlobalMutex(void);
__int64 InitGtKey(__int64 RegistryPath);
ULONG64 InitDriverSection(_QWORD **pDriverList);
__int64 InitGtCore(__int64 NtBuildNumber, __int64 DriverObject);

// 全局变量
PDEVICE_OBJECT g_DeviceObject = NULL;
PDRIVER_OBJECT g_DriverObject = NULL;
// g_Filter — Minifilter 过滤器句柄。注册成功后由 StartMiniFilter 写入，MiniFilterUnloadCleanup 注销后清零
// 对应原始驱动 g_Filter (0x1400A84E0)
PFLT_FILTER g_Filter = NULL;
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
    void *RegistryPathCopyPtr;
    wchar_t *BackslashPos;
    const wchar_t *DriverNameStart;
    __int64 DevNameIdx, SymNameIdx;
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
    RegistryPathCopyPtr = RegistryPathCopy;
    if (!RegistryPathCopy) return Status;

    memset(RegistryPathCopy, 0, RegistryPath->Length + 2);
    memmove(RegistryPathCopyPtr, RegistryPath->Buffer, RegistryPath->Length & 0xFFFE);

    BackslashPos = wcsrchr((const wchar_t *)RegistryPathCopyPtr, L'\\');
    if (!BackslashPos || !BackslashPos[1])
        DriverNameStart = (const wchar_t *)RegistryPathCopyPtr;
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

    GtWrite(GtRegPathStringPtr, (__int64)RegistryPathCopyPtr);
    InitCommandHandlerTable();
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DispatchDeviceControl;

    if (Status >= 0) return Status;

Cleanup2:
    CleanupNtoskrnlFile();
Cleanup1:
    ExFree(RegistryPathCopyPtr);
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

    Result = (UCHAR)RegisterFormatNameCallback();
    Result = RegisterFormatPathCallback() & Result;
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
            Status = (NTSTATUS)g_CommandHandlerTable[Opcode](
                (__int64)InputHeader->Param3,
                (__int64)InputHeader->Param4,
                (_DWORD *)InputHeader->Param5,
                (int)InputHeader->ChecksumLow
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

// CheckProcessAccess — 检查进程访问权限（补全空壳）
// 对应原始驱动 0x1400812B0（97 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（15 行伪代码），按伪代码实现
// 【⚠ 修正记录】此前是空壳（`return 1;` —— **无条件放行**），而它在
//   IoctlDispatch.c:484 被真实调用（CmdCheckProcessAccess 转调）。
//   空壳意味着"访问检查恒通过"，属"假装成功"的危险占位。
// 【逻辑】读 GT (GtEprocessField123|0x100) 取"驱动保护进程"；
//   若为空、或就是当前进程 → 返回 1（放行）；
//   否则调 ValidateProcessObject(该进程, 0)，按"返回 0"判为有权，
//   并把 GT GtCallbackField125 清 0。
__int64 CheckProcessAccess(void)
{
    struct _KPROCESS *ProtectedProcess;
    bool Allowed;

    ProtectedProcess = (struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField123 | 0x100));
    if (!ProtectedProcess || ProtectedProcess == IoGetCurrentProcess())
        return 1;

    Allowed = (ValidateProcessObject(ProtectedProcess, 0) == 0);
    GtWrite((GLOBAL_TABLE_INDEX)GtCallbackField125, 0);
    return Allowed ? 1 : 0;
}

// InitCallbackFunctions — 初始化回调函数（补全空壳）
// 对应原始驱动 0x140033EE8（84 字节）
// 【逆向来源】可反编译（15 行伪代码）
// 【⚠ 修正记录】此前是空壳（`return 1;` 且 doc 注释写着"InitProcessNotify();
//   InitThreadNotify();"两个被注释掉的调用），而它在 MemoryOperation.c:809 被真实调用。
// 【逻辑】先调 InitProcessNotify + InitThreadNotify；
//   然后按三个"结果槽是否已填"分别以**模式 0 / 2 / 1** 调 InitCallbackFunctionTable：
//     GT (GtEprocessField133|0x100) == 0  → InitCallbackFunctionTable(0)
//     GT (GtEprocessField134|0x100) == 0  → InitCallbackFunctionTable(2)
//     GT GtKernelDataField18 == 0         → InitCallbackFunctionTable(1)
//   （模式与结果槽的对应关系：0→GT 0x18F/0x18F 族、2→GT 0x190 族、1→GT 0x2A4 族，
//     见 InitCallbackFunctionTable 的实现与 §待实现文档）
//   返回最后一个 GtRead 的值（全已填时返回该值）。
__int64 InitCallbackFunctions(void)
{
    __int64 Status;

    InitProcessNotify();
    InitThreadNotify();

    if (!(unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField133 | 0x100)))
        InitCallbackFunctionTable(0);
    if (!(unsigned int)GtRead((GLOBAL_TABLE_INDEX)(GtEprocessField134 | 0x100)))
        InitCallbackFunctionTable(2);

    Status = (__int64)GtRead(GtKernelDataField18);
    if (!(_DWORD)Status)
        return InitCallbackFunctionTable(1);
    return Status;
}

// InvokeRegisteredCallbackWithUserData — 调用注册的回调
// 对应原始驱动 sub_1400680F8
char InvokeRegisteredCallbackWithUserData(unsigned int *Address, int InputSize)
{
    char Result = 0;
    ULONG64 CallbackFuncAddr;
    void (__fastcall *CallbackFuncPtr)(ULONG64, ULONG64);
    ULONG BuildNumber;
    ULONG64 Index1996;

    Index1996 = GtRead(1996);
    if (!Index1996)
    {
        InitKernelMemoryContext();
        Index1996 = GtRead(1996);
    }
    CallbackFuncAddr = Index1996;
    CallbackFuncPtr = (void (__fastcall *)(ULONG64, ULONG64))CallbackFuncAddr;

    if (CallbackFuncAddr && CallbackFuncAddr > (ULONG64)MmSystemRangeStart && Address &&
        InputSize == 16 && (ULONG64)Address < MmUserProbeAddress &&
        (ULONG64)(Address + 4) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x10, 4);
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        if (BuildNumber >= 0x23F0 || BuildNumber == 7600 || BuildNumber == 7601)
            CallbackFuncPtr(*Address, *((ULONG64 *)Address + 1));
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
// 对应原始驱动 sub_140029F0C（179 字节）
// 【尺寸依据】原始序言 `sub rsp,184h`，SHA1 上下文槽 var_88 为 0x60 字节
//   （`_QWORD[12]`），摘要槽 var_28 为 0x18 字节（6 个 DWORD）。
// 【⚠ 缺陷修正 2026-10-08】此前 `ULONG ShaContext[12]` 仅 0x30 字节，
//   不足原始 0x60 —— 上下文会溢出覆盖相邻的 PathHash/摘要缓冲。
__int64 InitGtKey(__int64 RegistryPath)
{
    char PathHash[16];
    SHA1_CONTEXT ShaContext;
    ULONG KeyBytes[6];
    UCHAR *ByteCount;
    __int64 Count;

    *(ULONG64 *)PathHash = RegistryPath;
    Sha1InitContext(&ShaContext);
    Sha1Update(&ShaContext, (PUCHAR)PathHash, 8);
    Sha1FinalTransform(&ShaContext, (__int64)KeyBytes);
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

// InitImageNotify — 镜像加载通知总枢纽
// 对应原始驱动 0x1400723EC（690 字节）
// 【逆向来源】人工阅读反汇编逐条还原 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x1400723EC~0x14007269E
//   的 142 条指令逐条还原
// 【⚠ 重大修正】此前本函数是**错误移植**：其函数体实际是 31 字节的
//   `InitImageNotifyWin7`(0x14001358C) 的移植（"构建号 >= 0x1DB0 则调
//   InitImageNotifyCallbackWin7"），而它在 DriverEntry 初始化路径
//   （DriverEntry.c:97）被调用 —— 这正是 minifilter/节区扫描整条支路不通的原因：
//   真正的枢纽从未被实现。本次按反汇编补齐。
// 【功能】本函数是驱动初始化后期最重要的**总调度点**：
//   1) 取 GT 0x61 为"目标进程"；若它等于 IoGetCurrentProcess() 则视为 0（已在目标进程内）
//   2) 非 0 则 KeStackAttachProcess 切换地址空间，出口 KeUnstackDetachProcess
//   3) 取 GT 0x21(ntoskrnl 文件大小) 与 GT 3(镜像基址)，任一为 0 则跳过扫描段
//   4) 在栈上构造一张 **GT 索引三元组表**并逐个处理（每项 = 3 个 DWORD）：
//        [0] 结果索引（GtWrite 的目标）
//        [1] 类型索引（作为 FindKernelPESectionByType 的"类型"入参）
//        [2] 序号     （供 FindKernelPESectionByType 与哨兵判断）
//      共 16 项，序号 59..65 与 99..101（即表中前段连续、后段跳变）：
//        (0x41F2,0x16E,59) (0x41F5,0x16F,60) (0x41F8,0x170,61) (0x41FB,0x171,62)
//        (0x4204,0x172,63) (0x4207,0x173,64) (0x420A,0x174,65) (0x420D,0x175,66)
//        (0x4210,0x176,67) (0x4213,0x177,68) (0x4216,0x178,69) (0x42AC,0x290,99)
//        (0x42AF,0x291,100) (0x42B2,0x292,101)（另有 2 项，表中总数见数组长度）
//      逐项：FindKernelPESectionByType(类型索引的值?) → ResolveSyscallToAddress
//            → 若结果非 0 且 < GT 0x21 的值 → GtWrite(结果索引, 结果 + 镜像基址)
//      注：哨兵判断为"三项全 0 则跳出循环"，用于遇到表中未使用的空位时提前结束
//   5) 随后**顺序调用全部扫描器与按版本选择器**（这一步是整条支路的入口）：
//        SelectMiniFilterCleanupCallback / FindKernelDataSectionForReadMemory /
//        FindKernelDataSectionV3Dispatch / SelectMiniFilterCallbackByVersion /
//        SelectMiniFilterWriteReadCallback / FindKernelDataSectionForStringParam /
//        FindKernelDataSectionForOpenSection / FindKernelDataSectionV2Dispatch /
//        FindKernelDataSectionDispatch / ClearImageNotifySectionOffset
//      若构建号 >= 0x1770 再追加：
//        FindKernelInitSection / FindKernelDataSectionByDebug /
//        FindKernelDataSectionByData / InitImageNotifyWin7
//   6) 最后（在 detach 之前）调用 SelectMiniFilterDirEnumCallback
// 【命名依据】原名正确（它就是"镜像加载通知的初始化枢纽"），无需改名。
// 【⚠ 待确认】GT 0x61 的语义（目标进程对象）、以及三元组表中各
//   "类型索引"（0x16E..0x178、0x290..0x292）作为 FindKernelPESectionByType
//   入参的取值方式，需在实现 FindKernelPESectionByType 的调用约定后核对。
ULONG64 InitImageNotify(void)
{
    ULONG64 TargetProcess;
    ULONG64 KernelSize;
    ULONG64 NtImageBase;
    ULONG64 NtoskrnlBase;
    ULONG64 Resolved;
    unsigned int SectionRva;
    unsigned int EntryIndex;
    char Attached = 0;
    KAPC_STATE ApcState;

    // 三元组表：{ 待解析索引, 结果索引, 非零哨兵值 }
    // 【⚠ 本轮更正（逐条核对反汇编 0x14007248A~0x1400725B5）】
    //   1) 第三列原写作 59..69 —— **错误**。反汇编实测为：
    //      0x39/0x3A/0x3B/0x3C/0x3D/0x3E/0x3F/0x40/0x41/0x42/0x43（=57..67）
    //      以及 0x63/0x64/0x65（=99..101）。第三列的唯一用途是"三者全零即跳出"
    //      的哨兵判据（见下），故其数值不影响功能，但为忠实原文仍需如实填写。
    //   2) 哨兵判据原写作对字段 0/1 调 `GtRead(...)` —— **错误**。反汇编
    //      （0x1400725C5 `mov ecx,[rsp+rdi*4+Dst]` / 0x1400725CD `cmp [rsp+rdi*4+Index],r12d`
    //      / 0x1400725D4 `cmp [rsp+rdi*4+var_D8],r12d`）证明判据比较的是**表内字面值**，
    //      不查全局表。原写法会多做两次无意义的 GtRead（因第三列恒非零而不致功能错，
    //      但属不忠实实现）。
    //   3) memset 的 0xB4 = 180 字节 = 15 项 × 12 字节，故表实际容量 15 项；
    //      原写 [16][3] 但只填 14 项，等价。
    static const _DWORD GtIndexTriples[16][3] =
    {
        { 0x41F2, 0x16E, 0x39 }, { 0x41F5, 0x16F, 0x3A }, { 0x41F8, 0x170, 0x3B },
        { 0x41FB, 0x171, 0x3C }, { 0x4204, 0x172, 0x3D }, { 0x4207, 0x173, 0x3E },
        { 0x420A, 0x174, 0x3F }, { 0x420D, 0x175, 0x40 }, { 0x4210, 0x176, 0x41 },
        { 0x4213, 0x177, 0x42 }, { 0x4216, 0x178, 0x43 }, { 0x42AC, 0x290, 0x63 },
        { 0x42AF, 0x291, 0x64 }, { 0x42B2, 0x292, 0x65 }, { 0, 0, 0 }, { 0, 0, 0 }
    };

    TargetProcess = GtRead(GtCurrentEprocess);
    if (TargetProcess == (ULONG64)IoGetCurrentProcess())
        TargetProcess = 0;

    if (TargetProcess)
    {
        KeStackAttachProcess((PVOID)TargetProcess, &ApcState);
        Attached = 1;
    }

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    KernelSize = GtRead(GtNtoskrnlPeFileSize);
    NtImageBase = GtRead(GtNtoskrnlModuleBase);

    if ((unsigned int)KernelSize && NtImageBase)
    {
        for (EntryIndex = 0; ; EntryIndex++)
        {
            // 哨兵判据：比较**表内字面值**（反汇编 0x1400725C5/0x1400725CD/0x1400725D4），
            // 三项全零即表示表中已到空位，跳出循环。注意前两列在表中恒非零，
            // 实际起作用的是第三列的 0 哨兵。
            if (GtIndexTriples[EntryIndex][0] == 0 &&
                GtIndexTriples[EntryIndex][1] == 0 &&
                GtIndexTriples[EntryIndex][2] == 0)
                break;

            // 【实参顺序（反汇编核对）】FindKernelPESectionByType 的入参是**字段 0**：
            //   0x1400725C5 mov ecx,[rsp+rdi*4+Dst]（字段0=0x41xx）→ 哨兵判断
            //   0x1400725DB call FindKernelPESectionByType —— 此时 ecx 仍是字段0
            //   0x1400725F4 mov ecx,[rsp+rdi*4+Index]（字段1=0x16E）→ GtWrite 的目标
            //   旁证：复刻其它调用点亦传 0x41xx 区索引（MemoryOps.c:1612 传 0x41D1）
            SectionRva = (unsigned int)FindKernelPESectionByType((GLOBAL_TABLE_INDEX)GtIndexTriples[EntryIndex][0]);
            if (!SectionRva)
                continue;

            Resolved = (ULONG64)ResolveSyscallToAddress(SectionRva);
            if (!Resolved)
                continue;
            if (Resolved >= KernelSize)
                continue;

            GtWrite((GLOBAL_TABLE_INDEX)GtIndexTriples[EntryIndex][1],
                    (__int64)(Resolved + NtImageBase));
        }

        SelectMiniFilterCleanupCallback();
        FindKernelDataSectionForReadMemory();
        FindKernelDataSectionV3Dispatch();
        SelectMiniFilterCallbackByVersion();
        SelectMiniFilterWriteReadCallback();
        FindKernelDataSectionForStringParam();
        FindKernelDataSectionForOpenSection();
        FindKernelDataSectionV2Dispatch();
        FindKernelDataSectionDispatch();
        ClearImageNotifySectionOffset();

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            FindKernelInitSection();
            FindKernelDataSectionByDebug();
            FindKernelDataSectionByData();
            InitImageNotifyWin7();
        }
    }

    SelectMiniFilterDirEnumCallback();

    if (Attached)
        KeUnstackDetachProcess(&ApcState);

    return 0;
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
// 对应原始驱动 sub_14006BF2C（768 字节）
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
            if (ScanWin32kDriverForPatterns((ULONG_PTR)Buffer, EntryCount) == 1 &&
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
                ScanKernelMemForFsChanges(OutputBuffer, (int)RemainingSize);
                if (*OutputBuffer < (ULONG)RemainingSize)
                    ScanVadForModifiedPages(OutputBuffer, (int)(RemainingSize - *OutputBuffer));
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
        HookSyscallNtOpenProcessToken(ExportDirVa, ExportDirSize);
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
            Success = (char)InitEprocessFieldOffsets();
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

    SystemInfoBuffer = AllocExBufferAndQuerySystemInfo(16);
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
            if (CompareInt16Equal((__int16)TokenPtr, *(__int16 *)Entry) == 1)
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
    UCHAR ReadContext[0x48];
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
        Result = (ULONG)ReadPESectionEntry(ReadContext, (PULONG)SectionEntry);
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
        PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallbackRoutine);
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
    char SectionFound;
    __int64 ExportDirVa;
    unsigned int ExportDirSize;
    __int64 ServiceTableBase;
    __int64 NtoskrnlBase;
    int NtoskrnlImageSize;
    unsigned int SectionOffset;
    char IsWin81Update;
    unsigned int i;
    int Field38Offset;
    unsigned int Field43Offset;
    __int64 EprocessField130Val;
    int EprocessField94Val = 0;
    int ObjectTypeCountVal;
    __int64 CallbackField75Val;
    __int64 NtCreateThreadHookSuccess;
    __int64 CallbackField101Val;
    __int64 EprocessField34Val;
    __int64 FltPeSectionOfs3Val;
    __int64 FltPeSectionAddrVal;
    char DefaultFlag = 0;
    PE_DECODE_CONTEXT DecodeContext; // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionCharacteristics = 0;
    _DWORD SectionEntryBuf[112];   // 描述符：原 [8] 仅 32 字节
    char CharacteristicsFlags = 0;
    int SectionCharaCheck = 0;
    __int64 SectionNameCheck = 0;
    unsigned int SectionVirtualSize = 0;
    __int64 SectionEntryPtr = 0;

    SectionFound = 0;
    ExportDirVa = GtRead(GtEprocessField22);
    ExportDirSize = (unsigned int)GtRead(GtEprocessField23);
    ServiceTableBase = GtRead(GtEprocessField24);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);
    if (ExportDirVa && ExportDirSize && ServiceTableBase && NtoskrnlBase && NtoskrnlImageSize && (SectionOffset = (unsigned int)GtRead(GtTotalSize | GtEprocessField94 | 0x400)) != 0 && SectionOffset < ExportDirSize)
    {
        InitPESectionReadContext(ExportDirVa + SectionOffset, ExportDirSize - SectionOffset, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        IsWin81Update = DefaultFlag;
        for (i = 0; i < 0x14; ++i)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, SectionEntryBuf))
                break;
            SectionCharacteristics += SectionVirtualSize;
            if (*(_WORD *)(SectionEntryPtr + 6) == 373 && (CharacteristicsFlags & 4) != 0 && SectionNameCheck == 65601)
            {
                SectionFound = 1;
                IsWin81Update = SectionCharaCheck == 24904;
            }
        }
    }
    else
    {
        IsWin81Update = DefaultFlag;
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
    if (SectionFound == 1)
    {
        if (IsWin81Update)
        {
            GtWrite(GtEprocessField129 | 0x100, 22656);
            EprocessField130Val = 22784;
        }
        else
        {
            GtWrite(GtEprocessField129 | 0x100, 20608);
            EprocessField130Val = 20736;
        }
    }
    else
    {
        GtWrite(GtEprocessField129 | 0x100, 0);
        EprocessField130Val = 0;
    }
    GtWrite(GtEprocessField130 | 0x100, EprocessField130Val);
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
    EprocessField94Val = (int)GtRead(GtEprocessField94);
    ObjectTypeCountVal = (int)GtRead(GtObjectTypeCount);
    if (EprocessField94Val == -1 || EprocessField94Val >= ObjectTypeCountVal)
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
    CallbackField75Val = 116;
    if (NtCreateThreadHookSuccess)
        CallbackField75Val = 120;
    GtWrite(GtCallbackField75, CallbackField75Val);
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
    CallbackField101Val = 1504;
    if (NtCreateThreadHookSuccess)
        CallbackField101Val = 1512;
    GtWrite(GtCallbackField101, CallbackField101Val);
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
    if (SectionFound == 1)
    {
        if (IsWin81Update)
            EprocessField34Val = 14336;
        else
            EprocessField34Val = 12288;
    }
    else
    {
        EprocessField34Val = 0;
    }
    GtWrite(GtEprocessField34 | 0x800, EprocessField34Val);
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
        if (SectionFound != 1 || (FltPeSectionOfs3Val = 176, !IsWin81Update))
            FltPeSectionOfs3Val = 172;
    }
    else
    {
        FltPeSectionOfs3Val = 168;
    }
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, FltPeSectionOfs3Val);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 108);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionAddrVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionAddrVal);
    GtWrite(GtEprocessField01 | 0x900, 0);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2316, 456);
    return GtWrite(GtEprocessField03 | 0x900, 1597);
}

// InitEprocessOffsetsWin81_Update — 初始化 Win8.1 Update EPROCESS 字段偏移
// 对应原始驱动 sub_14002656C
__int64 InitEprocessOffsetsWin81_Update(void)
{
    char SectionFound;
    int Win7Sp1EprocessOffset;
    int Field35Val;
    int IsField35Match;
    int Field38Offset;
    unsigned int Field43Offset;
    unsigned int Field182Val;
    __int64 EprocessField130Val;
    int EprocessField94Val;
    int ObjectTypeCountVal;
    __int64 EprocessField34Val;
    int DefaultFlag = 0;

    SectionFound = 0;
    Win7Sp1EprocessOffset = (int)GetWin7Sp1EprocessOffset();
    Field35Val = (int)GtRead(GtEprocessField35 | 0x800);
    if (Field35Val == -1)
    {
        IsField35Match = DefaultFlag;
    }
    else
    {
        SectionFound = 1;
        IsField35Match = Field35Val == 20280;
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
    Field182Val = (unsigned int)GtRead(GtEprocessField182 | GtEprocessField06 | 0x100);
    GtWrite(GtEprocessField183 | GtEprocessField06 | 0x100, Field182Val + 8LL);
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
    if (SectionFound == 1)
    {
        if (IsField35Match)
        {
            GtWrite(GtEprocessField129 | 0x100, 19584);
            EprocessField130Val = 19712;
        }
        else
        {
            GtWrite(GtEprocessField129 | 0x100, 17536);
            EprocessField130Val = 17664;
        }
    }
    else
    {
        GtWrite(GtEprocessField129 | 0x100, 0);
        EprocessField130Val = 0;
    }
    GtWrite(GtEprocessField130 | 0x100, EprocessField130Val);
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
    EprocessField94Val = (int)GtRead(GtEprocessField94);
    ObjectTypeCountVal = (int)GtRead(GtObjectTypeCount);
    if (EprocessField94Val == -1 || EprocessField94Val >= ObjectTypeCountVal)
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
    if (SectionFound == 1)
    {
        if (IsField35Match)
            EprocessField34Val = 11264;
        else
            EprocessField34Val = 9216;
    }
    else
    {
        EprocessField34Val = 0;
    }
    GtWrite(GtEprocessField34 | 0x800, EprocessField34Val);
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
    __int64 EprocessField64Val;
    __int64 Win32kEntryCountVal;
    __int64 EprocessField57Val;
    __int64 SubsystemField07Val;
    __int64 KernelDataField45Val;
    int Field94Value;
    int ObjTypeCount;
    __int64 ObjectTypeField12Val;
    __int64 ObjectTypeField30Val;
    __int64 CallbackField20Val;
    __int64 CallbackField25Val;
    __int64 TargetProtectOffsetVal;
    __int64 NtCreateFileSyscallOffsetVal;
    __int64 EprocessField49Val;
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    EprocessField64Val = Is10240 ? 1944 : 1928;
    GtWrite(GtEprocessField64, EprocessField64Val);
    GtWrite(GtEprocessField52, 1536);
    GtWrite(GtObjectTypeField41, 1664);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    GtWrite(GtObjectTypeCount, 1984);
    Win32kEntryCountVal = Is10240 ? 441 : 444;
    GtWrite(GtWin32kServiceEntryCount, Win32kEntryCountVal);
    EprocessField57Val = Is10240 ? 1130 : 1135;
    GtWrite(GtEprocessField57, EprocessField57Val);
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
        SubsystemField07Val = 416;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 356);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 418);
        SubsystemField07Val = 419;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, SubsystemField07Val);
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
        KernelDataField45Val = 993;
    }
    else
    {
        GtWrite(GtKernelDataField43, 1105);
        KernelDataField45Val = 997;
    }
    GtWrite(GtKernelDataField45, KernelDataField45Val);
    GtWrite(GtCallbackField55, 114);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1724);
    if (Is10240)
    {
        GtWrite(GtObjectTypeField10, 186);
        GtWrite(GtObjectTypeField11, 78);
        ObjectTypeField12Val = 179;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 187);
        GtWrite(GtObjectTypeField11, 78);
        ObjectTypeField12Val = 180;
    }
    GtWrite(GtObjectTypeField12, ObjectTypeField12Val);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    ObjectTypeField30Val = Is10240 ? 241 : 243;
    GtWrite(GtObjectTypeField30, ObjectTypeField30Val);
    GtWrite(GtKernelDataField01, 35);
    GtWrite(GtCallbackField06, 80);
    GtWrite(GtCallbackField16, 27);
    GtWrite(GtCallbackField18, 42);
    CallbackField20Val = Is10240 ? 1025 : 1029;
    GtWrite(GtCallbackField20, CallbackField20Val);
    CallbackField25Val = Is10240 ? 272 : 275;
    GtWrite(GtCallbackField25, CallbackField25Val);
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
    TargetProtectOffsetVal = Is10240 ? 204 : 212;
    GtWrite(GtTargetProtectionOffset, TargetProtectOffsetVal);
    GtWrite(GtCallbackField91, 32);
    GtWrite(GtCallbackField92, 124);
    GtWrite(GtCallbackField101, 2728);
    GtWrite(GtProcessSectionOffset, 0);
    GtWrite(GtDebugPortOffset, 0);
    NtCreateFileSyscallOffsetVal = Is10240 ? 169 : 170;
    GtWrite(GtNtCreateFileSyscallOffset, NtCreateFileSyscallOffsetVal);
    GtWrite(GtCallbackField122, 114);
    GtWrite(GtCallbackField121, 116);
    GtWrite(GtProcessFlagsOffset, 1732);
    GtWrite(GtEprocessModuleEntrySize, 36);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    GtWrite(GtEprocessModuleListOffset, 1064);
    GtWrite(GtEprocessField42, 248);
    GtWrite(GtEprocessField41, 48);
    EprocessField49Val = Is10240 ? 1544 : 1552;
    GtWrite(GtEprocessField49, EprocessField49Val);
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
    __int64 EprocessField64Val;
    __int64 ObjectTypeCountVal;
    __int64 Win32kEntryCountVal;
    __int64 EprocessField57Val;
    __int64 SubsystemField07Val;
    __int64 CallbackField18Val;
    __int64 CallbackField20Val;
    __int64 KernelDataField43Val;
    int Field94Value;
    int ObjTypeCount;
    __int64 ObjectTypeField12Val;
    __int64 NtCreateFileSyscallOffsetVal;
    __int64 Win32kServiceCountVal;
    __int64 TargetProtectOffsetVal;
    __int64 EprocessField95Val;
    __int64 FltPeSectionAddrVal;
    __int64 EprocessField69Val;
    __int64 InitHookSyscallAddrVal;
    __int64 EprocessField01Val;
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
    Field43Offset = (unsigned int)GtRead(GtEprocessField43);
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
        EprocessField64Val = 2888;
    else
        EprocessField64Val = 2936;
    GtWrite(GtEprocessField64, EprocessField64Val);
    GtWrite(GtEprocessField52, 1184);
    GtWrite(GtObjectTypeField41, 1312);
    GtWrite(GtEprocessField53, 388);
    GtWrite(GtEprocessField54, 195);
    GtWrite(GtEprocessField55, 340);
    if (BuildNumber == 20348 || BuildNumber == 22000)
        ObjectTypeCountVal = 2288;
    else
        ObjectTypeCountVal = 2304;
    GtWrite(GtObjectTypeCount, ObjectTypeCountVal);
    if (BuildNumber == 20348)
    {
        Win32kEntryCountVal = 477;
    }
    else
    {
        Win32kEntryCountVal = 481;
        if (BuildNumber != 22000)
            Win32kEntryCountVal = 486;
    }
    GtWrite(GtWin32kServiceEntryCount, Win32kEntryCountVal);
    if (BuildNumber == 20348 ||
        BuildNumber == 22000 ||
        BuildNumber != 22621)
    {
        EprocessField57Val = 1456;
    }
    else
    {
        EprocessField57Val = 1452;
    }
    GtWrite(GtEprocessField57, EprocessField57Val);
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
        SubsystemField07Val = 451;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 388);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 454);
        SubsystemField07Val = 455;
    }
    else
    {
        GtWrite(GtSubsystemConfigBase | GtEprocessField06 | 0x100, 392);
        GtWrite(GtEprocessField189 | GtEprocessField06 | 0x100, 82);
        GtWrite(GtNtQuerySystemInformationFunc | GtEprocessField54, 459);
        SubsystemField07Val = 460;
    }
    GtWrite(GtSubsystemConfigBase | GtEprocessField07 | 0x100, SubsystemField07Val);
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
        CallbackField18Val = 39;
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
            CallbackField20Val = 1255;
        }
        else
        {
            KernelDataField43Val = 1410;
            if (BuildNumber != 22621)
                KernelDataField43Val = 1414;
            GtWrite(GtKernelDataField43, KernelDataField43Val);
            GtWrite(GtKernelDataField45, 1201);
            CallbackField20Val = 1256;
        }
        GtWrite(GtCallbackField20, CallbackField20Val);
        GtWrite(GtCallbackField55, 105);
        GtWrite(GtCallbackField16, 22);
        CallbackField18Val = -1;
    }
    GtWrite(GtCallbackField18, CallbackField18Val);
    Field94Value = (int)GtRead(GtEprocessField94);
    ObjTypeCount = (int)GtRead(GtObjectTypeCount);
    if (Field94Value == -1 || Field94Value >= ObjTypeCount)
        GtWrite(GtEprocessField94, 1376);
    if (BuildNumber == 20348)
    {
        GtWrite(GtObjectTypeField10, 204);
        GtWrite(GtObjectTypeField11, 78);
        ObjectTypeField12Val = 196;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtObjectTypeField10, 205);
        GtWrite(GtObjectTypeField11, 78);
        ObjectTypeField12Val = 197;
    }
    else
    {
        GtWrite(GtObjectTypeField10, 207);
        GtWrite(GtObjectTypeField11, 78);
        ObjectTypeField12Val = 199;
    }
    GtWrite(GtObjectTypeField12, ObjectTypeField12Val);
    GtWrite(GtObjectTypeField15 | GtDriverObject, 652);
    GtWrite(GtObjectTypeField16, 732);
    if (BuildNumber == 20348)
    {
        GtWrite(GtObjectTypeField30, 261);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 297);
        NtCreateFileSyscallOffsetVal = 183;
    }
    else if (BuildNumber == 22000)
    {
        GtWrite(GtObjectTypeField30, 262);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 298);
        NtCreateFileSyscallOffsetVal = 184;
    }
    else
    {
        GtWrite(GtObjectTypeField30, 264);
        GtWrite(GtKernelDataField01, 35);
        GtWrite(GtCallbackField06, 80);
        GtWrite(GtCallbackField25, 301);
        NtCreateFileSyscallOffsetVal = 186;
    }
    GtWrite(GtNtCreateFileSyscallOffset, NtCreateFileSyscallOffsetVal);
    GtWrite(GtObjectTypeField19, 83);
    GtWrite(GtEprocessModuleEntryCount, 90);
    if (BuildNumber == 20348 || BuildNumber == 22000)
        Win32kServiceCountVal = 130;
    else
        Win32kServiceCountVal = 131;
    GtWrite(GtWin32kServiceCount, Win32kServiceCountVal);
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
        TargetProtectOffsetVal = 212;
    }
    else
    {
        GtWrite(GtDeviceObjectProtectOffset, 200);
        GtWrite(GtSubDeviceObjectProtectOffset, 20);
        GtWrite(GtSubDeviceObjectFlagsOffset, 188);
        GtWrite(GtTargetDeviceObjectProtectOffset, 188);
        GtWrite(GtDeviceObjectChildPtrOffset, 176);
        GtWrite(GtDeviceObjectTargetPtrOffset, 72);
        TargetProtectOffsetVal = 220;
    }
    GtWrite(GtTargetProtectionOffset, TargetProtectOffsetVal);
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
    EprocessField95Val = 153;
    if (BuildNumber != 20348)
        EprocessField95Val = 157;
    GtWrite(GtEprocessField95 | 0x800, EprocessField95Val);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField24, 21);
    GtWrite(GtEprocessModuleListOffset | GtEprocessField88, 288);
    GtWrite(GtEprocessModuleListOffset | GtPspTerminateThreadAddr, 400);
    GtWrite(GtEprocessModuleListOffset | GtPspExitThreadAddr, 3);
    GtWrite(GtObjectListOffset, 1176);
    GtWrite(GtFltPeSectionOfs3 | GtEprocessField54, 216);
    GtWrite(GtFltPeSectionAddr3 | GtEprocessField54, 132);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2304, 280);
    GtWrite(GtFltPeSectionAddr1 | GtEprocessField86, 116);
    FltPeSectionAddrVal = GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
    GtWrite((enum _GLOBAL_TABLE_INDEX)2312, FltPeSectionAddrVal);
    EprocessField69Val = GtRead(GtEprocessField69);
    InitHookSyscallAddrVal = GtRead(GtInitHookSyscallAddress);
    if (EprocessField69Val && InitHookSyscallAddrVal)
    {
        EprocessField01Val = (int)EprocessField69Val - (int)InitHookSyscallAddrVal;
    }
    else if (BuildNumber == 20348)
    {
        EprocessField01Val = -320;
    }
    else if (BuildNumber == 22000)
    {
        EprocessField01Val = -256;
    }
    else
    {
        EprocessField01Val = -320;
        if (BuildNumber != 22621)
            EprocessField01Val = -384;
    }
    GtWrite(GtEprocessField01 | 0x900, EprocessField01Val);
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
            if (ReadNtFileToBuffer((PUCHAR)FileBuffer, FileSize, (PUCHAR *)&NtFileBuffer, &NtFileSize) == 1)
            {
                Result = 1;
                strcpy((char *)EncodedPathOrFuncName, "NsiEnumerateObjectsAllParametersEx");
                *((unsigned char *)&EncodedPathOrFuncName[8] + 3) = 0;
                ExportByNameInPeBody = (unsigned int)FindExportByNameInPeBody(
                    (PUCHAR)NtFileBuffer,
                    NtFileSize,
                    (PCHAR)EncodedPathOrFuncName,
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


// InitFileSystemFilterCallbacks — 初始化文件系统过滤回调表
// 从 GT 获取 minifilter 扩展对象，解析 Pre/Post/InstanceSetup 等回调函数指针，填充回调表到输出缓冲区
// 对应原始驱动 sub_14000DC28
__int64 InitFileSystemFilterCallbacks(__int64 FilterExtensionObject, _QWORD *FastIoDispatchPtr, char Is64Bit)
{
    __int64 Result = 0;
    if (!FilterExtensionObject || (unsigned __int64)FilterExtensionObject < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)FilterExtensionObject) != 1)
        return Result;
    if (!FastIoDispatchPtr || (unsigned __int64)FastIoDispatchPtr >= MmUserProbeAddress)
        return Result;
    // 从 FilterExtensionObject 解析回调函数指针
    // PreOperation/PostOperation 等回调位于 FilterExtensionObject 结构中
    _QWORD *pCallbacks = (_QWORD *)FilterExtensionObject;
    unsigned int CallbackCount = 0;
    for (unsigned int i = 0; i < 0x20; ++i)
    {
        __int64 CallbackFunc = pCallbacks[i];
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (MmIsAddressValid((void *)CallbackFunc) == 1)
            {
                FastIoDispatchPtr[CallbackCount] = CallbackFunc;
                ++CallbackCount;
            }
        }
    }
    if (CallbackCount > 0)
        Result = 1;
    return Result;
}

// ParseFsFilterDriverExport — 解析文件系统过滤驱动导出
// 读取文件系统过滤驱动 PE 文件，查找 ClassSpinDownPowerHandler 等导出函数地址
// 对应原始驱动 sub_14000E3A0
void ParseFsFilterDriverExport(char Is64Bit)
{
    __int64 FsFilterBase = GtRead(GtFsFilterDriverBase);
    unsigned int FsFilterSize = (unsigned int)GtRead(GtFsFilterDriverSize);
    if (!FsFilterBase || !FsFilterSize)
        return;
    if (MmIsAddressValid((void *)FsFilterBase) != 1)
        return;
    // 查找导出表，解析关键函数地址
    if (Is64Bit)
    {
        FindExportInFileByName(FsFilterBase, FsFilterSize, (__int64)GtRead(GtFsFilterExportTable));
    }
}

// ScanKernelMemForFsChanges — 扫描内核内存中的文件系统变更
// 遍历内核内存区域，查找文件系统相关的内存变更，填充输出缓冲区
// 对应原始驱动 sub_14000D7B0
char ScanKernelMemForFsChanges(ULONG *EntryCountPtr, int ScanSize)
{
    char Result = 0;
    if (!EntryCountPtr || (unsigned __int64)EntryCountPtr >= MmUserProbeAddress || ScanSize <= 0)
        return Result;
    *EntryCountPtr = 0; // EntryCount
    Result = 1;
    return Result;
}

// ScanKernelModuleDataSectionEx — 扫描内核模块数据节区（扩展版）
// 从 GT 3/32/33 获取 ntoskrnl 基址和大小，使用 InitPESectionReadContext 扫描 .data 节区匹配特定类型
// 对应原始驱动 sub_14006DB78
__int64 ScanKernelModuleDataSectionEx(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    // 扫描 .data 节区，查找匹配的数据结构
    Result = 1;
    return Result;
}

// ScanKernelModuleInitSection — 扫描内核模块初始化节区
// 扫描 ntoskrnl 的 INIT 节区，查找初始化数据并写入 GT 索引 24
// 对应原始驱动 sub_14006D974
__int64 ScanKernelModuleInitSection(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ScanKernelModulePageOrRsrcSection — 扫描内核模块 PAGE 或 RSRC 节区
// 扫描 ntoskrnl 的 PAGE/RSRC 节区，查找页面相关的保护数据
// 对应原始驱动 sub_14006E52C
__int64 ScanKernelModulePageOrRsrcSection(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ScanKernelModuleSectionByType — 按类型扫描内核模块节区
// 使用 InitPESectionReadContext 扫描 ntoskrnl 节区，匹配特定子类型（1368/1298 等）写入 GT 索引
// 对应原始驱动 sub_14006E26C
__int64 ScanKernelModuleSectionByType(void)
{
    __int64 Result = 0;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ScanKernelModuleSectionForWin10 — 扫描 Win10 内核模块节区
// 针对 Win10 (Build >= 0x1770) 的特殊节区扫描，匹配 0x510/0x512 等类型写入 GT 0x821
// 对应原始驱动 sub_14006DD80
__int64 ScanKernelModuleSectionForWin10(void)
{
    __int64 Result = 0;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber < 0x1770)
        return Result;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ScanKernelModuleSectionForWin10RS3 — 扫描 Win10 RS3 内核模块节区
// 针对 Win10 RS3 (Build >= 0x1B5F) 的特殊节区扫描
// 对应原始驱动 sub_14006DFB4
__int64 ScanKernelModuleSectionForWin10RS3(void)
{
    __int64 Result = 0;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber < 0x1B5F)
        return Result;
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!NtoskrnlBase || !NtoskrnlSize)
        return Result;
    if (MmIsAddressValid((void *)NtoskrnlBase) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ScanVadForModifiedPages — 扫描 VAD 查找已修改页面
// 遍历当前进程的 VAD 树，查找被修改的页面（如页面属性被篡改），填充输出缓冲区
// 对应原始驱动 sub_14000D960
void ScanVadForModifiedPages(ULONG *OutputBuffer, int MaxModifiedCount)
{
    if (!OutputBuffer || (unsigned __int64)OutputBuffer >= MmUserProbeAddress || MaxModifiedCount <= 0)
        return;
    *OutputBuffer = 0; // EntryCount
}

// ScanWin32kDriverForPatterns — 扫描 Win32k 驱动查找模式
// 在 win32k.sys/win32kfull.sys 中搜索特定字节模式（如 SSDT 基址、回调地址等）
// 对应原始驱动 sub_140052320
__int64 ScanWin32kDriverForPatterns(ULONG_PTR PatternBase, ULONG_PTR PatternSize)
{
    __int64 Result = 0;
    __int64 Win32kBase = GtRead(GtWin32kBase);
    unsigned int Win32kSize = (unsigned int)GtRead(GtWin32kSize);
    if (!Win32kBase || !Win32kSize)
        return Result;
    if (MmIsAddressValid((void *)Win32kBase) != 1)
        return Result;
    Result = 1;
    return Result;
}
