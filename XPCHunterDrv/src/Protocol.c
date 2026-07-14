// Protocol.c — IRP 通信协议处理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"
// Forward declarations
bool GetDeviceObjectFromFileObject(ULONG64 FileObject, ULONG64 *pDeviceObject, ULONG64 *pFileDeviceObject);
bool OpenDriveDeviceObject(WCHAR *DriveLetter, _QWORD *pDeviceObject, _QWORD *pFileDevice);
bool __fastcall SendCreateFileIoControl(__int64 Handle, __int16 *FilePath);
PWSTR ResolveSymbolicLinkPath(void);

// 定义 MEMORY 宏，用于访问物理内存地址（替代 IDA 的 MEMORY[] 语法）
#define MEMORY ((volatile unsigned char *)0)

// wmemcpy — 宽字符内存复制（内核模式不提供此运行时函数）
wchar_t *wmemcpy(wchar_t *dest, const wchar_t *src, size_t count)
{
    return (wchar_t *)memcpy(dest, src, count * sizeof(wchar_t));
}

// 前向声明：Nt* 系统服务函数（ntoskrnl.exe 导出，通过 ntoskrnl.lib 链接）
extern NTSTATUS NTAPI NtFsControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG FsControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

extern NTSTATUS NTAPI NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

// 前向声明（仅保留未在头文件中声明的本地函数）
NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// IrpSetupBufferMdl — 设置 IRP 缓冲区 MDL
// 对应原始驱动 sub_14002DA04
__int64 IrpSetupBufferMdl(PIRP Irp, __int64 StackLocation, void *Buffer, ULONG BufferSize,
                          char ProbeAndLock, char WriteOperation, _DWORD *pFlags)
{
    ULONG TransferType;

    *pFlags = 0;
    Irp->Flags = 0;
    Irp->MdlAddress = NULL;
    Irp->AssociatedIrp.MasterIrp = NULL;

    TransferType = *(ULONG *)(StackLocation + 48);
    if ((TransferType & 4) != 0)
    {
        if (BufferSize)
        {
            PVOID pBuffer = ExAlloc(NonPagedPoolCacheAligned, BufferSize);
            Irp->AssociatedIrp.MasterIrp = pBuffer;
            if (!pBuffer)
                return (ULONG)-1073741670;
            Irp->Flags = 112;
            *pFlags |= 1;
        }
        else
        {
            Irp->Flags = 128;
        }
        Irp->UserBuffer = Buffer;
    }
    else if ((TransferType & 0x10) != 0)
    {
        if (BufferSize)
        {
            PMDL Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, TRUE, Irp);
            Irp->MdlAddress = Mdl;
            if (Mdl)
            {
                if (ProbeAndLock)
                {
                    MmProbeAndLockPages(Mdl, KernelMode, (LOCK_OPERATION)(WriteOperation != 0));
                    *pFlags |= 2;
                }
                else
                {
                    MmBuildMdlForNonPagedPool(Mdl);
                }
            }
            else
            {
                return (ULONG)-1073741670;
            }
        }
    }
    else
    {
        Irp->UserBuffer = Buffer;
    }

    return 0;
}

// IrpFsctlVolumeDismount — IRP FSCTL 卷卸载
// 对应原始驱动 sub_14002E3F8
__int64 IrpFsctlVolumeDismount(void *FileObject)
{
    UCHAR DismountFlag = 1;
    return IrpFileSystemControl(FileObject, (struct _IRP *)&DismountFlag, 1, 0x0D);
}

// IrpFileSystemControl — IRP 文件系统控制
// 对应原始驱动 sub_14002F1FC
__int64 IrpFileSystemControl(void *FileHandle, struct _IRP *FsctlBuffer, ULONG BufferSize, ULONG FsControlCode)
{
    ULONG Status;
    PIRP Irp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    struct _IO_STACK_LOCATION *StackLocation;
    __int64 DeviceObject;
    struct _FILE_OBJECT *FileObject;
    char IrpMonitorContext;
    char VolumeChangeLock;
    char DiskFunctionState;
    int CallResult;
    PVOID Object;
    __int64 DeviceObjectForFile;
    __int64 (__fastcall *pCallDriver)(__int64, ULONG_PTR, __int64);
    ULONG IoStatus;
    __int64 IoStatusHigh;
    char FileDeviceObject[8];
    struct _KEVENT Event;
    _OWORD BufferArray;

    Status = ObReferenceObjectByHandle(FileHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, NULL);
    if (Status)
        return Status;

    Status = -1073741823;
    if (!GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, FileDeviceObject))
        goto Cleanup;

    Status = -1073741670;
    Irp = IoAllocateIrp(*(UCHAR *)(DeviceObjectForFile + 76), FALSE);
    if (!Irp)
        goto Cleanup;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].Context = NULL;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
    CurrentStackLocation[-1].Control = 0xE0; // -32

    IoStatus = 0;
    IoStatusHigh = 0;
    Irp->MdlAddress = NULL;
    Irp->Overlay.AllocationSize.QuadPart = 0;
    Irp->Flags = 2100;
    Irp->AssociatedIrp.MasterIrp = FsctlBuffer;
    Irp->RequestorMode = KernelMode;
    Irp->UserEvent = &Event;
    Irp->UserIosb = (PIO_STATUS_BLOCK)&IoStatus;

    StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceObject = DeviceObjectForFile;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;

    StackLocation[-1].MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
    StackLocation[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObject;
    FileObject = (struct _FILE_OBJECT *)Object;
    StackLocation[-1].Parameters.CreatePipe.Parameters = NULL;
    StackLocation[-1].Parameters.Read.Length = BufferSize;
    StackLocation[-1].FileObject = FileObject;
    StackLocation[-1].Parameters.Create.Options = FsControlCode;

    if (FsControlCode == 10)
        StackLocation[-1].Parameters.SetFile.ReplaceIfExists = FsctlBuffer->Type;

    IrpMonitorContext = GetIrpMonitorContext(DeviceObject, IRP_MJ_FILE_SYSTEM_CONTROL, &BufferArray, &pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObject);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    CallResult = AllocateIrpStackAndCallDriver(pCallDriver, DeviceObject, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, DeviceObject, IRP_MJ_FILE_SYSTEM_CONTROL, &BufferArray);

    if (CallResult == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    NotifyVolumeDeviceChange(VolumeChangeLock, DeviceObject);
    RestoreDiskIrpFunctionPointer(DiskFunctionState);
    Status = IoStatus;

Cleanup:
    ObfDereferenceObject(Object);
    return Status;
}

// CompleteIrpAndCleanupMdl — 完成 IRP 并清理 MDL
// 对应原始驱动 sub_140079CB4
__int64 CompleteIrpAndCleanupMdl(__int64 a1, __int64 Irp, __int64 a3)
{
    *(_OWORD *)*(_QWORD *)(Irp + 72) = *(_OWORD *)(Irp + 48);
    struct _KEVENT *v5 = *(struct _KEVENT **)(Irp + 80);
    if (v5) KeSetEvent(v5, 0, 0);
    if (a3)
    {
        struct _MDL *v6 = *(struct _MDL **)(Irp + 8);
        if (v6) { MmUnlockPages(v6); IoFreeMdl(*(PMDL *)(Irp + 8)); *(_QWORD *)(Irp + 8) = 0; }
    }
    IoFreeIrp((PIRP)Irp);
    return 3221225494LL;
}

// IrpReadFileWithOffset — IRP 偏移读取文件
// 对应原始驱动 sub_14002E41C
// 通过 IRP 发送 IRP_MJ_READ 到文件对象所在设备，支持偏移量指定
__int64 IrpReadFileWithOffset(
    void *FileHandle,
    DWORD ByteOffset,
    void *Buffer,
    ULONG Length,
    char WaitForLock,
    _DWORD *pBytesRead,
    char UseSecondary)
{
    int Status;
    __int64 DeviceObject;
    PIRP Irp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    struct _IO_STACK_LOCATION *v15;
    __int64 DeviceObjectCopy;
    char IrpMonitorContext;
    char VolumeChangeLock;
    char DiskFunctionState;
    PVOID Object;
    __int64 BufferMdl;
    __int64 DeviceObjectForFile;
    __int64 (__fastcall *pCallDriver)(__int64, ULONG_PTR, __int64);
    _DWORD IoStatus[4];
    struct _KEVENT Event;
    __int64 FileDeviceObject;
    _OWORD BufferArray;

    Status = ObReferenceObjectByHandle(FileHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, NULL);
    if (Status)
        return Status;

    Status = -1073741823;
    if (!GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, &FileDeviceObject))
        goto Cleanup;

    DeviceObject = DeviceObjectForFile;
    Status = -1073741670;
    Irp = IoAllocateIrp(*(UCHAR *)(DeviceObjectForFile + 76), FALSE);
    if (!Irp)
        goto Cleanup;

    Status = IrpSetupBufferMdl(Irp, DeviceObject, Buffer, Length, (char)WaitForLock, 1, &BufferMdl);
    if (Status < 0)
    {
        IoFreeIrp(Irp);
        goto Cleanup;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].Control = 0xE0;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
    CurrentStackLocation[-1].Context = (PVOID)(ULONG_PTR)BufferMdl;

    Irp->RequestorMode = KernelMode;
    Irp->UserEvent = &Event;
    Irp->UserIosb = (PIO_STATUS_BLOCK)IoStatus;

    v15 = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceObjectCopy = DeviceObjectForFile;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;
    Irp->Overlay.AllocationSize.QuadPart = 0;

    *(WORD *)&v15[-1].MajorFunction = IRP_MJ_READ | (0x100); // MajorFunction=2, MinorFunction=0x100
    v15[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObjectCopy;
    v15[-1].FileObject = (PFILE_OBJECT)Object;
    v15[-1].Parameters.Read.Length = Length;
    v15[-1].Parameters.QueryDirectory.FileName = NULL;
    v15[-1].Parameters.Read.ByteOffset.LowPart = ByteOffset;
    v15[-1].Parameters.Read.ByteOffset.HighPart = 0;
    v15[-1].Flags = 0;
    v15[-1].Flags = WaitForLock == 1;

    if (UseSecondary == 1)
        v15[-1].Flags |= 2;

    IrpMonitorContext = GetIrpMonitorContext(DeviceObjectCopy, IRP_MJ_READ, &BufferArray, &pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObjectCopy);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    Status = AllocateIrpStackAndCallDriver(pCallDriver, DeviceObjectCopy, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, DeviceObjectCopy, IRP_MJ_READ, &BufferArray);

    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus[0];
    }

    NotifyVolumeDeviceChange(VolumeChangeLock, DeviceObjectCopy);
    RestoreDiskIrpFunctionPointer(DiskFunctionState);

    if (pBytesRead)
        *pBytesRead = IoStatus[2];

Cleanup:
    ObfDereferenceObject(Object);
    return (ULONG)Status;
}

// IrpReadFile — IRP 读取文件（查询文件信息）
// 对应原始驱动 sub_14002E6EC
// 发送 IRP_MJ_QUERY_INFORMATION（MajorFunction=5）到文件设备，查询文件信息
__int64 IrpReadFile(void *FileHandle, struct _IRP *AssociatedIrp, ULONG Length, ULONG CreateOptions)
{
    unsigned int Status;
    PIRP Irp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    struct _IO_STACK_LOCATION *StackLocation;
    __int64 DeviceObject;
    struct _FILE_OBJECT *FileObject;
    char IrpMonitorContext;
    char VolumeChangeLock;
    char DiskFunctionState;
    int CallResult;
    PVOID Object;
    __int64 DeviceObjectForFile;
    __int64 (__fastcall *pCallDriver)(__int64, ULONG_PTR, __int64);
    unsigned int IoStatus;
    struct _KEVENT Event;
    _OWORD BufferArray;
    char FileDeviceObject[8];

    Status = ObReferenceObjectByHandle(FileHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0);
    if (!Status)
    {
        Status = -1073741823;
        if (GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, FileDeviceObject))
        {
            Status = -1073741670;
            Irp = IoAllocateIrp(*(UCHAR *)(DeviceObjectForFile + 76), 0);
            if (Irp)
            {
                KeInitializeEvent(&Event, SynchronizationEvent, 0);
                CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
                CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
                CurrentStackLocation[-1].Context = 0;
                CurrentStackLocation[-1].Control = -32; // 0xE0
                Irp->AssociatedIrp.MasterIrp = AssociatedIrp;
                Irp->Flags = 16;
                Irp->MdlAddress = 0;
                Irp->RequestorMode = 0;
                Irp->Overlay.AllocationSize.QuadPart = 0;
                Irp->UserEvent = &Event;
                Irp->UserIosb = (PIO_STATUS_BLOCK)&IoStatus;
                StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
                DeviceObject = DeviceObjectForFile;
                Irp->Tail.Overlay.Thread = KeGetCurrentThread();
                Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;
                StackLocation[-1].MajorFunction = IRP_MJ_QUERY_INFORMATION; // 5
                StackLocation[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObject;
                FileObject = (struct _FILE_OBJECT *)Object;
                StackLocation[-1].Parameters.Read.Length = Length;
                StackLocation[-1].Parameters.Create.Options = CreateOptions;
                StackLocation[-1].FileObject = FileObject;
                IrpMonitorContext = GetIrpMonitorContext(DeviceObject, IRP_MJ_QUERY_INFORMATION, &BufferArray, &pCallDriver);
                VolumeChangeLock = AcquireVolumeChangeLock(DeviceObject);
                DiskFunctionState = SwapDiskIrpFunctionPointer();
                CallResult = AllocateIrpStackAndCallDriver(pCallDriver, DeviceObject, (ULONG_PTR)Irp);
                ReleaseIrpMonitorContext(IrpMonitorContext, DeviceObject, IRP_MJ_QUERY_INFORMATION, &BufferArray);
                if (CallResult == 259)
                    KeWaitForSingleObject(&Event, Executive, 0, 0, 0);
                NotifyVolumeDeviceChange(VolumeChangeLock, DeviceObject);
                RestoreDiskIrpFunctionPointer(DiskFunctionState);
                Status = IoStatus;
            }
        }
        ObfDereferenceObject(Object);
    }
    return Status;
}

// IrpWriteFile — IRP 写入文件
// 对应原始驱动 sub_14002EF18
// 通过 IRP 发送 IRP_MJ_WRITE 到文件设备，支持偏移量指定
__int64 IrpWriteFile(
    void *FileHandle,
    LARGE_INTEGER *ByteOffset,
    ULONG Length,
    void *Buffer,
    PLARGE_INTEGER Timeout,
    struct _IO_STATUS_BLOCK *IoStatusBlock)
{
    int Status;
    PVOID FileObject;
    __int64 DeviceObject;
    PIRP Irp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    struct _IO_STACK_LOCATION *StackLocation;
    __int64 DeviceObjectCopy;
    struct _FILE_OBJECT *FileObjectPtr;
    char IrpMonitorContext;
    char VolumeChangeLock;
    char DiskFunctionState;
    int CallResult;
    PVOID Object;
    __int64 BufferMdl;
    __int64 DeviceObjectForFile;
    __int64 (__fastcall *pCallDriver)(__int64, ULONG_PTR, __int64);
    struct _KEVENT Event;
    char FileDeviceObject[8];
    _OWORD BufferArray;

    Status = ObReferenceObjectByHandle(FileHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, NULL);
    if (Status < 0)
        return (ULONG)Status;

    FileObject = Object;
    if (!ByteOffset && (*((UCHAR *)Object + 80) & 2) != 0)
        ByteOffset = (LARGE_INTEGER *)((char *)Object + 104);

    Status = -1073741811;
    if (!ByteOffset)
    {
        ObfDereferenceObject(FileObject);
        return (ULONG)Status;
    }

    Status = -1073741823;
    if (!GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, FileDeviceObject))
    {
        ObfDereferenceObject(FileObject);
        return (ULONG)Status;
    }

    DeviceObject = DeviceObjectForFile;
    Status = -1073741670;
    Irp = IoAllocateIrp(*(UCHAR *)(DeviceObjectForFile + 76), FALSE);
    if (!Irp)
    {
        ObfDereferenceObject(Object);
        return (ULONG)Status;
    }

    Status = IrpSetupBufferMdl(Irp, DeviceObject, Buffer, Length, (char)Timeout, 1, &BufferMdl);
    if (Status < 0)
    {
        IoFreeIrp(Irp);
        ObfDereferenceObject(Object);
        return (ULONG)Status;
    }

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].Control = 0xE0;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
    CurrentStackLocation[-1].Context = (PVOID)(ULONG_PTR)BufferMdl;

    Irp->Flags |= 0x100;
    Irp->RequestorMode = KernelMode;
    Irp->UserIosb = IoStatusBlock;
    Irp->UserEvent = &Event;

    StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceObjectCopy = DeviceObjectForFile;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;

    *(WORD *)&StackLocation[-1].MajorFunction = IRP_MJ_WRITE;
    StackLocation[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObjectCopy;
    FileObjectPtr = (struct _FILE_OBJECT *)Object;
    StackLocation[-1].Parameters.Read.Length = Length;
    StackLocation[-1].FileObject = FileObjectPtr;
    StackLocation[-1].Parameters.Read.ByteOffset = *ByteOffset;

    IrpMonitorContext = GetIrpMonitorContext(DeviceObjectCopy, IRP_MJ_WRITE, &BufferArray, &pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObjectCopy);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    CallResult = AllocateIrpStackAndCallDriver(pCallDriver, DeviceObjectCopy, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, DeviceObjectCopy, IRP_MJ_WRITE, &BufferArray);

    if (CallResult == STATUS_PENDING)
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);

    NotifyVolumeDeviceChange(VolumeChangeLock, DeviceObjectCopy);
    RestoreDiskIrpFunctionPointer(DiskFunctionState);

    ObfDereferenceObject(Object);
    return (ULONG)IoStatusBlock->Status;
}

// SendDeviceIoControlIrp — 发送设备 IO 控制 IRP
// 对应原始驱动 sub_140059334
// 构造 SCSI 请求包（CDB），分配 IRP 和 MDL，发送到目标设备
__int64 SendDeviceIoControlIrp(_QWORD *DeviceInfo, int Direction, void *Buffer, int BlockCount, int SectorSize, int a6)
{
    int Status;
    WORD *ContextBuffer;
    _QWORD *CdbBuffer;
    int v12;
    PIRP Irp;
    PIRP v14;
    PMDL Mdl, v16;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    __int64 v18;
    __int64 v19;
    __int64 (__fastcall *v20)(_QWORD, PIRP);
    __int64 v21;
    _QWORD *v22;
    UCHAR CurrentIrql;
    int v25;
    struct _KEVENT Event;

    Status = -1073741670;
    ContextBuffer = ExAlloc(NonPagedPool, 0x58);
    if (!ContextBuffer)
        return (ULONG)Status;

    CdbBuffer = ExAlloc(NonPagedPool, 0x12);
    if (!CdbBuffer)
    {
        ExFree(ContextBuffer);
        return (ULONG)Status;
    }

    memset(ContextBuffer, 0, 0x58);
    *CdbBuffer = 0;
    CdbBuffer[1] = 0;
    *((WORD *)CdbBuffer + 8) = 0;
    *ContextBuffer = 88;
    *((UCHAR *)ContextBuffer + 2) = 0;
    *((_QWORD *)ContextBuffer + 3) = Buffer;
    *((_DWORD *)ContextBuffer + 4) = a6 * SectorSize;
    *(WORD *)((char *)ContextBuffer + 9) = 2560;
    *((_QWORD *)ContextBuffer + 4) = CdbBuffer;
    *((UCHAR *)ContextBuffer + 11) = 18;
    *((_DWORD *)ContextBuffer + 3) = 256;

    v12 = (Direction == 3) ? 64 : 128;
    *((_DWORD *)ContextBuffer + 3) = v12;
    *((_DWORD *)ContextBuffer + 5) = ((a6 * SectorSize) >> 10) + 1;
    *((_DWORD *)ContextBuffer + 16) = BlockCount;
    *((UCHAR *)ContextBuffer + 72) = 2 * (Direction + 17);
    *((UCHAR *)ContextBuffer + 73) = *((UCHAR *)ContextBuffer + 73) & 0x1F | 0x80;
    *((UCHAR *)ContextBuffer + 74) = HIBYTE(BlockCount);
    *((UCHAR *)ContextBuffer + 75) = BYTE2(BlockCount);
    *((UCHAR *)ContextBuffer + 76) = BYTE1(BlockCount);
    *((UCHAR *)ContextBuffer + 77) = BlockCount;
    *((UCHAR *)ContextBuffer + 79) = BYTE1(SectorSize);
    *((UCHAR *)ContextBuffer + 80) = SectorSize;

    Irp = IoAllocateIrp(*(UCHAR *)(*DeviceInfo + 76), FALSE);
    v14 = Irp;
    if (!Irp)
    {
        ExFree(CdbBuffer);
        ExFree(ContextBuffer);
        return (ULONG)Status;
    }

    Mdl = IoAllocateMdl(Buffer, a6 * SectorSize, FALSE, FALSE, Irp);
    v16 = Mdl;
    if (!Mdl)
    {
        IoFreeIrp(v14);
        ExFree(CdbBuffer);
        ExFree(ContextBuffer);
        return (ULONG)Status;
    }

    MmProbeAndLockPages(Mdl, KernelMode, (LOCK_OPERATION)(Direction != 3));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    CurrentStackLocation = v14->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)CompleteIrpAndCleanupMdl;
    CurrentStackLocation[-1].Context = ContextBuffer;
    CurrentStackLocation[-1].Control = 0xE0;
    *((_QWORD *)ContextBuffer + 6) = v14;
    v14->MdlAddress = v16;
    v14->Flags = 1;
    v14->RequestorMode = KernelMode;
    v14->UserIosb = (PIO_STATUS_BLOCK)&v25;
    v14->UserEvent = &Event;
    v14->Cancel = FALSE;
    v14->CancelRoutine = NULL;
    v14->Tail.Overlay.Thread = KeGetCurrentThread();
    v14->IoStatus.Status = 0;
    v14->IoStatus.Information = 0;
    v14->AssociatedIrp.MasterIrp = NULL;

    v18 = (__int64)&v14->Tail.Overlay.CurrentStackLocation[-1];
    *(UCHAR *)v18 = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    *(_QWORD *)(v18 + 40) = *DeviceInfo;
    *(_QWORD *)(v18 + 8) = ContextBuffer;
    v14->CurrentLocation--;
    v14->Tail.Overlay.CurrentStackLocation = (struct _IO_STACK_LOCATION *)v18;

    v19 = IdentityReturnParam(DeviceInfo[2]);
    v20 = (__int64 (__fastcall *)(_QWORD, PIRP))IdentityReturnParam(DeviceInfo[3]);
    v21 = *(_QWORD *)(DeviceInfo[1] + 96);

    CurrentIrql = KeGetCurrentIrql();
    __writecr8(0);
    *(_QWORD *)(DeviceInfo[1] + 96) = v19;

    Status = v20(*DeviceInfo, v14);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = v25;
    }

    __writecr8(CurrentIrql);
    *(_QWORD *)(DeviceInfo[1] + 96) = v21;

    v22 = (_QWORD *)*((_QWORD *)ContextBuffer + 4);
    if (v22 != CdbBuffer && v22)
        ExFreePoolWithTag(v22, 0);

    if (Status >= 0)
        Status = 0;

    ExFree(CdbBuffer);
    ExFree(ContextBuffer);
    return (ULONG)Status;
}

// CreateFileWithPath — 通过路径创建文件
// 对应原始驱动 sub_14002E8DC
// 支持多种路径格式，根据版本号选择不同的创建路径
__int64 CreateFileWithPath(
    __int16 *FilePath,
    const WCHAR *RelativePath,
    void **pFileHandle,
    ACCESS_MASK DesiredAccess,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG Disposition,
    ULONG CreateOptions)
{
    int Status;
    ULONG StringLength;
    ULONG PrefixLength;
    WCHAR *ResolvedPath, *AllocatedPath, *FreePath;
    __int16 *PathSuffix;
    WCHAR *SymbolicPath;
    PVOID DosPathBuffer;
    NTSTATUS CreateStatus;
    __int16 *ParentPath, *ParentPathCopy, *LastChar;
    int DirCreateStatus;
    HANDLE ParentHandle;
    HANDLE RootDirHandle = NULL;
    const WCHAR *FilePathForCreate;
    PCWSTR SourceString;
    PVOID Object;
    PHANDLE FileHandle = pFileHandle;
    struct _UNICODE_STRING DestinationString;
    struct _OBJECT_ATTRIBUTES ObjectAttributes;
    __int64 v35;
    struct _IO_STATUS_BLOCK IoStatusBlock;
    _DWORD encPath[6];
    ULONG ShareAccessMask = ShareAccess & 7;
    int PathLen;

    Status = -1073741811;
    if (Disposition > 5)
        return (ULONG)Status;

    StringLength = GetStringLength(FilePath);
    if ((CreateOptions & 0x2000) != 0)
    {
        RootDirHandle = NULL;
        if (StringLength > 3)
        {
            ParentPath = ExAlloc(PagedPool, 2 * StringLength + 2);
            ParentPathCopy = ParentPath;
            if (ParentPath)
            {
                WStringCopy(ParentPath, FilePath);
                LastChar = WStringFindLastChar(ParentPathCopy, L'\\');
                if (LastChar)
                {
                    if (LastChar == ParentPathCopy + 2 && ParentPathCopy[1] == L':')
                        LastChar[1] = 0;
                    else
                        *LastChar = 0;
                    DirCreateStatus = CreateFileWithPath(ParentPathCopy, NULL, (void **)&RootDirHandle,
                        0x80, 0x80, 1, 1, 0x20);
                    ParentHandle = DirCreateStatus ? 0 : RootDirHandle;
                    RootDirHandle = ParentHandle;
                }
                ExFree(ParentPathCopy);
            }
        }
        memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
        DestinationString.Buffer = (PWSTR)RelativePath;
        ObjectAttributes.RootDirectory = RootDirHandle;
        ObjectAttributes.ObjectName = &DestinationString;
        *(ULONG *)&DestinationString.Length = 524296;
        ObjectAttributes.Length = 48;
        ObjectAttributes.Attributes = 576;
        Status = IoCreateFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock,
            NULL, FileAttributes, ShareAccessMask, Disposition, CreateOptions, NULL, 0,
            CreateFileTypeNone, NULL, 0x100);
        if (Status >= 0) Status = 0;
        if (RootDirHandle) ZwClose(RootDirHandle);
    }
    else if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        if (FilePath[1] == L':' && FilePath[2] == L'\\')
        {
            DosPathBuffer = ExAlloc(PagedPool, 2 * StringLength + 20);
            SourceString = (PCWSTR)DosPathBuffer;
            if (DosPathBuffer)
            {
                *(ULONG *)DosPathBuffer = 4128860;
                *((ULONG *)DosPathBuffer + 1) = 6029375;
                WStringCopy((__int16 *)DosPathBuffer + 4, FilePath);
                RtlInitUnicodeString(&DestinationString, SourceString);
                memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
                ObjectAttributes.ObjectName = &DestinationString;
                ObjectAttributes.Length = 48;
                ObjectAttributes.RootDirectory = NULL;
                ObjectAttributes.Attributes = 576;
                CreateStatus = IoCreateFile(FileHandle, DesiredAccess, &ObjectAttributes,
                    &IoStatusBlock, NULL, FileAttributes, ShareAccessMask, Disposition,
                    CreateOptions, NULL, 0, CreateFileTypeNone, NULL, 0x100);
                FreePath = (WCHAR *)SourceString;
                Status = CreateStatus;
                if (CreateStatus >= 0) Status = 0;
                ExFree(FreePath);
            }
        }
        else
        {
            RtlInitUnicodeString(&DestinationString, (PCWSTR)FilePath);
            memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
            ObjectAttributes.ObjectName = &DestinationString;
            ObjectAttributes.Length = 48;
            ObjectAttributes.RootDirectory = NULL;
            ObjectAttributes.Attributes = 576;
            Status = IoCreateFile(FileHandle, DesiredAccess, &ObjectAttributes, &IoStatusBlock,
                NULL, FileAttributes, ShareAccessMask, Disposition, CreateOptions,
                NULL, 0, CreateFileTypeNone, NULL, 0x100);
            if (Status >= 0) return 0;
        }
    }
    else if (StringLength >= 3)
    {
        // 旧版路径处理
        encPath[0] = 5439580; encPath[1] = 7536761;
        encPath[2] = 6619252; encPath[3] = 5374061;
        encPath[4] = 7274607; encPath[5] = 116;

        PrefixLength = GetStringLength(encPath);
        if ((StringLength > PrefixLength &&
             StringCompare3Way((__int64)FilePath, (WORD *)encPath, PrefixLength) == 0) ||
            (FilePath[1] == L':' && FilePath[2] == L'\\'))
        {
            Status = -1073741823;
            if (OpenDriveDeviceObject((WCHAR *)FilePath, &v35, &SourceString))
            {
                if (*FilePath == L'\\')
                {
                    ResolvedPath = ResolveSymbolicLinkPath();
                    SymbolicPath = ResolvedPath;
                    if (!ResolvedPath) return (ULONG)Status;
                    ResolvedPath[259] = 0;
                    if (GetStringLength(ResolvedPath) >= 0x103)
                        AllocatedPath = SymbolicPath;
                    else
                    {
                        PathLen = GetStringLength(SymbolicPath);
                        PathSuffix = &FilePath[(ULONG)PrefixLength];
                        AllocatedPath = SymbolicPath;
                        WStringConcat(SymbolicPath, PathSuffix, 259 - PathLen);
                        SymbolicPath[259] = 0;
                    }
                    FilePathForCreate = AllocatedPath;
                }
                else
                {
                    FilePathForCreate = (const WCHAR *)(FilePath + 2);
                    AllocatedPath = NULL;
                }
                if (FilePathForCreate)
                {
                    RtlInitUnicodeString(&DestinationString, FilePathForCreate);
                    Status = CreateFileObject((__int64)&DestinationString, DesiredAccess,
                        FileAttributes, ShareAccessMask, Disposition, CreateOptions,
                        (struct _DEVICE_OBJECT *)SourceString, v35, &Object);
                    if (!Status)
                    {
                        Status = ObOpenObjectByPointer(Object, 0x200, NULL,
                            DesiredAccess | 0x100000, (POBJECT_TYPE)IoFileObjectType,
                            NULL, FileHandle);
                        if (Status >= 0) Status = 0;
                        ObfDereferenceObject(Object);
                    }
                }
                if (AllocatedPath) ExFree(AllocatedPath);
            }
        }
    }
    return (ULONG)Status;
}

// QueryFileInfoByHandle — 通过句柄查询文件信息
// 对应原始驱动 sub_14007107C
bool QueryFileInfoByHandle(__int64 Process, __int64 a2, __int64 a3)
{
    bool Result = 0;
    ULONG v5;
    int (__fastcall *v6)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, __int64 *);
    _QWORD *v7;
    void (__fastcall *v8)(__int64);
    __int64 v9;
    __int64 (*v10)(__int64, __int64 *, __int64 *, __int64);
    struct _KTHREAD *CurrentThread;
    char v12;
    int v13;
    __int64 v15 = a2;
    __int64 v16 = a3;
    __int64 v17;

    v5 = (ULONG)GtRead(GtSdstServiceCount);
    v6 = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, __int64 *))GtRead(16735);
    v7 = (_QWORD *)GtRead(16748);
    v8 = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    v9 = GtRead(16839);
    v10 = (__int64 (*)(__int64, __int64 *, __int64 *, __int64))v9;

    if (v5 == (ULONG)-1 || !v6 || !v7 || !v8 || !v9) return Result;

    CurrentThread = KeGetCurrentThread();
    if (v6(Process, 512, 0, 0x10000000, *v7, 0, &v17) >= 0)
    {
        v12 = *((UCHAR *)CurrentThread + v5);
        *((UCHAR *)CurrentThread + v5) = 0;
        v13 = v10(v17, &v15, &v16, 0x8000);
        *((UCHAR *)CurrentThread + v5) = v12;
        Result = v13 >= 0;
        v8(v17);
    }

    return Result;
}

// CmdCreateFile — 创建文件命令处理
// 对应原始驱动 sub_140074258
// 解析输入参数中的路径信息并调用 SendCreateFileIoControl 创建文件
__int64 CmdCreateFile(_QWORD *Address, int InputSize)
{
    bool FileIoControl = 0;
    void (__fastcall *InitUnicodeFunc)(WORD *, __int64);
    SIZE_T v6;
    volatile void *v7;
    ULONG64 v8;
    __int64 v9;
    ULONG v10;
    struct _KTHREAD *CurrentThread;
    char v12;
    int (__fastcall *v13)(_QWORD, WORD *);
    ULONG v15;
    int (__fastcall *v16)(_QWORD, WORD *);
    WORD v17[20];

    InitUnicodeFunc = (void (__fastcall *)(WORD *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    if (!InitUnicodeFunc) return FileIoControl;
    if (!Address) return FileIoControl;

    if (InputSize != 24 || (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 3) >= MmUserProbeAddress)
        return FileIoControl;

    ProbeForRead(Address, 0x18, 1);
    v6 = *((ULONG *)Address + 2);
    if ((ULONG)v6 < 2) return FileIoControl;

    v7 = (volatile void *)Address[2];
    if (!v7) return FileIoControl;
    if ((ULONG64)v7 >= MmUserProbeAddress || (ULONG64)v7 + v6 >= MmUserProbeAddress)
        return FileIoControl;

    ProbeForRead(v7, v6, 1);
    v8 = (ULONG64)(*((_DWORD *)Address + 2) - 2) >> 1;
    v9 = Address[2];
    if (*(WORD *)(v9 + 2 * v8))
        *(WORD *)(v9 + 2 * v8) = 0;
    InitUnicodeFunc(v17, Address[2]);
    FileIoControl = SendCreateFileIoControl(*Address, v17);

    if (!FileIoControl)
    {
        v16 = (int (__fastcall *)(_QWORD, WORD *))GtRead(0x415F);
        v10 = (ULONG)GtRead(GtSdstServiceCount);
        v15 = v10;
        if (!v16 || v10 == (ULONG)-1)
        {
            v13 = (int (__fastcall *)(_QWORD, WORD *))GtRead(16737);
            if (v13) return v13(*Address, v17) >= 0;
        }
        else
        {
            CurrentThread = KeGetCurrentThread();
            v12 = *((UCHAR *)CurrentThread + v10);
            *((UCHAR *)CurrentThread + v10) = 0;
            FileIoControl = v16(*Address, v17) >= 0;
            *((UCHAR *)CurrentThread + v15) = v12;
        }
    }

    return FileIoControl;
}

// OpenFileSection — 打开文件节区
// 对应原始驱动 sub_140078F48
// 通过对象管理器打开文件对应的 Section 对象
__int64 OpenFileSection(__int64 EncodedPath)
{
    __int64 Result;
    void (__fastcall *InitUnicodeFunc)(_BYTE *, __int64);
    int (__fastcall *CreateFileFunc)(_BYTE *, __int64, ULONG64, ULONG64, ULONG64, char, ULONG64, __int64 *);
    void (*CloseFunc)(void);
    _QWORD *DriverListHead;
    char v9;
    _BYTE UnicodeBuffer[16];
    __int64 FileHandle;

    Result = 0;
    InitUnicodeFunc = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (int (__fastcall *)(_BYTE *, __int64, ULONG64, ULONG64, ULONG64, char, ULONG64, __int64 *))GtRead(GtIoCreateFileFunc);
    CloseFunc = (void (*)(void))GtRead(GtCloseHandleFunc);
    DriverListHead = (_QWORD *)GtRead(GtDriverObjectListHead);

    if (!InitUnicodeFunc || !CreateFileFunc || !CloseFunc || !DriverListHead)
        return Result;

    InitUnicodeFunc(UnicodeBuffer, EncodedPath);
    v9 = 0;
    if (CreateFileFunc(UnicodeBuffer, 64, 0, 0, *DriverListHead, v9, 0, &FileHandle) >= 0)
    {
        if (FileHandle)
        {
            Result = FileHandle;
            CloseFunc();
        }
    }

    return Result;
}

// ResolveSymbolicLinkPath — 解析符号链接路径
// 对应原始驱动 sub_14002DB10
// 构造 \SystemRoot 路径，查询 KUSER_SHARED_DATA 获取系统盘符
PWSTR ResolveSymbolicLinkPath(void)
{
    PWSTR Buffer;
    HANDLE LinkHandle;
    UNICODE_STRING LinkTarget;
    UNICODE_STRING DestinationString;
    UNICODE_STRING SourceString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PWSTR Result;
    NTSTATUS Status;

    Buffer = (PWSTR)ExAlloc(NonPagedPool, 0x208);
    if (!Buffer)
        return NULL;

    // Check KUSER_SHARED_DATA for system path (NtSystemRoot)
    if (CheckMemoryValid((void *)0xFFFFF78000000030) == 1)
    {
        // Check if KUSER_SHARED_DATA has valid system root info
        if (*(WORD *)0xFFFFF78000000032 == 0x003A &&  // ":"
            *(WORD *)0xFFFFF78000000034 == 0x005C)    // "\"
        {
            // Copy drive letter from KUSER_SHARED_DATA (0x103 chars = 259)
            WStringCopyN((WORD *)Buffer, (WORD *)0xFFFFF78000000030, 0x103);
            Buffer[0x103] = 0;
            Result = Buffer;
            return Result;
        }
    }

    // Fallback: open \SystemRoot symbolic link and query it
    SourceString.Buffer = L"\\SystemRoot";
    SourceString.Length = 22;
    SourceString.MaximumLength = 24;
    RtlInitUnicodeString(&DestinationString, SourceString.Buffer);

    InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwOpenSymbolicLinkObject(&LinkHandle, GENERIC_READ, &ObjectAttributes);
    if (Status >= 0)
    {
        LinkTarget.Buffer = Buffer;
        LinkTarget.MaximumLength = 0x2080000;
        Status = ZwQuerySymbolicLinkObject(LinkHandle, &LinkTarget, NULL);

        if (Status >= 0)
        {
            // Null-terminate and find last backslash
            Buffer[LinkTarget.Length / 2] = 0;
            PWSTR LastSlash = WStringFindLastChar((WORD *)Buffer, L'\\');
            if (LastSlash && LastSlash[1] != 0)
            {
                ULONG Len = GetStringLength((WORD *)LastSlash) + 1;
                memmove(Buffer, LastSlash, Len * 2);
                Result = Buffer;
                ZwClose(LinkHandle);
                return Result;
            }
        }
        ZwClose(LinkHandle);
    }

    ExFree(Buffer);
    return NULL;
}

// GetDeviceObjectFromFileObject — 从文件对象获取设备对象
// 对应原始驱动 sub_14002DCD0
// 通过 VPB 解析文件对象关联的设备对象和文件系统设备对象
bool GetDeviceObjectFromFileObject(ULONG64 FileObject, ULONG64 *pDeviceObject, ULONG64 *pFileDeviceObject)
{
    ULONG64 Vpb;
    ULONG64 DeviceObj;

    Vpb = *(ULONG64 *)(FileObject + 16);
    *pDeviceObject = 0;

    if (Vpb)
    {
        DeviceObj = *(ULONG64 *)(Vpb + 8);
        if (DeviceObj)
            *pDeviceObject = DeviceObj;
    }

    if (!*pDeviceObject)
        *pDeviceObject = *(ULONG64 *)(FileObject + 8);

    if ((*(ULONG *)(FileObject + 80) & 0x800) == 0)
    {
        Vpb = *(ULONG64 *)(*(ULONG64 *)(FileObject + 8) + 56);
        if (Vpb)
        {
            DeviceObj = *(ULONG64 *)(Vpb + 8);
            if (DeviceObj)
                *pDeviceObject = DeviceObj;
        }
    }

    if (pFileDeviceObject)
    {
        *pFileDeviceObject = 0;
        if (Vpb)
        {
            DeviceObj = *(ULONG64 *)(Vpb + 16);
            if (DeviceObj)
                *pFileDeviceObject = DeviceObj;
        }

        if (!*pFileDeviceObject && (*(ULONG *)(FileObject + 80) & 0x800) == 0)
        {
            DeviceObj = *(ULONG64 *)(*(ULONG64 *)(FileObject + 8) + 56);
            if (DeviceObj)
                *pFileDeviceObject = *(ULONG64 *)(DeviceObj + 16);
        }
    }

    if (*pDeviceObject)
        return !pFileDeviceObject || *pFileDeviceObject != 0;

    return 0;
}

// ReadFileRawData — 读取文件原始数据
// 对应原始驱动 sub_14002F680
// 创建文件，查询标准信息，通过 FSCTL 或 IRP 读取文件内容
__int64 ReadFileRawData(WORD *FilePath, void **OutBuffer, ULONG *OutSize, char RequirePeHeader)
{
    ULONG Status;
    HANDLE Handle;
    ULONG FileInfo[2];
    char *FsctlBuffer;
    ULONG64 FsctlBufferSize;
    ULONG FileSize;
    void *AllocBuffer;
    IO_STATUS_BLOCK IoStatusBlock;

    Status = CreateFileWithPath(FilePath, 0, &Handle, 0x100020, 0x80, 1, 1, 0x20);
    if (Status != 0)
        return Status;

    Status = CmdQueryFileStandardInfo(Handle, FileInfo);
    if (Status != 0)
    {
        ZwClose(Handle);
        return Status;
    }

    FileSize = FileInfo[0];
    Status = QueryDiskFsControlInfo(FilePath, 0, &FsctlBuffer, &FsctlBufferSize);
    if (Status >= 0)
    {
        if (FsctlBufferSize >= FileSize &&
            (!RequirePeHeader || *(WORD *)FsctlBuffer == IMAGE_DOS_SIGNATURE))
        {
            *OutBuffer = FsctlBuffer;
            *OutSize = FileSize;
            ZwClose(Handle);
            return 0;
        }
        ExFree(FsctlBuffer);
    }

    AllocBuffer = ExAlloc(PagedPool, FileSize);
    if (!AllocBuffer)
    {
        ZwClose(Handle);
        return STATUS_UNSUCCESSFUL;
    }

    Status = IrpWriteFile(Handle, 0, FileSize, AllocBuffer, (LARGE_INTEGER *)1, &IoStatusBlock);
    if (Status != 0)
    {
        ExFree(AllocBuffer);
    }
    else
    {
        *OutBuffer = AllocBuffer;
        *OutSize = FileSize;
    }

    ZwClose(Handle);
    return Status;
}

// ReadNtFilePartial — 部分读取 NT 文件
// 对应原始驱动 sub_14002F7BC
// 打开文件，查询大小，读取指定字节数，检查 PE 签名
__int64 ReadNtFilePartial(WORD *FilePath, void *Buffer, ULONG Size, char RequirePeHeader)
{
    NTSTATUS Status;
    HANDLE Handle;
    ULONG64 FileSize;
    void *Src;
    ULONG64 FsctlBufferSize;
    IO_STATUS_BLOCK IoStatusBlock;

    Status = CreateFileWithPath(FilePath, 0, &Handle, 0x100020, 0x80, 1, 1, 0x20);
    if (Status < 0)
        return Status;

    Status = CmdQueryFileStandardInfo(Handle, &FileSize);
    if (Status >= 0)
    {
        if (FileSize < Size)
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            Status = QueryDiskFsControlInfo(FilePath, Size, (char **)&Src, &FsctlBufferSize);
            if (Status >= 0)
            {
                if (FsctlBufferSize < Size ||
                    (RequirePeHeader && *(WORD *)Src != IMAGE_DOS_SIGNATURE))
                {
                    Status = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    memmove(Buffer, Src, Size);
                    Status = STATUS_SUCCESS;
                }
                ExFree(Src);
            }

            if (Status < 0)
            {
                Status = IrpWriteFile(Handle, 0, Size, Buffer, (LARGE_INTEGER *)1, &IoStatusBlock);
            }
        }
    }

    ZwClose(Handle);
    return Status;
}

// ============================================================
// 辅助函数：物理内存 Qword 交换/写入（通过全局表索引）
// ============================================================

// SwapPhysicalMemoryQword — 交换物理内存 Qword
// 对应原始驱动 sub_14007ABD8
// 通过全局表索引读取目标地址和旧值，交换为新的值
char SwapPhysicalMemoryQword(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX OldValueGtIndex)
{
    char ExpectedValue = 0;
    __int64 pTargetAddress = GtRead(GtTotalSize | GtCallbackField00 | GtDriverObject); // 组合索引
    if (pTargetAddress)
    {
        __int64 *TargetAddress = (__int64 *)GtRead(AddressGtIndex);
        unsigned __int64 v7 = (unsigned __int64)TargetAddress;
        if (TargetAddress)
        {
            if (*TargetAddress != pTargetAddress)
            {
                GtWrite(OldValueGtIndex, *TargetAddress);
                WritePhysicalMemoryQword(v7, pTargetAddress);
                return 1;
            }
        }
    }
    return ExpectedValue;
}

// WritePhysicalMemoryFromGt — 从全局表写入物理内存
// 对应原始驱动 sub_140079C7C
// 从全局表中读取目标地址和值，写入物理内存
char WritePhysicalMemoryFromGt(GLOBAL_TABLE_INDEX AddressGtIndex, GLOBAL_TABLE_INDEX ValueGtIndex)
{
    __int64 TargetAddress = GtRead(AddressGtIndex);
    unsigned __int64 TargetValue = (unsigned __int64)TargetAddress;
    if (TargetAddress)
    {
        __int64 v5 = GtRead(ValueGtIndex);
        return WritePhysicalMemoryQword(TargetValue, v5);
    }
    return 0;
}

// ============================================================
// 辅助函数：通过路径打开文件对象
// ============================================================

// OpenFileObjectByPath — 通过路径打开文件对象
// 对应原始驱动 sub_1400591F0
bool OpenFileObjectByPath(PCWSTR SourceString, __int64 DeviceObjectBase, HANDLE *pHandle)
{
    bool Result = 0;
    UNICODE_STRING UnicodeString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    PVOID Object;

    RtlInitUnicodeString(&UnicodeString, SourceString);
    memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
    ObjectAttributes.Length = 48;
    ObjectAttributes.Attributes = 576; // OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
    ObjectAttributes.ObjectName = &UnicodeString;
    ObjectAttributes.RootDirectory = 0;

    if (IoCreateFile(pHandle, 0xC0000000, &ObjectAttributes, &IoStatusBlock,
        0, 0x80, 3, 1, 0, 0, 0, CreateFileTypeNone, 0, 0x100) >= 0)
    {
        if (ObReferenceObjectByHandle(*pHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0) >= 0 && Object)
        {
            Result = (DeviceObjectBase == *((__int64 *)Object + 1));
            ObfDereferenceObject(Object);
            if (!Result)
                ZwClose(*pHandle);
        }
        else
        {
            ZwClose(*pHandle);
        }
    }
    return Result;
}

// ============================================================
// 辅助函数：物理磁盘设备操作
// ============================================================

// OpenPhysicalDiskDevice — 打开物理磁盘设备
// 对应原始驱动 sub_140058AA4
// 根据驱动器号构造 NT 路径格式，通过 IoCreateFile 打开设备
__int64 OpenPhysicalDiskDevice(__int16 *a1, void *a2, void **a3)
{
    NTSTATUS Status = -1073741823; // STATUS_OBJECT_NAME_NOT_FOUND
    PVOID Object;
    UNICODE_STRING DestinationString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR SourceString[64];
    __int16 v15;
    int v16;
    int v8;

    if ((unsigned int)GetStringLength(a1) > 2)
    {
        wmemcpy(SourceString, L"\\??\\", 4);
        v16 = 58;
        if (a1[1] == 58)
        {
            v15 = *a1;
            SourceString[4] = *a1;
            SourceString[5] = L':';
            SourceString[6] = 0;

            RtlInitUnicodeString(&DestinationString, SourceString);
            memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
            ObjectAttributes.Length = 48;
            ObjectAttributes.RootDirectory = 0;
            ObjectAttributes.Attributes = 576;
            ObjectAttributes.ObjectName = &DestinationString;

            Status = IoCreateFile(a3, 0xC0000000, &ObjectAttributes, &IoStatusBlock,
                0, 0x80, 3, 1, 0, 0, 0, CreateFileTypeNone, 0, 0x100);
        }

        if (Status < 0)
        {
            if (ObReferenceObjectByHandle(a2, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0) >= 0 && Object)
            {
                __int64 v7 = *((__int64 *)Object + 1);
                ObfDereferenceObject(Object);

                Status = -1073741823;
                if (CheckMemoryValid((PVOID)0xFFFFF78000000030) == 1 &&
                    MEMORY[0xFFFFF78000000032] == 58 &&
                    MEMORY[0xFFFFF78000000034] == 92)
                {
                    v15 = MEMORY[0xFFFFF78000000030];
                    SourceString[0] = v15;
                    SourceString[1] = L':';
                    SourceString[2] = L'\\';
                    SourceString[3] = 0;
                    if (OpenFileObjectByPath(SourceString, v7, a3))
                        return 0;
                }

                for (v8 = 0; v8 < 26; v8++)
                {
                    wmemcpy(SourceString, L"\\Device\\HarddiskVolume", 22);
                    SourceString[22] = L'0' + v8;
                    SourceString[23] = 0;
                    if (OpenFileObjectByPath(SourceString, v7, a3))
                        return 0;
                }
            }
            else
            {
                return (ULONG)-1073741823;
            }
        }
    }
    return (ULONG)Status;
}

// CalcDiskPartitionOffset — 计算磁盘分区偏移
// 对应原始驱动 sub_140058928
// 遍历分区表计算偏移并乘以扇区大小
__int64 CalcDiskPartitionOffset(int *a1, unsigned int a2)
{
    unsigned int v2 = *a1;
    unsigned __int64 v3 = *((_QWORD *)a1 + 1);
    __int64 v4 = 0;
    unsigned int v5 = 0;

    if (*a1)
    {
        int *v6 = a1 + 4;
        while (1)
        {
            unsigned __int64 v7 = *(_QWORD *)v6;
            if (*(_QWORD *)v6 <= v3)
                break;
            ++v5;
            v6 += 4;
            unsigned __int64 v8 = v7 - v3;
            v3 = v7;
            v4 += v8;
            if (v5 >= v2)
                return v4 * a2;
        }
        v4 = 0;
    }
    return v4 * a2;
}

// QueryPhysicalDiskInfo — 查询物理磁盘信息
// 对应原始驱动 sub_140058F80
// 通过 NtDeviceIoControlFile 获取磁盘信息，构造 PhysicalDriveN 路径打开物理磁盘
__int64 QueryPhysicalDiskInfo(void *FileHandle, _QWORD *pDeviceObject, void **pPhysicalHandle)
{
    NTSTATUS Status = -1073741823;
    ULONG OutputBufferLength = 4096;
    __int64 v6 = GtRead(GtSdstServiceCount);
    __int64 v19 = v6;
    _DWORD *OutputBuffer = NULL;
    UNICODE_STRING DestinationString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    if ((_DWORD)v6 != -1)
    {
        while (1)
        {
            OutputBuffer = ExAlloc(PagedPool, OutputBufferLength);
            if (!OutputBuffer)
            {
                Status = -1073741670;
                break;
            }

            struct _KTHREAD *CurrentThread = KeGetCurrentThread();
            __int64 v11 = (unsigned int)v6;
            char v12 = *((UCHAR *)CurrentThread + (unsigned int)v6);
            *((UCHAR *)CurrentThread + v11) = 0;

            Status = NtDeviceIoControlFile(FileHandle, 0, 0, 0, &IoStatusBlock,
                0x560000, 0, 0, OutputBuffer, OutputBufferLength);

            *((UCHAR *)CurrentThread + v11) = v12;

            if (Status != -1073741820) // STATUS_BUFFER_TOO_SMALL
                break;

            ExFree(OutputBuffer);
            OutputBuffer = NULL;
            *(ULONG *)&v6 = (ULONG)v19;
            OutputBufferLength *= 2;
        }

        if (Status >= 0 && OutputBuffer)
        {
            if (OutputBuffer[2] < 0x1000)
            {
                WCHAR SourceString[64];
                wmemcpy(SourceString, L"\\??\\PhysicalDrive", 17);

                // Format drive number
                WCHAR DriveNumber[16];
                swprintf(DriveNumber, L"%d", OutputBuffer[2]);
                wcscat(SourceString, DriveNumber);

                RtlInitUnicodeString(&DestinationString, SourceString);
                memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
                ObjectAttributes.Length = 48;
                ObjectAttributes.RootDirectory = 0;
                ObjectAttributes.Attributes = 576;
                ObjectAttributes.ObjectName = &DestinationString;

                Status = IoCreateFile(pPhysicalHandle, 0xC0000000, &ObjectAttributes,
                    &IoStatusBlock, 0, 0x80, 3, 1, 0, 0, 0, CreateFileTypeNone, 0, 0x100);

                if (Status >= 0)
                {
                    PVOID Object;
                    Status = ObReferenceObjectByHandle(*pPhysicalHandle, 0,
                        (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0);
                    if (Status >= 0 && Object)
                    {
                        __int64 v15 = *((__int64 *)Object + 1);
                        if (v15)
                        {
                            *pDeviceObject = v15;
                            ObfDereferenceObject(Object);
                        }
                        else
                        {
                            Status = -1073741823;
                            ZwClose(*pPhysicalHandle);
                        }
                    }
                    else
                    {
                        Status = -1073741823;
                        ZwClose(*pPhysicalHandle);
                    }
                }
            }
        }

        if (OutputBuffer)
            ExFree(OutputBuffer);
    }

    return (ULONG)Status;
}

// QueryDeviceObjectInfo — 查询设备对象信息
// 对应原始驱动 sub_140058CE8
char QueryDeviceObjectInfo(__int64 a1, __int64 *a2)
{
    unsigned int v4 = 0;
    __int64 (*SystemRoutineAddress)(__int64) = (__int64 (*)(__int64))GtRead(0x415F); // GtUninstallHookSyscallPeOffset|GtEprocessField77|0x100
    void (*v6)(__int64) = (void (*)(__int64))GtRead(GtCloseHandleFunc);

    if (!SystemRoutineAddress)
    {
        UNICODE_STRING DestinationString;
        WCHAR SourceString[32];
        wcscpy(SourceString, L"IoGetDeviceAttachmentBaseRef");
        SourceString[29] = 0;
        RtlInitUnicodeString(&DestinationString, SourceString);
        SystemRoutineAddress = (__int64 (*)(__int64))MmGetSystemRoutineAddress(&DestinationString);
    }
    if (!v6)
        v6 = (void (*)(__int64))ObfDereferenceObject;

    if (a1 && SystemRoutineAddress && v6)
    {
        __int64 v7 = SystemRoutineAddress(a1);
        if (v7)
        {
            *a2 = v7;
            _QWORD *v8 = *(_QWORD **)(v7 + 8);
            v6(v7);
            if (v8)
            {
                __int64 *v9 = (__int64 *)v8[6];
                if (v9)
                {
                    __int64 v10 = *v9;
                    if (v8 == (_QWORD *)v10)
                    {
                        a2[1] = (__int64)v8;
                        a2[2] = v8[12];
                        a2[3] = v8[29];
                        v4 = (v4 & ~0xFFu) | 1;
                        return (char)v4;
                    }
                    if (v10)
                    {
                        unsigned int *v12 = (unsigned int *)ExAlloc(PagedPool, 0x100000);
                        unsigned int *v13 = v12;
                        if (v12)
                        {
                            *v12 = 0;
                            if (EnumerateDriverList(v12, 0x100000) == 1)
                            {
                                a2[1] = v10;
                                unsigned int v14 = 0;
                                if (*v13)
                                {
                                    unsigned __int64 v15 = *(_QWORD *)(v10 + 96);
                                    while (1)
                                    {
                                        __int64 v16 = 138LL * v14;
                                        unsigned __int64 v17 = *(_QWORD *)&v13[v16 + 8];
                                        if (v15 > v17 && v15 < v17 + v13[v16 + 10])
                                            break;
                                        if (++v14 >= *v13)
                                            goto LABEL_23;
                                    }
                                    a2[1] = (__int64)v8;
                                }
LABEL_23:
                                unsigned int v18 = 0;
                                a2[2] = *(_QWORD *)(v10 + 96);
                                if (*v13)
                                {
                                    unsigned __int64 v19 = v8[12];
                                    while (1)
                                    {
                                        __int64 v20 = 138LL * v18;
                                        unsigned __int64 v21 = *(_QWORD *)&v13[v20 + 8];
                                        if (v19 > v21 && v19 < v21 + v13[v20 + 10])
                                            break;
                                        if (++v18 >= *v13)
                                            goto LABEL_30;
                                    }
                                    a2[2] = v19;
                                }
LABEL_30:
                                a2[3] = *(_QWORD *)(v10 + 232);
                                if (*v13)
                                {
                                    unsigned __int64 v22 = v8[29];
                                    while (1)
                                    {
                                        __int64 v23 = 138LL * v4;
                                        unsigned __int64 v24 = *(_QWORD *)&v13[v23 + 8];
                                        if (v22 > v24 && v22 < v24 + v13[v23 + 10])
                                            break;
                                        if (++v4 >= *v13)
                                            goto LABEL_37;
                                    }
                                    a2[3] = v22;
                                }
LABEL_37:
                                v4 = (v4 & ~0xFFu) | 1;
                            }
                            ExFree(v13);
                        }
                    }
                }
            }
        }
        else
        {
            __int64 v25 = *(_QWORD *)(a1 + 8);
            if (v25)
            {
                a2[1] = v25;
                a2[2] = *(_QWORD *)(v25 + 96);
                a2[3] = *(_QWORD *)(v25 + 232);
                v4 = (v4 & ~0xFFu) | 1;
            }
        }
    }
    return (char)v4;
}

// CheckAddressInModuleRange — 检查地址是否在模块范围内
// 对应原始驱动 sub_140058974
char CheckAddressInModuleRange(__int64 a1)
{
    char v1 = 0;
    int v3 = 0;

    while (1)
    {
        unsigned __int64 v4 = v3 ? *(_QWORD *)(a1 + 24) : *(_QWORD *)(a1 + 16);
        unsigned __int64 v5 = GtRead(GtCallbackField40);
        unsigned int v6 = GtRead(GtCallbackField41);
        if (v5)
        {
            if (v6 && v6 < v5 && v5 <= v4 && v4 < v5 + v6)
                break;
        }
        unsigned __int64 v7 = GtRead(GtCallbackField57);
        unsigned int v8 = GtRead(GtCallbackField58);
        if (v7)
        {
            if (v8 && v8 < v7 && v7 <= v4 && v4 < v7 + v8)
                break;
        }
        unsigned __int64 v9 = GtRead(GtCallbackField59);
        unsigned int v10 = GtRead(GtCallbackField60);
        if (v9)
        {
            if (v10 && v10 < v9 && v9 <= v4 && v4 < v9 + v10)
                break;
        }
        unsigned __int64 v11 = GtRead(GtCallbackField42);
        unsigned int v12 = GtRead(GtCallbackField43);
        if (v11)
        {
            if (v12 && v12 < v11 && v11 <= v4 && v4 < v11 + v12)
                break;
        }
        if ((unsigned int)++v3 >= 2)
            return v1;
    }
    return 1;
}

// QueryDiskFsControlInfoEx — 查询磁盘 FS 控制信息（扩展版）
// 对应原始驱动 sub_140059970
__int64 QueryDiskFsControlInfoEx(void *FileHandle, __int64 a2, unsigned int a3, unsigned int a4, unsigned __int64 a5, char *a6)
{
    unsigned __int64 v6 = 0;
    int v9 = -1073741823;
    unsigned __int64 v26 = 0;
    unsigned int v10 = GtRead(GtSdstServiceCount);
    unsigned int v28 = v10;
    __int64 v29 = v10;
    HANDLE Handle = 0;

    if (v10 != -1)
    {
        if (a5)
        {
            __int64 v33 = 0;
            v9 = QueryPhysicalDiskInfo(FileHandle, &v33, &Handle);
            if (v9 >= 0)
            {
                v9 = -1073741823;
                __int64 v35[4] = {0};
                if (QueryDeviceObjectInfo(v33, v35) == 1 && CheckAddressInModuleRange((__int64)v35) == 1)
                {
                    unsigned __int64 v11 = *(_QWORD *)(a2 + 8);
                    unsigned int v12 = 0;
                    int v24 = 0;

                    if (*(_DWORD *)a2)
                    {
                        while (1)
                        {
                            __int64 v13 = 2LL * v12;
                            unsigned __int64 v14 = *(_QWORD *)(a2 + 16LL * v12 + 16);
                            if (v14 <= v11)
                                break;

                            unsigned __int64 v15 = 0;
                            unsigned __int64 v16 = v14 - v11;
                            unsigned int v17 = a3;
                            __int64 v18 = v10;
                            v29 = v10;

                            if (v16)
                            {
                                do
                                {
                                    __int64 InputBuffer = v17 * (v15 + *(_QWORD *)(a2 + 8 * v13 + 24));
                                    struct _KTHREAD *CurrentThread = KeGetCurrentThread();
                                    HANDLE v20 = FileHandle;
                                    char v21 = *((UCHAR *)CurrentThread + v18);
                                    *((UCHAR *)CurrentThread + v18) = 0;

                                    _BYTE OutputBuffer[16];
                                    __int64 v38 = 0;
                                    IO_STATUS_BLOCK IoStatusBlock;

                                    v9 = NtDeviceIoControlFile(v20, 0, 0, 0, &IoStatusBlock,
                                        0x560020, &InputBuffer, 8, OutputBuffer, 0x18);

                                    v18 = v29;
                                    *((UCHAR *)CurrentThread + v29) = v21;

                                    if (v9 >= 0)
                                    {
                                        v9 = SendDeviceIoControlIrp(v35, 3, a6, v38 / a4, a3 / a4, a4);
                                        if (v9 < 0)
                                            break;
                                        v17 = a3;
                                        a6 += a3;
                                        v26 += a3;
                                        if (v26 >= a5)
                                            goto LABEL_21;
                                        v18 = v29;
                                    }
                                    else
                                    {
                                        v17 = a3;
                                    }
                                    ++v15;
                                } while (v15 < v16);

                                v10 = v28;
                                v6 = v26;
                                v12 = v24;
                            }

                            if (v6 >= a5)
                            {
LABEL_21:
                                v9 = 0;
                                goto LABEL_23;
                            }
                            if (v15 < v16)
                                break;

                            v11 = *(_QWORD *)(a2 + 8 * v13 + 16);
                            v24 = ++v12;
                            if (v12 >= *(_DWORD *)a2)
                                goto LABEL_23;
                        }
                        v9 = -1073741823;
                    }
                }
LABEL_23:
                ZwClose(Handle);
            }
        }
    }
    return (ULONG)v9;
}

// ============================================================
// 12 个缺失函数实现
// ============================================================

// 1. IrpReadCompletionRoutine — IRP 读取完成回调例程
// 对应原始驱动 sub_14002E664
// 将 IRP 的 IoStatus 复制到 UserIosb，设置事件通知完成，根据 Context 标志释放系统缓冲区（bit0）和 MDL（bit1），最后释放 IRP
NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    // 复制 IoStatus 到 UserIosb
    *(_OWORD *)*(_QWORD *)((__int64)Irp + 72) = *(_OWORD *)((__int64)Irp + 48);

    // 设置事件通知完成
    struct _KEVENT *UserEvent = *(struct _KEVENT **)((__int64)Irp + 80);
    if (UserEvent)
        KeSetEvent(UserEvent, 0, 0);

    // 根据 Context 标志释放资源
    char ContextFlags = (char)(ULONG_PTR)Context;
    void *SystemBuffer = *(void **)((__int64)Irp + 24);
    if (SystemBuffer && (ContextFlags & 1) != 0)
    {
        ExFree(SystemBuffer);
        *(_QWORD *)((__int64)Irp + 24) = 0;
    }

    struct _MDL *Mdl = *(struct _MDL **)((__int64)Irp + 8);
    if (Mdl)
    {
        if ((ContextFlags & 2) != 0)
            MmUnlockPages(Mdl);
        IoFreeMdl(*(PMDL *)((__int64)Irp + 8));
        *(_QWORD *)((__int64)Irp + 8) = 0;
    }

    IoFreeIrp(Irp);
    return 3221225494; // STATUS_MORE_PROCESSING_REQUIRED
}

// 2. GetIrpMonitorContext — 获取 IRP 监视上下文
// 对应原始驱动 sub_14002F964
// 检查三个监视条目匹配设备对象，找到对应 MajorFunction 的监视入口，若激活则通过 AtomicExchange16Bytes 交换上下文并返回原始调用驱动指针
char GetIrpMonitorContext(__int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer, _QWORD *pCallDriver)
{
    char Result = 0;
    __int64 MajorFunc = IrpMajorFunc;
    __int64 *pMonitorEntry = NULL;

    *pCallDriver = 0;

    if (((unsigned int)GtRead(GtEprocessField134 | 0x100) &&
         GtRead(GtSavedDeviceObject) == *(_QWORD *)(DeviceObject + 8) &&
         (pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs1 | GtCallbackField79))) != 0) ||
        ((unsigned int)GtRead(GtEprocessField133 | 0x100) &&
         GtRead(GtSavedDeviceObject2) == *(_QWORD *)(DeviceObject + 8) &&
         (pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)(GtObjectTypeField31 | GtPathBuffer00 | 0x800))) != 0) ||
        ((unsigned int)GtRead(GtKernelDataField18) &&
         GtRead(GtSavedDeviceObject3) == *(_QWORD *)(DeviceObject + 8) &&
         (pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)3332)) != 0))
    {
        __int64 MonitorEntry = (__int64)&pMonitorEntry[6 * MajorFunc];
        if (*(_DWORD *)(MonitorEntry + 4) && *(_DWORD *)MonitorEntry == 1)
        {
            *pCallDriver = *(_QWORD *)(MonitorEntry + 8);
            return AtomicExchange16Bytes(MonitorEntry, pContextBuffer);
        }
    }

    return Result;
}

// 3. ReleaseIrpMonitorContext — 释放 IRP 监视上下文
// 对应原始驱动 sub_14002FA68
// 若已获取监视上下文，通过三个监视条目匹配设备对象，使用 AtomicWrite16Bytes 恢复原始上下文
char ReleaseIrpMonitorContext(char IsAcquired, __int64 DeviceObject, unsigned int IrpMajorFunc, _OWORD *pContextBuffer)
{
    char Result = 0;
    __int64 MajorFunc = IrpMajorFunc;
    __int64 *pMonitorEntry;

    if (IsAcquired == 1)
    {
        if ((unsigned int)GtRead(GtEprocessField134 | 0x100))
        {
            if (GtRead(GtSavedDeviceObject) == *(_QWORD *)(DeviceObject + 8))
            {
                pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)(GtFltPeSectionOfs1 | GtCallbackField79));
                if (pMonitorEntry)
                {
                    AtomicWrite16Bytes((__int64)&pMonitorEntry[6 * MajorFunc], pContextBuffer);
                    return 1;
                }
            }
        }
        if ((unsigned int)GtRead(GtEprocessField133 | 0x100))
        {
            if (GtRead(GtSavedDeviceObject2) == *(_QWORD *)(DeviceObject + 8))
            {
                pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)(GtObjectTypeField31 | GtPathBuffer00 | 0x800));
                if (pMonitorEntry)
                {
                    AtomicWrite16Bytes((__int64)&pMonitorEntry[6 * MajorFunc], pContextBuffer);
                    return 1;
                }
            }
        }
        if ((unsigned int)GtRead(GtKernelDataField18))
        {
            if (GtRead(GtSavedDeviceObject3) == *(_QWORD *)(DeviceObject + 8))
            {
                pMonitorEntry = GtAlloc((GLOBAL_TABLE_INDEX)3332);
                if (pMonitorEntry)
                {
                    AtomicWrite16Bytes((__int64)&pMonitorEntry[6 * MajorFunc], pContextBuffer);
                    return 1;
                }
            }
        }
    }
    return Result;
}

// 4. AllocateIrpStackAndCallDriver — 分配 IRP 栈位置并调用驱动
// 对应原始驱动 sub_1400777F8
// 递减 IRP 栈计数，调整栈位置指针，设置设备对象，然后调用驱动
__int64 AllocateIrpStackAndCallDriver(__int64 (*pCallDriver)(__int64, ULONG_PTR, __int64), __int64 DeviceObject, ULONG_PTR Irp)
{
    if ((char)--*(_BYTE *)(Irp + 67) <= 0)
        KeBugCheckEx(0x35, Irp, 0, 0, 0); // BUGCODE_ID_DRIVER

    unsigned __int8 *v3 = (unsigned __int8 *)(*(_QWORD *)(Irp + 184) - 72);
    *(_QWORD *)(Irp + 184) = v3;
    *((_QWORD *)v3 + 5) = DeviceObject;

    if (pCallDriver)
        return pCallDriver(DeviceObject, Irp, DeviceObject);
    else
        return (*(__int64 (**)(__int64, ULONG_PTR, __int64, _QWORD))(*(_QWORD *)(DeviceObject + 8) + 8LL * (UCHAR)*v3 + 112))(
            DeviceObject, Irp, DeviceObject, 0);
}

// 5. AcquireVolumeChangeLock — 获取卷更改锁
// 对应原始驱动 sub_14002F8E4
// 检查设备对象是否匹配三个保存的设备对象，若匹配则通过 SwapPhysicalMemoryQword 交换物理内存中的值
char AcquireVolumeChangeLock(__int64 DeviceObject)
{
    char Changed = 0;
    __int64 DeviceMatch = GtRead(GtSavedDeviceObject);
    if (DeviceMatch && DeviceMatch == *(_QWORD *)(DeviceObject + 8))
        return SwapPhysicalMemoryQword(GtKernelDataField25, GtKernelDataField28);

    __int64 DeviceMatch2 = GtRead(GtSavedDeviceObject2);
    if (DeviceMatch2 && DeviceMatch2 == *(_QWORD *)(DeviceObject + 8))
        return SwapPhysicalMemoryQword(GtKernelDataField26, GtKernelDataField29);

    __int64 DeviceMatch3 = GtRead(GtSavedDeviceObject3);
    if (DeviceMatch3 && DeviceMatch3 == *(_QWORD *)(DeviceObject + 8))
        return SwapPhysicalMemoryQword(GtKernelDataField27, GtKernelDataField30);

    return Changed;
}

// 6. NotifyVolumeDeviceChange — 通知卷设备更改
// 对应原始驱动 sub_14002DF70
// 检查设备对象是否匹配三个保存的设备对象，若匹配则通过 WritePhysicalMemoryFromGt 恢复物理内存值
void NotifyVolumeDeviceChange(char EventType, __int64 DeviceObject)
{
    if (EventType == 1)
    {
        __int64 Device1 = GtRead(GtSavedDeviceObject);
        if (Device1 && Device1 == *(_QWORD *)(DeviceObject + 8))
        {
            WritePhysicalMemoryFromGt(GtKernelDataField28, GtKernelDataField25);
            return;
        }

        __int64 Device2 = GtRead(GtSavedDeviceObject2);
        if (Device2 && Device2 == *(_QWORD *)(DeviceObject + 8))
        {
            WritePhysicalMemoryFromGt(GtKernelDataField29, GtKernelDataField26);
            return;
        }

        __int64 Device3 = GtRead(GtSavedDeviceObject3);
        if (Device3 && Device3 == *(_QWORD *)(DeviceObject + 8))
        {
            WritePhysicalMemoryFromGt(GtKernelDataField30, GtKernelDataField27);
            return;
        }
    }
}

// 7. SwapDiskIrpFunctionPointer — 交换磁盘 IRP 函数指针
// 对应原始驱动 sub_14007AC48
// 保存当前 IRP 函数指针到 GT 693，然后将新函数指针写入物理内存
char SwapDiskIrpFunctionPointer(void)
{
    char v0 = 0;
    __int64 *v1 = (__int64 *)GtRead(GtKernelDataField34);
    __int64 v2 = GtRead(GtIopfCompleteRequestAddr);
    __int64 v3 = v2;

    if (v1 && v2 && *v1 != v2)
    {
        GtWrite(GtKernelDataField35, *v1);
        WritePhysicalMemoryQword((unsigned __int64)v1, v3);
        return 1;
    }
    return v0;
}

// 8. RestoreDiskIrpFunctionPointer — 恢复磁盘 IRP 函数指针
// 对应原始驱动 sub_14007ACB0
// 从 GT 693 读取原始函数指针，通过 WritePhysicalMemoryQword 写回
void RestoreDiskIrpFunctionPointer(char State)
{
    if (State == 1)
    {
        unsigned __int64 v1 = GtRead(GtKernelDataField34);
        if (v1)
        {
            __int64 v2 = GtRead(GtKernelDataField35);
            WritePhysicalMemoryQword(v1, v2);
        }
    }
}

// 9. OpenDriveDeviceObject — 打开驱动器设备对象
// 对应原始驱动 sub_14002DDA4
// 构造 \DosDevices\X:\ 路径，通过 IoCreateFile 打开卷设备，获取文件对象，再通过 GetDeviceObjectFromFileObject 获取设备对象
bool OpenDriveDeviceObject(WCHAR *DriveLetter, _QWORD *pDeviceObject, _QWORD *pFileDevice)
{
    WCHAR DriveChar = *DriveLetter;
    bool DeviceObjectFromFileObject = 0;
    PVOID FileObject;
    HANDLE FileHandle;
    UNICODE_STRING DosPath;
    OBJECT_ATTRIBUTES ObjAttributes;
    IO_STATUS_BLOCK IoStatus;
    WCHAR PathBuffer[20];

    wcscpy(PathBuffer, L"\\DosDevices\\A:\\");

    if (DriveChar != 92 && // '\\'
        CheckMemoryValid((PVOID)0xFFFFF78000000030) == 1 &&
        MEMORY[0xFFFFF78000000030] != 0 &&
        MEMORY[0xFFFFF78000000032] == 58 &&
        MEMORY[0xFFFFF78000000034] == 92)
    {
        PathBuffer[12] = MEMORY[0xFFFFF78000000030];
    }
    else if (DriveChar == 92)
    {
        wcscpy(PathBuffer, L"\\SystemRoot");
    }
    else
    {
        PathBuffer[12] = DriveChar;
    }

    RtlInitUnicodeString(&DosPath, PathBuffer);
    memset(&ObjAttributes, 0, sizeof(ObjAttributes));
    ObjAttributes.Length = 48;
    ObjAttributes.RootDirectory = 0;
    ObjAttributes.Attributes = 576;
    ObjAttributes.ObjectName = &DosPath;

    if (!IoCreateFile(&FileHandle, 0x100000, &ObjAttributes, &IoStatus,
        0, 0, 3, 1, 0x21, 0, 0, CreateFileTypeNone, 0, 0x100))
    {
        if (!ObReferenceObjectByHandle(FileHandle, 1, (POBJECT_TYPE)IoFileObjectType, 0, &FileObject, 0))
        {
            DeviceObjectFromFileObject = GetDeviceObjectFromFileObject((__int64)FileObject, pFileDevice, pDeviceObject);
            ObfDereferenceObject(FileObject);
        }
        ZwClose(FileHandle);
    }

    return DeviceObjectFromFileObject;
}

// 10. CreateFileObject — 创建文件对象
// 对应原始驱动 sub_14002E01C
// 创建文件对象，设置文件名、设备对象，并发送 IRP_MJ_CREATE 打开文件
__int64 CreateFileObject(__int64 UnicodeString, unsigned int DesiredAccess, int FileAttributes,
    USHORT ShareAccess, int Disposition, int CreateOptions,
    struct _DEVICE_OBJECT *DeviceObject, __int64 DeviceObjectBase, _QWORD *pFileObject)
{
    unsigned int v12 = 216;
    _OWORD v40;
    memset(&v40, 0, sizeof(v40));
    int v30 = FileAttributes;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        v12 = 256;

    __int64 v37 = 0;
    __int64 v38 = 0;
    int v36 = 48;
    int v39 = 576;

    PVOID Object;
    int v13 = ObCreateObject(0, (__int64)IoFileObjectType, (__int64)&v36, 0, 0, v12, 0, 0, (__int64)&Object);
    if (v13 < 0)
        return (ULONG)v13;

    memset(Object, 0, v12);
    *(_WORD *)Object = 5;
    *((_WORD *)Object + 1) = v12;
    *((_QWORD *)Object + 1) = DeviceObjectBase;
    *((_DWORD *)Object + 20) = 2;
    *((_WORD *)Object + 44) = *(_WORD *)UnicodeString;
    *((_WORD *)Object + 45) = *(_WORD *)(UnicodeString + 2);
    *((_QWORD *)Object + 12) = ExAllocatePool(NonPagedPool, *(unsigned __int16 *)(UnicodeString + 2));

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
    {
        *((_QWORD *)Object + 24) = (char *)Object + 192;
        *((_QWORD *)Object + 25) = (char *)Object + 192;
    }

    _QWORD *v14 = Object;
    v13 = -1073741670;

    void *v15 = (void *)*((_QWORD *)Object + 12);
    if (!v15)
    {
        v14[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)v13;
    }

    memmove(v15, *(const void **)(UnicodeString + 8), *(unsigned __int16 *)(UnicodeString + 2));
    KeInitializeEvent((PRKEVENT)((UCHAR *)Object + 128), SynchronizationEvent, 0);
    KeInitializeEvent((PRKEVENT)((UCHAR *)Object + 152), NotificationEvent, 0);

    _BYTE Dst[224];
    memset(Dst, 0, sizeof(Dst));
    PGENERIC_MAPPING FileObjectGenericMapping = IoGetFileObjectGenericMapping();
    _BYTE v42[160];
    memset(v42, 0, sizeof(v42));

    if (SeCreateAccessState((__int64)v42, (__int64)Dst, DesiredAccess, (__int64)FileObjectGenericMapping))
        goto LABEL_15;

    CCHAR StackSize = DeviceObject->StackSize;
    _QWORD v32[2];
    int v34 = CreateOptions;
    v32[0] = 0;
    v32[1] = v42;
    unsigned int v33 = DesiredAccess;

    PIRP Irp = IoAllocateIrp(StackSize, 0);
    if (!Irp)
    {
        ExFreePoolWithTag(*((PVOID *)Object + 12), 0);
        *((_QWORD *)Object + 12) = 0;
        *((_WORD *)Object + 44) = 0;
        v14 = Object;
        v14[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)v13;
    }

    struct _KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, 0);

    struct _IO_STACK_LOCATION *CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
    CurrentStackLocation[-1].Context = 0;
    CurrentStackLocation[-1].Control = -32; // 0xE0
    Irp->Flags |= 0x84;
    Irp->MdlAddress = 0;
    Irp->AssociatedIrp.MasterIrp = 0;
    *(WORD *)&Irp->RequestorMode = 0;
    Irp->Cancel = 0;
    Irp->CancelRoutine = 0;

    int v35 = 0;
    Irp->UserIosb = (PIO_STATUS_BLOCK)&v35;
    Irp->UserEvent = &Event;

    struct _IO_STACK_LOCATION *v20 = Irp->Tail.Overlay.CurrentStackLocation;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.AuxiliaryBuffer = 0;
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;

    v20[-1].MajorFunction = 0; // IRP_MJ_CREATE
    v20[-1].DeviceObject = DeviceObject;
    struct _FILE_OBJECT *v21 = (struct _FILE_OBJECT *)Object;
    v20[-1].Parameters.Create.ShareAccess = ShareAccess;
    v20[-1].Parameters.Create.EaLength = 0;
    v20[-1].FileObject = v21;
    v20[-1].Parameters.WMI.ProviderId = (ULONG_PTR)v32;
    v20[-1].Parameters.Create.FileAttributes = v30;
    v20[-1].Parameters.Create.Options = (Disposition << 24) | CreateOptions & 0xFFFFFF;

    _OWORD v44;
    memset(&v44, 0, sizeof(v44));
    __int64 (*v31)(__int64, ULONG_PTR, __int64) = NULL;
    char IrpMonitorContext = GetIrpMonitorContext((__int64)DeviceObject, 0, &v44, &v31);
    char v23 = AcquireVolumeChangeLock((__int64)DeviceObject);
    char v24 = SwapDiskIrpFunctionPointer();
    int v25 = AllocateIrpStackAndCallDriver(v31, (__int64)DeviceObject, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, (__int64)DeviceObject, 0, &v44);

    if (v25 == 259)
        KeWaitForSingleObject(&Event, Executive, 0, 0, 0);

    NotifyVolumeDeviceChange(v23, (__int64)DeviceObject);
    RestoreDiskIrpFunctionPointer(v24);

    if (v35)
    {
LABEL_15:
        v13 = -1073741823;
        ExFreePoolWithTag(*((PVOID *)Object + 12), 0);
        *((_QWORD *)Object + 12) = 0;
        *((_WORD *)Object + 44) = 0;
        v14 = Object;
        v14[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)v13;
    }

    _InterlockedIncrement((volatile signed __int32 *)(*((_QWORD *)Object + 1) + 4));
    void *v26 = Object;
    __int64 v27 = *((_QWORD *)Object + 2);
    if (v27)
    {
        _InterlockedIncrement((volatile signed __int32 *)(v27 + 28));
        v26 = Object;
    }
    *pFileObject = v26;
    return 0;
}

// 11. QueryDiskFsControlInfo — 查询磁盘 FS 控制信息
// 对应原始驱动 sub_14005967C
// 打开文件路径，通过 NtFsControlFile 获取磁盘分区信息，然后打开物理磁盘获取扩展信息，计算分区偏移，最后读取引导扇区数据
__int64 QueryDiskFsControlInfo(__int16 *FilePath, __int64 Size, char **OutBuffer, __int64 *OutBufferSize)
{
    int DiskFsControlInfo = -1073741823;
    unsigned int v7 = GtRead(GtSdstServiceCount);
    __int64 v31 = v7;
    void *v10 = NULL;
    HANDLE FileHandle;

    *OutBuffer = 0;
    *OutBufferSize = 0;

    if (v7 == -1)
        return (ULONG)DiskFsControlInfo;

    _DWORD InputBuffer[2] = {0, 0};

    if (CreateFileWithPath(FilePath, 0, &FileHandle, 0x100020, 0x80, 1, 1, 0x20))
        return (ULONG)DiskFsControlInfo;

    ULONG OutputBufferLength = 4096;
    while (1)
    {
        v10 = ExAlloc(PagedPool, OutputBufferLength);
        if (!v10)
        {
            DiskFsControlInfo = -1073741670;
            goto LABEL_9;
        }

        struct _KTHREAD *CurrentThread = KeGetCurrentThread();
        __int64 v12 = v7;
        char v13 = *((UCHAR *)CurrentThread + v7);
        *((UCHAR *)CurrentThread + v12) = 0;

        IO_STATUS_BLOCK IoStatusBlock;
        DiskFsControlInfo = NtFsControlFile(FileHandle, 0, 0, 0, &IoStatusBlock,
            0x90073, InputBuffer, 8, v10, OutputBufferLength);

        *((UCHAR *)CurrentThread + v12) = v13;

        if (DiskFsControlInfo != -1073741820) // STATUS_BUFFER_TOO_SMALL
            break;

        ExFree(v10);
        v10 = NULL;
        v7 = v31;
        OutputBufferLength *= 2;
    }

    v7 = v31;
LABEL_9:
    if (DiskFsControlInfo >= 0)
    {
        HANDLE Handle;
        DiskFsControlInfo = OpenPhysicalDiskDevice(FilePath, FileHandle, &Handle);
        if (DiskFsControlInfo >= 0)
        {
            struct _KTHREAD *v15 = KeGetCurrentThread();
            __int64 v16 = v7;
            char v17 = *((UCHAR *)v15 + v7);
            *((UCHAR *)v15 + v16) = 0;

            char v36[40];
            unsigned int v37, v38;
            IO_STATUS_BLOCK IoStatusBlock;
            DiskFsControlInfo = NtFsControlFile(Handle, 0, 0, 0, &IoStatusBlock,
                0x90064, 0, 0, v36, 0x60);

            *((UCHAR *)v15 + v16) = v17;

            if (DiskFsControlInfo >= 0)
            {
                v38 = *(unsigned int *)(v36 + 36); // sector size
                v37 = *(unsigned int *)(v36 + 32); // partition count

                unsigned __int64 v19 = v38;
                __int64 v20 = CalcDiskPartitionOffset((int *)v10, v38);
                if (v20 && v19)
                {
                    unsigned __int64 v21;
                    if (Size)
                        v21 = v19 * ((v19 + Size - 1) / v19);
                    else
                        v21 = v20;

                    unsigned int v22 = (unsigned int)v21;
                    if ((unsigned int)v21 > 0x1000)
                        v22 = 4096;

                    char *v24 = (char *)ExAlloc(PagedPool, (unsigned int)(v21 + 256));
                    if (!v24)
                    {
                        DiskFsControlInfo = -1073741670;
                        goto LABEL_29;
                    }

                    memset(v24, 0, v22);
                    memset(&v24[v21], 0, 0x100);

                    DiskFsControlInfo = QueryDiskFsControlInfoEx(Handle, (__int64)v10, v38, v37, v21, v24);
                    if (DiskFsControlInfo < 0)
                    {
                        ExFree(v24);
                        goto LABEL_29;
                    }

                    unsigned int v25 = 0;
                    char *v26 = v24;
                    if (v22)
                    {
                        do
                        {
                            if (*v26)
                                break;
                            ++v25;
                            ++v26;
                        } while (v25 < v22);

                        if (v25 < v22)
                        {
                            *OutBuffer = v24;
                            *OutBufferSize = v21;
                            goto LABEL_29;
                        }
                    }
                    ExFree(v24);
                }
                DiskFsControlInfo = -1073741823;
            }
LABEL_29:
            ZwClose(Handle);
        }
    }

    if (v10)
        ExFree(v10);
    ZwClose(FileHandle);
    return (ULONG)DiskFsControlInfo;
}

// 12. CmdQueryFileStandardInfo — 查询文件标准信息
// 对应原始驱动 sub_14002EED8
// 通过 IrpReadFile 查询文件标准信息（0x18 字节，类型 5），返回标准信息到输出参数
__int64 CmdQueryFileStandardInfo(void *FileHandle, _QWORD *pStandardInfo)
{
    _BYTE IrpBuffer[8];
    __int64 StandardInfo = 0;
    ULONG Status;

    Status = IrpReadFile(FileHandle, (struct _IRP *)IrpBuffer, 0x18, 5);
    if (!Status)
        *pStandardInfo = StandardInfo;
    return Status;
}

// OpenFileCheckExists — 打开文件检查存在
// 对应原始驱动 sub_1400195A4
char OpenFileCheckExists(__int64 FilePath)
{
    void (__fastcall *InitUnicodeFunc)(_BYTE *, __int64);
    __int64 (__fastcall *CreateFileFunc)(__int64 *, __int64, int *);
    void (__fastcall *CloseFunc)(__int64);
    __int64 CloseFuncPtr;

    InitUnicodeFunc = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (__int64 (__fastcall *)(__int64 *, __int64, int *))GtRead(16883);
    CloseFuncPtr = GtRead(GtExFreePoolFunc);
    CloseFunc = (void (__fastcall *)(__int64))CloseFuncPtr;

    if (!InitUnicodeFunc || !CreateFileFunc || !CloseFuncPtr)
        return 1;

    _BYTE v9[16];
    int v10 = 48;
    __int64 v11 = 0;
    _BYTE *v12 = v9;
    int v13 = 576;
    _OWORD v14 = {0};
    __int64 v15;

    InitUnicodeFunc(v9, FilePath);
    __int64 Result = CreateFileFunc(&v15, 1, &v10);
    if (Result < 0)
        return Result != -1073741772;
    CloseFunc(v15);
    return 1;
}

// =========================================================================
// SendDeviceIoControlWithRetry — 带重试机制的设备IO控制发送
// 对应原始驱动 sub_140071E6C
// 发送IOCTL并验证响应签名
// =========================================================================
__int64 __fastcall SendDeviceIoControlWithRetry(__int64 Handle, unsigned int IoControlCode, char Flags, _DWORD **OutputHandle, __int64 IoStatusBlock)
{
    unsigned int Result = -1073741816;
    __int64 (__fastcall *NtFsControlFunc)(__int64, _QWORD, _QWORD, __int64, _DWORD **, __int64) =
        (__int64 (__fastcall *)(__int64, _QWORD, _QWORD, __int64, _DWORD **, __int64))GtRead(GtNtFsControlFileFunc);
    void (*CloseHandleFunc)(void) = (void (*)(void))GtRead(GtCloseHandleFunc);
    _QWORD *HandleValue = (_QWORD *)GtRead(GtEprocessField111 | 0x100);

    if (NtFsControlFunc && CloseHandleFunc && HandleValue)
    {
        Result = NtFsControlFunc(Handle, IoControlCode, *HandleValue, (__int64)Flags, OutputHandle, IoStatusBlock);
        if (!Result && **OutputHandle != 0x6B423432)
        {
            Result = -1073741816;
            CloseHandleFunc();
        }
    }
    return Result;
}

// =========================================================================
// DispatchHookSwapByVersion — 根据Windows版本分发Hook交换操作
// 对应原始驱动 sub_140071F28
// =========================================================================
__int64 __fastcall DispatchHookSwapByVersion(__int64 Handle, __int64 *OriginalValue)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return SwapKernelObjectPointerWin10(Handle, OriginalValue);
    else
        return SwapKernelObjectPointerPreWin10(Handle, OriginalValue);
}

// =========================================================================
// SwapKernelObjectPointerPreWin10 — 交换内核对象指针（Win10之前版本）
// 对应原始驱动 sub_140071F68
// =========================================================================
__int64 __fastcall SwapKernelObjectPointerPreWin10(__int64 Handle, __int64 *OriginalValue)
{
    // 简化实现 — 读取原始指针值
    // 完整实现需要从对象管理器中提取句柄表条目
    if (OriginalValue)
        *OriginalValue = 0;
    return 0;
}

// =========================================================================
// SwapKernelObjectPointerWin10 — 交换内核对象指针（Win10版本）
// 对应原始驱动 sub_1400720BC
// =========================================================================
__int64 __fastcall SwapKernelObjectPointerWin10(__int64 Handle, __int64 *OriginalValue)
{
    // 简化实现 — 读取原始指针值
    if (OriginalValue)
        *OriginalValue = 0;
    return 0;
}

// =========================================================================
// DispatchIoControlByBuildNumber — 根据构建号分发IO控制命令
// 对应原始驱动 sub_140075F48
// =========================================================================
__int64 __fastcall DispatchIoControlByBuildNumber(
    __int64 (__fastcall *HandlerFunc)(__int64, __int64),
    __int64 Arg2,
    __int64 Arg3,
    unsigned __int8 Arg4,
    unsigned int Arg5)
{
    if ((unsigned __int8)GtRead(GtEprocessModuleListOffset | GtNtoskrnlImageSize | 0x100) == 1)
        return HandlerFunc(Arg2, Arg3);
    else
        return ((__int64 (__fastcall *)(__int64, _QWORD, _QWORD, __int64))HandlerFunc)(Arg2, Arg4, Arg5, Arg3);
}

// =========================================================================
// AllocBufferAndQuerySystemInfo — 分配缓冲区并查询系统信息
// 对应原始驱动 sub_14007601C
// =========================================================================
__int64 __fastcall AllocBufferAndQuerySystemInfo(
    __int64 (__fastcall *QueryFunc)(__int64, __int64, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *),
    __int64 Arg2,
    __int64 Arg3,
    int Arg4,
    _BYTE *OutputBuffer,
    SIZE_T BufferSize,
    size_t *ReturnSize)
{
    unsigned int ResultSize = (unsigned int)BufferSize;
    int Result = -1073741823;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
    {
        _BYTE StackBuffer[64];
        _BYTE *PoolBuffer = 0;
        _BYTE *WorkBuffer;

        if ((unsigned int)BufferSize > 0x40)
        {
            PoolBuffer = ExAllocatePoolWithQuotaTag((POOL_TYPE)9, (unsigned int)BufferSize, 0x42424D43u);
            WorkBuffer = PoolBuffer;
        }
        else
        {
            WorkBuffer = StackBuffer;
        }

        if (WorkBuffer)
        {
            size_t MaxCount = 0;
            Result = QueryFunc(Arg2, Arg3, HIDWORD(Arg4), WorkBuffer, BufferSize, &MaxCount, Arg4, WorkBuffer);
            if (Result >= 0)
            {
                *(_DWORD *)ReturnSize = MaxCount;
                if ((unsigned int)BufferSize > MaxCount)
                    ResultSize = MaxCount;
                memmove(OutputBuffer, WorkBuffer, ResultSize);
            }
            if (PoolBuffer)
                ExFreePoolWithTag(PoolBuffer, 0x42424D43u);
        }
    }
    else
    {
        Result = (unsigned int)QueryFunc(Arg2, Arg3, HIDWORD(Arg4), OutputBuffer, BufferSize, ReturnSize, Arg4, 0);
    }
    return (unsigned int)Result;
}

// =========================================================================
// SendCreateFileIoControl — 发送创建文件的IO控制命令
// 对应原始驱动 sub_140072998
// =========================================================================
bool __fastcall SendCreateFileIoControl(__int64 Handle, __int16 *FilePath)
{
    bool Result = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        return 0;

    unsigned int ServiceCount = GtRead(GtSdstServiceCount);
    __int64 (__fastcall *NtFsControlFunc)(__int64, __int64, _QWORD, _QWORD, _DWORD **, unsigned int *) =
        (__int64 (__fastcall *)(__int64, __int64, _QWORD, _QWORD, _DWORD **, unsigned int *))GtRead(GtNtFsControlFileFunc);
    void (*CloseHandleFunc)(_DWORD *) = (void (*)(_DWORD *))GtRead(GtCloseHandleFunc);
    __int64 CallbackFunc = GtRead((enum _GLOBAL_TABLE_INDEX)384);
    __int64 (__fastcall *Callback)(_DWORD *, _WORD *, __int64, _QWORD) = (__int64 (__fastcall *)(_DWORD *, _WORD *, __int64, _QWORD))CallbackFunc;
    _QWORD *HandleValue = (_QWORD *)GtRead(GtEprocessField111 | 0x100);

    if (ServiceCount != -1 && NtFsControlFunc && CloseHandleFunc && CallbackFunc && HandleValue)
    {
        unsigned int *pResultSize = &ServiceCount;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770)
            pResultSize = 0;

        _DWORD *OutputHandle = 0;
        int Status;

        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
            Status = (int)SendDeviceIoControlWithRetry(Handle, 2, 0, &OutputHandle, (__int64)pResultSize);
        else
            Status = (int)NtFsControlFunc(Handle, 2, *HandleValue, 0, &OutputHandle, pResultSize);

        if (Status >= 0)
        {
            _WORD CharBuffer[4];
            __int64 CharBufferValue;
            CharBuffer[0] = *FilePath;
            CharBuffer[1] = FilePath[1];
            CharBufferValue = *((_QWORD *)FilePath + 1);

            if ((CharBuffer[0] & 1) == 0)
            {
                struct _KTHREAD *CurrentThread = KeGetCurrentThread();
                unsigned int ThreadFieldOffset = ServiceCount;
                char SavedFlag = *((char *)CurrentThread + ThreadFieldOffset);
                *((char *)CurrentThread + ThreadFieldOffset) = 0;

                __int64 SwapStorage = 0;
                _QWORD *StoragePtr = (_QWORD *)DispatchHookSwapByVersion((__int64)OutputHandle, &SwapStorage);

                int CallResult;
                if (pResultSize)
                {
                    unsigned int RetSize = *pResultSize;
                    GtRead(GtWindowsBuildNumber);
                    CallResult = (int)Callback(OutputHandle, CharBuffer, Handle, (RetSize >> 2) & 1);
                }
                else
                {
                    CallResult = -1073741823;
                }

                if (StoragePtr)
                    *StoragePtr = SwapStorage;

                *((char *)CurrentThread + ThreadFieldOffset) = SavedFlag;
                Result = CallResult >= 0;
            }
            CloseHandleFunc(OutputHandle);
        }
    }
    return Result;
}

// =========================================================================
// SendIoControlWithQueryBuffer — 发送带查询缓冲区的IO控制命令
// 对应原始驱动 sub_140073630
// =========================================================================
bool __fastcall SendIoControlWithQueryBuffer(__int64 Handle, unsigned int CommandType, _BYTE *OutputBuffer, int BufferSize, size_t *ReturnSize)
{
    bool Result = 0;

    if (CommandType > 5)
        return Result;

    unsigned int ServiceCount = GtRead(GtSdstServiceCount);
    __int64 (__fastcall *NtFsControlFunc)(__int64, __int64, _QWORD, _QWORD, int *, _BYTE *) =
        (__int64 (__fastcall *)(__int64, __int64, _QWORD, _QWORD, int *, _BYTE *))GtRead(GtNtFsControlFileFunc);
    void (*CloseHandleFunc)(void) = (void (*)(void))GtRead(GtCloseHandleFunc);
    __int64 QueryFuncPtr = GtRead(GtEprocessField114 | 0x100);
    _QWORD *HandleValue = (_QWORD *)GtRead(GtEprocessField111 | 0x100);

    if (ServiceCount == -1 || !NtFsControlFunc || !CloseHandleFunc || !QueryFuncPtr || !HandleValue)
        return Result;

    int Status;
    int OutputHandle[2] = { 0 };

    if (CommandType == 3)
    {
        _BYTE IoStatusBlock[4] = { 0 };
        int IoStatus;
        Status = (int)NtFsControlFunc(Handle, 0, *HandleValue, 0, &IoStatus, IoStatusBlock);
        if (!Status && !*(_DWORD *)IoStatusBlock)
        {
            CloseHandleFunc();
            Status = -1073741790;
        }
        goto ProcessStatus;
    }

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
        Status = (int)SendDeviceIoControlWithRetry(Handle, 1, 0, (_DWORD **)OutputHandle, 0);
    else
        Status = (int)NtFsControlFunc(Handle, 1, *HandleValue, 0, OutputHandle, 0);

    unsigned int IsNotSimple = 1;
    if (CommandType == 7)
        IsNotSimple = 0;

ProcessStatus:
    if (!Status)
    {
        struct _KTHREAD *CurrentThread = KeGetCurrentThread();
        char SavedFlag = *((char *)CurrentThread + ServiceCount);
        *((char *)CurrentThread + ServiceCount) = 0;

        __int64 SwapStorage = 0;
        _QWORD *StoragePtr = (_QWORD *)DispatchHookSwapByVersion(*(__int64 *)OutputHandle, &SwapStorage);

        int CallResult = -1073741823;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            __int64 (__fastcall *QueryHandler)(__int64, __int64) =
                (__int64 (__fastcall *)(__int64, __int64))GtRead(GtEprocessField141 | 0x100);
            if (QueryHandler)
            {
                int SubHandle[2] = { 0 };
                CallResult = (int)DispatchIoControlByBuildNumber(QueryHandler, (__int64)OutputHandle, (__int64)SubHandle, 0, IsNotSimple);
                if (!CallResult)
                {
                    __int64 SubHandleValue = *(__int64 *)SubHandle;
                    __int64 SwapStorage2 = 0;
                    _QWORD *SubStoragePtr = 0;

                    if (SubHandleValue)
                    {
                        __int64 ResultPtr = DispatchHookSwapByVersion(SubHandleValue, &SwapStorage2);
                        SubHandleValue = *(__int64 *)SubHandle;
                        SubStoragePtr = (_QWORD *)ResultPtr;
                    }

                    size_t NumberOfBytes = BufferSize;
                    CallResult = (int)AllocBufferAndQuerySystemInfo(
                        (__int64 (__fastcall *)(__int64, __int64, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *))QueryFuncPtr,
                        *(__int64 *)OutputHandle,
                        SubHandleValue,
                        CommandType,
                        OutputBuffer,
                        NumberOfBytes,
                        ReturnSize);

                    if (SubHandleValue)
                    {
                        if (SubStoragePtr)
                            *SubStoragePtr = SwapStorage2;
                        if (SubHandleValue)
                            CloseHandleFunc();
                    }
                }
            }
        }

        if (StoragePtr)
            *StoragePtr = SwapStorage;

        *((char *)CurrentThread + ServiceCount) = SavedFlag;
        ((void (__fastcall *)(_QWORD))CloseHandleFunc)(*(_QWORD *)OutputHandle);
        return CallResult == 0;
    }

    return Result;
}

// EnumerateDriverList — 枚举驱动列表
// 对应原始驱动 sub_14003BF64
// 遍历 PsLoadedModuleList，提取每个驱动模块的镜像基址、大小、完整路径名和基名称
