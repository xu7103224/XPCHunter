// Protocol.c — IRP 通信协议处理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"
#pragma warning(disable:4700)
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

// NtFsControlFile / NtDeviceIoControlFile 已由 WDK 头文件(ntifs.h)声明，
// 通过 ntoskrnl.lib 链接，此处不再重复声明以避免 C4273 dll 链接不一致。

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
    if (!GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, (ULONG64 *)FileDeviceObject))
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
        StackLocation[-1].Parameters.SetFile.ReplaceIfExists = (BOOLEAN)FsctlBuffer->Type;

    IrpMonitorContext = GetIrpMonitorContext(DeviceObject, IRP_MJ_FILE_SYSTEM_CONTROL, &BufferArray, (_QWORD *)&pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObject);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    CallResult = (int)AllocateIrpStackAndCallDriver(pCallDriver, DeviceObject, (ULONG_PTR)Irp);
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
__int64 CompleteIrpAndCleanupMdl(__int64 DeviceObject, __int64 Irp, __int64 Context)
{
    *(_OWORD *)*(_QWORD *)(Irp + 72) = *(_OWORD *)(Irp + 48);
    struct _KEVENT *pCompletionEvent = *(struct _KEVENT **)(Irp + 80);
    if (pCompletionEvent) KeSetEvent(pCompletionEvent, 0, 0);
    if (Context)
    {
        struct _MDL *Result = *(struct _MDL **)(Irp + 8);
        if (Result) { MmUnlockPages(Result); IoFreeMdl(*(PMDL *)(Irp + 8)); *(_QWORD *)(Irp + 8) = 0; }
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
    PLARGE_INTEGER Timeout,
    _DWORD *pBytesRead,
    char WaitForLock,
    char UseSecondary)
{
    int Status;
    __int64 DeviceObject;
    PIRP Irp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
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

    Status = (int)IrpSetupBufferMdl(Irp, DeviceObject, Buffer, Length, (char)Timeout, 1, (_DWORD *)&BufferMdl);
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

    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceObjectCopy = DeviceObjectForFile;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;
    Irp->Overlay.AllocationSize.QuadPart = 0;

    *(WORD *)&CurrentStackLocation[-1].MajorFunction = IRP_MJ_READ | (0x100); // MajorFunction=2, MinorFunction=0x100
    CurrentStackLocation[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObjectCopy;
    CurrentStackLocation[-1].FileObject = (PFILE_OBJECT)Object;
    CurrentStackLocation[-1].Parameters.Read.Length = Length;
    CurrentStackLocation[-1].Parameters.QueryDirectory.FileName = NULL;
    CurrentStackLocation[-1].Parameters.Read.ByteOffset.LowPart = ByteOffset;
    CurrentStackLocation[-1].Parameters.Read.ByteOffset.HighPart = 0;
    CurrentStackLocation[-1].Flags = 0;
    CurrentStackLocation[-1].Flags = WaitForLock == 1;

    if (UseSecondary == 1)
        CurrentStackLocation[-1].Flags |= 2;

    IrpMonitorContext = GetIrpMonitorContext(DeviceObjectCopy, IRP_MJ_READ, &BufferArray, (_QWORD *)&pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObjectCopy);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    Status = (int)AllocateIrpStackAndCallDriver(pCallDriver, DeviceObjectCopy, (ULONG_PTR)Irp);
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
        if (GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, (ULONG64 *)FileDeviceObject))
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
                IrpMonitorContext = GetIrpMonitorContext(DeviceObject, IRP_MJ_QUERY_INFORMATION, &BufferArray, (_QWORD *)&pCallDriver);
                VolumeChangeLock = AcquireVolumeChangeLock(DeviceObject);
                DiskFunctionState = SwapDiskIrpFunctionPointer();
                CallResult = (int)AllocateIrpStackAndCallDriver(pCallDriver, DeviceObject, (ULONG_PTR)Irp);
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
    if (!GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, (ULONG64 *)FileDeviceObject))
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

    Status = (int)IrpSetupBufferMdl(Irp, DeviceObject, Buffer, Length, (char)Timeout, 1, (_DWORD *)&BufferMdl);
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

    IrpMonitorContext = GetIrpMonitorContext(DeviceObjectCopy, IRP_MJ_WRITE, &BufferArray, (_QWORD *)&pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObjectCopy);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    CallResult = (int)AllocateIrpStackAndCallDriver(pCallDriver, DeviceObjectCopy, (ULONG_PTR)Irp);
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
__int64 SendDeviceIoControlIrp(_QWORD *DeviceInfo, int Direction, void *Buffer, int BlockCount, int SectorSize, int SectorCount)
{
    int Status;
    WORD *ContextBuffer;
    _QWORD *CdbBuffer;
    int Result;
    PIRP Irp;
    PMDL Mdl;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    __int64 StackLocationAddr;
    __int64 OldDeviceProcedure;
    __int64 (__fastcall *SendDeviceProcedure)(_QWORD, PIRP);
    __int64 SavedDeviceProcedure;
    _QWORD *pCdbBuffer;
    UCHAR CurrentIrql;
    int IoStatusBlock;
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
    *((_QWORD *)ContextBuffer + 3) = (_QWORD)Buffer;
    *((_DWORD *)ContextBuffer + 4) = SectorCount * SectorSize;
    *(WORD *)((char *)ContextBuffer + 9) = 2560;
    *((_QWORD *)ContextBuffer + 4) = (_QWORD)CdbBuffer;
    *((UCHAR *)ContextBuffer + 11) = 18;
    *((_DWORD *)ContextBuffer + 3) = 256;

    Result = (Direction == 3) ? 64 : 128;
    *((_DWORD *)ContextBuffer + 3) = Result;
    *((_DWORD *)ContextBuffer + 5) = ((SectorCount * SectorSize) >> 10) + 1;
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
    if (!Irp)
    {
        ExFree(CdbBuffer);
        ExFree(ContextBuffer);
        return (ULONG)Status;
    }

    Mdl = IoAllocateMdl(Buffer, SectorCount * SectorSize, FALSE, FALSE, Irp);
    if (!Mdl)
    {
        IoFreeIrp(Irp);
        ExFree(CdbBuffer);
        ExFree(ContextBuffer);
        return (ULONG)Status;
    }

    MmProbeAndLockPages(Mdl, KernelMode, (LOCK_OPERATION)(Direction != 3));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)CompleteIrpAndCleanupMdl;
    CurrentStackLocation[-1].Context = ContextBuffer;
    CurrentStackLocation[-1].Control = 0xE0;
    *((_QWORD *)ContextBuffer + 6) = (_QWORD)Irp;
    Irp->MdlAddress = Mdl;
    Irp->Flags = 1;
    Irp->RequestorMode = KernelMode;
    Irp->UserIosb = (PIO_STATUS_BLOCK)&IoStatusBlock;
    Irp->UserEvent = &Event;
    Irp->Cancel = FALSE;
    Irp->CancelRoutine = NULL;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->IoStatus.Status = 0;
    Irp->IoStatus.Information = 0;
    Irp->AssociatedIrp.MasterIrp = NULL;

    StackLocationAddr = (__int64)&Irp->Tail.Overlay.CurrentStackLocation[-1];
    *(UCHAR *)StackLocationAddr = IRP_MJ_INTERNAL_DEVICE_CONTROL;
    *(_QWORD *)(StackLocationAddr + 40) = *DeviceInfo;
    *(_QWORD *)(StackLocationAddr + 8) = (_QWORD)ContextBuffer;
    Irp->CurrentLocation--;
    Irp->Tail.Overlay.CurrentStackLocation = (struct _IO_STACK_LOCATION *)StackLocationAddr;

    OldDeviceProcedure = IdentityReturnParam(DeviceInfo[2]);
    SendDeviceProcedure = (__int64 (__fastcall *)(_QWORD, PIRP))IdentityReturnParam(DeviceInfo[3]);
    SavedDeviceProcedure = *(_QWORD *)(DeviceInfo[1] + 96);

    CurrentIrql = KeGetCurrentIrql();
    __writecr8(0);
    *(_QWORD *)(DeviceInfo[1] + 96) = OldDeviceProcedure;

    Status = (int)SendDeviceProcedure(*DeviceInfo, Irp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock;
    }

    __writecr8(CurrentIrql);
    *(_QWORD *)(DeviceInfo[1] + 96) = SavedDeviceProcedure;

    pCdbBuffer = (_QWORD *)*((_QWORD *)ContextBuffer + 4);
    if (pCdbBuffer != CdbBuffer && pCdbBuffer)
        ExFreePoolWithTag(pCdbBuffer, 0);

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
    __int64 DeviceObjectHandle;
    struct _IO_STATUS_BLOCK IoStatusBlock;
    _DWORD encPath[6];
    ULONG ShareAccessMask = ShareAccess & 7;
    int PathLen;

    Status = -1073741811;
    if (Disposition > 5)
        return (ULONG)Status;

    StringLength = (ULONG)GetStringLength(FilePath);
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
                    DirCreateStatus = (int)CreateFileWithPath(ParentPathCopy, NULL, (void **)&RootDirHandle,
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

        PrefixLength = (ULONG)GetStringLength((_WORD *)encPath);
        if ((StringLength > PrefixLength &&
             StringCompare3Way((__int64)FilePath, (unsigned __int16 *)encPath, PrefixLength) == 0) ||
            (FilePath[1] == L':' && FilePath[2] == L'\\'))
        {
            Status = -1073741823;
            if (OpenDriveDeviceObject((WCHAR *)FilePath, &DeviceObjectHandle, (_QWORD *)&SourceString))
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
                        PathLen = (int)GetStringLength(SymbolicPath);
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
                    Status = (int)CreateFileObject((__int64)&DestinationString, DesiredAccess,
                        FileAttributes, (USHORT)ShareAccessMask, Disposition, CreateOptions,
                        (struct _DEVICE_OBJECT *)SourceString, DeviceObjectHandle, (_QWORD *)&Object);
                    if (!Status)
                    {
                        Status = ObOpenObjectByPointer(Object, 0x200, NULL,
                            DesiredAccess | 0x100000, (POBJECT_TYPE)IoFileObjectType,
                            KernelMode, FileHandle);
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
bool QueryFileInfoByHandle(__int64 Process, __int64 FileHandle, __int64 InfoBuffer)
{
    bool Result = 0;
    ULONG ObjAttributes;
    int (__fastcall *ObjName)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, __int64 *);
    _QWORD *Status;
    void (__fastcall *BufferSize)(__int64);
    __int64 Buffer;
    __int64 (*QueryFileFunc)(__int64, __int64 *, __int64 *, __int64);
    struct _KTHREAD *CurrentThread;
    char SavedPrevMode;
    int QueryResult;
    __int64 FilePathOut = FileHandle;
    __int64 InfoOut = InfoBuffer;
    __int64 QueryInfoResult;

    ObjAttributes = (ULONG)GtRead(GtSdstServiceCount);
    ObjName = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, __int64 *))GtRead(16735);
    Status = (_QWORD *)GtRead(16748);
    BufferSize = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    Buffer = GtRead(16839);
    QueryFileFunc = (__int64 (*)(__int64, __int64 *, __int64 *, __int64))Buffer;

    if (ObjAttributes == (ULONG)-1 || !ObjName || !Status || !BufferSize || !Buffer) return Result;

    CurrentThread = KeGetCurrentThread();
    if (ObjName(Process, 512, 0, 0x10000000, *Status, 0, &QueryInfoResult) >= 0)
    {
        SavedPrevMode = *((UCHAR *)CurrentThread + ObjAttributes);
        *((UCHAR *)CurrentThread + ObjAttributes) = 0;
        QueryResult = (int)QueryFileFunc(QueryInfoResult, &FilePathOut, &InfoOut, 0x8000);
        *((UCHAR *)CurrentThread + ObjAttributes) = SavedPrevMode;
        Result = QueryResult >= 0;
        BufferSize(QueryInfoResult);
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
    SIZE_T DeviceObject;
    volatile void *pIrp;
    ULONG64 EventObj;
    __int64 Status;
    ULONG BytesReturned;
    struct _KTHREAD *CurrentThread;
    char SavedPrevMode;
    int (__fastcall *FileHandle)(_QWORD, WORD *);
    ULONG pObjAttr;
    int (__fastcall *pUnicodeStr)(_QWORD, WORD *);
    WORD UnicodeStr[20];

    InitUnicodeFunc = (void (__fastcall *)(WORD *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    if (!InitUnicodeFunc) return FileIoControl;
    if (!Address) return FileIoControl;

    if (InputSize != 24 || (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 3) >= MmUserProbeAddress)
        return FileIoControl;

    ProbeForRead(Address, 0x18, 1);
    DeviceObject = *((ULONG *)Address + 2);
    if ((ULONG)DeviceObject < 2) return FileIoControl;

    pIrp = (volatile void *)Address[2];
    if (!pIrp) return FileIoControl;
    if ((ULONG64)pIrp >= MmUserProbeAddress || (ULONG64)pIrp + DeviceObject >= MmUserProbeAddress)
        return FileIoControl;

    ProbeForRead(pIrp, DeviceObject, 1);
    EventObj = (ULONG64)(*((_DWORD *)Address + 2) - 2) >> 1;
    Status = Address[2];
    if (*(WORD *)(Status + 2 * EventObj))
        *(WORD *)(Status + 2 * EventObj) = 0;
    InitUnicodeFunc(UnicodeStr, Address[2]);
    FileIoControl = SendCreateFileIoControl(*Address, UnicodeStr);

    if (!FileIoControl)
    {
        pUnicodeStr = (int (__fastcall *)(_QWORD, WORD *))GtRead(0x415F);
        BytesReturned = (ULONG)GtRead(GtSdstServiceCount);
        pObjAttr = BytesReturned;
        if (!pUnicodeStr || BytesReturned == (ULONG)-1)
        {
            FileHandle = (int (__fastcall *)(_QWORD, WORD *))GtRead(16737);
            if (FileHandle) return FileHandle(*Address, UnicodeStr) >= 0;
        }
        else
        {
            CurrentThread = KeGetCurrentThread();
            SavedPrevMode = *((UCHAR *)CurrentThread + BytesReturned);
            *((UCHAR *)CurrentThread + BytesReturned) = 0;
            FileIoControl = pUnicodeStr(*Address, UnicodeStr) >= 0;
            *((UCHAR *)CurrentThread + pObjAttr) = SavedPrevMode;
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
    char Status;
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
    Status = 0;
    if (CreateFileFunc(UnicodeBuffer, 64, 0, 0, *DriverListHead, Status, 0, &FileHandle) >= 0)
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
            WStringCopyN((WORD *)Buffer, (__int64)0xFFFFF78000000030, 0x103);
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
        LinkTarget.MaximumLength = (USHORT)0x2080000;
        Status = ZwQuerySymbolicLinkObject(LinkHandle, &LinkTarget, NULL);

        if (Status >= 0)
        {
            // Null-terminate and find last backslash
            Buffer[LinkTarget.Length / 2] = 0;
            PWSTR LastSlash = WStringFindLastChar((WORD *)Buffer, L'\\');
            if (LastSlash && LastSlash[1] != 0)
            {
                ULONG Len = (ULONG)GetStringLength((WORD *)LastSlash) + 1;
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

    Status = (ULONG)CreateFileWithPath(FilePath, 0, &Handle, 0x100020, 0x80, 1, 1, 0x20);
    if (Status != 0)
        return Status;

    Status = (ULONG)CmdQueryFileStandardInfo(Handle, (_QWORD *)FileInfo);
    if (Status != 0)
    {
        ZwClose(Handle);
        return Status;
    }

    FileSize = FileInfo[0];
    Status = (ULONG)QueryDiskFsControlInfo(FilePath, 0, &FsctlBuffer, &FsctlBufferSize);
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

    Status = (ULONG)IrpWriteFile(Handle, 0, FileSize, AllocBuffer, (LARGE_INTEGER *)1, &IoStatusBlock);
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

    Status = (NTSTATUS)CreateFileWithPath(FilePath, 0, &Handle, 0x100020, 0x80, 1, 1, 0x20);
    if (Status < 0)
        return Status;

    Status = (NTSTATUS)CmdQueryFileStandardInfo(Handle, &FileSize);
    if (Status >= 0)
    {
        if (FileSize < Size)
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            Status = (NTSTATUS)QueryDiskFsControlInfo(FilePath, Size, (char **)&Src, &FsctlBufferSize);
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
                Status = (NTSTATUS)IrpWriteFile(Handle, 0, Size, Buffer, (LARGE_INTEGER *)1, &IoStatusBlock);
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
        unsigned __int64 pMdl = (unsigned __int64)TargetAddress;
        if (TargetAddress)
        {
            if (*TargetAddress != pTargetAddress)
            {
                GtWrite(OldValueGtIndex, *TargetAddress);
                WritePhysicalMemoryQword(pMdl, pTargetAddress);
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
        __int64 GtValue = GtRead(ValueGtIndex);
        return WritePhysicalMemoryQword(TargetValue, GtValue);
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
__int64 OpenPhysicalDiskDevice(__int16 *DevicePath, void *DeviceHandle, void **ppFileHandle)
{
    NTSTATUS Status = -1073741823; // STATUS_OBJECT_NAME_NOT_FOUND
    PVOID Object;
    UNICODE_STRING DestinationString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR SourceString[64];
    __int16 DriveLetter;
    int Result;
    int DriveIndex;

    if ((unsigned int)GetStringLength(DevicePath) > 2)
    {
        wmemcpy(SourceString, L"\\??\\", 4);
        Result = 58;
        if (DevicePath[1] == 58)
        {
            DriveLetter = *DevicePath;
            SourceString[4] = *DevicePath;
            SourceString[5] = L':';
            SourceString[6] = 0;

            RtlInitUnicodeString(&DestinationString, SourceString);
            memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
            ObjectAttributes.Length = 48;
            ObjectAttributes.RootDirectory = 0;
            ObjectAttributes.Attributes = 576;
            ObjectAttributes.ObjectName = &DestinationString;

            Status = IoCreateFile(ppFileHandle, 0xC0000000, &ObjectAttributes, &IoStatusBlock,
                0, 0x80, 3, 1, 0, 0, 0, CreateFileTypeNone, 0, 0x100);
        }

        if (Status < 0)
        {
            if (ObReferenceObjectByHandle(DeviceHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0) >= 0 && Object)
            {
                ObfDereferenceObject(Object);

                Status = -1073741823;
                if (CheckMemoryValid((PVOID)0xFFFFF78000000030) == 1 &&
                    MEMORY[0xFFFFF78000000032] == 58 &&
                    MEMORY[0xFFFFF78000000034] == 92)
                {
                    DriveLetter = MEMORY[0xFFFFF78000000030];
                    SourceString[0] = DriveLetter;
                    SourceString[1] = L':';
                    SourceString[2] = L'\\';
                    SourceString[3] = 0;
                    if (OpenFileObjectByPath(SourceString, Status, ppFileHandle))
                        return 0;
                }

                for (DriveIndex = 0; DriveIndex < 26; DriveIndex++)
                {
                    wmemcpy(SourceString, L"\\Device\\HarddiskVolume", 22);
                    SourceString[22] = L'0' + DriveIndex;
                    SourceString[23] = 0;
                    if (OpenFileObjectByPath(SourceString, DriveIndex, ppFileHandle))
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
__int64 CalcDiskPartitionOffset(int *PartitionEntry, unsigned int EntryCount)
{
    unsigned int PartitionCount = *PartitionEntry;
    unsigned __int64 PreviousOffset = *((_QWORD *)PartitionEntry + 1);
    __int64 CumulativeOffset = 0;
    unsigned int Offset = 0;

    if (*PartitionEntry)
    {
        int *Index = PartitionEntry + 4;
        while (1)
        {
            unsigned __int64 Result = *(_QWORD *)Index;
            if (*(_QWORD *)Index <= PreviousOffset)
                break;
            ++Offset;
            Index += 4;
            unsigned __int64 PartitionIndex = Result - PreviousOffset;
            PreviousOffset = Result;
            CumulativeOffset += PartitionIndex;
            if (Offset >= PartitionCount)
                return CumulativeOffset * EntryCount;
        }
        CumulativeOffset = 0;
    }
    return CumulativeOffset * EntryCount;
}

// QueryPhysicalDiskInfo — 查询物理磁盘信息
// 对应原始驱动 sub_140058F80
// 通过 NtDeviceIoControlFile 获取磁盘信息，构造 PhysicalDriveN 路径打开物理磁盘
__int64 QueryPhysicalDiskInfo(void *FileHandle, _QWORD *pDeviceObject, void **pPhysicalHandle)
{
    NTSTATUS Status = -1073741823;
    ULONG OutputBufferLength = 4096;
    __int64 DeviceObject = GtRead(GtSdstServiceCount);
    __int64 SavedDeviceObject = DeviceObject;
    _DWORD *OutputBuffer = NULL;
    UNICODE_STRING DestinationString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;

    if ((_DWORD)DeviceObject != -1)
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
            __int64 pBuffer = (unsigned int)DeviceObject;
            char BuildNumber = *((UCHAR *)CurrentThread + (unsigned int)DeviceObject);
            *((UCHAR *)CurrentThread + pBuffer) = 0;

            Status = NtDeviceIoControlFile(FileHandle, 0, 0, 0, &IoStatusBlock,
                0x560000, 0, 0, OutputBuffer, OutputBufferLength);

            *((UCHAR *)CurrentThread + pBuffer) = BuildNumber;

            if (Status != -1073741820) // STATUS_BUFFER_TOO_SMALL
                break;

            ExFree(OutputBuffer);
            OutputBuffer = NULL;
            *(ULONG *)&DeviceObject = (ULONG)SavedDeviceObject;
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
                        __int64 InfoBuffer = *((__int64 *)Object + 1);
                        if (InfoBuffer)
                        {
                            *pDeviceObject = InfoBuffer;
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
char QueryDeviceObjectInfo(__int64 DeviceObject, __int64 *pDeviceInfo)
{
    unsigned int Result = 0;
    __int64 (*SystemRoutineAddress)(__int64) = (__int64 (*)(__int64))GtRead(0x415F); // GtUninstallHookSyscallPeOffset|GtEprocessField77|0x100
    void (*pCloseFunc)(__int64) = (void (*)(__int64))GtRead(GtCloseHandleFunc);

    if (!SystemRoutineAddress)
    {
        UNICODE_STRING DestinationString;
        WCHAR SourceString[32];
        wcscpy(SourceString, L"IoGetDeviceAttachmentBaseRef");
        SourceString[29] = 0;
        RtlInitUnicodeString(&DestinationString, SourceString);
        SystemRoutineAddress = (__int64 (*)(__int64))MmGetSystemRoutineAddress(&DestinationString);
    }
    if (!pCloseFunc)
        pCloseFunc = (void (*)(__int64))ObfDereferenceObject;

    if (DeviceObject && SystemRoutineAddress && pCloseFunc)
    {
        __int64 DeviceBase = SystemRoutineAddress(DeviceObject);
        if (DeviceBase)
        {
            *pDeviceInfo = DeviceBase;
            _QWORD *DriverObj = *(_QWORD **)(DeviceBase + 8);
            pCloseFunc(DeviceBase);
            if (DriverObj)
            {
                __int64 *DriverObjList = (__int64 *)DriverObj[6];
                if (DriverObjList)
                {
                    __int64 DriverStart = *DriverObjList;
                    if (DriverObj == (_QWORD *)DriverStart)
                    {
                        pDeviceInfo[1] = (__int64)DriverObj;
                        pDeviceInfo[2] = DriverObj[12];
                        pDeviceInfo[3] = DriverObj[29];
                        Result = (Result & ~0xFFu) | 1;
                        return (char)Result;
                    }
                    if (DriverStart)
                    {
                        unsigned int *ModuleList = (unsigned int *)ExAlloc(PagedPool, 0x100000);
                        unsigned int *ModuleCount = ModuleList;
                        if (ModuleList)
                        {
                            *ModuleList = 0;
                            if (EnumerateDriverList(ModuleList, 0x100000) == 1)
                            {
                                pDeviceInfo[1] = DriverStart;
                                unsigned int Index = 0;
                                if (*ModuleCount)
                                {
                                    unsigned __int64 DeviceBaseAddr = *(_QWORD *)(DriverStart + 96);
                                    while (1)
                                    {
                                        __int64 EntryOffset = 138LL * Index;
                                        unsigned __int64 ModuleBase = *(_QWORD *)&ModuleCount[EntryOffset + 8];
                                        if (DeviceBaseAddr > ModuleBase && DeviceBaseAddr < ModuleBase + ModuleCount[EntryOffset + 10])
                                            break;
                                        if (++Index >= *ModuleCount)
                                            goto LABEL_23;
                                    }
                                    pDeviceInfo[1] = (__int64)DriverObj;
                                }
LABEL_23:
                                unsigned int Index2 = 0;
                                pDeviceInfo[2] = *(_QWORD *)(DriverStart + 96);
                                if (*ModuleCount)
                                {
                                    unsigned __int64 ModuleBase2 = DriverObj[12];
                                    while (1)
                                    {
                                        __int64 EntryOffset2 = 138LL * Index2;
                                        unsigned __int64 DeviceBase2 = *(_QWORD *)&ModuleCount[EntryOffset2 + 8];
                                        if (ModuleBase2 > DeviceBase2 && ModuleBase2 < DeviceBase2 + ModuleCount[EntryOffset2 + 10])
                                            break;
                                        if (++Index2 >= *ModuleCount)
                                            goto LABEL_30;
                                    }
                                    pDeviceInfo[2] = ModuleBase2;
                                }
LABEL_30:
                                pDeviceInfo[3] = *(_QWORD *)(DriverStart + 232);
                                if (*ModuleCount)
                                {
                                    unsigned __int64 ModuleBase3 = DriverObj[29];
                                    while (1)
                                    {
                                        __int64 EntryOffset3 = 138LL * Result;
                                        unsigned __int64 ModuleBase4 = *(_QWORD *)&ModuleCount[EntryOffset3 + 8];
                                        if (ModuleBase3 > ModuleBase4 && ModuleBase3 < ModuleBase4 + ModuleCount[EntryOffset3 + 10])
                                            break;
                                        if (++Result >= *ModuleCount)
                                            goto LABEL_37;
                                    }
                                    pDeviceInfo[3] = ModuleBase3;
                                }
LABEL_37:
                                Result = (Result & ~0xFFu) | 1;
                            }
                            ExFree(ModuleCount);
                        }
                    }
                }
            }
        }
        else
        {
            __int64 Offset = *(_QWORD *)(DeviceObject + 8);
            if (Offset)
            {
                pDeviceInfo[1] = Offset;
                pDeviceInfo[2] = *(_QWORD *)(Offset + 96);
                pDeviceInfo[3] = *(_QWORD *)(Offset + 232);
                Result = (Result & ~0xFFu) | 1;
            }
        }
    }
    return (char)Result;
}

// CheckAddressInModuleRange — 检查地址是否在模块范围内
// 对应原始驱动 sub_140058974
char CheckAddressInModuleRange(__int64 TargetAddress)
{
    char IsInRange = 0;
    int CheckRound = 0;

    while (1)
    {
        unsigned __int64 ModuleList = CheckRound ? *(_QWORD *)(TargetAddress + 24) : *(_QWORD *)(TargetAddress + 16);
        unsigned __int64 ModuleCount = GtRead(GtCallbackField40);
        unsigned int Index = (unsigned int)GtRead(GtCallbackField41);
        if (ModuleCount)
        {
            if (Index && Index < ModuleCount && ModuleCount <= ModuleList && ModuleList < ModuleCount + Index)
                break;
        }
        unsigned __int64 ModuleBase = GtRead(GtCallbackField57);
        unsigned int ModuleSize = (unsigned int)GtRead(GtCallbackField58);
        if (ModuleBase)
        {
            if (ModuleSize && ModuleSize < ModuleBase && ModuleBase <= ModuleList && ModuleList < ModuleBase + ModuleSize)
                break;
        }
        unsigned __int64 RangeBase3 = GtRead(GtCallbackField59);
        unsigned int RangeSize3 = (unsigned int)GtRead(GtCallbackField60);
        if (RangeBase3)
        {
            if (RangeSize3 && RangeSize3 < RangeBase3 && RangeBase3 <= ModuleList && ModuleList < RangeBase3 + RangeSize3)
                break;
        }
        unsigned __int64 RangeBase4 = GtRead(GtCallbackField42);
        unsigned int RangeSize4 = (unsigned int)GtRead(GtCallbackField43);
        if (RangeBase4)
        {
            if (RangeSize4 && RangeSize4 < RangeBase4 && RangeBase4 <= ModuleList && ModuleList < RangeBase4 + RangeSize4)
                break;
        }
        if ((unsigned int)++CheckRound >= 2)
            return IsInRange;
    }
    return 1;
}

// QueryDiskFsControlInfoEx — 查询磁盘 FS 控制信息（扩展版）
// 对应原始驱动 sub_140059970
__int64 QueryDiskFsControlInfoEx(void *FileHandle, __int64 InputHeader, unsigned int DesiredAccess, unsigned int SectorSize, unsigned __int64 TotalBytes, char *WriteBuffer)
{
    unsigned __int64 SavedTransferOffset = 0;
    int IoStatus = -1073741823;
    unsigned __int64 TransferOffset = 0;
    unsigned int EventObj = (unsigned int)GtRead(GtSdstServiceCount);
    __int64 ThreadByteIndex = EventObj;
    HANDLE Handle = 0;

    if (EventObj != -1)
    {
        if (TotalBytes)
        {
            __int64 PhysicalDiskInfo = 0;
            IoStatus = (int)QueryPhysicalDiskInfo(FileHandle, &PhysicalDiskInfo, &Handle);
            if (IoStatus >= 0)
            {
                IoStatus = -1073741823;
                __int64 DeviceInfo[4] = {0};
                if (QueryDeviceObjectInfo(PhysicalDiskInfo, DeviceInfo) == 1 && CheckAddressInModuleRange((__int64)DeviceInfo) == 1)
                {
                    unsigned __int64 StatusBlock = *(_QWORD *)(InputHeader + 8);
                    unsigned int DiskIndex = 0;
                    int LastStatus = 0;

                    if (*(_DWORD *)InputHeader)
                    {
                        while (1)
                        {
                            __int64 EntryOffset = 2LL * DiskIndex;
                            unsigned __int64 EntryBuffer = *(_QWORD *)(InputHeader + 16LL * DiskIndex + 16);
                            if (EntryBuffer <= StatusBlock)
                                break;

                            unsigned __int64 BufferIndex = 0;
                            unsigned __int64 BufferSize = EntryBuffer - StatusBlock;
                            unsigned int RemainingBytes = DesiredAccess;
                            __int64 SavedThreadByte = EventObj;
                            ThreadByteIndex = EventObj;

                            if (BufferSize)
                            {
                                do
                                {
                                    __int64 CdbCommand = RemainingBytes * (BufferIndex + *(_QWORD *)(InputHeader + 8 * EntryOffset + 24));
                                    struct _KTHREAD *CurrentThread = KeGetCurrentThread();
                                    HANDLE DeviceHandle = FileHandle;
                                    char SavedThreadByteVal = *((UCHAR *)CurrentThread + SavedThreadByte);
                                    *((UCHAR *)CurrentThread + SavedThreadByte) = 0;

                                    _BYTE OutputBuffer[16];
                                    __int64 BlockOffset = 0;
                                    IO_STATUS_BLOCK IoStatusBlock;

                                    IoStatus = NtDeviceIoControlFile(DeviceHandle, 0, 0, 0, &IoStatusBlock,
                                        0x560020, &CdbCommand, 8, OutputBuffer, 0x18);

                                    SavedThreadByte = ThreadByteIndex;
                                    *((UCHAR *)CurrentThread + ThreadByteIndex) = SavedThreadByteVal;

                                    if (IoStatus >= 0)
                                    {
                                        IoStatus = (int)SendDeviceIoControlIrp(DeviceInfo, 3, WriteBuffer, (int)(BlockOffset / SectorSize), DesiredAccess / SectorSize, SectorSize);
                                        if (IoStatus < 0)
                                            break;
                                        RemainingBytes = DesiredAccess;
                                        WriteBuffer += DesiredAccess;
                                        TransferOffset += DesiredAccess;
                                        if (TransferOffset >= TotalBytes)
                                            goto LABEL_21;
                                        SavedThreadByte = ThreadByteIndex;
                                    }
                                    else
                                    {
                                        RemainingBytes = DesiredAccess;
                                    }
                                    ++BufferIndex;
                                } while (BufferIndex < BufferSize);

                                SavedTransferOffset = TransferOffset;
                                DiskIndex = LastStatus;
                            }

                            if (SavedTransferOffset >= TotalBytes)
                            {
LABEL_21:
                                IoStatus = 0;
                                goto LABEL_23;
                            }
                            if (BufferIndex < BufferSize)
                                break;

                            StatusBlock = *(_QWORD *)(InputHeader + 8 * EntryOffset + 16);
                            LastStatus = ++DiskIndex;
                            if (DiskIndex >= *(_DWORD *)InputHeader)
                                goto LABEL_23;
                        }
                        IoStatus = -1073741823;
                    }
                }
LABEL_23:
                ZwClose(Handle);
            }
        }
    }
    return (ULONG)IoStatus;
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

    unsigned __int8 *StackLocation = (unsigned __int8 *)(*(_QWORD *)(Irp + 184) - 72);
    *(_QWORD *)(Irp + 184) = (_QWORD)StackLocation;
    *((_QWORD *)StackLocation + 5) = DeviceObject;

    if (pCallDriver)
        return pCallDriver(DeviceObject, Irp, DeviceObject);
    else
        return (*(__int64 (**)(__int64, ULONG_PTR, __int64, _QWORD))(*(_QWORD *)(DeviceObject + 8) + 8LL * (UCHAR)*StackLocation + 112))(
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
    char Result = 0;
    __int64 *pIrpFunctionAddr = (__int64 *)GtRead(GtKernelDataField34);
    __int64 CurrentIrpFunction = GtRead(GtIopfCompleteRequestAddr);
    __int64 NewIrpFunction = CurrentIrpFunction;

    if (pIrpFunctionAddr && CurrentIrpFunction && *pIrpFunctionAddr != CurrentIrpFunction)
    {
        GtWrite(GtKernelDataField35, *pIrpFunctionAddr);
        WritePhysicalMemoryQword((unsigned __int64)pIrpFunctionAddr, NewIrpFunction);
        return 1;
    }
    return Result;
}

// 8. RestoreDiskIrpFunctionPointer — 恢复磁盘 IRP 函数指针
// 对应原始驱动 sub_14007ACB0
// 从 GT 693 读取原始函数指针，通过 WritePhysicalMemoryQword 写回
void RestoreDiskIrpFunctionPointer(char State)
{
    if (State == 1)
    {
        unsigned __int64 IrpFunctionAddr = GtRead(GtKernelDataField34);
        if (IrpFunctionAddr)
        {
            __int64 SavedIrpFunction = GtRead(GtKernelDataField35);
            WritePhysicalMemoryQword(IrpFunctionAddr, SavedIrpFunction);
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
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    unsigned int ObjectSize = 216;
    _OWORD SecurityDescriptor;
    memset(&SecurityDescriptor, 0, sizeof(SecurityDescriptor));
    int SavedFileAttributes = FileAttributes;

    if (BuildNumber >= 0x1770)
        ObjectSize = 256;

    __int64 EventHandle = 0;
    __int64 IoStatusHandle = 0;
    int AccessMode = 48;
    int DesiredAccessLevel = 576;

    PVOID Object;
    int Result = ObCreateObject((KPROCESSOR_MODE)0, (POBJECT_TYPE)IoFileObjectType, (POBJECT_ATTRIBUTES)&AccessMode, (KPROCESSOR_MODE)0, 0, ObjectSize, 0, 0, (PVOID *)&Object);
    if (Result < 0)
        return (ULONG)Result;

    memset(Object, 0, ObjectSize);
    *(_WORD *)Object = 5;
    *((_WORD *)Object + 1) = ObjectSize;
    *((_QWORD *)Object + 1) = DeviceObjectBase;
    *((_DWORD *)Object + 20) = 2;
    *((_WORD *)Object + 44) = *(_WORD *)UnicodeString;
    *((_WORD *)Object + 45) = *(_WORD *)(UnicodeString + 2);
    *((_QWORD *)Object + 12) = (_QWORD)ExAllocatePool(NonPagedPool, *(unsigned __int16 *)(UnicodeString + 2));

    if (BuildNumber >= 0x1770)
    {
        *((_QWORD *)Object + 24) = (_QWORD)((char *)Object + 192);
        *((_QWORD *)Object + 25) = (_QWORD)((char *)Object + 192);
    }

    _QWORD *InfoSize = Object;
    Result = -1073741670;

    void *InfoBuffer = (void *)*((_QWORD *)Object + 12);
    if (!InfoBuffer)
    {
        InfoSize[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)Result;
    }

    memmove(InfoBuffer, *(const void **)(UnicodeString + 8), *(unsigned __int16 *)(UnicodeString + 2));
    KeInitializeEvent((PRKEVENT)((UCHAR *)Object + 128), SynchronizationEvent, 0);
    KeInitializeEvent((PRKEVENT)((UCHAR *)Object + 152), NotificationEvent, 0);

    _BYTE Dst[224];
    memset(Dst, 0, sizeof(Dst));
    PGENERIC_MAPPING FileObjectGenericMapping = IoGetFileObjectGenericMapping();
    _BYTE AccessState[160];
    memset(AccessState, 0, sizeof(AccessState));

    if (SeCreateAccessState((PACCESS_STATE)AccessState, (PACCESS_STATE)Dst, DesiredAccess, FileObjectGenericMapping))
        goto LABEL_15;

    CCHAR StackSize = DeviceObject->StackSize;
    _QWORD AccessStatePtr[2];
    AccessStatePtr[0] = 0;
    AccessStatePtr[1] = (_QWORD)AccessState;
    unsigned int AccessStateData = DesiredAccess;

    PIRP Irp = IoAllocateIrp(StackSize, 0);
    if (!Irp)
    {
        ExFreePoolWithTag(*((PVOID *)Object + 12), 0);
        *((_QWORD *)Object + 12) = 0;
        *((_WORD *)Object + 44) = 0;
        InfoSize = Object;
        InfoSize[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)Result;
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

    int CreateIoStatus = 0;
    Irp->UserIosb = (PIO_STATUS_BLOCK)&CreateIoStatus;
    Irp->UserEvent = &Event;

    struct _IO_STACK_LOCATION *StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.AuxiliaryBuffer = 0;
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;

    StackLocation[-1].MajorFunction = 0; // IRP_MJ_CREATE
    StackLocation[-1].DeviceObject = DeviceObject;
    struct _FILE_OBJECT *FileObject = (struct _FILE_OBJECT *)Object;
    StackLocation[-1].Parameters.Create.ShareAccess = ShareAccess;
    StackLocation[-1].Parameters.Create.EaLength = 0;
    StackLocation[-1].FileObject = FileObject;
    StackLocation[-1].Parameters.WMI.ProviderId = (ULONG_PTR)AccessStatePtr;
    StackLocation[-1].Parameters.Create.FileAttributes = FileAttributes;
    StackLocation[-1].Parameters.Create.Options = (Disposition << 24) | CreateOptions & 0xFFFFFF;

    _OWORD MonitorContext;
    memset(&MonitorContext, 0, sizeof(MonitorContext));
    __int64 (*pCallDriver)(__int64, ULONG_PTR, __int64) = NULL;
    char IrpMonitorContext = GetIrpMonitorContext((__int64)DeviceObject, 0, &MonitorContext, (_QWORD *)&pCallDriver);
    char VolumeChangeLock = AcquireVolumeChangeLock((__int64)DeviceObject);
    char SwapDiskFuncRet = SwapDiskIrpFunctionPointer();
    int Status = (int)AllocateIrpStackAndCallDriver(pCallDriver, (__int64)DeviceObject, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, (__int64)DeviceObject, 0, &MonitorContext);

    if (Status == 259)
        KeWaitForSingleObject(&Event, Executive, 0, 0, 0);

    NotifyVolumeDeviceChange(VolumeChangeLock, (__int64)DeviceObject);
    RestoreDiskIrpFunctionPointer(SwapDiskFuncRet);

    if (CreateIoStatus)
    {
LABEL_15:
        Result = -1073741823;
        ExFreePoolWithTag(*((PVOID *)Object + 12), 0);
        *((_QWORD *)Object + 12) = 0;
        *((_WORD *)Object + 44) = 0;
        InfoSize = Object;
        InfoSize[1] = 0;
        ObfDereferenceObject(Object);
        return (ULONG)Result;
    }

    _InterlockedIncrement((volatile signed __int32 *)(*((_QWORD *)Object + 1) + 4));
    void *OutFileObject = Object;
    __int64 ObjectRelatedPtr = *((_QWORD *)Object + 2);
    if (ObjectRelatedPtr)
    {
        _InterlockedIncrement((volatile signed __int32 *)(ObjectRelatedPtr + 28));
        OutFileObject = Object;
    }
    *pFileObject = (_QWORD)OutFileObject;
    return 0;
}

// 11. QueryDiskFsControlInfo — 查询磁盘 FS 控制信息
// 对应原始驱动 sub_14005967C
// 打开文件路径，通过 NtFsControlFile 获取磁盘分区信息，然后打开物理磁盘获取扩展信息，计算分区偏移，最后读取引导扇区数据
__int64 QueryDiskFsControlInfo(__int16 *FilePath, __int64 Size, char **OutBuffer, __int64 *OutBufferSize)
{
    int DiskFsControlInfo = -1073741823;
    unsigned int SavedThreadByte = (unsigned int)GtRead(GtSdstServiceCount);
    __int64 SavedThreadByteVal = SavedThreadByte;
    void *BufferSize = NULL;
    HANDLE FileHandle;

    *OutBuffer = 0;
    *OutBufferSize = 0;

    if (SavedThreadByte == -1)
        return (ULONG)DiskFsControlInfo;

    _DWORD InputBuffer[2] = {0, 0};

    if (CreateFileWithPath(FilePath, 0, &FileHandle, 0x100020, 0x80, 1, 1, 0x20))
        return (ULONG)DiskFsControlInfo;

    ULONG OutputBufferLength = 4096;
    while (1)
    {
        BufferSize = ExAlloc(PagedPool, OutputBufferLength);
        if (!BufferSize)
        {
            DiskFsControlInfo = -1073741670;
            goto LABEL_9;
        }

        struct _KTHREAD *CurrentThread = KeGetCurrentThread();
        __int64 ThreadByte = SavedThreadByte;
        char SavedThreadByteContent = *((UCHAR *)CurrentThread + SavedThreadByte);
        *((UCHAR *)CurrentThread + ThreadByte) = 0;

        IO_STATUS_BLOCK IoStatusBlock;
        DiskFsControlInfo = NtFsControlFile(FileHandle, 0, 0, 0, &IoStatusBlock,
            0x90073, InputBuffer, 8, BufferSize, OutputBufferLength);

        *((UCHAR *)CurrentThread + ThreadByte) = SavedThreadByteContent;

        if (DiskFsControlInfo != -1073741820) // STATUS_BUFFER_TOO_SMALL
            break;

        ExFree(BufferSize);
        BufferSize = NULL;
        SavedThreadByte = (unsigned int)SavedThreadByteVal;
        OutputBufferLength *= 2;
    }

    SavedThreadByte = (unsigned int)SavedThreadByteVal;
LABEL_9:
    if (DiskFsControlInfo >= 0)
    {
        HANDLE Handle;
        DiskFsControlInfo = (int)OpenPhysicalDiskDevice(FilePath, FileHandle, &Handle);
        if (DiskFsControlInfo >= 0)
        {
            struct _KTHREAD *DiskThread = KeGetCurrentThread();
            __int64 SavedDiskByte = SavedThreadByte;
            char SavedDiskByteContent = *((UCHAR *)DiskThread + SavedThreadByte);
            *((UCHAR *)DiskThread + SavedDiskByte) = 0;

            char PartitionInfo[40];
            unsigned int SectorSize, PartitionCount;
            IO_STATUS_BLOCK IoStatusBlock;
            DiskFsControlInfo = NtFsControlFile(Handle, 0, 0, 0, &IoStatusBlock,
                0x90064, 0, 0, PartitionInfo, 0x60);

            *((UCHAR *)DiskThread + SavedDiskByte) = SavedDiskByteContent;

            if (DiskFsControlInfo >= 0)
            {
                SectorSize = *(unsigned int *)(PartitionInfo + 36); // sector size
                PartitionCount = *(unsigned int *)(PartitionInfo + 32); // partition count

                unsigned __int64 SectorSize64 = SectorSize;
                __int64 PartitionOffset = CalcDiskPartitionOffset((int *)BufferSize, SectorSize);
                if (PartitionOffset && SectorSize64)
                {
                    unsigned __int64 TotalZoneSize;
                    if (Size)
                        TotalZoneSize = SectorSize64 * ((SectorSize64 + Size - 1) / SectorSize64);
                    else
                        TotalZoneSize = PartitionOffset;

                    unsigned int ZeroSize = (unsigned int)TotalZoneSize;
                    if ((unsigned int)TotalZoneSize > 0x1000)
                        ZeroSize = 4096;

                    char *DataBuffer = (char *)ExAlloc(PagedPool, (unsigned int)(TotalZoneSize + 256));
                    if (!DataBuffer)
                    {
                        DiskFsControlInfo = -1073741670;
                        goto LABEL_29;
                    }

                    memset(DataBuffer, 0, ZeroSize);
                    memset(&DataBuffer[TotalZoneSize], 0, 0x100);

                    DiskFsControlInfo = (int)QueryDiskFsControlInfoEx(Handle, (__int64)BufferSize, SectorSize, PartitionCount, TotalZoneSize, DataBuffer);
                    if (DiskFsControlInfo < 0)
                    {
                        ExFree(DataBuffer);
                        goto LABEL_29;
                    }

                    unsigned int ZeroCount = 0;
                    char *ScanBuffer = DataBuffer;
                    if (ZeroSize)
                    {
                        do
                        {
                            if (*ScanBuffer)
                                break;
                            ++ZeroCount;
                            ++ScanBuffer;
                        } while (ZeroCount < ZeroSize);

                        if (ZeroCount < ZeroSize)
                        {
                            *OutBuffer = DataBuffer;
                            *OutBufferSize = TotalZoneSize;
                            goto LABEL_29;
                        }
                    }
                    ExFree(DataBuffer);
                }
                DiskFsControlInfo = -1073741823;
            }
LABEL_29:
            ZwClose(Handle);
        }
    }

    if (BufferSize)
        ExFree(BufferSize);
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

    Status = (ULONG)IrpReadFile(FileHandle, (struct _IRP *)IrpBuffer, 0x18, 5);
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

    _BYTE UnicodeBuffer[16];
    int ObjAttributes = 48;
    __int64 RootDir = 0;
    _BYTE *ObjName = UnicodeBuffer;
    int ObjAttr = 576;
    _OWORD SecurityDesc = {0};
    __int64 Handle;

    InitUnicodeFunc(UnicodeBuffer, FilePath);
    __int64 Result = CreateFileFunc(&Handle, 1, &ObjAttributes);
    if (Result < 0)
        return Result != -1073741772;
    CloseFunc(Handle);
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
        Result = (unsigned int)NtFsControlFunc(Handle, IoControlCode, *HandleValue, (__int64)Flags, OutputHandle, IoStatusBlock);
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
// 根据系统版本和标志位，替换对象头中指定偏移处的函数指针以安装 Hook
// =========================================================================
__int64 __fastcall SwapKernelObjectPointerPreWin10(__int64 Handle, __int64 *OriginalValue)
{
    __int64 Result;          // rbx
    __int64 CallbackAlt1;    // rbp
    __int64 CallbackAlt2;    // rsi
    __int64 CallbackPrimary; // rdi
    __int64 CallbackAlt3;    // r13
    __int64 ObjectHeader;    // r9
    __int64 FunctionPtrSlot; // r10
    __int64 *pFunctionPtr;   // rdi
    char FlagByte;           // si
    bool FlagCleared;        // zf

    Result = 0;
    CallbackAlt1 = GtRead(GtCallbackField98);
    CallbackAlt2 = GtRead(GtCallbackField100);
    CallbackPrimary = GtRead(GtCallbackField94);
    CallbackAlt3 = GtRead(GtCallbackField96);
    if (CallbackAlt1 || CallbackAlt2 || CallbackPrimary && CallbackAlt3)
    {
        ObjectHeader = *(_QWORD *)(Handle + 8);
        if (ObjectHeader)
        {
            FunctionPtrSlot = *(_QWORD *)((unsigned int)GtRead(GtCallbackField91) + ObjectHeader);
            if (FunctionPtrSlot)
            {
                pFunctionPtr = (__int64 *)(FunctionPtrSlot + 8);
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28
                    && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0
                    && *(_QWORD *)(FunctionPtrSlot + 16))
                {
                    if (CallbackPrimary && *pFunctionPtr != CallbackPrimary)
                    {
                        *OriginalValue = *pFunctionPtr;
                        *pFunctionPtr = CallbackPrimary;
                        return FunctionPtrSlot + 8;
                    }
                }
                else
                {
                    FlagByte = *(_BYTE *)((unsigned int)GtRead(GtCallbackField92) + FunctionPtrSlot);
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
                        FlagCleared = (FlagByte & 1) == 0;
                    else
                        FlagCleared = FlagByte == 0;
                    if (FlagCleared)
                    {
                        if (CallbackAlt2 && *pFunctionPtr != CallbackAlt2)
                        {
                            *OriginalValue = *pFunctionPtr;
                            *pFunctionPtr = CallbackAlt2;
                            return FunctionPtrSlot + 8;
                        }
                    }
                    else if (CallbackAlt1 && *pFunctionPtr != CallbackAlt1)
                    {
                        *OriginalValue = *pFunctionPtr;
                        *pFunctionPtr = CallbackAlt1;
                        return FunctionPtrSlot + 8;
                    }
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// SwapKernelObjectPointerWin10 — 交换内核对象指针（Win10版本）
// 对应原始驱动 sub_1400720BC
// 根据标志位替换对象头中指定偏移处的函数指针以安装 Hook
// =========================================================================
__int64 __fastcall SwapKernelObjectPointerWin10(__int64 Handle, __int64 *OriginalValue)
{
    __int64 Result;          // rbx
    __int64 CallbackAlt2;    // rbp
    __int64 ObjectTypeIdx;   // rdi
    __int64 CallbackPrimary; // rsi
    __int64 CallbackAlt3;    // r14
    __int64 ObjectHeader;    // r9
    __int64 FunctionPtrSlot; // r10
    __int64 *pFunctionPtr;   // rdi

    Result = 0;
    CallbackAlt2 = GtRead(GtCallbackField100);
    ObjectTypeIdx = GtRead(GtObjectTypeIdxMatched);
    CallbackPrimary = GtRead(GtCallbackField98);
    CallbackAlt3 = GtRead(GtObjectTypeIdxNotMatched);
    if (CallbackAlt2 && ObjectTypeIdx || CallbackPrimary && CallbackAlt3)
    {
        ObjectHeader = *(_QWORD *)(Handle + 8);
        if (ObjectHeader)
        {
            FunctionPtrSlot = *(_QWORD *)((unsigned int)GtRead(GtCallbackField91) + ObjectHeader);
            if (FunctionPtrSlot)
            {
                pFunctionPtr = (__int64 *)(FunctionPtrSlot + 8);
                if ((*(_BYTE *)((unsigned int)GtRead(GtCallbackField92) + FunctionPtrSlot) & 1) != 0)
                {
                    if (CallbackPrimary && *pFunctionPtr != CallbackPrimary)
                    {
                        *OriginalValue = *pFunctionPtr;
                        *pFunctionPtr = CallbackPrimary;
                        return FunctionPtrSlot + 8;
                    }
                }
                else if (CallbackAlt2 && *pFunctionPtr != CallbackAlt2)
                {
                    *OriginalValue = *pFunctionPtr;
                    *pFunctionPtr = CallbackAlt2;
                    return FunctionPtrSlot + 8;
                }
            }
        }
    }
    return Result;
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
// SWAP_IOCTL_BLOCK — SendIoControlWithBufferSwap 的输入描述符
// =========================================================================
// 【逆向来源】原始驱动 0x1400731F4 的栈布局直接读出（基址 var_60 = rbp-0x09）：
//   +0x00 从未被调用方初始化，而是由 SwapKernelMemoryPointer 写入，
//         随后被 `*pSwap = [var_60]` 拷回 —— 故为"交换内存句柄槽"
//   +0x08 = 0x30（描述符长度），+0x0C = 0，+0x10 = 0
//   +0x18 = &UNICODE_STRING（拼接好的宽字符路径）
//   +0x20 = 0x240（576，缓冲大小类字段），+0x28/+0x30 = 0（movdqu xmm0 清零 16 字节）
//   共 0x38 字节。调用方把 &+0x08 作为输入结构传给
//   DispatchIoControlForServer2022，把 &+0x00 传给 SwapKernelMemoryPointer，
//   故二者必须连续 —— 用结构体而非两个独立局部变量来保证。
// 【⚠ 存疑】该描述符的确切类型尚未确认（+0x18 处放 UNICODE_STRING 指针、
//   +0x20 处为 0x240 这一点不匹配 OBJECT_ATTRIBUTES 等常见结构），
//   此处按偏移命名，待确认类型后再改名。
typedef struct _SWAP_IOCTL_BLOCK
{
    __int64 SwapHandle;             // +0x00 交换内存句柄（由 SwapKernelMemoryPointer 写入）

    struct
    {
        ULONG   Length;             // +0x08 = 0x30
        ULONG   Reserved0C;         // +0x0C = 0
        __int64 Field10;            // +0x10 = 0
        __int64 NamePtr;            // +0x18 = &UNICODE_STRING
        __int64 Field20;            // +0x20 = 0x240
        __int64 Field28;            // +0x28 = 0
        __int64 Field30;            // +0x30 = 0
    } Descriptor;
} SWAP_IOCTL_BLOCK;                 // 共 0x38 字节

// SendReadMemoryIoControl — 读内存 IOCTL 主流程（11 参数）
// 对应原始驱动 0x140072B64（866 字节，213 条指令）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用）。**参数语义取自唯一调用方的伪代码**
//   （CmdReadProcessMemoryStr @0x140074418 可反编译），不是从寄存器猜的。
// 【参数标定（决定性证据）】调用方伪代码给出的实参序列：
//     SendReadMemoryIoControl(&v32, Address[2], v38, v41, v5, a4,
//                             Address[4], v48, Address, v8, v35)
//   与反汇编调用点（0x14007461B）存栈的第 5..11 实参
//   （rsi / r13d / [r14+0x20] / 字节 / r14 / r12 / dword）**按序一一对应**；
//   且 Address = r14 被两处独立印证（第 7 实参 [r14+0x20]、第 9 实参 r14）。
//   共 11 个参数。
// 【⚠ 更正记录】此前按"IDA arg_XX 槽位"推算得 10 参数，并卡在"某槽位既被当
//   <=2 的小整数、又被当 64 位指针"的矛盾上。伪代码定案后确认：那只是
//   "槽位名 ↔ 形参序号"的换算错误，语义本身自洽 —— 第 4 参数（类型值）与
//   第 5 参数（缓冲指针）本来就是两个不同参数。
// 【参数含义（按调用方实参表达式）】
//   1  OutFlag     &v32          ：函数开头写 1；状态为 0x8000001A 时清 0
//   2  IoctlHandle Address+0x10  ：IOCTL 句柄
//   3  ModeByte    Address[6] 低字节，随即被 Address[1] 覆盖（参数替换）
//   4  Type        Address[7] 低 32 位，须 <= 2；非 0 时只搬运一次
//   5  Buffer5     v5            ：输出缓冲（[0] 收计数、[8] 收子调用结果字节、[0xC] 是推进步长基数）
//   6  BufferSize  a4            ：= 调用方的 OutputSize（循环中递减）
//   7  Arg7        Address+0x20  ：作为子调用第 8 实参
//   8  Arg8        v48           ：字节标志，== 1 时在两条分岔里调子函数
//   9  Address     Address       ：输入缓冲指针（作前缀描述符传给 SendIoControlWithBufferSwap）
//   10 OutBuffer10 v8            ：输出缓冲（子调用第 3 实参）
//   11 OutSize11   v35           ：输出大小（子调用第 4 实参）
// 【线程字节技巧】以 gs:188h 取当前线程（即 KeGetCurrentThread()），
//   用 GtRead(0x27) 作偏移**保存并清零**该字节，函数出口恢复
//   （与 SaveAndReplaceDiskExtension 同族）。
// 【⚠ 形参被修改】原始源码修改了自己的第 2、6 个形参（编译器把新值写回其 home 槽：
//   `mov [arg_10], edx` 与 `mov [arg_28], ecx`）。复刻中用独立局部 Advanced /
//   Accumulated 与形参 BufferSize 承担，语义等价。
// 【循环推进（关键细节）】每轮把读指针推进 `*(DWORD*)(Buffer5+0xC)+0x10` 字节，
//   并把该值记入计数器、把 BufferSize 递减同量，直到 `BufferSize <= 步长+0x10`
//   放不下为止 —— 即按缓冲自描述的长度字段逐段搬运。
// 【逻辑】置 *OutFlag=1 → 校验 GT 0x27（不得为 0xFFFFFFFF）与 0x41C6/0x4223/
//   0x17A/0x179 非 0 → 发 IOCTL(码 8) 取 Handle80（构建号 0x1DB0 分岔）→
//   保存并清零线程字节 → DispatchHookSwapByVersion 挂钩（HookTarget1）→
//   状态先置 0xC0000001；构建号 < 0x1770 或 GT 0x197 为 0 则直接收尾 →
//   DispatchIoControlByBuildNumber(…, 8) 取 Handle88（非 0 则跳过循环）→
//   Handle88 非 0 时再挂钩（HookTarget2）→ 首次 SendIoControlWithQuotaBuffer →
//   循环（Type 非 0 时只搬一次）：按 ModeByte / 内层状态 / Arg8 三条分岔决定
//   是否调 SendIoControlWithBufferSwap，随后推进读指针 → 收尾：写回两处钩子、
//   恢复线程字节、释放 Handle80/Handle88 → 状态为 0x8000001A 时清 *OutFlag →
//   返回 (状态 == 0)
char SendReadMemoryIoControl(
    unsigned char *OutFlag,
    __int64 IoctlHandle,
    unsigned char ModeByte,
    unsigned int Type,
    unsigned char *Buffer5,
    unsigned int BufferSize,
    __int64 Arg7,
    unsigned char Arg8,
    unsigned char *Address,
    __int64 OutBuffer10,
    unsigned int OutSize11)
{
    char Result = 0;
    int Status;
    int InnerStatus;
    unsigned int Counter;
    unsigned int Advanced;
    unsigned int One;
    unsigned int Step;
    unsigned int Remaining;
    unsigned int Accumulated;
    __int64 Id27;
    __int64 Func41C6;
    __int64 FreeFunc;
    __int64 Func17A;
    __int64 Func179;
    __int64 Func197;
    __int64 Handle80;
    __int64 Handle88;
    __int64 HookSave;
    __int64 HookSave2;
    __int64 *HookTarget1;
    __int64 *HookTarget2;
    unsigned char *ThreadPtr;
    unsigned __int64 ThreadOffset;
    unsigned char SavedThreadByte;
    unsigned char *Cursor;

    *OutFlag = 1;
    ModeByte = Address[1];
    if (Type > 2)
        return Result;

    Id27 = GtRead((GLOBAL_TABLE_INDEX)0x27);
    Func41C6 = GtRead((GLOBAL_TABLE_INDEX)0x41C6);
    FreeFunc = GtRead((GLOBAL_TABLE_INDEX)0x4223);
    Func17A = GtRead((GLOBAL_TABLE_INDEX)0x17A);
    Func179 = GtRead((GLOBAL_TABLE_INDEX)0x179);

    if ((unsigned int)Id27 == 0xFFFFFFFF)
        return Result;
    if (!Func41C6 || !FreeFunc || !Func17A || !Func179)
        return Result;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        Status = (int)((__int64(__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))Func41C6)(
            IoctlHandle, 8, *(__int64 *)Func179, 0, (__int64)&Handle80, 0);
    }
    else
    {
        Status = (int)SendDeviceIoControlWithRetry(IoctlHandle, 8, 0, (_DWORD **)&Handle80, 0);
    }

    if (Status < 0)
        return Result;

    ThreadPtr = (unsigned char *)KeGetCurrentThread();
    ThreadOffset = (unsigned __int64)(unsigned int)Id27;
    SavedThreadByte = ThreadPtr[ThreadOffset];
    ThreadPtr[ThreadOffset] = 0;

    Counter = 0;
    HookSave = 0;
    HookTarget1 = (__int64 *)DispatchHookSwapByVersion(Handle80, &HookSave);

    Status = (int)0xC0000001;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770)
        goto LABEL_RESTORE_THREAD;

    Func197 = GtRead((GLOBAL_TABLE_INDEX)0x197);
    if (!Func197)
        goto LABEL_RESTORE_THREAD;

    Handle88 = 0;

    Status = (int)DispatchIoControlByBuildNumber(
        (__int64(__fastcall *)(__int64, __int64))Func197,
        (__int64)&Handle80,
        (__int64)&Handle88,
        0,
        8);

    if (Status != 0)
        goto LABEL_FREE_HANDLE88;

    HookTarget2 = NULL;
    HookSave2 = 0;

    if (Handle88)
        HookTarget2 = (__int64 *)DispatchHookSwapByVersion(Handle88, &HookSave2);

    Cursor = Buffer5;
    Advanced = 0;
    Accumulated = 0;

    // 【实参顺序的定案依据】原始被调用方 sub_140075A9C 可反编译，其伪代码给出真实签名
    //   (a1 HandlerFunc, a2, a3, a4, a5, Dst, NumberOfBytes, a8)，体内：
    //     v12 = a1(a2, v18, a4, a5, PoolWithQuotaTag, NumberOfBytes, &MaxCount);
    //     memmove(Dst, PoolWithQuotaTag, v11);   // ← Dst 是搬运目的地
    //     *(_DWORD *)a8 = MaxCount;              // ← a8 是输出大小指针
    //   据此唯一确定本调用点的映射：Cursor→Dst、BufferSize→NumberOfBytes、
    //   Arg7→a8，剩下的 Type→a5（第 2 次调用处该位为 0，与反汇编一致）。
    //   【更正】此前据 IDA 栈槽名推断"声明在 Dst 前多插了 Arg5、整体错位一格"，
    //   该结论**错误**，已按被调用方伪代码撤销：声明是正确的。
    InnerStatus = (int)SendIoControlWithQuotaBuffer(
        (__int64(__fastcall *)(__int64, __int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *))Func17A,
        Handle80,
        Handle88,
        Accumulated,
        Type,
        (unsigned char *)Cursor,
        (SIZE_T)BufferSize,
        (size_t *)&Arg7);

    for (;;)
    {
        One = 1;

        if (ModeByte == 1)
            goto LABEL_MODE_EXIT;

        if (InnerStatus != 0)
            goto LABEL_ERROR_EXIT;

        if (Arg8 != 1)
            goto LABEL_ADVANCE;

        // ===== 0x140072D77：Arg8 == 1 时的子调用（拼路径 + 注册表键 IOCTL）=====
        *(unsigned __int32 *)(Cursor + 8) = (unsigned __int32)(unsigned __int8)SendIoControlWithBufferSwap(
            Address, Cursor, (unsigned char *)OutBuffer10, OutSize11);
        One = (unsigned int)(InnerStatus + 1);

    LABEL_ADVANCE:                                  // 0x140072D9E
        *(unsigned __int32 *)Cursor = Counter;

        Step = *(unsigned int *)(Cursor + 0x0C) + 0x10;
        Counter = Step;

        if (BufferSize <= Step + 0x10)              // 0x140072DB3
        {
            *(unsigned __int32 *)Cursor = 0;
            goto LABEL_FREE_HANDLE88;
        }

        Remaining = BufferSize - Step;
        Accumulated += One;
        Advanced += One;
        BufferSize = Remaining;

        Cursor += Step;

        InnerStatus = (int)SendIoControlWithQuotaBuffer(
            (__int64(__fastcall *)(__int64, __int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *))Func17A,
            Handle80,
            Handle88,
            Accumulated,
            0,
            (unsigned char *)Cursor,
            (SIZE_T)Remaining,
            (size_t *)&Arg7);
        continue;

    LABEL_MODE_EXIT:                                // 0x140072E12
        *(unsigned __int32 *)Cursor = 0;

        if (InnerStatus != 0)
            goto LABEL_FREE_HANDLE88;
        if (Arg8 != 1)
            goto LABEL_FREE_HANDLE88;

        *(unsigned __int32 *)(Cursor + 8) = (unsigned __int32)(unsigned __int8)SendIoControlWithBufferSwap(
            Address, Cursor, (unsigned char *)OutBuffer10, OutSize11);
        goto LABEL_FREE_HANDLE88;

    LABEL_ERROR_EXIT:                              // 0x140072E06
        *(unsigned __int32 *)Cursor = 0;

        if (Advanced != 0)
            goto LABEL_FREE_HANDLE88;

        InnerStatus = 0;
        *(unsigned __int32 *)Cursor = 0;
        goto LABEL_FREE_HANDLE88;
    }

LABEL_FREE_HANDLE88:                                // 0x140072E42
    if (Handle88)
    {
        if (HookTarget2)
            *HookTarget2 = HookSave2;

        ((void(__fastcall *)(__int64))FreeFunc)(Handle88);
    }

LABEL_RESTORE_THREAD:                               // 0x140072E63
    if (HookTarget1)
        *HookTarget1 = HookSave;

    ThreadPtr[ThreadOffset] = SavedThreadByte;

    ((void(__fastcall *)(__int64))FreeFunc)(Handle80);

    if (Status == 0x8000001A)
        *OutFlag = 0;

    Result = (Status == 0) ? 1 : 0;
    return Result;
}

// SendIoControlWithBufferSwap — 拼接宽字符路径并执行注册表键 IOCTL
// 对应原始驱动 0x1400731F4（760 字节）
// 【逆向来源】人工阅读反汇编逐条重建 —— IDA 无法分析该函数（Hex-Rays 报
//   "function frame is wrong"，无伪代码可用），由 0x1400731F4~0x1400734EB
//   的 213 条指令逐条还原
// 【⚠ 名称说明】名字里的 "IoControl" 只描述了后半段，本函数前半段是**路径拼接**：
//   把 Arg1 的缓冲搬入输出缓冲 → **强制把最后一个宽字符改写为 0x005C('\\')**
//   （`mov [rax+r12-2], cx`，cx = 0x5C）→ 追加 Arg2 的内联数据 →
//   补一个 0 宽字符结尾。名称沿用 IDA 数据库。
// 【参数（由寄存器用途与栈 home 槽位推出）】
//   Arg1 rcx 前缀描述符：+0x04 = 前缀字节长度，+0x08 = 前缀缓冲指针
//   Arg2 rdx 名字描述符：+0x0C = 名字字节长度，+0x10 = 内联名字数据（宽字符）
//   Arg3 r8  输出缓冲
//   Arg4 r9d 输出缓冲大小（32 位 —— 序言 `mov [rax+20h], r9d` 只存 32 位可证）
// 【栈参数槽位标定】IDA 显示的 Dst / NumberOfBytes / var_C0 分别是 rsp+0x20 /
//   rsp+0x28 / rsp+0x30，即第 5/6/7 个栈参数。依据：AllocBufferAndQuerySystemInfo
//   的第 7 参数（ReturnSize）实参 &var_68 落在 var_C0；且
//   DispatchIoControlForServer2022 的第 7 参数是 char，调用点对 var_C0 只写 1 字节。
// 【容量校验】`len2 + len1 + 2 < 输出缓冲大小`，用 `jnb`（无符号 >=）判失败。
// 【逻辑】
//   1) 从 7 个 GT 索引取值，任一个为 0 直接返回 0：
//      0x184 = IOCTL 执行函数指针，0x41C6 = 旧版构建号的发送函数，
//      0x4223 = 缓冲释放函数，0x17C(GtEprocessExtField124) = 查询函数，
//      0x4334 = 句柄关闭函数，0x179 = 指向待传参的指针，0x197 = 另一个函数指针
//   2) 拼接路径（见上），并据此填写 UNICODE_STRING（Length = 总长-2，
//      MaximumLength = 总长，Buffer = 输出缓冲）
//   3) 填 SWAP_IOCTL_BLOCK，调用 SwapKernelMemoryPointer 取得交换句柄，
//      并把句柄值经返回指针拷回
//   4) DispatchIoControlForServer2022(..., 0x20019 /*KEY_READ*/, &描述符, 0,0,0)
//   5) 按构建号 0x1DB0 分岔：低于则间接调用 0x41C6 的函数（6 参数），
//      否则调用 SendDeviceIoControlWithRetry
//   6) DispatchIoControlByBuildNumber(0x197 的函数, &ValueA8, &ValueA0, 0, 1)
//   7) DispatchHookSwapByVersion 两次（第二次仅在 ValueA0 非 0 时），
//      分别把原始值写回其返回的指针
//   8) AllocBufferAndQuerySystemInfo(0x17C 的函数, ValueA8, ValueA0, 2, 输出缓冲,
//      输出缓冲大小, &返回大小)
//   9) 结果 = (输出缓冲 +0x14 处的 DWORD > 0)
//   10) 释放 ValueA8、关闭句柄后返回
// 【⚠ 清理路径】函数内所有错误分支都汇合到「先释放 ValueA8 再关闭句柄」两步，
//   与原始驱动的 0x1400734BB/0x1400734C2 两个汇合点一一对应。
// =========================================================================
char SendIoControlWithBufferSwap(
    unsigned char *PrefixDesc,
    unsigned char *NameDesc,
    unsigned char *OutputBuffer,
    unsigned int OutputSize)
{
    char Result = 0;
    int Status;
    __int64 *SwapSlot;
    __int64 *HookTarget1;
    __int64 *HookTarget2;
    __int64 HookSave2;
    unsigned int PrefixLength;
    unsigned int NameLength;
    unsigned int TotalLength;
    __int64 Handle184;
    __int64 Func41C6;
    __int64 Func4223;
    __int64 Func4334;
    __int64 Func179;
    __int64 Value197;
    __int64 Value17C;
    __int64 OutHandle;
    __int64 ValueA0;
    __int64 ValueA8;
    __int64 ReturnSize;
    UNICODE_STRING PathString;
    SWAP_IOCTL_BLOCK Block;

    Handle184 = GtRead((GLOBAL_TABLE_INDEX)0x184);
    Func41C6 = GtRead((GLOBAL_TABLE_INDEX)0x41C6);
    Func4223 = GtRead((GLOBAL_TABLE_INDEX)0x4223);
    Value17C = GtRead(GtEprocessExtField124);
    Func4334 = GtRead((GLOBAL_TABLE_INDEX)0x4334);
    Func179 = GtRead((GLOBAL_TABLE_INDEX)0x179);
    Value197 = GtRead((GLOBAL_TABLE_INDEX)0x197);

    if (!Handle184 || !Func41C6 || !Func4223 || !Value17C || !Func4334 || !Func179 || !Value197)
        return Result;

    PrefixLength = *(unsigned int *)(PrefixDesc + 0x04);
    NameLength = *(unsigned int *)(NameDesc + 0x0C);
    TotalLength = NameLength + PrefixLength + 2;

    if (TotalLength >= OutputSize)
        return Result;

    memmove(OutputBuffer, *(void **)(PrefixDesc + 0x08), PrefixLength);
    *(unsigned short *)(OutputBuffer + PrefixLength - 2) = 0x5C;
    memmove(OutputBuffer + PrefixLength, NameDesc + 0x10, NameLength);
    *(unsigned short *)(OutputBuffer + PrefixLength + NameLength) = 0;

    if (TotalLength < 2)
    {
        PathString.Buffer = NULL;
        PathString.Length = 0;
        PathString.MaximumLength = 0;
    }
    else
    {
        PathString.MaximumLength = (USHORT)TotalLength;
        PathString.Buffer = (PWSTR)OutputBuffer;
        PathString.Length = (USHORT)(TotalLength - 2);
    }

    Block.Descriptor.Length = 0x30;
    Block.Descriptor.Field10 = 0;
    Block.Descriptor.Field20 = 0x240;
    Block.Descriptor.Field28 = 0;
    Block.Descriptor.Field30 = 0;
    Block.Descriptor.NamePtr = (__int64)&PathString;

    SwapSlot = SwapKernelMemoryPointer(&Block.SwapHandle);

    Status = (int)DispatchIoControlForServer2022(
        (__int64(__fastcall *)(__int64, _QWORD, __int64, _QWORD, __int64, char))Handle184,
        (__int64)&OutHandle,
        0x20019,
        (__int64)&Block.Descriptor,
        0,
        0,
        0);

    if (SwapSlot)
        *SwapSlot = Block.SwapHandle;

    if (Status < 0)
        return Result;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        Status = (int)((__int64(__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))Func41C6)(
            OutHandle,
            1,
            *(__int64 *)Func179,
            0,
            (__int64)&ValueA8,
            0);
    }
    else
    {
        Status = (int)SendDeviceIoControlWithRetry(OutHandle, 1, 0, (_DWORD **)&ValueA8, 0);
    }

    // 【⚠ 更正记录（本轮逐条核对反汇编 0x1400733F1 / 0x1400734BB / 0x1400734C2）】
    //   原实现把"第二次发送失败"也并入 LABEL_FREE_A8（会关闭 ValueA8）——**错误**。
    //   反汇编证明存在**两个不同出口**：
    //     0x1400733F1 `js loc_1400734C2` —— 第二次发送失败时**跳过** 0x1400734BB，
    //        即**不关闭 ValueA8**（此时 ValueA8 尚未被赋予有效句柄），只关 OutHandle；
    //     0x140073415 `js loc_1400734BB` —— DispatchIoControlByBuildNumber 失败时
    //        才走 0x1400734BB（关闭 ValueA8），再关 OutHandle。
    //   原实现让前者也去关闭未初始化的 ValueA8，属真实缺陷。此处按反汇编拆分。
    if (Status < 0)
        goto LABEL_CLOSE_OUT_ONLY;

    ValueA0 = 0;

    Status = (int)DispatchIoControlByBuildNumber(
        (__int64(__fastcall *)(__int64, __int64))Value197,
        (__int64)&ValueA8,
        (__int64)&ValueA0,
        0,
        1);

    if (Status < 0)
        goto LABEL_FREE_A8;

    HookTarget1 = (__int64 *)DispatchHookSwapByVersion(ValueA8, &Value197);
    HookTarget2 = NULL;
    HookSave2 = 0;

    if (ValueA0)
    {
        HookTarget2 = (__int64 *)DispatchHookSwapByVersion(ValueA0, &HookSave2);
    }

    Status = (int)AllocBufferAndQuerySystemInfo(
        (__int64(__fastcall *)(__int64, __int64, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *))Value17C,
        ValueA8,
        ValueA0,
        2,
        (unsigned char *)OutputBuffer,
        (size_t)OutputSize,
        (size_t *)&ReturnSize);

    if (HookTarget1)
        *HookTarget1 = Value197;

    if (ValueA0)
    {
        if (HookTarget2)
            *HookTarget2 = HookSave2;

        ((void(__fastcall *)(__int64))Func4223)(ValueA0);
    }

    if (Status >= 0)
    {
        Result = (*(unsigned int *)(OutputBuffer + 0x14) > 0) ? 1 : 0;
    }

LABEL_FREE_A8:                                      // 0x1400734BB
    ((void(__fastcall *)(__int64))Func4223)(ValueA8);

LABEL_CLOSE_OUT_ONLY:                               // 0x1400734C2
    ((void(__fastcall *)(__int64))Func4334)(OutHandle);

    return Result;
}

// =========================================================================
// DispatchIoControlForServer2022 — 根据构建号分发 Server 2022 的 IO 控制命令
// 对应原始驱动 sub_140075FA4
// 构建号 >= 0x4F7C 时使用 6 参数调用；否则使用 5 参数调用
// =========================================================================
__int64 __fastcall DispatchIoControlForServer2022(
    __int64 (__fastcall *IoControlFunc)(__int64, _QWORD, __int64, _QWORD, __int64, char),
    __int64 DeviceHandle,
    unsigned int IoControlCode,
    __int64 InputBuffer,
    unsigned int Arg5,
    __int64 Arg6,
    char Arg7)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4F7C)
        return IoControlFunc(DeviceHandle, IoControlCode, InputBuffer, Arg5, Arg6, Arg7);
    else
        return ((__int64 (__fastcall *)(__int64, _QWORD, __int64, _QWORD, __int64))IoControlFunc)(
            DeviceHandle, IoControlCode, InputBuffer, Arg5, Arg6);
}

// =========================================================================
// SendIoControlWithVersionCheck — 发送带版本检查的 IO 控制命令
// 对应原始驱动 sub_1400734EC
// 根据 Windows 版本选择不同的 IO 控制路径，并处理 Hook 交换
// =========================================================================
char __fastcall SendIoControlWithVersionCheck(__int64 DeviceHandle, unsigned int IoControlCode, __int64 InputBuffer)
{
    char Result;                       // bl
    unsigned int ServiceCount;         // edi
    __int64 IoControlFunc;             // rax
    __int64 CloseHandleFunc;           // rax
    struct _KTHREAD *CurrentThread;    // r13
    char SavedServiceFlag;             // cl
    _DWORD *pSectionHandle;            // rdi
    _QWORD *pHookResult;               // rsi
    __int64 HookContext;               // r15
    __int64 *pSwapResult;              // r14
    void (__fastcall *pCloseHandle)(_DWORD *); // [rsp+48h]
    __int64 SwapKey;                   // [rsp+50h] BYREF
    __int64 ServiceCountCopy;          // [rsp+58h]
    char SavedFlagCopy;                // [rsp+B8h]
    int IoControlResult;               // ebp

    Result = 0;
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    IoControlFunc = GtRead(GtEprocessField122 | 0x100);
    if (ServiceCount != -1 && IoControlFunc)
    {
        CloseHandleFunc = GtRead(GtCloseHandleFunc);
        CurrentThread = KeGetCurrentThread();
        pCloseHandle = (void (__fastcall *)(_DWORD *))CloseHandleFunc;
        SavedServiceFlag = *((_BYTE *)CurrentThread + ServiceCount);
        ServiceCountCopy = ServiceCount;
        *((_BYTE *)CurrentThread + ServiceCount) = 0;
        SavedFlagCopy = SavedServiceFlag;
        pSectionHandle = 0;
        pHookResult = 0;
        HookContext = 0;
        pSwapResult = SwapKernelMemoryPointer(&SwapKey);
        if (pCloseHandle)
        {
            pSectionHandle = SendIoControlWithUnicodeString(InputBuffer);
            if (pSectionHandle)
            {
                pHookResult = (_QWORD *)DispatchHookSwapByVersion((__int64)pSectionHandle, &HookContext);
            }
        }
        IoControlResult = (int)DispatchIoControlForServer2022(
            (__int64 (__fastcall *)(__int64, _QWORD, __int64, _QWORD, __int64, char))IoControlFunc,
            DeviceHandle, IoControlCode, InputBuffer, 0, 0, 0);
        if (pSectionHandle)
        {
            if (pHookResult)
                *pHookResult = HookContext;
            pCloseHandle(pSectionHandle);
        }
        if (pSwapResult)
            *pSwapResult = SwapKey;
        *((_BYTE *)CurrentThread + ServiceCountCopy) = SavedFlagCopy;
        return IoControlResult >= 0;
    }
    return Result;
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
            Result = (int)QueryFunc(Arg2, Arg3, HIDWORD(Arg4), WorkBuffer, (_DWORD)BufferSize, &MaxCount, Arg4, WorkBuffer);
            if (Result >= 0)
            {
                *(_DWORD *)ReturnSize = (DWORD)MaxCount;
                if ((unsigned int)BufferSize > MaxCount)
                    ResultSize = (unsigned int)MaxCount;
                memmove(OutputBuffer, WorkBuffer, ResultSize);
            }
            if (PoolBuffer)
                ExFreePoolWithTag(PoolBuffer, 0x42424D43u);
        }
    }
    else
    {
        Result = (int)QueryFunc(Arg2, Arg3, HIDWORD(Arg4), OutputBuffer, (_DWORD)BufferSize, ReturnSize, Arg4, 0);
    }
    return (unsigned int)Result;
}

// =========================================================================
// SendCreateFileIoControl — 发送创建文件的IO控制命令
// 对应原始驱动 sub_140072998
// =========================================================================
bool __fastcall SendCreateFileIoControl(__int64 Handle, __int16 *FilePath)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    bool Result = 0;

    if (BuildNumber >= 0x42EE)
        return 0;

    unsigned int ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    __int64 (__fastcall *NtFsControlFunc)(__int64, __int64, _QWORD, _QWORD, _DWORD **, unsigned int *) =
        (__int64 (__fastcall *)(__int64, __int64, _QWORD, _QWORD, _DWORD **, unsigned int *))GtRead(GtNtFsControlFileFunc);
    void (*CloseHandleFunc)(_DWORD *) = (void (*)(_DWORD *))GtRead(GtCloseHandleFunc);
    __int64 CallbackFunc = GtRead((enum _GLOBAL_TABLE_INDEX)384);
    __int64 (__fastcall *Callback)(_DWORD *, _WORD *, __int64, _QWORD) = (__int64 (__fastcall *)(_DWORD *, _WORD *, __int64, _QWORD))CallbackFunc;
    _QWORD *HandleValue = (_QWORD *)GtRead(GtEprocessField111 | 0x100);

    if (ServiceCount != -1 && NtFsControlFunc && CloseHandleFunc && CallbackFunc && HandleValue)
    {
        unsigned int *pResultSize = &ServiceCount;
        if (BuildNumber < 0x1770)
            pResultSize = 0;

        _DWORD *OutputHandle = 0;
        int Status;

        if (BuildNumber >= 0x1DB0)
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
                    BuildNumber;
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
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    bool Result = 0;

    if (CommandType > 5)
        return Result;

    unsigned int ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
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

    if (BuildNumber >= 0x1DB0)
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
        if (BuildNumber >= 0x1770)
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

// =========================================================================
// SendIoControlWithStringParam — 发送带字符串参数的IO控制命令 (0x140073BE4)
// 处理Unicode字符串参数并发送设备控制请求
// =========================================================================
bool __fastcall SendIoControlWithStringParam(__int64 Handle, PUNICODE_STRING UnicodeString, unsigned int CommandType, unsigned int SomeValue, __int64 OutputBuffer, unsigned int OutputSize)
{
    bool Result;
    unsigned int ServiceCount;
    int (*pBuffer)(__int64, __int64, __int64);
    void (*CloseHandleFunc)(_QWORD);
    __int64 IoControlFuncPtr;
    __int64 IoControlPtr;
    __int64 *pIoControl;
    unsigned int WindowsBuildNumber;
    __int64 IoControlCode;
    int *pIoStatus;
    unsigned __int16 StringLength;
    unsigned int i;
    struct _KTHREAD *CurrentThread;
    __int64 ThreadByteIndex;
    char SavedThreadByte;
    _QWORD *pHookContext;
    int IoControlResult;
    char IoStatusValue;
    __int64 *pOutputSize;
    __int64 DeviceHandle;
    int *pReturnStatus;
    int ReturnStatus;
    __int64 (*IoControlFunc)(__int64, unsigned __int16 *, _QWORD, __int64, __int64 *, __int64, bool);
    __int64 HookContext;
    void (*SavedCloseHandleFunc)(_QWORD);

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        return Result;
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    pBuffer = (int (*)(__int64, __int64, __int64))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = (void (*)(_QWORD))GtRead(GtCloseHandleFunc);
    SavedCloseHandleFunc = CloseHandleFunc;
    IoControlFuncPtr = GtRead(GtEprocessField116 | 0x100);
    IoControlFunc = (__int64 (*)(__int64, unsigned __int16 *, _QWORD, __int64, __int64 *, __int64, bool))IoControlFuncPtr;
    IoControlPtr = GtRead(GtEprocessField111 | 0x100);
    pIoControl = (__int64 *)IoControlPtr;
    if (ServiceCount != -1 && pBuffer && CloseHandleFunc && IoControlFuncPtr && IoControlPtr)
    {
        WindowsBuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
        IoControlCode = *pIoControl;
        pIoStatus = &ReturnStatus;
        if (WindowsBuildNumber < 0x1770)
            pIoStatus = 0;
        pReturnStatus = pIoStatus;
        pOutputSize = &DeviceHandle;
        if (pBuffer(Handle, 2, IoControlCode) >= 0)
        {
            StringLength = UnicodeString->Length;
            if (UnicodeString->Length < 0x7FFF && (StringLength & 1) == 0 && OutputSize <= 0x80000000)
            {
                for (i = StringLength; i; i -= 2)
                {
                    if (*(_WORD *)(*(_QWORD *)UnicodeString + 2 * ((i >> 1) - 1)))
                        break;
                }
                UnicodeString->Length = i;
                CurrentThread = KeGetCurrentThread();
                ThreadByteIndex = ServiceCount;
                SavedThreadByte = *((_BYTE *)CurrentThread + ServiceCount);
                *((_BYTE *)CurrentThread + ThreadByteIndex) = 0;
                pHookContext = (_QWORD *)DispatchHookSwapByVersion(DeviceHandle, &HookContext);
                if (pReturnStatus)
                {
                    IoStatusValue = ReturnStatus;
                    GtRead(GtWindowsBuildNumber);
                    pOutputSize = (__int64 *)(ULONG_PTR)OutputSize;
                    IoControlResult = (int)IoControlFunc(DeviceHandle, (unsigned __int16 *)UnicodeString, CommandType, OutputBuffer, pOutputSize, Handle, (IoStatusValue & 4) != 0);
                }
                else
                {
                    IoControlResult = -1073741823;
                }
                if (pHookContext)
                    *pHookContext = HookContext;
                *((_BYTE *)CurrentThread + ThreadByteIndex) = SavedThreadByte;
                CloseHandleFunc = SavedCloseHandleFunc;
                Result = IoControlResult >= 0;
            }
            CloseHandleFunc(DeviceHandle);
        }
    }
    return Result;
}

// EnumerateDriverList — 枚举驱动列表
// 对应原始驱动 sub_14003BF64
// 遍历 PsLoadedModuleList，提取每个驱动模块的镜像基址、大小、完整路径名和基名称


// ===== Functions moved from MissingFuncs.c =====

// CheckMbrBootablePartition — 检查 MBR 可引导分区
char CheckMbrBootablePartition(void *Buffer)
{
    int Index;
    for (Index = 0; Index < 4; Index++)
    {
        if (*(_BYTE *)((unsigned __int64)Buffer + 446 + Index * 16) == 0x80)
            return *(_BYTE *)((unsigned __int64)Buffer + 450 + Index * 16) == 7;
    }
    return 0;
}

// CmdQueryFileAllocationSize — 查询文件分配大小
__int64 CmdQueryFileAllocationSize(void *FileHandle, _QWORD *pAllocationSize)
{
    __int64 AllocationSize;
    __int64 result;
    result = IrpReadFile(FileHandle, (struct _IRP *)&AllocationSize, 8u, 0xEu);
    if (!(_DWORD)result) *pAllocationSize = AllocationSize;
    return result;
}

// CmdReadFileInfo — 读取文件信息命令处理
__int64 CmdReadFileInfo(void *FileHandle, _DWORD *pFileInfo)
{
    char IrpBuffer[0x28];
    int FileInfo;
    __int64 result;
    result = IrpReadFile(FileHandle, (struct _IRP *)IrpBuffer, 0x28u, 4u);
    if (!(_DWORD)result) *pFileInfo = FileInfo;
    return result;
}

// CmdSetFileBasicInfo — 设置文件基本信息
__int64 CmdSetFileBasicInfo(void *FileHandle, struct _IRP *FileBasicInfo)
{
    return IrpFileSystemControl(FileHandle, FileBasicInfo, 0x28u, 4u);
}

// CmdSendRenameFileIrp — 发送重命名文件 IRP
__int64 CmdSendRenameFileIrp(void *FileHandle, const void *RenameBuffer, unsigned int BufferSize)
{
    struct _IRP *IrpBuffer;
    unsigned int Status;
    if (BufferSize <= 2 || (BufferSize & 1) != 0) return (unsigned int)-1073741811;
    IrpBuffer = (struct _IRP *)ExAlloc(NonPagedPool, BufferSize + 24);
    if (IrpBuffer)
    {
        IrpBuffer->MdlAddress = 0;
        IrpBuffer->Flags = BufferSize - 2;
        *((char *)&IrpBuffer->Type) = 1;  // LOBYTE(IrpBuffer->Type)
        memmove(&IrpBuffer->Flags + 1, RenameBuffer, BufferSize - 2);
        Status = (unsigned int)IrpFileSystemControl(FileHandle, IrpBuffer, BufferSize + 24, 0xAu);
        ExFree(IrpBuffer);
        return Status;
    }
    return (unsigned int)-1073741670;
}

// ReadDisksSysFile — 读取磁盘.sys文件
bool ReadDisksSysFile(_QWORD *FileBuffer, unsigned int *FileSize)
{
    bool Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[20];

    EncodedPath[6] = 7929971;
    EncodedPath[17] = 7929971;
    Result = 0;
    EncodedPath[0] = 5439580; EncodedPath[1] = 7536761; EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061; EncodedPath[4] = 7274607; EncodedPath[5] = 6029428;
    EncodedPath[7] = 7602291; EncodedPath[8] = 7143525; EncodedPath[9] = 3276851;
    EncodedPath[10] = 6553692; EncodedPath[11] = 6881394; EncodedPath[12] = 6619254;
    EncodedPath[13] = 7536754; EncodedPath[14] = 6553692; EncodedPath[15] = 7536745;
    EncodedPath[16] = 3014763; EncodedPath[18] = 115;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)FileBuffer, (PULONG)FileSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// ReadCdromSysFile — 读取cdrom.sys文件
bool ReadCdromSysFile(_QWORD *FileBuffer, unsigned int *FileSize)
{
    bool Result;
    size_t MaxCount;
    void *Src;
    int EncodedPath[18];
    __int64 EncodedPathEnd;

    Result = 0;
    EncodedPath[0] = 5439580; EncodedPath[1] = 7536761; EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061; EncodedPath[4] = 7274607; EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971; EncodedPath[7] = 7602291; EncodedPath[8] = 7143525;
    EncodedPath[9] = 3276851; EncodedPath[10] = 6553692; EncodedPath[11] = 6881394;
    EncodedPath[12] = 6619254; EncodedPath[13] = 7536754; EncodedPath[14] = 6488156;
    EncodedPath[15] = 7471204; EncodedPath[16] = 7143535; EncodedPath[17] = 7536686;
    EncodedPathEnd = 7536761;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &Src, (ULONG *)&MaxCount, 1))
    {
        Result = ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)FileBuffer, (PULONG)FileSize) == 1;
        ExFree(Src);
    }
    return Result;
}

// DispatchDiskIrpWithHookInit — 分发磁盘 IRP 并初始化钩子
char DispatchDiskIrpWithHookInit(void *DeviceObject, int Direction, void *Buffer, int SectorOffset, unsigned int SectorIndex, unsigned int SectorSize)
{
    __int64 pBuffer[4];
    if (QueryDeviceObjectInfo((__int64)DeviceObject, pBuffer) != 1)
        goto BuildHooks;
    __int64 Result = SendDeviceIoControlIrp(pBuffer, Direction, Buffer, SectorOffset, SectorIndex, SectorSize);
    if ((int)Result >= 0)
        return (char)Result;
BuildHooks:
    if (!(unsigned int)GtRead(GtCallbackField37))
        BuildSsdtHookTargets2();
    if (!(unsigned int)GtRead(GtCallbackField44))
        BuildSsdtHookTargets3();
    if (!(unsigned int)GtRead(GtCallbackField49))
        BuildSsdtHookTargets4();
    if (!(unsigned int)GtRead(GtCallbackField61))
        ParseStorPortExportDir();
    return (char)SendIrpToDiskDevice(DeviceObject, Direction, Buffer, SectorOffset, SectorIndex, SectorSize);
}

// SendCdbCommandToDevice — 发送 CDB 命令到设备
char __fastcall SendCdbCommandToDevice(__int64 VirtualAddress)
{
    char Result;
    unsigned __int8 (__fastcall *pCallback)(void *, _QWORD, _QWORD, _QWORD);
    void *pBuffer;

    Result = 0;
    pCallback = (unsigned __int8 (__fastcall *)(void *, _QWORD, _QWORD, _QWORD))GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtSubsystemConfigBase | GtPathBuffer00 | 0x100));
    if (pCallback)
    {
        pBuffer = ExAlloc(NonPagedPool, 0x58u);
        if (pBuffer)
        {
            InitIrpBufferWithCdb((__int64)pBuffer, VirtualAddress, 0, (__int64)CdbCommandCompletionCallback, 0, 0, 0, 0);
            if (pCallback(pBuffer, 0, 0, 0) == 1)
                return 1;
            ExFree(pBuffer);
        }
    }
    return Result;
}

// SendDiskDeviceInternalIrp — 发送磁盘设备内部 IRP
char SendDiskDeviceInternalIrp(__int64 DeviceObject, struct _IRP *Irp)
{
    bool Result;
    PIRP pIrp;
    struct _IO_STACK_LOCATION *CurrentStackLocation;
    struct _KEVENT Event;

    Result = 0;
    pIrp = IoAllocateIrp(*(_BYTE *)(DeviceObject + 76), 0);
    if (pIrp)
    {
        KeInitializeEvent(&Event, SynchronizationEvent, 0);
        CurrentStackLocation = pIrp->Tail.Overlay.CurrentStackLocation;
        CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)RxTdiRequestCompletion;
        CurrentStackLocation[-1].Control = 0xE0;
        CurrentStackLocation[-1].Context = &Event;
        pIrp->IoStatus.Status = 0xC0000011;
        pIrp->IoStatus.Information = 0;
        pIrp->AssociatedIrp.MasterIrp = (struct _IRP *)Irp;
        CurrentStackLocation = pIrp->Tail.Overlay.CurrentStackLocation;
        CurrentStackLocation[-1].MajorFunction = 14;
        CurrentStackLocation[-1].Parameters.Read.ByteOffset.LowPart = 0x70000;
        CurrentStackLocation[-1].Parameters.Read.Length = 24;
        AllocateIrpStackAndCallDriver(0, DeviceObject, (ULONG_PTR)pIrp);
        KeWaitForSingleObject(&Event, Executive, 0, 0, 0);
        Result = pIrp->IoStatus.Status == 0;
        IoFreeIrp(pIrp);
    }
    return Result;
}

// OpenSectionWithIoControl — 通过 IO 控制打开节区
bool OpenSectionWithIoControl(__int64 DeviceHandle)
{
    char Result;
    unsigned int ServiceCount;
    unsigned int (__fastcall *FsControlFileFunc)(__int64, __int64, _QWORD, _QWORD, _DWORD **, _QWORD);
    void (__fastcall *CloseHandleFunc)(_DWORD *);
    __int64 (__fastcall *OpenSectionFunc)(_DWORD *);
    __int64 IoControlPtr;
    _QWORD *pIoControl;
    int IoControlResult;
    struct _KTHREAD *CurrentThread;
    __int64 ServiceCountCopy;
    char SavedServiceFlag;
    _QWORD *pHookResult;
    int OpenSectionResult;
    _DWORD *pSectionHandle;
    __int64 HookContext;

    Result = 0;
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    FsControlFileFunc = (unsigned int (__fastcall *)(__int64, __int64, _QWORD, _QWORD, _DWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = (void (__fastcall *)(_DWORD *))GtRead(GtCloseHandleFunc);
    OpenSectionFunc = (__int64 (__fastcall *)(_DWORD *))GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField117 | 0x100));
    IoControlPtr = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField111 | 0x100));
    pIoControl = (_QWORD *)IoControlPtr;
    if (ServiceCount != -1 && FsControlFileFunc && CloseHandleFunc && OpenSectionFunc && IoControlPtr)
    {
        IoControlResult = (unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0
           ? (int)SendDeviceIoControlWithRetry(DeviceHandle, 0x10000u, 0, &pSectionHandle, 0)
           : (int)FsControlFileFunc(DeviceHandle, 0x10000, *pIoControl, 0, &pSectionHandle, 0);
        if (IoControlResult >= 0)
        {
            CurrentThread = KeGetCurrentThread();
            ServiceCountCopy = ServiceCount;
            SavedServiceFlag = *((_BYTE *)CurrentThread + ServiceCount);
            *((_BYTE *)CurrentThread + ServiceCountCopy) = 0;
            pHookResult = (_QWORD *)DispatchHookSwapByVersion((__int64)pSectionHandle, &HookContext);
            OpenSectionResult = (int)OpenSectionFunc(pSectionHandle);
            if (pHookResult)
                *pHookResult = HookContext;
            *((_BYTE *)CurrentThread + ServiceCountCopy) = SavedServiceFlag;
            CloseHandleFunc(pSectionHandle);
            return OpenSectionResult >= 0;
        }
    }
    return Result;
}

// SendFsctlWithHookSwap — 发送带钩子交换的文件系统控制
char SendFsctlWithHookSwap(
    __int64 DeviceHandle,
    unsigned int IoControlCode,
    __int64 InputBuffer,
    unsigned int InputSize,
    __int64 OutputBuffer,
    int OutputSize,
    __int64 Flags)
{
    char Result;
    unsigned int ServiceCount;
    __int64 (__fastcall *IoControlFunc)(__int64, _QWORD, __int64, __int64, int, __int64, _QWORD);
    struct _KTHREAD *CurrentThread;
    __int64 ServiceCountCopy;
    char SavedServiceFlag;
    _DWORD *pSectionHandle;
    _QWORD *pHookResult;
    __int64 HookContext;
    __int64 *pSwapResult;
    _DWORD *SectionHandle;
    __int64 SwapResult;
    int IoControlStatus;
    int IoControlResult;
    char SavedServiceFlag2;
    __int64 NewHookContext;
    void (__fastcall *CloseHandleFunc)(_DWORD *);
    __int64 SwapBuffer[10];

    Result = 0;
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    IoControlFunc = (__int64 (__fastcall *)(__int64, _QWORD, __int64, __int64, int, __int64, _QWORD))GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField121 | 0x100));
    CloseHandleFunc = (void (__fastcall *)(_DWORD *))GtRead(GtCloseHandleFunc);
    if (ServiceCount != -1 && IoControlFunc)
    {
        CurrentThread = KeGetCurrentThread();
        ServiceCountCopy = ServiceCount;
        SavedServiceFlag = *((_BYTE *)CurrentThread + ServiceCount);
        *((_BYTE *)CurrentThread + ServiceCount) = 0;
        SavedServiceFlag2 = SavedServiceFlag;
        pSectionHandle = 0;
        pHookResult = 0;
        HookContext = 0;
        NewHookContext = 0;
        pSwapResult = SwapKernelMemoryPointer(SwapBuffer);
        if (CloseHandleFunc)
        {
            SectionHandle = SendIoControlWithUnicodeString(InputBuffer);
            pSectionHandle = SectionHandle;
            if (SectionHandle)
            {
                SwapResult = DispatchHookSwapByVersion((__int64)SectionHandle, &NewHookContext);
                HookContext = NewHookContext;
                pHookResult = (_QWORD *)SwapResult;
            }
        }
        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200)
            IoControlStatus = (int)IoControlFunc(DeviceHandle, IoControlCode, InputBuffer, OutputBuffer, OutputSize, Flags, 0);
        else
            IoControlStatus = (int)((__int64 (__fastcall *)(__int64, _QWORD, __int64, _QWORD, __int64, int, __int64, _QWORD))IoControlFunc)(
                      DeviceHandle, IoControlCode, InputBuffer, InputSize, OutputBuffer, OutputSize, Flags, 0);
        IoControlResult = IoControlStatus;
        if (pSectionHandle)
        {
            if (pHookResult)
                *pHookResult = HookContext;
            CloseHandleFunc(pSectionHandle);
        }
        if (pSwapResult)
            *pSwapResult = SwapBuffer[0];
        *((_BYTE *)CurrentThread + ServiceCountCopy) = SavedServiceFlag2;
        return IoControlResult >= 0;
    }
    return Result;
}

// IrpFsctlGetVolumeData — 获取卷数据（文件系统控制）
__int64 __fastcall IrpFsctlGetVolumeData(void *FileHandle, __int64 *pVolumeData)
{
    __int64 VolumeData;

    VolumeData = *pVolumeData;
    return IrpFileSystemControl(FileHandle, (struct _IRP *)&VolumeData, 8u, 0xEu);
}

// SaveAndReplaceDiskExtension — 保存并替换磁盘扩展结构
// 对应原始驱动 sub_14007D024
// 全局表 0x2FF 置位时取扩展结构（全局表 0x1076），校验字段 181/180 后，
// 把目标对象偏移 232 处的原指针存入 pSavedPointer，并原子替换为扩展结构中的新指针
char SaveAndReplaceDiskExtension(__int64 TargetObject, _QWORD *pSavedPointer)
{
    char Result;
    __int64 *Extension;
    __int64 OriginalPointer;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField49))
    {
        Extension = GtAlloc((GLOBAL_TABLE_INDEX)(GtEprocessField108 | 0x1000));
        if (*((_DWORD *)Extension + 181))
        {
            if (*((_DWORD *)Extension + 180) == 1)
            {
                OriginalPointer = *(_QWORD *)(TargetObject + 232);
                if (Extension[91] != OriginalPointer)
                {
                    *pSavedPointer = OriginalPointer;
                    Result = 1;
                    InterlockedExchange64((volatile __int64 *)(TargetObject + 232), Extension[91]);
                }
            }
        }
    }
    return Result;
}

// SaveAndReplaceDiskExtension2 — 保存并替换磁盘扩展结构版本2
// 对应原始驱动 sub_14007D09C
// 与版本1同构，改用全局表 0x2FA 开关与 0xFC2 扩展结构，作用于目标对象偏移 96（字段 337/336、索引 169）
char SaveAndReplaceDiskExtension2(__int64 TargetObject, _QWORD *pSavedPointer)
{
    char Result;
    __int64 *Extension;
    __int64 OriginalPointer;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField44))
    {
        Extension = GtAlloc((GLOBAL_TABLE_INDEX)0xFC2);
        if (*((_DWORD *)Extension + 337))
        {
            if (*((_DWORD *)Extension + 336) == 1)
            {
                OriginalPointer = *(_QWORD *)(TargetObject + 96);
                if (Extension[169] != OriginalPointer)
                {
                    *pSavedPointer = OriginalPointer;
                    Result = 1;
                    InterlockedExchange64((volatile __int64 *)(TargetObject + 96), Extension[169]);
                }
            }
        }
    }
    return Result;
}

// SaveAndReplaceDiskExtension3 — 保存并替换磁盘扩展结构版本3
// 对应原始驱动 sub_14007D168
// 与版本2同用 0x2FA 开关与 0xFC2 扩展结构，但作用于目标对象偏移 232（字段 181/180、索引 91）
char SaveAndReplaceDiskExtension3(__int64 TargetObject, _QWORD *pSavedPointer)
{
    char Result;
    __int64 *Extension;
    __int64 OriginalPointer;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField44))
    {
        Extension = GtAlloc((GLOBAL_TABLE_INDEX)0xFC2);
        if (*((_DWORD *)Extension + 181))
        {
            if (*((_DWORD *)Extension + 180) == 1)
            {
                OriginalPointer = *(_QWORD *)(TargetObject + 232);
                if (Extension[91] != OriginalPointer)
                {
                    *pSavedPointer = OriginalPointer;
                    Result = 1;
                    InterlockedExchange64((volatile __int64 *)(TargetObject + 232), Extension[91]);
                }
            }
        }
    }
    return Result;
}

// SaveAndReplaceDiskExtension4 — 保存并替换磁盘扩展结构版本4
// 对应原始驱动 sub_14007D2A4
// 改用全局表 0x30B 开关与 0x1124 扩展结构，作用于目标对象偏移 232（字段 181/180、索引 91）
char SaveAndReplaceDiskExtension4(__int64 TargetObject, _QWORD *pSavedPointer)
{
    char Result;
    __int64 *Extension;
    __int64 OriginalPointer;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField61))
    {
        Extension = GtAlloc((GLOBAL_TABLE_INDEX)0x1124);
        if (*((_DWORD *)Extension + 181))
        {
            if (*((_DWORD *)Extension + 180) == 1)
            {
                OriginalPointer = *(_QWORD *)(TargetObject + 232);
                if (Extension[91] != OriginalPointer)
                {
                    *pSavedPointer = OriginalPointer;
                    Result = 1;
                    InterlockedExchange64((volatile __int64 *)(TargetObject + 232), Extension[91]);
                }
            }
        }
    }
    return Result;
}

// SaveAndReplaceDiskExtension5 — 保存并替换磁盘扩展结构版本5
// 对应原始驱动 sub_14007D31C
// 与版本4同用 0x30B 开关与 0x1124 扩展结构，但作用于目标对象偏移 96（字段 337/336、索引 169）
char SaveAndReplaceDiskExtension5(__int64 TargetObject, _QWORD *pSavedPointer)
{
    char Result;
    __int64 *Extension;
    __int64 OriginalPointer;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField61))
    {
        Extension = GtAlloc((GLOBAL_TABLE_INDEX)0x1124);
        if (*((_DWORD *)Extension + 337))
        {
            if (*((_DWORD *)Extension + 336) == 1)
            {
                OriginalPointer = *(_QWORD *)(TargetObject + 96);
                if (Extension[169] != OriginalPointer)
                {
                    *pSavedPointer = OriginalPointer;
                    Result = 1;
                    InterlockedExchange64((volatile __int64 *)(TargetObject + 96), Extension[169]);
                }
            }
        }
    }
    return Result;
}

// 以下 7 个为 SendIrpToDiskDevice 使用的磁盘扩展辅助函数
// LookupStorPortFunctionTable — 查找 StorPort 函数表
// 对应原始驱动 sub_14007D10C
// 开关 0x2FA 置位且索引不超过 0x1C 时，把索引处的 16 字节函数表与 a2 原子交换
char LookupStorPortFunctionTable(unsigned int Index, _OWORD *ExchangeData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField44) && Index <= 0x1C)
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0xFC2);
        return AtomicExchange16Bytes((__int64)&Table[6 * Index], ExchangeData);
    }
    return Result;
}

// LookupStorPortFunctionTable2 — 查找 StorPort 函数表版本2
// 对应原始驱动 sub_14007D248
// 与版本1同构，开关改用 0x30B、缓冲索引改用 0x1124
char LookupStorPortFunctionTable2(unsigned int Index, _OWORD *ExchangeData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if ((unsigned int)GtRead(GtCallbackField61) && Index <= 0x1C)
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0x1124);
        return AtomicExchange16Bytes((__int64)&Table[6 * Index], ExchangeData);
    }
    return Result;
}

// QueryDiskExtensionFunctionTable — 查询磁盘扩展函数表
// 对应原始驱动 sub_14007D1E0
// 开关 0x2F3 置位且缓冲字段校验通过时，先把预设值取出写到 a2，再把 a1 原子交换进该槽位
char QueryDiskExtensionFunctionTable(_OWORD *ExchangeData, _QWORD *pPresetValue)
{
    char Result;
    __int64 *Table;
    _DWORD *Slot;

    Result = 0;
    *pPresetValue = 0;
    if ((unsigned int)GtRead(GtCallbackField37))
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0xF0F);
        Slot = (_DWORD *)(Table + 90);
        if (*((_DWORD *)Table + 181))
        {
            if (*Slot == 1)
            {
                *pPresetValue = Table[91];
                return AtomicExchange16Bytes((__int64)Slot, ExchangeData);
            }
        }
    }
    return Result;
}

// SaveDiskDeviceContextByIndex — 按索引保存磁盘设备上下文
// 对应原始驱动 sub_14007D38C
// 索引为 1 且开关 0x2FF 置位时，把 a2 原子写入缓冲偏移 720 处
char SaveDiskDeviceContextByIndex(char Index, _OWORD *ContextData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if (Index == 1 && (unsigned int)GtRead(GtCallbackField49))
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)(GtEprocessField108 | 0x1000));
        return AtomicWrite16Bytes((ULONG64)(Table + 90), ContextData);
    }
    return Result;
}

// SaveDiskDeviceContextByIndexV2 — 按索引保存磁盘设备上下文版本2
// 对应原始驱动 sub_14007D438
// 与版本1同构，开关改用 0x2F3、缓冲索引改用 0xF0F
char SaveDiskDeviceContextByIndexV2(char Index, _OWORD *ContextData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if (Index == 1 && (unsigned int)GtRead(GtCallbackField37))
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0xF0F);
        return AtomicWrite16Bytes((ULONG64)(Table + 90), ContextData);
    }
    return Result;
}

// SaveDiskDeviceContextByIndexEx — 按索引保存磁盘设备上下文扩展
// 对应原始驱动 sub_14007D3D8
// 索引为 1、开关 0x2FA 置位且条目索引不超过 0x1C 时，把 a3 原子写入对应 16 字节槽位
char SaveDiskDeviceContextByIndexEx(char Index, unsigned int EntryIndex, _OWORD *ContextData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if (Index == 1 && (unsigned int)GtRead(GtCallbackField44) && EntryIndex <= 0x1C)
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0xFC2);
        return AtomicWrite16Bytes((ULONG64)&Table[6 * EntryIndex], ContextData);
    }
    return Result;
}

// SaveDiskDeviceContextByIndexV3 — 按索引保存磁盘设备上下文版本3
// 对应原始驱动 sub_14007D484
// 与扩展版同构，开关改用 0x30B、缓冲索引改用 0x1124
char SaveDiskDeviceContextByIndexV3(char Index, unsigned int EntryIndex, _OWORD *ContextData)
{
    char Result;
    __int64 *Table;

    Result = 0;
    if (Index == 1 && (unsigned int)GtRead(GtCallbackField61) && EntryIndex <= 0x1C)
    {
        Table = GtAlloc((GLOBAL_TABLE_INDEX)0x1124);
        return AtomicWrite16Bytes((ULONG64)&Table[6 * EntryIndex], ContextData);
    }
    return Result;
}

// SendIrpToDiskDevice — 发送 IRP 到磁盘设备
// 对应原始驱动 sub_14007AF28
// 构造 0x58 字节 SCSI/ATA 命令描述块（CDB）+ 0x12 字节从属缓冲，分配并锁定 MDL，
// 初始化内部设备控制 IRP（MajorFunction=0x0F，完成例程 CompleteIrpAndCleanupMdl），
// 随后临时替换磁盘驱动/SSDT/StorPort 各处函数表与物理内存指针，下发 IRP，再逐一恢复原位
__int64 SendIrpToDiskDevice(struct _DEVICE_OBJECT *DeviceObject, int Command, void *Buffer, int SectorIndex, int BlockSize, int BlockCount)
{
    unsigned int Result;
    unsigned int TransferSize;
    int CdbSize;
    char *CdbContext;
    _QWORD *AuxBuffer;
    IRP *Irp;
    struct _MDL *Mdl;
    struct _IO_STACK_LOCATION *StackLocation;
    __int64 DiskDeviceContext;
    __int64 SsdtFunctionBase;
    _QWORD *DiskDriverSection;
    char RestoreState1, RestoreState2, RestoreState3, RestoreState4, RestoreState5;
    char RestoreState6, RestoreState7, RestoreState8, RestoreState9, RestoreState10;
    char RestoreState11;
    int CallStatus;
    __int64 SavedTable1, SavedTable2, SavedTable3, SavedTable4, SavedTable5;
    struct _KEVENT Event;
    char IoStatusBuffer;
    _OWORD FunctionTable1, FunctionTable2, FunctionTable3, FunctionTable4, FunctionTable5, FunctionTable6;
    __int64 (*pCallDriver)(__int64, ULONG_PTR, __int64);
    ULONG_PTR IrpAddress;

    pCallDriver = (__int64 (__fastcall *)(__int64, ULONG_PTR, __int64))DeviceObject;
    Result = 0xC000009A;
    SavedTable1 = 0;
    SavedTable2 = 0;
    SavedTable3 = 0;
    SavedTable4 = 0;
    SavedTable5 = 0;

    CdbContext = (char *)ExAlloc(NonPagedPool, 0x58);
    if (!CdbContext)
        return Result;

    AuxBuffer = (_QWORD *)ExAlloc(NonPagedPool, 0x12);
    if (!AuxBuffer)
    {
        ExFree(CdbContext);
        return Result;
    }

    memset(CdbContext, 0, 0x58);
    AuxBuffer[0] = 0;
    AuxBuffer[1] = 0;
    *((_WORD *)AuxBuffer + 8) = 0;

    *(_WORD *)CdbContext = 88;
    *((_QWORD *)CdbContext + 3) = (ULONG64)Buffer;
    TransferSize = (unsigned int)(BlockSize * BlockCount);
    *((_DWORD *)CdbContext + 4) = TransferSize;
    *(_WORD *)(CdbContext + 9) = 2592;
    *((_QWORD *)CdbContext + 4) = (ULONG64)AuxBuffer;
    CdbContext[11] = 18;
    CdbSize = 160;
    if (Command == 3)
        CdbSize = 608;
    *((_DWORD *)CdbContext + 3) = CdbSize;
    *((_DWORD *)CdbContext + 5) = (TransferSize >> 10) + 1;
    *((_DWORD *)CdbContext + 16) = SectorIndex;
    CdbContext[72] = (char)(2 * (Command + 17));
    CdbContext[73] = (char)((CdbContext[73] & 0x1F) | 0x80);
    CdbContext[74] = HIBYTE(SectorIndex);
    CdbContext[75] = BYTE2(SectorIndex);
    CdbContext[76] = BYTE1(SectorIndex);
    CdbContext[77] = (char)SectorIndex;
    CdbContext[79] = BYTE1(BlockSize);
    CdbContext[80] = (char)BlockSize;

    Irp = IoAllocateIrp(DeviceObject->StackSize, 0);
    if (!Irp)
    {
        ExFree(AuxBuffer);
        ExFree(CdbContext);
        return Result;
    }
    IrpAddress = (ULONG_PTR)Irp;

    Mdl = IoAllocateMdl(Buffer, TransferSize, 0, 0, Irp);
    if (!Mdl)
    {
        IoFreeIrp(Irp);
        ExFree(AuxBuffer);
        ExFree(CdbContext);
        return Result;
    }

    MmProbeAndLockPages(Mdl, 0, (LOCK_OPERATION)(Command != 3));
    KeInitializeEvent(&Event, NotificationEvent, 0);

    StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    StackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)CompleteIrpAndCleanupMdl;
    StackLocation[-1].Context = CdbContext;
    StackLocation[-1].Control = (char)0xE0;
    *((_QWORD *)CdbContext + 6) = (ULONG64)Irp;
    Irp->MdlAddress = Mdl;
    Irp->Flags = 5;
    Irp->RequestorMode = 0;
    Irp->UserIosb = (PIO_STATUS_BLOCK)&IoStatusBuffer;
    Irp->UserEvent = &Event;
    Irp->Cancel = 0;
    Irp->CancelRoutine = 0;
    Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
    Irp->IoStatus.Status = 0;
    Irp->IoStatus.Information = 0;
    Irp->AssociatedIrp.MasterIrp = 0;

    StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    StackLocation[-1].MajorFunction = 15;
    StackLocation[-1].DeviceObject = DeviceObject;
    StackLocation[-1].Parameters.WMI.ProviderId = (ULONG_PTR)CdbContext;

    DiskDeviceContext = DecryptDiskDeviceContextStr();
    SsdtFunctionBase = GetSsdtFunctionBase4();
    DiskDriverSection = GetDiskDriverSection();

    if (DiskDeviceContext)
    {
        RestoreState7 = SaveAndReplaceDiskExtension3(DiskDeviceContext, (_QWORD *)&SavedTable1);
        RestoreState8 = SaveAndReplaceDiskExtension2(DiskDeviceContext, (_QWORD *)&SavedTable2);
    }
    if (SsdtFunctionBase)
        RestoreState1 = SaveAndReplaceDiskExtension(SsdtFunctionBase, (_QWORD *)&SavedTable5);
    if (DiskDriverSection)
    {
        RestoreState4 = SaveAndReplaceDiskExtension4((__int64)DiskDriverSection, (_QWORD *)&SavedTable4);
        RestoreState6 = SaveAndReplaceDiskExtension5((__int64)DiskDriverSection, (_QWORD *)&SavedTable3);
    }

    RestoreState11 = QueryDiskExtensionFunctionTable(&FunctionTable2, (_QWORD *)&pCallDriver);
    RestoreState2 = LookupStorPortFunctionTable(0xF, &FunctionTable5);
    RestoreState3 = LookupStorPortFunctionTable(0x1C, &FunctionTable1);
    RestoreState9 = DispatchStorPortIoControl(&FunctionTable6);
    RestoreState5 = LookupStorPortFunctionTable2(0xF, &FunctionTable4);
    RestoreState10 = LookupStorPortFunctionTable2(0x1C, &FunctionTable3);
    RestoreState1 = SwapPhysicalMemoryQword(GtCallbackField38, GtCallbackField39);
    RestoreState2 = SwapPhysicalMemoryQword(GtCallbackField45, GtCallbackField46);
    RestoreState3 = SwapPhysicalMemoryQword(GtCallbackField50, GtCallbackField51);
    RestoreState4 = SwapPhysicalMemoryQword(GtCallbackField62, GtCallbackField63);
    RestoreState5 = SwapDiskIrpFunctionPointer();

    CallStatus = (int)AllocateIrpStackAndCallDriver(pCallDriver, (__int64)DeviceObject, IrpAddress);

    SaveDiskDeviceContextByIndexV3(RestoreState10, 0x1C, &FunctionTable3);
    SaveDiskDeviceContextByIndexV3(RestoreState5, 0xF, &FunctionTable4);
    SaveDiskDeviceContextByIndex(RestoreState9, &FunctionTable6);
    SaveDiskDeviceContextByIndexEx(RestoreState3, 0x1C, &FunctionTable1);
    SaveDiskDeviceContextByIndexEx(RestoreState2, 0xF, &FunctionTable5);
    SaveDiskDeviceContextByIndexV2(RestoreState11, &FunctionTable2);

    Result = (unsigned int)CallStatus;
    if (CallStatus == 259)
        KeWaitForSingleObject(&Event, Executive, 0, 0, 0);

    if (RestoreState1 == 1)
        WritePhysicalMemoryFromGt(GtCallbackField38, GtCallbackField39);
    if (RestoreState2 == 1)
        WritePhysicalMemoryFromGt(GtCallbackField45, GtCallbackField46);
    if (RestoreState3 == 1)
        WritePhysicalMemoryFromGt(GtCallbackField50, GtCallbackField51);
    if (RestoreState4 == 1)
        WritePhysicalMemoryFromGt(GtCallbackField62, GtCallbackField63);
    RestoreDiskIrpFunctionPointer(RestoreState5);

    if (DiskDeviceContext)
    {
        if (RestoreState7 == 1)
            InterlockedExchange64((volatile __int64 *)(DiskDeviceContext + 232), SavedTable1);
        if (RestoreState8 == 1)
            InterlockedExchange64((volatile __int64 *)(DiskDeviceContext + 96), SavedTable2);
    }
    if (SsdtFunctionBase && RestoreState1 == 1)
        InterlockedExchange64((volatile __int64 *)(SsdtFunctionBase + 232), SavedTable5);
    if (DiskDriverSection)
    {
        if (RestoreState4 == 1)
            InterlockedExchange64((volatile __int64 *)(DiskDriverSection + 29), SavedTable4);
        if (RestoreState6 == 1)
            InterlockedExchange64((volatile __int64 *)(DiskDriverSection + 12), SavedTable3);
    }

    if (*((_QWORD *)CdbContext + 4) != (ULONG64)AuxBuffer && *((_QWORD *)CdbContext + 4))
        ExFreePoolWithTag((PVOID)*((_QWORD *)CdbContext + 4), 0);
    if (CallStatus >= 0)
        Result = 0;

    ExFree(AuxBuffer);
    ExFree(CdbContext);
    return Result;
}

// CdbCommandCompletionCallback — CDB 命令完成回调：释放 IRP 缓冲区，恢复当前线程标志位，调用完成通知回调
__int64 CdbCommandCompletionCallback(void *Irp)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    __int64 (__fastcall *pNotifyFunc)(_QWORD);
    __int64 Result;
    unsigned int ThreadFlagOffset;
    int FlagValue;
    struct _KTHREAD *CurrentThread;
    unsigned int ThreadFlagOffset2;
    unsigned int EprocessField94 = (unsigned int)GtRead(GtEprocessField94);
    bool IsOldBuild;
    struct _KTHREAD *Status;

    ExFree(Irp);
    Result = GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField42);
    pNotifyFunc = (__int64 (__fastcall *)(_QWORD))Result;
    if (Result)
    {
        if (BuildNumber < 0x1DB1)
        {
            Result = EprocessField94;
            FlagValue = 16;
            ThreadFlagOffset = (unsigned int)Result;
        }
        else
        {
            ThreadFlagOffset = (unsigned int)GtRead(GtFltPeSectionAddr1 | GtEprocessField86);
            Result = BuildNumber;
            if ((_DWORD)Result == 7601)
            {
                FlagValue = 0x2000;
            }
            else
            {
                Result = BuildNumber;
                if ((_DWORD)Result == 9200)
                {
                    FlagValue = 4096;
                }
                else
                {
                    Result = BuildNumber;
                    FlagValue = 1024;
                    if ((_DWORD)Result == 9600)
                        FlagValue = 2048;
                }
            }
        }
        if (ThreadFlagOffset != -1)
        {
            CurrentThread = KeGetCurrentThread();
            *(_DWORD *)((char *)CurrentThread + ThreadFlagOffset) |= FlagValue;
            ThreadFlagOffset2 = EprocessField94;
            if (ThreadFlagOffset2 != -1)
            {
                IsOldBuild = BuildNumber < 0x23F0;
                Status = KeGetCurrentThread();
                *(_DWORD *)((char *)Status + ThreadFlagOffset2) &= ~(IsOldBuild ? 64 : 32);
                Status = KeGetCurrentThread();
                *(_DWORD *)((char *)Status + ThreadFlagOffset2) &= ~1u;
            }
            return (__int64)pNotifyFunc(0);
        }
    }
    return Result;
}

// RxTdiRequestCompletion — RxTDI 请求完成回调：IRP 完成例程，设置事件对象通知等待者
__int64 __fastcall RxTdiRequestCompletion(void *DeviceObject, void *Irp, void *Context)
{
    if (Context)
        KeSetEvent((struct _KEVENT *)Context, 0, 0);
    return 0xC0000016LL;
}

// ReadSystemDllAndInitSession — 读取系统 DLL 并初始化会话：读取系统 DLL 文件，解析 PE 格式，比较 PE 头，初始化会话状态表
__int64 ReadSystemDllAndInitSession(void)
{
    char Result;
    size_t MaxCount;
    void *Src;
    unsigned int PeFileSize;
    void *pPeFileBuffer;
    int EncodedBuffer[24];
    __int64 SessionTableBase;
    unsigned int SessionTableSize;

    Result = 0;
    EncodedBuffer[0] = 0x53005C;
    EncodedBuffer[1] = 0x730079;
    EncodedBuffer[2] = 0x650074;
    EncodedBuffer[3] = 0x52006D;
    EncodedBuffer[4] = 0x6F006F;
    EncodedBuffer[5] = 0x5C0074;
    EncodedBuffer[6] = 0x790073;
    EncodedBuffer[7] = 0x740073;
    EncodedBuffer[8] = 0x6D0065;
    EncodedBuffer[9] = 0x320033;
    EncodedBuffer[10] = 0x5C0077;
    EncodedBuffer[11] = 0x6E0069;
    EncodedBuffer[12] = 0x320033;
    EncodedBuffer[13] = 0x6B0073;
    EncodedBuffer[14] = 0x670064;
    EncodedBuffer[15] = 0x2E0073;
    EncodedBuffer[16] = 0x640064;
    EncodedBuffer[17] = 0x6C006C;
    EncodedBuffer[18] = 0x0;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedBuffer, &Src, (ULONG *)&MaxCount, 1))
    {
        if (ReadNtFileToBuffer((PUCHAR)Src, (unsigned int)MaxCount, (PUCHAR *)&pPeFileBuffer, (PULONG)&PeFileSize) == 1)
            Result = 1;
        else
            Result = 0;
        ExFree(Src);
        if (Result == 1)
        {
            SessionTableBase = GtRead((GLOBAL_TABLE_INDEX)0x91B);
            SessionTableSize = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x91C);
            if (pPeFileBuffer && PeFileSize && SessionTableBase && SessionTableSize > 0x1001)
            {
                if (ComparePeHeaders(SessionTableBase, SessionTableSize, (__int64)pPeFileBuffer, PeFileSize) == 1)
                {
                    Result = 1;
                }
                else
                {
                    if (InitSessionStateTable((__int64)pPeFileBuffer, PeFileSize) == 1)
                        Result = 1;
                    else
                        Result = 0;
                }
            }
            else
            {
                if (InitSessionStateTable((__int64)pPeFileBuffer, PeFileSize) == 1)
                    Result = 1;
                else
                    Result = 0;
            }
            ExFree(pPeFileBuffer);
        }
    }
    return Result;
}

// InitIrpBufferWithCdb — 初始化带 CDB 的 IRP 缓冲区，设置 SCSI 命令描述块(CDB)参数到 SRB 结构
void InitIrpBufferWithCdb(__int64 Buffer, __int64 Address, unsigned int Flags, __int64 CompletionRoutine, unsigned int BlockSize, unsigned int BlockCount, unsigned int CdbFlags, unsigned int CdbParam)
{
    __int64 (__fastcall *pInitFunc)(__int64, __int64, __int64, __int64, __int64, __int64, char, __int64);

    pInitFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, char, __int64))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField54);
    if (pInitFunc && Flags == 2)
    {
        pInitFunc(Buffer, Address, 2, CompletionRoutine, BlockSize, BlockCount, CdbFlags, CdbParam);
        return;
    }
    *(_BYTE *)Buffer = 0x12;
    *(_BYTE *)(Buffer + 2) = 0x58;
    *(_QWORD *)(Buffer + 40) = BlockSize;
    *(_BYTE *)(Buffer + 80) = Flags;
    *(_QWORD *)(Buffer + 8) = Address;
    *(_QWORD *)(Buffer + 32) = CompletionRoutine;
    *(_QWORD *)(Buffer + 48) = BlockCount;
    if (BlockCount)
    {
        *(_BYTE *)(Buffer + 81) = CdbFlags;
        *(_QWORD *)(Buffer + 56) = CdbParam;
    }
    else
    {
        *(_BYTE *)(Buffer + 81) = 0;
        *(_QWORD *)(Buffer + 56) = 0;
    }
    *(_BYTE *)(Buffer + 82) = 0;
}

// ReadRawFileToBuffer — 读取原始文件到缓冲区
// 通过编码路径字符串读取 ntoskrnl.exe 文件到内存缓冲区
char __fastcall ReadRawFileToBuffer(_QWORD *pFileBuffer, unsigned int *pFileSize)
{
    bool Result;
    size_t MaxCount;
    void *pRawData;
    int EncodedPath[20];

    // 编码的 ntoskrnl.exe 路径
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
    EncodedPath[14] = 5505116;
    EncodedPath[15] = 3014765;
    EncodedPath[16] = 7929971;
    EncodedPath[17] = 115;

    Result = 0;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &pRawData, (ULONG *)&MaxCount, 1))
    {
        Result = (ReadNtFileToBuffer((PUCHAR)pRawData, (unsigned int)MaxCount, (PUCHAR *)pFileBuffer, (PULONG)pFileSize) == 1);
        ExFree(pRawData);
    }
    return Result;
}

// InitSessionStateTable — 初始化会话状态表
// 在 win32k 中查找 SGDGetSessionState 和 SGDSessionInitialize 导出，定位会话状态数据结构
char __fastcall InitSessionStateTable(__int64 PeBase, unsigned int PeSize)
{
    char Result;
    __int64 NtoskrnlBase;
    unsigned int SectionOffset1;
    unsigned int SectionOffset2;
    unsigned int EntryIndex;
    int CurrentOffset;
    __int16 SectionType;
    int NextOffset;
    __int64 InfoBuffer;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：ReadPESectionEntry 会写 0x120 字节，原 [20] 仅 80 字节
    unsigned int EntrySize;
    __int64 FieldValue;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;
    _WORD ExportName[12];

    Result = 0;
    strcpy((char *)ExportName, "SGDGetSessionState");
    *((unsigned char *)&ExportName[9] + 1) = 0;

    NtoskrnlBase = GtRead(GtDisableHookProtectionAddr2 | GtNtoskrnlModuleBase | 0x100);
    if (!NtoskrnlBase)
        return Result;

    SectionOffset1 = 0;
    SectionOffset2 = 0;

    if (LookupExportByName((PUCHAR)PeBase, PeSize, (PCHAR)ExportName, (PULONG)&SectionOffset1) != 1 || !SectionOffset1 || SectionOffset1 >= PeSize || SectionOffset1 + 4096 >= PeSize)
        return Result;

    InitPESectionReadContext(PeBase + SectionOffset1, 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    EntryIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
    {
        CurrentOffset = EntryCumulSize + (int)CumulativeSize;
        CumulativeSize += EntryCumulSize;
        SectionType = *(_WORD *)(EntryDataPtr + 6);
        if (SectionType == 1298 && FieldValue == 0x40000 && EntrySize && InfoBuffer == 64)
        {
            if (!SectionOffset1)
            {
                SectionOffset1 = (unsigned int)(CurrentOffset + EntrySize - PeBase);
                goto LABEL_CHECK;
            }
        }
        else if (SectionType == 1296 && FieldValue == 0x40000 && EntrySize && InfoBuffer == 64 && !SectionOffset2)
        {
            SectionOffset2 = (unsigned int)(CurrentOffset + EntrySize - PeBase);
        }

LABEL_CHECK:
        if (SectionOffset1 && SectionOffset2 && SectionOffset1 < PeSize && SectionOffset2 < PeSize)
        {
            GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer02 | 0x100, NtoskrnlBase + SectionOffset1);
            GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer01 | 0x100, NtoskrnlBase + SectionOffset2);
            break;
        }

        if (++EntryIndex >= 0x1E)
            break;
    }

    if (SectionOffset1 && SectionOffset2)
    {
        strcpy((char *)ExportName, "SGDSessionInitialize");
        *((unsigned char *)&ExportName[10] + 1) = 0;
        ExportName[11] = 0;

        if (LookupExportByName((PUCHAR)PeBase, PeSize, (PCHAR)ExportName, (PULONG)&SectionOffset1) == 1 && SectionOffset1 && SectionOffset1 < PeSize && SectionOffset1 + 4096 < PeSize)
        {
            InitPESectionReadContext(PeBase + SectionOffset1, 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
            EntryIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, (PULONG)SectionEntry))
            {
                CurrentOffset = EntryCumulSize + (int)CumulativeSize;
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1245 && FieldValue == 0x40000)
                {
                    if (EntrySize && InfoBuffer == 32 && SectionEntry[2] == 1)
                    {
                        NextOffset = (int)(CurrentOffset + EntrySize - PeBase);
                        if (NextOffset && (unsigned int)NextOffset < PeSize)
                        {
                            GtWrite(GtDisableHookProtectionAddr2 | GtPathBuffer03 | 0x100, NtoskrnlBase + NextOffset);
                            return 1;
                        }
                    }
                }
                if (++EntryIndex >= 0x64)
                    return Result;
            }
        }
    }
    return Result;
}
// SendIoControlWithQuotaBuffer — 发送带配额缓冲区的 IO 控制命令
// 构建号 >= 0x42EE 时使用配额池分配中间缓冲区，否则直接调用处理函数
// 对应原始驱动 sub_140075A9C
__int64 __fastcall SendIoControlWithQuotaBuffer(
    __int64 (__fastcall *HandlerFunc)(__int64, __int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *),
    __int64 Arg2,
    __int64 Arg3,
    unsigned int Arg4,
    unsigned int Arg5,
    _BYTE *Dst,
    SIZE_T NumberOfBytes,
    size_t *pOutSize)
{
    unsigned int v11 = (unsigned int)NumberOfBytes;
    int v12 = -1073741823;
    _BYTE *PoolWithQuotaTag;
    unsigned int v14;
    size_t MaxCount;
    __int64 v18 = Arg3;
    _BYTE P[64];

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
    {
        if ((unsigned int)NumberOfBytes > 0x40)
            PoolWithQuotaTag = ExAllocatePoolWithQuotaTag((POOL_TYPE)9, (unsigned int)NumberOfBytes, 0x42424D43u);
        else
            PoolWithQuotaTag = P;
        if (PoolWithQuotaTag)
        {
            v12 = (int)HandlerFunc(Arg2, v18, Arg4, Arg5, PoolWithQuotaTag, (_DWORD)NumberOfBytes, &MaxCount);
            if (v12 >= 0)
            {
                v14 = (unsigned int)MaxCount;
                *(_DWORD *)pOutSize = (unsigned int)MaxCount;
                if ((unsigned int)NumberOfBytes > v14)
                    v11 = v14;
                memmove(Dst, PoolWithQuotaTag, v11);
            }
            if (PoolWithQuotaTag != P)
                ExFreePoolWithTag(PoolWithQuotaTag, 0x42424D43u);
        }
    }
    else
    {
        return (unsigned int)HandlerFunc(Arg2, Arg3, Arg4, Arg5, Dst, (_DWORD)NumberOfBytes, pOutSize);
    }
    return (unsigned int)v12;
}

// SendIoControlWithQuotaBufferEx — 扩展版发送带配额缓冲区的 IO 控制命令
// 构建号 >= 0x42EE 时使用配额池分配中间缓冲区，否则直接调用处理函数
// 对应原始驱动 sub_140075C24
__int64 __fastcall SendIoControlWithQuotaBufferEx(
    __int64 (__fastcall *HandlerFunc)(__int64, _QWORD, _QWORD, _BYTE *, _DWORD, size_t *, __int64, _BYTE *),
    __int64 Arg2,
    unsigned int Arg3,
    int Arg4,
    _BYTE *Dst,
    SIZE_T NumberOfBytes,
    size_t *pOutSize)
{
    unsigned int v10 = (unsigned int)NumberOfBytes;
    int v11 = -1073741823;
    _BYTE *PoolWithQuotaTag;
    unsigned int v13;
    __int64 v15;
    _BYTE *v16;
    size_t MaxCount;
    _BYTE P[64];

    v15 = (unsigned int)-1073741823 | ((unsigned __int64)(unsigned int)Arg4 << 32);
    v10 = (unsigned int)NumberOfBytes;
    v11 = -1073741823;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
    {
        if ((unsigned int)NumberOfBytes > 0x40)
        {
            PoolWithQuotaTag = ExAllocatePoolWithQuotaTag((POOL_TYPE)9, (unsigned int)NumberOfBytes, 0x42424D43u);
            v16 = PoolWithQuotaTag;
        }
        else
        {
            PoolWithQuotaTag = P;
            v16 = P;
        }
        if (PoolWithQuotaTag)
        {
            v11 = (int)HandlerFunc(Arg2, Arg3, HIDWORD(v15), PoolWithQuotaTag, (_DWORD)NumberOfBytes, &MaxCount, v15, v16);
            if (v11 >= 0)
            {
                v13 = (unsigned int)MaxCount;
                *(_DWORD *)pOutSize = (unsigned int)MaxCount;
                if ((unsigned int)NumberOfBytes > v13)
                    v10 = v13;
                memmove(Dst, PoolWithQuotaTag, v10);
            }
            if (PoolWithQuotaTag != P)
                ExFreePoolWithTag(PoolWithQuotaTag, 0x42424D43u);
        }
    }
    else
    {
        return (unsigned int)HandlerFunc(Arg2, Arg3, HIDWORD(v15), Dst, (_DWORD)NumberOfBytes, pOutSize, v15, 0);
    }
    return (unsigned int)v11;
}

// AllocBufferAndSendIoControl — 分配中间缓冲并发送 IO 控制
// 对应原始驱动 0x140075D94（436 字节）
// 【逆向来源】⚠ 可被 Hex-Rays 正常反编译（54 行伪代码），按伪代码实现
// 【参数】9 个：a1=处理函数、a2/a3=句柄、a4=类型、a5=标志、
//   Dst=输出缓冲、NumberOfBytes=大小、a8=输出大小指针
// 【逻辑】与 SendIoControlWithQuotaBuffer **同源**，差异是处理函数多一个参数
//   （9 参 vs 8 参）且多传一个 0。结构同样是：
//   构建号 < 0x42EE → 直接用栈上 64 字节缓冲 P[]（或配额池，当大小 > 0x40）
//   → 调用处理函数 → 把结果 memmove 到 Dst → 释放配额池（P 不释放）。
//   ⚠ 注意：内层 `if (GtRead >= 0x42EE)` 在外层 `< 0x42EE` 条件下是**死分支**
//   （编译器保留的冗余判断），故实际只走 else 那条直调路径 —— 与
//   SendIoControlWithQuotaBuffer 的情况相同（那边是外层 >= 时内层必然成立）。
// 【⚠ 上层调用约定】调用方 SendWriteMemoryIoControl 按 8 实参调用，
//   而本函数声明 9 个形参 —— 差异见该函数的【⚠ 未实现依赖】说明。
__int64 __fastcall AllocBufferAndSendIoControl(
    __int64 (__fastcall *a1)(__int64, __int64, _QWORD, _QWORD, int, _BYTE *, _DWORD, size_t *, _QWORD),
    __int64 a2, __int64 a3, unsigned int a4, int a5,
    _BYTE *Dst, SIZE_T NumberOfBytes, size_t *a8)
{
    unsigned int v11 = (unsigned int)NumberOfBytes;
    int v12 = -1073741823;
    _BYTE *PoolWithQuotaTag;
    unsigned int v14;
    size_t MaxCount = 0;
    __int64 v18 = a3;
    _BYTE P[64];

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x42EE)
    {
        if ((unsigned int)NumberOfBytes > 0x40)
            PoolWithQuotaTag = ExAllocatePoolWithQuotaTag((POOL_TYPE)9, (unsigned int)NumberOfBytes, 0x42424D43u);
        else
            PoolWithQuotaTag = P;

        if (PoolWithQuotaTag)
        {
            v12 = (int)a1(a2, v18, 0, a4, a5, PoolWithQuotaTag, (_DWORD)NumberOfBytes, &MaxCount, 0);
            if (v12 >= 0)
            {
                v14 = (unsigned int)MaxCount;
                *(_DWORD *)a8 = (unsigned int)MaxCount;
                if ((unsigned int)NumberOfBytes > v14)
                    v11 = v14;
                memmove(Dst, PoolWithQuotaTag, v11);
            }
            if (PoolWithQuotaTag != P)
                ExFreePoolWithTag(PoolWithQuotaTag, 0x42424D43u);
        }
        return (unsigned int)v12;
    }
    else
    {
        return (unsigned int)a1(a2, a3, 0, a4, a5, Dst, (_DWORD)NumberOfBytes, a8, 0);
    }
}
