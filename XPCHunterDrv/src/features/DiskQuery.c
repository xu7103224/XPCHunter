// MissingFuncs.c — 暂未分配到各源文件的函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"

// C4700 抑制：各种函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
#include <intrin.h>

// 前向声明 — 定义在 Protocol.c 中
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// 前向声明 — 内部辅助函数
extern char OpenDeviceTarget(__int64 EncodedPath, __int64 *pDeviceHandle, __int64 *pDeviceObjectHandle);
extern __int64 GetDeviceObjectFromContext(__int64 DeviceHandle);
extern char GetDiskDriverInfo(char State, void *pBuffer, __int64 *pFuncTable);
extern char SetDiskDriverInfo(char State, char Flags, void *pBuffer);
extern char FindPeSectionByTypeRsrc(__int64 Buffer, unsigned int Size, __int64 Address);
extern char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
extern __int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex);
extern __int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex);
extern __int64 ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern __int64 ReadWriteKernelMemory(void);

// =======================================================================
// 简单函数实现
// =======================================================================

char QueryDiskInfoAta(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    char Result;
    __int64 (__fastcall *SendDeviceIoControl)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    void (__fastcall *WaitForEvent)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD);
    __int64 CloseDeviceHandle;
    __int64 CloseHandle;
    __int64 DeviceObjectFromContext;
    __int64 IrpPtr;
    ULONG_PTR IrpResult;
    __int64 IrpStackLocation;
    char DiskDriverInfo;
    int IoStatus;
    unsigned int IdentifyBufferSize;
    _WORD *IdentifyBuffer;
    __int64 (__fastcall *IrpPtr2)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    __int64 IrpStackLocation2;
    char DiskDriverInfo2;
    int IoStatus2;
    unsigned __int64 PartitionCount;
    _WORD *SrcEntry;
    char *DstEntry;
    __int64 RemainingEntries;
    int TempValue;
    int WaitFlag;
    char DiskDriverInfo1;
    char RestoreFlag2;
    char RestoreFlag1;
    char RestoreFlag3;
    __int64 DeviceHandle;
    __int64 (__fastcall *DiskDriverInfoTable)(__int64, ULONG_PTR, __int64);
    __int64 (__fastcall *SendDeviceIoControl2)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *);
    unsigned int OutputBufferSizeCopy;
    int IoStatusBlock;
    unsigned __int64 DataTransferSize;
    __int64 DeviceObjectHandle;
    void (__fastcall *CloseDeviceHandleFunc)(__int64);
    void (__fastcall *CloseHandleFunc)(__int64);
    struct _KEVENT Event;
    _DWORD Dst[10];
    _DWORD AtaOutputBuffer[16];
    _DWORD EncodedDevicePath[6];
    _OWORD DiskDriverInfoBuffer;

    OutputBufferSizeCopy = BufferSize;
    Result = 0;
    SendDeviceIoControl = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    SendDeviceIoControl2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    WaitForEvent = (void (__fastcall *)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField06);
    CloseDeviceHandle = GtRead(GtCloseHandleFunc);
    CloseDeviceHandleFunc = (void (__fastcall *)(__int64))CloseDeviceHandle;
    CloseHandle = GtRead(GtExFreePoolFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandle;
    if (SendDeviceIoControl && WaitForEvent && CloseDeviceHandle && CloseHandle)
    {
        EncodedDevicePath[0] = 4456540;
        EncodedDevicePath[1] = 7733349;
        EncodedDevicePath[2] = 6488169;
        EncodedDevicePath[3] = 6029413;
        EncodedDevicePath[4] = 6488148;
        EncodedDevicePath[5] = 112;
        if (OpenDeviceTarget((__int64)EncodedDevicePath, &DeviceHandle, &DeviceObjectHandle) == 1)
        {
            memset(Dst, 0, sizeof(Dst));
            Dst[0] = 1024;
            Dst[2] = 512;
            Dst[3] = 256;
            Dst[4] = 1;
            DeviceObjectFromContext = GetDeviceObjectFromContext(DeviceHandle);
            if (DeviceObjectFromContext)
            {
                KeInitializeEvent(&Event, NotificationEvent, 0);
                memset(AtaOutputBuffer, 0, 0x3Cu);
                IrpPtr = SendDeviceIoControl(1179651, DeviceObjectFromContext, Dst, 40, (WORD *)AtaOutputBuffer, 60u, 0, &Event, &IoStatusBlock);
                IrpResult = IrpPtr;
                if (IrpPtr)
                {
                    IrpStackLocation = *(_QWORD *)(IrpPtr + 184);
                    *(_QWORD *)(IrpStackLocation - 32) = DeviceObjectFromContext;
                    *(_QWORD *)(IrpStackLocation - 24) = DeviceHandle;
                    DiskDriverInfo = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, (__int64 *)&DiskDriverInfoTable);
                    DiskDriverInfo1 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                    RestoreFlag1 = SwapDiskIrpFunctionPointer();
                    IoStatus = (int)AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, IrpResult);
                    SetDiskDriverInfo(DiskDriverInfo, 0, &DiskDriverInfoBuffer);
                    if (IoStatus == 259)
                    {
                        WaitForEvent(&Event, 0, 0, 0, 0);
                        IoStatus = IoStatusBlock;
                    }
                    if (DiskDriverInfo1 == 1)
                        WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                    RestoreDiskIrpFunctionPointer(RestoreFlag1);
                    if (!IoStatus)
                    {
                        IdentifyBufferSize = 24 * (AtaOutputBuffer[14] + 16);
                        IdentifyBuffer = ExAlloc(PagedPool, IdentifyBufferSize);
                        if (IdentifyBuffer)
                        {
                            Dst[4] = 258;
                            KeInitializeEvent(&Event, NotificationEvent, 0);
                            WaitFlag = 0;
                            IrpPtr2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, _WORD *, unsigned int, int, struct _KEVENT *, int *))(ULONG_PTR)SendDeviceIoControl2(1179651, DeviceObjectFromContext, Dst, 40, IdentifyBuffer, IdentifyBufferSize, WaitFlag, &Event, &IoStatusBlock);
                            SendDeviceIoControl2 = IrpPtr2;
                            if (IrpPtr2)
                            {
                                IrpStackLocation2 = *((_QWORD *)IrpPtr2 + 23);
                                *(_QWORD *)(IrpStackLocation2 - 32) = DeviceObjectFromContext;
                                *(_QWORD *)(IrpStackLocation2 - 24) = DeviceHandle;
                                DiskDriverInfo2 = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, (__int64 *)&DiskDriverInfoTable);
                                RestoreFlag3 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                                RestoreFlag2 = SwapDiskIrpFunctionPointer();
                                IoStatus2 = (int)AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, (ULONG_PTR)SendDeviceIoControl2);
                                SetDiskDriverInfo(DiskDriverInfo2, 0, &DiskDriverInfoBuffer);
                                if (IoStatus2 == 259)
                                {
                                    WaitForEvent(&Event, 0, 0, 0, 0);
                                    IoStatus2 = IoStatusBlock;
                                }
                                if (RestoreFlag3 == 1)
                                    WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                                RestoreDiskIrpFunctionPointer(RestoreFlag2);
                                if (!IoStatus2)
                                {
                                    PartitionCount = DataTransferSize / 0x18;
                                    *OutSize = (unsigned int)(DataTransferSize / 0x18) ? 52 * ((unsigned int)(DataTransferSize / 0x18) - 1) + 56 : 56;
                                    if (OutputBufferSizeCopy >= *OutSize)
                                    {
                                        memset(Buffer, 0, *OutSize);
                                        *(unsigned int *)Buffer = (unsigned int)PartitionCount;
                                        if ((_DWORD)PartitionCount)
                                        {
                                            SrcEntry = IdentifyBuffer + 8;
                                            DstEntry = Buffer + 8;
                                            RemainingEntries = (unsigned int)PartitionCount;
                                            do
                                            {
                                                *((_DWORD *)DstEntry - 1) = *((_DWORD *)SrcEntry - 4);
                                                *(_WORD *)DstEntry = *(SrcEntry - 4);
                                                DstEntry += 52;
                                                *((_WORD *)DstEntry - 25) = *SrcEntry;
                                                TempValue = *((_DWORD *)SrcEntry - 3);
                                                SrcEntry += 12;
                                                *((_DWORD *)DstEntry - 12) = TempValue;
                                                *((_DWORD *)DstEntry - 11) = *((_DWORD *)SrcEntry - 7);
                                                *((_WORD *)DstEntry - 20) = *(SrcEntry - 15);
                                                TempValue = *(SrcEntry - 11);
                                                *((_QWORD *)DstEntry - 2) = 0;
                                                *((_WORD *)DstEntry - 19) = TempValue;
                                                *((_DWORD *)DstEntry - 2) = *((_DWORD *)SrcEntry - 5) | 0x80000000;
                                                --RemainingEntries;
                                            } while (RemainingEntries);
                                        }
                                        Result = 1;
                                    }
                                }
                            }
                            ExFree(IdentifyBuffer);
                        }
                    }
                }
            }
            CloseDeviceHandleFunc(DeviceHandle);
            CloseHandleFunc(DeviceObjectHandle);
        }
    }
    return Result;
}

char SendAtaScsiCommand(char *Buffer, unsigned int BufferSize, unsigned int *OutSize)
{
    char Result;
    __int64 (__fastcall *SendDeviceIoControl)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    void (__fastcall *WaitForEvent)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD);
    __int64 CloseDeviceHandle;
    __int64 CloseHandle;
    __int64 DeviceObjectFromContext;
    __int64 IrpPtr;
    ULONG_PTR IrpResult;
    __int64 IrpStackLocation;
    char DiskDriverInfo;
    int IoStatus;
    unsigned int ScsiBufferSize;
    char *ScsiBuffer;
    __int64 (__fastcall *IrpPtr2)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    __int64 IrpStackLocation2;
    char DiskDriverInfo2;
    int IoStatus2;
    unsigned __int64 ScsiDeviceCount;
    char *SrcEntry;
    char *DstEntry;
    __int64 RemainingEntries;
    int TempValue;
    int WaitFlag;
    char DiskDriverInfo1;
    char RestoreFlag2;
    char RestoreFlag1;
    char RestoreFlag3;
    __int64 DeviceHandle;
    __int64 (__fastcall *DiskDriverInfoTable)(__int64, ULONG_PTR, __int64);
    __int64 (__fastcall *SendDeviceIoControl2)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *);
    unsigned int OutputBufferSizeCopy;
    int IoStatusBlock;
    unsigned __int64 DataTransferSize;
    __int64 DeviceObjectHandle;
    void (__fastcall *CloseDeviceHandleFunc)(__int64);
    struct _KEVENT Event;
    void (__fastcall *CloseHandleFunc)(__int64);
    _QWORD ScsiOutputBuffer[2];
    int ScsiStatus;
    _DWORD Dst[10];
    _DWORD EncodedDevicePath[6];
    _OWORD DiskDriverInfoBuffer;

    OutputBufferSizeCopy = BufferSize;
    Result = 0;
    SendDeviceIoControl = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    SendDeviceIoControl2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *))GtRead(GtTotalSize | GtObjectTypeField32 | GtNtoskrnlModuleBase);
    WaitForEvent = (void (__fastcall *)(struct _KEVENT *, _QWORD, _QWORD, _QWORD, _QWORD))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField06);
    CloseDeviceHandle = GtRead(GtCloseHandleFunc);
    CloseDeviceHandleFunc = (void (__fastcall *)(__int64))CloseDeviceHandle;
    CloseHandle = GtRead(GtExFreePoolFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandle;
    if (SendDeviceIoControl && WaitForEvent && CloseDeviceHandle && CloseHandle)
    {
        EncodedDevicePath[0] = 4456540;
        EncodedDevicePath[1] = 7733349;
        EncodedDevicePath[2] = 6488169;
        EncodedDevicePath[3] = 6029413;
        EncodedDevicePath[4] = 6553685;
        EncodedDevicePath[5] = 112;
        if (OpenDeviceTarget((__int64)EncodedDevicePath, &DeviceHandle, &DeviceObjectHandle) == 1)
        {
            memset(Dst, 0, sizeof(Dst));
            Dst[0] = 1025;
            Dst[2] = 512;
            Dst[3] = 256;
            Dst[4] = 1;
            DeviceObjectFromContext = GetDeviceObjectFromContext(DeviceHandle);
            if (DeviceObjectFromContext)
            {
                KeInitializeEvent(&Event, NotificationEvent, 0);
                ScsiOutputBuffer[0] = 0;
                ScsiOutputBuffer[1] = 0;
                ScsiStatus = 0;
                IrpPtr = SendDeviceIoControl(1179651, DeviceObjectFromContext, Dst, 40, (char *)ScsiOutputBuffer, 20u, 0, &Event, &IoStatusBlock);
                IrpResult = IrpPtr;
                if (IrpPtr)
                {
                    IrpStackLocation = *(_QWORD *)(IrpPtr + 184);
                    *(_QWORD *)(IrpStackLocation - 32) = DeviceObjectFromContext;
                    *(_QWORD *)(IrpStackLocation - 24) = DeviceHandle;
                    DiskDriverInfo = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, (__int64 *)&DiskDriverInfoTable);
                    DiskDriverInfo1 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                    RestoreFlag1 = SwapDiskIrpFunctionPointer();
                    IoStatus = (int)AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, IrpResult);
                    SetDiskDriverInfo(DiskDriverInfo, 0, &DiskDriverInfoBuffer);
                    if (IoStatus == 259)
                    {
                        WaitForEvent(&Event, 0, 0, 0, 0);
                        IoStatus = IoStatusBlock;
                    }
                    if (DiskDriverInfo1 == 1)
                        WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                    RestoreDiskIrpFunctionPointer(RestoreFlag1);
                    if (!IoStatus)
                    {
                        ScsiBufferSize = 12 * (ScsiStatus + 16);
                        ScsiBuffer = (char *)ExAlloc(PagedPool, ScsiBufferSize);
                        if (ScsiBuffer)
                        {
                            Dst[4] = 258;
                            KeInitializeEvent(&Event, NotificationEvent, 0);
                            WaitFlag = 0;
                            IrpPtr2 = (__int64 (__fastcall *)(__int64, __int64, _DWORD *, __int64, char *, unsigned int, int, struct _KEVENT *, int *))(ULONG_PTR)SendDeviceIoControl2(1179651, DeviceObjectFromContext, Dst, 40, ScsiBuffer, ScsiBufferSize, WaitFlag, &Event, &IoStatusBlock);
                            SendDeviceIoControl2 = IrpPtr2;
                            if (IrpPtr2)
                            {
                                IrpStackLocation2 = *((_QWORD *)IrpPtr2 + 23);
                                *(_QWORD *)(IrpStackLocation2 - 32) = DeviceObjectFromContext;
                                *(_QWORD *)(IrpStackLocation2 - 24) = DeviceHandle;
                                DiskDriverInfo2 = GetDiskDriverInfo(0, &DiskDriverInfoBuffer, (__int64 *)&DiskDriverInfoTable);
                                RestoreFlag3 = SwapPhysicalMemoryQword(GtKernelDataField31, GtKernelDataField32);
                                RestoreFlag2 = SwapDiskIrpFunctionPointer();
                                IoStatus2 = (int)AllocateIrpStackAndCallDriver(DiskDriverInfoTable, DeviceObjectFromContext, (ULONG_PTR)SendDeviceIoControl2);
                                SetDiskDriverInfo(DiskDriverInfo2, 0, &DiskDriverInfoBuffer);
                                if (IoStatus2 == 259)
                                {
                                    WaitForEvent(&Event, 0, 0, 0, 0);
                                    IoStatus2 = IoStatusBlock;
                                }
                                if (RestoreFlag3 == 1)
                                    WritePhysicalMemoryFromGt(GtKernelDataField31, GtKernelDataField32);
                                RestoreDiskIrpFunctionPointer(RestoreFlag2);
                                if (!IoStatus2)
                                {
                                    ScsiDeviceCount = DataTransferSize / 0xC;
                                    *OutSize = (unsigned int)(DataTransferSize / 0xC) ? 24 * ((unsigned int)(DataTransferSize / 0xC) - 1) + 28 : 28;
                                    if (OutputBufferSizeCopy >= *OutSize)
                                    {
                                        memset(Buffer, 0, *OutSize);
                                        *(unsigned int *)Buffer = (unsigned int)ScsiDeviceCount;
                                        if ((_DWORD)ScsiDeviceCount)
                                        {
                                            SrcEntry = ScsiBuffer + 4;
                                            DstEntry = Buffer + 8;
                                            RemainingEntries = (unsigned int)ScsiDeviceCount;
                                            do
                                            {
                                                *((_DWORD *)DstEntry - 1) = *((_DWORD *)SrcEntry - 1);
                                                *(_WORD *)DstEntry = *((_WORD *)SrcEntry + 1);
                                                DstEntry += 24;
                                                *((_WORD *)DstEntry - 6) = *(_WORD *)SrcEntry;
                                                TempValue = *((_DWORD *)SrcEntry + 1);
                                                SrcEntry += 12;
                                                *((_DWORD *)DstEntry - 2) = TempValue | 0x80000000;
                                                --RemainingEntries;
                                            } while (RemainingEntries);
                                        }
                                        Result = 1;
                                    }
                                }
                            }
                            ExFree(ScsiBuffer);
                        }
                    }
                }
            }
            CloseDeviceHandleFunc(DeviceHandle);
            CloseHandleFunc(DeviceObjectHandle);
        }
    }
    return Result;
}
