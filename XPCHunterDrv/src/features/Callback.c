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

char MiniFilterStreamHandleCleanup(PRKPROCESS PROCESS, __int64 CallbackContext, ULONG64 ContextFlag, __int64 BaseOffset, __int64 (*CallbackFunc)(void))
{
    ULONG64 ProtectedBase;
    __int64 SystemRootForThread;
    int CallbackResult;
    int IsSuccess;
    int CallbackResult2;

    MiniFilterOpLockPre(PROCESS, CallbackContext, ContextFlag, 0);
    if (CheckProtectedEntry((__int64)PROCESS))
    {
        ProtectedBase = GtRead(GtEprocessModuleListOffset | GtDriverObject);
        if (ProtectedBase
            || BaseOffset
            && (SystemRootForThread = GetSystemRootForThread(PROCESS)) != 0
            && (ProtectedBase = SystemRootForThread + BaseOffset,
                GtWrite(GtEprocessModuleListOffset | GtDriverObject, SystemRootForThread + BaseOffset),
                ProtectedBase))
        {
            MiniFilterOpLockPre(PROCESS, CallbackContext, ProtectedBase, 1);
        }
    }
    MiniFilterOpLockPost(PROCESS, 0, CallbackContext);
    MiniFilterOpLockPost(PROCESS, 1, CallbackContext);
    GtRead(GtEprocessField28);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
    {
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        {
            IsSuccess = CallbackResult2;
            return IsSuccess >= 0;
        }
        CallbackResult = InvokeCallbackWithZeroArg(
            (__int64)PROCESS,
            CallbackContext,
            0,
            (__int64(__fastcall *)(__int64, __int64, __int64, ULONG64))CallbackFunc);
    }
    else
    {
        CallbackResult = InvokeNullCallback(
            (__int64)PROCESS,
            CallbackContext,
            0,
            (__int64(*)(void))CallbackFunc);
    }
    IsSuccess = CallbackResult;
    return IsSuccess >= 0;
}

__int64 KernelNotifyRoutine(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 1);
}

__int64 KernelNotifyRoutineEx(void *NotificationBuffer, size_t BufferSize)
{
    return MiniFilterTeardownRoutine(NotificationBuffer, BufferSize, 0);
}

__int64 PowerCallbackRoutine(void **InputBuffer, int BufferSize)
{
    char Success;
    __int64 MapMemoryFunc;
    __int64 MapFunc;
    __int64 ZeroFunc;
    __int64 ReadNameFunc;
    __int64 UnmapFunc;
    __int64 FreeFunc;
    __int64 FreeFunc2;
    volatile void *TargetBuffer;
    unsigned int ReadSize;
    unsigned __int64 CurrentAddress;
    unsigned __int64 RemainingSize;
    char *OutputPtr;
    unsigned int PageRemainder;
    unsigned int BytesCopied;
    char PageSuccess;
    __int64 MappedMemory;
    __int64 MappedBuffer;
    __int64 MappedBuffer2;
    __int64 ObjectNameFromCallback;
    char CopySuccess;
    __int64 (__fastcall *ReadNameFuncTyped)(__int64, _QWORD, __int64);
    __int64 (__fastcall *MapMemoryFuncTyped)(unsigned __int64, __int64, _QWORD, _QWORD, _QWORD);
    void (__fastcall *UnmapFuncTyped)(__int64, __int64);
    void (__fastcall *MapFuncTyped)(__int64);
    void (__fastcall *FreeFuncTyped)(__int64);
    void (__fastcall *ZeroFuncTyped)(__int64, _QWORD, _QWORD);
    void (__fastcall *FreeFunc2Typed)(__int64);
    int SizeCopy;

    Success = 0;
    if (InputBuffer)
    {
        if (BufferSize == 24
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 3) < MmUserProbeAddress)
        {
            MapMemoryFunc = GtRead(GtAllocPhysPagesFunc);
            MapFunc = GtRead(GtMapPhysPagesFunc);
            MapFuncTyped = (void (__fastcall *)(__int64))MapFunc;
            ZeroFunc = GtRead(GtZeroPagesFunc);
            ZeroFuncTyped = (void (__fastcall *)(__int64, _QWORD, _QWORD))ZeroFunc;
            ReadNameFunc = GtRead(GtMapMemoryFunc);
            ReadNameFuncTyped = (__int64 (__fastcall *)(__int64, _QWORD, __int64))ReadNameFunc;
            UnmapFunc = GtRead(GtUnmapMemoryFunc);
            UnmapFuncTyped = (void (__fastcall *)(__int64, __int64))UnmapFunc;
            FreeFunc = GtRead(GtFreeMemoryFunc);
            FreeFuncTyped = (void (__fastcall *)(__int64))FreeFunc;
            FreeFunc2 = GtRead(GtFreePagesFunc);
            FreeFunc2Typed = (void (__fastcall *)(__int64))FreeFunc2;
            if (MapMemoryFunc && MapFunc && ZeroFunc && ReadNameFunc && UnmapFunc && FreeFunc && FreeFunc2)
            {
                ProbeForRead(InputBuffer, 0x18u, 4u);
                TargetBuffer = InputBuffer[2];
                if (TargetBuffer)
                {
                    ReadSize = *((_DWORD *)InputBuffer + 2);
                    if (ReadSize)
                    {
                        if (ReadSize < (unsigned __int64)MmSystemRangeStart
                            && *InputBuffer >= MmSystemRangeStart
                            && (char *)*InputBuffer + ReadSize >= MmSystemRangeStart
                            && (unsigned __int64)TargetBuffer < MmUserProbeAddress
                            && (unsigned __int64)TargetBuffer + ReadSize < MmUserProbeAddress)
                        {
                            ProbeForWrite(TargetBuffer, ReadSize, 1u);
                            CurrentAddress = (unsigned __int64)*InputBuffer;
                            RemainingSize = *((unsigned int *)InputBuffer + 2);
                            SizeCopy = *((_DWORD *)InputBuffer + 2);
                            OutputPtr = (char *)InputBuffer[2];
                            if (*InputBuffer >= MmSystemRangeStart
                                && RemainingSize < (unsigned __int64)MmSystemRangeStart
                                && CurrentAddress + (unsigned int)RemainingSize > (unsigned __int64)MmSystemRangeStart)
                            {
                                PageRemainder = 4096 - (CurrentAddress & 0xFFF);
                                BytesCopied = 0;
                                while (BytesCopied < (unsigned int)RemainingSize)
                                {
                                    if ((unsigned int)RemainingSize - BytesCopied < PageRemainder)
                                        PageRemainder = RemainingSize - BytesCopied;
                                    PageSuccess = 0;
                                    CopySuccess = 0;
                                    if (CheckMemoryValid((void *)CurrentAddress) == 1)
                                    {
                                        MappedMemory = MapMemoryFuncTyped(CurrentAddress & 0xFFFFFFFFFFFFF000uLL, 4096, 0, 0, 0);
                                        if (MappedMemory)
                                        {
                                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
                                            {
                                                ZeroFuncTyped(MappedMemory, 0, 0);
                                                ObjectNameFromCallback = ReadObjectNameFromCallback(
                                                    MappedMemory,
                                                    16,
                                                    ReadNameFuncTyped);
                                                if (ObjectNameFromCallback)
                                                {
                                                    memmove(
                                                        OutputPtr,
                                                        (const void *)(ObjectNameFromCallback + (CurrentAddress & 0xFFF)),
                                                        PageRemainder);
                                                    Success = 1;
                                                    CopySuccess = 1;
                                                }
                                                FreeFuncTyped(MappedMemory);
                                            }
                                            else
                                            {
                                                MapFuncTyped(MappedMemory);
                                                MappedBuffer = ReadNameFuncTyped(MappedMemory, 0, 1);
                                                MappedBuffer2 = MappedBuffer;
                                                if (MappedBuffer)
                                                {
                                                    memmove(
                                                        OutputPtr,
                                                        (const void *)(MappedBuffer + (CurrentAddress & 0xFFF)),
                                                        PageRemainder);
                                                    Success = 1;
                                                    CopySuccess = 1;
                                                    UnmapFuncTyped(MappedBuffer2, MappedMemory);
                                                }
                                            }
                                            FreeFunc2Typed(MappedMemory);
                                            PageSuccess = CopySuccess;
                                        }
                                    }
                                    if (!PageSuccess)
                                        memset(OutputPtr, 0, PageRemainder);
                                    if (BytesCopied)
                                        PageRemainder = 4096;
                                    BytesCopied += 4096;
                                    CurrentAddress += PageRemainder;
                                    OutputPtr += PageRemainder;
                                    LODWORD_LV(RemainingSize) = SizeCopy;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}

__int64 PowerCallbackUnregister(HANDLE *InputBuffer, int BufferSize)
{
    char Success;
    HANDLE ProcessHandle;
    unsigned int TargetSize;
    HANDLE TargetBufferVal;
    PVOID SourceBuffer;
    NTSTATUS AllocStatus;
    int LookupStatus;
    const void *SourcePtr;
    unsigned int BufferSizeCopy;
    void *TargetPtr;
    PEPROCESS Process;
    unsigned int SizeVal;
    HANDLE TargetHandle;
    HANDLE *InputBufferPtr;
    HANDLE SourceHandle;
    PRKPROCESS ProcessObject;
    struct _KAPC_STATE ApcState;

    Success = 0;
    Process = 0;
    if (InputBuffer)
    {
        if (BufferSize == 40
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 5) < MmUserProbeAddress)
        {
            ProbeForRead(InputBuffer, 0x28u, 4u);
            InputBufferPtr = InputBuffer;
            if (*InputBuffer)
            {
                if (InputBuffer[1])
                {
                    ProcessHandle = InputBuffer[4];
                    if (ProcessHandle)
                    {
                        TargetSize = *((_DWORD *)InputBuffer + 6);
                        if (TargetSize)
                        {
                            TargetBufferVal = InputBuffer[2];
                            if (TargetBufferVal)
                            {
                                if (TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)TargetBufferVal < MmUserProbeAddress
                                    && (unsigned __int64)TargetBufferVal + TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)ProcessHandle < MmUserProbeAddress
                                    && (unsigned __int64)ProcessHandle + TargetSize < MmUserProbeAddress)
                                {
                                    ProbeForWrite(ProcessHandle, TargetSize, 1u);
                                    SourceBuffer = ExAlloc(NonPagedPool, *((unsigned int *)InputBuffer + 6));
                                    if (SourceBuffer)
                                    {
                                        AllocStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
                                        LookupStatus = AllocStatus;
                                        if (!InputBuffer[1] && AllocStatus >= 0)
                                            InputBuffer[1] = Process;
                                        if (ValidateProcessObject((struct _KPROCESS *)InputBuffer[1], 0) == 1)
                                        {
                                            ProcessObject = (PRKPROCESS)InputBuffer[1];
                                            SourceHandle = InputBuffer[2];
                                            SourcePtr = SourceHandle;
                                            SizeVal = *((_DWORD *)InputBuffer + 6);
                                            BufferSizeCopy = SizeVal;
                                            TargetHandle = InputBuffer[4];
                                            TargetPtr = TargetHandle;
                                            KeStackAttachProcess(ProcessObject, &ApcState);
                                            memset(SourceBuffer, 0, BufferSizeCopy);
                                            memmove(SourceBuffer, SourcePtr, BufferSizeCopy);
                                            Success = 1;
                                            KeUnstackDetachProcess(&ApcState);
                                            memmove(TargetPtr, SourceBuffer, BufferSizeCopy);
                                        }
                                        if (LookupStatus >= 0)
                                            ObfDereferenceObject(Process);
                                        ExFree(SourceBuffer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}

__int64 ShutdownCallbackUnregister(PRKPROCESS *InputBuffer, int BufferSize)
{
    bool Success;
    PRKPROCESS TargetBuffer;
    unsigned int TargetSize;
    PRKPROCESS SourceBuffer;
    PVOID AllocBuffer;
    NTSTATUS LookupStatus;
    int Status;
    PRKPROCESS SourcePtr;
    unsigned int BufferSizeCopy;
    PEPROCESS Process;
    PVOID AllocBufferPtr;
    unsigned int SizeVal;
    PRKPROCESS SourceBufferPtr;
    PRKPROCESS TargetBufferPtr;
    PRKPROCESS ProcessObject;
    struct _KAPC_STATE ApcState;

    Success = 0;
    Process = 0;
    if (InputBuffer)
    {
        if (BufferSize == 40
            && (unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)(InputBuffer + 5) < MmUserProbeAddress)
        {
            AllocBufferPtr = 0;
            ProbeForRead(InputBuffer, 0x28u, 4u);
            if (*InputBuffer)
            {
                if (InputBuffer[1])
                {
                    TargetBuffer = InputBuffer[4];
                    if (TargetBuffer)
                    {
                        TargetSize = *((_DWORD *)InputBuffer + 6);
                        if (TargetSize)
                        {
                            SourceBuffer = InputBuffer[2];
                            if (SourceBuffer)
                            {
                                if (TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)SourceBuffer < MmUserProbeAddress
                                    && (unsigned __int64)SourceBuffer + TargetSize < MmUserProbeAddress
                                    && (unsigned __int64)TargetBuffer < MmUserProbeAddress
                                    && (unsigned __int64)TargetBuffer + TargetSize < MmUserProbeAddress)
                                {
                                    ProbeForRead(TargetBuffer, TargetSize, 1u);
                                    AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)InputBuffer + 6));
                                    AllocBufferPtr = AllocBuffer;
                                    if (AllocBuffer)
                                    {
                                        LookupStatus = PsLookupProcessByProcessId(*InputBuffer, &Process);
                                        Status = LookupStatus;
                                        if (!InputBuffer[1] && LookupStatus >= 0)
                                            InputBuffer[1] = Process;
                                        if (ValidateProcessObject(InputBuffer[1], 0) == 1)
                                        {
                                            ProcessObject = InputBuffer[1];
                                            SourceBufferPtr = InputBuffer[2];
                                            SourcePtr = SourceBufferPtr;
                                            BufferSizeCopy = *((_DWORD *)InputBuffer + 6);
                                            SizeVal = BufferSizeCopy;
                                            TargetBufferPtr = InputBuffer[4];
                                            memmove(AllocBuffer, TargetBufferPtr, BufferSizeCopy);
                                            KeStackAttachProcess(InputBuffer[1], &ApcState);
                                            ProbeForRead(SourcePtr, BufferSizeCopy, 1u);
                                            Success = WritePhysicalMemoryBuffer(
                                                (unsigned __int64)SourcePtr,
                                                AllocBuffer,
                                                BufferSizeCopy,
                                                1,
                                                0) == 1;
                                            KeUnstackDetachProcess(&ApcState);
                                        }
                                        if (Status >= 0)
                                            ObfDereferenceObject(Process);
                                        ExFree(AllocBuffer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return Success;
}
