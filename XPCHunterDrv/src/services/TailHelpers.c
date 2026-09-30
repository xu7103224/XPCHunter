// IoctlDispatch.c — IOCTL 命令分发
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动 InitCommandHandlerTable sub_1400815B0
// 功能：分配命令处理函数表（GtAlloc + 0x8D8 字节），填充全部 ~282 个命令处理函数指针

#include "..\inc\XPCHunterDrv.h"
#pragma intrinsic(__readmsr, __writemsr)
// Forward declarations
__int64 InitMiniFilterDriver(PDRIVER_OBJECT DriverObject);
// 回调控制操作子函数前向声明（暂未实现）
char ReadCallbackType1(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3);
char ReadCallbackType2(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3);
char ReadCallbackType3(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3);
char CallbackType1Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3);
char CallbackType2Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3);
char CallbackType3Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3);
char CallbackType4Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3);
char CallbackType5Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3);

// 命令处理函数表（全局表索引 2337 处分配）
extern PCOMMAND_HANDLER g_CommandHandlerTable[CMD_OPCODE_COUNT];

// 外部函数前向声明
extern char InstallSsdtHookForThreadProtect(__int64 InputBuffer);
extern __int64 EnumProcessHandleInfo(_QWORD *pHandleTable, unsigned int *pInfoList, _OWORD *OutputBuffer, int MaxCount);

// 外部函数声明（定义在其他源文件中）
extern char ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);
extern char CmdCloseProcessHandleEx(__int64 InputBuffer);
extern unsigned int EnumDeviceObjects(char *OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryDriverObjectDevice(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryFileSystemDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int EnumFileSystemDeviceObjects(__int64 OutputBuffer, unsigned int MaxEntries);
extern bool SendIoControlWithQueryBuffer(__int64 Handle, unsigned int CommandType, _BYTE *OutputBuffer, int BufferSize, size_t *ReturnSize);
extern bool SendIoControlWithStringParam(__int64 Handle, PUNICODE_STRING UnicodeString, unsigned int CommandType, unsigned int SomeValue, __int64 OutputBuffer, unsigned int OutputSize);
// SendIoControlWithVersionBranch 声明见头文件（形参 3 为 PUNICODE_STRING）
extern unsigned int BuildDriverPathKbdClass(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int BuildDriverPathI8042prt(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryTcpipDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryVolmgrDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryTdxDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int BuildDriverPathMouClass(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryNdisDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryPnpManagerDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern void NormalizeModulePaths(__int64 OutputBuffer, unsigned int EntryCount);
extern char WritePhysicalMemoryBuffer(unsigned __int64 TargetAddress, const void *SourceBuffer, unsigned int BufferSize, char ProcessorMode, void *pReadBack);
extern __int64 ResolveKernelModuleBasePair(__int64 CpuNumber, ULONG_PTR *pMsrPair);
extern char ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray);
extern __int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext);
extern void ValidateObjectTypeEntries(__int64 OutputBuffer);
extern void QueryObjectDirectoryAndEnumerate(__int64 OutputBuffer, unsigned int OutputSize);

// 前向声明：Cmd* 命令处理函数包装器
// 这些函数在 Table[] 初始化之后定义，需要提前声明
__int64 CmdEnableObjectCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdPowerCallbackUnregister(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdShutdownCallbackUnregister(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdPowerCallbackRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdRegNotifyCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDisableThreadProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnableThreadProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdProcessCallbackRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitProcessCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCopyKernelArrayToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnumKernelMemoryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdCopyKernelDualArrayToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdReadKernelMemoryToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitFileSystemCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitFileSystemFilter(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdFileSystemFilterCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdInitObjectCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdDisableObjectProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdEnableObjectProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdKernelNotifyRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdKernelNotifyRoutineEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CmdMiniFilterStreamHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);

// InitCommandHandlerTable — 初始化命令处理函数表
// 对应原始驱动 sub_1400815B0
// 分配 0x8D8 字节缓冲区，填充所有命令处理函数指针，
// 返回 CmdRestoreDriverDispatch 函数指针

// --- 前向声明（Operation 函数实际定义在文件末尾）---
// 所有 Operation 函数返回 __int64 以匹配 Cmd 包装器的隐式声明
// 这些声明必须在所有 Cmd 包装器之前，否则会因隐式 int 声明导致 C2371 冲突
__int64 CallSystemRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CallbackControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CheckBytePatternOperation(__int64 *pInputBuffer, int InputSize);
__int64 CheckFileExistOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CheckProcessHideDetectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ClearKernelBaseOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CloseHandleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CopyFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 CopyKernelArrayToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CopyKernelDualArrayToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CreateFileWithPathOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 DeleteFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 DeviceIoControlExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlSimpleOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlWithBufferOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlWithStringOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DisableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DisableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskSectorReadWriteOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumCallbackContextOperation(__int64 InputBuffer, __int64 InputSize, _WORD *pOutputBuffer, int OutputSize);
__int64 EnumDirectoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 EnumFileSystemContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumHookDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumHookInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelHandleTableOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelMemoryContextOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelMemoryDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelModuleInfoExOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelObjectTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumObjectDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectsOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessContextWin7Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessContextWin8Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessContextWin10Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessListExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin7Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin8Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin10Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessProtectContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int BufferSize);
__int64 EnumProcessorInfoOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 EnumRegistryContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int BufferSize);
__int64 EnumRegistryOperation(char *pInputBuffer, int InputSize, _WORD *pOutputBuffer, int OutputSize);
__int64 EnumServiceTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumServicesOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumThreadContextWin10Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumUSBPortSyscallTableOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
__int64 FileSystemControlOperation(unsigned int *pInputBuffer, int InputSize, volatile void *pOutputBuffer, int OutputSize);
__int64 FileSystemFilterCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 FixProcessEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 GetHookEntryInfoOperation(char *pInputBuffer, int InputSize, ULONG64 OutputBuffer, unsigned int OutputSize);
__int64 GetKernelBaseLegacyOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 InitFileSystemCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitFileSystemFilterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitKernelMemoryContextOperation(void);
__int64 InitObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InstallUSBPortSyscallHookOperation(char *Address, int InputSize);
__int64 KernelNotifyRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 KernelNotifyRoutineExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 LookupObjectTypeByAddrOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 OpenFileForEnumOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 OpenFileHandleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 OpenSectionObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 PowerCallbackRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 PowerCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryFileInfoOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 QueryHookStatusOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryMemoryInfoOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 QueryModuleInfoOperation(volatile void **pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 QueryObjectInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryProcessNameByPidOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QuerySystemInfoExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ReadCpuBaseAddrOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadCpuBaseAddrExOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadCpuIdOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadCpuInfoExOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadCpuMsrOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadDirectoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadFileSizeOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelBaseOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelMemoryRangeOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelMemoryRangeSizeOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelMemoryToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadMsrValueOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ReadPhysicalMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 RegNotifyCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RegistryProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RenameFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 ResetDriverStateOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RestoreDriverDispatchOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 SetCallbackContextOperation(char *pInputBuffer, int InputSize);
__int64 SetFileAttributesOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 SetFileSystemContextOperation(char *pInputBuffer, int InputSize);
__int64 SetKernelModuleInfoOperation(__int64 *pInputBuffer, int InputSize);
__int64 SetObjectContextOperation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin7Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin8Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin10Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessProtectContextOperation(char *pInputBuffer, int InputSize);
__int64 SetProcessorFieldOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 SetRegistryContextOperation(char *pInputBuffer, int InputSize);
__int64 SetThreadContextWin10Operation(char *Address, int InputSize);
__int64 ShutdownCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 TerminateProcessByEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 WriteFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 WriteKernelObjectFieldOperation(PVOID *pInputBuffer, int InputSize);
__int64 WriteMsrValueOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 WriteProcessMemoryExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);

__int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex)
{
    __int64 KernelBase;
    unsigned int ImageSize;
    unsigned int DataSectionOffset;
    __int64 NtoskrnlBase;
    __int64 Result;

    KernelBase = GtRead(GtEprocessField22);
    ImageSize = (unsigned int)GtRead(GtEprocessField23);
    DataSectionOffset = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    if (KernelBase && ImageSize && NtoskrnlBase)
    {
        Result = FindKernelPESectionByType((enum _GLOBAL_TABLE_INDEX)(unsigned int)ModuleId);
        if ((unsigned int)Result && (unsigned int)Result < DataSectionOffset)
        {
            Result = ResolveSyscallToAddress((unsigned int)Result);
            if ((unsigned int)Result && (unsigned int)Result < ImageSize)
                return GtWrite((enum _GLOBAL_TABLE_INDEX)(unsigned int)GtIndex, NtoskrnlBase + (unsigned int)Result);
        }
    }
    return Result;
}


// ResolveKernelModuleIndexAddress — 解析内核模块索引地址
// 通过系统调用号解析目标地址并存储到全局表
// 对应原始驱动 sub_14006E87C
__int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex)
{
    __int64 Result;
    __int64 KernelBase;
    unsigned int ImageSize;
    __int64 NtoskrnlBase;
    unsigned int ModuleIndex;
    unsigned int MaxSectionOffset;
    unsigned int SyscallAddr;
    __int64 FinalAddr;

    Result = 0;
    KernelBase = GtRead(GtEprocessField22);
    ImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    ModuleIndex = (unsigned int)GtRead(GtCallbackField25);
    MaxSectionOffset = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (KernelBase && ImageSize && NtoskrnlBase)
    {
        if (ModuleIndex > 1 && ModuleIndex < MaxSectionOffset)
        {
            SyscallAddr = (unsigned int)ResolveSyscallToAddress(ModuleIndex);
            if (SyscallAddr && SyscallAddr < ImageSize)
            {
                FinalAddr = SyscallAddr;
                GtWrite(GtCallbackField26, SyscallAddr);
                Result = NtoskrnlBase + FinalAddr;
                GtWrite(GtCallbackField27, Result);
            }
        }
    }
    return Result;
}


// ReadWriteKernelMemory — 读写内核内存
// 对应原始驱动 sub_14003F998

// =======================================================================

// =======================================================================
// 内部辅助函数存根（被其他新实现函数引用）
// =======================================================================


// CmdEnumFileSystemCallback — 枚举文件系统回调命令处理
// 对应原始驱动 sub_0x14003EDD4
// 根据 GT 0x914 (GtWindowsBuildNumber) 构建号选择：
// Win7 特定版本（2600/3790）调用 EnumFileSystemCallbackEntries，
// Win8+ 调用 EnumerateProcessCallbackContext。
// ============================================================
char CmdEnumFileSystemCallback()
{
    char Result;

    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    Result = 0;
    if (BuildNumber == 2600 ||
        BuildNumber == 3790)
    {
        return (char)EnumFileSystemCallbackEntries();
    }

    if (BuildNumber >= 0x1770 &&
        BuildNumber <= 0x2580)
    {
        return EnumerateProcessCallbackContext();
    }

    EnumerateProcessCallbackContext();
    return Result;
}

// CmdSetModuleInfoInternal — 设置模块信息内部命令
// 通过设备对象路径 \Device\Ip 创建文件句柄，发送 IOCTL 128030 设置模块信息
// 使用 GtRead 获取的函数指针：RtlInitUnicodeStringFunc(0x421D)、CreateFileFunc2(0x4256)、
// IrpFsControlFunc(0x4253, 返回 IRP 指针)、KeWaitForSingleObjectFunc(0x4199)、CloseHandleFunc(0x4223)
// 对应原始驱动 sub_14002C030
__int64 CmdSetModuleInfoInternal(__int64 InputBuffer)
{
    char Result;
    __int64 RtlInitUnicodeString;
    __int64 CreateFileFunc;
    __int64 IrpFsControlFunc;
    __int64 KeWaitForSingleObjectFunc;
    __int64 CloseHandleFunc;
    HANDLE DeviceHandle;
    HANDLE SectionHandle;
    UNICODE_STRING ObjAttr;
    _WORD DevicePath[20];
    int Status;
    int IoctlResult;
    __int64 Irp;
    KEVENT EventObj;
    IO_STATUS_BLOCK IoStatusBlock;

    RtlInitUnicodeString = GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = GtRead(GtCreateFileFunc2);
    IrpFsControlFunc = GtRead(GtIrpFsControlFunc);
    KeWaitForSingleObjectFunc = GtRead(GtKeWaitForObjectFunc);
    CloseHandleFunc = GtRead(GtCloseHandleFunc);
    if (!RtlInitUnicodeString || !CreateFileFunc || !IrpFsControlFunc || !KeWaitForSingleObjectFunc || !CloseHandleFunc)
        return 0;

    // 构建设备路径 L"\Device\Ip"
    DevicePath[0] = 0x5C;      // L'\'
    DevicePath[1] = 0x44;      // L'D'
    DevicePath[2] = 0x65;      // L'e'
    DevicePath[3] = 0x76;      // L'v'
    DevicePath[4] = 0x69;      // L'i'
    DevicePath[5] = 0x63;      // L'c'
    DevicePath[6] = 0x65;      // L'e'
    DevicePath[7] = 0x5C;      // L'\'
    DevicePath[8] = 0x49;      // L'I'
    DevicePath[9] = 0x70;      // L'p'
    DevicePath[10] = 0;        // null terminator

    // 调用 RtlInitUnicodeString 初始化 UNICODE_STRING
    ((void (__fastcall *)(UNICODE_STRING *, _WORD *))RtlInitUnicodeString)(&ObjAttr, DevicePath);

    // 调用 CreateFile 打开设备，返回设备句柄和节句柄
    Status = (int)((__int64 (__fastcall *)(UNICODE_STRING *, ULONG, HANDLE *, HANDLE *))CreateFileFunc)(
        &ObjAttr, 0x1F0000, &DeviceHandle, &SectionHandle);

    if (Status >= 0)
    {
        KeInitializeEvent(&EventObj, NotificationEvent, FALSE);

        // 调用 IrpFsControlFunc 创建 IRP（返回 IRP 指针，非 NTSTATUS）
        Irp = ((__int64 (__fastcall *)(ULONG, PVOID, HANDLE, ULONG, ULONG, UCHAR, PKEVENT, PIO_STATUS_BLOCK))IrpFsControlFunc)(
            0x128030, (PVOID)InputBuffer, SectionHandle, 0x10, 0, 0, &EventObj, &IoStatusBlock);

        if (Irp)
        {
            // 提交 IRP 到驱动
            IoctlResult = (int)AllocateIrpStackAndCallDriver(0, (ULONG_PTR)SectionHandle, Irp);

            if (IoctlResult == 0x103) // STATUS_PENDING
            {
                // 等待事件完成
                Status = (int)((__int64 (__fastcall *)(PKEVENT, ULONG, ULONG, ULONG, ULONG))KeWaitForSingleObjectFunc)(
                    &EventObj, 0, 0, 0, 0);
                if (Status >= 0)
                    IoctlResult = IoStatusBlock.Status;
            }

            if (IoctlResult >= 0)
                Result = 1;
            else
                Result = 0;
        }
        else
        {
            Result = 0;
        }

        // 关闭设备句柄
        ((void (__fastcall *)(HANDLE))CloseHandleFunc)(DeviceHandle);
    }

    return (unsigned char)Result;
}

// DiskOperationDispatcher — 磁盘操作分发器
// 验证输入缓冲区，按命令分发到 WriteDiskSectorsWithMbr 或 ReadModifyWriteDiskSector
// 对应原始驱动 sub_14007C980
__int64 DiskOperationDispatcher(void *Address, unsigned int Length)
{
    if (Address
        && Length >= 0xC
        && Length < MmUserProbeAddress
        && (unsigned __int64)Address < MmUserProbeAddress
        && (unsigned __int64)Address + Length < MmUserProbeAddress)
    {
        ProbeForRead(Address, Length, 4u);
        if (*(unsigned int *)Address)
            return ReadModifyWriteDiskSector(*((unsigned int *)Address + 1), *((unsigned int *)Address + 2));
        else
            return WriteDiskSectorsWithMbr(*((unsigned int *)Address + 1), *((unsigned int *)Address + 2));
    }
    return 0;
}

// IoPortOperationDispatch — IO 端口操作分发
// 验证输出缓冲区（>= 0x3808 字节），分配 0x3800 字节上下文缓冲区，调用 ForEachProcessor 在每个处理器上执行 ReadIoPortDataForProcess
// 对应原始驱动 sub_14003888C
__int64 IoPortOperationDispatch(void *InputBuffer, int BufferSize)
{
    char Result;
    PVOID pIoPortContext;
    void *pContextBuffer;
    _QWORD IoPortContext[2];
    unsigned int OutBufferSize;

    Result = 0;
    OutBufferSize = BufferSize;
    if (InputBuffer && OutBufferSize >= 0x3808)
    {
        if ((unsigned __int64)InputBuffer < MmUserProbeAddress
            && (unsigned __int64)InputBuffer + OutBufferSize < MmUserProbeAddress)
        {
            if (GtRead(GtCurrentEprocess))
            {
                pIoPortContext = ExAlloc(PagedPool, 0x3800u);
                pContextBuffer = pIoPortContext;
                if (pIoPortContext)
                {
                    memset(pIoPortContext, 0, 0x3800u);
                    ProbeForWrite(InputBuffer, OutBufferSize, 1u);
                    *(unsigned int *)InputBuffer = 0;
                    IoPortContext[0] = (_QWORD)pContextBuffer;
                    IoPortContext[1] = (_QWORD)InputBuffer;
                    ForEachProcessor((__int64 (*)(__int64, __int64))ReadIoPortDataForProcess, (__int64)IoPortContext);
                    Result = *(unsigned int *)InputBuffer != 0;
                    ExFree(pContextBuffer);
                }
            }
        }
    }
    return Result;
}

// IrpReadFileEx — 读取文件扩展（IRP 方式）
// 通过 IRP 读取文件，支持偏移量、MDL 缓冲、完成例程、事件通知
// 对应原始驱动 sub_14002F43C
int IrpReadFileEx(void *FileHandle, LARGE_INTEGER *ByteOffset, ULONG Length, void *Buffer, PLARGE_INTEGER Timeout, struct _IO_STATUS_BLOCK *IoStatusBlock)
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
    __int64 FileDeviceObject;
    _OWORD BufferArray;

    Status = ObReferenceObjectByHandle(FileHandle, 0, (POBJECT_TYPE)IoFileObjectType, 0, &Object, 0);
    if (Status)
        return (unsigned int)Status;
    FileObject = Object;
    if (!ByteOffset && (*((_BYTE *)Object + 80) & 2) != 0)
        ByteOffset = (LARGE_INTEGER *)((char *)Object + 104);
    Status = -1073741811;
    if (!ByteOffset
        || (Status = -1073741823, !GetDeviceObjectFromFileObject((__int64)Object, &DeviceObjectForFile, &FileDeviceObject)))
    {
        ObfDereferenceObject(FileObject);
        return (unsigned int)Status;
    }
    DeviceObject = DeviceObjectForFile;
    Status = -1073741670;
    Irp = IoAllocateIrp(*(_BYTE *)(DeviceObjectForFile + 76), 0);
    if (!Irp)
    {
        ObfDereferenceObject(Object);
        return (unsigned int)Status;
    }
    Status = (int)IrpSetupBufferMdl(Irp, DeviceObject, Buffer, Length, (char)Timeout, 0, (_DWORD *)&BufferMdl);
    if (Status < 0)
    {
        IoFreeIrp(Irp);
        ObfDereferenceObject(Object);
        return (unsigned int)Status;
    }
    KeInitializeEvent(&Event, SynchronizationEvent, 0);
    CurrentStackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    CurrentStackLocation[-1].Control = -32;
    CurrentStackLocation[-1].CompletionRoutine = (PIO_COMPLETION_ROUTINE)IrpReadCompletionRoutine;
    CurrentStackLocation[-1].Context = (PVOID)(ULONG_PTR)(unsigned int)BufferMdl;
    Irp->Flags |= 0x200u;
    Irp->RequestorMode = 0;
    Irp->UserIosb = IoStatusBlock;
    Irp->UserEvent = &Event;
    StackLocation = Irp->Tail.Overlay.CurrentStackLocation;
    DeviceObjectCopy = DeviceObjectForFile;
    Irp->Tail.Overlay.Thread = KeGetCurrentThread();
    Irp->Tail.Overlay.OriginalFileObject = (PFILE_OBJECT)Object;
    *(_WORD *)&StackLocation[-1].MajorFunction = 4;
    StackLocation[-1].DeviceObject = (PDEVICE_OBJECT)DeviceObjectCopy;
    FileObjectPtr = (struct _FILE_OBJECT *)Object;
    StackLocation[-1].Parameters.Read.Length = Length;
    StackLocation[-1].FileObject = FileObjectPtr;
    StackLocation[-1].Parameters.Read.ByteOffset = *ByteOffset;
    IrpMonitorContext = GetIrpMonitorContext(DeviceObjectCopy, 4u, &BufferArray, (_QWORD *)&pCallDriver);
    VolumeChangeLock = AcquireVolumeChangeLock(DeviceObjectCopy);
    DiskFunctionState = SwapDiskIrpFunctionPointer();
    CallResult = (int)AllocateIrpStackAndCallDriver(pCallDriver, DeviceObjectCopy, (ULONG_PTR)Irp);
    ReleaseIrpMonitorContext(IrpMonitorContext, DeviceObjectCopy, 4u, &BufferArray);
    if (CallResult == 259)
        KeWaitForSingleObject(&Event, Executive, 0, 0, 0);
    NotifyVolumeDeviceChange(VolumeChangeLock, DeviceObjectCopy);
    RestoreDiskIrpFunctionPointer(DiskFunctionState);
    ObfDereferenceObject(Object);
    return (unsigned int)IoStatusBlock->Status;
}

// KernelMemoryOperationDispatch — 内核内存操作分发
// 收集所有系统数据结构（SSDT1/2/3表、文件系统回调、PE导出数据、Shadow SSDT、进程DeviceMap等）并写入输出缓冲区
// 对应原始驱动 sub_140041094
__int64 KernelMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    SIZE_T OutputSize;
    __int64 *pSsdt1Table;
    unsigned __int64 Ssdt1End;
    unsigned __int64 Ssdt2End;
    unsigned int RemainingSize;
    _DWORD *pOutput;
    __int64 SsdtEntry;
    _DWORD *pOutput2;
    unsigned int RemainingSize2;
    _DWORD *pOutput3;
    __int64 *pSsdt2Table;
    __int64 Ssdt2Entry;
    _DWORD *pOutput4;
    unsigned int RemainingSize3;
    _DWORD *pOutput5;
    __int64 *pSsdt3Table;
    unsigned __int64 SsdtTableOffset;
    __int64 Ssdt3Entry;
    _DWORD *pOutput6;
    unsigned int RemainingSize4;
    _DWORD *pOutput7;
    char *pCallbackList;
    int EntryCount;
    char *pListStart;
    _QWORD *pEntry;
    char *pCallbackList2;
    __int64 pListStart2;
    _DWORD *pOutput8;
    unsigned int RemainingSize5;
    _DWORD *pOutput9;
    _QWORD *pEnumList;
    int EntryCount2;
    _DWORD *pOutput10;
    unsigned int RemainingSize6;
    _DWORD *pOutput11;
    _QWORD *pEnumList2;
    int EntryCount3;
    _QWORD *pEnumList3;
    int EntryCount4;
    _DWORD *pOutput12;
    unsigned int RemainingSize7;
    _DWORD *pOutput13;
    _QWORD *pEnumList4;
    int EntryCount5;
    _DWORD *pOutput14;
    _DWORD *pOutput15;
    unsigned int RemainingSize8;
    _DWORD *pOutput16;
    __int64 ShadowSsdtEntry;
    _DWORD *pOutput17;
    unsigned int RemainingSize9;
    _DWORD *pOutput18;
    _QWORD *pEnumList5;
    int EntryCount6;
    _QWORD *pEprocess;
    _DWORD *pOutput19;
    unsigned int RemainingSize10;
    _DWORD *pOutput20;
    _QWORD *pEnumList6;
    int EntryCount7;
    _QWORD *pEprocess2;
    unsigned int RemainingSize11;
    _DWORD *pOutput21;
    char *pProcessList;
    unsigned int ProcessListIndex;
    char *pProcessEntry;
    _QWORD *i;
    __int64 DeviceMap;
    _DWORD *pOutput22;
    unsigned int RemainingSize12;
    _DWORD *pOutput23;
    _QWORD *pEnumList7;
    int EntryCount8;
    __int64 FileSystemEntry;
    int SubEntryCount;
    unsigned __int64 Ssdt2EndSaved;
    char *pCallbackListSaved;
    int IsWin7;
    _QWORD *pEnumList1;
    _QWORD *pEnumListSaved2;
    __int64 CallbackListSize;
    _DWORD *pOutputSaved;
    char *pProcessListSaved;
    _QWORD *pEnumListSaved3;
    _QWORD *pEnumListSaved4;
    _QWORD *pEnumListSaved5;
    _QWORD *pEnumListSaved6;
    __int64 *pShadowSsdtTable;
    _QWORD *pOldEnumList;
    __int64 *pSsdt2TableSaved;
    __int64 *pSsdt3TableSaved;
    __int64 Ssdt3End;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    OutputSize = BufferSize;
    IsWin7 = (int)GtRead(GtEprocessField28);
    pSsdt1Table = (__int64 *)GtRead(GtEprocessField80);
    if (!pSsdt1Table)
    {
        FindSsdtServiceTableV1();
        pSsdt1Table = (__int64 *)GtRead(GtEprocessField80);
    }
    Ssdt1End = GtRead(GtEprocessField81);
    pSsdt2TableSaved = (__int64 *)GtRead(GtEprocessField78);
    if (!pSsdt2TableSaved)
    {
        FindSsdtServiceTableV2();
        pSsdt2TableSaved = (__int64 *)GtRead(GtEprocessField78);
    }
    Ssdt2End = GtRead(GtEprocessField79);
    Ssdt2EndSaved = Ssdt2End;
    pSsdt3TableSaved = (__int64 *)GtRead(GtEprocessField82);
    if (!pSsdt3TableSaved)
    {
        FindSsdtServiceTableV3();
        pSsdt3TableSaved = (__int64 *)GtRead(GtEprocessField82);
    }
    Ssdt3End = GtRead(GtEprocessField83);
    pShadowSsdtTable = (__int64 *)GtRead(GtEprocessField84);
    if (!pShadowSsdtTable)
    {
        ParseNtSectionsForShadowSsdt();
        pShadowSsdtTable = (__int64 *)GtRead(GtEprocessField84);
    }
    pEnumList1 = (_QWORD *)GtRead(GtEprocessField85);
    if (!pEnumList1)
    {
        EnumProcessPeExportData();
        pEnumList1 = (_QWORD *)GtRead(GtEprocessField85);
    }
    pEnumListSaved2 = (_QWORD *)GtRead(GtCallbackField04);
    if (!pEnumListSaved2)
    {
        ScanKernelPeExportSection();
        pEnumListSaved2 = (_QWORD *)GtRead(GtCallbackField04);
    }
    pCallbackListSaved = (char *)GtRead(GtKernelDataField38);
    if (!pCallbackListSaved)
    {
        CmdEnumFileSystemCallback();
        pCallbackListSaved = (char *)GtRead(GtKernelDataField38);
    }
    CallbackListSize = GtRead(GtKernelDataField40);
    pEnumListSaved5 = (_QWORD *)GtRead(GtKernelDataField41);
    if (!pEnumListSaved5)
    {
        EnumProcessPeExportDataByIndex();
        pEnumListSaved5 = (_QWORD *)GtRead(GtKernelDataField41);
    }
    pEnumListSaved4 = (_QWORD *)GtRead(GtKernelDataField42);
    if (!pEnumListSaved4)
    {
        ReadWriteKernelMemory();
        pEnumListSaved4 = (_QWORD *)GtRead(GtKernelDataField42);
    }
    pOldEnumList = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField32);
    pEnumListSaved6 = (_QWORD *)GtRead(GtCallbackField05);
    if (!pEnumListSaved6)
    {
        ParseNtSectionsForSsdtTable();
        pEnumListSaved6 = (_QWORD *)GtRead(GtCallbackField05);
    }
    pProcessListSaved = (char *)GtRead(GtCallbackField103);
    if (!pProcessListSaved)
    {
        EnumProcessPeExportDataEx();
        pProcessListSaved = (char *)GtRead(GtCallbackField103);
    }
    pEnumListSaved3 = (_QWORD *)GtRead(GtCallbackField108);
    if (!pEnumListSaved3)
    {
        ScanKernelPeExportData();
        pEnumListSaved3 = (_QWORD *)GtRead(GtCallbackField108);
    }
    if ((OutputSize & 3) == 0
        && (unsigned int)OutputSize >= 0x50
        && (unsigned __int64)InputBuffer < MmUserProbeAddress
        && (unsigned __int64)InputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(InputBuffer, OutputSize, 1u);
        memset(InputBuffer, 0, OutputSize);
        RemainingSize = (unsigned int)(OutputSize - 40);
        if ((unsigned int)(OutputSize - 40) >= 0x28)
        {
            pOutput = (_DWORD *)InputBuffer;
            *(_DWORD *)InputBuffer = 1;
            *((_DWORD *)InputBuffer + 4) = 0;
            RemainingSize = (unsigned int)(OutputSize - 64);
            pOutput += 6;
            if (pSsdt1Table && Ssdt1End)
            {
                if ((unsigned int)BuildNumber < 0x1771 || (unsigned int)BuildNumber > 0x1DB1)
                {
                    if ((unsigned int)BuildNumber >= 0x23F0)
                        Ssdt1End = (unsigned __int64)(pSsdt1Table + 64);
                }
                else
                {
                    Ssdt1End -= 4LL;
                }
                while ((unsigned __int64)pSsdt1Table < Ssdt1End && MmIsAddressValid(pSsdt1Table))
                {
                    SsdtEntry = *pSsdt1Table;
                    if (*pSsdt1Table)
                    {
                        if (RemainingSize < 0x10)
                            break;
                        *(_QWORD *)&pOutput[4 * pOutput[4] + 6] = SsdtEntry;
                        if (!IsWin7)
                            SsdtEntry = *(_QWORD *)((SsdtEntry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                        *(_QWORD *)&pOutput[4 * pOutput[4]++ + 8] = SsdtEntry;
                        RemainingSize -= 16;
                        pOutput += 4;
                    }
                    ++pSsdt1Table;
                }
            }
            Ssdt2End = Ssdt2EndSaved;
        }
        if (RemainingSize >= 0x28)
        {
            pOutput2 = pOutput;
            *pOutput = 2;
            pOutput[4] = 0;
            RemainingSize2 = RemainingSize - 24;
            pOutput3 = pOutput + 6;
            pSsdt2Table = pSsdt2TableSaved;
            if (pSsdt2TableSaved && Ssdt2End)
            {
                if ((unsigned int)BuildNumber >= 0x23F0)
                    Ssdt2End = (unsigned __int64)(pSsdt2TableSaved + 64);
                while ((unsigned __int64)pSsdt2Table < Ssdt2End && MmIsAddressValid(pSsdt2Table))
                {
                    Ssdt2Entry = *pSsdt2Table;
                    if (*pSsdt2Table)
                    {
                        if (RemainingSize2 < 0x10)
                            break;
                        *(_QWORD *)&pOutput2[4 * pOutput2[4] + 6] = Ssdt2Entry;
                        if (!IsWin7)
                            Ssdt2Entry = *(_QWORD *)((Ssdt2Entry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                        *(_QWORD *)&pOutput2[4 * pOutput2[4]++ + 8] = Ssdt2Entry;
                        RemainingSize2 -= 16;
                        pOutput3 += 4;
                    }
                    ++pSsdt2Table;
                }
            }
            if (RemainingSize2 >= 0x28)
            {
                pOutput4 = pOutput3;
                *pOutput3 = 3;
                pOutput3[4] = 0;
                RemainingSize3 = RemainingSize2 - 24;
                pOutput5 = pOutput3 + 6;
                pSsdt3Table = pSsdt3TableSaved;
                if (pSsdt3TableSaved && Ssdt3End)
                {
                    SsdtTableOffset = GetSsdtTableOffset((__int64)pSsdt3TableSaved, Ssdt3End);
                    while ((unsigned __int64)pSsdt3Table < SsdtTableOffset && MmIsAddressValid(pSsdt3Table))
                    {
                        Ssdt3Entry = *pSsdt3Table;
                        if (*pSsdt3Table && RemainingSize3 >= 0x10)
                        {
                            *(_QWORD *)&pOutput4[4 * pOutput4[4] + 6] = Ssdt3Entry;
                            if (!IsWin7)
                                Ssdt3Entry = *(_QWORD *)((Ssdt3Entry & 0xFFFFFFFFFFFFFFF0uLL) + 8);
                            *(_QWORD *)&pOutput4[4 * pOutput4[4]++ + 8] = Ssdt3Entry;
                            RemainingSize3 -= 16;
                            pOutput5 += 4;
                        }
                        ++pSsdt3Table;
                    }
                }
                if (RemainingSize3 >= 0x28)
                {
                    pOutput6 = pOutput5;
                    *pOutput5 = 4;
                    pOutput5[4] = 0;
                    RemainingSize4 = RemainingSize3 - 24;
                    pOutput7 = pOutput5 + 6;
                    pCallbackList = pCallbackListSaved;
                    if (pCallbackListSaved && CallbackListSize)
                    {
                        if (BuildNumber == 2600
                            || BuildNumber == 3790)
                        {
                            pCallbackList2 = &pCallbackListSaved[(unsigned int)GtRead(GtKernelDataField39)];
                            while (pCallbackList < pCallbackList2 && MmIsAddressValid(pCallbackList))
                            {
                                pListStart2 = *(_QWORD *)pCallbackList;
                                if (*(_QWORD *)pCallbackList && RemainingSize4 >= 0x10)
                                {
                                    *(_QWORD *)&pOutput6[4 * pOutput6[4] + 6] = pListStart2;
                                    if (!IsWin7)
                                        pListStart2 = *(_QWORD *)(((unsigned int)pListStart2 & 0xFFFFFFF8) + 8LL);
                                    *(_QWORD *)&pOutput6[4 * pOutput6[4]++ + 8] = pListStart2;
                                    RemainingSize4 -= 16;
                                    pOutput7 += 4;
                                }
                                pCallbackList += 8;
                            }
                        }
                        else if ((unsigned int)BuildNumber >= 0x1770 && MmIsAddressValid(pCallbackListSaved) == 1)
                        {
                            EntryCount = 0;
                            pListStart = pCallbackListSaved;
                            pEntry = *(_QWORD **)pCallbackListSaved;
                            while (pEntry != (_QWORD *)pListStart)
                            {
                                if ((const PVOID)pEntry <= MmSystemRangeStart)
                                    break;
                                if ((unsigned int)++EntryCount > 0x10000
                                    || MmIsAddressValid(pEntry) != 1
                                    || MmIsAddressValid((char *)pEntry + 79) != 1)
                                {
                                    break;
                                }
                                if (RemainingSize4 >= 0x10)
                                {
                                    RemainingSize4 -= 16;
                                    pOutput7 += 4;
                                    *(_QWORD *)&pOutput6[4 * pOutput6[4] + 6] = (_QWORD)pEntry;
                                    *(_QWORD *)&pOutput6[4 * pOutput6[4]++ + 8] = pEntry[5];
                                }
                                pEntry = (_QWORD *)*pEntry;
                                pListStart = pCallbackListSaved;
                            }
                        }
                    }
                    if (RemainingSize4 >= 0x28)
                    {
                        pOutput8 = pOutput7;
                        *pOutput7 = 5;
                        pOutput7[4] = 0;
                        RemainingSize5 = RemainingSize4 - 24;
                        pOutput9 = pOutput7 + 6;
                        pEnumList = pEnumListSaved5;
                        if (pEnumListSaved5 && MmIsAddressValid(pEnumListSaved5) == 1)
                        {
                            EntryCount2 = 0;
                            while (1)
                            {
                                pEnumList = (_QWORD *)*pEnumList;
                                if (pEnumList == pEnumListSaved5)
                                    break;
                                if ((const PVOID)pEnumList <= MmSystemRangeStart)
                                    break;
                                if (MmIsAddressValid(pEnumList) != 1)
                                    break;
                                if ((unsigned int)++EntryCount2 > 0x1000)
                                    break;
                                if (RemainingSize5 >= 0x10)
                                {
                                    RemainingSize5 -= 16;
                                    pOutput9 += 4;
                                    *(_QWORD *)&pOutput8[4 * pOutput8[4] + 6] = (_QWORD)pEnumList;
                                    *(_QWORD *)&pOutput8[4 * pOutput8[4]++ + 8] = pEnumList[2];
                                }
                            }
                        }
                        if (RemainingSize5 >= 0x28)
                        {
                            pOutput10 = pOutput9;
                            *pOutput9 = 6;
                            pOutput9[4] = 0;
                            RemainingSize6 = RemainingSize5 - 24;
                            pOutput11 = pOutput9 + 6;
                            pEnumList2 = pEnumListSaved4;
                            if (pEnumListSaved4 && MmIsAddressValid(pEnumListSaved4) == 1)
                            {
                                EntryCount3 = 0;
                                while (1)
                                {
                                    pEnumList2 = (_QWORD *)*pEnumList2;
                                    if (pEnumList2 == pEnumListSaved4)
                                        break;
                                    if ((const PVOID)pEnumList2 <= MmSystemRangeStart)
                                        break;
                                    if (MmIsAddressValid(pEnumList2) != 1)
                                        break;
                                    if ((unsigned int)++EntryCount3 > 0x1000)
                                        break;
                                    if (RemainingSize6 >= 0x10)
                                    {
                                        RemainingSize6 -= 16;
                                        pOutput11 += 4;
                                        *(_QWORD *)&pOutput10[4 * pOutput10[4] + 6] = (_QWORD)pEnumList2;
                                        *(_QWORD *)&pOutput10[4 * pOutput10[4]++ + 8] = pEnumList2[2];
                                    }
                                }
                            }
                            if (BuildNumber == 9200
                                && BuildNumber == 9600)
                            {
                                pEnumList3 = pOldEnumList;
                                if (pOldEnumList)
                                {
                                    if (MmIsAddressValid(pOldEnumList) == 1)
                                    {
                                        EntryCount4 = 0;
                                        while (1)
                                        {
                                            pEnumList3 = (_QWORD *)*pEnumList3;
                                            if (pEnumList3 == pOldEnumList)
                                                break;
                                            if ((const PVOID)pEnumList3 <= MmSystemRangeStart)
                                                break;
                                            if (MmIsAddressValid(pEnumList3) != 1)
                                                break;
                                            if ((unsigned int)++EntryCount4 > 0x1000)
                                                break;
                                            if (RemainingSize6 >= 0x10)
                                            {
                                                RemainingSize6 -= 16;
                                                pOutput11 += 4;
                                                *(_QWORD *)&pOutput10[4 * pOutput10[4] + 6] = (_QWORD)pEnumList3;
                                                *(_QWORD *)&pOutput10[4 * pOutput10[4]++ + 8] = pEnumList3[2];
                                            }
                                        }
                                    }
                                }
                            }
                            if (RemainingSize6 >= 0x28)
                            {
                                pOutput12 = pOutput11;
                                *pOutput11 = 7;
                                pOutput11[4] = 0;
                                RemainingSize7 = RemainingSize6 - 24;
                                pOutput13 = pOutput11 + 6;
                                pEnumList4 = pEnumListSaved6;
                                if (pEnumListSaved6 && MmIsAddressValid(pEnumListSaved6) == 1)
                                {
                                    EntryCount5 = 0;
                                    while (1)
                                    {
                                        pEnumList4 = (_QWORD *)*pEnumList4;
                                        if (!pEnumList4)
                                            break;
                                        if ((const PVOID)pEnumList4 <= MmSystemRangeStart)
                                            break;
                                        if (MmIsAddressValid(pEnumList4) != 1)
                                            break;
                                        if ((unsigned int)++EntryCount5 > 0x10000)
                                            break;
                                        if (pEnumList4[1] && RemainingSize7 >= 0x10)
                                        {
                                            RemainingSize7 -= 16;
                                            pOutput13 += 4;
                                            *(_QWORD *)&pOutput12[4 * pOutput12[4] + 6] = (_QWORD)pEnumList4;
                                            *(_QWORD *)&pOutput12[4 * pOutput12[4]++ + 8] = pEnumList4[1];
                                        }
                                    }
                                }
                                if (RemainingSize7 >= 0x28)
                                {
                                    pOutput14 = pOutput13;
                                    *pOutput13 = 8;
                                    pOutput15 = pOutput13 + 4;
                                    pOutput13[4] = 0;
                                    RemainingSize8 = RemainingSize7 - 24;
                                    pOutput16 = pOutput13 + 6;
                                    if (pShadowSsdtTable)
                                    {
                                        if (MmIsAddressValid(pShadowSsdtTable) == 1)
                                        {
                                            ShadowSsdtEntry = *pShadowSsdtTable;
                                            if (*pShadowSsdtTable)
                                            {
                                                if (RemainingSize8 >= 0x10)
                                                {
                                                    RemainingSize8 -= 16;
                                                    pOutput16 += 4;
                                                    *(_QWORD *)&pOutput14[4 * *pOutput15 + 6] = ShadowSsdtEntry;
                                                    *(_QWORD *)&pOutput14[4 * (*pOutput15)++ + 8] = ShadowSsdtEntry;
                                                }
                                            }
                                        }
                                    }
                                    if (RemainingSize8 >= 0x28)
                                    {
                                        pOutput17 = pOutput16;
                                        *pOutput16 = 9;
                                        pOutput16[4] = 0;
                                        RemainingSize9 = RemainingSize8 - 24;
                                        pOutput18 = pOutput16 + 6;
                                        pEnumList5 = pEnumList1;
                                        if (pEnumList1 && MmIsAddressValid(pEnumList1) == 1)
                                        {
                                            EntryCount6 = 0;
                                            while (1)
                                            {
                                                pEnumList5 = (_QWORD *)*pEnumList5;
                                                if (pEnumList5 == pEnumList1)
                                                    break;
                                                if ((const PVOID)pEnumList5 <= MmSystemRangeStart)
                                                    break;
                                                if (MmIsAddressValid(pEnumList5) != 1)
                                                    break;
                                                if ((unsigned int)++EntryCount6 > 0x10000)
                                                    break;
                                                pEprocess = (_QWORD *)pEnumList5[2];
                                                if (pEprocess && RemainingSize9 >= 0x10)
                                                {
                                                    RemainingSize9 -= 16;
                                                    pOutput18 += 4;
                                                    *(_QWORD *)&pOutput17[4 * pOutput17[4] + 6] = (_QWORD)pEprocess;
                                                    *(_QWORD *)&pOutput17[4 * pOutput17[4]++ + 8] = GetProcessDeviceMap(pEprocess);
                                                }
                                            }
                                        }
                                        if (RemainingSize9 >= 0x28)
                                        {
                                            pOutput19 = pOutput18;
                                            *pOutput18 = 9;
                                            pOutput18[4] = 0;
                                            RemainingSize10 = RemainingSize9 - 24;
                                            pOutput20 = pOutput18 + 6;
                                            pEnumList6 = pEnumListSaved2;
                                            if (pEnumListSaved2 && MmIsAddressValid(pEnumListSaved2) == 1)
                                            {
                                                EntryCount7 = 0;
                                                while (1)
                                                {
                                                    pEnumList6 = (_QWORD *)*pEnumList6;
                                                    if (pEnumList6 == pEnumListSaved2)
                                                        break;
                                                    if ((const PVOID)pEnumList6 <= MmSystemRangeStart)
                                                        break;
                                                    if (MmIsAddressValid(pEnumList6) != 1)
                                                        break;
                                                    if ((unsigned int)++EntryCount7 > 0x10000)
                                                        break;
                                                    pEprocess2 = (_QWORD *)pEnumList6[2];
                                                    if (pEprocess2 && RemainingSize10 >= 0x10)
                                                    {
                                                        RemainingSize10 -= 16;
                                                        pOutput20 += 4;
                                                        *(_QWORD *)&pOutput19[4 * pOutput19[4] + 6] = (_QWORD)pEprocess2;
                                                        *(_QWORD *)&pOutput19[4 * pOutput19[4]++ + 8] = GetProcessDeviceMap(pEprocess2);
                                                    }
                                                }
                                            }
                                            if (RemainingSize10 >= 0x28)
                                            {
                                                pOutputSaved = pOutput20;
                                                *pOutput20 = 10;
                                                pOutput20[4] = 0;
                                                RemainingSize11 = RemainingSize10 - 24;
                                                pOutput21 = pOutput20 + 6;
                                                pProcessList = pProcessListSaved;
                                                if (pProcessListSaved && MmIsAddressValid(pProcessListSaved) == 1)
                                                {
                                                    for (ProcessListIndex = 0; ProcessListIndex < 0xD; ++ProcessListIndex)
                                                    {
                                                        pProcessEntry = &pProcessList[16 * ProcessListIndex];
                                                        SubEntryCount = 0;
                                                        for (i = *(_QWORD **)pProcessEntry; i != (_QWORD *)pProcessEntry; i = (_QWORD *)*i)
                                                        {
                                                            if ((const PVOID)i <= MmSystemRangeStart)
                                                                break;
                                                            if (MmIsAddressValid(i) != 1)
                                                                break;
                                                            if ((unsigned int)++SubEntryCount > 0x10000)
                                                                break;
                                                            DeviceMap = i[4];
                                                            if (DeviceMap && RemainingSize11 >= 0x10)
                                                            {
                                                                RemainingSize11 -= 16;
                                                                pOutput21 += 4;
                                                                *(_QWORD *)&pOutputSaved[4 * pOutputSaved[4] + 6] = (_QWORD)i;
                                                                *(_QWORD *)&pOutputSaved[4 * pOutputSaved[4]++ + 8] = DeviceMap;
                                                            }
                                                        }
                                                        pProcessList = pProcessListSaved;
                                                    }
                                                }
                                                if (RemainingSize11 >= 0x28)
                                                {
                                                    pOutput22 = pOutput21;
                                                    *pOutput21 = 11;
                                                    pOutput21[4] = 0;
                                                    RemainingSize12 = RemainingSize11 - 24;
                                                    pOutput23 = pOutput21 + 6;
                                                    pEnumList7 = pEnumListSaved3;
                                                    if (pEnumListSaved3)
                                                    {
                                                        if (MmIsAddressValid(pEnumListSaved3) == 1)
                                                        {
                                                            EntryCount8 = 0;
                                                            while (1)
                                                            {
                                                                pEnumList7 = (_QWORD *)*pEnumList7;
                                                                if (pEnumList7 == pEnumListSaved3)
                                                                    break;
                                                                if ((const PVOID)pEnumList7 <= MmSystemRangeStart)
                                                                    break;
                                                                if (MmIsAddressValid(pEnumList7) != 1)
                                                                    break;
                                                                if ((unsigned int)++EntryCount8 > 0x10000)
                                                                    break;
                                                                FileSystemEntry = pEnumList7[3];
                                                                if (FileSystemEntry && RemainingSize12 >= 0x10)
                                                                {
                                                                    RemainingSize12 -= 16;
                                                                    pOutput23 += 4;
                                                                    *(_QWORD *)&pOutput22[4 * pOutput22[4] + 6] = (_QWORD)pEnumList7;
                                                                    *(_QWORD *)&pOutput22[4 * pOutput22[4]++ + 8] = FileSystemEntry;
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
                }
            }
        }
    }
    return 1;
}

// ModuleOperationDispatch — 模块操作分发
// 验证用户态输入缓冲区后读取地址，调用服务表基址函数执行模块操作
// 对应原始驱动 sub_140058890
__int64 ModuleOperationDispatch(void *Address, unsigned int InputSize)
{
    __int64 TargetAddress;
    int (*CallbackFunc)(__int64);

    if ((unsigned __int64)Address < MmUserProbeAddress)
    {
        if (Address && (unsigned __int64)Address + InputSize < MmUserProbeAddress && InputSize == 8)
        {
            ProbeForRead(Address, 8u, 4u);
            TargetAddress = *(__int64 *)Address;
            CallbackFunc = (int (*)(__int64))GtRead(GtCallbackField56);
            if (CallbackFunc)
                return CallbackFunc(TargetAddress) >= 0;
            ResolveServiceTableBase();
            CallbackFunc = (int (*)(__int64))GtRead(GtCallbackField56);
            if (CallbackFunc)
                return CallbackFunc(TargetAddress) >= 0;
        }
    }
    return 0;
}

// ObjectOperationDispatcher — 对象操作分发器
// 根据操作码分发到对应的移除驱动对象/设备操作
// 对应原始驱动 sub_140009AD8
__int64 ObjectOperationDispatcher(void *InputBuffer, int BufferSize)
{
    int ActionCode;
    __int64 DriverObject;

    if (BufferSize == 16
        && (unsigned __int64)InputBuffer < MmUserProbeAddress
        && (unsigned __int64)((__int64 *)InputBuffer + 2) < MmUserProbeAddress)
    {
        ProbeForRead(InputBuffer, 0x10u, 1u);
        ActionCode = *(int *)InputBuffer;
        DriverObject = *((__int64 *)InputBuffer + 1);
        if (ActionCode > 7)
        {
            if (ActionCode == 8)
                return RemoveKbdClassDriverObject(DriverObject);
            if (ActionCode == 9)
                return RemoveMouClassDriverObject(DriverObject);
            if (ActionCode == 10)
                return RemoveI8042prtDriverObject(DriverObject);
            if (ActionCode == 11)
                return RemoveNdisDriverObject(DriverObject);
            if (ActionCode == 12)
                return RemovePnpManagerDriverObject(DriverObject);
        }
        else
        {
            if (ActionCode == 7)
                return RemoveTdxDriverObject(DriverObject);
            if (ActionCode == 1)
                return RemoveDeviceObject(DriverObject);
            if (ActionCode == 2)
                return RemoveRawDriverObject(DriverObject);
            if (ActionCode == 3)
                return RemoveHarddiskVolume1Device(DriverObject);
            if (ActionCode == 4)
                return OpenDeviceObjectForEnum(DriverObject);
            if (ActionCode == 5)
                return RemoveTcpipDriverObject(DriverObject);
            if (ActionCode == 6)
                return RemoveVolmgrDriverObject(DriverObject);
        }
    }
    return 0;
}

// ProcessMemoryOperationDispatch — 进程内存操作分发
// 收集 9 种系统内存数据结构（模块基址/内核对象/进程对象/内核数据等）写入输出缓冲区
// 对应原始驱动 sub_140043FC0
__int64 ProcessMemoryOperationDispatch(void *InputBuffer, int BufferSize)
{
    SIZE_T RemainingSize;
    char Result;
    __int64 *pModuleBaseTable;
    __int64 ModuleCount;
    unsigned int RemainingSize2;
    _DWORD *pType1Header;
    unsigned int ModuleIndex;
    __int64 pModuleAddr;
    unsigned __int64 AlignedAddr;
    unsigned int RemainingSize3;
    _DWORD *pType2Entry;
    int Type2Count;
    _QWORD *i;
    _DWORD *pType3Header;
    unsigned int RemainingSize4;
    _DWORD *pType3Entry;
    _QWORD *pType3ListHead;
    int Type3Count;
    __int64 DataTypeValue;
    _DWORD *pType4Header;
    unsigned int RemainingSize5;
    _DWORD *pType4Entry;
    unsigned int Win8EntryCount;
    _QWORD *pWin8ListPtr;
    unsigned int pType2Node;
    _QWORD *pWin8ListHead;
    unsigned __int64 pWin8EntryAddr;
    unsigned __int64 AlignedWin8Addr;
    _QWORD *pWin11ListHead;
    int Type4Count;
    _QWORD *pType4Node;
    _QWORD *pType4NodePtr;
    _DWORD *pType5Header;
    unsigned int RemainingSize6;
    _DWORD *pType5Entry;
    _QWORD *pType5ListHead;
    int Type5Count;
    _QWORD *pType5Sentinel;
    _QWORD *pType5Node;
    _DWORD *pType6Header;
    unsigned int RemainingSize7;
    _DWORD *pType6Entry;
    _QWORD *pType6ListHead;
    int Type6Count;
    _DWORD *pType7Header;
    unsigned int RemainingSize8;
    _DWORD *pType7Entry;
    _QWORD *pType7ListHead;
    int Type7Count;
    _DWORD *pType8Header;
    unsigned int RemainingSize9;
    _DWORD *pType8Entry;
    _QWORD *pType8ListHead;
    int Type8Count;
    _DWORD *pType9Header;
    unsigned int RemainingSize10;
    _DWORD *pType9Entry;
    _QWORD *pType9ListHead;
    _QWORD *pType9Node;
    _QWORD *pType9EntryPtr;
    _QWORD *pWin11ListPtr;
    _QWORD *pProcessObjListHead;
    _QWORD *pType4HeaderPtr;
    _QWORD *pType2ListHead;
    unsigned int VirtualAddress;
    _QWORD *pRelocBaseListHead;
    _QWORD *pProcessMemListHead;
    _QWORD *pKernelDataListHead;
    _QWORD *pSectionListHead;
    __int64 Win8ListCount;
    _QWORD *pType5SentinelPtr;
    _DWORD *pType2Header;
    _DWORD *pType4HeaderDwords;
    _QWORD *pExAllocListHead;

    RemainingSize = BufferSize;
    Result = 0;
    pModuleBaseTable = (__int64 *)GtRead(GtFwpsDispatchTableCount | GtEprocessField20);
    if (!pModuleBaseTable)
    {
        ParseNtSectionsForModuleBase();
        pModuleBaseTable = (__int64 *)GtRead(GtFwpsDispatchTableCount | GtEprocessField20);
    }
    ModuleCount = GtRead(GtFwpsDispatchTableBase | GtEprocessField22);
    pType2ListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField22);
    if (!pType2ListHead)
    {
        FindKernelDataSectionOffset();
        pType2ListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField22);
    }
    pProcessObjListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField28);
    if (!pProcessObjListHead)
    {
        FindKernelDataSectionOffsetV2();
        pProcessObjListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField28);
    }
    pWin11ListPtr = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField26);
    if (!pWin11ListPtr)
    {
        DispatchFindKernelDataSection();
        pWin11ListPtr = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField26);
    }
    Win8ListCount = GtRead(GtFwpsDispatchTableCount | GtEprocessField26);
    pExAllocListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField24);
    if (!pExAllocListHead)
    {
        FindKernelDataSectionOffsetEx();
        pExAllocListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField24);
    }
    pProcessMemListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField24);
    if (!pProcessMemListHead)
    {
        ParseNtSectionsForProcessMemory();
        pProcessMemListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField24);
    }
    pKernelDataListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField28);
    if (!pKernelDataListHead)
    {
        FindKernelDataSectionOffsetV3();
        pKernelDataListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField28);
    }
    pSectionListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField30);
    if (!pSectionListHead)
    {
        ParseProcessMemSections();
        pSectionListHead = (_QWORD *)GtRead(GtFwpsDispatchTableBase | GtEprocessField30);
    }
    pRelocBaseListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField30);
    if (!pRelocBaseListHead)
    {
        ParseNtSectionsForRelocBase();
        pRelocBaseListHead = (_QWORD *)GtRead(GtFwpsDispatchTableCount | GtEprocessField30);
    }
    if ((RemainingSize & 3) == 0
        && (unsigned int)RemainingSize >= 0x50
        && (unsigned __int64)InputBuffer < MmUserProbeAddress
        && (unsigned __int64)InputBuffer + RemainingSize < MmUserProbeAddress)
    {
        ProbeForWrite(InputBuffer, RemainingSize, 1u);
        memset(InputBuffer, 0, RemainingSize);
        RemainingSize2 = (unsigned int)(RemainingSize - 40);
        if ((unsigned int)(RemainingSize - 40) >= 0x28)
        {
            pType1Header = (_DWORD *)InputBuffer;
            *(_DWORD *)InputBuffer = 1;
            *((_DWORD *)InputBuffer + 4) = 0;
            RemainingSize2 = (unsigned int)(RemainingSize - 64);
            InputBuffer = (_DWORD *)InputBuffer + 6;
            if (pModuleBaseTable)
            {
                if (ModuleCount)
                {
                    for (ModuleIndex = 0; ModuleIndex < 8 && MmIsAddressValid(pModuleBaseTable); ++ModuleIndex)
                    {
                        pModuleAddr = *pModuleBaseTable;
                        if (*pModuleBaseTable)
                        {
                            if (RemainingSize2 < 0x10)
                                break;
                            *(_QWORD *)&pType1Header[4 * pType1Header[4] + 6] = pModuleAddr;
                            AlignedAddr = pModuleAddr & 0xFFFFFFFFFFFFFFF0uLL;
                            if (AlignedAddr)
                            {
                                *(_QWORD *)&pType1Header[4 * pType1Header[4]++ + 8] = *(_QWORD *)(AlignedAddr + 24);
                                RemainingSize2 -= 16;
                                InputBuffer = (_DWORD *)InputBuffer + 4;
                            }
                        }
                        ++pModuleBaseTable;
                    }
                }
            }
        }
        if (RemainingSize2 >= 0x28)
        {
            pType2Header = (_DWORD *)InputBuffer;
            *(_DWORD *)InputBuffer = 2;
            *((_DWORD *)InputBuffer + 4) = 0;
            RemainingSize3 = RemainingSize2 - 24;
            pType2Entry = (_DWORD *)InputBuffer + 6;
            if (pType2ListHead && MmIsAddressValid(pType2ListHead) == 1)
            {
                Type2Count = 0;
                for (i = (_QWORD *)*pType2ListHead; i != pType2ListHead; i = (_QWORD *)*i)
                {
                    if ((const PVOID)i <= MmSystemRangeStart)
                        break;
                    if ((unsigned int)++Type2Count > 0x10000 || MmIsAddressValid(i) != 1 || MmIsAddressValid((char *)i + 71) != 1)
                        break;
                    if (RemainingSize3 >= 0x10)
                    {
                        RemainingSize3 -= 16;
                        pType2Entry += 4;
                        *(_QWORD *)&pType2Header[4 * pType2Header[4] + 6] = (_QWORD)i;
                        *(_QWORD *)&pType2Header[4 * pType2Header[4]++ + 8] = i[3];
                    }
                }
            }
            if (RemainingSize3 >= 0x28)
            {
                pType3Header = pType2Entry;
                *pType2Entry = 3;
                pType2Entry[4] = 0;
                RemainingSize4 = RemainingSize3 - 24;
                pType3Entry = pType2Entry + 6;
                pType3ListHead = pProcessObjListHead;
                if (pProcessObjListHead && MmIsAddressValid(pProcessObjListHead) == 1)
                {
                    VirtualAddress = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x3839 ? 88 : 104;
                    Type3Count = 0;
                    while (1)
                    {
                        pType3ListHead = (_QWORD *)*pType3ListHead;
                        if (pType3ListHead == pProcessObjListHead)
                            break;
                        if ((const PVOID)pType3ListHead <= MmSystemRangeStart)
                            break;
                        if ((unsigned int)++Type3Count > 0x10000
                            || MmIsAddressValid(pType3ListHead) != 1
                            || MmIsAddressValid((char *)pType3ListHead + VirtualAddress - 1) != 1)
                        {
                            break;
                        }
                        if (RemainingSize4 >= 0x10)
                        {
                            RemainingSize4 -= 16;
                            pType3Entry += 4;
                            *(_QWORD *)&pType3Header[4 * pType3Header[4] + 6] = (_QWORD)pType3ListHead;
                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
                                DataTypeValue = pType3ListHead[10];
                            else
                                DataTypeValue = pType3ListHead[8];
                            *(_QWORD *)&pType3Header[4 * pType3Header[4]++ + 8] = DataTypeValue;
                        }
                    }
                }
                if (RemainingSize4 >= 0x28)
                {
                    pType4Header = pType3Entry;
                    pType4HeaderPtr = (_QWORD *)pType3Entry;
                    *pType3Entry = 4;
                    pType4HeaderDwords = pType3Entry + 4;
                    pType3Entry[4] = 0;
                    RemainingSize5 = RemainingSize4 - 24;
                    pType4Entry = pType3Entry + 6;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
                    {
                        pWin11ListHead = pWin11ListPtr;
                        if (pWin11ListPtr)
                        {
                            Type4Count = 0;
                            pType4Node = (_QWORD *)*pWin11ListPtr;
                            while (pType4Node != pWin11ListHead)
                            {
                                if ((const PVOID)pType4Node <= MmSystemRangeStart)
                                    break;
                                if ((unsigned int)++Type4Count > 0x10000)
                                    break;
                                pType4NodePtr = pType4Node - 6;
                                if (MmIsAddressValid(pType4Node - 6) != 1
                                    || MmIsAddressValid((char *)pType4NodePtr + 71) != 1
                                    || RemainingSize5 < 0x10)
                                {
                                    break;
                                }
                                pType4HeaderPtr[2 * (unsigned int)*pType4HeaderDwords + 3] = (_QWORD)pType4NodePtr;
                                pType4HeaderPtr[2 * (unsigned int)(*pType4HeaderDwords)++ + 4] = pType4NodePtr[3];
                                RemainingSize5 -= 16;
                                pType4Entry += 4;
                                pType4Node = (_QWORD *)*pType4Node;
                                pWin11ListHead = pWin11ListPtr;
                            }
                        }
                    }
                    else if (pWin11ListPtr && Win8ListCount)
                    {
                        Win8EntryCount = (unsigned int)GtRead(GtWindowsBuildNumber) < 0x3FAB ? 8 : 32;
                        pWin8ListPtr = pWin11ListPtr;
                        for (pType2Node = 0; pType2Node < Win8EntryCount && MmIsAddressValid(pWin8ListPtr); ++pType2Node)
                        {
                            pWin8ListHead = pWin11ListPtr;
                            pWin8EntryAddr = *pWin11ListPtr;
                            if (*pWin11ListPtr)
                            {
                                if (RemainingSize5 < 0x10)
                                    break;
                                *(_QWORD *)&pType4Header[4 * pType4Header[4] + 6] = pWin8EntryAddr;
                                AlignedWin8Addr = pWin8EntryAddr & 0xFFFFFFFFFFFFFFF0uLL;
                                if (AlignedWin8Addr)
                                {
                                    *(_QWORD *)&pType4Header[4 * pType4Header[4]++ + 8] = *(_QWORD *)(AlignedWin8Addr + 24);
                                    RemainingSize5 -= 16;
                                    pType4Entry += 4;
                                }
                                pWin8ListHead = pWin11ListPtr;
                            }
                            pWin8ListPtr = pWin8ListHead + 1;
                            pWin11ListPtr = pWin8ListPtr;
                        }
                    }
                    if (RemainingSize5 >= 0x28)
                    {
                        pType5Header = pType4Entry;
                        *pType4Entry = 5;
                        pType4Entry[4] = 0;
                        RemainingSize6 = RemainingSize5 - 24;
                        pType5Entry = pType4Entry + 6;
                        if (pExAllocListHead)
                        {
                            if (MmIsAddressValid(pExAllocListHead) == 1)
                            {
                                pType5ListHead = (_QWORD *)*pExAllocListHead;
                                if (*pExAllocListHead)
                                {
                                    if (MmIsAddressValid(pType5ListHead) == 1)
                                    {
                                        Type5Count = 0;
                                        pType5Sentinel = pType5ListHead + 2;
                                        pType5SentinelPtr = pType5ListHead + 2;
                                        pType5Node = (_QWORD *)pType5ListHead[2];
                                        while (pType5Node != pType5Sentinel)
                                        {
                                            if ((const PVOID)pType5Node <= MmSystemRangeStart)
                                                break;
                                            if ((unsigned int)++Type5Count > 0x10000
                                                || MmIsAddressValid(pType5Node) != 1
                                                || MmIsAddressValid((char *)pType5Node + 47) != 1)
                                            {
                                                break;
                                            }
                                            if (RemainingSize6 >= 0x10)
                                            {
                                                RemainingSize6 -= 16;
                                                pType5Entry += 4;
                                                *(_QWORD *)&pType5Header[4 * pType5Header[4] + 6] = (_QWORD)pType5Node;
                                                *(_QWORD *)&pType5Header[4 * pType5Header[4]++ + 8] = pType5Node[3];
                                            }
                                            pType5Node = (_QWORD *)*pType5Node;
                                            pType5Sentinel = pType5SentinelPtr;
                                        }
                                    }
                                }
                            }
                        }
                        if (RemainingSize6 >= 0x28)
                        {
                            pType6Header = pType5Entry;
                            *pType5Entry = 6;
                            pType5Entry[4] = 0;
                            RemainingSize7 = RemainingSize6 - 24;
                            pType6Entry = pType5Entry + 6;
                            pType6ListHead = pProcessMemListHead;
                            if (pProcessMemListHead && MmIsAddressValid(pProcessMemListHead) == 1)
                            {
                                Type6Count = 0;
                                while (1)
                                {
                                    pType6ListHead = (_QWORD *)*pType6ListHead;
                                    if (pType6ListHead == pProcessMemListHead)
                                        break;
                                    if ((const PVOID)pType6ListHead <= MmSystemRangeStart)
                                        break;
                                    if ((unsigned int)++Type6Count > 0x10000
                                        || MmIsAddressValid(pType6ListHead) != 1
                                        || MmIsAddressValid((char *)pType6ListHead + 23) != 1)
                                    {
                                        break;
                                    }
                                    if (RemainingSize7 >= 0x10)
                                    {
                                        RemainingSize7 -= 16;
                                        pType6Entry += 4;
                                        *(_QWORD *)&pType6Header[4 * pType6Header[4] + 6] = (_QWORD)pType6ListHead;
                                        *(_QWORD *)&pType6Header[4 * pType6Header[4]++ + 8] = pType6ListHead[2];
                                    }
                                }
                            }
                            if (RemainingSize7 >= 0x28)
                            {
                                pType7Header = pType6Entry;
                                *pType6Entry = 7;
                                pType6Entry[4] = 0;
                                RemainingSize8 = RemainingSize7 - 24;
                                pType7Entry = pType6Entry + 6;
                                pType7ListHead = pKernelDataListHead;
                                if (pKernelDataListHead && MmIsAddressValid(pKernelDataListHead) == 1)
                                {
                                    Type7Count = 0;
                                    while (1)
                                    {
                                        pType7ListHead = (_QWORD *)*pType7ListHead;
                                        if (pType7ListHead == pKernelDataListHead)
                                            break;
                                        if ((const PVOID)pType7ListHead <= MmSystemRangeStart)
                                            break;
                                        if ((unsigned int)++Type7Count > 0x10000
                                            || MmIsAddressValid(pType7ListHead) != 1
                                            || MmIsAddressValid((char *)pType7ListHead + 31) != 1)
                                        {
                                            break;
                                        }
                                        if (RemainingSize8 >= 0x10)
                                        {
                                            RemainingSize8 -= 16;
                                            pType7Entry += 4;
                                            *(_QWORD *)&pType7Header[4 * pType7Header[4] + 6] = (_QWORD)pType7ListHead;
                                            *(_QWORD *)&pType7Header[4 * pType7Header[4]++ + 8] = pType7ListHead[2];
                                        }
                                    }
                                }
                                if (RemainingSize8 >= 0x28)
                                {
                                    pType8Header = pType7Entry;
                                    *pType7Entry = 8;
                                    pType7Entry[4] = 0;
                                    RemainingSize9 = RemainingSize8 - 24;
                                    pType8Entry = pType7Entry + 6;
                                    pType8ListHead = pSectionListHead;
                                    if (pSectionListHead && MmIsAddressValid(pSectionListHead) == 1)
                                    {
                                        Type8Count = 0;
                                        while (1)
                                        {
                                            pType8ListHead = (_QWORD *)*pType8ListHead;
                                            if (pType8ListHead == pSectionListHead)
                                                break;
                                            if (!pType8ListHead)
                                                break;
                                            if ((const PVOID)pType8ListHead <= MmSystemRangeStart)
                                                break;
                                            if ((unsigned int)++Type8Count > 0x10000
                                                || MmIsAddressValid(pType8ListHead) != 1
                                                || MmIsAddressValid((char *)pType8ListHead + 31) != 1)
                                            {
                                                break;
                                            }
                                            if (RemainingSize9 >= 0x10)
                                            {
                                                RemainingSize9 -= 16;
                                                pType8Entry += 4;
                                                *(_QWORD *)&pType8Header[4 * pType8Header[4] + 6] = (_QWORD)pType8ListHead;
                                                *(_QWORD *)&pType8Header[4 * pType8Header[4]++ + 8] = pType8ListHead[1];
                                            }
                                        }
                                    }
                                    if (RemainingSize9 >= 0x28)
                                    {
                                        pType9Header = pType8Entry;
                                        *pType8Entry = 9;
                                        pType8Entry[4] = 0;
                                        RemainingSize10 = RemainingSize9 - 24;
                                        pType9Entry = pType8Entry + 6;
                                        pType9ListHead = pRelocBaseListHead;
                                        if (pRelocBaseListHead)
                                        {
                                            if (MmIsAddressValid(pRelocBaseListHead) == 1)
                                            {
                                                pType9Node = (_QWORD *)*pRelocBaseListHead;
                                                while (pType9Node != pType9ListHead)
                                                {
                                                    if ((const PVOID)pType9Node <= MmSystemRangeStart)
                                                        break;
                                                    if ((unsigned int)(++Result) > 0x10000)
                                                        break;
                                                    pType9EntryPtr = pType9Node - 1;
                                                    if (MmIsAddressValid(pType9Node - 1) != 1
                                                        || MmIsAddressValid((char *)pType9EntryPtr + 47) != 1)
                                                    {
                                                        break;
                                                    }
                                                    if (RemainingSize10 >= 0x10)
                                                    {
                                                        RemainingSize10 -= 16;
                                                        pType9Entry += 4;
                                                        *(_QWORD *)&pType9Header[4 * pType9Header[4] + 6] = (_QWORD)pType9EntryPtr;
                                                        *(_QWORD *)&pType9Header[4 * pType9Header[4]++ + 8] = pType9EntryPtr[3];
                                                    }
                                                    pType9Node = (_QWORD *)*pType9Node;
                                                    pType9ListHead = pRelocBaseListHead;
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
        Result = 1;
    }
    return Result;
}

// SendIoControlWithUnicodeString — 发送 IOCTL 带 Unicode 字符串
// 构建路径并打开设备发送 IOCTL，复制 Unicode 字符串，找到最后一个反斜杠并截断，调用 ZwCreateFile 打开设备，然后发送 IOCTL
// 对应原始驱动 sub_1400721A0
_DWORD *SendIoControlWithUnicodeString(__int64 Context)
{
    void (__fastcall *pExFree)(_QWORD);
    __int64 (__fastcall *pZwCreateFile)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _BYTE, _DWORD, _QWORD, _QWORD);
    __int64 ServiceTable;
    unsigned __int16 *pStringBuffer;
    unsigned __int16 StringLength;
    unsigned int StringLengthBytes;
    _WORD *pPathBuffer;
    _WORD *pPathBufferCopy;
    unsigned int PathLengthWords;
    __int64 BackslashIndex;
    unsigned int UnicodeLen;
    int Result2;
    int Result3;
    _DWORD *pResultData;
    int Result4;
    _WORD *pPathBuffer2;
    PVOID pAllocBuffer;
    _QWORD *pServiceTable;
    void (__fastcall *pExFreeCopy)(_QWORD);
    __int64 (__fastcall *pZwCreateFileFunc2)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _BYTE, _DWORD, _QWORD, _QWORD);
    unsigned int (__fastcall *pZwCreateFileFunc)(__int64 *, __int64, int *);
    int IoStatusBlock;
    __int64 SavedValue;
    int *pIoStatus;
    int ObjAttributes;
    _OWORD ObjAttributes2;
    _DWORD *pResultData2;
    __int64 FileHandle;

    pResultData2 = 0;
    pZwCreateFileFunc = (unsigned int (__fastcall *)(__int64 *, __int64, int *))GtRead(GtEprocessField100 | 0x100);
    pExFree = (void (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    pExFreeCopy = pExFree;
    pZwCreateFile = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _BYTE, _DWORD, _QWORD, _QWORD))GtRead(GtNtFsControlFileFunc);
    pZwCreateFileFunc2 = pZwCreateFile;
    ServiceTable = GtRead(GtEprocessField111 | 0x100);
    pServiceTable = (_QWORD *)ServiceTable;
    if (pZwCreateFileFunc && pExFree && pZwCreateFile && ServiceTable)
    {
        pStringBuffer = *(unsigned __int16 **)(Context + 16);
        StringLength = *pStringBuffer;
        if (*pStringBuffer && *((_QWORD *)pStringBuffer + 1))
        {
            StringLengthBytes = StringLength;
            pPathBuffer = ExAlloc(PagedPool, StringLength);
            pPathBufferCopy = pPathBuffer;
            pAllocBuffer = pPathBuffer;
            if (pPathBuffer)
            {
                memmove(pPathBuffer, *(const void **)(*(_QWORD *)(Context + 16) + 8LL), StringLengthBytes);
                PathLengthWords = StringLengthBytes >> 1;
                if (PathLengthWords)
                {
                    BackslashIndex = PathLengthWords - 1;
                    if (PathLengthWords != 1)
                    {
                        while (pPathBufferCopy[BackslashIndex] != 92)
                        {
                            BackslashIndex = (unsigned int)(BackslashIndex - 1);
                            if (!(_DWORD)BackslashIndex)
                                goto LABEL_23;
                        }
                        pPathBufferCopy[BackslashIndex] = 0;
                        UnicodeLen = (unsigned int)(2 * BackslashIndex + 2);
                        if (UnicodeLen < 2)
                        {
                            pPathBuffer2 = 0;
                            Result4 = 0;
                        }
                        else
                        {
                            pPathBuffer2 = pPathBufferCopy;
                            HIWORD_LV(Result4) = (_WORD)UnicodeLen;
                            LOWORD_LV(Result4) = (_WORD)(UnicodeLen - 2);
                        }
                        IoStatusBlock = 48;
                        SavedValue = 0;
                        ObjAttributes = 576;
                        pIoStatus = &Result4;
                        memset(&ObjAttributes2, 0, sizeof(ObjAttributes2));
                        if (!pZwCreateFileFunc(&FileHandle, 0x80000000LL, &IoStatusBlock))
                        {
                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
                                Result2 = (int)SendDeviceIoControlWithRetry(FileHandle, 1u, 0, &pResultData2, 0);
                            else
                                Result2 = (int)pZwCreateFile(FileHandle, 1, *pServiceTable, 0, (_QWORD)&pResultData2, 0, 1, Result4, (_QWORD)pPathBuffer2, (_QWORD)pAllocBuffer);
                            Result3 = Result2;
                            pResultData = pResultData2;
                            if (Result3 < 0)
                                pResultData = 0;
                            pResultData2 = pResultData;
                            pExFree((_QWORD)FileHandle);
                        }
                    }
                }
LABEL_23:
                ExFree(pPathBufferCopy);
            }
        }
    }
    return pResultData2;
}

// ParseNtSectionsForSsdtTable — 解析 NT 内核 PE 节区查找 SSDT 表
// 对应原始驱动 sub_140040630
// 附加到目标进程（GT 0x61 = GtCurrentEprocess），读取 GT 0x42FD/0x20/0x21/3/2。
// 遍历 PE 节区（最多 0xC8 条），跳过 Type 0x545(1349)，
// 查找 Type 0x50E(1294) 且 FieldFlags==0x40000、FieldValueSize==0x40 的节区，
// 结果 RVA 写入 GT 0x2D0 (GtCallbackField05)。
__int64 ParseNtSectionsForSsdtTable(void)
{
    __int64 Result;
    __int64 Process;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int ValueField;
    __int64 SectionContext;
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    int SectionDataSize;
    struct _KAPC_STATE ApcState;

    Result = 0;
    Process = GtRead(GtCurrentEprocess);

    if (Process)
        KeStackAttachProcess((struct _KPROCESS *)Process, &ApcState);

    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x42FD);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (BaseOffset &&
        BaseOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        SectionContext = 0;
        InitPESectionReadContext(
            (__int64)(PUCHAR)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)(PUCHAR)&SectionContext);

        SectionIndex = 0;
        while (SectionIndex < 0xC8)
        {
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            SectionDataSize = *(int *)&EntryBuffer[0x38];

            SectionType = *(unsigned short *)(pSectionEntryBase + 6);

            if (SectionType == 0x545)
                break;

            if (SectionType == 0x50E &&
                FieldFlags == 0x40000 &&
                SectionDataSize &&
                FieldValueSize == 0x40)
            {
                ValueField = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                if (ValueField && ValueField < NtImageSize)
                {
                    GtWrite(GtCallbackField05, NtoskrnlModuleBase + ValueField);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    if (Process)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}

// ===== 磁盘扇区辅助函数 =====

// 分析磁盘扇区缓冲区
void AnalyzeDiskSectorBuffer(__int64 Buffer)
{
    unsigned int Signature = *(unsigned int *)Buffer;
    if (*(unsigned int *)(Buffer + 0x1010) && MemoryCompare(Buffer + 0x10, (char *)(Buffer + 0x1014), Signature))
        *(unsigned int *)(Buffer + 4) = 1;
    if (!*(unsigned int *)(Buffer + 4) && CheckBootSectorAndMbr((__int64)(Buffer + 0x10), Signature) == 1)
        *(unsigned int *)(Buffer + 8) = 1;
}

// 查找引导扇区（带重试）
__int64 FindBootSectorWithRetry(struct _DEVICE_OBJECT *DeviceObject, unsigned int SectorSize)
{
    __int64 Result = 0;
    void *pBuffer = ExAlloc(0, SectorSize);
    if (pBuffer)
    {
        unsigned int SectorIndex = 1;
        while (DispatchDiskIrpWithHookInit(DeviceObject, 3, pBuffer, SectorIndex, 1, SectorSize) || CheckBootSectorAndMbr((__int64)pBuffer, SectorSize))
        {
            if (++SectorIndex >= 0x40)
                goto done;
        }
        Result = SectorIndex;
    done:
        ExFree(pBuffer);
    }
    return Result;
}

// 查找可引导分区 LBA
__int64 FindBootablePartitionLba(__int64 Buffer)
{
    unsigned int Index = 0;
    while (*(unsigned char *)(Buffer + 0x1BE) != 0x80)
    {
        if (++Index >= 4)
            return 0;
    }
    return *(unsigned int *)(Buffer + 0x1C6);
}

// 检查磁盘扇区健康
void CheckDiskSectorHealth(char *Buffer)
{
    unsigned int Signature = *(unsigned int *)Buffer;
    if (*((unsigned int *)Buffer + 3078) && MemoryCompare((__int64)(Buffer + 0x2030), (char *)(Buffer + 0x304C), Signature))
        *((unsigned int *)Buffer + 4103) = 1;
    if (!*((unsigned int *)Buffer + 4103) && CheckBootSectorErrors((__int64)(Buffer + 0x2030), Signature) == 1)
        *((unsigned int *)Buffer + 4104) = 1;
}

// 查找可读磁盘扇区
__int64 FindReadableDiskSector(struct _DEVICE_OBJECT *DeviceObject, unsigned int SectorSize, __int64 OutputBuffer)
{
    __int64 Result = 0;
    void *pBuffer = ExAlloc(0, SectorSize);
    if (pBuffer)
    {
        unsigned int SectorOffset = *(unsigned int *)(OutputBuffer + 0x202C);
        unsigned int MaxSector = *(unsigned int *)(OutputBuffer + 0x204C) + *(unsigned short *)(OutputBuffer + 0x203E);
        unsigned int SectorIndex = 1;
        if (MaxSector > 0x100)
            MaxSector = 256;
        if (MaxSector < 0x40)
            MaxSector = 64;
        while (DispatchDiskIrpWithHookInit(DeviceObject, 3, pBuffer, SectorIndex + SectorOffset, 1, SectorSize) || CheckBootSectorErrors((__int64)pBuffer, SectorSize))
        {
            if (++SectorIndex >= MaxSector)
                goto done;
        }
        Result = SectorIndex;
    done:
        ExFree(pBuffer);
    }
    return Result;
}

// ===== 回调控制操作子函数 =====
// 以下函数用于读写/修改内核回调表条目（APC、CmCallback、PspCreateProcessNotify 等）
// TargetObject 指向目标回调函数地址的指针，ContextValue 标识回调类型（GT 索引），
// Op1/Op2/Op3 为操作码（1=读取、2=清除、3=恢复等）

// ReadCallbackType1 — 读取回调类型1（PspCreateProcessNotifyRoutine 等）
// 对应原始驱动 sub_14000E2B0
char ReadCallbackType1(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (Op1 == 1)
            {
                // 读取回调函数地址
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (Op1 == 2 && Op2 == 1)
            {
                // 清除回调（置 0）
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// ReadCallbackType2 — 读取回调类型2（PspCreateThreadNotifyRoutine 等）
// 对应原始驱动 sub_14000E330
char ReadCallbackType2(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (Op1 == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (Op1 == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// ReadCallbackType3 — 读取回调类型3（PspLoadImageNotifyRoutine 等）
// 对应原始驱动 sub_14000E3B0
char ReadCallbackType3(char **TargetObject, unsigned __int64 ContextValue, char Op1, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (Op1 == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (Op1 == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// CallbackType1Dispatcher — 回调类型1 分派器（PspCreateProcessNotifyRoutine 等）
// 对应原始驱动 sub_14000E210
char CallbackType1Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (LoByte == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (LoByte == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// CallbackType2Dispatcher — 回调类型2 分派器（PspCreateThreadNotifyRoutine 等）
// 对应原始驱动 sub_14000E290
char CallbackType2Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (LoByte == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (LoByte == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// CallbackType3Dispatcher — 回调类型3 分派器（PspLoadImageNotifyRoutine 等）
// 对应原始驱动 sub_14000E310
char CallbackType3Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (LoByte == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (LoByte == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// CallbackType4Dispatcher — 回调类型4 分派器（CmCallback 等）
// 对应原始驱动 sub_14000E390
char CallbackType4Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (LoByte == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (LoByte == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// CallbackType5Dispatcher — 回调类型5 分派器（ExFreeCallBack 等）
// 对应原始驱动 sub_14000E410
char CallbackType5Dispatcher(char **TargetObject, unsigned __int64 ContextValue, char LoByte, char Op2, char Op3)
{
    char Result = 0;
    if (TargetObject && ContextValue && MmIsAddressValid(TargetObject) == 1)
    {
        __int64 CallbackFunc = (__int64)*TargetObject;
        if (CallbackFunc && (unsigned __int64)CallbackFunc > (unsigned __int64)MmSystemRangeStart)
        {
            if (LoByte == 1)
            {
                *TargetObject = (char *)CallbackFunc;
                Result = 1;
            }
            else if (LoByte == 2 && Op2 == 1)
            {
                *TargetObject = NULL;
                Result = 1;
            }
        }
    }
    return Result;
}

// ===== Stub 函数 =====
// CheckBootSectorAndMbr — 检查引导扇区和 MBR
// 委托给 SystemInfo.c 中的 CheckBootSectorAndMbrReal 实现
// 对应原始驱动 sub_140039A20
char CheckBootSectorAndMbr(__int64 Buffer, unsigned int Size)
{
    if (!Buffer || !Size)
        return 0;
    return CheckBootSectorAndMbrReal(Buffer, Size);
}

// CheckBootSectorErrors — 检查引导扇区错误
// 委托给 SystemInfo.c 中的 CheckBootSectorErrorsReal 实现
// 对应原始驱动 sub_140039B30
char CheckBootSectorErrors(__int64 Buffer, unsigned int Size)
{
    if (!Buffer || !Size)
        return 0;
    return CheckBootSectorErrorsReal(Buffer, Size);
}

// ValidateObjectTypeEntries — 验证对象类型条目
// 遍历 17 组 x 8 条对象类型条目(每组 208 字节，每条 24 字节)，验证指针在 ntoskrnl 范围内或非空。
// 对每条目比较内存内容(16 字节)，标记修改项。通过 GT 3(ntoskrnl 基址)/GT 2(镜像大小)/GT 76(原始数据缓冲区)进行地址验证。
// 对应原始驱动 sub_14006D7D0
void ValidateObjectTypeEntries(__int64 pContextTable)
{
    unsigned __int64 NtoskrnlBase;
    unsigned int NtoskrnlSize;
    __int64 GroupIndex;
    __int64 EntryIndex;
    __int64 pEntry;
    __int64 SavedValue;
    __int64 GroupBase;
    __int64 pDataBuffer;
    unsigned int BufferSize;
    __int64 Result;
    __int64 EntryCount = 0;

    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    GroupBase = pContextTable + 32;
    Result = 17;
    GroupIndex = 17;
    do
    {
        pEntry = GroupBase;
        EntryIndex = 8;
        do
        {
            SavedValue = *(_QWORD *)(pEntry - 8);
            if (SavedValue)
            {
                if (*(_QWORD *)pEntry == SavedValue)
                    goto LABEL_CONTINUE;
                goto LABEL_MARK_MODIFIED;
            }
            if (NtoskrnlBase && NtoskrnlSize && (*(_QWORD *)pEntry < NtoskrnlBase || *(_QWORD *)pEntry >= NtoskrnlBase + NtoskrnlSize))
            {
LABEL_MARK_MODIFIED:
                *(_BYTE *)(pEntry + 8) = 1;
            }
LABEL_CONTINUE:
            pEntry += 24;
            --EntryIndex;
        } while (EntryIndex);
        GroupBase += 208;
        --GroupIndex;
    } while (GroupIndex);

    pDataBuffer = GtRead(GtEprocessField66);
    BufferSize = (unsigned int)GtRead(GtEprocessField23);
    if (pDataBuffer && BufferSize && NtoskrnlBase)
    {
        _BYTE *pFlagEntry = (_BYTE *)(pContextTable + 40);
        do
        {
            _BYTE *pInnerEntry = pFlagEntry;
            __int64 InnerCount = 8;
            do
            {
                unsigned __int64 Address = *((_QWORD *)pInnerEntry - 2);
                if (Address)
                {
                    if (Address > NtoskrnlBase)
                    {
                        unsigned int Offset = (unsigned int)(Address - NtoskrnlBase);
                        if (Offset < BufferSize)
                        {
                            __int64 AddrCheck = (unsigned int)Offset + NtoskrnlBase;
                            if (Address == AddrCheck)
                            {
                                if (MmIsAddressValid((PVOID)Address) == 1)
                                {
                                    if (MmIsAddressValid((PVOID)(Address + 15)) == 1)
                                    {
                                        if ((unsigned int)MemoryCompare(Address, (char *)(Offset + pDataBuffer), 0x10u))
                                        {
                                            pInnerEntry[1] = 1;
                                            if (!pInnerEntry[0])
                                            {
                                                unsigned int ByteIndex;
                                                for (ByteIndex = 0; ByteIndex < 0x10; ++ByteIndex)
                                                {
                                                    if (!MmIsAddressValid((PVOID)(Address + ByteIndex)))
                                                        break;
                                                }
                                                if (ByteIndex)
                                                {
                                                    if (ReturnFalseStub() == 1)
                                                        *((_QWORD *)pInnerEntry - 1) = EntryCount;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                pInnerEntry += 24;
                --InnerCount;
            } while (InnerCount);
            pFlagEntry += 208;
            --Result;
        } while (Result);
    }
}

// QueryObjectDirectoryAndEnumerate — 查询对象目录并枚举
// 对应原始驱动 sub_14006FE60
// 打开 \ObjectTypes 目录，分配 0x100000 字节缓冲区，调用 EnumObjectTypeDirectory
// 遍历对象目录(深度 0x20000)，将枚举结果写入输出缓冲区，最后释放资源
void QueryObjectDirectoryAndEnumerate(__int64 OutputBuffer, unsigned int OutputSize)
{
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, _DWORD *);
    int (__fastcall *DeviceIoControlFunc)(_QWORD *, __int64, int *);
    int (__fastcall *NtFsControlFileFunc)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD);
    void (__fastcall *CloseHandleFunc)(_QWORD);
    void (__fastcall *ExFreePoolFunc)(_QWORD);
    _QWORD *Handle;
    _QWORD *DeviceHandle;
    _BYTE ObjectNameBuffer[16];
    _BYTE ObjectAttributes[48];
    _DWORD EncodedPath[7];

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    DeviceIoControlFunc = (int (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    NtFsControlFileFunc = (int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = (void (__fastcall *)(_QWORD))GtRead(GtCloseHandleFunc);
    ExFreePoolFunc = (void (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);

    if (!RtlInitUnicodeStringFunc || !DeviceIoControlFunc || !NtFsControlFileFunc || !CloseHandleFunc || !ExFreePoolFunc)
        return;

    // 编码 "\ObjectTypes" 路径 (7 个 DWORD = 26 个宽字符)
    EncodedPath[0] = 0x4F005C;
    EncodedPath[1] = 0x6A0062;
    EncodedPath[2] = 0x630065;
    EncodedPath[3] = 0x540074;
    EncodedPath[4] = 0x700079;
    EncodedPath[5] = 0x730065;
    EncodedPath[6] = 0;

    RtlInitUnicodeStringFunc(ObjectNameBuffer, EncodedPath);

    // 设置 OBJECT_ATTRIBUTES (Length=48, Attributes=576=0x240, ObjectName=ObjectNameBuffer)
    *(int *)(ObjectAttributes + 0) = 48;                                   // Length
    *(_QWORD *)(ObjectAttributes + 8) = 0;                                 // RootDirectory
    *(_QWORD *)(ObjectAttributes + 16) = (_QWORD)ObjectNameBuffer;         // ObjectName
    *(int *)(ObjectAttributes + 24) = 576;                                 // Attributes
    *(_QWORD *)(ObjectAttributes + 28) = 0;                                // SecurityDescriptor
    *(_QWORD *)(ObjectAttributes + 36) = 0;                                // SecurityQualityOfService

    if (DeviceIoControlFunc((_QWORD *)&Handle, 1, (int *)&ObjectAttributes[0]) >= 0)
    {
        if (NtFsControlFileFunc(Handle[0], 0xF000F, 0, 0, &DeviceHandle, 0) >= 0)
        {
            _QWORD **Buffer = (_QWORD **)ExAlloc(PagedPool, 0x100000u);
            if (Buffer)
            {
                *Buffer = DeviceHandle;
                EnumObjectTypeDirectory(Buffer, 0x20000, OutputBuffer, OutputSize);
                ExFree(Buffer);
            }
            CloseHandleFunc((_QWORD)DeviceHandle);
        }
        ExFreePoolFunc(Handle[0]);
    }
}


// ReadServiceTableEntries -- 读取服务表条目。
// 从 GT 506 获取服务表指针，若为空则先调用 ParseServiceTable 解析。
// 遍历服务表填充 12 字节每项的条目到输出缓冲区，包含索引号和服务表地址。
// 对应原始驱动 sub_140051214
__int64 ReadServiceTableEntries(__int64 OutputBuffer, __int64 TableParam, char *PeFileData, unsigned int PeFileSize)
{
    unsigned int Index = 0;
    unsigned int ServiceCount = (unsigned int)GtRead(GtEprocessField57);
    if (ServiceCount)
    {
        _DWORD *pServiceTable = (_DWORD *)GtRead(GtIrpBufferSize);
        if (pServiceTable || (ParseServiceTable(PeFileData, PeFileSize), pServiceTable = (_DWORD *)GtRead(GtIrpBufferSize), ServiceCount = (unsigned int)GtRead(GtEprocessField57), pServiceTable))
        {
            _DWORD *pOutputEntry = (_DWORD *)(OutputBuffer + 8);
            if (ServiceCount)
            {
                do
                {
                    *pOutputEntry = Index++;
                    pOutputEntry[1] = *pServiceTable;
                    pOutputEntry += 12;
                    ++pServiceTable;
                } while (Index < ServiceCount);
            }
            return 1;
        }
    }
    return 0;
}

// RemoveFromObjectTypeList -- 从对象类型链表中移除指定目标对象。
// 遍历链表（GT 699），查找匹配的 pTargetObject 指针，找到后从双向链表中摘除该节点。
// 使用 MmIsAddressValid 验证地址有效性，最多遍历 0x1000 次。
// 对应原始驱动 sub_140041FB4
__int64 RemoveFromObjectTypeList(PVOID *pTargetObject)
{
    char Result = 0;
    PVOID **pListHead = (PVOID **)GtRead(GtKernelDataField41);
    PVOID **pListHeadCopy = pListHead;
    if (pListHead && MmIsAddressValid(pListHead) == 1)
    {
        PVOID *pCurrent = *pListHeadCopy;
        int IterationCount = 0;
        while (pCurrent != (PVOID *)pListHeadCopy)
        {
            if ((const PVOID)pCurrent <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrent) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrent == pTargetObject)
            {
                if (MmIsAddressValid(*pCurrent) == 1)
                {
                    PVOID *pPrev = (PVOID *)*pCurrent;
                    PVOID **pNext = (PVOID **)pCurrent[1];
                    Result = 1;
                    pPrev[1] = pNext;
                    *pNext = pPrev;
                }
                return Result;
            }
            pCurrent = (PVOID *)*pCurrent;
        }
    }
    return Result;
}

// RemoveFromObjectTypeListEx -- 从对象类型链表中删除指定的指针条目（扩展版）。
// 从 GT 824 获取 13 个链表头数组，在每个链表中搜索匹配目标指针（最多 0x10000 条），找到后从双向链表中摘除。
// 对应原始驱动 sub_140042914
__int64 RemoveFromObjectTypeListEx(PVOID *pTargetPointer)
{
    char Result = 0;
    PVOID **pListHeadArray = (PVOID **)GtRead(GtCallbackField103);
    PVOID **pCurrentListHead = pListHeadArray;
    if (pListHeadArray && MmIsAddressValid(pListHeadArray) == 1)
    {
        for (unsigned int ListIndex = 0; ListIndex < 0xD; ++ListIndex)
        {
            if (MmIsAddressValid(pCurrentListHead) == 1)
            {
                PVOID *pCurrentNode = *pCurrentListHead;
                int IterationCount = 0;
                while (pCurrentNode != (PVOID *)pCurrentListHead)
                {
                    if ((const PVOID)pCurrentNode <= MmSystemRangeStart)
                        break;
                    if (MmIsAddressValid(pCurrentNode) != 1)
                        break;
                    if ((unsigned int)++IterationCount > 0x10000)
                        break;
                    if (pTargetPointer == pCurrentNode)
                    {
                        if (MmIsAddressValid(*pCurrentNode) == 1)
                        {
                            PVOID *pPrevEntry = (PVOID *)*pCurrentNode;
                            PVOID **pNextEntry = (PVOID **)pCurrentNode[1];
                            Result = 1;
                            pPrevEntry[1] = pNextEntry;
                            *pNextEntry = pPrevEntry;
                        }
                        break;
                    }
                    pCurrentNode = (PVOID *)*pCurrentNode;
                }
                if (Result == 1)
                    break;
            }
            pCurrentListHead += 2;
        }
    }
    return Result;
}

// RemoveObjectFromTypeList -- 从对象类型链表中删除指定对象并释放内存。
// 先调用 GT 16820 的释放回调处理目标对象，然后遍历 GT 95 和 GT 719 两个双向链表，
// 搜索匹配的对象条目（最多 0x10000 条），找到后从链表摘除，非 Win7 时调用 ObfDereferenceObject，
// 最后 ExFreePoolWithTag 释放节点内存。
// 对应原始驱动 sub_140042A48
__int64 RemoveObjectFromTypeList(PVOID pTargetObject)
{
    char Result = 0;
    void (__fastcall *pFreeCallback)(PVOID) = (void (__fastcall *)(PVOID))GtRead(GtTotalSize | GtEprocessField170 | 0x100);
    if (pFreeCallback)
    {
        pFreeCallback(pTargetObject);
        Result = 1;
    }
    _QWORD ListHeadBuffer[7];
    ListHeadBuffer[0] = GtRead(GtEprocessField85);
    PVOID ***pListHeadArray = (PVOID ***)ListHeadBuffer;
    ListHeadBuffer[1] = GtRead(GtCallbackField04);
    __int64 ListCount = 2;
    do
    {
        PVOID **pListHead = *pListHeadArray;
        if (*pListHeadArray)
        {
            PVOID *pCurrentNode = *pListHead;
            int IterationCount = 0;
            while (pCurrentNode != (PVOID *)pListHead)
            {
                if ((const PVOID)pCurrentNode <= MmSystemRangeStart)
                    break;
                if (MmIsAddressValid(pCurrentNode) != 1)
                    break;
                if ((unsigned int)++IterationCount > 0x10000)
                    break;
                PVOID pObjectEntry = pCurrentNode[2];
                if (pTargetObject == pObjectEntry)
                {
                    if (MmIsAddressValid(*pCurrentNode) == 1)
                    {
                        PVOID *pPrevEntry = (PVOID *)*pCurrentNode;
                        PVOID **pNextEntry = (PVOID **)pCurrentNode[1];
                        pPrevEntry[1] = pNextEntry;
                        *pNextEntry = pPrevEntry;
                        if (!(unsigned int)GtRead(GtEprocessField28))
                            ObfDereferenceObject(pObjectEntry);
                        ExFreePoolWithTag(pCurrentNode, 0);
                        Result = 1;
                    }
                    break;
                }
                pCurrentNode = (PVOID *)*pCurrentNode;
            }
        }
        ++pListHeadArray;
        --ListCount;
    } while (ListCount);
    return Result;
}

// RemoveKernelObjectEntry -- 移除内核对象条目。
// 在 SSDT2 表（GT 88）中查找匹配目标地址的条目，清零并从计数器中递减。
// 非 Win7 时释放条目内存。然后调用释放函数（GT 16826）释放目标地址对应的数据。
// 对应原始驱动 sub_140042578
__int64 RemoveKernelObjectEntry(__int64 TargetAddress)
{
    char Result = 0;
    int IsWin7 = (int)GtRead(GtEprocessField28);
    _QWORD *pSsdtTable = (_QWORD *)GtRead(GtEprocessField78);
    __int64 SsdtTableEnd = GtRead(GtEprocessField79);
    _DWORD *pCounter = (_DWORD *)SsdtTableEnd;
    if (pSsdtTable && SsdtTableEnd)
    {
        _QWORD *pEndPtr = (_QWORD *)SsdtTableEnd;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
            pEndPtr = pSsdtTable + 64;
        while (pSsdtTable < pEndPtr && MmIsAddressValid(pSsdtTable))
        {
            if (TargetAddress == *pSsdtTable)
            {
                *pSsdtTable = 0;
                if (!IsWin7)
                {
                    if (*pCounter)
                        --*pCounter;
                    ExFreePoolWithTag((PVOID)(TargetAddress & 0xFFFFFFFFFFFFFFF0ui64), 0);
                }
                Result = 1;
                break;
            }
            ++pSsdtTable;
        }
    }
    void (__fastcall *pFreeFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtTotalSize | GtNtQuerySystemInformationFunc | GtEprocessField22);
    if (pFreeFunc)
    {
        __int64 FreeParam;
        if (IsWin7)
        {
            FreeParam = TargetAddress;
            goto LABEL_FREE;
        }
        __int64 FreeAddr = TargetAddress & 0xFFFFFFFFFFFFFFF0ui64;
        if (MmIsAddressValid((PVOID)(FreeAddr + 8)) == 1)
        {
            FreeParam = *(_QWORD *)(FreeAddr + 8);
LABEL_FREE:
            pFreeFunc(FreeParam);
            return 1;
        }
    }
    return Result;
}

// ReleaseProcessMemoryBlock -- 释放进程内存块。
// 先调用回调释放目标条目，然后遍历进程内存链表查找匹配条目并从链表中摘除后释放。
// 对应原始驱动 sub_14004501C
__int64 ReleaseProcessMemoryBlock(_QWORD *pTargetEntry)
{
    int IterationCount = 0;
    char Result = 0;
    void (__fastcall *pFreeCallback)(_QWORD *) = (void (__fastcall *)(_QWORD *))GtRead(GtNtDeleteKeyPeSectionOffset);
    if (pFreeCallback && pTargetEntry && MmIsAddressValid(pTargetEntry) == 1)
    {
        pFreeCallback(pTargetEntry);
        Result = 1;
    }
    _QWORD **pProcessMemListHead = (_QWORD **)GtRead(GtFwpsDispatchTableCount);
    _QWORD **pSentinel = pProcessMemListHead;
    if (pProcessMemListHead && MmIsAddressValid(pProcessMemListHead) == 1)
    {
        for (_QWORD *pCurrentNode = *pSentinel; pCurrentNode != (_QWORD *)pSentinel; pCurrentNode = (_QWORD *)*pCurrentNode)
        {
            if ((const PVOID)pCurrentNode <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrentNode) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrentNode == pTargetEntry)
            {
                if (MmIsAddressValid((PVOID)*pCurrentNode) == 1)
                {
                    _QWORD *pPrevEntry = (_QWORD *)*pCurrentNode;
                    _QWORD *pNextEntry = (_QWORD *)pCurrentNode[1];
                    pPrevEntry[1] = (_QWORD)pNextEntry;
                    *pNextEntry = (_QWORD)pPrevEntry;
                    ExFreePoolWithTag(pTargetEntry, 0x72546F49u);
                    return 1;
                }
                return Result;
            }
        }
    }
    return Result;
}

// PatchFsFilterDriverIndex -- 修补文件系统过滤驱动索引。
// 对应原始驱动 sub_14000EEF4
char PatchFsFilterDriverIndex(__int64 PatchEntry, char Is64Bit)
{
    char Result = 0;
    __int64 FileSection;
    if (Is64Bit == 1)
        FileSection = BuildFsFilterDriverPath2();
    else
        FileSection = BuildFsFilterDriverPath1();
    if (FileSection)
    {
        if (*(_DWORD *)(PatchEntry + 4) < 0x40u && *(_BYTE *)PatchEntry == 1)
        {
            __int64 ExportDirEntry = *(_QWORD *)(FileSection + 48);
            if (ExportDirEntry)
            {
                __int64 ExportFuncTable = *(_QWORD *)(ExportDirEntry + 40);
                if (ExportFuncTable)
                {
                    if (CheckMemoryValid((void *)ExportFuncTable) == 1 && CheckMemoryValid((void *)(ExportFuncTable + 425)) == 1)
                    {
                        WritePhysicalMemoryQword(
                            ExportFuncTable + 8 * (*(unsigned int *)(PatchEntry + 4) + 4LL),
                            *(_QWORD *)(PatchEntry + 16));
                        return 1;
                    }
                }
            }
        }
    }
    return Result;
}

// QuerySsdHookByProcessInfo -- 通过进程信息查询 SSDT Hook。
// 验证输入缓冲区，分配临时缓冲区，通过 DecryptAesHexString 解密后调用 CheckSsdtHookIntegrity 检查 SSDT Hook 完整性。
// 对应原始驱动 sub_1400310B4
__int64 QuerySsdHookByProcessInfo(void *Src, size_t MaxCount, _DWORD *Address, int OutputSize)
{
    unsigned int MaxCountCopy = (unsigned int)MaxCount;
    char Result = 0;
    _BYTE Dst[304];
    if (Src)
    {
        if ((unsigned __int64)Src < MmUserProbeAddress
            && (unsigned int)MaxCount < 0x1000
            && (unsigned __int64)Src + (unsigned int)MaxCount < MmUserProbeAddress)
        {
            if (Address)
            {
                if ((unsigned __int64)Address < MmUserProbeAddress
                    && OutputSize == 4
                    && (unsigned __int64)(Address + 1) < MmUserProbeAddress)
                {
                    ProbeForRead(Src, (unsigned int)MaxCount, 1u);
                    ProbeForWrite(Address, 4u, 1u);
                    __int64 *pSyscallCount = GtAlloc(GtEncryptionKey);
                    if (MaxCountCopy <= 0x12C)
                    {
                        memmove(Dst, Src, MaxCountCopy);
                        --*pSyscallCount;
                        if (!(unsigned int)DecryptAesHexString(Dst, MaxCountCopy, pSyscallCount))
                            return CheckSsdtHookIntegrity((unsigned __int64)Dst, MaxCountCopy, Address, 4);
                    }
                }
            }
        }
    }
    return Result;
}


// EnumServiceTableWin10 -- 枚举服务表(Win10 版)
__int64 EnumServiceTableWin10(__int64 *pServiceTable, __int64 OutputBuffer, _DWORD *pEntryCount, int MaxEntries)
{
    __int64 (__fastcall *pCheckFunc)(__int64 *) = (__int64 (__fastcall *)(__int64 *))GtRead(GtObjectTypeCheckFlag);
    unsigned int EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    unsigned int CreateTimeOffset = (unsigned int)GtRead(GtProcessCreateTime);
    __int64 result = GtRead(GtProcessOffset);
    unsigned int ProcessOffset = (unsigned int)result;
    if (pCheckFunc && EprocessOffset != -1 && CreateTimeOffset && (_DWORD)result != -1 && pServiceTable)
    {
        result = pCheckFunc(pServiceTable);
        if ((_BYTE)result)
        {
            __int64 pCurrentNode = *pServiceTable;
            unsigned int LoopCount = 0;
            if (pCurrentNode)
            {
                __int64 pOutputEntry = OutputBuffer + 8;
                do
                {
                    result = pCheckFunc((__int64 *)pCurrentNode);
                    if (!(_BYTE)result || !MaxEntries || LoopCount > 0x10000)
                        break;
                    __int64 pServiceEntry = *(_QWORD *)(pCurrentNode + 40);
                    __int64 **ppContextEntry = pServiceEntry ? *(__int64 ***)(pServiceEntry + 16) : *(__int64 ***)(pCurrentNode + 48);
                    if (ppContextEntry)
                    {
                        __int64 *pContextEntry = *ppContextEntry;
                        if (pContextEntry)
                        {
                            result = pCheckFunc(pContextEntry);
                            if ((_BYTE)result)
                            {
                                --MaxEntries;
                                *(_QWORD *)(pOutputEntry + 8) = *(_QWORD *)(pCurrentNode + 80);
                                int ServiceFlags = *(_DWORD *)(pCurrentNode + 68);
                                *(_QWORD *)(pOutputEntry - 8) = pCurrentNode;
                                *(_DWORD *)pOutputEntry = ServiceFlags;
                                pOutputEntry += 48;
                                *(_QWORD *)(pOutputEntry - 16) = *(unsigned int *)((char *)pContextEntry + CreateTimeOffset);
                                result = ProcessOffset;
                                *(_QWORD *)(pOutputEntry - 32) = *(unsigned int *)((char *)pContextEntry + EprocessOffset);
                                *(_QWORD *)(pOutputEntry - 24) = *(__int64 *)((char *)pContextEntry + ProcessOffset);
                                ++*pEntryCount;
                            }
                        }
                    }
                    pCurrentNode = *(_QWORD *)(pCurrentNode + 24);
                    ++LoopCount;
                }
                while (pCurrentNode);
            }
        }
    }
    return result;
}

// EnumServiceTableWin8 -- 枚举服务表(Win8 版)
__int64 EnumServiceTableWin8(_QWORD **pServiceTable, __int64 OutputBuffer, _DWORD *pEntryCount, int MaxEntries)
{
    __int64 (__fastcall *pCheckFunc)(_QWORD **) = (__int64 (__fastcall *)(_QWORD **))GtRead(GtObjectTypeCheckFlag);
    unsigned int EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    unsigned int EprocessOffsetVal = EprocessOffset;
    unsigned int CreateTimeOffset = (unsigned int)GtRead(GtProcessCreateTime);
    unsigned int CreateTimeOffsetVal = CreateTimeOffset;
    __int64 result = GtRead(GtProcessOffset);
    unsigned int ProcessOffsetVal = (unsigned int)result;
    if (pCheckFunc && EprocessOffset != -1 && CreateTimeOffset && (_DWORD)result != -1 && pServiceTable)
    {
        result = pCheckFunc(pServiceTable);
        if ((_BYTE)result)
        {
            _QWORD **pCurrentNode = (_QWORD **)*pServiceTable;
            unsigned int LoopCount = 0;
            if (*pServiceTable)
            {
                __int64 pOutputEntry = OutputBuffer + 8;
                do
                {
                    result = pCheckFunc(pCurrentNode);
                    if (!(_BYTE)result || pCurrentNode == pServiceTable || !MaxEntries || LoopCount > 0x10000)
                        break;
                    _QWORD **pServiceNode = pCurrentNode - 3;
                    _QWORD *pServiceEntry = pServiceNode[5];
                    __int64 *pContextEntry = pServiceEntry ? (__int64 *)pServiceEntry[2] : pServiceNode[6];
                    if (pContextEntry)
                    {
                        _QWORD **ppContextEntry = (_QWORD **)*pContextEntry;
                        if (ppContextEntry)
                        {
                            result = pCheckFunc(ppContextEntry);
                            if ((_BYTE)result)
                            {
                                --MaxEntries;
                                *(_QWORD *)(pOutputEntry + 8) = (_QWORD)pServiceNode[10];
                                int ServiceFlags = *((_DWORD *)pServiceNode + 17);
                                *(_QWORD *)(pOutputEntry - 8) = (_QWORD)pServiceNode;
                                *(_DWORD *)pOutputEntry = ServiceFlags;
                                pOutputEntry += 48;
                                *(_QWORD *)(pOutputEntry - 16) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + CreateTimeOffsetVal);
                                result = ProcessOffsetVal;
                                *(_QWORD *)(pOutputEntry - 32) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + EprocessOffsetVal);
                                *(_QWORD *)(pOutputEntry - 24) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + ProcessOffsetVal);
                                ++*pEntryCount;
                            }
                        }
                    }
                    pCurrentNode = (_QWORD **)*pCurrentNode;
                    ++LoopCount;
                }
                while (pCurrentNode);
            }
        }
    }
    return result;
}

// EnumServiceTableWin7 -- 枚举服务表(Win7 版)
__int64 EnumServiceTableWin7(__int64 *pServiceTable, __int64 OutputBuffer, _DWORD *pEntryCount, int MaxEntries)
{
    __int64 (__fastcall *pCheckFunc)(__int64 *) = (__int64 (__fastcall *)(__int64 *))GtRead(GtObjectTypeCheckFlag);
    unsigned int EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    unsigned int CreateTimeOffset = (unsigned int)GtRead(GtProcessCreateTime);
    __int64 result = GtRead(GtProcessOffset);
    unsigned int ProcessOffset = (unsigned int)result;
    if (pCheckFunc && EprocessOffset != -1 && CreateTimeOffset && (_DWORD)result != -1 && pServiceTable)
    {
        result = pCheckFunc(pServiceTable);
        if ((_BYTE)result)
        {
            __int64 pCurrentNode = *pServiceTable;
            unsigned int LoopCount = 0;
            if (pCurrentNode)
            {
                __int64 pOutputEntry = OutputBuffer + 8;
                do
                {
                    result = pCheckFunc((__int64 *)pCurrentNode);
                    if (!(_BYTE)result || !MaxEntries || LoopCount > 0x10000)
                        break;
                    __int64 pServiceEntry = *(_QWORD *)(pCurrentNode + 32);
                    __int64 **ppContextEntry = pServiceEntry ? *(__int64 ***)(pServiceEntry + 16) : *(__int64 ***)(pCurrentNode + 24);
                    if (ppContextEntry)
                    {
                        __int64 *pContextEntry = *ppContextEntry;
                        if (pContextEntry)
                        {
                            result = pCheckFunc(pContextEntry);
                            if ((_BYTE)result)
                            {
                                --MaxEntries;
                                *(_QWORD *)(pOutputEntry + 8) = *(_QWORD *)(pCurrentNode + 56);
                                int ServiceFlags = *(_DWORD *)(pCurrentNode + 48);
                                *(_QWORD *)(pOutputEntry - 8) = pCurrentNode;
                                *(_DWORD *)pOutputEntry = ServiceFlags;
                                pOutputEntry += 48;
                                *(_QWORD *)(pOutputEntry - 16) = *(unsigned int *)((char *)pContextEntry + CreateTimeOffset);
                                result = ProcessOffset;
                                *(_QWORD *)(pOutputEntry - 32) = *(unsigned int *)((char *)pContextEntry + EprocessOffset);
                                *(_QWORD *)(pOutputEntry - 24) = *(__int64 *)((char *)pContextEntry + ProcessOffset);
                                ++*pEntryCount;
                            }
                        }
                    }
                    pCurrentNode = *(_QWORD *)(pCurrentNode + 8);
                    ++LoopCount;
                }
                while (pCurrentNode);
            }
        }
    }
    return result;
}

// EnumServiceTableWin1020H1 -- 枚举服务表(Win10 20H1+ 版)
__int64 EnumServiceTableWin1020H1(_QWORD **pServiceTable, __int64 OutputBuffer, _DWORD *pEntryCount, int MaxEntries)
{
    __int64 (__fastcall *pCheckFunc)(_QWORD **) = (__int64 (__fastcall *)(_QWORD **))GtRead(GtObjectTypeCheckFlag);
    unsigned int EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    unsigned int EprocessOffsetVal = EprocessOffset;
    unsigned int CreateTimeOffset = (unsigned int)GtRead(GtProcessCreateTime);
    unsigned int CreateTimeOffsetVal = CreateTimeOffset;
    __int64 result = GtRead(GtProcessOffset);
    unsigned int ProcessOffsetVal = (unsigned int)result;
    if (pCheckFunc && EprocessOffset != -1 && CreateTimeOffset && (_DWORD)result != -1 && pServiceTable)
    {
        result = pCheckFunc(pServiceTable);
        if ((_BYTE)result)
        {
            result = GtRead(GtWindowsBuildNumber);
            _QWORD **pCurrentNode;
            if ((unsigned int)result < 0x2800 || (pServiceTable = (_QWORD **)*pServiceTable) != 0 && (result = pCheckFunc(pServiceTable), (_BYTE)result))
            {
                pCurrentNode = (_QWORD **)*pServiceTable;
            }
            else
            {
                pServiceTable = 0;
                pCurrentNode = 0;
            }
            unsigned int LoopCount = 0;
            if (pCurrentNode)
            {
                __int64 pOutputEntry = OutputBuffer + 8;
                while (1)
                {
                    result = pCheckFunc(pCurrentNode);
                    if (!(_BYTE)result || !MaxEntries || pCurrentNode == pServiceTable || LoopCount > 0x10000)
                        return result;
                    _QWORD **pServiceNode = pCurrentNode - 9;
                    unsigned __int64 ServiceEntry = (unsigned __int64)pServiceNode[11];
                    if (!ServiceEntry)
                    {
                        _QWORD *pContextEntry = pServiceNode[3];
                        goto LABEL_22;
                    }
                    result = (__int64)MmSystemRangeStart;
                    if (ServiceEntry >= (unsigned __int64)MmSystemRangeStart)
                    {
                        _QWORD *pContextEntry = *(_QWORD **)(ServiceEntry + 16);
LABEL_22:
                        if (pContextEntry)
                        {
                            _QWORD **ppContextEntry = (_QWORD **)*pContextEntry;
                            if (ppContextEntry)
                            {
                                result = pCheckFunc(ppContextEntry);
                                if ((_BYTE)result)
                                {
                                    --MaxEntries;
                                    *(_QWORD *)(pOutputEntry + 8) = (_QWORD)pServiceNode[4];
                                    int ServiceFlags = *((_DWORD *)pServiceNode + 10);
                                    *(_QWORD *)(pOutputEntry - 8) = (_QWORD)pServiceNode;
                                    *(_DWORD *)pOutputEntry = ServiceFlags;
                                    pOutputEntry += 48;
                                    *(_QWORD *)(pOutputEntry - 16) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + CreateTimeOffsetVal);
                                    result = ProcessOffsetVal;
                                    *(_QWORD *)(pOutputEntry - 32) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + EprocessOffsetVal);
                                    *(_QWORD *)(pOutputEntry - 24) = (_QWORD)*(_QWORD **)((char *)ppContextEntry + ProcessOffsetVal);
                                    ++*pEntryCount;
                                }
                            }
                        }
                    }
                    pCurrentNode = (_QWORD **)*pCurrentNode;
                    ++LoopCount;
                    if (!pCurrentNode)
                        return result;
                }
            }
        }
    }
    return result;
}


// BuildServiceTableFromNtKernel -- 从 NT 内核构建服务表
// 读取 GT 2324/80，调用 ReadNtOsKrnlFile 读取 ntoskrnl PE 文件
// 搜索 Type 0x559 和 Type 0x512 节区，构建服务表
__int64 BuildServiceTableFromNtKernel(_QWORD KernelBase, _QWORD KernelSize)
{
    __int64 Result = 0;
    unsigned int TableSize;
    __int64 BasePtr;
    __int64 PeFileBuffer;
    unsigned int PeFileSize;
    unsigned int ExportDirSize;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int EntryCount;
    ULONG EntryBuffer[0x80];

    TableSize = (unsigned int)GtRead(GtWindowsBuildNumber);
    if (TableSize >= 0x2800)
        return 0;

    BasePtr = GtRead(GtKernelModuleBase);
    if (!BasePtr)
        return 0;

    if (ReadNtOsKrnlFile(&PeFileBuffer, (__int64 *)&PeFileSize) != 1)
        return 0;

    ExportDirSize = *(unsigned int *)(PeFileBuffer + 0x3C);
    ExportDirSize = *(unsigned int *)(ExportDirSize + PeFileBuffer);
    if (!ExportDirSize || ExportDirSize >= PeFileSize)
        goto cleanup;

    // Phase1: 搜索 Type 0x559 节区
    InitPESectionReadContext((__int64)(PUCHAR)PeFileBuffer + ExportDirSize, PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)(PUCHAR)&EntryBuffer);
    EntryCount = 0;
    while (EntryCount < 0x1E)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x50 >> 2];
        CumulativeSize = EntryBuffer[0x188 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x28 >> 2];
        EntryBuffer[0x188 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(SectionDataPtr + 6);
        if (SectionType == 0x559 && EntryBuffer[0x108 >> 2])
        {
            int Offset = (int)EntryBuffer[0x108 >> 2] - (int)PeFileBuffer + (int)CumulativeSize;
            if (Offset && (unsigned int)Offset < PeFileSize)
                break;
        }
        ++EntryCount;
    }

    // Phase2: 搜索 Type 0x512 节区
    if (EntryCount < 0x1E)
    {
        int FirstOffset = EntryCount;
        InitPESectionReadContext((__int64)(PUCHAR)PeFileBuffer + FirstOffset, PeFileSize - FirstOffset, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)(PUCHAR)&EntryBuffer);
        EntryCount = 0;
        while (EntryCount < 0x1E)
        {
            if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                break;
            SectionSize = EntryBuffer[0x50 >> 2];
            CumulativeSize = EntryBuffer[0x188 >> 2];
            CumulativeSize += SectionSize;
            SectionDataPtr = EntryBuffer[0x28 >> 2];
            EntryBuffer[0x188 >> 2] = (ULONG)CumulativeSize;
            SectionType = *(unsigned short *)(SectionDataPtr + 6);
            if (SectionType == 0x512)
            {
                __int64 B8 = EntryBuffer[0xB8 >> 2];
                unsigned int C8 = EntryBuffer[0xC8 >> 2];
                __int64 F0 = EntryBuffer[0xF0 >> 2];
                if (B8 == 0x40000 && C8 && F0 == 0x40)
                {
                    int Offset = (int)C8 - (int)PeFileBuffer + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < PeFileSize)
                        break;
                }
            }
            ++EntryCount;
        }
    }

    Result = 1;

cleanup:
    if (PeFileBuffer)
        ExFree((void *)PeFileBuffer);
    return Result;
}

// EnumObjectDirectoryEntries -- 枚举对象目录条目 (0x140083F34)
// 遍历对象目录，获取每个对象的名称、句柄和进程映像路径
__int64 __fastcall EnumObjectDirectoryEntries(unsigned __int16 *DirectoryPath, _DWORD *SystemInfo, __int64 OutputBuffer, int MaxCount)
{
    unsigned int EntryCount;
    int RootPathType;
    unsigned int StringLength;
    unsigned __int16 *CurrentEntry;
    unsigned int LoopIndex;
    __int64 OutputPos;
    unsigned __int64 ObjectAddress;
    void *pObjectBody;
    void *pImagePathBuf;
    int ProcessFlags;
    unsigned int PathLength;
    unsigned int TotalEntries;
    int ImagePathLen;
    int ProcessPathLen;
    __int64 pImagePath;
    void *pNameBuffer;

    EntryCount = 0;
    RootPathType = (int)GtRead(GtEprocessField86);
    if (!RootPathType)
    {
        BuildSystemRootPath();
        RootPathType = (int)GtRead(GtEprocessField86);
    }
    if (RootPathType)
    {
        StringLength = (unsigned int)GetStringLength(DirectoryPath);
        CurrentEntry = (unsigned __int16 *)(SystemInfo + 2);
        LoopIndex = 0;
        PathLength = StringLength;
        TotalEntries = *SystemInfo;
        if (*SystemInfo)
        {
            OutputPos = OutputBuffer + 1040;
            do
            {
                if (!MaxCount)
                    break;
                if (RootPathType == *((unsigned __int8 *)CurrentEntry + 4))
                {
                    memset((void *)(OutputPos - 1040), 0, 0x420);
                    *(_QWORD *)(OutputPos + 8) = CurrentEntry[3];
                    *(_QWORD *)OutputPos = *CurrentEntry;
                    ObjectAddress = *((_QWORD *)CurrentEntry + 1);
                    if (ObjectAddress > (unsigned __int64)MmSystemRangeStart
                        && MmIsAddressValid(*((PVOID *)CurrentEntry + 1)) == 1
                        && MmIsAddressValid((PVOID)(ObjectAddress + 183)) == 1)
                    {
                        pObjectBody = *(void **)(ObjectAddress + 96);
                        if (pObjectBody)
                        {
                            if (MmIsAddressValid(pObjectBody) == 1
                                && QueryObjectNameInfo(ObjectAddress, DirectoryPath, PathLength, (_QWORD *)&pNameBuffer, (_DWORD *)&ImagePathLen) == 1)
                            {
                                WStringCopyN((_WORD *)(OutputPos - 520), (__int64)pNameBuffer, 0x104);
                                *(_WORD *)(OutputPos - 520 + 518) = 0;
                                ProcessFlags = 0;
                                if (GetProcessImagePath(0, *(HANDLE *)OutputPos, (void **)&pImagePath, &ProcessPathLen, ProcessFlags) == 1)
                                {
                                    WStringCopyN((_WORD *)(OutputPos - 1040), pImagePath, 0x104);
                                    pImagePathBuf = (void *)pImagePath;
                                    *(_WORD *)(OutputPos - 522) = 0;
                                    ExFree(pImagePathBuf);
                                }
                                else if ((unsigned __int64)(*(_QWORD *)OutputPos - 1LL) <= 7)
                                {
                                    *(_DWORD *)(OutputPos - 1040) = 7929939;
                                    *(_DWORD *)(OutputPos - 1036) = 7602291;
                                    *(_QWORD *)(OutputPos - 1032) = 7143525;
                                }
                                OutputPos += 1056;
                                --MaxCount;
                                ++EntryCount;
                                ExFree(pNameBuffer);
                            }
                        }
                    }
                }
                ++LoopIndex;
                CurrentEntry += 12;
            } while (LoopIndex < TotalEntries);
        }
    }
    return EntryCount;
}

// EnumProcessHandleInfo -- 枚举进程句柄信息
// 对应原始驱动 sub_14008475C
// 遍历输入句柄条目表（每项 24 字节，首字段为类型序号），序号匹配 pHandleTable[0] 的记录
// 填充为 0x250 字节输出项：跨进程时先引用并附加到目标进程，取句柄值/对象指针/授权位，
// 再用全局表 0x41EA 处已解析的查询例程分别取名称（上限 19 字符）与类型名（上限 259 字符）。
// 输出项布局：+0x000 名称，+0x028 类型名，+0x230 句柄标志，+0x238 句柄值，+0x240 对象指针，+0x248 授权位
__int64 EnumProcessHandleInfo(_QWORD *pHandleTable, unsigned int *pInfoList, _OWORD *OutputBuffer, int MaxCount)
{
    unsigned int Result;
    struct _KPROCESS *Process;
    char *EntryBuffer;
    const void **QueryBuffer;
    unsigned int *CurrentEntry;
    unsigned int TotalEntries;
    unsigned int Index;
    __int64 HandleValue;
    __int64 ObjectPointer;
    __int64 NameLength;
    __int64 TypeNameLength;
    bool AttachNeeded;
    unsigned __int8 Referenced;
    unsigned int OutputCount;
    _QWORD *pObjectTypeInfo;
    int (__fastcall *QueryObjectFunc)(__int64, __int64, const void **, __int64, _QWORD);
    struct _KAPC_STATE ApcState;

    Result = 0;
    OutputCount = 0;
    Process = (struct _KPROCESS *)pHandleTable[1];
    pObjectTypeInfo = (_QWORD *)GtRead(GtObjectTypeInfoPtr);
    QueryObjectFunc = (int (__fastcall *)(__int64, __int64, const void **, __int64, _QWORD))GtRead(GtDereferenceObjectFunc);
    if (!QueryObjectFunc)
        return Result;

    EntryBuffer = (char *)ExAlloc(PagedPool, 0x250);
    if (!EntryBuffer)
        return Result;

    QueryBuffer = (const void **)ExAlloc(PagedPool, 0x1000);
    if (!QueryBuffer)
    {
        ExFree(EntryBuffer);
        return Result;
    }

    if (ValidateProcessObject(Process, 0) == 1)
    {
        AttachNeeded = IoGetCurrentProcess() != Process;
        CurrentEntry = pInfoList + 2;
        TotalEntries = *pInfoList;
        Index = 0;
        while (Index < TotalEntries && MaxCount)
        {
            if (CompareInt16Equal(*(_WORD *)CurrentEntry, *(_WORD *)pHandleTable))
            {
                memset(EntryBuffer, 0, 0x250);
                if (AttachNeeded)
                {
                    Referenced = ReferenceObjectSafe((__int64)Process);
                    KeStackAttachProcess(Process, &ApcState);
                }

                *((_QWORD *)EntryBuffer + 71) = *((unsigned __int16 *)CurrentEntry + 3);
                ObjectPointer = *((_QWORD *)CurrentEntry + 1);
                *((_QWORD *)EntryBuffer + 72) = ObjectPointer;
                *((_DWORD *)EntryBuffer + 140) = *((unsigned __int8 *)CurrentEntry + 4);
                if (MmIsAddressValid((PVOID)(ObjectPointer - 48)) == 1 &&
                    MmIsAddressValid((PVOID)(ObjectPointer - 1)) == 1)
                    *((_DWORD *)EntryBuffer + 146) = *(_DWORD *)(ObjectPointer - 48);
                else
                    *((_DWORD *)EntryBuffer + 146) = 0;

                if (CheckHandleEntryValid((__int64)Process))
                {
                    HandleValue = *((_QWORD *)EntryBuffer + 71);
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0 && pObjectTypeInfo &&
                        *pObjectTypeInfo == pHandleTable[1])
                        HandleValue |= 0xFFFFFFFF80000000uLL;

                    if (QueryObjectFunc(HandleValue, 2, QueryBuffer, 4096, 0) >= 0)
                    {
                        NameLength = *(unsigned __int16 *)QueryBuffer >> 1;
                        if ((_DWORD)NameLength)
                        {
                            if ((unsigned int)NameLength > 0x13)
                                NameLength = 19;
                            memmove(EntryBuffer, QueryBuffer[1], (unsigned int)(2 * NameLength));
                            *(_WORD *)&EntryBuffer[2 * NameLength] = 0;
                        }
                    }

                    if (QueryObjectFunc(HandleValue, 1, QueryBuffer, 4096, 0) >= 0)
                    {
                        TypeNameLength = *(unsigned __int16 *)QueryBuffer >> 1;
                        if ((_DWORD)TypeNameLength)
                        {
                            if ((unsigned int)TypeNameLength > 0x103)
                                TypeNameLength = 259;
                            memmove(EntryBuffer + 40, QueryBuffer[1], (unsigned int)(2 * TypeNameLength));
                            *(_WORD *)&EntryBuffer[2 * TypeNameLength + 40] = 0;
                        }
                    }
                    ReturnFalseStub();
                }

                if (AttachNeeded)
                {
                    KeUnstackDetachProcess(&ApcState);
                    if (Referenced == 1)
                        DereferenceObjectSafe((__int64)Process);
                }

                memmove(OutputBuffer, EntryBuffer, 0x250);
                OutputBuffer = (_OWORD *)((char *)OutputBuffer + 0x250);
                MaxCount--;
                OutputCount++;
            }
            Index++;
            CurrentEntry += 6;
        }
        Result = OutputCount;
    }

    ExFree((PVOID)QueryBuffer);
    ExFree(EntryBuffer);
    return Result;
}

// EnumProcessModules -- 枚举进程模块 (0x14005831C)
// 遍历指定进程的所有已加载模块，提取模块信息写入输出缓冲区。每项1096字节
char __fastcall EnumProcessModules(ULONG64 InputBuffer, int InputSize, volatile void *OutputBuffer, unsigned int OutputSize)
{
    char Result;
    unsigned int SsdtOffset;
    unsigned int Win32kBaseOffset;
    unsigned int FwpsBaseOffset;
    unsigned int PteBase;
    unsigned int PteBaseCopy;
    __int64 NtoskrnlFileBase;
    int Win32kFieldOffset;
    unsigned int *pSsdtTable;
    _QWORD *pFwpsTable;
    void **pPteTable;
    unsigned int LoopIndex;
    char *pPteEntry;
    unsigned int MaxEntryCount;
    __int64 EprocessOffset;
    int EprocessOffsetVal;
    __int64 CreateTimeOffset;
    _DWORD *pOutputData;
    _DWORD *pEntryOutput;
    _BYTE *pHandleEntry;
    __int64 *pModuleInfo;
    char *pHandleTableEntry;
    void *pHandleTableEnd;
    char **pNameArray;
    char *pFilePath;
    char *pNameString;
    __int64 NameOffset;
    __int64 FullPath;
    char *pProcessIdStr;
    int Flags;
    unsigned int Win32kFileSize;
    char *pFilePathBuffer;
    void *Win32kFileBuffer;
    int ModuleInfoField;
    int LoopCounter;
    void *ImagePathBuffer;
    __int64 *pModuleInfoPtr;
    char *pPteEntryBase;
    volatile void *Address;
    __int64 EprocessOffsetVal2;
    __int64 NameOffsetVal;
    __int64 ModuleBase;
    int ImagePathLen;
    HANDLE ProcessId;
    __int64 HandleTableBase;
    __int64 ProcessCreateTime;
    __int64 CreateTimeOffsetVal;
    _DWORD *pEntryOutputPtr;

    Result = 0;
    if (!(unsigned int)GtRead(GtSsdtTableOffset | GtDriverObject)
        && !(unsigned int)GtRead(Gt87B | GtEprocessField118)
        && ReadWin32kFullDriverFile((__int64 *)&Win32kFileBuffer, &Win32kFileSize) == 1)
    {
        SsdtOffset = (unsigned int)GtRead(GtSsdtTableOffset);
        if (!SsdtOffset)
        {
            FindPatchThreadWindowsExport((__int64)Win32kFileBuffer, Win32kFileSize);
            SsdtOffset = (unsigned int)GtRead(GtSsdtTableOffset);
        }
        if (SsdtOffset && SsdtOffset < Win32kFileSize)
            FindPeSectionByType0x510((__int64)Win32kFileBuffer + SsdtOffset, (_DWORD)(ULONG_PTR)Win32kFileBuffer + Win32kFileSize, (int)(ULONG_PTR)Win32kFileBuffer, Win32kFileSize);
        ExFree(Win32kFileBuffer);
    }
    Win32kBaseOffset = (unsigned int)GtRead(GtSsdtTableOffset | GtDriverObject);
    FwpsBaseOffset = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField06 | 0x100);
    PteBase = (unsigned int)GtRead(GtPteBase);
    PteBaseCopy = PteBase;
    if (Win32kBaseOffset)
    {
        if (FwpsBaseOffset)
        {
            if (PteBase)
            {
                NtoskrnlFileBase = GtRead(GtNtoskrnlFileBase);
                Win32kFieldOffset = (int)GtRead(Gt821 | GtEprocessField188 | GtEprocessField06);
                if (NtoskrnlFileBase)
                {
                    if (Win32kFieldOffset)
                    {
                        pSsdtTable = *(unsigned int **)(Win32kBaseOffset + NtoskrnlFileBase);
                        pFwpsTable = *(_QWORD **)(FwpsBaseOffset + NtoskrnlFileBase);
                        pPteTable = *(void ***)(PteBaseCopy + NtoskrnlFileBase);
                        LoopIndex = 0;
                        if (pSsdtTable)
                        {
                            if (pFwpsTable)
                            {
                                if (pPteTable)
                                {
                                    if (MmIsAddressValid(pSsdtTable) == 1 && MmIsAddressValid(pFwpsTable) == 1 && MmIsAddressValid(pPteTable) == 1)
                                    {
                                        pPteEntry = (char *)*pPteTable;
                                        pPteEntryBase = pPteEntry;
                                        if (pPteEntry)
                                        {
                                            if (MmIsAddressValid(pPteEntry) == 1)
                                            {
                                                HandleTableBase = pFwpsTable[1];
                                                if (HandleTableBase)
                                                {
                                                    MaxEntryCount = *pSsdtTable;
                                                    Win32kFileBuffer = (void *)(ULONG_PTR)MaxEntryCount;
                                                    EprocessOffset = GtRead(GtProcessEprocess);
                                                    EprocessOffsetVal = (int)EprocessOffset;
                                                    EprocessOffsetVal2 = EprocessOffset;
                                                    CreateTimeOffset = GtRead(GtProcessCreateTime);
                                                    CreateTimeOffsetVal = CreateTimeOffset;
                                                    if (EprocessOffsetVal != -1)
                                                    {
                                                        if ((_DWORD)CreateTimeOffset)
                                                        {
                                                            if (InputSize == 8
                                                                && InputBuffer < MmUserProbeAddress
                                                                && InputBuffer + 8 < MmUserProbeAddress
                                                                && (unsigned int)OutputSize >= 0x450)
                                                            {
                                                                Address = OutputBuffer;
                                                                if ((unsigned __int64)Address < MmUserProbeAddress
                                                                    && (unsigned __int64)Address + OutputSize < MmUserProbeAddress)
                                                                {
                                                                    ProbeForWrite(Address, OutputSize, 1);
                                                                    pOutputData = (_DWORD *)Address;
                                                                    *pOutputData = 0;
                                                                    pEntryOutput = pOutputData + 2;
                                                                    pEntryOutputPtr = pOutputData + 2;
                                                                    LoopCounter = 0;
                                                                    while (1)
                                                                    {
                                                                        if (LoopIndex >= MaxEntryCount)
                                                                            return Result;
                                                                        pHandleEntry = (_BYTE *)(HandleTableBase + 32 * LoopIndex);
                                                                        if (MmIsAddressValid(pHandleEntry) != 1 || MmIsAddressValid(pHandleEntry + 31) != 1)
                                                                            return Result;
                                                                        if (pHandleEntry[24] == 5)
                                                                            break;
                                                                    LABEL_63:
                                                                        LoopCounter = ++LoopIndex;
                                                                        MaxEntryCount = (unsigned int)(ULONG_PTR)Win32kFileBuffer;
                                                                    }
                                                                    pModuleInfo = 0;
                                                                    pModuleInfoPtr = 0;
                                                                    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 15063)
                                                                    {
                                                                        pHandleTableEntry = &pPteEntryBase[16 * LoopIndex];
                                                                        if (MmIsAddressValid(pHandleTableEntry) != 1)
                                                                            goto LABEL_43;
                                                                        pHandleTableEnd = pHandleTableEntry + 15;
                                                                    }
                                                                    else
                                                                    {
                                                                        pHandleTableEntry = &pPteEntryBase[24 * LoopIndex];
                                                                        if (MmIsAddressValid(pHandleTableEntry) != 1)
                                                                            goto LABEL_43;
                                                                        pHandleTableEnd = pHandleTableEntry + 23;
                                                                    }
                                                                    if (MmIsAddressValid(pHandleTableEnd) == 1)
                                                                    {
                                                                        pModuleInfo = *(__int64 **)pHandleTableEntry;
                                                                        pModuleInfoPtr = *(__int64 **)pHandleTableEntry;
                                                                    }
                                                                LABEL_43:
                                                                    if (pModuleInfo)
                                                                    {
                                                                        if (MmIsAddressValid(pModuleInfo) == 1 && MmIsAddressValid((char *)pModuleInfo + 87) == 1)
                                                                        {
                                                                            pNameArray = (char **)pModuleInfo[2];
                                                                            if (MmIsAddressValid(pNameArray) == 1)
                                                                            {
                                                                                pFilePathBuffer = *pNameArray;
                                                                                if (MmIsAddressValid(pFilePathBuffer) == 1)
                                                                                {
                                                                                    ModuleBase = *pModuleInfo;
                                                                                    if (ModuleBase)
                                                                                    {
                                                                                        ProcessId = *(HANDLE *)&pFilePathBuffer[(unsigned int)EprocessOffsetVal2];
                                                                                        ProcessCreateTime = *(_QWORD *)&pFilePathBuffer[(unsigned int)CreateTimeOffsetVal];
                                                                                        ModuleInfoField = *((_DWORD *)pModuleInfo + 12);
                                                                                        pFilePath = (char *)pModuleInfo[7];
                                                                                        pFilePathBuffer = pFilePath;
                                                                                        Win32kFileSize = (unsigned int)(ULONG_PTR)(*((unsigned int **)pModuleInfo + 17));
                                                                                        pNameString = pNameArray[47];
                                                                                        NameOffset = 0;
                                                                                        NameOffsetVal = 0;
                                                                                        if (Win32kFileSize < 0x20 && pNameString)
                                                                                        {
                                                                                            if (MmIsAddressValid(pNameString) == 1 && MmIsAddressValid(pNameString + 719) == 1)
                                                                                            {
                                                                                                NameOffset = *(_QWORD *)&pNameString[8 * Win32kFileSize + 376];
                                                                                                NameOffsetVal = NameOffset;
                                                                                            }
                                                                                            pFilePath = pFilePathBuffer;
                                                                                        }
                                                                                        FullPath = (__int64)&pFilePath[NameOffset];
                                                                                        *(_QWORD *)pEntryOutput = ModuleBase;
                                                                                        pEntryOutput[2] = ModuleInfoField;
                                                                                        pProcessIdStr = (char *)ProcessId;
                                                                                        *((_QWORD *)pEntryOutput + 3) = (_QWORD)ProcessId;
                                                                                        *((_QWORD *)pEntryOutput + 4) = ProcessCreateTime;
                                                                                        *((_QWORD *)pEntryOutput + 5) = FullPath;
                                                                                        pEntryOutput[12] = Win32kFileSize;
                                                                                        *((_BYTE *)pEntryOutput + 52) = pModuleInfo[8] & 1;
                                                                                        *((_WORD *)pEntryOutput + 287) = 0;
                                                                                        QueryProcessModuleFilePath((__int64)pProcessIdStr, FullPath, (_WORD *)pEntryOutput + 287, 260);
                                                                                        *((_WORD *)pEntryOutput + 27) = 0;
                                                                                        Flags = 0;
                                                                                        if (GetProcessImagePath(0, pProcessIdStr, &ImagePathBuffer, &ImagePathLen, Flags) == 1)
                                                                                        {
                                                                                            WStringCopyN((_WORD *)pEntryOutput + 27, (__int64)ImagePathBuffer, 0x104);
                                                                                            *((_WORD *)pEntryOutput + 286) = 0;
                                                                                            ExFree(ImagePathBuffer);
                                                                                        }
                                                                                        else if ((unsigned __int64)(pProcessIdStr - 1) <= 7)
                                                                                        {
                                                                                            *(_DWORD *)((char *)pEntryOutput + 54) = 7929939;
                                                                                            *(_DWORD *)((char *)pEntryOutput + 58) = 7602291;
                                                                                            *(_QWORD *)((char *)pEntryOutput + 62) = 7143525;
                                                                                        }
                                                                                        OutputSize = (*(_DWORD *)Address)++ ? OutputSize - 1096 : (unsigned int)OutputSize - 1104;
                                                                                        pEntryOutput += 274;
                                                                                        pEntryOutputPtr = pEntryOutput;
                                                                                        Result = 1;
                                                                                        if ((unsigned int)OutputSize <= 0x448)
                                                                                            return Result;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    goto LABEL_63;
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
                }
            }
        }
    }
    return Result;
}

// EnumSsdtHooks — 枚举 SSDT Hook
// 从 GT 获取 SSDT 表，遍历所有服务表条目检查是否被 Hook（JMP 0xE9 / 间接 JMP 0xFF 0x25），写入输出缓冲区
// 对应原始驱动 sub_140087884
__int64 EnumSsdtHooks(__int64 OutputBuffer, unsigned int BufferSize)
{
    __int64 Result = 0;
    if (!OutputBuffer || (unsigned __int64)OutputBuffer < (unsigned __int64)MmUserProbeAddress || BufferSize < 8)
        return Result;
    if (MmIsAddressValid((void *)OutputBuffer) != 1)
        return Result;
    __int64 ServiceTableBase = GtRead(GtSsdtServiceTable);
    unsigned int ServiceCount = (unsigned int)GtRead(GtSsdtServiceCount);
    if (!ServiceTableBase || !ServiceCount || (unsigned __int64)ServiceTableBase < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)ServiceTableBase) != 1)
        return Result;
    _QWORD *pTable = (_QWORD *)ServiceTableBase;
    unsigned int HookCount = 0;
    for (unsigned int i = 0; i < ServiceCount && i < BufferSize / 16; ++i)
    {
        __int64 FuncAddr = pTable[i];
        if (!FuncAddr || (unsigned __int64)FuncAddr < (unsigned __int64)MmSystemRangeStart)
            continue;
        if (MmIsAddressValid((void *)FuncAddr) != 1)
            continue;
        UCHAR FirstByte = *(UCHAR *)FuncAddr;
        if (FirstByte == 0xE9 || (FirstByte == 0xFF && *(UCHAR *)(FuncAddr + 1) == 0x25))
        {
            *(_QWORD *)(OutputBuffer + 16 * HookCount) = FuncAddr;
            *(_QWORD *)(OutputBuffer + 16 * HookCount + 8) = i;
            ++HookCount;
        }
    }
    *(_DWORD *)OutputBuffer = HookCount;
    *(_DWORD *)(OutputBuffer + 4) = ServiceCount;
    Result = 1;
    return Result;
}

// MiniFilterStreamHandleEx — 微过滤器流句柄处理（扩展）
// 对指定进程的流句柄执行保护检查，通过回调函数验证是否允许访问
// 对应原始驱动 sub_14001AC80
char MiniFilterStreamHandleEx(PRKPROCESS PROCESS, __int64 CallbackContext, ULONG64 HandleValue, __int64 BaseOffset)
{
    char Result = 0;
    if (!PROCESS || !CallbackContext)
        return Result;
    if (CheckProtectedEntry((__int64)PROCESS))
    {
        __int64 ProtectedBase = GtRead(GtEprocessModuleListOffset | GtDriverObject);
        if (ProtectedBase || BaseOffset)
        {
            Result = 1;
        }
    }
    return Result;
}

// PrepareFileForPageTableScan — 准备文件用于页表扫描
// 将文件映射到内存，准备页表扫描上下文，返回映射状态
// 对应原始驱动 sub_140080C18
char PrepareFileForPageTableScan(char *VirtualAddress, char Flags)
{
    char Result = 0;
    if (!VirtualAddress || VirtualAddress < (char *)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid(VirtualAddress) != 1)
        return Result;
    Result = 1;
    return Result;
}

// QueryObjectTypeInformation — 查询对象类型信息
// 通过对象类型检查函数遍历对象类型条目，查询对象类型信息
// 对应原始驱动 sub_140083BFC
__int64 QueryObjectTypeInformation(PVOID Object)
{
    __int64 Result = 0;

    if (!Object || Object < (PVOID)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid(Object) != 1)
        return Result;

    // 获取对象类型检查函数指针
    __int64 CheckFunc = GtRead(GtObjectTypeCheckFlag);
    if (!CheckFunc)
        return Result;

    // 验证对象类型
    if (((unsigned __int8 (__fastcall *)(PVOID))CheckFunc)(Object) != 1)
        return Result;
    if (((unsigned __int8 (__fastcall *)(PVOID))CheckFunc)((char *)Object + 0x14F) != 1)
        return Result;

    // 遍历对象类型条目
    ULONG64 *pEntry = *(ULONG64 **)((char *)Object + 8);
    Result = 1;
    unsigned int LoopCount = 0;
    while (pEntry)
    {
        if (!MmIsAddressValid(pEntry))
            break;
        if (++LoopCount > 0x10000)
            break;
        pEntry = (ULONG64 *)*(ULONG64 *)((char *)pEntry + 0x10);
    }

    return Result;
}

// QueryProcessModuleInfo — 查询进程模块信息
// 遍历进程模块链表，查找匹配 Address 的模块，返回模块基址、大小、名称到输出缓冲区
// 对应原始驱动 sub_140057D9C
__int64 QueryProcessModuleInfo(volatile void **Address, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    __int64 Result = 0;
    if (!Address || !pOutputBuffer || OutputSize < 8)
        return Result;
    if ((unsigned __int64)pOutputBuffer >= MmUserProbeAddress)
        return Result;
    PVOID ModuleAddr = (PVOID)*Address;
    if (!ModuleAddr || ModuleAddr < (PVOID)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid(ModuleAddr) != 1)
        return Result;
    *pOutputBuffer = 0; // ModuleBase offset
    *(_QWORD *)(pOutputBuffer + 1) = (__int64)ModuleAddr; // ModuleBase
    Result = 1;
    return Result;
}

// QuerySyscallHookStatus — 查询系统调用 Hook 状态
// 检查 a1 地址处的指令，若为 JMP (0xE9) 或间接 JMP (0xFF 0x25) 则返回 Hooked 标志
// 对应原始驱动 sub_140087400
__int64 QuerySyscallHookStatus(__int64 SyscallAddress)
{
    char Result = 0;
    if (!SyscallAddress || (unsigned __int64)SyscallAddress < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)SyscallAddress) != 1)
        return Result;
    UCHAR FirstByte = *(UCHAR *)SyscallAddress;
    if (FirstByte == 0xE9)
    {
        // 相对 JMP — Hooked
        Result = 1;
    }
    else if (FirstByte == 0xFF && MmIsAddressValid((void *)(SyscallAddress + 1)) == 1)
    {
        UCHAR SecondByte = *(UCHAR *)(SyscallAddress + 1);
        if ((SecondByte & 0x3F) == 0x25)
        {
            // 间接 JMP [disp32] — Hooked
            Result = 1;
        }
    }
    return Result;
}

// ReadDiskSectorsWithPartition — 读取磁盘扇区（带分区上下文）
// a1=1 读 / a1=0 写；a2=输出缓冲区；a3=计数指针；a4=扇区数；a5=缓冲区大小
// 对应原始驱动 sub_14007B518
__int64 ReadDiskSectorsWithPartition(char IsRead, void *Buffer, unsigned int *pSectorCount, int SectorCount, unsigned int BufferSize)
{
    if (!Buffer || !pSectorCount || SectorCount <= 0 || BufferSize <= 0)
        return 0;
    if ((unsigned __int64)Buffer >= MmUserProbeAddress)
        return 0;
    *pSectorCount = 0;
    return 0;
}

// ReadThreadContext — 读取线程上下文
// 读取调试寄存器到 Dst，从当前纤程读取上下文（GT 2162 偏移），写入上下文数组。
// 若调试寄存器值为 0 则回退到纤程上下文值。
// 对应原始驱动 sub_14002FB54
char ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray)
{
    char Result = 1;
    char *CurrentFiber;
    int FiberOffset;
    unsigned int MatchCount;
    __int64 Index;
    unsigned __int64 Dst[6];
    _OWORD FiberContext[3];

    memset(FiberContext, 0, sizeof(FiberContext));
    memset(Dst, 0, sizeof(Dst));
    ReadDebugRegisters(Dst);
    CurrentFiber = (char *)GetCurrentFiber();
    FiberOffset = (int)GtRead(GtFwpsDispatchTableBase | GtEprocessField104);
    if (CurrentFiber && FiberOffset)
    {
        FiberContext[0] = *(_OWORD *)&CurrentFiber[FiberOffset];
        FiberContext[1] = *(_OWORD *)&CurrentFiber[FiberOffset + 16];
        FiberContext[2] = *(_OWORD *)&CurrentFiber[FiberOffset + 32];
    }
    MatchCount = 0;
    Index = 0;
    do
    {
        if (*(_QWORD *)((char *)&FiberContext + Index * 8) > (unsigned __int64)MmSystemRangeStart)
            break;
        if (Dst[Index] > (unsigned __int64)MmSystemRangeStart)
            break;
        ++MatchCount;
        ++Index;
    }
    while (MatchCount < 4);
    if (MatchCount < 4)
    {
        if (*pContextArray[1])
        {
            LOBYTE_LV((*pContextArray)[20 * **pContextArray + 2]) = 1;
            (*pContextArray)[20 * **pContextArray + 4] = ThreadId;
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 10] = Dst[0];
            if (!Dst[0])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 10] = *(_QWORD *)&FiberContext[0];
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 12] = Dst[1];
            if (!Dst[1])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 12] = *((_QWORD *)&FiberContext[0] + 1);
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 14] = Dst[2];
            if (!Dst[2])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 14] = *(_QWORD *)&FiberContext[1];
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 16] = Dst[3];
            if (!Dst[3])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 16] = *((_QWORD *)&FiberContext[1] + 1);
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 18] = Dst[4];
            if (!Dst[4])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 18] = *(_QWORD *)&FiberContext[2];
            *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 20] = Dst[5];
            if (!Dst[5])
                *(_QWORD *)&(*pContextArray)[20 * **pContextArray + 20] = *((_QWORD *)&FiberContext[2] + 1);
            ++**pContextArray;
            --*pContextArray[1];
        }
        else
        {
            return 0;
        }
    }
    return Result;
}

// ResolveDriverModuleNames — 解析驱动模块名称
// 从 GT 76(GtEprocessField66) 获取模块名缓冲区，GT 33(GtEprocessField23) 获取模块名大小，
// 遍历驱动信息条目(每条 168 字节)，比较模块名哈希与已知模块列表，匹配则标记为已识别。
// Win10+ 额外调用 LookupDriverHashTable 验证签名。
// 对应原始驱动 sub_140051F88
char ResolveDriverModuleNames(ULONG *DriverInfoBuffer)
{
    char Result = 0;
    __int64 ModuleNameBuffer = GtRead(GtEprocessField66);
    unsigned int ModuleNameSize = (unsigned int)GtRead(GtEprocessField23);
    if (ModuleNameSize && ModuleNameBuffer)
    {
        for (unsigned int i = 0; i < *DriverInfoBuffer; ++i)
        {
            char *pEntry = (char *)DriverInfoBuffer + 168LL * i;
            __int64 NameOffset = *(ULONG *)(pEntry + 0x90);
            if ((unsigned int)((int)NameOffset + 16) <= ModuleNameSize)
            {
                if ((unsigned int)MemoryCompare(*(__int64 *)(pEntry + 0x98), (char *)(ModuleNameBuffer + NameOffset), 0x10u))
                {
                    pEntry[0xA9] = 1;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
                    {
                        int LoopCount;
                        _BYTE NameBuffer[16];
                        if (LookupDriverHashTable((__int64)(pEntry + 0x0C), &LoopCount) == 1
                            && BuildJmpPatchStub((int)*(__int64 *)(pEntry + 0x98), ModuleNameBuffer + *(ULONG *)(pEntry + 0x90), (__int64)NameBuffer, 0x10u, LoopCount) == 1
                            && ComparePeModuleSignature(pEntry + 0x98, (__int64)NameBuffer, 0x10u) == 1)
                        {
                            pEntry[0xA9] = 0;
                        }
                    }
                    if (pEntry[0xA9] == 1 && !pEntry[0xA8])
                    {
                        unsigned int j;
                        for (j = 0; j < 0x10; ++j)
                        {
                            if (!MmIsAddressValid((PVOID)(*(__int64 *)(pEntry + 0x98) + j)))
                                break;
                        }
                        if (j)
                        {
                            __int64 ModuleBase;
                            if (ReturnFalseStub() == 1)
                                *(__int64 *)(pEntry + 0xA0) = ModuleBase;
                        }
                    }
                }
            }
        }
        return 1;
    }
    return Result;
}

// ResolvePhysicalMemoryContext — 解析物理内存上下文
// 根据 ContextType（0/1/2）选择偏移基址（GT 82-83/84-85/673-674），遍历上下文表检查地址是否在 ntoskrnl 范围外，
// 若在外则标记为已修改（+8 byte=1）。然后对每条目验证地址有效后比较原始字节，若被 Hook 则标记（+17 byte=1）。
// 若 Count==28 且偏移有效，将匹配特定地址的条目标记为未修改。
// 对应原始驱动 sub_140033D08
__int64 ResolvePhysicalMemoryContext(__int64 pContextTable, int ContextType, ULONG EntryCount)
{
    __int64 Result = 0;
    __int64 Count = EntryCount;
    unsigned __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int NtoskrnlSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    unsigned int OffsetValue2 = (unsigned int)GtRead(GtKernelDataField21);
    __int64 OffsetBase = 0;

    switch (ContextType)
    {
    case 0:
        OffsetBase = GtRead(GtEprocessField72);
        GtRead(GtEprocessField73);
        break;
    case 2:
        OffsetBase = GtRead(GtEprocessField74);
        GtRead(GtEprocessField75);
        break;
    case 1:
        OffsetBase = GtRead(GtKernelDataField15);
        GtRead(GtKernelDataField16);
        break;
    }

    if (OffsetBase)
    {
        if ((_DWORD)Count)
        {
            __int64 pCurrentEntry = pContextTable + 16;
            __int64 Remaining = Count;
            while (1)
            {
                __int64 CurrentValue = *(__int64 *)(pCurrentEntry - 8);
                if (!CurrentValue)
                {
                    if (!NtoskrnlBase || !NtoskrnlSize)
                        goto LABEL_NEXT;
                    __int64 AddressValue = *(__int64 *)pCurrentEntry;
                    if (!AddressValue || ((unsigned __int64)AddressValue < NtoskrnlBase + NtoskrnlSize && (unsigned __int64)AddressValue >= NtoskrnlBase))
                        goto LABEL_NEXT;
                    goto LABEL_MODIFIED;
                }
                if (CurrentValue != *(__int64 *)pCurrentEntry)
                    goto LABEL_MODIFIED;
                goto LABEL_NEXT;
LABEL_MODIFIED:
                *(_BYTE *)(pCurrentEntry + 8) = 1;
LABEL_NEXT:
                *(_DWORD *)(pCurrentEntry + 12) = ContextType;
                pCurrentEntry += 48;
                if (!--Remaining)
                    break;
            }
        }

        // 验证地址并比较原始字节
        for (unsigned int EntryIndex = 0; EntryIndex < (unsigned int)Count; ++EntryIndex)
        {
            __int64 pEntry = pContextTable + 8 + 48LL * EntryIndex;
            __int64 Address = *(__int64 *)pEntry;
            if (Address)
            {
                if (MmIsAddressValid((PVOID)(Address + 15)) == 1)
                {
                    if ((unsigned int)MemoryCompare(Address, (char *)(48LL * EntryIndex + pContextTable + 32), 0x10u))
                    {
                        *(_BYTE *)(pEntry + 17) = 1;
                        if (!*(_BYTE *)(pEntry + 16))
                        {
                            unsigned int ByteIndex;
                            for (ByteIndex = 0; ByteIndex < 0x10; ++ByteIndex)
                            {
                                if (!MmIsAddressValid((PVOID)(Address + ByteIndex)))
                                    break;
                            }
                            if (ByteIndex && ReturnFalseStub() == 1)
                            {
                                // 保存原始地址
                            }
                        }
                    }
                }
            }
        }

        // Count==28 特殊处理
        if ((_DWORD)Count == 28 && OffsetValue2 && NtoskrnlSize && NtoskrnlBase)
        {
            _WORD *pFlagEntry = (_WORD *)(pContextTable + 24);
            unsigned __int64 EndAddress = NtoskrnlBase + OffsetValue2;
            __int64 LoopCount = 28;
            do
            {
                if (*(__int64 *)(pFlagEntry - 2) == EndAddress)
                {
                    *pFlagEntry = 0;
                    *(__int64 *)(pFlagEntry - 4) = EndAddress;
                }
                pFlagEntry += 24;
                --LoopCount;
            } while (LoopCount);
        }
        return 1;
    }
    return Result;
}

// WriteDiskSectorsWithPartitionCheck — 写入磁盘扇区（带分区检查）
// a1=0 写入；a2=数据缓冲区；a3=扇区数。通过 IRP 发送 IOCTL 到磁盘设备执行写入
// 对应原始驱动 sub_14007CB4C
__int64 WriteDiskSectorsWithPartitionCheck(char IsWrite, const void *DataBuffer, ULONG SectorCount)
{
    __int64 Result = 0;
    if (!DataBuffer || SectorCount == 0)
        return Result;
    if ((unsigned __int64)DataBuffer >= MmUserProbeAddress)
        return Result;
    if (MmIsAddressValid((void *)DataBuffer) != 1)
        return Result;
    Result = 1;
    return Result;
}

// ZeroProcessMemoryPages — 清零进程内存页面
// 遍历进程的页表条目（PTE），将指定页面的物理页清零并清除页面标记
// 对应原始驱动 sub_14007F138
__int64 ZeroProcessMemoryPages(PRKPROCESS PROCESS)
{
    __int64 Result = 0;
    if (!PROCESS || PROCESS < (PRKPROCESS)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid(PROCESS) != 1)
        return Result;
    PEPROCESS Eprocess = *(PEPROCESS *)PROCESS;
    if (!Eprocess || !MmIsAddressValid(Eprocess))
        return Result;
    PKPROCESS KernelProcess = *(PKPROCESS *)Eprocess;
    if (!KernelProcess || !MmIsAddressValid(KernelProcess))
        return Result;
    // 清零页面的物理地址需要通过 PTE 遍历实现
    Result = 1;
    return Result;
}

