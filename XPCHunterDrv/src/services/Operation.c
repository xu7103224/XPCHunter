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
extern char SendIoControlWithVersionBranch(char *OutputBuffer, int Command, int *UnicodeString, int Param2, void *OutputBuf, SIZE_T OutputSize, __int64 Context);
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
extern __int64 ResolveKernelModuleBasePair(__int64 Address, __int64 Size, _QWORD *pResult, __int64 Flags);
extern char ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray);
extern __int64 ValidateAndClearProcessContext(__int64 Process, __int64 Flags, __int64 Context, __int64 Result);
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
__int64 DisableObjectProtectOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 DisableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskSectorReadWriteOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectProtectOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
__int64 EnableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumCallbackContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize);
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
__int64 InitObjectCallbackOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize);
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

__int64 CreateFileWithPathOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _WORD *pFilePath = (_WORD *)InputBuffer;
    SIZE_T FilePathLength = (unsigned int)InputSize;
    _QWORD *pFileHandle = (_QWORD *)pOutputBuffer;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    void *FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pFileHandle || OutputSize != 8)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + (unsigned int)FilePathLength >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pFileHandle >= MmUserProbeAddress ||
        (ULONG64)(pFileHandle + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, (unsigned int)FilePathLength, 2);
    ProbeForWrite(pFileHandle, 8, 8);
    LastCharIndex = (LengthCopy >> 1) - 1;
    pFilePath[LastCharIndex] = 0;
    if (!CheckFilePathFilter((__int64)pFilePath, LastCharIndex) &&
        !(unsigned int)CreateFileWithPath(pFilePath, 0, &FileHandle, 0x100081, 0x80, 1, 1, 0x20))
    {
        *pFileHandle = FileHandle;
        return 1;
    }
    return 0;
}

// CloseHandleOperation — 关闭句柄操作
// 对应原始驱动 sub_14002C430
// 验证输入参数，通过 ZwClose 关闭句柄
__int64 CloseHandleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    __int64 *pInputBuffer = (__int64 *)InputBuffer;
    __int64 HandleValue;
    unsigned int PreviousMode;
    struct _KTHREAD *CurrentThread;
    char PrevModeValue;
    int CloseResult;
    __int64 HandleValueCopy;
    __int64 (*pZwClose)(__int64);
    unsigned int Result;

    if (!pInputBuffer || InputSize != 8)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 8, 8);
    HandleValue = *pInputBuffer;
    HandleValueCopy = *pInputBuffer;
    pZwClose = (__int64 (*)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    PreviousMode = GtRead(GtSdstServiceCount);
    Result = PreviousMode;
    if (pZwClose && PreviousMode != -1 && CheckProcessJobObject(HandleValue))
    {
        CurrentThread = KeGetCurrentThread();
        PrevModeValue = *((_BYTE *)CurrentThread + Result);
        *((_BYTE *)CurrentThread + Result) = 0;
        CloseResult = pZwClose(HandleValueCopy);
        *((_BYTE *)CurrentThread + Result) = PrevModeValue;
        return CloseResult >= 0;
    }
    return 0;
}

// QueryFileInfoOperation — 查询文件信息操作
// 对应原始驱动 sub_14002D12C
// 查询文件标准信息，返回文件大小
__int64 QueryFileInfoOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    void **pInputHandle = (void **)InputBuffer;
    _QWORD *pOutputData = (_QWORD *)pOutputData;
    __int64 FileInfo;

    if (!pInputHandle || InputSize != 8)
        return 0;
    if (!pOutputData || OutputSize != 8)
        return 0;
    if ((ULONG64)pInputHandle >= MmUserProbeAddress ||
        (ULONG64)(pInputHandle + 1) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress ||
        (ULONG64)(pOutputData + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputHandle, 8, 8);
    ProbeForWrite(pOutputData, 8, 4);
    if (!(unsigned int)CmdQueryFileStandardInfo(*pInputHandle, &FileInfo))
    {
        *pOutputData = FileInfo;
        return 1;
    }
    return 0;
}

// OpenFileHandleOperation — 打开文件句柄操作
// 对应原始驱动 sub_14002D070
// 查询文件分配大小
__int64 OpenFileHandleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    void **pInputHandle = (void **)InputBuffer;
    _QWORD *pOutputData = (_QWORD *)pOutputData;
    __int64 FileSize;

    if (!pInputHandle || InputSize != 8)
        return 0;
    if (!pOutputData || OutputSize != 8)
        return 0;
    if ((ULONG64)pInputHandle >= MmUserProbeAddress ||
        (ULONG64)(pInputHandle + 1) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress ||
        (ULONG64)(pOutputData + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputHandle, 8, 8);
    ProbeForWrite(pOutputData, 8, 4);
    if (!(unsigned int)CmdQueryFileAllocationSize(*pInputHandle, &FileSize))
    {
        *pOutputData = FileSize;
        return 1;
    }
    return 0;
}

// ReadFileSizeOperation — 读取文件大小操作
// 对应原始驱动 sub_14002D858
// 查询文件标准信息和卷数据
__int64 ReadFileSizeOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    void **pInputBuffer = (void **)InputBuffer;
    void *VolumeLabel;
    __int64 FileStandardInfo;

    if (!pInputBuffer || InputSize != 16)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 2) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 16, 4);
    if (!(unsigned int)CmdQueryFileStandardInfo(*pInputBuffer, &FileStandardInfo) &&
        (__int64)pInputBuffer[1] <= FileStandardInfo)
    {
        VolumeLabel = pInputBuffer[1];
        return (unsigned int)IrpFsctlGetVolumeData(*pInputBuffer, (__int64 *)&VolumeLabel) == 0;
    }
    return 0;
}

// WriteFileOperation — 写入文件操作
// 对应原始驱动 sub_14002D418
// 验证用户缓冲区，通过 IrpWriteFile 写入数据到文件句柄
__int64 WriteFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    ULONG *pInputBuffer = (ULONG *)InputBuffer;
    _DWORD *pBytesWritten = pOutputBuffer;
    ULONG64 BufferSize;
    volatile void *pWriteBuffer;
    union _LARGE_INTEGER *Timeout;
    struct _IO_STATUS_BLOCK IoStatusBlock;

    if (!pInputBuffer || InputSize != 24)
        return 0;
    if (!pBytesWritten || OutputSize != 4)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 6) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pBytesWritten >= MmUserProbeAddress ||
        (ULONG64)(pBytesWritten + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 24, 4);
    ProbeForWrite(pBytesWritten, 4, 4);
    BufferSize = pInputBuffer[4];
    if ((_DWORD)BufferSize)
    {
        pWriteBuffer = (volatile void *)*((_QWORD *)pInputBuffer + 1);
        if (pWriteBuffer)
        {
            if ((ULONG64)pWriteBuffer < MmUserProbeAddress &&
                (ULONG64)pWriteBuffer + BufferSize < MmUserProbeAddress &&
                BufferSize < MmUserProbeAddress)
            {
                ProbeForWrite(pWriteBuffer, BufferSize, 1);
                *((_BYTE *)&Timeout) = 1;
                if ((int)IrpWriteFile(*(void **)pInputBuffer, 0, pInputBuffer[4],
                    *((void **)pInputBuffer + 1), Timeout, &IoStatusBlock) >= 0)
                {
                    *pBytesWritten = IoStatusBlock.Information;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// ReadFileOperation — 读取文件操作
// 对应原始驱动 sub_14002D8F0
// 验证用户缓冲区，通过 IrpReadFileEx 从文件句柄读取数据
__int64 ReadFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    ULONG *pInputBuffer = (ULONG *)InputBuffer;
    _DWORD *pBytesRead = pOutputBuffer;
    ULONG64 BufferSize;
    volatile void *pReadBuffer;
    union _LARGE_INTEGER *Timeout;
    struct _IO_STATUS_BLOCK IoStatusBlock;

    if (!pInputBuffer || InputSize != 24)
        return 0;
    if (!pBytesRead || OutputSize != 4)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 6) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pBytesRead >= MmUserProbeAddress ||
        (ULONG64)(pBytesRead + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 24, 4);
    ProbeForWrite(pBytesRead, 4, 4);
    BufferSize = pInputBuffer[4];
    if ((_DWORD)BufferSize)
    {
        pReadBuffer = (volatile void *)*((_QWORD *)pInputBuffer + 1);
        if (pReadBuffer)
        {
            if ((ULONG64)pReadBuffer < MmUserProbeAddress &&
                (ULONG64)pReadBuffer + BufferSize < MmUserProbeAddress &&
                BufferSize < MmUserProbeAddress)
            {
                ProbeForRead(pReadBuffer, BufferSize, 1);
                *((_BYTE *)&Timeout) = 1;
                if ((int)IrpReadFileEx(*(void **)pInputBuffer, 0, pInputBuffer[4],
                    *((void **)pInputBuffer + 1), Timeout, &IoStatusBlock) >= 0)
                {
                    *pBytesRead = IoStatusBlock.Information;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// ReadDirectoryOperation — 读取目录操作
// 对应原始驱动 sub_14002CD7C
// 验证用户缓冲区，通过 IrpReadFileWithOffset 读取目录内容
__int64 ReadDirectoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    void **pInputBuffer = (void **)InputBuffer;
    ULONG64 FilePathLen;
    void *pOutputData;
    SIZE_T PathSize;
    ULONG64 OutputBufferLen;
    void *pOutputBuffer2;
    unsigned __int64 LastCharIndex;
    _WORD *pFilePath;
    union _LARGE_INTEGER *Timeout;
    __int64 IoStatusBlock;

    if (!pInputBuffer || InputSize != 40)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 5) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 40, 4);
    FilePathLen = *((unsigned int *)pInputBuffer + 4);
    if ((unsigned int)FilePathLen <= 2 || (FilePathLen & 1) != 0)
        return 0;
    pOutputData = pInputBuffer[1];
    if (!pOutputData)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress)
        return 0;
    PathSize = (unsigned int)FilePathLen;
    if ((ULONG64)pOutputData + 2 * FilePathLen >= MmUserProbeAddress ||
        FilePathLen >= MmUserProbeAddress)
        return 0;
    OutputBufferLen = *((unsigned int *)pInputBuffer + 6);
    if ((unsigned int)OutputBufferLen <= 4)
        return 0;
    pOutputBuffer2 = pInputBuffer[4];
    if (!pOutputBuffer2)
        return 0;
    if ((ULONG64)pOutputBuffer2 >= MmUserProbeAddress ||
        (ULONG64)pOutputBuffer2 + OutputBufferLen >= MmUserProbeAddress ||
        OutputBufferLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer[1], PathSize, 1);
    ProbeForWrite(pInputBuffer[4], *((unsigned int *)pInputBuffer + 6), 1);
    LastCharIndex = ((ULONG64)*((unsigned int *)pInputBuffer + 4) - 2) >> 1;
    pFilePath = pInputBuffer[1];
    if (pFilePath[LastCharIndex])
        pFilePath[LastCharIndex] = 0;
    *((_BYTE *)&Timeout) = 1;
    return (unsigned int)IrpReadFileWithOffset(
        *pInputBuffer, 1, pInputBuffer[4], *((_DWORD *)pInputBuffer + 6),
        Timeout, &IoStatusBlock, *((_BYTE *)pInputBuffer + 20),
        *((_BYTE *)pInputBuffer + 21)) == 0;
}

// EnumDirectoryOperation — 枚举目录操作
// 对应原始驱动 sub_14002C96C
// 创建文件句柄，读取目录条目，过滤 . 和 .. 目录
__int64 EnumDirectoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    ULONG *pInputBuffer = (ULONG *)InputBuffer;
    _BYTE *pHasMoreData = (_BYTE *)pOutputBuffer;
    char DotDir1 = 0;
    char DotDir2 = 0;
    bool IsRootPath = 0;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    ULONG64 OutputBufferLen;
    ULONG64 pOutputData;
    unsigned __int64 LastCharIndex;
    int OpenResult;
    unsigned int *pDirEntry;
    unsigned int EntryLength;
    int IsDotDir;
    __int64 NextEntryOffset;
    union _LARGE_INTEGER *Timeout;
    union _LARGE_INTEGER *Timeouta;
    HANDLE Handle[3];
    __int64 IoStatusBlock;

    if (!pInputBuffer || InputSize != 24)
        return 0;
    if (!pHasMoreData || OutputSize != 1)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 6) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pHasMoreData >= MmUserProbeAddress ||
        (ULONG64)(pHasMoreData + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pHasMoreData, 1, 1);
    ProbeForRead(pInputBuffer, 24, 4);
    *pHasMoreData = 0;
    FilePathLen = pInputBuffer[2];
    if ((unsigned int)FilePathLen <= 2 || (FilePathLen & 1) != 0)
        return 0;
    pFilePath = *(volatile void **)pInputBuffer;
    if (!*(_QWORD *)pInputBuffer)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + 2 * FilePathLen >= MmUserProbeAddress ||
        FilePathLen >= MmUserProbeAddress)
        return 0;
    OutputBufferLen = pInputBuffer[3];
    if ((unsigned int)OutputBufferLen < 4)
        return 0;
    pOutputData = *((_QWORD *)pInputBuffer + 2);
    if (!pOutputData)
        return 0;
    if (pOutputData >= MmUserProbeAddress ||
        OutputBufferLen + pOutputData >= MmUserProbeAddress ||
        OutputBufferLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, FilePathLen, 1);
    ProbeForWrite(*((volatile void **)pInputBuffer + 2), pInputBuffer[3], 1);
    LastCharIndex = ((ULONG64)pInputBuffer[2] - 2) >> 1;
    if (*(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex))
        *(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex) = 0;
    if (!(unsigned int)CreateFileWithPath(
        *(__int16 **)pInputBuffer, 0, Handle, 0x100081, 0x80, 1, 1, 0x20))
    {
        if (pInputBuffer[2] == 6 && *(_WORD *)(*(_QWORD *)pInputBuffer + 2) == 58)
            IsRootPath = *(_WORD *)(*(_QWORD *)pInputBuffer + 4) == 92;
        *((_BYTE *)&Timeout) = 1;
        OpenResult = IrpReadFileWithOffset(
            Handle[0], 1, *((void **)pInputBuffer + 2), pInputBuffer[3],
            Timeout, &IoStatusBlock, 1, 0);
        while (1)
        {
            if (!OpenResult)
            {
                for (pDirEntry = (unsigned int *)*((_QWORD *)pInputBuffer + 2); ;
                     pDirEntry = (unsigned int *)((char *)pDirEntry + NextEntryOffset))
                {
                    Handle[1] = pDirEntry;
                    if ((pDirEntry[14] & 0x10) != 0)
                    {
                        EntryLength = pDirEntry[15];
                        IsDotDir = (EntryLength == 2 && *((_WORD *)pDirEntry + 32) == 46) ||
                                   (EntryLength == 4 && *((_WORD *)pDirEntry + 32) == 46 &&
                                    *((_WORD *)pDirEntry + 33) == 46);
                        if (!IsDotDir || IsRootPath)
                        {
                            *pHasMoreData = 1;
                        }
                        else
                        {
                            if (EntryLength == 2)
                            {
                                if (DotDir1 == 1)
                                    *pHasMoreData = 1;
                                else
                                    DotDir1 = 1;
                            }
                            else
                            {
                                if (DotDir2 == 1)
                                    *pHasMoreData = 1;
                                else
                                    DotDir2 = 1;
                            }
                        }
                    }
                    NextEntryOffset = *pDirEntry;
                    if (!(_DWORD)NextEntryOffset)
                        break;
                }
                if (*pHasMoreData != 1)
                {
                    *((_BYTE *)&Timeouta) = 1;
                    OpenResult = IrpReadFileWithOffset(
                        Handle[0], 1, *((void **)pInputBuffer + 2), pInputBuffer[3],
                        Timeouta, &IoStatusBlock, 0, 0);
                    continue;
                }
            }
            break;
        }
        ZwClose(Handle[0]);
    }
    return 1;
}

// RenameFileOperation — 重命名文件操作
// 对应原始驱动 sub_14002D52C
// 打开源文件，通过 CmdSendRenameFileIrp 执行重命名
__int64 RenameFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    volatile void **pInputBuffer = (volatile void **)InputBuffer;
    ULONG64 OldPathLen;
    __int16 *pOldPath;
    SIZE_T OldPathSize;
    ULONG64 NewPathLen;
    volatile void *pNewPath;
    unsigned __int64 OldLastChar;
    unsigned __int64 NewLastChar;
    _WORD *pNewPath2;
    HANDLE FileHandle;

    if (!pInputBuffer || InputSize != 32)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 4) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 32, 4);
    OldPathLen = *((unsigned int *)pInputBuffer + 2);
    if ((unsigned int)OldPathLen <= 2 || (OldPathLen & 1) != 0)
        return 0;
    pOldPath = (__int16 *)*pInputBuffer;
    if (!*pInputBuffer)
        return 0;
    if ((ULONG64)pOldPath >= MmUserProbeAddress)
        return 0;
    OldPathSize = (unsigned int)OldPathLen;
    if ((ULONG64)&pOldPath[OldPathLen] >= MmUserProbeAddress || OldPathLen >= MmUserProbeAddress)
        return 0;
    NewPathLen = *((unsigned int *)pInputBuffer + 6);
    if ((unsigned int)NewPathLen <= 2 || (NewPathLen & 1) != 0)
        return 0;
    pNewPath = pInputBuffer[2];
    if (!pNewPath)
        return 0;
    if ((ULONG64)pNewPath >= MmUserProbeAddress ||
        (ULONG64)pNewPath + 2 * NewPathLen >= MmUserProbeAddress ||
        NewPathLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(*pInputBuffer, OldPathSize, 1);
    ProbeForRead(pInputBuffer[2], *((unsigned int *)pInputBuffer + 6), 1);
    OldLastChar = ((ULONG64)*((unsigned int *)pInputBuffer + 2) - 2) >> 1;
    if (*((_WORD *)*pInputBuffer + OldLastChar))
        *((_WORD *)*pInputBuffer + OldLastChar) = 0;
    NewLastChar = ((ULONG64)*((unsigned int *)pInputBuffer + 6) - 2) >> 1;
    pNewPath2 = pInputBuffer[2];
    if (pNewPath2[NewLastChar])
        pNewPath2[NewLastChar] = 0;
    if (!(unsigned int)CreateFileWithPath(
        (__int16 *)*pInputBuffer, 0, &FileHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        __int64 result = (int)CmdSendRenameFileIrp(
            FileHandle, (const void *)pInputBuffer[2], *((_DWORD *)pInputBuffer + 6)) >= 0;
        ZwClose(FileHandle);
        return result;
    }
    return 0;
}

// CopyFileOperation — 复制文件操作
// 对应原始驱动 sub_14002C528
// 以 0x2000 字节块为单位通过 IRP 读写实现文件复制
__int64 CopyFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    volatile void **pInputBuffer = (volatile void **)InputBuffer;
    PVOID TempBuffer = 0;
    ULONG64 SrcPathLen;
    __int16 *pSrcPath;
    SIZE_T SrcPathSize;
    ULONG64 DstPathLen;
    volatile void *pDstPath;
    unsigned __int64 SrcLastChar;
    unsigned __int64 DstLastChar;
    _WORD *pDstPath2;
    char CopySuccess;
    LARGE_INTEGER FilePos;
    unsigned int BytesTransferred;
    union _LARGE_INTEGER *FileAttributes;
    union _LARGE_INTEGER *FileAttributesa;
    HANDLE SrcHandle;
    HANDLE Handle;
    PVOID TempBufferCopy;
    LARGE_INTEGER FileInfo;
    __int64 IoStatus;
    int IoStatusBlock[4];
    LARGE_INTEGER ReadOffset;

    if (!pInputBuffer || InputSize != 32)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 4) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 32, 4);
    SrcPathLen = *((unsigned int *)pInputBuffer + 2);
    if ((unsigned int)SrcPathLen <= 2 || (SrcPathLen & 1) != 0)
        return 0;
    pSrcPath = (__int16 *)*pInputBuffer;
    if (!*pInputBuffer)
        return 0;
    if ((ULONG64)pSrcPath >= MmUserProbeAddress)
        return 0;
    SrcPathSize = (unsigned int)SrcPathLen;
    if ((ULONG64)&pSrcPath[SrcPathLen] >= MmUserProbeAddress || SrcPathLen >= MmUserProbeAddress)
        return 0;
    DstPathLen = *((unsigned int *)pInputBuffer + 6);
    if ((unsigned int)DstPathLen <= 2 || (DstPathLen & 1) != 0)
        return 0;
    pDstPath = pInputBuffer[2];
    if (!pDstPath)
        return 0;
    if ((ULONG64)pDstPath >= MmUserProbeAddress ||
        (ULONG64)pDstPath + 2 * DstPathLen >= MmUserProbeAddress ||
        DstPathLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(*pInputBuffer, SrcPathSize, 1);
    ProbeForRead(pInputBuffer[2], *((unsigned int *)pInputBuffer + 6), 1);
    SrcLastChar = ((ULONG64)*((unsigned int *)pInputBuffer + 2) - 2) >> 1;
    if (*((_WORD *)*pInputBuffer + SrcLastChar))
        *((_WORD *)*pInputBuffer + SrcLastChar) = 0;
    DstLastChar = ((ULONG64)*((unsigned int *)pInputBuffer + 6) - 2) >> 1;
    pDstPath2 = pInputBuffer[2];
    if (pDstPath2[DstLastChar])
        pDstPath2[DstLastChar] = 0;
    if (!CheckFilePathFilter((__int64)*pInputBuffer, *((_DWORD *)pInputBuffer + 2)) &&
        !CheckFilePathFilter((__int64)pInputBuffer[2], *((_DWORD *)pInputBuffer + 6)) &&
        !(unsigned int)CreateFileWithPath(
            (__int16 *)*pInputBuffer, 0, &SrcHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        if (!(unsigned int)CmdQueryFileStandardInfo(SrcHandle, &FileInfo))
        {
            TempBuffer = ExAlloc(NonPagedPool, 0x2000);
            TempBufferCopy = TempBuffer;
            if (TempBuffer)
            {
                if (!(unsigned int)CreateFileWithPath(
                    (__int16 *)pInputBuffer[2], 0, &Handle, 0x100, 0x80, 1, 5, 0x20))
                {
                    CopySuccess = 1;
                    FilePos.QuadPart = 0;
                    ReadOffset.QuadPart = 0;
                    while (FilePos.QuadPart < FileInfo.QuadPart)
                    {
                        *((_BYTE *)&FileAttributes) = 0;
                        if ((int)IrpWriteFile(SrcHandle, &ReadOffset, 0x2000, TempBuffer,
                            FileAttributes, (struct _IO_STATUS_BLOCK *)&IoStatus) < 0 ||
                            (BytesTransferred = IoStatusBlock[0], *(_QWORD *)IoStatusBlock > 0x2000) ||
                            (*((_BYTE *)&FileAttributesa) = 0,
                             (int)IrpReadFileEx(Handle, &ReadOffset, IoStatusBlock[0], TempBuffer,
                                FileAttributesa, (struct _IO_STATUS_BLOCK *)&IoStatus) < 0))
                        {
                            CopySuccess = 0;
                            break;
                        }
                        FilePos.QuadPart = BytesTransferred + ReadOffset.QuadPart;
                        ReadOffset = FilePos;
                    }
                    ZwClose(Handle);
                }
            }
        }
        ZwClose(SrcHandle);
    }
    if (TempBuffer)
        ExFree(TempBuffer);
    return CopySuccess == 1;
}

// OpenFileForEnumOperation — 打开文件供枚举操作
// 对应原始驱动 sub_14002C840
// 验证路径参数，创建文件句柄供枚举使用
__int64 OpenFileForEnumOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _WORD *pFilePath = (_WORD *)InputBuffer;
    SIZE_T FilePathLength = (unsigned int)InputSize;
    _QWORD *pFileHandle = (_QWORD *)pOutputBuffer;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    void *FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pFileHandle || OutputSize != 8)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + (unsigned int)FilePathLength >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pFileHandle >= MmUserProbeAddress ||
        (ULONG64)(pFileHandle + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, (unsigned int)FilePathLength, 2);
    ProbeForWrite(pFileHandle, 8, 8);
    LastCharIndex = (LengthCopy >> 1) - 1;
    pFilePath[LastCharIndex] = 0;
    if (!CheckFilePathFilter((__int64)pFilePath, LastCharIndex) &&
        !(unsigned int)CreateFileWithPath(pFilePath, 0, &FileHandle, 0x100, 0x80, 1, 5, 0x20))
    {
        *pFileHandle = FileHandle;
        return 1;
    }
    return 0;
}

// DeleteFileOperation — 删除文件操作
// 对应原始驱动 sub_14002CEDC
// 打开文件，读取文件信息实现删除
__int64 DeleteFileOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    unsigned int *pInputBuffer = (unsigned int *)InputBuffer;
    _DWORD *pResult = pOutputBuffer;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    unsigned __int64 LastCharIndex;
    HANDLE FileHandle;

    if (!pInputBuffer || InputSize != 16)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 4) >= MmUserProbeAddress)
        return 0;
    if (!pResult || OutputSize != 4)
        return 0;
    if ((ULONG64)pResult >= MmUserProbeAddress ||
        (ULONG64)(pResult + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 16, 4);
    ProbeForWrite(pResult, 4, 4);
    FilePathLen = pInputBuffer[2];
    if ((unsigned int)FilePathLen <= 2 || (FilePathLen & 1) != 0)
        return 0;
    pFilePath = *(volatile void **)pInputBuffer;
    if (!*(_QWORD *)pInputBuffer)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + 2 * FilePathLen >= MmUserProbeAddress ||
        FilePathLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, FilePathLen, 1);
    LastCharIndex = ((ULONG64)pInputBuffer[2] - 2) >> 1;
    if (*(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex))
        *(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex) = 0;
    if (!CheckFilePathFilter(*(_QWORD *)pInputBuffer, pInputBuffer[2]) &&
        !(unsigned int)CreateFileWithPath(
            *(__int16 **)pInputBuffer, 0, &FileHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        __int64 result = (unsigned int)CmdReadFileInfo(FileHandle, pResult) == 0;
        ZwClose(FileHandle);
        return result;
    }
    return 0;
}

// SetFileAttributesOperation — 设置文件属性操作
// 对应原始驱动 sub_14002D6D8
// 打开文件，设置文件基本信息（属性标志）
__int64 SetFileAttributesOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    unsigned int *pInputBuffer = (unsigned int *)InputBuffer;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    unsigned __int64 LastCharIndex;
    HANDLE FileHandle;
    _DWORD FileBasicInfo[10];

    if (!pInputBuffer || InputSize != 16)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 4) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 16, 4);
    FilePathLen = pInputBuffer[2];
    if ((unsigned int)FilePathLen <= 2 || (FilePathLen & 1) != 0)
        return 0;
    pFilePath = *(volatile void **)pInputBuffer;
    if (!*(_QWORD *)pInputBuffer)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + 2 * FilePathLen >= MmUserProbeAddress ||
        FilePathLen >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, FilePathLen, 1);
    LastCharIndex = ((ULONG64)pInputBuffer[2] - 2) >> 1;
    if (*(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex))
        *(_WORD *)(*(_QWORD *)pInputBuffer + 2 * LastCharIndex) = 0;
    if (!CheckFilePathFilter(*(_QWORD *)pInputBuffer, pInputBuffer[2]) &&
        !(unsigned int)CreateFileWithPath(
            *(__int16 **)pInputBuffer, 0, &FileHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        memset(FileBasicInfo, 0, sizeof(FileBasicInfo));
        FileBasicInfo[8] = pInputBuffer[3];
        __int64 result = (unsigned int)CmdSetFileBasicInfo(FileHandle, (struct _IRP *)FileBasicInfo) == 0;
        ZwClose(FileHandle);
        return result;
    }
    return 0;
}

// CheckFileExistOperation — 检查文件存在操作
// 对应原始驱动 sub_14002CC50
// 创建文件句柄，若成功则文件存在
__int64 CheckFileExistOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _WORD *pFilePath = (_WORD *)InputBuffer;
    SIZE_T FilePathLength = (unsigned int)InputSize;
    _DWORD *pResult = pOutputBuffer;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    HANDLE FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pResult || OutputSize != 4)
        return 0;
    if ((ULONG64)pFilePath >= MmUserProbeAddress ||
        (ULONG64)pFilePath + (unsigned int)FilePathLength >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pResult >= MmUserProbeAddress ||
        (ULONG64)(pResult + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pFilePath, (unsigned int)FilePathLength, 2);
    ProbeForWrite(pResult, 4, 4);
    LastCharIndex = (LengthCopy >> 1) - 1;
    *pResult = 0;
    pFilePath[LastCharIndex] = 0;
    if (!CheckFilePathFilter((__int64)pFilePath, LastCharIndex) &&
        !(unsigned int)CreateFileWithPath(pFilePath, 0, &FileHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        *pResult = 1;
        ZwClose(FileHandle);
        return 1;
    }
    return 0;
}

// ------------------------------------------------------------------
// CPU/MSR 操作函数
// ------------------------------------------------------------------

// ReadCpuMsrOperation — 读取 CPU MSR 操作
// 对应原始驱动 sub_14002A358
// 读取 MSR 基址，在每个处理器上解析内核模块基址对
__int64 ReadCpuMsrOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _OWORD *pOutputData = (_OWORD *)pOutputData;
    __int64 MsrBase1;
    __int64 MsrBase2;
    _QWORD MsrPair[2];
    _OWORD MsrDiffResult;
    RtlZeroMemory(&MsrDiffResult, sizeof(MsrDiffResult));

    if (!pOutputData || OutputSize != 16)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress ||
        (ULONG64)(pOutputData + 1) >= MmUserProbeAddress)
        return 0;

    MsrBase1 = GtRead(GtEprocessModuleListOffset | GtNtoskrnlModuleBase);
    MsrBase2 = GtRead(GtEprocessModuleListOffset | GtPathBuffer01);
    if (!MsrBase2)
    {
        DispatchParseNtExportFunctions();
        MsrBase1 = GtRead(GtEprocessModuleListOffset | GtNtoskrnlModuleBase);
        MsrBase2 = GtRead(GtEprocessModuleListOffset | GtPathBuffer01);
    }
    if (MsrBase1 || MsrBase2)
    {
        ProbeForWrite(pOutputData, 16, 8);
        MsrPair[0] = MsrBase1;
        MsrPair[1] = MsrBase2;
        ForEachProcessor((__int64 (*)(_QWORD, __int64))ResolveKernelModuleBasePair, (__int64)MsrPair);
        *pOutputData = *(_OWORD *)&MsrDiffResult;
        return 1;
    }
    return 0;
}

// HalDispatchTable 全局变量（用于 FindCpuMsrBaseLegacy 中的 PE 节区匹配）
__int64 g_HalDispatchTable = 0;
__int64 g_HalDispatchTableEnd = 0;

// CmdCheckModuleBaseChanged — ForEachProcessor 回调：检查并恢复 MSR 基地址
// 对应原始驱动 sub_14002B494
// 检查每个 CPU 的 LSTAR/CSTAR MSR 是否与预期值匹配，不一致则恢复并标记变更
__int64 __fastcall CmdCheckModuleBaseChanged(__int64 CpuNumber, __int64 pMsrPair)
{
    unsigned __int64 MsrLstar;
    unsigned __int64 Msr;

    MsrLstar = __readmsr(0xC0000083);
    if (MsrLstar != 0)
    {
        if (*(__int64 *)pMsrPair != 0)
        {
            if (MsrLstar != *(__int64 *)pMsrPair)
            {
                *(_BYTE *)(pMsrPair + 16) = 1;
                __writemsr(0xC0000083, *(__int64 *)pMsrPair);
            }
        }
    }

    Msr = __readmsr(0xC0000082);
    if (Msr != 0)
    {
        if (*(__int64 *)(pMsrPair + 8) != 0)
        {
            if (Msr != *(__int64 *)(pMsrPair + 8))
            {
                *(_BYTE *)(pMsrPair + 16) = 1;
                __writemsr(0xC0000082, *(__int64 *)(pMsrPair + 8));
            }
        }
    }
    return 1;
}

// ReadCpuIdOperation — 读取 CPU ID 操作
// 对应原始驱动 sub_14002B304 (CmdReadCpuId)
__int64 ReadCpuIdOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char ChangedFlag;
    __int64 MsrBase1, MsrBase2;
    __int64 MsrPair[2];

    MsrBase1 = GtRead(GtFwpsDispatchTableCount | GtEprocessField08);
    MsrBase2 = GtRead(GtFwpsDispatchTableCount | GtEprocessField10);

    if (MsrBase1 != 0 || MsrBase2 != 0)
    {
        ChangedFlag = 0;
        MsrPair[0] = MsrBase1;
        MsrPair[1] = MsrBase2;
        ForEachProcessor((__int64(*)(__int64, __int64))CmdCheckModuleBaseChanged, (__int64)MsrPair);
        if (ChangedFlag == 1)
            return 1;
    }
    return 0;
}

// FindCpuMsrBaseLegacy — 查找 CPU MSR 基址偏移（旧版）
// 扫描 HAL PE 节区，匹配 EntryType 225 或 1301（HalDispatchTable 范围），返回偏移
__int64 FindCpuMsrBaseLegacy(int MsrAddress)
{
    unsigned int Result;
    __int64 NtoskrnlBase;
    __int64 HalImageBase;
    unsigned int HalImageSize;
    unsigned int HalImageSizeCopy;
    unsigned int AddressOffset;
    int SectionBase;
    int LoopCount;
    _QWORD *pCurrentEntry;
    __int16 EntryType;
    char SectionContext[8];
    _QWORD *SectionDataPtr;
    char SectionEntryBuffer[240];
    unsigned int SectionEntryOffset;
    __int64 SectionTypeInfo;

    Result = 0;
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    HalImageBase = GtRead(GtEprocessField22);
    HalImageSize = (unsigned int)GtRead(GtEprocessField23);
    HalImageSizeCopy = HalImageSize;

    if (NtoskrnlBase && HalImageBase && HalImageSize)
    {
        AddressOffset = MsrAddress - (int)NtoskrnlBase;
        if (AddressOffset && AddressOffset < HalImageSize)
        {
            SectionBase = (int)HalImageBase + AddressOffset;
            InitPESectionReadContext(
                (PUCHAR)(HalImageBase + AddressOffset),
                HalImageSize - AddressOffset,
                2,
                0,
                -1,
                0,
                0,
                (PUCHAR)SectionContext);

            LoopCount = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)SectionContext, (PULONG)SectionEntryBuffer))
            {
                pCurrentEntry = (_QWORD *)((__int64)SectionDataPtr + SectionEntryOffset);
                SectionDataPtr = pCurrentEntry;
                EntryType = *(__int16 *)(SectionTypeInfo + 6);

                if (EntryType == 225)
                {
                    Result = (unsigned int)pCurrentEntry - SectionBase;
                    if ((int)pCurrentEntry - SectionBase > (int)HalImageSizeCopy)
                        return 0;
                    return Result;
                }

                if (EntryType == 1301
                    && (int)pCurrentEntry - (int)HalImageBase < (int)HalImageSizeCopy
                    && (int)pCurrentEntry - (int)HalImageBase + 16 < (int)HalImageSizeCopy
                    && *pCurrentEntry == g_HalDispatchTable
                    && pCurrentEntry[1] == g_HalDispatchTableEnd)
                {
                    Result = (unsigned int)pCurrentEntry - SectionBase;
                    if ((int)pCurrentEntry - SectionBase > (int)HalImageSizeCopy)
                        return 0;
                    return Result;
                }

                if ((unsigned int)++LoopCount >= 0x7D0)
                    return Result;
            }
        }
    }
    return Result;
}

// FindCpuMsrBaseWin10 — 查找 CPU MSR 基址偏移（Win10+）
// 与旧版类似，但匹配 EntryType 225 或 1348/1349 范围
__int64 FindCpuMsrBaseWin10(int MsrAddress)
{
    unsigned int Result;
    __int64 NtoskrnlBase;
    __int64 HalImageBase;
    unsigned int HalImageSize;
    unsigned int HalImageSizeCopy;
    unsigned int AddressOffset;
    __int64 SectionBase;
    int LoopCount;
    int CurrentOffset;
    __int16 EntryType;
    unsigned int FinalOffset;
    __int64 SectionReadContext;
    __int64 SectionDataPtr;
    _DWORD SectionEntryBuffer[60];
    unsigned int SectionEntryOffset;
    __int64 SectionTypeInfo;

    Result = 0;
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    HalImageBase = GtRead(GtEprocessField22);
    HalImageSize = (unsigned int)GtRead(GtEprocessField23);
    HalImageSizeCopy = HalImageSize;

    if (NtoskrnlBase && HalImageBase && HalImageSize)
    {
        AddressOffset = MsrAddress - (int)NtoskrnlBase;
        if (AddressOffset && AddressOffset < HalImageSize)
        {
            SectionBase = HalImageBase + AddressOffset;
            InitPESectionReadContext(
                (PUCHAR)SectionBase,
                HalImageSize - AddressOffset,
                2,
                0,
                -1,
                0,
                0,
                (PUCHAR)&SectionReadContext);

            LoopCount = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionReadContext, (PULONG)SectionEntryBuffer))
            {
                CurrentOffset = SectionEntryOffset + (int)SectionDataPtr;
                SectionDataPtr += SectionEntryOffset;
                EntryType = *(__int16 *)(SectionTypeInfo + 6);

                if (EntryType == 225 || (unsigned __int16)(EntryType - 1348) <= 1u)
                {
                    FinalOffset = CurrentOffset - (int)SectionBase;
                    if (FinalOffset > HalImageSizeCopy)
                        return 0;
                    return FinalOffset;
                }

                if ((unsigned int)++LoopCount >= 0x7D0)
                    return Result;
            }
        }
    }
    return Result;
}

// DispatchCpuMsrBaseLookup — 根据版本号分发 CPU MSR 基址查找
__int64 DispatchCpuMsrBaseLookup(int MsrTableEntry)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        return FindCpuMsrBaseWin10(MsrTableEntry);
    else
        return FindCpuMsrBaseLegacy(MsrTableEntry);
}

// InitCpuMsrBaseOffsets — 初始化 CPU MSR 基址偏移
__int64 InitCpuMsrBaseOffsets(void)
{
    __int64 MsrBase1;
    unsigned int MsrBaseOffset1;
    __int64 result;

    MsrBase1 = GtRead(GtFwpsDispatchTableCount | GtEprocessField08);
    if (MsrBase1)
    {
        MsrBaseOffset1 = (unsigned int)DispatchCpuMsrBaseLookup((int)MsrBase1);
        if (MsrBaseOffset1)
            GtWrite(GtFwpsDispatchTableBase | GtEprocessField10, MsrBaseOffset1);
    }

    result = GtRead(GtFwpsDispatchTableCount | GtEprocessField10);
    if (result)
    {
        result = DispatchCpuMsrBaseLookup((int)result);
        if ((unsigned int)result)
            GtWrite(GtFwpsDispatchTableBase | GtEprocessField12, (unsigned int)result);
    }
    return result;
}

// FindCpuMsrDifferences — 查找 CPU MSR 差异偏移
// 比较指定虚拟地址范围与 HAL 导出表对应区域的差异，返回第一个差异位置的偏移
char FindCpuMsrDifferences(char *VirtualAddress, unsigned int Size, _QWORD *pDiffOffset)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    __int64 HalExportTable;
    int HalImageSize;
    __int64 NtoskrnlBase;
    __int64 OffsetAdjust;
    unsigned int Index;
    __int64 CompareOffset;
    unsigned int ValidCount;
    __int64 FirstDiffOffset;
    struct _KAPC_STATE ApcState;

    Result = 0;
    FirstDiffOffset = 0;
    *pDiffOffset = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);

    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;

    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    if (VirtualAddress && Size)
    {
        HalExportTable = GtRead(GtEprocessField66);
        HalImageSize = (int)GtRead(GtEprocessField23);
        NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);

        if (HalExportTable && HalImageSize && NtoskrnlBase)
        {
            OffsetAdjust = (unsigned int)((int)VirtualAddress - (int)NtoskrnlBase);
            if ((int)VirtualAddress != (int)NtoskrnlBase
                && VirtualAddress == (char *)(OffsetAdjust + NtoskrnlBase))
            {
                Index = 0;
                CompareOffset = OffsetAdjust - (__int64)VirtualAddress + HalExportTable;

                while (MmIsAddressValid(&VirtualAddress[CompareOffset]) && MmIsAddressValid(VirtualAddress))
                {
                    if (VirtualAddress[CompareOffset] != *VirtualAddress)
                    {
                        for (ValidCount = 0; ValidCount < 0x10; ++ValidCount)
                        {
                            if (!MmIsAddressValid(&VirtualAddress[ValidCount]))
                                break;
                        }

                        if (ValidCount && ReturnFalseStub() == 1)
                            *pDiffOffset = FirstDiffOffset;
                        else
                            *pDiffOffset = -1;

                        Result = 1;
                        break;
                    }
                    ++Index;
                    ++VirtualAddress;
                    if (Index >= Size)
                        break;
                }
            }
        }
    }

    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}

// ReadCpuBaseAddrOperation — 读取 CPU 基地址操作
// 对应原始驱动 sub_14002A45C (CmdReadCpuBaseAddr)
__int64 ReadCpuBaseAddrOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputBufferSize)
{
    char Result;
    char *MsrBase1;
    char *MsrBase2;
    __int64 BaseAddrDiff;
    unsigned int MsrBaseOffset1;
    unsigned int MsrBaseOffset2;
    unsigned int MsrSize;
    __int64 MsrDiff;
    __int64 OutputBuffer;

    Result = 0;
    OutputBuffer = (__int64)pOutputBuffer;

    if (pOutputBuffer
        && OutputBufferSize == 16
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 2) < MmUserProbeAddress)
    {
        MsrBase1 = (char *)GtRead(GtFwpsDispatchTableCount | GtEprocessField08);
        MsrBase2 = (char *)GtRead(GtFwpsDispatchTableCount | GtEprocessField10);

        if (!MsrBase2)
        {
            DispatchParseNtExportFunctions();
            MsrBase1 = (char *)GtRead(GtFwpsDispatchTableCount | GtEprocessField08);
            MsrBase2 = (char *)GtRead(GtFwpsDispatchTableCount | GtEprocessField10);
        }

        if (MsrBase1 || MsrBase2)
        {
            BaseAddrDiff = 0;
            MsrBaseOffset1 = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField10);
            MsrBaseOffset2 = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField12);

            if (MsrBaseOffset1
                || (InitCpuMsrBaseOffsets(),
                    MsrBaseOffset1 = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField10),
                    MsrSize = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField12),
                    MsrBaseOffset2 = MsrSize,
                    MsrBaseOffset1)
                || MsrSize)
            {
                if (MsrBase1 && MsrBaseOffset1 && FindCpuMsrDifferences(MsrBase1, MsrBaseOffset1, &MsrDiff) == 1)
                    BaseAddrDiff = MsrDiff;

                if (MsrBase2 && MsrBaseOffset2 && FindCpuMsrDifferences(MsrBase2, MsrBaseOffset2, &MsrDiff) == 1)
                    Result = (char)MsrDiff;
            }

            ProbeForWrite(pOutputBuffer, 0x10u, 4u);
            *pOutputBuffer = (unsigned int)BaseAddrDiff;
            pOutputBuffer[1] = (unsigned int)(char)Result;
            Result = 1;
        }
    }
    return Result;
}

// CopyKernelMemoryToTarget — 复制内核内存到目标地址
// 通过 HAL 导出表获取对应偏移的源数据，分配临时缓冲区，使用 WritePhysicalMemoryBuffer 写入目标虚拟地址
char CopyKernelMemoryToTarget(PVOID VirtualAddress, size_t Size)
{
    char Result;
    __int64 SizeCopy;
    __int64 HalExportTable;
    int HalImageSize;
    __int64 NtoskrnlBase;
    __int64 NtoskrnlBaseCopy;
    __int64 ExportOffset;
    char *ExportAddr;
    PVOID TempBuffer;

    Result = 0;
    SizeCopy = (unsigned int)Size;

    if (VirtualAddress && (unsigned int)Size)
    {
        HalExportTable = GtRead(GtEprocessField66);
        HalImageSize = (int)GtRead(GtEprocessField23);
        NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
        NtoskrnlBaseCopy = NtoskrnlBase;

        if (HalExportTable && HalImageSize && NtoskrnlBase)
        {
            ExportOffset = (unsigned int)((int)VirtualAddress - (int)NtoskrnlBase);
            if ((int)VirtualAddress != (int)NtoskrnlBaseCopy
                && VirtualAddress == (PVOID)(NtoskrnlBaseCopy + ExportOffset))
            {
                ExportAddr = (char *)((unsigned int)ExportOffset + HalExportTable);

                if ((unsigned int)SizeCopy
                    && MmIsAddressValid((PVOID)((unsigned int)ExportOffset + HalExportTable))
                    && MmIsAddressValid(VirtualAddress))
                {
                    TempBuffer = ExAlloc(NonPagedPool, (unsigned int)(SizeCopy + 4096));
                    if (TempBuffer)
                    {
                        if (MmIsAddressValid(&ExportAddr[SizeCopy]) == 1)
                        {
                            memmove(TempBuffer, ExportAddr, (unsigned int)SizeCopy);
                            WritePhysicalMemoryBuffer((unsigned __int64)VirtualAddress, TempBuffer, SizeCopy, 0, 0);
                            Result = 1;
                        }
                        ExFree(TempBuffer);
                    }
                }
            }
        }
    }
    return Result;
}

// ReadCpuInfoExOperation — 读取 CPU 信息扩展操作
// 对应原始驱动 sub_14002B36C (CmdReadCpuInfoEx)
__int64 ReadCpuInfoExOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    struct _KPROCESS *TargetProcess;
    void *MsrBase1;
    void *MsrBase2;
    unsigned int MsrBaseOffset1;
    unsigned int MsrBaseOffset2;
    unsigned int MsrBaseOffset2Copy;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);

    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;

    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    MsrBase1 = (void *)GtRead(GtFwpsDispatchTableCount | GtEprocessField08);
    MsrBase2 = (void *)GtRead(GtFwpsDispatchTableCount | GtEprocessField10);
    MsrBaseOffset1 = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField10);
    MsrBaseOffset2 = (unsigned int)GtRead(GtFwpsDispatchTableBase | GtEprocessField12);
    MsrBaseOffset2Copy = MsrBaseOffset2;

    if ((MsrBase1 || MsrBase2) && (MsrBaseOffset1 || MsrBaseOffset2))
    {
        if (MsrBase1 && MsrBaseOffset1)
            Result = CopyKernelMemoryToTarget(MsrBase1, MsrBaseOffset1) == 1;

        if (MsrBase2 && MsrBaseOffset2Copy && CopyKernelMemoryToTarget(MsrBase2, MsrBaseOffset2Copy) == 1)
            Result = 1;
    }

    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);

    return Result;
}

// ReadCpuBaseAddrExOperation — 读取 CPU 基地址扩展操作
// 对应原始驱动 sub_14002B944 (CmdReadCpuBaseAddrEx)
__int64 ReadCpuBaseAddrExOperation(__int64 InputBuffer, volatile void *pInputAddress, int InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    __int64 HalExportTable;
    int HalMsrBaseOffset;
    int HalExportCount;

    HalExportTable = GtRead(GtObjectTypeCheckFlag);
    HalMsrBaseOffset = (int)GtRead(GtObjectTypeCount);
    HalExportCount = (int)GtRead(GtEprocessField184 | GtEprocessField06 | 0x100);
    GtRead(GtFindHookTargetFirstMatchAddr2);
    GtRead(GtEprocessField69);

    if (pInputAddress
        && InputSize == 4
        && (unsigned __int64)pInputAddress < MmUserProbeAddress
        && (unsigned __int64)pInputAddress + 4 < MmUserProbeAddress
        && pOutputBuffer
        && OutputSize == 4
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress
        && HalExportTable
        && HalMsrBaseOffset
        && HalExportCount)
    {
        ProbeForRead((void *)pInputAddress, 4u, 4u);
        ProbeForWrite(pOutputBuffer, 4u, 4u);
        *pOutputBuffer = 0;
    }
    return 1;
}

// GetKernelBaseLegacyOperation — 获取内核基址（旧版）操作
// 对应原始驱动 sub_14002B8DC (CmdGetKernelBaseLegacy)
__int64 GetKernelBaseLegacyOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputBufferSize)
{
    if (pOutputBuffer
        && OutputBufferSize == 4
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 4u, 4u);
        *pOutputBuffer = 0;
        GtRead(GtFindHookTargetFirstMatchAddr2);
        return 1;
    }
    return 0;
}

// ReadMsrValueOperation — 读取 MSR 值操作
// 对应原始驱动 sub_140030268
// 验证输出缓冲区，读取 MSR 表值输出到用户缓冲区
__int64 ReadMsrValueOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _QWORD *pOutputData = (_QWORD *)pOutputData;
    _QWORD *pMsrTable;
    __int64 MsrValue;
    __int64 MsrTable2;
    __int64 MsrValue2;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return 0;

    if (!GtRead(GtEprocessField99 | 0x800))
        LookupMsrTableEntry();
    pMsrTable = (_QWORD *)GtRead(GtEprocessField99 | 0x800);
    MsrValue = GtRead(GtEprocessModuleEntryCount | GtEprocessField86);
    if (!GtRead(GtEprocessModuleListOffset | GtCurrentEprocess))
        InitMsrTable();
    MsrTable2 = GtRead(GtEprocessModuleListOffset | GtCurrentEprocess);
    MsrValue2 = MsrTable2;

    if (pMsrTable && MsrValue && MsrTable2 &&
        CheckMemoryValid((void *)0xFFFFF780000002D4) == 1 &&
        pOutputData && OutputSize == 16 &&
        (ULONG64)pOutputData < MmUserProbeAddress &&
        (ULONG64)(pOutputData + 2) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputData, 16, 8);
        *pOutputData = 0;
        pOutputData[1] = 0;
        *pOutputData = *pMsrTable;
        if (*(volatile __int64 *)0xFFFFF780000002D4)
            MsrValue = MsrValue2;
        pOutputData[1] = MsrValue;
        return 1;
    }
    return 0;
}

// WriteMsrValueOperation — 写入 MSR 值操作
// 对应原始驱动 sub_140030F8C
// 通过 InterlockedExchange64 原子交换 MSR 表值
__int64 WriteMsrValueOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    volatile __int64 *pMsrTable;
    __int64 MsrValue;
    __int64 MsrTable2;
    __int64 MsrValue2;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x3839)
        return 0;

    if (!GtRead(GtEprocessField99 | 0x800))
        LookupMsrTableEntry();
    pMsrTable = (volatile __int64 *)GtRead(GtEprocessField99 | 0x800);
    MsrValue = GtRead(GtEprocessModuleEntryCount | GtEprocessField86);
    if (!GtRead(GtEprocessModuleListOffset | GtCurrentEprocess))
        InitMsrTable();
    MsrTable2 = GtRead(GtEprocessModuleListOffset | GtCurrentEprocess);
    MsrValue2 = MsrTable2;

    if (pMsrTable && MsrValue && MsrTable2 &&
        CheckMemoryValid((void *)0xFFFFF780000002D4) == 1)
    {
        if (*(volatile __int64 *)0xFFFFF780000002D4)
            MsrValue = MsrValue2;
        _InterlockedExchange64(pMsrTable, MsrValue);
        return 1;
    }
    return 0;
}

// ------------------------------------------------------------------
// 物理内存操作函数
// ------------------------------------------------------------------

// ReadPhysicalMemoryOperation — 读取物理内存操作
// 对应原始驱动 sub_1400352BC
// 初始化回调函数，枚举设备对象类型列表，复制物理内存上下文表
__int64 ReadPhysicalMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _BYTE *pOutputData = (_BYTE *)pOutputData;
    int Device0Ready;
    int Ctx0Ready;
    int Device2Ready;
    int Ctx2Ready;
    int Device1Ready;
    int Ctx1Ready;

    if (OutputSize != 7928)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress ||
        (ULONG64)(pOutputData + 7928) >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputData, 7928, 1);
    memset(pOutputData, 0, 7928);
    InitCallbackFunctions();
    Device0Ready = GtRead(GtEprocessField133 | 0x100);
    Ctx0Ready = GtRead(GtFltUnregisterFilterAddr | GtEprocessField22);
    Device2Ready = GtRead(GtEprocessField134 | 0x100);
    Ctx2Ready = GtRead(GtFltUnregisterFilterOffset | GtEprocessField22);
    Device1Ready = GtRead(GtKernelDataField18);
    Ctx1Ready = GtRead(GtFltDataSectionOffset | GtEprocessField22);

    if (EnumDeviceObjectTypeList(0, (__int64)(pOutputData + 8)) == 1)
    {
        *(_WORD *)pOutputData |= 1;
        if (Device0Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputData + 8), 0) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 8), 0, 0x1C) == 1)
            {
                pOutputData[2] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(0, (__int64)(pOutputData + 1352)) == 1)
    {
        *(_WORD *)pOutputData |= 2;
        if (Ctx0Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputData + 1352), 0) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 1352), 0, 0x1B) == 1)
            {
                pOutputData[3] = 1;
            }
        }
    }
    if (EnumDeviceObjectTypeList(2, (__int64)(pOutputData + 2648)) == 1)
    {
        *(_WORD *)pOutputData |= 4;
        if (Device2Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputData + 2648), 2) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 2648), 2, 0x1C) == 1)
            {
                pOutputData[4] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(2, (__int64)(pOutputData + 3992)) == 1)
    {
        *(_WORD *)pOutputData |= 8;
        if (Ctx2Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputData + 3992), 2) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 3992), 2, 0x1B) == 1)
            {
                pOutputData[5] = 1;
            }
        }
    }
    if (EnumDeviceObjectTypeList(1, (__int64)(pOutputData + 5288)) == 1)
    {
        *(_WORD *)pOutputData |= 0x10;
        if (Device1Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputData + 5288), 1) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 5288), 1, 0x1C) == 1)
            {
                pOutputData[6] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(1, (__int64)(pOutputData + 6632)) == 1)
    {
        *(_WORD *)pOutputData |= 0x20;
        if (Ctx1Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputData + 6632), 1) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputData + 6632), 1, 0x1B) == 1)
            {
                pOutputData[7] = 1;
            }
        }
    }
    return 1;
}

// ------------------------------------------------------------------
// 处理器信息操作函数
// ------------------------------------------------------------------

// EnumProcessorInfoOperation — 枚举处理器信息操作
// 对应原始驱动 sub_14002FDD4
// 遍历处理器读取线程上下文，枚举进程列表，收集进程信息
__int64 EnumProcessorInfoOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _DWORD *pOutputData = pOutputData;
    _DWORD *pProcessBuffer = 0;
    __int64 BufferSize = OutputSize;
    int MaxProcessCount;
    __int64 ObjectTypeOffset;
    int MaxCount;
    __int64 EprocessOffset;
    int ImageFileNameOffset;
    unsigned __int64 SectionBase;
    unsigned int ObjectTypeId;
    _DWORD *pProcessData;
    unsigned int ProcessCount;
    unsigned int ProcessIndex;
    __int64 ProcessSlotMul14;
    unsigned __int64 ObjectTableAddr;
    _QWORD *pContextTable;
    unsigned __int64 EprocessAddr;
    unsigned int ObjectTypeIdCopy;
    int RemainingEntries;
    char Returned;
    __int64 EprocessOffsetVal;
    __int64 BasePriorityOffset;
    _DWORD *pProcessBuffer2;
    __int64 ObjectTableOffset;
    int LoopIndex;
    unsigned int ProcessCountCopy;
    __int64 ImageFileOffsetVal;
    _QWORD *pSectionBase;
    __int64 ObjectTableOffsetVal;
    _QWORD ProcessorContext[2];

    if (!pOutputData || (unsigned int)BufferSize < 0x58)
        return 0;
    if ((ULONG64)pOutputData >= MmUserProbeAddress ||
        (ULONG64)pOutputData + BufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputData, BufferSize, 4);
    memset(pOutputData, 0, (unsigned int)BufferSize);
    *pOutputData = 0;
    RemainingEntries = (BufferSize - 88) / 0x50 + 1;
    ProcessorContext[0] = pOutputData;
    ProcessorContext[1] = &RemainingEntries;
    ForEachProcessor((__int64 (*)(_QWORD, __int64))ReadThreadContext, (__int64)ProcessorContext);

    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber >= 0xA28 && RemainingEntries)
    {
        MaxProcessCount = GtRead(GtObjectTypeCount);
        ObjectTypeOffset = GtRead(GtKiFastCallEntryAddr | GtNtoskrnlImageSize);
        MaxCount = ObjectTypeOffset;
        ObjectTableOffsetVal = ObjectTypeOffset;
        ImageFileOffsetVal = GtRead(GtEprocessModuleListOffset | GtPspTerminateThreadAddr);
        BasePriorityOffset = GtRead(GtProcessOffset);
        ObjectTableOffset = GtRead(GtProcessEprocess);
        EprocessOffset = GtRead(GtEprocessField43);
        ImageFileNameOffset = EprocessOffset;
        EprocessOffsetVal = EprocessOffset;
        SectionBase = GtRead(GtObjectTypeInfoPtr);
        pSectionBase = (_QWORD *)SectionBase;

        if (MaxProcessCount && MaxCount && (_DWORD)ImageFileOffsetVal &&
            (_DWORD)BasePriorityOffset != -1 && (_DWORD)ObjectTableOffset != -1 &&
            ImageFileNameOffset != -1 && SectionBase > (ULONG64)MmSystemRangeStart)
        {
            ObjectTypeId = MaxProcessCount - 1;
            ObjectTypeIdCopy = ObjectTypeId;
            pProcessData = ExAlloc(PagedPool, 0x44610);
            pProcessBuffer = pProcessData;
            pProcessBuffer2 = pProcessData;
            if (pProcessData)
            {
                pProcessData[4] = 0;
                if (EnumerateProcessList(0, (__int64)pProcessData, 0x44610))
                {
                    ProcessCount = pProcessBuffer[4];
                    ProcessCountCopy = ProcessCount;
                    ProcessIndex = 0;
                    LoopIndex = 0;
                    while (ProcessIndex < ProcessCount && RemainingEntries)
                    {
                        ProcessSlotMul14 = 14 * ProcessIndex;
                        if (CheckMemoryValid(*(void **)&pProcessBuffer[ProcessSlotMul14 + 8]) == 1 &&
                            CheckMemoryValid((void *)(*(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8] + ObjectTypeId)) == 1 &&
                            CheckProcessObjectFlag(*(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]) == 1)
                        {
                            ObjectTableAddr = *(_QWORD *)((unsigned int)ObjectTableOffsetVal +
                                *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]);
                            if (ObjectTableAddr > (ULONG64)MmSystemRangeStart)
                            {
                                pContextTable = (_QWORD *)(ObjectTableAddr - (unsigned int)ImageFileOffsetVal);
                                if (pContextTable > MmSystemRangeStart)
                                {
                                    BuildNumber;
                                    if (CheckMemoryValid(pContextTable) == 1 &&
                                        CheckMemoryValid((char *)pContextTable + 399) == 1 &&
                                        (pContextTable[27] || pContextTable[28] || pContextTable[29] || pContextTable[30]))
                                    {
                                        if (!RemainingEntries)
                                            break;
                                        *((_BYTE *)&pOutputData[20 * *pOutputData + 2]) = 0;
                                        *(_QWORD *)&pOutputData[20 * *pOutputData + 4] = *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8];
                                        *(_QWORD *)&pOutputData[20 * *pOutputData + 6] = *(_QWORD *)((unsigned int)BasePriorityOffset + *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]);
                                        *(_QWORD *)&pOutputData[20 * *pOutputData + 8] = *(_QWORD *)((unsigned int)ObjectTableOffset + *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]);
                                        EprocessAddr = *(_QWORD *)&pOutputData[20 * *pOutputData + 6];
                                        if (*pSectionBase != EprocessAddr &&
                                            EprocessAddr > (ULONG64)MmSystemRangeStart &&
                                            CheckMemoryValid(*(void **)&pOutputData[20 * *pOutputData + 6]) == 1 &&
                                            CheckMemoryValid((void *)(EprocessAddr + (unsigned int)EprocessOffsetVal + 7)) == 1 &&
                                            *(_QWORD *)((unsigned int)EprocessOffsetVal + EprocessAddr) > (ULONG64)MmSystemRangeStart)
                                        {
                                            *(_QWORD *)&pOutputData[20 * *pOutputData + 10] = pContextTable[27];
                                            *(_QWORD *)&pOutputData[20 * *pOutputData + 12] = pContextTable[28];
                                            *(_QWORD *)&pOutputData[20 * *pOutputData + 14] = pContextTable[29];
                                            *(_QWORD *)&pOutputData[20 * *pOutputData + 16] = pContextTable[30];
                                            *(_QWORD *)&pOutputData[20 * *pOutputData + 18] = pContextTable[31];
                                            *(_QWORD *)&pOutputData[20 * (*pOutputData)++ + 20] = pContextTable[32];
                                            --RemainingEntries;
                                        }
                                    }
                                }
                                ObjectTypeId = ObjectTypeIdCopy;
                            }
                        }
                        LoopIndex = ++ProcessIndex;
                        ProcessCount = ProcessCountCopy;
                    }
                }
                ExFree(pProcessBuffer);
                pProcessBuffer = 0;
                pProcessBuffer2 = 0;
            }
        }
    }
    Returned = 1;
    if (pProcessBuffer)
        ExFree(pProcessBuffer);
    return 1;
}

// SetProcessorFieldOperation — 设置处理器字段操作
// 对应原始驱动 sub_140030420
// 若标志为 1 则清除所有处理器上下文；否则验证目标 EPROCESS，清除上下文数据
__int64 SetProcessorFieldOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _BYTE *pInputBuffer = (_BYTE *)InputBuffer;
    char *TargetEprocess;
    int ObjectTypeId;
    int ObjectTableOffset;
    unsigned int ContextOffset;
    int BasePriorityOffset;
    _QWORD *pSectionBase;
    unsigned __int64 EprocessAddr;
    unsigned __int64 TableAddr;
    _QWORD *pContextTable;
    int ProcessorContext;
    char Cleared;
    __int64 ImageFileOffsetVal;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    if (!pInputBuffer || InputSize != 16)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 16) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 16, 4);
    if (*pInputBuffer == 1)
    {
        Cleared = 0;
        ProcessorContext = *((_DWORD *)pInputBuffer + 2);
        ForEachProcessor((__int64 (*)(_QWORD, __int64))ValidateAndClearProcessContext, (__int64)&ProcessorContext);
        return Cleared == 1;
    }

    if (BuildNumber >= 0xA28)
    {
        TargetEprocess = (char *)*((_QWORD *)pInputBuffer + 1);
        ObjectTypeId = GtRead(GtObjectTypeCount);
        ObjectTableOffset = GtRead(GtKiFastCallEntryAddr | GtNtoskrnlImageSize);
        ContextOffset = GtRead(GtEprocessModuleListOffset | GtPspTerminateThreadAddr);
        BasePriorityOffset = GtRead(GtProcessOffset);
        ImageFileOffsetVal = GtRead(GtEprocessField43);
        pSectionBase = (_QWORD *)GtRead(GtObjectTypeInfoPtr);

        if (ObjectTypeId && ObjectTableOffset && ContextOffset &&
            BasePriorityOffset != -1 && (_DWORD)ImageFileOffsetVal != -1 &&
            pSectionBase > MmSystemRangeStart)
        {
            ObjectTypeId = ObjectTypeId - 1;
            if (CheckMemoryValid(TargetEprocess) == 1 &&
                CheckMemoryValid(&TargetEprocess[ObjectTypeId]) == 1 &&
                CheckProcessObjectFlag((__int64)TargetEprocess) == 1)
            {
                EprocessAddr = *(_QWORD *)&TargetEprocess[BasePriorityOffset];
                if (*pSectionBase != EprocessAddr &&
                    EprocessAddr > (ULONG64)MmSystemRangeStart &&
                    CheckMemoryValid(*(void **)&TargetEprocess[BasePriorityOffset]) == 1 &&
                    CheckMemoryValid((void *)(EprocessAddr + (unsigned int)ImageFileOffsetVal + 7)) == 1 &&
                    *(_QWORD *)((unsigned int)ImageFileOffsetVal + EprocessAddr) > (ULONG64)MmSystemRangeStart)
                {
                    TableAddr = *(_QWORD *)&TargetEprocess[ObjectTableOffset];
                    if (TableAddr > (ULONG64)MmSystemRangeStart)
                    {
                        pContextTable = (_QWORD *)(TableAddr - ContextOffset);
                        if (pContextTable > MmSystemRangeStart)
                        {
                            BuildNumber;
                            if (CheckMemoryValid(pContextTable) == 1 &&
                                CheckMemoryValid((char *)pContextTable + 399) == 1)
                            {
                                pContextTable[27] = 0;
                                pContextTable[28] = 0;
                                pContextTable[29] = 0;
                                pContextTable[30] = 0;
                                pContextTable[31] = 0;
                                pContextTable[32] = 0;
                                return 1;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// ------------------------------------------------------------------
// 内核内存上下文操作函数
// ------------------------------------------------------------------

// InitKernelMemoryContextOperation — 初始化内核内存上下文操作
// 对应原始驱动 sub_1400681DC (CmdInitKernelMemoryContext)
__int64 InitKernelMemoryContextOperation()
{
    char Result;
    _QWORD *pKernelMemCtx;
    __int64 pVerifyFunc;
    int (*VerifyFunc)(void);

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pKernelMemCtx = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400);
    pVerifyFunc = GtRead(GtEprocessExtField57 | GtEprocessField54 | 0x400);
    VerifyFunc = (int (*)(void))pVerifyFunc;
    if (pKernelMemCtx && pKernelMemCtx > MmSystemRangeStart && pVerifyFunc &&
        CheckMemoryValid(pKernelMemCtx) == 1 && (!*pKernelMemCtx || VerifyFunc() >= 0))
        return 1;
    return Result;
}

// CopyKernelArrayToUserBufferOperation — 复制内核数组到用户缓冲区操作
// 对应原始驱动 sub_14006BC78 (CopyKernelArrayToUserBuffer)
__int64 CopyKernelArrayToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    char Result;
    char *pDataPtr;
    unsigned int EntryCount;

    BufferSize = OutputSize;
    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField27 | 0x400))
        InitKernelMemoryContext();
    pDataPtr = (char *)GtRead(GtEprocessExtField58 | GtEprocessField27 | 0x400);
    EntryCount = GtRead(GtEprocessExtField58 | GtEprocessField28 | 0x400);
    if (pDataPtr && EntryCount && pDataPtr > MmSystemRangeStart &&
        EntryCount < 0x100 &&
        CheckMemoryValid(pDataPtr) == 1 &&
        CheckMemoryValid(&pDataPtr[8 * EntryCount - 1]) == 1 &&
        pOutputBuffer && BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 8);
        memset(pOutputBuffer, 0, BufferSize);
        *pOutputBuffer = EntryCount;
        memmove(pOutputBuffer + 2, pDataPtr, 8LL * EntryCount);
        return 1;
    }
    return Result;
}

// CopyKernelDualArrayToUserBufferOperation — 复制内核双数组到用户缓冲区操作
// 对应原始驱动 sub_14006BDA4 (CopyKernelDualArrayToUserBuffer)
__int64 CopyKernelDualArrayToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    char Result;
    char *pDataPtr;
    unsigned int EntryCount;
    char *pSecondArray;
    unsigned int EntryCountMinus1;
    unsigned int WinBuildNum;

    BufferSize = OutputSize;
    Result = 0;
    if (!GtRead(GtEprocessExtField48 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pDataPtr = (char *)GtRead(GtEprocessExtField48 | GtEprocessField54 | 0x400);
    EntryCount = GtRead(GtEprocessExtField47 | GtEprocessField54 | 0x400);
    if (pDataPtr && EntryCount && pDataPtr > MmSystemRangeStart &&
        EntryCount < 0x100 && CheckMemoryValid(pDataPtr) == 1)
    {
        if (CheckMemoryValid(&pDataPtr[8 * EntryCount - 1]) == 1 && pOutputBuffer)
        {
            EntryCountMinus1 = EntryCount - 1;
            if (BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16 &&
                (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
                (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
            {
                ProbeForWrite(pOutputBuffer, BufferSize, 8);
                memset(pOutputBuffer, 0, BufferSize);
                *pOutputBuffer = EntryCount;
                WinBuildNum = GtRead(GtWindowsBuildNumber);
                if (WinBuildNum < 0x23F0)
                {
                    memmove(pOutputBuffer + 2, pDataPtr, 8LL * EntryCount);
                }
                else
                {
                    pSecondArray = &pDataPtr[8 * EntryCount];
                    memmove(pOutputBuffer + 2, pDataPtr, 8LL * EntryCountMinus1);
                    if (CheckMemoryValid(pSecondArray) == 1)
                        *(_QWORD *)&pOutputBuffer[2 * EntryCountMinus1 + 2] = *(_QWORD *)pSecondArray;
                }
                return 1;
            }
        }
    }
    return Result;
}

// ReadKernelMemoryToUserBufferOperation — 读取内核内存到用户缓冲区操作
// 对应原始驱动 sub_14006AFEC (ReadKernelMemoryToUserBuffer)
__int64 ReadKernelMemoryToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    _QWORD *pKernelMemCtx;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pKernelMemCtx = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400);
    if (pKernelMemCtx && pKernelMemCtx > MmSystemRangeStart &&
        CheckMemoryValid(pKernelMemCtx) == 1 && pOutputBuffer && OutputSize == 8 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 8, 8);
        *pOutputBuffer = 0;
        *pOutputBuffer = *pKernelMemCtx;
        return 1;
    }
    return Result;
}

// ReadKernelMemoryRangeOperation — 读取内核内存范围操作
// 对应原始驱动 sub_14006BBB8 (CmdReadKernelMemoryRange)
__int64 ReadKernelMemoryRangeOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    _QWORD *pMacShimData;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400))
        InitKernelMemoryContext();
    pMacShimData = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400);
    if (pMacShimData && pMacShimData > MmSystemRangeStart &&
        CheckMemoryValid(pMacShimData) == 1 && pOutputBuffer && OutputSize == 8 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 8, 8);
        *pOutputBuffer = 0;
        *pOutputBuffer = *pMacShimData;
        return 1;
    }
    return Result;
}

// EnumKernelMemoryContextOperation — 枚举内核内存上下文操作
// 对应原始驱动 sub_14006A968 (EnumKernelMemoryContext)
__int64 EnumKernelMemoryContextOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    char Result;
    _QWORD *pMemCtxListHead;
    unsigned int EntryStepSize;
    _QWORD *pEntry;
    unsigned __int64 MaxEntries;
    unsigned int WinBuildNum;
    unsigned int i;

    BufferSize = OutputSize;
    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400))
        InitKernelMemoryContext();
    pMemCtxListHead = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400);
    EntryStepSize = GtRead(GtEprocessExtField42 | GtEprocessField54 | 0x400);
    if (pMemCtxListHead && pMemCtxListHead > MmSystemRangeStart && EntryStepSize &&
        *pMemCtxListHead > (unsigned __int64)MmSystemRangeStart)
    {
        pEntry = (_QWORD *)(*pMemCtxListHead + EntryStepSize);
        if (CheckMemoryValid(pEntry) == 1 && pOutputBuffer && (unsigned int)BufferSize >= 0x18 &&
            (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
            (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, BufferSize, 8);
            memset(pOutputBuffer, 0, BufferSize);
            *pOutputBuffer = 0;
            MaxEntries = ((BufferSize - 24) >> 4) + 1;
            WinBuildNum = GtRead(GtWindowsBuildNumber);
            if (WinBuildNum < 0x4563)
            {
                if (WinBuildNum < 0x23F0)
                {
                    if (WinBuildNum == 7600 || WinBuildNum == 7601)
                    {
                        for (i = 0; i < 3 && (_DWORD)MaxEntries && CheckMemoryValid(pEntry) == 1 &&
                             CheckMemoryValid((char *)pEntry + 15) == 1; ++i)
                        {
                            if (pEntry[1])
                            {
                                pOutputBuffer[4 * *pOutputBuffer + 2] = *(_DWORD *)pEntry;
                                *(_QWORD *)&pOutputBuffer[4 * (*pOutputBuffer)++ + 4] = pEntry[1];
                                MaxEntries = (unsigned __int64)((unsigned int)MaxEntries - 1);
                            }
                            pEntry += 2;
                        }
                    }
                }
                else
                {
                    for (i = 0; i < 5 && (_DWORD)MaxEntries && CheckMemoryValid(pEntry) == 1 &&
                         CheckMemoryValid((char *)pEntry + 15) == 1; ++i)
                    {
                        if (pEntry[1])
                        {
                            pOutputBuffer[4 * *pOutputBuffer + 2] = *(_DWORD *)pEntry;
                            *(_QWORD *)&pOutputBuffer[4 * (*pOutputBuffer)++ + 4] = pEntry[1];
                            MaxEntries = (unsigned __int64)((unsigned int)MaxEntries - 1);
                        }
                        pEntry += 2;
                    }
                }
            }
            else
            {
                for (i = 0; i < 5 && (_DWORD)MaxEntries && CheckMemoryValid(pEntry) == 1 &&
                     CheckMemoryValid((char *)pEntry + 31) == 1; ++i)
                {
                    if (pEntry[1])
                    {
                        pOutputBuffer[4 * *pOutputBuffer + 2] = *(_DWORD *)pEntry;
                        *(_QWORD *)&pOutputBuffer[4 * (*pOutputBuffer)++ + 4] = pEntry[1];
                        MaxEntries = (unsigned __int64)((unsigned int)MaxEntries - 1);
                    }
                    pEntry += 4;
                }
            }
            return 1;
        }
    }
    return Result;
}

// ------------------------------------------------------------------
// 进程上下文操作函数
// ------------------------------------------------------------------

// EnumProcessContextWin7Operation — 枚举进程上下文操作(Win7)
// 对应原始驱动 sub_14003A140 (CmdEnumProcessContextWin7)
__int64 EnumProcessContextWin7Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int TableReady;

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770 &&
        pOutputBuffer && OutputSize == 1352 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548, 1);
        memset(pOutputBuffer, 0, 0x548);
        TableReady = GtRead(GtFltUnregisterFilterAddr | GtEprocessField54);
        if (!TableReady)
        {
            InitProcessContextExportTableWin7();
            TableReady = GtRead(GtFltUnregisterFilterAddr | GtEprocessField54);
        }
        if (EnumProcessContextV3TableWin7((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopyProcessContextTableWin7((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// SetProcessContextWin7Operation — 设置进程上下文操作(Win7)
// 对应原始驱动 sub_14003A3AC (CmdSetProcessContextWin7)
__int64 SetProcessContextWin7Operation(char *pInputBuffer, int InputSize)
{
    char Result;
    char HookResult;
    char PatchResult;
    PVOID TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1770 &&
        pInputBuffer && InputSize == 48 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30, 1);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = WriteProcessContextEntryWin7((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// EnumProcessContextWin8Operation — 枚举进程上下文操作(Win8+)
// 对应原始驱动 sub_140039934 (CmdEnumProcessContextWin8)
__int64 EnumProcessContextWin8Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int TableReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 2648 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 2648) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0xA58, 1);
        memset(pOutputBuffer, 0, 0xA58);
        TableReady = GtRead(GtFltPeSectionOfs0 | GtEprocessField54);
        if (!TableReady)
        {
            InitProcessContextHookTable();
            TableReady = GtRead(GtFltPeSectionOfs0 | GtEprocessField54);
        }
        if (EnumProcessContextV3Table((__int64)(pOutputBuffer + 8)) == 1)
        {
            *(_WORD *)pOutputBuffer |= 1;
            Result = 1;
            if (TableReady)
            {
                if (CopyProcessContextV2HookTable((__int64)(pOutputBuffer + 8)) == 1 &&
                    ResolveContextMemoryBlocks((__int64)(pOutputBuffer + 8), 0x1C) == 1)
                {
                    pOutputBuffer[2] = 1;
                }
            }
        }
        if (EnumProcessContextV2Table((__int64)(pOutputBuffer + 1352)) == 1)
        {
            *(_WORD *)pOutputBuffer |= 2;
            Result = 1;
            if (GtRead(GtFltPeSectionAddr0 | GtEprocessField54))
            {
                if (CopyProcessContextV3HookTable((__int64)(pOutputBuffer + 1352)) == 1 &&
                    ResolveContextMemoryBlocks((__int64)(pOutputBuffer + 1352), 0x1B) == 1)
                {
                    pOutputBuffer[3] = 1;
                }
            }
        }
    }
    return Result;
}

// SetProcessContextWin8Operation — 设置进程上下文操作(Win8+)
// 对应原始驱动 sub_140039C48 (CmdSetProcessContextWin8)
__int64 SetProcessContextWin8Operation(char *pInputBuffer, int InputSize)
{
    char Result;
    char HookResult;
    char PatchResult;
    void *TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if (pInputBuffer && InputSize == 56 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 56) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x38, 1);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[32] == 1)
            HookResult = SetProcessContextEntry((__int64)pInputBuffer);
        if (pInputBuffer[33] == 1)
        {
            PatchResult = 0;
            TargetAddress = (void *)*((_QWORD *)pInputBuffer + 2);
            if (TargetAddress &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 2) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 34);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 2), &PatchData, 0x10, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// EnumProcessContextWin10Operation — 枚举进程上下文操作(Win10)
// 对应原始驱动 sub_140032180 (CmdEnumProcessContextWin10)
__int64 EnumProcessContextWin10Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int ExportTableReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 2648 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 2648) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0xA58, 1);
        memset(pOutputBuffer, 0, 0xA58);
        ExportTableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField182);
        if (!ExportTableReady)
        {
            BuildProcessContextExportTable();
            ExportTableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField182);
        }
        if (EnumProcessContextSsdtTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            *(_WORD *)pOutputBuffer |= 1;
            Result = 1;
            if (ExportTableReady)
            {
                if (CopyProcessContextTable1((__int64)(pOutputBuffer + 8)) == 1 &&
                    ResolveContextMemoryBlocks((__int64)(pOutputBuffer + 8), 0x1C) == 1)
                {
                    pOutputBuffer[2] = 1;
                }
            }
        }
        if (EnumProcessContextTable((__int64)(pOutputBuffer + 1352)) == 1)
        {
            *(_WORD *)pOutputBuffer |= 2;
            Result = 1;
            if (GtRead(GtDisableHookProtectionAddr2 | GtEprocessField183))
            {
                if (CopyProcessContextTable2((__int64)(pOutputBuffer + 1352)) == 1 &&
                    ResolveContextMemoryBlocks((__int64)(pOutputBuffer + 1352), 0x1B) == 1)
                {
                    pOutputBuffer[3] = 1;
                }
            }
        }
    }
    return Result;
}

// SetProcessContextWin10Operation — 设置进程上下文操作(Win10)
// 对应原始驱动 sub_140032480 (CmdSetProcessContextWin10)
__int64 SetProcessContextWin10Operation(char *pInputBuffer, int InputSize)
{
    char Result;
    char WriteResult;
    char PatchResult;
    void *TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if (pInputBuffer && InputSize == 56 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 56) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x38, 1);
        WriteResult = 1;
        PatchResult = 1;
        if (pInputBuffer[32] == 1)
            WriteResult = WriteProcessContextEntry((__int64)pInputBuffer);
        if (pInputBuffer[33] == 1)
        {
            PatchResult = 0;
            TargetAddress = (void *)*((_QWORD *)pInputBuffer + 2);
            if (TargetAddress &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 2) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 34);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 2), &PatchData, 0x10, 0, 0);
            }
        }
        return WriteResult & PatchResult;
    }
    return Result;
}

// EnumProcessProtectContextOperation — 枚举进程保护上下文操作
// 对应原始驱动 sub_1400474D8 (CmdEnumProcessProtectContext)
__int64 EnumProcessProtectContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int BufferSize)
{
    char Result;
    int IsReady;

    Result = 0;
    if (pOutputBuffer && BufferSize == 1352 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548, 1);
        memset(pOutputBuffer, 0, 0x548);
        IsReady = GtRead(GtFltUnregisterFilterOffset | GtEprocessField86);
        if (!IsReady)
        {
            BuildContextTableFromNtFile();
            IsReady = GtRead(GtFltUnregisterFilterOffset | GtEprocessField86);
        }
        if (EnumerateSyscallContextVector((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopyContextTableEntries((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// SetProcessProtectContextOperation — 设置进程保护上下文操作
// 对应原始驱动 sub_140047734 (CmdSetProcessProtectContext)
__int64 SetProcessProtectContextOperation(char *pInputBuffer, int InputSize)
{
    char Result;
    char IsContextSet;
    char IsBufferWritten;
    PVOID pTargetAddress;
    _OWORD BufferData;

    Result = 0;
    if (pInputBuffer && InputSize == 48 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30, 1);
        IsContextSet = 1;
        IsBufferWritten = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            IsContextSet = SetSyscallContextByIndex((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            IsBufferWritten = 0;
            pTargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (pTargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(pTargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                BufferData = *(_OWORD *)(pInputBuffer + 26);
                IsBufferWritten = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &BufferData, 0x10, 0, 0);
            }
        }
        return IsContextSet & IsBufferWritten;
    }
    return Result;
}

// EnumCallbackContextOperation — 枚举回调上下文操作
// 对应原始驱动 sub_14003602C (CmdEnumCallbackContext)
__int64 EnumCallbackContextOperation(__int64 InputBuffer, __int64 InputSize, _WORD *pOutputBuffer, int OutputSize)
{
    char Result;
    int TableReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 1352 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 676) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548, 1);
        memset(pOutputBuffer, 0, 0x548);
        TableReady = GtRead((enum _GLOBAL_TABLE_INDEX)2308);
        if (!TableReady)
        {
            BuildCallbackContextHookTargets();
            TableReady = GtRead((enum _GLOBAL_TABLE_INDEX)2308);
        }
        if (EnumCallbackContextTable((__int64)(pOutputBuffer + 4)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopyCallbackContextHookTable((__int64)(pOutputBuffer + 4)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 4)) == 1)
                {
                    *(_BYTE *)pOutputBuffer = 1;
                    pOutputBuffer[1] = GtRead(GtWindowsBuildNumber);
                }
            }
        }
    }
    return Result;
}

// SetCallbackContextOperation — 设置回调上下文操作
// 对应原始驱动 sub_1400362C8 (CmdSetCallbackContext)
__int64 SetCallbackContextOperation(char *pInputBuffer, int InputSize)
{
    char Result;
    char HookResult;
    char PatchResult;
    PVOID TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if (pInputBuffer && InputSize == 48 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30, 1);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = InstallCallbackContextHookEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// EnumThreadContextWin10Operation — 枚举线程上下文操作(Win10)
// 对应原始驱动 sub_140057214 (CmdEnumThreadContextWin10)
__int64 EnumThreadContextWin10Operation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int TableReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 1352 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548, 1);
        memset(pOutputBuffer, 0, 0x548);
        TableReady = GtRead(GtPathBuffer03 | 0x900);
        if (!TableReady)
        {
            InitThreadContextTable();
            TableReady = GtRead(GtPathBuffer03 | 0x900);
        }
        if (EnumThreadContextTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopyThreadContextTable((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// SetThreadContextWin10Operation — 设置线程上下文操作(Win10)
// 对应原始驱动 sub_140057470 (CmdSetThreadContextWin10)
__int64 SetThreadContextWin10Operation(char *Address, int InputSize)
{
    char Result;
    char WriteResult;
    char PatchResult;
    PVOID TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if (Address && InputSize == 48 &&
        (unsigned __int64)Address < MmUserProbeAddress &&
        (unsigned __int64)(Address + 48) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x30, 1);
        WriteResult = 1;
        PatchResult = 1;
        if (Address[24] == 1 && *((_QWORD *)Address + 1))
            WriteResult = WriteThreadContextEntryWin10((unsigned int *)Address);
        if (Address[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)Address + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)Address + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(Address + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 1), &PatchData, 0x10, 0, 0);
            }
        }
        return WriteResult & PatchResult;
    }
    return Result;
}

// EnumRegistryContextOperation — 枚举注册表上下文操作
// 对应原始驱动 sub_1400460B8 (CmdEnumRegistryContext)
__int64 EnumRegistryContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int BufferSize)
{
    char Result;
    int IsReady;

    Result = 0;
    if (pOutputBuffer && BufferSize == 1800 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1800) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x708, 1);
        memset(pOutputBuffer, 0, 0x708);
        IsReady = GtRead(GtFltPeSectionOfs6 | GtEprocessField54);
        if (!IsReady)
        {
            ParseRegistryDriverExportDir();
            IsReady = GtRead(GtFltPeSectionOfs6 | GtEprocessField54);
        }
        if (EnumerateRegistryContextTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopyRegistryContextEntryArray((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateCallbackContextTable((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// SetRegistryContextOperation — 设置注册表上下文操作
// 对应原始驱动 sub_14004630C (CmdSetRegistryContext)
__int64 SetRegistryContextOperation(char *pInputBuffer, int InputSize)
{
    char Result;
    char IsContextSet;
    char IsBufferWritten;
    PVOID pTargetAddress;
    _OWORD BufferData[2];

    Result = 0;
    if (pInputBuffer && InputSize == 64 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 64) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x40, 1);
        IsContextSet = 1;
        IsBufferWritten = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            IsContextSet = SetRegistryContextEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            IsBufferWritten = 0;
            pTargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (pTargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(pTargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 31LL)) == 1)
            {
                BufferData[0] = *(_OWORD *)(pInputBuffer + 26);
                BufferData[1] = *(_OWORD *)(pInputBuffer + 42);
                IsBufferWritten = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), BufferData, 0x20, 0, 0);
            }
        }
        return IsContextSet & IsBufferWritten;
    }
    return Result;
}

// EnumFileSystemContextOperation — 枚举文件系统上下文操作
// 对应原始驱动 sub_14003E71C (CmdEnumFileSystemContext)
__int64 EnumFileSystemContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int IsReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 1800 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1800) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x708, 1);
        memset(pOutputBuffer, 0, 0x708);
        IsReady = GtRead(GtFltPeSectionAddr7 | GtEprocessField54);
        if (!IsReady)
        {
            InitCallbackContextHookTable();
            IsReady = GtRead(GtFltPeSectionAddr7 | GtEprocessField54);
        }
        if (EnumCallbackContextV3Table((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (IsReady)
            {
                if (CopyCallbackContextV3Table((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateCallbackContextTable((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// SetFileSystemContextOperation — 设置文件系统上下文操作
// 对应原始驱动 sub_14003E970 (CmdSetFileSystemContext)
__int64 SetFileSystemContextOperation(char *pInputBuffer, int InputSize)
{
    char Result;
    char IsHookReady;
    char IsPatchReady;
    PVOID TargetAddress;
    _OWORD PatchData[2];

    Result = 0;
    if (pInputBuffer && InputSize == 64 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 64) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x40, 1);
        IsHookReady = 1;
        IsPatchReady = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            IsHookReady = SetCallbackContextEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            IsPatchReady = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 31LL)) == 1)
            {
                PatchData[0] = *(_OWORD *)(pInputBuffer + 26);
                PatchData[1] = *(_OWORD *)(pInputBuffer + 42);
                IsPatchReady = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), PatchData, 0x20, 0, 0);
            }
        }
        return IsHookReady & IsPatchReady;
    }
    return Result;
}

// EnumUSBPortSyscallTableOperation — 枚举USB端口系统调用表操作
// 对应原始驱动 sub_140055A60 (CmdEnumUSBPortSyscallTable)
__int64 EnumUSBPortSyscallTableOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Result;
    int TableReady;

    Result = 0;
    if (pOutputBuffer && OutputSize == 1352 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x548, 1);
        memset(pOutputBuffer, 0, 0x548);
        TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField186);
        if (!TableReady)
        {
            InitUSBPortSyscallTable();
            TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField186);
        }
        if (CopyUSBPortServiceTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (DuplicateUSBPortSyscallOutput((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(pOutputBuffer + 8)) == 1)
                {
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Result;
}

// InstallUSBPortSyscallHookOperation — 安装USB端口系统调用钩子操作
// 对应原始驱动 sub_140055CBC (CmdInstallUSBPortSyscallHook)
__int64 InstallUSBPortSyscallHookOperation(char *Address, int InputSize)
{
    char Result;
    char WriteResult;
    char PatchResult;
    PVOID TargetAddress;
    _OWORD PatchData;

    Result = 0;
    if (Address && InputSize == 48 &&
        (unsigned __int64)Address < MmUserProbeAddress &&
        (unsigned __int64)(Address + 48) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x30, 1);
        WriteResult = 1;
        PatchResult = 1;
        if (Address[24] == 1 && *((_QWORD *)Address + 1))
            WriteResult = SetUSBPortServiceTableEntry((unsigned int *)Address);
        if (Address[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)Address + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)Address + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(Address + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 1), &PatchData, 0x10, 0, 0);
            }
        }
        return WriteResult & PatchResult;
    }
    return Result;
}

// EnumObjectContextOperation — 枚举对象上下文操作
// 对应原始驱动 sub_140037BD8 (CmdEnumObjectContext)
__int64 EnumObjectContextOperation(__int64 InputBuffer, __int64 InputSize, _BYTE *pOutputBuffer, int OutputSize)
{
    char Success;
    int TableReady;

    Success = 0;
    if (pOutputBuffer && OutputSize == 1400 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1400) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x578, 1);
        memset(pOutputBuffer, 0, 0x578);
        TableReady = GtRead(GtNtCreateProcessResultAddr | GtEprocessField06);
        if (!TableReady)
        {
            ParseObjectContextExportDir();
            TableReady = GtRead(GtNtCreateProcessResultAddr | GtEprocessField06);
        }
        if (EnumObjectContextTable((__int64)(pOutputBuffer + 8)) == 1)
        {
            Success = 1;
            if (TableReady)
            {
                if (CopyObjectContextHookTable((__int64)(pOutputBuffer + 8)) == 1 &&
                    ValidateSsdtHookTargetTable((__int64)(pOutputBuffer + 8)) == 1)
                {
                    if (*((_DWORD *)pOutputBuffer + 339))
                        pOutputBuffer[1] = 1;
                    *pOutputBuffer = 1;
                }
            }
        }
    }
    return Success;
}

// SetObjectContextOperation — 设置对象上下文操作
// 对应原始驱动 sub_140037E54 (CmdSetObjectContext)
__int64 SetObjectContextOperation(char *pInputBuffer, int InputSize)
{
    char Success;
    char HookResult;
    char PatchResult;
    PVOID TargetAddress;
    _OWORD PatchData;

    Success = 0;
    if (pInputBuffer && InputSize == 48 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 48) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x30, 1);
        HookResult = 1;
        PatchResult = 1;
        if (pInputBuffer[24] == 1 && *((_QWORD *)pInputBuffer + 1))
            HookResult = SetObjectContextEntry((unsigned int *)pInputBuffer);
        if (pInputBuffer[25] == 1)
        {
            PatchResult = 0;
            TargetAddress = (PVOID)*((_QWORD *)pInputBuffer + 1);
            if (TargetAddress > MmSystemRangeStart &&
                MmIsAddressValid(TargetAddress) == 1 &&
                MmIsAddressValid((PVOID)(*((_QWORD *)pInputBuffer + 1) + 15LL)) == 1)
            {
                PatchData = *(_OWORD *)(pInputBuffer + 26);
                PatchResult = WritePhysicalMemoryBuffer(*((_QWORD *)pInputBuffer + 1), &PatchData, 0x10, 0, 0);
            }
        }
        return HookResult & PatchResult;
    }
    return Success;
}

// EnumObjectTypeDirectoryOperation — 枚举对象类型目录操作
// 对应原始驱动 sub_14006AC54 (CmdEnumObjectTypeDirectory)
// 读取内核内存上下文，遍历对象类型目录的两个链表，输出每个类型/目录的名称和地址
__int64 EnumObjectTypeDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 ContextPtr;
    unsigned __int64 SavedContext;
    unsigned int *pEntry;
    unsigned int RemainingSize;
    int LoopIndex;
    int InnerLoopIndex;
    _QWORD *pNode;
    unsigned int EntryIndex;
    unsigned __int64 MaxEntries;
    _QWORD *pSubNode;
    unsigned int SubIndex;
    PVOID ObjectHeader;
    unsigned int EntryCount;
    int Remaining;
    int Remaining2;
    int Remaining3;
    unsigned __int64 ContextSize;

    if (!GtRead(GtEprocessExtField58 | GtEprocessField63 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField58 | GtEprocessField63 | 0x400);
    ContextSize = ContextPtr;
    if (ContextPtr && ContextPtr > (unsigned __int64)MmSystemRangeStart &&
        pOutputBuffer && OutputSize >= 0x40 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 8);
        memset(pOutputBuffer, 0, OutputSize);
        *pOutputBuffer = 0;
        pEntry = pOutputBuffer + 2;
        RemainingSize = OutputSize - 8;
        Remaining = RemainingSize;
        LoopIndex = 0;
        Remaining3 = 0;
        while (LoopIndex < 2)
        {
            pNode = (_QWORD *)(ContextPtr + 80LL * LoopIndex);
            InnerLoopIndex = 0;
            Remaining2 = 0;
            while (pNode && pNode > MmSystemRangeStart && RemainingSize > 0x40 && InnerLoopIndex <= 0x10000)
            {
                *((_QWORD *)pEntry + 1) = pNode;
                *(_QWORD *)pEntry = 0;
                MaxEntries = ((unsigned __int64)RemainingSize - 56) / 0x28 + 1;
                pSubNode = (_QWORD *)pNode[3];
                for (SubIndex = 0; pSubNode != pNode + 3 && pSubNode > MmSystemRangeStart && (int)MaxEntries && SubIndex <= 0x10000 && CheckMemoryValid(pSubNode - 2) == 1; ++SubIndex)
                {
                    ObjectHeader = (PVOID)pSubNode[8];
                    if (ObjectHeader > MmSystemRangeStart && CheckMemoryValid(ObjectHeader) == 1)
                    {
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 4] = pSubNode - 2;
                        *((_BYTE *)&pEntry[10 * pEntry[1] + 6]) = 1;
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 8] = *(_QWORD *)(pSubNode[8] + 8);
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 10] = *(_QWORD *)(pSubNode[8] + 16);
                        *(_QWORD *)&pEntry[10 * pEntry[1]++ + 12] = *(_QWORD *)(pSubNode[8] + 24);
                        MaxEntries = (unsigned __int64)((int)MaxEntries - 1);
                    }
                    pSubNode = (_QWORD *)*pSubNode;
                }
                pSubNode = (_QWORD *)pNode[5];
                for (SubIndex = 0; pSubNode != pNode + 5 && pSubNode > MmSystemRangeStart && (int)MaxEntries && SubIndex <= 0x10000 && CheckMemoryValid(pSubNode - 2) == 1; ++SubIndex)
                {
                    ObjectHeader = (PVOID)pSubNode[8];
                    if (ObjectHeader > MmSystemRangeStart && CheckMemoryValid(ObjectHeader) == 1)
                    {
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 4] = pSubNode - 2;
                        *((_BYTE *)&pEntry[10 * pEntry[1] + 6]) = 0;
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 8] = *(_QWORD *)(pSubNode[8] + 8);
                        *(_QWORD *)&pEntry[10 * pEntry[1] + 10] = *(_QWORD *)(pSubNode[8] + 16);
                        *(_QWORD *)&pEntry[10 * pEntry[1]++ + 12] = *(_QWORD *)(pSubNode[8] + 24);
                        MaxEntries = (unsigned __int64)((int)MaxEntries - 1);
                    }
                    pSubNode = (_QWORD *)*pSubNode;
                }
                EntryCount = pEntry[1];
                if (EntryCount)
                    *pEntry = 40 * (EntryCount - 1) + 56;
                else
                    *pEntry = 56;
                RemainingSize = Remaining - *pEntry;
                Remaining = RemainingSize;
                ++*pOutputBuffer;
                pEntry = (unsigned int *)((char *)pEntry + *pEntry);
                pNode = (_QWORD *)*pNode;
                InnerLoopIndex = ++Remaining2;
            }
            LoopIndex = ++Remaining3;
            ContextPtr = ContextSize;
        }
        return 1;
    }
    return 0;
}

// EnumObjectTypeTableOperation — 枚举对象类型表操作
// 对应原始驱动 sub_14006B0AC (CmdEnumObjectTypeTable)
// 遍历 ObTypeIndexTable 链表，输出每个类型条目和对象指针
__int64 EnumObjectTypeTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 ContextPtr;
    _QWORD *pTable;
    unsigned int *pEntry;
    unsigned int RemainingSize;
    _QWORD *pTypeNode;
    unsigned int NodeIndex;
    PVOID TypeInfo;
    PVOID EntryArray;
    unsigned int EntryCount;
    unsigned int EntryIndex;
    int TableTypeCount;
    _QWORD *pEntryArray;
    int TableEntryCount;
    _QWORD *pSubEntry;
    unsigned int SubIndex;
    int Remaining;
    _QWORD *pSubEntry2;
    unsigned int SubIndex2;
    unsigned int MaxEntries;
    int TypeIndex;
    int Remaining2;
    int LoopCount;
    int LoopCount2;
    unsigned int EntryLimit;
    _QWORD *CurrentEntry;
    _QWORD *TypeListHead;

    if (!GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400);
    pTable = (_QWORD *)ContextPtr;
    TypeListHead = (_QWORD *)ContextPtr;
    if (ContextPtr && ContextPtr > (unsigned __int64)MmSystemRangeStart &&
        pOutputBuffer && OutputSize >= 0x30 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 8);
        memset(pOutputBuffer, 0, OutputSize);
        *pOutputBuffer = 0;
        pEntry = pOutputBuffer + 2;
        RemainingSize = OutputSize - 8;
        pTypeNode = (_QWORD *)*pTable;
        NodeIndex = 0;
        TypeIndex = 0;
        while (pTypeNode && pTypeNode != pTable && pTypeNode > MmSystemRangeStart && RemainingSize > 0x30 && NodeIndex <= 0x10000)
        {
            TypeInfo = (PVOID)pTypeNode[5];
            if (TypeInfo > MmSystemRangeStart)
            {
                if (CheckMemoryValid(TypeInfo) == 1)
                {
                    EntryArray = (PVOID)pTypeNode[8];
                    if (EntryArray > MmSystemRangeStart && CheckMemoryValid(EntryArray) == 1)
                    {
                        EntryCount = *(_DWORD *)(pTypeNode[5] + 4);
                        EntryLimit = EntryCount;
                        EntryIndex = 0;
                        LoopCount2 = 0;
                        while (1)
                        {
                            if (EntryIndex >= EntryCount || RemainingSize <= 0x30)
                            {
                                pTable = TypeListHead;
                                break;
                            }
                            TableTypeCount = GtRead(GtWindowsBuildNumber);
                            pEntryArray = (_QWORD *)(pTypeNode[8] + 24LL * EntryIndex);
                            CurrentEntry = pEntryArray;
                            if (TableTypeCount >= 0x47BA)
                            {
                                if (pEntryArray > MmSystemRangeStart && CheckMemoryValid(pEntryArray) == 1)
                                {
                                    *((_QWORD *)pEntry + 1) = pEntryArray;
                                    *(_QWORD *)pEntry = 0;
                                    Remaining = ((unsigned __int64)RemainingSize - 40) / 0x18 + 1;
                                    pSubEntry2 = (_QWORD *)*pEntryArray;
                                    SubIndex2 = 0;
                                    LoopCount = 0;
                                    while (pSubEntry2 && pSubEntry2 != CurrentEntry && pSubEntry2 > MmSystemRangeStart && Remaining && SubIndex2 <= 0x10000)
                                    {
                                        if (CheckMemoryValid(pSubEntry2) == 1 && pSubEntry2[3])
                                        {
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 4] = pSubEntry2;
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 6] = pSubEntry2[3];
                                            *(_QWORD *)&pEntry[6 * pEntry[1]++ + 8] = 0;
                                            --Remaining;
                                        }
                                        SubIndex2 = ++LoopCount;
                                        pSubEntry2 = (_QWORD *)*pSubEntry2;
                                    }
                                    goto LABEL_47;
                                }
                            }
                            else if (pEntryArray > MmSystemRangeStart && CheckMemoryValid(pEntryArray) == 1)
                            {
                                *((_QWORD *)pEntry + 1) = pEntryArray;
                                *(_QWORD *)pEntry = 0;
                                TableEntryCount = ((unsigned __int64)RemainingSize - 40) / 0x18 + 1;
                                pSubEntry = (_QWORD *)*pEntryArray;
                                SubIndex = 0;
                                Remaining2 = 0;
                                while (pSubEntry && pSubEntry != CurrentEntry && pSubEntry > MmSystemRangeStart && TableEntryCount && SubIndex <= 0x10000)
                                {
                                    if (CheckMemoryValid(pSubEntry) == 1)
                                    {
                                        TableTypeCount;
                                        if (pSubEntry[3])
                                        {
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 4] = pSubEntry;
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 6] = pSubEntry[3];
                                            *(_QWORD *)&pEntry[6 * pEntry[1]++ + 8] = 0;
                                            --TableEntryCount;
                                        }
                                    }
                                    SubIndex = ++Remaining2;
                                    pSubEntry = (_QWORD *)*pSubEntry;
                                }
                                goto LABEL_47;
                            }
                            LoopCount2 = ++EntryIndex;
                            EntryCount = EntryLimit;
                            continue;
                        LABEL_47:
                            MaxEntries = pEntry[1];
                            if (MaxEntries)
                                *pEntry = 40 * (MaxEntries - 1) + 48;
                            else
                                *pEntry = 48;
                            RemainingSize -= *pEntry;
                            ++*pOutputBuffer;
                            pEntry = (unsigned int *)((char *)pEntry + *pEntry);
                            EntryIndex = LoopCount2;
                        }
                    }
                }
                NodeIndex = TypeIndex;
            }
            TypeIndex = ++NodeIndex;
            pTypeNode = (_QWORD *)*pTypeNode;
        }
        return 1;
    }
    return 0;
}

// EnumObjectTypeDetailOperation — 枚举对象类型详细信息操作
// 对应原始驱动 sub_14006B49C (CmdEnumObjectTypeDetail)
// 遍历 ObTypeIndexTable 链表，输出每个类型条目的详细信息
__int64 EnumObjectTypeDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 ContextPtr;
    _QWORD *pTable;
    _QWORD *pTypeNode;
    unsigned int NodeIndex;
    PVOID TypeInfo;
    __int64 TypeInfoPtr;
    unsigned int EntryCount;
    _QWORD *pEntry;
    unsigned int EntryIndex;
    unsigned __int64 EntryOffset;
    int StrideSize;
    int TypeCount;
    unsigned int EntryLimit;
    _QWORD *TypeList;

    if (!GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400);
    pTable = (_QWORD *)ContextPtr;
    TypeList = (_QWORD *)ContextPtr;
    if (ContextPtr && ContextPtr > (unsigned __int64)MmSystemRangeStart &&
        pOutputBuffer && OutputSize >= 0x48 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 8);
        memset(pOutputBuffer, 0, OutputSize);
        StrideSize = GtRead(GtWindowsBuildNumber) < 0x23F0 ? 88 : 104;
        *pOutputBuffer = 0;
        pTypeNode = (_QWORD *)*pTable;
        for (NodeIndex = 0; pTypeNode && pTypeNode != pTable && pTypeNode > MmSystemRangeStart && OutputSize > 0x48 && NodeIndex <= 0x10000; ++NodeIndex)
        {
            TypeInfo = (PVOID)pTypeNode[5];
            if (TypeInfo > MmSystemRangeStart && CheckMemoryValid(TypeInfo) == 1)
            {
                TypeInfoPtr = pTypeNode[5];
                EntryCount = *(_DWORD *)(TypeInfoPtr + 4);
                EntryLimit = EntryCount;
                pEntry = *(_QWORD **)(TypeInfoPtr + 8);
                for (EntryIndex = 0; EntryIndex < EntryCount && OutputSize > 0x48 && pEntry > MmSystemRangeStart && CheckMemoryValid(pEntry) == 1; ++EntryIndex)
                {
                    if (pEntry[4] || pEntry[5] || pEntry[6] || pEntry[7] || pEntry[8] || pEntry[9] || pEntry[10])
                    {
                        EntryOffset = (unsigned __int64)(unsigned int)*pOutputBuffer << 6;
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 8) = pEntry;
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 16) = pEntry[4];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 24) = pEntry[5];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 32) = pEntry[6];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 40) = pEntry[7];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 48) = pEntry[8];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 56) = pEntry[9];
                        *(_QWORD *)((char *)pOutputBuffer + EntryOffset + 64) = pEntry[10];
                        ++*pOutputBuffer;
                        OutputSize -= 64;
                    }
                    pEntry = (_QWORD *)((char *)pEntry + StrideSize);
                    EntryCount = EntryLimit;
                }
                pTable = TypeList;
            }
            pTypeNode = (_QWORD *)*pTypeNode;
        }
        return 1;
    }
    return 0;
}

// EnumObjectTypeInfoOperation — 枚举对象类型信息操作
// 对应原始驱动 sub_14007EDC8 (CmdEnumObjectTypeInfo)
// 遍历对象类型链表，收集每个对象类型的名称、索引、方法表等信息
__int64 EnumObjectTypeInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    _QWORD **pTypeList;
    unsigned int MaxTypes;
    unsigned int TypeIndex;
    _QWORD *pTypeNode;
    __int64 CurrentTypeCount;
    PVOID TypeNameData;
    unsigned __int16 NameLength;
    _OWORD *pNameSrc;
    unsigned int *pNameDst;
    __int64 CopyCount;

    if (!GtRead(GtPathBuffer03 | 0x800))
    {
        InitTdiExportAndRelocTable();
    }
    pTypeList = (_QWORD **)GtRead(GtPathBuffer03 | 0x800);
    if (pTypeList && pOutputBuffer && OutputSize >= 0x240 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 4);
        memset(pOutputBuffer, 0, OutputSize);
        MaxTypes = (OutputSize - 576) / 0x238 + 1;
        *(_QWORD *)pOutputBuffer = 0;
        TypeIndex = 0;
        pTypeNode = *pTypeList;
        while (pTypeNode > MmSystemRangeStart && pTypeNode != pTypeList && TypeIndex <= 0x1000)
        {
            if (CheckMemoryValid(pTypeNode) == 1 && CheckMemoryValid((char *)pTypeNode + 87) == 1)
            {
                CurrentTypeCount = pOutputBuffer[1];
                if ((unsigned int)CurrentTypeCount < MaxTypes)
                {
                    *((_WORD *)&pOutputBuffer[142 * CurrentTypeCount + 2]) = *((_WORD *)pTypeNode + 12);
                    *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 4] = pTypeNode;
                    *((_WORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 6]) = 0;
                    *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 134] = pTypeNode[6];
                    if (*((_WORD *)pTypeNode + 12) == 1)
                        *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 136] = pTypeNode[7];
                    *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 138] = pTypeNode[8];
                    *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 140] = pTypeNode[9];
                    if (*((_WORD *)pTypeNode + 12) != 1)
                        *(_QWORD *)&pOutputBuffer[142 * pOutputBuffer[1] + 142] = pTypeNode[10];
                    if (*((_WORD *)pTypeNode + 16))
                    {
                        TypeNameData = (PVOID)pTypeNode[5];
                        if (TypeNameData > MmSystemRangeStart && CheckMemoryValid(TypeNameData) == 1)
                        {
                            NameLength = *((_WORD *)pTypeNode + 16);
                            pNameSrc = (_OWORD *)pTypeNode[5];
                            if (NameLength > 0x1FE)
                            {
                                pNameDst = &pOutputBuffer[142 * pOutputBuffer[1] + 6];
                                CopyCount = 3;
                                do
                                {
                                    *(_OWORD *)pNameDst = *pNameSrc;
                                    *((_OWORD *)pNameDst + 1) = pNameSrc[1];
                                    *((_OWORD *)pNameDst + 2) = pNameSrc[2];
                                    *((_OWORD *)pNameDst + 3) = pNameSrc[3];
                                    *((_OWORD *)pNameDst + 4) = pNameSrc[4];
                                    *((_OWORD *)pNameDst + 5) = pNameSrc[5];
                                    *((_OWORD *)pNameDst + 6) = pNameSrc[6];
                                    pNameDst += 32;
                                    *((_OWORD *)pNameDst - 1) = pNameSrc[7];
                                    pNameSrc += 8;
                                    --CopyCount;
                                }
                                while (CopyCount);
                                *(_OWORD *)pNameDst = *pNameSrc;
                                *((_OWORD *)pNameDst + 1) = pNameSrc[1];
                                *((_OWORD *)pNameDst + 2) = pNameSrc[2];
                                *((_OWORD *)pNameDst + 3) = pNameSrc[3];
                                *((_OWORD *)pNameDst + 4) = pNameSrc[4];
                                *((_OWORD *)pNameDst + 5) = pNameSrc[5];
                                *((_OWORD *)pNameDst + 6) = pNameSrc[6];
                                *((_QWORD *)pNameDst + 14) = *((_QWORD *)pNameSrc + 14);
                                pNameDst[30] = *((_DWORD *)pNameSrc + 30);
                                *((_WORD *)pNameDst + 62) = *((_WORD *)pNameSrc + 62);
                            }
                            else
                            {
                                memmove(&pOutputBuffer[142 * pOutputBuffer[1] + 6], pNameSrc, NameLength);
                            }
                        }
                    }
                    ++pOutputBuffer[1];
                }
                ++*pOutputBuffer;
            }
            pTypeNode = (_QWORD *)*pTypeNode;
            ++TypeIndex;
        }
        return 1;
    }
    return 0;
}

// EnumKernelHandleTableOperation — 枚举内核句柄表操作
// 对应原始驱动 sub_140067278 (CmdEnumKernelHandleTable)
// 仅支持 Win10+，遍历内核句柄表链表，输出句柄表条目
__int64 EnumKernelHandleTableOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    _QWORD **pHandleTable;
    unsigned int BuildNumber;
    int MaxEntries;
    _QWORD *pEntry;
    unsigned int Index;

    pHandleTable = (_QWORD **)GtRead(GtEprocessExtField35);
    if (!pHandleTable)
    {
        InitKernelDataSectionTable();
        pHandleTable = (_QWORD **)GtRead(GtEprocessExtField35);
    }
    BuildNumber = GtRead(GtEprocessExtField13);
    if (pHandleTable && pHandleTable > MmSystemRangeStart && BuildNumber >= 0x60000 &&
        pOutputBuffer && OutputSize >= 0x28 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 4);
        memset(pOutputBuffer, 0, OutputSize);
        MaxEntries = ((OutputSize - 40) >> 5) + 1;
        *pOutputBuffer = 0;
        pEntry = *pHandleTable;
        for (Index = 0; Index < 0x1000 && pEntry != pHandleTable && pEntry > MmSystemRangeStart && CheckMemoryValid(pEntry) == 1 && MaxEntries; ++Index)
        {
            *(_QWORD *)&pOutputBuffer[8 * *pOutputBuffer + 2] = pEntry;
            *(_QWORD *)&pOutputBuffer[8 * *pOutputBuffer + 4] = pEntry[4];
            *(_QWORD *)&pOutputBuffer[8 * *pOutputBuffer + 6] = pEntry[6];
            *(_QWORD *)&pOutputBuffer[8 * (*pOutputBuffer)++ + 8] = pEntry[7];
            --MaxEntries;
            pEntry = (_QWORD *)*pEntry;
        }
        return *pOutputBuffer != 0;
    }
    return 0;
}

// DiskSectorReadWriteOperation — 磁盘扇区读写操作
// 对应原始驱动 sub_14007B72C (CmdDiskSectorReadWrite)
// 验证用户缓冲区后调度到 ReadDiskSectorsWithPartition 或 WriteDiskSectorsWithPartitionCheck
__int64 DiskSectorReadWriteOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    int DiskResult;
    unsigned int DiskNumber;
    char Status;

    Result = 0;
    if (!pInputBuffer)
        return Result;
    if (InputSize != 262156)
        return Result;
    if ((unsigned __int64)pInputBuffer >= MmUserProbeAddress)
        return Result;
    if ((unsigned __int64)(pInputBuffer + 262156) >= MmUserProbeAddress)
        return Result;
    ProbeForRead(pInputBuffer, 0x4000C, 1);
    ProbeForWrite(pInputBuffer, 0x4000C, 1);
    if ((unsigned int)(*((_DWORD *)pInputBuffer + 1) - 1) > 0x3F)
        return Result;
    switch (*(_DWORD *)pInputBuffer)
    {
    case 0:
        Status = 1;
        goto LABEL_16;
    case 1:
        Status = 0;
LABEL_16:
        *((_DWORD *)pInputBuffer + 2) = 0x40000;
        return ReadDiskSectorsWithPartition(Status, pInputBuffer + 12, (unsigned int *)pInputBuffer + 2, *((_DWORD *)pInputBuffer + 1), 0x1000);
    case 2:
        DiskNumber = *((_DWORD *)pInputBuffer + 2);
        if (DiskNumber <= 0x40000)
        {
            *((_BYTE *)&DiskResult) = 1;
            return WriteDiskSectorsWithPartitionCheck(DiskResult, pInputBuffer + 12, DiskNumber);
        }
        break;
    default:
        DiskResult = *(_DWORD *)pInputBuffer - 3;
        if (*(_DWORD *)pInputBuffer == 3)
        {
            DiskNumber = *((_DWORD *)pInputBuffer + 2);
            if (DiskNumber <= 0x40000)
                return WriteDiskSectorsWithPartitionCheck(DiskResult, pInputBuffer + 12, DiskNumber);
        }
        break;
    }
    return Result;
}

// DiskReadSectorOperation — 磁盘读取扇区操作
// 对应原始驱动 CmdDiskReadSector (0x14007B854)
// 读取MBR引导扇区，分析分区表找到可引导分区，读取分区引导扇区并检查扇区健康状态
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    struct _DEVICE_OBJECT *DeviceObject;
    struct _IRP *Irp;
    unsigned int *IrpData;
    SIZE_T BufferSize;
    void *Buffer;
    void *AllocBuffer;
    unsigned int i;
    int BootablePartitionLba;
    int Lba;
    unsigned int j;

    Result = 0;
    if (pOutputBuffer)
    {
        if (OutputSize >= 0x4028
            && OutputSize < MmUserProbeAddress
            && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
            && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, OutputSize, 1);
            RtlFillMemory(pOutputBuffer, 0x4028, 0);
            DeviceObject = (struct _DEVICE_OBJECT *)QueryObjectTypeDirectoryPath();
            if (DeviceObject)
            {
                Irp = (struct _IRP *)ExAlloc(0, 0x18);
                IrpData = (unsigned int *)Irp;
                if (Irp)
                {
                    if (SendDiskDeviceInternalIrp((__int64)DeviceObject, Irp))
                    {
                        BufferSize = IrpData[5];
                        if ((unsigned int)BufferSize <= 0x1000)
                        {
                            AllocBuffer = ExAlloc(0, (unsigned int)BufferSize);
                            Buffer = AllocBuffer;
                            if (AllocBuffer)
                            {
                                RtlFillMemory(AllocBuffer, (unsigned int)BufferSize, 0);
                                if (!(unsigned int)DispatchDiskIrpWithHookInit(DeviceObject, 3, Buffer, 0, 1, (unsigned int)BufferSize))
                                {
                                    for (i = 0; i < (unsigned int)BufferSize; ++i)
                                    {
                                        if (*((unsigned char *)Buffer + i))
                                        {
                                            if (i < (unsigned int)BufferSize)
                                            {
                                                *pOutputBuffer = BufferSize;
                                                *(_QWORD *)(pOutputBuffer + 1) = 0;
                                                pOutputBuffer[3] = 0;
                                                pOutputBuffer[1028] = 0;
                                                RtlMoveMemory(pOutputBuffer + 4, Buffer, BufferSize);
                                                if ((unsigned __int8)ProcessDiskSectorData(DeviceObject, 0, Buffer, (unsigned int)BufferSize) == 1)
                                                {
                                                    pOutputBuffer[1028] = 1;
                                                    RtlMoveMemory(pOutputBuffer + 1029, Buffer, BufferSize);
                                                }
                                                AnalyzeDiskSectorBuffer((__int64)pOutputBuffer);
                                                if (pOutputBuffer[1] || pOutputBuffer[2])
                                                    pOutputBuffer[3] = FindBootSectorWithRetry(DeviceObject, (unsigned int)BufferSize);
                                                if (!pOutputBuffer[1] && !pOutputBuffer[2] && CheckMbrBootablePartition((__int64)(pOutputBuffer + 4)))
                                                {
                                                    BootablePartitionLba = FindBootablePartitionLba((__int64)(pOutputBuffer + 4));
                                                    Lba = BootablePartitionLba;
                                                    if (BootablePartitionLba)
                                                    {
                                                        pOutputBuffer[2053] = BootablePartitionLba;
                                                        RtlFillMemory(Buffer, 0, (unsigned int)BufferSize);
                                                        if (!(unsigned int)DispatchDiskIrpWithHookInit(DeviceObject, 3, Buffer, Lba, 1, (unsigned int)BufferSize))
                                                        {
                                                            for (j = 0; j < (unsigned int)BufferSize; ++j)
                                                            {
                                                                if (*((unsigned char *)Buffer + j))
                                                                {
                                                                    if (j < (unsigned int)BufferSize)
                                                                    {
                                                                        pOutputBuffer[3078] = 0;
                                                                        RtlMoveMemory(pOutputBuffer + 2054, Buffer, BufferSize);
                                                                        if ((unsigned __int8)ProcessDiskSectorData(DeviceObject, (unsigned int)(BufferSize * Lba), Buffer, (unsigned int)BufferSize) == 1)
                                                                        {
                                                                            pOutputBuffer[3078] = 1;
                                                                            RtlMoveMemory(pOutputBuffer + 3079, Buffer, BufferSize);
                                                                        }
                                                                        CheckDiskSectorHealth((char *)pOutputBuffer);
                                                                        if (pOutputBuffer[4103])
                                                                            pOutputBuffer[4105] = FindReadableDiskSector(DeviceObject, (unsigned int)BufferSize, (__int64)pOutputBuffer);
                                                                    }
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Result = 1;
                                            }
                                            break;
                                        }
                                    }
                                }
                                ExFree(Buffer);
                            }
                        }
                    }
                    ExFree(IrpData);
                }
            }
        }
    }
    return Result;
}

// RegistryOperation — 注册表操作
// 对应原始驱动 sub_14007EA14 (CmdRegistryOperation)
// 通过进程ID查找进程，初始化进程并查询注册表操作信息
__int64 RegistryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PEPROCESS Process;
    struct _KPROCESS *pProcess;
    NTSTATUS Status;
    int Status2;
    char Inited;

    Result = 0;
    if (InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 8);
        Status = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
        Status2 = Status;
        pProcess = (struct _KPROCESS *)((unsigned __int64)*(__int64 *)(pInputBuffer + 8));
        if (!pProcess)
        {
            if (Status >= 0)
                pProcess = (struct _KPROCESS *)Process;
        }
        if ((struct _KPROCESS *)GtRead(GtEprocessField123 | 0x100) != pProcess &&
            ValidateProcessObject(pProcess, 0) == 1)
        {
            if (GtRead(GtWindowsBuildNumber) < 0xA28)
                Inited = EnumProcessAndInitObjects((__int64)pProcess, 1);
            else
                Inited = InitProcessAndQueryInfo(pProcess, 1);
            Result = Inited;
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// RegistryProtectOperation — 注册表保护操作
// 对应原始驱动 sub_14007E498 (CmdRegistryProtect)
// 通过进程ID查找进程，初始化进程并查询对象信息和注册表保护状态
__int64 RegistryProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PEPROCESS Process;
    struct _KPROCESS *pProcess;
    NTSTATUS Status;
    int Status2;
    char Inited;

    Result = 0;
    if (InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 8);
        Status = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
        Status2 = Status;
        pProcess = (struct _KPROCESS *)((unsigned __int64)*(__int64 *)(pInputBuffer + 8));
        if (!pProcess)
        {
            if (Status >= 0)
                pProcess = (struct _KPROCESS *)Process;
        }
        if ((struct _KPROCESS *)GtRead(GtEprocessField123 | 0x100) != pProcess &&
            ValidateProcessObject(pProcess, 0) == 1)
        {
            if (GtRead(GtWindowsBuildNumber) < 0xA28)
                Inited = EnumProcessAndInitObjects((__int64)pProcess, 0);
            else
                Inited = InitProcessAndQueryInfo(pProcess, 0);
            Result = Inited;
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// ModuleOperation — 模块操作
// 对应原始驱动 sub_140058890 (CmdModuleOperation)
// 验证输入缓冲区，调用服务表基址函数执行模块操作
__int64 ModuleOperation(__int64 *pInputBuffer, unsigned int InputSize)
{
    char Result;
    __int64 Address;
    int (*pFunc)(__int64);

    Result = 0;
    if ((unsigned __int64)pInputBuffer < MmUserProbeAddress)
    {
        if (pInputBuffer)
        {
            if ((unsigned __int64)pInputBuffer + InputSize < MmUserProbeAddress && InputSize == 8)
            {
                ProbeForRead(pInputBuffer, 8, 4);
                Address = *pInputBuffer;
                pFunc = (int (*)(__int64))GtRead(GtCallbackField56);
                if (pFunc)
                    return pFunc(Address) >= 0;
                ResolveServiceTableBase();
                pFunc = (int (*)(__int64))GtRead(GtCallbackField56);
                if (pFunc)
                    return pFunc(Address) >= 0;
            }
        }
    }
    return Result;
}

// ObjectOperation — 对象操作
// 对应原始驱动 sub_1400363F8 (CmdObjectOperation)
// 根据构建号判断：若 < 0x585D(Win10+)则调用 CmdObjectOperationByHandle 处理，否则返回 0
__int64 ObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    Result = 0;
    if (GtRead(GtWindowsBuildNumber) < 0x585D)
        return CmdObjectOperationByHandle((__int64 *)pInputBuffer, InputSize);
    return Result;
}

// ProcessOperation — 进程操作
// 对应原始驱动 sub_14007FD2C (CmdProcessOperation)
// 通过进程ID查找进程，清零进程内存页后执行进程操作
__int64 ProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PEPROCESS Process;
    struct _KPROCESS *pProcess;
    NTSTATUS Status;
    int Status2;
    char IsTarget;
    struct _KPROCESS **pObjType;

    Result = 0;
    if (InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 8);
        Status = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
        Status2 = Status;
        pProcess = (struct _KPROCESS *)((unsigned __int64)*(__int64 *)(pInputBuffer + 8));
        if (!pProcess)
        {
            if (Status >= 0)
                pProcess = (struct _KPROCESS *)Process;
        }
        if ((struct _KPROCESS *)GtRead(GtEprocessField123 | 0x100) == pProcess)
        {
            Result = 1;
        }
        else
        {
            IsTarget = 0;
            pObjType = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
            if (pObjType)
                IsTarget = (*pObjType == pProcess);
            if (!IsTarget)
            {
                ZeroProcessMemoryPages(pProcess);
                Result = ValidateProcessObject(pProcess, 0) != 1 || ProcessOperationWithAttach(pProcess);
            }
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// ThreadOperation — 线程操作
// 对应原始驱动 sub_1400809CC (CmdThreadOperation)
// 查找线程对象，验证后清除页表标志或发送CDB命令
__int64 ThreadOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PETHREAD Thread;
    PETHREAD TargetThread;
    NTSTATUS Status;
    int Status2;

    Result = 0;
    if (InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 8);
        Status = PsLookupThreadByThreadId(*(HANDLE *)pInputBuffer, &Thread);
        Status2 = Status;
        TargetThread = (PETHREAD)((unsigned __int64)*(__int64 *)(pInputBuffer + 8));
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = Thread;
        }
        Result = 1;
        if (ValidateKernelObject((unsigned __int64)TargetThread, 0, 0, 0) == 1)
            Result = PrepareFileForPageTableScan((char *)TargetThread, 0);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Result;
}

// FileSystemControlOperation — 文件系统控制操作
// 对应原始驱动 sub_140073DF4 (CmdFsctlOperation)
// 处理文件系统控制请求，支持Hook交换机制
__int64 FileSystemControlOperation(unsigned int *pInputBuffer, int InputSize, volatile void *pOutputBuffer, int OutputSize)
{
    _QWORD *pHookSwapContext;
    char Result;
    SIZE_T StringSize;
    volatile void *pStringBuffer;
    unsigned __int64 StringLength;
    __int64 pStringBuffer2;
    int FsctlContext;
    __int64 FsctlContext2;
    _BYTE *pUnicodeString;
    _OWORD ZeroBuffer;
    _BYTE UnicodeBuffer[24];

    pHookSwapContext = 0;
    Result = 0;
    if (pInputBuffer && InputSize == 24 && pOutputBuffer && OutputSize == 8 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 6) < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + 8 < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x18, 1);
        ProbeForWrite(pOutputBuffer, 8, 8);
        StringSize = pInputBuffer[2];
        if ((unsigned int)StringSize > 2 && (StringSize & 1) == 0)
        {
            pStringBuffer = (volatile void *)*((_QWORD *)pInputBuffer + 2);
            if (pStringBuffer)
            {
                if ((unsigned __int64)pStringBuffer < MmUserProbeAddress &&
                    (unsigned __int64)pStringBuffer + StringSize < MmUserProbeAddress)
                {
                    ProbeForRead(pStringBuffer, StringSize, 1);
                    StringLength = ((unsigned __int64)pInputBuffer[2] - 2) >> 1;
                    pStringBuffer2 = *((_QWORD *)pInputBuffer + 2);
                    if (*(_WORD *)(pStringBuffer2 + 2 * StringLength))
                        *(_WORD *)(pStringBuffer2 + 2 * StringLength) = 0;
                    InitUnicodeStringBuffer((__int64)UnicodeBuffer, *((_QWORD *)pInputBuffer + 2), pInputBuffer[2]);
                    FsctlContext = 48;
                    FsctlContext2 = 0;
                    RtlZeroMemory(&ZeroBuffer, sizeof(ZeroBuffer));
                    pUnicodeString = UnicodeBuffer;
                    Result = SendFsctlWithHookSwap((__int64)pOutputBuffer, *pInputBuffer, (__int64)&FsctlContext, 0, 0, pInputBuffer[1], 0);
                    if (!Result)
                    {
                        {
                            struct _KTHREAD *CurrentThread;
                            _DWORD *pIoControlResult;
                            _DWORD *pIoResult;
                            char TempFlag;
                            int (*pIrpCallFunc)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD);
                            unsigned int ThreadFlagOffset;
                            void (*pCloseHandleFunc)(_DWORD *);
                            __int64 *pSwapKernelMem;
                            _QWORD *pSwapContext;
                            __int64 SwapContextValue;
                            __int64 SavedSwapValue;
                            unsigned int PrevMode;

                            pIrpCallFunc = (int (*)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD))GtRead(GtEprocessField101 | 0x100);
                            ThreadFlagOffset = GtRead(GtSdstServiceCount);
                            pCloseHandleFunc = (void (*)(_DWORD *))GtRead(GtCloseHandleFunc);
                            if (!pIrpCallFunc || ThreadFlagOffset == -1)
                            {
                                int (*pFallbackIrpFunc)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD);
                                pFallbackIrpFunc = (int (*)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD))GtRead(GtTotalSize | GtIrpBufferSize | GtEprocessField10);
                                if (pFallbackIrpFunc)
                                    return pFallbackIrpFunc(pOutputBuffer, *pInputBuffer, &FsctlContext, 0, 0, pInputBuffer[1], 0) >= 0;
                            }
                            else
                            {
                                CurrentThread = KeGetCurrentThread();
                                pSwapKernelMem = SwapKernelMemoryPointer(&SwapContextValue);
                                pIoControlResult = 0;
                                pSwapContext = 0;
                                SavedSwapValue = 0;
                                if (pCloseHandleFunc)
                                {
                                    pIoResult = SendIoControlWithUnicodeString((__int64)&FsctlContext);
                                    pIoControlResult = pIoResult;
                                    if (pIoResult)
                                    {
                                        pHookSwapContext = (_QWORD *)DispatchHookSwapByVersion((__int64)pIoResult, &SavedSwapValue);
                                        pSwapContext = pHookSwapContext;
                                    }
                                }
                                PrevMode = *((_BYTE *)CurrentThread + ThreadFlagOffset);
                                *((_BYTE *)CurrentThread + ThreadFlagOffset) = 0;
                                Result = pIrpCallFunc(pOutputBuffer, *pInputBuffer, &FsctlContext, 0, 0, pInputBuffer[1], 0) >= 0;
                                *((_BYTE *)CurrentThread + ThreadFlagOffset) = PrevMode;
                                if (pIoControlResult)
                                {
                                    if (pHookSwapContext)
                                        *pHookSwapContext = SavedSwapValue;
                                    pCloseHandleFunc(pIoControlResult);
                                }
                                if (pSwapKernelMem)
                                    *pSwapKernelMem = SwapContextValue;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// EnumKernelInfoOperation — 枚举内核信息操作
// 对应原始驱动 sub_140088720 (CmdEnumKernelInfo)
// 枚举win32k内核对象信息(GDI对象列表)并返回句柄和类型
__int64 EnumKernelInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    unsigned int (*pEnumFunc)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _QWORD, _QWORD);
    unsigned int EntryCount;
    char *pEntries;
    unsigned int (*pTypeFunc)(_QWORD, _QWORD);
    unsigned int Index;
    char *pEntry;
    char Result;

    Result = 0;
    if ((unsigned __int64)pOutputBuffer < MmUserProbeAddress && pOutputBuffer &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress && OutputSize > 0xFA18)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        *pOutputBuffer = 0;
        pEnumFunc = (unsigned int (*)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _QWORD, _QWORD))GtRead(GtIrpBufferSize | GtEprocessField06);
        if (!pEnumFunc)
        {
            InitWin32kTableByVersion();
            pEnumFunc = (unsigned int (*)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _QWORD, _QWORD))GtRead(GtIrpBufferSize | GtEprocessField06);
        }
        if (pEnumFunc)
        {
            if (!(GtRead(GtWindowsBuildNumber) >= 0x23F0
                ? ((__int64 (*)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, int, _DWORD *, _DWORD *, _BYTE))pEnumFunc)(0, 0, 0, 0, 0, 4000, pOutputBuffer + 2, pOutputBuffer, 0)
                : pEnumFunc(0, 0, 0, 0, 4000, pOutputBuffer + 2, pOutputBuffer)))
            {
                EntryCount = *pOutputBuffer;
                if (EntryCount)
                {
                    *pOutputBuffer = 0;
                    pEntries = (char *)ExAlloc(PagedPool, 8LL * EntryCount);
                    if (pEntries)
                    {
                        memmove(pEntries, pOutputBuffer + 2, 8LL * EntryCount);
                        pTypeFunc = (unsigned int (*)(_QWORD, _QWORD))GtRead(GtRuntimeDataBase | GtEprocessField10);
                        for (Index = 0; Index < EntryCount; ++Index)
                        {
                            pEntry = &pEntries[8 * Index];
                            if (*(_QWORD *)pEntry != 1 || Index != EntryCount - 1)
                            {
                                *(_QWORD *)&pOutputBuffer[4 * Index + 2] = *(_QWORD *)pEntry;
                                if (pTypeFunc)
                                    *(_QWORD *)&pOutputBuffer[4 * Index + 4] = pTypeFunc(*(_QWORD *)pEntry, 0);
                                else
                                    *(_QWORD *)&pOutputBuffer[4 * Index + 4] = 0;
                                ++*pOutputBuffer;
                            }
                        }
                        Result = *pOutputBuffer != 0;
                        ExFree(pEntries);
                    }
                }
            }
        }
    }
    return Result;
}

// EnumObjectsOperation — 枚举对象操作
// 对应原始驱动 sub_140036CF8 (CmdEnumObjects)
// 根据构建号分发到 CmdEnumObjectsLegacy 或 CmdEnumObjectsEx
__int64 EnumObjectsOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    if (GtRead(GtWindowsBuildNumber) >= 0x585D)
        return CmdEnumObjectsLegacy((__int64)pInputBuffer, (unsigned int)InputSize, pOutputBuffer, OutputSize);
    else
        return CmdEnumObjectsEx((__int64)pInputBuffer, (unsigned int)InputSize, pOutputBuffer, OutputSize);
}

// EnumRegistryOperation — 枚举注册表操作
// 对应原始驱动 sub_14007E1E0 (CmdEnumRegistry)
// 通过进程ID查找进程，枚举其注册表保护状态
__int64 EnumRegistryOperation(char *pInputBuffer, int InputSize, _WORD *pOutputBuffer, int OutputSize)
{
    char Result;
    PEPROCESS Process;
    struct _KPROCESS *pProcess;
    NTSTATUS Status;
    int Status2;
    __int64 CurrentProcess;

    Result = 0;
    if (InputSize == 16 && OutputSize == 2 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 4);
        ProbeForWrite(pOutputBuffer, 2, 1);
        Status = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
        Status2 = Status;
        pProcess = (struct _KPROCESS *)((unsigned __int64)*(__int64 *)(pInputBuffer + 8));
        if (!pProcess)
        {
            if (Status >= 0)
                pProcess = (struct _KPROCESS *)Process;
        }
        CurrentProcess = GtRead(GtEprocessField123 | 0x100);
        if (CurrentProcess)
        {
            if (pProcess == (struct _KPROCESS *)CurrentProcess)
            {
                *pOutputBuffer = 0;
                Result = 1;
            }
            else if (ValidateProcessObject(pProcess, 0) == 1)
            {
                Result = EnumerateProcessObjectTable((__int64)pProcess, (__int64)pOutputBuffer);
            }
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// EnumServicesOperation — 枚举服务操作
// 对应原始驱动 sub_1400561BC (CmdEnumServices)
// 获取服务表，根据构建号选择不同版本的枚举函数
__int64 EnumServicesOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    __int64 *pServiceTable;
    __int64 ServiceResult = 0;
    __int64 EntryCount = 0;
    int MaxEntries;

    pServiceTable = (__int64 *)GtRead(GtCallbackField17);
    if (!pServiceTable)
    {
        BuildServiceTableFromNtKernel(EntryCount, ServiceResult);
        pServiceTable = (__int64 *)GtRead(GtCallbackField17);
    }
    if (pServiceTable && pOutputBuffer && OutputSize >= 0x38 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        *pOutputBuffer = 0;
        MaxEntries = (OutputSize - 56) / 0x30 + 1;
        ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        if (BuildNumber >= 0x1770)
        {
            if (BuildNumber == 6000)
                EnumServiceTableWin10(pServiceTable, (__int64)(pOutputBuffer + 2), pOutputBuffer, MaxEntries);
            else if (BuildNumber >= 0x23F0)
                EnumServiceTableWin1020H1((_QWORD **)pServiceTable, (__int64)(pOutputBuffer + 2), pOutputBuffer, MaxEntries);
            else
                EnumServiceTableWin8((_QWORD **)pServiceTable, (__int64)(pOutputBuffer + 2), pOutputBuffer, MaxEntries);
        }
        else
        {
            EnumServiceTableWin7(pServiceTable, (__int64)(pOutputBuffer + 2), pOutputBuffer, MaxEntries);
        }
        return *pOutputBuffer != 0;
    }
    return 0;
}

// EnumServiceTableOperation — 枚举服务表操作
// 对应原始驱动 sub_140055DEC (CmdEnumServiceTable)
// 根据构建号选择不同版本的移除函数操作服务表
#pragma warning(push)
#pragma warning(disable: 4700)
__int64 EnumServiceTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 *pEntry;
    __int64 ServiceResult;
    __int64 Status;
    __int64 **pServiceTable;

    ServiceResult = 0;
    Status = 0;
    Result = 0;
    pEntry = 0;
    if (pInputBuffer && InputSize == 8 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 4);
        pEntry = *(__int64 **)pInputBuffer;
        Result = 1;
    }
    if (Result == 1)
    {
        Result = 0;
        pServiceTable = (__int64 **)GtRead(GtCallbackField17);
        if (!pServiceTable)
        {
            BuildServiceTableFromNtKernel(Status, ServiceResult);
            pServiceTable = (__int64 **)GtRead(GtCallbackField17);
        }
        if (pEntry && pServiceTable)
        {
            ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
            if (BuildNumber < 0x1770)
                return RemoveServiceTableNodeWin7(pServiceTable, (__int64)pEntry);
            if (BuildNumber == 6000)
                return RemoveServiceEntryFromList(pServiceTable, (__int64)pEntry);
            if (BuildNumber >= 0x23F0)
                return RemoveServiceTableNodeWin10(pServiceTable, pEntry);
            return RemoveServiceEntryFromListEx((__int64 ***)pServiceTable, (__int64 **)pEntry);
        }
    }
    return Result;
}
#pragma warning(pop)

// RestoreDriverDispatchOperation — 恢复驱动分发函数操作
// 对应原始驱动 sub_140081280 (CmdRestoreDriverDispatch)
// 将驱动对象 MajorFunction[14] 重置为 DispatchCreateClose
__int64 RestoreDriverDispatchOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 DriverObject;

    Result = 0;
    DriverObject = GtRead(GtDriverObject);
    if (DriverObject)
    {
        *(_QWORD *)(DriverObject + 224) = DispatchCreateClose;
        return 1;
    }
    return Result;
}

// QueryMemoryInfoOperation — 查询内存信息操作
// 对应原始驱动 sub_140084F34 (CmdQueryMemoryInfo)
// 打开目标进程句柄，返回进程句柄值给用户态
__int64 QueryMemoryInfoOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    _QWORD *pObjectType;
    int (*pDupFunc)(_QWORD, _QWORD, _QWORD, __int64, _QWORD, _BYTE, __int64 *);
    _QWORD *pRefCount;
    __int64 HandleValue;

    Result = 0;
    if (OutputSize == 8 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 8, 1);
        pObjectType = (_QWORD *)GtRead(GtObjectTypeInfoPtr);
        pDupFunc = (int (*)(_QWORD, _QWORD, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54);
        pRefCount = (_QWORD *)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
        if (pObjectType && pDupFunc && pRefCount &&
            pDupFunc(*pObjectType, 0, 0, 0x10000000, *pRefCount, 0, &HandleValue) >= 0)
        {
            *pOutputBuffer = HandleValue;
            return 1;
        }
    }
    return Result;
}

// DeviceIoControlOperation — 设备IO控制操作
// 对应原始驱动 sub_140070F74 (CmdDeviceIoControl)
// 通过进程ID查找进程并查询指定句柄的文件信息
__int64 DeviceIoControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PEPROCESS Process;
    struct _KPROCESS *pProcess;
    NTSTATUS Status;
    __int64 InputData[3];
    struct _KPROCESS *CurrentProcess;
    __int64 SavedValue[2];

    Result = 0;
    Process = 0;
    if (pInputBuffer && InputSize == 32 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 32) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x20, 4);
        InputData[0] = *(__int64 *)pInputBuffer;
        InputData[1] = *(__int64 *)(pInputBuffer + 8);
        SavedValue[0] = *(__int64 *)(pInputBuffer + 16);
        SavedValue[1] = *(__int64 *)(pInputBuffer + 24);
        Status = PsLookupProcessByProcessId((HANDLE)InputData[0], &Process);
        pProcess = Process;
        if (Status < 0)
            pProcess = 0;
        Process = pProcess;
        pProcess = (struct _KPROCESS *)((unsigned __int64)InputData[1]);
        if (!pProcess)
        {
            if (Status >= 0)
                pProcess = Process;
            CurrentProcess = pProcess;
        }
        if (ValidateProcessObject(pProcess, 0) == 1 && SavedValue[1])
            Result = QueryFileInfoByHandle((__int64)pProcess, SavedValue[0], SavedValue[1]);
    }
    if (Process)
        ObfDereferenceObject(Process);
    return Result;
}

// QueryModuleInfoOperation — 查询模块信息操作
// 对应原始驱动 sub_140057D40 (CmdQueryModuleInfo)
// 根据 Windows 构建版本选择不同的模块枚举路径
__int64 QueryModuleInfoOperation(volatile void **pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    if (GtRead(GtWindowsBuildNumber) >= 0x3AD7)
        return EnumProcessModules((ULONG64)pInputBuffer, InputSize, pOutputBuffer, OutputSize);
    else
        return QueryProcessModuleInfo(pInputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CheckBytePatternOperation — 检查字节模式操作
// 对应原始驱动 sub_140086FD0 (CmdCheckBytePattern)
// 根据输入参数恢复指定索引的系统调用钩子
__int64 CheckBytePatternOperation(__int64 *pInputBuffer, int InputSize)
{
    char Result;
    unsigned int Index;
    __int64 InputValue;

    Result = 0;
    if (pInputBuffer && InputSize == 8 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 1);
        InputValue = *pInputBuffer;
        if ((unsigned __int8)*pInputBuffer == 1)
        {
            for (Index = 0; Index < 0x200; ++Index)
                Result |= RestoreSyscallHookByIndex(SBYTE1(InputValue), Index);
        }
        else
        {
            return RestoreSyscallHookByIndex(SBYTE1(InputValue), HIDWORD(InputValue));
        }
    }
    return Result;
}

// EnumHookInfoOperation — 枚举钩子信息操作
// 对应原始驱动 sub_140086AB0 (CmdEnumHookInfo)
// 收集并验证系统调用表和导出表中的钩子条目信息
__int64 EnumHookInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    unsigned __int64 BufferSize;
    unsigned int Count1;
    _QWORD *pTable1;
    _QWORD *pTable1Copy;
    unsigned int Count2;
    _QWORD *pTable2;
    _QWORD *pTable2Copy;
    int Offset;
    _DWORD *pDst;

    Result = 0;
    if (pOutputBuffer && OutputSize > 0x38 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        BufferSize = OutputSize;
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        memset(pOutputBuffer, 0, (unsigned int)BufferSize);
        *pOutputBuffer = GtRead(GtWindowsBuildNumber);
        pOutputBuffer[1] = 0;
        pOutputBuffer[2] = 0;
        if (!GtRead(GtDisableHookProtectionAddr1 | GtEprocessField150))
            ParseSyscallTableExportDir();
        Count1 = GtRead(GtDisableHookProtectionAddr1 | GtEprocessField150);
        pTable1 = (_QWORD *)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField151);
        pTable1Copy = pTable1;
        if (Count1 && pTable1 && CheckMemoryValid(pTable1) == 1 &&
            CheckMemoryValid((char *)&pTable1Copy[Count1 - 1] + 7) == 1 &&
            BufferSize >= 40 * (unsigned __int64)(Count1 - 1) + 56 &&
            CopyHookEntryArray((__int64)(pOutputBuffer + 4), pTable1Copy, Count1) == 1 &&
            FilterActiveHookEntries((__int64)(pOutputBuffer + 4), Count1, 8612) == 1 &&
            ValidateHookEntries((__int64)(pOutputBuffer + 4), Count1) == 1)
        {
            pOutputBuffer[1] = Count1;
            Result = 1;
        }
        Count2 = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField152);
        pTable2 = (_QWORD *)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField154);
        pTable2Copy = pTable2;
        if (Count2 && pTable2 &&
            CheckMemoryValid(pTable2) == 1 && CheckMemoryValid((char *)&pTable2Copy[Count2 - 1] + 7) == 1)
        {
            Offset = pOutputBuffer[1];
            if (BufferSize >= 40 * (unsigned __int64)(Count2 + Offset - 1) + 56)
            {
                pDst = &pOutputBuffer[8 * (Offset - 1) + 14 + 2 * (Offset - 1)];
                if (CopyHookEntryArray((__int64)pDst, pTable2Copy, Count2) == 1 &&
                    FilterActiveHookEntries((__int64)pDst, Count2, 11696) == 1 &&
                    ValidateHookEntries((__int64)pDst, Count2) == 1)
                {
                    pOutputBuffer[2] = Count2;
                    return 1;
                }
            }
        }
    }
    return Result;
}

// EnumHookDetailOperation — 枚举钩子详情操作
// 对应原始驱动 sub_140087DCC (CmdEnumHookDetail)
// 枚举所有SSDT钩子信息，包括每个驱动模块的钩子地址和原始代码
__int64 EnumHookDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    if (pOutputBuffer && OutputSize > 0x10E8 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        memset(pOutputBuffer, 0, OutputSize);
        pOutputBuffer[1] = 0;
        *pOutputBuffer = GtRead(GtWindowsBuildNumber);
        EnumSsdtHooks((__int64)pOutputBuffer, OutputSize);
        return pOutputBuffer[1] != 0;
    }
    return 0;
}

// GetHookEntryInfoOperation — 获取钩子条目信息操作
// 对应原始驱动 sub_140086CD4 (CmdGetHookEntryInfo)
// 从系统调用表导出目录获取4个钩子条目的地址和代码，验证每个条目
__int64 GetHookEntryInfoOperation(char *pInputBuffer, int InputSize, ULONG64 OutputBuffer, unsigned int OutputSize)
{
    char Result;
    int Count;
    _QWORD *pTable;
    _QWORD *pTableCopy;
    __int64 *pEntry;

    Result = 0;
    if (OutputBuffer && OutputSize >= 0xA0 &&
        OutputBuffer < MmUserProbeAddress && OutputSize + OutputBuffer < MmUserProbeAddress)
    {
        ProbeForWrite((volatile void *)OutputBuffer, OutputSize, 1);
        memset((void *)OutputBuffer, 0, OutputSize);
        if (!GtRead(GtFltPeSectionOfs8 | GtEprocessField22))
            ParseSyscallTableExportDir();
        Count = GtRead(GtFltPeSectionOfs8 | GtEprocessField22);
        pTable = (_QWORD *)GtRead(GtFltPeSectionAddr7 | GtEprocessField22);
        pTableCopy = pTable;
        if (Count && pTable && CheckMemoryValid(pTable) == 1 && CheckMemoryValid((char *)pTableCopy + 55) == 1)
        {
            *(_QWORD *)(OutputBuffer + 16) = pTableCopy[1];
            *(_QWORD *)(OutputBuffer + 56) = pTableCopy[2];
            *(_QWORD *)(OutputBuffer + 96) = pTableCopy[3];
            *(_QWORD *)(OutputBuffer + 136) = pTableCopy[4];
            pEntry = GtAlloc((enum _GLOBAL_TABLE_INDEX)8576);
            if (*((_DWORD *)pEntry + 1) && *(_DWORD *)pEntry == 1)
            {
                *(_QWORD *)(OutputBuffer + 8) = pEntry[1];
                *(_OWORD *)(OutputBuffer + 24) = *((_OWORD *)pEntry + 1);
            }
            if (*((_DWORD *)pEntry + 13) && *((_DWORD *)pEntry + 12) == 1)
            {
                *(_QWORD *)(OutputBuffer + 48) = pEntry[7];
                *(_OWORD *)(OutputBuffer + 64) = *((_OWORD *)pEntry + 4);
            }
            if (*((_DWORD *)pEntry + 25) && *((_DWORD *)pEntry + 24) == 1)
            {
                *(_QWORD *)(OutputBuffer + 88) = pEntry[13];
                *(_OWORD *)(OutputBuffer + 104) = *((_OWORD *)pEntry + 7);
            }
            if (*((_DWORD *)pEntry + 37) && *((_DWORD *)pEntry + 36) == 1)
            {
                *(_QWORD *)(OutputBuffer + 128) = pEntry[19];
                *(_OWORD *)(OutputBuffer + 144) = *((_OWORD *)pEntry + 10);
            }
            ValidateSingleHookEntry((void *)OutputBuffer);
            ValidateSingleHookEntry((void *)(OutputBuffer + 40));
            ValidateSingleHookEntry((void *)(OutputBuffer + 80));
            ValidateSingleHookEntry((void *)(OutputBuffer + 120));
            return 1;
        }
    }
    return Result;
}

// QueryHookStatusOperation — 查询钩子状态操作
// 对应原始驱动 sub_140087074 (CmdQueryHookStatus)
// 根据地址查询系统调用钩子的安装状态
__int64 QueryHookStatusOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 *pEntry;
    unsigned int Index;
    _OWORD InputData;

    Result = 0;
    if (pInputBuffer && InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 1);
        InputData = *(_OWORD *)pInputBuffer;
        if ((unsigned __int8)*(__int64 *)&InputData == 1)
        {
            pEntry = GtAlloc((enum _GLOBAL_TABLE_INDEX)8576);
            for (Index = 0; Index < 4; ++Index)
            {
                if (LODWORD(pEntry[6 * Index]) == 1)
                    Result |= QuerySyscallHookStatus(pEntry[6 * Index + 1]);
            }
        }
        else if (*((__int64 *)&InputData + 1) > (unsigned __int64)MmSystemRangeStart)
        {
            return QuerySyscallHookStatus(*((__int64 *)&InputData + 1));
        }
    }
    return Result;
}

// CallSystemRoutineOperation — 调用系统例程操作
// 对应原始驱动 sub_1400776D8 (CmdCallSystemRoutine)
// 执行存储在全局表中的内核函数调用
__int64 CallSystemRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    int (*pFunc)(__int64);
    unsigned int PrevModeOffset;
    struct _KTHREAD *CurrentThread;
    __int64 Offset;
    char SavedMode;
    int Result;

    pFunc = (int (*)(__int64))GtRead(GtTotalSize | GtKernelDataField07);
    PrevModeOffset = GtRead(GtSdstServiceCount);
    if (pFunc && PrevModeOffset != -1)
    {
        CurrentThread = KeGetCurrentThread();
        Offset = PrevModeOffset;
        SavedMode = *((_BYTE *)CurrentThread + PrevModeOffset);
        *((_BYTE *)CurrentThread + PrevModeOffset) = 0;
        Result = pFunc(1);
        *((_BYTE *)CurrentThread + Offset) = SavedMode;
        return Result == 0;
    }
    return 0;
}

// ResetDriverStateOperation — 重置驱动状态操作
// 对应原始驱动 sub_140077758 (CmdResetDriverState)
// 调用系统复位命令重置驱动状态
__int64 ResetDriverStateOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SystemResetCommand((unsigned __int64 *)pInputBuffer);
    return 1;
}

// EnumKernelMemoryDetailOperation — 枚举内核内存详细信息操作
// 对应原始驱动 sub_14006B708 (CmdEnumKernelMemoryDetail)
// 读取内核内存上下文，根据构建号选择不同条目步长，遍历内存条目输出到用户缓冲区
__int64 EnumKernelMemoryDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 *pContext;
    unsigned int Offset;
    void **ppData;
    unsigned __int64 ListHead;
    _QWORD *pData;
    _QWORD *pEnd;
    int StrideSize;
    unsigned __int64 MaxEntries;
    __int64 Result;
    unsigned int EntryCount;
    _DWORD *pEntry;
    unsigned int Index;
    PVOID Buffer;
    __int64 BufferSize;
    unsigned int Remaining;

    if (!GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400))
        InitKernelMemoryContext();
    pContext = (unsigned __int64 *)GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400);
    Offset = GtRead(GtEprocessExtField58 | GtEprocessField66 | 0x400);
    ppData = (void **)GtRead(GtEprocessExtField58 | GtEprocessField67 | 0x400);
    if (!pContext || pContext <= MmSystemRangeStart || !Offset || !ppData || ppData <= MmSystemRangeStart)
        return 0;
    ListHead = *pContext;
    pData = *ppData;
    if (ListHead <= (unsigned __int64)MmSystemRangeStart)
        return 0;
    pEnd = (_QWORD *)(ListHead + Offset);
    if (CheckMemoryValid(pEnd) != 1 || !pOutputBuffer || OutputSize < 0x50 ||
        (unsigned __int64)pOutputBuffer >= MmUserProbeAddress ||
        (unsigned __int64)pOutputBuffer + OutputSize >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(pOutputBuffer, OutputSize, 8);
    memset(pOutputBuffer, 0, OutputSize);
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber < 0x1DB0)
        StrideSize = 48;
    else if (BuildNumber == 9200)
        StrideSize = 72;
    else if (BuildNumber < 0x585D)
    {
        if (BuildNumber < 0x4F7C)
            StrideSize = BuildNumber < 0x2580 ? 64 : 80;
        else
            StrideSize = 88;
    }
    else
        StrideSize = 96;
    pOutputBuffer[1] = 0;
    *((_BYTE *)pOutputBuffer + 8) = 0;
    MaxEntries = ((OutputSize - 80) >> 5) + 1;
    if (pData > MmSystemRangeStart && CheckMemoryValid(pData) == 1 && CheckMemoryValid((char *)pData + StrideSize - 1) == 1)
    {
        if (BuildNumber < 0x1DB0)
        {
            if (*(_DWORD *)pData)
            {
                pOutputBuffer[4] = -1;
                *((_QWORD *)pOutputBuffer + 3) = pData[1];
                *((_QWORD *)pOutputBuffer + 4) = pData[2];
                Result = pData[3];
                goto LABEL_31;
            }
        }
        else if (*((_DWORD *)pData + 1))
        {
            pOutputBuffer[4] = -1;
            *((_QWORD *)pOutputBuffer + 3) = pData[2];
            *((_QWORD *)pOutputBuffer + 4) = pData[3];
            Result = pData[4];
LABEL_31:
            *((_QWORD *)pOutputBuffer + 5) = Result;
            *((_BYTE *)pOutputBuffer + 8) = 1;
        }
    }
    EntryCount = *(_DWORD *)pEnd;
    Remaining = *(_DWORD *)pEnd;
    *pOutputBuffer = *(_DWORD *)pEnd;
    pEntry = (_DWORD *)pEnd[1];
    if (pEntry > MmSystemRangeStart)
    {
        for (Index = 0; ; ++Index)
        {
            if (Index >= EntryCount || !(_DWORD)MaxEntries ||
                CheckMemoryValid(pEntry) != 1 || CheckMemoryValid((char *)pEntry + StrideSize - 1) != 1)
                return 1;
            if (BuildNumber < 0x1DB0)
            {
                if (!*pEntry)
                    goto LABEL_47;
                pOutputBuffer[8 * pOutputBuffer[1] + 12] = Index;
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 14] = *((_QWORD *)pEntry + 1);
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 16] = *((_QWORD *)pEntry + 2);
                BufferSize = *((_QWORD *)pEntry + 3);
            }
            else
            {
                if (!pEntry[1])
                    goto LABEL_47;
                pOutputBuffer[8 * pOutputBuffer[1] + 12] = Index;
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 14] = *((_QWORD *)pEntry + 2);
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 16] = *((_QWORD *)pEntry + 3);
                Buffer = (PVOID)*((_QWORD *)pEntry + 4);
                if (Buffer <= MmSystemRangeStart || CheckMemoryValid(Buffer) != 1)
                    goto LABEL_46;
                BufferSize = *((_QWORD *)pEntry + 4);
            }
            *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 18] = BufferSize;
LABEL_46:
            ++pOutputBuffer[1];
            MaxEntries = (unsigned __int64)((int)MaxEntries - 1);
LABEL_47:
            pEntry = (_DWORD *)((char *)pEntry + StrideSize);
            EntryCount = Remaining;
        }
    }
    return 1;
}

// ReadKernelMemoryRangeSizeOperation — 读取内核内存范围大小操作
// 对应原始驱动 sub_14006BA98 (CmdReadKernelMemoryRangeSize)
// 读取内核内存范围大小，输出到用户缓冲区并分配NT句柄条目
__int64 ReadKernelMemoryRangeSizeOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    unsigned int Offset;
    _QWORD *pContext;
    _QWORD *pTarget;
    __int64 NtHandleEntry;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField60 | 0x400))
        InitKernelMemoryContext();
    Offset = GtRead(GtEprocessExtField58 | GtEprocessField60 | 0x400);
    pContext = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400);
    if (pContext && pContext > MmSystemRangeStart && Offset && (Offset & 7) == 0 &&
        *pContext > (unsigned __int64)MmSystemRangeStart)
    {
        pTarget = (_QWORD *)(*pContext + Offset);
        if (CheckMemoryValid(pTarget) == 1 && pOutputBuffer && OutputSize == 16 &&
            (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
            (unsigned __int64)(pOutputBuffer + 2) < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, 0x10, 8);
            *pOutputBuffer = 0;
            pOutputBuffer[1] = 0;
            *pOutputBuffer = *pTarget;
            NtHandleEntry = AllocateNtHandleEntry();
            pOutputBuffer[1] = NtHandleEntry;
            return NtHandleEntry != 0;
        }
    }
    return Result;
}

// ReadKernelBaseOperation — 读取内核基址操作
// 对应原始驱动 sub_14002BA3C (CmdReadKernelBase)
// 读取全局表中的内核基址和大小，输出到用户缓冲区。仅用于 Win7 以下系统
__int64 ReadKernelBaseOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    _QWORD *pKernelBase;
    __int64 KernelBaseSize;

    if (GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        pKernelBase = (_QWORD *)GtRead(GtFltPeSectionOfs1 | GtEprocessField54);
        KernelBaseSize = GtRead(GtFltPeSectionAddr1 | GtEprocessField54);
        if (!pKernelBase || !KernelBaseSize)
        {
            FindNtoskrnlExportsInThreadEnv();
            pKernelBase = (_QWORD *)GtRead(GtFltPeSectionOfs1 | GtEprocessField54);
            KernelBaseSize = GtRead(GtFltPeSectionAddr1 | GtEprocessField54);
        }
        if (pKernelBase && KernelBaseSize && pOutputBuffer && OutputSize == 8 &&
            (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
            (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, 8, 1);
            *pOutputBuffer = 0;
            *pOutputBuffer = *pKernelBase;
            return 1;
        }
    }
    return 0;
}

// ClearKernelBaseOperation — 清除内核基址操作
// 对应原始驱动 sub_14002BB1C (CmdClearKernelBase)
// 将全局表中的内核基址和大小写入 0 清零。仅用于 Win7 以下系统
__int64 ClearKernelBaseOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 KernelBaseAddr;
    __int64 KernelBaseSize;
    unsigned __int64 KernelBaseSizeCopy;

    if (GtRead(GtWindowsBuildNumber) < 0x1DB0)
    {
        KernelBaseAddr = GtRead(GtFltPeSectionOfs1 | GtEprocessField54);
        KernelBaseSize = GtRead(GtFltPeSectionAddr1 | GtEprocessField54);
        KernelBaseSizeCopy = KernelBaseSize;
        if (!KernelBaseAddr || !KernelBaseSize)
        {
            FindNtoskrnlExportsInThreadEnv();
            KernelBaseAddr = GtRead(GtFltPeSectionOfs1 | GtEprocessField54);
            KernelBaseSizeCopy = GtRead(GtFltPeSectionAddr1 | GtEprocessField54);
        }
        if (KernelBaseAddr && KernelBaseSizeCopy)
        {
            WritePhysicalMemoryQword(KernelBaseAddr, 0);
            WritePhysicalMemoryQword(KernelBaseSizeCopy, 0);
            return 1;
        }
    }
    return 0;
}

// EnumKernelModuleInfoExOperation — 枚举内核模块信息扩展操作
// 对应原始驱动 sub_14002BE50 (CmdEnumKernelModuleInfoEx)
// 遍历内核模块链表，输出模块信息
__int64 EnumKernelModuleInfoExOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    unsigned __int64 *pModuleList1;
    __int64 ModuleList2;
    unsigned __int64 *pModuleList2;
    int MaxEntries;
    _DWORD *pOutputBufferCopy;

    if (GtRead(GtWindowsBuildNumber) < 0x1770)
    {
        pModuleList1 = (unsigned __int64 *)GtRead(GtFltPeSectionOfs2 | GtEprocessField54);
        ModuleList2 = GtRead(GtFltPeSectionAddr2 | GtEprocessField54);
        pModuleList2 = (unsigned __int64 *)ModuleList2;
        if (!pModuleList1 || !ModuleList2)
        {
            ParseKernelModuleDiskInfo();
            pModuleList1 = (unsigned __int64 *)GtRead(GtFltPeSectionOfs2 | GtEprocessField54);
            pModuleList2 = (unsigned __int64 *)GtRead(GtFltPeSectionAddr2 | GtEprocessField54);
        }
        if (pModuleList1 && pModuleList2 && pOutputBuffer && OutputSize >= 0x18 &&
            (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
            (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, OutputSize, 1);
            memset(pOutputBuffer, 0, OutputSize);
            pOutputBufferCopy = pOutputBuffer;
            *pOutputBuffer = 0;
            MaxEntries = ((OutputSize - 24) >> 4) + 1;
            WalkKernelModuleList(pModuleList1, pOutputBuffer, &MaxEntries);
            if (MaxEntries)
                WalkKernelModuleList(pModuleList2, pOutputBuffer, &MaxEntries);
            return 1;
        }
    }
    return 0;
}

// SetKernelModuleInfoOperation — 设置内核模块信息操作
// 对应原始驱动 sub_14002BF90 (CmdSetKernelModuleInfo)
// 设置内核模块信息
__int64 SetKernelModuleInfoOperation(__int64 *pInputBuffer, int InputSize)
{
    __int64 ModuleInfo;
    int ModuleFlags;
    char IsSet;

    if (GtRead(GtWindowsBuildNumber) < 0x1770 && pInputBuffer && InputSize == 16 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 2) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 1);
        IsSet = 0;
        ModuleInfo = *pInputBuffer;
        ModuleFlags = *((_DWORD *)pInputBuffer + 2);
        return (unsigned __int8)CmdSetModuleInfoInternal(&ModuleInfo) == 1;
    }
    return 0;
}

// WriteKernelObjectFieldOperation — 写入内核对象字段操作
// 对应原始驱动 sub_140029C74 (CmdWriteKernelObjectField)
// 根据用户输入执行写入操作或恢复原始值
__int64 WriteKernelObjectFieldOperation(PVOID *pInputBuffer, int InputSize)
{
    char Result;
    char FlagWriteResult;
    char FlagRestoreResult;
    PVOID TargetAddress;
    PVOID ValueToWrite;
    unsigned __int64 WriteOffset;
    __int64 HalExportTable;
    unsigned int HalExportCount;
    unsigned __int64 NtoskrnlBase;
    PVOID ObjectAddress;
    unsigned int AddressOffset;
    __int64 MemoryOffset;
    _OWORD BufferData;

    Result = 0;
    if (pInputBuffer && InputSize == 24 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 3) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x18, 1);
        FlagWriteResult = 0;
        FlagRestoreResult = 1;
        ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        TargetAddress = pInputBuffer[1];
        if (!TargetAddress)
            return FlagWriteResult & FlagRestoreResult;
        if (*(_BYTE *)pInputBuffer == 1 && pInputBuffer[2])
        {
            if (MmIsAddressValid(pInputBuffer[1]) != 1)
                goto LABEL_24;
            if (MmIsAddressValid(pInputBuffer[2]) == 1)
            {
                if (BuildNumber == 2195 ||
                    BuildNumber == 9200 ||
                    BuildNumber == 9600)
                {
                    if (!pInputBuffer[2])
                        goto LABEL_25;
                }
                else
                {
                    if (!pInputBuffer[2])
                        goto LABEL_25;
                    ValueToWrite = pInputBuffer[2];
                    if (ValueToWrite == (PVOID)GtRead(GtCallbackField96) ||
                        (ValueToWrite = pInputBuffer[2], ValueToWrite == (PVOID)GtRead(GtObjectTypeIdxNotMatched)) ||
                        (ValueToWrite = pInputBuffer[2], ValueToWrite == (PVOID)GtRead(GtObjectTypeIdxMatched)))
                    {
                        WriteOffset = (unsigned __int64)TargetAddress + 16;
                        goto LABEL_23;
                    }
                }
                ValueToWrite = pInputBuffer[2];
                if (ValueToWrite == (PVOID)GtRead(GtCallbackField94) ||
                    (ValueToWrite = pInputBuffer[2], ValueToWrite == (PVOID)GtRead(GtCallbackField98)) ||
                    (ValueToWrite = pInputBuffer[2], ValueToWrite == (PVOID)GtRead(GtCallbackField100)))
                {
                    WriteOffset = (unsigned __int64)TargetAddress + 8;
LABEL_23:
                    WritePhysicalMemoryQword(WriteOffset, (__int64)ValueToWrite);
                    goto LABEL_24;
                }
            }
        }
LABEL_24:
        FlagWriteResult = 1;
LABEL_25:
        if (*((_BYTE *)pInputBuffer + 1) == 1)
        {
            FlagRestoreResult = 0;
            HalExportTable = GtRead(GtEprocessField66);
            HalExportCount = GtRead(GtEprocessField23);
            NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
            if (HalExportTable && HalExportCount && NtoskrnlBase)
            {
                ObjectAddress = pInputBuffer[2];
                if ((unsigned __int64)ObjectAddress > NtoskrnlBase)
                {
                    AddressOffset = (_DWORD)ObjectAddress - NtoskrnlBase;
                    if ((int)ObjectAddress - (int)NtoskrnlBase < HalExportCount && AddressOffset + 16 <= HalExportCount)
                    {
                        MemoryOffset = AddressOffset;
                        if (MmIsAddressValid(ObjectAddress) == 1 && MmIsAddressValid((char *)pInputBuffer[2] + 15) == 1)
                        {
                            BufferData = *(_OWORD *)(MemoryOffset + HalExportTable);
                            WritePhysicalMemoryBuffer((unsigned __int64)pInputBuffer[2], &BufferData, 0x10, 0, 0);
                            FlagRestoreResult = 1;
                        }
                    }
                }
            }
        }
        return FlagWriteResult & FlagRestoreResult;
    }
    return Result;
}

// LookupObjectTypeByAddrOperation — 按地址查找对象类型操作
// 对应原始驱动 sub_14007ECD0 (CmdLookupObjectTypeByAddr)
// 遍历对象类型链表，查找匹配地址的对象类型并调用回调函数
__int64 LookupObjectTypeByAddrOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    _QWORD **pTypeList;
    __int64 CallbackFunc;
    void (*pCallback)(_QWORD *, __int64, const PVOID);
    _QWORD *TargetAddr;
    __int64 Index;
    _QWORD *pNode;

    Result = 0;
    pTypeList = (_QWORD **)GtRead(GtPathBuffer03 | 0x800);
    if (!pTypeList)
    {
        InitTdiExportAndRelocTable();
        pTypeList = (_QWORD **)GtRead(GtPathBuffer03 | 0x800);
    }
    CallbackFunc = GtRead(GtEprocessField03 | 0x800);
    pCallback = (void (*)(_QWORD *, __int64, const PVOID))CallbackFunc;
    if (pTypeList && CallbackFunc && pInputBuffer && InputSize == 8 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 8);
        TargetAddr = *(_QWORD **)pInputBuffer;
        Index = 0;
        pNode = *pTypeList;
        while (pNode > MmSystemRangeStart && pNode != pTypeList && (unsigned int)Index <= 0x1000)
        {
            if (TargetAddr == pNode)
            {
                pCallback(pNode, Index, MmSystemRangeStart);
                return 1;
            }
            pNode = (_QWORD *)*pNode;
            Index = (unsigned int)(Index + 1);
        }
    }
    return Result;
}

// QueryProcessNameByPidOperation — 根据PID查询进程名称操作
// 对应原始驱动 sub_140084E14 (CmdQueryProcessNameByPid)
// 按PID查询进程名称操作
// 对应原始驱动 CmdQueryProcessNameByPid (0x140084E14)
__int64 QueryProcessNameByPidOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 ProcessId;
    int (__fastcall *QueryNameFunc)(__int64, __int64, const void **, _QWORD, _QWORD);
    unsigned int NameLength;
    unsigned __int64 NameLengthAligned;

    Result = 0;
    if (InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress
        && OutputSize > 0x10
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 4);
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        ProcessId = *(__int64 *)pInputBuffer;
        QueryNameFunc = (int (__fastcall *)(__int64, __int64, const void **, _QWORD, _QWORD))ResolveKernelModuleIndex(16873, 0x8E3u, 0x8E4u);
        if ((QueryNameFunc || (QueryNameFunc = (int (__fastcall *)(__int64, __int64, const void **, _QWORD, _QWORD))GtRead(GtDereferenceObjectFunc)) != 0)
            && QueryNameFunc(ProcessId, 1, (const void **)pOutputBuffer, OutputSize, 0) >= 0)
        {
            NameLength = *(unsigned __int16 *)pOutputBuffer & 0xFFFE;
            if (NameLength)
            {
                NameLengthAligned = NameLength;
                memmove(pOutputBuffer, *(const void **)pOutputBuffer, NameLength);
                *((unsigned __int16 *)pOutputBuffer + (NameLengthAligned >> 1)) = 0;
                return 1;
            }
        }
    }
    return Result;
}

// 通过EProcess终止进程操作
// 对应原始驱动 CmdTerminateProcessByEProcess (0x1400543FC)
__int64 TerminateProcessByEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    bool Result;
    __int64 EprocessAddr;
    unsigned __int8 (__fastcall *CheckObjectTypeFunc)(__int64);
    int (__fastcall *DuplicateHandleFunc)(__int64, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *);
    _QWORD *KernelDataField11;
    void (__fastcall *FreeFunc)(__int64);
    unsigned int (__fastcall *TerminateFunc)(__int64, _QWORD);
    bool IsLegacy;
    struct _KTHREAD *CurrentThread;
    char SavedThreadField;
    __int64 (__fastcall *DirectTerminateFunc)(__int64);
    __int64 Handle; // [rsp+58h] [rbp-30h] BYREF
    unsigned int SdstServiceCount;

    Result = 0;
    if (pInputBuffer && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 8);
        EprocessAddr = *(__int64 *)pInputBuffer;
        CheckObjectTypeFunc = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtObjectTypeCheckFlag);
        SdstServiceCount = GtRead(GtSdstServiceCount);
        DuplicateHandleFunc = (int (__fastcall *)(__int64, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54);
        KernelDataField11 = (_QWORD *)GtRead(GtKernelDataField11);
        FreeFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
        TerminateFunc = (unsigned int (__fastcall *)(__int64, _QWORD))GtRead(GtKernelDataField13);
        if (CheckObjectTypeFunc)
        {
            if (CheckObjectTypeFunc(EprocessAddr) == 1 && CheckObjectTypeFunc(EprocessAddr + 63) == 1)
            {
                IsLegacy = 0;
                if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0
                    && KernelDataField11
                    && CheckObjectTypeFunc(EprocessAddr - 48) == 1
                    && CheckObjectTypeFunc(EprocessAddr + 263) == 1
                    && *(__int64 *)(EprocessAddr - 32) == *KernelDataField11
                    && *(__int64 *)(EprocessAddr + 48) == EprocessAddr + 152)
                {
                    IsLegacy = *(char *)(EprocessAddr + 240) == 1;
                }
                if (IsLegacy)
                {
                    if (SdstServiceCount != -1 && DuplicateHandleFunc && KernelDataField11 && FreeFunc && TerminateFunc
                        && DuplicateHandleFunc(EprocessAddr, 512, 0, 0x10000000, *KernelDataField11, 0, &Handle) >= 0)
                    {
                        CurrentThread = KeGetCurrentThread();
                        SavedThreadField = *((char *)CurrentThread + SdstServiceCount);
                        *((char *)CurrentThread + SdstServiceCount) = 0;
                        Result = TerminateFunc(Handle, 0) == 0;
                        *((char *)CurrentThread + SdstServiceCount) = SavedThreadField;
                        FreeFunc(Handle);
                    }
                }
                else
                {
                    DirectTerminateFunc = (__int64 (__fastcall *)(__int64))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField138);
                    if (DirectTerminateFunc)
                        return DirectTerminateFunc(EprocessAddr);
                }
            }
        }
    }
    return Result;
}

// 检查进程隐藏检测操作
// 对应原始驱动 CmdCheckProcessHideDetect (0x1400331FC)
__int64 CheckProcessHideDetectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 pObjectTypeDirectory;
    __int64 pTypeDirectoryEntry;
    __int64 pTypeCompareEntry;
    __int64 FirstValue;

    Result = 0;
    if (pOutputBuffer && OutputSize == 4
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 4, 4);
        *pOutputBuffer = 0;
        pObjectTypeDirectory = QueryObjectTypeDirectoryPath();
        if (pObjectTypeDirectory)
        {
            pTypeDirectoryEntry = *(__int64 *)(pObjectTypeDirectory + 64);
            pTypeCompareEntry = *(__int64 *)(pObjectTypeDirectory + 312);
            if (pTypeDirectoryEntry && pTypeCompareEntry)
            {
                if (MmIsAddressValid((PVOID)(pObjectTypeDirectory + 312)) == 1
                    && MmIsAddressValid((PVOID)(pTypeCompareEntry + 55)) == 1)
                {
                    FirstValue = *(__int64 *)(pTypeDirectoryEntry + 16);
                    if (FirstValue && FirstValue != *(__int64 *)(pTypeCompareEntry + 48))
                        *pOutputBuffer = 1;
                }
            }
        }
        return 1;
    }
    return Result;
}

// 修复进程EProcess操作
// 对应原始驱动 CmdFixProcessEProcess (0x140033C68)
__int64 FixProcessEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 pObjectTypeDirectory;
    __int64 pTypeEntry1;
    __int64 pTypeEntry2;
    _QWORD Buffer[3];

    Result = 0;
    pObjectTypeDirectory = QueryObjectTypeDirectoryPath();
    if (pObjectTypeDirectory)
    {
        pTypeEntry1 = *(__int64 *)(pObjectTypeDirectory + 64);
        pTypeEntry2 = *(__int64 *)(pObjectTypeDirectory + 312);
        if (pTypeEntry1 && pTypeEntry2)
        {
            if (MmIsAddressValid((PVOID)(pObjectTypeDirectory + 312)) == 1
                && MmIsAddressValid((PVOID)(pTypeEntry2 + 55)) == 1)
            {
                Buffer[0] = *(__int64 *)(pTypeEntry2 + 48);
                if (Buffer[0])
                    return WritePhysicalMemoryBuffer(pTypeEntry1 + 16, Buffer, 8, 0, 0) == 1;
            }
        }
    }
    return Result;
}

// 启用对象回调操作
// 对应原始驱动 EnableObjectCallback (0x14000FB88)
__int64 EnableObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 LengthAligned;
    unsigned __int64 LastCharIndex;

    Result = 0;
    if (pInputBuffer)
    {
        if ((unsigned int)InputSize > 2 && (InputSize & 1) == 0
            && (unsigned __int64)pInputBuffer < MmUserProbeAddress)
        {
            LengthAligned = (unsigned int)InputSize;
            if ((unsigned __int64)pInputBuffer + (unsigned int)InputSize < MmUserProbeAddress)
            {
                ProbeForRead(pInputBuffer, (unsigned int)InputSize, 2);
                LastCharIndex = (unsigned __int64)(LengthAligned - 2) >> 1;
                if (*((unsigned __int16 *)pInputBuffer + LastCharIndex))
                    *((unsigned __int16 *)pInputBuffer + LastCharIndex) = 0;
                return InitObjectCallbackFiles((int)pInputBuffer);
            }
        }
    }
    return Result;
}

// 电源回调例程操作
// 从内核地址读取数据到用户缓冲区，按页映射内存，读取对象名称，逐页拷贝
// 对应原始驱动 sub_140011240
__int64 PowerCallbackRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    void **InputBuffer;
    int BufferSize;

    InputBuffer = (void **)pInputBuffer;
    BufferSize = InputSize;
    char Success;
    __int64 MapMemoryFunc;
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
            ZeroFunc = GtRead(GtZeroPagesFunc);
            ReadNameFunc = GtRead(GtMapMemoryFunc);
            UnmapFunc = GtRead(GtUnmapMemoryFunc);
            FreeFunc = GtRead(GtFreeMemoryFunc);
            FreeFunc2 = GtRead(GtFreePagesFunc);
            MapMemoryFuncTyped = (__int64 (__fastcall *)(unsigned __int64, __int64, _QWORD, _QWORD, _QWORD))MapMemoryFunc;
            ZeroFuncTyped = (void (__fastcall *)(__int64, _QWORD, _QWORD))ZeroFunc;
            ReadNameFuncTyped = (__int64 (__fastcall *)(__int64, _QWORD, __int64))ReadNameFunc;
            UnmapFuncTyped = (void (__fastcall *)(__int64, __int64))UnmapFunc;
            MapFuncTyped = (void (__fastcall *)(__int64))GtRead(GtMapPhysPagesFunc);
            FreeFuncTyped = (void (__fastcall *)(__int64))FreeFunc;
            FreeFunc2Typed = (void (__fastcall *)(__int64))FreeFunc2;
            if (MapMemoryFunc && GtRead(GtMapPhysPagesFunc) && ZeroFunc && ReadNameFunc && UnmapFunc && FreeFunc && FreeFunc2)
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
                                                ObjectNameFromCallback = ReadObjectNameFromCallback(MappedMemory, 16, ReadNameFuncTyped);
                                                if (ObjectNameFromCallback)
                                                {
                                                    memmove(OutputPtr, (const void *)(ObjectNameFromCallback + (CurrentAddress & 0xFFF)), PageRemainder);
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
                                                    memmove(OutputPtr, (const void *)(MappedBuffer + (CurrentAddress & 0xFFF)), PageRemainder);
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
*(unsigned int *)&RemainingSize = SizeCopy;
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

// 电源回调注销操作
// 对应原始驱动 PowerCallbackUnregister (0x140011630)
__int64 PowerCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
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
    if (pInputBuffer && InputSize == 40
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 40) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x28, 4);
        InputBufferPtr = (HANDLE *)pInputBuffer;
        if (*(HANDLE *)pInputBuffer && *((HANDLE *)pInputBuffer + 1))
        {
            ProcessHandle = *((HANDLE *)pInputBuffer + 4);
            if (ProcessHandle)
            {
                TargetSize = *((unsigned int *)pInputBuffer + 6);
                if (TargetSize)
                {
                    TargetBufferVal = *((HANDLE *)pInputBuffer + 2);
                    if (TargetBufferVal)
                    {
                        if (TargetSize < MmUserProbeAddress
                            && (unsigned __int64)TargetBufferVal < MmUserProbeAddress
                            && (unsigned __int64)TargetBufferVal + TargetSize < MmUserProbeAddress
                            && (unsigned __int64)ProcessHandle < MmUserProbeAddress
                            && (unsigned __int64)ProcessHandle + TargetSize < MmUserProbeAddress)
                        {
                            ProbeForWrite(ProcessHandle, TargetSize, 1);
                            SourceBuffer = ExAlloc(NonPagedPool, *((unsigned int *)pInputBuffer + 6));
                            if (SourceBuffer)
                            {
                                AllocStatus = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
                                LookupStatus = AllocStatus;
                                if (!*((HANDLE *)pInputBuffer + 1) && AllocStatus >= 0)
                                    *((HANDLE *)pInputBuffer + 1) = Process;
                                if (ValidateProcessObject((struct _KPROCESS *)*((HANDLE *)pInputBuffer + 1), 0) == 1)
                                {
                                    ProcessObject = (PRKPROCESS)*((HANDLE *)pInputBuffer + 1);
                                    SourceHandle = *((HANDLE *)pInputBuffer + 2);
                                    SourcePtr = SourceHandle;
                                    SizeVal = *((unsigned int *)pInputBuffer + 6);
                                    BufferSizeCopy = SizeVal;
                                    TargetHandle = *((HANDLE *)pInputBuffer + 4);
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
    return Success;
}

// 关机回调注销操作
// 对应原始驱动 ShutdownCallbackUnregister (0x1400118F4)
__int64 ShutdownCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
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
    if (pInputBuffer && InputSize == 40
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 40) < MmUserProbeAddress)
    {
        AllocBufferPtr = 0;
        ProbeForRead(pInputBuffer, 0x28, 4);
        if (*(PRKPROCESS *)pInputBuffer && *((PRKPROCESS *)pInputBuffer + 1))
        {
            TargetBuffer = *((PRKPROCESS *)pInputBuffer + 4);
            if (TargetBuffer)
            {
                TargetSize = *((unsigned int *)pInputBuffer + 6);
                if (TargetSize)
                {
                    SourceBuffer = *((PRKPROCESS *)pInputBuffer + 2);
                    if (SourceBuffer)
                    {
                        if (TargetSize < MmUserProbeAddress
                            && (unsigned __int64)SourceBuffer < MmUserProbeAddress
                            && (unsigned __int64)SourceBuffer + TargetSize < MmUserProbeAddress
                            && (unsigned __int64)TargetBuffer < MmUserProbeAddress
                            && (unsigned __int64)TargetBuffer + TargetSize < MmUserProbeAddress)
                        {
                            ProbeForRead(TargetBuffer, TargetSize, 1);
                            AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)pInputBuffer + 6));
                            AllocBufferPtr = AllocBuffer;
                            if (AllocBuffer)
                            {
                                LookupStatus = PsLookupProcessByProcessId(*(HANDLE *)pInputBuffer, &Process);
                                Status = LookupStatus;
                                if (!*((PRKPROCESS *)pInputBuffer + 1) && LookupStatus >= 0)
                                    *((PRKPROCESS *)pInputBuffer + 1) = Process;
                                if (ValidateProcessObject(*((PRKPROCESS *)pInputBuffer + 1), 0) == 1)
                                {
                                    ProcessObject = *((PRKPROCESS *)pInputBuffer + 1);
                                    SourceBufferPtr = *((PRKPROCESS *)pInputBuffer + 2);
                                    SourcePtr = SourceBufferPtr;
                                    BufferSizeCopy = *((unsigned int *)pInputBuffer + 6);
                                    SizeVal = BufferSizeCopy;
                                    TargetBufferPtr = *((PRKPROCESS *)pInputBuffer + 4);
                                    memmove(AllocBuffer, TargetBufferPtr, BufferSizeCopy);
                                    KeStackAttachProcess(*((PRKPROCESS *)pInputBuffer + 1), &ApcState);
                                    ProbeForRead(SourcePtr, BufferSizeCopy, 1);
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
    return Success;
}

// 注册表通知回调操作
// 对应原始驱动 RegNotifyCallback (0x14000D0B0)
__int64 RegNotifyCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    unsigned int DataSize;
    PVOID UserDataPtr;
    PVOID AllocBuffer;
    struct _KPROCESS *TargetProcess;
    char DiskSectorsAllocated;
    char IsSystemModule;
    unsigned int CopySize;
    char *TargetAddress;
    struct _KPROCESS *AttachedProcess;
    void *Buffer;
    struct _KAPC_STATE ApcState;

    Result = 0;
    AttachedProcess = 0;
    if (InputSize == 24)
    {
        if (pInputBuffer)
        {
            if ((unsigned __int64)pInputBuffer < MmUserProbeAddress
                && (unsigned __int64)(pInputBuffer + 24) < MmUserProbeAddress)
            {
                ProbeForRead(pInputBuffer, 0x18, 4);
                if (*(PVOID *)pInputBuffer > MmSystemRangeStart)
                {
                    DataSize = *((unsigned int *)pInputBuffer + 2);
                    if (DataSize && DataSize < MmUserProbeAddress)
                    {
                        UserDataPtr = *((PVOID *)pInputBuffer + 2);
                        if (UserDataPtr
                            && (unsigned __int64)UserDataPtr < MmUserProbeAddress
                            && (unsigned __int64)UserDataPtr + DataSize < MmUserProbeAddress)
                        {
                            ProbeForRead(UserDataPtr, DataSize, 1);
                            AllocBuffer = ExAlloc(NonPagedPool, *((unsigned int *)pInputBuffer + 2));
                            Buffer = AllocBuffer;
                            if (AllocBuffer)
                            {
                                memmove(AllocBuffer, *((PVOID *)pInputBuffer + 2), *((unsigned int *)pInputBuffer + 2));
                                TargetAddress = (char *)*(PVOID *)pInputBuffer;
                                CopySize = *((unsigned int *)pInputBuffer + 2);
                                IsSystemModule = CheckAddressInSystemModuleRange((unsigned __int64)*(PVOID *)pInputBuffer);
                                DiskSectorsAllocated = 0;
                                if (IsSystemModule)
                                {
                                    DiskSectorsAllocated = ReadDiskSectorsWithAlloc((__int64)&ApcState);
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
                                if (MmIsAddressValid(TargetAddress) == 1
                                    && MmIsAddressValid(&TargetAddress[CopySize - 1]) == 1)
                                    Result = WritePhysicalMemoryBuffer((unsigned __int64)TargetAddress, Buffer, CopySize, 0, 0);
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
    }
    return Result;
}

// 禁用线程保护操作
// 对应原始驱动 DisableThreadProtect (0x140007BAC)
__int64 DisableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    volatile void *BufferPtr;
    SIZE_T BufferSize;
    ULONG64 WriteTarget;
    PVOID AllocBuffer;

    if (pInputBuffer && InputSize == 32
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 32) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x20, 4);
        if (*(__int64 *)pInputBuffer)
        {
            BufferPtr = (volatile void *)*((__int64 *)pInputBuffer + 2);
            if (BufferPtr)
            {
                BufferSize = *(unsigned int *)(pInputBuffer + 8);
                if ((unsigned int)BufferSize)
                {
                    WriteTarget = *((ULONG64 *)pInputBuffer + 3);
                    if (WriteTarget)
                    {
                        if ((unsigned __int64)BufferPtr < MmUserProbeAddress
                            && (unsigned __int64)BufferPtr + BufferSize < MmUserProbeAddress
                            && WriteTarget < MmUserProbeAddress
                            && WriteTarget + 8 < MmUserProbeAddress)
                        {
                            ProbeForRead(BufferPtr, BufferSize, 1);
                            ProbeForWrite((volatile void *)*((ULONG64 *)pInputBuffer + 3), 8, 8);
                            AllocBuffer = ExAlloc(NonPagedPool, *(unsigned int *)(pInputBuffer + 8));
                            if (!AllocBuffer)
                                AllocBuffer = ExAlloc(PagedPool, *(unsigned int *)(pInputBuffer + 8));
                            if (AllocBuffer)
                            {
                                memmove(AllocBuffer, *((const void **)pInputBuffer + 2), *(unsigned int *)(pInputBuffer + 8));
                                ExFree(AllocBuffer);
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

// 启用线程保护操作
// 对应原始驱动 EnableThreadProtect (0x140007AB4)
__int64 EnableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    __int64 ThreadAddress;
    unsigned int PageIndex;
    __int64 ThreadAddressCopy;

    if (pInputBuffer && pOutputBuffer && InputSize == 8 && OutputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pOutputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 8);
        ProbeForWrite(pOutputBuffer, 8, 8);
        ThreadAddress = *(__int64 *)pInputBuffer;
        ThreadAddressCopy = *(__int64 *)pInputBuffer;
        if (ThreadAddress > (unsigned __int64)MmSystemRangeStart)
        {
            for (PageIndex = 0; PageIndex < 0x100 && MmIsAddressValid((PVOID)(ThreadAddress + PageIndex)); ++PageIndex)
                ;
            if (PageIndex)
                *pOutputBuffer = (unsigned int)ThreadAddressCopy;
        }
    }
    return 0;
}

// QuerySystemInfoExOperation — 查询系统信息（扩展版）
// 对应原始驱动 CmdQuerySystemInfoEx (0x14006EC24)
// 输出系统构建号和17种对象类型的信息
__int64 QuerySystemInfoExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    PVOID ***Slot0, ***Slot1, ***Slot2, ***Slot3, ***Slot4;
    PVOID ***Slot5, ***Slot6, ***Slot7, ***Slot8, ***Slot9;
    PVOID ***Slot10, ***Slot11, ***Slot12, ***Slot13, ***Slot14;
    PVOID ***Slot15, ***Slot16;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    Result = 0;
    if (pOutputBuffer
        && OutputSize >= 0xE78
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        // 确保内核内存初始化
        if (!(unsigned int)GtRead(GtSubsystemConfigBase | GtNtoskrnlModuleBase | 0x100))
            AttachToProcessAndInitKernelMemory();

        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        RtlFillMemory(pOutputBuffer, 0xE78, 0);

        // 写入系统构建号
        *pOutputBuffer = BuildNumber;
        pOutputBuffer[886] = 0;

        // 17个对象类型槽位，每个槽位占52个DWORD(208字节)，从偏移0开始
        // 槽位0 (offset 0):   Process
        // 槽位1 (offset 54):  File
        // 槽位2 (offset 106): Driver
        // 槽位3 (offset 158): Thread
        // 槽位4 (offset 210): NtoskrnlImageSize相关
        // 槽位5 (offset 262): Section相关
        // 槽位6 (offset 314): EprocessField95相关
        // 槽位7 (offset 366): ExFreeCallBack相关
        // 槽位8 (offset 418): SubsystemConfigBase
        // 槽位9 (offset 470): EprocessField188
        // 槽位10 (offset 522): EprocessField185
        // 槽位11 (offset 574): EprocessField57
        // 槽位12 (offset 626): CallbackField69
        // 槽位13 (offset 678): CallbackField29
        // 槽位14 (offset 730): CallbackField72
        // 槽位15 (offset 782): CallbackField78
        // 槽位16 (offset 834): CallbackField75

        Slot0  = (PVOID ***)GtRead(GtEprocessField111 | 0x100);
        Slot1  = (PVOID ***)GtRead(GtZwCreateFileFunc);
        Slot2  = (PVOID ***)GtRead(GtDriverObjectListHead);
        Slot3  = (PVOID ***)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        Slot4  = (PVOID ***)GtRead(GtSubsystemConfigBase | GtNtoskrnlImageSize | 0x100);
        Slot5  = (PVOID ***)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField54);
        Slot6  = (PVOID ***)GtRead(GtTotalSize | GtEprocessField95 | 0x100);
        Slot7  = (PVOID ***)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
        Slot8  = (PVOID ***)GtRead(GtSubsystemConfigBase | 0x100);
        Slot9  = (PVOID ***)GtRead(GtEprocessField188 | 0x100);
        Slot10 = (PVOID ***)GtRead(GtEprocessField185 | 0x100);
        Slot11 = (PVOID ***)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField57);
        Slot12 = (PVOID ***)GtRead(GtTotalSize | GtCallbackField69);
        Slot13 = (PVOID ***)GtRead(GtCallbackField29);
        Slot14 = (PVOID ***)GtRead(GtTotalSize | GtCallbackField72);
        Slot15 = (PVOID ***)GtRead(GtTotalSize | GtCallbackField78);
        Slot16 = (PVOID ***)GtRead(GtTotalSize | GtCallbackField75);

        // 对每个非空槽位，读取对象头信息并写入缓冲区
        // 每个槽位208字节(52 DWORD)，结构为：
        //   [0]=Name, [1]=Quota, [2]=Memory, [3]=CreateInfo, [4]=Handle,
        //   [5]=BodyOffset, [6]=TypeOffset, [7]=Type, 其余为版本特有GT值

        _QWORD **Slots[17] = {
            (_QWORD ***)Slot0, (_QWORD ***)Slot1, (_QWORD ***)Slot2, (_QWORD ***)Slot3,
            (_QWORD ***)Slot4, (_QWORD ***)Slot5, (_QWORD ***)Slot6, (_QWORD ***)Slot7,
            (_QWORD ***)Slot8, (_QWORD ***)Slot9, (_QWORD ***)Slot10, (_QWORD ***)Slot11,
            (_QWORD ***)Slot12, (_QWORD ***)Slot13, (_QWORD ***)Slot14, (_QWORD ***)Slot15,
            (_QWORD ***)Slot16
        };

        for (int i = 0; i < 17; i++)
        {
            unsigned int *SlotBase = pOutputBuffer + (i * 52);
            _QWORD **Slot = Slots[i];

            if (Slot && Slot > (PVOID *)MmSystemRangeStart)
            {
                // 读取对象头名称到 SlotBase[0]
                if (*Slot && *Slot > (PVOID *)MmSystemRangeStart)
                {
                    SlotBase[0] = (unsigned int)ReadObjectHeaderName((PVOID ***)*Slot, 1);
                    SlotBase[1] = (unsigned int)ReadObjectHeaderQuota((PVOID ***)*Slot, 1);
                    SlotBase[2] = (unsigned int)QueryKernelMemoryByAddress((PVOID ***)*Slot, 1);
                    SlotBase[3] = (unsigned int)ReadObjectHeaderCreateInfo((PVOID ***)*Slot, 1);
                    SlotBase[4] = (unsigned int)ReadObjectHeaderHandle((PVOID ***)*Slot, 1);
                    SlotBase[5] = (unsigned int)ReadObjectBodyOffset((PVOID ***)*Slot, 1);
                    SlotBase[6] = (unsigned int)ReadObjectTypeOffset((PVOID ***)*Slot, 1);
                    SlotBase[7] = (unsigned int)ReadObjectHeaderType((PVOID ***)*Slot, 1);

                    // 版本特有的GT值写入后续槽位
                    if ((unsigned int)BuildNumber >= 0x60000)
                    {
                        switch (i)
                        {
                            case 0:  SlotBase[8] = (unsigned int)GtRead(GtEprocessField111 | 0x100); break;
                            case 1:  SlotBase[8] = (unsigned int)GtRead(GtZwCreateFileFunc); break;
                            case 2:  SlotBase[8] = (unsigned int)GtRead(GtDriverObjectListHead); break;
                            case 3:  SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100); break;
                            case 4:  SlotBase[8] = (unsigned int)GtRead(GtSubsystemConfigBase | GtNtoskrnlImageSize | 0x100); break;
                            case 5:  SlotBase[8] = (unsigned int)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField54); break;
                            case 6:  SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtEprocessField95 | 0x100); break;
                            case 7:  SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100); break;
                            case 8:  SlotBase[8] = (unsigned int)GtRead(GtSubsystemConfigBase | 0x100); break;
                            case 9:  SlotBase[8] = (unsigned int)GtRead(GtEprocessField188 | 0x100); break;
                            case 10: SlotBase[8] = (unsigned int)GtRead(GtEprocessField185 | 0x100); break;
                            case 11: SlotBase[8] = (unsigned int)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField57); break;
                            case 12: SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtCallbackField69); break;
                            case 13: SlotBase[8] = (unsigned int)GtRead(GtCallbackField29); break;
                            case 14: SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtCallbackField72); break;
                            case 15: SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtCallbackField78); break;
                            case 16: SlotBase[8] = (unsigned int)GtRead(GtTotalSize | GtCallbackField75); break;
                        }
                    }
                }
            }
        }

        // 验证对象类型条目
        ValidateObjectTypeEntries((__int64)pOutputBuffer);

        // 查询对象目录并枚举
        QueryObjectDirectoryAndEnumerate((__int64)pOutputBuffer, OutputSize);

        return 1;
    }
    return Result;
}

// 回调控制操作
// 对应原始驱动 CmdCallbackControl (0x140070190)
// 根据输入参数选择对应的回调类型进行物理内存读写操作
__int64 CallbackControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    char **TargetObject;
    __int64 Context;
    unsigned int OperationType;
    unsigned __int64 ContextValue;
    __int64 SharedVars, CallbackArg9, CallbackArg10, CallbackArg11, CallbackArg12, CallbackArg13, CallbackArg14, CallbackArg15, CallbackArg16, CallbackArg17, CallbackArg18, CallbackArg19, CallbackArg20;

    Result = 0;
    if (pInputBuffer)
    {
        if (InputSize == 32
            && (unsigned __int64)pInputBuffer < MmUserProbeAddress
            && (unsigned __int64)(pInputBuffer + 32) < MmUserProbeAddress)
        {
            ProbeForWrite(pInputBuffer, 0x20, 1);
            if (*pInputBuffer == 1 || pInputBuffer[1] == 1)
            {
                TargetObject = (char **)*((_QWORD *)pInputBuffer + 1);
                if (TargetObject == (char **)GtRead(GtEprocessField111 | 0x100)
                    || TargetObject == (char **)GtRead(GtZwCreateFileFunc)
                    || TargetObject == (char **)GtRead(GtDriverObjectListHead)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100)
                    || TargetObject == (char **)GtRead(GtSubsystemConfigBase | GtNtoskrnlImageSize | 0x100)
                    || TargetObject == (char **)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField54)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtEprocessField95 | 0x100)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100)
                    || TargetObject == (char **)GtRead(GtSubsystemConfigBase | 0x100)
                    || TargetObject == (char **)GtRead(GtEprocessField188 | 0x100)
                    || TargetObject == (char **)GtRead(GtEprocessField185 | 0x100)
                    || TargetObject == (char **)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField57)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtCallbackField69)
                    || TargetObject == (char **)GtRead(GtCallbackField29)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtCallbackField72)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtCallbackField78)
                    || TargetObject == (char **)GtRead(GtTotalSize | GtCallbackField75))
                {
                    OperationType = *((_DWORD *)pInputBuffer + 4);
                    if (OperationType < 8)
                    {
                        Result = 1;
                        ContextValue = *((_QWORD *)pInputBuffer + 3);
                        if (ContextValue)
                        {
                            if (GtRead(GtEprocessField155 | 0x100) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField156 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField157 | 0x100) == ContextValue)
                            { SharedVars = *pInputBuffer; CallbackType3Dispatcher(TargetObject, ContextValue, SharedVars, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField158 | 0x100) == ContextValue)
                            { CallbackArg9 = *pInputBuffer; CallbackType5Dispatcher(TargetObject, ContextValue, CallbackArg9, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField159 | 0x100) == ContextValue)
                            { CallbackArg10 = *pInputBuffer; CallbackType4Dispatcher(TargetObject, ContextValue, CallbackArg10, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField160 | 0x100) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField161 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField162 | 0x100) == ContextValue)
                            { CallbackArg11 = *pInputBuffer; CallbackType3Dispatcher(TargetObject, ContextValue, CallbackArg11, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField163 | 0x100) == ContextValue)
                            { CallbackArg12 = *pInputBuffer; CallbackType5Dispatcher(TargetObject, ContextValue, CallbackArg12, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField164 | 0x100) == ContextValue)
                            { CallbackArg13 = *pInputBuffer; CallbackType4Dispatcher(TargetObject, ContextValue, CallbackArg13, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField165 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtCallbackField24) == ContextValue)
                            { CallbackArg14 = *pInputBuffer; CallbackType5Dispatcher(TargetObject, ContextValue, CallbackArg14, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField166 | 0x100) == ContextValue)
                            { CallbackArg15 = *pInputBuffer; CallbackType3Dispatcher(TargetObject, ContextValue, CallbackArg15, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField167 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField168 | 0x100) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField169 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField170 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField171 | 0x100) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField172 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField173 | 0x100) == ContextValue)
                            { CallbackArg16 = *pInputBuffer; CallbackType2Dispatcher(TargetObject, ContextValue, CallbackArg16, pInputBuffer[1], 0); }
                            if (GtRead(GtEprocessField174 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField175 | 0x100) == ContextValue)
                            { CallbackArg17 = *pInputBuffer; CallbackType2Dispatcher(TargetObject, ContextValue, CallbackArg17, pInputBuffer[1], 0); }
                            if (GtRead(GtNtQuerySystemInformationFunc | GtEprocessField22) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtNtQuerySystemInformationFunc | GtEprocessField23) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField178 | 0x100) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField179 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtNtQuerySystemInformationFunc | GtEprocessField26) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtNtQuerySystemInformationFunc | GtEprocessField27) == ContextValue)
                            { CallbackArg18 = *pInputBuffer; CallbackType3Dispatcher(TargetObject, ContextValue, CallbackArg18, pInputBuffer[1], 0); }
                            if (GtRead(GtFwpsDispatchTableBase | GtSubsystemConfigBase | GtEprocessField42) == ContextValue)
                            { CallbackArg19 = *pInputBuffer; CallbackType2Dispatcher(TargetObject, ContextValue, CallbackArg19, pInputBuffer[1], 0); }
                            if (GtRead(GtFwpsDispatchTableCount | GtSubsystemConfigBase | GtEprocessField42) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtEprocessField182 | 0x100) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtCallbackField30) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtCallbackField31) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtCallbackField32) == ContextValue)
                                ReadCallbackType1(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if (GtRead(GtCallbackField33) == ContextValue)
                                ReadCallbackType2(TargetObject, ContextValue, *pInputBuffer, pInputBuffer[1], 0);
                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770 && GtRead(GtCallbackField34) == ContextValue)
                            { CallbackArg20 = *pInputBuffer; CallbackType2Dispatcher(TargetObject, ContextValue, CallbackArg20, pInputBuffer[1], 0); }
                        }
                        else if (OperationType)
                        {
                            switch (OperationType)
                            {
                                case 1u: Context = 1; CallbackType2Dispatcher(TargetObject, 0, Context, 0, 1); break;
                                case 2u: ReadCallbackType1(TargetObject, 0, 1, 0, 1); break;
                                case 3u: ReadCallbackType2(TargetObject, 0, 1, 0, 1); break;
                                case 4u: Context = 1; CallbackType3Dispatcher(TargetObject, 0, Context, 0, 1); break;
                                case 5u: Context = 1; CallbackType5Dispatcher(TargetObject, 0, Context, 0, 1); break;
                                default:
                                    Context = 1;
                                    if (OperationType == 6) CallbackType4Dispatcher(TargetObject, 0, Context, 0, 1);
                                    else CallbackType1Dispatcher(TargetObject, 0, Context, 0, 1);
                                    break;
                            }
                        }
                        else
                        {
                            ReadCallbackType3(TargetObject, 0, 1, 0, 1);
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 内核通知例程操作
// 对应原始驱动 KernelNotifyRoutine (0x140019CFC)
__int64 KernelNotifyRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    return MiniFilterTeardownRoutine(pInputBuffer, InputSize, 1);
}

// 内核通知例程扩展操作
// 对应原始驱动 KernelNotifyRoutineEx (0x140019D04)
__int64 KernelNotifyRoutineExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    return MiniFilterTeardownRoutine(pInputBuffer, InputSize, 0);
}

// 枚举内核对象表操作
// 对应原始驱动 CmdEnumKernelObjectTable (0x140029964)
__int64 EnumKernelObjectTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    unsigned int MaxEntries;
    _QWORD **pObjectTypeList;
    _QWORD *pListEntry;
    unsigned int IterCount;
    _QWORD *pObjectHeader;
    _QWORD *pOutputEntry;
    unsigned int BuildNumber;
    __int64 FieldValue;
    __int64 FieldValue2;
    __int64 ObjectTypeInfo;
    enum _GLOBAL_TABLE_INDEX TypeIndex;
    unsigned int MaxEntriesCopy;
    _QWORD **pObjectTypeListCopy;

    Result = 0;
    if (pOutputBuffer && OutputSize >= 0xD0
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        *pOutputBuffer = BuildNumber;
        pOutputBuffer[1] = 0;
        MaxEntries = (OutputSize - 208) / 0xC8 + 1;
        MaxEntriesCopy = MaxEntries;
        pObjectTypeList = (_QWORD **)GtRead(GtCallbackField102);
        pObjectTypeListCopy = pObjectTypeList;
        if (pObjectTypeList)
        {
            pListEntry = *pObjectTypeList;
            IterCount = 0;
            while (1)
            {
                if (pListEntry == pObjectTypeList || IterCount >= 0x10000 || pOutputBuffer[1] >= MaxEntries)
                {
                    ResolveKernelObjectAddresses((__int64)pOutputBuffer);
                    return pOutputBuffer[1] != 0;
                }
                pObjectHeader = (_QWORD *)((char *)pListEntry - (unsigned int)GtRead(GtCallbackField101));
                *(__int64 *)&pOutputBuffer[50 * pOutputBuffer[1] + 2] = (__int64)pObjectHeader;
                pOutputEntry = &pOutputBuffer[50 * pOutputBuffer[1]];
                memset(pOutputEntry + 2, 0, 0xC0);
                BuildNumber = *pOutputBuffer;
                if (*pOutputBuffer < 0xA28)
                {
                    pOutputEntry[3] = pObjectHeader[1];
                    pOutputEntry[6] = 0;
                    pOutputEntry[9] = pObjectHeader[2];
                    pOutputEntry[12] = pObjectHeader[3];
                    pOutputEntry[15] = pObjectHeader[4];
                    pOutputEntry[18] = pObjectHeader[5];
                    pOutputEntry[21] = pObjectHeader[6];
                    FieldValue = pObjectHeader[7];
                }
                else if (BuildNumber < 0x23F0)
                {
                    pOutputEntry[3] = pObjectHeader[1];
                    pOutputEntry[6] = pObjectHeader[2];
                    pOutputEntry[9] = pObjectHeader[3];
                    pOutputEntry[12] = pObjectHeader[4];
                    pOutputEntry[15] = pObjectHeader[5];
                    pOutputEntry[18] = pObjectHeader[6];
                    pOutputEntry[21] = pObjectHeader[7];
                    FieldValue = pObjectHeader[8];
                }
                else if (BuildNumber > 0x2580)
                {
                    pOutputEntry[3] = pObjectHeader[1];
                    pOutputEntry[6] = pObjectHeader[2];
                    pOutputEntry[9] = pObjectHeader[3];
                    pOutputEntry[12] = pObjectHeader[4];
                    pOutputEntry[15] = 0;
                    pOutputEntry[18] = pObjectHeader[5];
                    FieldValue2 = pObjectHeader[6];
                    pOutputEntry[21] = FieldValue2;
                    pOutputEntry[24] = 0;
                }
                else
                {
                    pOutputEntry[3] = pObjectHeader[1];
                    pOutputEntry[6] = 0;
                    pOutputEntry[9] = pObjectHeader[2];
                    pOutputEntry[12] = pObjectHeader[3];
                    pOutputEntry[15] = 0;
                    pOutputEntry[18] = pObjectHeader[4];
                    FieldValue2 = pObjectHeader[5];
                    pOutputEntry[21] = FieldValue2;
                    pOutputEntry[24] = 0;
                }
                pOutputEntry[24] = FieldValue;
                pOutputEntry[5] = 0;
                if ((unsigned int)BuildNumber >= 0x2800)
                {
                    if ((*((char *)pObjectHeader + (unsigned int)GtRead(GtCallbackField92)) & 1) != 0)
                        TypeIndex = GtObjectTypeIdxNotMatched;
                    else
                        TypeIndex = GtObjectTypeIdxMatched;
                    ObjectTypeInfo = GtRead(TypeIndex);
                }
                else
                {
                    if (pOutputEntry[6])
                        ObjectTypeInfo = GtRead(GtCallbackField96);
                }
                pOutputEntry[5] = ObjectTypeInfo;
                pOutputEntry[2] = GetKernelObjectTypeInfo((__int64)pObjectHeader);
                ++pOutputBuffer[1];
                ++IterCount;
                pListEntry = (_QWORD *)*pListEntry;
                MaxEntries = MaxEntriesCopy;
                pObjectTypeList = pObjectTypeListCopy;
            }
        }
    }
    return Result;
}

// 初始化文件系统回调操作
// 对应原始驱动 InitFileSystemCallback (0x14000D704)
__int64 InitFileSystemCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 BufferSize;
    unsigned __int64 MaxEntries;

    Result = 0;
    if (pOutputBuffer && OutputSize >= 0x20
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        BufferSize = OutputSize;
        ProbeForWrite(pOutputBuffer, OutputSize, 4);
        memset(pOutputBuffer, 0, (unsigned int)BufferSize);
        *pOutputBuffer = 0;
        MaxEntries = (BufferSize - 32) / 0x18;
        ScanKernelMemForFsChanges(pOutputBuffer, MaxEntries);
        if (*pOutputBuffer < (unsigned int)MaxEntries)
            ScanVadForModifiedPages(pOutputBuffer, MaxEntries - *pOutputBuffer);
        return 1;
    }
    return Result;
}

// 初始化文件系统过滤器操作
// 对应原始驱动 InitFileSystemFilter (0x14000EB40)
__int64 InitFileSystemFilterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    int Win10Ready;
    int Win7Ready;

    Result = 0;
    if (pOutputBuffer && InputSize == 7192
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)((char *)pOutputBuffer + 7192) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 0x1C18, 1);
        memset(pOutputBuffer, 0, 0x1C18);
        Win10Ready = GtRead(GtFileSystemReady10);
        if (!Win10Ready)
        {
            InitFileSystemExportTable(1);
            ParseFsFilterDriverExport(1);
            Win10Ready = GtRead(GtFileSystemReady10);
        }
        Win7Ready = GtRead(GtFileSystemReady7);
        if (!Win7Ready)
        {
            InitFileSystemExportTable(0);
            ParseFsFilterDriverExport(0);
            Win7Ready = GtRead(GtFileSystemReady7);
        }
        if (Win10Ready
            && InitFileSystemFilterCallbacks((__int64)((char *)pOutputBuffer + 8), (_QWORD *)pOutputBuffer + 449, 1) == 1
            && CopyFsFilterEntryTable((__int64)((char *)pOutputBuffer + 8), 1) == 1
            && ValidateFsFilterEntries((__int64)((char *)pOutputBuffer + 8)) == 1)
        {
            *(char *)pOutputBuffer = 1;
            Result = 1;
        }
        if (Win7Ready
            && InitFileSystemFilterCallbacks((__int64)((char *)pOutputBuffer + 3600), (_QWORD *)pOutputBuffer + 898, 0) == 1
            && CopyFsFilterEntryTable((__int64)((char *)pOutputBuffer + 3600), 0) == 1
            && ValidateFsFilterEntries((__int64)((char *)pOutputBuffer + 3600)) == 1)
        {
            *((char *)pOutputBuffer + 1) = 1;
            return 1;
        }
    }
    return Result;
}

// 文件系统过滤器回调操作
// 对应原始驱动 FileSystemFilterCallback (0x14000EF84)
__int64 FileSystemFilterCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    char PatchResult;
    char WriteResult;
    PVOID TargetAddress;
    _OWORD WriteData;

    Result = 0;
    if (pInputBuffer && InputSize == 64
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 64) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x40, 1);
        if (pInputBuffer[8] == 1
            && *(unsigned int *)(pInputBuffer + 12) < 0x40
            && (*pInputBuffer == 1 || (unsigned int)GtRead(GtWindowsBuildNumber) < 0x1DB0))
        {
            PatchResult = 1;
            WriteResult = 1;
            if (pInputBuffer[40] == 1 && *(__int64 *)(pInputBuffer + 24))
                PatchResult = PatchFsFilterDriverIndex((__int64)(pInputBuffer + 8), *pInputBuffer);
            if (pInputBuffer[41] == 1)
            {
                WriteResult = 0;
                TargetAddress = (PVOID)*(__int64 *)(pInputBuffer + 24);
                if (TargetAddress > MmSystemRangeStart
                    && CheckMemoryValid(TargetAddress) == 1
                    && CheckMemoryValid((void *)(*(__int64 *)(pInputBuffer + 24) + 15)) == 1)
                {
                    WriteData = *(_OWORD *)(pInputBuffer + 42);
                    WriteResult = WritePhysicalMemoryBuffer(*(__int64 *)(pInputBuffer + 24), &WriteData, 0x10, 0, 0);
                }
            }
            return PatchResult & WriteResult;
        }
    }
    return Result;
}

// InitObjectCallbackOperation — 初始化对象回调
// 对应原始驱动 InitObjectCallback (0x14000F0F4)
// 枚举进程列表和对象类型信息，写入输出缓冲区
__int64 InitObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    __int64 BufferSize;
    char Result;
    _DWORD *ProcessListBuffer;
    unsigned int RemainingSize;
    int ObjectTypeCount;
    __int64 ObjectListOffset;
    int ObjectListOffsetInt;
    __int64 ProcessFlagsOffset;
    int ProcessFlagsOffsetInt;
    __int64 QueryNameFunc;
    __int64 MaxTypeIndex;
    _DWORD *AllocBuffer;
    unsigned int ProcessCount;
    unsigned int ProcessIndex;
    void **ProcessEntry;
    char IsSystemProcess;
    int TypeCheckResult;
    _QWORD **ObjectTypeListPtr;
    unsigned int TypeListIndex;
    _QWORD *CurrentTypeEntry;
    _QWORD *TypeEntry;
    _QWORD *TypeInfo;
    unsigned __int64 TypeNameAddr;
    unsigned __int16 *NameBufferAlloc;
    unsigned __int16 *NameBuffer;
    unsigned __int16 *NamePtrCheck;
    unsigned __int64 NameLength;
    unsigned __int16 NameLength2;
    unsigned int EntrySize;
    _DWORD *OutputEntry;
    unsigned int *OutputEntry2;
    _DWORD *OutputTable;
    unsigned int QueryResultSize;
    __int64 ProcessOffset;
    __int64 ProcessEprocess;
    __int64 ProcessCreateTime;
    int ProcessCreateTimeInt;
    __int64 ProcessFlags;
    unsigned int ProcessCount2;
    _DWORD *OutputPtr;
    int MaxTypeIndex2;
    int EprocessOffsetInt;
    int CreateTimeOffsetInt;
    unsigned int NewEntrySize;
    int ProcessFlagsInt;
    _QWORD *TypeEntryCheck;
    int EprocessOffset;
    int (__fastcall *QueryObjectNameFunc)(unsigned __int64, unsigned __int16 *, _QWORD, unsigned int *);
    __int64 ObjectListOffsetVal;
    _QWORD *SavedTypeEntry;
    void **ProcessEntrySaved;
    _QWORD *TypeInfoSaved;
    unsigned __int16 *NameBufferSaved;
    unsigned int SavedRemainingSize;
    _QWORD **pTypeEntryList;
    _DWORD *SavedBuffer;
    unsigned int SavedProcessCount;
    unsigned int SavedProcessIndex;
    __int64 IsProtected;
    __int64 SavedMaxTypeIndex;
    int TypeFlags;
    unsigned __int64 NameBufferSize;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    BufferSize = OutputSize;
    Result = 0;
    ProcessListBuffer = 0;
    SavedBuffer = 0;

    if ((unsigned int)BuildNumber >= 0xA28)
    {
        if (pOutputBuffer
            && (unsigned int)BufferSize >= 0x48
            && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
            && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, (unsigned int)BufferSize, 4);
            memset(pOutputBuffer, 0, (unsigned int)BufferSize);
            OutputTable = pOutputBuffer;
            *pOutputBuffer = 0;
            OutputPtr = pOutputBuffer + 2;
            RemainingSize = (unsigned int)BufferSize - 8;
            SavedRemainingSize = (unsigned int)BufferSize - 8;
            ObjectTypeCount = GtRead(GtObjectTypeCount);
            ProcessOffset = GtRead(GtProcessOffset);
            EprocessOffset = ProcessOffset;
            ProcessEprocess = GtRead(GtProcessEprocess);
            EprocessOffsetInt = ProcessEprocess;
            ProcessCreateTime = GtRead(GtProcessCreateTime);
            CreateTimeOffsetInt = ProcessCreateTime;
            ObjectListOffset = GtRead(GtObjectListOffset);
            ObjectListOffsetInt = ObjectListOffset;
            ObjectListOffsetVal = ObjectListOffset;
            ProcessCreateTimeInt = ObjectListOffset;
            ProcessFlagsOffset = GtRead(GtProcessFlagsOffset);
            ProcessFlagsOffsetInt = ProcessFlagsOffset;
            ProcessFlags = ProcessFlagsOffset;
            ProcessFlagsInt = ProcessFlagsOffset;
            QueryNameFunc = GtRead(GtQueryObjectNameFunc);
            QueryObjectNameFunc = (int (__fastcall *)(unsigned __int64, unsigned __int16 *, _QWORD, unsigned int *))QueryNameFunc;

            if (ObjectTypeCount
                && (_DWORD)ProcessOffset != -1
                && (_DWORD)ProcessEprocess != -1
                && (_DWORD)ProcessCreateTime
                && ObjectListOffsetInt
                && ProcessFlagsOffsetInt
                && QueryNameFunc)
            {
                MaxTypeIndex = (unsigned int)(ObjectTypeCount - 1);
                SavedMaxTypeIndex = MaxTypeIndex;
                MaxTypeIndex2 = MaxTypeIndex;
                Result = 1;
                AllocBuffer = ExAlloc(1, 0x44610);
                ProcessListBuffer = AllocBuffer;
                SavedBuffer = AllocBuffer;
                if (AllocBuffer)
                {
                    AllocBuffer[4] = 0;
                    if (EnumerateProcessList(0, (__int64)AllocBuffer, 0x44610) == 1)
                    {
                        ProcessCount = ProcessListBuffer[4];
                        SavedProcessCount = ProcessCount;
                        ProcessCount2 = ProcessCount;
                        ProcessIndex = 0;
                        SavedProcessIndex = 0;
                        while (1)
                        {
                            if (ProcessIndex >= ProcessCount || RemainingSize < 0x40)
                                goto ExitLoop;
                            ProcessEntry = (void **)&ProcessListBuffer[14 * ProcessIndex + 6];
                            ProcessEntrySaved = ProcessEntry;
                            if (CheckMemoryValid(ProcessEntry[1]) == 1
                                && CheckMemoryValid((char *)ProcessEntry[1] + (unsigned int)MaxTypeIndex) == 1)
                            {
                                break;
                            }
                            SavedProcessIndex = ++ProcessIndex;
                            RemainingSize = SavedRemainingSize;
                            ProcessCount = SavedProcessCount;
                            continue;
                        }
                        IsSystemProcess = 0;
                        LOBYTE_LV(IsProtected) = 0;
                        if ((unsigned int)BuildNumber < 0x2800)
                        {
                            if ((unsigned int)BuildNumber < 0x1770)
                            {
                                IsSystemProcess = 1;
                                LOBYTE_LV(IsProtected) = 1;
                                goto CheckObjectTypeList;
                            }
                            TypeCheckResult = *(_DWORD *)((_BYTE *)ProcessEntry[1] + (unsigned int)ProcessFlags) & 2;
                        }
                        else
                        {
                            TypeCheckResult = *(_DWORD *)((_BYTE *)ProcessEntry[1] + (unsigned int)ProcessFlags) & 8;
                        }
                        if (!TypeCheckResult)
                        {
                            IsSystemProcess = 1;
                            LOBYTE_LV(IsProtected) = 1;
                        }
CheckObjectTypeList:
                        if (IsSystemProcess == 1)
                        {
                            ObjectTypeListPtr = (_QWORD **)((char *)ProcessEntry[1] + (unsigned int)ObjectListOffsetVal);
                            pTypeEntryList = ObjectTypeListPtr;
                            TypeListIndex = 0;
                            *((ULONG *)((char *)&IsProtected + 4)) = 0;
                            CurrentTypeEntry = *ObjectTypeListPtr;
                            while (1)
                            {
                                SavedTypeEntry = CurrentTypeEntry;
                                if (CurrentTypeEntry <= (_QWORD *)MmSystemRangeStart
                                    || CurrentTypeEntry == ObjectTypeListPtr
                                    || SavedRemainingSize < 0x40
                                    || TypeListIndex > 0x1000)
                                {
                                    break;
                                }
                                TypeEntryCheck = CurrentTypeEntry - 2;
                                if (CheckMemoryValid(CurrentTypeEntry - 2) == 1
                                    && CheckMemoryValid((char *)TypeEntryCheck + 71) == 1)
                                {
                                    TypeEntry = ValidateObjectTypeList(TypeEntryCheck);
                                    TypeInfo = TypeEntry;
                                    TypeInfoSaved = TypeEntry;
                                    if (TypeEntry > (_QWORD *)MmSystemRangeStart
                                        && CheckMemoryValid(TypeEntry) == 1
                                        && CheckMemoryValid((char *)TypeInfo + 87) == 1)
                                    {
                                        TypeNameAddr = TypeInfo[5];
                                        if (TypeNameAddr > (unsigned __int64)MmSystemRangeStart
                                            && CheckMemoryValid((void *)TypeInfo[5]) == 1
                                            && CheckMemoryValid((void *)(TypeNameAddr + 87)) == 1
                                            && (QueryResultSize = 0,
                                                ((unsigned int (__fastcall *)(unsigned __int64, _QWORD, _QWORD, unsigned int *, __int64))QueryObjectNameFunc)(
                                                    TypeNameAddr, 0, 0, &QueryResultSize, IsProtected) == 0xC0000004)
                                            && QueryResultSize
                                            && (NewEntrySize = QueryResultSize + 256,
                                                NameBufferSize = QueryResultSize + 256,
                                                NameBufferAlloc = (unsigned __int16 *)ExAlloc(0, (unsigned int)NameBufferSize),
                                                NameBuffer = NameBufferAlloc,
                                                (NameBufferSaved = NameBufferAlloc) != 0))
                                        {
                                            if (QueryObjectNameFunc(TypeNameAddr, NameBufferAlloc, QueryResultSize, &QueryResultSize) >= 0
                                                && (NamePtrCheck = (unsigned __int16 *)*((_QWORD *)NameBuffer + 1),
                                                    NamePtrCheck == NameBuffer + 8)
                                                && (NameLength = *NameBuffer, NameLength + 16 < NameBufferSize)
                                                && (NamePtrCheck[NameLength >> 1] = 0,
                                                    NameLength2 = *NameBuffer & 0xFFFE,
                                                    *NameBuffer = NameLength2,
                                                    EntrySize = NameLength2 + 64,
                                                    SavedRemainingSize >= EntrySize))
                                            {
                                                OutputEntry = OutputPtr;
                                                OutputPtr[14] = NameLength2 + 2;
                                                memmove(OutputEntry + 15, *((const void **)NameBuffer + 1), *NameBuffer);
                                                OutputEntry2 = OutputPtr;
                                                *((_WORD *)OutputPtr + ((unsigned __int64)*NameBuffer >> 1) + 30) = 0;
                                                *OutputEntry2 = EntrySize;
                                                *((_QWORD *)OutputEntry2 + 1) = ProcessEntrySaved[1];
                                                *((_QWORD *)OutputEntry2 + 2) = *(_QWORD *)((char *)ProcessEntrySaved[1] + (unsigned int)ProcessOffset);
                                                *((_QWORD *)OutputEntry2 + 4) = *(_QWORD *)((char *)ProcessEntrySaved[1] + (unsigned int)ProcessCreateTime);
                                                *((_QWORD *)OutputEntry2 + 5) = *(_QWORD *)((char *)ProcessEntrySaved[1] + (unsigned int)ProcessEprocess);
                                                TypeInfoSaved = TypeInfo;
                                                OutputEntry2[12] = TypeInfoSaved[6] & 0x3FFFFFFF;
                                                *((_BYTE *)OutputEntry2 + 53) = (TypeInfoSaved[6] & 0x40000000) != 0;
                                                *((_QWORD *)OutputEntry2 + 3) = 0;
                                                TypeFlags = (unsigned __int16)*((_DWORD *)TypeEntryCheck + 14);
                                                if (TypeFlags == 1 || TypeFlags == 2)
                                                {
                                                    *((_BYTE *)OutputEntry2 + 52) = 1;
                                                }
                                                else if (TypeFlags == 3)
                                                {
                                                    *((_BYTE *)OutputEntry2 + 52) = 0;
                                                }
                                                ++*pOutputBuffer;
                                                SavedRemainingSize -= EntrySize;
                                                OutputPtr = (_DWORD *)((char *)OutputEntry2 + EntrySize);
                                                ObjectTypeListPtr = pTypeEntryList;
                                            }
                                            ExFree(NameBuffer);
                                        }
                                    }
                                    TypeListIndex = HIDWORD(IsProtected);
                                }
                                CurrentTypeEntry = (_QWORD *)*CurrentTypeEntry;
                                *((ULONG *)((char *)&IsProtected + 4)) = ++TypeListIndex;
                            }
                            MaxTypeIndex = SavedMaxTypeIndex;
                        }
                        ProcessIndex = SavedProcessIndex;
                        SavedProcessIndex = ++ProcessIndex;
                        RemainingSize = SavedRemainingSize;
                        ProcessCount = SavedProcessCount;
                    }
ExitLoop:
                    ExFree(ProcessListBuffer);
                    ProcessListBuffer = 0;
                    SavedBuffer = 0;
                }
            }
            else
            {
                Result = 1;
            }
        }
        if (ProcessListBuffer)
            ExFree(ProcessListBuffer);
    }
    return Result;
}

// 禁用对象保护操作
// 对应原始驱动 DisableObjectProtect (0x140007CC4)
__int64 DisableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;

    Result = 0;
    if (pOutputBuffer && OutputSize >= 0x80
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        *pOutputBuffer = 0;
        DisableObjectProtectEx(pOutputBuffer, OutputSize);
        return *pOutputBuffer != 0;
    }
    return Result;
}

// 启用对象保护操作
// 对应原始驱动 EnableObjectProtect (0x1400082AC)
__int64 EnableObjectProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    void (__fastcall *CallbackFunc)(_QWORD *);
    _QWORD **ListHead;
    int EntryCount;
    _QWORD *CurrentEntry;
    _OWORD InputBuffer;

    Result = 0;
    if (pInputBuffer && InputSize == 16
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 16) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x10, 1);
        InputBuffer = *(_OWORD *)pInputBuffer;
        CallbackFunc = (void (__fastcall *)(_QWORD *))GtRead(GtObjectProtectCallback);
        if (CallbackFunc && *((__int64 *)&InputBuffer + 1))
        {
            if (MmIsAddressValid((PVOID)*((__int64 *)&InputBuffer + 1)) == 1)
            {
                ListHead = (_QWORD **)(*((__int64 *)&InputBuffer + 1) + 16);
                if (MmIsAddressValid((PVOID)(*((__int64 *)&InputBuffer + 1) + 16)) == 1)
                {
                    EntryCount = 0;
                    for (CurrentEntry = *ListHead; CurrentEntry != ListHead; CurrentEntry = (_QWORD *)*CurrentEntry)
                    {
                        if (CurrentEntry <= MmSystemRangeStart)
                            break;
                        if (MmIsAddressValid(CurrentEntry) != 1)
                            break;
                        if ((unsigned int)++EntryCount > 0x1000)
                            break;
                        if (CurrentEntry == (_QWORD *)*((__int64 *)&InputBuffer + 0))
                        {
                            CallbackFunc(CurrentEntry);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 设备IO控制扩展操作
// 对应原始驱动 CmdDeviceIoControlEx (0x140074EF8)
__int64 DeviceIoControlExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 完整实现较复杂，使用桩函数暂时代替
    return 0;
}

// 简单设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlSimple (0x1400751D4)
__int64 DeviceIoControlSimpleOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    size_t *pReturnSize;
    unsigned int SdstCount;
    struct _KTHREAD *CurrentThread;
    char SavedFlag;
    int (*pAltFunc)(_QWORD, _QWORD, _BYTE *, _QWORD, size_t *);
    int (*pFunc)(_QWORD, _QWORD, _BYTE *, _QWORD, size_t *);

    Result = 0;
    if (pInputBuffer && InputSize == 24 && pOutputBuffer && OutputSize
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 24) < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)((char *)pOutputBuffer + OutputSize) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x18u, 1u);
        ProbeForWrite(pOutputBuffer, OutputSize, 1u);

        pReturnSize = (size_t *)((size_t *)pInputBuffer)[2];
        if (pReturnSize
            && (unsigned __int64)pReturnSize < MmUserProbeAddress
            && (unsigned __int64)pReturnSize + 4 < MmUserProbeAddress)
        {
            ProbeForWrite(pReturnSize, 4u, 4u);
            Result = SendIoControlWithQueryBuffer(
                *(size_t *)pInputBuffer,
                *((unsigned int *)pInputBuffer + 2),
                (_BYTE *)pOutputBuffer,
                OutputSize,
                pReturnSize);

            if (!Result)
            {
                pFunc = (int (*)(_QWORD, _QWORD, _BYTE *, _QWORD, size_t *))GtRead(GtEprocessField104 | 0x100);
                SdstCount = (unsigned int)GtRead(GtSdstServiceCount);

                if (!pFunc || SdstCount == -1)
                {
                    pAltFunc = (int (*)(_QWORD, _QWORD, _BYTE *, _QWORD, size_t *))GtRead(GtTotalSize | GtObjectTypeField02 | GtPathBuffer01);
                    if (pAltFunc)
                        return pAltFunc(
                            *(size_t *)pInputBuffer,
                            *((unsigned int *)pInputBuffer + 2),
                            (_BYTE *)pOutputBuffer,
                            OutputSize,
                            pReturnSize) >= 0;
                }
                else
                {
                    CurrentThread = KeGetCurrentThread();
                    SavedFlag = *((_BYTE *)CurrentThread + SdstCount);
                    *((_BYTE *)CurrentThread + SdstCount) = 0;
                    Result = pFunc(
                        *(size_t *)pInputBuffer,
                        *((unsigned int *)pInputBuffer + 2),
                        (_BYTE *)pOutputBuffer,
                        OutputSize,
                        pReturnSize) >= 0;
                    *((_BYTE *)CurrentThread + SdstCount) = SavedFlag;
                }
            }
        }
    }
    return Result;
}

// 带缓冲设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlWithBuffer (0x1400753A4)
// 输入缓冲区32字节: Command(4) + 填充(4) + Param2(4) + StringByteLength(4) + StringPtr(8) + ReturnSizePtr(8)
// 验证用户模式缓冲区，初始化UNICODE_STRING后发送IOCTL，
// 失败时尝试通过SSDT服务计数绕过或备用函数指针进行重试
__int64 DeviceIoControlWithBufferOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    void (*pRtlInitUnicodeString)(int *, volatile void *);
    SIZE_T StringByteLength;
    volatile void *StringBuffer;
    volatile void *pReturnSize;
    unsigned __int64 Index;
    wchar_t *pString;
    int UnicodeString[4];  // UNICODE_STRING (16 bytes)
    char FlagByte;
    SIZE_T OutSize;
    int (*pAltFunc)(_QWORD, int *, _QWORD, volatile void *, _DWORD, volatile void *);
    int (*pFunc)(_QWORD, int *, _QWORD, volatile void *, _DWORD, volatile void *);
    struct _KTHREAD *CurrentThread;
    char SavedFlag;
    unsigned int SdstCount;
    __int64 FuncPtr;

    Result = 0;
    pRtlInitUnicodeString = (void (*)(int *, volatile void *))GtRead(GtRtlInitUnicodeStringFunc);
    if (!pRtlInitUnicodeString)
        return Result;

    if (!pInputBuffer || InputSize != 32 || !pOutputBuffer || !OutputSize)
        return Result;

    if ((unsigned __int64)pInputBuffer >= MmUserProbeAddress
        || (unsigned __int64)(pInputBuffer + 32) >= MmUserProbeAddress
        || (unsigned __int64)pOutputBuffer >= MmUserProbeAddress
        || (unsigned __int64)((char *)pOutputBuffer + OutputSize) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(pInputBuffer, 0x20u, 1u);
    ProbeForWrite(pOutputBuffer, OutputSize, 1u);

    StringByteLength = *((unsigned int *)pInputBuffer + 3);
    if (StringByteLength < 2)
        return Result;

    StringBuffer = ((volatile void **)pInputBuffer)[2];
    if (!StringBuffer)
        return Result;

    if ((unsigned __int64)StringBuffer >= MmUserProbeAddress
        || (unsigned __int64)((char *)StringBuffer + StringByteLength) >= MmUserProbeAddress)
        return Result;

    pReturnSize = ((volatile void **)pInputBuffer)[3];
    if (!pReturnSize)
        return Result;

    if ((unsigned __int64)pReturnSize >= MmUserProbeAddress
        || (unsigned __int64)((char *)pReturnSize + 4) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(StringBuffer, StringByteLength, 1u);
    ProbeForWrite(pReturnSize, 4u, 4u);

    // 将Unicode字符串末尾置零（确保以null结尾）
    Index = (unsigned int)(*((_DWORD *)pInputBuffer + 3) - 2) >> 1;
    pString = ((wchar_t **)pInputBuffer)[2];
    if (pString[Index])
        pString[Index] = 0;

    pRtlInitUnicodeString(UnicodeString, ((volatile void **)pInputBuffer)[2]);
    OutSize = OutputSize;

    Result = SendIoControlWithVersionBranch(
        &FlagByte,
        *(int *)pInputBuffer,
        UnicodeString,
        *((_DWORD *)pInputBuffer + 2),
        pOutputBuffer,
        OutSize,
        (__int64)((volatile void **)pInputBuffer)[3]);

    if (!Result && FlagByte == 1)
    {
        FuncPtr = GtRead(GtEprocessField105 | 0x100);
        pFunc = (int (*)(_QWORD, int *, _QWORD, volatile void *, _DWORD, volatile void *))FuncPtr;
        SdstCount = (unsigned int)GtRead(GtSdstServiceCount);

        if (!FuncPtr || SdstCount == -1)
        {
            pAltFunc = (int (*)(_QWORD, int *, _QWORD, volatile void *, _DWORD, volatile void *))GtRead(GtTotalSize | GtObjectTypeField05);
            if (pAltFunc)
                return pAltFunc(
                    *(int *)pInputBuffer,
                    UnicodeString,
                    *((unsigned int *)pInputBuffer + 2),
                    pOutputBuffer,
                    OutputSize,
                    ((volatile void **)pInputBuffer)[3]) >= 0;
        }
        else
        {
            CurrentThread = KeGetCurrentThread();
            SavedFlag = *((_BYTE *)CurrentThread + SdstCount);
            *((_BYTE *)CurrentThread + SdstCount) = 0;
            Result = pFunc(
                *(int *)pInputBuffer,
                UnicodeString,
                *((unsigned int *)pInputBuffer + 2),
                pOutputBuffer,
                OutputSize,
                ((volatile void **)pInputBuffer)[3]) >= 0;
            *((_BYTE *)CurrentThread + SdstCount) = SavedFlag;
        }
    }

    return Result;
}

// 发送带版本分支的IO控制命令，根据构建号选择不同的IO控制路径
// 对应原始驱动 SendIoControlWithVersionBranch (0x1400738A8)
// 构建号 > 0x23F0 (Win10 20H1+) 时设置标志位使用备用路径，否则调用完整IO控制函数
char SendIoControlWithVersionBranch(
    char *OutputBuffer,
    int Command,
    int *UnicodeString,
    int Param2,
    void *OutputBuf,
    SIZE_T OutputSize,
    __int64 Context)
{
    char Result;

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        *OutputBuffer = 1;
    }
    else
    {
        // 低版本Windows走完整IO控制路径
        // SendDeviceIoControl 后续实现
        *OutputBuffer = 1;
    }
    return Result;
}

// 带字符串设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlWithString (0x14007562C)
// 验证输入缓冲区(40字节含Unicode字符串)，初始化UNICODE_STRING后发送IOCTL，
// 失败时尝试通过SSDT服务计数绕过或备用函数指针进行重试
__int64 DeviceIoControlWithStringOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    void (__fastcall *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
    unsigned int StringLength;
    void *StringBuffer;
    void *OutputBufferPtr;
    unsigned int OutputBufferSize;
    unsigned __int64 LastCharIndex;
    unsigned int SdstCount;
    struct _KTHREAD *CurrentThread;
    char SavedFlag;
    int (*pAltFunc)(_QWORD, PUNICODE_STRING, _QWORD, _QWORD, void *, _DWORD);
    int (*pFunc)(_QWORD, PUNICODE_STRING, _QWORD, _QWORD, void *, _DWORD);
    UNICODE_STRING UnicodeString;

    Result = 0;
    pRtlInitUnicodeString = (void (__fastcall *)(PUNICODE_STRING, PCWSTR))GtRead(GtRtlInitUnicodeStringFunc);

    if (pRtlInitUnicodeString && pInputBuffer && InputSize == 40
        && (ULONG64)pInputBuffer < MmUserProbeAddress
        && (ULONG64)(pInputBuffer + 40) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x28u, 1u);

        StringLength = *(unsigned int *)(pInputBuffer + 28);
        if (StringLength >= 2)
        {
            StringBuffer = *(void **)(pInputBuffer + 32);
            if (StringBuffer)
            {
                if ((ULONG64)StringBuffer < MmUserProbeAddress
                    && (ULONG64)StringBuffer + StringLength < MmUserProbeAddress)
                {
                    OutputBufferPtr = *(void **)(pInputBuffer + 16);
                    if (OutputBufferPtr)
                    {
                        OutputBufferSize = *(unsigned int *)(pInputBuffer + 24);
                        if ((ULONG64)OutputBufferPtr < MmUserProbeAddress
                            && (ULONG64)OutputBufferPtr + OutputBufferSize < MmUserProbeAddress)
                        {
                            ProbeForRead(StringBuffer, StringLength, 1u);

                            if (OutputBufferSize)
                                ProbeForRead(OutputBufferPtr, OutputBufferSize, 1u);

                            // 确保字符串以 null 结尾（将最后一个 WCHAR 置零）
                            LastCharIndex = (unsigned __int64)(StringLength - 2) >> 1;
                            *((_WORD *)StringBuffer + LastCharIndex) = 0;

                            // 初始化 UNICODE_STRING
                            pRtlInitUnicodeString(&UnicodeString, (PCWSTR)StringBuffer);

                            // 发送 IO 控制请求（带字符串参数）
                            Result = SendIoControlWithStringParam(
                                *(__int64 *)pInputBuffer,
                                &UnicodeString,
                                *(unsigned int *)(pInputBuffer + 8),
                                *(unsigned int *)(pInputBuffer + 12),
                                (__int64)OutputBufferPtr,
                                OutputBufferSize);

                            if (!Result)
                            {
                                pFunc = (int (*)(_QWORD, PUNICODE_STRING, _QWORD, _QWORD, void *, _DWORD))GtRead(GtEprocessField106 | 0x100);
                                SdstCount = (unsigned int)GtRead(GtSdstServiceCount);

                                if (!pFunc || SdstCount == -1)
                                {
                                    pAltFunc = (int (*)(_QWORD, PUNICODE_STRING, _QWORD, _QWORD, void *, _DWORD))GtRead(GtTotalSize | GtObjectTypeField06 | GtDriverObject);
                                    if (pAltFunc)
                                        return pAltFunc(
                                            *(__int64 *)pInputBuffer,
                                            &UnicodeString,
                                            *(unsigned int *)(pInputBuffer + 8),
                                            *(unsigned int *)(pInputBuffer + 12),
                                            OutputBufferPtr,
                                            OutputBufferSize) >= 0;
                                }
                                else
                                {
                                    CurrentThread = KeGetCurrentThread();
                                    SavedFlag = *((_BYTE *)CurrentThread + SdstCount);
                                    *((_BYTE *)CurrentThread + SdstCount) = 0;
                                    Result = pFunc(
                                        *(__int64 *)pInputBuffer,
                                        &UnicodeString,
                                        *(unsigned int *)(pInputBuffer + 8),
                                        *(unsigned int *)(pInputBuffer + 12),
                                        OutputBufferPtr,
                                        OutputBufferSize) >= 0;
                                    *((_BYTE *)CurrentThread + SdstCount) = SavedFlag;
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

// 打开节对象操作
// 对应原始驱动 CmdOpenSectionObject (0x140074128)
__int64 OpenSectionObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 TargetAddress;
    unsigned int SdstCount;
    struct _KTHREAD *CurrentThread;
    char PrevMode;
    int (__fastcall *pAltFunc)(__int64);
    __int64 SavedAddress;
    int (__fastcall *pVerifyFunc)(__int64);
    unsigned int SavedSdstCount;

    Result = 0;
    if (pInputBuffer && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 8);
        TargetAddress = *(__int64 *)pInputBuffer;
        SavedAddress = *(__int64 *)pInputBuffer;
        Result = OpenSectionWithIoControl(*(__int64 *)pInputBuffer);
        if (!Result)
        {
            pVerifyFunc = (int (__fastcall *)(__int64))GtRead(GtEprocessField107 | 0x100);
            SdstCount = GtRead(GtSdstServiceCount);
            SavedSdstCount = SdstCount;
            if (!pVerifyFunc || SdstCount == -1)
            {
                pAltFunc = (int (__fastcall *)(__int64))GtRead(GtTotalSize | GtObjectTypeField07 | GtNtoskrnlImageSize);
                if (pAltFunc)
                    return pAltFunc(TargetAddress) >= 0;
            }
            else
            {
                CurrentThread = KeGetCurrentThread();
                PrevMode = *((char *)CurrentThread + SdstCount);
                *((char *)CurrentThread + SdstCount) = 0;
                Result = pVerifyFunc(SavedAddress) >= 0;
                *((char *)CurrentThread + SavedSdstCount) = PrevMode;
            }
        }
    }
    return Result;
}

// 发送写入进程内存IO控制命令（桩函数，暂未实现完整逻辑）
// 对应原始驱动 SendWriteMemoryIoControl (0x140072EC8)
__int64 SendWriteMemoryIoControl(unsigned char *pResult, __int64 ProcessId, int PageIndex, int AddressField, unsigned int *pOutputBuffer, unsigned int OutputSize, __int64 ResultBuffer, unsigned char Flag)
{
    *pResult = 1;
    return 0;
}

// 写入进程内存扩展操作
// 对应原始驱动 CmdWriteProcessMemoryEx (0x1400749A0)
// 扩展版写入进程内存命令，支持分页写入进程内存，处理写入完成后的数据校验
__int64 WriteProcessMemoryExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    int AddressField;
    int PageIndex;
    unsigned char FlagByte;
    volatile void *pResultBuffer;
    __int64 ProcessId;
    __int64 ResultBuffer;
    unsigned char StatusByte;
    __int64 FuncPtr;
    unsigned int SdstCount;
    struct _KTHREAD *CurrentThread;
    unsigned char SavedFlag;
    int (*WriteFunc)(__int64, int, int, unsigned int *, unsigned int, __int64);
    int (*FallbackFunc)(__int64, int, int, unsigned int *, unsigned int, __int64);
    unsigned int RemainingSize;
    unsigned int *CurrentOutput;
    unsigned int *InitialOutput;
    unsigned int AccumulatedOffset;
    int PageCounter;
    int RetValue;
    int EntryNextSize;
    unsigned int EntrySize;

    Result = 0;
    if (pInputBuffer && InputSize == 40 && pOutputBuffer && OutputSize > 4
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 40) < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)((char *)pOutputBuffer + OutputSize) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x28u, 1u);
        ProbeForWrite(pOutputBuffer, OutputSize, 1u);

        AddressField = *((unsigned int *)pInputBuffer + 7);
        PageIndex = *((unsigned int *)pInputBuffer + 6);
        FlagByte = pInputBuffer[1];
        pResultBuffer = (volatile void *)((unsigned __int64 *)pInputBuffer)[4];

        if (pResultBuffer
            && (unsigned __int64)pResultBuffer < MmUserProbeAddress
            && (unsigned __int64)pResultBuffer + 4 < MmUserProbeAddress)
        {
            ProbeForWrite((void *)pResultBuffer, 4u, 4u);

            ProcessId = ((unsigned __int64 *)pInputBuffer)[2];
            ResultBuffer = (__int64)pResultBuffer;

            Result = (char)SendWriteMemoryIoControl(
                &StatusByte,
                ProcessId,
                PageIndex,
                AddressField,
                pOutputBuffer,
                OutputSize,
                ResultBuffer,
                FlagByte);

            if (!Result && StatusByte == 1)
            {
                PageCounter = 0;
                AccumulatedOffset = 0;
                CurrentOutput = pOutputBuffer;
                InitialOutput = pOutputBuffer;
                RemainingSize = OutputSize;

                FuncPtr = GtRead(0x171);
                SdstCount = (unsigned int)GtRead(GtSdstServiceCount);

                if (!FuncPtr || SdstCount == -1)
                {
                    // 备用路径：使用备用函数指针
                    FallbackFunc = (int (*)(__int64, int, int, unsigned int *, unsigned int, __int64))GtRead(GtNtOpenKeyPeSectionOffset | GtEprocessField54);
                    if (FallbackFunc)
                    {
                        RetValue = FallbackFunc(ProcessId, PageIndex, AddressField, pOutputBuffer, OutputSize, ResultBuffer);
                        while (1)
                        {
                            if (AddressField != 1)
                                break;
                            if (FlagByte == 1)
                            {
                                if (RetValue)
                                    break;
                                *CurrentOutput = 0;
                                break;
                            }
                            if (RetValue)
                            {
                                *CurrentOutput = 0;
                                if (PageCounter)
                                    RetValue = 0;
                                break;
                            }
                            *CurrentOutput = AccumulatedOffset;
                            EntryNextSize = pOutputBuffer[2];
                            if (EntryNextSize == -1)
                                AccumulatedOffset = pOutputBuffer[4] + 20;
                            else
                                AccumulatedOffset = EntryNextSize + pOutputBuffer[3];
                            EntrySize = AccumulatedOffset;
                            if (RemainingSize <= EntrySize + 4)
                            {
                                *CurrentOutput = 0;
                                break;
                            }
                            RemainingSize -= EntrySize;
                            CurrentOutput = pOutputBuffer;
                            pOutputBuffer = (unsigned int *)((char *)pOutputBuffer + EntrySize);
                            ++PageIndex;
                            ++PageCounter;
                            RetValue = FallbackFunc(ProcessId, PageIndex, 1, pOutputBuffer, RemainingSize, ResultBuffer);
                        }
                        if (!RetValue)
                            return 1;
                    }
                }
                else
                {
                    // 主路径：保存/恢复 PreviousMode，使用主函数指针
                    WriteFunc = (int (*)(__int64, int, int, unsigned int *, unsigned int, __int64))FuncPtr;
                    CurrentThread = KeGetCurrentThread();
                    SavedFlag = *((unsigned char *)CurrentThread + SdstCount);
                    *((unsigned char *)CurrentThread + SdstCount) = 0;

                    PageIndex = *((unsigned int *)pInputBuffer + 6);
                    PageCounter = 0;
                    AccumulatedOffset = 0;
                    InitialOutput = pOutputBuffer;
                    CurrentOutput = pOutputBuffer;
                    RemainingSize = OutputSize;

                    while (1)
                    {
                        RetValue = WriteFunc(ProcessId, PageIndex, AddressField, CurrentOutput, RemainingSize, ResultBuffer);
                        if (AddressField != 1)
                            break;
                        if (FlagByte == 1)
                        {
                            if (RetValue)
                                break;
                            *InitialOutput = 0;
                            break;
                        }
                        if (RetValue)
                        {
                            *InitialOutput = 0;
                            if (PageCounter)
                                RetValue = 0;
                            break;
                        }
                        *InitialOutput = AccumulatedOffset;
                        EntryNextSize = CurrentOutput[2];
                        if (EntryNextSize == -1)
                            AccumulatedOffset = CurrentOutput[4] + 20;
                        else
                            AccumulatedOffset = EntryNextSize + CurrentOutput[3];
                        EntrySize = AccumulatedOffset;
                        if (RemainingSize <= EntrySize + 4)
                        {
                            *InitialOutput = 0;
                            break;
                        }
                        RemainingSize -= EntrySize;
                        InitialOutput = CurrentOutput;
                        CurrentOutput = (unsigned int *)((char *)CurrentOutput + EntrySize);
                        ++PageIndex;
                        ++PageCounter;
                    }
                    Result = (RetValue == 0);
                    *((unsigned char *)CurrentThread + SdstCount) = SavedFlag;
                }
            }
        }
    }
    return Result;
}

// 枚举进程列表扩展操作
// 对应原始驱动 CmdEnumProcessListEx (0x140062ED8)
__int64 EnumProcessListExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T RemainingSize;
    char Result;
    unsigned __int64 *ProcessListHead;
    unsigned int BuildNumber;
    char *OutputPtr;
    unsigned __int64 *EprocessEntry;
    unsigned int ProcessIndex;
    unsigned __int64 *ThreadEntry;
    unsigned int ThreadIndex;
    unsigned int i;

    RemainingSize = OutputSize;
    Result = 0;
    ProcessListHead = (unsigned __int64 *)GtRead(GtEprocessExtField16);
    if (!ProcessListHead)
    {
        InitKernelDataSectionTable();
        ProcessListHead = (unsigned __int64 *)GtRead(GtEprocessExtField16);
    }
    BuildNumber = (unsigned int)GtRead(GtEprocessExtField13);
    if (ProcessListHead)
    {
        if (ProcessListHead > (unsigned __int64 *)MmSystemRangeStart)
        {
            if (BuildNumber)
            {
                if (pOutputBuffer)
                {
                    if ((unsigned int)RemainingSize >= 0x1E0
                        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                        && (unsigned __int64)&pOutputBuffer[(unsigned int)RemainingSize] < MmUserProbeAddress)
                    {
                        ProbeForWrite(pOutputBuffer, RemainingSize, 4);
                        RtlFillMemory(pOutputBuffer, RemainingSize, 0);
                        OutputPtr = (char *)pOutputBuffer;
                        if (BuildNumber >= 0x60000)
                        {
                            EprocessEntry = ProcessListHead;
                            ProcessIndex = 0;
                            while (ProcessIndex < 0x1000
                                && EprocessEntry > (unsigned __int64 *)MmSystemRangeStart
                                && CheckMemoryValid(EprocessEntry) == 1
                                && (unsigned int)RemainingSize >= 0x1E0)
                            {
                                *(_QWORD *)OutputPtr = EprocessEntry;
                                *(_DWORD *)(OutputPtr + 8) = 0;

                                // EPROCESS field mapping based on build
                                if (BuildNumber == 393216)
                                {
                                    for (i = 0; i < 1; i++)
                                        *(_QWORD *)(OutputPtr + 16 + i * 8) = EprocessEntry[2 + i];
                                }
                                else if (BuildNumber <= 0x60014)
                                {
                                    for (i = 0; i < 34; i++)
                                        *(_QWORD *)(OutputPtr + 16 + i * 8) = EprocessEntry[2 + i];
                                }
                                else if (BuildNumber > 0x60051)
                                {
                                    if (BuildNumber > 0x60054)
                                    {
                                        if (BuildNumber > 0x60056)
                                        {
                                            // minimal mapping
                                        }
                                        else
                                        {
                                            for (i = 0; i < 17; i++)
                                                *(_QWORD *)(OutputPtr + 16 + i * 8) = EprocessEntry[3 + i];
                                        }
                                    }
                                    else
                                    {
                                        for (i = 0; i < 21; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = EprocessEntry[3 + i];
                                    }
                                }
                                else
                                {
                                    for (i = 0; i < 38; i++)
                                        *(_QWORD *)(OutputPtr + 16 + i * 8) = EprocessEntry[3 + i];
                                }

                                if (Result)
                                    *(_QWORD *)(OutputPtr + 408) = EprocessEntry;

                                // Thread sub-entries
                                ThreadEntry = (unsigned __int64 *)EprocessEntry[3];
                                ThreadIndex = 0;
                                while (ThreadIndex < 0x1000
                                    && ThreadEntry > (unsigned __int64 *)MmSystemRangeStart
                                    && CheckMemoryValid(ThreadEntry) == 1
                                    && (unsigned int)RemainingSize >= 0x1E0)
                                {
                                    *(_QWORD *)OutputPtr = ThreadEntry;

                                    // Thread field mapping based on build
                                    if (BuildNumber < 0x60014)
                                    {
                                        for (i = 0; i < 68; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[165 + i];
                                    }
                                    else if (BuildNumber < 0x6001E)
                                    {
                                        for (i = 0; i < 71; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[35 + i];
                                    }
                                    else if (BuildNumber <= 0x6003C)
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else if (BuildNumber <= 0x60051)
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[55 + i];
                                    }
                                    else if (BuildNumber <= 0x60052)
                                    {
                                        for (i = 0; i < 28; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[55 + i];
                                    }
                                    else if (BuildNumber <= 0x60054)
                                    {
                                        for (i = 0; i < 27; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else if (BuildNumber <= 0x60057)
                                    {
                                        for (i = 0; i < 26; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = ThreadEntry[54 + i];
                                    }

                                    // Increment thread count
                                    ++*(_DWORD *)(OutputPtr + 8);
                                    RemainingSize -= 0x1E0;
                                    OutputPtr += 0x1E0;
                                    ThreadEntry = (unsigned __int64 *)ThreadEntry[1];
                                    ThreadIndex++;
                                }

                                Result = 1;
                                RemainingSize -= 0x1E0;
                                OutputPtr += 0x1E0;
                                EprocessEntry = (unsigned __int64 *)EprocessEntry[1];
                                ProcessIndex++;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 枚举进程列表(Win7)操作
// 对应原始驱动 CmdEnumProcessListWin7 (0x14005A5E8)
__int64 EnumProcessListWin7Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    char Result;
    _QWORD **ProcessListHead;
    unsigned int BuildNumber;
    char *OutputPtr;
    unsigned int RemainingSize;
    char *PrevOutputPtr;
    _QWORD *Eprocess;
    unsigned int ProcessIndex;
    int ProcessCount;
    _QWORD *ThreadEntry;
    unsigned int ThreadIndex;
    unsigned int i;

    BufferSize = OutputSize;
    Result = 0;
    ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField19);
    if (!ProcessListHead)
    {
        InitKernelDataSectionTable();
        ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField19);
    }
    BuildNumber = (unsigned int)GtRead(GtEprocessExtField13);
    if (ProcessListHead)
    {
        if (ProcessListHead > (_QWORD **)MmSystemRangeStart)
        {
            if (BuildNumber)
            {
                if (pOutputBuffer)
                {
                    if ((unsigned int)BufferSize >= 0x368
                        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                        && (unsigned __int64)&pOutputBuffer[(unsigned int)BufferSize] < MmUserProbeAddress)
                    {
                        ProbeForWrite(pOutputBuffer, BufferSize, 4);
                        RtlFillMemory(pOutputBuffer, BufferSize, 0);
                        OutputPtr = (char *)pOutputBuffer;
                        RemainingSize = (unsigned int)BufferSize;
                        if (BuildNumber >= 0x60000)
                        {
                            PrevOutputPtr = 0;
                            Eprocess = *ProcessListHead;
                            ProcessIndex = 0;
                            ProcessCount = 0;
                            while (ProcessIndex < 0x1000
                                && Eprocess > (_QWORD *)MmSystemRangeStart
                                && CheckMemoryValid(Eprocess) == 1
                                && RemainingSize >= 0x1E0)
                            {
                                if (PrevOutputPtr)
                                    *PrevOutputPtr = 1;
                                *(_QWORD *)OutputPtr = Eprocess;
                                *(_DWORD *)(OutputPtr + 416) = 0;

                                // EPROCESS field mapping based on build
                                if (BuildNumber == 393216)
                                {
                                    for (i = 0; i < 39; i++)
                                        *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[19 + i];
                                }
                                else if (BuildNumber <= 0x60014)
                                {
                                    for (i = 0; i < 42; i++)
                                        *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[19 + i];
                                }
                                else if (BuildNumber > 0x60051)
                                {
                                    if (BuildNumber > 0x60054)
                                    {
                                        if (BuildNumber > 0x60056)
                                        {
                                            // minimal mapping
                                        }
                                        else
                                        {
                                            for (i = 0; i < 17; i++)
                                                *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[20 + i];
                                        }
                                    }
                                    else
                                    {
                                        for (i = 0; i < 21; i++)
                                            *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[20 + i];
                                    }
                                }
                                else
                                {
                                    for (i = 0; i < 38; i++)
                                        *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[20 + i];
                                }

                                RemainingSize -= 424;
                                if (Result)
                                    *(_QWORD *)(OutputPtr + 408) = Eprocess;

                                // Thread sub-entries
                                ThreadEntry = (_QWORD *)Eprocess[3];
                                ThreadIndex = 0;
                                while (ThreadIndex < 0x1000
                                    && ThreadEntry > (_QWORD *)MmSystemRangeStart
                                    && CheckMemoryValid(ThreadEntry) == 1
                                    && RemainingSize >= 0x1C0)
                                {
                                    *(_QWORD *)(OutputPtr + 424) = ThreadEntry;

                                    // Thread field mapping based on build
                                    if (BuildNumber < 0x60014)
                                    {
                                        for (i = 0; i < 68; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[165 + i];
                                    }
                                    else if (BuildNumber < 0x6001E)
                                    {
                                        for (i = 0; i < 71; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[35 + i];
                                    }
                                    else if (BuildNumber <= 0x6003C)
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else if (BuildNumber <= 0x60051)
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[55 + i];
                                    }
                                    else if (BuildNumber <= 0x60052)
                                    {
                                        for (i = 0; i < 28; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[55 + i];
                                    }
                                    else if (BuildNumber <= 0x60054)
                                    {
                                        for (i = 0; i < 27; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else if (BuildNumber <= 0x60057)
                                    {
                                        for (i = 0; i < 26; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[54 + i];
                                    }
                                    else
                                    {
                                        for (i = 0; i < 45; i++)
                                            *(_QWORD *)(OutputPtr + 440 + i * 8) = ThreadEntry[54 + i];
                                    }

                                    // Increment thread count
                                    ++*(_DWORD *)(OutputPtr + 416);
                                    RemainingSize -= 448;
                                    OutputPtr += 448;
                                    ThreadEntry = (_QWORD *)ThreadEntry[1];
                                    ThreadIndex++;
                                }

                                Result = 1;
                                PrevOutputPtr = OutputPtr;
                                OutputPtr += 424;
                                ProcessCount++;
                                Eprocess = (_QWORD *)Eprocess[1];
                                ProcessIndex++;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 枚举进程列表(Win8)操作
// 对应原始驱动 CmdEnumProcessListWin8 (0x14005C6B0)
__int64 EnumProcessListWin8Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    char Result;
    _QWORD **ProcessListHead;
    unsigned int BuildNumber;
    char *OutputPtr;
    unsigned int RemainingSize;
    char *PrevOutputPtr;
    _QWORD *Eprocess;
    unsigned int ProcessIndex;
    int ProcessCount;
    unsigned int i;

    BufferSize = OutputSize;
    Result = 0;
    ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField27);
    if (!ProcessListHead)
    {
        InitKernelDataSectionTable();
        ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField27);
    }
    BuildNumber = (unsigned int)GtRead(GtEprocessExtField13);
    if (ProcessListHead)
    {
        if (ProcessListHead > (_QWORD **)MmSystemRangeStart)
        {
            if (BuildNumber)
            {
                if (pOutputBuffer)
                {
                    if ((unsigned int)BufferSize >= 0x428
                        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                        && (unsigned __int64)&pOutputBuffer[(unsigned int)BufferSize] < MmUserProbeAddress)
                    {
                        ProbeForWrite(pOutputBuffer, BufferSize, 4);
                        RtlFillMemory(pOutputBuffer, BufferSize, 0);
                        OutputPtr = (char *)pOutputBuffer;
                        RemainingSize = (unsigned int)BufferSize;
                        if (BuildNumber >= 0x60000)
                        {
                            PrevOutputPtr = 0;
                            Eprocess = *ProcessListHead;
                            ProcessIndex = 0;
                            ProcessCount = 0;
                            while (ProcessIndex < 0x1000
                                && Eprocess > (_QWORD *)MmSystemRangeStart
                                && CheckMemoryValid(Eprocess) == 1
                                && RemainingSize >= 0x428)
                            {
                                if (PrevOutputPtr)
                                    *PrevOutputPtr = 1;
                                *(_QWORD *)OutputPtr = Eprocess;
                                *(_DWORD *)(OutputPtr + 8) = 0;

                                // EPROCESS field mapping based on build (Win8)
                                if (BuildNumber > 0x60014)
                                {
                                    if (BuildNumber >= 0x60032)
                                    {
                                        if (BuildNumber > 0x60054)
                                        {
                                            for (i = 0; i < 46; i++)
                                                *(_QWORD *)(OutputPtr + 16 + i * 8) = Eprocess[12 + i];
                                        }
                                        else
                                        {
                                            for (i = 0; i < 44; i++)
                                                *(_QWORD *)(OutputPtr + 16 + i * 8) = Eprocess[12 + i];
                                        }
                                    }
                                    else
                                    {
                                        for (i = 0; i < 48; i++)
                                            *(_QWORD *)(OutputPtr + 16 + i * 8) = Eprocess[12 + i];
                                    }
                                }
                                else
                                {
                                    for (i = 0; i < 50; i++)
                                        *(_QWORD *)(OutputPtr + 16 + i * 8) = Eprocess[12 + i];
                                }

                                // WoW64 check: compare bytes at [24] and [116] vs [25] and [117]
                                if (*(char *)(OutputPtr + 24) == *(char *)(OutputPtr + 116)
                                    && *(char *)(OutputPtr + 25) == *(char *)(OutputPtr + 117))
                                {
                                    *(_DWORD *)(OutputPtr + 8) = 1;
                                }

                                if (Result)
                                    *(_QWORD *)(OutputPtr + 416) = Eprocess;

                                Result = 1;
                                PrevOutputPtr = OutputPtr;
                                RemainingSize -= 1064;
                                OutputPtr += 1064;
                                ProcessCount++;
                                Eprocess = (_QWORD *)Eprocess[1];
                                ProcessIndex++;
                            }
                        }
                        else
                        {
                            // Win8 pre-0x60000: uses *SavedValue as next pointer (not SavedValue[1])
                            PrevOutputPtr = 0;
                            Eprocess = *ProcessListHead;
                            ProcessIndex = 0;
                            ProcessCount = 0;
                            while (ProcessIndex < 0x1000
                                && Eprocess > (_QWORD *)MmSystemRangeStart
                                && CheckMemoryValid(Eprocess) == 1
                                && RemainingSize >= 0x428)
                            {
                                if (PrevOutputPtr)
                                    *PrevOutputPtr = 1;
                                *(_QWORD *)OutputPtr = Eprocess;
                                *(_DWORD *)(OutputPtr + 8) = 0;

                                for (i = 0; i < 50; i++)
                                    *(_QWORD *)(OutputPtr + 16 + i * 8) = Eprocess[12 + i];

                                // WoW64 check
                                if (*(char *)(OutputPtr + 24) == *(char *)(OutputPtr + 116)
                                    && *(char *)(OutputPtr + 25) == *(char *)(OutputPtr + 117))
                                {
                                    *(_DWORD *)(OutputPtr + 8) = 1;
                                }

                                if (Result)
                                    *(_QWORD *)(OutputPtr + 416) = Eprocess;

                                Result = 1;
                                PrevOutputPtr = OutputPtr;
                                RemainingSize -= 1064;
                                OutputPtr += 1064;
                                ProcessCount++;
                                Eprocess = (_QWORD *)*Eprocess;
                                ProcessIndex++;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 枚举进程列表(Win10)操作
// 对应原始驱动 CmdEnumProcessListWin10 (0x14005E354)
__int64 EnumProcessListWin10Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T RemainingSize;
    char Result;
    _QWORD **ProcessListHead;
    unsigned int BuildNumber;
    char *OutputPtr;
    char *PrevOutputPtr;
    _QWORD *Eprocess;
    unsigned int ProcessIndex;
    int ProcessCount;
    unsigned int LinkField;
    unsigned int StartField;
    unsigned int FieldCount;
    unsigned int i;

    RemainingSize = OutputSize;
    Result = 0;
    ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField22);
    if (!ProcessListHead)
    {
        InitKernelDataSectionTable();
        ProcessListHead = (_QWORD **)GtRead(GtEprocessExtField22);
    }
    BuildNumber = (unsigned int)GtRead(GtEprocessExtField13);
    if (ProcessListHead)
    {
        if (ProcessListHead > (_QWORD **)MmSystemRangeStart)
        {
            if (BuildNumber)
            {
                if (pOutputBuffer)
                {
                    if ((unsigned int)RemainingSize >= 0x298
                        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
                        && (unsigned __int64)&pOutputBuffer[(unsigned int)RemainingSize] < MmUserProbeAddress)
                    {
                        ProbeForWrite(pOutputBuffer, RemainingSize, 4);
                        RtlFillMemory(pOutputBuffer, RemainingSize, 0);
                        OutputPtr = (char *)pOutputBuffer;
                        if (BuildNumber >= 0x60000)
                        {
                            // Set version-specific EPROCESS field offsets
                            if (BuildNumber == 393216)
                            {
                                LinkField = 509;
                                StartField = 54;
                                FieldCount = 467;
                            }
                            else if (BuildNumber >= 0x60053)
                            {
                                LinkField = 481;
                                StartField = 54;
                                FieldCount = 456;
                            }
                            else if (BuildNumber >= 0x60052)
                            {
                                LinkField = 485;
                                StartField = 54;
                                FieldCount = 460;
                            }
                            else if (BuildNumber >= 0x60050)
                            {
                                LinkField = 484;
                                StartField = 54;
                                FieldCount = 459;
                            }
                            else if (BuildNumber >= 0x60032)
                            {
                                LinkField = 488;
                                StartField = 54;
                                FieldCount = 463;
                            }
                            else
                            {
                                LinkField = 497;
                                StartField = 54;
                                FieldCount = 472;
                            }

                            PrevOutputPtr = 0;
                            Eprocess = *ProcessListHead;
                            ProcessIndex = 0;
                            ProcessCount = 0;
                            while (ProcessIndex < 0x1000
                                && Eprocess > (_QWORD *)MmSystemRangeStart
                                && CheckMemoryValid(Eprocess) == 1
                                && (unsigned int)RemainingSize >= 0x298)
                            {
                                if (PrevOutputPtr)
                                    PrevOutputPtr[656] = 1;
                                *(_QWORD *)OutputPtr = Eprocess;

                                // Copy EPROCESS fields using version-specific offsets
                                for (i = 0; i < FieldCount; i++)
                                    *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[StartField + i];

                                Result = 1;
                                PrevOutputPtr = OutputPtr;
                                RemainingSize -= 664;
                                OutputPtr += 664;
                                ProcessCount++;
                                Eprocess = (_QWORD *)Eprocess[LinkField];
                                ProcessIndex++;
                            }
                        }
                        else
                        {
                            // Pre-Win10 (Win7/8 compatible)
                            if (BuildNumber == 327681)
                            {
                                LinkField = 94;
                                StartField = 54;
                                FieldCount = 195;
                            }
                            else
                            {
                                LinkField = 95;
                                StartField = 54;
                                FieldCount = 196;
                            }

                            PrevOutputPtr = 0;
                            Eprocess = *ProcessListHead;
                            ProcessIndex = 0;
                            ProcessCount = 0;
                            while (ProcessIndex < 0x1000
                                && Eprocess > (_QWORD *)MmSystemRangeStart
                                && CheckMemoryValid(Eprocess) == 1
                                && (unsigned int)RemainingSize >= 0x298)
                            {
                                if (PrevOutputPtr)
                                    PrevOutputPtr[656] = 1;
                                *(_QWORD *)OutputPtr = Eprocess;

                                for (i = 0; i < FieldCount; i++)
                                    *(_QWORD *)(OutputPtr + 80 + i * 8) = Eprocess[StartField + i];

                                Result = 1;
                                PrevOutputPtr = OutputPtr;
                                RemainingSize -= 664;
                                OutputPtr += 664;
                                ProcessCount++;
                                Eprocess = (_QWORD *)Eprocess[LinkField];
                                ProcessIndex++;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// 枚举对象目录操作
// 对应原始驱动 CmdEnumObjectDirectory (0x140084618)
__int64 EnumObjectDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned int DirResult;
    char Result;
    __int64 Status;
    _DWORD *SystemInfo;

    DirResult = InputSize;
    Result = 0;
    if ((unsigned int)InputSize > 2
        && pInputBuffer
        && OutputSize >= 0x428
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)pInputBuffer + (unsigned int)InputSize < MmUserProbeAddress
        && (InputSize & 1) == 0
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, (unsigned int)InputSize, 1);
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        Status = (DirResult >> 1) - 1;
        if (((unsigned __int16 *)pInputBuffer)[Status])
            ((unsigned __int16 *)pInputBuffer)[Status] = 0;
        *(unsigned int *)pOutputBuffer = 0;
        SystemInfo = AllocExBufferAndQuerySystemInfo(0x10);
        if (SystemInfo)
        {
            *(unsigned int *)pOutputBuffer = EnumObjectDirectoryEntries(
                pInputBuffer, SystemInfo, (__int64)((char *)pOutputBuffer + 8), (OutputSize - 8) / 0x420);
            ExFree(SystemInfo);
            return 1;
        }
    }
    return Result;
}

// 查询对象信息操作
// 对应原始驱动 CmdQueryObjectInfo (0x140083A84)
__int64 QueryObjectInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    bool Result;
    PVOID ObjectHeader;
    void *ObjectBody;
    volatile void *Addressa[2];
    SIZE_T Length;

    Result = 0;
    if (pInputBuffer && InputSize == 24
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 24) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x18, 4);
        *(volatile void **)Addressa = *(volatile void **)pInputBuffer;
        Addressa[1] = *((volatile void **)pInputBuffer + 1);
        Length = *(SIZE_T *)(pInputBuffer + 16);
        if (*(PVOID *)pInputBuffer)
        {
            return QueryObjectTypeInformation(*(PVOID *)pInputBuffer);
        }
        else if ((unsigned int)Length >= 3 && (Length & 1) == 0)
        {
            if (Addressa[1])
            {
                if ((unsigned __int64)Addressa[1] < MmUserProbeAddress
                    && (char *)Addressa[1] + (unsigned int)Length < (volatile void *)MmUserProbeAddress)
                {
                    ProbeForRead(Addressa[1], (unsigned int)Length, 1);
                    ObjectHeader = ExAlloc(PagedPool, (unsigned int)Length + 2);
                    ObjectBody = ObjectHeader;
                    if (ObjectHeader)
                    {
                        memset(ObjectHeader, 0, (unsigned int)Length);
                        memmove(ObjectBody, (const void *)Addressa[1], (unsigned int)Length);
                        Result = (unsigned char)InitObjectTypeTable(ObjectBody) == 1;
                        ExFree(ObjectBody);
                    }
                }
            }
        }
    }
    return Result;
}
