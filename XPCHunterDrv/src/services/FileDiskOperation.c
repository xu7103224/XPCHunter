// FileDiskOperation.c — 文件/磁盘操作（从 Operation.c 拆分）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：文件创建/读写/枚举/重命名/复制/删除，磁盘扇区读写

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
extern char ReadThreadContext(unsigned int ThreadId, unsigned int **pContextArray);
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
__int64 DisableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskSectorReadWriteOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
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
    unsigned int LengthCopy = (unsigned int)FilePathLength;
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
        *pFileHandle = (_QWORD)FileHandle;
        return 1;
    }
    return 0;
}
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
    PreviousMode = (unsigned int)GtRead(GtSdstServiceCount);
    Result = PreviousMode;
    if (pZwClose && PreviousMode != -1 && CheckProcessJobObject(HandleValue))
    {
        CurrentThread = KeGetCurrentThread();
        PrevModeValue = *((_BYTE *)CurrentThread + Result);
        *((_BYTE *)CurrentThread + Result) = 0;
        CloseResult = (int)pZwClose(HandleValueCopy);
        *((_BYTE *)CurrentThread + Result) = PrevModeValue;
        return CloseResult >= 0;
    }
    return 0;
}
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
                    *pBytesWritten = (_DWORD)IoStatusBlock.Information;
                    return 1;
                }
            }
        }
    }
    return 0;
}
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
                    *pBytesRead = (_DWORD)IoStatusBlock.Information;
                    return 1;
                }
            }
        }
    }
    return 0;
}
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
        Timeout, (_DWORD *)&IoStatusBlock, *((_BYTE *)pInputBuffer + 20),
        *((_BYTE *)pInputBuffer + 21)) == 0;
}
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
        OpenResult = (int)IrpReadFileWithOffset(
            Handle[0], 1, *((void **)pInputBuffer + 2), pInputBuffer[3],
            Timeout, (_DWORD *)&IoStatusBlock, 1, 0);
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
                    OpenResult = (int)IrpReadFileWithOffset(
                        Handle[0], 1, *((void **)pInputBuffer + 2), pInputBuffer[3],
                        Timeouta, (_DWORD *)&IoStatusBlock, 0, 0);
                    continue;
                }
            }
            break;
        }
        ZwClose(Handle[0]);
    }
    return 1;
}
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
    pNewPath2 = (_WORD *)(ULONG_PTR)pInputBuffer[2];
    if (pNewPath2[NewLastChar])
        pNewPath2[NewLastChar] = 0;
    if (!(unsigned int)CreateFileWithPath(
        (__int16 *)*pInputBuffer, 0, &FileHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        __int64 result = (int)CmdSendRenameFileIrp(
            FileHandle, (const void *)(ULONG_PTR)pInputBuffer[2], *((_DWORD *)pInputBuffer + 6)) >= 0;
        ZwClose(FileHandle);
        return result;
    }
    return 0;
}
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
    pDstPath2 = (_WORD *)(ULONG_PTR)pInputBuffer[2];
    if (pDstPath2[DstLastChar])
        pDstPath2[DstLastChar] = 0;
    if (!CheckFilePathFilter((__int64)*pInputBuffer, *((_DWORD *)pInputBuffer + 2)) &&
        !CheckFilePathFilter((__int64)pInputBuffer[2], *((_DWORD *)pInputBuffer + 6)) &&
        !(unsigned int)CreateFileWithPath(
            (__int16 *)(ULONG_PTR)*pInputBuffer, 0, &SrcHandle, 0x80, 0x80, 1, 1, 0x20))
    {
        if (!(unsigned int)CmdQueryFileStandardInfo(SrcHandle, (_QWORD *)&FileInfo))
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
__int64 OpenFileForEnumOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _WORD *pFilePath = (_WORD *)InputBuffer;
    SIZE_T FilePathLength = (unsigned int)InputSize;
    _QWORD *pFileHandle = (_QWORD *)pOutputBuffer;
    unsigned int LengthCopy = (unsigned int)FilePathLength;
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
        *pFileHandle = (_QWORD)FileHandle;
        return 1;
    }
    return 0;
}
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
__int64 CheckFileExistOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _WORD *pFilePath = (_WORD *)InputBuffer;
    SIZE_T FilePathLength = (unsigned int)InputSize;
    _DWORD *pResult = pOutputBuffer;
    unsigned int LengthCopy = (unsigned int)FilePathLength;
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
                                                *pOutputBuffer = (unsigned int)BufferSize;
                                                *(_QWORD *)(pOutputBuffer + 1) = 0;
                                                pOutputBuffer[3] = 0;
                                                pOutputBuffer[1028] = 0;
                                                RtlMoveMemory(pOutputBuffer + 4, Buffer, BufferSize);
                                                if ((unsigned __int8)ProcessDiskSectorData((__int64)DeviceObject, 0, (__int64)Buffer, (unsigned int)BufferSize) == 1)
                                                {
                                                    pOutputBuffer[1028] = 1;
                                                    RtlMoveMemory(pOutputBuffer + 1029, Buffer, BufferSize);
                                                }
                                                AnalyzeDiskSectorBuffer((__int64)pOutputBuffer);
                                                if (pOutputBuffer[1] || pOutputBuffer[2])
                                                    pOutputBuffer[3] = (unsigned int)FindBootSectorWithRetry(DeviceObject, (unsigned int)BufferSize);
                                                if (!pOutputBuffer[1] && !pOutputBuffer[2] && CheckMbrBootablePartition((void *)(pOutputBuffer + 4)))
                                                {
                                                    BootablePartitionLba = (int)FindBootablePartitionLba((__int64)(pOutputBuffer + 4));
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
                                                                        if ((unsigned __int8)ProcessDiskSectorData((__int64)DeviceObject, (unsigned int)(BufferSize * Lba), (__int64)Buffer, (unsigned int)BufferSize) == 1)
                                                                        {
                                                                            pOutputBuffer[3078] = 1;
                                                                            RtlMoveMemory(pOutputBuffer + 3079, Buffer, BufferSize);
                                                                        }
                                                                        CheckDiskSectorHealth((char *)pOutputBuffer);
                                                                        if (pOutputBuffer[4103])
                                                                            pOutputBuffer[4105] = (unsigned int)FindReadableDiskSector(DeviceObject, (unsigned int)BufferSize, (__int64)pOutputBuffer);
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
