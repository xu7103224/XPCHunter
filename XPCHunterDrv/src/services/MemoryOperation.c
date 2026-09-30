// MemoryOperation.c — 内存/CPU/MSR 操作（从 Operation.c 拆分）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：内核内存读写、CPU/MSR、物理内存、处理器信息

#include "..\inc\XPCHunterDrv.h"
#pragma intrinsic(__readmsr, __writemsr)

// 全局变量（原 Operation.c 文件级定义，随内存操作迁移至此）
__int64 g_HalDispatchTable = 0;
__int64 g_HalDispatchTableEnd = 0;

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
__int64 ReadCpuBaseAddrExOperation(__int64 InputBuffer, volatile void *pInputAddress, int InputSize, _DWORD *pOutputBuffer, int OutputSize);
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
        ForEachProcessor((__int64 (*)(__int64, __int64))ResolveKernelModuleBasePair, (__int64)MsrPair);
        *pOutputData = *(_OWORD *)&MsrDiffResult;
        return 1;
    }
    return 0;
}
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
    char SectionContext[72];            // 0x48 字节解码上下文（原 [8] 仅 8 字节；保持数组形式）
    _QWORD *SectionDataPtr = 0;
    char SectionEntryBuffer[448];       // 描述符：原 [240] 仅 240 字节
    unsigned int SectionEntryOffset = 0;
    __int64 SectionTypeInfo = 0;

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
                (__int64)(HalImageBase + AddressOffset),
                HalImageSize - AddressOffset,
                2,
                0,
                -1,
                0,
                0,
                (__int64)SectionContext);

            LoopCount = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)SectionContext, (PULONG)SectionEntryBuffer))
            {
                pCurrentEntry = (_QWORD *)((__int64)SectionDataPtr + SectionEntryOffset);
                SectionDataPtr = pCurrentEntry;
                EntryType = *(__int16 *)(SectionTypeInfo + 6);

                if (EntryType == 225)
                {
                    Result = (unsigned int)(ULONG_PTR)pCurrentEntry - SectionBase;
                    if ((int)(ULONG_PTR)pCurrentEntry - SectionBase > (int)HalImageSizeCopy)
                        return 0;
                    return Result;
                }

                if (EntryType == 1301
                    && (int)(ULONG_PTR)pCurrentEntry - (int)HalImageBase < (int)HalImageSizeCopy
                    && (int)(ULONG_PTR)pCurrentEntry - (int)HalImageBase + 16 < (int)HalImageSizeCopy
                    && *pCurrentEntry == g_HalDispatchTable
                    && pCurrentEntry[1] == g_HalDispatchTableEnd)
                {
                    Result = (unsigned int)(ULONG_PTR)pCurrentEntry - SectionBase;
                    if ((int)(ULONG_PTR)pCurrentEntry - SectionBase > (int)HalImageSizeCopy)
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
    PE_DECODE_CONTEXT SectionReadContext;   // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 SectionDataPtr = 0;
    _DWORD SectionEntryBuffer[112];     // 描述符：原 [60] 仅 240 字节
    unsigned int SectionEntryOffset = 0;
    __int64 SectionTypeInfo = 0;

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
                (__int64)SectionBase,
                HalImageSize - AddressOffset,
                2,
                0,
                -1,
                0,
                0,
                (__int64)&SectionReadContext);

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
__int64 DispatchCpuMsrBaseLookup(int MsrTableEntry)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4563)
        return FindCpuMsrBaseWin10(MsrTableEntry);
    else
        return FindCpuMsrBaseLegacy(MsrTableEntry);
}
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
            OffsetAdjust = (unsigned int)((int)(ULONG_PTR)VirtualAddress - (int)NtoskrnlBase);
            if ((int)(ULONG_PTR)VirtualAddress != (int)NtoskrnlBase
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
            ExportOffset = (unsigned int)((int)(ULONG_PTR)VirtualAddress - (int)NtoskrnlBase);
            if ((int)(ULONG_PTR)VirtualAddress != (int)NtoskrnlBaseCopy
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
                            WritePhysicalMemoryBuffer((unsigned __int64)VirtualAddress, TempBuffer, (unsigned int)SizeCopy, 0, 0);
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
    Device0Ready = (int)GtRead(GtEprocessField133 | 0x100);
    Ctx0Ready = (int)GtRead(GtFltUnregisterFilterAddr | GtEprocessField22);
    Device2Ready = (int)GtRead(GtEprocessField134 | 0x100);
    Ctx2Ready = (int)GtRead(GtFltUnregisterFilterOffset | GtEprocessField22);
    Device1Ready = (int)GtRead(GtKernelDataField18);
    Ctx1Ready = (int)GtRead(GtFltDataSectionOffset | GtEprocessField22);

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
__int64 EnumProcessorInfoOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    _DWORD *pOutputData = pOutputBuffer;
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
    RemainingEntries = (int)((BufferSize - 88) / 0x50 + 1);
    ProcessorContext[0] = (_QWORD)pOutputData;
    ProcessorContext[1] = (_QWORD)&RemainingEntries;
    ForEachProcessor((__int64 (*)(__int64, __int64))ReadThreadContext, (__int64)ProcessorContext);

    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber >= 0xA28 && RemainingEntries)
    {
        MaxProcessCount = (int)GtRead(GtObjectTypeCount);
        ObjectTypeOffset = GtRead(GtKiFastCallEntryAddr | GtNtoskrnlImageSize);
        MaxCount = (int)ObjectTypeOffset;
        ObjectTableOffsetVal = ObjectTypeOffset;
        ImageFileOffsetVal = GtRead(GtEprocessModuleListOffset | GtPspTerminateThreadAddr);
        BasePriorityOffset = GtRead(GtProcessOffset);
        ObjectTableOffset = GtRead(GtProcessEprocess);
        EprocessOffset = GtRead(GtEprocessField43);
        ImageFileNameOffset = (int)EprocessOffset;
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
                        if ((ULONG64)pContextTable > (ULONG64)MmSystemRangeStart)
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
        ForEachProcessor((__int64 (*)(__int64, __int64))ValidateAndClearProcessContext, (__int64)&ProcessorContext);
        return Cleared == 1;
    }

    if (BuildNumber >= 0xA28)
    {
        TargetEprocess = (char *)*((_QWORD *)pInputBuffer + 1);
        ObjectTypeId = (int)GtRead(GtObjectTypeCount);
        ObjectTableOffset = (int)GtRead(GtKiFastCallEntryAddr | GtNtoskrnlImageSize);
        ContextOffset = (unsigned int)GtRead(GtEprocessModuleListOffset | GtPspTerminateThreadAddr);
        BasePriorityOffset = (int)GtRead(GtProcessOffset);
        ImageFileOffsetVal = GtRead(GtEprocessField43);
        pSectionBase = (_QWORD *)GtRead(GtObjectTypeInfoPtr);

        if (ObjectTypeId && ObjectTableOffset && ContextOffset &&
            BasePriorityOffset != -1 && (_DWORD)ImageFileOffsetVal != -1 &&
            (ULONG64)pSectionBase > (ULONG64)MmSystemRangeStart)
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
                        if ((ULONG64)pContextTable > (ULONG64)MmSystemRangeStart)
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
    if (pKernelMemCtx && (ULONG64)pKernelMemCtx > (ULONG64)MmSystemRangeStart && pVerifyFunc &&
        CheckMemoryValid(pKernelMemCtx) == 1 && (!*pKernelMemCtx || VerifyFunc() >= 0))
        return 1;
    return Result;
}
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
    EntryCount = (unsigned int)GtRead(GtEprocessExtField58 | GtEprocessField28 | 0x400);
    if (pDataPtr && EntryCount && (ULONG64)pDataPtr > (ULONG64)MmSystemRangeStart &&
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
    EntryCount = (unsigned int)GtRead(GtEprocessExtField47 | GtEprocessField54 | 0x400);
    if (pDataPtr && EntryCount && (ULONG64)pDataPtr > (ULONG64)MmSystemRangeStart &&
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
                WinBuildNum = (unsigned int)GtRead(GtWindowsBuildNumber);
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
__int64 ReadKernelMemoryToUserBufferOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    _QWORD *pKernelMemCtx;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pKernelMemCtx = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400);
    if (pKernelMemCtx && (ULONG64)pKernelMemCtx > (ULONG64)MmSystemRangeStart &&
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
__int64 ReadKernelMemoryRangeOperation(__int64 InputBuffer, __int64 InputSize, _QWORD *pOutputBuffer, int OutputSize)
{
    char Result;
    _QWORD *pMacShimData;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400))
        InitKernelMemoryContext();
    pMacShimData = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400);
    if (pMacShimData && (ULONG64)pMacShimData > (ULONG64)MmSystemRangeStart &&
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
    EntryStepSize = (unsigned int)GtRead(GtEprocessExtField42 | GtEprocessField54 | 0x400);
    if (pMemCtxListHead && (ULONG64)pMemCtxListHead > (ULONG64)MmSystemRangeStart && EntryStepSize &&
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
            WinBuildNum = (unsigned int)GtRead(GtWindowsBuildNumber);
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
    Offset = (unsigned int)GtRead(GtEprocessExtField58 | GtEprocessField66 | 0x400);
    ppData = (void **)GtRead(GtEprocessExtField58 | GtEprocessField67 | 0x400);
    if (!pContext || (ULONG64)pContext <= (ULONG64)MmSystemRangeStart || !Offset || !ppData || (ULONG64)ppData <= (ULONG64)MmSystemRangeStart)
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
    if ((ULONG64)pData > (ULONG64)MmSystemRangeStart && CheckMemoryValid(pData) == 1 && CheckMemoryValid((char *)pData + StrideSize - 1) == 1)
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
    if ((ULONG64)pEntry > (ULONG64)MmSystemRangeStart)
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
    Offset = (unsigned int)GtRead(GtEprocessExtField58 | GtEprocessField60 | 0x400);
    pContext = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400);
    if (pContext && (ULONG64)pContext > (ULONG64)MmSystemRangeStart && Offset && (Offset & 7) == 0 &&
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
