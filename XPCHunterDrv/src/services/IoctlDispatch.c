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
__int64 InitCommandHandlerTable(void)
{
    PCOMMAND_HANDLER *Table = (PCOMMAND_HANDLER *)GtAlloc(GtCommandHandlerBase);

    RtlZeroMemory(Table, 0x8D8);

    // 按索引顺序填充命令处理函数表
    Table[0] = (PCOMMAND_HANDLER)CmdReadProcessMemory;
    Table[1] = (PCOMMAND_HANDLER)CmdResetProcessContext;
    Table[2] = (PCOMMAND_HANDLER)CmdQueryProcessInfo;
    Table[3] = (PCOMMAND_HANDLER)NULL;
    Table[4] = (PCOMMAND_HANDLER)CmdGetModuleCount;
    Table[5] = (PCOMMAND_HANDLER)CmdEnumKernelDrivers;
    Table[6] = (PCOMMAND_HANDLER)CmdEnumHandles;
    Table[7] = (PCOMMAND_HANDLER)CmdCheckProcessAccess;
    Table[8] = (PCOMMAND_HANDLER)CmdProcessOperation;
    Table[9] = (PCOMMAND_HANDLER)CmdMiniFilterStreamHandle;
    Table[10] = (PCOMMAND_HANDLER)CmdEnumThreads;
    Table[11] = (PCOMMAND_HANDLER)CmdReadProcessMemoryBlock;
    Table[12] = (PCOMMAND_HANDLER)CmdQueryModuleInfo;
    Table[13] = (PCOMMAND_HANDLER)CmdModuleOperation;
    Table[14] = (PCOMMAND_HANDLER)CmdEnumRegistry;
    Table[15] = (PCOMMAND_HANDLER)CmdRegistryOperation;
    Table[16] = (PCOMMAND_HANDLER)CmdRegistryProtect;
    Table[17] = (PCOMMAND_HANDLER)CmdEnumServices;
    Table[18] = (PCOMMAND_HANDLER)CmdEnumServiceTable;
    Table[19] = (PCOMMAND_HANDLER)CmdEnumObjects;
    Table[20] = (PCOMMAND_HANDLER)CmdObjectOperation;
    Table[21] = (PCOMMAND_HANDLER)CmdEnumKernelInfo;
    Table[22] = (PCOMMAND_HANDLER)CmdQueryMemoryInfo;
    Table[23] = (PCOMMAND_HANDLER)CmdReadProcessMemoryEx;
    Table[24] = (PCOMMAND_HANDLER)CmdDeviceIoControl;
    Table[25] = (PCOMMAND_HANDLER)CmdVirtualMemoryOp;
    Table[26] = (PCOMMAND_HANDLER)CmdProcessMonitor;
    Table[27] = (PCOMMAND_HANDLER)CmdEnumThreadsEx;
    Table[28] = (PCOMMAND_HANDLER)CmdEnumKernelModules;
    Table[29] = (PCOMMAND_HANDLER)CmdThreadOperation;
    Table[30] = (PCOMMAND_HANDLER)CmdThreadMonitor;
    Table[31] = (PCOMMAND_HANDLER)CmdKernelObjectMonitor;
    Table[32] = (PCOMMAND_HANDLER)CmdHandleMonitor;
    Table[33] = (PCOMMAND_HANDLER)CmdProtectStatus;
    Table[34] = (PCOMMAND_HANDLER)CmdQuerySsdtInfo;
    Table[35] = (PCOMMAND_HANDLER)CmdEnumKernelDriver;
    Table[36] = (PCOMMAND_HANDLER)CmdDriverLoadUnload;
    Table[37] = (PCOMMAND_HANDLER)CmdReadPhysicalMemory;
    Table[38] = (PCOMMAND_HANDLER)CmdIoPortOperation;
    Table[39] = (PCOMMAND_HANDLER)CmdKernelMemoryOperation;
    Table[40] = (PCOMMAND_HANDLER)CmdProcessMemoryOperation;
    Table[41] = (PCOMMAND_HANDLER)CmdEnumProcessModules;
    Table[42] = (PCOMMAND_HANDLER)CmdKernelMemoryOpDispatch;
    Table[43] = (PCOMMAND_HANDLER)CmdProcessMemoryOpDispatch;
    Table[44] = (PCOMMAND_HANDLER)CmdMemoryQueryOp;
    Table[45] = (PCOMMAND_HANDLER)CmdQuerySystemInfo;
    Table[46] = (PCOMMAND_HANDLER)CmdDriverProtectStatus;
    Table[47] = (PCOMMAND_HANDLER)CmdDriverProtectOp;
    Table[48] = (PCOMMAND_HANDLER)CmdThreadProtectStatus;
    Table[49] = (PCOMMAND_HANDLER)InitRegFilter;
    Table[50] = (PCOMMAND_HANDLER)InitRegNotify;
    Table[51] = (PCOMMAND_HANDLER)InitRegCallback;
    Table[52] = (PCOMMAND_HANDLER)CmdEnumProcessHandles;
    Table[53] = (PCOMMAND_HANDLER)CmdQueryProcessInfoEx;
    Table[54] = (PCOMMAND_HANDLER)CmdEnumObjectAllTypes;
    Table[55] = (PCOMMAND_HANDLER)CmdObjectOperationDispatch;
    Table[56] = (PCOMMAND_HANDLER)CmdDeviceIoControlEx;
    Table[57] = (PCOMMAND_HANDLER)CmdFsctlOperation;
    Table[58] = (PCOMMAND_HANDLER)CmdReadProcessMemoryStr;
    Table[59] = (PCOMMAND_HANDLER)CmdWriteProcessMemoryEx;
    Table[60] = (PCOMMAND_HANDLER)CmdDeviceIoControlSimple;
    Table[61] = (PCOMMAND_HANDLER)CmdDeviceIoControlWithBuffer;
    Table[62] = (PCOMMAND_HANDLER)CmdDeviceIoControlWithString;
    Table[63] = (PCOMMAND_HANDLER)CmdOpenSectionObject;
    Table[64] = (PCOMMAND_HANDLER)CmdCreateFile;
    Table[65] = (PCOMMAND_HANDLER)CmdEnumHandlesByPid;
    Table[66] = (PCOMMAND_HANDLER)CmdCreateFileWithPath;
    Table[67] = (PCOMMAND_HANDLER)CmdCloseHandle;
    Table[68] = (PCOMMAND_HANDLER)CmdQueryFileInfo;
    Table[69] = (PCOMMAND_HANDLER)CmdOpenFileHandle;
    Table[70] = (PCOMMAND_HANDLER)CmdReadFileSize;
    Table[71] = (PCOMMAND_HANDLER)CmdWriteFile;
    Table[72] = (PCOMMAND_HANDLER)CmdReadFile;
    Table[73] = (PCOMMAND_HANDLER)CmdReadDirectory;
    Table[74] = (PCOMMAND_HANDLER)CmdEnumDirectory;
    Table[75] = (PCOMMAND_HANDLER)CmdEnableObjectCallback;
    Table[76] = (PCOMMAND_HANDLER)CmdRenameFile;
    Table[77] = (PCOMMAND_HANDLER)CmdCopyFile;
    Table[78] = (PCOMMAND_HANDLER)CmdOpenFileForEnum;
    Table[79] = (PCOMMAND_HANDLER)CmdDeleteFile;
    Table[80] = (PCOMMAND_HANDLER)CmdSetFileAttributes;
    Table[81] = (PCOMMAND_HANDLER)CmdCheckFileExist;
    Table[82] = (PCOMMAND_HANDLER)CmdPowerCallbackUnregister;
    Table[83] = (PCOMMAND_HANDLER)CmdShutdownCallbackUnregister;
    Table[84] = (PCOMMAND_HANDLER)CmdPowerCallbackRoutine;
    Table[85] = (PCOMMAND_HANDLER)CmdRegNotifyCallback;
    Table[86] = (PCOMMAND_HANDLER)CmdDisableThreadProtect;
    Table[87] = (PCOMMAND_HANDLER)CmdEnableThreadProtect;
    Table[88] = (PCOMMAND_HANDLER)CmdQuerySystemInfoEx;
    Table[89] = (PCOMMAND_HANDLER)CmdCallbackControl;
    Table[90] = (PCOMMAND_HANDLER)CmdReadCpuMsr;
    Table[91] = (PCOMMAND_HANDLER)CmdReadCpuId;
    Table[92] = (PCOMMAND_HANDLER)CmdReadCpuBaseAddr;
    Table[93] = (PCOMMAND_HANDLER)CmdReadCpuInfoEx;
    Table[94] = (PCOMMAND_HANDLER)CmdReadCpuBaseAddrEx;
    Table[95] = (PCOMMAND_HANDLER)CmdStubAlwaysTrue;
    Table[96] = (PCOMMAND_HANDLER)CmdGetKernelBaseLegacy;
    Table[97] = (PCOMMAND_HANDLER)NULL;
    Table[98] = (PCOMMAND_HANDLER)NULL;
    Table[99] = (PCOMMAND_HANDLER)MiniFilterGenerateFileName;
    Table[100] = (PCOMMAND_HANDLER)RegisterFormatNameCallback;
    Table[101] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameEx;
    Table[102] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameWithContext;
    Table[103] = (PCOMMAND_HANDLER)RegisterFormatPathCallback;
    Table[104] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameWithPathEx;
    // 105-110: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[105], 0x30);
    Table[111] = (PCOMMAND_HANDLER)MiniFilterCommPortSend;
    Table[112] = (PCOMMAND_HANDLER)MiniFilterCommPortRecv;
    Table[113] = (PCOMMAND_HANDLER)MiniFilterCommPortReply;
    // 114-119: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[114], 0x30);
    Table[120] = (PCOMMAND_HANDLER)CmdQueryProcessNameByPid;
    Table[121] = (PCOMMAND_HANDLER)NULL;
    Table[122] = (PCOMMAND_HANDLER)NULL;
    Table[123] = (PCOMMAND_HANDLER)NULL;
    Table[124] = (PCOMMAND_HANDLER)MiniFilterCommPortConnect;
    Table[125] = (PCOMMAND_HANDLER)MiniFilterCommPortDisconnect;
    Table[126] = (PCOMMAND_HANDLER)MiniFilterCommPortCleanup;
    Table[127] = (PCOMMAND_HANDLER)CmdEnumObjectDirectory;
    Table[128] = (PCOMMAND_HANDLER)CmdCloseProcessHandle;
    Table[129] = (PCOMMAND_HANDLER)CmdEnumObjectHandles;
    Table[130] = (PCOMMAND_HANDLER)CmdTerminateProcessByEProcess;
    // 131-138: NULL (memset 0x40 = 64 bytes = 8 entries)
    RtlZeroMemory(&Table[131], 0x40);
    Table[139] = (PCOMMAND_HANDLER)CmdQueryObjectInfo;
    Table[140] = (PCOMMAND_HANDLER)CmdEnumSyscallEntries;
    Table[141] = (PCOMMAND_HANDLER)CmdInstallSystemHook;
    Table[142] = (PCOMMAND_HANDLER)CmdEnumShadowSyscallEntries;
    Table[143] = (PCOMMAND_HANDLER)CmdInstallShadowHook;
    Table[144] = (PCOMMAND_HANDLER)CmdEnumSyscallTable2;
    Table[145] = (PCOMMAND_HANDLER)CmdInstallSyscallHook2;
    Table[146] = (PCOMMAND_HANDLER)CmdEnumSyscallTable3;
    Table[147] = (PCOMMAND_HANDLER)CmdInstallSyscallHook3;
    Table[148] = (PCOMMAND_HANDLER)CmdEnumSyscallTable4;
    Table[149] = (PCOMMAND_HANDLER)CmdInstallSyscallHook4;
    Table[150] = (PCOMMAND_HANDLER)CmdEnumSyscallTable5;
    Table[151] = (PCOMMAND_HANDLER)CmdInstallSyscallHook5;
    Table[152] = (PCOMMAND_HANDLER)CmdEnumSyscallTable6;
    Table[153] = (PCOMMAND_HANDLER)CmdInstallSyscallHook6;
    Table[154] = (PCOMMAND_HANDLER)CmdEnumSyscallTable7;
    Table[155] = (PCOMMAND_HANDLER)CmdInstallSyscallHook7;
    Table[156] = (PCOMMAND_HANDLER)CmdEnumSyscallTable8;
    Table[157] = (PCOMMAND_HANDLER)CmdInstallSyscallHook8;
    Table[158] = (PCOMMAND_HANDLER)MiniFilterPreRename;
    Table[159] = (PCOMMAND_HANDLER)MiniFilterPreVolumeMount;
    Table[160] = (PCOMMAND_HANDLER)CmdEnumSyscallTable9;
    Table[161] = (PCOMMAND_HANDLER)CmdInstallSyscallHook9;
    Table[162] = (PCOMMAND_HANDLER)CmdEnumGdiObjects;
    Table[163] = (PCOMMAND_HANDLER)CmdCheckProcessHideDetect;
    Table[164] = (PCOMMAND_HANDLER)CmdFixProcessEProcess;
    Table[165] = (PCOMMAND_HANDLER)NULL;
    Table[166] = (PCOMMAND_HANDLER)NULL;
    Table[167] = (PCOMMAND_HANDLER)CmdSetCallbackFlagTrue;
    Table[168] = (PCOMMAND_HANDLER)CmdSetCallbackFlagFalse;
    Table[169] = (PCOMMAND_HANDLER)MiniFilterContextCleanup;
    Table[170] = (PCOMMAND_HANDLER)CmdDiskReadSector;
    Table[171] = (PCOMMAND_HANDLER)CmdDiskOperationDispatch;
    Table[172] = (PCOMMAND_HANDLER)CmdDiskSectorReadWrite;
    Table[173] = (PCOMMAND_HANDLER)CmdCollectAllCpuGdtEntries;
    Table[174] = (PCOMMAND_HANDLER)CmdForEachCpuClearGdtBit;
    Table[175] = (PCOMMAND_HANDLER)RegisterFilterUnloadCallback;
    Table[176] = (PCOMMAND_HANDLER)MiniFilterActiveRoutine;
    Table[177] = (PCOMMAND_HANDLER)MiniFilterNotifyRoutineEx2;
    Table[178] = (PCOMMAND_HANDLER)EnableProcessProtect;
    Table[179] = (PCOMMAND_HANDLER)DisableProcessProtect;
    Table[180] = (PCOMMAND_HANDLER)CmdEnumObjectTypes;
    Table[181] = (PCOMMAND_HANDLER)CmdEnumKernelObjectTable;
    Table[182] = (PCOMMAND_HANDLER)CmdWriteKernelObjectField;
    Table[183] = (PCOMMAND_HANDLER)CmdProcessCallbackRoutine;
    Table[184] = (PCOMMAND_HANDLER)CmdInitProcessCallback;
    // 185-190: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[185], 0x30);
    Table[191] = (PCOMMAND_HANDLER)CmdOpenFilterVolumeFile;
    Table[192] = (PCOMMAND_HANDLER)CmdRemoveFilterContextNode;
    Table[193] = (PCOMMAND_HANDLER)CmdEnumProcessListEx;
    Table[194] = (PCOMMAND_HANDLER)CmdEnumProcessListWin7;
    Table[195] = (PCOMMAND_HANDLER)CmdEnumProcessListWin8;
    Table[196] = (PCOMMAND_HANDLER)CmdEnumProcessListWin10;
    Table[197] = (PCOMMAND_HANDLER)CmdEnumKernelHandleTable;
    Table[198] = (PCOMMAND_HANDLER)CmdGetSsdtTableInfo;
    Table[199] = (PCOMMAND_HANDLER)CmdRestoreSsdtTable;
    Table[200] = (PCOMMAND_HANDLER)CmdEnumObjectTypeInfo;
    Table[201] = (PCOMMAND_HANDLER)CmdLookupObjectTypeByAddr;
    Table[202] = (PCOMMAND_HANDLER)CmdQuerySsdtDetails;
    Table[203] = (PCOMMAND_HANDLER)CmdSetSsdtEntry;
    Table[204] = (PCOMMAND_HANDLER)CmdReadExportDirectory;
    Table[205] = (PCOMMAND_HANDLER)CmdUpdateExportEntry;
    Table[206] = (PCOMMAND_HANDLER)CmdRestoreExportTable;
    Table[207] = (PCOMMAND_HANDLER)CmdInitSsdtTable;
    Table[208] = (PCOMMAND_HANDLER)CmdEnumKernelModules;
    Table[209] = (PCOMMAND_HANDLER)CmdInitFwpsDispatchTables2;
    Table[210] = (PCOMMAND_HANDLER)CmdInitFwpsDispatchTables;
    Table[211] = (PCOMMAND_HANDLER)CmdCopyKernelArrayToUserBuffer;
    Table[212] = (PCOMMAND_HANDLER)CmdEnumKernelMemoryContext;
    Table[213] = (PCOMMAND_HANDLER)InvokeRegisteredCallbackWithUserData;
    Table[214] = (PCOMMAND_HANDLER)CmdCopyKernelDualArrayToUserBuffer;
    Table[215] = (PCOMMAND_HANDLER)CmdReadKernelMemoryToUserBuffer;
    Table[216] = (PCOMMAND_HANDLER)CmdInitKernelMemoryContext;
    Table[217] = (PCOMMAND_HANDLER)CmdReadKernelMemoryRange;
    Table[218] = (PCOMMAND_HANDLER)CmdReadKernelMemoryRangeSize;
    Table[219] = (PCOMMAND_HANDLER)CmdWriteKernelMemoryRange;
    Table[220] = (PCOMMAND_HANDLER)CmdEnumKernelMemoryDetail;
    Table[221] = (PCOMMAND_HANDLER)CmdCallKernelMemoryFunction;
    Table[222] = (PCOMMAND_HANDLER)CmdEnumObjectTypeDirectory;
    Table[223] = (PCOMMAND_HANDLER)CmdEnumObjectTypeTable;
    Table[224] = (PCOMMAND_HANDLER)CmdEnumObjectTypeDetail;
    Table[225] = (PCOMMAND_HANDLER)CmdReadSsdtEntryTable;
    Table[226] = (PCOMMAND_HANDLER)CmdReadSsdtEntryTableEx;
    Table[227] = (PCOMMAND_HANDLER)CmdDispatchSsdtByVersion;
    Table[228] = (PCOMMAND_HANDLER)CmdFixSsdtEntryAddress;
    Table[229] = (PCOMMAND_HANDLER)CmdEnumSsdtEntryTable;
    Table[230] = (PCOMMAND_HANDLER)CmdReadMsrValue;
    Table[231] = (PCOMMAND_HANDLER)CmdWriteMsrValue;
    Table[232] = (PCOMMAND_HANDLER)CmdEnumProcessorInfo;
    Table[233] = (PCOMMAND_HANDLER)CmdSetProcessorField;
    Table[234] = (PCOMMAND_HANDLER)CmdInitFileSystemCallback;
    Table[235] = (PCOMMAND_HANDLER)MiniFilterPreAcquire;
    Table[236] = (PCOMMAND_HANDLER)MiniFilterPreRelease;
    Table[237] = (PCOMMAND_HANDLER)MiniFilterPreDelete;
    Table[238] = (PCOMMAND_HANDLER)MiniFilterPreFlush;
    Table[239] = (PCOMMAND_HANDLER)MiniFilterPreHardLink;
    Table[240] = (PCOMMAND_HANDLER)MiniFilterPreShutdown;
    Table[241] = (PCOMMAND_HANDLER)InitMiniFilterDriver;
    Table[242] = (PCOMMAND_HANDLER)CmdEnumAleEndpointLayers;
    Table[243] = (PCOMMAND_HANDLER)CmdInitFileSystemFilter;
    Table[244] = (PCOMMAND_HANDLER)CmdFileSystemFilterCallback;
    Table[245] = (PCOMMAND_HANDLER)CmdCallSystemRoutine;
    Table[246] = (PCOMMAND_HANDLER)CmdResetDriverState;
    Table[247] = (PCOMMAND_HANDLER)CmdEnumHookInfo;
    Table[248] = (PCOMMAND_HANDLER)CmdCheckBytePattern;
    Table[249] = (PCOMMAND_HANDLER)CmdGetHookEntryInfo;
    Table[250] = (PCOMMAND_HANDLER)CmdQueryHookStatus;
    Table[251] = (PCOMMAND_HANDLER)CmdEnumHookDetail;
    Table[252] = (PCOMMAND_HANDLER)CmdInitObjectCallback;
    Table[253] = (PCOMMAND_HANDLER)CmdEnumProcessContextWin7;
    Table[254] = (PCOMMAND_HANDLER)CmdSetProcessContextWin7;
    Table[255] = (PCOMMAND_HANDLER)CmdEnumProcessContextWin8;
    Table[256] = (PCOMMAND_HANDLER)CmdSetProcessContextWin8;
    Table[257] = (PCOMMAND_HANDLER)CmdReadKernelBase;
    Table[258] = (PCOMMAND_HANDLER)CmdClearKernelBase;
    Table[259] = (PCOMMAND_HANDLER)CmdEnumKernelModuleInfoEx;
    Table[260] = (PCOMMAND_HANDLER)CmdSetKernelModuleInfo;
    Table[261] = (PCOMMAND_HANDLER)CmdEnumProcessContextWin10;
    Table[262] = (PCOMMAND_HANDLER)CmdSetProcessContextWin10;
    Table[263] = (PCOMMAND_HANDLER)CmdEnumRegistryContext;
    Table[264] = (PCOMMAND_HANDLER)CmdSetRegistryContext;
    Table[265] = (PCOMMAND_HANDLER)CmdEnumFileSystemContext;
    Table[266] = (PCOMMAND_HANDLER)CmdSetFileSystemContext;
    Table[267] = (PCOMMAND_HANDLER)CmdEnumUSBPortSyscallTable;
    Table[268] = (PCOMMAND_HANDLER)CmdInstallUSBPortSyscallHook;
    Table[269] = (PCOMMAND_HANDLER)CmdEnumObjectContext;
    Table[270] = (PCOMMAND_HANDLER)CmdSetObjectContext;
    Table[271] = (PCOMMAND_HANDLER)CmdEnumProcessProtectContext;
    Table[272] = (PCOMMAND_HANDLER)CmdSetProcessProtectContext;
    Table[273] = (PCOMMAND_HANDLER)CmdEnumCallbackContext;
    Table[274] = (PCOMMAND_HANDLER)CmdSetCallbackContext;
    Table[275] = (PCOMMAND_HANDLER)CmdEnumThreadContextWin10;
    Table[276] = (PCOMMAND_HANDLER)CmdSetThreadContextWin10;
    Table[277] = (PCOMMAND_HANDLER)CmdDisableObjectProtect;
    Table[278] = (PCOMMAND_HANDLER)CmdEnableObjectProtect;
    Table[279] = (PCOMMAND_HANDLER)CmdKernelNotifyRoutine;
    Table[280] = (PCOMMAND_HANDLER)CmdKernelNotifyRoutineEx;
    Table[281] = (PCOMMAND_HANDLER)CmdRestoreDriverDispatch;

    return (__int64)CmdRestoreDriverDispatch;
}

// ===================================================================
// Cmd* 命令处理函数实现
// ===================================================================

// CmdReadProcessMemory — 读取进程内存命令处理
// 对应原始驱动 sub_14007F384
__int64 CmdReadProcessMemory(__int64 Address, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    GtWrite(GtEprocessField123 | 0x100, (__int64)CurrentProcess);
    ULONG64 CurrentProcessId = (ULONG64)PsGetCurrentProcessId();
    GtWrite(GtEprocessModuleEntrySize | GtEprocessField22, CurrentProcessId & 0xFFFFFFFFFFFFFFFCui64);
    ULONG PsExitSpecialApcAddr = (ULONG)GtRead(GtPsExitSpecialApcAddr);
    if (Address)
    {
        if (InputSize == 8 && (ULONG64)Address < MmUserProbeAddress && (ULONG64)(Address + 1) < MmUserProbeAddress)
        {
            ProbeForRead((PVOID)Address, 8, 4);
            __int64 TargetAddress = *(__int64 *)Address;
            if (TargetAddress != -1 && !PsExitSpecialApcAddr)
            {
                struct _KPROCESS *CurrentProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
                KAPC_STATE ApcState;
                if (CurrentProcess)
                    KeStackAttachProcess(CurrentProcess, &ApcState);
                if (ReadProcessMemoryWithAttach(TargetAddress) == 1)
                {
                    PsExitSpecialApcAddr;
                    GtRead(GtExFreeCallBackAddr);
                    GtRead(GtPspExitNormalApcAddr);
                }
                if (CurrentProcess)
                    KeUnstackDetachProcess(&ApcState);
            }
        }
    }
    return 0;
}

// CmdResetProcessContext — 重置进程上下文命令处理
// 对应原始驱动 sub_14007F118
__int64 CmdResetProcessContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    GtWrite(GtEprocessField123 | 0x100, 0);
    return GtWrite(GtEprocessModuleEntrySize | GtEprocessField22, 0);
}

// CmdQueryProcessInfo — 查询进程信息命令处理
// 对应原始驱动 sub_14003105C
__int64 CmdQueryProcessInfo(__int64 ProcessId, __int64 BufferSize, _DWORD *pOutputBuffer, int OutputSize)
{
    if ((unsigned int)BufferSize > 0xA)
        return QuerySsdHookByProcessInfo((void *)ProcessId, BufferSize, pOutputBuffer, OutputSize);
    AllocProcessInfoBuffer();
    return CheckSsdtHookIntegrity((ULONG64)ProcessId, (unsigned int)BufferSize, pOutputBuffer, OutputSize);
}

// CmdGetModuleCount — 获取模块计数命令
// 对应原始驱动 sub_140071C8C
__int64 CmdGetModuleCount(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    if (pOutputBuffer && (ULONG64)pOutputBuffer < MmUserProbeAddress && (ULONG64)(pOutputBuffer + 1) < MmUserProbeAddress && OutputSize == 4)
    {
        ProbeForWrite(pOutputBuffer, 4, 4);
        *pOutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
        return 1;
    }
    return 0;
}

// CmdEnumKernelDrivers — 枚举内核驱动程序列表
// 对应原始驱动 sub_14004F340
__int64 CmdEnumKernelDrivers(__int64 InputBuffer, __int64 InputSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!OutputBuffer || BufferSize <= 0x50)
        return 0;
    if ((ULONG64)OutputBuffer >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    __int64 (*pObjectTypeFunc)(void) = (__int64 (*)(void))GtRead(GtObjectTypeRefFunc);
    __int64 (*pDriverObjectFunc)(void) = (__int64 (*)(void))GtRead(GtTotalSize | GtObjectTypeField42 | GtDriverObject);
    __int64 ServiceTable = GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField120);
    __int64 (*pCurrentThreadFunc)(void) = (__int64 (*)(void))ServiceTable;
    if (!pObjectTypeFunc || !pDriverObjectFunc || !ServiceTable)
        return 0;
    __int64 FuncResult1 = pDriverObjectFunc();
    __int64 FuncResult2 = pObjectTypeFunc();
    char HasData = 1;
    __int64 CallbackResult = pCurrentThreadFunc();
    int Result = EnumProcessInformationWorker(&HasData, (__int64)OutputBuffer, BufferSize);
    if (Result)
    {
        unsigned int HeaderValue = OutputBuffer[4];
        unsigned int EntryCount = 0;
        for (unsigned int i = 0; i < HeaderValue; i++)
        {
            __int64 EntryOffset = 14LL * i;
            if (CallbackResult == *(__int64 *)&OutputBuffer[EntryOffset + 10])
            {
                OutputBuffer[4]--;
            }
            else
            {
                if (EntryCount != i)
                {
                    __int64 EntryOffset2 = 14LL * EntryCount;
                    *(_OWORD *)&OutputBuffer[EntryOffset2 + 6] = *(_OWORD *)&OutputBuffer[EntryOffset + 6];
                    *(_OWORD *)&OutputBuffer[EntryOffset2 + 10] = *(_OWORD *)&OutputBuffer[EntryOffset + 10];
                    *(_OWORD *)&OutputBuffer[EntryOffset2 + 14] = *(_OWORD *)&OutputBuffer[EntryOffset + 14];
                    *(__int64 *)&OutputBuffer[EntryOffset2 + 18] = *(__int64 *)&OutputBuffer[EntryOffset + 18];
                }
                EntryCount++;
            }
        }
        return 1;
    }
    return 0;
}

// CmdEnumHandles — 枚举句柄命令处理
// 对应原始驱动 sub_14004ABB4

// CmdCheckProcessAccess — 检查进程访问权限
// 对应原始驱动 sub_1400800C0
__int64 CmdCheckProcessAccess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return CheckProcessAccess();
}

// CmdProcessOperation — 进程操作命令处理
// 对应原始驱动 sub_14007FD2C
// 读取 16 字节输入（ProcessId + 可选 EPROCESS），查找进程，验证后清零内存页并执行进程操作
__int64 CmdProcessOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;
    if (InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        PEPROCESS Process;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        bool Result;
        struct _KPROCESS **pObjectTypeInfo;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        Status2 = Status;
        TargetProcess = (struct _KPROCESS *)InputData.qword[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
            SavedData.qword[1] = (__int64)TargetProcess;
        }
        if ((struct _KPROCESS *)GtRead(GtEprocessField123 | 0x100) == TargetProcess)
        {
            Result = 1;
        }
        else
        {
            Result = 0;
            pObjectTypeInfo = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
            if (pObjectTypeInfo)
                Result = *pObjectTypeInfo == TargetProcess;
            if (!Result)
            {
                ZeroProcessMemoryPages(TargetProcess);
                Result = ValidateProcessObject(TargetProcess, 0) != 1 || ProcessOperationWithAttach(TargetProcess);
            }
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// CmdEnumThreads — 枚举线程命令处理
// 对应原始驱动 sub_14004B764
// 获取进程名写入输出缓冲区，特殊进程(MemCompression/Registry)使用编码后的进程名，输出格式 520 字节

// CmdReadProcessMemoryBlock — 读取进程内存块
// 对应原始驱动 sub_14004A0B0
// 读取 16 字节输入(ProcessId + EPROCESS)，查找进程，验证后分配缓冲区并读取内存复制到用户缓冲区
__int64 CmdReadProcessMemoryBlock(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    SIZE_T BufferSize = OutputSize;
    char Result = 0;
    if (InputSize == 16 && OutputSize > 2)
    {
        _OWORD InputData;
        _OWORD PatchData;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        PEPROCESS Process;
        PVOID AllocBuffer;
        void *TempBuffer;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 4u);
        ProbeForWrite(pOutputBuffer, (unsigned int)BufferSize, 2u);
        InputData = *(_OWORD *)InputBuffer;
        PatchData = InputData;
        memset(pOutputBuffer, 0, (unsigned int)BufferSize);
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        Status2 = Status;
        TargetProcess = (struct _KPROCESS *)PatchData.qword[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
        }
        if (ValidateProcessObject(TargetProcess, 0) == 1)
        {
            AllocBuffer = ExAlloc(PagedPool, (ULONG)BufferSize);
            TempBuffer = AllocBuffer;
            if (AllocBuffer)
            {
                if (ReadProcessMemoryBlock(TargetProcess, AllocBuffer, (unsigned int)BufferSize) == 1)
                {
                    memmove(pOutputBuffer, TempBuffer, BufferSize - 2);
                    Result = 1;
                }
                ExFree(TempBuffer);
            }
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// CmdEnumKernelModules — 枚举内核模块
// 对应原始驱动 sub_14004F9F4
// 接收 24 字节输入参数(ProcessId + EPROCESS + 附加数据)，调用 EnumProcessInformationWorker 枚举模块信息

// CmdThreadOperation — 线程操作命令处理
// 对应原始驱动 sub_1400809CC
// 查找线程对象，验证后准备页表扫描
__int64 CmdThreadOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;
    if (InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        PETHREAD Thread;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupThreadByThreadId((HANDLE)InputData.qword[0], &Thread);
        Status2 = Status;
        TargetThread = (char *)InputData.qword[1];
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = (char *)Thread;
            SavedData.qword[1] = (__int64)TargetThread;
        }
        Result = 1;
        if (ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1)
            Result = PrepareFileForPageTableScan(TargetThread, 0);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Result;
}

// CmdThreadMonitor — 线程监控命令处理
// 对应原始驱动 sub_1400807F0
// 根据线程ID查找线程对象，验证并准备页表扫描(用于线程保护/监控)
__int64 CmdThreadMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;
    if (InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        PETHREAD Thread;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupThreadByThreadId((HANDLE)InputData.qword[0], &Thread);
        Status2 = Status;
        TargetThread = (char *)InputData.qword[1];
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = (char *)Thread;
            SavedData.qword[1] = (__int64)TargetThread;
        }
        Result = 1;
        if (ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1)
            Result = PrepareFileForPageTableScan(TargetThread, 1);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Result;
}

// CmdKernelObjectMonitor — 内核对象监控命令处理
// 对应原始驱动 sub_14007EBC4
// 通过线程ID查找线程，验证内核对象后初始化对象并查询名称
__int64 CmdKernelObjectMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Inited = 0;
    if (InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        __int64 (*pCurrentThreadFunc)(void);
        PETHREAD Thread;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupThreadByThreadId((HANDLE)InputData.qword[0], &Thread);
        Status2 = Status;
        TargetThread = (char *)InputData.qword[1];
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = (char *)Thread;
            SavedData.qword[1] = (__int64)TargetThread;
        }
        pCurrentThreadFunc = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (pCurrentThreadFunc && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1 && TargetThread != (char *)pCurrentThreadFunc())
            Inited = (bool)InitObjectAndQueryName((__int64)TargetThread, 1);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Inited;
}

// CmdHandleMonitor — 句柄监控命令处理
// 对应原始驱动 sub_14007E59C
// 通过线程ID查找线程，初始化对象并查询句柄监视信息
__int64 CmdHandleMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Inited = 0;
    if (InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        __int64 (*pCurrentThreadFunc)(void);
        PETHREAD Thread;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupThreadByThreadId((HANDLE)InputData.qword[0], &Thread);
        Status2 = Status;
        TargetThread = (char *)InputData.qword[1];
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = (char *)Thread;
            SavedData.qword[1] = (__int64)TargetThread;
        }
        pCurrentThreadFunc = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (pCurrentThreadFunc && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1 && TargetThread != (char *)pCurrentThreadFunc())
            Inited = (bool)InitObjectAndQueryName((__int64)TargetThread, 0);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Inited;
}

// CmdProtectStatus — 保护状态查询命令处理
// 对应原始驱动 sub_14007E32C
// 通过线程ID查找线程，检查线程是否受保护
__int64 CmdProtectStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputSize == 16
        && (ULONG64)InputBuffer < MmUserProbeAddress
        && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress
        && OutputSize == 2
        && (ULONG64)pOutputBuffer < MmUserProbeAddress
        && (ULONG64)(pOutputBuffer + 2) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        PETHREAD TargetThread;
        __int64 (*CurrentThreadFunc)(void);
        unsigned int Result;
        PETHREAD Thread;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 4u);
        ProbeForWrite(pOutputBuffer, 2u, 1u);
        InputData = *(_OWORD *)InputBuffer;
        SavedData = InputData;
        Status = PsLookupThreadByThreadId((HANDLE)InputData.qword[0], &Thread);
        Status2 = Status;
        TargetThread = (PETHREAD)InputData.qword[1];
        if (!TargetThread)
        {
            if (Status >= 0)
                TargetThread = Thread;
            SavedData.qword[1] = (__int64)TargetThread;
        }
        CurrentThreadFunc = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (CurrentThreadFunc && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1)
        {
            *(_WORD *)pOutputBuffer = 0;
            if (TargetThread != (PETHREAD)CurrentThreadFunc())
            {
                Result = (unsigned int)GtRead(GtKiFastCallEntryAddr | GtEprocessField08);
                if (Result)
                {
                    if (*((_BYTE *)TargetThread + Result))
                        *((_BYTE *)pOutputBuffer + 1) = 1;
                    else
                        *(_BYTE *)pOutputBuffer = 1;
                }
            }
            Result = 1;
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Result;
}

// CmdQuerySsdtInfo — 查询 SSDT 信息命令处理
// 对应原始驱动 sub_14003B0A0
// 验证输入缓冲区(24 字节)，检查用户模式地址后调用 ProbeForRead/ProbeForWrite，清空输出缓冲区后调用 CmdEnumDriverObjects 枚举驱动对象信息
__int64 CmdQuerySsdtInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputBuffer)
    {
        if (InputSize == 24
            && (ULONG64)InputBuffer < MmUserProbeAddress
            && (ULONG64)(InputBuffer + 24) < MmUserProbeAddress)
        {
            void **pInputBuffer = (void **)InputBuffer;
            volatile void *pOutputBuffer;
            SIZE_T BufferSize;

            ProbeForRead(pInputBuffer, 0x18u, 4u);
            pOutputBuffer = pInputBuffer[1];
            if (pOutputBuffer)
            {
                BufferSize = *((unsigned int *)pInputBuffer + 4);
                if ((_DWORD)BufferSize)
                {
                    if ((ULONG64)pOutputBuffer < MmUserProbeAddress
                        && (ULONG64)pOutputBuffer + BufferSize < MmUserProbeAddress)
                    {
                        ProbeForWrite(pOutputBuffer, BufferSize, 1u);
                        memset(pInputBuffer[1], 0, *((unsigned int *)pInputBuffer + 4));
                        return CmdEnumDriverObjects(
                            (unsigned int *)pInputBuffer[1],
                            *((_DWORD *)pInputBuffer + 4),
                            0,
                            *(_BYTE *)pInputBuffer);
                    }
                }
            }
        }
    }
    return Result;
}

// CmdEnumKernelDriver — 枚举内核驱动命令处理
// 对应原始驱动 sub_14005335C
// 读取 GT 服务数，验证输出缓冲区大小(168*(服务数-1)+176)，调用 EnumKernelDriverObjects 枚举驱动对象，BuildDriverInfoEntries 构建条目，ResolveDriverModuleNames 解析模块名
__int64 CmdEnumKernelDriver(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (ServiceCount)
    {
        if (pOutputBuffer && (unsigned int)OutputSize >= 168 * (ServiceCount - 1) + 176
            && (ULONG64)pOutputBuffer < MmUserProbeAddress
            && (ULONG64)pOutputBuffer + OutputSize < MmUserProbeAddress)
        {
            ProbeForWrite(pOutputBuffer, OutputSize, 1u);
            memset(pOutputBuffer, 0, OutputSize);
            if (EnumKernelDriverObjects(pOutputBuffer, ServiceCount) == 1 && BuildDriverInfoEntries(pOutputBuffer, OutputSize) == 1)
                return ResolveDriverModuleNames(pOutputBuffer) == 1;
        }
    }
    return Result;
}

// CmdDriverLoadUnload — 驱动加载/卸载命令处理
// 对应原始驱动 sub_1400516C0
// 验证用户缓冲区，读取 ntoskrnl.exe 文件，调用 ReadServiceTableEntries 读取服务表，解析驱动地址
__int64 CmdDriverLoadUnload(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;
    __int64 ServiceTable = GtRead(GtEprocessField69);
    int ServiceCount = (int)GtRead(GtEprocessField57);
    if (ServiceTable && ServiceCount)
    {
        if ((unsigned int)OutputSize >= (unsigned int)(48 * (ServiceCount - 1) + 56)
            && (ULONG64)pOutputBuffer < MmUserProbeAddress
            && (ULONG64)pOutputBuffer + OutputSize < MmUserProbeAddress)
        {
            unsigned int FileSize;
            void *FileBuffer;

            ProbeForWrite(pOutputBuffer, OutputSize, 1u);
            memset(pOutputBuffer, 0, OutputSize);
            if (ReadNtOsKrnlFile((__int64 *)&FileBuffer, (__int64 *)&FileSize))
            {
                if (ReadServiceTableEntries((__int64)pOutputBuffer, OutputSize, FileBuffer, FileSize) == 1)
                {
                    pOutputBuffer[1] = (unsigned int)ServiceCount;
                    *pOutputBuffer = (unsigned int)GtRead(GtWindowsBuildNumber);
                    if (ResolveDriverRelativeAddresses((__int64)pOutputBuffer, OutputSize, (int **)(ServiceTable + 32)) == 1
                        && ParseExportDirForDriver((__int64)pOutputBuffer, OutputSize, (__int64)FileBuffer, FileSize) == 1)
                    {
                        Result = ResolveDriverEntryAddresses((__int64)pOutputBuffer) == 1;
                    }
                }
                ExFree(FileBuffer);
            }
        }
    }
    return Result;
}


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


// InitObjectCallback — 初始化对象回调
// 对应原始驱动 sub_14000F0F4
__int64 CmdInitObjectCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)InitObjectCallbackOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessContextWin7 — Win7 枚举进程上下文命令处理
// 对应原始驱动 sub_14003A140
__int64 CmdEnumProcessContextWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessContextWin7Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetProcessContextWin7 — Win7 设置进程上下文命令处理
// 对应原始驱动 sub_14003A3AC
__int64 CmdSetProcessContextWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetProcessContextWin7Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessContextWin8 — Win8 枚举进程上下文命令处理
// 对应原始驱动 sub_140039934
__int64 CmdEnumProcessContextWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessContextWin8Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}


// CmdReadPhysicalMemory — 读取物理内存命令处理
// 对应原始驱动 sub_1400352BC
__int64 CmdReadPhysicalMemory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadPhysicalMemoryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdIoPortOperation — IO 端口操作命令处理
// 对应原始驱动 sub_14003888C
__int64 CmdIoPortOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)IoPortOperationDispatch)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdKernelMemoryOperation — 内核内存操作命令处理
// 对应原始驱动 sub_140041094
__int64 CmdKernelMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)KernelMemoryOperationDispatch)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdProcessMemoryOperation — 进程内存操作命令处理
// 对应原始驱动 sub_140043FC0
__int64 CmdProcessMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ProcessMemoryOperationDispatch)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessModules — 枚举进程模块命令处理
// 对应原始驱动 sub_1400457A4

// CmdKernelMemoryOpDispatch — 内核内存操作分发
// 对应原始驱动 sub_140042814
// 根据命令码(1-11)将清理请求分发到对应的清理子函数
__int64 CmdKernelMemoryOpDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputBuffer && InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        int *pInputBuffer = (int *)InputBuffer;
        _QWORD *pTargetPtr;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPtr = (_QWORD *)*((_QWORD *)pInputBuffer + 1);
        if ((ULONG64)pTargetPtr > (ULONG64)MmSystemRangeStart)
        {
            int CommandCode = *pInputBuffer;
            if (CommandCode > 6)
            {
                if (CommandCode == 7) return FreeObjectByCallback(pTargetPtr);
                if (CommandCode == 8) return ClearKernelMemoryPointer();
                if (CommandCode == 9) return RemoveObjectFromTypeList(pTargetPtr);
                if (CommandCode == 10) return RemoveFromObjectTypeListEx((PVOID *)pTargetPtr);
                if (CommandCode == 11) return CallKernelCleanupEntryV3(pTargetPtr);
            }
            else
            {
                if (CommandCode == 6) return EnumObjectTypeCleanupList((PVOID *)pTargetPtr);
                if (CommandCode == 1) return ClearKernelObjectEntry((__int64)pTargetPtr);
                if (CommandCode == 2) return RemoveKernelObjectEntry((__int64)pTargetPtr);
                if (CommandCode == 3) return ClearSsdtRelatedEntry((__int64)pTargetPtr);
                if (CommandCode == 4) return DispatchKernelMemoryCleanup(pTargetPtr);
                if (CommandCode == 5) return RemoveFromObjectTypeList((PVOID *)pTargetPtr);
            }
        }
    }
    return Result;
}

// CmdProcessMemoryOpDispatch — 进程内存操作分发
// 对应原始驱动 sub_140044F3C
// 根据命令码(1-9)分发到对应的释放/摘除/清理子函数
__int64 CmdProcessMemoryOpDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputBuffer && InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _DWORD *pInputBuffer = (_DWORD *)InputBuffer;
        _QWORD *pTargetPointer;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPointer = (_QWORD *)*((_QWORD *)pInputBuffer + 1);
        if ((ULONG64)pTargetPointer > (ULONG64)MmSystemRangeStart)
        {
            switch (*pInputBuffer)
            {
                case 1: return FreeProcessMemoryAllocation((__int64)pTargetPointer);
                case 2: return UnlinkProcessMemoryBlock(pTargetPointer);
                case 3: return FreeProcessMemoryBuffer(pTargetPointer);
                case 4: return DispatchFreeProcessMemory((char *)pTargetPointer);
                case 5: return CleanupProcessMemoryEntry(pTargetPointer);
                case 6: return ReleaseProcessMemoryBlock(pTargetPointer);
                case 7: return UnlinkFromMemoryBlockList((PVOID *)pTargetPointer);
                case 8: return FreeProcessMemoryAllocationEx(pTargetPointer);
                case 9: return UnlinkFromProcessMemoryList((PVOID *)pTargetPointer);
            }
        }
    }
    return Result;
}

// CmdMemoryQueryOp — 内存查询操作命令处理
// 对应原始驱动 sub_140045B0C
// 命令码 1/2 分别删除模块链表 1/2 中的条目
__int64 CmdMemoryQueryOp(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputBuffer && InputSize == 16 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        PVOID **pInputBuffer = (PVOID **)InputBuffer;
        PVOID *pTargetPointer;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPointer = pInputBuffer[1];
        if ((ULONG64)pTargetPointer > (ULONG64)MmSystemRangeStart)
        {
            if (*(_DWORD *)pInputBuffer == 1)
                return RemoveFromModuleLinkedList(pTargetPointer, 0);
            if (*(_DWORD *)pInputBuffer == 2)
                return RemoveFromModuleLinkedList(pTargetPointer, 1);
        }
    }
    return Result;
}

// CmdQuerySystemInfo — 查询系统信息命令处理
// 对应原始驱动 sub_1400496A8
// 根据构建号分发：2195/2600/3790 调用 DiskInfo 查询，>=6000 调用 QuerySystemInfoExV2，其余返回不支持
__int64 CmdQuerySystemInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber == 2195)
        return 0;
    if (BuildNumber == 2600 || BuildNumber == 3790)
        return CmdQueryDiskInfo((char *)pOutputBuffer, OutputSize);
    if (BuildNumber >= 0x1770)
        return CmdQuerySystemInfoExV2((char *)pOutputBuffer, OutputSize);
    return Result;
}

// CmdDriverProtectStatus — 驱动保护状态命令处理
// 对应原始驱动 sub_1400534B8
// 验证 168 字节输入缓冲区，偏移 160=1 时恢复服务表索引，偏移 161=1 时通过 WritePhysicalMemoryBuffer 恢复 16 字节钩子
__int64 CmdDriverProtectStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputSize == 168 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 168) < MmUserProbeAddress)
    {
        unsigned int *Address = (unsigned int *)InputBuffer;
        ProbeForRead(Address, 0xA8u, 1u);
        unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
        if (ServiceCount && *Address < ServiceCount)
        {
            char Result = 1;
            char IsServiceValid = 1;
            if (*((_BYTE *)Address + 160) == 1)
            {
                Result = 0;
                _QWORD *pServiceTable = (_QWORD *)GtRead(GtFindHookTargetFirstMatchAddr2);
                if (pServiceTable)
                {
                    Result = 1;
                    WritePhysicalMemoryDword(
                        *pServiceTable + 4LL * *Address,
                        (ULONG)(*(_DWORD *)(*pServiceTable + 4LL * *Address) & 0xF | (16 * *((_QWORD *)Address + 18) - 16 * *pServiceTable)));
                }
            }
            if (*((_BYTE *)Address + 161) == 1)
            {
                IsServiceValid = 0;
                __int64 DataBuffer = GtRead(GtEprocessField66);
                unsigned int DataBufferSize = (unsigned int)GtRead(GtEprocessField23);
                if (DataBufferSize && DataBuffer)
                {
                    __int64 DataOffset = Address[34];
                    if ((int)DataOffset + 16 <= (int)DataBufferSize)
                    {
                        _OWORD PatchedData = *(_OWORD *)(DataOffset + DataBuffer);
                        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
                        {
                            int HashTableIndex[3];
                            _OWORD JumpPatchData;
                            if (LookupDriverHashTable((__int64)(Address + 1), HashTableIndex) == 1
                                && BuildJmpPatchStub((int)*((_QWORD *)Address + 18), DataBuffer + Address[34], (__int64)&JumpPatchData, 0x10u, HashTableIndex[0]) == 1)
                            {
                                PatchedData = JumpPatchData;
                            }
                        }
                        IsServiceValid = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 18), &PatchedData, 0x10u, 0, 0);
                    }
                }
            }
            return Result & IsServiceValid;
        }
    }
    return Result;
}

// CmdDriverProtectOp — 驱动保护操作命令处理
// 对应原始驱动 sub_140051B64
// 检查 48 字节输入缓冲区，根据偏移 24=1 时调用 WritePhysicalMemoryDword 修改服务表索引，偏移 25=1 时调用 WritePhysicalMemoryBuffer 写入数据
__int64 CmdDriverProtectOp(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result = 0;
    if (InputSize == 48 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 48) < MmUserProbeAddress)
    {
        char *Address = (char *)InputBuffer;
        ProbeForRead(Address, 0x30u, 1u);
        __int64 ServiceTable = GtRead(GtEprocessField69);
        int ServiceCount = (int)GtRead(GtEprocessField57);
        if (ServiceTable && ServiceCount)
        {
            char Result2 = 1;
            if (Address[24] == 1)
                WritePhysicalMemoryDword(
                    *(_QWORD *)(ServiceTable + 32) + 4LL * *(unsigned int *)Address,
                    (ULONG)(*(_DWORD *)(*(_QWORD *)(ServiceTable + 32) + 4LL * *(unsigned int *)Address) & 0xF
                    | (16 * *((_QWORD *)Address + 1) - 16 * *(_QWORD *)(ServiceTable + 32))));
            if (Address[25] == 1)
            {
                Result2 = 0;
                if (MmIsAddressValid(*((PVOID *)Address + 1)) == 1
                    && MmIsAddressValid((PVOID)(*((_QWORD *)Address + 1) + 15LL)) == 1)
                {
                    unsigned int WriteLength = 16;
                    _OWORD PatchData = *(_OWORD *)(Address + 26);
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800 && (*(WORD *)&PatchData) == 0x25FF)
                        WriteLength = 6;
                    Result2 = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 1), &PatchData, WriteLength, 0, 0);
                }
            }
            return Result2 & 1;
        }
    }
    return Result;
}

// CmdThreadProtectStatus — 线程保护状态命令处理
// 对应原始驱动 sub_14003590C
// 检查 56 字节输入缓冲区，根据偏移 32=1 时安装 SSDT 线程保护钩子，偏移 33=1 时通过 WritePhysicalMemoryBuffer 写入 16 字节物理内存补丁
__int64 CmdThreadProtectStatus(__int64 Address, int InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result; // bl
    char HookResult; // r14
    char PatchResult; // si
    void *TargetAddress; // rcx
    _OWORD PatchData; // [rsp+38h] [rbp-30h] BYREF

    Result = 0;
    if (InputSize == 56
        && (ULONG64)Address < MmUserProbeAddress
        && (ULONG64)(Address + 56) < MmUserProbeAddress)
    {
        ProbeForRead((PVOID)Address, 0x38u, 1u);
        HookResult = 1;
        PatchResult = 1;
        if (*(char *)(Address + 32) == 1)
            HookResult = InstallSsdtHookForThreadProtect(Address);
        if (*(char *)(Address + 33) == 1)
        {
            PatchResult = 0;
            TargetAddress = (void *)*(__int64 *)(Address + 16);
            if (TargetAddress)
            {
                if (MmIsAddressValid(TargetAddress) == 1
                    && MmIsAddressValid((PVOID)(*(__int64 *)(Address + 16) + 15)) == 1)
                {
                    PatchData = *(_OWORD *)(Address + 40);
                    PatchResult = WritePhysicalMemoryBuffer((unsigned __int64)TargetAddress, &PatchData, 0x10u, 0, 0);
                }
            }
        }
        return HookResult & PatchResult;
    }
    return Result;
}

// CmdEnumProcessHandles — 枚举进程句柄命令处理
// 对应原始驱动 sub_140085010
// 根据进程ID枚举指定进程的所有句柄及详细信息
__int64 CmdEnumProcessHandles(__int64 Address, int InputSize, _DWORD *OutputBuffer, unsigned int OutputBufferSize)
{
    char Result; // bl
    _OWORD InputData; // xmm6, 保存原始输入数据
    NTSTATUS Status; // eax
    int ProcessLookupResult; // r15d
    PEPROCESS TargetProcess; // rdx
    unsigned int *SystemInfo; // rsi
    PEPROCESS Process; // [rsp+30h] [rbp-38h] BYREF
    _OWORD ProcessData; // [rsp+38h] [rbp-30h] BYREF, 传递给 EnumProcessHandleInfo 的数据

    Result = 0;
    if (InputSize == 16
        && OutputBufferSize >= 0x258
        && (ULONG64)Address < MmUserProbeAddress
        && (ULONG64)(Address + 16) < MmUserProbeAddress
        && (ULONG64)OutputBuffer < MmUserProbeAddress
        && (ULONG64)OutputBuffer + OutputBufferSize < MmUserProbeAddress)
    {
        ProbeForRead((PVOID)Address, 0x10u, 1u);
        ProbeForWrite(OutputBuffer, OutputBufferSize, 1u);
        InputData = *(_OWORD *)Address;
        ProcessData = InputData;
        *OutputBuffer = 0;
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        ProcessLookupResult = Status;
        TargetProcess = (PEPROCESS)InputData.qword[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = Process;
            ProcessData.qword[1] = (__int64)TargetProcess;
        }
        SystemInfo = (unsigned int *)AllocExBufferAndQuerySystemInfo(0x10u);
        if (SystemInfo)
        {
            *OutputBuffer = (_DWORD)EnumProcessHandleInfo((_QWORD *)&ProcessData, SystemInfo, (_OWORD *)(OutputBuffer + 2), (OutputBufferSize - 8) / 0x250);
            ExFree(SystemInfo);
            Result = *OutputBuffer != 0;
        }
        if (ProcessLookupResult >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}

// CmdQueryProcessInfoEx — 查询进程信息扩展命令处理
// 对应原始驱动 sub_140084D3C
// 扩展的进程信息查询：根据进程ID查找进程，调用关闭进程句柄扩展函数
__int64 CmdQueryProcessInfoEx(__int64 Address, int InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    char Result; // bl
    NTSTATUS Status; // edi
    PEPROCESS Process; // rax
    PEPROCESS ProcessLookup; // [rsp+28h] [rbp-50h] BYREF
    _OWORD InputData; // [rsp+30h] [rbp-48h]
    _OWORD OutputData[2]; // [rsp+40h] [rbp-38h] BYREF
    __int64 SavedValue; // [rsp+60h] [rbp-18h]

    Result = 0;
    if (InputSize == 40
        && (ULONG64)Address < MmUserProbeAddress
        && (ULONG64)(Address + 40) < MmUserProbeAddress)
    {
        ProbeForRead((PVOID)Address, 0x28u, 1u);
        InputData = *(_OWORD *)Address;
        OutputData[0] = *(_OWORD *)&InputData;
        OutputData[1] = *(_OWORD *)(Address + 16);
        SavedValue = *(__int64 *)(Address + 32);
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &ProcessLookup);
        Process = (PEPROCESS)InputData.qword[1];
        if (!Process)
        {
            if (Status >= 0)
                Process = ProcessLookup;
            *((__int64 *)&OutputData[0] + 1) = (__int64)Process;
        }
        Result = CmdCloseProcessHandleEx((__int64)OutputData);
        if (!Status)
            ObfDereferenceObject(ProcessLookup);
    }
    return Result;
}

// CmdEnumObjectAllTypes — 枚举所有对象类型命令处理
// 对应原始驱动 sub_140009838
// 枚举所有驱动对象、设备对象、文件系统设备和特定驱动路径，整理到输出缓冲区
__int64 CmdEnumObjectAllTypes(__int64 OutputBuffer, __int64 OutputSize, char *UserBuffer, unsigned int UserBufferSize)
{
    char Result; // di
    unsigned __int64 TotalSize; // rbx
    unsigned __int64 MaxEntries; // rbx
    int DeviceCount; // esi
    char *DevicePtr; // rdi
    int DriverObjectDevice; // eax
    int TotalCount; // esi
    __int64 DevicePtr2; // rdi
    unsigned int FileSystemDriverObject; // eax
    int TotalCount2; // esi
    __int64 DevicePtr3; // rdi
    unsigned int FileSysCount; // eax
    int TotalCount3; // esi
    __int64 DevicePtr4; // rdi
    unsigned int KbdClassCount; // eax
    int TotalCount4; // esi
    __int64 DevicePtr5; // rdi
    unsigned int I8042prtCount; // eax
    int TotalCount5; // esi
    __int64 DevicePtr6; // rdi
    int RemainingCount; // ebx
    __int64 TcpipDriverObject; // r14
    __int64 DevicePtr7; // rdi
    int RemainingCount2; // ebx
    unsigned int VolmgrDriverObject; // eax
    __int64 DevicePtr8; // rdi
    int RemainingCount3; // ebx
    unsigned int MouClassCount; // eax
    int TotalCount6; // esi
    __int64 DevicePtr9; // rdi
    int RemainingCount4; // ebx
    unsigned int NdisDriverObject; // eax
    unsigned int PnpCount; // esi

    Result = 0;
    if (UserBufferSize >= 0x838 && (ULONG64)UserBuffer < MmUserProbeAddress)
    {
        TotalSize = UserBufferSize;
        if ((ULONG64)(UserBuffer + UserBufferSize) < MmUserProbeAddress)
        {
            ProbeForWrite(UserBuffer, UserBufferSize, 1u);
            memset(UserBuffer, 0, (unsigned int)TotalSize);
            MaxEntries = TotalSize / 0x838;
            DeviceCount = EnumDeviceObjects(UserBuffer, (unsigned int)MaxEntries);
            DevicePtr = &UserBuffer[2104 * DeviceCount];
            MaxEntries = MaxEntries - DeviceCount;
            DriverObjectDevice = QueryDriverObjectDevice((__int64)DevicePtr, (int)MaxEntries);
            TotalCount = DriverObjectDevice + DeviceCount;
            DevicePtr2 = (__int64)&DevicePtr[2104 * DriverObjectDevice];
            MaxEntries = MaxEntries - DriverObjectDevice;
            FileSystemDriverObject = QueryFileSystemDriverObject(DevicePtr2, (int)MaxEntries);
            TotalCount2 = FileSystemDriverObject + TotalCount;
            DevicePtr3 = 2104LL * FileSystemDriverObject + DevicePtr2;
            MaxEntries = MaxEntries - FileSystemDriverObject;
            FileSysCount = EnumFileSystemDeviceObjects(DevicePtr3, (int)MaxEntries);
            TotalCount3 = FileSysCount + TotalCount2;
            DevicePtr4 = 2104LL * FileSysCount + DevicePtr3;
            MaxEntries = MaxEntries - FileSysCount;
            KbdClassCount = BuildDriverPathKbdClass(DevicePtr4, (int)MaxEntries);
            TotalCount4 = KbdClassCount + TotalCount3;
            DevicePtr5 = 2104LL * KbdClassCount + DevicePtr4;
            MaxEntries = MaxEntries - KbdClassCount;
            I8042prtCount = BuildDriverPathI8042prt(DevicePtr5, (int)MaxEntries);
            TotalCount5 = I8042prtCount + TotalCount4;
            DevicePtr6 = 2104LL * I8042prtCount + DevicePtr5;
            RemainingCount = (int)MaxEntries - (int)I8042prtCount;
            TcpipDriverObject = (unsigned int)QueryTcpipDriverObject(DevicePtr6, RemainingCount);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
            {
                DevicePtr7 = 2104 * TcpipDriverObject + DevicePtr6;
                RemainingCount2 = RemainingCount - (int)TcpipDriverObject;
                VolmgrDriverObject = QueryVolmgrDriverObject(DevicePtr7, RemainingCount2);
                TotalCount5 += (int)VolmgrDriverObject + (int)TcpipDriverObject;
                DevicePtr6 = 2104LL * VolmgrDriverObject + DevicePtr7;
                RemainingCount = RemainingCount2 - VolmgrDriverObject;
                TcpipDriverObject = QueryTdxDriverObject(DevicePtr6, RemainingCount);
            }
            DevicePtr8 = 2104LL * (unsigned int)TcpipDriverObject + DevicePtr6;
            RemainingCount3 = RemainingCount - (int)TcpipDriverObject;
            MouClassCount = BuildDriverPathMouClass(DevicePtr8, RemainingCount3);
            TotalCount6 = (int)MouClassCount + (int)TcpipDriverObject + TotalCount5;
            DevicePtr9 = 2104LL * MouClassCount + DevicePtr8;
            RemainingCount4 = RemainingCount3 - MouClassCount;
            NdisDriverObject = QueryNdisDriverObject(DevicePtr9, RemainingCount4);
            PnpCount = QueryPnpManagerDriverObject(2104LL * NdisDriverObject + DevicePtr9, RemainingCount4 - NdisDriverObject)
                     + NdisDriverObject
                     + TotalCount6;
            if (PnpCount)
                NormalizeModulePaths((__int64)UserBuffer, PnpCount);
            return 1;
        }
    }
    return Result;
}

// CmdObjectOperationDispatch — 对象操作分发
// 对应原始驱动 sub_140009AD8
__int64 CmdObjectOperationDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ObjectOperationDispatcher)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDeviceIoControlEx — 设备 IO 控制扩展命令处理
// 对应原始驱动 sub_140074EF8
__int64 CmdDeviceIoControlEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeviceIoControlExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdFsctlOperation — 文件系统控制操作命令处理
// 对应原始驱动 sub_140073DF4
__int64 CmdFsctlOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)FileSystemControlOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadProcessMemoryStr — 读取进程内存字符串命令处理
// 对应原始驱动 sub_140074418
__int64 CmdReadProcessMemoryStr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadProcessMemoryString)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdWriteProcessMemoryEx — 写入进程内存扩展命令处理
// 对应原始驱动 sub_1400749A0
__int64 CmdWriteProcessMemoryEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)WriteProcessMemoryExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDeviceIoControlSimple — 简单设备 IO 控制命令处理
// 对应原始驱动 sub_1400751D4
__int64 CmdDeviceIoControlSimple(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeviceIoControlSimpleOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDeviceIoControlWithBuffer — 带缓冲设备 IO 控制命令处理
// 对应原始驱动 sub_1400753A4
__int64 CmdDeviceIoControlWithBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeviceIoControlWithBufferOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDeviceIoControlWithString — 带字符串设备 IO 控制命令处理
// 对应原始驱动 sub_14007562C
__int64 CmdDeviceIoControlWithString(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeviceIoControlWithStringOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdOpenSectionObject — 打开节区对象命令处理
// 对应原始驱动 sub_140074128
__int64 CmdOpenSectionObject(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)OpenSectionObjectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCreateFile — 创建文件命令处理
// 对应原始驱动 sub_140074258

// CmdEnumHandlesByPid — 按 PID 枚举句柄命令处理
// 对应原始驱动 sub_1400858B8

// CmdCreateFileWithPath — 按路径创建文件命令处理
// 对应原始驱动 sub_14002D2EC
__int64 CmdCreateFileWithPath(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CreateFileWithPathOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCloseHandle — 关闭句柄命令处理
// 对应原始驱动 sub_14002C430
__int64 CmdCloseHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CloseHandleOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQueryFileInfo — 查询文件信息命令处理
// 对应原始驱动 sub_14002D12C
__int64 CmdQueryFileInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryFileInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdOpenFileHandle — 打开文件句柄命令处理
// 对应原始驱动 sub_14002D070
__int64 CmdOpenFileHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)OpenFileHandleOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadFileSize — 读取文件大小命令处理
// 对应原始驱动 sub_14002D858
__int64 CmdReadFileSize(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadFileSizeOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdWriteFile — 写入文件命令处理
// 对应原始驱动 sub_14002D418
__int64 CmdWriteFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)WriteFileOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadFile — 读取文件命令处理
// 对应原始驱动 sub_14002D8F0
__int64 CmdReadFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadFileOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadDirectory — 读取目录命令处理
// 对应原始驱动 sub_14002CD7C
__int64 CmdReadDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadDirectoryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumDirectory — 枚举目录命令处理
// 对应原始驱动 sub_14002C96C
__int64 CmdEnumDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumDirectoryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// EnableObjectCallback — 启用对象回调
// 对应原始驱动 sub_1400819C4
__int64 CmdEnableObjectCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnableObjectCallbackOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdRenameFile — 重命名文件命令处理
// 对应原始驱动 sub_14002D52C
__int64 CmdRenameFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)RenameFileOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCopyFile — 复制文件命令处理
// 对应原始驱动 sub_14002C528
__int64 CmdCopyFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CopyFileOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdOpenFileForEnum — 打开文件供枚举命令处理
// 对应原始驱动 sub_14002C840
__int64 CmdOpenFileForEnum(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)OpenFileForEnumOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDeleteFile — 删除文件命令处理
// 对应原始驱动 sub_14002CEDC
__int64 CmdDeleteFile(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeleteFileOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetFileAttributes — 设置文件属性命令处理
// 对应原始驱动 sub_14002D6D8
__int64 CmdSetFileAttributes(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetFileAttributesOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCheckFileExist — 检查文件存在命令处理
// 对应原始驱动 sub_14002CC50
__int64 CmdCheckFileExist(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CheckFileExistOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// PowerCallbackUnregister — 注销电源回调
// 对应原始驱动 sub_140081A34
__int64 CmdPowerCallbackUnregister(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)PowerCallbackUnregisterOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// ShutdownCallbackUnregister — 注销关机回调
// 对应原始驱动 sub_140081A42
__int64 CmdShutdownCallbackUnregister(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ShutdownCallbackUnregisterOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// PowerCallbackRoutine — 电源回调例程
// 对应原始驱动 sub_140081A50
__int64 CmdPowerCallbackRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)PowerCallbackRoutineOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// RegNotifyCallback — 注册表通知回调
// 对应原始驱动 sub_140081A5E
__int64 CmdRegNotifyCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)RegNotifyCallbackOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// DisableThreadProtect — 禁用线程保护
// 对应原始驱动 sub_140081A6C
__int64 CmdDisableThreadProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DisableThreadProtectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// EnableThreadProtect — 启用线程保护
// 对应原始驱动 sub_140081A7A
__int64 CmdEnableThreadProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnableThreadProtectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQuerySystemInfoEx — 查询系统信息扩展命令处理
// 对应原始驱动 sub_14006EC24
__int64 CmdQuerySystemInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QuerySystemInfoExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCallbackControl — 回调控制命令处理
// 对应原始驱动 sub_140070190
__int64 CmdCallbackControl(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CallbackControlOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadCpuMsr — 读取 CPU MSR 命令处理
// 对应原始驱动 sub_14002A358
__int64 CmdReadCpuMsr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadCpuMsrOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadCpuId — 读取 CPU ID 命令处理
// 对应原始驱动 sub_14002B304
__int64 CmdReadCpuId(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadCpuIdOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadCpuBaseAddr — 读取 CPU 基地址命令处理
// 对应原始驱动 sub_14002A45C
__int64 CmdReadCpuBaseAddr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadCpuBaseAddrOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadCpuInfoEx — 读取 CPU 信息扩展命令处理
// 对应原始驱动 sub_14002B36C
__int64 CmdReadCpuInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadCpuInfoExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadCpuBaseAddrEx — 读取 CPU 基地址扩展命令处理
// 对应原始驱动 sub_14002B944
__int64 CmdReadCpuBaseAddrEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadCpuBaseAddrExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdStubAlwaysTrue — 固定返回 1 的桩函数
// 对应原始驱动 sub_14002BA38
__int64 CmdStubAlwaysTrue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return 1;
}

// CmdGetKernelBaseLegacy — 获取内核基址（旧版）命令处理
// 对应原始驱动 sub_14002B8DC
__int64 CmdGetKernelBaseLegacy(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)GetKernelBaseLegacyOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQueryProcessNameByPid — 按 PID 查询进程名命令处理
// 对应原始驱动 sub_140084E14
__int64 CmdQueryProcessNameByPid(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryProcessNameByPidOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjectDirectory — 枚举对象目录命令处理
// 对应原始驱动 sub_140084618
__int64 CmdEnumObjectDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectDirectoryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCloseProcessHandle — 关闭进程句柄命令处理
// 对应原始驱动 sub_140084154

// CmdEnumObjectHandles — 枚举对象句柄命令处理
// 对应原始驱动 sub_140054C38

// CmdTerminateProcessByEProcess — 通过 EPROCESS 终止进程命令处理
// 对应原始驱动 sub_1400543FC
__int64 CmdTerminateProcessByEProcess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)TerminateProcessByEProcessOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQueryObjectInfo — 查询对象信息命令处理
// 对应原始驱动 sub_140083A84
__int64 CmdQueryObjectInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryObjectInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumSyscallEntries — 枚举系统调用条目命令处理
// 对应原始驱动 sub_1400538C8

// CmdInstallSystemHook — 安装系统钩子命令处理
// 对应原始驱动 sub_1400539FC

// CmdEnumShadowSyscallEntries — 枚举影子系统调用条目命令处理
// 对应原始驱动 sub_14003D464

// CmdInstallShadowHook — 安装影子钩子命令处理
// 对应原始驱动 sub_14003D6C4

// CmdEnumSyscallTable2 — 枚举系统调用表 2 命令处理
// 对应原始驱动 sub_1400338A0

// CmdInstallSyscallHook2 — 安装系统调用钩子 2 命令处理
// 对应原始驱动 sub_140033B38

// CmdEnumSyscallTable3 — 枚举系统调用表 3 命令处理
// 对应原始驱动 sub_140032D40

// CmdInstallSyscallHook3 — 安装系统调用钩子 3 命令处理
// 对应原始驱动 sub_140032FE0

// CmdEnumSyscallTable4 — 枚举系统调用表 4 命令处理
// 对应原始驱动 sub_1400316E0

// CmdInstallSyscallHook4 — 安装系统调用钩子 4 命令处理
// 对应原始驱动 sub_140031934

// CmdEnumSyscallTable5 — 枚举系统调用表 5 命令处理
// 对应原始驱动 sub_140050AC0

// CmdInstallSyscallHook5 — 安装系统调用钩子 5 命令处理
// 对应原始驱动 sub_140050D64

// CmdEnumSyscallTable6 — 枚举系统调用表 6 命令处理
// 对应原始驱动 sub_14003DD2C

// CmdInstallSyscallHook6 — 安装系统调用钩子 6 命令处理
// 对应原始驱动 sub_14003DF8C

// CmdEnumSyscallTable7 — 枚举系统调用表 7 命令处理
// 对应原始驱动 sub_140046C2C

// CmdInstallSyscallHook7 — 安装系统调用钩子 7 命令处理
// 对应原始驱动 sub_140046EA4

// CmdEnumSyscallTable8 — 枚举系统调用表 8 命令处理
// 对应原始驱动 sub_140054050

// CmdInstallSyscallHook8 — 安装系统调用钩子 8 命令处理
// 对应原始驱动 sub_1400542B4

// CmdEnumGdiObjects — 枚举 GDI 对象命令处理
// 对应原始驱动 sub_14006D3A8

// CmdCheckProcessHideDetect — 检查进程隐藏检测命令处理
// 对应原始驱动 sub_1400331FC
__int64 CmdCheckProcessHideDetect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CheckProcessHideDetectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdFixProcessEProcess — 修复进程 EPROCESS 命令处理
// 对应原始驱动 sub_140033C68
__int64 CmdFixProcessEProcess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)FixProcessEProcessOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDiskReadSector — 磁盘读取扇区命令处理
// 对应原始驱动 sub_14007B854
__int64 CmdDiskReadSector(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DiskReadSectorOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDiskOperationDispatch — 磁盘操作分发
// 对应原始驱动 sub_14007C980
__int64 CmdDiskOperationDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DiskOperationDispatcher)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdDiskSectorReadWrite — 磁盘扇区读写命令处理
// 对应原始驱动 sub_14007B72C
__int64 CmdDiskSectorReadWrite(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DiskSectorReadWriteOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjectTypes — 枚举对象类型命令处理
// 对应原始驱动 sub_14007EDC8
__int64 CmdEnumObjectTypes(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectTypeInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumKernelObjectTable — 枚举内核对象表命令处理
// 对应原始驱动 sub_140029964
__int64 CmdEnumKernelObjectTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelObjectTableOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdWriteKernelObjectField — 写入内核对象字段命令处理
// 对应原始驱动 sub_140029C74
__int64 CmdWriteKernelObjectField(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)WriteKernelObjectFieldOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// ProcessCallbackRoutine — 进程回调例程
// 对应原始驱动 sub_140081A88
__int64 CmdProcessCallbackRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ProcessCallbackRoutine)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// InitProcessCallback — 初始化进程回调
// 对应原始驱动 sub_1400106C0
__int64 CmdInitProcessCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return InitProcessCallback((struct _KPROCESS **)InputSize, OutputSize);
}

// CmdEnumProcessListEx — 扩展枚举进程列表命令处理
// 对应原始驱动 sub_140062ED8
__int64 CmdEnumProcessListEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessListExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessListWin7 — Win7 枚举进程列表命令处理
// 对应原始驱动 sub_14005A5E8
__int64 CmdEnumProcessListWin7(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessListWin7Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessListWin8 — Win8 枚举进程列表命令处理
// 对应原始驱动 sub_14005C6B0
__int64 CmdEnumProcessListWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessListWin8Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessListWin10 — Win10 枚举进程列表命令处理
// 对应原始驱动 sub_14005E354
__int64 CmdEnumProcessListWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessListWin10Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumKernelHandleTable — 枚举内核句柄表命令处理
// 对应原始驱动 sub_140067278
__int64 CmdEnumKernelHandleTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelHandleTableOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdGetSsdtTableInfo — 获取 SSDT 表信息命令处理
// 对应原始驱动 sub_140067DBC

// CmdRestoreSsdtTable — 恢复 SSDT 表命令处理
// 对应原始驱动 sub_140068054

// CmdEnumObjectTypeInfo — 枚举对象类型信息命令处理
// 对应原始驱动 sub_14007EDC8
__int64 CmdEnumObjectTypeInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectTypeInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdLookupObjectTypeByAddr — 按地址查找对象类型命令处理
// 对应原始驱动 sub_14007ECCC
__int64 CmdLookupObjectTypeByAddr(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)LookupObjectTypeByAddrOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQuerySsdtDetails — 查询 SSDT 详情命令处理
// 对应原始驱动 sub_140067428

// CmdSetSsdtEntry — 设置 SSDT 条目命令处理
// 对应原始驱动 sub_140067664

// CmdReadExportDirectory — 读取导出目录命令处理
// 对应原始驱动 sub_1400608E4

// CmdUpdateExportEntry — 更新导出条目命令处理
// 对应原始驱动 sub_140060AF4

// CmdRestoreExportTable — 恢复导出表命令处理
// 对应原始驱动 sub_140060C68

// CmdInitSsdtTable — 初始化 SSDT 表命令处理
// 对应原始驱动 sub_140060A68

// CmdCopyKernelArrayToUserBuffer — 复制内核数组到用户缓冲区
// 对应原始驱动 sub_140071F6C
__int64 CmdCopyKernelArrayToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CopyKernelArrayToUserBufferOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumKernelMemoryContext — 枚举内核内存上下文
// 对应原始驱动 sub_140071FCC
__int64 CmdEnumKernelMemoryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelMemoryContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// InvokeRegisteredCallbackWithUserData — 调用注册的回调
// 对应原始驱动 sub_1400680F8
// (already implemented in DriverEntry.c)

// CmdCopyKernelDualArrayToUserBuffer — 复制内核双数组到用户缓冲区
// 对应原始驱动 sub_1400720B0
__int64 CmdCopyKernelDualArrayToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CopyKernelDualArrayToUserBufferOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadKernelMemoryToUserBuffer — 读取内核内存到用户缓冲区
// 对应原始驱动 sub_1400721B0
__int64 CmdReadKernelMemoryToUserBuffer(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadKernelMemoryToUserBufferOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdInitKernelMemoryContext — 初始化内核内存上下文命令处理
// 对应原始驱动 sub_1400681DC
__int64 CmdInitKernelMemoryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)InitKernelMemoryContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadKernelMemoryRange — 读取内核内存范围命令处理
// 对应原始驱动 sub_14006BBB8
__int64 CmdReadKernelMemoryRange(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadKernelMemoryRangeOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadKernelMemoryRangeSize — 读取内核内存范围大小命令处理
// 对应原始驱动 sub_14006BA98
__int64 CmdReadKernelMemoryRangeSize(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadKernelMemoryRangeSizeOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdWriteKernelMemoryRange — 写入内核内存范围命令处理
// 对应原始驱动 sub_14006C510

// CmdEnumKernelMemoryDetail — 枚举内核内存详情命令处理
// 对应原始驱动 sub_14006B708
__int64 CmdEnumKernelMemoryDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelMemoryDetailOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCallKernelMemoryFunction — 调用内核内存函数命令处理
// 对应原始驱动 sub_14006C42C

// CmdEnumObjectTypeDirectory — 枚举对象类型目录命令处理
// 对应原始驱动 sub_14006AC54
__int64 CmdEnumObjectTypeDirectory(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectTypeDirectoryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjectTypeTable — 枚举对象类型表命令处理
// 对应原始驱动 sub_14006B0AC
__int64 CmdEnumObjectTypeTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectTypeTableOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjectTypeDetail — 枚举对象类型详情命令处理
// 对应原始驱动 sub_14006B49C
__int64 CmdEnumObjectTypeDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectTypeDetailOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadSsdtEntryTable — 读取 SSDT 条目表命令处理
// 对应原始驱动 sub_140028E60

// CmdReadSsdtEntryTableEx — 读取 SSDT 条目表扩展命令处理
// 对应原始驱动 sub_140029020

// CmdDispatchSsdtByVersion — 按版本分发 SSDT 命令处理
// 对应原始驱动 sub_140028B18

// CmdFixSsdtEntryAddress — 修复 SSDT 条目地址命令处理
// 对应原始驱动 sub_1400295B8

// CmdEnumSsdtEntryTable — 枚举 SSDT 条目表命令处理
// 对应原始驱动 sub_14002916C

// CmdReadMsrValue — 读取 MSR 值命令处理
// 对应原始驱动 sub_140030268
__int64 CmdReadMsrValue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadMsrValueOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdWriteMsrValue — 写入 MSR 值命令处理
// 对应原始驱动 sub_140030F8C
__int64 CmdWriteMsrValue(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)WriteMsrValueOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessorInfo — 枚举处理器信息命令处理
// 对应原始驱动 sub_14002FDD4
__int64 CmdEnumProcessorInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessorInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetProcessorField — 设置处理器字段命令处理
// 对应原始驱动 sub_140030420
__int64 CmdSetProcessorField(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetProcessorFieldOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// InitFileSystemCallback — 初始化文件系统回调
// 对应原始驱动 sub_14000D704
__int64 CmdInitFileSystemCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)InitFileSystemCallbackOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// InitFileSystemFilter — 初始化文件系统过滤器
// 对应原始驱动 sub_14000EB40
__int64 CmdInitFileSystemFilter(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)InitFileSystemFilterOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// FileSystemFilterCallback — 文件系统过滤回调
// 对应原始驱动 sub_14000DAF0
__int64 CmdFileSystemFilterCallback(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)FileSystemFilterCallbackOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCallSystemRoutine — 调用系统例程命令处理
// 对应原始驱动 sub_1400776D8
__int64 CmdCallSystemRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CallSystemRoutineOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdResetDriverState — 重置驱动状态命令处理
// 对应原始驱动 sub_140077758
__int64 CmdResetDriverState(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ResetDriverStateOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumHookInfo — 枚举钩子信息命令处理
// 对应原始驱动 sub_140086AB0
__int64 CmdEnumHookInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumHookInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdCheckBytePattern — 检查字节模式命令处理
// 对应原始驱动 sub_140086FD0
__int64 CmdCheckBytePattern(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)CheckBytePatternOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdGetHookEntryInfo — 获取钩子条目信息命令处理
// 对应原始驱动 sub_140086CD4
__int64 CmdGetHookEntryInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)GetHookEntryInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQueryHookStatus — 查询钩子状态命令处理
// 对应原始驱动 sub_140087074
__int64 CmdQueryHookStatus(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryHookStatusOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumHookDetail — 枚举钩子详情命令处理
// 对应原始驱动 sub_140087DCC
__int64 CmdEnumHookDetail(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumHookDetailOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// // CmdSetProcessContextWin8 — Win8 设置进程上下文命令处理
// 对应原始驱动 sub_140039C48
__int64 CmdSetProcessContextWin8(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetProcessContextWin8Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadKernelBase — 读取内核基址命令处理
// 对应原始驱动 sub_14002BA3C
__int64 CmdReadKernelBase(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ReadKernelBaseOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdClearKernelBase — 清除内核基址命令处理
// 对应原始驱动 sub_14002BB1C
__int64 CmdClearKernelBase(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ClearKernelBaseOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumKernelModuleInfoEx — 枚举内核模块信息扩展命令处理
// 对应原始驱动 sub_14002BE50
__int64 CmdEnumKernelModuleInfoEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelModuleInfoExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetKernelModuleInfo — 设置内核模块信息命令处理
// 对应原始驱动 sub_14002BF90
__int64 CmdSetKernelModuleInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetKernelModuleInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessContextWin10 — Win10 枚举进程上下文命令处理
// 对应原始驱动 sub_140032180
__int64 CmdEnumProcessContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessContextWin10Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetProcessContextWin10 — Win10 设置进程上下文命令处理
// 对应原始驱动 sub_140032480
__int64 CmdSetProcessContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetProcessContextWin10Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumRegistryContext — 枚举注册表上下文命令处理
// 对应原始驱动 sub_1400460B8
__int64 CmdEnumRegistryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumRegistryContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetRegistryContext — 设置注册表上下文命令处理
// 对应原始驱动 sub_14004630C
__int64 CmdSetRegistryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetRegistryContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumFileSystemContext — 枚举文件系统上下文命令处理
// 对应原始驱动 sub_14003E71C
__int64 CmdEnumFileSystemContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumFileSystemContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetFileSystemContext — 设置文件系统上下文命令处理
// 对应原始驱动 sub_14003E970
__int64 CmdSetFileSystemContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetFileSystemContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumUSBPortSyscallTable — 枚举 USB 端口系统调用表命令处理
// 对应原始驱动 sub_140055A60
__int64 CmdEnumUSBPortSyscallTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumUSBPortSyscallTableOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdInstallUSBPortSyscallHook — 安装 USB 端口系统调用钩子命令处理
// 对应原始驱动 sub_140055CBC
__int64 CmdInstallUSBPortSyscallHook(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)InstallUSBPortSyscallHookOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjectContext — 枚举对象上下文命令处理
// 对应原始驱动 sub_140037BD8
__int64 CmdEnumObjectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetObjectContext — 设置对象上下文命令处理
// 对应原始驱动 sub_140037E54
__int64 CmdSetObjectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetObjectContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumProcessProtectContext — 枚举进程保护上下文命令处理
// 对应原始驱动 sub_1400474D8
__int64 CmdEnumProcessProtectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumProcessProtectContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetProcessProtectContext — 设置进程保护上下文命令处理
// 对应原始驱动 sub_140047734
__int64 CmdSetProcessProtectContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetProcessProtectContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumCallbackContext — 枚举回调上下文命令处理
// 对应原始驱动 sub_14003602C
__int64 CmdEnumCallbackContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumCallbackContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetCallbackContext — 设置回调上下文命令处理
// 对应原始驱动 sub_1400362C8
__int64 CmdSetCallbackContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetCallbackContextOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumThreadContextWin10 — Win10 枚举线程上下文命令处理
// 对应原始驱动 sub_140057214
__int64 CmdEnumThreadContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumThreadContextWin10Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdSetThreadContextWin10 — Win10 设置线程上下文命令处理
// 对应原始驱动 sub_140057470
__int64 CmdSetThreadContextWin10(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)SetThreadContextWin10Operation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// DisableObjectProtect — 禁用对象保护
// 对应原始驱动 sub_140081A6C
__int64 CmdDisableObjectProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DisableObjectProtectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// EnableObjectProtect — 启用对象保护
// 对应原始驱动 sub_140081A7A
__int64 CmdEnableObjectProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnableObjectProtectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// KernelNotifyRoutine — 内核通知例程
// 对应原始驱动 sub_140081BA0
__int64 CmdKernelNotifyRoutine(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)KernelNotifyRoutineOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// KernelNotifyRoutineEx — 内核通知例程扩展
// 对应原始驱动 sub_140081C00
__int64 CmdKernelNotifyRoutineEx(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)KernelNotifyRoutineExOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdRestoreDriverDispatch — 恢复驱动分发命令处理
// 对应原始驱动 sub_140081280
__int64 CmdRestoreDriverDispatch(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)RestoreDriverDispatchOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumRegistry — 枚举注册表命令处理
// 对应原始驱动 sub_14007E1E0
__int64 CmdEnumRegistry(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumRegistryOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdRegistryOperation — 注册表操作命令处理
// 对应原始驱动 sub_14007EA14
__int64 CmdRegistryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)RegistryOperationDispatch)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdRegistryProtect — 注册表保护命令处理
// 对应原始驱动 sub_14007E498
__int64 CmdRegistryProtect(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)RegistryProtectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumServices — 枚举服务命令处理
// 对应原始驱动 sub_1400561BC
__int64 CmdEnumServices(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumServicesOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumServiceTable — 枚举服务表命令处理
// 对应原始驱动 sub_140055DEC
__int64 CmdEnumServiceTable(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumServiceTableOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumObjects — 枚举对象命令处理
// 对应原始驱动 sub_140036CF8
__int64 CmdEnumObjects(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumObjectsOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdObjectOperation — 对象操作命令处理
// 对应原始驱动 sub_1400363F8
__int64 CmdObjectOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ObjectOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdEnumKernelInfo — 枚举内核信息命令处理
// 对应原始驱动 sub_140088720
__int64 CmdEnumKernelInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)EnumKernelInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdQueryMemoryInfo — 查询内存信息命令处理
// 对应原始驱动 sub_140084F34
__int64 CmdQueryMemoryInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryMemoryInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdReadProcessMemoryEx — 读取进程内存扩展命令处理
// 对应原始驱动 sub_140071470

// CmdDeviceIoControl — 设备 IO 控制命令处理
// 对应原始驱动 sub_140070F74
__int64 CmdDeviceIoControl(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)DeviceIoControlOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdVirtualMemoryOp — 虚拟内存操作命令处理
// 对应原始驱动 sub_1400715C0

// CmdProcessMonitor — 进程监控命令处理
// 对应原始驱动 sub_140070D1C

// CmdEnumThreadsEx — 枚举线程扩展命令处理
// 对应原始驱动 sub_14004CE68

// CmdQueryModuleInfo — 查询模块信息命令处理
// 对应原始驱动 sub_140057D40
__int64 CmdQueryModuleInfo(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)QueryModuleInfoOperation)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdModuleOperation — 模块操作命令处理
// 对应原始驱动 sub_140058890
__int64 CmdModuleOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    return ((PCOMMAND_HANDLER)ModuleOperationDispatch)(InputBuffer, InputSize, pOutputBuffer, OutputSize);
}

// CmdHandleStreamProcessInput — Minifilter 流句柄
// 对应原始驱动 sub_14001AB5C
// 读取 40 字节输入(ProcessId + EPROCESS + StreamData + StreamContext)，验证后调用 MiniFilterStreamHandleEx
__int64 CmdMiniFilterStreamHandle(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;
    if (InputBuffer && InputSize == 40 && (ULONG64)InputBuffer < MmUserProbeAddress && (ULONG64)(InputBuffer + 40) < MmUserProbeAddress)
    {
        _OWORD InputData;
        __int64 StreamDataLow;
        __int64 StreamDataHigh;
        __int64 StreamContext;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        struct _KPROCESS *CurrentProcess;
        PEPROCESS Process;

        ProbeForRead((PVOID)InputBuffer, 0x28u, 4u);
        InputData = *(_OWORD *)InputBuffer;
        StreamDataLow = *((__int64 *)InputBuffer + 2);
        StreamDataHigh = *((__int64 *)InputBuffer + 3);
        StreamContext = *((__int64 *)InputBuffer + 4);
        TargetProcess = (struct _KPROCESS *)InputData.qword[1];
        CurrentProcess = TargetProcess;
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        Status2 = Status;
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
            CurrentProcess = TargetProcess;
        }
        if (ValidateProcessObject(TargetProcess, 0) == 1
            && (ULONG64)StreamDataLow < MmUserProbeAddress
            && (ULONG64)StreamDataHigh < MmUserProbeAddress)
        {
            Result = MiniFilterStreamHandleEx(TargetProcess, StreamDataLow, StreamDataHigh, StreamContext);
        }
        if (Status2 >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
}
