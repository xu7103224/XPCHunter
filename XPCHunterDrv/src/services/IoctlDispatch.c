// IoctlDispatch.c — IOCTL 命令分发
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动 InitCommandHandlerTable sub_1400815B0
// 功能：分配命令处理函数表（GtAlloc + 0x8D8 字节），填充全部 ~282 个命令处理函数指针

#include "..\inc\XPCHunterDrv.h"
#pragma intrinsic(__readmsr, __writemsr)
// Forward declarations
__int64 InitMiniFilterDriver(PDRIVER_OBJECT DriverObject);
// 回调控制操作子函数前向声明（定义见 TailHelpers.c / MemoryOps.c）
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
    /* 【2026-10-29 二次修正】原版 InitCommandHandlerTable 里有 `v0[3] = 0;`
       —— 槽位 3 在原版就是 NULL（CmdGetModuleCount 在 v0[4]）。
       上一轮我误以为它是漏掉的，实际是我方原本就对的。 */
    Table[3] = (PCOMMAND_HANDLER)NULL;
    Table[4] = (PCOMMAND_HANDLER)CmdGetModuleCount;
    Table[5] = (PCOMMAND_HANDLER)CmdEnumKernelDrivers;
    Table[6] = (PCOMMAND_HANDLER)CmdEnumHandles;
    Table[7] = (PCOMMAND_HANDLER)CmdCheckProcessAccess;
    Table[8] = (PCOMMAND_HANDLER)CmdProcessOperation;
    Table[9] = (PCOMMAND_HANDLER)CmdHandleStreamProcessInput;
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
    Table[75] = (PCOMMAND_HANDLER)EnableObjectCallback;
    Table[76] = (PCOMMAND_HANDLER)CmdRenameFile;
    Table[77] = (PCOMMAND_HANDLER)CmdCopyFile;
    Table[78] = (PCOMMAND_HANDLER)CmdOpenFileForEnum;
    Table[79] = (PCOMMAND_HANDLER)CmdDeleteFile;
    Table[80] = (PCOMMAND_HANDLER)CmdSetFileAttributes;
    Table[81] = (PCOMMAND_HANDLER)CmdCheckFileExist;
    Table[82] = (PCOMMAND_HANDLER)PowerCallbackUnregister;
    Table[83] = (PCOMMAND_HANDLER)ShutdownCallbackUnregister;
    Table[84] = (PCOMMAND_HANDLER)PowerCallbackRoutine;
    Table[85] = (PCOMMAND_HANDLER)RegNotifyCallback;
    Table[86] = (PCOMMAND_HANDLER)DisableThreadProtect;
    Table[87] = (PCOMMAND_HANDLER)EnableThreadProtect;
    Table[88] = (PCOMMAND_HANDLER)CmdQuerySystemInfoEx;
    Table[89] = (PCOMMAND_HANDLER)CmdCallbackControl;
    Table[90] = (PCOMMAND_HANDLER)CmdReadCpuMsr;
    Table[91] = (PCOMMAND_HANDLER)CmdReadCpuId;
    Table[92] = (PCOMMAND_HANDLER)CmdReadCpuBaseAddr;
    Table[93] = (PCOMMAND_HANDLER)CmdReadCpuInfoEx;
    Table[94] = (PCOMMAND_HANDLER)CmdReadCpuBaseAddrEx;
    Table[95] = (PCOMMAND_HANDLER)CmdStubAlwaysTrue;
    Table[96] = (PCOMMAND_HANDLER)CmdGetKernelBaseLegacy;
    /* 【2026-10-29 二次修正】原版 v0[97]=0 / v0[98]=0 也是显式清零。
       RegisterFormatNameCallback 实际在 v0[100]、MiniFilterFormatFileNameEx 在 v0[101]。 */
    Table[97] = (PCOMMAND_HANDLER)NULL;
    Table[98] = (PCOMMAND_HANDLER)NULL;
    Table[99] = (PCOMMAND_HANDLER)MiniFilterGenerateFileName;
    Table[100] = (PCOMMAND_HANDLER)RegisterFormatNameCallback;
    Table[101] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameEx;
    Table[102] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameWithContext;
    Table[103] = (PCOMMAND_HANDLER)RegisterFormatPathCallback;
    Table[104] = (PCOMMAND_HANDLER)MiniFilterFormatFileNameWithPathEx;
    /* 2026-10-29 修正：105-110 此前整段清零，但原版六个槽位都有实现。
       对应函数我方早已存在，只是没接进表。 */
    Table[105] = (PCOMMAND_HANDLER)NULL;     /* 原版 0x140084E14 */
    Table[106] = (PCOMMAND_HANDLER)NULL;    /* 原版 0x140019784 */
    Table[107] = (PCOMMAND_HANDLER)NULL; /* 原版 0x140019400 */
    Table[108] = (PCOMMAND_HANDLER)NULL;    /* 原版 0x1400198D8 */
    Table[109] = (PCOMMAND_HANDLER)NULL;       /* 原版 0x140084618 */
    Table[110] = (PCOMMAND_HANDLER)NULL;        /* 原版 0x140084154 */
    Table[111] = (PCOMMAND_HANDLER)MiniFilterCommPortSend;
    Table[112] = (PCOMMAND_HANDLER)MiniFilterCommPortRecv;
    Table[113] = (PCOMMAND_HANDLER)MiniFilterCommPortReply;
    /* 2026-10-29 修正：114-119 此前整段清零，原版均有实现 */
    Table[114] = (PCOMMAND_HANDLER)NULL;          /* 原版 0x140054C38 */
    Table[115] = (PCOMMAND_HANDLER)NULL; /* 原版 0x1400543FC */
    Table[116] = (PCOMMAND_HANDLER)NULL;            /* 原版 0x140083A84 */
    Table[117] = (PCOMMAND_HANDLER)NULL;         /* 原版 0x1400538C8 */
    Table[118] = (PCOMMAND_HANDLER)NULL;          /* 原版 0x1400539FC */
    Table[119] = (PCOMMAND_HANDLER)NULL;   /* 原版 0x14003D464 */
    Table[120] = (PCOMMAND_HANDLER)CmdQueryProcessNameByPid;
    /* 【2026-10-29 二次修正】原版 v0[121..123]=0 显式清零。
       CmdInstallShadowHook 在 v0[143]、CmdEnumSyscallTable2 在 v0[144]、CmdInstallSyscallHook2 在 v0[145]。 */
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
    /* 2026-10-29 修正：131-138 此前整段清零，原版均有实现 */
    Table[131] = (PCOMMAND_HANDLER)NULL;    /* 原版 0x1400542B4 */
    Table[132] = (PCOMMAND_HANDLER)NULL;       /* 原版 0x140017938 */
    Table[133] = (PCOMMAND_HANDLER)NULL;  /* 原版 0x140018D14 */
    Table[134] = (PCOMMAND_HANDLER)NULL;      /* 原版 0x1400869C0 */
    Table[135] = (PCOMMAND_HANDLER)NULL;    /* 原版 0x14008719C */
    Table[136] = (PCOMMAND_HANDLER)NULL;         /* 原版 0x14006D3A8 */
    Table[137] = (PCOMMAND_HANDLER)NULL; /* 原版 0x1400331FC */
    Table[138] = (PCOMMAND_HANDLER)NULL;     /* 原版 0x140033C68 */
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
    /* 【2026-10-29 二次修正】原版 v0[165]=0 / v0[166]=0 显式清零。
       CmdRestoreSsdtTable 在 v0[199]、CmdEnumObjectTypeInfo 在 v0[200]。 */
    Table[165] = (PCOMMAND_HANDLER)NULL;
    Table[166] = (PCOMMAND_HANDLER)NULL;
    Table[167] = (PCOMMAND_HANDLER)MiniFilterClientContext;   /* 原版名 CmdSetCallbackFlagTrue，我方同语义实现 */
    Table[168] = (PCOMMAND_HANDLER)MiniFilterServerContext;   /* 原版名 CmdSetCallbackFlagFalse，我方同语义实现 */
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
    Table[183] = (PCOMMAND_HANDLER)ProcessCallbackRoutine;
    Table[184] = (PCOMMAND_HANDLER)InitProcessCallback;
    /* 2026-10-29 修正：185-190 此前整段清零 —— 这正是"内核 Dump 内存 /
       内核编辑器 / 对象类型"系列以为"需要新增驱动命令"的根因。
       原版六个槽位都有实现，我方函数也早已写好，只是没接。 */
    Table[185] = (PCOMMAND_HANDLER)NULL;      /* 原版 0x14006C510 */
    Table[186] = (PCOMMAND_HANDLER)NULL;      /* 原版 0x14006B708 */
    Table[187] = (PCOMMAND_HANDLER)NULL;    /* 原版 0x14006C42C */
    Table[188] = (PCOMMAND_HANDLER)NULL;     /* 原版 0x14006AC54 */
    Table[189] = (PCOMMAND_HANDLER)NULL;         /* 原版 0x14006B0AC */
    Table[190] = (PCOMMAND_HANDLER)NULL;        /* 原版 0x14006B49C */
    Table[191] = (PCOMMAND_HANDLER)MiniFilterInstanceSetup;   /* 原版名 CmdOpenFilterVolumeFile，我方同语义实现 */   // 原始 0x1400129CC
    Table[192] = (PCOMMAND_HANDLER)MiniFilterInstanceQuery;   /* 原版名 CmdRemoveFilterContextNode，我方同语义实现 */
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
    Table[208] = (PCOMMAND_HANDLER)EnumKernelModules;   /* 原始 0x1400669B8（0xF0 Ndis Interface 前端实际使用） */
    Table[209] = (PCOMMAND_HANDLER)MiniFilterAcquireForModWrite;   /* 原版名 CmdInitFwpsDispatchTables2，我方同语义实现 */
    Table[210] = (PCOMMAND_HANDLER)CmdInitFwpsDispatchTables;
    Table[211] = (PCOMMAND_HANDLER)CopyKernelArrayToUserBuffer;
    Table[212] = (PCOMMAND_HANDLER)EnumKernelMemoryContext;
    Table[213] = (PCOMMAND_HANDLER)InvokeRegisteredCallbackWithUserData;
    Table[214] = (PCOMMAND_HANDLER)CopyKernelDualArrayToUserBuffer;
    Table[215] = (PCOMMAND_HANDLER)ReadKernelMemoryToUserBuffer;
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
    Table[234] = (PCOMMAND_HANDLER)InitFileSystemCallback;
    Table[235] = (PCOMMAND_HANDLER)MiniFilterPreAcquire;
    Table[236] = (PCOMMAND_HANDLER)MiniFilterPreRelease;
    Table[237] = (PCOMMAND_HANDLER)MiniFilterPreDelete;
    Table[238] = (PCOMMAND_HANDLER)MiniFilterPreFlush;
    Table[239] = (PCOMMAND_HANDLER)MiniFilterPreHardLink;
    Table[240] = (PCOMMAND_HANDLER)MiniFilterPreShutdown;
    Table[241] = (PCOMMAND_HANDLER)InitMiniFilterDriver;
    Table[242] = (PCOMMAND_HANDLER)MiniFilterPreFastIo;   /* 原版名 CmdEnumAleEndpointLayers，我方同语义实现 */        // 原始 0x14001B2B4
    Table[243] = (PCOMMAND_HANDLER)InitFileSystemFilter;
    Table[244] = (PCOMMAND_HANDLER)FileSystemFilterCallback;
    Table[245] = (PCOMMAND_HANDLER)CmdCallSystemRoutine;
    Table[246] = (PCOMMAND_HANDLER)CmdResetDriverState;
    Table[247] = (PCOMMAND_HANDLER)CmdEnumHookInfo;
    Table[248] = (PCOMMAND_HANDLER)CmdCheckBytePattern;
    Table[249] = (PCOMMAND_HANDLER)CmdGetHookEntryInfo;
    Table[250] = (PCOMMAND_HANDLER)CmdQueryHookStatus;
    Table[251] = (PCOMMAND_HANDLER)CmdEnumHookDetail;
    Table[252] = (PCOMMAND_HANDLER)InitObjectCallback;
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
    Table[277] = (PCOMMAND_HANDLER)DisableObjectProtect;
    Table[278] = (PCOMMAND_HANDLER)EnableObjectProtect;
    Table[279] = (PCOMMAND_HANDLER)KernelNotifyRoutine;
    Table[280] = (PCOMMAND_HANDLER)KernelNotifyRoutineEx;
    Table[281] = (PCOMMAND_HANDLER)CmdRestoreDriverDispatch;
    /* 【诊断专用 2026-10-20】命令 0x13A 在原始命令表里是空槽（283 数组的
       末项，原版前端永远不会发送），这里挂只读诊断处理器。

       【2026-10-30 权衡说明】026f56b 做 283 槽对齐时曾把这一槽改回 NULL
       以与原件逐槽一致，结果是自研诊断通道整条断掉：
         · CmdDumpCallStats 变成死代码（无注册点）
         · 客户端 SettingViews.c:99 靠 0x13A 取 IoXxxObjectType / PsXxxType
           地址 → 拿到全 0 → g_StObjReady=0 → Setting 页 6 项 Forbid 全部失效
       实测证据：guest 上 --setting-cli 输出 object types: NOT READY，
       五个类型地址与 extra[0..12] 全为 0。

       结论：原版该槽为空，挂上它不会与任何原版行为冲突（原版前端不发送
       0x13A），而可以恢复 6 项界面功能。故选"偏离 1 槽"而非"丢功能"。
       若将来要求 283 槽逐位一致，替代方案是让客户端自己从磁盘 ntoskrnl.exe
       的导出表解析这些地址 —— 需新增用户态 PE 解析，工作量更大。 */
    Table[282] = (PCOMMAND_HANDLER)CmdDumpCallStats;

    /* 【诊断 2026-10-22】写完立即回读三个关键槽，判断"没写进去"还是
       "写完后被别处清零"。诊断值随 0x13A 导出：
         0x4F80 GT[写出值]  0x4F81 GT[回读198]  0x4F82 GT[回读207]
       选用 0x4F80 是因为 CMD_STAT_PID(0x4C00..0x4D1B)、
       CMD_STAT_DIAG(0x4E60..0x4F7B) 都不覆盖它。 */
    GtWrite((GLOBAL_TABLE_INDEX)0x4F80, (__int64)Table[198]);
    GtWrite((GLOBAL_TABLE_INDEX)0x4F81, GtRead((GLOBAL_TABLE_INDEX)(0x921 + 198)));
    GtWrite((GLOBAL_TABLE_INDEX)0x4F82, GtRead((GLOBAL_TABLE_INDEX)(0x921 + 207)));
    GtWrite((GLOBAL_TABLE_INDEX)0x4F83, GtRead((GLOBAL_TABLE_INDEX)(0x921 + 216)));

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
    GtWrite((GLOBAL_TABLE_INDEX)0x185, (__int64)CurrentProcess);
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
    GtWrite((GLOBAL_TABLE_INDEX)0x185, 0);
    return GtWrite(GtEprocessModuleEntrySize | GtEprocessField22, 0);
}

// CmdQueryProcessInfo — 查询进程信息命令处理
// 对应原始驱动 sub_14003105C
__int64 CmdQueryProcessInfo(__int64 ProcessId, __int64 BufferSize, _DWORD *pOutputBuffer, int OutputSize)
{
    /* 【注意】第 2 参数是请求的 OutSize（+0x24），不是 InSize。
       分发器 ABI：Handler(rcx=CtxPtr, edx=OutSize, r8=ExtraPtr, r9=CtxSize)。
       BufferSize <= 0xA 会走 AllocProcessInfoBuffer，后者
       memset(GtAlloc(GtCommandHandlerBase)+198, 0, 0xD8) 清空命令表
       槽 198..224（命令 0xE6..0x100），包括 0xF0/0xF4/0xF6。
       客户端调用 0x22 时必须让 OutSize > 0xA。 */
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
// 对应原始驱动 0x14004F340
//
// 【2026-10-21 修正：入参上下文 24 字节，不是 1 字节】
// 原始在栈上构造一个 24 字节上下文（rsp+0x30，反编译变量 v18/v19/v20）：
//     0x14004F4xx  v20 = pDriverObjectFunc()      ; IoGetCurrentProcess()
//                  v19 = pObjectTypeFunc()         ; PsGetCurrentProcessId()
//                  v18[0] = 1
//                  v12 = pCurrentThreadFunc()      ; PsGetCurrentThreadId()
//                  EnumProcessInformationWorker(v18, OutputBuffer, BufferSize)
// 即 +0 字节 = 1（InfoFlag）、+8 = 当前进程 ID、+16 = 当前 EPROCESS。
// EnumProcessInformationWorker 把 +8 当 PID（PsLookupProcessByProcessId）、
// 把 +16 当 EPROCESS（ValidateProcessObject/ReferenceObjectSafe），
// 都为零时还会用 +16 回填查到的 EPROCESS。
//
// 旧移植只声明了 `char HasData = 1;` 并把它当上下文传入，+8/+16 是**未初始化的
// 栈垃圾** → 内核拿垃圾值去 PsLookupProcessByProcessId / ValidateProcessObject。
// 实机表现：`--raw 0x25` 直接把 guest 打到自旋（CPU 147%）并最终 bugcheck 0x139。
//
// 三个槽的真实含义（用 ntoskrnl 导出表反查基线槽位确认）：
//     GtObjectTypeRefFunc                                                  = PsGetCurrentProcessId
//     GtTotalSize|GtObjectTypeField42|GtDriverObject  (0x4271, 93 组)      = IoGetCurrentProcess
//     GtUninstallHookSyscallPeOffset|GtEprocessField120 (0x42AA, 112 组)   = PsGetCurrentThreadId
//
// 【2026-10-29 修正：第三个槽算成了 0x4278，应为 0x42AA】
//   原版 0x14004F3C5 `mov ecx,42AAh; call GtRead` 读的是 0x42AA。
//   我方此前写 `GtUninstallHookSyscallPeOffset | GtEprocessField120`，而
//   xpc_gt_enum.h 的别名链把 GtEprocessField120 塌缩成了 **120**：
//       #define GtEprocessField120  GtEprocessField110   // 120
//   于是 0x4228|120 = 0x4278 —— 那是 GtSyscallHashInit94 的**哈希常量槽**，
//   InitSyscallNumberTable 往里写的正是 0x59FA3B98。驱动随后 `call rbp`
//   直接跳用户态地址 → 内核页错误。
//
//   实机表现（原版 PCHunter64.exe 打我方驱动，Win10 17763 LTSC）：
//       bugcheck 0x3B (0x80000003)，Arg2 落在我方驱动内，
//       !analyze 栈顶 View___Driver64+0x22e39 = CmdEnumKernelDrivers+0xC9，
//       即 `call rbp`（GtRead(0x4278) 的返回值）。
//   本条命令我方客户端此前列在 g_FeSkip 里从未发送，故一直未暴露。
//
//   0x42AA 是 112 组导出的 VA 槽（哈希槽 0x42A8 + 2），值由 BuildHookTable
//   在解析 ntoskrnl 导出表后写入。改用字面量 0x42AA 与原始汇编一致。
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
    __int64 (*pCurrentThreadFunc)(void) = (__int64 (*)(void))GtRead((GLOBAL_TABLE_INDEX)0x42AA);
    if (!pObjectTypeFunc || !pDriverObjectFunc || !pCurrentThreadFunc)
        return 0;

    /* 与原始一致：24 字节上下文，+0 是 InfoFlag，+8 是 PID，+16 是 EPROCESS。
       （原始只初始化 +0/+8/+16，中间字节是栈垃圾且从不被读，这里显式清零更安全。） */
    struct {
        __int64 Context[3];
    } EnumContext;
    EnumContext.Context[0] = 0;
    EnumContext.Context[1] = 0;
    EnumContext.Context[2] = 0;
    *((char *)&EnumContext) = 1;

    EnumContext.Context[2] = pDriverObjectFunc();   /* +16 = IoGetCurrentProcess() */
    EnumContext.Context[1] = pObjectTypeFunc();     /* +8  = PsGetCurrentProcessId() */
    __int64 CallbackResult = pCurrentThreadFunc();

    int Result = EnumProcessInformationWorker((char *)&EnumContext, (__int64)OutputBuffer, BufferSize);
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

// CmdEnumHandles — 枚举句柄（命令 0x026）
// 对应原始驱动 0x14004ABB4。实现在 kernel/HandleMgmt.c（与本文件 Table[6] 对应）。
// 【2026-10-23 备注】原版逻辑：OutputBuffer 非空 且 BufferSize > 0x230 且两者都
// 在用户态范围内 → ProbeForWrite → ValidateProcessContext，返回其非零结果。
// HandleMgmt.c 中的实现已逐条对齐，此处不再重复定义（曾因两处定义触发 LNK2005）。

// CmdCheckProcessAccess — 检查进程访问权限
// 对应原始驱动 sub_1400800C0（共 0x12C 字节，bool 返回）
//
// 【2026-10-24 修正】此前是 `return CheckProcessAccess();` —— 完全忽略入参。
// CheckProcessAccess 是**无参**的分发器内部门禁（判"当前进程是否可以访问驱动"），
// 与本命令的语义（"给定 PID/EPROCESS，该目标进程是否受保护"）不是一回事。
// 实机差分：原版对 InSize=0 返回 REJ（result=0），我方返回 OK（result=1）。
//
// 原版流程（逐条对应 0x1400800C0）：
//   InSize == 16 且入参指针与指针+16 都在用户态范围
//   → ProbeForRead(0x10, 8)
//   → ProcessId = Input[0]，TargetProcess = Input[1]
//   → PsLookupProcessByProcessId(ProcessId, &Process)
//   → TargetProcess 为 0 时用查到的 Process 回填（并写回输入副本 +8）
//   → 目标 == GT[0x185]（驱动保护进程 / 当前进程）            → 1
//   → 否则取 GT[GtObjectTypeInfoPtr] 解引用，等于目标          → 1
//   → 否则 ValidateProcessObject(目标,0) != 1 || ProcessOperationWithAttach(目标)
//   → Status >= 0 时 ObfDereferenceObject
__int64 CmdCheckProcessAccess(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    bool Result = 0;

    if (InputSize == 16
        && (ULONG64)InputBuffer < MmUserProbeAddress
        && (ULONG64)(InputBuffer + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        PEPROCESS Process;
        NTSTATUS Status;
        struct _KPROCESS *TargetProcess;
        struct _KPROCESS **pObjectTypeInfo;
        bool IsProtected;

        ProbeForRead((PVOID)InputBuffer, 0x10u, 8u);
        InputData = *(_OWORD *)InputBuffer;

        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        TargetProcess = (struct _KPROCESS *)InputData.qword[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
        }

        if ((struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)0x185) == TargetProcess)
        {
            Result = 1;
        }
        else
        {
            IsProtected = 0;
            pObjectTypeInfo = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
            if (pObjectTypeInfo)
                IsProtected = (*pObjectTypeInfo == TargetProcess);
            if (!IsProtected)
                Result = ValidateProcessObject(TargetProcess, 0) != 1
                      || ProcessOperationWithAttach(TargetProcess);
        }

        if (Status >= 0)
            ObfDereferenceObject(Process);
    }
    return Result;
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
        if ((struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)0x185) == TargetProcess)
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
// 对应原始驱动 0x1400809CC
// 查找线程对象，验证后准备页表扫描
// 【⚠ 必须 noinline】本函数与 CmdThreadMonitor 的唯一差别是传给
//   PrepareFileForPageTableScan 的第 2 个参数（0 vs 1），函数体其余部分完全相同。
//   LTCG 会把两者**合并成同一个地址**（实测 .map 中两者都是 0x1400232C0），
//   导致命令表 Table[29]/Table[30] 指向同一实现、Monitor 实际拿到 0 而非 1。
//   实机 GT[0x93F]（= Table[30]）原始为 CmdThreadMonitor、我方却是 CmdThreadOperation。
__declspec(noinline) __int64 CmdThreadOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
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
// 对应原始驱动 0x1400807F0
// 根据线程ID查找线程对象，验证并准备页表扫描(用于线程保护/监控)
// 原始 0x140080893..898：`mov dl,bl`（bl=1）→ PrepareFileForPageTableScan(Thread, 1)
__declspec(noinline) __int64 CmdThreadMonitor(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
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
//
// 【修正 2026-10-22】原版这个处理器**自己**校验并处理输出缓冲，签名是四参数
// (DeviceObject, Irp, pOutputBuffer, OutputSize)。我方原来转调
// `IoPortOperationDispatch(InputBuffer, InputSize, pOutputBuffer, OutputSize)`，
// 而那个函数只有 (void *InputBuffer, int BufferSize) 两个参数 —— 参数整体
// 左移，OutputSize 位置拿到的是 pOutputBuffer 的指针、BufferSize 拿到的是
// OutputSize，于是 `OutBufferSize >= 0x3808` 恒不成立（实测 result=0、
// 0x046 链条 stage 一直是 0）。这里按 IDA 伪代码逐行重写。
__int64 CmdIoPortOperation(__int64 DeviceObject, __int64 Irp, _DWORD *pOutputBuffer, int OutputSize)
{
    /* 【修正 2026-10-22 之二】ReadIoPortDataForProcess 从上下文里读三样东西：
         +0x00  上下文缓冲指针
         +0x08  输出缓冲指针（用户缓冲，+0x00 处是条目计数）
         +0x10  输出缓冲大小
       原版把这 3 个字段排在同一个栈帧的连续位置（IoPortContext[2] + BufferSize），
       所以用 `IoPortContext[2]` 的地址 +0x10 就能读到大小。我们照抄成两个独立
       局部变量时，编译器把 BufferSize 放到了别的偏移，`+0x10` 读到的是栈垃圾
       → 越界判断失效 → `movups [rax-170h]` 写飞 → 0x3B（实测 RIP 落在
       VPChainW+0xb27f）。这里改成显式结构体，偏移与原版一致。 */
    typedef struct _FE_IOPORT_CTX {
        void    *ContextBuffer;   /* +0x00 */
        ULONG   *OutputBuffer;    /* +0x08，+0x00 是已写条目数 */
        unsigned OutputSize;      /* +0x10 */
        unsigned Reserved;        /* +0x14，对齐 */
    } FE_IOPORT_CTX;
    bool Result = 0;
    PVOID pIoPortContext;
    FE_IOPORT_CTX Ctx;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    /* 【修正 2026-10-22】原版这里只测 GtCurrentEprocess 是否非零。该槽由
       InitGtCore 与 0x20 写入；本复刻的 InitGtCore 因 GT 描述表未初始化而没写，
       于是 0x046 永远停在第一步（实测 ioPortStage 恒 0）。0x20 的写法就是
       `GtWrite(0x185, IoGetCurrentProcess())`，这里照同样语义补一次。 */
    if (GtRead(GtCurrentEprocess) == 0)
        GtWrite(GtCurrentEprocess, (__int64)IoGetCurrentProcess());

    if (pOutputBuffer)
    {
        if ((unsigned int)OutputSize >= 0x3808
            && (ULONG64)pOutputBuffer < MmUserProbeAddress
            && (ULONG64)pOutputBuffer + (unsigned int)OutputSize < MmUserProbeAddress)
        {
            if (GtRead(GtCurrentEprocess))
            {
                pIoPortContext = ExAlloc(PagedPool, 0x3800u);
                if (pIoPortContext)
                {
                    memset(pIoPortContext, 0, 0x3800u);
                    ProbeForWrite(pOutputBuffer, (unsigned int)OutputSize, 1u);
                    *pOutputBuffer = 0;
                    Ctx.ContextBuffer = pIoPortContext;
                    Ctx.OutputBuffer  = pOutputBuffer;
                    Ctx.OutputSize    = (unsigned int)OutputSize;
                    Ctx.Reserved      = 0;
                    ForEachProcessor((__int64 (*)(__int64, __int64))ReadIoPortDataForProcess,
                                     (__int64)&Ctx);
                    Result = *pOutputBuffer != 0;
                    ExFree(pIoPortContext);
                }
            }
        }
    }
    return Result;
}

// CmdKernelMemoryOperation — 内核内存操作命令处理
// 对应原始驱动 sub_140041094
__int64 CmdKernelMemoryOperation(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    /* 【2026-10-26 修正·关键】原版 0x1400410AE/0x1400410B1：
           mov r14d, r9d     ; 长度 = 第 4 个参数 OutSize
           mov rbx,  r8      ; 缓冲 = 第 3 个参数 OutPtr
       全部数据块都写进 OutPtr。此前把 (InputBuffer, InputSize) 当作
       (缓冲, 长度) 传入，而 0x047 的调用方 InPtr=NULL / InSize=0，
       于是 `OutSize >= 0x50` 门限直接失败 → 输出 0 字节。 */
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputSize);
    return KernelMemoryOperationDispatch((void *)pOutputBuffer, OutputSize);
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
            /* 【修正 2026-10-21】MaxEntries 是 unsigned __int64，后面每步都
               `MaxEntries = MaxEntries - <已用条目数>`。一旦某个枚举器返回的
               条目数**超过**当前剩余量（例如调用方给的 OutSize 只够 3 条，
               而 EnumDeviceObjects 实写了更多），减法就下溢成接近 2^64 的
               巨大值，后续枚举器拿到荒唐的上限 → 越界写 → 蓝屏/挂死。
               实测 OutSize=0x2000（MaxEntries=3）时 0x056 直接把 guest 挂死。
               这里把返回值夹到剩余量以内，下溢就不可能发生。 */
            DeviceCount = EnumDeviceObjects(UserBuffer, (unsigned int)MaxEntries);
            if (DeviceCount < 0) DeviceCount = 0;
            if ((unsigned __int64)DeviceCount > MaxEntries) DeviceCount = (int)MaxEntries;
            DevicePtr = &UserBuffer[2104 * DeviceCount];
            if (DevicePtr > &UserBuffer[(ULONG)TotalSize]) DevicePtr = &UserBuffer[(ULONG)TotalSize];
            MaxEntries -= (unsigned __int64)DeviceCount;
            DriverObjectDevice = QueryDriverObjectDevice((__int64)DevicePtr, (int)MaxEntries);
            if (DriverObjectDevice < 0) DriverObjectDevice = 0;
            if ((unsigned __int64)DriverObjectDevice > MaxEntries) DriverObjectDevice = (int)MaxEntries;
            TotalCount = DriverObjectDevice + DeviceCount;
            DevicePtr2 = (__int64)&DevicePtr[2104 * DriverObjectDevice];
            MaxEntries -= (unsigned __int64)DriverObjectDevice;
            FileSystemDriverObject = QueryFileSystemDriverObject(DevicePtr2, (int)MaxEntries);
            if ((unsigned __int64)FileSystemDriverObject > MaxEntries) FileSystemDriverObject = (unsigned int)MaxEntries;
            TotalCount2 = FileSystemDriverObject + TotalCount;
            DevicePtr3 = 2104LL * FileSystemDriverObject + DevicePtr2;
            MaxEntries -= (unsigned __int64)FileSystemDriverObject;
            FileSysCount = EnumFileSystemDeviceObjects(DevicePtr3, (int)MaxEntries);
            if ((unsigned __int64)FileSysCount > MaxEntries) FileSysCount = (unsigned int)MaxEntries;
            TotalCount3 = FileSysCount + TotalCount2;
            DevicePtr4 = 2104LL * FileSysCount + DevicePtr3;
            MaxEntries -= (unsigned __int64)FileSysCount;
            KbdClassCount = BuildDriverPathKbdClass(DevicePtr4, (int)MaxEntries);
            if ((unsigned __int64)KbdClassCount > MaxEntries) KbdClassCount = (unsigned int)MaxEntries;
            TotalCount4 = KbdClassCount + TotalCount3;
            DevicePtr5 = 2104LL * KbdClassCount + DevicePtr4;
            MaxEntries -= (unsigned __int64)KbdClassCount;
            I8042prtCount = BuildDriverPathI8042prt(DevicePtr5, (int)MaxEntries);
            if ((unsigned __int64)I8042prtCount > MaxEntries) I8042prtCount = (unsigned int)MaxEntries;
            TotalCount5 = I8042prtCount + TotalCount4;
            DevicePtr6 = 2104LL * I8042prtCount + DevicePtr5;
            RemainingCount = (int)MaxEntries - (int)I8042prtCount;
            if (RemainingCount < 0) RemainingCount = 0;
            TcpipDriverObject = (unsigned int)QueryTcpipDriverObject(DevicePtr6, RemainingCount);
            if (TcpipDriverObject > (unsigned int)RemainingCount) TcpipDriverObject = (unsigned int)RemainingCount;
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
            {
                DevicePtr7 = 2104 * TcpipDriverObject + DevicePtr6;
                RemainingCount2 = RemainingCount - (int)TcpipDriverObject;
                VolmgrDriverObject = QueryVolmgrDriverObject(DevicePtr7, RemainingCount2);
                if (VolmgrDriverObject > (unsigned int)RemainingCount2) VolmgrDriverObject = (unsigned int)RemainingCount2;
                /* 【修正 2026-10-21】原版在 0x1400099C9 有 `add esi, r14d`
                   （累加 TcpipDriverObject），0x1400099F2 再 `add esi, eax`
                   （累加 VolmgrDriverObject）；而 jb（build<0x1770）跳到
                   loc_140009A1A 时**只**执行那一条 `add esi, r14d`。
                   也就是说 TcpipDriverObject 在两条路径上都只累加一次。
                   我方原写法在 Volmgr 分支里把 TcpipDriverObject 也加进
                   TotalCount5，随后 TotalCount6 又加一次 → 重复计数，
                   导致 NormalizeModulePaths 的 EntryCount 偏大 → 按偏大的
                   条目数步进 1052 字节 → 越界读 → 0xC0000005。
                   这里改为只累加 Volmgr。 */
                TotalCount5 += (int)VolmgrDriverObject;
                DevicePtr6 = 2104LL * VolmgrDriverObject + DevicePtr7;
                RemainingCount = RemainingCount2 - VolmgrDriverObject;
                TcpipDriverObject = QueryTdxDriverObject(DevicePtr6, RemainingCount);
                if (TcpipDriverObject > (unsigned int)RemainingCount) TcpipDriverObject = (unsigned int)RemainingCount;
            }
            DevicePtr8 = 2104LL * (unsigned int)TcpipDriverObject + DevicePtr6;
            RemainingCount3 = RemainingCount - (int)TcpipDriverObject;
            if (RemainingCount3 < 0) RemainingCount3 = 0;
            MouClassCount = BuildDriverPathMouClass(DevicePtr8, RemainingCount3);
            if (MouClassCount > (unsigned int)RemainingCount3) MouClassCount = (unsigned int)RemainingCount3;
            TotalCount6 = (int)MouClassCount + (int)TcpipDriverObject + TotalCount5;
            DevicePtr9 = 2104LL * MouClassCount + DevicePtr8;
            RemainingCount4 = RemainingCount3 - (int)MouClassCount;
            if (RemainingCount4 < 0) RemainingCount4 = 0;
            NdisDriverObject = QueryNdisDriverObject(DevicePtr9, RemainingCount4);
            if (NdisDriverObject > (unsigned int)RemainingCount4) NdisDriverObject = (unsigned int)RemainingCount4;
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
// 对应原始驱动 0x140088A60（275 字节）
// 【2026-10-26 恢复原版实现】此前本函数被错误转调到 EnumObjectTypeInfoOperation
//   （那是槽 200 的另一条命令），导致 0x0D4 输出布局完全不同。
//   原版按构建号分三条路径：
//     build > 0x2580  -> ScanProcessVadForObjectTypes(Out+2, Out, MaxEntries)
//     build > 0x23F0  -> DispatchEnumObjectTypes(Out+2, Out, MaxEntries)
//     否则            -> EnumProcessObjectTypes(GT[0x31A], 3, Out+2, Out, Max)
//   共同前置：*OutputBuffer=0；MaxEntries=((BufferSize-40)>>5)+1（条目步长 0x20）
//   返回 *OutputBuffer != 0
// 【曾经阻塞的原因，已查明】ScanProcessVadForObjectTypes 的第一道门是
//   GT[0x41DB]。该槽属于 GT[0x4158+3k+2] 三元组（hash/RVA/VA），由
//   BuildHookTable 在 DriverEntry 里写入，与命令 0x6B 无关。
//   在本机实测：GT[0x41DB]=0xfffff800288c22f0（nt!MmIsAddressValid）、
//   GT[0x4265]=0xfffff80028b6f3a0，与原版逐值相同，故本路径可用。
__int64 CmdEnumObjectTypes(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    ULONG_PTR MaxEntries;
    _QWORD *pObjectTypeTable;
    ULONG BuildNumber;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputSize);

    if (!pOutputBuffer)
        return 0;
    if ((unsigned int)OutputSize < 0x28)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pOutputBuffer + (unsigned int)OutputSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputBuffer, OutputSize, 1);

    *pOutputBuffer = 0;
    MaxEntries = (((ULONG_PTR)(unsigned int)OutputSize - 40) >> 5) + 1;

    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber >= 0x23F0)
    {
        BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
        if (BuildNumber > 0x2580)
            ScanProcessVadForObjectTypes((_OWORD *)(pOutputBuffer + 2),
                                         (int *)pOutputBuffer, (int)MaxEntries);
        else
            DispatchEnumObjectTypes((__int64)(pOutputBuffer + 2),
                                    (__int64)pOutputBuffer, (int)MaxEntries);
    }
    else
    {
        pObjectTypeTable = (_QWORD *)GtRead(GtCallbackField73);      // 0x31A
        if (pObjectTypeTable
            || (FindWin32kSectionByType(),
                (pObjectTypeTable = (_QWORD *)GtRead(GtCallbackField73)) != NULL))
        {
            EnumProcessObjectTypes(pObjectTypeTable, 3u,
                                   (_OWORD *)(pOutputBuffer + 2),
                                   (int *)pOutputBuffer, (int)MaxEntries);
        }
    }
    return *pOutputBuffer != 0;
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

// CmdInitKernelMemoryContext — 初始化内核内存上下文（命令 0x0F8）
// 对应原始驱动 0x1400681DC（42 条指令，0x83 字节）
// 【重新逆向 2026-10-23】旧实现只有一句注释 + 直接转调别的函数，与原版无关。
// 按 0x1400681DC..0x14006825F 逐条重写：
//
//   0x1400681F4  GT[0x7D0]（NsiDeregister 数据节地址）；为 0 才调 InitKernelMemoryContext
//   0x140068205  rdi = GT[0x7D0]（重读，可能已被 InitKernelMemoryContext 填上）
//   0x140068212  rsi = GT[0x7CF]（要调用的函数指针）
//   0x14006821A  !rdi → 失败
//   0x140068226  rdi <= MmSystemRangeStart → 失败（必须是内核地址）
//   0x14006822B  !rsi → 失败
//   0x140068235  CheckMemoryValid(rdi, 1) != 1 → 失败
//   0x14006823E  rcx = *rdi；为 0 直接成功（bl=1）
//   0x140068246  call rsi(rcx)；返回值 < 0 → 失败，否则成功
//   返回 bl（1=成功 / 0=失败）
__int64 CmdInitKernelMemoryContext(__int64 InputBuffer, __int64 InputSize, _DWORD *pOutputBuffer, int OutputSize)
{
    __int64 NsiAddr;
    __int64 FnPtr;
    char    ok = 0;

    if (!GtRead((GLOBAL_TABLE_INDEX)0x7D0))                        // 0x1400681F4
        InitKernelMemoryContext();                                 // 0x1400681FE

    NsiAddr = GtRead((GLOBAL_TABLE_INDEX)0x7D0);                   // 0x140068205
    FnPtr   = GtRead((GLOBAL_TABLE_INDEX)0x7CF);                   // 0x140068212

    if (NsiAddr
        && (ULONG64)NsiAddr > (ULONG64)MmSystemRangeStart          // 0x140068226
        && FnPtr)                                                  // 0x14006822B
    {
        if (CheckMemoryValid((PVOID)NsiAddr, 1) == 1)              // 0x140068235
        {
            __int64 Arg = *(__int64 *)NsiAddr;                     // 0x14006823E
            if (!Arg)                                              // 0x140068241
            {
                ok = 1;                                            // 0x14006824C
            }
            else
            {
                __int64 st = ((__int64 (__fastcall *)(__int64))FnPtr)(Arg);   // 0x140068246
                if (st >= 0)                                       // 0x14006824A
                    ok = 1;
            }
        }
    }
    return (__int64)ok;
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

// ===================================================================
// LocateHalDispatchTables — 定位 HAL 两个分发表（2026-10-29 新增）
//
// Hal 页需要 HalDispatchTable / HalPrivateDispatchTable 的地址。
// 做法：从 ntoskrnl 镜像的 .data 节起扫描，找形如
//   [0] 小整数（4 / 0x31 这类"版本或项数"）
//   [1..N] 全部是内核代码指针（MmSystemRangeStart 之上、且落在某个已加载
//          模块范围内）
// 的连续 qword 区块。登记第一个为 HalDispatchTable，第二个为
// HalPrivateDispatchTable。
//
// 【为什么不硬编码偏移】实测 Win10 18362 上
//   HalDispatchTable        = nt + 0x423250
//   HalPrivateDispatchTable = nt + 0x423CE0
// 但该偏移随 build 变化，硬编码跨版本必错。
//
// 【为什么不用符号】驱动里拿不到 nt 的 PDB；MmGetSystemRoutineAddress
// 只解析导出函数，解析不到数据符号。
//
// 【HalAcpiDispatchTable】Win10 起 HAL 并入内核，该符号已被移除
// （KD 实测 `x nt!*AcpiDispatch*` 无结果）。所以只找两个，
// 客户端对该节点显示"(not present on this build)"。
// ===================================================================
/* 【2026-10-29】仅保留供后续校准使用；当前未被调用（见 CmdDumpCallStats 里的说明） */
static ULONG g_HalScanCount;   /* 找到的表数量 */

static BOOLEAN HalLooksLikeCodePtr(ULONG64 Value, ULONG64 ImageBase, ULONG64 ImageSize)
{
    if (Value < (ULONG64)MmSystemRangeStart)
        return FALSE;
    /* 必须落在内核镜像范围内（HAL 表项都指向 nt 或 hal 内的函数） */
    if (Value < ImageBase || Value >= ImageBase + ImageSize)
        return FALSE;
    return TRUE;
}

static void LocateHalDispatchTables(void)
{
    ULONG64 V2 = (ULONG64)GtRead(GtNtoskrnlImageSize);
    ULONG64 V3 = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    ULONG64 NtosBase;
    ULONG64 NtosSize;
    ULONG64 ScanBase;
    ULONG64 ScanLimit;
    ULONG64 p;
    ULONG64 Found[2];
    ULONG FoundCount = 0;

    /* 已扫过就不重复扫（结果缓存在 GT 槽） */
    if (GtRead((GLOBAL_TABLE_INDEX)0x4FD3))
        return;

    /* 【实测修正 2026-10-29】GT[2]/GT[3] 的实际内容与本文件枚举名的字面
       语义相反：实测 GT[3]=0x56F3B8（像大小）、GT[2]=0xFFFFF8006FF6F3B8
       （像内核地址）。所以这里按"哪个更像内核地址"来判定，不盲信槽位名。 */
    if (V2 > (ULONG64)MmSystemRangeStart)
    {
        NtosBase = V2;
        NtosSize = V3;
    }
    else if (V3 > (ULONG64)MmSystemRangeStart)
    {
        NtosBase = V3;
        NtosSize = V2;
    }
    else
    {
        return;                      /* 两个都不像，放弃 */
    }

    if (!NtosBase || NtosSize < 0x1000 || NtosSize > 0x4000000)
        return;

    /* 只在镜像的 60% ~ 95% 区间里扫：HAL 表在 .data/.rdata 尾部，
       避开 .text 开头能显著降低误匹配概率。 */
    ScanBase = NtosBase + NtosSize * 6 / 10;
    ScanLimit = NtosBase + NtosSize;
    /* 按 8 字节对齐扫 */
    ScanBase &= ~(ULONG64)7;

    /* 【2026-10-29 收紧判据】
       仅仅"表头小整数 + 后 8 个内核指针"太宽松 —— ntoskrnl 的 .data 里
       这种结构很多（实测扫到了一个非 HAL 表的结构）。
       真正的 HAL 表有两个可验证的强特征：
         1) 表头是固定小值：HalDispatchTable 恒为 4（版本号），
            HalPrivateDispatchTable 恒为 0x31（49，项数）
         2) 后面至少 16 个连续指针全部落在**模块内且可反汇编首字节合法**
       因此这里只接受表头 ∈ {4, 0x31} 的位置。 */
    for (p = ScanBase; p + 24 * 8 < ScanLimit && FoundCount < 2; p += 8)
    {
        ULONG64 Head;
        ULONG i;
        BOOLEAN ok;

        if (MmIsAddressValid((PVOID)p) != 1)
            continue;
        Head = *(ULONG64 *)p;
        /* 强特征：只认 4（HalDispatchTable 版本）或 0x31（HalPrivate 项数） */
        if (Head != 4 && Head != 0x31)
            continue;
        /* 后面 16 个连续的内核代码指针（HAL 表项都是 nt 内的函数） */
        ok = TRUE;
        for (i = 1; i <= 16; i++)
        {
            ULONG64 v;
            if (MmIsAddressValid((PVOID)(p + i * 8)) != 1) { ok = FALSE; break; }
            v = *(ULONG64 *)(p + i * 8);
            if (!HalLooksLikeCodePtr(v, NtosBase, NtosSize)) { ok = FALSE; break; }
        }
        if (!ok)
            continue;

        /* 同一个表不重复登记：如果与已有结果距离 < 0x4000，视为同一张表 */
        if (FoundCount >= 1 && (p - Found[0]) < 0x4000)
            continue;

        Found[FoundCount++] = p;
    }

    if (FoundCount >= 1)
        GtWrite((GLOBAL_TABLE_INDEX)0x4FD1, (__int64)Found[0]);
    if (FoundCount >= 2)
        GtWrite((GLOBAL_TABLE_INDEX)0x4FD2, (__int64)Found[1]);
    GtWrite((GLOBAL_TABLE_INDEX)0x4FD3, (__int64)FoundCount);
    g_HalScanCount = FoundCount;
}

// ===================================================================
// CmdDumpCallStats — 诊断专用（命令 0x13A）
//
// 原始命令表里 Table[282]（= 命令 0x13A）是空槽，任何前端都不会发送。
// 本处理函数把 DispatchDeviceControl 记录的调用统计导出到用户缓冲，
// 用于验证外部前端是否真的在用本驱动：
//
//   输出布局（每项 16 字节，共 283 项）：
//     +0x00 ULONG  Command
//     +0x04 ULONG  CallCount
//     +0x08 ULONG  LastResult
//     +0x0C ULONG  LastCallerPid
//
// 输入被忽略；要求 OutputSize >= 283*16 且缓冲在用户态范围内。
// ===================================================================
__int64 CmdDumpCallStats(__int64 InputBuffer, __int64 InputSize,
                         _DWORD *pOutputBuffer, int OutputSize)
{
    ULONG Index;
    PUCHAR Out;
    /* 末尾追加的表快照与诊断计数，见 XPCHunterDrv.h 的 CMD_STAT_EXT_TOTAL_SIZE */
    ULONG Need = CMD_STAT_EXT_TOTAL_SIZE;

    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputSize);

    if (!pOutputBuffer || OutputSize < (int)Need)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)pOutputBuffer + Need >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputBuffer, Need, 4);

    Out = (PUCHAR)pOutputBuffer;
    for (Index = 0; Index < CMD_STAT_N; Index++)
    {
        *(ULONG *)(Out + 0x00) = 0x20 + Index;
        *(ULONG *)(Out + 0x04) =
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)(CMD_STAT_COUNT + Index));
        *(ULONG *)(Out + 0x08) =
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)(CMD_STAT_RESULT + Index));
        *(ULONG *)(Out + 0x0C) =
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)(CMD_STAT_PID + Index));
        Out += 16;
    }

    /* 末尾追加"设备打开"统计：
       Command 0xFFFE，CallCount = 打开次数，LastCallerPid = 最近打开者。 */
    *(ULONG *)(Out + 0x00) = 0xFFFE;
    *(ULONG *)(Out + 0x04) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E00);
    *(ULONG *)(Out + 0x08) = 0;
    *(ULONG *)(Out + 0x0C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E01);
    Out += 16;

    /*
     * 再追加"驱动环境"块（CMD_ENV_SIZE 字节）。前端据此判断驱动是否
     * 已经完成各项内核数据解析；进程枚举等命令依赖这些槽非零。
     *
     *   +0x00 DWORD  WindowsBuildNumber      GT[0x914]
     *   +0x04 DWORD  NdisVersion              GT[0x363]
     *   +0x08 QWORD  ProcessListHead          GT[0x366]
     *   +0x10 QWORD  NdisBase                 GT[0x361]
     *   +0x18 QWORD  NtoskrnlBase             GT[0x20]
     *   +0x20 QWORD  KernelDataSectionReady   GT[0x369]
     *   +0x28 QWORD  FilterTableReady         GT[0x8F3] (见注释)
     *   +0x30 DWORD  DriverReady              GT[0x304]
     *   +0x34 DWORD  Reserved
     *   +0x38 QWORD  Win32kBase               GT[0x8xx]
     */
    memset(Out, 0, CMD_ENV_SIZE);
    *(ULONG *)(Out + 0x00) = (ULONG)GtRead(GtWindowsBuildNumber);
    *(ULONG *)(Out + 0x04) = (ULONG)GtRead(GtEprocessExtField13);
    *(ULONG64 *)(Out + 0x08) = (ULONG64)GtRead(GtEprocessExtField16);
    *(ULONG64 *)(Out + 0x10) = (ULONG64)GtRead(GtEprocessExtField11);
    *(ULONG64 *)(Out + 0x18) = (ULONG64)GtRead(GtNtoskrnlModuleBase);
    *(ULONG64 *)(Out + 0x20) = (ULONG64)GtRead(GtEprocessExtField19);
    *(ULONG64 *)(Out + 0x28) = (ULONG64)GtRead(GtFltEnumerateFilterDataSection);
    *(ULONG *)(Out + 0x30) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x304);
    *(ULONG64 *)(Out + 0x38) = (ULONG64)GtRead(GtWin32kServiceTable);
    /* 初始化诊断：ndis.sys 是否读取成功 / 文件大小 */
    *(ULONG *)(Out + 0x40) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E10);
    *(ULONG *)(Out + 0x44) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E11);
    *(ULONG *)(Out + 0x48) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E12);
    *(ULONG *)(Out + 0x4C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E13);
    *(ULONG *)(Out + 0x50) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E15);
    *(ULONG *)(Out + 0x54) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E16);
    *(ULONG *)(Out + 0x58) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E17);
    *(ULONG *)(Out + 0x5C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E18);
    *(ULONG *)(Out + 0x60) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E19);
    *(ULONG *)(Out + 0x64) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1A);
    *(ULONG *)(Out + 0x68) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E14);
    *(ULONG *)(Out + 0x6C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1B);
    *(ULONG *)(Out + 0x70) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1C);
    *(ULONG *)(Out + 0x74) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1D);
    *(ULONG *)(Out + 0x78) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1E);
    *(ULONG *)(Out + 0x7C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E1F);
    *(ULONG *)(Out + 0x80) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E20);
    /* 进程枚举链的另外两个关键槽（0x84..0x98 已被下面的 0x4E40+i 占用，
       0xA4 会与 0xA8 的 ULONG 重叠，故放到空槽 0xB0）：
       0xB0 = GT[0x36C] Win10 进程链表头（命令 0xE4 的数据源） */
    *(ULONG64 *)(Out + 0xB0) = (ULONG64)GtRead(GtEprocessExtField22);
    *(ULONG *)(Out + 0xA8) = (ULONG)GtRead(GtEprocessExtField20);  /* NdisIMInitializeDeviceInstanceEx */
    *(ULONG *)(Out + 0xAC) = (ULONG)GtRead(GtEprocessExtField26);  /* 中间槽 */
    *(ULONG *)(Out + 0xC0) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20016);
    *(ULONG *)(Out + 0xE4) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E3F);
    *(ULONG *)(Out + 0xE8) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E3E);
    *(ULONG *)(Out + 0xEC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E3D);
    *(ULONG *)(Out + 0xF0) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E50);
    *(ULONG *)(Out + 0xC4) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20017);
    *(ULONG *)(Out + 0xC8) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20018);
    *(ULONG *)(Out + 0xCC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20019);
    *(ULONG *)(Out + 0xD0) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20020);
    *(ULONG *)(Out + 0xD4) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20021);
    *(ULONG *)(Out + 0xD8) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20022);
    *(ULONG *)(Out + 0xDC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20023);
    *(ULONG *)(Out + 0xE0) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)20024);
    *(ULONG *)(Out + 0x84) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 0));
    *(ULONG *)(Out + 0x88) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 1));
    *(ULONG *)(Out + 0x8C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 2));
    *(ULONG *)(Out + 0x90) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 3));
    *(ULONG *)(Out + 0x94) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 4));
    *(ULONG *)(Out + 0x98) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)(0x4E40 + 5));
    *(ULONG *)(Out + 0x9C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4E21);

    /* 【诊断 2026-10-21】ParseNtSectionsForModuleList1/2 的 6 个入口输入槽
       （任一为 0 就整函数直接 return，GT[0x89C]/[0x89D] 永远为空 = 0x49 空表）。
       这里只导出低 32 位，够判断"缺哪一项"。 */
    *(ULONG *)(Out + 0xA0) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x20);   /* KernelBase   */
    *(ULONG *)(Out + 0xB8) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x21);   /* KernelSize   */
    *(ULONG *)(Out + 0xBC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)3);      /* NtImageBase  */
    *(ULONG *)(Out + 0xF4) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4420); /* SectionOffset*/
    *(ULONG *)(Out + 0xF8) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4477); /* MatchOffset  */
    *(ULONG *)(Out + 0xFC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4414); /* AltMatchOffset*/

    /* 【诊断 2026-10-21】BuildHookTable 分步计数 + 0xA2 的三个前置槽采样。
       0x41DB / 0x41C3 / 0x4334 都是 GT[0x4158+3k+2]，由 BuildHookTable 的
       `GtWrite(i+2, RVA + ImageBase)` 写入；为 0 说明整表没填出来。
       这段落在 env 块扩容出来的 0x100..0x17F。 */
    *(ULONG64 *)(Out + 0x100) = g_DiagHookPeBase;      /* GT[0x20] 展开镜像（QWORD） */
    *(ULONG64 *)(Out + 0x108) = g_DiagHookImageBase;   /* GT[3]   运行期基址（QWORD）*/
    *(ULONG *)(Out + 0x110) = g_DiagHookPeSize;        /* GT[0x21] 镜像大小   */
    *(ULONG *)(Out + 0x114) = g_DiagHookPeLfanew;      /* GT[0x20] 的 e_lfanew */
    *(ULONG *)(Out + 0x118) = g_DiagHookExportCount;   /* GetExportDirSize 返回 */
    *(ULONG *)(Out + 0x11C) = g_DiagHookIdxEntries;    /* 索引表条目数        */
    *(ULONG *)(Out + 0x120) = g_DiagHookIter;          /* 循环迭代次数        */
    *(ULONG *)(Out + 0x124) = g_DiagHookHashZero;      /* 哈希槽为 0 的次数   */
    *(ULONG *)(Out + 0x128) = g_DiagHookHits;          /* 查找命中次数        */
    *(ULONG *)(Out + 0x12C) = g_DiagHookWrites;        /* 实际写入次数        */
    *(ULONG *)(Out + 0x130) = g_DiagHookFirstIdxHash;  /* 索引表[0].hash      */
    *(ULONG *)(Out + 0x134) = g_DiagHookFirstIdxRva;   /* 索引表[0].rva       */
    *(ULONG *)(Out + 0x138) = g_DiagHookTargetHash;    /* GT[0x41D9] 目标哈希 */
    *(ULONG *)(Out + 0x13C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41DB); /* GtObjectTypeCheckFlag */
    *(ULONG *)(Out + 0x140) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x41C3); /* DuplicateHandle      */
    *(ULONG *)(Out + 0x144) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4334); /* ExFreePool           */
    *(ULONG *)(Out + 0x148) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4159); /* 第 1 组 RVA          */
    *(ULONG *)(Out + 0x14C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x415A); /* 第 1 组 VA           */
    *(ULONG *)(Out + 0x150) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x29C);  /* GtKernelDataField11  */
    *(ULONG *)(Out + 0x154) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x29F);  /* GtKernelDataField13  */
    *(ULONG *)(Out + 0x158) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)39);     /* GtSdstServiceCount   */

    /* 【诊断 2026-10-21】 0xA2 TerminateProcessByEProcessOperation 逐级 trace。
       stage：1=GT[0x41DB]为0 2=对象类型校验不过 3=legacy 路径
              4=直接终止已调用 5=GT[0x42BC]为0 6=入参校验失败 */
    *(ULONG *)(Out + 0x160) = g_DiagKillStage;
    *(ULONG *)(Out + 0x164) = g_DiagKillBuild;
    *(ULONG *)(Out + 0x168) = g_DiagKillCheck1;
    *(ULONG *)(Out + 0x16C) = g_DiagKillCheck2;
    *(ULONG *)(Out + 0x170) = g_DiagKillIsLegacy;
    *(ULONG *)(Out + 0x174) = g_DiagKillSdst;
    *(ULONG *)(Out + 0x178) = g_DiagKillDupRet;
    *(ULONG *)(Out + 0x17C) = g_DiagKillTermRet;
    *(ULONG *)(Out + 0x180) = g_DiagKillDirectRet;
    *(ULONG64 *)(Out + 0x188) = g_DiagKillEp;
    *(ULONG64 *)(Out + 0x190) = g_DiagKillDirectFn;
    *(ULONG64 *)(Out + 0x198) = g_DiagKillCheckFn;
    *(ULONG64 *)(Out + 0x1A0) = g_DiagKillDupFn;
    *(ULONG64 *)(Out + 0x1A8) = g_DiagKillFreeFn;
    *(ULONG64 *)(Out + 0x1B0) = g_DiagKillTermFn;
    *(ULONG *)(Out + 0x1B8) = (ULONG)GtRead(GtTerminateProcessByEprocess);
    *(ULONG *)(Out + 0x1BC) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x42BB);   /* 118 组 RVA 槽 */

    /* 【诊断 2026-10-21】0x79 CmdCallbackControl 的 TargetObject 必须精确等于
       驱动解析出的 IoXxxObjectType 地址（驱动会逐一比对，不匹配直接返回 0）。
       Setting 页的 6 个 Forbid 需要这些地址，因此在此导出（QWORD）。
         0x1C0 .. 0x1FF  16 个候选对象类型槽（与 CallbackControlOperation 的比对列表同源）
       注：槽 0x422F/0x4160/0x4163 已用 ntoskrnl 导出表反查确认为
           IoFileObjectType / IoDriverObjectType / IoDeviceObjectType。 */
    *(ULONG64 *)(Out + 0x1C0) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x422F); /* IoFileObjectType   */

    /* 【2026-10-29】HAL 分发表定位所需的环境值。
       Hal 页三个节点需要 HalDispatchTable / HalPrivateDispatchTable 的地址。
       原版驱动没有专门命令，客户端靠 HAL 数据段偏移自己算。
       这里把"能算出什么"暴露出来，客户端据此决定显示哪些节点。

         0x200 QWORD  HalDataSectionOffset   GT[0x831]（FindHalDataSectionOffset 填充）
         0x208 QWORD  NtoskrnlBase           GT[3]
         0x210 QWORD  NtoskrnlImageSize      GT[2]
         0x218 QWORD  HalImageBase           GT[32]
         0x220 QWORD  HalImageSize           GT[33]
         0x228 QWORD  HalDispatchTable       （扫描结果；0 = 未找到）
         0x230 QWORD  HalPrivateDispatchTable
         0x238 DWORD  HalTableCount          （找到几个表：0..3）

       注：HalAcpiDispatchTable 在 Win10 上不存在（HAL 并入内核后该符号
       被移除），所以不单独占槽 —— 客户端按地址是否非零决定节点显示。 */
    /* 【2026-10-29 状态】LocateHalDispatchTables 已实现但扫描判据尚未校准：
       实测找到的地址与 KD 的 nt!HalDispatchTable 不一致（说明 .data 里
       存在同样形态的其他结构）。在判据可靠之前**不调用**，避免给客户端
       喂错地址。客户端此时读到 0，按"未解析"显示。
       详见 docs/reversing/HAL三个分发表_可行性核查_2026-10-29.md */
    *(ULONG64 *)(Out + 0x200) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x831);
    /* 【实测 2026-10-29】GT[3] 实测是大小、GT[2] 才是内核基址，
       与枚举名相反；两个都导出，客户端按"像不像内核地址"自行判定。 */
    *(ULONG64 *)(Out + 0x208) = (ULONG64)GtRead(GtNtoskrnlImageSize);   /* 实测=内核基址 */
    *(ULONG64 *)(Out + 0x210) = (ULONG64)GtRead(GtNtoskrnlModuleBase);  /* 实测=镜像大小 */
    *(ULONG64 *)(Out + 0x218) = (ULONG64)GtRead(GtEprocessField22);
    *(ULONG64 *)(Out + 0x220) = (ULONG64)GtRead(GtEprocessField23);
    *(ULONG64 *)(Out + 0x228) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4FD1);
    *(ULONG64 *)(Out + 0x230) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4FD2);
    *(ULONG *)(Out + 0x238) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x4FD3);

    /* 【诊断 2026-10-26】进程遍历漏斗，放在 env 块尾部 0x410..0x440
       （0x1C0..0x1DF 是 16 个对象类型候选槽，0x240.. 是系统调用表链条槽）。
       0x410 stage（1=进入 2=前置校验通过 3=EnumerateProcessList 成功
                   4=有进程 5=循环结束）
       0x414 ListRet / 0x418 Count / 0x41C Ok1 / 0x420 Ok2 / 0x424 Ok3
       0x428 Ok4 / 0x42C Ok5 / 0x430 Written / 0x434 TypeId / 0x438 FlagOff
       0x43C VadStage（0x0D4 用：1=门通过 2=ValidateKernelObject 3=对象标志
                   4=VAD 区间有效 6=找到地址）
       0x440 VadCount / 0x444 VadFound */
    *(ULONG *)(Out + 0x410) = g_DiagPcStage;
    *(ULONG *)(Out + 0x414) = g_DiagPcListRet;
    *(ULONG *)(Out + 0x418) = g_DiagPcCount;
    *(ULONG *)(Out + 0x41C) = g_DiagPcOk1;
    *(ULONG *)(Out + 0x420) = g_DiagPcOk2;
    *(ULONG *)(Out + 0x424) = g_DiagPcOk3;
    *(ULONG *)(Out + 0x428) = g_DiagPcOk4;
    *(ULONG *)(Out + 0x42C) = g_DiagPcOk5;
    *(ULONG *)(Out + 0x430) = g_DiagPcWritten;
    *(ULONG *)(Out + 0x434) = g_DiagPcTypeId;
    *(ULONG *)(Out + 0x438) = g_DiagPcFlagOff;
    *(ULONG *)(Out + 0x43C) = g_DiagVadStage;
    *(ULONG *)(Out + 0x440) = g_DiagVadCount;
    *(ULONG *)(Out + 0x444) = g_DiagVadFound;
    *(ULONG *)(Out + 0x448) = g_DiagVkStage;
    *(ULONG *)(Out + 0x44C) = g_DiagEpiA;
    *(ULONG *)(Out + 0x450) = g_DiagEpiB;
    *(ULONG *)(Out + 0x454) = g_DiagEpiC;
    *(ULONG *)(Out + 0x458) = g_DiagEpiD;
    *(ULONG *)(Out + 0x45C) = g_DiagEpiE;

    /* 【诊断 2026-10-21】系统调用表链条的关键槽位。
       0x117/0x42 等命令依赖它们；任一为 0 链条就断在对应环节。
         0x240 GT[0x8AE] wdf01000.sys 模块基址（链条起点）
         0x248 GT[0x8B4] 描述符偏移（FindSyscallTableDescriptor 产出）
         0x250 GT[0x8B5] 描述符运行期地址
         0x258 GT[0x8B7] 第一张表条目数
         0x260 GT[0x8B9] 第一张表指针
         0x268 GT[0x8BA] 第二张表条目数
         0x270 GT[0x8BC] 第二张表指针
         0x278 GT[0x8BD] 第一张表已收集标志
         0x27C GT[0x8BE] 第二张表已收集标志
         0x280 "wdf01000.sys" 字符串是否已解码（InitThreadNotify 的产物）
         0x288 GT[0x21A4] 第一张表缓冲
         0x290 GT[0x2DB0] 第二张表缓冲 */
    *(ULONG64 *)(Out + 0x240) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8AE);
    *(ULONG64 *)(Out + 0x248) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8B4);
    *(ULONG64 *)(Out + 0x250) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8B5);
    *(ULONG *)(Out + 0x258) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8B7);
    *(ULONG64 *)(Out + 0x260) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8B9);
    *(ULONG *)(Out + 0x268) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8BA);
    *(ULONG64 *)(Out + 0x270) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x8BC);
    *(ULONG *)(Out + 0x278) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8BD);
    *(ULONG *)(Out + 0x27C) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x8BE);
    *(ULONG64 *)(Out + 0x288) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x21A4);
    *(ULONG64 *)(Out + 0x290) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x2DB0);
    *(ULONG *)(Out + 0x298) = g_DiagNotifyDriverObj;
    *(ULONG *)(Out + 0x29C) = g_DiagNotifyEntryHead;
    *(ULONG *)(Out + 0x2A0) = g_DiagNotifyNodes;
    *(ULONG *)(Out + 0x2A4) = g_DiagNotifyFound;
    *(ULONG *)(Out + 0x2A8) = g_DiagNotifyNameFirst;
    *(ULONG *)(Out + 0x2AC) = g_DiagChainStage;
    *(ULONG *)(Out + 0x2B0) = g_DiagChainWdfSize;
    *(ULONG *)(Out + 0x2B4) = g_DiagChainWdfRet;
    *(ULONG *)(Out + 0x2B8) = g_DiagChainFindRet;
    *(ULONG *)(Out + 0x2BC) = g_DiagChainNtExport;
    *(ULONG64 *)(Out + 0x1C8) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4160); /* IoDriverObjectType */
    *(ULONG64 *)(Out + 0x1D0) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4163); /* IoDeviceObjectType */
    {
        /* 其余候选项按 CallbackControlOperation 的比对顺序逐个导出，
           供前端挑选（Process/Thread/Section/Desktop 等在此列）。 */
        static const ULONG ExtraSlots[13] = {
            0x4161, 0x4162, 0x4164, 0x4165, 0x4166, 0x4167, 0x4168,
            0x4169, 0x416A, 0x416B, 0x416C, 0x416D, 0x416E
        };
        ULONG i;
        for (i = 0; i < 13; i++)
            *(ULONG64 *)(Out + 0x1D8 + i * 8) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)ExtraSlots[i]);
    }

    *(ULONG64 *)(Out + 0x2C0) = (ULONG64)GtRead(GtRtlInitUnicodeStringFunc); /* 0x421D */
    *(ULONG64 *)(Out + 0x2C8) = (ULONG64)GtRead(GtIoCreateFileFunc);         /* 0x421A */
    *(ULONG64 *)(Out + 0x2D0) = (ULONG64)GtRead(GtCloseHandleFunc);          /* 0x4223 */
    *(ULONG64 *)(Out + 0x2D8) = (ULONG64)GtRead(GtDriverObjectListHead);     /* 0x4160（同 0x1C8） */
    /* SSDT / Shadow SSDT 链条（0x8C / 0x8E）的就绪位与结果。
       OpenFileSection 需要上面 4 个槽全部非零；任一个为 0 就返回 0。 */
    *(ULONG64 *)(Out + 0x2E0) = (ULONG64)GtRead(GtEprocessField135 | 0x100);  /* 0x8C 就绪位 */
    *(ULONG64 *)(Out + 0x2E8) = (ULONG64)GtRead(GtCallbackField15);           /* 0x8E 就绪位 */
    /* 【不要在这里调 OpenTcpIpDriverSection()】它内部会 `call` GT 里的
       RtlInitUnicodeString / IoCreateFile / CloseHandle 三个函数指针，
       一旦某个槽不是可执行地址就直接 0x3B。诊断函数必须无副作用。
       要判断链条是否通，看上面 4 个槽是否全非零即可。 */
    *(ULONG *)(Out + 0x2F0) = g_DiagOpenStage;   /* OpenFileSection 走到第几步 */
    *(ULONG *)(Out + 0x2F4) = (ULONG)g_DiagOpenStatus;  /* IoCreateFile 的 NTSTATUS */
    *(ULONG64 *)(Out + 0x2F8) = g_DiagOpenHandle;       /* IoCreateFile 写回的句柄 */

    /* 【诊断 2026-10-22】IDT / I/O Port（0x046）链条。 */
    /* 【诊断 2026-10-22】回调上下文表（0x131）链条的关键槽：
       0x330 GT[0x902] volmgr/ftdisk 导出目录基址
       0x338 GT[0x904] 回调上下文表就绪标志
       0x340 GT[0x3FE6] 目标表指针 */
    *(ULONG64 *)(Out + 0x330) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x902);
    *(ULONG *)(Out + 0x338) = (ULONG)GtRead((GLOBAL_TABLE_INDEX)0x904);
    *(ULONG64 *)(Out + 0x340) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x3FE6);
    *(ULONG *)(Out + 0x348) = g_DiagCbCtxStage;
    *(ULONG *)(Out + 0x34C) = g_DiagCbCtxFileSize;
    *(ULONG *)(Out + 0x350) = g_DiagSsdtRestoreStage;
    *(ULONG64 *)(Out + 0x358) = g_DiagSsdtSectionBase;
    /* 0x360 GT[0x804] FindDllInitExport 产出（relocs 解析第一步的入口） */
    *(ULONG64 *)(Out + 0x360) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x804);
    /* 0x368 GT[0x802] ntoskrnl 镜像大小（relocs 解析的第二入口） */
    *(ULONG64 *)(Out + 0x368) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x802);
    /* 0x380 GT[0x322]/0x323 tdx.sys 基址/大小（证明模块枚举本身在工作） */
    *(ULONG64 *)(Out + 0x380) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x322);
    *(ULONG64 *)(Out + 0x388) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x323);
    /* 0x390 GT[0x803] td.sys 大小（与 0x802 配对） */
    *(ULONG64 *)(Out + 0x390) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x803);
    /* diag 2026-10-22: netio read chain (env+0x398/0x39C/0x3A0) */
    *(ULONG *)(Out + 0x398) = g_DiagNetioReadStatus;
    *(ULONG *)(Out + 0x39C) = g_DiagNetioFileSize;
    *(ULONG *)(Out + 0x3A0) = g_DiagNetioCopyOk;
    /* 0x370 GT[0x80B] TDI reloc 表（0xE7 的直接前置） */
    *(ULONG64 *)(Out + 0x370) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x80B);
    /* 0x378 GT[0x80C] TDI 导出 RVA */
    *(ULONG64 *)(Out + 0x378) = (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x80C);
    *(ULONG *)(Out + 0x300) = g_DiagIoPortStage;
    *(ULONG *)(Out + 0x304) = g_DiagIoPortIdtValid;
    *(ULONG64 *)(Out + 0x308) = g_DiagIoPortIdtGt;
    *(ULONG64 *)(Out + 0x310) = g_DiagIoPortIdtBase;

    /* 【诊断 2026-10-22】DecryptAesHexString 阶段与中间值。
       0x3A4 阶段码, 0x3A8 MD5(计算), 0x3AC MD5(预期) */
    *(ULONG *)(Out + 0x3A4) = g_DiagAesStage;
    *(ULONG *)(Out + 0x3A8) = g_DiagAesMd5Calc;
    *(ULONG *)(Out + 0x3AC) = g_DiagAesMd5Expect;
    /* 0xF8 InitKernelMemoryContext 阶段与 netio.sys 大小
       （CMD_ENV_SIZE 已从 0x3B0 扩到 0x3C0，这两项占用原末尾空位） */
    *(ULONG *)(Out + 0x3B0) = g_DiagKmCtxStage;
    *(ULONG *)(Out + 0x3B4) = g_DiagKmCtxFileSize;

    /* ParseNtExportSectionsV3 逐级计数（0x131 为何返回 0） */
    *(ULONG *)(Out + 0x3B8) = g_DiagPeL1;
    *(ULONG *)(Out + 0x3BC) = g_DiagPeL2;
    *(ULONG *)(Out + 0x3C0) = g_DiagPe1294;
    *(ULONG *)(Out + 0x3C4) = g_DiagPeCond;
    *(ULONG *)(Out + 0x3C8) = g_DiagPeDst;
    *(ULONG *)(Out + 0x3CC) = g_DiagPeRva;
    *(ULONG *)(Out + 0x3D0) = g_DiagPeImgSize;
    *(ULONG *)(Out + 0x3D4) = g_DiagPeLoop1Exit;
    *(ULONG *)(Out + 0x3D8) = g_DiagPeEntryRva;
    *(ULONG *)(Out + 0x3DC) = g_DiagPeType1294;

    /* 【2026-10-22】Network 页数据源：0xF8 InitKernelMemoryContext 的
       26 组 WFP/KFD/NSI 解析结果。每组在 GT 里成对出现
       （RVA 与解析出的绝对地址），这里导出各组的第一个槽。
       布局：0x400 起，共 20 个 QWORD。 */
    {
        static const ULONG KmSlots[] = {
            0x7B2, 0x7B4, 0x7B8, 0x7BB, 0x7BC, 0x7BE, 0x7C0, 0x7C1,
            0x7C3, 0x7C7, 0x7C8, 0x7CA, 0x7CD, 0x7CE, 0x7D0, 0x7D1,
            0x7D3, 0x7D4, 0x7D6, 0x7D7
        };
        ULONG n;
        for (n = 0; n < sizeof(KmSlots) / sizeof(KmSlots[0]); n++)
            *(ULONG64 *)(Out + 0x400 + n * 8) =
                (ULONG64)GtRead((GLOBAL_TABLE_INDEX)KmSlots[n]);
    }

    /* 【诊断 2026-10-22】命令表原文快照 GT[0x921+198 .. 0x921+224]。
       用途：判定 0xEF–0xF8 等槽位"处理器为 0"到底是
         (a) InitCommandHandlerTable 从未写入，还是
         (b) 写入后被 AllocProcessInfoBuffer 的 memset 清掉
           —— 该函数 memset(GtAlloc(GtCommandHandlerBase)+198, 0xD8)，
              范围正是 198..224，由 CmdQueryProcessInfo(0x22) 在
              InSize <= 0xA 时调用。
       必须写在 diag / reject 两张表之后，否则会被它们覆盖。
       偏移 = 表尾 CMD_STAT_TOTAL_SIZE，27 个 QWORD。 */
    for (Index = 0; Index < 27; Index++)
        *(ULONG64 *)(Out + CMD_STAT_TBLSNAP_INENV + Index * 8) =
            (ULONG64)GtRead((GLOBAL_TABLE_INDEX)(0x921 + 198 + Index));

    /* 以下偏移都相对 Out（env 块起点），见 XPCHunterDrv.h 的说明。 */
    *(ULONG *)(Out + CMD_STAT_ALLOCPROC_INENV) = g_DiagAllocProcBufCalls;
    *(ULONG64 *)(Out + CMD_STAT_ALLOCPROC_INENV + 8) =
        (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4F80);
    *(ULONG64 *)(Out + CMD_STAT_ALLOCPROC_INENV + 16) =
        (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4F82);
    *(ULONG64 *)(Out + CMD_STAT_ALLOCPROC_INENV + 24) =
        (ULONG64)GtRead((GLOBAL_TABLE_INDEX)0x4F90);
    /* 导出通道自校验：槽 0 与槽 281 在正常运行下必然非 0 */
    *(ULONG64 *)(Out + CMD_STAT_ALLOCPROC_INENV + 32) =
        (ULONG64)GtRead((GLOBAL_TABLE_INDEX)(0x921 + 0));
    *(ULONG64 *)(Out + CMD_STAT_ALLOCPROC_INENV + 40) =
        (ULONG64)GtRead((GLOBAL_TABLE_INDEX)(0x921 + 281));

    /* 【诊断 2026-10-21】按命令的分派器拒绝原因表 + 协议级拒绝计数表。
       用途：结果字节 0 无法区分"被拒"与"处理器执行完但设计上返回 0"，
       客户端据此把每条命令判为 HANDLED（处理器真的跑了）/ REJECTED(reason) /
       NOT-ATTEMPTED。偏移定义见 XPCHunterDrv.h；此处 Out 指向环境块起点。 */
    for (Index = 0; Index < CMD_STAT_DIAG_N; Index++)
        *(ULONG *)(Out + CMD_ENV_SIZE + Index * 4) =
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)(CMD_STAT_DIAG_BASE + Index));
    for (Index = 0; Index < CMD_STAT_REJECT_N; Index++)
        *(ULONG *)(Out + CMD_ENV_SIZE + CMD_STAT_DIAG_SIZE + Index * 4) =
            (ULONG)GtRead((GLOBAL_TABLE_INDEX)(CMD_STAT_REJECT_BASE + Index));

    return 1;
}
