// IoctlDispatch.c — IOCTL 命令分发
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 对应原始驱动 InitCommandHandlerTable sub_1400815B0
// 功能：分配命令处理函数表（GtAlloc + 0x8D8 字节），填充全部 ~282 个命令处理函数指针

#include "..\inc\XPCHunterDrv.h"
// Forward declarations
__int64 InitMiniFilterDriver(PDRIVER_OBJECT DriverObject);

// 命令处理函数表（全局表索引 2337 处分配）
extern PCOMMAND_HANDLER g_CommandHandlerTable[CMD_OPCODE_COUNT];

// 外部函数前向声明
extern char InstallSsdtHookForThreadProtect(__int64 InputBuffer);
extern unsigned int EnumProcessHandleInfo(_OWORD *pInput, unsigned int *pSystemInfo, _DWORD *pOutput, unsigned int MaxEntries);
extern char CmdCloseProcessHandleEx(__int64 InputBuffer);
extern unsigned int EnumDeviceObjects(char *OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryDriverObjectDevice(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int QueryFileSystemDriverObject(__int64 OutputBuffer, unsigned int MaxEntries);
extern unsigned int EnumFileSystemDeviceObjects(__int64 OutputBuffer, unsigned int MaxEntries);
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
extern __int64 ResolveKernelModuleBasePair(__int64 a1, __int64 a2, _QWORD *a3, __int64 a4);
extern __int64 ReadThreadContext(__int64 a1, __int64 a2, __int64 a3, __int64 a4);
extern __int64 ValidateAndClearProcessContext(__int64 a1, __int64 a2, __int64 a3, __int64 a4);

// 前向声明：Cmd* 命令处理函数包装器
// 这些函数在 Table[] 初始化之后定义，需要提前声明
__int64 CmdEnableObjectCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdPowerCallbackUnregister(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdShutdownCallbackUnregister(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdPowerCallbackRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdRegNotifyCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDisableThreadProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnableThreadProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdProcessCallbackRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitProcessCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdCopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitFileSystemCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitFileSystemFilter(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdFileSystemFilterCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdInitObjectCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdDisableObjectProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdEnableObjectProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdKernelNotifyRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdKernelNotifyRoutineEx(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CmdMiniFilterStreamHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4);

// InitCommandHandlerTable — 初始化命令处理函数表
// 对应原始驱动 sub_1400815B0
// 分配 0x8D8 字节缓冲区，填充所有命令处理函数指针，
// 返回 CmdRestoreDriverDispatch 函数指针
__int64 InitCommandHandlerTable(void)
{
    PCOMMAND_HANDLER *Table = (PCOMMAND_HANDLER *)GtAlloc(GtCommandHandlerBase);

    RtlZeroMemory(Table, 0x8D8);

    // 按索引顺序填充命令处理函数表
    Table[0] = CmdReadProcessMemory;
    Table[1] = CmdResetProcessContext;
    Table[2] = CmdQueryProcessInfo;
    Table[3] = NULL;
    Table[4] = CmdGetModuleCount;
    Table[5] = CmdEnumKernelDrivers;
    Table[6] = CmdEnumHandles;
    Table[7] = CmdCheckProcessAccess;
    Table[8] = CmdProcessOperation;
    Table[9] = CmdMiniFilterStreamHandle;
    Table[10] = CmdEnumThreads;
    Table[11] = CmdReadProcessMemoryBlock;
    Table[12] = CmdQueryModuleInfo;
    Table[13] = CmdModuleOperation;
    Table[14] = CmdEnumRegistry;
    Table[15] = CmdRegistryOperation;
    Table[16] = CmdRegistryProtect;
    Table[17] = CmdEnumServices;
    Table[18] = CmdEnumServiceTable;
    Table[19] = CmdEnumObjects;
    Table[20] = CmdObjectOperation;
    Table[21] = CmdEnumKernelInfo;
    Table[22] = CmdQueryMemoryInfo;
    Table[23] = CmdReadProcessMemoryEx;
    Table[24] = CmdDeviceIoControl;
    Table[25] = CmdVirtualMemoryOp;
    Table[26] = CmdProcessMonitor;
    Table[27] = CmdEnumThreadsEx;
    Table[28] = CmdEnumKernelModules;
    Table[29] = CmdThreadOperation;
    Table[30] = CmdThreadMonitor;
    Table[31] = CmdKernelObjectMonitor;
    Table[32] = CmdHandleMonitor;
    Table[33] = CmdProtectStatus;
    Table[34] = CmdQuerySsdtInfo;
    Table[35] = CmdEnumKernelDriver;
    Table[36] = CmdDriverLoadUnload;
    Table[37] = CmdReadPhysicalMemory;
    Table[38] = CmdIoPortOperation;
    Table[39] = CmdKernelMemoryOperation;
    Table[40] = CmdProcessMemoryOperation;
    Table[41] = CmdEnumProcessModules;
    Table[42] = CmdKernelMemoryOpDispatch;
    Table[43] = CmdProcessMemoryOpDispatch;
    Table[44] = CmdMemoryQueryOp;
    Table[45] = CmdQuerySystemInfo;
    Table[46] = CmdDriverProtectStatus;
    Table[47] = CmdDriverProtectOp;
    Table[48] = CmdThreadProtectStatus;
    Table[49] = InitRegFilter;
    Table[50] = InitRegNotify;
    Table[51] = InitRegCallback;
    Table[52] = CmdEnumProcessHandles;
    Table[53] = CmdQueryProcessInfoEx;
    Table[54] = CmdEnumObjectAllTypes;
    Table[55] = CmdObjectOperationDispatch;
    Table[56] = CmdDeviceIoControlEx;
    Table[57] = CmdFsctlOperation;
    Table[58] = CmdReadProcessMemoryStr;
    Table[59] = CmdWriteProcessMemoryEx;
    Table[60] = CmdDeviceIoControlSimple;
    Table[61] = CmdDeviceIoControlWithBuffer;
    Table[62] = CmdDeviceIoControlWithString;
    Table[63] = CmdOpenSectionObject;
    Table[64] = CmdCreateFile;
    Table[65] = CmdEnumHandlesByPid;
    Table[66] = CmdCreateFileWithPath;
    Table[67] = CmdCloseHandle;
    Table[68] = CmdQueryFileInfo;
    Table[69] = CmdOpenFileHandle;
    Table[70] = CmdReadFileSize;
    Table[71] = CmdWriteFile;
    Table[72] = CmdReadFile;
    Table[73] = CmdReadDirectory;
    Table[74] = CmdEnumDirectory;
    Table[75] = CmdEnableObjectCallback;
    Table[76] = CmdRenameFile;
    Table[77] = CmdCopyFile;
    Table[78] = CmdOpenFileForEnum;
    Table[79] = CmdDeleteFile;
    Table[80] = CmdSetFileAttributes;
    Table[81] = CmdCheckFileExist;
    Table[82] = CmdPowerCallbackUnregister;
    Table[83] = CmdShutdownCallbackUnregister;
    Table[84] = CmdPowerCallbackRoutine;
    Table[85] = CmdRegNotifyCallback;
    Table[86] = CmdDisableThreadProtect;
    Table[87] = CmdEnableThreadProtect;
    Table[88] = CmdQuerySystemInfoEx;
    Table[89] = CmdCallbackControl;
    Table[90] = CmdReadCpuMsr;
    Table[91] = CmdReadCpuId;
    Table[92] = CmdReadCpuBaseAddr;
    Table[93] = CmdReadCpuInfoEx;
    Table[94] = CmdReadCpuBaseAddrEx;
    Table[95] = CmdStubAlwaysTrue;
    Table[96] = CmdGetKernelBaseLegacy;
    Table[97] = NULL;
    Table[98] = NULL;
    Table[99] = MiniFilterGenerateFileName;
    Table[100] = MiniFilterFormatFileName;
    Table[101] = MiniFilterFormatFileNameEx;
    Table[102] = MiniFilterFormatFileNameWithContext;
    Table[103] = MiniFilterFormatFileNameWithPath;
    Table[104] = MiniFilterFormatFileNameWithPathEx;
    // 105-110: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[105], 0x30);
    Table[111] = MiniFilterCommPortSend;
    Table[112] = MiniFilterCommPortRecv;
    Table[113] = MiniFilterCommPortReply;
    // 114-119: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[114], 0x30);
    Table[120] = CmdQueryProcessNameByPid;
    Table[121] = NULL;
    Table[122] = NULL;
    Table[123] = NULL;
    Table[124] = MiniFilterCommPortConnect;
    Table[125] = MiniFilterCommPortDisconnect;
    Table[126] = MiniFilterCommPortCleanup;
    Table[127] = CmdEnumObjectDirectory;
    Table[128] = CmdCloseProcessHandle;
    Table[129] = CmdEnumObjectHandles;
    Table[130] = CmdTerminateProcessByEProcess;
    // 131-138: NULL (memset 0x40 = 64 bytes = 8 entries)
    RtlZeroMemory(&Table[131], 0x40);
    Table[139] = CmdQueryObjectInfo;
    Table[140] = CmdEnumSyscallEntries;
    Table[141] = CmdInstallSystemHook;
    Table[142] = CmdEnumShadowSyscallEntries;
    Table[143] = CmdInstallShadowHook;
    Table[144] = CmdEnumSyscallTable2;
    Table[145] = CmdInstallSyscallHook2;
    Table[146] = CmdEnumSyscallTable3;
    Table[147] = CmdInstallSyscallHook3;
    Table[148] = CmdEnumSyscallTable4;
    Table[149] = CmdInstallSyscallHook4;
    Table[150] = CmdEnumSyscallTable5;
    Table[151] = CmdInstallSyscallHook5;
    Table[152] = CmdEnumSyscallTable6;
    Table[153] = CmdInstallSyscallHook6;
    Table[154] = CmdEnumSyscallTable7;
    Table[155] = CmdInstallSyscallHook7;
    Table[156] = CmdEnumSyscallTable8;
    Table[157] = CmdInstallSyscallHook8;
    Table[158] = MiniFilterPreRename;
    Table[159] = MiniFilterPreVolumeMount;
    Table[160] = CmdEnumSyscallTable9;
    Table[161] = CmdInstallSyscallHook9;
    Table[162] = CmdEnumGdiObjects;
    Table[163] = CmdCheckProcessHideDetect;
    Table[164] = CmdFixProcessEProcess;
    Table[165] = NULL;
    Table[166] = NULL;
    Table[167] = MiniFilterClientContext;
    Table[168] = MiniFilterServerContext;
    Table[169] = MiniFilterContextCleanup;
    Table[170] = CmdDiskReadSector;
    Table[171] = CmdDiskOperationDispatch;
    Table[172] = CmdDiskSectorReadWrite;
    Table[173] = MiniFilterAcquireForSectionSync;
    Table[174] = MiniFilterReleaseForCcFlush;
    Table[175] = MiniFilterNotifyRoutineEx;
    Table[176] = MiniFilterActiveRoutine;
    Table[177] = MiniFilterNotifyRoutineEx2;
    Table[178] = EnableProcessProtect;
    Table[179] = DisableProcessProtect;
    Table[180] = CmdEnumObjectTypes;
    Table[181] = CmdEnumKernelObjectTable;
    Table[182] = CmdWriteKernelObjectField;
    Table[183] = CmdProcessCallbackRoutine;
    Table[184] = CmdInitProcessCallback;
    // 185-190: NULL (memset 0x30 = 48 bytes = 6 entries)
    RtlZeroMemory(&Table[185], 0x30);
    Table[191] = MiniFilterInstanceSetup;
    Table[192] = MiniFilterInstanceQuery;
    Table[193] = CmdEnumProcessListEx;
    Table[194] = CmdEnumProcessListWin7;
    Table[195] = CmdEnumProcessListWin8;
    Table[196] = CmdEnumProcessListWin10;
    Table[197] = CmdEnumKernelHandleTable;
    Table[198] = CmdGetSsdtTableInfo;
    Table[199] = CmdRestoreSsdtTable;
    Table[200] = CmdEnumObjectTypeInfo;
    Table[201] = CmdLookupObjectTypeByAddr;
    Table[202] = CmdQuerySsdtDetails;
    Table[203] = CmdSetSsdtEntry;
    Table[204] = CmdReadExportDirectory;
    Table[205] = CmdUpdateExportEntry;
    Table[206] = CmdRestoreExportTable;
    Table[207] = CmdInitSsdtTable;
    Table[208] = CmdEnumKernelModules;
    Table[209] = MiniFilterAcquireForModWrite;
    Table[210] = MiniFilterPostFastIo;
    Table[211] = CmdCopyKernelArrayToUserBuffer;
    Table[212] = CmdEnumKernelMemoryContext;
    Table[213] = InvokeRegisteredCallbackWithUserData;
    Table[214] = CmdCopyKernelDualArrayToUserBuffer;
    Table[215] = CmdReadKernelMemoryToUserBuffer;
    Table[216] = CmdInitKernelMemoryContext;
    Table[217] = CmdReadKernelMemoryRange;
    Table[218] = CmdReadKernelMemoryRangeSize;
    Table[219] = CmdWriteKernelMemoryRange;
    Table[220] = CmdEnumKernelMemoryDetail;
    Table[221] = CmdCallKernelMemoryFunction;
    Table[222] = CmdEnumObjectTypeDirectory;
    Table[223] = CmdEnumObjectTypeTable;
    Table[224] = CmdEnumObjectTypeDetail;
    Table[225] = CmdReadSsdtEntryTable;
    Table[226] = CmdReadSsdtEntryTableEx;
    Table[227] = CmdDispatchSsdtByVersion;
    Table[228] = CmdFixSsdtEntryAddress;
    Table[229] = CmdEnumSsdtEntryTable;
    Table[230] = CmdReadMsrValue;
    Table[231] = CmdWriteMsrValue;
    Table[232] = CmdEnumProcessorInfo;
    Table[233] = CmdSetProcessorField;
    Table[234] = CmdInitFileSystemCallback;
    Table[235] = MiniFilterPreAcquire;
    Table[236] = MiniFilterPreRelease;
    Table[237] = MiniFilterPreDelete;
    Table[238] = MiniFilterPreFlush;
    Table[239] = MiniFilterPreHardLink;
    Table[240] = MiniFilterPreShutdown;
    Table[241] = InitMiniFilterDriver;
    Table[242] = MiniFilterPreFastIo;
    Table[243] = CmdInitFileSystemFilter;
    Table[244] = CmdFileSystemFilterCallback;
    Table[245] = CmdCallSystemRoutine;
    Table[246] = CmdResetDriverState;
    Table[247] = CmdEnumHookInfo;
    Table[248] = CmdCheckBytePattern;
    Table[249] = CmdGetHookEntryInfo;
    Table[250] = CmdQueryHookStatus;
    Table[251] = CmdEnumHookDetail;
    Table[252] = CmdInitObjectCallback;
    Table[253] = CmdEnumProcessContextWin7;
    Table[254] = CmdSetProcessContextWin7;
    Table[255] = CmdEnumProcessContextWin8;
    Table[256] = CmdSetProcessContextWin8;
    Table[257] = CmdReadKernelBase;
    Table[258] = CmdClearKernelBase;
    Table[259] = CmdEnumKernelModuleInfoEx;
    Table[260] = CmdSetKernelModuleInfo;
    Table[261] = CmdEnumProcessContextWin10;
    Table[262] = CmdSetProcessContextWin10;
    Table[263] = CmdEnumRegistryContext;
    Table[264] = CmdSetRegistryContext;
    Table[265] = CmdEnumFileSystemContext;
    Table[266] = CmdSetFileSystemContext;
    Table[267] = CmdEnumUSBPortSyscallTable;
    Table[268] = CmdInstallUSBPortSyscallHook;
    Table[269] = CmdEnumObjectContext;
    Table[270] = CmdSetObjectContext;
    Table[271] = CmdEnumProcessProtectContext;
    Table[272] = CmdSetProcessProtectContext;
    Table[273] = CmdEnumCallbackContext;
    Table[274] = CmdSetCallbackContext;
    Table[275] = CmdEnumThreadContextWin10;
    Table[276] = CmdSetThreadContextWin10;
    Table[277] = CmdDisableObjectProtect;
    Table[278] = CmdEnableObjectProtect;
    Table[279] = CmdKernelNotifyRoutine;
    Table[280] = CmdKernelNotifyRoutineEx;
    Table[281] = CmdRestoreDriverDispatch;

    return (__int64)CmdRestoreDriverDispatch;
}

// ===================================================================
// Cmd* 命令处理函数实现
// ===================================================================

// CmdReadProcessMemory — 读取进程内存命令处理
// 对应原始驱动 sub_14007F384
__int64 CmdReadProcessMemory(__int64 Address, __int64 a2, _DWORD *a3, int a4)
{
    PEPROCESS CurrentProcess = IoGetCurrentProcess();
    GtWrite(GtEprocessField123 | 0x100, (__int64)CurrentProcess);
    ULONG64 CurrentProcessId = (ULONG64)PsGetCurrentProcessId();
    GtWrite(GtEprocessModuleEntrySize | GtEprocessField22, CurrentProcessId & 0xFFFFFFFFFFFFFFFCui64);
    if (Address)
    {
        if (a2 == 8 && (ULONG64)Address < MmUserProbeAddress && (ULONG64)(Address + 1) < MmUserProbeAddress)
        {
            ProbeForRead((PVOID)Address, 8, 4);
            __int64 v6 = *(__int64 *)Address;
            if (v6 != -1 && !GtRead(GtPsExitSpecialApcAddr))
            {
                struct _KPROCESS *v7 = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
                KAPC_STATE ApcState;
                if (v7)
                    KeStackAttachProcess(v7, &ApcState);
                if (ReadProcessMemoryWithAttach(v6) == 1)
                {
                    GtRead(GtPsExitSpecialApcAddr);
                    GtRead(GtExFreeCallBackAddr);
                    GtRead(GtPspExitNormalApcAddr);
                }
                if (v7)
                    KeUnstackDetachProcess(&ApcState);
            }
        }
    }
    return 0;
}

// CmdResetProcessContext — 重置进程上下文命令处理
// 对应原始驱动 sub_14007F118
__int64 CmdResetProcessContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
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
__int64 CmdGetModuleCount(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    if (a3 && (ULONG64)a3 < MmUserProbeAddress && (ULONG64)(a3 + 1) < MmUserProbeAddress && a4 == 4)
    {
        ProbeForWrite(a3, 4, 4);
        *a3 = GtRead(GtWindowsBuildNumber);
        return 1;
    }
    return 0;
}

// CmdEnumKernelDrivers — 枚举内核驱动程序列表
// 对应原始驱动 sub_14004F340
__int64 CmdEnumKernelDrivers(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!OutputBuffer || BufferSize <= 0x50)
        return 0;
    if ((ULONG64)OutputBuffer >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    __int64 (*v8)(void) = (__int64 (*)(void))GtRead(GtObjectTypeRefFunc);
    __int64 (*v9)(void) = (__int64 (*)(void))GtRead(GtTotalSize | GtObjectTypeField42 | GtDriverObject);
    __int64 v10 = GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField120);
    __int64 (*v11)(void) = (__int64 (*)(void))v10;
    if (!v8 || !v9 || !v10)
        return 0;
    __int64 v19 = v9();
    __int64 v20 = v8();
    char v18 = 1;
    __int64 v12 = v11();
    int v7 = EnumProcessInformationWorker(&v18, (__int64)OutputBuffer, BufferSize);
    if (v7)
    {
        unsigned int v13 = OutputBuffer[4];
        unsigned int v6 = 0;
        for (unsigned int i = 0; i < v13; i++)
        {
            __int64 v15 = 14LL * i;
            if (v12 == *(__int64 *)&OutputBuffer[v15 + 10])
            {
                OutputBuffer[4]--;
            }
            else
            {
                if (v6 != i)
                {
                    __int64 v16 = 14LL * v6;
                    *(_OWORD *)&OutputBuffer[v16 + 6] = *(_OWORD *)&OutputBuffer[v15 + 6];
                    *(_OWORD *)&OutputBuffer[v16 + 10] = *(_OWORD *)&OutputBuffer[v15 + 10];
                    *(_OWORD *)&OutputBuffer[v16 + 14] = *(_OWORD *)&OutputBuffer[v15 + 14];
                    *(__int64 *)&OutputBuffer[v16 + 18] = *(__int64 *)&OutputBuffer[v15 + 18];
                }
                v6++;
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
__int64 CmdCheckProcessAccess(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CheckProcessAccess();
}

// CmdProcessOperation — 进程操作命令处理
// 对应原始驱动 sub_14007FD2C
// 读取 16 字节输入（ProcessId + 可选 EPROCESS），查找进程，验证后清零内存页并执行进程操作
__int64 CmdProcessOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Result = 0;
    if (a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        PEPROCESS Process;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        bool v8;
        struct _KPROCESS **v9;

        ProbeForRead((PVOID)a1, 0x10u, 8u);
        InputData = *(_OWORD *)a1;
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
            v8 = 0;
            v9 = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
            if (v9)
                v8 = *v9 == TargetProcess;
            if (!v8)
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
__int64 CmdReadProcessMemoryBlock(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    SIZE_T BufferSize = a4;
    char Result = 0;
    if (a2 == 16 && a4 > 2)
    {
        _OWORD InputData;
        _OWORD v8;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        PEPROCESS Process;
        PVOID AllocBuffer;
        void *TempBuffer;

        ProbeForRead((PVOID)a1, 0x10u, 4u);
        ProbeForWrite(a3, (unsigned int)BufferSize, 2u);
        InputData = *(_OWORD *)a1;
        v8 = InputData;
        memset(a3, 0, (unsigned int)BufferSize);
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        Status2 = Status;
        TargetProcess = (struct _KPROCESS *)v8.qword[1];
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
        }
        if (ValidateProcessObject(TargetProcess, 0) == 1)
        {
            AllocBuffer = ExAlloc(PagedPool, BufferSize);
            TempBuffer = AllocBuffer;
            if (AllocBuffer)
            {
                if (ReadProcessMemoryBlock(TargetProcess, AllocBuffer, (unsigned int)BufferSize) == 1)
                {
                    memmove(a3, TempBuffer, BufferSize - 2);
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
__int64 CmdThreadOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Result = 0;
    if (a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        PETHREAD Thread;

        ProbeForRead((PVOID)a1, 0x10u, 8u);
        InputData = *(_OWORD *)a1;
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
__int64 CmdThreadMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Result = 0;
    if (a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        PETHREAD Thread;

        ProbeForRead((PVOID)a1, 0x10u, 8u);
        InputData = *(_OWORD *)a1;
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
__int64 CmdKernelObjectMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Inited = 0;
    if (a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        __int64 (*v8)(void);
        PETHREAD Thread;

        ProbeForRead((PVOID)a1, 0x10u, 8u);
        InputData = *(_OWORD *)a1;
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
        v8 = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (v8 && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1 && TargetThread != (char *)v8())
            Inited = InitObjectAndQueryName(TargetThread, 1);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Inited;
}

// CmdHandleMonitor — 句柄监控命令处理
// 对应原始驱动 sub_14007E59C
// 通过线程ID查找线程，初始化对象并查询句柄监视信息
__int64 CmdHandleMonitor(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Inited = 0;
    if (a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        char *TargetThread;
        __int64 (*v8)(void);
        PETHREAD Thread;

        ProbeForRead((PVOID)a1, 0x10u, 8u);
        InputData = *(_OWORD *)a1;
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
        v8 = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (v8 && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1 && TargetThread != (char *)v8())
            Inited = InitObjectAndQueryName(TargetThread, 0);
        if (Status2 >= 0)
            ObfDereferenceObject(Thread);
    }
    return Inited;
}

// CmdProtectStatus — 保护状态查询命令处理
// 对应原始驱动 sub_14007E32C
// 通过线程ID查找线程，检查线程是否受保护
__int64 CmdProtectStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a2 == 16
        && (ULONG64)a1 < MmUserProbeAddress
        && (ULONG64)(a1 + 16) < MmUserProbeAddress
        && a4 == 2
        && (ULONG64)a3 < MmUserProbeAddress
        && (ULONG64)(a3 + 2) < MmUserProbeAddress)
    {
        _OWORD InputData;
        _OWORD SavedData;
        NTSTATUS Status;
        int Status2;
        PETHREAD TargetThread;
        __int64 (*v11)(void);
        unsigned int v12;
        PETHREAD Thread;

        ProbeForRead((PVOID)a1, 0x10u, 4u);
        ProbeForWrite(a3, 2u, 1u);
        InputData = *(_OWORD *)a1;
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
        v11 = (__int64 (*)(void))GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField75);
        if (v11 && ValidateKernelObject((ULONG64)TargetThread, 0, 0, 0) == 1)
        {
            *(_WORD *)a3 = 0;
            if (TargetThread != (PETHREAD)v11())
            {
                v12 = (unsigned int)GtRead(GtKiFastCallEntryAddr | GtEprocessField08);
                if (v12)
                {
                    if (*((_BYTE *)TargetThread + v12))
                        *((_BYTE *)a3 + 1) = 1;
                    else
                        *(_BYTE *)a3 = 1;
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
__int64 CmdQuerySsdtInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a1)
    {
        if (a2 == 24
            && (ULONG64)a1 < MmUserProbeAddress
            && (ULONG64)(a1 + 24) < MmUserProbeAddress)
        {
            void **pInputBuffer = (void **)a1;
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
__int64 CmdEnumKernelDriver(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (ServiceCount)
    {
        if (a3 && (unsigned int)a4 >= 168 * (ServiceCount - 1) + 176
            && (ULONG64)a3 < MmUserProbeAddress
            && (ULONG64)a3 + a4 < MmUserProbeAddress)
        {
            ProbeForWrite(a3, a4, 1u);
            memset(a3, 0, a4);
            if (EnumKernelDriverObjects(a3, ServiceCount) == 1 && BuildDriverInfoEntries(a3, a4) == 1)
                return ResolveDriverModuleNames(a3) == 1;
        }
    }
    return Result;
}

// CmdDriverLoadUnload — 驱动加载/卸载命令处理
// 对应原始驱动 sub_1400516C0
// 验证用户缓冲区，读取 ntoskrnl.exe 文件，调用 ReadServiceTableEntries 读取服务表，解析驱动地址
__int64 CmdDriverLoadUnload(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Result = 0;
    __int64 v7 = GtRead(GtEprocessField69);
    int v8 = (int)GtRead(GtEprocessField57);
    if (v7 && v8)
    {
        if ((unsigned int)a4 >= 48 * (v8 - 1) + 56
            && (ULONG64)a3 < MmUserProbeAddress
            && (ULONG64)a3 + a4 < MmUserProbeAddress)
        {
            unsigned int v10;
            void *v11;

            ProbeForWrite(a3, a4, 1u);
            memset(a3, 0, a4);
            if (ReadNtOsKrnlFile(&v11, &v10))
            {
                if (ReadServiceTableEntries((__int64)a3, a4, v11, v10) == 1)
                {
                    a3[1] = (unsigned int)GtRead(GtEprocessField57);
                    *a3 = (unsigned int)GtRead(GtWindowsBuildNumber);
                    if (ResolveDriverRelativeAddresses((__int64)a3, a4, (int **)(v7 + 32)) == 1
                        && ParseExportDirForDriver((__int64)a3, a4, (__int64)v11, v10) == 1)
                    {
                        Result = ResolveDriverEntryAddresses((__int64)a3) == 1;
                    }
                }
                ExFree(v11);
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
__int64 CheckFileExistOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CheckProcessHideDetectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ClearKernelBaseOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 CloseHandleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CopyFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 CopyKernelArrayToUserBufferOperation(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4);
__int64 CopyKernelDualArrayToUserBufferOperation(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4);
__int64 CreateFileWithPathOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 DeleteFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 DeviceIoControlExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlSimpleOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlWithBufferOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DeviceIoControlWithStringOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DisableObjectProtectOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 DisableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 DiskSectorReadWriteOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnableObjectProtectOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 EnableThreadProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumCallbackContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumDirectoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 EnumFileSystemContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumHookDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumHookInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelHandleTableOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelInfoOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelMemoryContextOperation(__int64 a1, __int64 a2, _DWORD *a3, unsigned int a4);
__int64 EnumKernelMemoryDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelModuleInfoExOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumKernelObjectTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumObjectDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeDetailOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectTypeTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumObjectsOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessContextWin7Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessContextWin8Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessContextWin10Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize);
__int64 EnumProcessListExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin7Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin8Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessListWin10Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumProcessProtectContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int BufferSize);
__int64 EnumProcessorInfoOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 EnumRegistryContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int BufferSize);
__int64 EnumRegistryOperation(char *pInputBuffer, int InputSize, _WORD *pOutputBuffer, int OutputSize);
__int64 EnumServiceTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 EnumServicesOperation(char *pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 EnumThreadContextWin10Operation(__int64 a1, __int64 a2, _BYTE *a3, int a4);
__int64 EnumUSBPortSyscallTableOperation(__int64 a1, __int64 a2, _BYTE *a3, int a4);
__int64 FileSystemControlOperation(unsigned int *pInputBuffer, int InputSize, volatile void *pOutputBuffer, int OutputSize);
__int64 FileSystemFilterCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 FixProcessEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 GetHookEntryInfoOperation(char *pInputBuffer, int InputSize, ULONG64 OutputBuffer, unsigned int OutputSize);
__int64 GetKernelBaseLegacyOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 InitFileSystemCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitFileSystemFilterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 InitKernelMemoryContextOperation(void);
__int64 InitObjectCallbackOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 InstallUSBPortSyscallHookOperation(char *Address, int InputSize);
__int64 KernelNotifyRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 KernelNotifyRoutineExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 LookupObjectTypeByAddrOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 OpenFileForEnumOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 OpenFileHandleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 OpenSectionObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 PowerCallbackRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 PowerCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryFileInfoOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 QueryHookStatusOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryMemoryInfoOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 QueryModuleInfoOperation(volatile void **pInputBuffer, int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize);
__int64 QueryObjectInfoOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QueryProcessNameByPidOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 QuerySystemInfoExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 ReadCpuBaseAddrOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadCpuBaseAddrExOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadCpuIdOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadCpuInfoExOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadCpuMsrOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadDirectoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadFileSizeOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadKernelBaseOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelMemoryRangeOperation(__int64 a1, __int64 a2, _QWORD *a3, int a4);
__int64 ReadKernelMemoryRangeSizeOperation(char *pInputBuffer, int InputSize, _QWORD *pOutputBuffer, int OutputSize);
__int64 ReadKernelMemoryToUserBufferOperation(__int64 a1, __int64 a2, _QWORD *a3, int a4);
__int64 ReadMsrValueOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ReadPhysicalMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 RegNotifyCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RegistryProtectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RenameFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 ResetDriverStateOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 RestoreDriverDispatchOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 SetCallbackContextOperation(char *pInputBuffer, int InputSize);
__int64 SetFileAttributesOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 SetFileSystemContextOperation(char *pInputBuffer, int InputSize);
__int64 SetKernelModuleInfoOperation(__int64 *pInputBuffer, int InputSize);
__int64 SetObjectContextOperation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin7Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin8Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessContextWin10Operation(char *pInputBuffer, int InputSize);
__int64 SetProcessProtectContextOperation(char *pInputBuffer, int InputSize);
__int64 SetProcessorFieldOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 SetRegistryContextOperation(char *pInputBuffer, int InputSize);
__int64 SetThreadContextWin10Operation(char *Address, int InputSize);
__int64 ShutdownCallbackUnregisterOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 TerminateProcessByEProcessOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);
__int64 WriteFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 WriteKernelObjectFieldOperation(PVOID *pInputBuffer, int InputSize);
__int64 WriteMsrValueOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4);
__int64 WriteProcessMemoryExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize);


// InitObjectCallback — 初始化对象回调
// 对应原始驱动 sub_14000F0F4
__int64 CmdInitObjectCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InitObjectCallbackOperation(a1, a2, a3, a4);
}

// CmdEnumProcessContextWin7 — Win7 枚举进程上下文命令处理
// 对应原始驱动 sub_14003A140
__int64 CmdEnumProcessContextWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessContextWin7Operation(a1, a2, a3, a4);
}

// CmdSetProcessContextWin7 — Win7 设置进程上下文命令处理
// 对应原始驱动 sub_14003A3AC
__int64 CmdSetProcessContextWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetProcessContextWin7Operation(a1, a2, a3, a4);
}

// CmdEnumProcessContextWin8 — Win8 枚举进程上下文命令处理
// 对应原始驱动 sub_140039934
__int64 CmdEnumProcessContextWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessContextWin8Operation(a1, a2, a3, a4);
}


// CmdReadPhysicalMemory — 读取物理内存命令处理
// 对应原始驱动 sub_1400352BC
__int64 CmdReadPhysicalMemory(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadPhysicalMemoryOperation(a1, a2, a3, a4);
}

// CmdIoPortOperation — IO 端口操作命令处理
// 对应原始驱动 sub_14003888C
__int64 CmdIoPortOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return IoPortOperationDispatch(a1, a2, a3, a4);
}

// CmdKernelMemoryOperation — 内核内存操作命令处理
// 对应原始驱动 sub_140041094
__int64 CmdKernelMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return KernelMemoryOperationDispatch(a1, a2, a3, a4);
}

// CmdProcessMemoryOperation — 进程内存操作命令处理
// 对应原始驱动 sub_140043FC0
__int64 CmdProcessMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ProcessMemoryOperationDispatch(a1, a2, a3, a4);
}

// CmdEnumProcessModules — 枚举进程模块命令处理
// 对应原始驱动 sub_1400457A4

// CmdKernelMemoryOpDispatch — 内核内存操作分发
// 对应原始驱动 sub_140042814
// 根据命令码(1-11)将清理请求分发到对应的清理子函数
__int64 CmdKernelMemoryOpDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a1 && a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        int *pInputBuffer = (int *)a1;
        _QWORD *pTargetPtr;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPtr = (_QWORD *)*((_QWORD *)pInputBuffer + 1);
        if (pTargetPtr > MmSystemRangeStart)
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
__int64 CmdProcessMemoryOpDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a1 && a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        _DWORD *pInputBuffer = (_DWORD *)a1;
        _QWORD *pTargetPointer;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPointer = (_QWORD *)*((_QWORD *)pInputBuffer + 1);
        if (pTargetPointer > MmSystemRangeStart)
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
__int64 CmdMemoryQueryOp(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a1 && a2 == 16 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 16) < MmUserProbeAddress)
    {
        PVOID **pInputBuffer = (PVOID **)a1;
        PVOID *pTargetPointer;

        ProbeForRead(pInputBuffer, 0x10u, 4u);
        pTargetPointer = pInputBuffer[1];
        if (pTargetPointer > MmSystemRangeStart)
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
__int64 CmdQuerySystemInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2195)
        return 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 2600 || (unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
        return CmdQueryDiskInfo((char *)a3, a4);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        return CmdQuerySystemInfoExV2((char *)a3, a4);
    return Result;
}

// CmdDriverProtectStatus — 驱动保护状态命令处理
// 对应原始驱动 sub_1400534B8
// 验证 168 字节输入缓冲区，偏移 160=1 时恢复服务表索引，偏移 161=1 时通过 WritePhysicalMemoryBuffer 恢复 16 字节钩子
__int64 CmdDriverProtectStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a2 == 168 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 168) < MmUserProbeAddress)
    {
        unsigned int *Address = (unsigned int *)a1;
        ProbeForRead(Address, 0xA8u, 1u);
        unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
        if (ServiceCount && *Address < ServiceCount)
        {
            char v5 = 1;
            char v6 = 1;
            if (*((_BYTE *)Address + 160) == 1)
            {
                v5 = 0;
                _QWORD *v7 = (_QWORD *)GtRead(GtFindHookTargetFirstMatchAddr2);
                if (v7)
                {
                    v5 = 1;
                    WritePhysicalMemoryDword(
                        *v7 + 4LL * *Address,
                        *(_DWORD *)(*v7 + 4LL * *Address) & 0xF | (16 * *((_QWORD *)Address + 18) - 16 * *v7));
                }
            }
            if (*((_BYTE *)Address + 161) == 1)
            {
                v6 = 0;
                __int64 v8 = GtRead(GtEprocessField66);
                unsigned int v9 = (unsigned int)GtRead(GtEprocessField23);
                if (v9 && v8)
                {
                    __int64 v10 = Address[34];
                    if ((int)v10 + 16 <= v9)
                    {
                        _OWORD v13 = *(_OWORD *)(v10 + v8);
                        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
                        {
                            int v12[3];
                            _OWORD v14;
                            if (LookupDriverHashTable((__int64)(Address + 1), v12) == 1
                                && BuildJmpPatchStub(*((_QWORD *)Address + 18), v8 + Address[34], (__int64)&v14, 0x10u, v12[0]) == 1)
                            {
                                v13 = v14;
                            }
                        }
                        v6 = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 18), &v13, 0x10u, 0, 0);
                    }
                }
            }
            return v5 & v6;
        }
    }
    return Result;
}

// CmdDriverProtectOp — 驱动保护操作命令处理
// 对应原始驱动 sub_140051B64
// 检查 48 字节输入缓冲区，根据偏移 24=1 时调用 WritePhysicalMemoryDword 修改服务表索引，偏移 25=1 时调用 WritePhysicalMemoryBuffer 写入数据
__int64 CmdDriverProtectOp(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    char Result = 0;
    if (a2 == 48 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 48) < MmUserProbeAddress)
    {
        char *Address = (char *)a1;
        ProbeForRead(Address, 0x30u, 1u);
        __int64 v4 = GtRead(GtEprocessField69);
        int v5 = (int)GtRead(GtEprocessField57);
        if (v4 && v5)
        {
            char v6 = 1;
            if (Address[24] == 1)
                WritePhysicalMemoryDword(
                    *(_QWORD *)(v4 + 32) + 4LL * *(unsigned int *)Address,
                    *(_DWORD *)(*(_QWORD *)(v4 + 32) + 4LL * *(unsigned int *)Address) & 0xF
                    | (16 * *((_QWORD *)Address + 1) - 16 * *(_QWORD *)(v4 + 32)));
            if (Address[25] == 1)
            {
                v6 = 0;
                if (MmIsAddressValid(*((PVOID *)Address + 1)) == 1
                    && MmIsAddressValid((PVOID)(*((_QWORD *)Address + 1) + 15LL)) == 1)
                {
                    unsigned int v7 = 16;
                    _OWORD v9 = *(_OWORD *)(Address + 26);
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800 && (*(WORD *)&v9) == 0x25FF)
                        v7 = 6;
                    v6 = WritePhysicalMemoryBuffer(*((_QWORD *)Address + 1), &v9, v7, 0, 0);
                }
            }
            return v6 & 1;
        }
    }
    return Result;
}

// CmdThreadProtectStatus — 线程保护状态命令处理
// 对应原始驱动 sub_14003590C
// 检查 56 字节输入缓冲区，根据偏移 32=1 时安装 SSDT 线程保护钩子，偏移 33=1 时通过 WritePhysicalMemoryBuffer 写入 16 字节物理内存补丁
__int64 CmdThreadProtectStatus(__int64 Address, int InputSize, _DWORD *a3, int a4)
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
            *OutputBuffer = EnumProcessHandleInfo(&ProcessData, SystemInfo, OutputBuffer + 2, (OutputBufferSize - 8) / 0x250);
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
__int64 CmdQueryProcessInfoEx(__int64 Address, int InputSize, _DWORD *a3, int a4)
{
    char Result; // bl
    NTSTATUS Status; // edi
    PEPROCESS Process; // rax
    PEPROCESS ProcessLookup; // [rsp+28h] [rbp-50h] BYREF
    _OWORD InputData; // [rsp+30h] [rbp-48h]
    _OWORD OutputData[2]; // [rsp+40h] [rbp-38h] BYREF
    __int64 v10; // [rsp+60h] [rbp-18h]

    Result = 0;
    if (InputSize == 40
        && (ULONG64)Address < MmUserProbeAddress
        && (ULONG64)(Address + 40) < MmUserProbeAddress)
    {
        ProbeForRead((PVOID)Address, 0x28u, 1u);
        InputData = *(_OWORD *)Address;
        OutputData[0] = *(_OWORD *)&InputData;
        OutputData[1] = *(_OWORD *)(Address + 16);
        v10 = *(__int64 *)(Address + 32);
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
            DriverObjectDevice = QueryDriverObjectDevice((__int64)DevicePtr, MaxEntries);
            TotalCount = DriverObjectDevice + DeviceCount;
            DevicePtr2 = (__int64)&DevicePtr[2104 * DriverObjectDevice];
            MaxEntries = MaxEntries - DriverObjectDevice;
            FileSystemDriverObject = QueryFileSystemDriverObject(DevicePtr2, MaxEntries);
            TotalCount2 = FileSystemDriverObject + TotalCount;
            DevicePtr3 = 2104LL * FileSystemDriverObject + DevicePtr2;
            MaxEntries = MaxEntries - FileSystemDriverObject;
            FileSysCount = EnumFileSystemDeviceObjects(DevicePtr3, MaxEntries);
            TotalCount3 = FileSysCount + TotalCount2;
            DevicePtr4 = 2104LL * FileSysCount + DevicePtr3;
            MaxEntries = MaxEntries - FileSysCount;
            KbdClassCount = BuildDriverPathKbdClass(DevicePtr4, MaxEntries);
            TotalCount4 = KbdClassCount + TotalCount3;
            DevicePtr5 = 2104LL * KbdClassCount + DevicePtr4;
            MaxEntries = MaxEntries - KbdClassCount;
            I8042prtCount = BuildDriverPathI8042prt(DevicePtr5, MaxEntries);
            TotalCount5 = I8042prtCount + TotalCount4;
            DevicePtr6 = 2104LL * I8042prtCount + DevicePtr5;
            RemainingCount = MaxEntries - I8042prtCount;
            TcpipDriverObject = (unsigned int)QueryTcpipDriverObject(DevicePtr6, RemainingCount);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
            {
                DevicePtr7 = 2104 * TcpipDriverObject + DevicePtr6;
                RemainingCount2 = RemainingCount - TcpipDriverObject;
                VolmgrDriverObject = QueryVolmgrDriverObject(DevicePtr7, RemainingCount2);
                TotalCount5 += VolmgrDriverObject + TcpipDriverObject;
                DevicePtr6 = 2104LL * VolmgrDriverObject + DevicePtr7;
                RemainingCount = RemainingCount2 - VolmgrDriverObject;
                TcpipDriverObject = QueryTdxDriverObject(DevicePtr6, RemainingCount);
            }
            DevicePtr8 = 2104LL * (unsigned int)TcpipDriverObject + DevicePtr6;
            RemainingCount3 = RemainingCount - TcpipDriverObject;
            MouClassCount = BuildDriverPathMouClass(DevicePtr8, RemainingCount3);
            TotalCount6 = MouClassCount + TcpipDriverObject + TotalCount5;
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
__int64 CmdObjectOperationDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ObjectOperationDispatcher(a1, a2, a3, a4);
}

// CmdDeviceIoControlEx — 设备 IO 控制扩展命令处理
// 对应原始驱动 sub_140074EF8
__int64 CmdDeviceIoControlEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeviceIoControlExOperation(a1, a2, a3, a4);
}

// CmdFsctlOperation — 文件系统控制操作命令处理
// 对应原始驱动 sub_140073DF4
__int64 CmdFsctlOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return FileSystemControlOperation(a1, a2, a3, a4);
}

// CmdReadProcessMemoryStr — 读取进程内存字符串命令处理
// 对应原始驱动 sub_140074418
__int64 CmdReadProcessMemoryStr(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadProcessMemoryString(a1, a2, a3, a4);
}

// CmdWriteProcessMemoryEx — 写入进程内存扩展命令处理
// 对应原始驱动 sub_1400749A0
__int64 CmdWriteProcessMemoryEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return WriteProcessMemoryExOperation(a1, a2, a3, a4);
}

// CmdDeviceIoControlSimple — 简单设备 IO 控制命令处理
// 对应原始驱动 sub_1400751D4
__int64 CmdDeviceIoControlSimple(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeviceIoControlSimpleOperation(a1, a2, a3, a4);
}

// CmdDeviceIoControlWithBuffer — 带缓冲设备 IO 控制命令处理
// 对应原始驱动 sub_1400753A4
__int64 CmdDeviceIoControlWithBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeviceIoControlWithBufferOperation(a1, a2, a3, a4);
}

// CmdDeviceIoControlWithString — 带字符串设备 IO 控制命令处理
// 对应原始驱动 sub_14007562C
__int64 CmdDeviceIoControlWithString(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeviceIoControlWithStringOperation(a1, a2, a3, a4);
}

// CmdOpenSectionObject — 打开节区对象命令处理
// 对应原始驱动 sub_140074128
__int64 CmdOpenSectionObject(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return OpenSectionObjectOperation(a1, a2, a3, a4);
}

// CmdCreateFile — 创建文件命令处理
// 对应原始驱动 sub_140074258

// CmdEnumHandlesByPid — 按 PID 枚举句柄命令处理
// 对应原始驱动 sub_1400858B8

// CmdCreateFileWithPath — 按路径创建文件命令处理
// 对应原始驱动 sub_14002D2EC
__int64 CmdCreateFileWithPath(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CreateFileWithPathOperation(a1, a2, a3, a4);
}

// CmdCloseHandle — 关闭句柄命令处理
// 对应原始驱动 sub_14002C430
__int64 CmdCloseHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CloseHandleOperation(a1, a2, a3, a4);
}

// CmdQueryFileInfo — 查询文件信息命令处理
// 对应原始驱动 sub_14002D12C
__int64 CmdQueryFileInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryFileInfoOperation(a1, a2, a3, a4);
}

// CmdOpenFileHandle — 打开文件句柄命令处理
// 对应原始驱动 sub_14002D070
__int64 CmdOpenFileHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return OpenFileHandleOperation(a1, a2, a3, a4);
}

// CmdReadFileSize — 读取文件大小命令处理
// 对应原始驱动 sub_14002D858
__int64 CmdReadFileSize(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadFileSizeOperation(a1, a2, a3, a4);
}

// CmdWriteFile — 写入文件命令处理
// 对应原始驱动 sub_14002D418
__int64 CmdWriteFile(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return WriteFileOperation(a1, a2, a3, a4);
}

// CmdReadFile — 读取文件命令处理
// 对应原始驱动 sub_14002D8F0
__int64 CmdReadFile(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadFileOperation(a1, a2, a3, a4);
}

// CmdReadDirectory — 读取目录命令处理
// 对应原始驱动 sub_14002CD7C
__int64 CmdReadDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadDirectoryOperation(a1, a2, a3, a4);
}

// CmdEnumDirectory — 枚举目录命令处理
// 对应原始驱动 sub_14002C96C
__int64 CmdEnumDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumDirectoryOperation(a1, a2, a3, a4);
}

// EnableObjectCallback — 启用对象回调
// 对应原始驱动 sub_1400819C4
__int64 CmdEnableObjectCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnableObjectCallbackOperation(a1, a2, a3, a4);
}

// CmdRenameFile — 重命名文件命令处理
// 对应原始驱动 sub_14002D52C
__int64 CmdRenameFile(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return RenameFileOperation(a1, a2, a3, a4);
}

// CmdCopyFile — 复制文件命令处理
// 对应原始驱动 sub_14002C528
__int64 CmdCopyFile(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CopyFileOperation(a1, a2, a3, a4);
}

// CmdOpenFileForEnum — 打开文件供枚举命令处理
// 对应原始驱动 sub_14002C840
__int64 CmdOpenFileForEnum(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return OpenFileForEnumOperation(a1, a2, a3, a4);
}

// CmdDeleteFile — 删除文件命令处理
// 对应原始驱动 sub_14002CEDC
__int64 CmdDeleteFile(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeleteFileOperation(a1, a2, a3, a4);
}

// CmdSetFileAttributes — 设置文件属性命令处理
// 对应原始驱动 sub_14002D6D8
__int64 CmdSetFileAttributes(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetFileAttributesOperation(a1, a2, a3, a4);
}

// CmdCheckFileExist — 检查文件存在命令处理
// 对应原始驱动 sub_14002CC50
__int64 CmdCheckFileExist(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CheckFileExistOperation(a1, a2, a3, a4);
}

// PowerCallbackUnregister — 注销电源回调
// 对应原始驱动 sub_140081A34
__int64 CmdPowerCallbackUnregister(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return PowerCallbackUnregisterOperation(a1, a2, a3, a4);
}

// ShutdownCallbackUnregister — 注销关机回调
// 对应原始驱动 sub_140081A42
__int64 CmdShutdownCallbackUnregister(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ShutdownCallbackUnregisterOperation(a1, a2, a3, a4);
}

// PowerCallbackRoutine — 电源回调例程
// 对应原始驱动 sub_140081A50
__int64 CmdPowerCallbackRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return PowerCallbackRoutineOperation(a1, a2, a3, a4);
}

// RegNotifyCallback — 注册表通知回调
// 对应原始驱动 sub_140081A5E
__int64 CmdRegNotifyCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return RegNotifyCallbackOperation(a1, a2, a3, a4);
}

// DisableThreadProtect — 禁用线程保护
// 对应原始驱动 sub_140081A6C
__int64 CmdDisableThreadProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DisableThreadProtectOperation(a1, a2, a3, a4);
}

// EnableThreadProtect — 启用线程保护
// 对应原始驱动 sub_140081A7A
__int64 CmdEnableThreadProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnableThreadProtectOperation(a1, a2, a3, a4);
}

// CmdQuerySystemInfoEx — 查询系统信息扩展命令处理
// 对应原始驱动 sub_14006EC24
__int64 CmdQuerySystemInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QuerySystemInfoExOperation(a1, a2, a3, a4);
}

// CmdCallbackControl — 回调控制命令处理
// 对应原始驱动 sub_140070190
__int64 CmdCallbackControl(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CallbackControlOperation(a1, a2, a3, a4);
}

// CmdReadCpuMsr — 读取 CPU MSR 命令处理
// 对应原始驱动 sub_14002A358
__int64 CmdReadCpuMsr(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadCpuMsrOperation(a1, a2, a3, a4);
}

// CmdReadCpuId — 读取 CPU ID 命令处理
// 对应原始驱动 sub_14002B304
__int64 CmdReadCpuId(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadCpuIdOperation(a1, a2, a3, a4);
}

// CmdReadCpuBaseAddr — 读取 CPU 基地址命令处理
// 对应原始驱动 sub_14002A45C
__int64 CmdReadCpuBaseAddr(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadCpuBaseAddrOperation(a1, a2, a3, a4);
}

// CmdReadCpuInfoEx — 读取 CPU 信息扩展命令处理
// 对应原始驱动 sub_14002B36C
__int64 CmdReadCpuInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadCpuInfoExOperation(a1, a2, a3, a4);
}

// CmdReadCpuBaseAddrEx — 读取 CPU 基地址扩展命令处理
// 对应原始驱动 sub_14002B944
__int64 CmdReadCpuBaseAddrEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadCpuBaseAddrExOperation(a1, a2, a3, a4);
}

// CmdStubAlwaysTrue — 固定返回 1 的桩函数
// 对应原始驱动 sub_14002BA38
__int64 CmdStubAlwaysTrue(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 1;
}

// CmdGetKernelBaseLegacy — 获取内核基址（旧版）命令处理
// 对应原始驱动 sub_14002B8DC
__int64 CmdGetKernelBaseLegacy(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return GetKernelBaseLegacyOperation(a1, a2, a3, a4);
}

// CmdQueryProcessNameByPid — 按 PID 查询进程名命令处理
// 对应原始驱动 sub_140084E14
__int64 CmdQueryProcessNameByPid(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryProcessNameByPidOperation(a1, a2, a3, a4);
}

// CmdEnumObjectDirectory — 枚举对象目录命令处理
// 对应原始驱动 sub_140084618
__int64 CmdEnumObjectDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectDirectoryOperation(a1, a2, a3, a4);
}

// CmdCloseProcessHandle — 关闭进程句柄命令处理
// 对应原始驱动 sub_140084154

// CmdEnumObjectHandles — 枚举对象句柄命令处理
// 对应原始驱动 sub_140054C38

// CmdTerminateProcessByEProcess — 通过 EPROCESS 终止进程命令处理
// 对应原始驱动 sub_1400543FC
__int64 CmdTerminateProcessByEProcess(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return TerminateProcessByEProcessOperation(a1, a2, a3, a4);
}

// CmdQueryObjectInfo — 查询对象信息命令处理
// 对应原始驱动 sub_140083A84
__int64 CmdQueryObjectInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryObjectInfoOperation(a1, a2, a3, a4);
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
__int64 CmdCheckProcessHideDetect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CheckProcessHideDetectOperation(a1, a2, a3, a4);
}

// CmdFixProcessEProcess — 修复进程 EPROCESS 命令处理
// 对应原始驱动 sub_140033C68
__int64 CmdFixProcessEProcess(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return FixProcessEProcessOperation(a1, a2, a3, a4);
}

// CmdDiskReadSector — 磁盘读取扇区命令处理
// 对应原始驱动 sub_14007B854
__int64 CmdDiskReadSector(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DiskReadSectorOperation(a1, a2, a3, a4);
}

// CmdDiskOperationDispatch — 磁盘操作分发
// 对应原始驱动 sub_14007C980
__int64 CmdDiskOperationDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DiskOperationDispatcher(a1, a2, a3, a4);
}

// CmdDiskSectorReadWrite — 磁盘扇区读写命令处理
// 对应原始驱动 sub_14007B72C
__int64 CmdDiskSectorReadWrite(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DiskSectorReadWriteOperation(a1, a2, a3, a4);
}

// CmdEnumObjectTypes — 枚举对象类型命令处理
// 对应原始驱动 sub_14007EDC8
__int64 CmdEnumObjectTypes(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectTypeInfoOperation(a1, a2, a3, a4);
}

// CmdEnumKernelObjectTable — 枚举内核对象表命令处理
// 对应原始驱动 sub_140029964
__int64 CmdEnumKernelObjectTable(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelObjectTableOperation(a1, a2, a3, a4);
}

// CmdWriteKernelObjectField — 写入内核对象字段命令处理
// 对应原始驱动 sub_140029C74
__int64 CmdWriteKernelObjectField(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return WriteKernelObjectFieldOperation(a1, a2, a3, a4);
}

// ProcessCallbackRoutine — 进程回调例程
// 对应原始驱动 sub_140081A88
__int64 CmdProcessCallbackRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ProcessCallbackRoutine(a1, a2, a3, a4);
}

// InitProcessCallback — 初始化进程回调
// 对应原始驱动 sub_1400106C0
__int64 CmdInitProcessCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InitProcessCallback((struct _KPROCESS **)a2, a4);
}

// CmdEnumProcessListEx — 扩展枚举进程列表命令处理
// 对应原始驱动 sub_140062ED8
__int64 CmdEnumProcessListEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessListExOperation(a1, a2, a3, a4);
}

// CmdEnumProcessListWin7 — Win7 枚举进程列表命令处理
// 对应原始驱动 sub_14005A5E8
__int64 CmdEnumProcessListWin7(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessListWin7Operation(a1, a2, a3, a4);
}

// CmdEnumProcessListWin8 — Win8 枚举进程列表命令处理
// 对应原始驱动 sub_14005C6B0
__int64 CmdEnumProcessListWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessListWin8Operation(a1, a2, a3, a4);
}

// CmdEnumProcessListWin10 — Win10 枚举进程列表命令处理
// 对应原始驱动 sub_14005E354
__int64 CmdEnumProcessListWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessListWin10Operation(a1, a2, a3, a4);
}

// CmdEnumKernelHandleTable — 枚举内核句柄表命令处理
// 对应原始驱动 sub_140067278
__int64 CmdEnumKernelHandleTable(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelHandleTableOperation(a1, a2, a3, a4);
}

// CmdGetSsdtTableInfo — 获取 SSDT 表信息命令处理
// 对应原始驱动 sub_140067DBC

// CmdRestoreSsdtTable — 恢复 SSDT 表命令处理
// 对应原始驱动 sub_140068054

// CmdEnumObjectTypeInfo — 枚举对象类型信息命令处理
// 对应原始驱动 sub_14007EDC8
__int64 CmdEnumObjectTypeInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectTypeInfoOperation(a1, a2, a3, a4);
}

// CmdLookupObjectTypeByAddr — 按地址查找对象类型命令处理
// 对应原始驱动 sub_14007ECCC
__int64 CmdLookupObjectTypeByAddr(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return LookupObjectTypeByAddrOperation(a1, a2, a3, a4);
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
__int64 CmdCopyKernelArrayToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CopyKernelArrayToUserBufferOperation(a1, a2, a3, a4);
}

// CmdEnumKernelMemoryContext — 枚举内核内存上下文
// 对应原始驱动 sub_140071FCC
__int64 CmdEnumKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelMemoryContextOperation(a1, a2, a3, a4);
}

// InvokeRegisteredCallbackWithUserData — 调用注册的回调
// 对应原始驱动 sub_1400680F8
// (already implemented in DriverEntry.c)

// CmdCopyKernelDualArrayToUserBuffer — 复制内核双数组到用户缓冲区
// 对应原始驱动 sub_1400720B0
__int64 CmdCopyKernelDualArrayToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CopyKernelDualArrayToUserBufferOperation(a1, a2, a3, a4);
}

// CmdReadKernelMemoryToUserBuffer — 读取内核内存到用户缓冲区
// 对应原始驱动 sub_1400721B0
__int64 CmdReadKernelMemoryToUserBuffer(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadKernelMemoryToUserBufferOperation(a1, a2, a3, a4);
}

// CmdInitKernelMemoryContext — 初始化内核内存上下文命令处理
// 对应原始驱动 sub_1400681DC
__int64 CmdInitKernelMemoryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InitKernelMemoryContextOperation(a1, a2, a3, a4);
}

// CmdReadKernelMemoryRange — 读取内核内存范围命令处理
// 对应原始驱动 sub_14006BBB8
__int64 CmdReadKernelMemoryRange(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadKernelMemoryRangeOperation(a1, a2, a3, a4);
}

// CmdReadKernelMemoryRangeSize — 读取内核内存范围大小命令处理
// 对应原始驱动 sub_14006BA98
__int64 CmdReadKernelMemoryRangeSize(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadKernelMemoryRangeSizeOperation(a1, a2, a3, a4);
}

// CmdWriteKernelMemoryRange — 写入内核内存范围命令处理
// 对应原始驱动 sub_14006C510

// CmdEnumKernelMemoryDetail — 枚举内核内存详情命令处理
// 对应原始驱动 sub_14006B708
__int64 CmdEnumKernelMemoryDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelMemoryDetailOperation(a1, a2, a3, a4);
}

// CmdCallKernelMemoryFunction — 调用内核内存函数命令处理
// 对应原始驱动 sub_14006C42C

// CmdEnumObjectTypeDirectory — 枚举对象类型目录命令处理
// 对应原始驱动 sub_14006AC54
__int64 CmdEnumObjectTypeDirectory(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectTypeDirectoryOperation(a1, a2, a3, a4);
}

// CmdEnumObjectTypeTable — 枚举对象类型表命令处理
// 对应原始驱动 sub_14006B0AC
__int64 CmdEnumObjectTypeTable(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectTypeTableOperation(a1, a2, a3, a4);
}

// CmdEnumObjectTypeDetail — 枚举对象类型详情命令处理
// 对应原始驱动 sub_14006B49C
__int64 CmdEnumObjectTypeDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectTypeDetailOperation(a1, a2, a3, a4);
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
__int64 CmdReadMsrValue(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadMsrValueOperation(a1, a2, a3, a4);
}

// CmdWriteMsrValue — 写入 MSR 值命令处理
// 对应原始驱动 sub_140030F8C
__int64 CmdWriteMsrValue(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return WriteMsrValueOperation(a1, a2, a3, a4);
}

// CmdEnumProcessorInfo — 枚举处理器信息命令处理
// 对应原始驱动 sub_14002FDD4
__int64 CmdEnumProcessorInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessorInfoOperation(a1, a2, a3, a4);
}

// CmdSetProcessorField — 设置处理器字段命令处理
// 对应原始驱动 sub_140030420
__int64 CmdSetProcessorField(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetProcessorFieldOperation(a1, a2, a3, a4);
}

// InitFileSystemCallback — 初始化文件系统回调
// 对应原始驱动 sub_14000D704
__int64 CmdInitFileSystemCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InitFileSystemCallbackOperation(a1, a2, a3, a4);
}

// InitFileSystemFilter — 初始化文件系统过滤器
// 对应原始驱动 sub_14000EB40
__int64 CmdInitFileSystemFilter(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InitFileSystemFilterOperation(a1, a2, a3, a4);
}

// FileSystemFilterCallback — 文件系统过滤回调
// 对应原始驱动 sub_14000DAF0
__int64 CmdFileSystemFilterCallback(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return FileSystemFilterCallbackOperation(a1, a2, a3, a4);
}

// CmdCallSystemRoutine — 调用系统例程命令处理
// 对应原始驱动 sub_1400776D8
__int64 CmdCallSystemRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CallSystemRoutineOperation(a1, a2, a3, a4);
}

// CmdResetDriverState — 重置驱动状态命令处理
// 对应原始驱动 sub_140077758
__int64 CmdResetDriverState(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ResetDriverStateOperation(a1, a2, a3, a4);
}

// CmdEnumHookInfo — 枚举钩子信息命令处理
// 对应原始驱动 sub_140086AB0
__int64 CmdEnumHookInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumHookInfoOperation(a1, a2, a3, a4);
}

// CmdCheckBytePattern — 检查字节模式命令处理
// 对应原始驱动 sub_140086FD0
__int64 CmdCheckBytePattern(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return CheckBytePatternOperation(a1, a2, a3, a4);
}

// CmdGetHookEntryInfo — 获取钩子条目信息命令处理
// 对应原始驱动 sub_140086CD4
__int64 CmdGetHookEntryInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return GetHookEntryInfoOperation(a1, a2, a3, a4);
}

// CmdQueryHookStatus — 查询钩子状态命令处理
// 对应原始驱动 sub_140087074
__int64 CmdQueryHookStatus(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryHookStatusOperation(a1, a2, a3, a4);
}

// CmdEnumHookDetail — 枚举钩子详情命令处理
// 对应原始驱动 sub_140087DCC
__int64 CmdEnumHookDetail(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumHookDetailOperation(a1, a2, a3, a4);
}

// // CmdSetProcessContextWin8 — Win8 设置进程上下文命令处理
// 对应原始驱动 sub_140039C48
__int64 CmdSetProcessContextWin8(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetProcessContextWin8Operation(a1, a2, a3, a4);
}

// CmdReadKernelBase — 读取内核基址命令处理
// 对应原始驱动 sub_14002BA3C
__int64 CmdReadKernelBase(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ReadKernelBaseOperation(a1, a2, a3, a4);
}

// CmdClearKernelBase — 清除内核基址命令处理
// 对应原始驱动 sub_14002BB1C
__int64 CmdClearKernelBase(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ClearKernelBaseOperation(a1, a2, a3, a4);
}

// CmdEnumKernelModuleInfoEx — 枚举内核模块信息扩展命令处理
// 对应原始驱动 sub_14002BE50
__int64 CmdEnumKernelModuleInfoEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelModuleInfoExOperation(a1, a2, a3, a4);
}

// CmdSetKernelModuleInfo — 设置内核模块信息命令处理
// 对应原始驱动 sub_14002BF90
__int64 CmdSetKernelModuleInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetKernelModuleInfoOperation(a1, a2, a3, a4);
}

// CmdEnumProcessContextWin10 — Win10 枚举进程上下文命令处理
// 对应原始驱动 sub_140032180
__int64 CmdEnumProcessContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessContextWin10Operation(a1, a2, a3, a4);
}

// CmdSetProcessContextWin10 — Win10 设置进程上下文命令处理
// 对应原始驱动 sub_140032480
__int64 CmdSetProcessContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetProcessContextWin10Operation(a1, a2, a3, a4);
}

// CmdEnumRegistryContext — 枚举注册表上下文命令处理
// 对应原始驱动 sub_1400460B8
__int64 CmdEnumRegistryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumRegistryContextOperation(a1, a2, a3, a4);
}

// CmdSetRegistryContext — 设置注册表上下文命令处理
// 对应原始驱动 sub_14004630C
__int64 CmdSetRegistryContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetRegistryContextOperation(a1, a2, a3, a4);
}

// CmdEnumFileSystemContext — 枚举文件系统上下文命令处理
// 对应原始驱动 sub_14003E71C
__int64 CmdEnumFileSystemContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumFileSystemContextOperation(a1, a2, a3, a4);
}

// CmdSetFileSystemContext — 设置文件系统上下文命令处理
// 对应原始驱动 sub_14003E970
__int64 CmdSetFileSystemContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetFileSystemContextOperation(a1, a2, a3, a4);
}

// CmdEnumUSBPortSyscallTable — 枚举 USB 端口系统调用表命令处理
// 对应原始驱动 sub_140055A60
__int64 CmdEnumUSBPortSyscallTable(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumUSBPortSyscallTableOperation(a1, a2, a3, a4);
}

// CmdInstallUSBPortSyscallHook — 安装 USB 端口系统调用钩子命令处理
// 对应原始驱动 sub_140055CBC
__int64 CmdInstallUSBPortSyscallHook(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return InstallUSBPortSyscallHookOperation(a1, a2, a3, a4);
}

// CmdEnumObjectContext — 枚举对象上下文命令处理
// 对应原始驱动 sub_140037BD8
__int64 CmdEnumObjectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectContextOperation(a1, a2, a3, a4);
}

// CmdSetObjectContext — 设置对象上下文命令处理
// 对应原始驱动 sub_140037E54
__int64 CmdSetObjectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetObjectContextOperation(a1, a2, a3, a4);
}

// CmdEnumProcessProtectContext — 枚举进程保护上下文命令处理
// 对应原始驱动 sub_1400474D8
__int64 CmdEnumProcessProtectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumProcessProtectContextOperation(a1, a2, a3, a4);
}

// CmdSetProcessProtectContext — 设置进程保护上下文命令处理
// 对应原始驱动 sub_140047734
__int64 CmdSetProcessProtectContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetProcessProtectContextOperation(a1, a2, a3, a4);
}

// CmdEnumCallbackContext — 枚举回调上下文命令处理
// 对应原始驱动 sub_14003602C
__int64 CmdEnumCallbackContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumCallbackContextOperation(a1, a2, a3, a4);
}

// CmdSetCallbackContext — 设置回调上下文命令处理
// 对应原始驱动 sub_1400362C8
__int64 CmdSetCallbackContext(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetCallbackContextOperation(a1, a2, a3, a4);
}

// CmdEnumThreadContextWin10 — Win10 枚举线程上下文命令处理
// 对应原始驱动 sub_140057214
__int64 CmdEnumThreadContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumThreadContextWin10Operation(a1, a2, a3, a4);
}

// CmdSetThreadContextWin10 — Win10 设置线程上下文命令处理
// 对应原始驱动 sub_140057470
__int64 CmdSetThreadContextWin10(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return SetThreadContextWin10Operation(a1, a2, a3, a4);
}

// DisableObjectProtect — 禁用对象保护
// 对应原始驱动 sub_140081A6C
__int64 CmdDisableObjectProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DisableObjectProtectOperation(a1, a2, a3, a4);
}

// EnableObjectProtect — 启用对象保护
// 对应原始驱动 sub_140081A7A
__int64 CmdEnableObjectProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnableObjectProtectOperation(a1, a2, a3, a4);
}

// KernelNotifyRoutine — 内核通知例程
// 对应原始驱动 sub_140081BA0
__int64 CmdKernelNotifyRoutine(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return KernelNotifyRoutineOperation(a1, a2, a3, a4);
}

// KernelNotifyRoutineEx — 内核通知例程扩展
// 对应原始驱动 sub_140081C00
__int64 CmdKernelNotifyRoutineEx(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return KernelNotifyRoutineExOperation(a1, a2, a3, a4);
}

// CmdRestoreDriverDispatch — 恢复驱动分发命令处理
// 对应原始驱动 sub_140081280
__int64 CmdRestoreDriverDispatch(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return RestoreDriverDispatchOperation(a1, a2, a3, a4);
}

// CmdEnumRegistry — 枚举注册表命令处理
// 对应原始驱动 sub_14007E1E0
__int64 CmdEnumRegistry(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumRegistryOperation(a1, a2, a3, a4);
}

// CmdRegistryOperation — 注册表操作命令处理
// 对应原始驱动 sub_14007EA14
__int64 CmdRegistryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return RegistryOperationDispatch(a1, a2, a3, a4);
}

// CmdRegistryProtect — 注册表保护命令处理
// 对应原始驱动 sub_14007E498
__int64 CmdRegistryProtect(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return RegistryProtectOperation(a1, a2, a3, a4);
}

// CmdEnumServices — 枚举服务命令处理
// 对应原始驱动 sub_1400561BC
__int64 CmdEnumServices(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumServicesOperation(a1, a2, a3, a4);
}

// CmdEnumServiceTable — 枚举服务表命令处理
// 对应原始驱动 sub_140055DEC
__int64 CmdEnumServiceTable(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumServiceTableOperation(a1, a2, a3, a4);
}

// CmdEnumObjects — 枚举对象命令处理
// 对应原始驱动 sub_140036CF8
__int64 CmdEnumObjects(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumObjectsOperation(a1, a2, a3, a4);
}

// CmdObjectOperation — 对象操作命令处理
// 对应原始驱动 sub_1400363F8
__int64 CmdObjectOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ObjectOperation(a1, a2, a3, a4);
}

// CmdEnumKernelInfo — 枚举内核信息命令处理
// 对应原始驱动 sub_140088720
__int64 CmdEnumKernelInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return EnumKernelInfoOperation(a1, a2, a3, a4);
}

// CmdQueryMemoryInfo — 查询内存信息命令处理
// 对应原始驱动 sub_140084F34
__int64 CmdQueryMemoryInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryMemoryInfoOperation(a1, a2, a3, a4);
}

// CmdReadProcessMemoryEx — 读取进程内存扩展命令处理
// 对应原始驱动 sub_140071470

// CmdDeviceIoControl — 设备 IO 控制命令处理
// 对应原始驱动 sub_140070F74
__int64 CmdDeviceIoControl(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return DeviceIoControlOperation(a1, a2, a3, a4);
}

// CmdVirtualMemoryOp — 虚拟内存操作命令处理
// 对应原始驱动 sub_1400715C0

// CmdProcessMonitor — 进程监控命令处理
// 对应原始驱动 sub_140070D1C

// CmdEnumThreadsEx — 枚举线程扩展命令处理
// 对应原始驱动 sub_14004CE68

// CmdQueryModuleInfo — 查询模块信息命令处理
// 对应原始驱动 sub_140057D40
__int64 CmdQueryModuleInfo(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return QueryModuleInfoOperation(a1, a2, a3, a4);
}

// CmdModuleOperation — 模块操作命令处理
// 对应原始驱动 sub_140058890
__int64 CmdModuleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return ModuleOperationDispatch(a1, a2, a3, a4);
}

// MiniFilterStreamHandle — Minifilter 流句柄
// 对应原始驱动 sub_14001AB5C
// 读取 40 字节输入(ProcessId + EPROCESS + StreamData + StreamContext)，验证后调用 MiniFilterStreamHandleEx
__int64 CmdMiniFilterStreamHandle(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    bool Result = 0;
    if (a1 && a2 == 40 && (ULONG64)a1 < MmUserProbeAddress && (ULONG64)(a1 + 40) < MmUserProbeAddress)
    {
        _OWORD InputData;
        __int64 StreamDataLow;
        __int64 StreamDataHigh;
        __int64 StreamContext;
        NTSTATUS Status;
        int Status2;
        struct _KPROCESS *TargetProcess;
        struct _KPROCESS *v10;
        PEPROCESS Process;

        ProbeForRead((PVOID)a1, 0x28u, 4u);
        InputData = *(_OWORD *)a1;
        StreamDataLow = *((__int64 *)a1 + 2);
        StreamDataHigh = *((__int64 *)a1 + 3);
        StreamContext = *((__int64 *)a1 + 4);
        TargetProcess = (struct _KPROCESS *)InputData.qword[1];
        v10 = TargetProcess;
        Status = PsLookupProcessByProcessId((HANDLE)InputData.qword[0], &Process);
        Status2 = Status;
        if (!TargetProcess)
        {
            if (Status >= 0)
                TargetProcess = (struct _KPROCESS *)Process;
            v10 = TargetProcess;
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
// XxxOperation 函数实现
// 这些是 CmdXxx 包装器调用的实际操作函数
// ===================================================================

// ------------------------------------------------------------------
// 文件操作函数
// ------------------------------------------------------------------

// CreateFileWithPathOperation — 按路径创建文件操作
// 对应原始驱动 sub_14002D2EC
// 验证路径参数，创建文件并返回句柄
__int64 CreateFileWithPathOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _WORD *pFilePath = (_WORD *)a1;
    SIZE_T FilePathLength = (unsigned int)a2;
    _QWORD *pFileHandle = (_QWORD *)a3;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    void *FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pFileHandle || a4 != 8)
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
__int64 CloseHandleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    __int64 *pInputBuffer = (__int64 *)a1;
    __int64 HandleValue;
    unsigned int PreviousMode;
    struct _KTHREAD *CurrentThread;
    char PrevModeValue;
    int CloseResult;
    __int64 HandleValueCopy;
    __int64 (*pZwClose)(__int64);
    unsigned int v12;

    if (!pInputBuffer || a2 != 8)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 8, 8);
    HandleValue = *pInputBuffer;
    HandleValueCopy = *pInputBuffer;
    pZwClose = (__int64 (*)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    PreviousMode = GtRead(GtSdstServiceCount);
    v12 = PreviousMode;
    if (pZwClose && PreviousMode != -1 && CheckProcessJobObject(HandleValue))
    {
        CurrentThread = KeGetCurrentThread();
        PrevModeValue = *((_BYTE *)CurrentThread + v12);
        *((_BYTE *)CurrentThread + v12) = 0;
        CloseResult = pZwClose(HandleValueCopy);
        *((_BYTE *)CurrentThread + v12) = PrevModeValue;
        return CloseResult >= 0;
    }
    return 0;
}

// QueryFileInfoOperation — 查询文件信息操作
// 对应原始驱动 sub_14002D12C
// 查询文件标准信息，返回文件大小
__int64 QueryFileInfoOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    void **pInputHandle = (void **)a1;
    _QWORD *pOutputBuffer = (_QWORD *)a3;
    __int64 FileInfo;

    if (!pInputHandle || a2 != 8)
        return 0;
    if (!pOutputBuffer || a4 != 8)
        return 0;
    if ((ULONG64)pInputHandle >= MmUserProbeAddress ||
        (ULONG64)(pInputHandle + 1) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pOutputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputHandle, 8, 8);
    ProbeForWrite(pOutputBuffer, 8, 4);
    if (!(unsigned int)CmdQueryFileStandardInfo(*pInputHandle, &FileInfo))
    {
        *pOutputBuffer = FileInfo;
        return 1;
    }
    return 0;
}

// OpenFileHandleOperation — 打开文件句柄操作
// 对应原始驱动 sub_14002D070
// 查询文件分配大小
__int64 OpenFileHandleOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    void **pInputHandle = (void **)a1;
    _QWORD *pOutputBuffer = (_QWORD *)a3;
    __int64 FileSize;

    if (!pInputHandle || a2 != 8)
        return 0;
    if (!pOutputBuffer || a4 != 8)
        return 0;
    if ((ULONG64)pInputHandle >= MmUserProbeAddress ||
        (ULONG64)(pInputHandle + 1) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pOutputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputHandle, 8, 8);
    ProbeForWrite(pOutputBuffer, 8, 4);
    if (!(unsigned int)CmdQueryFileAllocationSize(*pInputHandle, &FileSize))
    {
        *pOutputBuffer = FileSize;
        return 1;
    }
    return 0;
}

// ReadFileSizeOperation — 读取文件大小操作
// 对应原始驱动 sub_14002D858
// 查询文件标准信息和卷数据
__int64 ReadFileSizeOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    void **pInputBuffer = (void **)a1;
    void *VolumeLabel;
    __int64 FileStandardInfo;

    if (!pInputBuffer || a2 != 16)
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
__int64 WriteFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    ULONG *pInputBuffer = (ULONG *)a1;
    _DWORD *pBytesWritten = a3;
    ULONG64 BufferSize;
    volatile void *pWriteBuffer;
    union _LARGE_INTEGER *Timeout;
    struct _IO_STATUS_BLOCK IoStatusBlock;

    if (!pInputBuffer || a2 != 24)
        return 0;
    if (!pBytesWritten || a4 != 4)
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
__int64 ReadFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    ULONG *pInputBuffer = (ULONG *)a1;
    _DWORD *pBytesRead = a3;
    ULONG64 BufferSize;
    volatile void *pReadBuffer;
    union _LARGE_INTEGER *Timeout;
    struct _IO_STATUS_BLOCK IoStatusBlock;

    if (!pInputBuffer || a2 != 24)
        return 0;
    if (!pBytesRead || a4 != 4)
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
__int64 ReadDirectoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    void **pInputBuffer = (void **)a1;
    ULONG64 FilePathLen;
    void *pOutputBuffer;
    SIZE_T PathSize;
    ULONG64 OutputBufferLen;
    void *pOutputBuffer2;
    unsigned __int64 LastCharIndex;
    _WORD *pFilePath;
    union _LARGE_INTEGER *Timeout;
    __int64 IoStatusBlock;

    if (!pInputBuffer || a2 != 40)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 5) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(pInputBuffer, 40, 4);
    FilePathLen = *((unsigned int *)pInputBuffer + 4);
    if ((unsigned int)FilePathLen <= 2 || (FilePathLen & 1) != 0)
        return 0;
    pOutputBuffer = pInputBuffer[1];
    if (!pOutputBuffer)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress)
        return 0;
    PathSize = (unsigned int)FilePathLen;
    if ((ULONG64)pOutputBuffer + 2 * FilePathLen >= MmUserProbeAddress ||
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
__int64 EnumDirectoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    ULONG *pInputBuffer = (ULONG *)a1;
    _BYTE *pHasMoreData = (_BYTE *)a3;
    char DotDir1 = 0;
    char DotDir2 = 0;
    bool IsRootPath = 0;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    ULONG64 OutputBufferLen;
    ULONG64 pOutputBuffer;
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

    if (!pInputBuffer || a2 != 24)
        return 0;
    if (!pHasMoreData || a4 != 1)
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
    pOutputBuffer = *((_QWORD *)pInputBuffer + 2);
    if (!pOutputBuffer)
        return 0;
    if (pOutputBuffer >= MmUserProbeAddress ||
        OutputBufferLen + pOutputBuffer >= MmUserProbeAddress ||
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
__int64 RenameFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    volatile void **pInputBuffer = (volatile void **)a1;
    ULONG64 OldPathLen;
    __int16 *pOldPath;
    SIZE_T OldPathSize;
    ULONG64 NewPathLen;
    volatile void *pNewPath;
    unsigned __int64 OldLastChar;
    unsigned __int64 NewLastChar;
    _WORD *pNewPath2;
    HANDLE FileHandle;

    if (!pInputBuffer || a2 != 32)
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
__int64 CopyFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    volatile void **pInputBuffer = (volatile void **)a1;
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

    if (!pInputBuffer || a2 != 32)
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
__int64 OpenFileForEnumOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _WORD *pFilePath = (_WORD *)a1;
    SIZE_T FilePathLength = (unsigned int)a2;
    _QWORD *pFileHandle = (_QWORD *)a3;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    void *FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pFileHandle || a4 != 8)
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
__int64 DeleteFileOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    unsigned int *pInputBuffer = (unsigned int *)a1;
    _DWORD *pResult = a3;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    unsigned __int64 LastCharIndex;
    HANDLE FileHandle;

    if (!pInputBuffer || a2 != 16)
        return 0;
    if ((ULONG64)pInputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pInputBuffer + 4) >= MmUserProbeAddress)
        return 0;
    if (!pResult || a4 != 4)
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
__int64 SetFileAttributesOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    unsigned int *pInputBuffer = (unsigned int *)a1;
    ULONG64 FilePathLen;
    volatile void *pFilePath;
    unsigned __int64 LastCharIndex;
    HANDLE FileHandle;
    _DWORD FileBasicInfo[10];

    if (!pInputBuffer || a2 != 16)
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
__int64 CheckFileExistOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _WORD *pFilePath = (_WORD *)a1;
    SIZE_T FilePathLength = (unsigned int)a2;
    _DWORD *pResult = a3;
    unsigned int LengthCopy = FilePathLength;
    unsigned int LastCharIndex;
    HANDLE FileHandle;

    if (!pFilePath || (unsigned int)FilePathLength <= 2 || (FilePathLength & 1) != 0)
        return 0;
    if (!pResult || a4 != 4)
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
__int64 ReadCpuMsrOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _OWORD *pOutputBuffer = (_OWORD *)a3;
    __int64 MsrBase1;
    __int64 MsrBase2;
    _QWORD MsrPair[2];
    _OWORD MsrDiffResult;
    RtlZeroMemory(&MsrDiffResult, sizeof(MsrDiffResult));

    if (!pOutputBuffer || a4 != 16)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pOutputBuffer + 1) >= MmUserProbeAddress)
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
        ProbeForWrite(pOutputBuffer, 16, 8);
        MsrPair[0] = MsrBase1;
        MsrPair[1] = MsrBase2;
        ForEachProcessor((__int64 (*)(_QWORD, __int64))ResolveKernelModuleBasePair, (__int64)MsrPair);
        *pOutputBuffer = *(_OWORD *)&MsrDiffResult;
        return 1;
    }
    return 0;
}

// ReadCpuIdOperation — 读取 CPU ID 操作
// 对应原始驱动 sub_14002B304
__int64 ReadCpuIdOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 0;
}

// ReadCpuBaseAddrOperation — 读取 CPU 基地址操作
// 对应原始驱动 sub_14002A45C
__int64 ReadCpuBaseAddrOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 0;
}

// ReadCpuInfoExOperation — 读取 CPU 信息扩展操作
// 对应原始驱动 sub_14002B36C
__int64 ReadCpuInfoExOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 0;
}

// ReadCpuBaseAddrExOperation — 读取 CPU 基地址扩展操作
// 对应原始驱动 sub_14002B944
__int64 ReadCpuBaseAddrExOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 0;
}

// GetKernelBaseLegacyOperation — 获取内核基址（旧版）操作
// 对应原始驱动 sub_14002B8DC
__int64 GetKernelBaseLegacyOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    return 0;
}

// ReadMsrValueOperation — 读取 MSR 值操作
// 对应原始驱动 sub_140030268
// 验证输出缓冲区，读取 MSR 表值输出到用户缓冲区
__int64 ReadMsrValueOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _QWORD *pOutputBuffer = (_QWORD *)a3;
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
        pOutputBuffer && a4 == 16 &&
        (ULONG64)pOutputBuffer < MmUserProbeAddress &&
        (ULONG64)(pOutputBuffer + 2) < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, 16, 8);
        *pOutputBuffer = 0;
        pOutputBuffer[1] = 0;
        *pOutputBuffer = *pMsrTable;
        if (*(volatile __int64 *)0xFFFFF780000002D4)
            MsrValue = MsrValue2;
        pOutputBuffer[1] = MsrValue;
        return 1;
    }
    return 0;
}

// WriteMsrValueOperation — 写入 MSR 值操作
// 对应原始驱动 sub_140030F8C
// 通过 InterlockedExchange64 原子交换 MSR 表值
__int64 WriteMsrValueOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
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
__int64 ReadPhysicalMemoryOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _BYTE *pOutputBuffer = (_BYTE *)a3;
    int Device0Ready;
    int Ctx0Ready;
    int Device2Ready;
    int Ctx2Ready;
    int Device1Ready;
    int Ctx1Ready;

    if (a4 != 7928)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)(pOutputBuffer + 7928) >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputBuffer, 7928, 1);
    memset(pOutputBuffer, 0, 7928);
    InitCallbackFunctions();
    Device0Ready = GtRead(GtEprocessField133 | 0x100);
    Ctx0Ready = GtRead(GtFltUnregisterFilterAddr | GtEprocessField22);
    Device2Ready = GtRead(GtEprocessField134 | 0x100);
    Ctx2Ready = GtRead(GtFltUnregisterFilterOffset | GtEprocessField22);
    Device1Ready = GtRead(GtKernelDataField18);
    Ctx1Ready = GtRead(GtFltDataSectionOffset | GtEprocessField22);

    if (EnumDeviceObjectTypeList(0, (__int64)(pOutputBuffer + 8)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 1;
        if (Device0Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputBuffer + 8), 0) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 8), 0, 0x1C) == 1)
            {
                pOutputBuffer[2] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(0, (__int64)(pOutputBuffer + 1352)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 2;
        if (Ctx0Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputBuffer + 1352), 0) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 1352), 0, 0x1B) == 1)
            {
                pOutputBuffer[3] = 1;
            }
        }
    }
    if (EnumDeviceObjectTypeList(2, (__int64)(pOutputBuffer + 2648)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 4;
        if (Device2Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputBuffer + 2648), 2) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 2648), 2, 0x1C) == 1)
            {
                pOutputBuffer[4] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(2, (__int64)(pOutputBuffer + 3992)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 8;
        if (Ctx2Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputBuffer + 3992), 2) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 3992), 2, 0x1B) == 1)
            {
                pOutputBuffer[5] = 1;
            }
        }
    }
    if (EnumDeviceObjectTypeList(1, (__int64)(pOutputBuffer + 5288)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 0x10;
        if (Device1Ready)
        {
            if (CopyPhysicalMemoryContextTable((__int64)(pOutputBuffer + 5288), 1) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 5288), 1, 0x1C) == 1)
            {
                pOutputBuffer[6] = 1;
            }
        }
    }
    if (InitPhysicalMemoryContextTable(1, (__int64)(pOutputBuffer + 6632)) == 1)
    {
        *(_WORD *)pOutputBuffer |= 0x20;
        if (Ctx1Ready)
        {
            if (CopyCallbackContextTable((__int64)(pOutputBuffer + 6632), 1) == 1 &&
                ResolvePhysicalMemoryContext((__int64)(pOutputBuffer + 6632), 1, 0x1B) == 1)
            {
                pOutputBuffer[7] = 1;
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
__int64 EnumProcessorInfoOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _DWORD *pOutputBuffer = a3;
    _DWORD *pProcessBuffer = 0;
    __int64 BufferSize = a4;
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

    if (!pOutputBuffer || (unsigned int)BufferSize < 0x58)
        return 0;
    if ((ULONG64)pOutputBuffer >= MmUserProbeAddress ||
        (ULONG64)pOutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(pOutputBuffer, BufferSize, 4);
    memset(pOutputBuffer, 0, (unsigned int)BufferSize);
    *pOutputBuffer = 0;
    RemainingEntries = (BufferSize - 88) / 0x50 + 1;
    ProcessorContext[0] = pOutputBuffer;
    ProcessorContext[1] = &RemainingEntries;
    ForEachProcessor((__int64 (*)(_QWORD, __int64))ReadThreadContext, (__int64)ProcessorContext);

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28 && RemainingEntries)
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
                                    GtRead(GtWindowsBuildNumber);
                                    if (CheckMemoryValid(pContextTable) == 1 &&
                                        CheckMemoryValid((char *)pContextTable + 399) == 1 &&
                                        (pContextTable[27] || pContextTable[28] || pContextTable[29] || pContextTable[30]))
                                    {
                                        if (!RemainingEntries)
                                            break;
                                        *((_BYTE *)&pOutputBuffer[20 * *pOutputBuffer + 2]) = 0;
                                        *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 4] = *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8];
                                        *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 6] = *(_QWORD *)((unsigned int)BasePriorityOffset + *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]);
                                        *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 8] = *(_QWORD *)((unsigned int)ObjectTableOffset + *(_QWORD *)&pProcessBuffer[ProcessSlotMul14 + 8]);
                                        EprocessAddr = *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 6];
                                        if (*pSectionBase != EprocessAddr &&
                                            EprocessAddr > (ULONG64)MmSystemRangeStart &&
                                            CheckMemoryValid(*(void **)&pOutputBuffer[20 * *pOutputBuffer + 6]) == 1 &&
                                            CheckMemoryValid((void *)(EprocessAddr + (unsigned int)EprocessOffsetVal + 7)) == 1 &&
                                            *(_QWORD *)((unsigned int)EprocessOffsetVal + EprocessAddr) > (ULONG64)MmSystemRangeStart)
                                        {
                                            *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 10] = pContextTable[27];
                                            *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 12] = pContextTable[28];
                                            *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 14] = pContextTable[29];
                                            *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 16] = pContextTable[30];
                                            *(_QWORD *)&pOutputBuffer[20 * *pOutputBuffer + 18] = pContextTable[31];
                                            *(_QWORD *)&pOutputBuffer[20 * (*pOutputBuffer)++ + 20] = pContextTable[32];
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
__int64 SetProcessorFieldOperation(__int64 a1, __int64 a2, _DWORD *a3, int a4)
{
    _BYTE *pInputBuffer = (_BYTE *)a1;
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

    if (!pInputBuffer || a2 != 16)
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

    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28)
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
                            GtRead(GtWindowsBuildNumber);
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
__int64 CopyKernelArrayToUserBufferOperation(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    SIZE_T BufferSize;
    char Result;
    char *pDataPtr;
    unsigned int EntryCount;

    BufferSize = a4;
    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField27 | 0x400))
        InitKernelMemoryContext();
    pDataPtr = (char *)GtRead(GtEprocessExtField58 | GtEprocessField27 | 0x400);
    EntryCount = GtRead(GtEprocessExtField58 | GtEprocessField28 | 0x400);
    if (pDataPtr && EntryCount && pDataPtr > MmSystemRangeStart &&
        EntryCount < 0x100 &&
        CheckMemoryValid(pDataPtr) == 1 &&
        CheckMemoryValid(&pDataPtr[8 * EntryCount - 1]) == 1 &&
        a3 && BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16 &&
        (unsigned __int64)a3 < MmUserProbeAddress &&
        (unsigned __int64)a3 + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(a3, BufferSize, 8);
        memset(a3, 0, BufferSize);
        *a3 = EntryCount;
        memmove(a3 + 2, pDataPtr, 8LL * EntryCount);
        return 1;
    }
    return Result;
}

// CopyKernelDualArrayToUserBufferOperation — 复制内核双数组到用户缓冲区操作
// 对应原始驱动 sub_14006BDA4 (CopyKernelDualArrayToUserBuffer)
__int64 CopyKernelDualArrayToUserBufferOperation(__int64 a1, __int64 a2, unsigned int *a3, unsigned int a4)
{
    SIZE_T BufferSize;
    char Result;
    char *pDataPtr;
    unsigned int EntryCount;
    char *pSecondArray;
    unsigned int EntryCountMinus1;
    unsigned int WinBuildNum;

    BufferSize = a4;
    Result = 0;
    if (!GtRead(GtEprocessExtField48 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pDataPtr = (char *)GtRead(GtEprocessExtField48 | GtEprocessField54 | 0x400);
    EntryCount = GtRead(GtEprocessExtField47 | GtEprocessField54 | 0x400);
    if (pDataPtr && EntryCount && pDataPtr > MmSystemRangeStart &&
        EntryCount < 0x100 && CheckMemoryValid(pDataPtr) == 1)
    {
        if (CheckMemoryValid(&pDataPtr[8 * EntryCount - 1]) == 1 && a3)
        {
            EntryCountMinus1 = EntryCount - 1;
            if (BufferSize >= 8 * (unsigned __int64)(EntryCount - 1) + 16 &&
                (unsigned __int64)a3 < MmUserProbeAddress &&
                (unsigned __int64)a3 + BufferSize < MmUserProbeAddress)
            {
                ProbeForWrite(a3, BufferSize, 8);
                memset(a3, 0, BufferSize);
                *a3 = EntryCount;
                WinBuildNum = GtRead(GtWindowsBuildNumber);
                if (WinBuildNum < 0x23F0)
                {
                    memmove(a3 + 2, pDataPtr, 8LL * EntryCount);
                }
                else
                {
                    pSecondArray = &pDataPtr[8 * EntryCount];
                    memmove(a3 + 2, pDataPtr, 8LL * EntryCountMinus1);
                    if (CheckMemoryValid(pSecondArray) == 1)
                        *(_QWORD *)&a3[2 * EntryCountMinus1 + 2] = *(_QWORD *)pSecondArray;
                }
                return 1;
            }
        }
    }
    return Result;
}

// ReadKernelMemoryToUserBufferOperation — 读取内核内存到用户缓冲区操作
// 对应原始驱动 sub_14006AFEC (ReadKernelMemoryToUserBuffer)
__int64 ReadKernelMemoryToUserBufferOperation(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    char Result;
    _QWORD *pKernelMemCtx;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    pKernelMemCtx = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField54 | 0x400);
    if (pKernelMemCtx && pKernelMemCtx > MmSystemRangeStart &&
        CheckMemoryValid(pKernelMemCtx) == 1 && a3 && a4 == 8 &&
        (unsigned __int64)a3 < MmUserProbeAddress &&
        (unsigned __int64)(a3 + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(a3, 8, 8);
        *a3 = 0;
        *a3 = *pKernelMemCtx;
        return 1;
    }
    return Result;
}

// ReadKernelMemoryRangeOperation — 读取内核内存范围操作
// 对应原始驱动 sub_14006BBB8 (CmdReadKernelMemoryRange)
__int64 ReadKernelMemoryRangeOperation(__int64 a1, __int64 a2, _QWORD *a3, int a4)
{
    char Result;
    _QWORD *pMacShimData;

    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400))
        InitKernelMemoryContext();
    pMacShimData = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField57 | 0x400);
    if (pMacShimData && pMacShimData > MmSystemRangeStart &&
        CheckMemoryValid(pMacShimData) == 1 && a3 && a4 == 8 &&
        (unsigned __int64)a3 < MmUserProbeAddress &&
        (unsigned __int64)(a3 + 1) < MmUserProbeAddress)
    {
        ProbeForWrite(a3, 8, 8);
        *a3 = 0;
        *a3 = *pMacShimData;
        return 1;
    }
    return Result;
}

// EnumKernelMemoryContextOperation — 枚举内核内存上下文操作
// 对应原始驱动 sub_14006A968 (EnumKernelMemoryContext)
__int64 EnumKernelMemoryContextOperation(__int64 a1, __int64 a2, _DWORD *a3, unsigned int a4)
{
    SIZE_T BufferSize;
    char Result;
    _QWORD *pMemCtxListHead;
    unsigned int EntryStepSize;
    _QWORD *pEntry;
    unsigned __int64 MaxEntries;
    unsigned int WinBuildNum;
    unsigned int i;

    BufferSize = a4;
    Result = 0;
    if (!GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400))
        InitKernelMemoryContext();
    pMemCtxListHead = (_QWORD *)GtRead(GtEprocessExtField58 | GtEprocessField32 | 0x400);
    EntryStepSize = GtRead(GtEprocessExtField42 | GtEprocessField54 | 0x400);
    if (pMemCtxListHead && pMemCtxListHead > MmSystemRangeStart && EntryStepSize &&
        *pMemCtxListHead > (unsigned __int64)MmSystemRangeStart)
    {
        pEntry = (_QWORD *)(*pMemCtxListHead + EntryStepSize);
        if (CheckMemoryValid(pEntry) == 1 && a3 && (unsigned int)BufferSize >= 0x18 &&
            (unsigned __int64)a3 < MmUserProbeAddress &&
            (unsigned __int64)a3 + BufferSize < MmUserProbeAddress)
        {
            ProbeForWrite(a3, BufferSize, 8);
            memset(a3, 0, BufferSize);
            *a3 = 0;
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
                                a3[4 * *a3 + 2] = *(_DWORD *)pEntry;
                                *(_QWORD *)&a3[4 * (*a3)++ + 4] = pEntry[1];
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
                            a3[4 * *a3 + 2] = *(_DWORD *)pEntry;
                            *(_QWORD *)&a3[4 * (*a3)++ + 4] = pEntry[1];
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
                        a3[4 * *a3 + 2] = *(_DWORD *)pEntry;
                        *(_QWORD *)&a3[4 * (*a3)++ + 4] = pEntry[1];
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
__int64 EnumProcessContextWin7Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
__int64 EnumProcessContextWin8Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
__int64 EnumProcessContextWin10Operation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
__int64 EnumProcessProtectContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int BufferSize)
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
__int64 EnumCallbackContextOperation(__int64 a1, __int64 a2, _WORD *pOutputBuffer, int OutputSize)
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
__int64 EnumThreadContextWin10Operation(__int64 a1, __int64 a2, _BYTE *a3, int a4)
{
    char Result;
    int TableReady;

    Result = 0;
    if (a3 && a4 == 1352 &&
        (unsigned __int64)a3 < MmUserProbeAddress &&
        (unsigned __int64)(a3 + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(a3, 0x548, 1);
        memset(a3, 0, 0x548);
        TableReady = GtRead(GtPathBuffer03 | 0x900);
        if (!TableReady)
        {
            InitThreadContextTable();
            TableReady = GtRead(GtPathBuffer03 | 0x900);
        }
        if (EnumThreadContextTable((__int64)(a3 + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (CopyThreadContextTable((__int64)(a3 + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(a3 + 8)) == 1)
                {
                    *a3 = 1;
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
__int64 EnumRegistryContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int BufferSize)
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
__int64 EnumFileSystemContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
__int64 EnumUSBPortSyscallTableOperation(__int64 a1, __int64 a2, _BYTE *a3, int a4)
{
    char Result;
    int TableReady;

    Result = 0;
    if (a3 && a4 == 1352 &&
        (unsigned __int64)a3 < MmUserProbeAddress &&
        (unsigned __int64)(a3 + 1352) < MmUserProbeAddress)
    {
        ProbeForWrite(a3, 0x548, 1);
        memset(a3, 0, 0x548);
        TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField186);
        if (!TableReady)
        {
            InitUSBPortSyscallTable();
            TableReady = GtRead(GtDisableHookProtectionAddr2 | GtEprocessField186);
        }
        if (CopyUSBPortServiceTable((__int64)(a3 + 8)) == 1)
        {
            Result = 1;
            if (TableReady)
            {
                if (DuplicateUSBPortSyscallOutput((__int64)(a3 + 8)) == 1 &&
                    ValidateSsdtHookTargetTable2((__int64)(a3 + 8)) == 1)
                {
                    *a3 = 1;
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
__int64 EnumObjectContextOperation(__int64 a1, __int64 a2, _BYTE *pOutputBuffer, int OutputSize)
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
    unsigned int v23;
    int v25;
    int v26;
    int v27;
    unsigned __int64 v28;

    if (!GtRead(GtEprocessExtField58 | GtEprocessField63 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField58 | GtEprocessField63 | 0x400);
    v28 = ContextPtr;
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
        v25 = RemainingSize;
        LoopIndex = 0;
        v27 = 0;
        while (LoopIndex < 2)
        {
            pNode = (_QWORD *)(ContextPtr + 80LL * LoopIndex);
            InnerLoopIndex = 0;
            v26 = 0;
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
                v23 = pEntry[1];
                if (v23)
                    *pEntry = 40 * (v23 - 1) + 56;
                else
                    *pEntry = 56;
                RemainingSize = v25 - *pEntry;
                v25 = RemainingSize;
                ++*pOutputBuffer;
                pEntry = (unsigned int *)((char *)pEntry + *pEntry);
                pNode = (_QWORD *)*pNode;
                InnerLoopIndex = ++v26;
            }
            LoopIndex = ++v27;
            ContextPtr = v28;
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
    int v17;
    _QWORD *pEntryArray;
    int v19;
    _QWORD *pSubEntry;
    unsigned int SubIndex;
    int v22;
    _QWORD *pSubEntry2;
    unsigned int SubIndex2;
    unsigned int v25;
    int v27;
    int v28;
    int v29;
    int v30;
    unsigned int v31;
    _QWORD *v32;
    _QWORD *v33;

    if (!GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400);
    pTable = (_QWORD *)ContextPtr;
    v33 = (_QWORD *)ContextPtr;
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
        v27 = 0;
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
                        v31 = EntryCount;
                        EntryIndex = 0;
                        v30 = 0;
                        while (1)
                        {
                            if (EntryIndex >= EntryCount || RemainingSize <= 0x30)
                            {
                                pTable = v33;
                                break;
                            }
                            v17 = GtRead(GtWindowsBuildNumber);
                            pEntryArray = (_QWORD *)(pTypeNode[8] + 24LL * EntryIndex);
                            v32 = pEntryArray;
                            if (v17 >= 0x47BA)
                            {
                                if (pEntryArray > MmSystemRangeStart && CheckMemoryValid(pEntryArray) == 1)
                                {
                                    *((_QWORD *)pEntry + 1) = pEntryArray;
                                    *(_QWORD *)pEntry = 0;
                                    v22 = ((unsigned __int64)RemainingSize - 40) / 0x18 + 1;
                                    pSubEntry2 = (_QWORD *)*pEntryArray;
                                    SubIndex2 = 0;
                                    v29 = 0;
                                    while (pSubEntry2 && pSubEntry2 != v32 && pSubEntry2 > MmSystemRangeStart && v22 && SubIndex2 <= 0x10000)
                                    {
                                        if (CheckMemoryValid(pSubEntry2) == 1 && pSubEntry2[3])
                                        {
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 4] = pSubEntry2;
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 6] = pSubEntry2[3];
                                            *(_QWORD *)&pEntry[6 * pEntry[1]++ + 8] = 0;
                                            --v22;
                                        }
                                        SubIndex2 = ++v29;
                                        pSubEntry2 = (_QWORD *)*pSubEntry2;
                                    }
                                    goto LABEL_47;
                                }
                            }
                            else if (pEntryArray > MmSystemRangeStart && CheckMemoryValid(pEntryArray) == 1)
                            {
                                *((_QWORD *)pEntry + 1) = pEntryArray;
                                *(_QWORD *)pEntry = 0;
                                v19 = ((unsigned __int64)RemainingSize - 40) / 0x18 + 1;
                                pSubEntry = (_QWORD *)*pEntryArray;
                                SubIndex = 0;
                                v28 = 0;
                                while (pSubEntry && pSubEntry != v32 && pSubEntry > MmSystemRangeStart && v19 && SubIndex <= 0x10000)
                                {
                                    if (CheckMemoryValid(pSubEntry) == 1)
                                    {
                                        GtRead(GtWindowsBuildNumber);
                                        if (pSubEntry[3])
                                        {
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 4] = pSubEntry;
                                            *(_QWORD *)&pEntry[6 * pEntry[1] + 6] = pSubEntry[3];
                                            *(_QWORD *)&pEntry[6 * pEntry[1]++ + 8] = 0;
                                            --v19;
                                        }
                                    }
                                    SubIndex = ++v28;
                                    pSubEntry = (_QWORD *)*pSubEntry;
                                }
                                goto LABEL_47;
                            }
                            v30 = ++EntryIndex;
                            EntryCount = v31;
                            continue;
                        LABEL_47:
                            v25 = pEntry[1];
                            if (v25)
                                *pEntry = 40 * (v25 - 1) + 48;
                            else
                                *pEntry = 48;
                            RemainingSize -= *pEntry;
                            ++*pOutputBuffer;
                            pEntry = (unsigned int *)((char *)pEntry + *pEntry);
                            EntryIndex = v30;
                        }
                    }
                }
                NodeIndex = v27;
            }
            v27 = ++NodeIndex;
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
    int v18;
    unsigned int v19;
    _QWORD *v20;

    if (!GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400))
        InitKernelMemoryContext();
    ContextPtr = GtRead(GtEprocessExtField55 | GtEprocessField54 | 0x400);
    pTable = (_QWORD *)ContextPtr;
    v20 = (_QWORD *)ContextPtr;
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
                v19 = EntryCount;
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
                    EntryCount = v19;
                }
                pTable = v20;
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
    int v4;
    unsigned int v5;
    char v7;

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
        v7 = 1;
        goto LABEL_16;
    case 1:
        v7 = 0;
LABEL_16:
        *((_DWORD *)pInputBuffer + 2) = 0x40000;
        return ReadDiskSectorsWithPartition(v7, pInputBuffer + 12, (unsigned int *)pInputBuffer + 2, *((_DWORD *)pInputBuffer + 1), 0x1000);
    case 2:
        v5 = *((_DWORD *)pInputBuffer + 2);
        if (v5 <= 0x40000)
        {
            *((_BYTE *)&v4) = 1;
            return WriteDiskSectorsWithPartitionCheck(v4, pInputBuffer + 12, v5);
        }
        break;
    default:
        v4 = *(_DWORD *)pInputBuffer - 3;
        if (*(_DWORD *)pInputBuffer == 3)
        {
            v5 = *((_DWORD *)pInputBuffer + 2);
            if (v5 <= 0x40000)
                return WriteDiskSectorsWithPartitionCheck(v4, pInputBuffer + 12, v5);
        }
        break;
    }
    return Result;
}

// DiskReadSectorOperation — 磁盘读取扇区操作
// 对应原始驱动 sub_14007B854 (CmdDiskReadSector)
// 读取磁盘扇区数据
__int64 DiskReadSectorOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    return 0;
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
    _QWORD *v6;
    char Result;
    SIZE_T StringSize;
    volatile void *pStringBuffer;
    unsigned __int64 v10;
    __int64 v11;
    int v27;
    __int64 v28;
    _BYTE *v29;
    _OWORD v31;
    _BYTE v32[24];

    v6 = 0;
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
                    v10 = ((unsigned __int64)pInputBuffer[2] - 2) >> 1;
                    v11 = *((_QWORD *)pInputBuffer + 2);
                    if (*(_WORD *)(v11 + 2 * v10))
                        *(_WORD *)(v11 + 2 * v10) = 0;
                    InitUnicodeStringBuffer((__int64)v32, *((_QWORD *)pInputBuffer + 2), pInputBuffer[2]);
                    v27 = 48;
                    v28 = 0;
                    RtlZeroMemory(&v31, sizeof(v31));
                    v29 = v32;
                    Result = SendFsctlWithHookSwap((__int64)pOutputBuffer, *pInputBuffer, (__int64)&v27, 0, 0, pInputBuffer[1], 0);
                    if (!Result)
                    {
                        {
                            struct _KTHREAD *CurrentThread;
                            _DWORD *v14;
                            _DWORD *v15;
                            char v16;
                            int (*v21)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD);
                            unsigned int v12;
                            void (*v20)(_DWORD *);
                            __int64 *v22;
                            _QWORD *v23;
                            __int64 v24;
                            __int64 v19;
                            unsigned int PrevMode;

                            v21 = (int (*)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD))GtRead(GtEprocessField101 | 0x100);
                            v12 = GtRead(GtSdstServiceCount);
                            v20 = (void (*)(_DWORD *))GtRead(GtCloseHandleFunc);
                            if (!v21 || v12 == -1)
                            {
                                int (*v17)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD);
                                v17 = (int (*)(volatile void *, _QWORD, int *, _QWORD, _QWORD, unsigned int, _QWORD))GtRead(GtTotalSize | GtIrpBufferSize | GtEprocessField10);
                                if (v17)
                                    return v17(pOutputBuffer, *pInputBuffer, &v27, 0, 0, pInputBuffer[1], 0) >= 0;
                            }
                            else
                            {
                                CurrentThread = KeGetCurrentThread();
                                v22 = SwapKernelMemoryPointer(&v24);
                                v14 = 0;
                                v23 = 0;
                                v19 = 0;
                                if (v20)
                                {
                                    v15 = SendIoControlWithUnicodeString((__int64)&v27);
                                    v14 = v15;
                                    if (v15)
                                    {
                                        v6 = (_QWORD *)DispatchHookSwapByVersion((__int64)v15, &v19);
                                        v23 = v6;
                                    }
                                }
                                PrevMode = *((_BYTE *)CurrentThread + v12);
                                *((_BYTE *)CurrentThread + v12) = 0;
                                Result = v21(pOutputBuffer, *pInputBuffer, &v27, 0, 0, pInputBuffer[1], 0) >= 0;
                                *((_BYTE *)CurrentThread + v12) = PrevMode;
                                if (v14)
                                {
                                    if (v6)
                                        *v6 = v19;
                                    v20(v14);
                                }
                                if (v22)
                                    *v22 = v24;
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
    __int64 v7 = 0;
    __int64 v8 = 0;
    int MaxEntries;

    pServiceTable = (__int64 *)GtRead(GtCallbackField17);
    if (!pServiceTable)
    {
        BuildServiceTableFromNtKernel(v8, v7);
        pServiceTable = (__int64 *)GtRead(GtCallbackField17);
    }
    if (pServiceTable && pOutputBuffer && OutputSize >= 0x38 &&
        (unsigned __int64)pOutputBuffer < MmUserProbeAddress &&
        (unsigned __int64)pOutputBuffer + OutputSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, OutputSize, 1);
        *pOutputBuffer = 0;
        MaxEntries = (OutputSize - 56) / 0x30 + 1;
        if (GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            if (GtRead(GtWindowsBuildNumber) == 6000)
                EnumServiceTableWin10(pServiceTable, (__int64)(pOutputBuffer + 2), pOutputBuffer, MaxEntries);
            else if (GtRead(GtWindowsBuildNumber) >= 0x23F0)
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
__int64 EnumServiceTableOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    __int64 *pEntry;
    __int64 v5 = 0;
    __int64 v6 = 0;
    __int64 **pServiceTable;

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
            BuildServiceTableFromNtKernel(v6, v5);
            pServiceTable = (__int64 **)GtRead(GtCallbackField17);
        }
        if (pEntry && pServiceTable)
        {
            if (GtRead(GtWindowsBuildNumber) < 0x1770)
                return RemoveServiceTableNodeWin7(pServiceTable, (__int64)pEntry);
            if (GtRead(GtWindowsBuildNumber) == 6000)
                return RemoveServiceEntryFromList(pServiceTable, (__int64)pEntry);
            if (GtRead(GtWindowsBuildNumber) >= 0x23F0)
                return RemoveServiceTableNodeWin10(pServiceTable, pEntry);
            return RemoveServiceEntryFromListEx((__int64 ***)pServiceTable, (__int64 **)pEntry);
        }
    }
    return Result;
}

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
    struct _KPROCESS *v10;
    __int64 v11[2];

    Result = 0;
    Process = 0;
    if (pInputBuffer && InputSize == 32 &&
        (unsigned __int64)pInputBuffer < MmUserProbeAddress &&
        (unsigned __int64)(pInputBuffer + 32) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 0x20, 4);
        InputData[0] = *(__int64 *)pInputBuffer;
        InputData[1] = *(__int64 *)(pInputBuffer + 8);
        v11[0] = *(__int64 *)(pInputBuffer + 16);
        v11[1] = *(__int64 *)(pInputBuffer + 24);
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
            v10 = pProcess;
        }
        if (ValidateProcessObject(pProcess, 0) == 1 && v11[1])
            Result = QueryFileInfoByHandle((__int64)pProcess, v11[0], v11[1]);
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
    __int64 v15;
    unsigned int EntryCount;
    _DWORD *pEntry;
    unsigned int Index;
    PVOID v19;
    __int64 v20;
    unsigned int v22;

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
    if (GtRead(GtWindowsBuildNumber) < 0x1DB0)
        StrideSize = 48;
    else if (GtRead(GtWindowsBuildNumber) == 9200)
        StrideSize = 72;
    else if (GtRead(GtWindowsBuildNumber) < 0x585D)
    {
        if (GtRead(GtWindowsBuildNumber) < 0x4F7C)
            StrideSize = GtRead(GtWindowsBuildNumber) < 0x2580 ? 64 : 80;
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
        if (GtRead(GtWindowsBuildNumber) < 0x1DB0)
        {
            if (*(_DWORD *)pData)
            {
                pOutputBuffer[4] = -1;
                *((_QWORD *)pOutputBuffer + 3) = pData[1];
                *((_QWORD *)pOutputBuffer + 4) = pData[2];
                v15 = pData[3];
                goto LABEL_31;
            }
        }
        else if (*((_DWORD *)pData + 1))
        {
            pOutputBuffer[4] = -1;
            *((_QWORD *)pOutputBuffer + 3) = pData[2];
            *((_QWORD *)pOutputBuffer + 4) = pData[3];
            v15 = pData[4];
LABEL_31:
            *((_QWORD *)pOutputBuffer + 5) = v15;
            *((_BYTE *)pOutputBuffer + 8) = 1;
        }
    }
    EntryCount = *(_DWORD *)pEnd;
    v22 = *(_DWORD *)pEnd;
    *pOutputBuffer = *(_DWORD *)pEnd;
    pEntry = (_DWORD *)pEnd[1];
    if (pEntry > MmSystemRangeStart)
    {
        for (Index = 0; ; ++Index)
        {
            if (Index >= EntryCount || !(_DWORD)MaxEntries ||
                CheckMemoryValid(pEntry) != 1 || CheckMemoryValid((char *)pEntry + StrideSize - 1) != 1)
                return 1;
            if (GtRead(GtWindowsBuildNumber) < 0x1DB0)
            {
                if (!*pEntry)
                    goto LABEL_47;
                pOutputBuffer[8 * pOutputBuffer[1] + 12] = Index;
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 14] = *((_QWORD *)pEntry + 1);
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 16] = *((_QWORD *)pEntry + 2);
                v20 = *((_QWORD *)pEntry + 3);
            }
            else
            {
                if (!pEntry[1])
                    goto LABEL_47;
                pOutputBuffer[8 * pOutputBuffer[1] + 12] = Index;
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 14] = *((_QWORD *)pEntry + 2);
                *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 16] = *((_QWORD *)pEntry + 3);
                v19 = (PVOID)*((_QWORD *)pEntry + 4);
                if (v19 <= MmSystemRangeStart || CheckMemoryValid(v19) != 1)
                    goto LABEL_46;
                v20 = *((_QWORD *)pEntry + 4);
            }
            *(_QWORD *)&pOutputBuffer[8 * pOutputBuffer[1] + 18] = v20;
LABEL_46:
            ++pOutputBuffer[1];
            MaxEntries = (unsigned __int64)((int)MaxEntries - 1);
LABEL_47:
            pEntry = (_DWORD *)((char *)pEntry + StrideSize);
            EntryCount = v22;
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
        TargetAddress = pInputBuffer[1];
        if (!TargetAddress)
            return FlagWriteResult & FlagRestoreResult;
        if (*(_BYTE *)pInputBuffer == 1 && pInputBuffer[2])
        {
            if (MmIsAddressValid(pInputBuffer[1]) != 1)
                goto LABEL_24;
            if (MmIsAddressValid(pInputBuffer[2]) == 1)
            {
                if (GtRead(GtWindowsBuildNumber) == 2195 ||
                    GtRead(GtWindowsBuildNumber) == 9200 ||
                    GtRead(GtWindowsBuildNumber) == 9600)
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
// 对应原始驱动 PowerCallbackRoutine (0x140011240)
__int64 PowerCallbackRoutineOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Success;

    // NOTE: 此函数实现较复杂，涉及内核内存映射和逐页拷贝
    // 完整实现需要大量辅助函数，使用桩函数返回0
    // TODO: 实现完整逻辑
    Success = 0;
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

// 查询系统信息扩展操作
// 对应原始驱动 CmdQuerySystemInfoEx (0x14006EC24)
__int64 QuerySystemInfoExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // 此函数输出17种对象类型信息到缓冲区，缓冲区大小要求 0xE78 字节
    // 完整实现较复杂，需要大量辅助函数
    // 使用桩函数暂时代替
    return 0;
}

// 回调控制操作
// 对应原始驱动 CmdCallbackControl (0x140070190)
__int64 CallbackControlOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char Result;
    void **CallbackAddr;
    unsigned int CallbackType;
    unsigned __int64 CallbackValue;

    // NOTE: 完整实现需要大量回调处理函数
    // 使用桩函数暂时代替
    return 0;
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
        *pOutputBuffer = GtRead(GtWindowsBuildNumber);
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
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
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

// 初始化对象回调操作
// 对应原始驱动 InitObjectCallback (0x14000F0F4)
__int64 InitObjectCallbackOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // 此函数较复杂，枚举进程列表和对象类型信息
    // 使用桩函数暂时代替
    return 0;
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
    _QWORD *v6;
    char v7;
    SIZE_T v8;
    volatile void *v9;
    __int64 v10;
    unsigned __int64 v11;
    __int64 v12;
    unsigned int v13;
    struct _KTHREAD *CurrentThread;
    _DWORD *v15;
    _DWORD *v16;
    char v17;
    unsigned int (__fastcall *v18)(volatile void *, _QWORD, int *);
    __int64 v20;
    void (__fastcall *v21)(_DWORD *);
    unsigned int (__fastcall *v22)(volatile void *, _QWORD, int *);
    __int64 *v23;
    _QWORD *v24;
    __int64 v25;
    struct _KTHREAD *v26;
    _DWORD *v27;
    int v28;
    __int64 v29;
    _BYTE *v30;
    int v31;
    _OWORD v32;
    _BYTE v33[24];
    unsigned int v34;

    // NOTE: 完整实现较复杂，使用桩函数暂时代替
    return 0;
}

// 简单设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlSimple (0x1400751D4)
__int64 DeviceIoControlSimpleOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 使用桩函数暂时代替
    return 0;
}

// 带缓冲设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlWithBuffer (0x1400753A4)
__int64 DeviceIoControlWithBufferOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 使用桩函数暂时代替
    return 0;
}

// 带字符串设备IO控制操作
// 对应原始驱动 CmdDeviceIoControlWithString (0x14007562C)
__int64 DeviceIoControlWithStringOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 使用桩函数暂时代替
    return 0;
}

// 打开节对象操作
// 对应原始驱动 CmdOpenSectionObject (0x140074128)
__int64 OpenSectionObjectOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    char v3;
    __int64 v4;
    unsigned int v5;
    struct _KTHREAD *CurrentThread;
    char v7;
    int (__fastcall *v8)(__int64);
    __int64 v10;
    int (__fastcall *v11)(__int64);
    unsigned int v12;

    v3 = 0;
    if (pInputBuffer && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 8) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8, 8);
        v4 = *(__int64 *)pInputBuffer;
        v10 = *(__int64 *)pInputBuffer;
        v3 = OpenSectionWithIoControl(*(__int64 *)pInputBuffer);
        if (!v3)
        {
            v11 = (int (__fastcall *)(__int64))GtRead(GtEprocessField107 | 0x100);
            v5 = GtRead(GtSdstServiceCount);
            v12 = v5;
            if (!v11 || v5 == -1)
            {
                v8 = (int (__fastcall *)(__int64))GtRead(GtTotalSize | GtObjectTypeField07 | GtNtoskrnlImageSize);
                if (v8)
                    return v8(v4) >= 0;
            }
            else
            {
                CurrentThread = KeGetCurrentThread();
                v7 = *((char *)CurrentThread + v5);
                *((char *)CurrentThread + v5) = 0;
                v3 = v11(v10) >= 0;
                *((char *)CurrentThread + v12) = v7;
            }
        }
    }
    return v3;
}

// 写入进程内存扩展操作
// 对应原始驱动 CmdWriteProcessMemoryEx (0x1400749A0)
__int64 WriteProcessMemoryExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 完整实现较复杂，使用桩函数暂时代替
    return 0;
}

// 枚举进程列表扩展操作
// 对应原始驱动 CmdEnumProcessListEx (0x140062ED8)
__int64 EnumProcessListExOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 此函数较大(0x3777字节)，需要单独分析
    return 0;
}

// 枚举进程列表(Win7)操作
// 对应原始驱动 CmdEnumProcessListWin7 (0x14005A5E8)
__int64 EnumProcessListWin7Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 此函数较大(0x20C8字节)，需要单独分析
    return 0;
}

// 枚举进程列表(Win8)操作
// 对应原始驱动 CmdEnumProcessListWin8 (0x14005C6B0)
__int64 EnumProcessListWin8Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 此函数较大(0x1CA4字节)，需要单独分析
    return 0;
}

// 枚举进程列表(Win10)操作
// 对应原始驱动 CmdEnumProcessListWin10 (0x14005E354)
__int64 EnumProcessListWin10Operation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    // NOTE: 此函数较大(0x258D字节)，需要单独分析
    return 0;
}

// 枚举对象目录操作
// 对应原始驱动 CmdEnumObjectDirectory (0x140084618)
__int64 EnumObjectDirectoryOperation(char *pInputBuffer, int InputSize, unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned int v6;
    char Result;
    __int64 v9;
    _DWORD *SystemInfo;

    v6 = InputSize;
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
        v9 = (v6 >> 1) - 1;
        if (((unsigned __int16 *)pInputBuffer)[v9])
            ((unsigned __int16 *)pInputBuffer)[v9] = 0;
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
    PVOID v4;
    void *v5;
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
                    v4 = ExAlloc(PagedPool, (unsigned int)Length + 2);
                    v5 = v4;
                    if (v4)
                    {
                        memset(v4, 0, (unsigned int)Length);
                        memmove(v5, (const void *)Addressa[1], (unsigned int)Length);
                        Result = (unsigned char)InitObjectTypeTable(v5) == 1;
                        ExFree(v5);
                    }
                }
            }
        }
    }
    return Result;
}

