// ProcessMgmt.c — 进程管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include <intrin.h>
#include "..\inc\XPCHunterDrv.h"
// Forward declarations
bool IsProcessObjectTerminated(char *VirtualAddress);
bool ReadUser32DllFile(_QWORD *FileBuffer, unsigned int *FileSize, char Is64Bit);
__int64 ParseNtRelocationTable(PUCHAR ImageBase);
ULONG64 ParseNtRelocationTableEx(PRKPROCESS Process, char IsWin32kFlag, _QWORD *OutImageBase, _QWORD *OutImageSize, void **OutDataBuffer);
WORD *InitSystemPath(void);
__int16 *WStringCopy(__int16 *Dest, __int16 *Src);
__int64 BuildDevicePathFromObjects(unsigned __int16 *Dst, unsigned int *p33, int *p23);
__int64 GetKernelVirtualAddressRange(__int64 *RangeStart, __int64 *RangeEnd);
__int64 GtWrite(enum _GLOBAL_TABLE_INDEX Index, __int64 Value);

// 外部函数声明（在其他模块中定义，未在头文件中声明）
char ReturnFalseStub(void);
char ValidateEnumerationResult(__int64 a1, __int64 a2, __int64 a3);
__int64 CallRegisteredCallback(__int64 a1, __int64 a2);

// 本文件后向引用前向声明
ULONG64 FindModuleInLoaderList(_QWORD **ListHead, _QWORD *TargetName);
__int64 FindWin32kServiceTableByPattern(__int64 ImageBase, unsigned int ImageSize, unsigned int ExportOffset);
ULONG64 FindUser32ModuleInList(unsigned int *ListHead, int Depth);
__int64 ScanWin32kSectionForServiceTable(__int64 ImageBase, unsigned int ImageSize);

extern POBJECT_TYPE MmSectionObjectType;

// DisableProcessProtect — 禁用进程保护
// 对应原始驱动 sub_14000700C
// 写入内存值恢复原始状态，清理进程保护上下文
char DisableProcessProtect(_OWORD *Address, int InputSize)
{
    char Result;
    int Status;
    char WriteSuccess;
    NTSTATUS LookupStatus;
    struct _KPROCESS *ProcessObject;
    char IsWin32k;
    char BufferWriteSuccess;
    PEPROCESS Process;
    _OWORD InputBuffer[2];
    _OWORD ProcessIdPairCopy;
    _OWORD OutputBuffer;
    __int64 BufferTail;
    _OWORD InputProcessIdPair;

    Result = 0;
    Process = NULL;
    Status = -1073741823;

    if (!Address || InputSize != 72 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)&Address[4].qword[1] >= MmUserProbeAddress)
        goto Cleanup;

    WriteSuccess = 1;
    ProbeForRead(Address, 0x48, 1);

    InputProcessIdPair = *(_OWORD *)Address;
    InputBuffer[0] = InputProcessIdPair;
    InputBuffer[1] = Address[1];
    ProcessIdPairCopy = Address[2];
    OutputBuffer = Address[3];
    BufferTail = Address[4].qword[0];

    LookupStatus = PsLookupProcessByProcessId(
        (HANDLE)InputProcessIdPair.qword[1], &Process);
    Status = LookupStatus;
    ProcessObject = (struct _KPROCESS *)InputProcessIdPair.qword[0];
    *(ULONG64 *)&InputBuffer[0] = InputProcessIdPair.qword[0];

    if (!InputProcessIdPair.qword[0])
    {
        if (LookupStatus >= 0)
            ProcessObject = (struct _KPROCESS *)Process;
        *(ULONG64 *)&InputBuffer[0] = (ULONG64)ProcessObject;
    }

    if (ValidateProcessObject(ProcessObject, NULL) == 1)
    {
        IsWin32k = 1;
        *(WORD *)&OutputBuffer.qword[0] = 257;
        BufferWriteSuccess = 1;

        if (ProcessIdPairCopy.qword[0])
        {
            IsWin32k = WriteProcessMemoryValue(InputBuffer);
            BufferWriteSuccess = *((UCHAR *)&OutputBuffer.qword[0] + 1);
        }

        if (BufferWriteSuccess == 1)
            WriteSuccess = WriteProcessMemoryBuffer(InputBuffer);

        Result = IsWin32k & WriteSuccess;
    }

Cleanup:
    if (Status >= 0 && Process)
        ObfDereferenceObject(Process);

    return Result;
}

// InitProcessCallback — 初始化进程回调
// 对应原始驱动 sub_1400106C0
// 清除调试端口，检查进程保护标记
char InitProcessCallback(struct _KPROCESS **ProcessPtr, int BufferSize)
{
    char Success;
    struct _KPROCESS *ProcessObject;
    ULONG DebugPortOffset;
    ULONG SectionOffset;
    __int64 (__fastcall *TerminateFunc)(struct _KPROCESS *, ULONG64);

    Success = 0;
    if (BufferSize == 8 &&
        (ULONG64)ProcessPtr < MmUserProbeAddress &&
        (ULONG64)(ProcessPtr + 1) < MmUserProbeAddress)
    {
        ProbeForRead(ProcessPtr, 8, 8);
        ProcessObject = *ProcessPtr;
        if (ValidateProcessObject(ProcessObject, ProcessObject) == 1)
        {
            DebugPortOffset = (ULONG)GtRead(GtDebugPortOffset);
            if (DebugPortOffset)
            {
                *((UCHAR *)ProcessObject + DebugPortOffset) = 0;
                Success = 1;
            }
            SectionOffset = (ULONG)GtRead(GtProcessSectionOffset);
            if (SectionOffset)
            {
                if (*(WORD *)((char *)ProcessObject + SectionOffset) != 8364)
                {
                    TerminateFunc = (__int64 (__fastcall *)(struct _KPROCESS *, ULONG64))GtRead(GtMemoryCheckFunc);
                    if (TerminateFunc)
                        return TerminateFunc(ProcessObject, 0);
                }
            }
        }
    }
    return Success;
}

// ProcessCallbackRoutine — 进程回调例程
// 对应原始驱动 sub_140010780
// 枚举受保护进程列表，检查保护状态，输出进程信息
char ProcessCallbackRoutine(__int64 Reserved, __int64 Reserved2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Success = 0;
    ULONG64 BufferSizeCopy;
    ULONG64 MaxEntryCount;
    unsigned int *ProcessBuffer, *ProcessBufferPtr;
    ULONG ProcessCount, ProcessIndex, ProcessOffset;
    int ProtectionType;
    ULONG RemainingCount, CurrentIndex;

    if (BufferSize < 0x228 || (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Success;

    BufferSizeCopy = BufferSize;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    memset(OutputBuffer, 0, (ULONG)BufferSizeCopy);

    MaxEntryCount = BufferSizeCopy / 0x228;
    RemainingCount = (ULONG)MaxEntryCount;
    *OutputBuffer = 0;

    ProcessBuffer = ExAlloc(PagedPool, 0x43850);
    ProcessBufferPtr = ProcessBuffer;
    if (!ProcessBuffer) return Success;

    if (ValidateProcessContext(ProcessBuffer, 0x43850))
    {
        ProcessCount = *ProcessBufferPtr;
        for (ProcessIndex = 0; ProcessIndex < ProcessCount && (ULONG)MaxEntryCount; ProcessIndex++)
        {
            ProcessOffset = 138 * ProcessIndex;
            if (CheckProcessProtection(*(__int64 *)&ProcessBufferPtr[ProcessOffset + 10], &ProtectionType) == 1)
            {
                OutputBuffer[136 * *OutputBuffer + 2] = ProtectionType;
                *(__int64 *)&OutputBuffer[136 * *OutputBuffer + 6] = *(__int64 *)&ProcessBufferPtr[ProcessOffset + 10];
                *(__int64 *)&OutputBuffer[136 * *OutputBuffer + 4] = *(__int64 *)&ProcessBufferPtr[ProcessOffset + 6];
                WStringCopyN(&OutputBuffer[136 * *OutputBuffer + 8],
                    (__int64)&ProcessBufferPtr[ProcessOffset + 12], 0x104);
                ++*OutputBuffer;
                MaxEntryCount--;
                RemainingCount = (ULONG)MaxEntryCount;
            }
            CurrentIndex = ProcessIndex;
        }
        Success = 1;
    }

    ExFree(ProcessBufferPtr);
    return Success;
}

// EnumerateProcessListEntry — 枚举进程链表条目
// 对应原始驱动 sub_1400503DC
// 遍历双向链表，最大 0x10000 项
void EnumerateProcessListEntry(_QWORD **ListHead, unsigned int Offset, __int64 OutputBuffer, unsigned int BufferSize)
{
    if (!ListHead || MmIsAddressValid(ListHead) != 1) return;

    _QWORD *Current = *ListHead;
    ULONG Count = 0;

    while (Current != ListHead)
    {
        if (!MmIsAddressValid(Current)) break;
        if (++Count > 0x10000) break;
        FillProcessInformationEntry((char *)Current - Offset, (char *)Current - Offset,
            OutputBuffer, BufferSize, 0, 1, 0);
        Current = (_QWORD *)*Current;
    }
}

// QueryProcessInfoByHandle — 通过句柄查询进程信息
// 对应原始驱动 sub_140070E3C
bool QueryProcessInfoByHandle(__int64 Process, __int64 a2, __int64 a3, int a4)
{
    bool Result = 0;
    ULONG PrevModeOffset;
    int (__fastcall *OpenObjFunc)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *);
    _QWORD *v8;
    void (__fastcall *CloseFunc)(_QWORD);
    __int64 v10;
    __int64 (*QueryFunc)(_QWORD, __int64 *, ULONG64, __int64 *, int, int);
    struct _KTHREAD *CurrentThread;
    int v13, v15;
    char v14;
    _QWORD v17[9];
    __int64 v18, v19;
    int v20 = a4;

    v19 = a3;
    v18 = a2;
    PrevModeOffset = (ULONG)GtRead(GtSdstServiceCount);
    OpenObjFunc = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *))GtRead(16735);
    v8 = (_QWORD *)GtRead(16748);
    CloseFunc = (void (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    v10 = GtRead(16839);
    QueryFunc = (__int64 (*)(_QWORD, __int64 *, ULONG64, __int64 *, int, int))v10;

    if (PrevModeOffset == (ULONG)-1 || !OpenObjFunc || !v8 || !CloseFunc || !v10) return Result;

    CurrentThread = KeGetCurrentThread();
    if (OpenObjFunc(Process, 512, 0, 0x10000000, *v8, 0, v17) >= 0)
    {
        v14 = *((UCHAR *)CurrentThread + PrevModeOffset);
        *((UCHAR *)CurrentThread + PrevModeOffset) = 0;
        v15 = QueryFunc(v17[0], &v18, 0, &v19, 4096, v20);
        *((UCHAR *)CurrentThread + PrevModeOffset) = v14;
        Result = v15 >= 0;
        CloseFunc(v17[0]);
    }

    return Result;
}

// CmdProcessMonitor — 进程监视命令处理
// 对应原始驱动 sub_140070D1C
__int64 CmdProcessMonitor(_OWORD *Address, int InputSize)
{
    bool ProcessInfoByHandle = 0;
    NTSTATUS v4;
    struct _KPROCESS *v5, *v6;
    PEPROCESS Process = NULL;
    HANDLE v9[3];
    struct _KPROCESS *v10;
    _OWORD v11;
    __int64 v12;

    if (!Address || InputSize != 40 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)&Address[2].qword[1] >= MmUserProbeAddress)
        return ProcessInfoByHandle;

    ProbeForRead(Address, 0x28, 4);
    *(_OWORD *)v9 = *(_OWORD *)Address;
    v11 = Address[1];
    v12 = Address[2].qword[0];

    v4 = PsLookupProcessByProcessId(v9[0], &Process);
    v5 = (struct _KPROCESS *)Process;
    if (v4 < 0) v5 = NULL;
    Process = (PEPROCESS)v5;

    v6 = (struct _KPROCESS *)((_OWORD *)v9)->qword[1];
    if (!v6) { if (v4 >= 0) v6 = v5; v10 = v6; }

    if (ValidateProcessObject(v6, NULL) == 1 && v11.qword[1])
        ProcessInfoByHandle = QueryProcessInfoByHandle((__int64)v6, v11.qword[0], v11.qword[1], v12);

    if (Process) ObfDereferenceObject(Process);
    return ProcessInfoByHandle;
}

// EnumerateProcessList — 枚举进程列表
// 对应原始驱动 sub_14004FF98
// 通过 EPROCESS 对象枚举进程信息
bool EnumerateProcessList(struct _KPROCESS *Process, __int64 OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    UCHAR v7;
    _BYTE v9[8];
    __int64 v10;
    struct _KPROCESS *v11;

    if (BufferSize <= 0x50) return Result;

    v11 = Process;
    v10 = 0;
    *(__int64 *)OutputBuffer = 0;
    *(__int64 *)(OutputBuffer + 8) = (__int64)Process;
    *(ULONG *)(OutputBuffer + 16) = 0;

    if (Process)
    {
        if (ValidateProcessObject(Process, NULL) == 1)
        {
            v7 = ReferenceObjectSafe((__int64)Process);
            DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
                (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject,
                (__int64)v9);
            EnumerateProcessInformation((__int64)Process, OutputBuffer, BufferSize);
            if (v7 == 1) DereferenceObjectSafe((__int64)Process);
        }
    }
    else
    {
        DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
            (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject,
            (__int64)v9);
        EnumerateProcessInformation(0, OutputBuffer, BufferSize);
    }

    return *(ULONG *)(OutputBuffer + 16) != 0;
}

// EnumerateProcessObjects — 枚举单个进程对象并填充到输出缓冲区
// 对应原始驱动 sub_14004BB00
// 检查进程内存有效性，填写 552 字节每项的进程信息结构
char EnumerateProcessObjects(
    struct _KPROCESS *PROCESS,
    struct _KPROCESS *AlternateProcess,
    _DWORD *OutputBuffer,
    unsigned int BufferSize,
    char MarkType,
    char ValidateFlag,
    char PathFlag)
{
    struct _KPROCESS *TargetProcess;
    ULONG Field64, Field30, Field37;
    ULONG EntryIndex;
    __int64 EntryOffset;
    __int64 ProcessId;
    char IsNewProcess;
    ULONG Field36;
    _DWORD *Entry;
    int v28;
    void *v29;
    WORD v30[8];
    __int64 v26;
    __int64 (*GetProcessNameFunc)(struct _KPROCESS *);
    ULONG BuildNumber;

    TargetProcess = AlternateProcess ? AlternateProcess : PROCESS;
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);

    Field64 = (ULONG)GtRead(GtEprocessField64) - 1;
    if (MmIsAddressValid(PROCESS) != 1) return 0;
    if (MmIsAddressValid((char *)PROCESS + Field64) != 1) return 0;

    Field30 = (ULONG)GtRead(GtEprocessField30);
    Field37 = (ULONG)GtRead(GtEprocessField37);
    if (Field30 == (ULONG)-1 || Field37 == (ULONG)-1) return 0;

    Field36 = (ULONG)GtRead(GtEprocessField36);

    EntryIndex = *OutputBuffer;
    if (552 * (int)EntryIndex + 560 >= BufferSize) return 0;

    // Dedup check
    {
        ULONG i;
        for (i = 0; i < EntryIndex; i++)
            if (TargetProcess == *(struct _KPROCESS **)(OutputBuffer + 138 * i + 10))
                return 0;
    }

    if (ValidateFlag && ValidateProcessObject(PROCESS, TargetProcess) != 1)
        return 0;

    EntryOffset = 138 * EntryIndex;
    *(__int64 *)&OutputBuffer[EntryOffset + 10] = (__int64)TargetProcess;
    ProcessId = GetProcessFromHandleEntry((__int64)PROCESS);
    *(__int64 *)&OutputBuffer[EntryOffset + 6] = ProcessId;
    if (!ProcessId)
        *(__int64 *)&OutputBuffer[EntryOffset + 6] = *(__int64 *)((char *)PROCESS + Field30);
    *(__int64 *)&OutputBuffer[EntryOffset + 4] = *(__int64 *)((char *)PROCESS + Field37);
    LOBYTE_LV(OutputBuffer[EntryOffset + 2]) = MarkType;

    if (MarkType == 1)
    {
        IsNewProcess = 1;
        if (Field36 != (ULONG)-1)
        {
            __int64 CreateTime = *(__int64 *)((char *)PROCESS + Field36);
            if (*(volatile ULONG64 *)0xFFFFF78000000014 >= (ULONG64)CreateTime)
                IsNewProcess = ((*(volatile ULONG64 *)0xFFFFF78000000014 - CreateTime) / 10000000) >= 0x14;
        }
        LOBYTE_LV(OutputBuffer[EntryOffset + 2]) = IsNewProcess;
    }

    BYTE1_LV(OutputBuffer[EntryOffset + 2]) = CheckProtectedEntry((__int64)PROCESS);
    if (Field36 == (ULONG)-1)
        *(__int64 *)&OutputBuffer[EntryOffset + 8] = 0;
    else
        *(__int64 *)&OutputBuffer[EntryOffset + 8] = *(__int64 *)((char *)PROCESS + Field36);

    Entry = &OutputBuffer[EntryOffset];
    LOWORD_LV(OutputBuffer[EntryOffset + 12]) = 0;

    if (GetProcessImagePath(PROCESS, *(HANDLE *)&OutputBuffer[EntryOffset + 6], &v29, NULL, (char)PathFlag) == 1)
    {
        WStringCopyN((WORD *)Entry + 24, (__int64)v29, 0x100);
        HIWORD_LV(OutputBuffer[EntryOffset + 139]) = 0;
        ExFree(v29);
    }
    else
    {
        if (PathFlag) return 0;
        _QWORD **pTypeInfo = (_QWORD **)GtRead(GtObjectTypeInfoPtr);
        if (pTypeInfo && *pTypeInfo == TargetProcess)
        {
            Entry[12] = 7929939;
            Entry[13] = 7602291;
            *((__int64 *)Entry + 7) = 7143525;
        }
        else
        {
            if (BuildNumber >= 0x3839)
            {
                GetProcessNameFunc = (__int64 (*)(struct _KPROCESS *))GtRead(16777);
                if (GetProcessNameFunc)
                {
                    strcpy((char *)v30, "MemCompression");
                    v26 = GetProcessNameFunc(PROCESS);
                    if (StringCompareCaseInsensitiveV2(v26, (__int64)v30) == 0)
                    {
                        Entry[12] = 6619213; Entry[13] = 4391021;
                        Entry[14] = 7143535; Entry[15] = 7471216;
                        Entry[16] = 7536741; Entry[17] = 6881395;
                        *((__int64 *)Entry + 9) = 7209071;
                        goto Done;
                    }
                    if (BuildNumber >= 0x42EE)
                    {
                        strcpy((char *)v30, "Registry");
                        if (StringCompareCaseInsensitiveV2(v26, (__int64)v30) == 0)
                        {
                            Entry[12] = 6619218; Entry[13] = 6881383;
                            Entry[14] = 7602291;
                            *(__int64 *)(Entry + 15) = 7929970;
                            goto Done;
                        }
                    }
                }
            }
            if (ValidateProcessObjectBasic((char *)PROCESS) != 1) return 0;
            *((WORD *)Entry + 24) = 0;
        }
    }

Done:
    *OutputBuffer = (ULONG)(EntryIndex + 1);
    return 1;
}

// ValidateAndEnumerateObject — 验证并枚举对象
// 对应原始驱动 sub_140050078
char ValidateAndEnumerateObject(char *VirtualAddress, __int64 OutputBuffer, unsigned int BufferSize, __int64 Context)
{
    __int64 *v8 = (__int64 *)GtRead(16748);
    int v9_val = (int)GtRead(GtProcessOffset);
    char v12;
    bool v11;

    if (!v8 || v9_val == -1 || (ULONG64)VirtualAddress <= (ULONG64)MmSystemRangeStart)
        return 0;

    char *v10 = &VirtualAddress[(unsigned int)v9_val];
    if (MmIsAddressValid(VirtualAddress - 48) != 1 || MmIsAddressValid(v10) != 1)
        return 0;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        v12 = CheckObjectTypeFlagWrapper((__int64)(VirtualAddress - 48));
        v11 = ((UCHAR)GtRead(16960) == (UCHAR)v12);
    }
    else
    {
        v11 = (*((__int64 *)VirtualAddress - 4) == *v8);
    }

    if (v11)
    {
        __int64 ctx_val = *(__int64 *)(Context + 16);
        if (!ctx_val || *(__int64 *)v10 == ctx_val)
            return FillProcessInformationEntry(VirtualAddress, VirtualAddress, OutputBuffer, BufferSize, 0, 0, 0);
    }
    return 0;
}

// ValidateProcessObjectEx — 扩展进程对象验证
// 对应原始驱动 sub_14004B398
// 验证进程对象类型标志和是否已终止，有效则调用 EnumerateProcessObjects
char ValidateProcessObjectEx(char *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char *v4 = VirtualAddress - 48;
    __int64 (*v7)(char *) = (__int64 (*)(char *))GtRead(16752);
    __int64 (*v8)(char *) = v7;
    UCHAR Index16960 = (UCHAR)GtRead(16960);
    __int64 Index16748 = GtRead(16748);

    if (!v7) return 0;
    if ((ULONG64)VirtualAddress <= (ULONG64)MmSystemRangeStart) return 0;
    if (MmIsAddressValid(v4) != 1) return 0;

    _QWORD *v9;
    __int64 v10;
    bool v13;
    char v14, v15;
    char *v16;
    struct _KPROCESS *v11, *v12;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        v14 = CheckObjectTypeFlagWrapper((__int64)v4);
        if (v14 == Index16960)
        {
            if (!IsProcessObjectTerminated(VirtualAddress))
            {
                v11 = (struct _KPROCESS *)VirtualAddress;
                v12 = (struct _KPROCESS *)VirtualAddress;
                return EnumerateProcessObjects(v12, v11, OutputBuffer, BufferSize, 0, 0, 0);
            }
            return 0;
        }
        v15 = CheckObjectTypeFlagWrapper((__int64)v4);
        v13 = (v15 == Index16960);
    }
    else
    {
        v9 = (_QWORD *)Index16748;
        v7 = (__int64 (*)(char *))Index16748;
        if (!v9 || !v7) return 0;
        v10 = *((__int64 *)v4 + 2);
        if (v10 == *v9)
        {
            if (!IsProcessObjectTerminated(VirtualAddress))
            {
                v11 = (struct _KPROCESS *)VirtualAddress;
                v12 = (struct _KPROCESS *)VirtualAddress;
                return EnumerateProcessObjects(v12, v11, OutputBuffer, BufferSize, 0, 0, 0);
            }
            return 0;
        }
        v13 = (v10 == *(__int64 *)v7);
    }

    if (v13)
    {
        v16 = (char *)v8(VirtualAddress);
        if (!IsProcessObjectTerminated(v16))
        {
            v12 = (struct _KPROCESS *)v16;
            v11 = (struct _KPROCESS *)v16;
            return EnumerateProcessObjects(v12, v11, OutputBuffer, BufferSize, 0, 0, 0);
        }
    }
    return 0;
}

// FillProcessInformationEntry — 填充进程信息条目
// 对应原始驱动 sub_14005017C
char FillProcessInformationEntry(
    char *VirtualAddress, char *AlternateAddr, __int64 OutputBuffer,
    unsigned int BufferSize, char ValidateFlag, char EntryType, char a7)
{
    char *TargetAddr = AlternateAddr ? AlternateAddr : VirtualAddress;
    int CreateTimeOffset, Field51, Field52, Field41, Field53, Field54, Field55, FlagsOffset;
    _QWORD *v24;
    int MaxIndex;
    ULONG EntryIndex, BuildNumber;
    __int64 Offset;

    CreateTimeOffset = (int)GtRead(GtProcessCreateTime);
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    Field51 = (int)GtRead(GtEprocessField51);
    Field52 = (int)GtRead(GtEprocessField52);
    Field41 = (int)GtRead(GtObjectTypeField41);
    Field53 = (int)GtRead(GtEprocessField53);
    Field54 = (int)GtRead(GtEprocessField54);
    Field55 = (int)GtRead(GtEprocessField55);
    FlagsOffset = (int)GtRead(GtProcessFlagsOffset);
    v24 = (_QWORD *)GtRead(16748);
    if (!v24) return 0;

    MaxIndex = (int)GtRead(GtObjectTypeCount) - 1;
    if (MmIsAddressValid(VirtualAddress) != 1 || MmIsAddressValid(&VirtualAddress[MaxIndex]) != 1) return 0;

    EntryIndex = *(unsigned int *)(OutputBuffer + 16);
    if (56 * EntryIndex + 80 >= BufferSize) return 0;
    if (IsProcessThreadInList(OutputBuffer, (__int64)VirtualAddress, (__int64)TargetAddr, a7) != 1) return 0;
    if (ValidateFlag && ValidateKernelObject((ULONG64)VirtualAddress, (ULONG64)TargetAddr, 0, 0) != 1) return 0;

    Offset = 56 * EntryIndex;
    *(UCHAR *)(Offset + OutputBuffer + 24) = EntryType;
    *(__int64 *)(Offset + OutputBuffer + 32) = (__int64)TargetAddr;
    *(__int64 *)(Offset + OutputBuffer + 40) = *(__int64 *)&VirtualAddress[CreateTimeOffset];
    *(__int64 *)(Offset + OutputBuffer + 48) = *(__int64 *)&VirtualAddress[Field51];
    *(ULONG *)(Offset + OutputBuffer + 56) = (UCHAR)VirtualAddress[Field54];
    *(__int64 *)(Offset + OutputBuffer + 64) = *(__int64 *)&VirtualAddress[Field52];

    if (BuildNumber < 0x2800)
    {
        if (BuildNumber < 0x1770)
        {
            if (*(__int64 *)(Offset + OutputBuffer + 64) < *v24)
            {
                __int64 v18 = *(__int64 *)&VirtualAddress[Field41];
                if (v18)
                {
                    if ((BuildNumber < 0xA28)
                        ? VirtualAddress[FlagsOffset] == 0
                        : (VirtualAddress[FlagsOffset] & 1) == 0)
                        *(__int64 *)(Offset + OutputBuffer + 64) = v18;
                }
            }
            goto Done;
        }
        if (!(*(ULONG *)&VirtualAddress[FlagsOffset] & 2)) goto Done;
    }
    else if (!(*(ULONG *)&VirtualAddress[FlagsOffset] & 8)) goto Done;

    *(__int64 *)(Offset + OutputBuffer + 64) = *(__int64 *)&VirtualAddress[Field41];

Done:
    *(ULONG *)(Offset + OutputBuffer + 72) = *(ULONG *)&VirtualAddress[Field55];
    *(ULONG *)(Offset + OutputBuffer + 76) = (UCHAR)VirtualAddress[Field53];
    *(ULONG *)(OutputBuffer + 16) = EntryIndex + 1;
    return 1;
}

// ValidateKernelObject — 验证内核对象有效性
// 对应原始驱动 sub_14004F600
// 全面检查对象结构完整性：对象类型标志、句柄表链表验证
char ValidateKernelObject(ULONG64 ObjectAddr, ULONG64 AltAddr, _QWORD *OutContext, ULONG64 *OutProcess)
{
    char Result = 0;
    ULONG64 TargetAddr = AltAddr ? AltAddr : ObjectAddr;
    __int64 v7;
    ULONG64 v8;
    _QWORD *v9;
    bool v10;
    char v11;
    ULONG v12, v13, v14, v17, v19, v20, v23, v25, v34, v37, BuildNumber;
    ULONG64 v15, v16, v21, v30, v32;
    __int64 v18, v22, v26, v39;
    _QWORD *v31, *v33, *v35;
    UCHAR Index16960 = (UCHAR)GtRead(16960);
    ULONG Index16774 = (ULONG)GtRead(16774);
    __int64 Index16748 = GtRead(16748);

    if (ObjectAddr <= (ULONG64)MmSystemRangeStart) return Result;

    v7 = (int)GtRead(GtObjectTypeCount) - 1;
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (MmIsAddressValid((PVOID)(ObjectAddr - 48)) != 1 ||
        MmIsAddressValid((PVOID)(v7 + ObjectAddr)) != 1 ||
        ObjectAddr <= (ULONG64)MmSystemRangeStart)
        return Result;

    v8 = v7 + TargetAddr;

    if (BuildNumber >= 0x1DB0)
    {
        v11 = CheckObjectTypeFlagWrapper((__int64)(ObjectAddr - 48));
        v10 = (Index16960 == (UCHAR)v11);
    }
    else
    {
        v9 = (_QWORD *)Index16748;
        if (!v9) return Result;
        v10 = (*(_QWORD *)(ObjectAddr - 32) == *v9);
    }

    if (!v10) return Result;

    v12 = (ULONG)GtRead(0x42C);
    v13 = Index16774;
    v14 = Index16774;
    v15 = *(_QWORD *)(v12 + ObjectAddr);
    v16 = *(_QWORD *)(v13 + ObjectAddr);
    if (v15 <= v16 || v15 <= (ULONG64)MmSystemRangeStart ||
        v16 <= (ULONG64)MmSystemRangeStart ||
        *(_QWORD *)(v14 + ObjectAddr) <= (ULONG64)MmSystemRangeStart)
        return Result;

    v17 = (ULONG)GtRead(GtProcessEprocess);
    v18 = (ULONG)GtRead(GtEprocessField51);
    v39 = *(_QWORD *)(v17 + ObjectAddr);
    if (*(_QWORD *)(v18 + ObjectAddr) < (ULONG64)MmSystemRangeStart) return Result;
    v19 = (ULONG)GtRead(GtProcessOffset);
    v20 = (ULONG)GtRead(GtEprocessField53);
    v21 = *(_QWORD *)(v19 + ObjectAddr);
    if ((v21 & 7) != 0 || v21 <= (ULONG64)MmSystemRangeStart ||
        MmIsAddressValid(*(PVOID *)(v19 + ObjectAddr)) != 1 ||
        *(UCHAR *)(v20 + ObjectAddr) > 5)
        return Result;

    v22 = (ULONG)GtRead(GtEprocessField48);
    v23 = (ULONG)GtRead(GtEprocessField47);
    v25 = v23;
    v26 = v22 + TargetAddr;

    // Extensive pointer validation chain
    PVOID ptr = *(PVOID *)(v22 + ObjectAddr);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(v22 + ObjectAddr) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(v22 + ObjectAddr + 8);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(v22 + ObjectAddr + 8) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(v25 + ObjectAddr);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(v25 + ObjectAddr) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(v25 + ObjectAddr + 8);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(v25 + ObjectAddr + 8) + 15)) != 1)
        return Result;

    // Verify linked list consistency
    v30 = *(_QWORD *)(v22 + ObjectAddr);
    if (*(_QWORD *)(v30 + 8) != v26) return Result;
    v31 = *(_QWORD **)(v22 + ObjectAddr + 8);
    if (*v31 != v26) return Result;
    v32 = *(_QWORD *)(v25 + ObjectAddr);
    if (*(_QWORD *)(v32 + 8) != v25 + TargetAddr) return Result;
    v33 = *(_QWORD **)(v25 + ObjectAddr + 8);
    if (*v33 != v25 + TargetAddr) return Result;

    if (v30 < TargetAddr || v30 > v8 ||
        (ULONG64)v31 < TargetAddr || (ULONG64)v31 > v8 ||
        v32 < TargetAddr || v32 > v8 ||
        (ULONG64)v33 < TargetAddr || (ULONG64)v33 > v8)
        return Result;

    v34 = (ULONG)GtRead(GtEprocessField30);
    if (MmIsAddressValid((PVOID)(v21 + v34)) != 1) return Result;

    if (BuildNumber >= 0x1DB0)
    {
        if (MmIsAddressValid((PVOID)(v21 - 24)) != 1) return Result;
        v37 = (UCHAR)CheckObjectTypeFlagWrapper(v21 - 48);
        v10 = ((ULONG)Index16960 == v37);
    }
    else
    {
        v35 = (_QWORD *)Index16748;
        if (!v35 || MmIsAddressValid((PVOID)(v21 - 32)) != 1) return Result;
        v10 = (*(_QWORD *)(v21 - 32) == *v35);
    }

    if (v10)
    {
        if (OutContext) *OutContext = v39;
        if (OutProcess) *OutProcess = v21;
        return 1;
    }

    return Result;
}

// EnumProcessInformationWorker — 进程信息枚举工作函数
// 对应原始驱动 sub_14004F4C0
// 通过进程ID查找EPROCESS，验证后枚举句柄表和进程信息
bool EnumProcessInformationWorker(char *InputBuffer, __int64 OutputBuffer, unsigned int BufferSize)
{
    char v6 = 0;
    NTSTATUS v7;
    PEPROCESS Process;
    UCHAR v9;

    if (BufferSize <= 0x50) return v6;

    *(__int64 *)OutputBuffer = *((__int64 *)InputBuffer + 1);
    *(__int64 *)(OutputBuffer + 8) = *((__int64 *)InputBuffer + 2);
    *(ULONG *)(OutputBuffer + 16) = 0;

    char v12 = *InputBuffer;
    v7 = PsLookupProcessByProcessId(*((HANDLE *)InputBuffer + 1), &Process);
    int v8 = v7;
    if (!*((__int64 *)InputBuffer + 2) && v7 >= 0)
        *((__int64 *)InputBuffer + 2) = (__int64)Process;

    if (ValidateProcessObject(*((struct _KPROCESS **)InputBuffer + 2), NULL) == 1)
    {
        v9 = ReferenceObjectSafe(*((__int64 *)InputBuffer + 2));
        DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
            (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject, (__int64)InputBuffer);
        EnumerateProcessHandleTableData(*((struct _KPROCESS **)InputBuffer + 2), OutputBuffer, BufferSize);
        if (v12)
            EnumerateProcessInformation(*((__int64 *)InputBuffer + 2), OutputBuffer, BufferSize);
        if (v9 == 1)
            DereferenceObjectSafe(*((__int64 *)InputBuffer + 2));
    }

    if (v8 >= 0)
        ObfDereferenceObject(Process);

    return *(ULONG *)(OutputBuffer + 16) != 0;
}

// CheckProcessProtection — 检查进程保护
// 对应原始驱动 sub_140010914
// 根据调试端口和 Section 偏移值判断进程是否被保护
char CheckProcessProtection(__int64 ProcessObject, _DWORD *OutProtectionType)
{
    char Success;
    ULONG DebugPortOffset;
    ULONG SectionOffset;
    char DebugPortVal;
    __int64 (__fastcall *AllocFunc)(__int64);
    UCHAR (__fastcall *CheckFunc)(__int64, __int64);
    __int64 FreeFunc;
    void (__fastcall *FreeFuncTyped)(__int64, __int64);
    __int64 AllocResult;
    __int64 BufferPtr;

    Success = 0;
    DebugPortOffset = (ULONG)GtRead(GtDebugPortOffset);
    SectionOffset = (ULONG)GtRead(GtProcessSectionOffset);

    if (!ProcessObject || !SectionOffset)
        return Success;

    if (DebugPortOffset)
        DebugPortVal = *(char *)(DebugPortOffset + ProcessObject);
    else
        DebugPortVal = 0;

    if (DebugPortOffset && DebugPortVal)
    {
        *OutProtectionType = 0;
        return 1;
    }
    else if (*(WORD *)(SectionOffset + ProcessObject) != 8364)
    {
        Success = 1;
        *OutProtectionType = 2;

        AllocFunc = (__int64 (__fastcall *)(__int64))GtRead(GtMemoryAllocExFunc);
        CheckFunc = (UCHAR (__fastcall *)(__int64, __int64))GtRead(GtMemoryAllocFunc);
        FreeFunc = GtRead(GtMemoryFreeFunc);
        FreeFuncTyped = (void (__fastcall *)(__int64, __int64))FreeFunc;

        if (AllocFunc && CheckFunc && FreeFunc)
        {
            AllocResult = AllocFunc(0x2000);
            BufferPtr = AllocResult;
            if (AllocResult)
            {
                if (CheckFunc(1, AllocResult) == 1 && (*(UCHAR *)(BufferPtr + 12) & 1) == 0)
                    *OutProtectionType = 1;
                FreeFuncTyped(BufferPtr, 0x2000);
            }
        }
    }

    return Success;
}

// GetProcessImagePath — 获取进程映像路径
// 对应原始驱动 sub_14004A1FC
// 尝试从 SectionObject 或句柄获取文件名，失败时附加到进程获取路径
char GetProcessImagePath(PRKPROCESS PROCESS, HANDLE ProcessId, void **OutBuffer, _DWORD *OutSize, int Flags)
{
    char Result = 0;
    ULONG SectionFieldOffset;
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    ULONG v13;
    char SectionObjectNameFromHandle;
    bool v16;
    void *v19[6];

    SectionFieldOffset = (ULONG)GtRead(GtEprocessField31);
    if (SectionFieldOffset == (ULONG)-1) goto Fallback;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!PROCESS) PROCESS = (PRKPROCESS)Process;

    v13 = (ULONG)GtRead(GtEprocessField64) - 1;
    if (PROCESS && MmIsAddressValid(PROCESS) == 1 && MmIsAddressValid((char *)PROCESS + v13) == 1)
    {
        if ((ULONG)GtRead(GtEprocessField28) == 1)
            SectionObjectNameFromHandle = GetSectionObjectNameFromHandle(PROCESS, *(HANDLE *)((char *)PROCESS + SectionFieldOffset), OutBuffer, OutSize);
        else
        {
            ULONG64 v14 = *(ULONG64 *)((char *)PROCESS + SectionFieldOffset);
            if (!v14) goto Cleanup;
            SectionObjectNameFromHandle = QueryObjectNameByAddress(v14, OutBuffer, OutSize);
        }
        Result = SectionObjectNameFromHandle;
    }

Cleanup:
    if (Status >= 0 && Process) ObfDereferenceObject(Process);

Fallback:
    if (!(UCHAR)Flags)
    {
        v16 = Result == 0;
        if (Result == 1)
        {
            if (OutSize)
            {
                if (*OutSize <= 6) v16 = 1;
            }
            else if (GetStringLength(*OutBuffer) <= 3) v16 = 1;
            if (!WStringFindChar((WORD *)*OutBuffer, L'.')) v16 = 1;
        }
        if (v16 && GetProcessImagePathByAttach(PROCESS, ProcessId, v19, &Flags) == 1)
        {
            ParseFilePathForSystemRoot((WORD **)v19, &Flags);
            if (Result == 1 && *OutBuffer) ExFree(*OutBuffer);
            *OutBuffer = v19[0];
            if (OutSize) *OutSize = (ULONG)Flags;
            Result = 1;
        }
    }

    if (!Result)
        return QueryDevicePathFromSymbolicLink((__int64)ProcessId, OutBuffer, OutSize);
    return Result;
}

// IsProcessObjectTerminated — 检查进程对象是否已终止
// 对应原始驱动 sub_14004A674
bool IsProcessObjectTerminated(char *VirtualAddress)
{
    char Result = 0;
    __int64 (*GetCurrentProcess)(void);
    int v4;

    GetCurrentProcess = (__int64 (*)(void))GtRead(16733);
    if (GetCurrentProcess && VirtualAddress == (char *)GetCurrentProcess())
        return Result;

    v4 = (int)GtRead(GtEprocessField64) - 1;
    if (MmIsAddressValid(VirtualAddress) == 1 &&
        MmIsAddressValid(&VirtualAddress[v4]) == 1)
        return *(__int64 *)&VirtualAddress[(ULONG)GtRead(GtEprocessField44)] == 0;

    return Result;
}

// ValidateProcessObject — 验证进程对象
// 对应原始驱动 sub_14004A7AC
char ValidateProcessObject(struct _KPROCESS *ProcessObject, struct _KPROCESS *AlternateProcess)
{
    ULONG64 EprocessBase;
    ULONG64 SectionOffset;
    ULONG64 ProcessSection;
    UCHAR *FlagsPtr;

    if (!ProcessObject)
        return 0;

    EprocessBase = (ULONG64)ProcessObject;
    if (EprocessBase < MmSystemRangeStart)
        return 0;

    // 检查进程的 Section 对象偏移
    SectionOffset = GtRead(GtProcessSectionOffset);
    if (SectionOffset)
    {
        ProcessSection = *(ULONG64 *)(EprocessBase + SectionOffset);
        if (ProcessSection && ProcessSection < MmSystemRangeStart)
            return 0;
    }

    return 1;
}

// BuildExportServiceTable — 构建导出服务表
// 对应原始驱动 sub_1400063D0
// 读取用户态 DLL（win32k/其他），解析导出目录，构建服务表到缓冲区
char BuildExportServiceTableForProcess(
    __int64 ImageBase,
    struct _KPROCESS *TargetProcess,
    char Is64Bit,
    _QWORD *OutServiceTable)
{
    char Success;
    unsigned int ServiceCount;
    unsigned int ModuleEntrySize;
    __int64 *RelocAllocBuffer;
    int IsWin32k;
    __int64 *RelocBuffer;
    __int64 ImageBasePtr;
    int IsWin32kCopy;
    ULONG64 ModuleBase;
    unsigned int *ExportEntry;
    __int64 ServiceCount2;
    ULONG64 FuncTableAddr;
    unsigned int ServiceIndex;
    __int64 FuncValue;
    ULONG64 FuncAddrPtr;
    unsigned int v22;
    int v23;
    char *v24;
    __int64 v25;
    ULONG64 v26;
    __int64 v27;
    __int64 v28[9];

    Success = 0;
    ServiceCount = (unsigned int)GtRead(GtWin32kServiceCount);
    if (Is64Bit)
    {
        ModuleEntrySize = (unsigned int)GtRead(GtWin32kServiceTableSize64);
        RelocAllocBuffer = GtAlloc(GtWin32kServiceBuffer64);
        IsWin32k = 1;
    }
    else
    {
        ModuleEntrySize = (unsigned int)GtRead(GtWin32kServiceTableSize32);
        RelocAllocBuffer = GtAlloc(GtWin32kServiceBuffer32);
        IsWin32k = 0;
    }
    RelocBuffer = RelocAllocBuffer;
    v26 = ParseNtRelocationTable(TargetProcess, Is64Bit, &v27, v28, (void **)&v25);
    if (v26)
    {
        if (ServiceCount && ModuleEntrySize && RelocBuffer)
        {
            ImageBasePtr = v27;
            if (v27)
            {
                if (ReadUser32DllFile(&v24, &v22, Is64Bit))
                {
                    IsWin32kCopy = IsWin32k;
                    ModuleBase = v26;
                    if (ParseNtExportDir((__int64)v24, v22, v26, IsWin32kCopy) == 1)
                    {
                        ExportEntry = (unsigned int *)RelocBuffer + 1;
                        ServiceCount2 = ServiceCount;
                        do
                        {
                            *(ExportEntry - 1) = 0;
                            if (*ExportEntry < v22 && *ExportEntry + 16 <= v22)
                            {
                                *(ExportEntry - 1) = 1;
                                *(_OWORD *)(ExportEntry + 3) = *(_OWORD *)&v24[*ExportEntry];
                            }
                            ExportEntry += 12;
                            --ServiceCount2;
                        }
                        while (ServiceCount2);
                    }
                    ExFree(v24);
                }
                else
                {
                    ModuleBase = v26;
                }
                FuncTableAddr = ModuleBase + ModuleEntrySize;
                OutServiceTable[1] = ImageBasePtr;
                OutServiceTable[3] = v28[0];
                OutServiceTable[2] = FuncTableAddr;
                ServiceIndex = 0;
                v23 = 0;
                while (ServiceIndex < ServiceCount)
                {
                    OutServiceTable[9 * ServiceIndex + 8] = ServiceIndex;
                    if (Is64Bit)
                    {
                        FuncValue = *(unsigned int *)(v25 + 4LL * ServiceIndex);
                        FuncAddrPtr = FuncTableAddr + 4LL * ServiceIndex;
                    }
                    else
                    {
                        FuncValue = *(_QWORD *)(v25 + 8LL * ServiceIndex);
                        FuncAddrPtr = FuncTableAddr + 8LL * ServiceIndex;
                    }
                    OutServiceTable[9 * ServiceIndex + 10] = FuncValue;
                    OutServiceTable[9 * ServiceIndex + 7] = FuncAddrPtr;
                    OutServiceTable[9 * ServiceIndex + 5] = (_QWORD)TargetProcess;
                    OutServiceTable[9 * ServiceIndex + 6] = ImageBase;
                    OutServiceTable[9 * ServiceIndex + 9] = ModuleBase + HIDWORD(RelocBuffer[6 * ServiceIndex]);
                    v23 = ++ServiceIndex;
                }
                Success = 1;
            }
        }
        ExFree((void *)v25);
    }
    return Success;
}

// CopyValidServiceEntries — 复制有效服务条目
// 对应原始驱动 sub_14000680C
// 从全局表缓冲区中筛选出有效条目，写入目标结构
char CopyValidServiceEntries(__int64 OutputBuffer, char Is64Bit)
{
    char Result;
    unsigned int ServiceCount;
    enum _GLOBAL_TABLE_INDEX BufferIndex;
    __int64 *ServiceEntry;
    __int64 EntryIndex;

    Result = 0;
    ServiceCount = (unsigned int)GtRead(GtWin32kServiceCount);
    if (ServiceCount)
    {
        BufferIndex = GtWin32kServiceBuffer32;
        if (Is64Bit)
            BufferIndex = GtWin32kServiceBuffer64;
        ServiceEntry = GtAlloc(BufferIndex);
        for (EntryIndex = 0; (unsigned int)EntryIndex < ServiceCount; EntryIndex = (unsigned int)(EntryIndex + 1))
        {
            *(_DWORD *)(OutputBuffer + 72 * EntryIndex + 28) = HIDWORD(ServiceEntry[6 * EntryIndex]);
            if (HIDWORD(ServiceEntry[6 * EntryIndex]))
            {
                if (LODWORD(ServiceEntry[6 * EntryIndex]) == 1)
                {
                    *(_OWORD *)(OutputBuffer + 72 * EntryIndex + 50) = *(_OWORD *)&ServiceEntry[6 * EntryIndex + 2];
                    Result = 1;
                }
            }
        }
    }
    return Result;
}

// ParseNtImageSectionHeaders — 解析 NT 镜像节头
// 对应原始驱动 sub_1400061C0
// 附加到目标进程，逐节比较内存内容，标记修改过的节
char ParseNtImageSectionHeadersForProcess(PRKPROCESS PROCESS, __int64 SectionInfoArray)
{
    unsigned int SectionCount;
    unsigned int SectionCountCopy;
    __int64 CurrentSection;
    __int64 LoopCount;
    __int64 SectionIndex;
    char FuncResult;
    __int64 SavedValue;
    __int64 SectionOffset;
    unsigned __int8 ProcessAttached;
    __int64 SectionEntry;
    _OWORD SectionHeader1;
    _OWORD SectionHeader2;
    _OWORD SectionHeader3;
    _OWORD SectionHeader4;
    __int64 SectionHeader5;
    KAPC_STATE ApcState;
    _OWORD v21;

    SectionCount = (unsigned int)GtRead(GtWin32kServiceCount);
    SectionCountCopy = SectionCount;
    if (SectionCount)
    {
        CurrentSection = SectionInfoArray + 32;
        LoopCount = SectionCount;
        do
        {
            if (*(_QWORD *)CurrentSection && *(_QWORD *)CurrentSection != *(_QWORD *)(CurrentSection + 8))
                *(_BYTE *)(CurrentSection + 16) = 1;
            CurrentSection += 72;
            --LoopCount;
        }
        while (LoopCount);
    }
    ProcessAttached = ReferenceObjectSafe((__int64)PROCESS);
    for (SectionIndex = 0; (unsigned int)SectionIndex < SectionCountCopy; SectionIndex = (unsigned int)(SectionIndex + 1))
    {
        if (*(_QWORD *)(SectionInfoArray + 72 * SectionIndex + 32))
        {
            SectionHeader1 = *(_OWORD *)(SectionInfoArray + 72 * SectionIndex);
            SectionHeader2 = *(_OWORD *)(SectionInfoArray + 72 * SectionIndex + 16);
            SectionHeader3 = *(_OWORD *)(SectionInfoArray + 72 * SectionIndex + 32);
            SectionHeader4 = *(_OWORD *)(SectionInfoArray + 72 * SectionIndex + 48);
            SectionHeader5 = *(_QWORD *)(SectionInfoArray + 72 * SectionIndex + 64);
            KeStackAttachProcess(PROCESS, &ApcState);
            if (SectionHeader3.qword[0] < MmUserProbeAddress && SectionHeader3.qword[0] + 15 < MmUserProbeAddress)
            {
                if ((unsigned int)MemoryCompare(SectionHeader3.qword[0], (char *)&SectionHeader4 + 2, 0x10u))
                {
                    BYTE1_LV(SectionHeader4) = 1;
                    if (!LOBYTE_LV(SectionHeader4.qword[0]))
                    {
                        memset(&v21, 0, sizeof(v21));
                        v21 = *(_OWORD *)SectionHeader3.qword[0];
                        FuncResult = ReturnFalseStub();
                        SavedValue = SectionHeader3.qword[1];
                        if (FuncResult == 1)
                            SavedValue = SectionEntry;
                        SectionHeader3.qword[1] = SavedValue;
                    }
                }
            }
            KeUnstackDetachProcess(&ApcState);
            SectionOffset = 9LL * (unsigned int)SectionIndex;
            *(_OWORD *)(SectionInfoArray + 8 * SectionOffset) = SectionHeader1;
            *(_OWORD *)(SectionInfoArray + 8 * SectionOffset + 16) = SectionHeader2;
            *(_OWORD *)(SectionInfoArray + 8 * SectionOffset + 32) = SectionHeader3;
            *(_OWORD *)(SectionInfoArray + 8 * SectionOffset + 48) = SectionHeader4;
            *(_QWORD *)(SectionInfoArray + 8 * SectionOffset + 64) = SectionHeader5;
        }
    }
    if (ProcessAttached == 1)
        DereferenceObjectSafe((__int64)PROCESS);
    return 1;
}

// ResolveWin32kServiceTable — 解析 win32k 服务表
// 对应原始驱动 sub_140006608
// 读取 user32.dll，查找 UserClientDllInitialize 导出函数，解析服务表大小并构建服务编号表
void ResolveWin32kServiceTable(char IsWow64Process)
{
    unsigned int ExportByNameInPeBody;
    unsigned int ServiceTableSize;
    unsigned int ServiceCount;
    enum _GLOBAL_TABLE_INDEX TableIndex;
    unsigned int FileSize;
    void *FileBuffer;
    char ExportName[24];

    if (ReadUser32DllFile(&FileBuffer, &FileSize, IsWow64Process))
    {
        strcpy(ExportName, "UserClientDllInitialize");
        ExportByNameInPeBody = FindExportByNameInPeBody(
            (__int64)FileBuffer,
            FileSize,
            (__int64)ExportName,
            IsWow64Process != 0);
        if (ExportByNameInPeBody)
        {
            ServiceTableSize = IsWow64Process
                ? ResolveWin32kServiceTableEx((__int64)FileBuffer, FileSize)
                : ResolveWin32kServiceTableDispatch((__int64)FileBuffer, FileSize, ExportByNameInPeBody);
            ServiceCount = ServiceTableSize;
            if (ServiceTableSize)
            {
                TableIndex = GtWin32kServiceTableSize32;
                if (IsWow64Process)
                    TableIndex = GtWin32kServiceTableSize64;
                GtWrite(TableIndex, ServiceTableSize);
                BuildPeServiceNumberTable((__int64)FileBuffer, FileSize, ServiceCount, IsWow64Process);
            }
        }
        ExFree(FileBuffer);
    }
}

// WriteProcessMemoryBuffer — 写入进程内存缓冲区
// 对应原始驱动 sub_1400071AC
char WriteProcessMemoryBuffer(_QWORD *InputParams)
{
    char Result;
    ULONG64 TargetAddress;
    unsigned __int8 ProcessRefed;
    KAPC_STATE ApcState;
    _OWORD SectionData;

    Result = 0;
    TargetAddress = InputParams[4];
    if (TargetAddress)
    {
        if (TargetAddress < MmUserProbeAddress
            && TargetAddress + 15 < MmUserProbeAddress
            && *((_DWORD *)InputParams + 6) < (unsigned int)GtRead(GtWin32kServiceCount))
        {
            ProcessRefed = ReferenceObjectSafe(*InputParams);
            KeStackAttachProcess((PRKPROCESS)*InputParams, &ApcState);
            SectionData = *(_OWORD *)((char *)InputParams + 50);
            Result = WritePhysicalMemoryBuffer(InputParams[4], &SectionData, 0x10u, 1, 0);
            KeUnstackDetachProcess(&ApcState);
            if (ProcessRefed == 1)
                DereferenceObjectSafe(*InputParams);
        }
    }
    return Result;
}

// GetProcessImagePathByAttach — 通过附加(Attach)方式获取进程镜像路径
// 对应原始驱动 sub_14004A3E0
// 附加到目标进程后获取其镜像路径
char GetProcessImagePathByAttach(PRKPROCESS PROCESS, HANDLE ProcessId, void **a3, _DWORD *a4)
{
    char v6;
    unsigned int v7;
    NTSTATUS v8;
    unsigned __int64 v9;
    unsigned __int64 v10;
    unsigned __int64 v11;
    __int64 v12;
    unsigned __int64 v13;
    PVOID v14;
    unsigned __int8 v16;
    PEPROCESS Process;
    _DWORD *v19;
    void **v20;
    KAPC_STATE ApcState;

    v19 = a4;
    v20 = a3;
    v6 = 0;
    *a3 = 0;
    v7 = (unsigned int)GtRead(GtEprocessField33);
    if (v7 != -1)
    {
        v8 = PsLookupProcessByProcessId(ProcessId, &Process);
        if (!v8 && !PROCESS)
            PROCESS = (PRKPROCESS)Process;
        if (PROCESS && ValidateProcessObject(PROCESS, 0) == 1)
        {
            v16 = ReferenceObjectSafe((__int64)PROCESS);
            KeStackAttachProcess(PROCESS, &ApcState);
            if (MmIsAddressValid((char *)PROCESS + v7) == 1)
            {
                v9 = *(_QWORD *)((char *)PROCESS + v7);
                if (v9 < (unsigned __int64)MmSystemRangeStart && v9 + 96 < (unsigned __int64)MmSystemRangeStart)
                {
                    v10 = *(_QWORD *)(v9 + 24);
                    if (v10 < (unsigned __int64)MmSystemRangeStart && v10 + 72 < (unsigned __int64)MmSystemRangeStart)
                    {
                        v11 = *(_QWORD *)(v10 + 16);
                        if (v11 < (unsigned __int64)MmSystemRangeStart && v11 + 136 < (unsigned __int64)MmSystemRangeStart)
                        {
                            v12 = *(unsigned __int16 *)(v11 + 72);
                            if ((unsigned int)v12 > 0x1000)
                                v12 = 4096;
                            if ((unsigned int)v12 > 2)
                            {
                                v13 = *(_QWORD *)(v11 + 80);
                                if (v13 < (unsigned __int64)MmSystemRangeStart)
                                {
                                    if (v13)
                                    {
                                        if ((unsigned int)v12 + v13 < (unsigned __int64)MmSystemRangeStart)
                                        {
                                            v14 = ExAlloc(PagedPool, v12 + 2);
                                            *a3 = v14;
                                            if (v14)
                                            {
                                                if (v19)
                                                    *v19 = (unsigned int)v12;
                                                memmove(*a3, *(const void **)(v11 + 80), (unsigned int)v12);
                                                *((_WORD *)*a3 + ((unsigned __int64)(unsigned int)v12 >> 1)) = 0;
                                                v6 = 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            KeUnstackDetachProcess(&ApcState);
            if (v16 == 1)
                DereferenceObjectSafe((__int64)PROCESS);
        }
        if (!v8)
            ObfDereferenceObject(Process);
    }
    return v6;
}

// ParseFilePathForSystemRoot — 解析文件路径中的系统根目录
// 对应原始驱动 sub_14004B9A0
// 将 \SystemRoot\ 等系统路径前缀替换为实际系统根目录路径，\??\ 前缀则跳过前 4 字符
char ParseFilePathForSystemRoot(__int16 **a1, _DWORD *a2)
{
    char v2;
    __int16 *v4;
    int v6;
    __int16 *v7;
    __int16 *inited;
    __int16 *v9;
    __int64 StringLength;
    unsigned int v11;
    unsigned int v12;
    SIZE_T v13;
    __int16 *v14;
    __int16 *v15;
    _DWORD v17[2];
    _DWORD v18[5];
    __int64 v19;

    v2 = 0;
    v4 = *a1;
    if (*v4 == 92)  // L'\\'
    {
        // "\\??\\" 前缀检查
        v17[0] = 4128860;  // L"\\??"
        v17[1] = 6029375;  // L"\\\0\0"
        v6 = WStringCompare((__int64)v4, (unsigned __int16 *)v17, 4u);
        v7 = *a1;
        if (v6)
        {
            // "\\SystemRoot\\" 前缀检查 (12 个字符)
            v18[0] = 5439580;   // L"\\Sys"
            v18[1] = 7536761;   // L"temR"
            v18[2] = 6619252;   // L"oot\\"
            v18[3] = 5374061;   // L"syst"
            v18[4] = 7274607;   // L"em32"
            v19 = 6029428;      // L"\\\0\0\0"
            if (!(unsigned int)StringCompare3Way((__int64)v7, (unsigned __int16 *)v18, 0xCu))
            {
                inited = InitSystemPath();
                v9 = inited;
                if (inited)
                {
                    StringLength = (unsigned int)GetStringLength(inited);
                    v11 = GetStringLength(*a1);
                    v12 = v11 + (unsigned int)StringLength;
                    if (v11 + (unsigned int)StringLength > (unsigned int)StringLength && v12 > v11)
                    {
                        v13 = 2 * v12;
                        if ((unsigned int)v13 > v12)
                        {
                            v14 = (__int16 *)ExAlloc(PagedPool, v13);
                            v15 = v14;
                            if (v14)
                            {
                                WStringCopy(v14, v9);
                                WStringCopy(&v15[StringLength], *a1 + 11);
                                ExFree(*a1);
                                *a1 = v15;
                                if (a2)
                                    *a2 = 2 * GetStringLength(v15);
                                v2 = 1;
                            }
                        }
                    }
                    ExFree(v9);
                }
            }
        }
        else
        {
            // 跳过 "\\??\\" 前缀 (4 个字符)
            WStringCopy(v7, v7 + 4);
            if (a2)
                *a2 = 2 * GetStringLength(*a1);
            return 1;
        }
    }
    return v2;
}

// QueryObjectNameByAddress — 按地址查询对象名称
// 对应原始驱动 sub_1400794A0
// 根据Windows版本选择新版或旧版名称查询方式
char QueryObjectNameByAddress(unsigned __int64 a1, _QWORD *a2, _DWORD *a3)
{
    char v7;
    _QWORD *v8;
    _QWORD *v9;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x2800)
        return QueryObjectNameLegacy((_QWORD *)a1, a2, a3);

    v7 = 0;
    if (a1 > (unsigned __int64)MmSystemRangeStart && (a1 & 7) == 0)
    {
        v8 = (_QWORD *)ResolveObjectNamePointer(a1);
        v9 = v8;
        if (v8)
        {
            if (v8 > MmSystemRangeStart && MmIsAddressValid(v8) == 1 && MmIsAddressValid((char *)v9 + 127) == 1)
                return QueryObjectNameString(v9[8], a2, a3);
        }
    }
    return v7;
}

// GetSectionObjectNameFromHandle — 从句柄获取节区对象名称
// 对应原始驱动 sub_1400793F0
// 附加到进程并通过句柄查询Section对象名称
char GetSectionObjectNameFromHandle(PRKPROCESS PROCESS, HANDLE Handle, _QWORD *a3, _DWORD *a4)
{
    char ObjectNameByAddress;
    unsigned __int8 v9;
    NTSTATUS v10;
    PVOID Object;
    KAPC_STATE ApcState;

    ObjectNameByAddress = 0;
    v9 = ReferenceObjectSafe((__int64)PROCESS);
    KeStackAttachProcess(PROCESS, &ApcState);
    v10 = ObReferenceObjectByHandle(Handle, 0x80000000, MmSectionObjectType, 0, &Object, 0);
    KeUnstackDetachProcess(&ApcState);
    if (v9 == 1)
        DereferenceObjectSafe((__int64)PROCESS);
    if (!v10)
    {
        ObjectNameByAddress = QueryObjectNameByAddress((unsigned __int64)Object, a3, a4);
        ObfDereferenceObject(Object);
    }
    return ObjectNameByAddress;
}

// QueryDevicePathFromSymbolicLink — 从符号链接查询设备路径
// 对应原始驱动 sub_140079970
// 通过符号链接查询设备路径
char QueryDevicePathFromSymbolicLink(__int64 a1, void **a2, _DWORD *a3)
{
    char v5;
    int (__fastcall *v6)(__int64 *, __int64, int *, _QWORD *);
    __int64 (__fastcall *v7)(__int64, __int64, void **, __int64, unsigned int *);
    void (__fastcall *v8)(__int64);
    unsigned int v9;
    unsigned int v10;
    struct _KTHREAD *CurrentThread;
    __int64 v12;
    char v13;
    int v14;
    unsigned int v15;
    char v16;
    int v17;
    void *v18;
    unsigned int v20;
    _WORD *v21;
    unsigned int v23;
    void *Dst;
    __int64 v25;
    _QWORD v26[2];
    int v27;
    __int64 v28;
    __int64 v29;
    int v30;
    _OWORD v31;
    __int16 v33;

    v5 = 0;
    v6 = (int (__fastcall *)(__int64 *, __int64, int *, _QWORD *))GtRead(GtUninstallHookSyscallPeOffset|GtPathBuffer02|0x100);
    v7 = (__int64 (__fastcall *)(__int64, __int64, void **, __int64, unsigned int *))GtRead(GtTotalSize|GtObjectTypeField34|GtDriverObject);
    v8 = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    v9 = (unsigned int)GtRead(GtSdstServiceCount);
    v10 = v9;
    if (v6 && v7 && v8 && v9 != -1)
    {
        v27 = 48;
        memset(&v31, 0, sizeof(v31));
        v28 = 0;
        v30 = 512;
        v29 = 0;
        v26[0] = a1;
        v26[1] = 0;
        if (v6(&v25, 1024, &v27, v26) >= 0)
        {
            v23 = 0;
            CurrentThread = KeGetCurrentThread();
            v12 = v10;
            v13 = *((_BYTE *)CurrentThread + v10);
            *((_BYTE *)CurrentThread + v12) = 0;
            v14 = v7(v25, 27, &Dst, 8, &v23);
            *((_BYTE *)CurrentThread + v12) = v13;
            if (v14 != -1073741820)
                goto LABEL_19;
            v15 = v23;
            if (!v23)
                goto LABEL_19;
            v23 += 20;
            Dst = ExAlloc(PagedPool, v15 + 20);
            if (!Dst)
                goto LABEL_19;
            v16 = *((_BYTE *)CurrentThread + v12);
            *((_BYTE *)CurrentThread + v12) = 0;
            v17 = v7(v25, 27, (void **)Dst, v23 - 4, &v23);
            *((_BYTE *)CurrentThread + v12) = v16;
            if (v17 >= 0)
            {
                v18 = Dst;
                if ((char *)Dst + 16 != *((void **)Dst + 1))
                    goto LABEL_18;
                if ((*(_WORD *)Dst & 0xFFFE) == 0)
                    goto LABEL_18;
                v20 = *(_WORD *)Dst & 0xFFFE;
                v23 = v20;
                memmove(Dst, *((const void **)Dst + 1), v20);
                *((_WORD *)Dst + ((unsigned __int64)v23 >> 1)) = 0;
                if (BuildDevicePathFromObjects((unsigned __int16 *)Dst, &v33, (int *)&v23) == 1 && v23 > 2)
                {
                    *(_WORD *)Dst = v33;
                    *((_WORD *)Dst + 1) = 58;  // L':'
                    WStringCopy((__int16 *)Dst + 2, (__int16 *)Dst + v23);
                    v21 = Dst;
                    *a2 = Dst;
                    if (a3)
                        *a3 = 2 * GetStringLength(v21);
                    v5 = 1;
                    goto LABEL_19;
                }
            }
            v18 = Dst;
LABEL_18:
            ExFree(v18);
LABEL_19:
            v8(v25);
        }
    }
    return v5;
}

// IsProcessThreadInList — 检查进程或线程是否已在输出列表中
// 对应原始驱动 sub_14004F2A0
// 遍历已填充的条目，按对象地址比较，防止重复枚举
char IsProcessThreadInList(__int64 a1, __int64 a2, __int64 a3, char a4)
{
    char v8;
    unsigned int v9;
    unsigned int v10;
    unsigned int v11;
    int v12;
    __int64 *i;
    __int64 v14;

    v8 = 1;
    v9 = (unsigned int)GtRead(GtKiFastCallEntryAddr|GtNtoskrnlImageSize);
    v10 = (unsigned int)GtRead(GtEprocessField182|GtEprocessField06|0x100);
    v11 = *(_DWORD *)(a1 + 16);
    v12 = 0;
    if (v11)
    {
        for (i = (__int64 *)(a1 + 32); ; i += 7)
        {
            v14 = *i;
            if (a3 == *i
                || a4 == 1
                && v9
                && v10 != -1
                && *(_QWORD *)(v9 + a2) == *(_QWORD *)(v14 + v9)
                && *(_QWORD *)(v10 + a2) == *(_QWORD *)(v14 + v10))
            {
                break;
            }
            if (++v12 >= v11)
                return v8;
        }
        return 0;
    }
    return v8;
}

// EnumerateProcessInformation — 枚举进程信息
// 对应原始驱动 sub_14004FAC4
// 分配缓冲区，读取 GT 索引获取函数指针，遍历内核地址空间填充进程条目
char EnumerateProcessInformation(__int64 a1, __int64 a2, unsigned int a3)
{
    char Result;
    void *Buffer;
    ULONG64 v6;
    ULONG64 v7;
    ULONG64 v8;
    ULONG64 v9;
    ULONG64 v10;
    ULONG64 v11;
    ULONG64 v12;
    ULONG64 v13;
    ULONG64 v14;
    ULONG64 v15;
    ULONG64 v16;
    ULONG64 v17;
    ULONG64 v18;
    __int64 v19;
    __int64 v20;
    unsigned int v21;
    int v22;
    __int64 v23;
    __int64 v24;
    __int64 v25;
    __int64 v26;
    __int64 v27;
    __int64 v28;
    __int64 v29;
    ULONG64 v30;
    __int64 v31;
    __int64 v32;
    __int64 v33;
    __int64 v34;
    __int64 Dst[8];
    char v36;
    ULONG64 v37;
    __int64 v38;
    KAPC_STATE ApcState;
    __int64 v40;
    char v41;
    char v42;
    char v43;
    char v44;
    char v45;
    void *v46;
    ULONG64 *v47;
    int v48;
    int v49;
    char v50;
    __int64 v51;
    __int64 v52;
    __int64 v53;
    __int64 v54;
    __int64 v55;
    __int64 v56;
    __int64 v57;
    __int64 v58;
    __int64 v59;
    __int64 v60;
    __int64 v61;
    __int64 v62;
    __int64 v63;
    __int64 v64;
    __int64 v65;
    __int64 v66;
    __int64 v67;
    __int64 v68;
    __int64 v69;
    __int64 v70;
    __int64 v71;
    __int64 v72;
    __int64 v73;
    __int64 v74;
    __int64 v75;
    __int64 v76;
    __int64 v77;
    __int64 v78;
    __int64 v79;
    __int64 v80;
    __int64 v81;
    ULONG64 v82;
    __int64 v83;
    __int64 v84;
    __int64 v85;
    __int64 v86;
    __int64 v87;
    __int64 v88;
    __int64 v89;
    __int64 v90;
    __int64 v91;
    __int64 v92;
    ULONG64 v93;
    ULONG64 v94;
    __int64 v95;
    ULONG64 v96;
    ULONG64 v97;
    ULONG64 v98;
    ULONG64 v99;
    __int64 v100;
    __int64 v101;
    __int64 v102;
    __int64 v103;
    __int64 v104;
    __int64 v105;
    __int64 v106;
    __int64 v107;
    __int64 v108;
    __int64 v109;
    __int64 v110;
    __int64 v111;
    __int64 v112;
    __int64 v113;
    __int64 v114;
    __int64 v115;
    __int64 v116;
    __int64 v117;
    __int64 v118;
    __int64 v119;
    __int64 v120;
    __int64 v121;
    __int64 v122;
    __int64 v123;
    ULONG64 v124;
    ULONG64 v125;
    char v126;
    char v127;
    char v128;
    ULONG64 v129;
    ULONG64 v130;
    __int64 v131;
    ULONG64 v132;
    char v133;
    char v134;
    char v135;
    char v136;
    ULONG64 *v137;
    ULONG64 *v138;
    __int64 v139;
    ULONG64 *v140;
    ULONG64 v141;
    __int64 v142;
    __int64 v143;
    ULONG64 v144;
    ULONG64 v145;
    ULONG64 v146;
    ULONG64 v147;
    ULONG64 v148;
    ULONG64 v149;
    ULONG64 v150;
    ULONG64 v151;
    ULONG64 *v152;
    ULONG64 *v153;
    ULONG64 *v154;
    ULONG64 v155;
    ULONG64 v156;
    ULONG64 v157;
    ULONG64 v158;
    ULONG64 v159;
    ULONG64 v160;
    ULONG64 v161;
    ULONG64 v162;
    ULONG64 v163;
    ULONG64 v164;
    ULONG64 v165;
    ULONG64 v166;
    ULONG64 v167;
    ULONG64 v168;

    // 分配 0x3000 字节缓冲区
    Buffer = ExAlloc((POOL_TYPE)1, 0x3000);
    if (!Buffer)
        return 0;

    memset(Buffer, 0, 0x3000);

    // 读取所需 GT 索引
    v6 = GtRead((GLOBAL_TABLE_INDEX)0x41DE);
    v7 = GtRead((GLOBAL_TABLE_INDEX)0x41E4);
    v8 = GtRead((GLOBAL_TABLE_INDEX)0x41E1);
    v9 = GtRead((GLOBAL_TABLE_INDEX)0x27);
    v10 = GtRead((GLOBAL_TABLE_INDEX)0x41DB);
    v11 = GtRead((GLOBAL_TABLE_INDEX)3);
    v12 = GtRead((GLOBAL_TABLE_INDEX)2);
    v13 = GtRead((GLOBAL_TABLE_INDEX)0x4B);
    v14 = GtRead((GLOBAL_TABLE_INDEX)0x4169);

    // 验证所有必要指针
    if (!v11 || !v12 || !v13 || !v14 || !v10 || !v6 || !v7 || !v8 || v9 == -1)
    {
        ExFree(Buffer);
        return 0;
    }

    // 初始化结构
    memset(&Dst, 0, 0x40);

    // 设置当前线程 PreviousMode
    v19 = (__int64)KeGetCurrentThread();
    v20 = v9;
    v21 = *(unsigned __int8 *)(v19 + v9);
    *(unsigned __int8 *)(v19 + v20) = 0;

    // 调用枚举函数
    v22 = ((__int64(__fastcall *)(__int64, __int64, __int64, __int64))v6)(
        (__int64)&Dst, 0, 0x40, 0);
    *(unsigned __int8 *)(v19 + v20) = (unsigned __int8)v21;

    // 获取内核地址范围
    GetKernelVirtualAddressRange((__int64)&Dst, &v37, &v38);

    // 计算步进
    v21 = (unsigned int)(v13 + 0x30) & 0xFFFFFFF8;

    // 遍历地址空间 — 简化版本
    // 汇编完整实现需要深入分析，当前为骨架
    v23 = 0;
    v24 = 0;
    v25 = 0;
    Result = 0;

    // 主循环
    // ...

    ExFree(Buffer);
    return Result;
}

// BuildPeServiceNumberTable — 构建 PE 服务编号表
// 对应原始驱动 sub_1400066E4
// 从 PE 镜像中提取服务表，分配缓冲区，将服务号写入全局表
__int64 BuildPeServiceNumberTable(__int64 ImageBase, unsigned int ImageSize, unsigned int ServiceTableOffset, char Is64Bit)
{
    int EntrySize = 4;
    __int64 ServiceTablePtr = ServiceTableOffset;
    if (!Is64Bit)
        EntrySize = 8;
    __int64 result = GtRead(GtWin32kServiceCount);
    unsigned int ServiceCount = (unsigned int)result;
    if (ServiceCount
        && (unsigned int)ServiceTablePtr < ImageSize
        && (int)ServiceTablePtr + EntrySize * (int)result <= ImageSize)
    {
        __int64 PeOffset = *(int *)(ImageBase + 60);
        __int64 ImageBaseDelta;
        __int64 *BufferPtr;
        GLOBAL_TABLE_INDEX FlagIndex;
        if (Is64Bit)
        {
            ImageBaseDelta = (unsigned int)*(int *)(PeOffset + ImageBase + 52);
            BufferPtr = GtAlloc(GtWin32kServiceBuffer64);
            FlagIndex = GtWin32kServiceTable64Flag;
        }
        else
        {
            ImageBaseDelta = *(_QWORD *)(PeOffset + ImageBase + 48);
            BufferPtr = GtAlloc(GtWin32kServiceBuffer32);
            FlagIndex = GtWin32kServiceTable32Flag;
        }
        __int64 *ServiceBuffer = BufferPtr;
        result = GtWrite(FlagIndex, 1);
        int *RvaTable32 = (int *)(ServiceTablePtr + ImageBase);
        if (ServiceCount)
        {
            int *RvaTable64 = (int *)(ServiceTablePtr + ImageBase);
            char *CurrentEntry = (char *)ServiceBuffer + 4;
            __int64 EntryIndex = ServiceCount;
            do
            {
                int FuncRva;
                if (Is64Bit)
                    FuncRva = *RvaTable32;
                else
                    FuncRva = *RvaTable64;
                *((_DWORD *)CurrentEntry - 1) = 0;
                result = (unsigned int)(FuncRva - (int)ImageBaseDelta);
                __int64 FuncRvaRaw = (unsigned int)result;
                *(_DWORD *)CurrentEntry = (int)result;
                if ((unsigned int)result < ImageSize)
                {
                    result = (unsigned int)(result + 16);
                    if ((unsigned int)result <= ImageSize)
                    {
                        *((_DWORD *)CurrentEntry - 1) = 1;
                        *(_OWORD *)(CurrentEntry + 12) = *(_OWORD *)(FuncRvaRaw + ImageBase);
                    }
                }
                RvaTable64 += 2;
                ++RvaTable32;
                CurrentEntry += 48;
                --EntryIndex;
            }
            while (EntryIndex);
        }
    }
    return result;
}

// GetKernelVirtualAddressRange — 获取内核虚拟地址范围
// 对应原始驱动 sub_14007AD54
// 根据系统版本返回内核地址扫描起始和结束地址

// ParseNtRelocationTable — 解析 NT 重定位表
// 对应原始驱动 sub_1400068AC
// 附加到目标进程，读取用户态模块列表，复制服务表到内核缓冲区
ULONG64 ParseNtRelocationTableEx(PRKPROCESS Process, char IsWin32kFlag, _QWORD *OutImageBase, _QWORD *OutImageSize, void **OutDataBuffer)
{
    ULONG64 User32ModuleInList = 0;
    *OutImageBase = 0;
    *OutImageSize = 0;
    *OutDataBuffer = 0;

    unsigned int ModuleListOffset;
    unsigned int ModuleEntrySize;
    unsigned int ServiceTableOffset;
    if (IsWin32kFlag)
    {
        ModuleListOffset = GtRead(GtEprocessModuleListOffset);
        ModuleEntrySize = 48;
        ServiceTableOffset = GtRead(GtWin32kServiceTableSize64);
    }
    else
    {
        ModuleListOffset = GtRead(GtEprocessField33);
        ModuleEntrySize = 96;
        ServiceTableOffset = GtRead(GtWin32kServiceTableSize32);
    }
    unsigned int ServiceCount = GtRead(GtWin32kServiceCount);
    if (!ServiceCount || !ServiceTableOffset)
        return User32ModuleInList;

    __int64 ServiceCountCopy = ServiceCount;
    ULONG64 BufferSize = 8LL * ServiceCount;
    PVOID Buffer = ExAlloc(PagedPool, (unsigned long)BufferSize);
    *OutDataBuffer = Buffer;
    if (!Buffer)
        return User32ModuleInList;

    if (ModuleListOffset != -1)
    {
        ULONG64 *ModuleListPtr = (ULONG64 *)((char *)Process + ModuleListOffset);
        if (MmIsAddressValid(ModuleListPtr) == 1)
        {
            _QWORD *ModuleListPtrOrig = (_QWORD *)*ModuleListPtr;
            ULONG64 ModuleListValueCopy = *ModuleListPtr;
            char IsWin32k = IsWin32kFlag;
            if (IsWin32kFlag)
            {
                char PointerValid = ResolvePointerSafe(ModuleListPtrOrig, &ModuleListValueCopy);
                ModuleListPtrOrig = (_QWORD *)ModuleListValueCopy;
                if (!PointerValid)
                    ModuleListPtrOrig = 0;
                ModuleListValueCopy = (ULONG64)ModuleListPtrOrig;
            }
            if (ModuleListPtrOrig)
            {
                unsigned __int8 ProcessRefed = ReferenceObjectSafe((__int64)Process);
                KAPC_STATE ApcState;
                KeStackAttachProcess(Process, &ApcState);
                ULONG64 ModuleListValue = ModuleListValueCopy;
                if (ModuleListValueCopy < MmUserProbeAddress && ModuleListValueCopy + ModuleEntrySize < MmUserProbeAddress)
                {
                    if (IsWin32k)
                    {
                        *OutImageBase = ModuleListValueCopy + 44;
                        *OutImageSize = *(unsigned int *)(ModuleListValue + 44);
                        ULONG64 ModuleInUserSpace = *(unsigned int *)(ModuleListValue + 12);
                        if (ModuleInUserSpace < MmUserProbeAddress && ModuleInUserSpace + 40 < MmUserProbeAddress)
                        {
                            User32ModuleInList = FindUser32ModuleInList((unsigned int *)(ModuleInUserSpace + 12), 0);
                            ULONG64 ModuleInProcessCopy = User32ModuleInList;
                            if (User32ModuleInList)
                            {
                                if (User32ModuleInList < MmUserProbeAddress)
                                {
                                    const void *CopySrc = (const void *)(ServiceTableOffset + User32ModuleInList);
                                    if ((unsigned __int64)CopySrc < MmUserProbeAddress)
                                    {
                                        ULONG64 CopySize = 4 * ServiceCountCopy;
                                        ULONG64 ModuleInLoader = 4 * ServiceCountCopy + ServiceTableOffset;
                                        if (ModuleInLoader + User32ModuleInList < MmUserProbeAddress
                                            && ServiceTableOffset < MmUserProbeAddress
                                            && CopySize < MmUserProbeAddress
                                            && ModuleInLoader < MmUserProbeAddress)
                                        {
                                            memmove(*OutDataBuffer, CopySrc, CopySize);
                                            goto LABEL_EXIT;
                                        }
                                    }
                                }
                                User32ModuleInList = 0;
                            }
                        }
                    }
                    else
                    {
                        *OutImageBase = ModuleListValueCopy + 88;
                        *OutImageSize = *(_QWORD *)(ModuleListValue + 88);
                        ULONG64 ModuleInProcess = *(_QWORD *)(ModuleListValue + 24);
                        if (ModuleInProcess < MmUserProbeAddress && ModuleInProcess + 72 < MmUserProbeAddress)
                        {
                            ULONG64 ModuleInLoaderList = FindModuleInLoaderList((_QWORD **)(ModuleInProcess + 16), 0);
                            User32ModuleInList = ModuleInLoaderList;
                            ULONG64 ModuleInProcessCopy = ModuleInLoaderList;
                            if (ModuleInLoaderList)
                            {
                                if (ModuleInLoaderList < MmUserProbeAddress)
                                {
                                    const void *CopySrc = (const void *)(ServiceTableOffset + ModuleInLoaderList);
                                    if ((unsigned __int64)CopySrc < MmUserProbeAddress
                                        && ServiceTableOffset + BufferSize + ModuleInLoaderList < MmUserProbeAddress
                                        && ServiceTableOffset < MmUserProbeAddress
                                        && BufferSize < MmUserProbeAddress
                                        && ServiceTableOffset + BufferSize < MmUserProbeAddress)
                                    {
                                        memmove(*OutDataBuffer, CopySrc, BufferSize);
                                        goto LABEL_EXIT;
                                    }
                                }
                                User32ModuleInList = 0;
                            }
                        }
                    }
                }
LABEL_EXIT:
                KeUnstackDetachProcess(&ApcState);
                if (ProcessRefed == 1)
                    DereferenceObjectSafe((__int64)Process);
            }
        }
    }
    if (!User32ModuleInList)
        ExFree(*OutDataBuffer);
    return User32ModuleInList;
}

// ReadUser32DllFile — 读取 user32.dll 文件
// 对应原始驱动 sub_140006DD4
// 读取 user32.dll 或 user32_64.dll 文件到缓冲区
bool ReadUser32DllFile(_QWORD *FileBuffer, unsigned int *FileSize, char Is64Bit)
{
    bool Result = 0;
    int EncodedPath[7];
    int EncodedPath2, EncodedPath3, EncodedPath4, EncodedPath5, EncodedPath6, EncodedPath7, EncodedPath8, EncodedPath9, EncodedPathTerm;

    EncodedPath[0] = 5439580;
    EncodedPath[1] = 7536761;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 5374061;
    EncodedPath[4] = 7274607;
    EncodedPath[5] = 6029428;
    EncodedPath[6] = 7929971;
    if (Is64Bit)
    {
        EncodedPath2 = 5701747;
        EncodedPath3 = 5701711;
        EncodedPath4 = 3407926;
    }
    else
    {
        EncodedPath2 = 7602291;
        EncodedPath3 = 7143525;
        EncodedPath4 = 3276851;
    }
    EncodedPath5 = 7667804;
    EncodedPath6 = 6619251;
    EncodedPath7 = 3342450;
    EncodedPath8 = 3014706;
    EncodedPath9 = 7077988;
    EncodedPathTerm = 108;

    size_t RawFileSize;
    void *RawBuffer;
    if (!(unsigned int)ReadFileRawData((__int16 *)EncodedPath, &RawBuffer, (ULONG *)&RawFileSize, 1))
    {
        Result = ReadNtFileToBuffer((unsigned char *)RawBuffer, (unsigned int)RawFileSize, FileBuffer, FileSize) == 1;
        ExFree(RawBuffer);
    }
    return Result;
}

// ResolveWin32kServiceTableDispatch — 解析 Win32k 服务表分发
// 对应原始驱动 sub_1400075A4
// 先尝试扫描节区，失败则回退到模式匹配
__int64 ResolveWin32kServiceTableDispatch(__int64 ImageBase, unsigned int ImageSize, unsigned int ExportOffset)
{
    __int64 result = ScanWin32kSectionForServiceTable(ImageBase, ImageSize);
    if (!(_DWORD)result)
        return FindWin32kServiceTableByPattern(ImageBase, ImageSize, ExportOffset);
    return result;
}

// ResolveWin32kServiceTableEx — 解析 Win32k 服务表（扩展版）
// 对应原始驱动 sub_140007914
// 解析 Unicode 字符串中的服务表 RVA
__int64 ResolveWin32kServiceTableEx(__int64 ImageBase, unsigned int ImageSize)
{
    __int64 PeOffset = *(int *)(ImageBase + 60);
    unsigned int ImageBaseDelta = *(_DWORD *)(PeOffset + ImageBase + 52);
    __int64 ServiceTableOffset = *(unsigned int *)(PeOffset + ImageBase + 40);
    unsigned int ImageBaseDeltaCopy = ImageBaseDelta;
    unsigned int Result = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        unsigned int ServiceTableRva = 0;
        if ((unsigned int)ServiceTableOffset >= ImageSize)
            return Result;
        if ((int)ServiceTableOffset + 4096 >= ImageSize)
            goto LABEL_22;
        unsigned __int8 *ScanPosEx = (unsigned __int8 *)(ImageBase + ServiceTableOffset);
        int LoopCount64 = 0;
        unsigned __int64 ScanEnd = ImageBase + ServiceTableOffset + 4096;

        _WORD DecodedChar[24];

        while (DecodeUnicodeChar(ScanPosEx, ScanEnd, DecodedChar))
        {
            ScanPosEx += *(unsigned int *)((char *)DecodedChar + 24);
            if (*(int *)(*(__int64 *)((char *)DecodedChar + 40)) == 4275)
            {
                if (ServiceTableRva)
                    ServiceTableOffset = ServiceTableRva;
                goto LABEL_21;
            }
            if (*(int *)(*(__int64 *)((char *)DecodedChar + 40)) == 4301)
            {
                int CharCode = (int)DecodedChar[0];
                ServiceTableRva = CharCode + (int)(ScanPosEx - (unsigned __int8 *)ImageBase);
            }
            ScanEnd = ImageBase + ServiceTableOffset + 4096;
            if (++LoopCount64 >= 0x14)
                goto LABEL_21;
        }
        goto LABEL_21;
    }

    if ((unsigned int)ServiceTableOffset >= ImageSize)
        return Result;
    if ((int)ServiceTableOffset + 4096 < ImageSize)
    {
        unsigned __int8 *ScanPos = (unsigned __int8 *)(ImageBase + ServiceTableOffset);
        int LoopCount32 = 0;
        _WORD DecodedChar2[24];

        while (DecodeUnicodeChar(ScanPos, ImageBase + ServiceTableOffset + 4096, DecodedChar2))
        {
            ScanPos += *(unsigned int *)((char *)DecodedChar2 + 24);
            if (*(int *)(*(__int64 *)((char *)DecodedChar2 + 40)) == 4302)
            {
                int CharCode = (int)DecodedChar2[0];
                ServiceTableOffset = (unsigned int)(CharCode + (int)(ScanPos - (unsigned __int8 *)ImageBase));
                break;
            }
            if (++LoopCount32 >= 0x14)
                break;
        }
LABEL_21:
        ImageBaseDelta = ImageBaseDeltaCopy;
    }

LABEL_22:
    if ((unsigned int)ServiceTableOffset < ImageSize && (int)ServiceTableOffset + 4096 < ImageSize)
    {
        unsigned __int8 *ScanPos2 = (unsigned __int8 *)(ImageBase + ServiceTableOffset);
        unsigned __int64 ScanEnd2 = (unsigned __int64)(ScanPos2 + 4096);
        _WORD DecodedChar3[24];
        unsigned int NextRva = 0;

        while ((unsigned __int64)ScanPos2 < ScanEnd2 && DecodeUnicodeChar(ScanPos2, ScanEnd2, DecodedChar3))
        {
            if (*(int *)(*(__int64 *)((char *)DecodedChar3 + 40)) == 4280 && (int)DecodedChar3[0] == 44 && NextRva > ImageBaseDelta && ImageSize > NextRva - ImageBaseDelta)
                return NextRva - ImageBaseDelta;
            ScanPos2 += *(unsigned int *)((char *)DecodedChar3 + 24);
        }
    }
    return Result;
}

// QueryObjectNameLegacy — 旧版对象名称查询
// 对应原始驱动 sub_14007955C
// 通过对象头中的名称信息指针解析对象名称
char QueryObjectNameLegacy(_QWORD *Object, _QWORD *NameBuffer, _DWORD *NameLength)
{
    char Result = 0;
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (Object > MmSystemRangeStart && MmIsAddressValid(Object) == 1 && MmIsAddressValid((char *)Object + 47) == 1)
    {
        unsigned __int64 **NameInfoPtr;
        if (BuildNumber < 0x23F0 || BuildNumber >= 0x2580)
            NameInfoPtr = (unsigned __int64 **)Object[5];
        else
            NameInfoPtr = (unsigned __int64 **)Object[4];
        if (NameInfoPtr > MmSystemRangeStart && MmIsAddressValid(NameInfoPtr) == 1 && MmIsAddressValid((char *)NameInfoPtr + 7) == 1)
        {
            unsigned __int64 *NameEntry = *NameInfoPtr;
            if (NameEntry > MmSystemRangeStart && MmIsAddressValid(NameEntry) == 1 && MmIsAddressValid((char *)NameEntry + 127) == 1)
                return QueryObjectNameString(NameEntry[8], NameBuffer, NameLength);
        }
    }
    return Result;
}

// FindModuleInLoaderList — 在 PEB 加载器链表中查找模块
// 对应原始驱动 sub_140046BFC
// 遍历 PEB 加载器链表，查找指定名称的模块条目
// 返回模块基址，0 表示未找到
ULONG64 FindModuleInLoaderList(_QWORD **ListHead, _QWORD *TargetName)
{
    ULONG64 Result = 0;
    _QWORD *CurrentEntry;

    if (!ListHead)
        return Result;

    // 简化实现 — 完整实现需要比较模块名称字符串
    // 当前为占位符，返回 0 表示未找到
    return Result;
}

// ParseNtRelocationTable — 解析 NT 重定位表
// 对应原始驱动 sub_140032A30
// 解析 PE 重定位表 (.reloc 节)，返回重定位基址
// 声明在头文件: __int64 ParseNtRelocationTable(PUCHAR ImageBase);
__int64 ParseNtRelocationTable(PUCHAR ImageBase)
{
    __int64 Result = 0;
    if (!ImageBase)
        return Result;

    // 解析 PE 重定位表需要完整实现
    // 当前为占位符
    return Result;
}

// FindWin32kServiceTableByPattern — 通过模式扫描查找 Win32k 服务表
// 对应原始驱动 sub_14002B980
// 扫描 win32k 基址空间，查找服务表特征模式
// 匹配模式: 48 8D ?? ?? ?? ?? 48 89 ?? 58 (lea reg, [rip+offset]; mov [rax+xx], rbx)
// 验证匹配地址处的 10 个 QWORD 指针是否全部在镜像范围内
// 返回服务表 RVA，0 表示未找到
__int64 FindWin32kServiceTableByPattern(__int64 ImageBase, unsigned int ImageSize, unsigned int ExportOffset)
{
    ULONG64 ImageBaseDelta;
    ULONG64 ScanPos, ScanLimit;
    int OffsetDelta;
    ULONG ServiceTableRva;
    ULONG64 *TableEntry;
    unsigned int EntryIndex;
    unsigned int Result = 0;

    // 从 PE 可选头读取镜像基址（ImageBase）
    ImageBaseDelta = *(ULONG64 *)(*(int *)(ImageBase + 60) + ImageBase + 48);

    if (ExportOffset > 0x1000)
    {
        ScanPos = ExportOffset + ImageBase - 4096;
        ScanLimit = ExportOffset + ImageBase - 16;

        while (ScanPos < ScanLimit)
        {
            // 匹配 lea reg, [rip+disp32] 后跟 mov [rax+xx], rbx 的模式
            if (*(UCHAR *)ScanPos == 0x48
                && *(UCHAR *)(ScanPos + 1) == 0x8D
                && *(UCHAR *)(ScanPos + 7) == 0x48
                && *(UCHAR *)(ScanPos + 8) == 0x89
                && *(UCHAR *)(ScanPos + 10) == 0x58)
            {
                // 计算服务表 RVA: (ScanPos + 7) + offset - ImageBase低32位
                OffsetDelta = *(int *)(ScanPos + 3) - (int)(ULONG)ImageBase;
                ServiceTableRva = (ULONG)(OffsetDelta + (int)(ULONG)ScanPos + 7);

                if (ServiceTableRva != 0
                    && ServiceTableRva < ImageSize
                    && ServiceTableRva + 80 < ImageSize)
                {
                    // 验证 10 个连续的 QWORD 指针是否都在镜像范围内
                    TableEntry = (ULONG64 *)(ServiceTableRva + ImageBase);
                    for (EntryIndex = 0; EntryIndex < 10; ++EntryIndex)
                    {
                        if (*TableEntry <= ImageBaseDelta)
                            break;
                        if (*TableEntry >= ImageBaseDelta + ImageSize)
                            break;
                        ++TableEntry;
                    }
                    if (EntryIndex >= 10)
                        return ServiceTableRva;
                }
            }
            ++ScanPos;
        }
    }
    return Result;
}

// FindUser32ModuleInList — 在 PEB 模块链表中查找 user32 模块
// 对应原始驱动 sub_140046D2C
// 遍历 PEB 模块链表，查找 user32.dll 条目
// 返回模块条目指针，0 表示未找到
ULONG64 FindUser32ModuleInList(unsigned int *ListHead, int Depth)
{
    ULONG64 Result = 0;
    if (!ListHead)
        return Result;

    // 简化实现 — 完整实现需要比较模块名称字符串
    // 当前为占位符，返回 0 表示未找到
    return Result;
}

// ScanWin32kSectionForServiceTable — 扫描 Win32k 驱动节区查找服务表
// 对应原始驱动 sub_140025130
// 扫描 win32k 驱动 PE 节区，查找服务表入口
// 遍历 PE 节表，匹配特定节特征（0x559/0x512/0x50E/0x558），返回服务表偏移
// 反编译失败，从汇编分析实现
__int64 ScanWin32kSectionForServiceTable(__int64 ImageBase, unsigned int ImageSize)
{
    ULONG EntryPoint;               // edi - PE AddressOfEntryPoint
    ULONG SectionIndex;             // r15d - 节区循环计数器
    int Status;                     // eax - ReadPESectionEntry 返回值
    ULONG AccumulatedOffset;        // ecx - 累积偏移跟踪
    UCHAR Context[0x120];           // PE 节区读取上下文
    ULONG SectionInfo[0x48];        // 0x120 字节节区信息缓冲区
    ULONG Dst[16];                  // 0x40 字节目标数组
    ULONG64 CharTablePtr;           // 特征表指针
    ULONG SectionOffset;            // 节区偏移量 (SectionInfo[0xF0])
    ULONG VirtualAddress;           // 虚拟地址 (SectionInfo[0x38])
    ULONG Result;                   // ebx - 返回值
    ULONG i;                        // 循环计数器

    // 从 PE 可选头读取 AddressOfEntryPoint
    EntryPoint = *(unsigned int *)(*(int *)(ImageBase + 0x3C) + ImageBase + 0x28);
    Result = 0;

    // 第一阶段：在入口点附近扫描节区，查找特征 0x559
    if (EntryPoint < ImageSize && EntryPoint + 0x1000 < ImageSize)
    {
        InitPESectionReadContext(
            (PUCHAR)(ImageBase + EntryPoint),   // Base
            0x1000,                             // Size
            2,                                  // Mode
            0,                                  // a4
            -1,                                 // a5 (0xFFFFFFFF)
            0,                                  // a6
            (LONG64)(ULONG64)Context,           // a7 = 上下文指针
            Context);                           // a8 = 上下文输出

        AccumulatedOffset = 0;

        for (SectionIndex = 0; SectionIndex < 30; SectionIndex++)
        {
            Status = ReadPESectionEntry(Context, SectionInfo);
            if (Status != 0)
                break;

            SectionOffset = *(PULONG)((ULONG64)SectionInfo + 0xF0);
            CharTablePtr = *(ULONG64 *)((ULONG64)SectionInfo + 0x118);
            AccumulatedOffset += SectionOffset;

            // 检查节特征是否为 0x559
            if (*(USHORT *)(CharTablePtr + 6) == 0x559)
            {
                VirtualAddress = *(PULONG)((ULONG64)SectionInfo + 0x38);
                if (VirtualAddress != 0)
                {
                    ULONG Offset = VirtualAddress - (ULONG)ImageBase + (AccumulatedOffset - SectionOffset);
                    if (Offset != 0 && Offset < ImageSize)
                    {
                        EntryPoint = Offset;
                        break;
                    }
                }
            }
        }
    }

    // 第二阶段：重新扫描，匹配多个节特征
    if (EntryPoint >= ImageSize || EntryPoint + 0x1000 >= ImageSize)
        return Result;

    InitPESectionReadContext(
        (PUCHAR)(ImageBase + EntryPoint),
        0x1000,
        2,
        0,
        -1,
        0,
        (LONG64)(ULONG64)Context,
        Context);

    memset(Dst, 0, 0x40);
    AccumulatedOffset = 0;

    for (i = 0; i < 0x3E8; i++)
    {
        Status = ReadPESectionEntry(Context, SectionInfo);
        if (Status != 0)
            return Result;

        SectionOffset = *(PULONG)((ULONG64)SectionInfo + 0xF0);
        CharTablePtr = *(ULONG64 *)((ULONG64)SectionInfo + 0x118);
        AccumulatedOffset += SectionOffset;

        USHORT Characteristics = *(USHORT *)(CharTablePtr + 6);
        ULONG64 SizeField = *(ULONG64 *)((ULONG64)SectionInfo + 0x88);
        ULONG VaField = *(PULONG)((ULONG64)SectionInfo + 0x78);
        ULONG64 PtrField = *(ULONG64 *)((ULONG64)SectionInfo + 0x50);

        // Case 0x512: 初始化数据节 — 存储节 RVA
        if (Characteristics == 0x512)
        {
            if (SizeField == 0x40000 && VaField != 0 && PtrField == 0x40)
            {
                ULONG Index = *(PULONG)((ULONG64)SectionInfo + 0x58);
                Dst[Index] = VaField - (ULONG)ImageBase + (AccumulatedOffset - SectionOffset);
            }
        }
        // Case 0x50E: 代码节 — 验证后返回结果
        else if (Characteristics == 0x50E)
        {
            if ((PtrField & 0x4000) != 0 && (PtrField & 0x40) != 0)
            {
                ULONG CharLow = *(PULONG)((ULONG64)SectionInfo + 0xDC) & 0xF;
                if (CharLow != 4 && SizeField == 0x40)
                {
                    ULONG TypeField = *(PULONG)((ULONG64)SectionInfo + 0x40);
                    if (TypeField == 0x58)
                    {
                        ULONG SectionIdx = *(PULONG)((ULONG64)SectionInfo + 0x90);
                        if (Dst[SectionIdx] != 0 && Dst[SectionIdx] < ImageSize)
                        {
                            Result = Dst[SectionIdx];
                        }
                    }
                }
            }
        }
        // Case 0x558: 共享节 — 清空 Dst 数组
        else if (Characteristics == 0x558)
        {
            memset(Dst, 0, 0x40);
        }
    }

    return Result;
}


// ===== Functions moved from MissingFuncs.c =====

// CheckProcessObjectFlag — 检查进程对象标志位，根据Windows版本检查进程保护标志（如PsProtectedProcess）
__int64 CheckProcessObjectFlag(__int64 ProcessObject)
{
    unsigned int FlagOffset, BuildNumber;
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    FlagOffset = GtRead(GtCallbackField75);
    if (!FlagOffset) return 0;
    if (BuildNumber < 0x1770)
    {
        if (*(_BYTE *)(FlagOffset + ProcessObject) != 0) return 1;
        return 0;
    }
    if (BuildNumber >= 0x2800)
    {
        if (BuildNumber >= 0x3FAB)
        {
            if ((*(_DWORD *)(FlagOffset + ProcessObject) & 0x20000) != 0) return 1;
        }
        else
        {
            if ((*(_DWORD *)(FlagOffset + ProcessObject) & 0x10000) != 0) return 1;
        }
        return 0;
    }
    if (BuildNumber == 9600)
    {
        if (GtRead(GtNtCreateThreadHookSuccess) != 0)
            return (*(_DWORD *)(FlagOffset + ProcessObject) & 0x10000) != 0;
    }
    else
    {
        if ((*(_BYTE *)(FlagOffset + ProcessObject) & 1) != 0) return 1;
    }
    return 0;
}

// CheckProcessJobObject — 检查进程作业对象，查询进程是否属于某个作业对象
__int64 CheckProcessJobObject(__int64 ProcessHandle)
{
    unsigned int ServiceCount;
    __int64 QueryFuncPtr;
    __int64 (*QueryObjectFunc)(__int64, __int64, _QWORD *, __int64, _QWORD);
    _QWORD *Buffer, *BufferPtr;
    struct _KTHREAD *CurrentThread;
    __int64 ServiceCountCopy;
    char SavedServiceFlag;
    int QueryResult;
    ServiceCount = GtRead(GtSdstServiceCount);
    QueryFuncPtr = GtRead(GtDereferenceObjectFunc);
    QueryObjectFunc = (__int64 (*)(__int64, __int64, _QWORD *, __int64, _QWORD))QueryFuncPtr;
    if (ServiceCount == -1 || !QueryFuncPtr) return 0;
    Buffer = ExAlloc(PagedPool, 0x2000u);
    BufferPtr = Buffer;
    if (!Buffer) return 0;
    CurrentThread = KeGetCurrentThread();
    ServiceCountCopy = ServiceCount;
    SavedServiceFlag = *((_BYTE *)CurrentThread + ServiceCount);
    *((_BYTE *)CurrentThread + ServiceCountCopy) = 0;
    QueryResult = QueryObjectFunc(ProcessHandle, 2, BufferPtr, 0x2000, 0);
    *((_BYTE *)CurrentThread + ServiceCountCopy) = SavedServiceFlag;
    ExFree(Buffer);
    if (QueryResult >= 0 && BufferPtr[1] != 0)
        return 1;
    return 0;
}

// ReadProcessMemoryWithAttach — 附加并读取进程内存：附加到目标进程后使用系统调用查询进程内存信息，扫描PE节区
__int64 ReadProcessMemoryWithAttach(__int64 ProcessHandle)
{
    char Result;
    unsigned int (__fastcall *AttachToProcessFunc)(__int64, struct _KTHREAD **);
    __int64 (__fastcall *KeAttachProcessFunc)(struct _KTHREAD *, __int64, _QWORD, __int64, _QWORD, char, __int64 *);
    _QWORD *pContextFlags;
    __int64 ContextFlags;
    void (__fastcall *DeregisterFunc)(__int64);
    void (__fastcall *CloseHandleFunc)(struct _KTHREAD *);
    void (__fastcall *DetachProcessFunc)(__int64, _QWORD);
    unsigned int ServiceCount;
    unsigned int ServiceCountCopy, BuildNumber;
    int AttachResult;
    int SavedServiceFlag;
    __int64 PspExitNormalApcAddr2;
    __int64 ExFreeCallBackAddr2;
    __int64 PsExitSpecialApcAddr2;
    char AttachFlags;
    struct _KTHREAD *CurrentThread;
    __int64 AttachContext;
    __int64 ObjectTypeField21 = GtRead(GtObjectTypeField21);
    __int64 PspExitNormalApcAddrVal = GtRead(GtPspExitNormalApcAddr);
    __int64 ExFreeCallBackAddrVal = GtRead(GtExFreeCallBackAddr);
    __int64 PsExitSpecialApcAddrVal = GtRead(GtPsExitSpecialApcAddr);

    Result = 0;
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    AttachToProcessFunc = (unsigned int (__fastcall *)(__int64, struct _KTHREAD **))GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField182 | 0x100));
    KeAttachProcessFunc = (__int64 (__fastcall *)(struct _KTHREAD *, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead((GLOBAL_TABLE_INDEX)(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54));
    pContextFlags = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField95 | 0x100));
    ContextFlags = GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtSubsystemConfigBase | GtPathBuffer00 | 0x100));
    DeregisterFunc = (void (__fastcall *)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    CloseHandleFunc = (void (__fastcall *)(struct _KTHREAD *))GtRead(GtCloseHandleFunc);
    DetachProcessFunc = (void (__fastcall *)(__int64, _QWORD))ObjectTypeField21;
    if (!DetachProcessFunc)
    {
        ResolveSyscallAddressesInProcess();
        DetachProcessFunc = (void (__fastcall *)(__int64, _QWORD))GtRead(GtObjectTypeField21);
    }
    ServiceCount = GtRead(GtSdstServiceCount);
    ServiceCountCopy = ServiceCount;
    if (AttachToProcessFunc && KeAttachProcessFunc && pContextFlags && ContextFlags && DetachProcessFunc && ServiceCount != -1 && DeregisterFunc && CloseHandleFunc)
    {
        if (!AttachToProcessFunc(ProcessHandle, &CurrentThread))
        {
            AttachFlags = 0;
            AttachResult = KeAttachProcessFunc(CurrentThread, 512, 0, 0x10000000, *pContextFlags, AttachFlags, &AttachContext);
            CloseHandleFunc(CurrentThread);
            if (!AttachResult)
            {
                CurrentThread = KeGetCurrentThread();
                SavedServiceFlag = *((unsigned __int8 *)CurrentThread + ServiceCountCopy);
                *((_BYTE *)CurrentThread + ServiceCountCopy) = 0;
                DetachProcessFunc(AttachContext, 0);
                DeregisterFunc(AttachContext);
                *((_BYTE *)CurrentThread + ServiceCountCopy) = SavedServiceFlag;
                if (BuildNumber < 0x2580)
                {
                    if ((!PspExitNormalApcAddrVal || !ExFreeCallBackAddrVal || !PsExitSpecialApcAddrVal) && BuildNumber >= 0x1770)
                        ScanProcessPESections();
                    PspExitNormalApcAddr2 = GtRead(GtPspExitNormalApcAddr);
                    ExFreeCallBackAddr2 = GtRead(GtExFreeCallBackAddr);
                    PsExitSpecialApcAddr2 = GtRead(GtPsExitSpecialApcAddr);
                    if (PspExitNormalApcAddr2 && ExFreeCallBackAddr2)
                        return PsExitSpecialApcAddr2 != 0;
                }
            }
        }
    }
    return Result;
}

// ExecuteWithThreadContext — 在线程上下文中执行
char ExecuteWithThreadContext(__int64 Handle, __int64 VirtualAddress)
{
    unsigned int v4 = GtRead(GtSdstServiceCount);
    __int64 (__fastcall *TargetFunc)(__int64) = (__int64 (__fastcall *)(__int64))GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessExtField58 | GtDriverObject));
    unsigned int FlagOffset;
    unsigned int ThreadFlagOffset;
    __int64 SavedFlags1;
    char SavedFlags2;
    struct _KTHREAD *CurrentThread;
    char SavedThreadFlag;
    unsigned int Result, BuildNumber;

    if (v4 == -1 || !TargetFunc)
        return -1073741823;
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    FlagOffset = GtRead(GtCallbackField122);
    ThreadFlagOffset = GtRead(GtCallbackField121);
    if (BuildNumber >= 0x1770)
    {
        if (BuildNumber >= 0x2800)
            *(_BYTE *)(ThreadFlagOffset + VirtualAddress) |= 0x10u;
        else
            *(_BYTE *)(ThreadFlagOffset + VirtualAddress) |= 0x20u;
    }
    else
        *(_BYTE *)(ThreadFlagOffset + VirtualAddress) = 1;
    SavedFlags1 = *(_BYTE *)(FlagOffset + VirtualAddress);
    SavedFlags2 = *(_BYTE *)(FlagOffset + VirtualAddress + 1);
    *(_WORD *)(FlagOffset + VirtualAddress) = 0;
    CurrentThread = KeGetCurrentThread();
    SavedThreadFlag = *((_BYTE *)CurrentThread + v4);
    *((_BYTE *)CurrentThread + v4) = 0;
    Result = TargetFunc(Handle);
    *((_BYTE *)CurrentThread + v4) = SavedThreadFlag;
    *(_BYTE *)(FlagOffset + VirtualAddress) = (char)SavedFlags1;
    *(_BYTE *)(FlagOffset + VirtualAddress + 1) = SavedFlags2;
    return Result;
}

// ExecuteWithThreadFlagCleared — 清除线程标志后执行
__int64 ExecuteWithThreadFlagCleared(__int64 Address)
{
    unsigned int v2 = GtRead(GtSdstServiceCount);
    __int64 (__fastcall *SyscallFunc)(__int64, _QWORD) = (__int64 (__fastcall *)(__int64, _QWORD))ResolveSyscallAddressesInProcess();
    __int64 (__fastcall *AttachSyscall)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *) = (__int64 (__fastcall *)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead((GLOBAL_TABLE_INDEX)(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54));
    _QWORD *pFlags = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField95 | 0x100));
    void (__fastcall *CleanupFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    __int64 Handle;
    unsigned int Result;
    struct _KTHREAD *CurrentThread;
    char SavedFlag;

    if (v2 == -1 || !SyscallFunc || !AttachSyscall || !pFlags || !CleanupFunc)
        return -1073741823;
    Result = AttachSyscall(Address, 512, 0, 0x10000000, *pFlags, 0, &Handle);
    if (!Result)
    {
        CurrentThread = KeGetCurrentThread();
        SavedFlag = *((_BYTE *)CurrentThread + v2);
        *((_BYTE *)CurrentThread + v2) = 0;
        Result = SyscallFunc(Handle, 0);
        CleanupFunc(Handle);
        *((_BYTE *)CurrentThread + v2) = SavedFlag;
    }
    return Result;
}

// EnableProcessProtect — 启用进程保护
__int64 EnableProcessProtect(PVOID *Address, int InputSize, _DWORD *OutputBuffer, int OutputBufferSize)
{
    PEPROCESS Process = 0;
    NTSTATUS Status = -1073741823;
    _OWORD ProcessIdPair;
    void *ProcessId;
    struct _KPROCESS *ProcessObject;
    char IsProtected;
    GLOBAL_TABLE_INDEX TableIndex;
    unsigned int ServiceCount;

    if (!Address || InputSize != 16
        || (unsigned __int64)Address >= MmUserProbeAddress
        || (unsigned __int64)(Address + 1) >= MmUserProbeAddress
        || !OutputBuffer || OutputBufferSize != 21712
        || (unsigned __int64)OutputBuffer >= MmUserProbeAddress
        || (unsigned __int64)(OutputBuffer + 5428) >= MmUserProbeAddress)
        goto Cleanup;
    ProbeForRead(Address, 0x10u, 4u);
    ProbeForWrite(OutputBuffer, 0x54D0u, 1u);
    ProcessIdPair = *(_OWORD *)Address;
    ProcessId = (void *)ProcessIdPair.qword[1];
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    ProcessObject = (struct _KPROCESS *)ProcessIdPair.qword[0];
    if (!ProcessIdPair.qword[0] && Status >= 0)
        ProcessObject = (struct _KPROCESS *)Process;
    if (ValidateProcessObject(ProcessObject, 0) != 1)
        goto Cleanup;
    IsProtected = CheckProtectedEntry((__int64)ProcessObject);
    TableIndex = IsProtected ? GtWin32kServiceTable64Flag : GtWin32kServiceTable32Flag;
    if (!(unsigned int)GtRead(TableIndex))
    {
        ResolveWin32kServiceTable(IsProtected);
        TableIndex = IsProtected ? GtWin32kServiceTable64Flag : GtWin32kServiceTable32Flag;
        if (!(unsigned int)GtRead(TableIndex))
            goto Cleanup;
    }
    memset(OutputBuffer, 0, 0x54D0u);
    *OutputBuffer = GtRead(GtWindowsBuildNumber);
    ServiceCount = GtRead(GtWin32kServiceCount);
    OutputBuffer[8] = ServiceCount;
    if (ServiceCount <= 0x12D
        && BuildExportServiceTable((__int64)ProcessId, ProcessObject, IsProtected, OutputBuffer) == 1
        && CopyValidServiceEntries((__int64)(OutputBuffer + 10), IsProtected) == 1
        && ParseNtImageSectionHeaders(ProcessObject, (__int64)(OutputBuffer + 10)) == 1)
    {
        *((_BYTE *)OutputBuffer + 4) = 1;
        if (Status >= 0)
            ObfDereferenceObject(Process);
        return 1;
    }
Cleanup:
    if (Status >= 0)
        ObfDereferenceObject(Process);
    return 0;
}

// ProcessOperationWithAttach — 挂载到目标进程上下文中执行操作：附加到进程，清除进程保护标志和页表标志，执行回调后分离
__int64 ProcessOperationWithAttach(struct _KPROCESS *TargetProcess)
{
    bool Result;
    unsigned int ServiceCount;
    int (__fastcall *KeAttachProcessFunc)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *);
    int (__fastcall *KeDetachProcessFunc)(__int64, _QWORD);
    _QWORD *pContextFlags;
    __int64 RegisterFuncPtr;
    void (__fastcall *DeregisterFunc)(__int64);
    struct _KTHREAD *CurrentThread;
    unsigned __int8 RefCount;
    unsigned int ProcessFlagsOffset;
    __int64 FlagsOffset;
    char SavedServiceFlag;
    __int64 AttachContext;
    __int64 PspExitThreadAddr = GtRead(GtPspExitThreadAddr);
    __int64 KiInsertQueueApcFunc = GtRead(GtKiInsertQueueApcFunc);

    Result = 0;
    ServiceCount = GtRead(GtSdstServiceCount);
    KeAttachProcessFunc = (int (__fastcall *)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead((enum _GLOBAL_TABLE_INDEX)(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54));
    KeDetachProcessFunc = (int (__fastcall *)(__int64, _QWORD))GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField124 | 0x100));
    if (!KeDetachProcessFunc)
        KeDetachProcessFunc = (int (__fastcall *)(__int64, _QWORD))ResolveSyscallAddressesWithAttach();
    pContextFlags = (_QWORD *)GtRead((enum _GLOBAL_TABLE_INDEX)(GtTotalSize | GtExFreeCallBackAddr | 0x100));
    RegisterFuncPtr = GtRead(GtRegisterObjectCallbacksFunc);
    DeregisterFunc = (void (__fastcall *)(__int64))RegisterFuncPtr;
    if (ServiceCount != -1 && KeAttachProcessFunc && KeDetachProcessFunc && pContextFlags && RegisterFuncPtr)
    {
        CurrentThread = KeGetCurrentThread();
        if (KeAttachProcessFunc(TargetProcess, 512, 0, 0x10000000, *pContextFlags, 0, &AttachContext) >= 0)
        {
            if (!PspExitThreadAddr)
            {
                ScanProcessPESectionsV2();
                GtRead(GtPspExitThreadAddr);
            }
            if (!KiInsertQueueApcFunc)
            {
                InitHookFunctionTable();
                GtRead(GtKiInsertQueueApcFunc);
            }
            if (ValidateProcessObject(TargetProcess, 0) == 1)
            {
                RefCount = ReferenceObjectSafe((__int64)TargetProcess);
                ProcessFlagsOffset = GtRead(GtCallbackField124);
                if (ProcessFlagsOffset)
                {
                    FlagsOffset = ProcessFlagsOffset;
                    *(_DWORD *)((char *)TargetProcess + ProcessFlagsOffset) &= ~0x2000u;
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x1770)
                        *(_DWORD *)((char *)TargetProcess + FlagsOffset) &= ~8u;
                    else
                        *(_DWORD *)((char *)TargetProcess + FlagsOffset) &= 0xBFFFFFF7;
                }
                if (RefCount == 1)
                    DereferenceObjectSafe((__int64)TargetProcess);
            }
            ClearProcessPageTableFlags(TargetProcess);
            SavedServiceFlag = *((_BYTE *)CurrentThread + ServiceCount);
            *((_BYTE *)CurrentThread + ServiceCount) = 0;
            Result = KeDetachProcessFunc(AttachContext, 0) >= 0;
            DeregisterFunc(AttachContext);
            *((_BYTE *)CurrentThread + ServiceCount) = SavedServiceFlag;
        }
    }
    return Result;
}

// UnlinkFromProcessMemoryList — 从进程内存链表解除链接
__int64 UnlinkFromProcessMemoryList(PVOID *pTargetPointer)
{
    char Result;
    PVOID **pListHead;
    PVOID **pSentinel;
    PVOID *pCurrentNode;
    int IterationCount;
    PVOID *pPrevEntry;
    PVOID **pNextEntry;

    Result = 0;
    pListHead = (PVOID **)GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessField31 | 0x800));
    pSentinel = pListHead;
    if (pListHead && MmIsAddressValid(pListHead) == 1)
    {
        pCurrentNode = *pSentinel;
        IterationCount = 0;
        while (pCurrentNode != (PVOID *)pSentinel)
        {
            if (pCurrentNode <= MmSystemRangeStart)
                break;
            if (MmIsAddressValid(pCurrentNode) != 1)
                break;
            if ((unsigned int)++IterationCount > 0x1000)
                break;
            if (pCurrentNode - 1 == pTargetPointer)
            {
                if (MmIsAddressValid(*pCurrentNode) == 1)
                {
                    pPrevEntry = (PVOID *)*pCurrentNode;
                    pNextEntry = (PVOID **)pCurrentNode[1];
                    Result = 1;
                    pPrevEntry[1] = pNextEntry;
                    *pNextEntry = pPrevEntry;
                }
                return Result;
            }
            pCurrentNode = (PVOID *)*pCurrentNode;
        }
    }
    return Result;
}

// ValidateAndClearProcessContext — 验证并清除进程上下文
__int64 ValidateAndClearProcessContext(int CurrentProcessor, __int64 pContext)
{
    char Result;
    char *CurrentFiber;
    int FiberOffset;
    bool IsSameProcessor;

    Result = 1;
    if (*(_DWORD *)pContext == -1 || *(_DWORD *)pContext == CurrentProcessor)
    {
        ClearDebugRegisters();
        CurrentFiber = (char *)j_GetCurrentFiber();
        FiberOffset = GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField88));
        if (CurrentFiber && FiberOffset)
            memset(&CurrentFiber[FiberOffset], 0, 0x30u);
        IsSameProcessor = *(_DWORD *)pContext == CurrentProcessor;
        *(_BYTE *)(pContext + 4) = 1;
        return !IsSameProcessor;
    }
    return Result;
}

// InitProcessAndQueryInfo — 初始化进程并查询信息
// 对应原始驱动 sub_14007E6A4
bool InitProcessAndQueryInfo(struct _KPROCESS *Process, char Flags)
{
    bool Result;
    unsigned int (__fastcall *AttachProcessFunc)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *);
    _QWORD *ServiceCountPtr;
    enum _GLOBAL_TABLE_INDEX GtIndex;
    __int64 (__fastcall *QueryFunc)(__int64);
    void (__fastcall *FreePoolFunc)(__int64);
    enum _GLOBAL_TABLE_INDEX GtIndex2;
    __int64 CallbackValue;
    unsigned int ServiceCount;
    struct _KTHREAD *CurrentThread;
    __int64 ServiceCount64;
    char SavedByte;
    int QueryResult;
    __int64 ContextBuffer;
    __int64 ServiceCountCopy;

    Result = 0;
    ServiceCountCopy = GtRead(GtSdstServiceCount);
    AttachProcessFunc = (unsigned int (__fastcall *)(struct _KPROCESS *, __int64, _QWORD, __int64, _QWORD, _BYTE, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset);
    ServiceCountPtr = (_QWORD *)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
    GtIndex = GtNtQuerySystemInformationFunc | GtEprocessField58;
    if (Flags != 1)
        GtIndex = GtSubsystemConfigBase | GtEprocessField10 | 0x100;
    QueryFunc = (__int64(__fastcall *)(__int64))GtRead(GtIndex);
    FreePoolFunc = (void(__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    if (!QueryFunc)
    {
        ResolveKernelModuleFunctionAddrs(0, 0, 0);
        GtIndex2 = GtNtQuerySystemInformationFunc | GtEprocessField58;
        if (Flags != 1)
            GtIndex2 = GtSubsystemConfigBase | GtEprocessField10 | 0x100;
        QueryFunc = (__int64(__fastcall *)(__int64))GtRead(GtIndex2);
    }
    if (!GtRead(GtKiInsertQueueApcFunc))
    {
        InitHookFunctionTable(0, 0, 0, 0);
        GtRead(GtKiInsertQueueApcFunc);
    }
    if (Flags == 1 && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28)
    {
        CallbackValue = GtRead(GtCallbackField11);
        GtRead(GtCallbackField12);
        if (!CallbackValue)
        {
            ScanKernelModulePESectionsEx(0, 0, 0, 0, 0, 0);
            GtRead(GtCallbackField11);
            GtRead(GtCallbackField12);
        }
    }
    ServiceCount = (unsigned int)ServiceCountCopy;
    if ((_DWORD)ServiceCountCopy != -1
        && AttachProcessFunc
        && QueryFunc
        && FreePoolFunc
        && ServiceCountPtr
        && !AttachProcessFunc(Process, 512, 0, 0x10000000, *ServiceCountPtr, 0, &ContextBuffer))
    {
        GtRead(GtWindowsBuildNumber);
        if (Flags == 1)
            TraverseEprocessListAndInit((__int64)Process, 0, 0, 0, 0, 0);
        CurrentThread = KeGetCurrentThread();
        ServiceCount64 = ServiceCount;
        SavedByte = *((_BYTE *)CurrentThread + ServiceCount);
        *((_BYTE *)CurrentThread + ServiceCount64) = 0;
        QueryResult = (int)QueryFunc(ContextBuffer);
        *((_BYTE *)CurrentThread + ServiceCount64) = SavedByte;
        Result = QueryResult == 0;
        GtRead(GtWindowsBuildNumber);
        FreePoolFunc(ContextBuffer);
    }
    return Result;
}

// TraverseEprocessListAndInit — 遍历 EPROCESS 链表并初始化内核对象头
// 遍历进程链表，验证每个进程对象并初始化内核对象头
// 对应原始驱动 sub_14007DF2C
char TraverseEprocessListAndInit(struct _KPROCESS *Process)
{
    unsigned int ListOffset;
    unsigned int ObjectHeaderOffset;
    unsigned int Iterations;
    _QWORD **pListEntry;
    unsigned __int8 IsReferenced;
    _QWORD *CurrentEntry;

    ListOffset = GtRead(GtEprocessField41);
    ObjectHeaderOffset = GtRead(GtEprocessField48);
    if (ListOffset && ObjectHeaderOffset)
    {
        if (ValidateProcessObject(Process, 0) == 1)
        {
            pListEntry = (_QWORD **)((char *)Process + ListOffset);
            IsReferenced = ReferenceObjectSafe((__int64)Process);
            if (MmIsAddressValid(pListEntry) == 1)
            {
                CurrentEntry = *pListEntry;
                for (Iterations = 0; CurrentEntry > MmSystemRangeStart; ++Iterations)
                {
                    if (CurrentEntry == pListEntry)
                        break;
                    if (Iterations > 0x10000)
                        break;
                    if (MmIsAddressValid(CurrentEntry) != 1)
                        break;
                    if (ValidateKernelObject((unsigned __int64)CurrentEntry - ObjectHeaderOffset, 0, 0, 0) != 1)
                        break;
                    InitKernelObjectHeader((char *)CurrentEntry - ObjectHeaderOffset);
                    CurrentEntry = (_QWORD *)*CurrentEntry;
                }
            }
            if (IsReferenced == 1)
                DereferenceObjectSafe((__int64)Process);
        }
    }
    return 0;
}

__int64 GetProcessDeviceMap(_QWORD *pEprocessPtr)
{
    __int64 Result;
    _QWORD *pEprocess;

    Result = 0;
    if (pEprocessPtr)
    {
        if (MmIsAddressValid(pEprocessPtr) == 1 && MmIsAddressValid((char *)pEprocessPtr + 335) == 1)
        {
            pEprocess = (_QWORD *)pEprocessPtr[1];
            if (pEprocess)
            {
                if (MmIsAddressValid(pEprocess) == 1 && MmIsAddressValid((char *)pEprocess + 335) == 1)
                    return pEprocess[30];
            }
        }
    }
    return Result;
}


// ResolveSyscallAddressesWithAttach -- 附加并解析系统调用地址。
// 附加到目标进程上下文，通过系统调用号解析内核函数地址。
// 对应原始驱动 sub_14007FE80
__int64 ResolveSyscallAddressesWithAttach(void)
{
    __int64 Result = 0;
    struct _KPROCESS *TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    struct _KAPC_STATE ApcState;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    __int64 FieldOffset = GtRead(GtEprocessField22);
    unsigned int FieldSize = GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int KernelPESectionByType = FindKernelPESectionByType(210 | GtTotalSize);
    unsigned int ServiceCount = GtRead(GtWin32kServiceEntryCount);
    if (FieldOffset && FieldSize && NtoskrnlBase && KernelPESectionByType && KernelPESectionByType < ServiceCount)
    {
        unsigned int SyscallIndex = ResolveSyscallToAddress(KernelPESectionByType);
        if (SyscallIndex && SyscallIndex < FieldSize)
        {
            __int64 SyscallOffset = SyscallIndex;
            GtWrite(GtObjectTypeField18, SyscallIndex);
            Result = NtoskrnlBase + SyscallOffset;
            GtWrite(GtEprocessField124 | 0x100, Result);
        }
    }
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}

// BuildExportServiceTable -- 构建导出服务表
// 读取 GT 服务表配置，调用 ParseNtRelocationTableEx 获取映像基址
// 读取 user32.dll 文件，解析导出目录，构建服务条目表
char BuildExportServiceTable(PUCHAR ImageBase, ULONG ImageSize, PUCHAR ServiceTable, ULONG TableSize)
{
    char Result = 0;
    unsigned int ServiceCount;
    unsigned int ServiceTableSize;
    __int64 ServiceBuffer;
    _QWORD RelocatedBase;
    _QWORD RelocatedSizeVal;
    void **DataBuffer;
    __int64 FileBuffer;
    unsigned int FileSize;
    unsigned int EntryIndex;
    char Is64Bit;
    _QWORD ServiceTablePtr;

    if (!ImageBase || !ImageSize || !ServiceTable || !TableSize)
        return 0;

    // 读取 GT 服务表配置
    ServiceCount = (unsigned int)GtRead(GtWin32kServiceCount);
    if ((unsigned int)GtRead(GtWin32kServiceTable32Flag))
    {
        ServiceTableSize = (unsigned int)GtRead(GtWin32kServiceTableSize32);
        ServiceBuffer = (__int64)GtAlloc(GtWin32kServiceBuffer32);
        Is64Bit = 0;
    }
    else
    {
        ServiceTableSize = (unsigned int)GtRead(GtWin32kServiceTableSize64);
        ServiceBuffer = (__int64)GtAlloc(GtWin32kServiceBuffer64);
        Is64Bit = 1;
    }
    ServiceTablePtr = *(_QWORD *)ServiceTable;

    // 解析重定位表获取 relocated 基址
    RelocatedBase = ParseNtRelocationTableEx((PRKPROCESS)ImageBase, Is64Bit, &RelocatedSizeVal, &DataBuffer, &DataBuffer);
    if (!RelocatedBase)
        goto cleanup;
    if (!ServiceCount || !ServiceTableSize || !ServiceBuffer || !RelocatedSizeVal)
        goto cleanup;

    // 读取 user32.dll 文件
    if (!ReadUser32DllFile(&FileBuffer, &FileSize, Is64Bit))
        goto cleanup;

    // 解析导出目录
    if (ParseNtExportDir((PUCHAR)FileBuffer, FileSize, RelocatedBase, Is64Bit) != 1)
    {
        if (FileBuffer)
            ExFree((void *)FileBuffer);
        goto cleanup;
    }
    if (FileBuffer)
        ExFree((void *)FileBuffer);

    // 构建服务条目
    if (ServiceCount && ServiceTableSize && ServiceBuffer)
    {
        ServiceTableSize = *(unsigned int *)(ServiceBuffer + 4);
        if (ServiceTableSize <= TableSize)
        {
            for (EntryIndex = 0; EntryIndex < ServiceCount; ++EntryIndex)
            {
                __int64 EntryAddr = ServiceBuffer + 0x40 + EntryIndex * 0x30;
                *(unsigned int *)EntryAddr = EntryIndex;
                if (ServiceTablePtr)
                {
                    if (Is64Bit)
                    {
                        *(unsigned int *)(EntryAddr + 0x50) = *(unsigned int *)(RelocatedSizeVal + EntryIndex * 8);
                        *(__int64 *)(EntryAddr + 0x38) = RelocatedBase + EntryIndex * 8;
                    }
                    else
                    {
                        *(unsigned int *)(EntryAddr + 0x50) = *(unsigned int *)(RelocatedSizeVal + EntryIndex * 4);
                        *(__int64 *)(EntryAddr + 0x38) = RelocatedBase + EntryIndex * 4;
                    }
                }
                *(__int64 *)(EntryAddr + 0x28) = (__int64)ImageBase;
                *(__int64 *)(EntryAddr + 0x30) = (__int64)ServiceTable;
                __int64 Offset = ServiceBuffer + 4 + (EntryIndex + EntryIndex * 2) << 4;
                *(unsigned int *)(EntryAddr + 0x48) = *(unsigned int *)(Offset + 4);
                *(unsigned int *)(EntryAddr + 0x40) = EntryIndex;
            }
        }
        Result = 1;
    }

cleanup:
    if (DataBuffer)
        ExFree(*DataBuffer);
    return Result;
}
