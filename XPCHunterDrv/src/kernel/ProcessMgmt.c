// ProcessMgmt.c — 进程管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include <intrin.h>
#include "XPCHunterDrv.h"
// Forward declarations
bool IsProcessObjectTerminated(char *VirtualAddress);
bool ReadUser32DllFile(_QWORD *FileBuffer, unsigned int *FileSize, char Is64Bit);
ULONG64 ParseNtRelocationTableEx(PRKPROCESS Process, char IsWin32kFlag, _QWORD *OutImageBase, _QWORD *OutImageSize, void **OutDataBuffer);
WORD *InitSystemPath(void);
__int16 *WStringCopy(__int16 *Dest, __int16 *Src);
__int64 BuildDevicePathFromObjects(unsigned __int16 *Dst, WORD *pDriveLetter, int *pOffset);
__int64 GtWrite(enum _GLOBAL_TABLE_INDEX Index, __int64 Value);

// 外部函数声明（在其他模块中定义，未在头文件中声明）
char ReturnFalseStub(void);
char ValidateEnumerationResult(__int64 ObjectEntry, __int64 Context, __int64 Result);

// 本文件后向引用前向声明
ULONG64 FindModuleInLoaderList(_QWORD **ModuleListHead, unsigned int EntryOffset);
__int64 FindWin32kServiceTableByPattern(__int64 ImageBase, unsigned int ImageSize, unsigned int ExportOffset);
ULONG64 FindUser32ModuleInList(unsigned int *ModuleListHead, unsigned int EntryOffset);
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
            IsWin32k = WriteProcessMemoryValue((_QWORD *)InputBuffer);
            BufferWriteSuccess = *((UCHAR *)&OutputBuffer.qword[0] + 1);
        }

        if (BufferWriteSuccess == 1)
            WriteSuccess = WriteProcessMemoryBuffer((_QWORD *)InputBuffer);

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
                        return (char)TerminateFunc(ProcessObject, 0);
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
                WStringCopyN((_WORD *)&OutputBuffer[136 * *OutputBuffer + 8],
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

    while (Current != (_QWORD *)ListHead)
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
bool QueryProcessInfoByHandle(__int64 Process, __int64 Handle, __int64 InfoBuffer, int BufferSize)
{
    bool Result = 0;
    ULONG PrevModeOffset;
    int (__fastcall *OpenObjFunc)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *);
    _QWORD *InfoSize;
    void (__fastcall *CloseFunc)(_QWORD);
    __int64 QueryFuncAddr;
    __int64 (*QueryFunc)(_QWORD, __int64 *, ULONG64, __int64 *, int, int);
    struct _KTHREAD *CurrentThread;
    int QueryStatus;
    char PrevModeValue;
    _QWORD ObjectHandleArr[9];
    __int64 HandleValue, InfoBufferValue;
    int BufferSizeLocal = BufferSize;

    InfoBufferValue = InfoBuffer;
    HandleValue = Handle;
    PrevModeOffset = (ULONG)GtRead(GtSdstServiceCount);
    OpenObjFunc = (int (__fastcall *)(__int64, __int64, ULONG64, __int64, ULONG64, UCHAR, _QWORD *))GtRead(16735);
    InfoSize = (_QWORD *)GtRead(16748);
    CloseFunc = (void (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    QueryFuncAddr = GtRead(16839);
    QueryFunc = (__int64 (*)(_QWORD, __int64 *, ULONG64, __int64 *, int, int))QueryFuncAddr;

    if (PrevModeOffset == (ULONG)-1 || !OpenObjFunc || !InfoSize || !CloseFunc || !QueryFuncAddr) return Result;

    CurrentThread = KeGetCurrentThread();
    if (OpenObjFunc(Process, 512, 0, 0x10000000, *InfoSize, 0, ObjectHandleArr) >= 0)
    {
        PrevModeValue = *((UCHAR *)CurrentThread + PrevModeOffset);
        *((UCHAR *)CurrentThread + PrevModeOffset) = 0;
        QueryStatus = (int)QueryFunc(ObjectHandleArr[0], &HandleValue, 0, &InfoBufferValue, 4096, BufferSizeLocal);
        *((UCHAR *)CurrentThread + PrevModeOffset) = PrevModeValue;
        Result = QueryStatus >= 0;
        CloseFunc(ObjectHandleArr[0]);
    }

    return Result;
}

// CmdProcessMonitor — 进程监视命令处理
// 对应原始驱动 sub_140070D1C
__int64 CmdProcessMonitor(_OWORD *Address, int InputSize)
{
    bool ProcessInfoByHandle = 0;
    NTSTATUS LookupStatus;
    struct _KPROCESS *LookedUpProcess, *Result;
    PEPROCESS Process = NULL;
    HANDLE ProcessId[3];
    _OWORD ProcessIdData;
    __int64 ProcessIdData2;

    if (!Address || InputSize != 40 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)&Address[2].qword[1] >= MmUserProbeAddress)
        return ProcessInfoByHandle;

    ProbeForRead(Address, 0x28, 4);
    *(_OWORD *)ProcessId = *(_OWORD *)Address;
    ProcessIdData = Address[1];
    ProcessIdData2 = Address[2].qword[0];

    LookupStatus = PsLookupProcessByProcessId(ProcessId[0], &Process);
    LookedUpProcess = (struct _KPROCESS *)Process;
    if (LookupStatus < 0) LookedUpProcess = NULL;
    Process = (PEPROCESS)LookedUpProcess;

    Result = (struct _KPROCESS *)((_OWORD *)ProcessId)->qword[1];
    if (!Result) { if (LookupStatus >= 0) Result = LookedUpProcess; Result = Result; }

    if (ValidateProcessObject(Result, NULL) == 1 && ProcessIdData.qword[1])
        ProcessInfoByHandle = QueryProcessInfoByHandle((__int64)Result, ProcessIdData.qword[0], ProcessIdData.qword[1], (int)ProcessIdData2);

    if (Process) ObfDereferenceObject(Process);
    return ProcessInfoByHandle;
}

// EnumerateProcessList — 枚举进程列表
// 对应原始驱动 sub_14004FF98
// 通过 EPROCESS 对象枚举进程信息
bool EnumerateProcessList(struct _KPROCESS *Process, __int64 OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    UCHAR ProcessRefed;
    _BYTE ContextData[8];
    __int64 EntryCount;
    struct _KPROCESS *ProcessLocal;

    if (BufferSize <= 0x50) return Result;

    ProcessLocal = Process;
    EntryCount = 0;
    *(__int64 *)OutputBuffer = 0;
    *(__int64 *)(OutputBuffer + 8) = (__int64)Process;
    *(ULONG *)(OutputBuffer + 16) = 0;

    if (Process)
    {
        if (ValidateProcessObject(Process, NULL) == 1)
        {
            ProcessRefed = ReferenceObjectSafe((__int64)Process);
            DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
                (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject,
                (__int64)ContextData);
            EnumerateProcessInformation((__int64)Process, OutputBuffer, BufferSize);
            if (ProcessRefed == 1) DereferenceObjectSafe((__int64)Process);
        }
    }
    else
    {
        DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
            (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject,
            (__int64)ContextData);
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
    __int64 ProcessId;
    char IsNewProcess;
    ULONG Field36;
    _DWORD *Entry;
    int EntryOffset;
    void *ObjectBuffer;
    WORD NameBuffer[8];
    __int64 ProcessName;
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
    if ((unsigned int)(552 * (int)EntryIndex + 560) >= BufferSize) return 0;

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

    BYTE1_LV(OutputBuffer[EntryOffset + 2]) = (UCHAR)CheckProtectedEntry((__int64)PROCESS);
    if (Field36 == (ULONG)-1)
        *(__int64 *)&OutputBuffer[EntryOffset + 8] = 0;
    else
        *(__int64 *)&OutputBuffer[EntryOffset + 8] = *(__int64 *)((char *)PROCESS + Field36);

    Entry = &OutputBuffer[EntryOffset];
    LOWORD_LV(OutputBuffer[EntryOffset + 12]) = 0;

    if (GetProcessImagePath(PROCESS, *(HANDLE *)&OutputBuffer[EntryOffset + 6], &ObjectBuffer, NULL, (char)PathFlag) == 1)
    {
        WStringCopyN((WORD *)Entry + 24, (__int64)ObjectBuffer, 0x100);
        HIWORD_LV(OutputBuffer[EntryOffset + 139]) = 0;
        ExFree(ObjectBuffer);
    }
    else
    {
        if (PathFlag) return 0;
        _QWORD **pTypeInfo = (_QWORD **)GtRead(GtObjectTypeInfoPtr);
        if (pTypeInfo && *pTypeInfo == (_QWORD *)TargetProcess)
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
                    strcpy((char *)NameBuffer, "MemCompression");
                    ProcessName = GetProcessNameFunc(PROCESS);
                    if (StringCompareCaseInsensitiveV2(ProcessName, (__int64)NameBuffer) == 0)
                    {
                        Entry[12] = 6619213; Entry[13] = 4391021;
                        Entry[14] = 7143535; Entry[15] = 7471216;
                        Entry[16] = 7536741; Entry[17] = 6881395;
                        *((__int64 *)Entry + 9) = 7209071;
                        goto Done;
                    }
                    if (BuildNumber >= 0x42EE)
                    {
                        strcpy((char *)NameBuffer, "Registry");
                        if (StringCompareCaseInsensitiveV2(ProcessName, (__int64)NameBuffer) == 0)
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
// ValidateAndEnumerateObject — 验证并枚举对象
// 对应原始驱动 0x140050078（258 字节）
// 【⚠ GT 索引修正 2026-10-13】原写十进制 16748(=0x416C)，原始为 **0x4169**
//   （依据原始读序 0x140050078：`0x4169 → 0x38 → 0x914 → 0x81C`，
//     见 0x1400500下一行的 `mov ecx,0x4169; call GtRead`）。
//   第二处 GtProcessOffset(=56=0x38) 经核对**正确**。
char ValidateAndEnumerateObject(char *VirtualAddress, __int64 OutputBuffer, unsigned int BufferSize, __int64 Context)
{
    __int64 *ObjectTypeTable = (__int64 *)GtRead((GLOBAL_TABLE_INDEX)0x4169);
    int ProcessOffset = (int)GtRead(GtProcessOffset);
    char TypeFlagValue;
    bool IsProcessMatch;

    if (!ObjectTypeTable || ProcessOffset == -1 || (ULONG64)VirtualAddress <= (ULONG64)MmSystemRangeStart)
        return 0;

    char *ProcessFieldPtr = &VirtualAddress[(unsigned int)ProcessOffset];
    if (MmIsAddressValid(VirtualAddress - 48) != 1 || MmIsAddressValid(ProcessFieldPtr) != 1)
        return 0;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        TypeFlagValue = CheckObjectTypeFlagWrapper((__int64)(VirtualAddress - 48));
        IsProcessMatch = ((UCHAR)GtRead(16960) == (UCHAR)TypeFlagValue);
    }
    else
    {
        IsProcessMatch = (*((__int64 *)VirtualAddress - 4) == *ObjectTypeTable);
    }

    if (IsProcessMatch)
    {
        __int64 ctx_val = *(__int64 *)(Context + 16);
        if (!ctx_val || *(__int64 *)ProcessFieldPtr == ctx_val)
            return FillProcessInformationEntry(VirtualAddress, VirtualAddress, OutputBuffer, BufferSize, 0, 0, 0);
    }
    return 0;
}

// ValidateProcessObjectEx — 扩展进程对象验证
// 对应原始驱动 sub_14004B398
// 验证进程对象类型标志和是否已终止，有效则调用 EnumerateProcessObjects
char ValidateProcessObjectEx(char *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char *HeaderPtr = VirtualAddress - 48;
    // 【GT 索引修正 2026-10-13】原写 16752(0x4170)/16960(0x4240)/16748(0x416C)；
    //   原始读序为 `0x4196 → 0x914 → 0x4166 → 0x4169 → 0x81B → 0x81C`
    //   （0x14004B398 起）。故第一处应为 **0x4196**、第三处应为 **0x4169**。
    __int64 (*ObjectType)(char *) = (__int64 (*)(char *))GtRead((GLOBAL_TABLE_INDEX)0x4196);
    __int64 (*ObjectHeader)(char *) = ObjectType;
    UCHAR Index16960 = (UCHAR)GtRead((GLOBAL_TABLE_INDEX)0x4166);
    __int64 Index16748 = GtRead((GLOBAL_TABLE_INDEX)0x4169);

    if (!ObjectType) return 0;
    if ((ULONG64)VirtualAddress <= (ULONG64)MmSystemRangeStart) return 0;
    if (MmIsAddressValid(HeaderPtr) != 1) return 0;

    _QWORD *TypeIndex;
    __int64 TypeOffset;
    bool IsTypeMatch;
    char TypeFlagCheck, TypeFlagCheck2;
    char *ObjectHeaderPtr;
    struct _KPROCESS *TypeInfo, *ProcessBody;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
    {
        TypeFlagCheck = CheckObjectTypeFlagWrapper((__int64)HeaderPtr);
        if (TypeFlagCheck == Index16960)
        {
            if (!IsProcessObjectTerminated(VirtualAddress))
            {
                TypeInfo = (struct _KPROCESS *)VirtualAddress;
                ProcessBody = (struct _KPROCESS *)VirtualAddress;
                return EnumerateProcessObjects(ProcessBody, TypeInfo, OutputBuffer, BufferSize, 0, 0, 0);
            }
            return 0;
        }
        TypeFlagCheck2 = CheckObjectTypeFlagWrapper((__int64)HeaderPtr);
        IsTypeMatch = (TypeFlagCheck2 == Index16960);
    }
    else
    {
        TypeIndex = (_QWORD *)Index16748;
        ObjectType = (__int64 (*)(char *))Index16748;
        if (!TypeIndex || !ObjectType) return 0;
        TypeOffset = *((__int64 *)HeaderPtr + 2);
        if (TypeOffset == *TypeIndex)
        {
            if (!IsProcessObjectTerminated(VirtualAddress))
            {
                TypeInfo = (struct _KPROCESS *)VirtualAddress;
                ProcessBody = (struct _KPROCESS *)VirtualAddress;
                return EnumerateProcessObjects(ProcessBody, TypeInfo, OutputBuffer, BufferSize, 0, 0, 0);
            }
            return 0;
        }
        IsTypeMatch = (TypeOffset == *(__int64 *)ObjectType);
    }

    if (IsTypeMatch)
    {
        ObjectHeaderPtr = (char *)ObjectHeader(VirtualAddress);
        if (!IsProcessObjectTerminated(ObjectHeaderPtr))
        {
            ProcessBody = (struct _KPROCESS *)ObjectHeaderPtr;
            TypeInfo = (struct _KPROCESS *)ObjectHeaderPtr;
            return EnumerateProcessObjects(ProcessBody, TypeInfo, OutputBuffer, BufferSize, 0, 0, 0);
        }
    }
    return 0;
}

// FillProcessInformationEntry — 填充进程信息条目
// 对应原始驱动 sub_14005017C
char FillProcessInformationEntry(
    char *VirtualAddress, char *AlternateAddr, __int64 OutputBuffer,
    unsigned int BufferSize, char ValidateFlag, char EntryType, char CheckFlag)
{
    char *TargetAddr = AlternateAddr ? AlternateAddr : VirtualAddress;
    int CreateTimeOffset, Field51, Field52, Field41, Field53, Field54, Field55, FlagsOffset;
    _QWORD *ObjectTypeTable;
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
    ObjectTypeTable = (_QWORD *)GtRead(16748);
    if (!ObjectTypeTable) return 0;

    MaxIndex = (int)GtRead(GtObjectTypeCount) - 1;
    if (MmIsAddressValid(VirtualAddress) != 1 || MmIsAddressValid(&VirtualAddress[MaxIndex]) != 1) return 0;

    EntryIndex = *(unsigned int *)(OutputBuffer + 16);
    if (56 * EntryIndex + 80 >= BufferSize) return 0;
    if (IsProcessThreadInList(OutputBuffer, (__int64)VirtualAddress, (__int64)TargetAddr, CheckFlag) != 1) return 0;
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
            if ((_QWORD)*(__int64 *)(Offset + OutputBuffer + 64) < *ObjectTypeTable)
            {
                __int64 AltOffsetValue = *(__int64 *)&VirtualAddress[Field41];
                if (AltOffsetValue)
                {
                    if ((BuildNumber < 0xA28)
                        ? VirtualAddress[FlagsOffset] == 0
                        : (VirtualAddress[FlagsOffset] & 1) == 0)
                        *(__int64 *)(Offset + OutputBuffer + 64) = AltOffsetValue;
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
    __int64 ObjectType;
    ULONG64 ObjectHeader;
    _QWORD *ObjectBody;
    bool TypeIndex;
    char TypeOffset;
    ULONG TypeInfo, TypeName, TypeCount, TypeFlags, TypeField2, TypeField3, TypeField6, TypeField8, EprocessField30, TypeFlagCheck, BuildNumber;
    ULONG64 TypeList, TypeEntry, TypeField4, ListFlink, ListFlink2;
    __int64 TypeField, TypeField5, TypeField9, ProcessFlagsValue;
    _QWORD *ListBlink, *ListBlink2, *ObjectTypeTable;
    UCHAR Index16960 = (UCHAR)GtRead(16960);
    ULONG Index16774 = (ULONG)GtRead(16774);
    __int64 Index16748 = GtRead(16748);

    if (ObjectAddr <= (ULONG64)MmSystemRangeStart) return Result;

    ObjectType = (int)GtRead(GtObjectTypeCount) - 1;
    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (MmIsAddressValid((PVOID)(ObjectAddr - 48)) != 1 ||
        MmIsAddressValid((PVOID)(ObjectType + ObjectAddr)) != 1 ||
        ObjectAddr <= (ULONG64)MmSystemRangeStart)
        return Result;

    ObjectHeader = ObjectType + TargetAddr;

    if (BuildNumber >= 0x1DB0)
    {
        TypeOffset = CheckObjectTypeFlagWrapper((__int64)(ObjectAddr - 48));
        TypeIndex = (Index16960 == (UCHAR)TypeOffset);
    }
    else
    {
        ObjectBody = (_QWORD *)Index16748;
        if (!ObjectBody) return Result;
        TypeIndex = (*(_QWORD *)(ObjectAddr - 32) == *ObjectBody);
    }

    if (!TypeIndex) return Result;

    TypeInfo = (ULONG)GtRead(0x42C);
    TypeName = Index16774;
    TypeCount = Index16774;
    TypeList = *(_QWORD *)(TypeInfo + ObjectAddr);
    TypeEntry = *(_QWORD *)(TypeName + ObjectAddr);
    if (TypeList <= TypeEntry || TypeList <= (ULONG64)MmSystemRangeStart ||
        TypeEntry <= (ULONG64)MmSystemRangeStart ||
        *(_QWORD *)(TypeCount + ObjectAddr) <= (ULONG64)MmSystemRangeStart)
        return Result;

    TypeFlags = (ULONG)GtRead(GtProcessEprocess);
    TypeField = (ULONG)GtRead(GtEprocessField51);
    ProcessFlagsValue = *(_QWORD *)(TypeFlags + ObjectAddr);
    if (*(_QWORD *)(TypeField + ObjectAddr) < (ULONG64)MmSystemRangeStart) return Result;
    TypeField2 = (ULONG)GtRead(GtProcessOffset);
    TypeField3 = (ULONG)GtRead(GtEprocessField53);
    TypeField4 = *(_QWORD *)(TypeField2 + ObjectAddr);
    if ((TypeField4 & 7) != 0 || TypeField4 <= (ULONG64)MmSystemRangeStart ||
        MmIsAddressValid(*(PVOID *)(TypeField2 + ObjectAddr)) != 1 ||
        *(UCHAR *)(TypeField3 + ObjectAddr) > 5)
        return Result;

    TypeField5 = (ULONG)GtRead(GtEprocessField48);
    TypeField6 = (ULONG)GtRead(GtEprocessField47);
    TypeField8 = TypeField6;
    TypeField9 = TypeField5 + TargetAddr;

    // Extensive pointer validation chain
    PVOID ptr = *(PVOID *)(TypeField5 + ObjectAddr);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(TypeField5 + ObjectAddr) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(TypeField5 + ObjectAddr + 8);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(TypeField5 + ObjectAddr + 8) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(TypeField8 + ObjectAddr);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(TypeField8 + ObjectAddr) + 15)) != 1)
        return Result;

    ptr = *(PVOID *)(TypeField8 + ObjectAddr + 8);
    if (ptr <= (PVOID)MmSystemRangeStart || MmIsAddressValid(ptr) != 1 ||
        MmIsAddressValid((PVOID)(*(_QWORD *)(TypeField8 + ObjectAddr + 8) + 15)) != 1)
        return Result;

    // Verify linked list consistency
    ListFlink = *(_QWORD *)(TypeField5 + ObjectAddr);
    if (*(_QWORD *)(ListFlink + 8) != TypeField9) return Result;
    ListBlink = *(_QWORD **)(TypeField5 + ObjectAddr + 8);
    if (*ListBlink != TypeField9) return Result;
    ListFlink2 = *(_QWORD *)(TypeField8 + ObjectAddr);
    if (*(_QWORD *)(ListFlink2 + 8) != TypeField8 + TargetAddr) return Result;
    ListBlink2 = *(_QWORD **)(TypeField8 + ObjectAddr + 8);
    if (*ListBlink2 != TypeField8 + TargetAddr) return Result;

    if (ListFlink < TargetAddr || ListFlink > ObjectHeader ||
        (ULONG64)ListBlink < TargetAddr || (ULONG64)ListBlink > ObjectHeader ||
        ListFlink2 < TargetAddr || ListFlink2 > ObjectHeader ||
        (ULONG64)ListBlink2 < TargetAddr || (ULONG64)ListBlink2 > ObjectHeader)
        return Result;

    EprocessField30 = (ULONG)GtRead(GtEprocessField30);
    if (MmIsAddressValid((PVOID)(TypeField4 + EprocessField30)) != 1) return Result;

    if (BuildNumber >= 0x1DB0)
    {
        if (MmIsAddressValid((PVOID)(TypeField4 - 24)) != 1) return Result;
        TypeFlagCheck = (UCHAR)CheckObjectTypeFlagWrapper(TypeField4 - 48);
        TypeIndex = ((ULONG)Index16960 == TypeFlagCheck);
    }
    else
    {
        ObjectTypeTable = (_QWORD *)Index16748;
        if (!ObjectTypeTable || MmIsAddressValid((PVOID)(TypeField4 - 32)) != 1) return Result;
        TypeIndex = (*(_QWORD *)(TypeField4 - 32) == *ObjectTypeTable);
    }

    if (TypeIndex)
    {
        if (OutContext) *OutContext = ProcessFlagsValue;
        if (OutProcess) *OutProcess = TypeField4;
        return 1;
    }

    return Result;
}

// EnumProcessInformationWorker — 进程信息枚举工作函数
// 对应原始驱动 sub_14004F4C0
// 通过进程ID查找EPROCESS，验证后枚举句柄表和进程信息
bool EnumProcessInformationWorker(char *InputBuffer, __int64 OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    NTSTATUS LookupStatus;
    PEPROCESS Process;
    UCHAR ProcessRefed;

    if (BufferSize <= 0x50) return Result;

    *(__int64 *)OutputBuffer = *((__int64 *)InputBuffer + 1);
    *(__int64 *)(OutputBuffer + 8) = *((__int64 *)InputBuffer + 2);
    *(ULONG *)(OutputBuffer + 16) = 0;

    char InfoFlag = *InputBuffer;
    LookupStatus = PsLookupProcessByProcessId(*((HANDLE *)InputBuffer + 1), &Process);
    int LookupStatusCopy = LookupStatus;
    if (!*((__int64 *)InputBuffer + 2) && LookupStatus >= 0)
        *((__int64 *)InputBuffer + 2) = (__int64)Process;

    if (ValidateProcessObject(*((struct _KPROCESS **)InputBuffer + 2), NULL) == 1)
    {
        ProcessRefed = ReferenceObjectSafe(*((__int64 *)InputBuffer + 2));
        DispatchProcessHandleTableEnum(OutputBuffer, BufferSize,
            (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateAndEnumerateObject, (__int64)InputBuffer);
        EnumerateProcessHandleTableData(*((struct _KPROCESS **)InputBuffer + 2), OutputBuffer, BufferSize);
        if (InfoFlag)
            EnumerateProcessInformation(*((__int64 *)InputBuffer + 2), OutputBuffer, BufferSize);
        if (ProcessRefed == 1)
            DereferenceObjectSafe(*((__int64 *)InputBuffer + 2));
    }

    if (LookupStatusCopy >= 0)
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
    ULONG EprocessField64;
    char SectionObjectNameFromHandle;
    bool NeedsFallback;
    void *FallbackPath[6];

    SectionFieldOffset = (ULONG)GtRead(GtEprocessField31);
    if (SectionFieldOffset == (ULONG)-1) goto Fallback;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!PROCESS) PROCESS = (PRKPROCESS)Process;

    EprocessField64 = (ULONG)GtRead(GtEprocessField64) - 1;
    if (PROCESS && MmIsAddressValid(PROCESS) == 1 && MmIsAddressValid((char *)PROCESS + EprocessField64) == 1)
    {
        if ((ULONG)GtRead(GtEprocessField28) == 1)
            SectionObjectNameFromHandle = GetSectionObjectNameFromHandle(PROCESS, *(HANDLE *)((char *)PROCESS + SectionFieldOffset), (_QWORD *)OutBuffer, OutSize);
        else
        {
            ULONG64 SectionObjectAddr = *(ULONG64 *)((char *)PROCESS + SectionFieldOffset);
            if (!SectionObjectAddr) goto Cleanup;
            SectionObjectNameFromHandle = QueryObjectNameByAddress(SectionObjectAddr, (_QWORD *)OutBuffer, OutSize);
        }
        Result = SectionObjectNameFromHandle;
    }

Cleanup:
    if (Status >= 0 && Process) ObfDereferenceObject(Process);

Fallback:
    if (!(UCHAR)Flags)
    {
        NeedsFallback = Result == 0;
        if (Result == 1)
        {
            if (OutSize)
            {
                if (*OutSize <= 6) NeedsFallback = 1;
            }
            else if (GetStringLength(*OutBuffer) <= 3) NeedsFallback = 1;
            if (!WStringFindChar((WORD *)*OutBuffer, L'.')) NeedsFallback = 1;
        }
        if (NeedsFallback && GetProcessImagePathByAttach(PROCESS, ProcessId, FallbackPath, &Flags) == 1)
        {
            ParseFilePathForSystemRoot((WORD **)FallbackPath, &Flags);
            if (Result == 1 && *OutBuffer) ExFree(*OutBuffer);
            *OutBuffer = FallbackPath[0];
            if (OutSize) *OutSize = (ULONG)Flags;
            Result = 1;
        }
    }

    if (!Result)
        return QueryDevicePathFromSymbolicLink((__int64)ProcessId, OutBuffer, OutSize);
    return Result;
}

// IsProcessObjectTerminated — 检查进程对象是否已终止
// 对应原始驱动 0x14004A674（142 字节）
// 【⚠ GT 索引修正 2026-10-13】第一处原写十进制字面量 16733
//   （= 0x415D），原始实为 **0x4271**（函数指针槽）。
//   依据：原始汇编 `mov ecx,0x4271; call GtRead; test rax,rax;
//   je ...; call rax`（即取出指针后直接调用，见 0x14004A68B–A69C）。
//   其余两处索引经核对**本就正确**：第二处 GtEprocessField64=74=0x4A、
//   第三处 GtEprocessField44=54=0x36（原始 `lea ecx,[rbp+0x35]`，rbp=1）。
bool IsProcessObjectTerminated(char *VirtualAddress)
{
    char Result = 0;
    __int64 (*GetCurrentProcess)(void);
    int PathStr;

    GetCurrentProcess = (__int64 (*)(void))GtRead((GLOBAL_TABLE_INDEX)0x4271);  // 原写 16733(0x415D)，应为 0x4271
    if (GetCurrentProcess && VirtualAddress == (char *)GetCurrentProcess())
        return Result;

    PathStr = (int)GtRead(GtEprocessField64) - 1;
    if (MmIsAddressValid(VirtualAddress) == 1 &&
        MmIsAddressValid(&VirtualAddress[PathStr]) == 1)
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

    if (!ProcessObject)
        return 0;

    EprocessBase = (ULONG64)ProcessObject;
    if (EprocessBase < (ULONG64)MmSystemRangeStart)
        return 0;

    // 检查进程的 Section 对象偏移
    SectionOffset = GtRead(GtProcessSectionOffset);
    if (SectionOffset)
    {
        ProcessSection = *(ULONG64 *)(EprocessBase + SectionOffset);
        if (ProcessSection && ProcessSection < (ULONG64)MmSystemRangeStart)
            return 0;
    }

    return 1;
}

// BuildExportServiceTable — 构建导出服务表
// 对应原始驱动 0x1400063E0（526 字节）
// 【⚠ 地址修正 2026-10-13】原注释写 `sub_1400063D0`，但 0x1400063D0 实为
//   **另一函数 ParseNtImageSectionHeaders (0x1400061B8) 的内部地址**。
//   真实入口是 0x1400063E0（名 BuildExportServiceTable，526 字节），差 0x10 字节，系转写笔误。
//   发现方式：逐函数差分报本函数为 gt_read_diff（GT 0x314），核对时发现
//   原始并无以 0x1400063D0 为入口的函数。
//   另：本函数 GT 索引与原始**完全一致**（0x314/0x312/0x313 即
//   GtWin32kServiceCount / GtWin32kServiceTableSize32 / Size64 = 788/786/787），无需修改。
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
    unsigned int UserDllSize;
    int ServiceIndexEnd;
    char *UserDllBuffer;
    __int64 RelocTableAddr;
    __int64 ImageBaseAddr;
    __int64 RelocDataOut[9];

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
    ModuleBase = ParseNtRelocationTableEx(TargetProcess, Is64Bit, (_QWORD *)&ImageBaseAddr, (_QWORD *)RelocDataOut, (void **)&RelocTableAddr);
    if (ModuleBase)
    {
        if (ServiceCount && ModuleEntrySize && RelocBuffer)
        {
            ImageBasePtr = ImageBaseAddr;
            if (ImageBaseAddr)
            {
                if (ReadUser32DllFile((_QWORD *)&UserDllBuffer, &UserDllSize, Is64Bit))
                {
                    IsWin32kCopy = IsWin32k;
                    ModuleBase = ModuleBase;
                    if (ParseNtExportDir((PUCHAR)UserDllBuffer, UserDllSize, ModuleBase, IsWin32kCopy) == 1)
                    {
                        ExportEntry = (unsigned int *)RelocBuffer + 1;
                        ServiceCount2 = ServiceCount;
                        do
                        {
                            *(ExportEntry - 1) = 0;
                            if (*ExportEntry < UserDllSize && *ExportEntry + 16 <= UserDllSize)
                            {
                                *(ExportEntry - 1) = 1;
                                *(_OWORD *)(ExportEntry + 3) = *(_OWORD *)&UserDllBuffer[*ExportEntry];
                            }
                            ExportEntry += 12;
                            --ServiceCount2;
                        }
                        while (ServiceCount2);
                    }
                    ExFree(UserDllBuffer);
                }
                else
                {
                    ModuleBase = ModuleBase;
                }
                FuncTableAddr = ModuleBase + ModuleEntrySize;
                OutServiceTable[1] = ImageBasePtr;
                OutServiceTable[3] = RelocDataOut[0];
                OutServiceTable[2] = FuncTableAddr;
                ServiceIndex = 0;
                ServiceIndexEnd = 0;
                while (ServiceIndex < ServiceCount)
                {
                    OutServiceTable[9 * ServiceIndex + 8] = ServiceIndex;
                    if (Is64Bit)
                    {
                        FuncValue = *(unsigned int *)(RelocTableAddr + 4LL * ServiceIndex);
                        FuncAddrPtr = FuncTableAddr + 4LL * ServiceIndex;
                    }
                    else
                    {
                        FuncValue = *(_QWORD *)(RelocTableAddr + 8LL * ServiceIndex);
                        FuncAddrPtr = FuncTableAddr + 8LL * ServiceIndex;
                    }
                    OutServiceTable[9 * ServiceIndex + 10] = FuncValue;
                    OutServiceTable[9 * ServiceIndex + 7] = FuncAddrPtr;
                    OutServiceTable[9 * ServiceIndex + 5] = (_QWORD)TargetProcess;
                    OutServiceTable[9 * ServiceIndex + 6] = ImageBase;
                    OutServiceTable[9 * ServiceIndex + 9] = ModuleBase + HIDWORD(RelocBuffer[6 * ServiceIndex]);
                    ServiceIndexEnd = ++ServiceIndex;
                }
                Success = 1;
            }
        }
        ExFree((void *)RelocTableAddr);
    }
    return Success;
}

// CopyValidServiceEntries — 复制有效服务条目
// 对应原始驱动 sub_140006800（170 字节）
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
    _OWORD SectionDataCopy;

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
                        memset(&SectionDataCopy, 0, sizeof(SectionDataCopy));
                        SectionDataCopy = *(_OWORD *)SectionHeader3.qword[0];
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
// 对应原始驱动 sub_1400065F0（241 字节）
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

    if (ReadUser32DllFile((_QWORD *)&FileBuffer, &FileSize, IsWow64Process))
    {
        strcpy(ExportName, "UserClientDllInitialize");
        ExportByNameInPeBody = (unsigned int)FindExportByNameInPeBody(
            (PUCHAR)FileBuffer,
            FileSize,
            (PCHAR)ExportName,
            IsWow64Process != 0);
        if (ExportByNameInPeBody)
        {
            ServiceTableSize = (unsigned int)(IsWow64Process
                ? ResolveWin32kServiceTableEx((__int64)FileBuffer, FileSize)
                : ResolveWin32kServiceTableDispatch((__int64)FileBuffer, FileSize, ExportByNameInPeBody));
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
// 对应原始驱动 sub_140007188（262 字节）
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
// 对应原始驱动 sub_14004A3D4（538 字节）
// 附加到目标进程后获取其镜像路径
char GetProcessImagePathByAttach(PRKPROCESS PROCESS, HANDLE ProcessId, void **pImagePathBuffer, _DWORD *pImagePathSize)
{
    unsigned int TargetProcess;
    NTSTATUS LookupStatus;
    unsigned __int64 ImagePath;
    unsigned __int64 PathLen;
    unsigned __int64 Status;
    __int64 Result;
    unsigned __int64 PathDataPtr;
    PVOID PathBuffer;
    unsigned __int8 ProcessRefed;
    PEPROCESS Process;
    _DWORD *pPathSizeCopy;
    void **pPathBufCopy;
    KAPC_STATE ApcState;

    pPathSizeCopy = pImagePathSize;
    pPathBufCopy = pImagePathBuffer;
    Result = 0;
    *pImagePathBuffer = 0;
    TargetProcess = (unsigned int)GtRead(GtEprocessField33);
    if (TargetProcess != -1)
    {
        LookupStatus = PsLookupProcessByProcessId(ProcessId, &Process);
        if (!LookupStatus && !PROCESS)
            PROCESS = (PRKPROCESS)Process;
        if (PROCESS && ValidateProcessObject(PROCESS, 0) == 1)
        {
            ProcessRefed = ReferenceObjectSafe((__int64)PROCESS);
            KeStackAttachProcess(PROCESS, &ApcState);
            if (MmIsAddressValid((char *)PROCESS + TargetProcess) == 1)
            {
                ImagePath = *(_QWORD *)((char *)PROCESS + TargetProcess);
                if (ImagePath < (unsigned __int64)MmSystemRangeStart && ImagePath + 96 < (unsigned __int64)MmSystemRangeStart)
                {
                    PathLen = *(_QWORD *)(ImagePath + 24);
                    if (PathLen < (unsigned __int64)MmSystemRangeStart && PathLen + 72 < (unsigned __int64)MmSystemRangeStart)
                    {
                        Status = *(_QWORD *)(PathLen + 16);
                        if (Status < (unsigned __int64)MmSystemRangeStart && Status + 136 < (unsigned __int64)MmSystemRangeStart)
                        {
                            Result = *(unsigned __int16 *)(Status + 72);
                            if ((unsigned int)Result > 0x1000)
                                Result = 4096;
                            if ((unsigned int)Result > 2)
                            {
                                PathDataPtr = *(_QWORD *)(Status + 80);
                                if (PathDataPtr < (unsigned __int64)MmSystemRangeStart)
                                {
                                    if (PathDataPtr)
                                    {
                                        if ((unsigned int)Result + PathDataPtr < (unsigned __int64)MmSystemRangeStart)
                                        {
                                            PathBuffer = ExAlloc(PagedPool, (ULONG)(Result + 2));
                                            *pImagePathBuffer = PathBuffer;
                                            if (PathBuffer)
                                            {
                                                if (pPathSizeCopy)
                                                    *pPathSizeCopy = (unsigned int)Result;
                                                memmove(*pImagePathBuffer, *(const void **)(Status + 80), (unsigned int)Result);
                                                *((_WORD *)*pImagePathBuffer + ((unsigned __int64)(unsigned int)Result >> 1)) = 0;
                                                Result = 1;
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
            if (ProcessRefed == 1)
                DereferenceObjectSafe((__int64)PROCESS);
        }
        if (!LookupStatus)
            ObfDereferenceObject(Process);
    }
    return (char)Result;
}

// ParseFilePathForSystemRoot — 解析文件路径中的系统根目录
// 对应原始驱动 sub_14004B990（366 字节）
// 将 \SystemRoot\ 等系统路径前缀替换为实际系统根目录路径，\??\ 前缀则跳过前 4 字符
char ParseFilePathForSystemRoot(__int16 **pPathString, _DWORD *pPathLength)
{
    char IsParsed;
    __int16 *PathStr;
    int Result;
    __int16 *PathLen;
    __int16 *inited;
    __int16 *PathChar;
    __int64 StringLength;
    unsigned int ColonPos;
    unsigned int BackslashPos;
    SIZE_T SystemRoot;
    __int16 *NewBuffer;
    __int16 *NewBufferCopy;
    _DWORD DosPrefix[2];
    _DWORD SystemRootPrefix[5];
    __int64 SystemRootSuffix;

    IsParsed = 0;
    PathStr = *pPathString;
    if (*PathStr == 92)  // L'\\'
    {
        // "\\??\\" 前缀检查
        DosPrefix[0] = 4128860;  // L"\\??"
        DosPrefix[1] = 6029375;  // L"\\\0\0"
        Result = (int)WStringCompare((__int64)PathStr, (unsigned __int16 *)DosPrefix, 4u);
        PathLen = *pPathString;
        if (Result)
        {
            // "\\SystemRoot\\" 前缀检查 (12 个字符)
            SystemRootPrefix[0] = 5439580;   // L"\\Sys"
            SystemRootPrefix[1] = 7536761;   // L"temR"
            SystemRootPrefix[2] = 6619252;   // L"oot\\"
            SystemRootPrefix[3] = 5374061;   // L"syst"
            SystemRootPrefix[4] = 7274607;   // L"em32"
            SystemRootSuffix = 6029428;      // L"\\\0\0\0"
            if (!(unsigned int)StringCompare3Way((__int64)PathLen, (unsigned __int16 *)SystemRootPrefix, 0xCu))
            {
                inited = InitSystemPath();
                PathChar = inited;
                if (inited)
                {
                    StringLength = GetStringLength(inited);
                    ColonPos = (unsigned int)GetStringLength(*pPathString);
                    BackslashPos = ColonPos + (unsigned int)StringLength;
                    if (ColonPos + (unsigned int)StringLength > (unsigned int)StringLength && BackslashPos > ColonPos)
                    {
                        SystemRoot = 2 * BackslashPos;
                        if ((unsigned int)SystemRoot > BackslashPos)
                        {
                            NewBuffer = (__int16 *)ExAlloc(PagedPool, (ULONG)SystemRoot);
                            NewBufferCopy = NewBuffer;
                            if (NewBuffer)
                            {
                                WStringCopy(NewBuffer, PathChar);
                                WStringCopy(&NewBufferCopy[StringLength], *pPathString + 11);
                                ExFree(*pPathString);
                                *pPathString = NewBufferCopy;
                                if (pPathLength)
                                    *pPathLength = (_DWORD)(2 * GetStringLength(NewBufferCopy));
                                IsParsed = 1;
                            }
                        }
                    }
                    ExFree(PathChar);
                }
            }
        }
        else
        {
            // 跳过 "\\??\\" 前缀 (4 个字符)
            WStringCopy(PathLen, PathLen + 4);
            if (pPathLength)
                *pPathLength = (_DWORD)(2 * GetStringLength(*pPathString));
            return 1;
        }
    }
    return IsParsed;
}

// QueryObjectNameByAddress — 按地址查询对象名称
// 对应原始驱动 sub_1400794A0
// 根据Windows版本选择新版或旧版名称查询方式
char QueryObjectNameByAddress(unsigned __int64 ObjectAddress, _QWORD *pNameBuffer, _DWORD *pNameLength)
{
    char Result;
    _QWORD *NamePointer;
    _QWORD *NamePointerCheck;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x2800)
        return QueryObjectNameLegacy((_QWORD *)ObjectAddress, pNameBuffer, pNameLength);

    Result = 0;
    if (ObjectAddress > (unsigned __int64)MmSystemRangeStart && (ObjectAddress & 7) == 0)
    {
        NamePointer = (_QWORD *)ResolveObjectNamePointer(ObjectAddress);
        NamePointerCheck = NamePointer;
        if (NamePointer)
        {
            if ((unsigned __int64)NamePointer > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid(NamePointer) == 1 && MmIsAddressValid((char *)NamePointerCheck + 127) == 1)
                return QueryObjectNameString(NamePointerCheck[8], pNameBuffer, pNameLength);
        }
    }
    return Result;
}

// GetSectionObjectNameFromHandle — 从句柄获取节区对象名称
// 对应原始驱动 sub_1400793E0（192 字节）
// 附加到进程并通过句柄查询Section对象名称
char GetSectionObjectNameFromHandle(PRKPROCESS PROCESS, HANDLE Handle, _QWORD *pNameBuffer, _DWORD *pNameLength)
{
    char ObjectNameByAddress;
    unsigned __int8 ProcessRefed;
    NTSTATUS LookupStatus;
    PVOID Object;
    KAPC_STATE ApcState;

    ObjectNameByAddress = 0;
    ProcessRefed = ReferenceObjectSafe((__int64)PROCESS);
    KeStackAttachProcess(PROCESS, &ApcState);
    LookupStatus = ObReferenceObjectByHandle(Handle, 0x80000000, MmSectionObjectType, 0, &Object, 0);
    KeUnstackDetachProcess(&ApcState);
    if (ProcessRefed == 1)
        DereferenceObjectSafe((__int64)PROCESS);
    if (!LookupStatus)
    {
        ObjectNameByAddress = QueryObjectNameByAddress((unsigned __int64)Object, pNameBuffer, pNameLength);
        ObfDereferenceObject(Object);
    }
    return ObjectNameByAddress;
}

// QueryDevicePathFromSymbolicLink — 从符号链接查询设备路径
// 对应原始驱动 sub_140079958（554 字节）
// 通过符号链接查询设备路径
char QueryDevicePathFromSymbolicLink(__int64 SymLink, void **pPathBuffer, _DWORD *pPathLength)
{
    char Success;
    int (__fastcall *QuerySymLinkFunc)(__int64 *, __int64, int *, _QWORD *);
    __int64 (__fastcall *UnicodeStr)(__int64, __int64, void **, __int64, unsigned int *);
    void (__fastcall *ObjAttr)(__int64);
    unsigned int SymLinkHandle;
    unsigned int DevicePath;
    struct _KTHREAD *CurrentThread;
    __int64 PathBuffer;
    char Status;
    int QueryStatus;
    unsigned int BufferSize;
    char BufferSize2;
    int BuildNumber;
    void *PathBufferOut;
    unsigned int PathLen2;
    _WORD *PathBuffer2;
    unsigned int NameLen;
    void *Dst;
    __int64 SymLinkHandleOut;
    _QWORD ObjectAttributes[2];
    int AttrLength;
    __int64 AttrOffset;
    __int64 AttrFlags;
    int AttrSize;
    _OWORD AttrBuffer;
    __int16 DevicePathFirst;

    Success = 0;
    QuerySymLinkFunc = (int (__fastcall *)(__int64 *, __int64, int *, _QWORD *))GtRead(GtUninstallHookSyscallPeOffset|GtPathBuffer02|0x100);
    UnicodeStr = (__int64 (__fastcall *)(__int64, __int64, void **, __int64, unsigned int *))GtRead(GtTotalSize|GtObjectTypeField34|GtDriverObject);
    ObjAttr = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    SymLinkHandle = (unsigned int)GtRead(GtSdstServiceCount);
    DevicePath = SymLinkHandle;
    if (QuerySymLinkFunc && UnicodeStr && ObjAttr && SymLinkHandle != -1)
    {
        AttrLength = 48;
        memset(&AttrBuffer, 0, sizeof(AttrBuffer));
        AttrOffset = 0;
        AttrSize = 512;
        AttrFlags = 0;
        ObjectAttributes[0] = SymLink;
        ObjectAttributes[1] = 0;
        if (QuerySymLinkFunc(&SymLinkHandleOut, 1024, &AttrLength, ObjectAttributes) >= 0)
        {
            NameLen = 0;
            CurrentThread = KeGetCurrentThread();
            PathBuffer = DevicePath;
            Status = *((_BYTE *)CurrentThread + DevicePath);
            *((_BYTE *)CurrentThread + PathBuffer) = 0;
            QueryStatus = (int)UnicodeStr(SymLinkHandleOut, 27, &Dst, 8, &NameLen);
            *((_BYTE *)CurrentThread + PathBuffer) = Status;
            if (QueryStatus != -1073741820)
                goto LABEL_19;
            BufferSize = NameLen;
            if (!NameLen)
                goto LABEL_19;
            NameLen += 20;
            Dst = ExAlloc(PagedPool, BufferSize + 20);
            if (!Dst)
                goto LABEL_19;
            BufferSize2 = *((_BYTE *)CurrentThread + PathBuffer);
            *((_BYTE *)CurrentThread + PathBuffer) = 0;
            BuildNumber = (int)UnicodeStr(SymLinkHandleOut, 27, (void **)Dst, NameLen - 4, &NameLen);
            *((_BYTE *)CurrentThread + PathBuffer) = BufferSize2;
            if (BuildNumber >= 0)
            {
                PathBufferOut = Dst;
                if ((char *)Dst + 16 != *((void **)Dst + 1))
                    goto LABEL_18;
                if ((*(_WORD *)Dst & 0xFFFE) == 0)
                    goto LABEL_18;
                PathLen2 = *(_WORD *)Dst & 0xFFFE;
                NameLen = PathLen2;
                memmove(Dst, *((const void **)Dst + 1), PathLen2);
                *((_WORD *)Dst + ((unsigned __int64)NameLen >> 1)) = 0;
                if (BuildDevicePathFromObjects((unsigned __int16 *)Dst, (WORD *)&DevicePathFirst, (int *)&NameLen) == 1 && NameLen > 2)
                {
                    *(_WORD *)Dst = DevicePathFirst;
                    *((_WORD *)Dst + 1) = 58;  // L':'
                    WStringCopy((__int16 *)Dst + 2, (__int16 *)Dst + NameLen);
                    PathBuffer2 = Dst;
                    *pPathBuffer = Dst;
                    if (pPathLength)
                        *pPathLength = (_DWORD)(2 * GetStringLength(PathBuffer2));
                    Success = 1;
                    goto LABEL_19;
                }
            }
            PathBufferOut = Dst;
LABEL_18:
            ExFree(PathBufferOut);
LABEL_19:
            ObjAttr(SymLinkHandleOut);
        }
    }
    return Success;
}

// IsProcessThreadInList — 检查进程或线程是否已在输出列表中
// 对应原始驱动 sub_14004F284（186 字节）
// 遍历已填充的条目，按对象地址比较，防止重复枚举
char IsProcessThreadInList(__int64 Process, __int64 Thread, __int64 ListHead, char CheckFlag)
{
    char IsInList;
    unsigned int EntryOffset;
    unsigned int Result;
    unsigned int EntryCount;
    int LoopIndex;
    __int64 *i;
    __int64 CurrentEntry;

    IsInList = 1;
    EntryOffset = (unsigned int)GtRead(GtKiFastCallEntryAddr|GtNtoskrnlImageSize);
    Result = (unsigned int)GtRead(GtEprocessField182|GtEprocessField06|0x100);
    EntryCount = *(_DWORD *)(Process + 16);
    LoopIndex = 0;
    if (EntryCount)
    {
        for (i = (__int64 *)(Process + 32); ; i += 7)
        {
            CurrentEntry = *i;
            if (IsInList == *i
                || CheckFlag == 1
                && EntryOffset
                && Result != -1
                && *(_QWORD *)(EntryOffset + Thread) == *(_QWORD *)(CurrentEntry + EntryOffset)
                && *(_QWORD *)(Result + Thread) == *(_QWORD *)(CurrentEntry + Result))
            {
                break;
            }
            if ((unsigned int)(++LoopIndex) >= EntryCount)
                return IsInList;
        }
        return 0;
    }
    return IsInList;
}

// EnumerateProcessInformation — 枚举进程信息
// 对应原始驱动 sub_14004FAC4
// 分配缓冲区，读取 GT 索引获取函数指针，遍历内核地址空间填充进程条目
char EnumerateProcessInformation(__int64 Process, __int64 InfoBuffer, unsigned int BufferSize)
{
    char Result;                       // var_CF：是否找到并填充条目
    char SecondPageFlag;               // var_D0 / bl
    unsigned char SavedPrevMode;       // bl：KTHREAD 原 PreviousMode
    void *Buffer;                      // r13：0x3000 缓冲区
    ULONG64 ServiceTableFunc;          // r12：0x41DE 查询函数
    ULONG64 ServiceTableSize;          // var_B8：0x41E4 取值函数
    ULONG64 KernelBase;                // var_A8：0x41E1
    ULONG64 EntryStrideVal;            // rdi：0x27 偏移 / 步进
    ULONG64 ProcessEntry;              // r14：0x41DB 检查函数
    ULONG64 BuildNumber;               // rbx：GT 3
    ULONG64 ProcessIndex;              // rsi：GT 2
    ULONG64 EntryCount;                // r15：0x4B
    ULONG64 MaxCount;                  // var_88：0x4169
    __int64 Dst[8];                    // Dst
    __int64 ScanStart;                 // Src：当前扫描地址
    __int64 ScanEnd;                   // var_90：扫描结束地址
    __int64 *pStepCount;               // var_A0：步进乘积
    int RemCounter2;                   // var_B0：0xFD0 - EntryCount
    int EntryStride;                   // var_AC：(EntryCount+0x30)&~7
    int CurSize;                       // var_C0
    int CopySize;                      // ebx：复制大小
    int InnerIndex;                    // esi：内层循环索引
    int InnerLimit;                    // edi：内层循环上限
    __int64 Offset;                    // rbx：取值函数返回的偏移
    __int64 ObjectContext;             // var_80：ValidateKernelObject 输出
    __int64 QueryCount;                // rdi：服务查询返回的条目数
    __int64 RangeValue;                // 步进范围
    int *pDstInt;                      // 访问 Dst 的 int 字段
    char *pCurrentThread;              // 当前线程指针
    __int64 (*pGetOffsetFunc)(__int64);        // ServiceTableSize 函数指针
    __int64 (*pQueryFunc)(__int64, __int64, __int64, __int64); // ServiceTableFunc 函数指针
    __int64 (*pCheckFunc)(__int64);            // ProcessEntry 函数指针

    Result = 0;
    Buffer = ExAlloc((POOL_TYPE)1, 0x3000);
    if (!Buffer)
        return 0;

    memset(Buffer, 0, 0x3000);

    // 读取所需 GT 索引
    ServiceTableFunc = GtRead((GLOBAL_TABLE_INDEX)0x41DE);
    ServiceTableSize = GtRead((GLOBAL_TABLE_INDEX)0x41E4);
    KernelBase = GtRead((GLOBAL_TABLE_INDEX)0x41E1);
    EntryStrideVal = GtRead((GLOBAL_TABLE_INDEX)0x27);
    ProcessEntry = GtRead((GLOBAL_TABLE_INDEX)0x41DB);
    BuildNumber = GtRead((GLOBAL_TABLE_INDEX)3);
    ProcessIndex = GtRead((GLOBAL_TABLE_INDEX)2);
    EntryCount = GtRead((GLOBAL_TABLE_INDEX)0x4B);
    MaxCount = GtRead((GLOBAL_TABLE_INDEX)0x4169);

    // 验证所有必要指针
    if (!BuildNumber || !ProcessIndex || !EntryCount || !MaxCount || !ProcessEntry
        || !ServiceTableFunc || !ServiceTableSize || !KernelBase || EntryStrideVal == -1)
    {
        ExFree(Buffer);
        return 0;
    }

    // 初始化结构
    memset(&Dst, 0, 0x40);

    // 设置当前线程 PreviousMode（偏移为 GT 0x27）
    pCurrentThread = (char *)KeGetCurrentThread();
    SavedPrevMode = *(unsigned __int8 *)(pCurrentThread + EntryStrideVal);
    *(unsigned __int8 *)(pCurrentThread + EntryStrideVal) = 0;

    // 调用查询函数，返回条目数
    pQueryFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64))ServiceTableFunc;
    QueryCount = pQueryFunc((__int64)&Dst, 0, 0x40, 0);
    *(unsigned __int8 *)(pCurrentThread + EntryStrideVal) = SavedPrevMode;

    // 计算步进范围：构建号 >= 0x4F7C 用 Dst[4]，否则取 Dst[2]/Dst[4] 较大者
    pDstInt = (int *)&Dst;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x4F7C)
        RangeValue = (int)pDstInt[4];
    else
    {
        int MaxVal = pDstInt[2];
        if (pDstInt[4] > MaxVal)
            MaxVal = pDstInt[4];
        RangeValue = MaxVal;
    }
    pStepCount = (__int64 *)(QueryCount * RangeValue);

    // 初始化剩余计数
    RemCounter2 = 0xFD0 - (int)EntryCount;

    // 获取内核地址扫描范围
    GetKernelVirtualAddressRange((__int64)&Dst, &ScanStart, (unsigned __int64 *)&ScanEnd);

    // 计算条目步进
    EntryStride = ((int)EntryCount + 0x30) & 0xFFFFFFF8;

    SecondPageFlag = 0;
    ScanStart = *(unsigned __int64 *)&ScanStart;

    // 主循环：遍历 [ScanStart, ScanEnd)，每次步进 0x1000
    for (; ScanStart < ScanEnd; ScanStart += 0x1000)
    {
        __int64 SecondPage;
        char NewSecondFlag;
        char FirstOk;

        // 第一页检查（SecondPageFlag 为 0 时才执行）
        if (SecondPageFlag == 0)
        {
            FirstOk = 0;
            pCheckFunc = (__int64 (__fastcall *)(__int64))ProcessEntry;
            pGetOffsetFunc = (__int64 (__fastcall *)(__int64))ServiceTableSize;
            if (pCheckFunc(ScanStart) == 1
                && CallRegisteredCallback(ScanStart) == 1)
            {
                Offset = pGetOffsetFunc(ScanStart);
                if (Offset != 0 && Offset < (__int64)pStepCount
                    && CmdStubAlwaysTrue(ProcessEntry, Offset, NULL, 0) == 1
                    && ValidateEnumerationResult(KernelBase, ScanStart, Offset) == 1)
                    FirstOk = 1;
            }
            if (!FirstOk)
                continue;  // 第一页不匹配，前进一步
        }

        // 第二页检查（ScanStart + 0x1000）
        SecondPage = ScanStart + 0x1000;
        NewSecondFlag = 0;
        CurSize = RemCounter2;
        CopySize = 0x1000;
        pCheckFunc = (__int64 (__fastcall *)(__int64))ProcessEntry;
        pGetOffsetFunc = (__int64 (__fastcall *)(__int64))ServiceTableSize;
        if (pCheckFunc(SecondPage) == 1
            && CallRegisteredCallback(SecondPage) == 1)
        {
            Offset = pGetOffsetFunc(SecondPage);
            if (Offset != 0 && Offset < (__int64)pStepCount
                && CmdStubAlwaysTrue(ProcessEntry, Offset, NULL, 0) == 1
                && ValidateEnumerationResult(KernelBase, SecondPage, Offset) == 1)
            {
                NewSecondFlag = 1;
                CurSize = RemCounter2 + 0x1000;
                CopySize = 0x2000;
            }
        }
        SecondPageFlag = NewSecondFlag;

        // 复制页到缓冲区（检查 ScanStart 与尾部地址）
        pCheckFunc = (__int64 (__fastcall *)(__int64))ProcessEntry;
        if (pCheckFunc(ScanStart) == 1
            && pCheckFunc(ScanStart - 1 + CopySize) == 1)
        {
            memmove(Buffer, (void *)ScanStart, (unsigned int)CopySize);
            InnerLimit = CurSize;
            InnerIndex = 0;

            // 内层循环：逐条目填充
            do
            {
                __int64 EntryPtr = (__int64)Buffer + InnerIndex;
                char Match = 0;

                // 对象类型过滤
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
                {
                    if (CheckObjectTypeFlag(EntryPtr) == (char)GtRead((GLOBAL_TABLE_INDEX)0x81C))
                        Match = 1;
                }
                else
                {
                    if (*(__int64 *)(EntryPtr + 16) == *(__int64 *)MaxCount)
                        Match = 1;
                }

                if (Match)
                {
                    __int64 AltAddr = ScanStart + 0x30 + InnerIndex;
                    __int64 EntryObj = EntryPtr + 0x30;
                    if (ValidateKernelObject(EntryObj, AltAddr, 0, &ObjectContext) == 1)
                    {
                        pCheckFunc = (__int64 (__fastcall *)(__int64))ProcessEntry;
                        if (pCheckFunc(AltAddr) == 1
                            && (Process == 0 || ObjectContext == Process))
                        {
                            FillProcessInformationEntry(
                                (char *)EntryObj, (char *)AltAddr, InfoBuffer, BufferSize, 1, 1, 0);
                            Result = 1;
                        }
                    }
                }

                InnerIndex += EntryStride;
                InnerIndex += 8;
            } while (InnerIndex <= InnerLimit);
        }
    }

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
        && (unsigned int)((int)ServiceTablePtr + EntrySize * (int)result) <= ImageSize)
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
        ModuleListOffset = (unsigned int)GtRead(GtEprocessModuleListOffset);
        ModuleEntrySize = 48;
        ServiceTableOffset = (unsigned int)GtRead(GtWin32kServiceTableSize64);
    }
    else
    {
        ModuleListOffset = (unsigned int)GtRead(GtEprocessField33);
        ModuleEntrySize = 96;
        ServiceTableOffset = (unsigned int)GtRead(GtWin32kServiceTableSize32);
    }
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceCount);
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
        Result = ReadNtFileToBuffer((unsigned char *)RawBuffer, (unsigned int)RawFileSize, (PUCHAR *)FileBuffer, (PULONG)FileSize) == 1;
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
        if ((unsigned int)((int)ServiceTableOffset + 4096) >= ImageSize)
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
    if ((unsigned int)((int)ServiceTableOffset + 4096) < ImageSize)
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
    if ((unsigned int)ServiceTableOffset < ImageSize && (unsigned int)((int)ServiceTableOffset + 4096) < ImageSize)
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
    if ((unsigned __int64)Object > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid(Object) == 1 && MmIsAddressValid((char *)Object + 47) == 1)
    {
        unsigned __int64 **NameInfoPtr;
        if (BuildNumber < 0x23F0 || BuildNumber >= 0x2580)
            NameInfoPtr = (unsigned __int64 **)Object[5];
        else
            NameInfoPtr = (unsigned __int64 **)Object[4];
        if ((unsigned __int64)NameInfoPtr > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid(NameInfoPtr) == 1 && MmIsAddressValid((char *)NameInfoPtr + 7) == 1)
        {
            unsigned __int64 *NameEntry = *NameInfoPtr;
            if ((unsigned __int64)NameEntry > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid(NameEntry) == 1 && MmIsAddressValid((char *)NameEntry + 127) == 1)
                return QueryObjectNameString(NameEntry[8], NameBuffer, NameLength);
        }
    }
    return Result;
}

// FindModuleInLoaderList — 在 PEB 加载器链表中查找模块
// 对应原始驱动 sub_140007290
// 遍历 PEB 加载器链表，查找名称为 "user32.dll" 的模块条目
// 返回模块基址，0 表示未找到
ULONG64 FindModuleInLoaderList(_QWORD **ModuleListHead, unsigned int EntryOffset)
{
    unsigned int Offset;
    ULONG64 Result;
    _WORD *PathBuffer;
    int EntryCount;
    _QWORD *CurrentEntry;
    ULONG64 ModuleEntry;
    __int64 NameLength;
    const void *ImageNamePtr;
    unsigned __int64 NameLength2;
    _WORD *LastChar;
    _DWORD TargetName[4];
    __int64 TargetNameCont;

    Offset = EntryOffset;
    Result = 0;
    PathBuffer = ExAlloc(PagedPool, 0x1000u);
    if (PathBuffer)
    {
        // 目标名称 "user32.dll"（宽字符编码）
        TargetName[0] = 7536757;
        TargetName[1] = 7471205;
        TargetName[2] = 3276851;
        TargetName[3] = 6553646;
        TargetNameCont = 7077996;
        EntryCount = 0;
        CurrentEntry = *ModuleListHead;
        while (CurrentEntry != (_QWORD *)ModuleListHead)
        {
            if ((unsigned int)++EntryCount > 0x1000)
                break;
            ModuleEntry = (ULONG64)CurrentEntry - Offset;
            if (ModuleEntry >= MmUserProbeAddress || ModuleEntry + 136 >= MmUserProbeAddress)
                break;
            if (*(_QWORD *)(ModuleEntry + 48))
            {
                NameLength = *(unsigned __int16 *)(ModuleEntry + 72);
                if ((unsigned int)NameLength > 0x1FE)
                    NameLength = 510;
                if ((unsigned int)NameLength > 2)
                {
                    ImageNamePtr = *(const void **)(ModuleEntry + 80);
                    if ((unsigned __int64)ImageNamePtr < MmUserProbeAddress)
                    {
                        if (ImageNamePtr)
                        {
                            NameLength2 = (unsigned int)NameLength;
                            if ((unsigned __int64)ImageNamePtr + NameLength < MmUserProbeAddress)
                            {
                                memmove(PathBuffer, ImageNamePtr, (unsigned int)NameLength);
                                PathBuffer[NameLength2 >> 1] = 0;
                                LastChar = WStringFindLastChar(PathBuffer, 92);
                                if (LastChar)
                                {
                                    if (!(unsigned int)WStringCompareCaseInsensitive((__int64)(LastChar + 1), (__int64)TargetName))
                                    {
                                        Result = *(_QWORD *)(ModuleEntry + 48);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            CurrentEntry = (_QWORD *)*CurrentEntry;
            Offset = EntryOffset;
        }
        ExFree(PathBuffer);
    }
    return Result;
}

// 注：原始 sub_140032A30 实为 ParseAtaPortInitForHookTargets，
// 真正的 ParseNtRelocationTable 位于 sub_1400068AC，已由 ParseNtRelocationTableEx 实现。

// FindWin32kServiceTableByPattern — 通过模式扫描查找 Win32k 服务表
// 对应原始驱动 sub_140007840（212 字节）
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
// 对应原始驱动 sub_140007420
// 遍历 PEB 模块链表，查找 user32.dll 条目
// 返回模块条目指针，0 表示未找到
ULONG64 FindUser32ModuleInList(unsigned int *ModuleListHead, unsigned int EntryOffset)
{
    unsigned int Offset;
    ULONG64 Result;
    _WORD *PathBuffer;
    int EntryCount;
    unsigned int *CurrentEntry;
    ULONG64 ModuleEntry;
    __int64 NameLength;
    ULONG64 ImageNamePtr;
    unsigned __int64 NameLength2;
    _WORD *LastChar;
    _DWORD TargetName[4];
    __int64 TargetNameCont;

    Offset = EntryOffset;
    Result = 0;
    PathBuffer = ExAlloc(PagedPool, 0x1000u);
    if (PathBuffer)
    {
        // 目标名称 "user32.dll"（宽字符编码）
        TargetName[0] = 7536757;
        TargetName[1] = 7471205;
        TargetName[2] = 3276851;
        TargetName[3] = 6553646;
        TargetNameCont = 7077996;
        EntryCount = 0;
        CurrentEntry = (unsigned int *)(ULONG_PTR)*ModuleListHead;
        while (CurrentEntry != ModuleListHead)
        {
            if ((unsigned int)++EntryCount > 0x1000)
                break;
            ModuleEntry = (ULONG64)CurrentEntry - Offset;
            if (ModuleEntry >= MmUserProbeAddress || ModuleEntry + 72 >= MmUserProbeAddress)
                break;
            if (*(_DWORD *)(ModuleEntry + 24))
            {
                NameLength = *(unsigned __int16 *)(ModuleEntry + 36);
                if ((unsigned int)NameLength > 0x1FE)
                    NameLength = 510;
                if ((unsigned int)NameLength > 2)
                {
                    ImageNamePtr = *(unsigned int *)(ModuleEntry + 40);
                    if (ImageNamePtr < MmUserProbeAddress)
                    {
                        if ((_DWORD)ImageNamePtr)
                        {
                            NameLength2 = (unsigned int)NameLength;
                            if (ImageNamePtr + NameLength < MmUserProbeAddress)
                            {
                                memmove(PathBuffer, (const void *)ImageNamePtr, (unsigned int)NameLength);
                                PathBuffer[NameLength2 >> 1] = 0;
                                LastChar = WStringFindLastChar(PathBuffer, 92);
                                if (LastChar)
                                {
                                    if (!(unsigned int)WStringCompareCaseInsensitive((__int64)(LastChar + 1), (__int64)TargetName))
                                    {
                                        Result = *(unsigned int *)(ModuleEntry + 24);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            CurrentEntry = (unsigned int *)(ULONG_PTR)*CurrentEntry;
            Offset = EntryOffset;
        }
        ExFree(PathBuffer);
    }
    return Result;
}

// ScanWin32kSectionForServiceTable — 扫描 Win32k 驱动节区查找服务表
// 对应原始驱动 sub_1400075E4（604 字节）
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
            (__int64)(ImageBase + EntryPoint),  // Base
            0x1000,                             // Size
            2,                                  // Mode
            0,                                  // ValidateFlag
            -1,                                 // SectionType (0xFFFFFFFF)
            0,                                  // EntryIndex
            (LONG64)(ULONG64)Context,           // Context = 上下文指针
            (__int64)Context);                  // a8 = 上下文输出

        AccumulatedOffset = 0;

        for (SectionIndex = 0; SectionIndex < 30; SectionIndex++)
        {
            Status = (int)ReadPESectionEntry(Context, SectionInfo);
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
        (__int64)(ImageBase + EntryPoint),
        0x1000,
        2,
        0,
        -1,
        0,
        (LONG64)(ULONG64)Context,
        (__int64)Context);

    memset(Dst, 0, 0x40);
    AccumulatedOffset = 0;

    for (i = 0; i < 0x3E8; i++)
    {
        Status = (int)ReadPESectionEntry(Context, SectionInfo);
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
// 对应原始驱动 0x140078638（209 字节）
// 【读序修正 2026-10-13】原始首读 GT **0x31C**（= GtCallbackField75，
//   见 0x14007864A），空则直接返回 0；其后才读 0x914（构建号）。
//   原稿把 0x914 提到了最前（指数集合相同，仅顺序不同）。
//   另：原始在 `构建号 == 0x2580` 时会额外读 GT 0x8EA（见 0x1400786CB）。
__int64 CheckProcessObjectFlag(__int64 ProcessObject)
{
    unsigned int FlagOffset, BuildNumber;
    FlagOffset = (unsigned int)GtRead(GtCallbackField75);
    if (!FlagOffset) return 0;
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
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
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
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
    QueryResult = (int)QueryObjectFunc(ProcessHandle, 2, BufferPtr, 0x2000, 0);
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
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
    ServiceCountCopy = ServiceCount;
    if (AttachToProcessFunc && KeAttachProcessFunc && pContextFlags && ContextFlags && DetachProcessFunc && ServiceCount != -1 && DeregisterFunc && CloseHandleFunc)
    {
        if (!AttachToProcessFunc(ProcessHandle, &CurrentThread))
        {
            AttachFlags = 0;
            AttachResult = (int)KeAttachProcessFunc(CurrentThread, 512, 0, 0x10000000, *pContextFlags, AttachFlags, &AttachContext);
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
    unsigned int PrevModeOffset = (unsigned int)GtRead(GtSdstServiceCount);
    __int64 (__fastcall *TargetFunc)(__int64) = (__int64 (__fastcall *)(__int64))GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessExtField58 | GtDriverObject));
    unsigned int FlagOffset;
    unsigned int ThreadFlagOffset;
    __int64 SavedFlags1;
    char SavedFlags2;
    struct _KTHREAD *CurrentThread;
    char SavedThreadFlag;
    unsigned int Result, BuildNumber;

    if (PrevModeOffset == -1 || !TargetFunc)
        return (char)-1073741823;
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
    FlagOffset = (unsigned int)GtRead(GtCallbackField122);
    ThreadFlagOffset = (unsigned int)GtRead(GtCallbackField121);
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
    SavedThreadFlag = *((_BYTE *)CurrentThread + PrevModeOffset);
    *((_BYTE *)CurrentThread + PrevModeOffset) = 0;
    Result = (unsigned int)TargetFunc(Handle);
    *((_BYTE *)CurrentThread + PrevModeOffset) = SavedThreadFlag;
    *(_BYTE *)(FlagOffset + VirtualAddress) = (char)SavedFlags1;
    *(_BYTE *)(FlagOffset + VirtualAddress + 1) = SavedFlags2;
    return Result;
}

// ExecuteWithThreadFlagCleared — 清除线程标志后执行
__int64 ExecuteWithThreadFlagCleared(__int64 Address)
{
    unsigned int PrevModeOffset = (unsigned int)GtRead(GtSdstServiceCount);
    __int64 (__fastcall *SyscallFunc)(__int64, _QWORD) = (__int64 (__fastcall *)(__int64, _QWORD))ResolveSyscallAddressesInProcess();
    __int64 (__fastcall *AttachSyscall)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *) = (__int64 (__fastcall *)(__int64, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead((GLOBAL_TABLE_INDEX)(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54));
    _QWORD *pFlags = (_QWORD *)GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField95 | 0x100));
    void (__fastcall *CleanupFunc)(__int64) = (void (__fastcall *)(__int64))GtRead(GtRegisterObjectCallbacksFunc);
    __int64 Handle;
    unsigned int Result;
    struct _KTHREAD *CurrentThread;
    char SavedFlag;

    if (PrevModeOffset == -1 || !SyscallFunc || !AttachSyscall || !pFlags || !CleanupFunc)
        return -1073741823;
    Result = (unsigned int)AttachSyscall(Address, 512, 0, 0x10000000, *pFlags, 0, &Handle);
    if (!Result)
    {
        CurrentThread = KeGetCurrentThread();
        SavedFlag = *((_BYTE *)CurrentThread + PrevModeOffset);
        *((_BYTE *)CurrentThread + PrevModeOffset) = 0;
        Result = (unsigned int)SyscallFunc(Handle, 0);
        CleanupFunc(Handle);
        *((_BYTE *)CurrentThread + PrevModeOffset) = SavedFlag;
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
    IsProtected = (char)CheckProtectedEntry((__int64)ProcessObject);
    TableIndex = IsProtected ? GtWin32kServiceTable64Flag : GtWin32kServiceTable32Flag;
    if (!(unsigned int)GtRead(TableIndex))
    {
        ResolveWin32kServiceTable(IsProtected);
        TableIndex = IsProtected ? GtWin32kServiceTable64Flag : GtWin32kServiceTable32Flag;
        if (!(unsigned int)GtRead(TableIndex))
            goto Cleanup;
    }
    memset(OutputBuffer, 0, 0x54D0u);
    *OutputBuffer = (_DWORD)GtRead(GtWindowsBuildNumber);
    ServiceCount = (unsigned int)GtRead(GtWin32kServiceCount);
    OutputBuffer[8] = ServiceCount;
    if (ServiceCount <= 0x12D
        && BuildExportServiceTableForProcess((__int64)ProcessId, ProcessObject, IsProtected, (_QWORD *)OutputBuffer) == 1
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
    ServiceCount = (unsigned int)GtRead(GtSdstServiceCount);
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
                ProcessFlagsOffset = (unsigned int)GtRead(GtCallbackField124);
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
            if ((unsigned __int64)pCurrentNode <= (unsigned __int64)MmSystemRangeStart)
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
        FiberOffset = (int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtEprocessModuleListOffset | GtEprocessField88));
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
        ResolveKernelModuleFunctionAddrs();
        GtIndex2 = GtNtQuerySystemInformationFunc | GtEprocessField58;
        if (Flags != 1)
            GtIndex2 = GtSubsystemConfigBase | GtEprocessField10 | 0x100;
        QueryFunc = (__int64(__fastcall *)(__int64))GtRead(GtIndex2);
    }
    if (!GtRead(GtKiInsertQueueApcFunc))
    {
        #pragma warning(push)
#pragma warning(disable: 4087)
        InitHookFunctionTable(0, 0, 0, 0);
#pragma warning(pop)
        GtRead(GtKiInsertQueueApcFunc);
    }
    if (Flags == 1 && (unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28)
    {
        CallbackValue = GtRead(GtCallbackField11);
        GtRead(GtCallbackField12);
        if (!CallbackValue)
        {
            #pragma warning(push)
#pragma warning(disable: 4087)
            ScanKernelModulePESectionsEx(0, 0, 0, 0, 0, 0);
#pragma warning(pop)
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
            TraverseEprocessListAndInit((struct _KPROCESS *)Process);
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

    ListOffset = (unsigned int)GtRead(GtEprocessField41);
    ObjectHeaderOffset = (unsigned int)GtRead(GtEprocessField48);
    if (ListOffset && ObjectHeaderOffset)
    {
        if (ValidateProcessObject(Process, 0) == 1)
        {
            pListEntry = (_QWORD **)((char *)Process + ListOffset);
            IsReferenced = ReferenceObjectSafe((__int64)Process);
            if (MmIsAddressValid(pListEntry) == 1)
            {
                CurrentEntry = *pListEntry;
                for (Iterations = 0; (unsigned __int64)CurrentEntry > (unsigned __int64)MmSystemRangeStart; ++Iterations)
                {
                    if ((unsigned __int64)CurrentEntry == (unsigned __int64)pListEntry)
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
    unsigned int FieldSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int KernelPESectionByType = (unsigned int)FindKernelPESectionByType(210 | GtTotalSize);
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    if (FieldOffset && FieldSize && NtoskrnlBase && KernelPESectionByType && KernelPESectionByType < ServiceCount)
    {
        unsigned int SyscallIndex = (unsigned int)ResolveSyscallToAddress(KernelPESectionByType);
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
    RelocatedBase = ParseNtRelocationTableEx((PRKPROCESS)ImageBase, Is64Bit, &RelocatedSizeVal, (_QWORD *)&DataBuffer, (void **)&DataBuffer);
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
                __int64 Offset = (ServiceBuffer + 4 + (EntryIndex + EntryIndex * 2)) << 4;
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
