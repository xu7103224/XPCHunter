// HandleMgmt.c — 句柄管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"

// 前向声明（本文件内后定义的函数被前引用）
char ValidateProcessContext(unsigned int *OutputBuffer, unsigned int BufferSize);
char EnumerateProcessHandleTable(_DWORD *OutputBuffer, unsigned int BufferSize);
char DispatchProcessHandleTableEnum(__int64 OutputBuffer, unsigned int BufferSize, void (__fastcall *Callback)(__int64, __int64, ULONG64, __int64), __int64 Context);
char GetProcessVirtualizationContext(_DWORD *OutputBuffer, unsigned int BufferSize);
char EnumerateSessionProcesses(unsigned int *OutputBuffer, unsigned int BufferSize);
char EnumerateAllProcesses(unsigned int *OutputBuffer, unsigned int BufferSize);
char ResolveHandleEntry(unsigned __int16 *HandleEntry, _BYTE *OutputBuffer, unsigned int BufferSize);
bool CompareInt16Equal(__int16 Value1, __int16 Value2);
_QWORD *EnumObjectHandleTable(unsigned int *OutputBuffer, unsigned int MaxEntries);
_QWORD *EnumerateObjectHandles(unsigned int *OutputBuffer, unsigned int MaxEntries);
__int64 EnumObjectHandlesWin8Plus(unsigned int *OutputBuffer, unsigned int MaxEntries);
char TraverseProcessHandleTableWin7(__int64 HandleTable, __int64 OutputBuffer, unsigned int BufferSize, void (__fastcall *Callback)(__int64, __int64, _QWORD, __int64), __int64 Context);
char TraverseProcessHandleTableWin10(__int64 *HandleTable, __int64 OutputBuffer, unsigned int BufferSize, __int64 (__fastcall *Callback)(unsigned __int64, __int64, _QWORD, __int64), __int64 Context);
void EnumProcessHandleTable(void);
unsigned __int64 FindCsrssProcessEntry(unsigned int *OutputBuffer);
void QueryProcessVirtualization(void);
void DecodeObjectPointerFromHandleEntry(__int64 *HandleEntry, __int64 OutputBuffer, unsigned int BufferSize, __int64 (__fastcall *Callback)(unsigned __int64, __int64, _QWORD, __int64), __int64 Context);
bool ValidateHandleEntry(__int64 HandleTableEntry);
unsigned __int64 DecodeObjectHandleEntry(__int64 HandleEntry);
void *AllocExBufferAndQuerySystemInfo(unsigned int SystemInfoClass);
bool CallRegisteredCallback(__int64 Address);
__int64 GetObjectTableCode(void);

// CmdEnumHandles — 枚举句柄命令
// 对应原始驱动 sub_14004ABB4
__int64 CmdEnumHandles(__int64 UnusedArg1, __int64 UnusedArg2, volatile void *OutputBuffer, unsigned int BufferSize)
{
    if (!OutputBuffer || BufferSize <= 0x230)
        return 0;

    if ((ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, BufferSize, 1);
    return ValidateProcessContext((unsigned int *)OutputBuffer, BufferSize);
}

// ValidateProcessContext — 验证进程上下文
// 对应原始驱动 sub_14004A044
// 调用多个枚举函数填充进程上下文表
char ValidateProcessContext(unsigned int *OutputBuffer, unsigned int BufferSize)
{
    *OutputBuffer = 0;
    GetProcessVirtualizationContext(OutputBuffer, BufferSize);
    DispatchProcessHandleTableEnum((__int64)OutputBuffer, BufferSize,
        (void (__fastcall *)(__int64, __int64, ULONG64, __int64))ValidateProcessObjectEx, 0);
    EnumerateProcessHandleTable(OutputBuffer, BufferSize);
    EnumerateAllProcesses(OutputBuffer, BufferSize);
    EnumerateSessionProcesses(OutputBuffer, BufferSize);
    return *OutputBuffer != 0;
}

// EnumerateProcessHandleTable — 枚举进程句柄表
// 对应原始驱动 sub_14004AC44
// 遍历进程句柄表链表节点，枚举所有有效进程对象
char EnumerateProcessHandleTable(_DWORD *OutputBuffer, unsigned int BufferSize)
{
    char HasItems;
    ULONG Process, ObjectTableOffset, EntryCount;
    UCHAR (*CheckFunc)(struct _KPROCESS *);
    int EntryIndex;
    __int64 SecondTableList;
    _QWORD ***HandleValue;
    _QWORD **ObjectPtr;
    _QWORD *GrantedAccess;
    ULONG HandleAttr;
    struct _KPROCESS *ProcessId;
    __int64 ObjectType;
    _QWORD TableListArray[12];
    ULONG EntryCountCopy;
    _QWORD **ObjectName;
    _QWORD *TypeIndex;
    __int64 EntryOffset;
    _QWORD *OutputEntry;
    ULONG ValidEntry;
    struct _KPROCESS *pProcessObject;
    _QWORD *TableListPtr;
    __int64 TypeCounter;

    HasItems = 0;
    Process = (ULONG)GtRead(0x41A0);
    ObjectTableOffset = (ULONG)GtRead(GtProcessOffset);
    CheckFunc = (UCHAR (*)(struct _KPROCESS *))GtRead(GtObjectTypeCheckFlag);

    if (!Process || ObjectTableOffset == -1 || ObjectTableOffset <= Process || !CheckFunc)
        return HasItems;

    EntryCount = ObjectTableOffset - Process;
    TableListArray[0] = GtRead(GtEprocessField58);
    TableListArray[1] = GtRead(GtEprocessField59);
    EntryIndex = (ULONG)GtRead(GtEprocessField28) == 1 ? 1 : 32;
    SecondTableList = GtRead(GtEprocessField60);
    EntryCountCopy = EntryIndex;
    TableListPtr = TableListArray;
    TypeCounter = 2;
    HandleValue = (_QWORD ***)TableListArray;
    ObjectType = 2;

    do
    {
        ObjectPtr = *HandleValue;
        if (ObjectPtr)
        {
            GrantedAccess = *ObjectPtr;
            HandleAttr = 0;
            if (GrantedAccess != (_QWORD *)ObjectPtr)
            {
                do
                {
                    if (HandleAttr >= 0x2000) break;
                    if (CheckFunc((struct _KPROCESS *)((char *)GrantedAccess + EntryCount)) == 1)
                    {
                        ProcessId = *(struct _KPROCESS **)((char *)GrantedAccess + EntryCount);
                        if (CheckFunc(ProcessId) == 1)
                        {
                            HasItems = 1;
                            EnumerateProcessObjects(ProcessId, ProcessId, OutputBuffer, BufferSize, 1, 0, 0);
                        }
                    }
                    GrantedAccess = (_QWORD *)*GrantedAccess;
                    HandleAttr++;
                } while (GrantedAccess != (_QWORD *)ObjectPtr);
                HandleValue = (_QWORD ***)TableListPtr;
                ObjectType = TypeCounter;
            }
        }
        HandleValue++;
        TypeCounter = --ObjectType;
        TableListPtr = (_QWORD *)HandleValue;
    } while (ObjectType);

    ObjectName = (_QWORD **)SecondTableList;
    if (SecondTableList && EntryCountCopy)
    {
        TypeIndex = (_QWORD *)SecondTableList;
        EntryOffset = EntryCountCopy;
        do
        {
            OutputEntry = *ObjectName;
            ValidEntry = 0;
            if (OutputEntry != TypeIndex)
            {
                do
                {
                    if (ValidEntry >= 0x2000) break;
                    if (CheckFunc((struct _KPROCESS *)((char *)OutputEntry + EntryCount)) == 1)
                    {
                        pProcessObject = *(struct _KPROCESS **)((char *)OutputEntry + EntryCount);
                        if (CheckFunc(pProcessObject) == 1)
                        {
                            HasItems = 1;
                            EnumerateProcessObjects(pProcessObject, pProcessObject, OutputBuffer, BufferSize, 1, 0, 0);
                        }
                    }
                    OutputEntry = (_QWORD *)*OutputEntry;
                    ValidEntry++;
                } while (OutputEntry != TypeIndex);
                ObjectName = (_QWORD **)SecondTableList;
                EntryOffset = EntryCountCopy;
            }
            ObjectName += 2;
            TypeIndex += 2;
            EntryCountCopy = (ULONG)(--EntryOffset);
            SecondTableList = (__int64)ObjectName;
        } while (EntryOffset);
    }

    return HasItems;
}

// EnumHandlesByType — 按类型枚举句柄
// 对应原始驱动 sub_140085194
// 遍历句柄表，根据对象类型匹配枚举所有指定类型的句柄
__int64 EnumHandlesByType(WORD *TargetName, ULONG NameLen, _DWORD *TypeTable, _DWORD *OutputBuffer, int MaxEntries)
{
    ULONG Count = 0;
    int TypeFlag = (int)GtRead(GtCallbackField69);

    if (!TypeFlag)
    {
        InitHandleTypeTable();
        TypeFlag = (int)GtRead(GtCallbackField69);
    }
    if (!TypeFlag) return Count;

    UCHAR *Buffer = ExAlloc(PagedPool, 0x10002);
    if (!Buffer) return Count;

    WORD *EntryPtr = (WORD *)(TypeTable + 2);
    ULONG EntryCount = *TypeTable;

    for (ULONG i = 0; i < EntryCount && MaxEntries; i++)
    {
        if (TypeFlag == *((UCHAR *)EntryPtr + 4))
        {
            memset(OutputBuffer, 0, 0x420);
            *((__int64 *)OutputBuffer + 131) = EntryPtr[3];
            *((__int64 *)OutputBuffer + 130) = *EntryPtr;

            if (ResolveHandleEntry(EntryPtr, Buffer, 0x10000))
            {
                Buffer[0x10000] = 0;
                Buffer[0x10001] = 0;
                ULONG StrLen = *(ULONG *)Buffer;
                if (StrLen + 8 >= 0x10000) goto Next;
                if (StrLen >> 1 < NameLen) goto Next;

                *(WORD *)&Buffer[2 * (StrLen >> 1) + 4] = 0;
                if (StringCompare3Way((__int64)(Buffer + 4), TargetName, NameLen)) goto Next;

                void *ImagePathBuffer = NULL;
                int ImagePathLength;
                WStringCopyN((WORD *)OutputBuffer + 260, (__int64)(Buffer + 4), 0x104);
                *((WORD *)OutputBuffer + 519) = 0;

                if (GetProcessImagePath(NULL, *((HANDLE *)OutputBuffer + 130), &ImagePathBuffer, &ImagePathLength, 0) == 1)
                {
                    WStringCopyN((WORD *)OutputBuffer, (__int64)ImagePathBuffer, 0x104);
                    *((WORD *)OutputBuffer + 259) = 0;
                }
                else if ((ULONG64)(*((__int64 *)OutputBuffer + 130) - 1) <= 7)
                {
                    OutputBuffer[0] = 7929939;
                    OutputBuffer[1] = 7602291;
                    *((__int64 *)OutputBuffer + 1) = 7143525;
                }
                OutputBuffer += 264;
                MaxEntries--;
                Count++;
                if (ImagePathBuffer) ExFree(ImagePathBuffer);
            }
        }
Next:
        EntryPtr += 12;
    }

    ExFree(Buffer);
    return Count;
}

// CmdEnumHandlesByPid — 按 PID 枚举句柄
// 对应原始驱动 sub_1400858B8
// 根据进程ID遍历句柄表，获取匹配的句柄信息
__int64 CmdEnumHandlesByPid(volatile void *Address, SIZE_T Length, char *OutputBuffer, unsigned int BufferSize)
{
    ULONG NameLength = (ULONG)Length;
    char Result = 0;
    ULONG EntryIndex;
    _DWORD *SystemInfo;

    if (NameLength <= 2 || !Address) return Result;
    if (BufferSize < 0x428 ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)Address + NameLength >= MmUserProbeAddress ||
        (Length & 1) != 0 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, NameLength, 1);
    ProbeForWrite(OutputBuffer, BufferSize, 1);

    EntryIndex = NameLength >> 1;
    *(ULONG *)OutputBuffer = 0;

    SystemInfo = AllocExBufferAndQuerySystemInfo(0x10);
    if (SystemInfo)
    {
        *(ULONG *)OutputBuffer = (ULONG)EnumHandlesByType(
            (WORD *)Address, EntryIndex - 1, SystemInfo,
            (_DWORD *)OutputBuffer + 2, (int)((BufferSize - 8) / 0x420));
        ExFree(SystemInfo);
        return 1;
    }

    return Result;
}

// CheckHandleEntryValid — 检查句柄条目是否有效
// 对应原始驱动 sub_140077DB8
bool CheckHandleEntryValid(__int64 Process)
{
    ULONG Offset = (ULONG)GtRead(GtEprocessField44);
    return Offset ? *(_QWORD *)(Offset + Process) != 0 : 0;
}

// EnumerateProcessHandleTableData — 枚举进程句柄表数据
// 对应原始驱动 sub_14004FED8
// 从 EPROCESS 偏移获取句柄表链表头，遍历链表
void EnumerateProcessHandleTableData(struct _KPROCESS *Process, __int64 OutputBuffer, unsigned int BufferSize)
{
    ULONG HandleTable = (ULONG)GtRead(GtEprocessField41);
    ULONG EntryCount = (ULONG)GtRead(GtEprocessField40);
    ULONG HandleEntry = (ULONG)GtRead(GtEprocessField48);
    ULONG HandleEntry2 = (ULONG)GtRead(GtEprocessField47);
    ULONG TableBase = HandleEntry2;

    if (HandleTable && EntryCount && HandleEntry && HandleEntry2 && ValidateProcessObject(Process, NULL) == 1)
    {
        EnumerateProcessListEntry((_QWORD **)((char *)Process + HandleTable), TableBase, OutputBuffer, BufferSize);
        EnumerateProcessListEntry((_QWORD **)((char *)Process + EntryCount), TableBase, OutputBuffer, BufferSize);
    }
}

// CmdCloseProcessHandle — 关闭进程句柄命令
// 对应原始驱动 sub_140084154
// 根据进程ID和句柄值，跨进程附加后关闭指定句柄
__int64 CmdCloseProcessHandle(__int64 UnusedArg1, __int64 UnusedArg2, _DWORD *pOutputBuffer, int BufferSize)
{
    char Result = 0;
    _OWORD *Address = (_OWORD *)pOutputBuffer;
    int InputSize = BufferSize;
    PEPROCESS *pObjectTypeInfo;
    __int64 DerefFunc;
    int (__fastcall *CloseHandleFunc)(unsigned __int64, __int64, char *, __int64, _QWORD);
    bool IsRemoteProcess;
    unsigned __int64 HandleValue;
    void (__fastcall *AltCloseFunc)(unsigned __int64, __int64, char *, __int64);
    UCHAR RefCount;
    char StatusByte;
    char DeregisterFlag = 0;
    PEPROCESS Process;
    HANDLE AdjustedHandle;
    HANDLE Handle[2];
    KAPC_STATE ApcState;

    pObjectTypeInfo = (PEPROCESS *)GtRead(GtObjectTypeInfoPtr);
    DerefFunc = GtRead(GtDereferenceObjectFunc);
    CloseHandleFunc = (int (__fastcall *)(unsigned __int64, __int64, char *, __int64, _QWORD))DerefFunc;

    if (pObjectTypeInfo && DerefFunc && InputSize == 16 && Address
        && (ULONG64)Address < MmUserProbeAddress && (ULONG64)(Address + 1) < MmUserProbeAddress)
    {
        ProbeForRead(Address, 0x10, 4);
        *(_OWORD *)Handle = *Address;

        if (PsLookupProcessByProcessId(Handle[0], &Process) >= 0)
        {
            IsRemoteProcess = IoGetCurrentProcess() != Process;
            if (IsRemoteProcess)
            {
                RefCount = ReferenceObjectSafe((__int64)Process);
                KeStackAttachProcess(Process, &ApcState);
            }

            HandleValue = (unsigned __int64)Handle[1];
            AdjustedHandle = Handle[1];
            if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0 && *pObjectTypeInfo == Process)
            {
                HandleValue |= 0xFFFFFFFF80000000ULL;
                AdjustedHandle = (HANDLE)HandleValue;
            }

            if (CheckHandleEntryValid((__int64)Process) == 1)
            {
                if (CloseHandleFunc(HandleValue, 4, &StatusByte, 2, 0) >= 0)
                {
                    if (DeregisterFlag == 1)
                    {
                        AltCloseFunc = (void (__fastcall *)(unsigned __int64, __int64, char *, __int64))GtRead(GtAltRegisterCallbackFunc);
                        if (AltCloseFunc)
                        {
                            DeregisterFlag = 0;
                            AltCloseFunc(HandleValue, 4, &StatusByte, 2);
                        }
                    }
                    ZwClose((HANDLE)HandleValue);
                    Result = 1;
                }
                ReturnFalseStub();
            }

            if (IsRemoteProcess)
            {
                KeUnstackDetachProcess(&ApcState);
                if (RefCount == 1) DereferenceObjectSafe((__int64)Process);
            }
            ObfDereferenceObject(Process);
        }
    }
    return Result;
}

// CmdCloseProcessHandleEx — 关闭进程句柄（扩展）
// 从 InputBuffer 读取进程 ID 和句柄值，通过 ZwClose 关闭指定句柄
// 对应原始驱动 sub_140084B5C
char CmdCloseProcessHandleEx(__int64 InputBuffer)
{
    char Result = 0;
    if (!InputBuffer || (unsigned __int64)InputBuffer < (unsigned __int64)MmUserProbeAddress)
        return Result;
    if (MmIsAddressValid((void *)InputBuffer) != 1)
        return Result;
    _DWORD *pInput = (_DWORD *)InputBuffer;
    unsigned int ProcessId = pInput[0];
    HANDLE Handle = (HANDLE)(ULONG_PTR)pInput[1];
    if (!ProcessId || !Handle)
        return Result;
    PEPROCESS Process = NULL;
    NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &Process);
    if (NT_SUCCESS(Status) && Process)
    {
        Status = ZwClose(Handle);
        if (NT_SUCCESS(Status))
            Result = 1;
        ObfDereferenceObject(Process);
    }
    return Result;
}

// CmdEnumObjectHandles — 枚举对象句柄
// 对应原始驱动 sub_140054C38
// 验证输出缓冲区，根据构建号选择 Win8+ 或旧版句柄枚举
__int64 CmdEnumObjectHandles(__int64 UnusedArg1, __int64 UnusedArg2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    ULONG64 pObjectType;
    ULONG HandleTable;

    if (!OutputBuffer || BufferSize < 0x40 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    pObjectType = BufferSize;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    *OutputBuffer = 0;
    HandleTable = (ULONG)((pObjectType - 64) / 0x38 + 1);

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
        EnumObjectHandlesWin8Plus(OutputBuffer, HandleTable);
    else
    {
        ULONG KernelDataField08 = (ULONG)GtRead(GtKernelDataField08);
        if (!KernelDataField08)
        {
            EnumProcessHandleTable();
            KernelDataField08 = (ULONG)GtRead(GtKernelDataField08);
        }
        if (KernelDataField08 && (UCHAR)GtRead(GtKernelDataField10))
            EnumerateObjectHandles(OutputBuffer, HandleTable);
        else
            EnumObjectHandleTable(OutputBuffer, HandleTable);
    }

    return *OutputBuffer != 0;
}

// GetProcessFromHandleEntry — 从句柄条目获取进程对象
// 对应原始驱动 sub_14004A5F0
__int64 GetProcessFromHandleEntry(__int64 HandleTableEntry)
{
    UCHAR (*CheckFunc)(__int64);
    ULONG Offset;

    CheckFunc = (UCHAR (*)(__int64))GtRead(GtObjectTypeCheckFlag);
    Offset = (ULONG)GtRead(GtEprocessField44);

    if (!CheckFunc || !Offset)
        return 0;

    __int64 Object = *(__int64 *)(Offset + HandleTableEntry);
    if (CheckFunc(Object) != 1)
        return 0;

    ULONG BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNum == 2195)
        return *(__int64 *)(Object + 24);
    if (BuildNum >= 0x23F0)
        return *(unsigned int *)(Object + 40);
    return *(__int64 *)(Object + 16);
}

// DispatchProcessHandleTableEnum — 分发进程句柄表枚举
// 对应原始驱动 sub_140071940
// 根据 Windows 版本选择 Win7 或 Win10 的句柄表遍历
char DispatchProcessHandleTableEnum(
    __int64 OutputBuffer, unsigned int BufferSize,
    void (__fastcall *Callback)(__int64, __int64, ULONG64, __int64),
    __int64 Context)
{
    __int64 **HandleTableList = (__int64 **)GtRead(GtEprocessField27);
    if (!HandleTableList) return 0;

    __int64 *HandleTableEntry = *HandleTableList;
    if ((ULONG)GtRead(GtEprocessField28) == 1)
        return TraverseProcessHandleTableWin7((__int64)HandleTableEntry, OutputBuffer, BufferSize, Callback, Context);
    else
        return TraverseProcessHandleTableWin10(HandleTableEntry, OutputBuffer, BufferSize,
            (__int64 (__fastcall *)(ULONG64, __int64, ULONG64, __int64))Callback, Context);
}

// GetProcessVirtualizationContext — 获取进程虚拟化上下文
// 对应原始驱动 sub_140049B94
char GetProcessVirtualizationContext(_DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    __int64 ObjectTypeInfo;
    UCHAR (*CheckFunc)(__int64);
    ULONG VirtualAddr, PageOffset;
    __int64 PageTable, PageEntry, Field11;
    ULONG Field12;
    char Field14 = 0;

    if (BuildNumber < 0x1771 || BuildNumber >= 0x1DB0)
        return GetProcessVirtualizationContextFallback(OutputBuffer, BufferSize);

    ObjectTypeInfo = GtRead(GtObjectTypeInfoPtr);
    CheckFunc = (UCHAR (*)(__int64))GtRead(GtObjectTypeCheckFlag);
    VirtualAddr = (ULONG)GtRead(GtEprocessField30);
    PageOffset = VirtualAddr;
    if (!ObjectTypeInfo || !CheckFunc || VirtualAddr == (ULONG)-1) return Field14;
    if (!CheckFunc(ObjectTypeInfo + 8)) return Field14;

    PageTable = *(__int64 *)(ObjectTypeInfo + 8);
    if (!CheckFunc(PageTable)) return Field14;

    PageEntry = (ULONG)*OutputBuffer;
    if ((unsigned int)(552 * (int)PageEntry + 560) >= BufferSize) return Field14;

    PageEntry = 138 * PageEntry;
    *(__int64 *)&OutputBuffer[(int)PageEntry + 10] = PageTable;
    Field11 = *(__int64 *)(PageOffset + PageTable);
    *(__int64 *)&OutputBuffer[(int)PageEntry + 4] = 0;
    *(__int64 *)&OutputBuffer[(int)PageEntry + 6] = Field11;
    LOWORD_LV(OutputBuffer[(int)PageEntry + 2]) = 0;
    Field12 = (ULONG)GtRead(GtEprocessField36);
    if (Field12 == (ULONG)-1)
        *(__int64 *)&OutputBuffer[(int)PageEntry + 8] = 0;
    else
        *(__int64 *)&OutputBuffer[(int)PageEntry + 8] = *(__int64 *)(Field12 + PageTable);
    OutputBuffer[(int)PageEntry + 14] = 0;
    OutputBuffer[(int)PageEntry + 12] = 6553673;
    OutputBuffer[(int)PageEntry + 13] = 6619244;
    ++*OutputBuffer;
    return Field14;
}

// EnumerateSessionProcesses — 按会话 ID 枚举进程
// 对应原始驱动 sub_14004AEB4
// 查找 CSRSS 进程创建时间戳，筛选匹配的进程
char EnumerateSessionProcesses(unsigned int *OutputBuffer, unsigned int BufferSize)
{
    char SessionId;
    unsigned __int64 CsrssProcessEntry;
    __int16 CsrssTimestamp;
    struct _KPROCESS **SystemInfo;
    struct _KPROCESS **pSystemInfo;
    struct _KPROCESS **pEntry;
    __int64 EntryCount;

    if ((unsigned int)GtRead(GtEprocessField61)
        || (QueryProcessVirtualization(), (unsigned int)GtRead(GtEprocessField61)))
    {
        SessionId = (char)GtRead(GtEprocessField62);
        CsrssProcessEntry = FindCsrssProcessEntry(OutputBuffer);
        CsrssTimestamp = (__int16)CsrssProcessEntry;
        if (CsrssProcessEntry)
        {
            SystemInfo = (struct _KPROCESS **)AllocExBufferAndQuerySystemInfo(0x10);
            pSystemInfo = SystemInfo;
            if (SystemInfo)
            {
                if (*(_DWORD *)SystemInfo)
                {
                    pEntry = SystemInfo + 2;
                    EntryCount = *(unsigned int *)SystemInfo;
                    do
                    {
                        if (*((_BYTE *)pEntry - 4) == SessionId && CompareInt16Equal(*((_WORD *)pEntry - 4), CsrssTimestamp))
                            EnumerateProcessObjects(*pEntry, *pEntry, OutputBuffer, BufferSize, 1, 1, 0);
                        pEntry += 3;
                        --EntryCount;
                    } while (EntryCount);
                }
                ExFree(pSystemInfo);
            }
        }
    }
    return 0;
}

// CompareInt16Equal — 比较两个 16 位整数是否相等
// 对应原始驱动 sub_14007AAC8
bool CompareInt16Equal(__int16 Value1, __int16 Value2)
{
    return Value1 == Value2;
}

// AllocExBufferAndQuerySystemInfo — 分配扩展缓冲区并查询系统信息
// 对应原始驱动 sub_14007A7F8
// 分配缓冲区后调用 NtQuerySystemInformation，自动调整缓冲区大小直至成功

// AllocateNtHandleEntry — 分配 NT 句柄条目
// 对应原始驱动 sub_14006C34C
// 通过加密字符串路径解码后打开对象，分配句柄条目
__int64 AllocateNtHandleEntry(void)
{
    __int64 Result = 0;
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, _DWORD *);
    int (__fastcall *CreateFileFunc)(_BYTE *, __int64, __int64 *, _BYTE *);
    void (*CloseHandleFunc)(void);
    __int64 Handle;
    _BYTE ObjectNameBuffer[16];
    _BYTE ObjectAttributes[48];
    _DWORD EncodedPath[6];

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (int (__fastcall *)(_BYTE *, __int64, __int64 *, _BYTE *))GtRead(GtCreateFileFunc2);
    CloseHandleFunc = (void (*)(void))GtRead(GtCloseHandleFunc);

    if (RtlInitUnicodeStringFunc && CreateFileFunc && CloseHandleFunc)
    {
        EncodedPath[0] = 4456540;
        EncodedPath[1] = 7733349;
        EncodedPath[2] = 6488169;
        EncodedPath[3] = 6029413;
        EncodedPath[4] = 6684791;
        EncodedPath[5] = 112;

        RtlInitUnicodeStringFunc(ObjectNameBuffer, EncodedPath);
        if (CreateFileFunc(ObjectNameBuffer, 128, &Handle, ObjectAttributes) >= 0)
        {
            Result = *(_QWORD *)(Handle + 8);
            CloseHandleFunc();
        }
    }
    return Result;
}

// EnumHandleTableToBuffer — 枚举句柄表到缓冲区
// 对应原始驱动 sub_14006C8F0
// 分配临时缓冲区调用 ValidateProcessContext 获取句柄表，遍历每个句柄条目
void EnumHandleTableToBuffer(unsigned int *OutputBuffer, _DWORD *pCount)
{
    unsigned int *TempBuffer;
    unsigned int EntryCount;
    unsigned int Index;
    __int64 *EntryPtr;

    TempBuffer = (unsigned int *)ExAlloc(PagedPool, 0x43850);
    if (TempBuffer)
    {
        if (ValidateProcessContext(TempBuffer, 0x43850))
        {
            EntryCount = *TempBuffer;
            Index = 0;
            if (*TempBuffer)
            {
                EntryPtr = (__int64 *)(TempBuffer + 10);
                do
                {
                    if (!*pCount)
                        break;
                    if (*((_BYTE *)EntryPtr - 32) == 1 || ValidateHandleEntry(*EntryPtr) == 1)
                        CopyObjectEntryToBuffer((__int64)&TempBuffer[138 * Index + 2], 4, 4, OutputBuffer, pCount);
                    ++Index;
                    EntryPtr += 69;
                }
                while (Index < EntryCount);
            }
        }
        ExFree(TempBuffer);
    }
}

// EnumObjectHandleTable — 枚举对象句柄表（备选版）
// 对应原始驱动 sub_14005505C
// 遍历句柄表链表，对每个有效句柄条目填充 56 字节每项的句柄信息
_QWORD *EnumObjectHandleTable(unsigned int *OutputBuffer, unsigned int MaxEntries)
{
    unsigned __int8 (__fastcall *CheckFunc)(_QWORD *);
    unsigned int TableCount;
    _QWORD *TableBase;
    _QWORD *TableEnd;
    _QWORD *SyscallCheckPtr;
    __int64 Remaining;
    _QWORD *CurrentEntry;
    unsigned int LoopCount;
    _QWORD *Entry;
    __int64 ObjectHeader;
    unsigned int ProcessEprocessOffset;

    CheckFunc = (unsigned __int8 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    TableCount = (ULONG)GtRead(GtKernelDataField09);
    TableBase = (_QWORD *)GtRead(GtKernelDataField08);
    if (!CheckFunc || !TableBase)
        return TableBase;
    SyscallCheckPtr = (_QWORD *)GtRead(GtKernelDataField11);
    if (!SyscallCheckPtr)
    {
        ResolveSyscallNumberFromKernel();
        SyscallCheckPtr = (_QWORD *)GtRead(GtKernelDataField11);
    }
    if (!TableCount)
        return SyscallCheckPtr;

    TableEnd = TableBase + 1;
    Remaining = TableCount;
    do
    {
        CurrentEntry = (_QWORD *)*TableEnd;
        LoopCount = 0;
        if ((_QWORD *)*TableEnd == TableBase)
            goto Advance;
        do
        {
            if (*OutputBuffer >= MaxEntries)
                break;
            if (LoopCount >= 0x10000)
                break;
            Entry = CurrentEntry - 4;
            if (CheckFunc(CurrentEntry) != 1 || CheckFunc(CurrentEntry - 4) != 1)
                break;
            if (SyscallCheckPtr
                && CheckFunc(CurrentEntry - 10) == 1
                && CheckFunc((_QWORD *)((char *)Entry + 263)) == 1
                && *(CurrentEntry - 8) == *SyscallCheckPtr
                && (_QWORD *)Entry[6] == Entry + 19
                && *((_BYTE *)Entry + 240) == 1)
            {
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = (_QWORD)Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = Entry[14];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
                ObjectHeader = Entry[6];
                if (ObjectHeader)
                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(ObjectHeader + 24);
                if (*(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] < (unsigned __int64)MmSystemRangeStart)
                {
                    ProcessEprocessOffset = (ULONG)GtRead(GtProcessEprocess);
                    unsigned int ProcessEprocess = (ULONG)GtRead(GtProcessCreateTime);
                    unsigned int ProcessCreateTime = ProcessEprocess;
                    if (ProcessEprocessOffset != -1)
                    {
                        if (ProcessEprocess)
                        {
                            _QWORD *ProcessPtr = (_QWORD *)Entry[9];
                            if (CheckFunc(ProcessPtr) == 1
                                && CheckFunc((_QWORD *)((char *)ProcessPtr + ProcessEprocessOffset + 3)) == 1
                                && CheckFunc((_QWORD *)((char *)ProcessPtr + ProcessCreateTime + 3)) == 1)
                            {
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = *(unsigned int *)((char *)ProcessPtr + ProcessEprocessOffset);
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = *(unsigned int *)((char *)ProcessPtr + ProcessCreateTime);
                            }
                            LoopCount = LoopCount;
                        }
                    }
                }
            }
            else
            {
                ObjectHeader = Entry[6];
                if (!ObjectHeader || !*(_QWORD *)(ObjectHeader + 24))
                    goto Next;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = (_QWORD)Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(ObjectHeader + 24);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
            }
            ++*OutputBuffer;
Next:
            CurrentEntry = (_QWORD *)CurrentEntry[1];
            MaxEntries = MaxEntries;
            LoopCount = ++LoopCount;
        }
        while (CurrentEntry != TableBase);
        TableEnd = TableEnd;
        Remaining = Remaining;
Advance:
        TableEnd += 2;
        TableBase += 2;
        Remaining = --Remaining;
        TableEnd = TableEnd;
    }
    while (Remaining);
    return TableEnd;
}

// EnumerateObjectHandles — 枚举对象句柄（主函数）
// 对应原始驱动 sub_140054D4C
// 遍历句柄表链表，填充 56 字节每项的句柄条目
_QWORD *EnumerateObjectHandles(unsigned int *OutputBuffer, unsigned int MaxEntries)
{
    unsigned __int8 (__fastcall *CheckFunc)(_QWORD *);
    unsigned int TableCount;
    _QWORD *TableBase;
    _QWORD *TableEnd;
    _QWORD *SyscallCheckPtr;
    __int64 Remaining;
    _QWORD *CurrentEntry;
    unsigned int LoopCount;
    _QWORD *Entry;
    __int64 ObjectHeader;

    CheckFunc = (unsigned __int8 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    TableCount = (ULONG)GtRead(GtKernelDataField09);
    TableBase = (_QWORD *)GtRead(GtKernelDataField08);
    if (!CheckFunc || !TableBase)
        return TableBase;
    SyscallCheckPtr = (_QWORD *)GtRead(GtKernelDataField11);
    if (!SyscallCheckPtr)
    {
        ResolveSyscallNumberFromKernel();
        SyscallCheckPtr = (_QWORD *)GtRead(GtKernelDataField11);
    }
    if (!TableCount)
        return SyscallCheckPtr;

    TableEnd = TableBase + 1;
    Remaining = TableCount;
    do
    {
        CurrentEntry = (_QWORD *)*TableEnd;
        LoopCount = 0;
        LoopCount = 0;
        if ((_QWORD *)*TableEnd == TableBase)
            goto Advance;
        do
        {
            if (*OutputBuffer >= MaxEntries)
                break;
            if (LoopCount >= 0x10000)
                break;
            Entry = CurrentEntry - 4;
            if (!CurrentEntry || CheckFunc(CurrentEntry) != 1 || CheckFunc(CurrentEntry - 4) != 1)
                break;
            if (SyscallCheckPtr
                && CheckFunc(CurrentEntry - 10) == 1
                && CheckFunc((_QWORD *)((char *)Entry + 263)) == 1
                && *(CurrentEntry - 8) == *SyscallCheckPtr
                && (_QWORD *)Entry[6] == Entry + 19
                && *((_BYTE *)Entry + 240) == 1)
            {
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = (_QWORD)Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = Entry[14];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
                ObjectHeader = Entry[6];
                if (ObjectHeader)
                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(ObjectHeader + 24);
                if (*(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] < (unsigned __int64)MmSystemRangeStart)
                {
                    unsigned int ProcessEprocess = (ULONG)GtRead(GtProcessEprocess);
                    unsigned int ProcessCreateTime = (ULONG)GtRead(GtProcessCreateTime);
                    unsigned int ProcessCreateTimeCopy = ProcessCreateTime;
                    if (ProcessEprocess != -1)
                    {
                        if (ProcessCreateTime)
                        {
                            _QWORD *ProcessPtr = (_QWORD *)Entry[9];
                            if (CheckFunc(ProcessPtr) == 1
                                && CheckFunc((_QWORD *)((char *)ProcessPtr + ProcessEprocess + 3)) == 1
                                && CheckFunc((_QWORD *)((char *)ProcessPtr + ProcessCreateTimeCopy + 3)) == 1)
                            {
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = *(unsigned int *)((char *)ProcessPtr + ProcessEprocess);
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = *(unsigned int *)((char *)ProcessPtr + ProcessCreateTimeCopy);
                            }
                        }
                    }
                    LoopCount = LoopCount;
                }
            }
            else
            {
                ObjectHeader = Entry[6];
                if (!ObjectHeader || !*(_QWORD *)(ObjectHeader + 24))
                    goto Next;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = (_QWORD)Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(ObjectHeader + 24);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
            }
            ++*OutputBuffer;
Next:
            CurrentEntry = (_QWORD *)CurrentEntry[1];
            MaxEntries = MaxEntries;
            LoopCount = ++LoopCount;
        }
        while (CurrentEntry != TableBase);
        TableEnd = TableEnd;
        Remaining = Remaining;
Advance:
        TableEnd += 3;
        TableBase += 3;
        Remaining = --Remaining;
    }
    while (Remaining);
    return TableEnd;
}

// EnumObjectHandlesWin8Plus — 枚举对象句柄（Win8+ 版）
// 对应原始驱动 sub_140055374
// 从 GT 714 获取句柄表，遍历句柄表条目，解码句柄并填充 56 字节每项
__int64 EnumObjectHandlesWin8Plus(unsigned int *OutputBuffer, unsigned int MaxEntries)
{
    _QWORD *TableBase;
    __int64 (__fastcall *CheckFunc)(_QWORD *);
    unsigned int TableCount;
    unsigned int TableOffset;
    unsigned int ObjectTableCode;
    unsigned int StepSize;
    __int64 Remaining;
    _QWORD **TablePtr;
    _QWORD *Entry;
    unsigned int i;
    unsigned int StepSizeBackup;
    _QWORD *TableBaseBackup;

    TableBase = (_QWORD *)GtRead(GtCallbackField00);
    TableBaseBackup = TableBase;
    CheckFunc = (__int64 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    TableCount = (ULONG)GtRead(GtEprocessField33 | 0x800);
    TableOffset = (ULONG)GtRead(GtEprocessField34 | 0x800);
    StepSize = TableOffset;

    if (CheckFunc && TableBase && TableCount && TableOffset)
    {
        ObjectTableCode = (unsigned int)GetObjectTableCode();
        if (TableCount > ObjectTableCode)
            TableCount = ObjectTableCode;
        StepSize = (ULONG)GtRead(GtWindowsBuildNumber) < 0x4A61 ? 256 : 512;
        StepSizeBackup = StepSize;
        if (TableCount)
        {
            Remaining = TableCount;
            do
            {
                if (*TableBase > (unsigned __int64)MmSystemRangeStart && StepSize)
                {
                    __int64 StepCounter = StepSize;
                    TablePtr = (_QWORD **)(*TableBase + TableOffset + 8);
                    do
                    {
                        Entry = *TablePtr;
                        for (i = 0; (_QWORD *)Entry != (_QWORD *)TablePtr; ++i)
                        {
                            if (*OutputBuffer >= MaxEntries)
                                break;
                            if (i >= 0x10000)
                                break;
                            Entry = Entry - 4;
                            if (CheckFunc(Entry - 4) != 1)
                                break;
                            if (CheckFunc((_QWORD *)((char *)Entry + 63)) != 1)
                                break;
                            __int64 Decoded = DecodeObjectHandleEntry((__int64)(Entry - 4));
                            if (Decoded)
                            {
                                if (*(_QWORD *)(Decoded + 24))
                                {
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = (_QWORD)Entry;
                                    OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(Decoded + 24);
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = 0;
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
                                    ++*OutputBuffer;
                                }
                            }
                            Entry = (_QWORD *)*Entry;
                        }
                        TablePtr += 4;
                        --StepCounter;
                    }
                    while (StepCounter);
                    StepSize = StepSizeBackup;
                    TableBase = TableBaseBackup;
                    Remaining = Remaining;
                    TableOffset = StepSize;
                }
                ++TableBase;
                Remaining = --Remaining;
                TableBaseBackup = TableBase;
            }
            while (Remaining);
        }
    }
    return 0;
}

// ResolveHandleEntry — 解析句柄条目
// 对应原始驱动 sub_140085630
// 通过句柄值查询对象名称和类型信息，跨进程附加执行 IOCTL 查询
char ResolveHandleEntry(unsigned __int16 *HandleEntry, _BYTE *OutputBuffer, unsigned int BufferSize)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    char Result = 0;
    unsigned __int8 (__fastcall *CheckFunc)(_QWORD *);
    int (__fastcall *ValidateTypeFunc)(_QWORD, struct _KPROCESS **);
    struct _KPROCESS **ObjectTypeInfo;
    __int64 HandleValue;
    _QWORD *ObjectHeader;
    __int64 HandleValue2;
    PEPROCESS CurrentProcess;
    bool IsDifferentProcess;
    unsigned __int8 RefCount;
    struct _KPROCESS *TargetProcess;
    unsigned __int8 DefaultRefCount = 0;
    unsigned int BufferSizeCopy;
    char IoctlReturnBuf[8];
    void (__fastcall *AttachProcessFunc)(struct _KPROCESS *, _BYTE *);
    _BYTE *OutputBufferCopy;
    void (__fastcall *CloseHandleFunc)(struct _KPROCESS *);
    void (__fastcall *DetachProcessFunc)(_BYTE *);
    _BYTE ApcState[48];

    BufferSizeCopy = BufferSize;
    OutputBufferCopy = OutputBuffer;
    CheckFunc = (unsigned __int8 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    ValidateTypeFunc = (int (__fastcall *)(_QWORD, struct _KPROCESS **))GtRead(GtValidateObjectTypeFunc);
    CloseHandleFunc = (void (__fastcall *)(struct _KPROCESS *))GtRead(GtCloseHandleFunc);
    ObjectTypeInfo = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
    AttachProcessFunc = (void (__fastcall *)(struct _KPROCESS *, _BYTE *))GtRead(GtCreateObjectTypeFunc);
    DetachProcessFunc = (void (__fastcall *)(_BYTE *))GtRead(GtCloseObjectTypeFunc);

    if (CheckFunc && ValidateTypeFunc && CloseHandleFunc && AttachProcessFunc && DetachProcessFunc)
    {
        HandleValue = *((_QWORD *)HandleEntry + 1);
        if (BuildNumber >= 0x1770)
            HandleValue &= 0xFFFFFFFFFFFFFFF0ULL;
        if ((unsigned __int64)HandleValue > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid((PVOID)HandleValue) == 1)
        {
            ObjectHeader = (_QWORD *)(HandleValue - 48);
            if (ObjectHeader)
            {
                if (CheckFunc(ObjectHeader) == 1 && *ObjectHeader && ValidateTypeFunc(*HandleEntry, &TargetProcess) >= 0)
                {
                    HandleValue2 = HandleEntry[3];
                    if (BuildNumber >= 0x1DB0 && ObjectTypeInfo && *ObjectTypeInfo == TargetProcess)
                        HandleValue2 |= 0xFFFFFFFF80000000ULL;
                    CurrentProcess = IoGetCurrentProcess();
                    IsDifferentProcess = CurrentProcess != TargetProcess;
                    if (CurrentProcess != TargetProcess)
                    {
                        RefCount = ReferenceObjectSafe((__int64)TargetProcess);
                        AttachProcessFunc(TargetProcess, ApcState);
                    }
                    else
                    {
                        RefCount = DefaultRefCount;
                    }
                    if (CheckHandleEntryValid((__int64)TargetProcess))
                    {
                        Result = SendIoControlWithQueryBuffer(HandleValue2, 3, OutputBuffer, BufferSize, (size_t *)IoctlReturnBuf);
                        if (!Result)
                        {
                            __int64 CallbackFunc = GtRead(GtEprocessField104 | 0x100);
                            AttachProcessFunc = (void (__fastcall *)(struct _KPROCESS *, _BYTE *))CallbackFunc;
                            unsigned int ServiceCount = (ULONG)GtRead(GtSdstServiceCount);
                            if (CallbackFunc && ServiceCount != -1)
                            {
                                struct _KTHREAD *CurrentThread = KeGetCurrentThread();
                                __int64 BufferSize2 = BufferSize;
                                _BYTE *OutputBuffer2 = OutputBuffer;
                                __int64 ServiceCountBak = ServiceCount;
                                char SavedFlag = *((_BYTE *)CurrentThread + ServiceCount);
                                *((_BYTE *)CurrentThread + ServiceCount) = 0;
                                int QueryResult = (int)((__int64 (__fastcall *)(__int64, __int64, _BYTE *, __int64, char *))AttachProcessFunc)(HandleValue2, 3, OutputBuffer2, BufferSize2, IoctlReturnBuf);
                                *((_BYTE *)CurrentThread + ServiceCountBak) = SavedFlag;
                                QueryResult = QueryResult >= 0;
                            }
                        }
                        ReturnFalseStub();
                    }
                    if (IsDifferentProcess)
                    {
                        DetachProcessFunc(ApcState);
                        if (RefCount == 1)
                            DereferenceObjectSafe((__int64)TargetProcess);
                    }
                    CloseHandleFunc(TargetProcess);
                }
            }
        }
    }
    return Result;
}

// TraverseProcessHandleTableWin7 — 遍历进程句柄表（Win7 版）
// 对应原始驱动 sub_1400719C4
// 三级页表结构遍历所有句柄条目并调用回调函数
char TraverseProcessHandleTableWin7(
    __int64 HandleTable,
    __int64 OutputBuffer,
    unsigned int BufferSize,
    void (__fastcall *Callback)(__int64, __int64, _QWORD, __int64),
    __int64 Context)
{
    _QWORD ***Level1Table;
    char Result = 0;
    __int64 Level1Count;
    _QWORD **Level2Table;
    __int64 Level2Count;
    _QWORD *Level3Table;
    __int64 Level3Count;
    __int64 Level1CountBak;

    Level1Table = *(_QWORD ****)(HandleTable + 8);
    if (Level1Table)
    {
        Level1Count = 256;
        Level1CountBak = 256;
        do
        {
            Level2Table = *Level1Table;
            if (*Level1Table)
            {
                Level2Count = 256;
                do
                {
                    Level3Table = *Level2Table;
                    if (*Level2Table)
                    {
                        Level3Count = 256;
                        do
                        {
                            if (*Level3Table)
                                Callback(*Level3Table | 0x80000000LL, OutputBuffer, BufferSize, Context);
                            Result = 1;
                            Level3Table += 2;
                            --Level3Count;
                        }
                        while (Level3Count);
                    }
                    ++Level2Table;
                    --Level2Count;
                }
                while (Level2Count);
                Level1Count = Level1CountBak;
            }
            ++Level1Table;
            Level1CountBak = --Level1Count;
        }
        while (Level1Count);
    }
    return Result;
}

// TraverseProcessHandleTableWin10 — 遍历进程句柄表（Win10 版）
// 对应原始驱动 sub_140071A78
// 根据构建号选择句柄表字段偏移，按句柄表条目低 2 位标志位选择三级深度遍历
char TraverseProcessHandleTableWin10(
    __int64 *HandleTable,
    __int64 OutputBuffer,
    unsigned int BufferSize,
    __int64 (__fastcall *Callback)(unsigned __int64, __int64, _QWORD, __int64),
    __int64 Context)
{
    char Result = 0;
    __int64 TableValue;
    int Flags;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x23F0)
        TableValue = HandleTable[1];
    else
        TableValue = *HandleTable;

    Flags = TableValue & 3;
    if (Flags == 2)
    {
        PVOID **Level1Table = (PVOID **)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        PVOID **Level1TableBak = Level1Table;
        if (Level1Table)
        {
            __int64 Level1Count = 128;
            __int64 Level1CountBak = 128;
            do
            {
                PVOID *Level2Entry = *Level1Table;
                if (*Level1Table)
                {
                    __int64 Level2Count = 512;
                    __int64 Level2CountBak = 512;
                    PVOID *Level2TableBak = *Level1Table;
                    do
                    {
                        if (MmIsAddressValid(Level2TableBak) == 1)
                        {
                            __int64 *Level3Table = (__int64 *)*Level2Entry;
                            if (*Level2Entry && MmIsAddressValid(*Level2Entry) == 1)
                            {
                                __int64 Level3Count = 256;
                                do
                                {
                                    DecodeObjectPointerFromHandleEntry(Level3Table, OutputBuffer, BufferSize, Callback, Context);
                                    Level3Table += 2;
                                    --Level3Count;
                                }
                                while (Level3Count);
                                Result = 1;
                                Level2Count = Level2CountBak;
                            }
                        }
                        ++Level2TableBak;
                        ++Level2Entry;
                        Level2CountBak = --Level2Count;
                    }
                    while (Level2Count);
                    Level1Table = Level1TableBak;
                    Level1Count = Level1CountBak;
                }
                ++Level1Table;
                Level1CountBak = --Level1Count;
                Level1TableBak = Level1Table;
            }
            while (Level1Count);
        }
    }
    else if (Flags == 1)
    {
        __int64 **Level1Table2 = (__int64 **)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        if (Level1Table2)
        {
            __int64 Level1Count2 = 512;
            do
            {
                __int64 *Level2Table2 = *Level1Table2;
                if (*Level1Table2)
                {
                    __int64 Level2Count2 = 256;
                    do
                    {
                        DecodeObjectPointerFromHandleEntry(Level2Table2, OutputBuffer, BufferSize, Callback, Context);
                        Level2Table2 += 2;
                        --Level2Count2;
                    }
                    while (Level2Count2);
                    Result = 1;
                }
                ++Level1Table2;
                --Level1Count2;
            }
            while (Level1Count2);
        }
    }
    else if ((TableValue & 3) == 0)
    {
        __int64 *EntryTable = (__int64 *)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        if (EntryTable)
        {
            Result = 1;
            __int64 EntryCount = 256;
            do
            {
                DecodeObjectPointerFromHandleEntry(EntryTable, OutputBuffer, BufferSize, Callback, Context);
                EntryTable += 2;
                --EntryCount;
            }
            while (EntryCount);
        }
    }
    return Result;
}

// EnumProcessHandleTable — 枚举进程句柄表
// 对应原始驱动 sub_140054848
// 通过解码 Unicode 字符串查找进程句柄表偏移，写入 GT 0x299/0x29A/0x29B
void EnumProcessHandleTable(void)
{
    __int64 TargetProcess;
    __int64 CurrentProc;
    __int64 rsi;
    unsigned int r15d;
    __int64 rbx;
    __int64 rcx;
    __int64 r13;
    __int64 r14;
    int esi;
    int ecx;
    _WORD DecodeBuffer[24];
    KAPC_STATE ApcState;

    TargetProcess = GtRead(0x61);
    CurrentProc = (__int64)IoGetCurrentProcess();
    if (TargetProcess == CurrentProc)
        TargetProcess = 0;

    if (TargetProcess)
        KeStackAttachProcess((PRKPROCESS)TargetProcess, &ApcState);

    rsi = GtRead(0x20);
    r15d = (ULONG)GtRead(0x21);
    rbx = GtRead(3);
    rcx = GtRead(0x42B8);

    if (rsi && r15d && rbx && rcx && rcx < r15d)
    {
        r13 = *(__int64 *)((char *)rsi + *(int *)((char *)rsi + 0x3C) + 0x30);
        rbx = rcx + rsi;
        r14 = r15d + rsi;
        esi = 0;

        // First loop: find matching entries
        while (1)
        {
            if (!DecodeUnicodeChar((unsigned __int8 *)rbx, r14, DecodeBuffer))
                break;
            rbx += *(unsigned int *)((char *)DecodeBuffer + 24);
            __int64 TableEntry = *(__int64 *)((char *)DecodeBuffer + 40);
            ecx = *(int *)TableEntry;
            int eax = *(int *)((char *)DecodeBuffer + 12);
            if ((ecx == 0x107C && eax < 0) || (ecx == 0x1096 && eax < 0))
                break;
            esi++;
            if (esi >= 0x50)
                goto Done;
        }

        // Found match - resolve offsets
        int Value = 0x100;
        int r12d = 0;
        esi = 0;
        while (1)
        {
            if (!DecodeUnicodeChar((unsigned __int8 *)rbx, r14, DecodeBuffer))
                break;
            rbx += *(unsigned int *)((char *)DecodeBuffer + 24);
            __int64 TableEntry = *(__int64 *)((char *)DecodeBuffer + 40);
            ecx = *(int *)TableEntry;
            if (ecx == 0x1024 || ecx == 0x1285)
            {
                if (*(int *)((char *)DecodeBuffer + 16) == 0x7F)
                    Value = 0x80;
                if (*(int *)((char *)DecodeBuffer + 16) == 0x1FF)
                    r12d = 1;
                if (!DecodeUnicodeChar((unsigned __int8 *)rbx, r14, DecodeBuffer))
                    break;
                if (r12d)
                {
                    if (*(int *)TableEntry != 0x1080)
                        goto Next;
                    int Diff = *(int *)((char *)DecodeBuffer + 12);
                    if (Diff <= r13)
                        goto Next;
                    Diff -= (int)r13;
                    goto WriteGt;
                }
                else
                {
                    if (*(int *)TableEntry != 0x1270)
                        goto Next;
                    if (!DecodeUnicodeChar((unsigned __int8 *)rbx, r14, DecodeBuffer))
                        break;
                    if (*(int *)TableEntry != 0x1037)
                        goto Next;
                    int Diff = *(int *)((char *)DecodeBuffer + 12);
                    if (Diff <= r13)
                        goto Next;
                    Diff -= (int)r13;
                    Diff -= 0xC;
WriteGt:
                    if (Diff && (unsigned int)Diff < r15d)
                    {
                        GtWrite(0x299, rbx + Diff);
                        GtWrite(0x29A, Value);
                        GtWrite(0x29B, r12d);
                    }
                }
            }
Next:
            esi++;
            if (esi >= 0xA)
                break;
        }
    }

Done:
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
}

// =========================================================================
// ResolveSyscallTableEntry — 解析系统调用表条目
// 对应原始驱动 sub_140054AD0
// 附加到 CSRSS 进程，读取 ntoskrnl 映射和系统调用号表，查找特定系统调用的内核地址偏移
// =========================================================================
void ResolveSyscallTableEntry(void)
{
    struct _KPROCESS *TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    KAPC_STATE ApcState;

    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    __int64 KernelBase = GtRead(GtEprocessField22);
    unsigned int KernelSize = (unsigned int)GtRead(GtEprocessField23);
    unsigned int ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    __int64 NtosBase = GtRead(GtNtoskrnlModuleBase);
    __int64 SyscallTable = GtRead(GtEprocessField88);

    if (!SyscallTable)
    {
        ResolveSyscallNumbers();
        SyscallTable = GtRead(GtEprocessField88);
    }

    if (KernelBase && KernelSize && NtosBase && SyscallTable)
    {
        __int64 PeExportDir = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 0x48);
        unsigned int SyscallIndex = (unsigned int)GtRead(GtUninstallHookSyscallPeOffset | GtEprocessField140) + 1;

        if (SyscallIndex > 1 && SyscallIndex + 4 < (unsigned __int64)KernelSize)
        {
            unsigned int SyscallNum = *(unsigned int *)((unsigned __int64)SyscallIndex + KernelBase);
            if (SyscallNum && SyscallNum < ServiceCount)
            {
                unsigned __int64 SyscallAddr = *(_QWORD *)(SyscallTable + 8 * SyscallNum);
                if (SyscallAddr > (unsigned __int64)PeExportDir)
                {
                    unsigned int Offset = (unsigned int)(SyscallAddr - PeExportDir);
                    if (Offset < KernelSize && SyscallAddr == PeExportDir + Offset)
                    {
                        GtWrite(GtKernelDataField12, Offset);
                        GtWrite(GtKernelDataField13, (__int64)(SyscallAddr + NtosBase));
                    }
                }
            }
        }
    }

    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
}

// =========================================================================
// ResolveSyscallNumberFromKernel — 从内核解析系统调用号
// 对应原始驱动 sub_140054650
// 附加到目标进程，从 PE 文件中解码 Unicode 字符串，查找匹配特殊标记的代码位置
// =========================================================================
void ResolveSyscallNumberFromKernel(void)
{
    struct _KPROCESS *TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    KAPC_STATE ApcState;
    int LoopCount = 0;

    unsigned int KernelDataField12 = (unsigned int)GtRead(GtKernelDataField12);
    if (!KernelDataField12)
    {
        ResolveSyscallTableEntry();
        KernelDataField12 = (unsigned int)GtRead(GtKernelDataField12);
    }

    if (!KernelDataField12)
        return;

    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    __int64 KernelBase = GtRead(GtEprocessField22);
    unsigned int KernelSize = (unsigned int)GtRead(GtEprocessField23);
    __int64 NtosBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int TotalSizeOr = (unsigned int)GtRead(GtTotalSize | GtEprocessField187 | 0x100);

    if (KernelBase && KernelSize && NtosBase && TotalSizeOr && KernelDataField12 < KernelSize)
    {
        __int64 PeExportDir = *(_QWORD *)(*(int *)(KernelBase + 60) + KernelBase + 0x48);
        unsigned __int8 *ScanPos = (unsigned __int8 *)(KernelBase + KernelDataField12);
        unsigned __int8 *PrevResult1 = 0;
        unsigned __int8 *PrevResult2 = 0;
        unsigned __int8 *PrevPos = 0;
        _WORD DecodeResult[24];

        while (DecodeUnicodeChar(ScanPos, KernelBase + KernelSize, DecodeResult))
        {
            PrevResult2 = PrevResult1;
            PrevResult1 = PrevPos;
            PrevPos = ScanPos;
            ScanPos += *(unsigned int *)((char *)DecodeResult + 24);

            __int64 TableEntry = *(__int64 *)((char *)DecodeResult + 40);
            int TokenValue = *(int *)TableEntry;
            int OffsetValue = *(int *)((char *)DecodeResult + 12);
            int AbsoluteOffset = OffsetValue + (int)(ScanPos - (unsigned __int8 *)KernelBase);

            if (TokenValue == 4301 && AbsoluteOffset == TotalSizeOr)
            {
                if (PrevResult2 && DecodeUnicodeChar(PrevResult2, KernelBase + KernelSize, DecodeResult))
                {
                    __int64 TableEntry2 = *(__int64 *)((char *)DecodeResult + 40);
                    if (*(int *)TableEntry2 == 4534)
                    {
                        int EntryOffset = *(int *)((char *)DecodeResult + 12);
                        if (EntryOffset > (int)PeExportDir && EntryOffset - (int)PeExportDir < (int)KernelSize)
                        {
                            GtWrite(GtKernelDataField11, NtosBase + (unsigned int)(EntryOffset - (int)PeExportDir));
                        }
                    }
                }
                break;
            }

            if (++LoopCount >= 0x100)
                break;
        }
    }

    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
}

// EnumerateAllProcesses — 枚举所有进程
// 对应原始驱动 sub_14004AFA0
// 分配 0x3000 字节缓冲区，遍历内核虚拟地址范围，每 0x1000 步长检查地址有效性。
// 对每个有效地址验证进程对象完整性并调用 EnumerateProcessObjects 填充输出。
char EnumerateAllProcesses(unsigned int *OutputBuffer, unsigned int BufferSize)
{
    char *Buffer;
    __int64 (__fastcall *NtQuerySysInfoFunc)(_QWORD, PVOID, _QWORD, _QWORD);
    __int64 (__fastcall *GetOffsetFunc)(__int64);
    __int64 (__fastcall *ValidateFunc)(__int64, __int64, __int64);
    unsigned int ServiceCount;
    __int64 (__fastcall *pCallbackFunc)(__int64);
    __int64 (__fastcall *CheckTypeFunc)(__int64);
    __int64 (__fastcall *v2Func)(__int64);
    unsigned int FieldOffset4A;
    __int64 FieldOffset4166;
    __int64 Src;
    __int64 Dst[2];
    __int64 EndAddr;
    __int64 ScanSize;
    int StepSize;
    int PageCount, PageSize, PageSizeAlt;
    char NtBuf[0x40];
    char ValidatedFlag;
    unsigned int StepSize2;
    unsigned int StepSizeReg;
    unsigned int RangeSize;
    __int64 CurrentThread;
    __int64 FieldOffset;
    __int64 CallbackFunc;
    __int64 BufferPtr;

    Buffer = (char *)ExAlloc(PagedPool, 0x3000);
    if (!Buffer)
        return 0;

    memset(Buffer, 0, 0x3000);

    NtQuerySysInfoFunc = (__int64 (__fastcall *)(_QWORD, PVOID, _QWORD, _QWORD))GtRead(0x41DE);
    GetOffsetFunc = (__int64 (__fastcall *)(__int64))GtRead(0x41E4);
    ValidateFunc = (__int64 (__fastcall *)(__int64, __int64, __int64))GtRead(0x41E1);
    ServiceCount = (ULONG)GtRead(0x27);
    pCallbackFunc = (__int64 (__fastcall *)(__int64))GtRead(0x41DB);
    CheckTypeFunc = (__int64 (__fastcall *)(__int64))GtRead(3);
    v2Func = (__int64 (__fastcall *)(__int64))GtRead(2);
    FieldOffset4A = (ULONG)GtRead(0x4A);
    FieldOffset4166 = GtRead(0x4166);
    ULONG Gt914 = (ULONG)GtRead(0x914);

    if (!v2Func || !FieldOffset4A || !FieldOffset4166 || !CheckTypeFunc || !NtQuerySysInfoFunc || !GetOffsetFunc || !ValidateFunc || ServiceCount == -1)
    {
        ExFree(Buffer);
        return 0;
    }

    memset(NtBuf, 0, 0x40);
    CurrentThread = (__int64)KeGetCurrentThread();
    FieldOffset = FieldOffset4166;
    CallbackFunc = (__int64)pCallbackFunc;
    BufferPtr = (__int64)Buffer;
    char SavedFlag = *(_BYTE *)(CurrentThread + ServiceCount);
    *(_BYTE *)(CurrentThread + ServiceCount) = 0;
    NtQuerySysInfoFunc(0, NtBuf, 0x40, 0);
    *(_BYTE *)(CurrentThread + ServiceCount) = SavedFlag;

    PageCount = *(int *)&NtBuf[0x18];
    PageSize = *(int *)&NtBuf[0x1C];
    PageSizeAlt = *(int *)&NtBuf[0x24];

    if (Gt914 >= 0x4F7C)
        PageSize = PageSizeAlt;
    else if (PageSize > PageSizeAlt)
        PageSize = PageSizeAlt;

    ScanSize = PageCount * PageSize;
    StepSize = 0xFD0 - (int)FieldOffset;
    StepSize2 = StepSize;

    GetKernelVirtualAddressRange((__int64)&Src, (unsigned __int64 *)Dst, (unsigned __int64 *)&EndAddr);

    StepSizeReg = StepSize;
    RangeSize = 0x1000;
    ValidatedFlag = 0;

    for (__int64 CurrentAddr = Src; CurrentAddr < EndAddr; CurrentAddr += 0x1000)
    {
        if (ValidatedFlag)
        {
            __int64 ScanAddr = CurrentAddr + 0x1000;
            ValidatedFlag = 0;
            RangeSize = 0x1000;
            StepSize = StepSizeReg;

            if (CheckTypeFunc(ScanAddr) == 1
                && CallRegisteredCallback(ScanAddr) == 1)
            {
                __int64 Offset = GetOffsetFunc(ScanAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue((__int64)CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc((__int64)ValidateFunc, ScanAddr, Offset) == 1)
                {
                    ValidatedFlag = 1;
                    StepSize = StepSizeReg + 0x1000;
                    RangeSize = 0x2000;
                }
            }

            if (CheckTypeFunc(CurrentAddr) == 1
                && CallRegisteredCallback(CurrentAddr) == 1)
            {
                __int64 Offset = GetOffsetFunc(CurrentAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue((__int64)CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc((__int64)ValidateFunc, CurrentAddr, Offset) == 1)
                {
                    ValidatedFlag = 1;
                    StepSize = StepSize2 + 0x1000;
                    RangeSize = 0x2000;
                }
            }

            if (ValidatedFlag
                && CheckTypeFunc(CurrentAddr) == 1
                && CheckTypeFunc(CurrentAddr + RangeSize - 1) == 1)
            {
                memmove(Buffer, (void *)CurrentAddr, 0x1000);
                EnumerateProcessObjects(
                    (struct _KPROCESS *)(Buffer + 0x30),
                    (struct _KPROCESS *)(Buffer + 0x30),
                    OutputBuffer, BufferSize, 1, 0, 0);

                // Inner loop: scan through buffer entries
                unsigned int InnerIndex = 0;
                while (InnerIndex <= (unsigned int)(ULONG_PTR)pCallbackFunc)
                {
                    StepSizeReg = 0;
                    char *EntryBuf = Buffer + InnerIndex;
                    char IsMatch = 0;

                    if (Gt914 >= 0x1DB0)
                    {
                        char TypeFlag = CheckObjectTypeFlag((__int64)(EntryBuf + 0x30));
                        if ((UCHAR)GtRead(0x81B) == TypeFlag)
                            IsMatch = 1;
                    }
                    else
                    {
                        if (v2Func && *(__int64 *)v2Func == *(__int64 *)(EntryBuf + 0x10))
                            IsMatch = 1;
                    }

                    if (IsMatch)
                    {
                        char *ValidateAddr = (char *)CurrentAddr + 0x30 + StepSizeReg;
                        if (ValidateProcessObject((struct _KPROCESS *)(EntryBuf + 0x30), (struct _KPROCESS *)ValidateAddr) == 1)
                        {
                            EnumerateProcessObjects(
                                (struct _KPROCESS *)(EntryBuf + 0x30),
                                (struct _KPROCESS *)ValidateAddr,
                                OutputBuffer, BufferSize, 1, 0, 0);
                            InnerIndex += StepSize2;
                        }
                    }
                    InnerIndex += 8;
                }
            }
        }
        else
        {
            if (CheckTypeFunc(CurrentAddr) == 1
                && CallRegisteredCallback(CurrentAddr) == 1)
            {
                __int64 Offset = GetOffsetFunc(CurrentAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue((__int64)CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc((__int64)ValidateFunc, CurrentAddr, Offset) == 1)
                {
                    ValidatedFlag = 1;
                }
            }
        }
    }

    ExFree(Buffer);
    return 0;
}

// FindCsrssProcessEntry — 查找 CSRSS 进程条目
// 对应原始驱动 sub_140049E28
// 遍历进程虚拟化上下文表，查找 csrss.exe 进程，选择创建时间最早的进程对象
unsigned __int64 FindCsrssProcessEntry(unsigned int *OutputBuffer)
{
    unsigned int Count;
    __int64 Result = 0;
    unsigned __int64 MinCreateTime = -1;
    __int64 CsrssProcess = 0;
    _DWORD EncodedCsrss[6];
    unsigned int *Entry;
    __int64 Remaining;
    WORD *LastChar;
    __int64 NamePtr;

    EncodedCsrss[0] = 7536739;
    EncodedCsrss[1] = 7536754;
    EncodedCsrss[2] = 3014771;
    EncodedCsrss[3] = 7864421;
    EncodedCsrss[4] = 101;

    Count = *OutputBuffer;
    if (Count)
    {
        Entry = OutputBuffer + 12;
        Remaining = Count;
        do
        {
            LastChar = WStringFindLastChar((WORD *)Entry, 92);
            if (LastChar)
                NamePtr = (__int64)(LastChar + 1);
            else
                NamePtr = (__int64)Entry;
            if (!WStringCompareCaseInsensitive((__int64)EncodedCsrss, NamePtr) && *((_QWORD *)Entry - 3) < MinCreateTime)
            {
                CsrssProcess = *((_QWORD *)Entry - 1);
                MinCreateTime = *((_QWORD *)Entry - 3);
            }
            Entry += 138;
            --Remaining;
        }
        while (Remaining);
        if (MinCreateTime != -1)
        {
            if (!GtRead(GtObjectTypeField15))
                GtWrite(GtObjectTypeField15, CsrssProcess);
            return MinCreateTime;
        }
    }
    return Result;
}

// GetProcessVirtualizationContextFallback — 获取进程虚拟化上下文（回退版本）
// 对应原始驱动 sub_140049CD0
// 通过 Fiber 获取当前线程信息，构建进程虚拟化上下文条目
char GetProcessVirtualizationContextFallback(_DWORD *OutputBuffer, unsigned int BufferSize)
{
    _QWORD *CurrentFiber;
    __int64 FiberValue;
    unsigned int VirtualAddr;
    unsigned int PageOffset;
    unsigned int PageTable;
    unsigned __int8 (__fastcall *CheckFunc)(__int64);
    unsigned __int8 (__fastcall *CheckFunc2)(__int64);
    __int64 PageTableEntry;
    __int64 OutputCount;
    __int64 EntryIndex;
    __int64 FieldValue;
    unsigned int FieldOffset;

    CurrentFiber = (_QWORD *)KeGetCurrentThread();
    if (CurrentFiber)
    {
        FiberValue = CurrentFiber[3];
        VirtualAddr = (ULONG)GtRead(GtEprocessField132 | 0x100);
        PageOffset = (ULONG)GtRead(GtEprocessField30);
        PageTable = (ULONG)GtRead(GtProcessOffset);
        CheckFunc = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtObjectTypeCheckFlag);
        CheckFunc2 = CheckFunc;
        if (VirtualAddr)
        {
            if (PageOffset != -1 && PageTable != -1 && CheckFunc && CheckFunc(FiberValue) == 1)
            {
                PageTableEntry = (ULONG)GtRead(GtWindowsBuildNumber) >= 0x1771
                    ? *(_QWORD *)(PageTable + FiberValue)
                    : *(_QWORD *)(VirtualAddr + FiberValue + 32);
                if (CheckFunc2(PageTableEntry) == 1)
                {
                    OutputCount = *OutputBuffer;
                    if ((unsigned int)(552 * (int)OutputCount + 560) < BufferSize)
                    {
                        EntryIndex = 138 * OutputCount;
                        *(_QWORD *)&OutputBuffer[EntryIndex + 10] = PageTableEntry;
                        FieldValue = *(int *)(PageOffset + PageTableEntry);
                        *(_QWORD *)&OutputBuffer[EntryIndex + 4] = 0;
                        *(_QWORD *)&OutputBuffer[EntryIndex + 6] = FieldValue;
                        LOWORD_LV(OutputBuffer[EntryIndex + 2]) = 0;
                        FieldOffset = (ULONG)GtRead(GtEprocessField36);
                        if (FieldOffset == -1)
                            *(_QWORD *)&OutputBuffer[EntryIndex + 8] = 0;
                        else
                            *(_QWORD *)&OutputBuffer[EntryIndex + 8] = *(_QWORD *)(FieldOffset + PageTableEntry);
                        OutputBuffer[EntryIndex + 14] = 0;
                        OutputBuffer[EntryIndex + 12] = 6553673;
                        OutputBuffer[EntryIndex + 13] = 6619244;
                        ++*OutputBuffer;
                    }
                }
            }
        }
    }
    return 0;
}

// QueryProcessVirtualization — 查询进程虚拟化状态
// 对应原始驱动 sub_140049F18
// 通过 ZwQueryInformationProcess 获取虚拟化信息，查询系统信息匹配会话 ID
void QueryProcessVirtualization(void)
{
    PEPROCESS CurrentProcess;
    __int16 SessionId;
    __int64 (__fastcall *QueryInfoFunc)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *);
    _QWORD *BufferPtr;
    __int64 (__fastcall *ExFreeFunc)(__int64);
    unsigned int EntryIndex;
    __int16 *SystemInfo;
    __int16 *PageTable;
    unsigned int EntryCount;
    __int16 *SysInfoEntry;
    unsigned int TypeFlag;
    char BoolFlag;
    __int64 VirtualizationInfo;

    CurrentProcess = IoGetCurrentProcess();
    SessionId = (__int16)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField86);
    QueryInfoFunc = (__int64 (__fastcall *)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54);
    BufferPtr = (_QWORD *)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
    ExFreeFunc = (__int64 (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);
    EntryIndex = 0;
    if (QueryInfoFunc && BufferPtr && ExFreeFunc)
    {
        BoolFlag = 0;
        if (QueryInfoFunc(CurrentProcess, 512, 0, 0x80000000, *BufferPtr, BoolFlag, &VirtualizationInfo) >= 0)
        {
            SystemInfo = (__int16 *)AllocExBufferAndQuerySystemInfo(0x10);
            PageTable = SystemInfo;
            if (SystemInfo)
            {
                EntryCount = *(_DWORD *)SystemInfo;
                if (*(_DWORD *)SystemInfo)
                {
                    SysInfoEntry = SystemInfo + 4;
                    while (SysInfoEntry[3] != (__int16)VirtualizationInfo || !CompareInt16Equal(*SysInfoEntry, SessionId))
                    {
                        ++EntryIndex;
                        SysInfoEntry += 12;
                        if (EntryIndex >= EntryCount)
                            goto Cleanup;
                    }
                    TypeFlag = (UCHAR)(PageTable[12 * EntryIndex + 6]);
                    GtWrite(GtEprocessField61, 1);
                    GtWrite(GtEprocessField62, TypeFlag);
                }
            Cleanup:
                ExFree(PageTable);
            }
            ExFreeFunc(VirtualizationInfo);
        }
    }
}

// DecodeObjectPointerFromHandleEntry — 从句柄表条目解码对象指针
// 对应原始驱动 sub_1400718BC
// 根据 Windows 版本选择不同的指针解码方式，Win10+ 使用移位解码，之前使用掩码解码
void DecodeObjectPointerFromHandleEntry(
    __int64 *HandleEntry,
    __int64 OutputBuffer,
    unsigned int BufferSize,
    __int64 (__fastcall *Callback)(unsigned __int64, __int64, _QWORD, __int64),
    __int64 Context)
{
    unsigned __int64 DecodedPtr;
    unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);

    if (BuildNumber >= 0x23F0)
    {
        if (BuildNumber == 9200)
            DecodedPtr = (HandleEntry[0] >> 19) & 0xFFFFFFFFFFFFFFF0ULL;
        else
            DecodedPtr = (HandleEntry[0] >> 16) & 0xFFFFFFFFFFFFFFF0ULL;
    }
    else
    {
        DecodedPtr = HandleEntry[0] & 0xFFFFFFFFFFFFFFFEULL;
    }

    if (DecodedPtr)
        Callback(DecodedPtr, OutputBuffer, BufferSize, Context);
}

// ValidateHandleEntry — 验证句柄条目
// 对应原始驱动 sub_14006D324
// 读取 GT 中当前进程 EPROCESS 和进程 ID 偏移，通过 GetProcessFromHandleEntry 获取进程地址
bool ValidateHandleEntry(__int64 HandleTableEntry)
{
    unsigned int Field30 = (unsigned int)GtRead(GtEprocessField30);
    unsigned int Field38 = (unsigned int)GtRead(GtEprocessField38);

    if (Field30 && Field38 != -1)
    {
        unsigned __int64 ProcessFromHandleEntry = GetProcessFromHandleEntry(HandleTableEntry);
        return ProcessFromHandleEntry >= 8
            && ProcessFromHandleEntry != *(_QWORD *)(Field30 + HandleTableEntry)
            || *(_BYTE *)(Field38 + HandleTableEntry) == 0;
    }
    return 0;
}

// DecodeObjectHandleEntry — 解码对象句柄条目
// 对应原始驱动 sub_140055594
// 使用内核句柄表的加密密钥对句柄条目进行解密，返回解码后的对象头指针
unsigned __int64 DecodeObjectHandleEntry(__int64 HandleEntry)
{
    __int64 Result = 0;
    _QWORD *Key1 = (_QWORD *)GtRead(GtDisableHookProtectionAddr1);
    __int64 *Key2 = (__int64 *)GtRead(GtDisableHookProtectionAddr2);

    if (Key1 && Key2)
    {
        __int64 Key2Value = *Key2;
        __int64 RotatedValue = RotateLeft64Impl(*Key1, (int)(*Key1 ^ *(_QWORD *)(HandleEntry + 48)));
        return Key2Value ^ ByteSwap64(HandleEntry ^ RotatedValue);
    }
    return Result;
}

// ValidateProcessObjectBasic — 验证进程对象基础
// 对应原始驱动 sub_14004A704
// 检查进程地址有效性、类型标志、关键字段是否在有效内存范围内
bool ValidateProcessObjectBasic(char *VirtualAddress)
{
    char Result = 1;
    __int64 (*GetCurrentProcess)(void);
    int Field64, Field34, Field44;

    GetCurrentProcess = (__int64 (*)(void))GtRead(16733);
    if (GetCurrentProcess && VirtualAddress == (char *)GetCurrentProcess())
        return Result;

    Field64 = (int)GtRead(GtEprocessField64) - 1;
    if (MmIsAddressValid(VirtualAddress) == 1 && MmIsAddressValid(&VirtualAddress[Field64]) == 1)
    {
        Field34 = (int)GtRead(GtEprocessField34);
        Field44 = (int)GtRead(GtEprocessField44);
        if (*(ULONG64 *)&VirtualAddress[Field34])
            return *(ULONG64 *)&VirtualAddress[Field44] != 0;
    }

    return Result;
}

// CallRegisteredCallback — 调用已注册的回调函数
// 对应原始驱动 sub_1400777B8
bool CallRegisteredCallback(__int64 Address)
{
    unsigned __int8 (__fastcall *pCallback)(__int64);

    pCallback = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtTotalSize | GtCallbackField60);
    if (pCallback)
        return pCallback(Address) == 1;
    return 0;
}

// GetObjectTableCode — 获取对象表代码
// 对应原始驱动 sub_140079B84
__int64 GetObjectTableCode(void)
{
    unsigned int Result = 0;
    unsigned __int8 *pByte = (unsigned __int8 *)GtRead(GtNtCreateProcessPeSectionOffset | 0x100);
    if (pByte)
        Result = *pByte;
    unsigned int *pDword = (unsigned int *)GtRead(GtEprocessModuleListOffset | GtExFreeCallBackAddr);
    if (pDword)
        Result = *pDword;
    if (!Result)
        return 1;
    return Result;
}
