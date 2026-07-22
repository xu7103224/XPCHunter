// HandleMgmt.c — 句柄管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"

// 前向声明（本文件内后定义的函数被前引用）
char ValidateProcessContext(unsigned int *OutputBuffer, unsigned int BufferSize);
char EnumerateProcessHandleTable(_DWORD *OutputBuffer, unsigned int BufferSize);
char DispatchProcessHandleTableEnum(__int64 OutputBuffer, unsigned int BufferSize, void (__fastcall *Callback)(__int64, __int64, ULONG64, __int64), __int64 Context);
char GetProcessVirtualizationContext(_DWORD *OutputBuffer, unsigned int BufferSize);
char EnumerateSessionProcesses(unsigned int *OutputBuffer, unsigned int BufferSize);
char EnumerateAllProcesses(unsigned int *OutputBuffer, unsigned int BufferSize);
char ResolveHandleEntry(unsigned __int16 *HandleEntry, _BYTE *OutputBuffer, unsigned int BufferSize);
bool CompareInt16Equal(__int16 a1, __int16 a2);
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
bool CallRegisteredCallback(__int64 a1);
__int64 GetObjectTableCode(void);

// CmdEnumHandles — 枚举句柄命令
// 对应原始驱动 sub_14004ABB4
__int64 CmdEnumHandles(__int64 a1, __int64 a2, volatile void *OutputBuffer, unsigned int BufferSize)
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
    ULONG v3, v4, v7;
    UCHAR (*CheckFunc)(struct _KPROCESS *);
    int v8;
    __int64 v23;
    _QWORD ***v10;
    _QWORD **v12;
    _QWORD *v13;
    ULONG v14;
    struct _KPROCESS *v15;
    __int64 v11;
    _QWORD v26[12];
    ULONG v30;
    _QWORD **v16;
    _QWORD *v17;
    __int64 v18;
    _QWORD *v19;
    ULONG v20;
    struct _KPROCESS *v21;
    _QWORD *v24;
    __int64 v25;

    HasItems = 0;
    v3 = (ULONG)GtRead(0x41A0);
    v4 = (ULONG)GtRead(GtProcessOffset);
    CheckFunc = (UCHAR (*)(struct _KPROCESS *))GtRead(GtObjectTypeCheckFlag);

    if (!v3 || v4 == -1 || v4 <= v3 || !CheckFunc)
        return HasItems;

    v7 = v4 - v3;
    v26[0] = GtRead(GtEprocessField58);
    v26[1] = GtRead(GtEprocessField59);
    v8 = (ULONG)GtRead(GtEprocessField28) == 1 ? 1 : 32;
    v23 = GtRead(GtEprocessField60);
    v30 = v8;
    v24 = v26;
    v25 = 2;
    v10 = (_QWORD ***)v26;
    v11 = 2;

    do
    {
        v12 = *v10;
        if (v12)
        {
            v13 = *v12;
            v14 = 0;
            if (v13 != v12)
            {
                do
                {
                    if (v14 >= 0x2000) break;
                    if (CheckFunc((struct _KPROCESS *)((char *)v13 + v7)) == 1)
                    {
                        v15 = *(struct _KPROCESS **)((char *)v13 + v7);
                        if (CheckFunc(v15) == 1)
                        {
                            HasItems = 1;
                            EnumerateProcessObjects(v15, v15, OutputBuffer, BufferSize, 1, 0, 0);
                        }
                    }
                    v13 = (_QWORD *)*v13;
                    v14++;
                } while (v13 != v12);
                v10 = (_QWORD ***)v24;
                v11 = v25;
            }
        }
        v10++;
        v25 = --v11;
        v24 = (_QWORD *)v10;
    } while (v11);

    v16 = (_QWORD **)v23;
    if (v23 && v30)
    {
        v17 = (_QWORD *)v23;
        v18 = v30;
        do
        {
            v19 = *v16;
            v20 = 0;
            if (v19 != v17)
            {
                do
                {
                    if (v20 >= 0x2000) break;
                    if (CheckFunc((struct _KPROCESS *)((char *)v19 + v7)) == 1)
                    {
                        v21 = *(struct _KPROCESS **)((char *)v19 + v7);
                        if (CheckFunc(v21) == 1)
                        {
                            HasItems = 1;
                            EnumerateProcessObjects(v21, v21, OutputBuffer, BufferSize, 1, 0, 0);
                        }
                    }
                    v19 = (_QWORD *)*v19;
                    v20++;
                } while (v19 != v17);
                v16 = (_QWORD **)v23;
                v18 = v30;
            }
            v16 += 2;
            v17 += 2;
            v30 = --v18;
            v23 = (__int64)v16;
        } while (v18);
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

                void *v17 = NULL;
                int v18;
                WStringCopyN((WORD *)OutputBuffer + 260, (__int64)(Buffer + 4), 0x104);
                *((WORD *)OutputBuffer + 519) = 0;

                if (GetProcessImagePath(NULL, *((HANDLE *)OutputBuffer + 130), &v17, &v18, 0) == 1)
                {
                    WStringCopyN(OutputBuffer, (__int64)v17, 0x104);
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
                if (v17) ExFree(v17);
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
    ULONG v9;
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

    v9 = NameLength >> 1;
    *(ULONG *)OutputBuffer = 0;

    SystemInfo = AllocExBufferAndQuerySystemInfo(0x10);
    if (SystemInfo)
    {
        *(ULONG *)OutputBuffer = EnumHandlesByType(
            (WORD *)Address, v9 - 1, SystemInfo,
            (_DWORD *)OutputBuffer + 2, (BufferSize - 8) / 0x420);
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
    ULONG v6 = (ULONG)GtRead(GtEprocessField41);
    ULONG v7 = (ULONG)GtRead(GtEprocessField40);
    ULONG v8 = (ULONG)GtRead(GtEprocessField48);
    ULONG v9 = (ULONG)GtRead(GtEprocessField47);
    ULONG v10 = v9;

    if (v6 && v7 && v8 && v9 && ValidateProcessObject(Process, NULL) == 1)
    {
        EnumerateProcessListEntry((_QWORD **)((char *)Process + v6), v8, OutputBuffer, BufferSize);
        EnumerateProcessListEntry((_QWORD **)((char *)Process + v7), v10, OutputBuffer, BufferSize);
    }
}

// CmdCloseProcessHandle — 关闭进程句柄命令
// 对应原始驱动 sub_140084154
// 根据进程ID和句柄值，跨进程附加后关闭指定句柄
__int64 CmdCloseProcessHandle(__int64 a1, __int64 a2, _DWORD *pOutputBuffer, int BufferSize)
{
    char Result = 0;
    _OWORD *Address = (_OWORD *)pOutputBuffer;
    int InputSize = BufferSize;
    PEPROCESS *v5;
    __int64 v6;
    int (__fastcall *v7)(ULONG64, __int64, char *, __int64, ULONG64);
    bool v8;
    ULONG64 v9;
    void (__fastcall *v10)(ULONG64, __int64, char *, __int64);
    UCHAR v12;
    char v13, v14 = 0;
    PEPROCESS Process;
    HANDLE v16;
    HANDLE Handle[2];
    KAPC_STATE ApcState;

    v5 = (PEPROCESS *)GtRead(GtObjectTypeInfoPtr);
    v6 = GtRead(GtDereferenceObjectFunc);
    v7 = (int (__fastcall *)(ULONG64, __int64, char *, __int64, ULONG64))v6;

    if (!v5 || !v6) return Result;
    if (InputSize != 16 || !Address) return Result;
    if ((ULONG64)Address >= MmUserProbeAddress || (ULONG64)(Address + 1) >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x10, 4);
    *(_OWORD *)Handle = *Address;

    if (PsLookupProcessByProcessId(Handle[0], &Process) < 0) return Result;

    v8 = IoGetCurrentProcess() != Process;
    if (v8)
    {
        v12 = ReferenceObjectSafe((__int64)Process);
        KeStackAttachProcess(Process, &ApcState);
    }

    v9 = (ULONG64)Handle[1];
    v16 = Handle[1];
    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0 && *v5 == Process)
    {
        v9 |= 0xFFFFFFFF80000000ULL;
        v16 = (HANDLE)v9;
    }

    if (CheckHandleEntryValid((__int64)Process) == 1)
    {
        if (v7(v9, 4, &v13, 2, 0) >= 0)
        {
            if (v14 == 1)
            {
                v10 = (void (__fastcall *)(ULONG64, __int64, char *, __int64))GtRead(GtAltRegisterCallbackFunc);
                if (v10)
                {
                    v14 = 0;
                    v10(v9, 4, &v13, 2);
                }
            }
            ZwClose((HANDLE)v9);
            Result = 1;
        }
        ReturnFalseStub();
    }

    if (v8)
    {
        KeUnstackDetachProcess(&ApcState);
        if (v12 == 1) DereferenceObjectSafe((__int64)Process);
    }
    ObfDereferenceObject(Process);
    return Result;
}

// CmdCloseProcessHandleEx — 关闭进程句柄（扩展）
// 对应原始驱动 sub_140084B5C
char CmdCloseProcessHandleEx(__int64 InputBuffer)
{
    return 0;
}

// CmdEnumObjectHandles — 枚举对象句柄
// 对应原始驱动 sub_140054C38
// 验证输出缓冲区，根据构建号选择 Win8+ 或旧版句柄枚举
__int64 CmdEnumObjectHandles(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    ULONG64 v6;
    ULONG v7;

    if (!OutputBuffer || BufferSize < 0x40 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    v6 = BufferSize;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    *OutputBuffer = 0;
    v7 = (ULONG)((v6 - 64) / 0x38 + 1);

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
        EnumObjectHandlesWin8Plus(OutputBuffer, v7);
    else
    {
        ULONG KernelDataField08 = (ULONG)GtRead(GtKernelDataField08);
        if (!KernelDataField08)
        {
            EnumProcessHandleTable();
            KernelDataField08 = (ULONG)GtRead(GtKernelDataField08);
        }
        if (KernelDataField08 && (UCHAR)GtRead(GtKernelDataField10))
            EnumerateObjectHandles(OutputBuffer, v7);
        else
            EnumObjectHandleTable(OutputBuffer, v7);
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
    __int64 **v9 = (__int64 **)GtRead(GtEprocessField27);
    if (!v9) return 0;

    __int64 *v10 = *v9;
    if ((ULONG)GtRead(GtEprocessField28) == 1)
        return TraverseProcessHandleTableWin7((__int64)v10, OutputBuffer, BufferSize, Callback, Context);
    else
        return TraverseProcessHandleTableWin10(v10, OutputBuffer, BufferSize,
            (__int64 (__fastcall *)(ULONG64, __int64, ULONG64, __int64))Callback, Context);
}

// GetProcessVirtualizationContext — 获取进程虚拟化上下文
// 对应原始驱动 sub_140049B94
char GetProcessVirtualizationContext(_DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    __int64 v4;
    UCHAR (*v5)(__int64);
    ULONG v6, v7;
    __int64 v8, v9, v10, v11;
    ULONG v12;
    char v14 = 0;

    if (BuildNumber < 0x1771 || BuildNumber >= 0x1DB0)
        return GetProcessVirtualizationContextFallback(OutputBuffer, BufferSize);

    v4 = GtRead(GtObjectTypeInfoPtr);
    v5 = (UCHAR (*)(__int64))GtRead(GtObjectTypeCheckFlag);
    v6 = (ULONG)GtRead(GtEprocessField30);
    v7 = v6;
    if (!v4 || !v5 || v6 == (ULONG)-1) return v14;
    if (!v5(v4 + 8)) return v14;

    v8 = *(__int64 *)(v4 + 8);
    if (!v5(v8)) return v14;

    v9 = (ULONG)*OutputBuffer;
    if (552 * (int)v9 + 560 >= BufferSize) return v14;

    v10 = 138 * v9;
    *(__int64 *)&OutputBuffer[v10 + 10] = v8;
    v11 = *(__int64 *)(v7 + v8);
    *(__int64 *)&OutputBuffer[v10 + 4] = 0;
    *(__int64 *)&OutputBuffer[v10 + 6] = v11;
    LOWORD_LV(OutputBuffer[v10 + 2]) = 0;
    v12 = (ULONG)GtRead(GtEprocessField36);
    if (v12 == (ULONG)-1)
        *(__int64 *)&OutputBuffer[v10 + 8] = 0;
    else
        *(__int64 *)&OutputBuffer[v10 + 8] = *(__int64 *)(v12 + v8);
    OutputBuffer[v10 + 14] = 0;
    OutputBuffer[v10 + 12] = 6553673;
    OutputBuffer[v10 + 13] = 6619244;
    ++*OutputBuffer;
    return v14;
}

// EnumerateSessionProcesses — 按会话 ID 枚举进程
// 对应原始驱动 sub_14004AEB4
// 查找 CSRSS 进程创建时间戳，筛选匹配的进程
char EnumerateSessionProcesses(unsigned int *OutputBuffer, unsigned int BufferSize)
{
    ULONG64 CsrssProcessEntry;
    short v6;
    struct _KPROCESS **SystemInfo, **v8, **v9;
    __int64 v10;
    ULONG EprocessField61;

    EprocessField61 = (ULONG)GtRead(GtEprocessField61);
    if (!EprocessField61)
    {
        QueryProcessVirtualization();
        EprocessField61 = (ULONG)GtRead(GtEprocessField61);
    }
    if (!EprocessField61)
        return 0;

    UCHAR v4 = (UCHAR)GtRead(GtEprocessField62);
    CsrssProcessEntry = FindCsrssProcessEntry(OutputBuffer);
    v6 = (short)CsrssProcessEntry;
    if (!CsrssProcessEntry)
        return 0;

    SystemInfo = (struct _KPROCESS **)AllocExBufferAndQuerySystemInfo(0x10);
    v8 = SystemInfo;
    if (!SystemInfo)
        return 0;

    if (*(ULONG *)SystemInfo)
    {
        v9 = SystemInfo + 2;
        v10 = *(unsigned int *)SystemInfo;
        do
        {
            if (*((UCHAR *)v9 - 4) == v4 && CompareInt16Equal(*((WORD *)v9 - 4), v6))
                EnumerateProcessObjects(*v9, *v9, OutputBuffer, BufferSize, 1, 1, 0);
            v9 += 3;
            v10--;
        } while (v10);
    }

    ExFree(v8);
    return 0;
}

// CompareInt16Equal — 比较两个 16 位整数是否相等
// 对应原始驱动 sub_14007AAC8
bool CompareInt16Equal(__int16 a1, __int16 a2)
{
    return a1 == a2;
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
    __int64 v17;
    _QWORD *v18;
    __int64 v19;
    unsigned int v21;
    unsigned int v22;

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
    v18 = TableBase + 1;
    v19 = TableCount;
    do
    {
        CurrentEntry = (_QWORD *)*TableEnd;
        LoopCount = 0;
        v21 = 0;
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
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = Entry[14];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
                v17 = Entry[6];
                if (v17)
                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(v17 + 24);
                if (*(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] < (unsigned __int64)MmSystemRangeStart)
                {
                    v22 = (ULONG)GtRead(GtProcessEprocess);
                    unsigned int v14 = (ULONG)GtRead(GtProcessCreateTime);
                    unsigned int v15 = v14;
                    if (v22 != -1)
                    {
                        if (v14)
                        {
                            _QWORD *v16 = (_QWORD *)Entry[9];
                            if (CheckFunc(v16) == 1
                                && CheckFunc((_QWORD *)((char *)v16 + v22 + 3)) == 1
                                && CheckFunc((_QWORD *)((char *)v16 + v15 + 3)) == 1)
                            {
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = *(unsigned int *)((char *)v16 + v22);
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = *(unsigned int *)((char *)v16 + v15);
                            }
                            LoopCount = v21;
                        }
                    }
                }
            }
            else
            {
                v17 = Entry[6];
                if (!v17 || !*(_QWORD *)(v17 + 24))
                    goto Next;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(v17 + 24);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
            }
            ++*OutputBuffer;
Next:
            CurrentEntry = (_QWORD *)CurrentEntry[1];
            MaxEntries = MaxEntries;
            v21 = ++LoopCount;
        }
        while (CurrentEntry != TableBase);
        TableEnd = v18;
        Remaining = v19;
Advance:
        TableEnd += 2;
        TableBase += 2;
        v19 = --Remaining;
        v18 = TableEnd;
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
    _QWORD *SyscallCheckPtr;
    __int64 Remaining;
    _QWORD *CurrentEntry;
    unsigned int LoopCount;
    _QWORD *Entry;
    __int64 v17;
    _QWORD *v22;
    __int64 v19;
    unsigned int v21;

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

    v22 = TableBase + 1;
    Remaining = TableCount;
    v19 = TableCount;
    do
    {
        CurrentEntry = (_QWORD *)*v22;
        LoopCount = 0;
        v21 = 0;
        if ((_QWORD *)*v22 == TableBase)
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
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = Entry[14];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
                v17 = Entry[6];
                if (v17)
                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(v17 + 24);
                if (*(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] < (unsigned __int64)MmSystemRangeStart)
                {
                    unsigned int v14 = (ULONG)GtRead(GtProcessEprocess);
                    unsigned int v15 = (ULONG)GtRead(GtProcessCreateTime);
                    unsigned int v16 = v15;
                    if (v14 != -1)
                    {
                        if (v15)
                        {
                            _QWORD *v17ptr = (_QWORD *)Entry[9];
                            if (CheckFunc(v17ptr) == 1
                                && CheckFunc((_QWORD *)((char *)v17ptr + v14 + 3)) == 1
                                && CheckFunc((_QWORD *)((char *)v17ptr + v16 + 3)) == 1)
                            {
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = *(unsigned int *)((char *)v17ptr + v14);
                                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = *(unsigned int *)((char *)v17ptr + v16);
                            }
                        }
                    }
                    LoopCount = v21;
                }
            }
            else
            {
                v17 = Entry[6];
                if (!v17 || !*(_QWORD *)(v17 + 24))
                    goto Next;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = Entry;
                OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)Entry + 15);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = Entry[3];
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 8] = *(_QWORD *)(v17 + 24);
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 10] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 12] = 0;
                *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 14] = 0;
            }
            ++*OutputBuffer;
Next:
            CurrentEntry = (_QWORD *)CurrentEntry[1];
            MaxEntries = MaxEntries;
            v21 = ++LoopCount;
        }
        while (CurrentEntry != TableBase);
        v22 = v22;
        Remaining = v19;
Advance:
        v22 += 3;
        TableBase += 3;
        v19 = --Remaining;
    }
    while (Remaining);
    return v22;
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
    _QWORD *v14;
    __int64 v15;
    __int64 (__fastcall *v16)(_QWORD *);
    unsigned int v17;
    unsigned int v19;
    _QWORD *v20;

    TableBase = (_QWORD *)GtRead(GtCallbackField00);
    v20 = TableBase;
    v16 = (__int64 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    TableCount = (ULONG)GtRead(GtEprocessField33 | 0x800);
    TableOffset = (ULONG)GtRead(GtEprocessField34 | 0x800);
    v17 = TableOffset;

    if (v16 && TableBase && TableCount && TableOffset)
    {
        ObjectTableCode = GetObjectTableCode();
        if (TableCount > ObjectTableCode)
            TableCount = ObjectTableCode;
        StepSize = (ULONG)GtRead(GtWindowsBuildNumber) < 0x4A61 ? 256 : 512;
        v19 = StepSize;
        if (TableCount)
        {
            Remaining = TableCount;
            v15 = TableCount;
            do
            {
                if (*TableBase > (unsigned __int64)MmSystemRangeStart && StepSize)
                {
                    __int64 v10 = StepSize;
                    TablePtr = (_QWORD **)(*TableBase + TableOffset + 8);
                    do
                    {
                        Entry = *TablePtr;
                        for (i = 0; Entry != TablePtr; ++i)
                        {
                            if (*OutputBuffer >= MaxEntries)
                                break;
                            if (i >= 0x10000)
                                break;
                            v14 = Entry - 4;
                            if (v16(Entry - 4) != 1)
                                break;
                            if (v16((_QWORD *)((char *)v14 + 63)) != 1)
                                break;
                            __int64 Decoded = DecodeObjectHandleEntry((__int64)(Entry - 4));
                            if (Decoded)
                            {
                                if (*(_QWORD *)(Decoded + 24))
                                {
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 2] = v14;
                                    OutputBuffer[14 * *OutputBuffer + 4] = *((_DWORD *)v14 + 15);
                                    *(_QWORD *)&OutputBuffer[14 * *OutputBuffer + 6] = v14[3];
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
                        --v10;
                    }
                    while (v10);
                    StepSize = v19;
                    TableBase = v20;
                    Remaining = v15;
                    TableOffset = v17;
                }
                ++TableBase;
                v15 = --Remaining;
                v20 = TableBase;
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
    __int64 CloseHandleFunc;
    struct _KPROCESS **ObjectTypeInfo;
    __int64 AttachProcessFunc;
    __int64 DetachProcessFunc;
    __int64 HandleValue;
    _QWORD *ObjectHeader;
    __int64 HandleValue2;
    PEPROCESS CurrentProcess;
    bool IsDifferentProcess;
    unsigned __int8 RefCount;
    struct _KPROCESS *TargetProcess;
    unsigned __int8 v28 = 0;
    unsigned int v29;
    char v30[8];
    void (__fastcall *v31)(struct _KPROCESS *, _BYTE *);
    _BYTE *v32;
    void (__fastcall *v33)(struct _KPROCESS *);
    void (__fastcall *v34)(_BYTE *);
    _BYTE ApcState[48];

    v29 = BufferSize;
    v32 = OutputBuffer;
    CheckFunc = (unsigned __int8 (__fastcall *)(_QWORD *))GtRead(GtObjectTypeCheckFlag);
    ValidateTypeFunc = (int (__fastcall *)(_QWORD, struct _KPROCESS **))GtRead(GtValidateObjectTypeFunc);
    CloseHandleFunc = GtRead(GtCloseHandleFunc);
    v33 = (void (__fastcall *)(struct _KPROCESS *))CloseHandleFunc;
    ObjectTypeInfo = (struct _KPROCESS **)GtRead(GtObjectTypeInfoPtr);
    AttachProcessFunc = GtRead(GtCreateObjectTypeFunc);
    v31 = (void (__fastcall *)(struct _KPROCESS *, _BYTE *))AttachProcessFunc;
    DetachProcessFunc = GtRead(GtCloseObjectTypeFunc);
    v34 = (void (__fastcall *)(_BYTE *))DetachProcessFunc;

    if (CheckFunc && ValidateTypeFunc && CloseHandleFunc && AttachProcessFunc && DetachProcessFunc)
    {
        HandleValue = *((_QWORD *)HandleEntry + 1);
        if (BuildNumber >= 0x1770)
            HandleValue &= 0xFFFFFFFFFFFFFFF0ULL;
        if (HandleValue > (unsigned __int64)MmSystemRangeStart && MmIsAddressValid((PVOID)HandleValue) == 1)
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
                        v31(TargetProcess, ApcState);
                    }
                    else
                    {
                        RefCount = v28;
                    }
                    if (CheckHandleEntryValid((__int64)TargetProcess))
                    {
                        Result = SendIoControlWithQueryBuffer(HandleValue2, 3, OutputBuffer, BufferSize, (size_t *)v30);
                        if (!Result)
                        {
                            __int64 v18 = GtRead(GtEprocessField104 | 0x100);
                            v31 = (void (__fastcall *)(struct _KPROCESS *, _BYTE *))v18;
                            unsigned int v19 = (ULONG)GtRead(GtSdstServiceCount);
                            if (v18 && v19 != -1)
                            {
                                struct _KTHREAD *CurrentThread = KeGetCurrentThread();
                                __int64 v21 = BufferSize;
                                _BYTE *v22 = OutputBuffer;
                                __int64 v23 = v19;
                                char v24 = *((_BYTE *)CurrentThread + v19);
                                *((_BYTE *)CurrentThread + v19) = 0;
                                int v25 = ((__int64 (__fastcall *)(__int64, __int64, _BYTE *, __int64, char *))v31)(HandleValue2, 3, v22, v21, v30);
                                *((_BYTE *)CurrentThread + v23) = v24;
                                Result = v25 >= 0;
                            }
                        }
                        ReturnFalseStub();
                    }
                    if (IsDifferentProcess)
                    {
                        v34(ApcState);
                        if (RefCount == 1)
                            DereferenceObjectSafe((__int64)TargetProcess);
                    }
                    v33(TargetProcess);
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
    _QWORD ***v5;
    char Result = 0;
    __int64 v9;
    _QWORD **v10;
    __int64 v11;
    _QWORD *v12;
    __int64 v13;
    __int64 v14;

    v5 = *(_QWORD ****)(HandleTable + 8);
    if (v5)
    {
        v9 = 256;
        v14 = 256;
        do
        {
            v10 = *v5;
            if (*v5)
            {
                v11 = 256;
                do
                {
                    v12 = *v10;
                    if (*v10)
                    {
                        v13 = 256;
                        do
                        {
                            if (*v12)
                                Callback(*v12 | 0x80000000LL, OutputBuffer, BufferSize, Context);
                            Result = 1;
                            v12 += 2;
                            --v13;
                        }
                        while (v13);
                    }
                    ++v10;
                    --v11;
                }
                while (v11);
                v9 = v14;
            }
            ++v5;
            v14 = --v9;
        }
        while (v9);
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
        PVOID **v12 = (PVOID **)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        PVOID **v27 = v12;
        if (v12)
        {
            __int64 v13 = 128;
            __int64 v28 = 128;
            do
            {
                PVOID *v14 = *v12;
                if (*v12)
                {
                    __int64 v15 = 512;
                    __int64 v26 = 512;
                    PVOID *v16 = *v12;
                    do
                    {
                        if (MmIsAddressValid(v16) == 1)
                        {
                            __int64 *v17 = (__int64 *)*v14;
                            if (*v14 && MmIsAddressValid(*v14) == 1)
                            {
                                __int64 v18 = 256;
                                do
                                {
                                    DecodeObjectPointerFromHandleEntry(v17, OutputBuffer, BufferSize, Callback, Context);
                                    v17 += 2;
                                    --v18;
                                }
                                while (v18);
                                Result = 1;
                                v15 = v26;
                            }
                        }
                        ++v16;
                        ++v14;
                        v26 = --v15;
                    }
                    while (v15);
                    v12 = v27;
                    v13 = v28;
                }
                ++v12;
                v28 = --v13;
                v27 = v12;
            }
            while (v13);
        }
    }
    else if (Flags == 1)
    {
        __int64 **v19 = (__int64 **)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        if (v19)
        {
            __int64 v20 = 512;
            do
            {
                __int64 *v21 = *v19;
                if (*v19)
                {
                    __int64 v22 = 256;
                    do
                    {
                        DecodeObjectPointerFromHandleEntry(v21, OutputBuffer, BufferSize, Callback, Context);
                        v21 += 2;
                        --v22;
                    }
                    while (v22);
                    Result = 1;
                }
                ++v19;
                --v20;
            }
            while (v20);
        }
    }
    else if ((TableValue & 3) == 0)
    {
        __int64 *v23 = (__int64 *)(TableValue & 0xFFFFFFFFFFFFFFFCULL);
        if (v23)
        {
            Result = 1;
            __int64 v24 = 256;
            do
            {
                DecodeObjectPointerFromHandleEntry(v23, OutputBuffer, BufferSize, Callback, Context);
                v23 += 2;
                --v24;
            }
            while (v24);
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
    int r13d;
    _WORD DecodeBuffer[24];
    KAPC_STATE ApcState;

    TargetProcess = GtRead(0x61);
    CurrentProc = IoGetCurrentProcess();
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
            if (!DecodeUnicodeChar(rbx, r14, DecodeBuffer))
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
            if (!DecodeUnicodeChar(rbx, r14, DecodeBuffer))
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
                if (!DecodeUnicodeChar(rbx, r14, DecodeBuffer))
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
                    if (!DecodeUnicodeChar(rbx, r14, DecodeBuffer))
                        break;
                    if (*(int *)TableEntry != 0x1037)
                        goto Next;
                    int Diff = *(int *)((char *)DecodeBuffer + 12);
                    if (Diff <= r13)
                        goto Next;
                    Diff -= (int)r13;
                    Diff -= 0xC;
WriteGt:
                    if (Diff && Diff < r15d)
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
    unsigned int KernelSize = GtRead(GtEprocessField23);
    unsigned int ServiceCount = GtRead(GtWin32kServiceEntryCount);
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
                if (SyscallAddr > PeExportDir)
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

    unsigned int KernelDataField12 = GtRead(GtKernelDataField12);
    if (!KernelDataField12)
    {
        ResolveSyscallTableEntry();
        KernelDataField12 = GtRead(GtKernelDataField12);
    }

    if (!KernelDataField12)
        return;

    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);

    __int64 KernelBase = GtRead(GtEprocessField22);
    unsigned int KernelSize = GtRead(GtEprocessField23);
    __int64 NtosBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int TotalSizeOr = GtRead(GtTotalSize | GtEprocessField187 | 0x100);

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
    __int64 (__fastcall *v41DB)(__int64);
    __int64 (__fastcall *CheckTypeFunc)(__int64);
    __int64 (__fastcall *v2Func)(__int64);
    unsigned int v4A;
    __int64 v4166;
    __int64 Src;
    __int64 Dst[2];
    __int64 EndAddr;
    __int64 ScanSize;
    int StepSize;
    int var_68, var_64, var_5C;
    char NtBuf[0x40];
    char var_D0;
    unsigned int var_C0;
    unsigned int var_B0;
    unsigned int r12d;
    unsigned int r15d;
    __int64 rdi;
    __int64 rsi;
    __int64 rbx;
    __int64 r14;
    __int64 r13;

    Buffer = (char *)ExAlloc(PagedPool, 0x3000);
    if (!Buffer)
        return 0;

    memset(Buffer, 0, 0x3000);

    NtQuerySysInfoFunc = (__int64 (__fastcall *)(_QWORD, PVOID, _QWORD, _QWORD))GtRead(0x41DE);
    GetOffsetFunc = (__int64 (__fastcall *)(__int64))GtRead(0x41E4);
    ValidateFunc = (__int64 (__fastcall *)(__int64, __int64, __int64))GtRead(0x41E1);
    ServiceCount = (ULONG)GtRead(0x27);
    v41DB = (__int64 (__fastcall *)(__int64))GtRead(0x41DB);
    CheckTypeFunc = (__int64 (__fastcall *)(__int64))GtRead(3);
    v2Func = (__int64 (__fastcall *)(__int64))GtRead(2);
    v4A = (ULONG)GtRead(0x4A);
    v4166 = GtRead(0x4166);
    ULONG Gt914 = (ULONG)GtRead(0x914);

    if (!v2Func || !v4A || !v4166 || !CheckTypeFunc || !NtQuerySysInfoFunc || !GetOffsetFunc || !ValidateFunc || ServiceCount == -1)
    {
        ExFree(Buffer);
        return 0;
    }

    memset(NtBuf, 0, 0x40);
    rsi = (__int64)KeGetCurrentThread();
    rdi = ServiceCount;
    rbx = v4166;
    r14 = v41DB;
    r13 = (__int64)Buffer;
    char SavedFlag = *(_BYTE *)(rsi + ServiceCount);
    *(_BYTE *)(rsi + ServiceCount) = 0;
    NtQuerySysInfoFunc(0, NtBuf, 0x40, 0);
    *(_BYTE *)(rsi + ServiceCount) = SavedFlag;

    var_68 = *(int *)&NtBuf[0x18];
    var_64 = *(int *)&NtBuf[0x1C];
    var_5C = *(int *)&NtBuf[0x24];

    if (Gt914 >= 0x4F7C)
        var_64 = var_5C;
    else if (var_64 > var_5C)
        var_64 = var_5C;

    ScanSize = var_68 * var_64;
    StepSize = 0xFD0 - (int)rbx;
    var_B0 = StepSize;

    GetKernelVirtualAddressRange(&Src, Dst, &EndAddr, &ScanSize);

    r12d = StepSize;
    r15d = 0x1000;
    var_D0 = 0;

    for (__int64 CurrentAddr = Src; CurrentAddr < EndAddr; CurrentAddr += 0x1000)
    {
        if (var_D0)
        {
            __int64 ScanAddr = CurrentAddr + 0x1000;
            var_D0 = 0;
            r15d = 0x1000;
            var_C0 = r12d;

            if (CheckTypeFunc(ScanAddr) == 1
                && CallRegisteredCallback(ScanAddr, 0) == 1)
            {
                __int64 Offset = GetOffsetFunc(ScanAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue(CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc(ValidateFunc, ScanAddr, Offset) == 1)
                {
                    var_D0 = 1;
                    var_C0 = r12d + 0x1000;
                    r15d = 0x2000;
                }
            }

            if (CheckTypeFunc(CurrentAddr) == 1
                && CallRegisteredCallback(CurrentAddr, 0) == 1)
            {
                __int64 Offset = GetOffsetFunc(CurrentAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue(CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc(ValidateFunc, CurrentAddr, Offset) == 1)
                {
                    var_D0 = 1;
                    var_C0 = var_B0 + 0x1000;
                    r15d = 0x2000;
                }
            }

            if (var_D0
                && CheckTypeFunc(CurrentAddr) == 1
                && CheckTypeFunc(CurrentAddr + r15d - 1) == 1)
            {
                memmove(Buffer, (void *)CurrentAddr, 0x1000);
                EnumerateProcessObjects(
                    (struct _KPROCESS *)(Buffer + 0x30),
                    (struct _KPROCESS *)(Buffer + 0x30),
                    OutputBuffer, BufferSize, 1, 0, 0);

                // Inner loop: scan through buffer entries
                unsigned int esi = 0;
                while (esi <= (unsigned int)v41DB)
                {
                    r12d = 0;
                    char *EntryBuf = Buffer + esi;
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
                        char *ValidateAddr = (char *)CurrentAddr + 0x30 + r12d;
                        if (ValidateProcessObject((struct _KPROCESS *)(EntryBuf + 0x30), (struct _KPROCESS *)ValidateAddr) == 1)
                        {
                            EnumerateProcessObjects(
                                (struct _KPROCESS *)(EntryBuf + 0x30),
                                (struct _KPROCESS *)ValidateAddr,
                                OutputBuffer, BufferSize, 1, 0, 0);
                            esi += var_B0;
                        }
                    }
                    esi += 8;
                }
            }
        }
        else
        {
            if (CheckTypeFunc(CurrentAddr) == 1
                && CallRegisteredCallback(CurrentAddr, 0) == 1)
            {
                __int64 Offset = GetOffsetFunc(CurrentAddr);
                if (Offset && Offset < ScanSize
                    && CmdStubAlwaysTrue(CheckTypeFunc, Offset, NULL, 0) == 1
                    && ValidateFunc(ValidateFunc, CurrentAddr, Offset) == 1)
                {
                    var_D0 = 1;
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
            LastChar = WStringFindLastChar(Entry, 92);
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
    __int64 v5;
    unsigned int v6;
    unsigned int v7;
    unsigned int v8;
    unsigned __int8 (__fastcall *CheckFunc)(__int64);
    unsigned __int8 (__fastcall *v10)(__int64);
    __int64 v11;
    __int64 v12;
    __int64 v13;
    __int64 v14;
    unsigned int v15;

    CurrentFiber = KeGetCurrentThread();
    if (!CurrentFiber)
        return 0;

    v5 = CurrentFiber[3];
    v6 = (ULONG)GtRead(GtEprocessField132 | 0x100);
    v7 = (ULONG)GtRead(GtEprocessField30);
    v8 = (ULONG)GtRead(GtProcessOffset);
    CheckFunc = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtObjectTypeCheckFlag);
    v10 = CheckFunc;

    if (!v6 || v7 == -1 || v8 == -1 || !CheckFunc || CheckFunc(v5) != 1)
        return 0;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1771)
        v11 = *(_QWORD *)(v8 + v5);
    else
        v11 = *(_QWORD *)(v6 + v5 + 32);

    if (v10(v11) != 1)
        return 0;

    v12 = *OutputBuffer;
    if (552 * (int)v12 + 560 >= BufferSize)
        return 0;

    v13 = 138 * v12;
    *(_QWORD *)&OutputBuffer[v13 + 10] = v11;
    v14 = *(int *)(v7 + v11);
    *(_QWORD *)&OutputBuffer[v13 + 4] = 0;
    *(_QWORD *)&OutputBuffer[v13 + 6] = v14;
    LOWORD_LV(OutputBuffer[v13 + 2]) = 0;
    v15 = (ULONG)GtRead(GtEprocessField36);
    if (v15 == -1)
        *(_QWORD *)&OutputBuffer[v13 + 8] = 0;
    else
        *(_QWORD *)&OutputBuffer[v13 + 8] = *(_QWORD *)(v15 + v11);
    OutputBuffer[v13 + 14] = 0;
    OutputBuffer[v13 + 12] = 6553673;
    OutputBuffer[v13 + 13] = 6619244;
    ++*OutputBuffer;
    return 0;
}

// QueryProcessVirtualization — 查询进程虚拟化状态
// 对应原始驱动 sub_140049F18
// 通过 ZwQueryInformationProcess 获取虚拟化信息，查询系统信息匹配会话 ID
void QueryProcessVirtualization(void)
{
    PEPROCESS CurrentProcess;
    __int16 v1;
    __int64 (__fastcall *QueryInfoFunc)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *);
    _QWORD *v3;
    __int64 (__fastcall *ExFreeFunc)(__int64);
    unsigned int v5;
    __int16 *SystemInfo;
    __int16 *v8;
    unsigned int v9;
    __int16 *v10;
    unsigned int v11;
    char v12;
    __int64 v13;

    CurrentProcess = IoGetCurrentProcess();
    v1 = (__int16)GtRead(GtDisableHookProtectionAddr2 | GtEprocessField86);
    QueryInfoFunc = (__int64 (__fastcall *)(PEPROCESS, __int64, _QWORD, __int64, _QWORD, char, __int64 *))GtRead(GtNtDuplicateObjectPeSectionOffset | GtEprocessField54);
    v3 = (_QWORD *)GtRead(GtTotalSize | GtExFreeCallBackAddr | 0x100);
    ExFreeFunc = (__int64 (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);

    if (!QueryInfoFunc || !v3 || !ExFreeFunc)
        return;

    v12 = 0;
    if ((int)QueryInfoFunc(CurrentProcess, 512, 0, 0x80000000, *v3, v12, &v13) < 0)
        return;

    SystemInfo = (__int16 *)AllocExBufferAndQuerySystemInfo(0x10);
    v8 = SystemInfo;
    if (!SystemInfo)
    {
        ExFreeFunc(v13);
        return;
    }

    v9 = *(_DWORD *)SystemInfo;
    v5 = 0;
    if (v9)
    {
        v10 = SystemInfo + 4;
        while (v10[3] != (__int16)v13 || !CompareInt16Equal(*v10, v1))
        {
            ++v5;
            v10 += 12;
            if (v5 >= v9)
                goto Cleanup;
        }
        v11 = (UCHAR)v8[12 * v5 + 6];
        GtWrite(GtEprocessField61, 1);
        GtWrite(GtEprocessField62, v11);
    }

Cleanup:
    ExFree(v8);
    ExFreeFunc(v13);
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
    unsigned int v3 = GtRead(GtEprocessField30);
    unsigned int v4 = GtRead(GtEprocessField38);

    if (v3 && v4 != -1)
    {
        unsigned __int64 ProcessFromHandleEntry = GetProcessFromHandleEntry(HandleTableEntry);
        return ProcessFromHandleEntry >= 8
            && ProcessFromHandleEntry != *(_QWORD *)(v3 + HandleTableEntry)
            || *(_BYTE *)(v4 + HandleTableEntry) == 0;
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
        __int64 v5 = *Key2;
        __int64 v6 = RotateLeft64Impl(*Key1, *Key1 ^ *(_QWORD *)(HandleEntry + 48));
        return v5 ^ ByteSwap64(HandleEntry ^ v6);
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
    int v4, v5, v6;

    GetCurrentProcess = (__int64 (*)(void))GtRead(16733);
    if (GetCurrentProcess && VirtualAddress == (char *)GetCurrentProcess())
        return Result;

    v4 = (int)GtRead(GtEprocessField64) - 1;
    if (MmIsAddressValid(VirtualAddress) == 1 && MmIsAddressValid(&VirtualAddress[v4]) == 1)
    {
        v5 = (int)GtRead(GtEprocessField34);
        v6 = (int)GtRead(GtEprocessField44);
        if (*(ULONG64 *)&VirtualAddress[v5])
            return *(ULONG64 *)&VirtualAddress[v6] != 0;
    }

    return Result;
}

// CallRegisteredCallback — 调用已注册的回调函数
// 对应原始驱动 sub_1400777B8
bool CallRegisteredCallback(__int64 a1)
{
    unsigned __int8 (__fastcall *pCallback)(__int64);

    pCallback = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtTotalSize | GtCallbackField60);
    if (pCallback)
        return pCallback(a1) == 1;
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
