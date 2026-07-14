// Registry.c — 注册表保护
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"

// InitRegCallback — 初始化注册表回调
// 对应原始驱动 sub_14000A094
char InitRegCallback(void *OutputBuffer, int OutputSize, volatile void *UserBuffer, unsigned int UserBufferSize)
{
    int RefCount;

    RefCount = (int)GtRead(GtWin32kServiceTableVersion);
    GtWrite(GtWin32kServiceTableVersion, RefCount + 1);

    if (OutputSize != 552 || UserBufferSize < 0x218)
        return 0;

    if ((ULONG64)OutputBuffer >= MmUserProbeAddress || (ULONG64)OutputBuffer + 552 >= MmUserProbeAddress)
        return 0;

    if (!UserBuffer)
        return 0;

    if ((ULONG64)UserBuffer >= MmUserProbeAddress || (ULONG64)UserBuffer + UserBufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, 0x228, 1);
    ProbeForWrite(UserBuffer, UserBufferSize, 1);
    memset((void *)UserBuffer, 0, UserBufferSize);
    *((WORD *)OutputBuffer + 275) = 0;

    if (FindRegCallbackEntry((__int64)OutputBuffer) == 1)
    {
        if (UserBufferSize >= 0x98C)
            ParseNtKernelFile((__int64)OutputBuffer, (__int64)UserBuffer, UserBufferSize);
        FindExportEntryByName((char *)OutputBuffer);
        return 1;
    }

    return 0;
}

// FindRegCallbackEntry — 查找注册表回调条目
// 对应原始驱动 sub_14000A1A4
char FindRegCallbackEntry(__int64 RegEntry)
{
    _DWORD *CallbackList, *CallbackListPtr;
    ULONG EntryCount, EntryIndex;

    CallbackList = (_DWORD *)GtRead(GtModuleBuffer);
    if (!CallbackList)
        return 0;

    CallbackListPtr = CallbackList;
    EntryCount = *CallbackList;
    if (!EntryCount)
        return 0;

    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        _DWORD *Entry = CallbackListPtr + 138 * EntryIndex;
        if (*((__int64 *)Entry - 1) == *(__int64 *)(RegEntry + 24) &&
            *Entry == *(ULONG *)(RegEntry + 32) &&
            WStringCompare((__int64)(Entry + 11), (WORD *)(RegEntry + 36), 0x100) == 0)
            return 1;
    }

    return 0;
}

// InitRegNotify — 初始化注册表通知
// 对应原始驱动 sub_14000C1E0
char InitRegNotify(void)
{
    void *CallbackBuffer;
    ULONG EntryIndex;
    _QWORD *ListAllocation;

    CallbackBuffer = (void *)GtRead(GtModuleBuffer);
    if (CallbackBuffer)
    {
        ExFree(CallbackBuffer);
        GtWrite(GtModuleBuffer, 0);
    }

    GtWrite(GtWin32kServiceTableVersion, 0);

    ListAllocation = (_QWORD *)GtRead(0x415F);
    if (ListAllocation)
    {
        FreeListAllocation(ListAllocation);
        GtWrite(0x415F, 0);
    }

    for (EntryIndex = 0; EntryIndex < 0x100; EntryIndex++)
        GtWrite((GLOBAL_TABLE_INDEX)(EntryIndex + 109), 0);

    GtWrite(GtCallbackInitialized, 0);
    return 1;
}

// InitRegFilter — 初始化注册表过滤器
// 对应原始驱动 sub_14000C738
// 分配驱动对象缓冲区，枚举驱动对象，初始化注册表通知
char InitRegFilter(__int64 DeviceObject, __int64 Irp, _OWORD *OutputBuffer, int OutputSize)
{
    unsigned int Result;
    void *DriverObjectBuffer;
    void *TempBuffer;
    _OWORD *SourceDataPtr;
    __int64 QuadCount;

    Result = 0;
    DriverObjectBuffer = NULL;

    if (OutputSize != 552 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + 552 >= MmUserProbeAddress)
        return Result;

    if (!GtRead(GtCallbackInitialized))
    {
        InitRegNotify();
        GtWrite(GtCallbackInitialized, 1);

        TempBuffer = ExAlloc(PagedPool, 0x28910);
        DriverObjectBuffer = TempBuffer;
        if (TempBuffer)
        {
            memset(TempBuffer, 0, 0x28910);
            if (CmdEnumDriverObjects((unsigned int *)DriverObjectBuffer, 0x28910, 1, 0) == 1)
            {
                GtWrite(GtModuleBuffer, (__int64)DriverObjectBuffer);
                ((void (*)(void *))0x14000D2B8)(DriverObjectBuffer); // CPullPin::Process

                ULONG Index;
                for (Index = 0; Index < 0x100; Index++)
                    GtWrite((GLOBAL_TABLE_INDEX)(Index + 109), 0);
                Result = 1;
            }
            else
                ExFree(DriverObjectBuffer);
        }
    }

    if (Result == 1)
    {
        ProbeForWrite(OutputBuffer, 0x228, 2);
        SourceDataPtr = (_OWORD *)((char *)DriverObjectBuffer + 8);
        QuadCount = 4;
        do
        {
            *OutputBuffer = *SourceDataPtr;
            OutputBuffer[1] = SourceDataPtr[1];
            OutputBuffer[2] = SourceDataPtr[2];
            OutputBuffer[3] = SourceDataPtr[3];
            OutputBuffer[4] = SourceDataPtr[4];
            OutputBuffer[5] = SourceDataPtr[5];
            OutputBuffer[6] = SourceDataPtr[6];
            OutputBuffer += 8;
            *(OutputBuffer - 1) = SourceDataPtr[7];
            SourceDataPtr += 8;
            QuadCount--;
        } while (QuadCount);
        *OutputBuffer = *SourceDataPtr;
        OutputBuffer[1] = SourceDataPtr[1];
        *((__int64 *)OutputBuffer + 4) = *((__int64 *)SourceDataPtr + 4);
    }

    return Result;
}

// RegNotifyCallback — 注册表通知回调
// 对应原始驱动 sub_14000D0B0
NTSTATUS RegNotifyCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    return STATUS_SUCCESS;
}

// RegisterMiniFilterRegistry — 注册 Minifilter 注册表项
// 对应原始驱动 sub_140018F4C
void RegisterMiniFilterRegistry(void)
{
}

// InitRegistryCallback — 初始化注册表回调
// 对应原始驱动 sub_140010BF8
// 从输入缓冲区读取值，根据大小（2或4字节）存入输出缓冲区
ULONG64 InitRegistryCallback(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *StateFlags, UCHAR *OutputBuffer)
{
    int CurrentOffset;
    ULONG *ValuePtr;
    __int64 ValueSize;
    ULONG64 Result;

    CurrentOffset = StateFlags[4];
    ValuePtr = (ULONG *)((ULONG)(StateFlags[1] + StateFlags[2] + StateFlags[3] + CurrentOffset + 1) + InputBuffer);
    StateFlags[4] = CurrentOffset + *OutputBuffer;
    ValueSize = *OutputBuffer;
    Result = (ULONG64)ValuePtr + ValueSize - 1;

    if (Result >= BufferSize)
    {
        *StateFlags |= 2;
        return Result;
    }

    Result = (ULONG)StateFlags[5];
    if (Result)
    {
        if (Result == 1)
        {
            if (*(UCHAR *)&ValueSize == 4)
                Result = *ValuePtr;
            else if (*(UCHAR *)&ValueSize == 2)
                Result = (ULONG)*(short *)ValuePtr;
            else
                goto Done;
            *((ULONG *)OutputBuffer + 5) = (ULONG)Result;
        }
    }
    else
    {
        if (*(UCHAR *)&ValueSize == 4)
        {
            Result = *ValuePtr;
            goto StoreResult;
        }
        if (*(UCHAR *)&ValueSize == 2)
            Result = (ULONG)*(short *)ValuePtr;
        else
            goto Done;

StoreResult:
        *((ULONG *)OutputBuffer + 4) = (ULONG)Result;
    }

Done:
    ++StateFlags[5];
    return Result;
}

// RegistryCallbackRoutine — 注册表回调例程
// 对应原始驱动 sub_140010C74
// 解析注册表回调数据，提取 16 位值到输出缓冲区偏移 16 或 20 处
ULONG64 RegistryCallbackRoutine(ULONG64 InputBuffer, ULONG64 BufferSize, PULONG StateFlags, ULONG64 OutputBuffer)
{
    ULONG CurrentOffset;
    ULONG64 DataOffset;
    ULONG64 Result;

    CurrentOffset = StateFlags[4];
    DataOffset = (ULONG)(StateFlags[1] + StateFlags[2] + StateFlags[3] + CurrentOffset + 1);
    StateFlags[4] = CurrentOffset + 2;
    Result = DataOffset + InputBuffer + 1;

    if (Result >= BufferSize)
    {
        *StateFlags |= 2;
    }
    else
    {
        Result = StateFlags[5];
        if (Result == 0)
        {
            Result = (ULONG)*(SHORT *)(InputBuffer + DataOffset);
            *(PULONG)(OutputBuffer + 16) = (ULONG)Result;
        }
        else if (Result == 1)
        {
            Result = (ULONG)*(SHORT *)(InputBuffer + DataOffset);
            *(PULONG)(OutputBuffer + 20) = (ULONG)Result;
        }
        StateFlags[5]++;
    }

    return Result;
}

// FreeListAllocation — 释放链表分配
// 对应原始驱动 sub_1400575A0
// 遍历链表依次释放每个节点，直到链表为空
void FreeListAllocation(_QWORD *Allocation)
{
    _QWORD *CurrentEntry;

    if (Allocation)
    {
        do
        {
            CurrentEntry = (_QWORD *)Allocation[4];
            ExFree(Allocation);
            Allocation = CurrentEntry;
        } while (CurrentEntry);
    }
}

// CmdEnumDriverObjects — 枚举驱动对象命令处理函数
// 对应原始驱动 sub_14003A6E8
// 依次调用多个子枚举函数收集驱动列表、驱动对象、对象类型等信息
char CmdEnumDriverObjects(unsigned int *pOutputBuffer, unsigned int OutputSize, char Flags, char Flags2)
{
    char Success;

    Success = 0;
    if (OutputSize > 0x230)
    {
        *pOutputBuffer = 0;
        EnumerateDriverList(pOutputBuffer, OutputSize);
        EnumerateDriverObjects(pOutputBuffer, OutputSize);
        EnumObjectTypeList(pOutputBuffer, OutputSize);
        EnumerateDriverObjectsEx(pOutputBuffer, OutputSize);
        EnumerateDriverObjectsFull(pOutputBuffer, OutputSize);
        if (!Flags && Flags2 == 1)
            EnumerateKernelModules(pOutputBuffer, OutputSize);
        if (*pOutputBuffer)
        {
            EnumerateDriverFiles(pOutputBuffer);
            return 1;
        }
    }
    return Success;
}
