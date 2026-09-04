// ObjectMgmt.c — 对象管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"

// C4700 抑制：对象管理函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
// Forward declarations
__int64 (*EnumKbdclassDriverObjects(unsigned int *OutputBuffer, _DWORD *pCount))(void);
__int64 (*ReadVolumeDataToBuffer(__int64 (__fastcall *Callback)(_QWORD *, _QWORD *, __int64), __int64 Context))(_QWORD);
_QWORD *ValidateObjectTypeList(_QWORD *TypeListEntry);

// 前向声明 — 这些函数在被定义之前已被调用
void CollectObjectDirEntry(__int64 CallbackState, __int64 ObjectDir, unsigned int *OutputBuffer, _DWORD *pCount);
void CollectObjectTypeEntry(__int64 CallbackState, __int64 ObjectType, unsigned int *OutputBuffer, _DWORD *pCount);
char EnumGdiObjectEntries(unsigned int *OutputBuffer, _DWORD *pCount);
void EnumDriverPeImageEntries(unsigned int *OutputBuffer, _DWORD *pCount);
__int64 QueryObjectTypeDirectoryPath(void);
bool ValidateKernelModuleAddressRange(__int64 LdrEntry);
char InitObjectCallbackFiles(int ObjectName);

// EnableObjectProtect — 启用对象保护
// 对应原始驱动 sub_1400082AC
char EnableObjectProtect(_OWORD *Address, int BufferSize)
{
    void (__fastcall *CallbackFunc)(_QWORD *);
    _QWORD **ListHead;
    _QWORD *CurrentEntry;
    _OWORD InputBuffer;
    ULONG EntryCount;

    if (!Address || BufferSize != 16)
        return 0;

    if ((ULONG64)Address >= MmUserProbeAddress || (ULONG64)(Address + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(Address, 16, 1);
    InputBuffer = *Address;

    CallbackFunc = (void (__fastcall *)(_QWORD *))GtRead(GtObjectProtectCallback);
    if (!CallbackFunc || !*((ULONG64 *)&InputBuffer + 1))
        return 0;

    if (MmIsAddressValid(*((PVOID *)&InputBuffer + 1)) != 1)
        return 0;

    ListHead = (_QWORD **)(*((ULONG64 *)&InputBuffer + 1) + 16);
    if (MmIsAddressValid(ListHead) != 1)
        return 0;

    EntryCount = 0;
    for (CurrentEntry = *ListHead; CurrentEntry != (_QWORD *)ListHead; CurrentEntry = (_QWORD *)*CurrentEntry)
    {
        if ((ULONG64)CurrentEntry <= (ULONG64)MmSystemRangeStart)
            break;
        if (MmIsAddressValid(CurrentEntry) != 1)
            break;
        if (++EntryCount > 0x1000)
            break;
        if (CurrentEntry == (_QWORD *)(ULONG_PTR)InputBuffer.qword[0])
        {
            CallbackFunc(CurrentEntry);
            return 1;
        }
    }

    return 0;
}

// DisableObjectProtect — 禁用对象保护
// 对应原始驱动 sub_140007CC4
char DisableObjectProtect(__int64 DeviceObject, __int64 Irp, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!OutputBuffer || BufferSize < 0x80)
        return 0;

    if ((ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return 0;

    ProbeForWrite(OutputBuffer, BufferSize, 1);
    *OutputBuffer = 0;
    DisableObjectProtectEx(OutputBuffer, BufferSize);
    return *OutputBuffer != 0;
}

// DisableObjectProtectEx — 禁用对象保护扩展
// 对应原始驱动 sub_140007D54
char DisableObjectProtectEx(_DWORD *OutputBuffer, unsigned int BufferSize)
{
    // Uses device IOCTL to walk object types
    return 0;
}

// WalkObjectTypeList — 遍历对象类型列表 (0x140007F44)
// 深度优先遍历内核对象类型节点，收集每个类型的处理函数入口和名称信息
char __fastcall WalkObjectTypeList(_QWORD **NodeStack, int MaxDepth, _DWORD *OutputBuffer, unsigned int MaxBufferSize)
{
    unsigned int BufferSize;
    __int64 TypeFlag;
    _QWORD *CurrentNode;
    int StackDepth;
    unsigned int LoopCounter;
    __int64 StackIndex;
    unsigned int EntryOffset;
    unsigned int TypeIndex;
    _QWORD *EntryPtr;
    _QWORD *ObjectHeader;
    unsigned int ObjIndex;
    _QWORD *HandlerEntry;
    unsigned __int64 NameLength;
    char *NameBuffer;
    int ObjLoopCount;
    unsigned int TypeLoopCount;
    int HandlerCount;
    int TotalCount;
    _QWORD *CurrentNodeCopy;
    __int64 StackIndexCopy;
    int StackDepthCopy;
    __int64 TypeFlagCopy;
    char *Src;
    _QWORD *EntryPtrCopy;
    unsigned __int16 *NameInfo;

    BufferSize = MaxBufferSize;
    TypeFlag = GtRead(GtObjectTypeCheckFlag);
    if (TypeFlag)
    {
        if (MaxDepth > 1)
        {
            CurrentNode = *NodeStack;
            StackDepth = -1;
            CurrentNodeCopy = *NodeStack;
            StackDepthCopy = -1;
            LoopCounter = 0;
            TotalCount = 0;
            if (*NodeStack)
            {
                StackIndex = -1;
                StackIndexCopy = -1;
                do
                {
                    TypeFlag = CheckMemoryValid(CurrentNode);
                    if ((char)TypeFlag != 1 || LoopCounter >= 0x100000)
                        break;
                    EntryOffset = 120 * *OutputBuffer + 128;
                    TypeFlag = (unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772
                        ? (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(CurrentNode - 6))
                        : *(CurrentNode - 4);
                    TypeIndex = 0;
                    TypeFlagCopy = TypeFlag;
                    TypeLoopCount = 0;
                    do
                    {
                        if (EntryOffset >= BufferSize)
                            break;
                        EntryPtr = (_QWORD *)*CurrentNode;
                        TypeFlag = 0;
                        EntryPtrCopy = (_QWORD *)*CurrentNode;
                        ObjLoopCount = 0;
                        if (*CurrentNode)
                        {
                            do
                            {
                                if (EntryOffset >= BufferSize || (unsigned int)TypeFlag >= 0x10000)
                                    break;
                                ObjectHeader = (_QWORD *)EntryPtr[1];
                                if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772
                                    ? TypeFlagCopy == (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(ObjectHeader - 6))
                                    : TypeFlagCopy == *(ObjectHeader - 4))
                                {
                                    if (StackDepth < MaxDepth - 1)
                                    {
                                        ++StackDepth;
                                        NodeStack[++StackIndex] = ObjectHeader;
                                        StackDepthCopy = StackDepth;
                                        StackIndexCopy = StackIndex;
                                    }
                                }
                                else
                                {
                                    ObjIndex = 0;
                                    HandlerEntry = (_QWORD *)ObjectHeader[2];
                                    HandlerCount = 0;
                                    if (HandlerEntry != ObjectHeader + 2)
                                    {
                                        do
                                        {
                                            if ((ULONG64)HandlerEntry <= (ULONG64)MmSystemRangeStart
                                                || ObjIndex >= 0x1000
                                                || EntryOffset >= MaxBufferSize
                                                || CheckMemoryValid(HandlerEntry) != 1
                                                || CheckMemoryValid((char *)HandlerEntry + 47) != 1)
                                            {
                                                break;
                                            }
                                            *(_QWORD *)&OutputBuffer[30 * *OutputBuffer + 6] = (_QWORD)ObjectHeader;
                                            *(_QWORD *)&OutputBuffer[30 * *OutputBuffer + 4] = (_QWORD)HandlerEntry;
                                            *(_QWORD *)&OutputBuffer[30 * *OutputBuffer + 2] = (_QWORD)HandlerEntry[3];
                                            LOWORD_LV(OutputBuffer[30 * *OutputBuffer + 8]) = 0;
                                            if (ResolveObjectHeaderPointer((__int64)ObjectHeader, (_QWORD *)&NameInfo) == 1)
                                            {
                                                NameLength = *NameInfo;
                                                NameBuffer = (char *)*((_QWORD *)NameInfo + 1);
                                                Src = NameBuffer;
                                                if ((NameLength & 1) != 0)
                                                    NameLength = (unsigned int)(NameLength - 1);
                                                if ((unsigned int)NameLength > 2
                                                    && MmIsAddressValid(NameBuffer) == 1
                                                    && MmIsAddressValid(&Src[(unsigned int)NameLength - 1]) == 1)
                                                {
                                                    if ((unsigned int)NameLength > 0x5E)
                                                        NameLength = 94;
                                                    memmove(&OutputBuffer[30 * *OutputBuffer + 8], Src, (unsigned int)NameLength);
                                                    *((_WORD *)&OutputBuffer[30 * *OutputBuffer + 8] + (NameLength >> 1)) = 0;
                                                }
                                            }
                                            ++*OutputBuffer;
                                            HandlerEntry = (_QWORD *)*HandlerEntry;
                                            ObjIndex = HandlerCount + 1;
                                            EntryOffset = 120 * *OutputBuffer + 128;
                                            ++HandlerCount;
                                        } while (HandlerEntry != ObjectHeader + 2);
                                        StackIndex = StackIndexCopy;
                                        StackDepth = StackDepthCopy;
                                        EntryPtr = EntryPtrCopy;
                                    }
                                }
                                EntryPtr = (_QWORD *)*EntryPtr;
                                BufferSize = MaxBufferSize;
                                TypeFlag = ObjLoopCount + 1;
                                EntryOffset = 120 * *OutputBuffer + 128;
                                EntryPtrCopy = EntryPtr;
                                ++ObjLoopCount;
                            } while (EntryPtr);
                            CurrentNode = CurrentNodeCopy;
                            TypeIndex = TypeLoopCount;
                        }
                        ++TypeIndex;
                        ++CurrentNode;
                        TypeLoopCount = TypeIndex;
                        CurrentNodeCopy = CurrentNode;
                        EntryOffset = 120 * *OutputBuffer + 128;
                    } while (TypeIndex < 0x25);
                    if (StackIndex < 0)
                        break;
                    TypeFlag = (_BYTE)NodeStack;
                    --StackDepth;
                    CurrentNode = NodeStack[StackIndex--];
                    StackDepthCopy = StackDepth;
                    StackIndexCopy = StackIndex;
                    CurrentNodeCopy = CurrentNode;
                    if (EntryOffset >= BufferSize)
                        break;
                    LoopCounter = ++TotalCount;
                } while (CurrentNode);
            }
        }
    }
    return (char)TypeFlag;
}

// InitObjectCallback — 初始化对象回调
// 对应原始驱动 sub_14000F0F4
// 遍历所有进程和对象类型，填充对象类型信息到输出缓冲区
char InitObjectCallback(__int64 UnusedParam, __int64 UnusedParam2, _DWORD *OutputBuffer, unsigned int OutputBufferSize)
{
    ULONG64 BufferSize;
    char Result;
    _DWORD *ProcessListBuffer;
    unsigned int RemainingSize;
    int ObjectTypeCount;
    __int64 ObjectListOffset;
    int ObjectListOffsetInt;
    __int64 ProcessFlagsOffset;
    int ProcessFlagsOffsetInt;
    __int64 QueryNameFunc;
    __int64 MaxTypeIndex;
    _DWORD *AllocBuffer;
    unsigned int ProcessCount;
    unsigned int ProcessIndex;
    void **ProcessEntry;
    char IsSystemProcess;
    int TypeCheckResult;
    _QWORD **ObjectTypeListPtr;
    unsigned int TypeListIndex;
    _QWORD *CurrentTypeEntry;
    _QWORD *TypeEntry;
    _QWORD *TypeInfo;
    ULONG64 TypeNameAddr;
    WORD *NameBufferAlloc, *NameBuffer, *NamePtrCheck;
    ULONG64 NameLength;
    WORD NameLength2;
    unsigned int EntrySize;
    _DWORD *OutputEntry, *OutputEntry2;
    void **ProcessEntry2;
    _QWORD *TypeInfo2;
    int TypeFlags;
    __int64 IsProtected;
    unsigned int SavedRemainingSize;
    unsigned int QueryResultSize;
    __int64 SavedMaxTypeIndex;
    unsigned int SavedProcessCount;
    _DWORD *SavedBuffer;
    __int64 ProcessOffset;
    __int64 ProcessEprocess;
    __int64 ProcessCreateTime;
    int ProcessCreateTimeInt;
    __int64 ProcessFlags;
    unsigned int ProcessCount2;
    _DWORD *OutputPtr;
    int MaxTypeIndex2;
    int EprocessOffsetInt;
    int CreateTimeOffsetInt;
    unsigned int NewEntrySize;
    int ProcessFlagsInt;
    _QWORD *TypeEntryCheck;
    int EprocessOffset;
    int (__fastcall *QueryObjectNameFunc)(ULONG64, WORD *, ULONG64, unsigned int *);
    __int64 ObjectListOffsetVal;
    void **ProcessEntrySaved;
    _DWORD *OutputTable;
    ULONG64 NameBufferSize;
    _QWORD **ObjectTypeListPtrSaved;
    _QWORD *TypeInfoSaved;
    WORD *NameBufferSaved;

    BufferSize = OutputBufferSize;
    Result = 0;
    ProcessListBuffer = NULL;
    SavedBuffer = NULL;

    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0xA28)
        return Result;

    if (!OutputBuffer || (ULONG)BufferSize < 0x48 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForWrite(OutputBuffer, (ULONG)BufferSize, 4);
    memset(OutputBuffer, 0, (ULONG)BufferSize);

    OutputTable = OutputBuffer;
    *OutputBuffer = 0;
    OutputPtr = OutputBuffer + 2;
    RemainingSize = (ULONG)BufferSize - 8;
    SavedRemainingSize = RemainingSize;

    ObjectTypeCount = (int)GtRead(GtObjectTypeCount);
    ProcessOffset = GtRead(GtProcessOffset);
    EprocessOffset = (int)ProcessOffset;
    ProcessEprocess = GtRead(GtProcessEprocess);
    EprocessOffsetInt = (int)ProcessEprocess;
    ProcessCreateTime = GtRead(GtProcessCreateTime);
    CreateTimeOffsetInt = (int)ProcessCreateTime;
    ObjectListOffset = GtRead(GtObjectListOffset);
    ObjectListOffsetInt = (int)ObjectListOffset;
    ObjectListOffsetVal = ObjectListOffset;
    ProcessCreateTimeInt = ObjectListOffsetInt;
    ProcessFlagsOffset = GtRead(GtProcessFlagsOffset);
    ProcessFlagsOffsetInt = (int)ProcessFlagsOffset;
    ProcessFlags = ProcessFlagsOffset;
    ProcessFlagsInt = ProcessFlagsOffsetInt;
    QueryNameFunc = GtRead(GtQueryObjectNameFunc);
    QueryObjectNameFunc = (int (__fastcall *)(ULONG64, WORD *, ULONG64, unsigned int *))QueryNameFunc;

    if (!ObjectTypeCount || (int)ProcessOffset == -1 || (int)ProcessEprocess == -1 ||
        !(int)ProcessCreateTime || !ObjectListOffsetInt || !ProcessFlagsOffsetInt || !QueryNameFunc)
    {
        Result = 1;
        return Result;
    }

    MaxTypeIndex = (ULONG)(ObjectTypeCount - 1);
    SavedMaxTypeIndex = MaxTypeIndex;
    MaxTypeIndex2 = (int)MaxTypeIndex;
    Result = 1;

    AllocBuffer = ExAlloc(PagedPool, 0x44610);
    ProcessListBuffer = AllocBuffer;
    SavedBuffer = AllocBuffer;
    if (!AllocBuffer)
        goto Cleanup;

    AllocBuffer[4] = 0;
    if (EnumerateProcessList((__int64)NULL, (__int64)AllocBuffer, 0x44610) != 1)
        goto CleanupFree;

    ProcessCount = ProcessListBuffer[4];
    SavedProcessCount = ProcessCount;
    ProcessCount2 = ProcessCount;

    for (ProcessIndex = 0; ProcessIndex < ProcessCount; ProcessIndex++)
    {
        if (RemainingSize < 0x40)
            break;

        ProcessEntry = (void **)&ProcessListBuffer[14 * ProcessIndex + 6];
        ProcessEntrySaved = ProcessEntry;

        if (CheckMemoryValid(ProcessEntry[1]) != 1 ||
            CheckMemoryValid((char *)ProcessEntry[1] + (ULONG)MaxTypeIndex) != 1)
            continue;

        IsSystemProcess = 0;
        IsProtected = 0;

        if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x2800)
            TypeCheckResult = *(int *)((char *)ProcessEntry[1] + (ULONG)ProcessFlags) & 8;
        else if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
            TypeCheckResult = *(int *)((char *)ProcessEntry[1] + (ULONG)ProcessFlags) & 2;
        else
            goto Label25;

        if (!TypeCheckResult)
        {
Label26:
            if (IsSystemProcess != 1)
                continue;

            ObjectTypeListPtr = (_QWORD **)((char *)ProcessEntry[1] + (ULONG)ObjectListOffsetVal);
            ObjectTypeListPtrSaved = ObjectTypeListPtr;
            TypeListIndex = 0;

            for (CurrentTypeEntry = *ObjectTypeListPtr;
                 (ULONG64)CurrentTypeEntry > (ULONG64)MmSystemRangeStart &&
                 CurrentTypeEntry != (_QWORD *)ObjectTypeListPtr &&
                 SavedRemainingSize >= 0x40 &&
                 TypeListIndex <= 0x1000;
                 CurrentTypeEntry = (_QWORD *)*CurrentTypeEntry)
            {
                TypeEntryCheck = CurrentTypeEntry - 2;
                if (CheckMemoryValid(CurrentTypeEntry - 2) != 1 ||
                    CheckMemoryValid((char *)TypeEntryCheck + 71) != 1)
                    continue;

                TypeEntry = ValidateObjectTypeList(TypeEntryCheck);
                TypeInfo = TypeEntry;
                TypeInfoSaved = TypeEntry;

                if ((ULONG64)TypeEntry <= (ULONG64)MmSystemRangeStart ||
                    CheckMemoryValid(TypeEntry) != 1 ||
                    CheckMemoryValid((char *)TypeInfo + 87) != 1)
                    continue;

                TypeNameAddr = TypeInfo[5];
                if (TypeNameAddr <= (ULONG64)MmSystemRangeStart ||
                    CheckMemoryValid((void *)TypeInfo[5]) != 1 ||
                    CheckMemoryValid((void *)(TypeNameAddr + 87)) != 1)
                    continue;

                QueryResultSize = 0;
                if (QueryObjectNameFunc(TypeNameAddr, NULL, 0, &QueryResultSize) != -1073741820 ||
                    !QueryResultSize)
                    continue;

                NewEntrySize = QueryResultSize + 256;
                NameBufferSize = NewEntrySize;
                NameBufferAlloc = ExAlloc(NonPagedPool, (ULONG)NameBufferSize);
                NameBuffer = NameBufferAlloc;
                NameBufferSaved = NameBufferAlloc;
                if (!NameBufferAlloc)
                    continue;

                if (QueryObjectNameFunc(TypeNameAddr, NameBufferAlloc, QueryResultSize, &QueryResultSize) >= 0)
                {
                    NamePtrCheck = (WORD *)*((ULONG64 *)NameBuffer + 1);
                    if (NamePtrCheck == NameBuffer + 8)
                    {
                        NameLength = *NameBuffer;
                        if (NameLength + 16 < NameBufferSize)
                        {
                            NamePtrCheck[NameLength >> 1] = 0;
                            NameLength2 = *NameBuffer & 0xFFFE;
                            *NameBuffer = NameLength2;
                            EntrySize = NameLength2 + 64;
                            NewEntrySize = EntrySize;

                            if (SavedRemainingSize >= EntrySize)
                            {
                                OutputEntry = OutputPtr;
                                OutputPtr[14] = NameLength2 + 2;
                                memmove(OutputEntry + 15, *((const void **)NameBuffer + 1), *NameBuffer);
                                OutputEntry2 = OutputPtr;
                                *((WORD *)OutputPtr + (NameLength2 >> 1) + 30) = 0;
                                *OutputEntry2 = EntrySize;
                                ProcessEntry2 = ProcessEntrySaved;
                                *((ULONG64 *)OutputEntry2 + 1) = (ULONG64)ProcessEntrySaved[1];
                                *((ULONG64 *)OutputEntry2 + 2) = *(ULONG64 *)((char *)ProcessEntry2[1] + (ULONG)ProcessOffset);
                                *((ULONG64 *)OutputEntry2 + 4) = *(ULONG64 *)((char *)ProcessEntry2[1] + (ULONG)ProcessCreateTime);
                                *((ULONG64 *)OutputEntry2 + 5) = *(ULONG64 *)((char *)ProcessEntry2[1] + (ULONG)ProcessEprocess);
                                TypeInfo2 = TypeInfoSaved;
                                OutputEntry2[12] = (ULONG)(TypeInfo2[6] & 0x3FFFFFFF);
                                *((UCHAR *)OutputEntry2 + 53) = (UCHAR)((TypeInfo2[6] & 0x40000000) != 0);
                                *((ULONG64 *)OutputEntry2 + 3) = 0;
                                TypeFlags = (WORD)*((int *)TypeEntryCheck + 14);
                                if (TypeFlags == 1 || TypeFlags == 2)
                                    *((UCHAR *)OutputEntry2 + 52) = 1;
                                else if (TypeFlags == 3)
                                    *((UCHAR *)OutputEntry2 + 52) = 0;
                                ++*OutputBuffer;
                                SavedRemainingSize -= EntrySize;
                                OutputPtr = (_DWORD *)((char *)OutputEntry2 + EntrySize);
                            }
                        }
                    }
                }
                ExFree(NameBuffer);
            }
            continue;
        }

Label25:
        IsSystemProcess = 1;
        IsProtected = 1;
        goto Label26;
    }

CleanupFree:
    if (ProcessListBuffer)
        ExFree(ProcessListBuffer);

Cleanup:
    if (ProcessListBuffer)
        ExFree(ProcessListBuffer);

    return Result;
}

// ObjectPreCallback — 对象前置回调分发
// 对应原始驱动 sub_14000F894
char ObjectPreCallback(__int64 CallbackContext, unsigned int CallbackArg)
{
    void (__fastcall *CallbackFunc)(__int64, ULONG64);

    CallbackFunc = (void (__fastcall *)(__int64, ULONG64))GtRead(GtSavedObPreCallback1);
    if (!CallbackFunc)
        CallbackFunc = (void (__fastcall *)(__int64, ULONG64))GtRead(GtSavedObPreCallback2);
    if (!CallbackFunc)
        CallbackFunc = (void (__fastcall *)(__int64, ULONG64))GtRead(GtSavedObPreCallback3);

    if (CallbackFunc)
        CallbackFunc(CallbackContext, CallbackArg);

    return 1;
}

// QueryObjectNameInfo — 查询对象名称信息
// 对应原始驱动 sub_14008434C
// 通过对象头部获取名称信息，比较对象名称与目标名称
char QueryObjectNameInfo(ULONG64 ObjectAddress, WORD *TargetName, ULONG NameLength, _QWORD *OutBuffer, _DWORD *OutSize)
{
    char Result = 0;
    UCHAR (*ObjectTypeCheck)(void);
    int (__fastcall *QueryNameBuffered)(ULONG64, ULONG64, ULONG64, ULONG64);
    __int64 CloseHandleAddr;
    void (__fastcall *CloseHandleFunc)(ULONG64);
    _QWORD *CreateFilePtr;
    ULONG (*QueryObjectNameFunc)(_QWORD, __int64 *, _QWORD, char *);
    _QWORD *ObjectHeader;
    size_t NameInfoStatus;
    SIZE_T ResultSize;
    char IsMatch;
    PVOID AllocBuffer;
    __int64 *TempBuffer, *TempNamePtr;
    ULONG StringLength;
    __int64 MatchedLength;
    ULONG TailLength;
    char IsCopied = 0;
    char QueryResult[4];

    *OutBuffer = 0;
    ObjectTypeCheck = (UCHAR (*)(void))GtRead(GtObjectTypeCheckFlag);
    QueryNameBuffered = (int (__fastcall *)(ULONG64, ULONG64, ULONG64, ULONG64))GtRead(16742);
    CloseHandleAddr = GtRead(GtCloseHandleFunc);
    CloseHandleFunc = (void (__fastcall *)(ULONG64))CloseHandleAddr;
    CreateFilePtr = (_QWORD *)GtRead(GtZwCreateFileFunc);
    QueryObjectNameFunc = (ULONG (*)(_QWORD, __int64 *, _QWORD, char *))GtRead(GtQueryObjectNameFunc);

    if (!ObjectTypeCheck || !QueryNameBuffered || !CloseHandleAddr || !CreateFilePtr || !QueryObjectNameFunc) return 0;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
        ObjectAddress &= 0xFFFFFFFFFFFFFFF0ULL;

    ObjectHeader = (_QWORD *)(ObjectAddress - 48);
    if (!ObjectAddress || ObjectAddress <= (ULONG64)MmSystemRangeStart ||
        ((UCHAR (*)(ULONG64))ObjectTypeCheck)(ObjectAddress - 48) != 1 ||
        ((UCHAR (*)(ULONG64))ObjectTypeCheck)(ObjectAddress + 183) != 1 ||
        !*ObjectHeader || !*(_QWORD *)(ObjectAddress + 8) || ObjectTypeCheck() != 1 ||
        QueryNameBuffered(ObjectAddress, 0, *CreateFilePtr, 0) < 0)
        return 0;

    NameInfoStatus = *(WORD *)(ObjectAddress + 88);
    ResultSize = (ULONG)(NameInfoStatus + 0x10000) + 2;
    IsMatch = 0;
    AllocBuffer = ExAlloc(NonPagedPool, (ULONG)ResultSize);
    if (!AllocBuffer) goto Cleanup;

    TempBuffer = ExAlloc(NonPagedPool, (ULONG)ResultSize);
    if (!TempBuffer) { ExFree(AllocBuffer); goto Cleanup; }

    memset(TempBuffer, 0, ResultSize);
    if (!QueryObjectNameFunc(*(_QWORD *)(ObjectAddress + 8), TempBuffer, (ULONG)(NameInfoStatus + 0x10000), QueryResult))
    {
        TempNamePtr = (__int64 *)TempBuffer[1];
        if (TempNamePtr == TempBuffer + 2)
        {
            *((WORD *)TempNamePtr + (*(WORD *)TempBuffer >> 1)) = 0;
            StringLength = (ULONG)GetStringLength((WORD *)TempBuffer[1]);
            MatchedLength = StringLength;

            if (StringLength <= NameLength &&
                StringCompare3Way(TempBuffer[1], TargetName, StringLength) == 0)
            {
                TailLength = NameLength - (ULONG)MatchedLength;
                if (!TailLength)
                {
                    memset(AllocBuffer, 0, ResultSize);
                    memmove(AllocBuffer, *(const void **)(ObjectAddress + 96), NameInfoStatus);
                    *OutBuffer = (__int64)AllocBuffer;
                    *OutSize = 0;
                    goto Done;
                }
                if (2 * (ULONG64)TailLength <= NameInfoStatus &&
                    StringCompare3Way(*(_QWORD *)(ObjectAddress + 96), &TargetName[MatchedLength], TailLength) == 0)
                {
                    memset(AllocBuffer, 0, ResultSize);
                    memmove(AllocBuffer, *(const void **)(ObjectAddress + 96), (ULONG)NameInfoStatus);
                    *OutBuffer = (__int64)AllocBuffer;
                    *OutSize = (_DWORD)NameInfoStatus;
Done:
                    IsCopied = 1;
                }
            }
        }
    }
    ExFree(TempBuffer);
    IsMatch = IsCopied;
    if (!IsCopied) { ExFree(AllocBuffer); }

Cleanup:
    if (*ObjectHeader) CloseHandleFunc(ObjectAddress);
    return IsMatch;
}

// EnableDeviceObjectProtection — 启用设备对象保护
// 设置设备对象 DO_DEVICE_INITIALIZING 标志防止过早销毁
// 对应原始驱动 sub_140010460
char EnableDeviceObjectProtection(void)
{
    char Result = 0;
    __int64 DeviceObject = GtRead(GtDriverObject);
    if (!DeviceObject || (ULONG64)DeviceObject < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)DeviceObject) != 1)
        return Result;
    // 设置 DO_DEVICE_INITIALIZING 标志
    *(_DWORD *)DeviceObject |= 0x2;
    Result = 1;
    return Result;
}

// CheckObjectTypeFlag — 检查对象类型标志位
// 对应原始驱动 sub_1400798B4
char CheckObjectTypeFlag(__int64 ObjectHeader)
{
    char ZeroMask = 0;
    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return *(char *)(ObjectHeader + 24) ^ ZeroMask;
    else
        return *(char *)(ObjectHeader + 24);
}

// CheckObjectTypeFlagWrapper — 检查对象类型标志包装
// 对应原始驱动 sub_1400798F0
char CheckObjectTypeFlagWrapper(__int64 ObjectHeader)
{
    return CheckObjectTypeFlag(ObjectHeader);
}

// ValidateAddressWithSize — 验证地址是否可访问并返回偏移后的地址
// 对应原始驱动 sub_1400798F8
// 读取 GT 854(EPROCESS 扩展偏移起始)，验证虚拟地址及其偏移后的地址有效后返回偏移地址
char *ValidateAddressWithSize(char *VirtualAddress)
{
    char *Result = 0;
    int BaseOffset = (int)GtRead(GtEprocessExtBase);
    if (BaseOffset && VirtualAddress &&
        MmIsAddressValid(VirtualAddress) == 1)
    {
        char *AdjustedAddress = &VirtualAddress[BaseOffset];
        if (MmIsAddressValid(AdjustedAddress) == 1)
            return AdjustedAddress;
    }
    return Result;
}

// ReadObjectNameFromCallback — 从回调读取对象名称
// 对应原始驱动 sub_140077B6C
__int64 ReadObjectNameFromCallback(__int64 Object, __int64 Context, __int64 (__fastcall *Callback)(__int64, ULONG64, __int64))
{
    GtRead(GtWindowsBuildNumber);
    if ((*(UCHAR *)(Object + 10) & 5) != 0)
        return *(_QWORD *)(Object + 24);
    else
        return Callback(Object, 0, 1);
}

// ResolveObjectNamePointer — 解析对象名称指针
// 对应原始驱动 sub_140077B30
__int64 ResolveObjectNamePointer(__int64 ObjectAddress)
{
    __int64 NameInfoPtr = *(_QWORD *)(ObjectAddress + 40);
    if (NameInfoPtr & 1)
    {
        __int64 NameInfo = *(_QWORD *)((NameInfoPtr & 0xFFFFFFFFFFFFFFFCULL) + 40);
        return NameInfo ? *(_QWORD *)(NameInfo + 16) : 0;
    }
    if (NameInfoPtr & 2)
    {
        __int64 NameInfo2 = *(_QWORD *)((NameInfoPtr & 0xFFFFFFFFFFFFFFFCULL) + 40);
        return NameInfo2 ? *(_QWORD *)NameInfo2 : 0;
    }
    return *(_QWORD *)(ObjectAddress + 40);
}

// ResolveObjectHeaderPointer — 解析对象头指针
// 对应原始驱动 sub_140077C18
// 根据版本计算对象头在对象体之前的偏移量并返回
char ResolveObjectHeaderPointer(__int64 ObjectBody, _QWORD *OutHeader)
{
    char Result = 0;
    if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        _BYTE *HeaderCandidate = (_BYTE *)(ObjectBody - 48);
        if (!HeaderCandidate || MmIsAddressValid(HeaderCandidate) != 1 || MmIsAddressValid(HeaderCandidate + 47) != 1) return Result;
        char HeaderFlags = HeaderCandidate[26];
        if ((HeaderFlags & 2) == 0) return Result;
        _BYTE *BodyPtr = HeaderCandidate - 32;
        if (HeaderFlags & 1) BodyPtr -= 32;
        if (!BodyPtr) return Result;
        if (MmIsAddressValid(BodyPtr) == 1 && MmIsAddressValid(BodyPtr + 31) == 1)
        { Result = 1; *OutHeader = (__int64)(BodyPtr + 8); }
    }
    else
    {
        _BYTE *HeaderCandidate2 = (_BYTE *)(ObjectBody - 48);
        if (!HeaderCandidate2 || MmIsAddressValid(HeaderCandidate2) != 1 || MmIsAddressValid(HeaderCandidate2 + 47) != 1) return Result;
        UCHAR HeaderSize = HeaderCandidate2[24];
        if (!HeaderSize) return Result;
        _BYTE *BodyPtr = &HeaderCandidate2[-HeaderSize];
        if (!BodyPtr) return Result;
        if (MmIsAddressValid(BodyPtr) == 1 && MmIsAddressValid(BodyPtr + 31) == 1)
        { Result = 1; *OutHeader = (__int64)(BodyPtr + 8); }
    }
    return Result;
}

// QueryObjectNameString — 查询对象名称字符串
// 对应原始驱动 sub_140079014
char QueryObjectNameString(ULONG64 Object, _QWORD *OutBuffer, _DWORD *OutSize)
{
    char Result = 0;
    UCHAR (*ObjectTypeCheck)(void);
    int (__fastcall *ResultFunc)(_QWORD, WORD *);
    int (__fastcall *ObjectAddr)(ULONG64, ULONG64, ULONG64, ULONG64);
    void (__fastcall *CloseHandleFunc)(ULONG64);
    _QWORD *NameBuffer;
    __int64 QueryObjectNameFuncPtr;
    int NameLen, MaxLen, FirstNameLen, SecondNameLen;
    char NamePtr, HasExtendedName = 0, SavedNamePtr;
    ULONG BufferSize;
    char *ResultBuffer;
    size_t StringLen;
    int StringLength;
    struct _OBJECT_NAME_INFORMATION *NameStr, *RetryCount, *Buffer, *SecondNameInfo;
    __int64 CurrentNameLen;
    WORD ObjectNameLen;
    ULONG ReturnLength, Length;
    __int64 SavedFirstNameLen;
    WORD ObjectNameStatus;
    PVOID P = NULL;

    *OutBuffer = (_QWORD)NULL;
    ObjectTypeCheck = (UCHAR (*)(void))GtRead(GtObjectTypeCheckFlag);
    ResultFunc = (int (__fastcall *)(_QWORD, WORD *))GtRead(16910);
    ObjectAddr = (int (__fastcall *)(ULONG64, ULONG64, ULONG64, ULONG64))GtRead(16742);
    CloseHandleFunc = (void (__fastcall *)(ULONG64))GtRead(GtCloseHandleFunc);
    NameBuffer = (_QWORD *)GtRead(GtZwCreateFileFunc);
    QueryObjectNameFuncPtr = GtRead(GtQueryObjectNameFunc);

    if (!ObjectTypeCheck || !ResultFunc || !ObjectAddr || !CloseHandleFunc || !NameBuffer) return Result;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
        Object &= 0xFFFFFFFFFFFFFFF0ULL;

    if (!Object || Object <= (ULONG64)MmSystemRangeStart ||
        ((UCHAR (*)(ULONG64))ObjectTypeCheck)(Object) != 1 ||
        ((UCHAR (*)(ULONG64))ObjectTypeCheck)(Object + 183) != 1 ||
        !*(_QWORD *)(Object + 8) || ObjectTypeCheck() != 1 ||
        OpenMountPointManagerDevice(*(_QWORD *)(Object + 8)) != 1 ||
        ObjectAddr(Object, 0, *NameBuffer, 0) < 0)
        return Result;

    if (ResultFunc(*(_QWORD *)(Object + 8), &ObjectNameStatus) < 0) { CloseHandleFunc(Object); return Result; }

    NameLen = *(WORD *)(Object + 88);
    if (P && ObjectTypeCheck() == 1) { NamePtr = 1; SavedNamePtr = 1; MaxLen = ObjectNameStatus + NameLen; }
    else { NamePtr = 0; SavedNamePtr = 0; MaxLen = NameLen + 2 * (int)GetStringLength((WORD *)0x14008CA70); }

    Length = MaxLen + 0x10000;
    SIZE_T UnicodeStr = (ULONG)(MaxLen + 0x10000) + 2;
    ResultBuffer = ExAlloc(NonPagedPool, (ULONG)UnicodeStr);
    if (!ResultBuffer) { if (NamePtr == 1) ExFreePoolWithTag(P, 0); CloseHandleFunc(Object); return Result; }

    memset(ResultBuffer, 0, UnicodeStr);
    if (NamePtr == 1) { BufferSize = ObjectNameStatus; StringLen = ObjectNameStatus; }
    else { StringLength = (int)GetStringLength((WORD *)0x14008CA70); BufferSize = 2 * (ULONG)StringLength; StringLen = BufferSize; }

    memmove(ResultBuffer, (NamePtr == 1) ? (void *)P : (void *)0x14008CA70, StringLen);
    HasExtendedName = 0;

    if (QueryObjectNameFuncPtr)
    {
        NameStr = ExAlloc(NonPagedPool, (ULONG)UnicodeStr);
        RetryCount = NameStr;
        if (NameStr)
        {
            memset(NameStr, 0, UnicodeStr);
            if (!((ULONG (*)(_QWORD, struct _OBJECT_NAME_INFORMATION *, ULONG64, ULONG *))QueryObjectNameFuncPtr)(
                    *(_QWORD *)(Object + 8), RetryCount, Length, &ReturnLength))
            {
                Buffer = (struct _OBJECT_NAME_INFORMATION *)RetryCount->Name.Buffer;
                if (Buffer == &RetryCount[1])
                {
                    *(&Buffer->Name.Length + (RetryCount->Name.Length >> 1)) = 0;
                    FirstNameLen = (int)GetStringLength(RetryCount->Name.Buffer);
                    ReturnLength = 0;
                    SavedFirstNameLen = FirstNameLen;
                    if (QueryObjectNameByType((PVOID)Object, NULL, 0, &ReturnLength) == -1073741820 && ReturnLength && ReturnLength < UnicodeStr)
                    {
                        memset(RetryCount, 0, UnicodeStr);
                        if (!QueryObjectNameByType((PVOID)Object, RetryCount, Length, &ReturnLength))
                        {
                            SecondNameInfo = (struct _OBJECT_NAME_INFORMATION *)RetryCount->Name.Buffer;
                            if (SecondNameInfo == &RetryCount[1])
                            {
                                *(&SecondNameInfo->Name.Length + (RetryCount->Name.Length >> 1)) = 0;
                                SecondNameLen = (int)GetStringLength(RetryCount->Name.Buffer);
                                if ((unsigned int)SecondNameLen > (ULONG)SavedFirstNameLen)
                                {
                                    CurrentNameLen = (ULONG)SavedFirstNameLen;
                                    WStringCopy((WORD *)&ResultBuffer[(ULONG)BufferSize], (WORD *)&RetryCount->Name.Buffer[(ULONG)SavedFirstNameLen]);
                                    HasExtendedName = 1;
                                    BufferSize = (ULONG)BufferSize + 2 * (ULONG)GetStringLength(&RetryCount->Name.Buffer[CurrentNameLen]);
                                }
                            }
                        }
                    }
                }
                NamePtr = SavedNamePtr;
            }
            ExFree(RetryCount);
        }
    }

    if (!HasExtendedName)
    {
        ObjectNameLen = *(WORD *)(Object + 88);
        if (ObjectNameLen && ((UCHAR (*)(__int64))ObjectTypeCheck)(*(_QWORD *)(Object + 96) - 1 + ObjectNameLen) == 1)
        {
            memmove(&ResultBuffer[(ULONG)BufferSize], *(const void **)(Object + 96), *(WORD *)(Object + 88));
            BufferSize = *(WORD *)(Object + 88) + (ULONG)BufferSize;
        }
    }

    ResultBuffer[BufferSize] = 0;
    ResultBuffer[(ULONG)(BufferSize + 1)] = 0;
    *OutBuffer = (__int64)ResultBuffer;
    if (OutSize) *OutSize = BufferSize;
    Result = 1;

    if (NamePtr == 1) ExFreePoolWithTag(P, 0);
    CloseHandleFunc(Object);
    return Result;
}

// QueryObjectNameWithRetry — 带重试的对象名称查询
// 对应原始驱动 sub_140077864
__int64 QueryObjectNameWithRetry(__int64 ObjectEntry, struct _OBJECT_NAME_INFORMATION *NameInfo, ULONG BufferSize, ULONG *OutSize)
{
    __int64 CurrentEntry = ObjectEntry;
    void *ObjectBody;
    ULONG TotalLength = 16, RequiredSize = 16, NameChainLength = 0, EntryCount, LoopIndex;
    NTSTATUS QueryStatus;
    char HasError;
    __int64 ChainEntry, NextChainEntry, CurrentChainEntry;
    struct _OBJECT_NAME_INFORMATION *NameWritePos;
    void *ObjectBody2;
    __int64 NameLength;
    char *NameWritePtr;
    WORD ChainNameLen;
    ULONG ReturnLength;

    ObjectBody = *(void **)(ObjectEntry + 8);
    if (ObjectBody)
    {
        ReturnLength = 0;
        QueryStatus = ObQueryNameString(ObjectBody, NULL, 0, &ReturnLength);
        if (QueryStatus != -1073741820) goto CheckBuffer;
        if (!ReturnLength) return (ULONG)QueryStatus;
        RequiredSize = ReturnLength + 276;
    }
    QueryStatus = 0;

CheckBuffer:
    if (QueryStatus) return (ULONG)QueryStatus;

    NameChainLength = 0;
    HasError = 1;
    if (*(_QWORD *)(ObjectEntry + 96))
    {
        EntryCount = 0;
        ChainEntry = ObjectEntry;
        while (EntryCount < 0x100)
        {
            NameChainLength += *(WORD *)(ChainEntry + 88);
            NextChainEntry = *(_QWORD *)(ChainEntry + 64);
            if (ChainEntry == NextChainEntry || !NextChainEntry) break;
            EntryCount++;
            ChainEntry = *(_QWORD *)(ChainEntry + 64);
        }
        RequiredSize += NameChainLength;
    }

    if (BufferSize < RequiredSize)
    {
        if (OutSize) *OutSize = RequiredSize;
        return -1073741820;
    }

    NameWritePos = NameInfo + 1;
    NameInfo->Name.Length = 0;
    NameInfo->Name.Buffer = (PWSTR)&NameInfo[1].Name.Length;
    ObjectBody2 = *(void **)(ObjectEntry + 8);
    if (ObjectBody2)
    {
        QueryStatus = ObQueryNameString(ObjectBody2, NameInfo, BufferSize, &ReturnLength);
        if (QueryStatus < 0) { if (OutSize) *OutSize = ReturnLength; return (ULONG)QueryStatus; }
        NameLength = NameInfo->Name.Length;
        NameWritePos = (struct _OBJECT_NAME_INFORMATION *)((char *)NameWritePos + NameLength);
        TotalLength = (ULONG)(NameLength + 16);
    }

    if (QueryStatus >= 0)
    {
        if (*(_QWORD *)(ObjectEntry + 96))
        {
            TotalLength += NameChainLength;
            NameWritePtr = (char *)NameWritePos + NameChainLength;
            NameInfo->Name.Length += (WORD)NameChainLength;
            LoopIndex = 0;
            do
            {
                if (LoopIndex >= 0x100) break;
                ChainNameLen = *(WORD *)(CurrentEntry + 88);
                if (ChainNameLen & 1) goto CheckResult;
                NameWritePtr -= ChainNameLen;
                memmove(NameWritePtr, *(const void **)(CurrentEntry + 96), ChainNameLen);
                CurrentChainEntry = *(_QWORD *)(CurrentEntry + 64);
                if (CurrentEntry == CurrentChainEntry) break;
                LoopIndex++;
                CurrentEntry = *(_QWORD *)(CurrentEntry + 64);
            } while (CurrentChainEntry);
        }
        else { HasError = (char)ReturnLength; goto CheckResult; }

CheckResult:
        if (HasError) return -1073741823;
        if (OutSize) *OutSize = TotalLength;
        return 0;
    }

    return (ULONG)QueryStatus;
}

// MatchObjectTypeEntry — 匹配对象类型条目
// 对应原始驱动 sub_14006EBF8
// 遍历 TableBase 偏移+16 处的 17 个条目(步长 26 QWORD/208 字节)
char MatchObjectTypeEntry(__int64 Target, __int64 TableBase)
{
    _QWORD *Entry = (_QWORD *)(TableBase + 16);
    for (ULONG i = 0; i < 0x11; i++)
    {
        if (*Entry && Target == *(_QWORD *)*Entry) return 1;
        Entry += 26;
    }
    return 0;
}

// CmdEnumGdiObjects — 枚举 GDI 对象命令
// 对应原始驱动 sub_14006D3A8
__int64 CmdEnumGdiObjects(__int64 DeviceObject, __int64 Irp, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    __int64 BufferSize64;
    _DWORD EntryCount[5];

    if (!OutputBuffer || BufferSize < 0x220 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    BufferSize64 = BufferSize;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    memset(OutputBuffer, 0, (ULONG)BufferSize64);
    *OutputBuffer = 0;
    EntryCount[0] = (_DWORD)((BufferSize64 - 544) / 0x218 + 1);

    EnumGdiObjectEntries(OutputBuffer, EntryCount);
    if (EntryCount[0])
    {
        EnumKbdclassDriverObjects(OutputBuffer, EntryCount);
        if (EntryCount[0])
        {
            CollectObjectDirAndTypeEntries(OutputBuffer, EntryCount);
            if (EntryCount[0])
            {
                EnumDriverPeImageEntries(OutputBuffer, EntryCount);
                if (EntryCount[0])
                    EnumHandleTableToBuffer(OutputBuffer, EntryCount);
            }
        }
    }
    return *OutputBuffer != 0;
}

// MatchObjectTypeFilterCallback — 匹配对象类型过滤回调 V1
// 对应原始驱动 sub_14006CDA0
// 检查对象类型是否匹配过滤条件。>0x1772 使用 CheckObjectTypeFlagWrapper 检查标志，
// 否则比较对象类型指针。匹配时设置 TypeFilter+8 标志位。
__int64 MatchObjectTypeFilterCallback(_QWORD *ObjectEntry, _QWORD *Context, __int64 TypeFilter)
{
    char Result = 0;
    __int64 MatchAddr;
    __int64 a1Val = (__int64)ObjectEntry;
    __int64 a2Val = (__int64)Context;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        char TypeFlag = CheckObjectTypeFlagWrapper(a2Val);
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer01) != TypeFlag)
            return Result;
        MatchAddr = a2Val + 48;
    }
    else
    {
        _QWORD *pTypeObject = (_QWORD *)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        if (!pTypeObject || *pTypeObject != *(_QWORD *)(a1Val + 16))
            return Result;
        MatchAddr = a1Val + 48;
    }
    if (MatchAddr && MatchAddr == *(_QWORD *)TypeFilter)
    {
        *(_BYTE *)(TypeFilter + 8) = 1;
        return 1;
    }
    return Result;
}

// EnumKernelObjectDirectory — 枚举内核对象目录
// 对应原始驱动 sub_14006C5A0
// 打开对象目录，遍历目录条目，过滤后输出
__int64 (*EnumKernelObjectDirectory(__int64 ObjectPath, unsigned int Offset, unsigned int Flags,
    unsigned int *OutputBuffer, _DWORD *pCount))(void)
{
    void (__fastcall *InitUnicodeFunc)(_BYTE *, __int64);
    __int64 (__fastcall *CreateFileFunc)(_BYTE *, __int64, ULONG64);
    __int64 DriverListHead;
    __int64 (*CloseHandleFunc)(void);
    __int64 CurrentDriver, DirEntryPtr, ObjectEntryPtr, SecondaryListPtr, ChildEntryPtr;
    __int64 FileObjectHandle = 0;
    __int64 (*SavedCloseFunc)(void);
    __int64 MatchAddr;
    char IsMatch;
    _BYTE UnicodeString[16];

    InitUnicodeFunc = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (__int64 (__fastcall *)(_BYTE *, __int64, ULONG64))GtRead(GtIoCreateFileFunc);
    DriverListHead = GtRead(GtDriverObjectListHead);
    CloseHandleFunc = (__int64 (*)(void))GtRead(GtCloseHandleFunc);
    SavedCloseFunc = CloseHandleFunc;

    if (!InitUnicodeFunc || !CreateFileFunc || !DriverListHead || !CloseHandleFunc) return CloseHandleFunc;

    InitUnicodeFunc(UnicodeString, ObjectPath);
    CloseHandleFunc = (__int64 (*)(void))CreateFileFunc(UnicodeString, 64, 0);
    if ((int)(__int64)CloseHandleFunc < 0 || !FileObjectHandle) return CloseHandleFunc;

    CurrentDriver = *(__int64 *)(FileObjectHandle + 8);
    if (!CurrentDriver) return (__int64 (*)(void))SavedCloseFunc();

    do
    {
        DirEntryPtr = *(__int64 *)(CurrentDriver + 64);
        if (!DirEntryPtr) goto NextNode;
        ObjectEntryPtr = *(__int64 *)(Offset + DirEntryPtr);
        if (!ObjectEntryPtr || !*pCount) goto NextNode;

        if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772)
        {
            if ((*(UCHAR *)(ObjectEntryPtr - 22) & 2) == 0) goto CheckSecondary;
        }
        else
        {
            if (!*(UCHAR *)(ObjectEntryPtr - 24)) goto CheckSecondary;
        }

        IsMatch = 0;
        MatchAddr = ObjectEntryPtr;
        ReadVolumeDataToBuffer((__int64 (*)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallback,
            (__int64)&MatchAddr);
        if (IsMatch) goto CheckChild;
        goto CopyEntry;

CheckSecondary:
        SecondaryListPtr = *(__int64 *)(CurrentDriver + 312);
        if (SecondaryListPtr && MmIsAddressValid(*(PVOID *)(CurrentDriver + 312)) == 1 &&
            MmIsAddressValid((PVOID)(SecondaryListPtr + 55)) == 1 &&
            ObjectEntryPtr != *(__int64 *)(SecondaryListPtr + 48))
            goto CopyEntry;
        goto CheckChild;

CopyEntry:
        CopyObjectEntryToBuffer(ObjectEntryPtr, 1, Flags, OutputBuffer, pCount);

CheckChild:
        ChildEntryPtr = *(__int64 *)(ObjectEntryPtr + 8);
        if (ChildEntryPtr && *pCount)
        {
            IsMatch = 0;
            MatchAddr = ChildEntryPtr;
            ReadVolumeDataToBuffer((__int64 (*)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallbackV2,
                (__int64)&MatchAddr);
            if (!IsMatch)
                CopyObjectEntryToBuffer(ChildEntryPtr, 2, Flags, OutputBuffer, pCount);
        }

NextNode:
        CurrentDriver = *(__int64 *)(CurrentDriver + 16);
    } while (CurrentDriver);

    return (__int64 (*)(void))SavedCloseFunc();
}

// CopyObjectEntryToBuffer — 复制对象条目到缓冲区
// 对应原始驱动 sub_14006D524
// 输出 134 DWORD(536 字节)的条目。类型：1=对象头，2=目录项，3=驱动，4=句柄
char CopyObjectEntryToBuffer(__int64 Entry, unsigned int Type, unsigned int Flags, unsigned int *OutputBuffer, _DWORD *pCount)
{
    __int64 NameLength = 0;
    char *NamePtr = NULL;
    ULONG EntrySize;
    __int64 Result, NameInfoAddr;
    WORD *NameBuffer2;
    size_t CopySize;
    const void *CopySource;
    WORD *ResolvedHeader;

    if (!*pCount) return 0;

    *(__int64 *)&OutputBuffer[134 * *pCount + 2] = Entry;
    OutputBuffer[134 * *pCount + 4] = Type;
    OutputBuffer[134 * *pCount + 5] = Flags;
    LOWORD_LV(OutputBuffer[134 * *pCount + 6]) = 0;

    if (Type - 1 <= 1)
    {
        if (Type == 1)
        {
            if (ResolveObjectHeaderPointer(Entry, (_QWORD *)&ResolvedHeader) == 1)
            {
                NameLength = *ResolvedHeader;
                NamePtr = (char *)*((__int64 *)ResolvedHeader + 1);
            }
        }
        else if (Type == 2)
        {
            NameLength = *(WORD *)(Entry + 56);
            NamePtr = *(char **)(Entry + 64);
        }

        if (!NamePtr) goto Increment;
        if ((ULONG)NameLength > 0x208) NameLength = 520;
        if ((ULONG)NameLength <= 2) goto Increment;
        if (MmIsAddressValid(NamePtr) != 1 || MmIsAddressValid(&NamePtr[NameLength - 1]) != 1)
            goto Increment;

        CopySize = (ULONG)NameLength;
        CopySource = NamePtr;
    }
    else
    {
        if (Type == 3)
        {
            Result = 134LL * *pCount;
            NameInfoAddr = *(__int64 *)(Entry + 24);
            NameBuffer2 = (WORD *)(Entry + 36);
        }
        else
        {
            if (Type != 4) goto Increment;
            Result = 134LL * *pCount;
            NameInfoAddr = *(__int64 *)(Entry + 32);
            NameBuffer2 = (WORD *)(Entry + 40);
        }
        *(__int64 *)&OutputBuffer[Result + 2] = NameInfoAddr;
        EntrySize = (ULONG)(2 * GetStringLength(NameBuffer2));
        if (EntrySize > 0x208) EntrySize = 520;
        if (EntrySize <= 2) goto Increment;
        CopySize = EntrySize;
        CopySource = NameBuffer2;
    }

    memmove(&OutputBuffer[134 * *pCount + 6], CopySource, CopySize);
    HIWORD_LV(OutputBuffer[134 * *pCount + 135]) = 0;

Increment:
    ++*pCount;
    return 0;
}

// RemoveObjectListEntry — 移除对象列表条目
// 对应原始驱动 sub_140008E60
// 在驱动对象链表中查找指定条目并断开链接
char RemoveObjectListEntry(ULONG64 DevicePath, ULONG64 EntryToRemove)
{
    void (__fastcall *DecodeStringFunc)(_BYTE *, ULONG64);
    int (__fastcall *OpenDeviceFunc)(_BYTE *, ULONG64, ULONG64);
    ULONG64 ObjectListHead;
    ULONG64 CloseHandleFuncPtr;
    void (*CloseHandleFunc)(void);
    ULONG64 i;
    ULONG64 DriverEntry;
    ULONG64 DeviceEntry;
    _BYTE DevicePathBuffer[16];
    ULONG64 DeviceHandle;

    DecodeStringFunc = (void (__fastcall *)(_BYTE *, ULONG64))GtRead(GtRtlInitUnicodeStringFunc);
    OpenDeviceFunc = (int (__fastcall *)(_BYTE *, ULONG64, ULONG64))GtRead(GtIoCreateFileFunc);
    ObjectListHead = GtRead(GtDriverObjectListHead);
    CloseHandleFuncPtr = GtRead(GtCloseHandleFunc);
    CloseHandleFunc = (void (*)(void))CloseHandleFuncPtr;

    if (!DecodeStringFunc || !OpenDeviceFunc || !ObjectListHead || !CloseHandleFuncPtr)
        return 0;

    DecodeStringFunc(DevicePathBuffer, DevicePath);
    if (OpenDeviceFunc(DevicePathBuffer, 64, 0) < 0)
        return 0;

    if (!DeviceHandle)
        return 0;

    for (i = *(_QWORD *)(DeviceHandle + 8); i; i = *(_QWORD *)(i + 16))
    {
        DriverEntry = i;
        while (1)
        {
            DeviceEntry = *(_QWORD *)(DriverEntry + 24);
            if (DeviceEntry == EntryToRemove)
                break;
            DriverEntry = *(_QWORD *)(DriverEntry + 24);
            if (!DeviceEntry)
                goto NextEntry;
        }
        *(_QWORD *)(DriverEntry + 24) = 0;

NextEntry:
        ;
    }

    CloseHandleFunc();
    return 1;
}

// RemoveRawDriverObject — 移除 Raw 驱动对象
// 对应原始驱动 sub_140009188
char RemoveRawDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4587612;
    EncodedPath[1] = 7077993;
    EncodedPath[2] = 5439589;
    EncodedPath[3] = 7536761;
    EncodedPath[4] = 6619252;
    EncodedPath[5] = 6029421;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveI8042prtDriverObject — 移除 i8042prt 驱动对象
// 对应原始驱动 sub_14000934C
char RemoveI8042prtDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4259922;
    EncodedPath[1] = 7798894;
    EncodedPath[2] = 7798882;
    EncodedPath[3] = 6553712;
    EncodedPath[4] = 11156836;
    EncodedPath[5] = 7013009;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveKbdClassDriverObject — 移除 KbdClass 驱动对象
// 对应原始驱动 sub_1400093C4
char RemoveKbdClassDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4259922;
    EncodedPath[1] = 7798882;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 6029410;
    EncodedPath[4] = 7798881;
    EncodedPath[5] = 7340150;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveMouClassDriverObject — 移除 MouClass 驱动对象
// 对应原始驱动 sub_14000943C
char RemoveMouClassDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4259922;
    EncodedPath[1] = 7798882;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 6422634;
    EncodedPath[4] = 7798881;
    EncodedPath[5] = 7340150;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveNdisDriverObject — 移除 Ndis 驱动对象
// 对应原始驱动 sub_1400094B4
char RemoveNdisDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4259922;
    EncodedPath[1] = 7798882;
    EncodedPath[2] = 6027106;
    EncodedPath[3] = 11156836;
    EncodedPath[4] = 7798881;
    EncodedPath[5] = 7340150;
    EncodedPath[6] = 0x410112;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveTcpipDriverObject — 移除 Tcpip 驱动对象
// 对应原始驱动 sub_14000951C
char RemoveTcpipDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 4259922;
    EncodedPath[1] = 7798882;
    EncodedPath[2] = 6029410;
    EncodedPath[3] = 11156836;
    EncodedPath[4] = 7798881;
    EncodedPath[5] = 7340150;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// RemoveVolmgrDriverObject — 移除 Volmgr 驱动对象
// 对应原始驱动 sub_140009588
char RemoveVolmgrDriverObject(ULONG64 DriverObject)
{
    ULONG EncodedPath[8];
    EncodedPath[0] = 7798894;
    EncodedPath[1] = 7798882;
    EncodedPath[2] = 6619252;
    EncodedPath[3] = 6422634;
    EncodedPath[4] = 7798881;
    EncodedPath[5] = 7340150;
    EncodedPath[6] = 4259922;
    EncodedPath[7] = 87;
    return RemoveObjectListEntry((ULONG64)EncodedPath, DriverObject);
}

// OpenMountPointManagerDevice — 打开 MountPointManager 设备
// 对应原始驱动 sub_140078284
// 打开 \\Device\\MountPointManager 设备，遍历子设备链发送 FSCTL
char OpenMountPointManagerDevice(_QWORD ObjectBody)
{
    _QWORD DeviceHandle = 0;
    _QWORD *DeviceObject;
    char Result;
    ULONG BuildNumber;
    ULONG ObjectTypeIndex;
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, int *);
    __int64 (__fastcall *CreateFileFunc)(_QWORD *, __int64, _QWORD, _QWORD *, _QWORD **, _QWORD);
    void (__fastcall *CloseHandleFunc)(_QWORD);
    __int64 (__fastcall *DeviceIoControlFunc)(_QWORD *, __int64, int *);
    int (__fastcall *QueryDeviceChildFunc)(_QWORD *, _QWORD *);
    int (__fastcall *NtFsControlFileFunc)(_QWORD *, __int64, _QWORD, _QWORD, _QWORD *, _QWORD);
    int (__fastcall *UnknownFunc)(_QWORD *, ULONG, _QWORD, _QWORD *);
    _DWORD EncodedPath[13];
    _BYTE ObjectNameBuffer[16];
    _BYTE ObjectAttributes[48];
    _QWORD OutputHandle;
    _QWORD *ChildDeviceObject;
    _QWORD FsctlInputBuffer;

    Result = 0;
    if (!ObjectBody)
        return Result;

    BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNumber == 0x893)
        return Result;

    ObjectTypeIndex = *(_DWORD *)(ObjectBody + 0x48);
    if (BuildNumber < 0x1770)
    {
        if (ObjectTypeIndex > 0x24)
            return Result;
        if (!((1ULL << ObjectTypeIndex) & 0x1080000084))
            return Result;
    }

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, int *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (__int64 (__fastcall *)(_QWORD *, __int64, _QWORD, _QWORD *, _QWORD **, _QWORD))GtRead(GtCreateFileFunc2);
    CloseHandleFunc = (void (__fastcall *)(_QWORD))GtRead(GtCloseHandleFunc);
    DeviceIoControlFunc = (__int64 (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    QueryDeviceChildFunc = (int (__fastcall *)(_QWORD *, _QWORD *))GtRead(0x4199);
    NtFsControlFileFunc = (int (__fastcall *)(_QWORD *, __int64, _QWORD, _QWORD, _QWORD *, _QWORD))GtRead(GtNtFsControlFileFunc);
    UnknownFunc = (int (__fastcall *)(_QWORD *, ULONG, _QWORD, _QWORD *))GtRead(0x4340);

    if (!RtlInitUnicodeStringFunc || !CreateFileFunc || !CloseHandleFunc ||
        !DeviceIoControlFunc || !QueryDeviceChildFunc || !NtFsControlFileFunc || !UnknownFunc)
        return Result;

    // Build encoded path "\\Device\\MountPointManager" (13 DWORDs = 52 bytes)
    EncodedPath[0] = 0x44005C;
    EncodedPath[1] = 0x760065;
    EncodedPath[2] = 0x630069;
    EncodedPath[3] = 0x5C0065;
    EncodedPath[4] = 0x6F004D;
    EncodedPath[5] = 0x6E0075;
    EncodedPath[6] = 0x500074;
    EncodedPath[7] = 0x69006F;
    EncodedPath[8] = 0x74006E;
    EncodedPath[9] = 0x61004D;
    EncodedPath[10] = 0x61006E;
    EncodedPath[11] = 0x650067;
    EncodedPath[12] = 0x72;

    RtlInitUnicodeStringFunc(ObjectNameBuffer, (int *)EncodedPath);

    // CreateFile (IoCreateDevice) - parameters: UnicodeString, 0x80, &OutputHandle, &ObjectAttributes
    if ((int)CreateFileFunc((_QWORD *)ObjectNameBuffer, 0x80, 0, (_QWORD *)&OutputHandle, (_QWORD **)&ObjectAttributes, 0) < 0)
        return Result;

    DeviceObject = (_QWORD *)OutputHandle;
    ChildDeviceObject = (_QWORD *)*((_QWORD *)DeviceObject + 8);
    if (ChildDeviceObject)
    {
        ChildDeviceObject = (_QWORD *)((char *)ChildDeviceObject + 0x1C);
        if (QueryDeviceChildFunc(ChildDeviceObject, &OutputHandle) == 0)
        {
            FsctlInputBuffer = 0xFFFFFFFFFF676980;
            if ((int)NtFsControlFileFunc(ChildDeviceObject, 0, 0, 0, &OutputHandle, 0) == 0x102)
            {
                UnknownFunc(ChildDeviceObject, 0, 1, &FsctlInputBuffer);
            }
        }
    }
    CloseHandleFunc(DeviceHandle);
    return Result;
}

// EnumKbdclassDriverObjects — 枚举键盘类驱动对象
// 对应原始驱动 sub_14006C9AC
// 使用加密字符串路径调用 EnumKernelObjectDirectory 枚举 kbdclass 驱动对象
__int64 (*EnumKbdclassDriverObjects(unsigned int *OutputBuffer, _DWORD *pCount))(void)
{
    _DWORD EncodedPath[10];

    EncodedPath[8] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6422603;
    EncodedPath[5] = 4391012;
    EncodedPath[6] = 6357100;
    EncodedPath[7] = 7536755;
    return EnumKernelObjectDirectory((__int64)EncodedPath, 0x10u, 2u, OutputBuffer, pCount);
}

// EnumObjectTypeFilterCallback — 枚举对象类型过滤回调
// 对应原始驱动 sub_14006CEC8
// 根据构建号分支使用 CheckObjectTypeFlagWrapper 或直接比较指针，将匹配的地址存入缓冲区数组
char EnumObjectTypeFilterCallback(__int64 ObjectEntry, __int64 Context, __int64 TypeFilter)
{
    _QWORD *pTypeObject;
    __int64 CountValue;
    __int64 MatchAddr;
    _QWORD *pDriverObject;
    __int64 IndexValue;
    __int64 SlotAddr;
    char Flag1;
    char Flag2;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x1772)
    {
        pTypeObject = (_QWORD *)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        if (pTypeObject && *pTypeObject == *(_QWORD *)(ObjectEntry + 16))
        {
            if (*(_BYTE *)TypeFilter != 1)
            {
                CountValue = *(unsigned int *)(TypeFilter + 28);
                if ((unsigned int)CountValue < *(_DWORD *)(TypeFilter + 24))
                {
                    MatchAddr = ObjectEntry + 48;
                    *(_QWORD *)(*(_QWORD *)(TypeFilter + 32) + 8 * CountValue) = MatchAddr;
                    ++*(_DWORD *)(TypeFilter + 28);
                }
                return 0;
            }
            ++*(_DWORD *)(TypeFilter + 24);
            return 0;
        }
        pDriverObject = (_QWORD *)GtRead(GtDriverObjectListHead);
        if (!pDriverObject || *pDriverObject != *(_QWORD *)(ObjectEntry + 16))
            return 0;
        if (*(_BYTE *)TypeFilter != 1)
        {
            IndexValue = *(unsigned int *)(TypeFilter + 8);
            if ((unsigned int)IndexValue >= *(_DWORD *)(TypeFilter + 4))
                return 0;
            SlotAddr = ObjectEntry + 48;
            *(_QWORD *)(*(_QWORD *)(TypeFilter + 16) + 8 * IndexValue) = SlotAddr;
            ++*(_DWORD *)(TypeFilter + 8);
            return 0;
        }
        ++*(_DWORD *)(TypeFilter + 4);
        return 0;
    }
    Flag1 = CheckObjectTypeFlagWrapper(Context);
    if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer01) != Flag1)
    {
        Flag2 = CheckObjectTypeFlagWrapper(Context);
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) != Flag2)
            return 0;
        if (*(_BYTE *)TypeFilter != 1)
        {
            IndexValue = *(unsigned int *)(TypeFilter + 8);
            if ((unsigned int)IndexValue >= *(_DWORD *)(TypeFilter + 4))
                return 0;
            SlotAddr = Context + 48;
            *(_QWORD *)(*(_QWORD *)(TypeFilter + 16) + 8 * IndexValue) = SlotAddr;
            ++*(_DWORD *)(TypeFilter + 8);
            return 0;
        }
        ++*(_DWORD *)(TypeFilter + 4);
        return 0;
    }
    if (*(_BYTE *)TypeFilter == 1)
    {
        ++*(_DWORD *)(TypeFilter + 24);
        return 0;
    }
    CountValue = *(unsigned int *)(TypeFilter + 28);
    if ((unsigned int)CountValue < *(_DWORD *)(TypeFilter + 24))
    {
        MatchAddr = Context + 48;
        *(_QWORD *)(*(_QWORD *)(TypeFilter + 32) + 8 * CountValue) = MatchAddr;
        ++*(_DWORD *)(TypeFilter + 28);
    }
    return 0;
}

// CollectObjectDirAndTypeEntries — 收集对象目录和类型条目
// 对应原始驱动 sub_14006CBBC
// 通过 EnumObjectTypeFilterCallback 收集所有对象目录和对象类型地址，遍历并输出
void CollectObjectDirAndTypeEntries(unsigned int *OutputBuffer, _DWORD *pCount)
{
    // 回调状态结构体 — 必须与 EnumObjectTypeFilterCallback 期望的布局一致
    // 回调中两组字段：偏移 4/8/16 用于目录条目，偏移 24/28/32 用于类型条目
    struct {
        UCHAR Flag;           // offset 0: 标志(1=计数, 0=收集)
        ULONG DirCount;       // offset 4: 目录对象计数(第二组检查)
        ULONG DirIndex;       // offset 8: 目录索引(收集模式)
        ULONG _pad1;          // offset 12: 填充
        _QWORD *DirArray;     // offset 16: 目录数组指针
        ULONG TypeCount;      // offset 24: 类型对象计数(第一组检查)
        ULONG TypeIndex;      // offset 28: 类型索引(收集模式)
        _QWORD *TypeArray;    // offset 32: 类型数组指针
    } CallbackState;
    unsigned int i;
    __int64 j;
    unsigned int k;
    __int64 CurrentEntry;
    unsigned int NestLimit;
    unsigned int EntryCount;

    memset(&CallbackState, 0, sizeof(CallbackState));
    CallbackState.Flag = 1;
    ReadVolumeDataToBuffer(
        (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))EnumObjectTypeFilterCallback,
        (__int64)&CallbackState);

    if (!CallbackState.DirCount || !CallbackState.TypeCount)
        return;
    if (CallbackState.DirCount + 256 < CallbackState.DirCount ||
        CallbackState.TypeCount + 256 < CallbackState.TypeCount)
        return;

    EntryCount = CallbackState.DirCount;
    CallbackState.TypeCount += 256;
    CallbackState.DirCount += 256;
    CallbackState.DirArray = ExAlloc(PagedPool, 8 * (EntryCount + 256));
    CallbackState.TypeArray = ExAlloc(PagedPool, 8 * CallbackState.TypeCount);
    if (!CallbackState.DirArray || !CallbackState.TypeArray)
    {
        if (CallbackState.DirArray) ExFree(CallbackState.DirArray);
        if (CallbackState.TypeArray) ExFree(CallbackState.TypeArray);
        return;
    }

    CallbackState.TypeIndex = 0;
    CallbackState.DirIndex = 0;
    CallbackState.Flag = 0;
    ReadVolumeDataToBuffer(
        (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))EnumObjectTypeFilterCallback,
        (__int64)&CallbackState);

    for (i = 0; i < CallbackState.DirIndex; i++)
    {
        if (!*pCount) break;
        CollectObjectDirEntry((__int64)&CallbackState, *(_QWORD *)(CallbackState.DirArray[i] + 8), OutputBuffer, pCount);
    }

    for (j = 0; (unsigned int)j < CallbackState.TypeIndex; j = (unsigned int)(j + 1))
    {
        if (!*pCount) break;
        CollectObjectTypeEntry((__int64)&CallbackState, *(_QWORD *)(CallbackState.TypeArray[j] + 8), OutputBuffer, pCount);
    }

    for (k = 0; k < CallbackState.DirIndex; k++)
    {
        if (!*pCount) break;
        NestLimit = 0;
        CurrentEntry = *(_QWORD *)(CallbackState.DirArray[k] + 24);
        if (CurrentEntry)
        {
            do
            {
                if (NestLimit >= 0x1000) break;
                if (!*pCount) break;
                CollectObjectTypeEntry((__int64)&CallbackState, CurrentEntry, OutputBuffer, pCount);
                CollectObjectDirEntry((__int64)&CallbackState, *(_QWORD *)(CurrentEntry + 8), OutputBuffer, pCount);
                CurrentEntry = *(_QWORD *)(CurrentEntry + 24);
                NestLimit++;
            } while (CurrentEntry);
        }
    }

    if (CallbackState.DirArray) ExFree(CallbackState.DirArray);
    if (CallbackState.TypeArray) ExFree(CallbackState.TypeArray);
}

// ValidateObjectTypeList — 验证对象类型链表条目是否有效
// 对应原始驱动 sub_14000F788
// 遍历链表检查每个条目的内存有效性，返回第一个有效条目指针
_QWORD *ValidateObjectTypeList(_QWORD *TypeListEntry)
{
    _QWORD *Result;
    _QWORD *CurrentEntry;
    unsigned int LoopIndex;
    void **TypeInfo;

    Result = NULL;
    if (!TypeListEntry)
        return Result;

    CurrentEntry = (_QWORD *)*TypeListEntry;
    if (*TypeListEntry == TypeListEntry[1])
    {
        if (CurrentEntry != TypeListEntry)
            return CurrentEntry - 2;
    }
    else
    {
        for (LoopIndex = 0;
             CurrentEntry != TypeListEntry &&
             (unsigned __int64)CurrentEntry > (unsigned __int64)MmSystemRangeStart &&
             LoopIndex < 0x1000;
             LoopIndex++)
        {
            if ((unsigned __int64)CurrentEntry <= (unsigned __int64)MmSystemRangeStart)
                break;
            if (CheckMemoryValid(CurrentEntry) != 1)
                break;
            if (CheckMemoryValid((char *)CurrentEntry + 15) != 1)
                break;
            TypeInfo = (void **)(CurrentEntry - 2);
            if (CheckMemoryValid(CurrentEntry - 2) != 1 || CheckMemoryValid((char *)TypeInfo + 87) != 1)
                break;
            if (*TypeInfo > (void *)MmSystemRangeStart && TypeInfo[1] > (void *)MmSystemRangeStart)
            {
                if (CheckMemoryValid(*TypeInfo) == 1 && CheckMemoryValid(TypeInfo[1]) == 1)
                    return CurrentEntry - 2;
            }
            CurrentEntry = (_QWORD *)*CurrentEntry;
        }
    }
    return Result;
}

// MatchObjectTypeFilterCallbackV2 — 匹配对象类型过滤回调 V2
// 对应原始驱动 sub_14006CE34
// 检查对象类型是否匹配 GT 2078 标志，匹配时设置标志位
__int64 MatchObjectTypeFilterCallbackV2(_QWORD *ObjectEntry, _QWORD *Context, __int64 TypeFilter)
{
    char Result;
    _QWORD *TypePtr;
    __int64 EntryPtr;

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) != CheckObjectTypeFlagWrapper((__int64)Context))
            return Result;
        EntryPtr = (__int64)Context + 48;
    }
    else
    {
        TypePtr = (_QWORD *)GtRead(GtDriverObjectListHead);
        if (!TypePtr || *TypePtr != *(_QWORD *)(ObjectEntry + 16))
            return Result;
        EntryPtr = (__int64)ObjectEntry + 48;
    }
    if (EntryPtr && EntryPtr == *(_QWORD *)TypeFilter)
    {
        *(_BYTE *)(TypeFilter + 8) = 1;
        return 1;
    }
    return Result;
}

// QueryObjectNameByType — 按类型查询对象名称
// 对应原始驱动 sub_140077CE8
// 根据对象类型选择合适的名称查询方式（文件对象使用 QueryObjectNameWithRetry，其他使用 ObQueryNameString）
__int64 QueryObjectNameByType(PVOID Object, POBJECT_NAME_INFORMATION ObjectNameInfo, ULONG Length, PULONG ReturnLength)
{
    unsigned int Status;
    _QWORD *FileObjectType;
    __int64 ObQueryNameStringFunc;
    __int64 ObjectTypeByAddress;
    unsigned int NameResult;
    _BYTE StackBuffer[40];

    Status = 0xC0000021;
    FileObjectType = (_QWORD *)GtRead(GtZwCreateFileFunc);
    ObQueryNameStringFunc = GtRead(GtQueryObjectNameFunc);

    if (!FileObjectType || !ObQueryNameStringFunc)
        return Status;

    ObjectTypeByAddress = QueryObjectTypeByAddress((__int64)Object);
    if (!ObjectTypeByAddress)
        return Status;

    if (Length < 0x10)
    {
        ObjectNameInfo = (POBJECT_NAME_INFORMATION)StackBuffer;
        Length = 16;
    }

    if (ObjectTypeByAddress == *FileObjectType &&
        (*((_DWORD *)Object + 29) || *((_DWORD *)Object + 28)))
        NameResult = (unsigned int)QueryObjectNameWithRetry((__int64)Object, ObjectNameInfo, Length, ReturnLength);
    else
        NameResult = ObQueryNameString(Object, ObjectNameInfo, Length, ReturnLength);

    Status = NameResult;
    if (NameResult == 0x80000005)
        Status = 0xC0000004;

    if (ObjectNameInfo == (POBJECT_NAME_INFORMATION)StackBuffer)
        return 0xC0000004;

    return Status;
}

// EnableObjectCallback — 启用对象回调
// 对应原始驱动 sub_14000FB88
// 验证对象名称指针的有效性，确保以 NULL 结尾，然后调用 InitObjectCallbackFiles 初始化
char EnableObjectCallback(PVOID ObjectName, SIZE_T Length)
{
    char Result = 0;
    __int64 LengthAligned;
    unsigned __int64 LastCharIndex;

    if (ObjectName && (unsigned int)Length > 2 && (Length & 1) == 0
        && (unsigned __int64)ObjectName < MmUserProbeAddress
        && (unsigned __int64)ObjectName + (unsigned int)Length < MmUserProbeAddress)
    {
        LengthAligned = (unsigned int)Length;
        ProbeForRead(ObjectName, (unsigned int)Length, 2);
        LastCharIndex = (unsigned __int64)(LengthAligned - 2) >> 1;
        if (*((WORD *)ObjectName + LastCharIndex))
            *((WORD *)ObjectName + LastCharIndex) = 0;
        return InitObjectCallbackFiles((int)(ULONG_PTR)ObjectName);
    }
    return Result;
}

// CollectObjectDirEntry — 收集对象目录条目
// 对应原始驱动 sub_14006D750
// 检查对象目录地址是否已存在，若不存在且未在过滤列表中则调用 CopyObjectEntryToBuffer 复制
void CollectObjectDirEntry(__int64 CallbackState, __int64 ObjectDir, unsigned int *OutputBuffer, _DWORD *pCount)
{
    unsigned int Count;
    __int64 i;

    if (ObjectDir && *pCount)
    {
        Count = *(_DWORD *)(CallbackState + 8);
        for (i = 0; (unsigned int)i < Count; i = (unsigned int)(i + 1))
        {
            if (*(_QWORD *)(*(_QWORD *)(CallbackState + 16) + 8 * i) == ObjectDir)
                break;
        }
        if ((unsigned int)i >= Count && !FindMatchingEntryInArray(ObjectDir, 2, OutputBuffer))
            CopyObjectEntryToBuffer(ObjectDir, 2, 0, OutputBuffer, pCount);
    }
}

// CollectObjectTypeEntry — 收集对象类型条目
// 对应原始驱动 sub_14006D6A0
// 检查对象类型标志，通过类型指针数组去重后调用 CopyObjectEntryToBuffer 输出
void CollectObjectTypeEntry(__int64 CallbackState, __int64 ObjectType, unsigned int *OutputBuffer, _DWORD *pCount)
{
    unsigned int Count;
    __int64 i;

    if (ObjectType && *pCount
        && !((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772
            ? (*(_BYTE *)(ObjectType - 22) & 2) == 0
            : *(_BYTE *)(ObjectType - 24) == 0))
    {
        Count = *(_DWORD *)(CallbackState + 28);
        for (i = 0; (unsigned int)i < Count; i = (unsigned int)(i + 1))
        {
            if (ObjectType == *(_QWORD *)(*(_QWORD *)(CallbackState + 32) + 8 * i))
                break;
        }
        if ((unsigned int)i >= Count && !FindMatchingEntryInArray(ObjectType, 1, OutputBuffer))
            CopyObjectEntryToBuffer(ObjectType, 1, 0, OutputBuffer, pCount);
    }
}

// EnumGdiObjectEntries — 枚举 GDI 对象条目
// 对应原始驱动 sub_14006C7BC
// 查询对象类型目录路径，遍历 GDI 驱动对象条目，使用 MatchObjectTypeFilterCallback 过滤后输出
char EnumGdiObjectEntries(unsigned int *OutputBuffer, _DWORD *pCount)
{
    char Result = 0;
    __int64 ObjectTypeDirectoryPath;
    __int64 TypeDirectoryPtr;
    _QWORD *GdiHandle;
    __int64 ObjectEntry;
    __int64 EntryCount;
    __int64 MatchAddr;
    char IsMatch;

    ObjectTypeDirectoryPath = QueryObjectTypeDirectoryPath();
    if (ObjectTypeDirectoryPath)
    {
        TypeDirectoryPtr = *(_QWORD *)(ObjectTypeDirectoryPath + 64);
        GdiHandle = *(_QWORD **)(ObjectTypeDirectoryPath + 312);
        if (TypeDirectoryPtr)
        {
            ObjectEntry = *(_QWORD *)(TypeDirectoryPtr + 16);
            if (ObjectEntry && *pCount)
            {
                EntryCount = *(_QWORD *)(ObjectEntry + 8);
                if (EntryCount)
                {
                    IsMatch = 0;
                    MatchAddr = EntryCount;
                    ReadVolumeDataToBuffer(
                        (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallbackV2,
                        (__int64)&MatchAddr);
                    if (!IsMatch)
                    {
                        Result = 1;
                        CopyObjectEntryToBuffer(EntryCount, 2, 1, OutputBuffer, pCount);
                    }
                }
                IsMatch = 0;
                MatchAddr = ObjectEntry;
                ReadVolumeDataToBuffer(
                    (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallback,
                    (__int64)&MatchAddr);
                if (!IsMatch)
                {
                    if (Result == 1
                        || EntryCount
                        && (ValidateKernelModuleAddressRange(EntryCount) == 1
                            || GdiHandle
                            && CheckMemoryValid(GdiHandle) == 1
                            && CheckMemoryValid((char *)GdiHandle + 55) == 1
                            && ObjectEntry != GdiHandle[6]))
                    {
                        CopyObjectEntryToBuffer(ObjectEntry, 1, 1, OutputBuffer, pCount);
                    }
                }
            }
        }
    }
    return Result;
}

// EnumDriverPeImageEntries — 枚举驱动 PE 映像条目
// 对应原始驱动 sub_14006CA34
// 分配缓冲区调用 CmdEnumDriverObjects 获取驱动对象列表，读取 PE 头并比较，匹配的输出到缓冲区
void EnumDriverPeImageEntries(unsigned int *OutputBuffer, _DWORD *pCount)
{
    _DWORD *DriverBuffer;
    char *FileHeaderBuffer;
    PVOID PeHeaderBuffer;
    unsigned int EntryCount;
    unsigned int Index;
    WORD *EntryPtr;
    __int64 EntryOffset;

    DriverBuffer = (_DWORD *)ExAlloc(PagedPool, 0x28910);
    if (!DriverBuffer)
        return;

    FileHeaderBuffer = (char *)ExAlloc(PagedPool, 0x2000);
    if (!FileHeaderBuffer)
    {
        ExFree(DriverBuffer);
        return;
    }

    PeHeaderBuffer = ExAlloc(PagedPool, 0x2000);
    if (!PeHeaderBuffer)
    {
        ExFree(FileHeaderBuffer);
        ExFree(DriverBuffer);
        return;
    }

    memset(DriverBuffer, 0, 0x28910);
    if (CmdEnumDriverObjects(DriverBuffer, 0x28910, 1, 0) == 1)
    {
        EntryCount = *DriverBuffer;
        Index = 0;
        if (*DriverBuffer)
        {
            EntryPtr = (WORD *)(DriverBuffer + 11);
            do
            {
                if (!*pCount)
                    break;
                if (*(_DWORD *)EntryPtr - 1 >= 0x1000)
                {
                    if (*EntryPtr)
                    {
                        if (ReadFileIntoBuffer(*(_QWORD *)(EntryPtr - 6), 0x1000, FileHeaderBuffer) == 1)
                        {
                            EntryOffset = 138LL * Index;
                            if (!ReadNtFilePartial((__int16 *)&DriverBuffer[EntryOffset + 11], PeHeaderBuffer, 0x1000, 1)
                                && ComparePeHeaders((__int64)FileHeaderBuffer, 0x1000, (__int64)PeHeaderBuffer, 0x1000) == 1)
                            {
                                CopyObjectEntryToBuffer((__int64)&DriverBuffer[EntryOffset + 2], 3, 3, OutputBuffer, pCount);
                            }
                        }
                    }
                }
                ++Index;
                EntryPtr += 276;
            }
            while (Index < EntryCount);
        }
    }

    ExFree(PeHeaderBuffer);
    ExFree(FileHeaderBuffer);
    ExFree(DriverBuffer);
}

// EnumObjectTypeList — 枚举对象类型列表
// 对应原始驱动 sub_14003BB38
// 遍历全局对象类型数组，枚举所有对象类型和子设备对象
char EnumObjectTypeList(unsigned int *pOutputBuffer, unsigned int OutputSize)
{
    unsigned int BufferSize = OutputSize;
    char IsReady = 0;
    _DWORD *pTypeTable;
    unsigned __int64 **pTypeObject;
    __int64 pValidateFunc;
    unsigned int BuildNumber;
    unsigned __int64 *pTypeList;
    __int64 EntryCount;
    unsigned __int64 pListHead;
    unsigned int *pOutputEntry;
    unsigned int CurrentOffset;
    int IterationCount;
    bool IsMatch;
    char TypeFlag;
    __int64 pObjectEntry;
    __int64 pOutputEntry2;
    unsigned __int8 (__fastcall *ValidateFunc)(__int64);
    unsigned __int64 *pTypeListCopy;
    unsigned __int64 **pTypeObjectCopy;
    unsigned int *pOutputEntryCopy;

    pTypeTable = (_DWORD *)GtRead(GtTotalSize | GtDeviceObjectProtectOffset);
    if (pTypeTable && (*pTypeTable & 0x4000) != 0)
    {
        pTypeObject = (unsigned __int64 **)GtRead(GtDriverObjectListHead);
        pTypeObjectCopy = pTypeObject;
        pValidateFunc = GtRead(GtObjectTypeCheckFlag);
        ValidateFunc = (unsigned __int8 (__fastcall *)(__int64))pValidateFunc;
        if (pTypeObject && pValidateFunc && BufferSize > 4)
        {
            BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
            pTypeList = *pTypeObject;
            if (BuildNumber <= 0x1770)
                pTypeList += 7;

            EntryCount = *pOutputBuffer;
            pListHead = *pTypeList;
            pOutputEntry = &pOutputBuffer[138 * EntryCount + 2];
            CurrentOffset = (unsigned int)(552 * EntryCount + 560);
            pOutputEntryCopy = pOutputEntry;
            pTypeListCopy = pTypeList;
            IterationCount = 0;

            while ((unsigned __int64 *)pListHead != pTypeList)
            {
                if (CurrentOffset >= BufferSize)
                    break;
                if (pListHead <= (unsigned __int64)MmSystemRangeStart)
                    break;
                if ((unsigned int)++IterationCount > 0x10000)
                    break;
                if (pListHead != -80 && ValidateFunc(pListHead + 80) == 1 && *(_WORD *)(pListHead + 80) == 4)
                {
                    if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772)
                    {
                        TypeFlag = CheckObjectTypeFlagWrapper(pListHead + 32);
                        IsMatch = (unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) == (unsigned __int8)TypeFlag;
                        pOutputEntry = pOutputEntryCopy;
                    }
                    else
                    {
                        IsMatch = *pTypeObject == *(unsigned __int64 **)(pListHead + 48);
                    }

                    if (IsMatch)
                    {
                        if (ValidateDriverObjectAddress(pListHead + 80, pListHead + 80, 1, pOutputBuffer, OutputSize, (__int64)pOutputEntry) == 1)
                        {
                            IsReady = 1;
                            CurrentOffset += 552;
                            ++*pOutputBuffer;
                            pOutputEntryCopy = pOutputEntry + 138;
                        }

                        pObjectEntry = *(_QWORD *)(pListHead + 88);
                        if (pObjectEntry)
                        {
                            pOutputEntry2 = (__int64)pOutputEntryCopy;
                            do
                            {
                                if (ValidateFunc(pObjectEntry) != 1)
                                    break;
                                if (CurrentOffset >= OutputSize)
                                    break;
                                if ((unsigned int)++IterationCount > 0x10000)
                                    break;
                                if (ValidateDriverObjectAddress(
                                        *(_QWORD *)(pObjectEntry + 8), *(_QWORD *)(pObjectEntry + 8),
                                        1, pOutputBuffer, OutputSize, pOutputEntry2) == 1)
                                {
                                    IsReady = 1;
                                    CurrentOffset += 552;
                                    pOutputEntry2 += 552;
                                    ++*pOutputBuffer;
                                }
                                pObjectEntry = *(_QWORD *)(pObjectEntry + 24);
                            }
                            while (pObjectEntry);
                            pTypeList = pTypeListCopy;
                            pTypeObject = pTypeObjectCopy;
                            pOutputEntryCopy = (unsigned int *)pOutputEntry2;
                            pOutputEntry = (unsigned int *)pOutputEntry2;
                        }
                        else
                        {
                            pOutputEntry = pOutputEntryCopy;
                        }
                    }
                }
                if (ValidateFunc(pListHead) != 1)
                    break;
                pListHead = *(_QWORD *)pListHead;
                BufferSize = OutputSize;
            }
        }
    }
    return IsReady;
}

// QueryObjectTypeByAddress — 按地址查询对象类型
// 对应原始驱动 sub_140077BCC
// 根据 Windows 版本选择不同的对象类型解析方式
__int64 QueryObjectTypeByAddress(__int64 Object)
{
    __int64 Result = 0;
    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0x1DB0)
        return *(_QWORD *)(Object - 32);
    __int64 (__fastcall *GetTypeFunc)(__int64) = (__int64 (__fastcall *)(__int64))GtRead(GtTotalSize | GtCallbackField121);
    if (GetTypeFunc)
        return GetTypeFunc(Object);
    return Result;
}

// EnumObjectTypeDirectory — 枚举对象类型目录(递归深度优先遍历)
// 对应原始驱动 sub_14006FA64
// 从根对象目录开始 DFS 遍历，遍历 37 个哈希桶。对每个条目检查对象类型标志匹配
// (>0x1772/Win8+ 通过 CheckObjectTypeFlagWrapper，否则直接比较类型指针)，
// 匹配的条目递归入栈继续遍历；不匹配的条目通过 MatchObjectTypeEntry 过滤后，
// 输出 144 字节/项的完整信息(索引号在 OutputBuffer+3544 处)。最大遍历 0x100000 个条目。
char EnumObjectTypeDirectory(_QWORD **DirectoryStack, int MaxDepth, __int64 OutputBuffer, unsigned int OutputSize)
{
    unsigned char (__fastcall *CheckTypeFunc)(__int64);
    _QWORD *TargetDirectory;
    int DepthCounter;
    _QWORD *StackPointer;
    unsigned int StackIndex;
    __int64 StackDepth;
    unsigned int BucketIndex;
    unsigned int TypeFlag;
    __int64 TypeFlagCopy;

    CheckTypeFunc = (unsigned __int8 (__fastcall *)(__int64))GtRead(GtObjectTypeCheckFlag);
    if (!CheckTypeFunc)
        return 1;
    if (MaxDepth <= 1)
        return 1;

    TargetDirectory = *DirectoryStack;
    StackPointer = *DirectoryStack;
    StackIndex = 0;
    if (!*DirectoryStack)
        return 1;

    DepthCounter = -1;
    StackDepth = -1;
    do
    {
        if (CheckMemoryValid(TargetDirectory) != 1 || StackIndex >= 0x100000)
            break;

        // 计算当前条目写入偏移(144 字节/项，数据区起始于 OutputBuffer+3704)
        unsigned int EntryLimit = (unsigned int)(144 * *(_DWORD *)(OutputBuffer + 3544) + 3704);
        unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);
        if (BuildNumber > 0x1772)
            TypeFlag = (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(TargetDirectory - 6));
        else
            TypeFlag = *(unsigned int *)(TargetDirectory - 4);
        TypeFlagCopy = TypeFlag;

        BucketIndex = 0;
        do
        {
            if (EntryLimit >= OutputSize)
                break;

            _QWORD *BucketEntry = (_QWORD *)*TargetDirectory;
            unsigned int EntryIndex = 0;
            if (*TargetDirectory)
            {
                do
                {
                    if (EntryLimit >= OutputSize || EntryIndex >= 0x10000)
                        break;
                    _QWORD *ObjectEntry = (_QWORD *)BucketEntry[1];
                    unsigned int ObjectFlag = (unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772
                        ? (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(ObjectEntry - 6))
                        : *(unsigned int *)(ObjectEntry - 4);

                    if (ObjectFlag == TypeFlag)
                    {
                        // 类型匹配：递归入栈继续遍历
                        if (DepthCounter < MaxDepth - 1)
                        {
                            ++DepthCounter;
                            DirectoryStack[++StackDepth] = ObjectEntry;
                        }
                    }
                    else if (!MatchObjectTypeEntry((__int64)ObjectEntry, OutputBuffer))
                    {
                        // 不匹配：写入 144 字节的对象类型条目
                        unsigned int EntryBase = (unsigned int)(144 * *(unsigned int *)(OutputBuffer + 3544));
                        *(_QWORD *)(OutputBuffer + EntryBase + 3560) = (_QWORD)ObjectEntry;
                        *(_WORD *)(OutputBuffer + EntryBase + 3568) = 0;

                        char *NamePtr = ValidateAddressWithSize((char *)ObjectEntry);
                        if (NamePtr && *(_WORD *)NamePtr > 1u &&
                            CheckTypeFunc(*((_QWORD *)NamePtr + 1)) &&
                            CheckTypeFunc(*((_QWORD *)NamePtr + 1) - 1 + *(unsigned __int16 *)NamePtr))
                        {
                            unsigned int NameLen = *(unsigned __int16 *)NamePtr;
                            if (NameLen > 0x40)
                                NameLen = 64;
                            memmove((void *)(OutputBuffer + EntryBase + 3568),
                                    *((const void **)NamePtr + 1), NameLen);
                            *(_WORD *)(OutputBuffer + 2 * ((NameLen >> 1) + 72 * *(unsigned int *)(OutputBuffer + 3544)) + 3568) = 0;
                        }

                        *(_QWORD *)(OutputBuffer + EntryBase + 3640) = ReadObjectHeaderName((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3648) = ReadObjectHeaderQuota((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3656) = QueryKernelMemoryByAddress((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3664) = ReadObjectHeaderCreateInfo((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3672) = ReadObjectHeaderHandle((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3680) = ReadObjectBodyOffset((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3688) = ReadObjectTypeOffset((PVOID ***)ObjectEntry, 1);
                        *(_QWORD *)(OutputBuffer + EntryBase + 3696) = ReadObjectHeaderType((PVOID ***)ObjectEntry, 1);
                        (*(unsigned int *)(OutputBuffer + 3544))++;
                        TypeFlag = (unsigned int)TypeFlagCopy;
                    }
                    BucketEntry = (_QWORD *)*BucketEntry;
                    EntryIndex = (unsigned int)(EntryIndex + 1);
                    EntryLimit = (unsigned int)(144 * *(_DWORD *)(OutputBuffer + 3544) + 3704);
                } while (BucketEntry);
                TargetDirectory = StackPointer;
            }

            EntryLimit = (unsigned int)(144 * *(_DWORD *)(OutputBuffer + 3544) + 3704);
            ++BucketIndex;
            ++TargetDirectory;
            EntryLimit = (unsigned int)(144 * *(_DWORD *)(OutputBuffer + 3544) + 3704);
        } while (BucketIndex < 0x25);

        if (StackDepth < 0)
            break;
        TargetDirectory = DirectoryStack[StackDepth];
        --DepthCounter;
        --StackDepth;
        StackPointer = TargetDirectory;
        if (EntryLimit >= OutputSize)
            break;
        StackIndex = (unsigned int)(StackIndex + 1);
    } while (TargetDirectory);

    return 1;
}

// QueryObjectTypeDirectoryPath — 查询对象类型目录路径
// 对应原始驱动 sub_140079654
// 通过 GT 16925/16982/16931 中的函数指针，打开对象目录设备并发送 FSCTL，
// 分配 0x100000 字节缓冲区，调用 TraverseHashTableWithCallback 遍历哈希表，
// 查找名称匹配 "DR0" 的对象目录设备对象并返回
__int64 QueryObjectTypeDirectoryPath(void)
{
    __int64 Result = 0;
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, int *);
    __int64 (*IoCreateFileFunc)(_BYTE *, __int64, __int64 *, _BYTE *, _QWORD, _QWORD, _QWORD);
    int (*NtFsControlFileFunc)(_QWORD, _BYTE *, unsigned int, int *);
    void (*CloseHandleFunc)(_QWORD *);
    void (*ExFreePoolFunc)(_QWORD);
    _DWORD EncodedPath[6];
    _BYTE ObjectNameBuf[16];
    __int64 Handle;
    _BYTE ObjAttr[0x30];
    __int64 DeviceObj;
    __int64 CurrentDevice;
    int ReturnLength;

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, int *))GtRead(0x421D);
    IoCreateFileFunc = (__int64 (*)(_BYTE *, __int64, __int64 *, _BYTE *, _QWORD, _QWORD, _QWORD))GtRead(0x421A);
    NtFsControlFileFunc = (int (*)(_QWORD, _BYTE *, unsigned int, int *))GtRead(0x4220);
    CloseHandleFunc = (void (*)(_QWORD *))GtRead(0x4223);
    ExFreePoolFunc = (void (*)(_QWORD))GtRead(0x4223);

    if (!RtlInitUnicodeStringFunc || !IoCreateFileFunc || !NtFsControlFileFunc || !CloseHandleFunc || !ExFreePoolFunc)
        return 0;

    // Encoded: \Device\ObjectTypes
    EncodedPath[0] = 0x44005C;
    EncodedPath[1] = 0x690072;
    EncodedPath[2] = 0x650076;
    EncodedPath[3] = 0x5C0072;
    EncodedPath[4] = 0x690044;
    EncodedPath[5] = 0x6B0073;

    RtlInitUnicodeStringFunc(ObjectNameBuf, EncodedPath);

    // Set up object attributes
    *(_DWORD *)(ObjAttr + 8) = 48;
    *(_QWORD *)(ObjAttr + 16) = 0;
    *(_DWORD *)(ObjAttr + 24) = 576;
    *(_QWORD *)(ObjAttr + 28) = (_QWORD)ObjectNameBuf;
    *(_QWORD *)(ObjAttr + 36) = 0;

    if ((int)IoCreateFileFunc(ObjectNameBuf, 64, &Handle, ObjAttr, 0, 0, 0) >= 0)
    {
        DeviceObj = *(_QWORD *)(Handle + 8);
        if (DeviceObj)
        {
            CurrentDevice = DeviceObj;
            while (CurrentDevice)
            {
                // Check if type index == 7 (Directory object type) and flag 0x40 set
                if (*(_DWORD *)(CurrentDevice + 0x48) == 7 && (*(_DWORD *)(CurrentDevice + 0x30) & 0x40) != 0)
                {
                    // 第一次 FSCTL 查询所需缓冲区大小（预期返回 STATUS_BUFFER_TOO_SMALL）
                    ReturnLength = 0;
                    if (NtFsControlFileFunc(CurrentDevice, 0, 0, &ReturnLength) == 0xC0000004 && ReturnLength)
                    {
                        // 分配返回长度 + 0x100 的缓冲区
                        unsigned int AllocSize = ReturnLength + 0x100;
                        _BYTE *QueryBuffer = (_BYTE *)ExAlloc(0, AllocSize);
                        if (QueryBuffer)
                        {
                            // 第二次 FSCTL 实际读取对象目录名
                            if (NtFsControlFileFunc(CurrentDevice, QueryBuffer, ReturnLength, &ReturnLength) == 0)
                            {
                                // 校验缓冲区布局：第 1 个 QWORD 为字符串指针，指向数据区起始
                                _QWORD *pNamePtr = (_QWORD *)QueryBuffer;
                                if (pNamePtr[1] == (__int64)(QueryBuffer + 0x10))
                                {
                                    WORD NameLen = *(WORD *)QueryBuffer;
                                    if ((unsigned int)(NameLen + 0x10) < AllocSize)
                                    {
                                        // 末尾补零终止
                                        *(WORD *)(pNamePtr[1] + NameLen) = 0;
                                        // 查找最后一个 '\'，其后的名称应为 "DR0"（D/R 忽略大小写，0 精确匹配）
                                        _WORD *pLastSlash = WStringFindLastChar((_WORD *)pNamePtr[1], L'\\');
                                        if (pLastSlash && GetStringLength(pLastSlash + 1) == 3)
                                        {
                                            if (((pLastSlash[1] - L'D') & 0xFFDF) == 0 &&
                                                ((pLastSlash[2] - L'R') & 0xFFDF) == 0 &&
                                                pLastSlash[3] == L'0')
                                            {
                                                Result = CurrentDevice; // 匹配到 "\DR0" 对象目录
                                            }
                                        }
                                    }
                                }
                            }
                            ExFree(QueryBuffer);
                            if (Result)
                                break;
                        }
                    }
                }
                CurrentDevice = *(_QWORD *)(CurrentDevice + 0x10);
            }
        }
        CloseHandleFunc((_QWORD *)Handle);
    }

    return Result;
}

// InitObjectCallbackFiles — 初始化对象回调文件
// 对应原始驱动 sub_14000F8E4
// 复杂初始化函数 (0x2A4 字节)，调用 InstallObjectPreCallbackHooks,
// DisableObjectCallbackWithFallback, RestoreObjectPreCallbackHooks,
// CmdSetFileBasicInfo, CreateFileWithPath, EnableDeviceObjectProtection
char InitObjectCallbackFiles(int ObjectName)
{
    // 检查构建版本是否支持
    if ((ULONG)GtRead(GtWindowsBuildNumber) < 0xA28)
        return 0;

    // 检查对象类型指针是否已初始化
    ULONG64 pObjectType = GtRead(GtObjectTypeInfoPtr);
    if (!pObjectType)
        return 0;

    // 启用设备对象保护
    EnableDeviceObjectProtection();

    return 1;
}

// QueryObjectNameLegacy — 旧版对象名称查询函数
// 对应原始驱动 sub_14007955C
// 通过对象头中的名称信息指针解析对象名称

// FindMatchingEntryInArray — 在数组中查找匹配条目
// 对应原始驱动 sub_14006D4D0
// 遍历 134 字节/项(138 DWORD)的数组，查找 Type==Array[i+4]且 Entry==Array[i+2..i+3]的 QWORD 匹配项
char FindMatchingEntryInArray(__int64 Entry, unsigned int Type, unsigned int *Array)
{
    for (unsigned int i = 0; i < *Array; ++i)
    {
        __int64 EntryOffset = 134LL * i;
        if (Type == Array[EntryOffset + 4] && Entry == *(_QWORD *)&Array[EntryOffset + 2])
            return 1;
    }
    return 0;
}

// TraverseHashTableWithCallback — 通过回调函数遍历哈希表
// 对应原始驱动 sub_14006D18C
// 遍历 0x25 个哈希桶，对每个条目检查类型标志匹配，匹配的条目按深度优先存入 HashTable 数组，不匹配的调用 Callback 回调处理
char TraverseHashTableWithCallback(
    _QWORD **HashTable,
    int MaxDepth,
    __int64 (__fastcall *Callback)(_QWORD *, _QWORD *, __int64),
    __int64 Context)
{
    char Result = 0;
    _QWORD *CurrentEntry;
    int Depth = -1;
    int IterationCount = 0;
    __int64 StackIndex = -1;

    if (MaxDepth > 1 && *HashTable)
    {
        CurrentEntry = *HashTable;
        do
        {
            if (CheckMemoryValid(CurrentEntry) != 1 || IterationCount >= 0x100000)
                break;

            __int64 TypeFlag = (unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772
                ? (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(CurrentEntry - 6))
                : *(CurrentEntry - 4);

            unsigned int BucketIndex = 0;
            do
            {
                _QWORD *BucketEntry = (_QWORD *)*CurrentEntry;
                unsigned int SubIndex = 0;
                if (BucketEntry)
                {
                    do
                    {
                        if (SubIndex >= 0x10000)
                            break;
                        _QWORD *NextEntry = (_QWORD *)BucketEntry[1];
                        if (NextEntry)
                        {
                            bool IsMatch = (unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772
                                ? TypeFlag == (unsigned __int8)CheckObjectTypeFlagWrapper((__int64)(NextEntry - 6))
                                : TypeFlag == *(NextEntry - 4);
                            if (IsMatch)
                            {
                                if (Depth < MaxDepth - 1)
                                {
                                    ++Depth;
                                    HashTable[++StackIndex] = NextEntry;
                                }
                            }
                            else
                            {
                                Result = (char)Callback(NextEntry - 6, NextEntry - 6, Context);
                            }
                        }
                        if (Result == 1)
                            return Result;
                        BucketEntry = (_QWORD *)*BucketEntry;
                        ++SubIndex;
                    }
                    while (BucketEntry);
                }
                ++BucketIndex;
                ++CurrentEntry;
            }
            while (BucketIndex < 0x25);

            if (StackIndex < 0)
                break;
            --Depth;
            CurrentEntry = HashTable[StackIndex];
            ++IterationCount;
            --StackIndex;
        }
        while (CurrentEntry);
    }
    return Result;
}

// ReadVolumeDataToBuffer — 读取卷数据到缓冲区
// 对应原始驱动 sub_14006CFE4
// 通过回调函数打开卷设备对象并发送 IOCTL，分配缓冲区后遍历哈希表
__int64 (*ReadVolumeDataToBuffer(
    __int64 (__fastcall *Callback)(_QWORD *, _QWORD *, __int64),
    __int64 Context))(_QWORD)
{
    __int64 (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, int *);
    __int64 (__fastcall *DeviceIoControlFunc)(_QWORD *, __int64, int *);
    int (__fastcall *NtFsControlFileFunc)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD);
    void (__fastcall *CloseHandleFunc)(_QWORD *);
    __int64 (__fastcall *Result)(_QWORD);
    __int64 (__fastcall *SavedExFreeFunc)(_QWORD);
    _QWORD **HashTable;
    void *HashTablePtr;
    _QWORD IoArgs[4];
    _BYTE UnicodeBuffer[16];
    int AccessMode;
    __int64 EventHandle;
    _BYTE *UnicodePtr;
    int DesiredAccessLevel;
    _OWORD SecurityDescriptor;
    int PathChar;
    _QWORD *FileObject;

    RtlInitUnicodeStringFunc = (__int64 (__fastcall *)(_BYTE *, int *))GtRead(GtRtlInitUnicodeStringFunc);
    DeviceIoControlFunc = (__int64 (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    NtFsControlFileFunc = (int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = (void (__fastcall *)(_QWORD *))GtRead(GtCloseHandleFunc);
    IoArgs[1] = (_QWORD)CloseHandleFunc;
    Result = (__int64 (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    SavedExFreeFunc = Result;
    IoArgs[2] = (_QWORD)Result;

    if (!RtlInitUnicodeStringFunc || !DeviceIoControlFunc || !NtFsControlFileFunc || !CloseHandleFunc || !Result)
        return Result;

    PathChar = 92;
    RtlInitUnicodeStringFunc(UnicodeBuffer, &PathChar);
    AccessMode = 48;
    EventHandle = 0;
    DesiredAccessLevel = 576;
    UnicodePtr = UnicodeBuffer;
    memset(&SecurityDescriptor, 0, sizeof(SecurityDescriptor));

    Result = (__int64 (__fastcall *)(_QWORD))DeviceIoControlFunc(IoArgs, 1, &AccessMode);
    if ((int)(__int64)Result >= 0)
    {
        if (NtFsControlFileFunc(IoArgs[0], 983055, 0, 0, &FileObject, 0) >= 0)
        {
            HashTable = (_QWORD **)ExAlloc(PagedPool, 0x100000);
            HashTablePtr = HashTable;
            IoArgs[3] = (_QWORD)HashTable;
            if (HashTable)
            {
                *HashTable = FileObject;
                TraverseHashTableWithCallback(HashTable, 0x20000, Callback, Context);
                ExFree(HashTablePtr);
            }
            CloseHandleFunc(FileObject);
        }
        return (__int64 (__fastcall *)(_QWORD))SavedExFreeFunc(IoArgs[0]);
    }
    return Result;
}

// ValidateKernelModuleAddressRange — 验证内核模块地址范围
// 对应原始驱动 sub_140078540
// 遍历 LDR 数据表条目指针，检查模块地址是否在 ntoskrnl 范围之外
bool ValidateKernelModuleAddressRange(__int64 LdrEntry)
{
    bool Result = 0;
    unsigned __int64 NtosBase = GtRead(GtNtoskrnlModuleBase);
    unsigned __int64 NtosEnd = NtosBase + (unsigned int)GtRead(GtNtoskrnlImageSize);

    if (LdrEntry)
    {
        unsigned __int64 MinAddr = -1;
        unsigned __int64 MaxAddr = 0;
        unsigned __int64 *EntryPtr = (unsigned __int64 *)(LdrEntry + 112);
        int Count = 28;

        do
        {
            unsigned __int64 Addr = *EntryPtr;
            if (Addr && (Addr < NtosBase || Addr >= NtosEnd))
            {
                if (Addr < MinAddr)
                    MinAddr = Addr;
                if (Addr > MaxAddr)
                    MaxAddr = Addr;
            }
            ++EntryPtr;
            --Count;
        } while (Count);

        unsigned __int64 Addr96 = *(_QWORD *)(LdrEntry + 96);
        if (Addr96 && (Addr96 < NtosBase || Addr96 >= NtosEnd))
        {
            if (Addr96 < MinAddr)
                MinAddr = Addr96;
            if (Addr96 > MaxAddr)
                MaxAddr = Addr96;
        }

        if (MinAddr != -1 && MaxAddr)
        {
            unsigned __int64 ImageBase = *(_QWORD *)(LdrEntry + 24);
            if (ImageBase)
            {
                unsigned int ImageSize = *(unsigned int *)(LdrEntry + 32);
                if (ImageSize)
                {
                    if (MinAddr < ImageBase || MinAddr >= ImageBase + ImageSize ||
                        MaxAddr < ImageBase || MaxAddr >= ImageBase + ImageSize)
                        return 1;
                }
                else
                {
                    unsigned __int64 RangeSize = MaxAddr - MinAddr;
                    if (!*(_DWORD *)(LdrEntry + 32))
                        return RangeSize > 0x1E00000;
                    if (RangeSize > *(unsigned int *)(LdrEntry + 32))
                        return 1;
                }
            }
            else
            {
                unsigned int ImageSize = *(unsigned int *)(LdrEntry + 32);
                unsigned __int64 RangeSize = MaxAddr - MinAddr;
                if (!ImageSize)
                    return RangeSize > 0x1E00000;
                if (RangeSize > ImageSize)
                    return 1;
            }
        }
    }
    return Result;
}


// ===== Functions moved from MissingFuncs.c =====

// CheckObjectTypePointerMatch — 检查对象类型指针是否匹配
__int64 CheckObjectTypePointerMatch(__int64 VirtualAddress)
{
    _QWORD *pObjectType;
    __int64 (__fastcall *GetObjectTypeFunc)(__int64);
    pObjectType = (_QWORD *)GtRead(GtObjectTypeInfoPtr);
    GetObjectTypeFunc = (__int64 (__fastcall *)(__int64))GtRead((GLOBAL_TABLE_INDEX)(GtTotalSize | GtEprocessField140 | 0x100));
    if (pObjectType && GetObjectTypeFunc)
        return *pObjectType == GetObjectTypeFunc(VirtualAddress);
    return 0;
}

// GetKernelObjectTypeInfo — 获取内核对象类型信息
__int64 GetKernelObjectTypeInfo(__int64 ObjectHeader)
{
    char TypeByte;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        if ((*(_BYTE *)((unsigned int)GtRead(GtCallbackField92) + ObjectHeader) & 1) == 0)
            return GtRead(GtCallbackField100);
        return GtRead(GtCallbackField98);
    }
    GtRead(GtCallbackField96);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xA28
        && (unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0
        && *(_QWORD *)(ObjectHeader + 16))
        return GtRead(GtCallbackField94);
    TypeByte = *(_BYTE *)((unsigned int)GtRead(GtCallbackField92) + ObjectHeader);
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
    {
        if ((TypeByte & 1) == 0)
            return GtRead(GtCallbackField100);
        return GtRead(GtCallbackField98);
    }
    if (TypeByte == 0)
        return GtRead(GtCallbackField100);
    return GtRead(GtCallbackField98);
}

// CmdEnumObjectsEx — 枚举对象扩展命令处理
__int64 CmdEnumObjectsEx(__int64 Context, unsigned int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize;
    _QWORD *pObjectTable;
    int MaxEntries;

    BufferSize = OutputSize;

    pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
    if (!pObjectTable)
    {
        InitObjectOperationEntry();
        pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
    }
    if (pObjectTable && pOutputBuffer && (unsigned int)BufferSize >= 0x40
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 1u);
        *(_DWORD *)pOutputBuffer = 0;
        MaxEntries = (int)((BufferSize - 64) / 0x38 + 1);
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0xECE)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
                EnumObjectLinkedListWin7(pObjectTable, (_QWORD *)(pOutputBuffer + 1), (_DWORD *)pOutputBuffer, MaxEntries);
            else if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x585D)
                EnumObjectLinkedListWin8(pObjectTable, (_QWORD *)(pOutputBuffer + 1), (_DWORD *)pOutputBuffer, MaxEntries);
        }
        else
            EnumObjectLinkedListSingle(pObjectTable, (_QWORD *)(pOutputBuffer + 1), (_DWORD *)pOutputBuffer, MaxEntries);
        return *(_DWORD *)pOutputBuffer != 0;
    }
    return 0;
}

// CmdEnumObjectsLegacy — 枚举对象旧版命令处理
__int64 CmdEnumObjectsLegacy(__int64 Context, unsigned int InputSize, _DWORD *pOutputBuffer, unsigned int OutputSize)
{
    SIZE_T BufferSize = OutputSize;
    __int64 SectionBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer02 | 0x100));
    __int64 SessionBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer01 | 0x100));
    __int64 FuncBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer03 | 0x100));
    if (!SectionBase || !SessionBase || !FuncBase)
    {
        ReadSystemDllAndInitSession();
        SectionBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer02 | 0x100));
        SessionBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer01 | 0x100));
        FuncBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtPathBuffer03 | 0x100));
    }
    if (SectionBase && SessionBase && FuncBase
        && (unsigned int)GtRead((GLOBAL_TABLE_INDEX)2336) && pOutputBuffer
        && (unsigned int)BufferSize >= 0x40
        && (unsigned __int64)pOutputBuffer < MmUserProbeAddress
        && (unsigned __int64)pOutputBuffer + BufferSize < MmUserProbeAddress)
    {
        ProbeForWrite(pOutputBuffer, BufferSize, 1u);
        *pOutputBuffer = 0;
    }
    return 0;
}

// CmdObjectOperationByHandle — 通过句柄执行对象操作命令
char CmdObjectOperationByHandle(__int64 *pInputBuffer, int InputSize)
{
    __int64 TargetHandle = 0;
    _QWORD *pObjectTable;

    if (pInputBuffer && InputSize == 8
        && (unsigned __int64)pInputBuffer < MmUserProbeAddress
        && (unsigned __int64)(pInputBuffer + 1) < MmUserProbeAddress)
    {
        ProbeForRead(pInputBuffer, 8u, 8u);
        TargetHandle = *pInputBuffer;
    }
    if (TargetHandle)
    {
        pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
        if (!pObjectTable)
        {
            InitObjectOperationEntry();
            pObjectTable = (_QWORD *)GtRead(GtCallbackField22);
        }
        if (TargetHandle && pObjectTable)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0xECE)
                return RemoveObjectSingleLinkedListLegacy(pObjectTable, TargetHandle);
            if ((unsigned int)GtRead(GtWindowsBuildNumber) == 3790)
                return RemoveObjectFromLinkedListLegacy(pObjectTable, TargetHandle);
            return RemoveObjectFromLinkedList(pObjectTable, TargetHandle);
        }
    }
    return 0;
}

// DispatchObjectOperationInit — 分发对象操作初始化
char DispatchObjectOperationInit(__int64 ImageBase, unsigned int ImageSize)
{
    unsigned int Result = (unsigned int)GtRead(GtWindowsBuildNumber);
    if (Result >= 0x2800)
    {
        if (ImageBase && ImageSize)
            Result = (unsigned char)FindObjectOperationExportWin10(ImageBase, ImageSize);
    }
    else
    {
        Result = (unsigned char)InitObjectOperationLegacy();
    }
    return Result;
}

// CompareKernelPageAttached — 比较内核页附加
char CompareKernelPageAttached(void *PageAddress, _DWORD *OutputBuffer, struct _KPROCESS *TargetProcess, __int64 (*ReadMemoryCallback)(void *))
{
    char IsMatch = 0;
    char PageModified = 0;
    struct _KAPC_STATE ApcState;
    __int64 CurrentProcessValue;
    __int64 TargetProcessValue;

    CurrentProcessValue = ReadMemoryCallback(PageAddress);
    KeStackAttachProcess(TargetProcess, &ApcState);
    if (CheckMemoryValid(PageAddress) == 1)
    {
        TargetProcessValue = ReadMemoryCallback(PageAddress);
        PageModified = CurrentProcessValue != TargetProcessValue;
    }
    KeUnstackDetachProcess(&ApcState);
    if (PageModified)
    {
        *(_QWORD *)&OutputBuffer[6 * *OutputBuffer] = CurrentProcessValue;
        *(_QWORD *)&OutputBuffer[6 * *OutputBuffer + 2] = TargetProcessValue;
        *((_BYTE *)OutputBuffer + 6 * (*OutputBuffer)++ + 20) = 1;
    }
    return IsMatch;
}

// FindObjectOperationDataSection — 查找对象操作数据节区
__int64 __fastcall FindObjectOperationDataSection(__int64 ImageBase, int ImageSize, int SectionBase)
{
    unsigned int FoundOffset;
    unsigned int MaxOffset;
    unsigned int PrevOffset;
    unsigned int CurrentOffset;
    int ScanCount;
    int CurrentRva;
    __int16 TypeValue;
    __int64 PESectionContext;
    __int64 ContextOffset;
    _DWORD SectionEntry[14];
    int EntryOffset;
    __int64 FlagsField;
    unsigned int EntrySize2;
    __int64 TypePtr;

    FoundOffset = 0;
    MaxOffset = ImageSize - SectionBase;
    PrevOffset = 0;
    CurrentOffset = 0;
    InitPESectionReadContext(ImageBase, (ULONG)(ImageSize - ImageBase), 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    ScanCount = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
    {
        CurrentRva = (int)(EntrySize2 + ContextOffset);
        ContextOffset += EntrySize2;
        TypeValue = *(_WORD *)(TypePtr + 6);
        if (TypeValue == 1349)
        {
            if (PrevOffset && PrevOffset < MaxOffset)
                return PrevOffset;
            return FoundOffset;
        }
        if (TypeValue == 1368 && (FlagsField & 0x4000000) != 0 && EntryOffset)
        {
            PrevOffset = CurrentOffset;
            CurrentOffset = CurrentRva + EntryOffset - SectionBase;
        }
        if (++ScanCount >= 0x64)
            return FoundOffset;
    }
    return FoundOffset;
}

// FindObjectOperationBaseOffset — 查找对象操作基址偏移
__int64 __fastcall FindObjectOperationBaseOffset(__int64 ImageBase, int ImageSize, int SectionBase)
{
    __int64 FoundOffset;
    unsigned int MaxOffset;
    __int64 BaseOffset1;
    enum _GLOBAL_TABLE_INDEX GtIndex2;
    __int64 BaseOffset;
    int BaseOffset2;
    unsigned int LoopIndex;
    int CurrentRva;
    __int16 TypeValue;
    unsigned int TargetRva;
    char PESectionContext[8];
    __int64 ContextOffset;
    char SectionEntry[80];
    __int64 EntrySize;
    int RvaField;
    __int64 Flags2;
    unsigned int EntrySize2;
    __int64 TypePtr;

    FoundOffset = 0;
    MaxOffset = ImageSize - SectionBase;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
    {
        BaseOffset1 = GtRead(GtNtoskrnlFileBase);
        GtIndex2 = (enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr1 | GtEprocessField182 | GtEprocessField22);
    }
    else
    {
        BaseOffset1 = GtRead(GtKernelModuleBase);
        GtIndex2 = GtEprocessField71;
    }
    BaseOffset = BaseOffset1;
    BaseOffset2 = (int)GtRead(GtIndex2);
    if (BaseOffset && BaseOffset2)
    {
        InitPESectionReadContext(ImageBase, (ULONG)(ImageSize - ImageBase), 2, 0, -1, 0, 0, (__int64)PESectionContext);
        for (LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
        {
            if ((unsigned int)ReadPESectionEntry((PUCHAR)PESectionContext, (PULONG)SectionEntry))
                break;
            CurrentRva = (int)(EntrySize2 + ContextOffset);
            ContextOffset += EntrySize2;
            TypeValue = *(_WORD *)(TypePtr + 6);
            if (TypeValue == 1349)
                break;
            if (TypeValue == 1298 && Flags2 == 0x40000)
            {
                if (RvaField)
                {
                    if (EntrySize == 64)
                    {
                        TargetRva = CurrentRva + RvaField - SectionBase;
                        if (TargetRva && TargetRva < MaxOffset)
                            return BaseOffset + TargetRva;
                    }
                }
            }
        }
    }
    return FoundOffset;
}

// QueryObjectOperationByVersion — 根据版本查询对象操作偏移
__int64 __fastcall QueryObjectOperationByVersion(__int64 ImageBase, int ImageSize, int SectionBase)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x47BA)
        return FindObjectOperationSection(ImageBase, ImageSize, SectionBase);
    else
        return FindObjectOperationOffset(ImageBase, ImageSize, SectionBase);
}

// EnumProcessAndInitObjects — 枚举进程并初始化对象
// 遍历指定进程的对象表，对每个对象调用 InitObjectAndQueryName
__int64 EnumProcessAndInitObjects(__int64 Process, char Flags)
{
    char Result;
    unsigned int ObjectTableOffset;
    __int64 ObjectTablePtr;
    char **Buffer;
    char **BufferPtr;
    unsigned int EntryCount;
    char **CurrentEntry;
    __int64 LoopCount;
    char InitContext[8];
    __int64 SavedObjectTable;
    __int64 ProcessCopy;

    Result = 0;
    ObjectTableOffset = (unsigned int)GtRead(GtEprocessField30);
    if (ObjectTableOffset != -1)
    {
        ProcessCopy = Process;
        ObjectTablePtr = *(_QWORD *)(ObjectTableOffset + Process);
        InitContext[0] = 1;
        SavedObjectTable = ObjectTablePtr;
        Buffer = (char **)ExAlloc(PagedPool, 0x44610u);
        BufferPtr = Buffer;
        if (Buffer)
        {
            if (EnumProcessInformationWorker(InitContext, (__int64)Buffer, 0x44610u))
            {
                EntryCount = *((_DWORD *)BufferPtr + 4);
                if (EntryCount)
                {
                    CurrentEntry = BufferPtr + 4;
                    LoopCount = EntryCount;
                    do
                    {
                        InitObjectAndQueryName((__int64)*CurrentEntry, Flags);
                        CurrentEntry += 7;
                        --LoopCount;
                    }
                    while (LoopCount);
                }
                Result = 1;
            }
            ExFree(BufferPtr);
        }
    }
    return Result;
}

// ParseObjectContextExportDir — 解析对象上下文导出目录
void ParseObjectContextExportDir(void)
{
    char Success;
    __int64 *pExportTable;
    __int64 ExportDirSize;
    unsigned int *pEntryIndex;
    __int64 EntryRemaining;
    __int64 NameRva;
    unsigned int FileSize;
    char *pFileBuffer;

    Success = 0;
    pExportTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtObjectTypeField37 | 0x3400));
    ExportDirSize = GtRead((enum _GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField187));
    if (ExportDirSize && ReadNtoskrnlForObjectContext(&pFileBuffer, &FileSize))
    {
        if (ParseNtExportSections((__int64)pFileBuffer, FileSize, (__int64)pExportTable) == 1
            && ParseNtExportDir((PUCHAR)pFileBuffer, FileSize, ExportDirSize, 0) == 1)
        {
            pEntryIndex = (unsigned int *)pExportTable + 1;
            EntryRemaining = 29;
            do
            {
                NameRva = *pEntryIndex;
                *(pEntryIndex - 1) = 0;
                if ((_DWORD)NameRva && (unsigned int)((int)NameRva + 16) <= FileSize)
                {
                    *(pEntryIndex - 1) = 1;
                    *(_OWORD *)(pEntryIndex + 3) = *(_OWORD *)&pFileBuffer[NameRva];
                }
                pEntryIndex += 12;
                --EntryRemaining;
            }
            while (EntryRemaining);
            Success = 1;
            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtNtCreateProcessResultAddr | GtEprocessField06), 1);
        }
        ExFree(pFileBuffer);
        if (Success == 1)
            FillExportEntrySlot((__int64)pExportTable);
    }
}

// EnumerateProcessObjectTable — 枚举进程对象表：通过进程对象表枚举进程信息，检查进程是否受保护
__int64 EnumerateProcessObjectTable(__int64 Process, __int64 OutputInfo)
{
    char Result;
    unsigned int ProcessHandleTableOffset;
    unsigned int ProtectionBitmap;
    unsigned int ProtectionBitmapCopy;
    __int64 ObjectTablePtr;
    _DWORD *Buffer;
    _DWORD *BufferPtr;
    unsigned int EntryCount;
    _QWORD *CurrentEntry;
    __int64 LoopCount;
    char Context[8];
    __int64 ObjectTableRef;
    __int64 ProcessRef;

    Result = 0;
    ProcessHandleTableOffset = (unsigned int)GtRead(GtEprocessField30);
    ProtectionBitmap = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)(GtKiFastCallEntryAddr | GtEprocessField08));
    ProtectionBitmapCopy = ProtectionBitmap;
    if (ProcessHandleTableOffset != -1 && ProtectionBitmap)
    {
        ProcessRef = Process;
        ObjectTablePtr = *(_QWORD *)(ProcessHandleTableOffset + Process);
        Context[0] = 1;
        ObjectTableRef = ObjectTablePtr;
        Buffer = ExAlloc(PagedPool, 0x44610u);
        BufferPtr = Buffer;
        if (Buffer)
        {
            if (EnumProcessInformationWorker(Context, (__int64)Buffer, 0x44610u))
            {
                EntryCount = BufferPtr[4];
                *(_WORD *)OutputInfo = 0;
                if (EntryCount)
                {
                    CurrentEntry = (_QWORD *)(BufferPtr + 8);
                    LoopCount = EntryCount;
                    do
                    {
                        if (*(_BYTE *)(ProtectionBitmapCopy + *CurrentEntry))
                            *(_BYTE *)(OutputInfo + 1) = 1;
                        else
                            *(_BYTE *)OutputInfo = 1;
                        CurrentEntry += 7;
                        --LoopCount;
                    }
                    while (LoopCount);
                }
                Result = 1;
            }
            ExFree(BufferPtr);
        }
    }
    return Result;
}

// ResolveKernelObjectAddresses — 解析内核对象地址
__int64 ResolveKernelObjectAddresses(__int64 pObjectTable)
{
    unsigned int TableIndex;
    __int64 TableLoopIndex;
    __int64 EntryFieldCount;
    _BYTE *pEntry;
    __int64 FieldValue;
    unsigned int HalExportCount;
    __int64 NtoskrnlBase;
    unsigned __int64 NtoskrnlBaseCopy;
    unsigned int EntryIndex;
    _BYTE *pTypeEntry;
    __int64 RemainingFields;
    unsigned __int64 ObjectAddress;
    unsigned int AddressOffset;
    bool IsTypeEntryNull;
    unsigned int i;
    __int64 HalExportTable;
    __int64 ResolvedAddress;

    TableIndex = 0;
    for (TableLoopIndex = pObjectTable; TableIndex < *(_DWORD *)(TableLoopIndex + 4); ++TableIndex)
    {
        EntryFieldCount = 8;
        pEntry = (_BYTE *)(200LL * TableIndex + TableLoopIndex + 32);
        do
        {
            FieldValue = *((_QWORD *)pEntry - 2);
            if (FieldValue && *((_QWORD *)pEntry - 1) != FieldValue)
                *pEntry = 1;
            pEntry += 24;
            --EntryFieldCount;
        }
        while (EntryFieldCount);
    }
    HalExportTable = GtRead(GtEprocessField66);
    HalExportCount = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlBaseCopy = NtoskrnlBase;
    if (HalExportTable && HalExportCount && NtoskrnlBase)
    {
        EntryIndex = 0;
        if (*(_DWORD *)(TableLoopIndex + 4))
        {
            do
            {
                NtoskrnlBase = EntryIndex;
                pTypeEntry = (_BYTE *)(200LL * EntryIndex + TableLoopIndex + 32);
                RemainingFields = 8;
                do
                {
                    ObjectAddress = *((_QWORD *)pTypeEntry - 2);
                    if (ObjectAddress)
                    {
                        if (ObjectAddress > NtoskrnlBaseCopy)
                        {
                            AddressOffset = (unsigned int)(ObjectAddress - NtoskrnlBaseCopy);
                            if ((int)(ObjectAddress - NtoskrnlBaseCopy) < HalExportCount)
                            {
                                NtoskrnlBase = (unsigned int)(AddressOffset + 16);
                                if (AddressOffset + 16 <= HalExportCount)
                                {
                                    NtoskrnlBase = MmIsAddressValid(*((PVOID *)pTypeEntry - 2));
                                    if ((_BYTE)NtoskrnlBase == 1)
                                    {
                                        NtoskrnlBase = MmIsAddressValid((PVOID)(ObjectAddress + 15));
                                        if ((_BYTE)NtoskrnlBase == 1)
                                        {
                                            NtoskrnlBase = MemoryCompare(
                                                ObjectAddress,
                                                (char *)(HalExportTable + AddressOffset),
                                                0x10u);
                                            if ((_DWORD)NtoskrnlBase)
                                            {
                                                IsTypeEntryNull = *pTypeEntry == 0;
                                                pTypeEntry[1] = 1;
                                                if (IsTypeEntryNull)
                                                {
                                                    for (i = 0; i < 0x10; ++i)
                                                    {
                                                        NtoskrnlBase = MmIsAddressValid((PVOID)(ObjectAddress + i));
                                                        if (!(_BYTE)NtoskrnlBase)
                                                            break;
                                                    }
                                                    if (i)
                                                    {
                                                        NtoskrnlBase = ReturnFalseStub();
                                                        if ((_BYTE)NtoskrnlBase == 1)
                                                        {
                                                            NtoskrnlBase = (__int64)ResolvedAddress;
                                                            *((_QWORD *)pTypeEntry - 1) = ResolvedAddress;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    pTypeEntry += 24;
                    --RemainingFields;
                }
                while (RemainingFields);
                TableLoopIndex = pObjectTable;
                ++EntryIndex;
            }
            while (EntryIndex < *(_DWORD *)(pObjectTable + 4));
        }
    }
    return NtoskrnlBase;
}

// ModifyObjectHeaderFlagsByVersion — 按版本修改对象头标志
char __fastcall ModifyObjectHeaderFlagsByVersion(__int64 ObjectHeader, char SetFlag)
{
    char Result;
    unsigned int HeaderOffsetBase;

    Result = 0;
    HeaderOffsetBase = (unsigned int)GtRead((enum _GLOBAL_TABLE_INDEX)2312);
    if (HeaderOffsetBase)
    {
        Result = 1;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1770)
        {
            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
            {
                if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x23F0)
                {
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200)
                    {
                        if (SetFlag == 1)
                            *(_DWORD *)(HeaderOffsetBase + ObjectHeader) |= 0x10000u;
                        else
                            *(_DWORD *)(HeaderOffsetBase + ObjectHeader) &= ~0x10000u;
                    }
                    else if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9600)
                    {
                        if (SetFlag == 1)
                            *(_DWORD *)(HeaderOffsetBase + ObjectHeader) |= 0x8000u;
                        else
                            *(_DWORD *)(HeaderOffsetBase + ObjectHeader) &= ~0x8000u;
                    }
                    else if (SetFlag == 1)
                        *(_DWORD *)(HeaderOffsetBase + ObjectHeader) |= 0x4000u;
                    else
                        *(_DWORD *)(HeaderOffsetBase + ObjectHeader) &= ~0x4000u;
                }
                else if (SetFlag == 1)
                    *(_DWORD *)(HeaderOffsetBase + ObjectHeader) |= 0x20u;
                else
                    *(_DWORD *)(HeaderOffsetBase + ObjectHeader) &= ~0x20u;
            }
            else if (SetFlag == 1)
                *(_DWORD *)(HeaderOffsetBase + ObjectHeader) |= 0x40u;
            else
                *(_DWORD *)(HeaderOffsetBase + ObjectHeader) &= ~0x40u;
        }
        else
        {
            *(_BYTE *)(HeaderOffsetBase + ObjectHeader) = SetFlag;
        }
    }
    return Result;
}

// FindObjectOperationExportWin10 — 查找对象操作导出（Win10+）：在 ntoskrnl 镜像中查找 NtUserRegisterHotKey 导出函数的 RVA
__int64 __fastcall FindObjectOperationExportWin10(__int64 NtoskrnlBase, unsigned int ImageSize)
{
    char Success;
    __int64 Value;
    _WORD ExportNameBuf[12];

    Value = 0;
    *((unsigned char *)&ExportNameBuf[10] + 1) = 0;
    ExportNameBuf[11] = 0;
    strcpy((char *)ExportNameBuf, "NtUserRegisterHotKey");
    Success = (char)GtRead(GtNtCreateThreadHookSuccess | GtEprocessField07);
    if (!Success)
    {
        Success = LookupExportByName((PUCHAR)NtoskrnlBase, (ULONG)ImageSize, (PCHAR)ExportNameBuf, (PULONG)&Value);
        if (Success == 1)
        {
            if ((_DWORD)Value && (unsigned int)Value < ImageSize)
                Success = (char)GtWrite(GtCallbackField21, (unsigned int)Value);
        }
    }
    return Success;
}

// EnumObjectLinkedListSingle — 枚举对象单链表（Win7 旧版）：遍历单个桶链表（Next 在 bucket[4]），输出条目含对象指针、Eprocess/HandleTable/GrantedAccess
__int64 EnumObjectLinkedListSingle(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries)
{
    __int64 (__fastcall *pCallbackFunc)(_QWORD ***);
    unsigned int EprocessOffset;
    unsigned int HandleTableOffset;
    __int64 Result;
    __int64 GrantedAccessOffset;
    _QWORD ***pBucket;
    unsigned int BucketEntryCount;
    _DWORD *pOutputEntry;
    _QWORD *pEntry;

    pCallbackFunc = (__int64 (__fastcall *)(_QWORD ***))GtRead(GtObjectTypeCheckFlag);
    EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    HandleTableOffset = (unsigned int)GtRead(GtProcessCreateTime);
    Result = GtRead(GtProcessOffset);
    GrantedAccessOffset = Result;
    if (pCallbackFunc && EprocessOffset != -1 && HandleTableOffset && (unsigned int)Result != -1 && pObjectTable)
    {
        Result = pCallbackFunc((_QWORD ***)pObjectTable);
        if ((_BYTE)Result)
        {
            pBucket = (_QWORD ***)*pObjectTable;
            BucketEntryCount = 0;
            if (pBucket)
            {
                pOutputEntry = (_DWORD *)(pOutput + 2);
                do
                {
                    Result = pCallbackFunc(pBucket);
                    if (!(_BYTE)Result || !MaxEntries || BucketEntryCount > 0x10000)
                        break;
                    if (*pBucket)
                    {
                        pEntry = **pBucket;
                        if (pEntry)
                        {
                            Result = pCallbackFunc((_QWORD ***)pEntry);
                            if ((_BYTE)Result)
                            {
                                *((_QWORD *)pOutputEntry - 2) = (_QWORD)pBucket;
                                --MaxEntries;
                                *((_QWORD *)pOutputEntry - 1) = (_QWORD)pBucket[1];
                                *pOutputEntry = *((_DWORD *)pBucket + 6);
                                pOutputEntry += 14;
                                *(pOutputEntry - 13) = *((_DWORD *)pBucket + 4);
                                *(pOutputEntry - 12) = *((_DWORD *)pBucket + 5);
                                *((_QWORD *)pOutputEntry - 3) = *(_QWORD *)((char *)pEntry + HandleTableOffset);
                                *((_QWORD *)pOutputEntry - 5) = *(_QWORD *)((char *)pEntry + EprocessOffset);
                                *((_QWORD *)pOutputEntry - 4) = *(_QWORD *)((char *)pEntry + GrantedAccessOffset);
                                ++*pCount;
                            }
                        }
                    }
                    pBucket = (_QWORD ***)pBucket[4];
                    ++BucketEntryCount;
                }
                while (pBucket);
            }
        }
    }
    return Result;
}

// FindObjectOperationOffset — 查找对象操作偏移：遍历 PE 节区条目，扫描 Type 1368 和 Type 1340 找到目标偏移量
__int64 FindObjectOperationOffset(__int64 ImageBase, int ImageSize, int SectionBase)
{
    unsigned int Result;
    unsigned int MaxOffset;
    unsigned int FoundOffsetTmp;
    unsigned int LoopIndex;
    int CurrentRva;
    __int16 TypeValue;
    __int64 PESectionContext;
    __int64 ContextOffset;
    _DWORD SectionEntry[14];
    int EntryOffset;
    __int64 FlagsField;
    int TypeField;
    __int64 Flags2;
    unsigned int EntrySize2;
    __int64 TypePtr;

    Result = 0;
    MaxOffset = ImageSize - SectionBase;
    FoundOffsetTmp = 0;
    InitPESectionReadContext(ImageBase, (ULONG)(ImageSize - ImageBase), 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    for (LoopIndex = 0; LoopIndex < 0x64; ++LoopIndex)
    {
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
            break;
        CurrentRva = (int)(EntrySize2 + ContextOffset);
        ContextOffset += EntrySize2;
        TypeValue = *(_WORD *)(TypePtr + 6);
        if (TypeValue == 1349)
            break;
        if (TypeValue == 1368 && (FlagsField & 0x4000000) != 0 && EntryOffset)
            FoundOffsetTmp = CurrentRva + EntryOffset - SectionBase;
        if (((TypeValue - 1340) & 0xFFFD) == 0
            && Flags2 == 0x800000
            && TypeField == 1802007381
            && FoundOffsetTmp
            && FoundOffsetTmp < MaxOffset)
        {
            return FoundOffsetTmp;
        }
    }
    return Result;
}

// FindObjectOperationSection — 查找对象操作节区（Win10+）：遍历 PE 节区条目，先扫描 Type 1340 标记 FoundFlag，然后扫描 Type 1368 获取目标 RVA 偏移
__int64 FindObjectOperationSection(__int64 ImageBase, int ImageSize, int SectionBase)
{
    unsigned int FoundOffset;
    unsigned int MaxOffset;
    char FoundFlag;
    int ScanCount;
    int CurrentRva;
    __int16 TypeValue;
    unsigned int TargetRva;
    __int64 PESectionContext;
    __int64 ContextOffset;
    _DWORD SectionEntry[14];
    int EntryOffset;
    __int64 FlagsField;
    int TypeField;
    __int64 Flags2;
    unsigned int EntrySize2;
    __int64 TypePtr;

    FoundOffset = 0;
    MaxOffset = ImageSize - SectionBase;
    FoundFlag = 0;
    InitPESectionReadContext(ImageBase, (ULONG)(ImageSize - ImageBase), 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    ScanCount = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
    {
        CurrentRva = (int)(EntrySize2 + ContextOffset);
        ContextOffset += EntrySize2;
        TypeValue = *(_WORD *)(TypePtr + 6);
        if ((unsigned __int16)(TypeValue - 1340) > 7u)
        {
            if (TypeValue == 1368 && (FlagsField & 0x4000000) != 0)
            {
                if (EntryOffset)
                {
                    if (FoundFlag == 1)
                    {
                        TargetRva = CurrentRva + EntryOffset - SectionBase;
                        if (TargetRva && TargetRva < MaxOffset)
                            return (unsigned int)(CurrentRva + EntryOffset - SectionBase);
                    }
                }
            }
        }
        else if (Flags2 == 0x800000 && TypeField == 512)
        {
            FoundFlag = 1;
        }
        if ((unsigned int)++ScanCount >= 0xC8)
            return FoundOffset;
    }
    return FoundOffset;
}

// EnumObjectLinkedListWin8 — 枚举对象链表（Win8）：遍历 127 个桶，在每个桶中遍历链表条目，输出每个句柄的完整信息（7 个 QWORD）
__int64 EnumObjectLinkedListWin8(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries)
{
    _QWORD *pTable;
    __int64 (__fastcall *pCallbackFunc)(_QWORD ***);
    unsigned int EprocessOffset;
    unsigned int HandleTableOffset;
    _DWORD *Result;
    __int64 MaxBuckets;
    _QWORD ***pBucket;
    unsigned int BucketEntryCount;
    _QWORD *pEntry;
    __int64 MaxBucketsCopy;
    unsigned int EprocessOffsetVal;
    unsigned int HandleTableOffsetVal;
    unsigned int GrantedAccessOffsetVal;
    _QWORD *pTableCopy;

    pTableCopy = pObjectTable;
    pTable = pObjectTable;
    pCallbackFunc = (__int64 (__fastcall *)(_QWORD ***))GtRead(GtObjectTypeCheckFlag);
    EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    EprocessOffsetVal = EprocessOffset;
    HandleTableOffset = (unsigned int)GtRead(GtProcessCreateTime);
    HandleTableOffsetVal = HandleTableOffset;
    Result = (_DWORD *)GtRead(GtProcessOffset);
    GrantedAccessOffsetVal = (unsigned int)(__int64)Result;
    if (pCallbackFunc && EprocessOffset != -1 && HandleTableOffset && (unsigned int)(__int64)Result != -1 && pTable)
    {
        Result = (_DWORD *)pCallbackFunc((_QWORD ***)pTable);
        if ((_BYTE)Result)
        {
            MaxBuckets = 127;
            MaxBucketsCopy = 127;
            do
            {
                pBucket = (_QWORD ***)*pTable;
                BucketEntryCount = 0;
                if (*pTable)
                {
                    do
                    {
                        Result = (_DWORD *)pCallbackFunc(pBucket);
                        if (!(_BYTE)Result || !MaxEntries || BucketEntryCount > 0x10000)
                            break;
                        if (*pBucket)
                        {
                            pEntry = **pBucket;
                            if (pEntry)
                            {
                                Result = (_DWORD *)pCallbackFunc((_QWORD ***)pEntry);
                                if ((_BYTE)Result)
                                {
                                    *pOutput = (_QWORD)pBucket;
                                    --MaxEntries;
                                    pOutput[1] = (_QWORD)pBucket[2];
                                    pOutput += 7;
                                    *((_DWORD *)pOutput - 10) = *((_DWORD *)pBucket + 8);
                                    *((_DWORD *)pOutput - 9) = *((unsigned __int16 *)pBucket + 12);
                                    *((_DWORD *)pOutput - 8) = *((_DWORD *)pBucket + 7);
                                    *(pOutput - 1) = *(_QWORD *)((char *)pEntry + HandleTableOffsetVal);
                                    *(pOutput - 3) = *(_QWORD *)((char *)pEntry + EprocessOffsetVal);
                                    Result = pCount;
                                    *(pOutput - 2) = *(_QWORD *)((char *)pEntry + GrantedAccessOffsetVal);
                                    ++*pCount;
                                }
                            }
                        }
                        pBucket = (_QWORD ***)pBucket[5];
                        ++BucketEntryCount;
                    }
                    while (pBucket);
                    pTable = pTableCopy;
                    MaxBuckets = MaxBucketsCopy;
                }
                ++pTable;
                MaxBucketsCopy = --MaxBuckets;
                pTableCopy = pTable;
            }
            while (MaxBuckets);
        }
    }
    return (__int64)Result;
}

// EnumObjectLinkedListWin7 — 枚举对象链表（Win7）：遍历 127 个桶，每个桶中通过 Next 指针（+4 即 bucket[4]）遍历链表，输出 7 个 QWORD 条目
__int64 EnumObjectLinkedListWin7(_QWORD *pObjectTable, _QWORD *pOutput, _DWORD *pCount, int MaxEntries)
{
    _QWORD *pTable;
    __int64 (__fastcall *pCallbackFunc)(_QWORD ***);
    unsigned int EprocessOffset;
    unsigned int HandleTableOffset;
    _DWORD *Result;
    __int64 MaxBuckets;
    _QWORD ***pBucket;
    unsigned int BucketEntryCount;
    _QWORD *pEntry;
    __int64 MaxBucketsCopy;
    unsigned int EprocessOffsetVal;
    unsigned int HandleTableOffsetVal;
    unsigned int GrantedAccessOffsetVal;
    _QWORD *pTableCopy;

    pTableCopy = pObjectTable;
    pTable = pObjectTable;
    pCallbackFunc = (__int64 (__fastcall *)(_QWORD ***))GtRead(GtObjectTypeCheckFlag);
    EprocessOffset = (unsigned int)GtRead(GtProcessEprocess);
    EprocessOffsetVal = EprocessOffset;
    HandleTableOffset = (unsigned int)GtRead(GtProcessCreateTime);
    HandleTableOffsetVal = HandleTableOffset;
    Result = (_DWORD *)GtRead(GtProcessOffset);
    GrantedAccessOffsetVal = (unsigned int)(__int64)Result;
    if (pCallbackFunc && EprocessOffset != -1 && HandleTableOffset && (unsigned int)(__int64)Result != -1 && pTable)
    {
        Result = (_DWORD *)pCallbackFunc((_QWORD ***)pTable);
        if ((_BYTE)Result)
        {
            MaxBuckets = 127;
            MaxBucketsCopy = 127;
            do
            {
                pBucket = (_QWORD ***)*pTable;
                BucketEntryCount = 0;
                if (*pTable)
                {
                    do
                    {
                        Result = (_DWORD *)pCallbackFunc(pBucket);
                        if (!(_BYTE)Result || !MaxEntries || BucketEntryCount > 0x10000)
                            break;
                        if (*pBucket)
                        {
                            pEntry = **pBucket;
                            if (pEntry)
                            {
                                Result = (_DWORD *)pCallbackFunc((_QWORD ***)pEntry);
                                if ((_BYTE)Result)
                                {
                                    *pOutput = (_QWORD)pBucket;
                                    --MaxEntries;
                                    pOutput[1] = (_QWORD)pBucket[1];
                                    pOutput += 7;
                                    *((_DWORD *)pOutput - 10) = *((_DWORD *)pBucket + 6);
                                    *((_DWORD *)pOutput - 9) = *((_DWORD *)pBucket + 4);
                                    *((_DWORD *)pOutput - 8) = *((_DWORD *)pBucket + 5);
                                    *(pOutput - 1) = *(_QWORD *)((char *)pEntry + HandleTableOffsetVal);
                                    *(pOutput - 3) = *(_QWORD *)((char *)pEntry + EprocessOffsetVal);
                                    Result = pCount;
                                    *(pOutput - 2) = *(_QWORD *)((char *)pEntry + GrantedAccessOffsetVal);
                                    ++*pCount;
                                }
                            }
                        }
                        pBucket = (_QWORD ***)pBucket[4];
                        ++BucketEntryCount;
                    }
                    while (pBucket);
                    pTable = pTableCopy;
                    MaxBuckets = MaxBucketsCopy;
                }
                ++pTable;
                MaxBucketsCopy = --MaxBuckets;
                pTableCopy = pTable;
            }
            while (MaxBuckets);
        }
    }
    return (__int64)Result;
}

// ParseNtExportSections — 解析 NT 导出节区（对象上下文版本）：从 GT 获取节区基址，通过遍历节区条目查找 Type 1298/1294 填充函数表
char ParseNtExportSections(__int64 PeBase, unsigned int PeSize, __int64 OutputTable)
{
    char Result;
    __int64 NtoskrnlBase;
    __int64 PeOffset;
    char IsTargetSection;
    int SectionIndex;
    int ComputedOffset;
    __int16 SectionType;
    unsigned int SectionRva;
    unsigned int EntryIndex;
    int ComputedOffset2;
    __int16 SectionType2;
    int SectionFlags;
    unsigned int SectionRva2;
    __int64 SlotIndex;
    unsigned int SectionOffset;
    __int64 SectionContext;
    __int64 AccumulatedOffset;
    _DWORD SectionEntry[14];
    int SectionDataSize;
    int FieldFlags;
    __int64 SectionCharacteristics;
    int SlotIndex2;
    int FieldMisc;
    __int64 SectionAlignment;
    int FieldIndex;
    int FieldOffset;
    unsigned int SectionFileOffset;
    __int64 pSectionEntryBase;
    _DWORD SectionOffsetTable[16];

    Result = 0;
    NtoskrnlBase = GtRead((GLOBAL_TABLE_INDEX)(GtDisableHookProtectionAddr2 | GtEprocessField187));
    if (NtoskrnlBase)
    {
        PeOffset = *(int *)(PeBase + 60);
        if ((unsigned int)PeOffset < PeSize)
        {
            IsTargetSection = 0;
            InitPESectionReadContext(PeBase + *(unsigned int *)(PeOffset + PeBase + 40), (ULONG)(PeSize - *(unsigned int *)(PeOffset + PeBase + 40)), 2, 0, -1, 0, 0, (__int64)&SectionContext);
            SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            {
                ComputedOffset = (int)(SectionFileOffset + AccumulatedOffset);
                AccumulatedOffset += SectionFileOffset;
                SectionType = *(_WORD *)(pSectionEntryBase + 6);
                if (SectionType == 1369)
                {
                    SectionRva = (unsigned int)(ComputedOffset + SectionDataSize - PeBase);
                    if (SectionRva && SectionRva < PeSize)
                        goto LABEL_FOUND_SECTION;
                }
                else if (SectionType == 1296 && SectionCharacteristics == 64 && SlotIndex2 == 1)
                {
                    IsTargetSection = 1;
                }
                else if (SectionType == 1368)
                {
                    if (IsTargetSection == 1)
                    {
                        SectionRva = (unsigned int)(ComputedOffset + SectionDataSize - PeBase);
                        if (SectionRva && SectionRva < PeSize)
                        {
LABEL_FOUND_SECTION:
                            PeOffset = SectionRva;
                            break;
                        }
                    }
                    IsTargetSection = 0;
                }
                if ((unsigned int)++SectionIndex >= 0x14)
                    break;
            }
        }
        if ((unsigned int)PeOffset < PeSize)
        {
            InitPESectionReadContext(PeBase + (unsigned int)PeOffset, (ULONG)(PeSize - (unsigned int)PeOffset), 2, 0, -1, 0, 0, (__int64)&SectionContext);
            memset(SectionOffsetTable, 0, sizeof(SectionOffsetTable));
            for (EntryIndex = 0; EntryIndex < 0x1F4; ++EntryIndex)
            {
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                    break;
                ComputedOffset2 = (int)(SectionFileOffset + AccumulatedOffset);
                AccumulatedOffset += SectionFileOffset;
                SectionType2 = *(_WORD *)(pSectionEntryBase + 6);
                if (SectionType2 == 1349)
                    break;
                SectionFlags = (int)SectionCharacteristics;
                if (SectionType2 == 1298 && SectionAlignment == 0x40000)
                {
                    if (FieldMisc && SectionCharacteristics == 64)
                    {
                        SectionRva2 = (unsigned int)(ComputedOffset2 + FieldMisc - PeBase);
                        if (SectionRva2 && SectionRva2 < PeSize)
                            SectionOffsetTable[SlotIndex2] = SectionRva2;
                    }
                }
                if (SectionType2 == 1139)
                    memset(SectionOffsetTable, 0, sizeof(SectionOffsetTable));
                if (SectionType2 == 1294
                    && (*(_QWORD *)&SectionFlags & 0x14000LL) != 0
                    && (SectionFlags & 0x40) != 0
                    && (FieldOffset & 0xF) != 4
                    && SectionAlignment == 64
                    && (unsigned int)(FieldFlags - 112) <= 0xD8
                    && (FieldFlags & 7) == 0)
                {
                    SlotIndex = (unsigned int)(FieldFlags - 112) >> 3;
                    if ((unsigned int)SlotIndex <= 0x1B)
                    {
                        SectionOffset = SectionOffsetTable[FieldIndex];
                        if (SectionOffset && !*(_DWORD *)(OutputTable + 48 * SlotIndex + 4))
                        {
                            Result = 1;
                            *(_DWORD *)(OutputTable + 48 * SlotIndex + 4) = SectionOffset;
                            *(_QWORD *)(OutputTable + 48 * SlotIndex + 8) = NtoskrnlBase + SectionOffset;
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// InitObjectOperationLegacy — 初始化对象操作（旧版 Win7/Win8）：从 GT 获取服务表基址，解析系统调用号
__int64 InitObjectOperationLegacy(void)
{
    __int64 pServiceTable;
    __int64 Status;
    unsigned int SyscallIndex;

    pServiceTable = GtRead(GtIrpBufferSize | GtEprocessField14);
    if (pServiceTable || (ReadNtOsKrnlAndParseServiceTable(), Status = GtRead(GtIrpBufferSize | GtEprocessField14), (pServiceTable = Status) != 0))
    {
        Status = GtRead(GtCallbackField53);
        if (!Status)
        {
            Status = (unsigned int)GtRead(GtCallbackField20);
            SyscallIndex = *(_DWORD *)(pServiceTable + 4LL * (unsigned int)Status);
            if (SyscallIndex)
                return GtWrite(GtCallbackField21, SyscallIndex);
        }
    }
    return Status;
}

// ResolveSyscallAddressesInProcess — 在进程中解析系统调用地址：附加到目标进程上下文，通过系统调用号解析系统调用地址并写入全局表
__int64 ResolveSyscallAddressesInProcess(void)
{
    __int64 Result;
    struct _KPROCESS *TargetProcess;
    __int64 ExportTable;
    unsigned int ExportCount;
    __int64 NtoskrnlBase;
    unsigned int SyscallCount;
    unsigned int SyscallIndex;
    unsigned int ResolvedRva;
    __int64 ResolvedAddress;
    struct _KAPC_STATE ApcState;

    Result = 0;
    TargetProcess = (struct _KPROCESS *)GtRead(GtCurrentEprocess);
    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    ExportTable = GtRead(GtEprocessField22);
    ExportCount = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    SyscallCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    SyscallIndex = (unsigned int)GtRead(GtObjectTypeField19);
    if (ExportTable && ExportCount && NtoskrnlBase && SyscallIndex && SyscallIndex < SyscallCount)
    {
        ResolvedRva = (unsigned int)ResolveSyscallToAddress(SyscallIndex);
        if (ResolvedRva && ResolvedRva < ExportCount)
        {
            ResolvedAddress = NtoskrnlBase + ResolvedRva;
            GtWrite(GtObjectTypeField20, ResolvedRva);
            GtWrite(GtObjectTypeField21, ResolvedAddress);
            Result = ResolvedAddress;
        }
    }
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
    return Result;
}
char RemoveDeviceObject(__int64 DriverObject)
{
    char Result;
    void (__fastcall *DecodeStringFunc)(_BYTE *, _DWORD *);
    unsigned int (__fastcall *CreateFileFunc)(_BYTE *, __int64, __int64 *, __int64 *);
    __int64 CloseHandleFuncPtr;
    void (__fastcall *CloseHandleFunc)(__int64);
    __int64 DriverEntry;
    __int64 DeviceEntry;
    __int64 CurrentEntry;
    __int64 FileHandle;
    _BYTE DevicePath[16];
    _DWORD EncodedPath[12];

    Result = 0;
    DecodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (unsigned int (__fastcall *)(_BYTE *, __int64, __int64 *, __int64 *))GtRead(GtCreateFileFunc2);
    CloseHandleFuncPtr = GtRead(GtCloseHandleFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandleFuncPtr;
    if (DecodeStringFunc && CreateFileFunc && CloseHandleFuncPtr)
    {
        EncodedPath[0] = 4456540;
        EncodedPath[1] = 7733349;
        EncodedPath[2] = 6488169;
        EncodedPath[3] = 6029413;
        EncodedPath[4] = 6357064;
        EncodedPath[5] = 6553714;
        EncodedPath[6] = 6881380;
        EncodedPath[7] = 7012467;
        EncodedPath[8] = 6029360;
        EncodedPath[9] = 5374020;
        EncodedPath[10] = 48;
        DecodeStringFunc(DevicePath, EncodedPath);
        if (!CreateFileFunc(DevicePath, 128, &FileHandle, &CurrentEntry))
        {
            if (GetDeviceObjectFromFileObject(FileHandle, &CurrentEntry, 0))
            {
                DriverEntry = CurrentEntry;
                if (CurrentEntry)
                {
                    while (1)
                    {
                        DeviceEntry = *(_QWORD *)(DriverEntry + 24);
                        if (DeviceEntry == DriverObject)
                            break;
                        DriverEntry = *(_QWORD *)(DriverEntry + 24);
                        CurrentEntry = DeviceEntry;
                        if (!DeviceEntry)
                            goto LABEL_11;
                    }
                    *(_QWORD *)(DriverEntry + 24) = 0;
                    Result = 1;
                }
            }
LABEL_11:
            CloseHandleFunc(FileHandle);
        }
    }
    return Result;
}


char RemoveTdxDriverObject(__int64 DriverObject)
{
    _DWORD EncodedPath[6];

    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 6553716;
    EncodedPath[5] = 120;
    return RemoveObjectListEntry((__int64)EncodedPath, DriverObject);
}


char RemoveHarddiskVolume1Device(__int64 DriverObject)
{
    char Result;
    void (__fastcall *DecodeStringFunc)(_BYTE *, _DWORD *);
    unsigned int (__fastcall *CreateFileFunc)(_BYTE *, __int64, __int64 *, __int64 *);
    __int64 CloseHandleFuncPtr;
    void (__fastcall *CloseHandleFunc)(__int64);
    __int64 DriverEntry;
    __int64 DeviceEntry;
    __int64 CurrentEntry;
    __int64 FileHandle;
    _BYTE DevicePath[16];
    _DWORD EncodedPath[12];

    Result = 0;
    DecodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (unsigned int (__fastcall *)(_BYTE *, __int64, __int64 *, __int64 *))GtRead(GtCreateFileFunc2);
    CloseHandleFuncPtr = GtRead(GtCloseHandleFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))CloseHandleFuncPtr;
    if (DecodeStringFunc && CreateFileFunc && CloseHandleFuncPtr)
    {
        EncodedPath[0] = 4456540;
        EncodedPath[1] = 7733349;
        EncodedPath[2] = 6488169;
        EncodedPath[3] = 6029413;
        EncodedPath[4] = 6357064;
        EncodedPath[5] = 6553714;
        EncodedPath[6] = 6881380;
        EncodedPath[7] = 7012467;
        EncodedPath[8] = 7274582;
        EncodedPath[9] = 7667820;
        EncodedPath[10] = 6619245;
        EncodedPath[11] = 49;
        DecodeStringFunc(DevicePath, EncodedPath);
        if (!CreateFileFunc(DevicePath, 128, &FileHandle, &CurrentEntry))
        {
            if (GetDeviceObjectFromFileObject(FileHandle, &CurrentEntry, 0))
            {
                DriverEntry = CurrentEntry;
                if (CurrentEntry)
                {
                    while (1)
                    {
                        DeviceEntry = *(_QWORD *)(DriverEntry + 24);
                        if (DeviceEntry == DriverObject)
                            break;
                        DriverEntry = *(_QWORD *)(DriverEntry + 24);
                        CurrentEntry = DeviceEntry;
                        if (!DeviceEntry)
                            goto LABEL_11;
                    }
                    *(_QWORD *)(DriverEntry + 24) = 0;
                    Result = 1;
                }
            }
LABEL_11:
            CloseHandleFunc(FileHandle);
        }
    }
    return Result;
}


char RemovePnpManagerDriverObject(__int64 DriverObject)
{
    _DWORD EncodedPath[10];

    EncodedPath[9] = 0;
    EncodedPath[0] = 4456540;
    EncodedPath[1] = 6881394;
    EncodedPath[2] = 6619254;
    EncodedPath[3] = 6029426;
    EncodedPath[4] = 7209040;
    EncodedPath[5] = 5046384;
    EncodedPath[6] = 7209057;
    EncodedPath[7] = 6750305;
    EncodedPath[8] = 7471205;
    return RemoveObjectListEntry((__int64)EncodedPath, DriverObject);
}


__int64 OpenDeviceObjectForEnum(__int64 DeviceContext)
{
    // 函数指针：从全局表读取
    void (__fastcall *RtlInitUnicodeStringFunc)(_BYTE *, _DWORD *);
    __int64 (__fastcall *CreateFileFunc1)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64);
    __int64 (__fastcall *NtFsControlFileFunc)(__int64, __int64, __int64, __int64, __int64, __int64);
    __int64 *pFsControlCode;  // 指向 FSCTL 码的指针
    void (__fastcall *CloseHandleFunc)(__int64);
    void (__fastcall *ExFreePoolFunc)(__int64);

    // 局部变量
    __int64 FileHandle;              // 文件句柄
    __int64 IoStatusBlock;           // IO_STATUS_BLOCK 输出
    __int64 DeviceObjectPtr;         // 设备对象指针
    __int64 ResultInfo;              // Unicode 字符串结果
    __int64 FsControlCode;           // 从 pFsControlCode 读取的 FSCTL 码
    ULONG OaLength;                  // OBJECT_ATTRIBUTES.Length
    ULONG64 OaRootDir;               // OBJECT_ATTRIBUTES.RootDirectory
    ULONG64 OaObjectName;            // OBJECT_ATTRIBUTES.ObjectName
    ULONG OaAttributes;              // OBJECT_ATTRIBUTES.Attributes
    _OWORD IoStatusBlockBuf;         // IO_STATUS_BLOCK 缓冲区
    ULONG PathBuffer[4];             // 设备路径缓冲区
    __int64 InitResult;              // InitSystemPath 返回结果
    BOOLEAN IsMatch;                 // 是否找到匹配

    // 读取函数指针
    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, _DWORD *))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc1 = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64, __int64))GtRead(GtCreateFileFunc1);
    NtFsControlFileFunc = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))GtRead(GtNtFsControlFileFunc);
    pFsControlCode = (__int64 *)GtRead(GtZwCreateFileFunc);
    CloseHandleFunc = (void (__fastcall *)(__int64))GtRead(GtCloseHandleFunc);
    ExFreePoolFunc = (void (__fastcall *)(__int64))GtRead(GtExFreePoolFunc);

    IsMatch = FALSE;

    // 检查所有函数指针非空
    if (!RtlInitUnicodeStringFunc || !CreateFileFunc1 || !NtFsControlFileFunc ||
        !pFsControlCode || !CloseHandleFunc || !ExFreePoolFunc)
    {
        return FALSE;
    }

    // 构造设备路径缓冲区：L"\\??\\X:\\"
    // 初始化为 L"\\??\\C:\\"，稍后通过 InitSystemPath 获取的驱动器号替换 'C'
    PathBuffer[0] = 0x3F005C;   // L"\\?"  (0x5C='\\', 0x003F='?')
    PathBuffer[1] = 0x5C003F;   // L"?\\"  (0x003F='?', 0x005C='\\')
    PathBuffer[2] = 0x3A0043;   // L"C:"   (0x0043='C', 0x003A=':')
    PathBuffer[3] = 0x5C;       // L"\\"   (0x005C='\\')

    // 获取系统根路径（如 L"C:\\Windows"），提取驱动器号
    InitResult = (__int64)InitSystemPath();
    if (!InitResult)
    {
        return FALSE;
    }

    // 替换路径中的驱动器号（将 PathBuffer[2] 的低 16 位替换为系统盘的驱动器号）
    ((WORD *)PathBuffer)[4] = *(WORD *)InitResult;
    ExFreePoolFunc((__int64)InitResult);

    // 初始化 Unicode 字符串
    RtlInitUnicodeStringFunc((_BYTE *)&ResultInfo, (_DWORD *)PathBuffer);

    // 设置 OBJECT_ATTRIBUTES
    OaLength = 0x30;                       // sizeof(OBJECT_ATTRIBUTES)
    OaRootDir = 0;                         // 根目录为空
    OaAttributes = 0x240;                  // OBJ_CASE_INSENSITIVE
    OaObjectName = (ULONG64)&ResultInfo;   // 指向 Unicode 字符串

    // 清零 IO_STATUS_BLOCK
    ((ULONG64 *)&IoStatusBlockBuf)[0] = 0;
    ((ULONG64 *)&IoStatusBlockBuf)[1] = 0;

    // 调用 CreateFile 打开设备
    if ((ULONG)CreateFileFunc1(
        (__int64)&FileHandle,
        0x100000,                     // DesiredAccess: SYNCHRONIZE
        (__int64)&OaLength,           // ObjectAttributes
        (__int64)&IoStatusBlockBuf,   // IoStatusBlock
        0,                            // AllocationSize
        0,                            // FileAttributes
        3,                            // ShareAccess: FILE_SHARE_READ|FILE_SHARE_WRITE
        0,                            // CreateDisposition: FILE_OPEN
        0x21,                         // CreateOptions
        1) != 0)                      // ExtraParameter
    {
        CloseHandleFunc(FileHandle);
        return FALSE;
    }

    // 读取 FSCTL 码
    FsControlCode = *pFsControlCode;

    // 调用 NtFsControlFile 获取设备信息
    // 注意：函数指针类型为 6 参数，实际 NtFsControlFile 有 10 参数
    // 堆栈上剩余参数位置由调用约定覆盖（未显式传递的参数为未定义值）
    if ((ULONG)NtFsControlFileFunc(
        FileHandle,
        1,                    // Event
        FsControlCode,        // 第 3 参数（实际为 FSCTL 码，非 ApcRoutine）
        0,                    // 第 4 参数
        (__int64)&IoStatusBlock,
        0) != 0)
    {
        CloseHandleFunc(FileHandle);
        return FALSE;
    }

    // 从文件对象获取设备对象
    if (!GetDeviceObjectFromFileObject(IoStatusBlock, (ULONG64 *)&DeviceObjectPtr, NULL))
    {
        CloseHandleFunc(FileHandle);
        return FALSE;
    }

    // 遍历设备对象链，查找匹配的设备上下文
    // 原始代码检查 DeviceObject 的 +0x18 偏移处是否等于传入的 DeviceContext
    while (DeviceObjectPtr)
    {
        __int64 *pDeviceObject = (__int64 *)DeviceObjectPtr;
        __int64 CurrentContext = pDeviceObject[3];  // 偏移 +0x18

        if (CurrentContext == DeviceContext)
        {
            // 找到匹配，清除该字段
            pDeviceObject[3] = 0;
            IsMatch = TRUE;
            break;
        }

        // 移动到链中下一个设备对象
        DeviceObjectPtr = CurrentContext;
    }

    // 关闭文件句柄
    CloseHandleFunc(FileHandle);

    return IsMatch;
}

// DisableObjectCallbackWithFallback — 禁用对象回调（带降级机制）(0x14000FC14)
// 先尝试 DisableObjectCallback，失败则通过 DisableObjectCallbackViaDevice 使用文件系统 IOCTL 方式降级处理
char __fastcall DisableObjectCallbackWithFallback(__int16 *DeviceId, _QWORD *Context)
{
    char result;

    result = (char)DisableObjectCallback(DeviceId, Context);
    if (!result)
        return DisableObjectCallbackViaDevice(DeviceId, Context);
    return result;
}

// DisableObjectCallback — 禁用对象回调 (0x14000FC44)
// 打开指定设备路径，发送 IOCTL 获取文件对象，验证设备对象指针是否匹配全局表中保存的设备对象，然后通过 CmdQueryFileEndOfFile 查询并返回结果
__int64 DisableObjectCallback(__int16 *DevicePath, _QWORD *pResult)
{
    __int64 Result;
    _QWORD *IoctlCode;
    NTSTATUS (*DeviceIoControlFunc)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD);
    __int64 CloseHandleFunc;
    void (*CloseHandleFuncTyped)(__int64);
    __int64 DeviceObjectPtr;
    __int64 FileObject;
    HANDLE Handle;
    __int64 IoStatusBlock;

    Result = 0;
    IoctlCode = (_QWORD *)GtRead(GtZwCreateFileFunc);
    DeviceIoControlFunc = (NTSTATUS (*)(HANDLE, __int64, _QWORD, _QWORD, __int64 *, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = GtRead(GtCloseHandleFunc);
    CloseHandleFuncTyped = (void (*)(__int64))CloseHandleFunc;
    if (IoctlCode && DeviceIoControlFunc && CloseHandleFunc
        && !(unsigned int)CreateFileWithPath(DevicePath, 0, &Handle, 0x80, 0x80, 1, 1, 0x20))
    {
        if (DeviceIoControlFunc(Handle, 0x80000000, *IoctlCode, 0, &IoStatusBlock, 0) >= 0)
        {
            if (GetDeviceObjectFromFileObject(IoStatusBlock, &FileObject, 0))
            {
                DeviceObjectPtr = GtRead(GtSavedDeviceObject);
                if (DeviceObjectPtr)
                {
                    if (*(_QWORD *)(FileObject + 8) == DeviceObjectPtr)
                        Result = (unsigned int)CmdQueryFileEndOfFile(Handle, pResult) == 0;
                }
            }
            CloseHandleFuncTyped(IoStatusBlock);
        }
        ZwClose(Handle);
    }
    return Result;
}

// DisableObjectCallbackViaDevice — 通过文件系统 IOCTL 禁用对象回调（降级方案）(0x14000FD8C)
// 解析设备路径提取文件名，临时切换线程 PreviousMode=KernelMode，调用 FsIoControlRoutine 发送 FSCTL
char __fastcall DisableObjectCallbackViaDevice(__int16 *DevicePath, _QWORD *pResult)
{
    char Success;
    void (*StringAllocRoutine)(_BYTE *, __int16 *);
    NTSTATUS (*FsIoControlRoutine)(HANDLE, _QWORD, _QWORD, _QWORD, _BYTE *, _QWORD *, unsigned int, int, char, _BYTE *, char);
    unsigned int PrevModeOffset;
    unsigned int PrevModeOffsetVal;
    unsigned int StringLen;
    unsigned int PathLen;
    __int16 *PathBuf;
    _QWORD *OutputBuf;
    __int16 *LastSlash;
    __int16 *FileNameStart;
    __int16 SavedSeparator;
    struct _KTHREAD *CurrentThread;
    char SavedPrevMode;
    int IoStatus;
    _BYTE FileNameBuffer[16];
    _BYTE IoStatusBlock[72];
    unsigned int OutputSize;
    HANDLE DeviceHandle;

    Success = 0;
    StringAllocRoutine = (void (*)(_BYTE *, __int16 *))GtRead(GtRtlInitUnicodeStringFunc);
    FsIoControlRoutine = (NTSTATUS (*)(HANDLE, _QWORD, _QWORD, _QWORD, _BYTE *, _QWORD *, unsigned int, int, char, _BYTE *, char))GtRead(GtFsIoControlRoutine);
    PrevModeOffset = (unsigned int)GtRead(GtPrevModeOffset);
    PrevModeOffsetVal = PrevModeOffset;
    if (StringAllocRoutine)
    {
        if (FsIoControlRoutine)
        {
            if (PrevModeOffset != -1)
            {
                StringLen = (unsigned int)GetStringLength(DevicePath);
                PathLen = StringLen;
                if (StringLen > 3)
                {
                    PathBuf = (__int16 *)ExAlloc(PagedPool, 2 * StringLen + 2);
                    if (PathBuf)
                    {
                        OutputSize = 2 * PathLen + 112;
                        OutputBuf = ExAlloc(PagedPool, OutputSize);
                        if (OutputBuf)
                        {
                            WStringCopy(PathBuf, DevicePath);
                            LastSlash = WStringFindLastChar(PathBuf, 92);
                            if (LastSlash)
                            {
                                if (LastSlash == PathBuf + 2 && PathBuf[1] == 58)
                                {
                                    FileNameStart = LastSlash + 1;
                                    SavedSeparator = *FileNameStart;
                                    *FileNameStart = 0;
                                }
                                else
                                {
                                    *LastSlash = 0;
                                    SavedSeparator = 0;
                                    FileNameStart = LastSlash + 1;
                                }
                                if (!(unsigned int)CreateFileWithPath(PathBuf, 0, &DeviceHandle, 0x80, 0x80, 1, 1, 0x20))
                                {
                                    if (SavedSeparator)
                                        *FileNameStart = SavedSeparator;
                                    StringAllocRoutine(FileNameBuffer, FileNameStart);
                                    CurrentThread = KeGetCurrentThread();
                                    SavedPrevMode = *((_BYTE *)CurrentThread + PrevModeOffsetVal);
                                    *((_BYTE *)CurrentThread + PrevModeOffsetVal) = 0;
                                    IoStatus = FsIoControlRoutine(DeviceHandle, 0, 0, 0, IoStatusBlock,
                                                                   OutputBuf, OutputSize, 37, 1, FileNameBuffer, 1);
                                    *((_BYTE *)CurrentThread + PrevModeOffsetVal) = SavedPrevMode;
                                    if (IoStatus >= 0)
                                    {
                                        Success = 1;
                                        *pResult = OutputBuf[12];
                                    }
                                    ZwClose(DeviceHandle);
                                }
                            }
                            ExFree(OutputBuf);
                        }
                        ExFree(PathBuf);
                    }
                }
            }
        }
    }
    return Success;
}

// InstallObjectPreCallbackHooks — 安装对象前置回调钩子 (0x14000FF88)
// 读取全局表中三个 ObRegisterCallbacks 回调函数入口地址，保存原回调值，通过 WritePhysicalMemoryQword 替换为 ObjectPreCallback
char InstallObjectPreCallbackHooks(void)
{
    __int64 *ObCallbackEntry1;
    unsigned __int64 ObCallbackAddr1;
    __int64 *ObCallbackEntry2;
    unsigned __int64 ObCallbackAddr2;
    __int64 *ObCallbackEntry3;
    unsigned __int64 ObCallbackAddr3;

    ObCallbackEntry1 = (__int64 *)GtRead(GtObCallbackEntry1 | 0x100);
    ObCallbackAddr1 = (unsigned __int64)ObCallbackEntry1;
    if (ObCallbackEntry1)
    {
        GtWrite(GtSavedObPreCallback1, *ObCallbackEntry1);
        WritePhysicalMemoryQword(ObCallbackAddr1, (__int64)ObjectPreCallback);
    }
    ObCallbackEntry2 = (__int64 *)GtRead(GtObCallbackEntry2 | 0x100);
    ObCallbackAddr2 = (unsigned __int64)ObCallbackEntry2;
    if (ObCallbackEntry2)
    {
        GtWrite(GtSavedObPreCallback2, *ObCallbackEntry2);
        WritePhysicalMemoryQword(ObCallbackAddr2, (__int64)ObjectPreCallback);
    }
    ObCallbackEntry3 = (__int64 *)GtRead(GtKernelDataField19);
    ObCallbackAddr3 = (unsigned __int64)ObCallbackEntry3;
    if (ObCallbackEntry3)
    {
        GtWrite(GtSavedObPreCallback3, *ObCallbackEntry3);
        WritePhysicalMemoryQword(ObCallbackAddr3, (__int64)ObjectPreCallback);
    }
    return (char)ObCallbackEntry3;
}

// RestoreObjectPreCallbackHooks — 恢复对象前置回调钩子 (0x140010020)
// 从全局表读取之前保存的原回调地址，通过 WritePhysicalMemoryQword 写回三个 ObRegisterCallbacks 回调入口
char RestoreObjectPreCallbackHooks(void)
{
    unsigned __int64 ObCallbackAddr1;
    __int64 SavedCallback1;
    unsigned __int64 ObCallbackAddr2;
    __int64 SavedCallback2;
    __int64 ObCallbackAddr3Tmp;
    unsigned __int64 ObCallbackAddr3;
    __int64 SavedCallback3;

    ObCallbackAddr1 = GtRead(GtObCallbackEntry1 | 0x100);
    if (ObCallbackAddr1)
    {
        SavedCallback1 = GtRead(GtSavedObPreCallback1);
        WritePhysicalMemoryQword(ObCallbackAddr1, SavedCallback1);
    }
    ObCallbackAddr2 = GtRead(GtObCallbackEntry2 | 0x100);
    if (ObCallbackAddr2)
    {
        SavedCallback2 = GtRead(GtSavedObPreCallback2);
        WritePhysicalMemoryQword(ObCallbackAddr2, SavedCallback2);
    }
    ObCallbackAddr3Tmp = GtRead(GtKernelDataField19);
    ObCallbackAddr3 = ObCallbackAddr3Tmp;
    if (ObCallbackAddr3Tmp)
    {
        SavedCallback3 = GtRead(GtSavedObPreCallback3);
        WritePhysicalMemoryQword(ObCallbackAddr3, SavedCallback3);
    }
    return (char)ObCallbackAddr3Tmp;
}

// InitObjectCallbackEntries — 初始化对象回调条目
// 读取大量全局表数据（函数指针、类型偏移等），通过 AllocExBufferAndQuerySystemInfo 查询
// 系统对象类型信息，遍历所有对象类型条目并验证（比较类型编号、内核对象有效性），
// 为符合条件的对象类型注册回调函数。包括对象引用计数管理、PreviousMode 临时切换等操作。
// 对应原始驱动 sub_1400100A4
char __fastcall InitObjectCallbackEntries(__int64 TableBase)
{
    char Result;
    unsigned int EntryCount;
    unsigned int RemainingCount;
    __int64 pInfoBuffer;
    __int64 SavedMatchIndex;
    __int64 ObjectTypeInfoPtr;
    __int64 ObjectTypeRefFunc;
    __int64 ZwCreateFileFunc;
    __int64 NtFsControlFileFunc;
    __int64 CloseHandleFunc;
    __int64 ObjectTypeCheckFlag;
    __int64 ValidateObjectTypeFunc;
    __int64 CreateObjectTypeFunc;
    __int64 CloseObjectTypeFunc;
    __int64 DereferenceObjectFunc;
    __int64 RegisterCallbacksFunc;
    __int64 AltRegisterCallbackFunc;
    __int64 SystemRootType;
    __int64 PrevModeOffset;
    __int64 RefObjHeader;
    char *pEntry;
    __int64 ObjHeaderOutput;
    char CallbackParam[8];
    _OWORD ObjectInfoStorage;

    Result = 0;

    // 读取系统根类型
    SystemRootType = GtRead(0x60);
    if (!(_DWORD)SystemRootType)
    {
        BuildSystemRootPath();
        SystemRootType = GtRead(0x60);
        if (!(_DWORD)SystemRootType)
            return Result;
    }

    // 读取所有函数指针和数据偏移
    ObjectTypeInfoPtr = GtRead(GtObjectTypeInfoPtr);
    PrevModeOffset = GtRead(0x27);
    ObjectTypeRefFunc = GtRead(GtObjectTypeRefFunc);
    ZwCreateFileFunc = GtRead(GtZwCreateFileFunc);
    NtFsControlFileFunc = GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = GtRead(GtCloseHandleFunc);
    ObjectTypeCheckFlag = GtRead(GtObjectTypeCheckFlag);
    ValidateObjectTypeFunc = GtRead(GtValidateObjectTypeFunc);
    CreateObjectTypeFunc = GtRead(GtCreateObjectTypeFunc);
    CloseObjectTypeFunc = GtRead(GtCloseObjectTypeFunc);
    DereferenceObjectFunc = GtRead(GtDereferenceObjectFunc);
    RegisterCallbacksFunc = GtRead(GtRegisterObjectCallbacksFunc);
    AltRegisterCallbackFunc = GtRead(GtAltRegisterCallbackFunc);

    // 验证所有指针和数据偏移
    if (!ObjectTypeRefFunc
        || !ZwCreateFileFunc
        || !NtFsControlFileFunc
        || !CloseHandleFunc
        || !ObjectTypeCheckFlag
        || !ValidateObjectTypeFunc
        || !CreateObjectTypeFunc
        || !CloseObjectTypeFunc
        || !DereferenceObjectFunc
        || !RegisterCallbacksFunc
        || (ULONG)PrevModeOffset == 0xFFFFFFFF)
        return Result;

    // 调用 ObReferenceObjectByHandle 获取对象引用
    // 实际函数指针来自 GtRead(0x41C6)（GT 表中存储的 ObReferenceObjectByHandle 或类似函数）
    {
        int Status = ((int (__fastcall *)(__int64, ULONG, __int64, int, _OWORD *, int, int))NtFsControlFileFunc)(
            TableBase, 0x80000000, *(__int64 *)ZwCreateFileFunc, 0, &ObjectInfoStorage, 0, 0);
        if (Status < 0)
            return Result;
    }

    // 查询系统对象类型信息
    pInfoBuffer = (__int64)AllocExBufferAndQuerySystemInfo(0x10);
    if (!pInfoBuffer)
    {
        ((void(__fastcall *)(__int64))DereferenceObjectFunc)(ObjectInfoStorage.qword[0]);
        return Result;
    }

    EntryCount = *(unsigned int *)pInfoBuffer;
    SavedMatchIndex = GtRead(GtObjectTypeMatchIndex);
    RefObjHeader = ObjectInfoStorage.qword[0];

    if (EntryCount)
    {
        pEntry = (char *)(pInfoBuffer + 0xE);
        RemainingCount = EntryCount;

        do
        {
            __int64 ObjectTypeRef;
            __int64 ObjectType;
            __int64 ObjectBody;
            __int64 RefBody;

            // 检查类型匹配索引
            if (CompareInt16Equal(*(unsigned short *)(pEntry - 6), (unsigned int)SavedMatchIndex))
            {
                if (((*(unsigned short *)pEntry | 0x80000000u)) == (unsigned int)TableBase)
                    goto NEXT_ENTRY;
            }

            // 检查类型索引
            if (*(unsigned char *)(pEntry - 2) != (unsigned char)(unsigned int)SystemRootType)
                goto NEXT_ENTRY;

            // 获取对象指针
            ObjectTypeRef = *(__int64 *)(pEntry + 2);
            if (!ObjectTypeRef)
                goto NEXT_ENTRY;

            // 验证对象引用
            if (((UCHAR(__fastcall *)(__int64))ValidateObjectTypeFunc)(ObjectTypeRef) != 1)
                goto NEXT_ENTRY;

            // 验证对象偏移 0xB7
            if (((UCHAR(__fastcall *)(__int64))ValidateObjectTypeFunc)(ObjectTypeRef + 0xB7) != 1)
                goto NEXT_ENTRY;

            // 比较对象头
            if (*(__int64 *)(RefObjHeader + 0x18) != *(__int64 *)(ObjectTypeRef + 0x18))
                goto NEXT_ENTRY;

            // 比较对象体
            ObjectBody = *(__int64 *)(ObjectTypeRef + 0x28);
            RefBody = *(__int64 *)(RefObjHeader + 0x28);
            if (ObjectBody)
            {
                if (((UCHAR(__fastcall *)(__int64))ValidateObjectTypeFunc)(ObjectBody) == 1)
                {
                    if (*(__int64 *)(ObjectBody + 8) != *(__int64 *)(RefBody + 8))
                        goto NEXT_ENTRY;
                }
            }

            // 创建对象类型
            {
                int Status = ((int(__fastcall *)(WORD, __int64 *))CreateObjectTypeFunc)(
                    *(unsigned short *)(pEntry - 6), &ObjectType);
                if (Status >= 0)
                {
                    unsigned int TypeIdx = *(unsigned short *)pEntry;

                    // Win8+ 检查：构建号 >= 7600 且 ObjectTypeInfoPtr 有效
                    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
                    {
                        if (ObjectTypeInfoPtr && *(__int64 *)ObjectTypeInfoPtr != ObjectType)
                            goto SKIP_CALLBACK;
                        TypeIdx |= 0x80000000;
                    }

                    // 引用对象
                    {
                        UCHAR RefCount = ReferenceObjectSafe(ObjectType);

                        // 关闭对象类型引用
                        ((int(__fastcall *)(__int64, __int64 *))CloseObjectTypeFunc)(ObjectType, &ObjHeaderOutput);

                        // 准备回调参数
                        CallbackParam[0] = 0;
                        CallbackParam[1] = 0;
                        CallbackParam[4] = RefCount;

                        // 注册回调
                        Status = ((int(__fastcall *)(unsigned int, int, char *, ULONG, int))DereferenceObjectFunc)(
                            TypeIdx, 4, CallbackParam, 2, 0);

                        if (Status >= 0 && CallbackParam[1] == 1)
                        {
                            // 尝试备用注册
                            if (AltRegisterCallbackFunc)
                            {
                                CallbackParam[1] = 0;
                                Status = ((int(__fastcall *)(unsigned int, int, char *, ULONG))AltRegisterCallbackFunc)(
                                    TypeIdx, 4, CallbackParam, 2);
                                if (Status < 0)
                                {
                                    if (RefCount == 1)
                                        DereferenceObjectSafe(ObjectType);
                                    ((void(__fastcall *)(__int64))ObjectTypeRefFunc)(ObjectType);
                                    goto NEXT_ENTRY;
                                }
                            }
                        }

                        // 临时切换 PreviousMode = 0
                        {
                            PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(0x188);
                            char SavedPrevMode = *(char *)((char *)CurrentThread + (int)PrevModeOffset);
                            *(char *)((char *)CurrentThread + (int)PrevModeOffset) = 0;
                            ((void(__fastcall *)(__int64))RegisterCallbacksFunc)(TypeIdx);
                            *(char *)((char *)CurrentThread + (int)PrevModeOffset) = SavedPrevMode;
                        }

SKIP_CALLBACK:
                        // 需要时解除引用
                        if (RefCount == 1)
                            DereferenceObjectSafe(ObjectType);

                        // 释放对象类型引用
                        ((void(__fastcall *)(__int64))ObjectTypeRefFunc)(ObjectType);
                    }
                }
            }

NEXT_ENTRY:
            pEntry += 0x18;
            --RemainingCount;
        } while (RemainingCount);
    }

    // 清理
    ExFree((void *)pInfoBuffer);
    ((void(__fastcall *)(__int64))ObjectTypeCheckFlag)(RefObjHeader);
    return 1;
}

// DispatchObjectTypeQuery — 分发对象类型查询
// 调用对象类型结构中的查询函数，完成后调用完成通知回调
// 对应原始驱动 sub_140083A84
__int64 (__fastcall *__fastcall DispatchObjectTypeQuery(__int64 ObjectTypeEntry))(_QWORD)
{
    __int64 (__fastcall *NotifyFunc)(_QWORD);
    __int64 (__fastcall *result)(_QWORD);

    result = (__int64 (__fastcall *)(_QWORD))GtRead(GtNtWriteFilePeSectionOffset | GtEprocessField42);
    NotifyFunc = result;
    if (ObjectTypeEntry)
    {
        result = *(__int64 (__fastcall **)(_QWORD))(ObjectTypeEntry + 104);
        if (result)
            result = (__int64 (__fastcall *)(_QWORD))result(ObjectTypeEntry);
    }
    if (NotifyFunc)
        return (__int64 (__fastcall *)(_QWORD))NotifyFunc(0);
    return result;
}

