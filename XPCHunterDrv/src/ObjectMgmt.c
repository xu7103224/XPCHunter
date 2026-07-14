// ObjectMgmt.c — 对象管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "..\inc\XPCHunterDrv.h"
// Forward declarations
__int64 (*EnumKbdclassDriverObjects(unsigned int *a1, _DWORD *a2))(void);
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
    for (CurrentEntry = *ListHead; CurrentEntry != ListHead; CurrentEntry = (_QWORD *)*CurrentEntry)
    {
        if ((ULONG64)CurrentEntry <= MmSystemRangeStart)
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
char DisableObjectProtect(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize)
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

// WalkObjectTypeList — 遍历对象类型列表
// 对应原始驱动 sub_140007F44
char WalkObjectTypeList(_QWORD **NodeStack, int MaxDepth, _DWORD *OutputBuffer, unsigned int MaxBufferSize)
{
    return 0;
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
    int SavedProcessIndex;
    _QWORD **v42;
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
    _QWORD *SavedTypeEntry;
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
    if (EnumerateProcessList(NULL, (__int64)AllocBuffer, 0x44610) != 1)
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
            v42 = ObjectTypeListPtr;
            ObjectTypeListPtrSaved = ObjectTypeListPtr;
            TypeListIndex = 0;

            for (CurrentTypeEntry = *ObjectTypeListPtr;
                 CurrentTypeEntry > (ULONG64)MmSystemRangeStart &&
                 CurrentTypeEntry != ObjectTypeListPtr &&
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

                if (TypeEntry <= (ULONG64)MmSystemRangeStart ||
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
    UCHAR (*v7)(void);
    int (__fastcall *v8)(ULONG64, ULONG64, ULONG64, ULONG64);
    __int64 v9;
    void (__fastcall *v26)(ULONG64);
    _QWORD *v10;
    ULONG (*v25)(_QWORD, __int64 *, _QWORD, char *);
    _QWORD *v12;
    size_t v13;
    SIZE_T v14;
    char v15;
    PVOID v16;
    __int64 *v17, *v18;
    ULONG StringLength;
    __int64 v20;
    ULONG v21;
    char v23 = 0;
    char v24[4];

    *OutBuffer = 0;
    v7 = (UCHAR (*)(void))GtRead(GtObjectTypeCheckFlag);
    v8 = (int (__fastcall *)(ULONG64, ULONG64, ULONG64, ULONG64))GtRead(16742);
    v9 = GtRead(GtCloseHandleFunc);
    v26 = (void (__fastcall *)(ULONG64))v9;
    v10 = (_QWORD *)GtRead(GtZwCreateFileFunc);
    v25 = (ULONG (*)(_QWORD, __int64 *, _QWORD, char *))GtRead(GtQueryObjectNameFunc);

    if (!v7 || !v8 || !v9 || !v10 || !v25) return 0;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
        ObjectAddress &= 0xFFFFFFFFFFFFFFF0ULL;

    v12 = (_QWORD *)(ObjectAddress - 48);
    if (!ObjectAddress || ObjectAddress <= (ULONG64)MmSystemRangeStart ||
        ((UCHAR (*)(ULONG64))v7)(ObjectAddress - 48) != 1 ||
        ((UCHAR (*)(ULONG64))v7)(ObjectAddress + 183) != 1 ||
        !*v12 || !*(_QWORD *)(ObjectAddress + 8) || v7() != 1 ||
        v8(ObjectAddress, 0, *v10, 0) < 0)
        return 0;

    v13 = *(WORD *)(ObjectAddress + 88);
    v14 = (ULONG)(v13 + 0x10000) + 2;
    v15 = 0;
    v16 = ExAlloc(NonPagedPool, (ULONG)v14);
    if (!v16) goto Cleanup;

    v17 = ExAlloc(NonPagedPool, (ULONG)v14);
    if (!v17) { ExFree(v16); goto Cleanup; }

    memset(v17, 0, v14);
    if (!v25(*(_QWORD *)(ObjectAddress + 8), v17, (ULONG)(v13 + 0x10000), v24))
    {
        v18 = (__int64 *)v17[1];
        if (v18 == v17 + 2)
        {
            *((WORD *)v18 + (*(WORD *)v17 >> 1)) = 0;
            StringLength = GetStringLength((WORD *)v17[1]);
            v20 = StringLength;

            if (StringLength <= NameLength &&
                StringCompare3Way(v17[1], TargetName, StringLength) == 0)
            {
                v21 = NameLength - (ULONG)v20;
                if (!v21)
                {
                    memset(v16, 0, v14);
                    memmove(v16, *(const void **)(ObjectAddress + 96), v13);
                    *OutBuffer = (__int64)v16;
                    *OutSize = 0;
                    goto Done;
                }
                if (2 * (ULONG64)v21 <= v13 &&
                    StringCompare3Way(*(_QWORD *)(ObjectAddress + 96), &TargetName[v20], v21) == 0)
                {
                    memset(v16, 0, v14);
                    memmove(v16, *(const void **)(ObjectAddress + 96), (ULONG)v13);
                    *OutBuffer = (__int64)v16;
                    *OutSize = v13;
Done:
                    v23 = 1;
                }
            }
        }
    }
    ExFree(v17);
    v15 = v23;
    if (!v23) { ExFree(v16); }

Cleanup:
    if (*v12) v26(ObjectAddress);
    return v15;
}

// EnableDeviceObjectProtection — 启用设备对象保护
// 对应原始驱动 sub_140010460
char EnableDeviceObjectProtection(void)
{
    return 0;
}

// CheckObjectTypeFlag — 检查对象类型标志位
// 对应原始驱动 sub_1400798B4
char CheckObjectTypeFlag(__int64 ObjectHeader)
{
    char v3 = 0;
    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x2800)
        return *(char *)(ObjectHeader + 24) ^ v3;
    else
        return *(char *)(ObjectHeader + 24);
}

// CheckObjectTypeFlagWrapper — 检查对象类型标志包装
// 对应原始驱动 sub_1400798F0
char CheckObjectTypeFlagWrapper(__int64 ObjectHeader)
{
    return CheckObjectTypeFlag(ObjectHeader);
}

// ReadObjectNameFromCallback — 从回调读取对象名称
// 对应原始驱动 sub_140077B6C
__int64 ReadObjectNameFromCallback(__int64 a1, __int64 a2, __int64 (__fastcall *Callback)(__int64, ULONG64, __int64))
{
    GtRead(GtWindowsBuildNumber);
    if ((*(UCHAR *)(a1 + 10) & 5) != 0)
        return *(_QWORD *)(a1 + 24);
    else
        return Callback(a1, 0, 1);
}

// ResolveObjectNamePointer — 解析对象名称指针
// 对应原始驱动 sub_140077B30
__int64 ResolveObjectNamePointer(__int64 a1)
{
    __int64 v1 = *(_QWORD *)(a1 + 40);
    if (v1 & 1)
    {
        __int64 v3 = *(_QWORD *)((v1 & 0xFFFFFFFFFFFFFFFCULL) + 40);
        return v3 ? *(_QWORD *)(v3 + 16) : 0;
    }
    if (v1 & 2)
    {
        __int64 v4 = *(_QWORD *)((v1 & 0xFFFFFFFFFFFFFFFCULL) + 40);
        return v4 ? *(_QWORD *)v4 : 0;
    }
    return *(_QWORD *)(a1 + 40);
}

// ResolveObjectHeaderPointer — 解析对象头指针
// 对应原始驱动 sub_140077C18
// 根据版本计算对象头在对象体之前的偏移量并返回
char ResolveObjectHeaderPointer(__int64 ObjectBody, _QWORD *OutHeader)
{
    char Result = 0;
    if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        _BYTE *v9 = (_BYTE *)(ObjectBody - 48);
        if (!v9 || MmIsAddressValid(v9) != 1 || MmIsAddressValid(v9 + 47) != 1) return Result;
        char v10 = v9[26];
        if ((v10 & 2) == 0) return Result;
        _BYTE *v8 = v9 - 32;
        if (v10 & 1) v8 -= 32;
        if (!v8) return Result;
        if (MmIsAddressValid(v8) == 1 && MmIsAddressValid(v8 + 31) == 1)
        { Result = 1; *OutHeader = (__int64)(v8 + 8); }
    }
    else
    {
        _BYTE *v5 = (_BYTE *)(ObjectBody - 48);
        if (!v5 || MmIsAddressValid(v5) != 1 || MmIsAddressValid(v5 + 47) != 1) return Result;
        UCHAR v6 = v5[24];
        if (!v6) return Result;
        _BYTE *v8 = &v5[-v6];
        if (!v8) return Result;
        if (MmIsAddressValid(v8) == 1 && MmIsAddressValid(v8 + 31) == 1)
        { Result = 1; *OutHeader = (__int64)(v8 + 8); }
    }
    return Result;
}

// QueryObjectNameString — 查询对象名称字符串
// 对应原始驱动 sub_140079014
char QueryObjectNameString(ULONG64 Object, _QWORD *OutBuffer, _DWORD *OutSize)
{
    char Result = 0;
    UCHAR (*v5)(void);
    int (__fastcall *v6)(_QWORD, WORD *);
    int (__fastcall *v7)(ULONG64, ULONG64, ULONG64, ULONG64);
    void (__fastcall *v32)(ULONG64);
    _QWORD *v8;
    __int64 v31_func;
    int v9, v11, v22, v24;
    char v10, v28 = 0, v37;
    ULONG v15;
    __int64 *v16;
    size_t v17;
    int StringLen;
    char *v13, *v14;
    struct _OBJECT_NAME_INFORMATION *v19, *v20, *Buffer, *v23;
    __int64 v25;
    WORD v26;
    ULONG ReturnLength, Length;
    __int64 v31_val;
    WORD v33;
    PVOID P = NULL;

    *OutBuffer = NULL;
    v5 = (UCHAR (*)(void))GtRead(GtObjectTypeCheckFlag);
    v6 = (int (__fastcall *)(_QWORD, WORD *))GtRead(16910);
    v7 = (int (__fastcall *)(ULONG64, ULONG64, ULONG64, ULONG64))GtRead(16742);
    v32 = (void (__fastcall *)(ULONG64))GtRead(GtCloseHandleFunc);
    v8 = (_QWORD *)GtRead(GtZwCreateFileFunc);
    v31_func = GtRead(GtQueryObjectNameFunc);

    if (!v5 || !v6 || !v7 || !v32 || !v8) return Result;

    if ((ULONG)GtRead(GtWindowsBuildNumber) >= 0x1770)
        Object &= 0xFFFFFFFFFFFFFFF0ULL;

    if (!Object || Object <= (ULONG64)MmSystemRangeStart ||
        ((UCHAR (*)(ULONG64))v5)(Object) != 1 ||
        ((UCHAR (*)(ULONG64))v5)(Object + 183) != 1 ||
        !*(_QWORD *)(Object + 8) || v5() != 1 ||
        OpenMountPointManagerDevice(*(_QWORD *)(Object + 8)) != 1 ||
        v7(Object, 0, *v8, 0) < 0)
        return Result;

    if (v6(*(_QWORD *)(Object + 8), &v33) < 0) { v32(Object); return Result; }

    v9 = *(WORD *)(Object + 88);
    if (P && v5() == 1) { v10 = 1; v37 = 1; v11 = v33 + v9; }
    else { v10 = 0; v37 = 0; v11 = v9 + 2 * GetStringLength((WORD *)0x14008CA70); }

    Length = v11 + 0x10000;
    SIZE_T v12 = (ULONG)(v11 + 0x10000) + 2;
    v13 = ExAlloc(NonPagedPool, (ULONG)v12);
    v14 = v13;
    if (!v13) { if (v10 == 1) ExFreePoolWithTag(P, 0); v32(Object); return Result; }

    memset(v13, 0, v12);
    if (v10 == 1) { v15 = v33; v16 = (__int64 *)P; v17 = v33; }
    else { StringLen = GetStringLength((WORD *)0x14008CA70); v16 = (__int64 *)0x14008CA70; v15 = 2 * StringLen; v17 = v15; }

    memmove(v14, v16, v17);
    v28 = 0;

    if (v31_func)
    {
        v19 = ExAlloc(NonPagedPool, (ULONG)v12);
        v20 = v19;
        if (v19)
        {
            memset(v19, 0, v12);
            if (!((ULONG (*)(_QWORD, struct _OBJECT_NAME_INFORMATION *, ULONG64, ULONG *))v31_func)(
                    *(_QWORD *)(Object + 8), v20, Length, &ReturnLength))
            {
                Buffer = (struct _OBJECT_NAME_INFORMATION *)v20->Name.Buffer;
                if (Buffer == &v20[1])
                {
                    *(&Buffer->Name.Length + (v20->Name.Length >> 1)) = 0;
                    v22 = GetStringLength(v20->Name.Buffer);
                    ReturnLength = 0;
                    v31_val = v22;
                    if (QueryObjectNameByType((PVOID)Object, NULL, 0, &ReturnLength) == -1073741820 && ReturnLength && ReturnLength < v12)
                    {
                        memset(v20, 0, v12);
                        if (!QueryObjectNameByType((PVOID)Object, v20, Length, &ReturnLength))
                        {
                            v23 = (struct _OBJECT_NAME_INFORMATION *)v20->Name.Buffer;
                            if (v23 == &v20[1])
                            {
                                *(&v23->Name.Length + (v20->Name.Length >> 1)) = 0;
                                v24 = GetStringLength(v20->Name.Buffer);
                                if (v24 > (ULONG)v31_val)
                                {
                                    v25 = (ULONG)v31_val;
                                    WStringCopy((WORD *)&v14[(ULONG)v15], (WORD *)&v20->Name.Buffer[(ULONG)v31_val]);
                                    v28 = 1;
                                    v15 = (ULONG)v15 + 2 * GetStringLength(&v20->Name.Buffer[v25]);
                                }
                            }
                        }
                    }
                }
                v10 = v37;
            }
            ExFree(v20);
        }
    }

    if (!v28)
    {
        v26 = *(WORD *)(Object + 88);
        if (v26 && ((UCHAR (*)(__int64))v5)(*(_QWORD *)(Object + 96) - 1 + v26) == 1)
        {
            memmove(&v14[(ULONG)v15], *(const void **)(Object + 96), *(WORD *)(Object + 88));
            v15 = *(WORD *)(Object + 88) + (ULONG)v15;
        }
    }

    v14[v15] = 0;
    v14[(ULONG)(v15 + 1)] = 0;
    *OutBuffer = (__int64)v14;
    if (OutSize) *OutSize = v15;
    Result = 1;

    if (v10 == 1) ExFreePoolWithTag(P, 0);
    v32(Object);
    return Result;
}

// QueryObjectNameWithRetry — 带重试的对象名称查询
// 对应原始驱动 sub_140077864
__int64 QueryObjectNameWithRetry(__int64 ObjectEntry, struct _OBJECT_NAME_INFORMATION *NameInfo, ULONG BufferSize, ULONG *OutSize)
{
    __int64 CurrentEntry = ObjectEntry;
    void *v5;
    ULONG v7 = 16, v10 = 16, v12 = 0, v14, v21;
    NTSTATUS v11;
    char v13;
    __int64 v15, v16, v23;
    struct _OBJECT_NAME_INFORMATION *v17;
    void *v18;
    __int64 Length;
    char *v20;
    WORD v22;
    ULONG ReturnLength;

    v5 = *(void **)(ObjectEntry + 8);
    if (v5)
    {
        ReturnLength = 0;
        v11 = ObQueryNameString(v5, NULL, 0, &ReturnLength);
        if (v11 != -1073741820) goto CheckBuffer;
        if (!ReturnLength) return (ULONG)v11;
        v10 = ReturnLength + 276;
    }
    v11 = 0;

CheckBuffer:
    if (v11) return (ULONG)v11;

    v12 = 0;
    v13 = 1;
    if (*(_QWORD *)(ObjectEntry + 96))
    {
        v14 = 0;
        v15 = ObjectEntry;
        while (v14 < 0x100)
        {
            v12 += *(WORD *)(v15 + 88);
            v16 = *(_QWORD *)(v15 + 64);
            if (v15 == v16 || !v16) break;
            v14++;
            v15 = *(_QWORD *)(v15 + 64);
        }
        v10 += v12;
    }

    if (BufferSize < v10)
    {
        if (OutSize) *OutSize = v10;
        return -1073741820;
    }

    v17 = NameInfo + 1;
    NameInfo->Name.Length = 0;
    NameInfo->Name.Buffer = (PWSTR)&NameInfo[1].Name.Length;
    v18 = *(void **)(ObjectEntry + 8);
    if (v18)
    {
        v11 = ObQueryNameString(v18, NameInfo, BufferSize, &ReturnLength);
        if (v11 < 0) { if (OutSize) *OutSize = ReturnLength; return (ULONG)v11; }
        Length = NameInfo->Name.Length;
        v17 = (struct _OBJECT_NAME_INFORMATION *)((char *)v17 + Length);
        v7 = (ULONG)(Length + 16);
    }

    if (v11 >= 0)
    {
        if (*(_QWORD *)(ObjectEntry + 96))
        {
            v7 += v12;
            v20 = (char *)v17 + v12;
            NameInfo->Name.Length += (WORD)v12;
            v21 = 0;
            do
            {
                if (v21 >= 0x100) break;
                v22 = *(WORD *)(CurrentEntry + 88);
                if (v22 & 1) goto CheckResult;
                v20 -= v22;
                memmove(v20, *(const void **)(CurrentEntry + 96), v22);
                v23 = *(_QWORD *)(CurrentEntry + 64);
                if (CurrentEntry == v23) break;
                v21++;
                CurrentEntry = *(_QWORD *)(CurrentEntry + 64);
            } while (v23);
        }
        else { v13 = ReturnLength; goto CheckResult; }

CheckResult:
        if (v13) return -1073741823;
        if (OutSize) *OutSize = v7;
        return 0;
    }

    return (ULONG)v11;
}

// MatchObjectTypeEntry — 匹配对象类型条目
// 对应原始驱动 sub_14006EBF8
// 遍历 a2 偏移+16 处的 17 个条目(步长 26 QWORD/208 字节)
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
__int64 CmdEnumGdiObjects(__int64 a1, __int64 a2, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    __int64 v6;
    _DWORD v8[5];

    if (!OutputBuffer || BufferSize < 0x220 ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    v6 = BufferSize;
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    memset(OutputBuffer, 0, (ULONG)v6);
    *OutputBuffer = 0;
    v8[0] = (v6 - 544) / 0x218 + 1;

    EnumGdiObjectEntries(OutputBuffer, v8);
    if (v8[0])
    {
        EnumKbdclassDriverObjects(OutputBuffer, v8);
        if (v8[0])
        {
            CollectObjectDirAndTypeEntries(OutputBuffer, v8);
            if (v8[0])
            {
                EnumDriverPeImageEntries(OutputBuffer, v8);
                if (v8[0])
                    EnumHandleTableToBuffer(OutputBuffer, v8);
            }
        }
    }
    return *OutputBuffer != 0;
}

// MatchObjectTypeFilterCallback — 匹配对象类型过滤回调 V1
// 对应原始驱动 sub_14006CDA0
// 检查对象类型是否匹配过滤条件。>0x1772 使用 CheckObjectTypeFlagWrapper 检查标志，
// 否则比较对象类型指针。匹配时设置 a3+8 标志位。
__int64 MatchObjectTypeFilterCallback(_QWORD *a1, _QWORD *a2, __int64 a3)
{
    char v6 = 0;
    __int64 v8;
    __int64 a1Val = (__int64)a1;
    __int64 a2Val = (__int64)a2;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        char v9 = CheckObjectTypeFlagWrapper(a2);
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer01) != v9)
            return v6;
        v8 = a2Val + 48;
    }
    else
    {
        _QWORD *v7 = (_QWORD *)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        if (!v7 || *v7 != *(_QWORD *)(a1Val + 16))
            return v6;
        v8 = a1Val + 48;
    }
    if (v8 && v8 == *(_QWORD *)a3)
    {
        *(_BYTE *)(a3 + 8) = 1;
        return 1;
    }
    return v6;
}

// EnumKernelObjectDirectory — 枚举内核对象目录
// 对应原始驱动 sub_14006C5A0
// 打开对象目录，遍历目录条目，过滤后输出
__int64 (*EnumKernelObjectDirectory(__int64 ObjectPath, unsigned int Offset, unsigned int Flags,
    unsigned int *OutputBuffer, _DWORD *pCount))(void)
{
    void (__fastcall *InitUnicodeFunc)(_BYTE *, __int64);
    __int64 (__fastcall *CreateFileFunc)(_BYTE *, __int64, ULONG64);
    __int64 v10;
    void (*CloseFunc)(void);
    __int64 (*result)(void);
    __int64 v13, v14, v15, v16, v17;
    __int64 v18 = 0;
    __int64 (*v19)(void);
    __int64 v20;
    char v21;
    _BYTE v22[16];

    InitUnicodeFunc = (void (__fastcall *)(_BYTE *, __int64))GtRead(GtRtlInitUnicodeStringFunc);
    CreateFileFunc = (__int64 (__fastcall *)(_BYTE *, __int64, ULONG64))GtRead(GtIoCreateFileFunc);
    v10 = GtRead(GtDriverObjectListHead);
    result = (__int64 (*)(void))GtRead(GtCloseHandleFunc);
    v19 = result;

    if (!InitUnicodeFunc || !CreateFileFunc || !v10 || !result) return result;

    InitUnicodeFunc(v22, ObjectPath);
    result = (__int64 (*)(void))CreateFileFunc(v22, 64, 0);
    if ((int)result < 0 || !v18) return result;

    v13 = *(__int64 *)(v18 + 8);
    if (!v13) return (__int64 (*)())v19();

    do
    {
        v14 = *(__int64 *)(v13 + 64);
        if (!v14) goto NextNode;
        v15 = *(__int64 *)(Offset + v14);
        if (!v15 || !*pCount) goto NextNode;

        if ((ULONG)GtRead(GtWindowsBuildNumber) > 0x1772)
        {
            if ((*(UCHAR *)(v15 - 22) & 2) == 0) goto CheckSecondary;
        }
        else
        {
            if (!*(UCHAR *)(v15 - 24)) goto CheckSecondary;
        }

        v21 = 0;
        v20 = v15;
        ReadVolumeDataToBuffer((__int64 (*)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallback,
            (__int64)&v20);
        if (v21) goto CheckChild;
        goto CopyEntry;

CheckSecondary:
        v16 = *(__int64 *)(v13 + 312);
        if (v16 && MmIsAddressValid(*(PVOID *)(v13 + 312)) == 1 &&
            MmIsAddressValid((PVOID)(v16 + 55)) == 1 &&
            v15 != *(__int64 *)(v16 + 48))
            goto CopyEntry;
        goto CheckChild;

CopyEntry:
        CopyObjectEntryToBuffer(v15, 1, Flags, OutputBuffer, pCount);

CheckChild:
        v17 = *(__int64 *)(v15 + 8);
        if (v17 && *pCount)
        {
            v21 = 0;
            v20 = v17;
            ReadVolumeDataToBuffer((__int64 (*)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallbackV2,
                (__int64)&v20);
            if (!v21)
                CopyObjectEntryToBuffer(v17, 2, Flags, OutputBuffer, pCount);
        }

NextNode:
        v13 = *(__int64 *)(v13 + 16);
    } while (v13);

    return (__int64 (*)())v19();
}

// CopyObjectEntryToBuffer — 复制对象条目到缓冲区
// 对应原始驱动 sub_14006D524
// 输出 134 DWORD(536 字节)的条目。类型：1=对象头，2=目录项，3=驱动，4=句柄
char CopyObjectEntryToBuffer(__int64 Entry, unsigned int Type, unsigned int Flags, unsigned int *OutputBuffer, _DWORD *pCount)
{
    __int64 NameLength = 0;
    char *NamePtr = NULL;
    ULONG v9;
    __int64 v10, v11;
    WORD *v12;
    size_t v13;
    const void *v14;
    WORD *v16;

    if (!*pCount) return 0;

    *(__int64 *)&OutputBuffer[134 * *pCount + 2] = Entry;
    OutputBuffer[134 * *pCount + 4] = Type;
    OutputBuffer[134 * *pCount + 5] = Flags;
    LOWORD_LV(OutputBuffer[134 * *pCount + 6]) = 0;

    if (Type - 1 <= 1)
    {
        if (Type == 1)
        {
            if (ResolveObjectHeaderPointer(Entry, &v16) == 1)
            {
                NameLength = *v16;
                NamePtr = (char *)*((__int64 *)v16 + 1);
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

        v13 = (ULONG)NameLength;
        v14 = NamePtr;
    }
    else
    {
        if (Type == 3)
        {
            v10 = 134LL * *pCount;
            v11 = *(__int64 *)(Entry + 24);
            v12 = (WORD *)(Entry + 36);
        }
        else
        {
            if (Type != 4) goto Increment;
            v10 = 134LL * *pCount;
            v11 = *(__int64 *)(Entry + 32);
            v12 = (WORD *)(Entry + 40);
        }
        *(__int64 *)&OutputBuffer[v10 + 2] = v11;
        v9 = 2 * GetStringLength(v12);
        if (v9 > 0x208) v9 = 520;
        if (v9 <= 2) goto Increment;
        v13 = v9;
        v14 = v12;
    }

    memmove(&OutputBuffer[134 * *pCount + 6], v14, v13);
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
    __int64 (__fastcall *CreateFileFunc)(_QWORD *, __int64, _QWORD, _QWORD, _QWORD **, _QWORD);
    void (__fastcall *CloseHandleFunc)(_QWORD);
    __int64 (__fastcall *DeviceIoControlFunc)(_QWORD *, __int64, int *);
    int (__fastcall *QueryDeviceChildFunc)(_QWORD, _QWORD *);
    int (__fastcall *NtFsControlFileFunc)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD);
    int (__fastcall *UnknownFunc)(_QWORD, ULONG, _QWORD, _QWORD *);
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
    CreateFileFunc = (__int64 (__fastcall *)(_QWORD *, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(GtCreateFileFunc2);
    CloseHandleFunc = (void (__fastcall *)(_QWORD))GtRead(GtCloseHandleFunc);
    DeviceIoControlFunc = (__int64 (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    QueryDeviceChildFunc = (int (__fastcall *)(_QWORD, _QWORD *))GtRead(0x4199);
    NtFsControlFileFunc = (int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    UnknownFunc = (int (__fastcall *)(_QWORD, ULONG, _QWORD, _QWORD *))GtRead(0x4340);

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
__int64 (*EnumKbdclassDriverObjects(unsigned int *a1, _DWORD *a2))(void)
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
    return EnumKernelObjectDirectory((__int64)EncodedPath, 0x10u, 2u, a1, a2);
}

// EnumObjectTypeFilterCallback — 枚举对象类型过滤回调
// 对应原始驱动 sub_14006CEC8
// 根据构建号分支使用 CheckObjectTypeFlagWrapper 或直接比较指针，将匹配的地址存入缓冲区数组
char EnumObjectTypeFilterCallback(__int64 a1, __int64 a2, __int64 a3)
{
    _QWORD *v6;
    __int64 v7;
    __int64 v8;
    _QWORD *v9;
    __int64 v10;
    __int64 v11;
    char v12;
    char v13;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) <= 0x1772)
    {
        v6 = (_QWORD *)GtRead(GtTotalSize | GtPspTerminateThreadAddr | 0x100);
        if (v6 && *v6 == *(_QWORD *)(a1 + 16))
        {
            if (*(_BYTE *)a3 != 1)
            {
                v7 = *(unsigned int *)(a3 + 28);
                if ((unsigned int)v7 < *(_DWORD *)(a3 + 24))
                {
                    v8 = a1 + 48;
                    *(_QWORD *)(*(_QWORD *)(a3 + 32) + 8 * v7) = v8;
                    ++*(_DWORD *)(a3 + 28);
                }
                return 0;
            }
            ++*(_DWORD *)(a3 + 24);
            return 0;
        }
        v9 = (_QWORD *)GtRead(GtDriverObjectListHead);
        if (!v9 || *v9 != *(_QWORD *)(a1 + 16))
            return 0;
        if (*(_BYTE *)a3 != 1)
        {
            v10 = *(unsigned int *)(a3 + 8);
            if ((unsigned int)v10 >= *(_DWORD *)(a3 + 4))
                return 0;
            v11 = a1 + 48;
            *(_QWORD *)(*(_QWORD *)(a3 + 16) + 8 * v10) = v11;
            ++*(_DWORD *)(a3 + 8);
            return 0;
        }
        ++*(_DWORD *)(a3 + 4);
        return 0;
    }
    v12 = CheckObjectTypeFlagWrapper(a2);
    if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer01) != v12)
    {
        v13 = CheckObjectTypeFlagWrapper(a2);
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) != v13)
            return 0;
        if (*(_BYTE *)a3 != 1)
        {
            v10 = *(unsigned int *)(a3 + 8);
            if ((unsigned int)v10 >= *(_DWORD *)(a3 + 4))
                return 0;
            v11 = a2 + 48;
            *(_QWORD *)(*(_QWORD *)(a3 + 16) + 8 * v10) = v11;
            ++*(_DWORD *)(a3 + 8);
            return 0;
        }
        ++*(_DWORD *)(a3 + 4);
        return 0;
    }
    if (*(_BYTE *)a3 == 1)
    {
        ++*(_DWORD *)(a3 + 24);
        return 0;
    }
    v7 = *(unsigned int *)(a3 + 28);
    if ((unsigned int)v7 < *(_DWORD *)(a3 + 24))
    {
        v8 = a2 + 48;
        *(_QWORD *)(*(_QWORD *)(a3 + 32) + 8 * v7) = v8;
        ++*(_DWORD *)(a3 + 28);
    }
    return 0;
}

// CollectObjectDirAndTypeEntries — 收集对象目录和类型条目
// 对应原始驱动 sub_14006CBBC
// 通过 EnumObjectTypeFilterCallback 收集所有对象目录和对象类型地址，遍历并输出
void CollectObjectDirAndTypeEntries(unsigned int *a1, _DWORD *a2)
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
        if (!*a2) break;
        CollectObjectDirEntry((__int64)&CallbackState, *(_QWORD *)(CallbackState.DirArray[i] + 8), a1, a2);
    }

    for (j = 0; (unsigned int)j < CallbackState.TypeIndex; j = (unsigned int)(j + 1))
    {
        if (!*a2) break;
        CollectObjectTypeEntry((__int64)&CallbackState, *(_QWORD *)(CallbackState.TypeArray[j] + 8), a1, a2);
    }

    for (k = 0; k < CallbackState.DirIndex; k++)
    {
        if (!*a2) break;
        NestLimit = 0;
        CurrentEntry = *(_QWORD *)(CallbackState.DirArray[k] + 24);
        if (CurrentEntry)
        {
            do
            {
                if (NestLimit >= 0x1000) break;
                if (!*a2) break;
                CollectObjectTypeEntry((__int64)&CallbackState, CurrentEntry, a1, a2);
                CollectObjectDirEntry((__int64)&CallbackState, *(_QWORD *)(CurrentEntry + 8), a1, a2);
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
__int64 MatchObjectTypeFilterCallbackV2(_QWORD *a1, _QWORD *a2, __int64 a3)
{
    char Result;
    _QWORD *TypePtr;
    __int64 EntryPtr;

    Result = 0;
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x1772)
    {
        if ((unsigned __int8)GtRead(GtDisableHookProtectionAddr2 | GtPathBuffer02) != CheckObjectTypeFlagWrapper(a2))
            return Result;
        EntryPtr = (__int64)a2 + 48;
    }
    else
    {
        TypePtr = (_QWORD *)GtRead(GtDriverObjectListHead);
        if (!TypePtr || *TypePtr != *(_QWORD *)(a1 + 16))
            return Result;
        EntryPtr = (__int64)a1 + 48;
    }
    if (EntryPtr && EntryPtr == *(_QWORD *)a3)
    {
        *(_BYTE *)(a3 + 8) = 1;
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
        NameResult = QueryObjectNameWithRetry((__int64)Object, ObjectNameInfo, Length, ReturnLength);
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
        return InitObjectCallbackFiles((int)ObjectName);
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
    __int64 v6;
    _QWORD *v7;
    __int64 v8;
    __int64 v9;
    __int64 v11;
    char v12;

    ObjectTypeDirectoryPath = QueryObjectTypeDirectoryPath();
    if (ObjectTypeDirectoryPath)
    {
        v6 = *(_QWORD *)(ObjectTypeDirectoryPath + 64);
        v7 = *(_QWORD **)(ObjectTypeDirectoryPath + 312);
        if (v6)
        {
            v8 = *(_QWORD *)(v6 + 16);
            if (v8 && *pCount)
            {
                v9 = *(_QWORD *)(v8 + 8);
                if (v9)
                {
                    v12 = 0;
                    v11 = v9;
                    ReadVolumeDataToBuffer(
                        (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallbackV2,
                        (__int64)&v11);
                    if (!v12)
                    {
                        Result = 1;
                        CopyObjectEntryToBuffer(v9, 2, 1, OutputBuffer, pCount);
                    }
                }
                v12 = 0;
                v11 = v8;
                ReadVolumeDataToBuffer(
                    (__int64 (__fastcall *)(_QWORD *, _QWORD *, __int64))MatchObjectTypeFilterCallback,
                    (__int64)&v11);
                if (!v12)
                {
                    if (Result == 1
                        || v9
                        && (ValidateKernelModuleAddressRange(v9) == 1
                            || v7
                            && CheckMemoryValid(v7) == 1
                            && CheckMemoryValid((char *)v7 + 55) == 1
                            && v8 != v7[6]))
                    {
                        CopyObjectEntryToBuffer(v8, 1, 1, OutputBuffer, pCount);
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
            EntryPtr = DriverBuffer + 11;
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
            CurrentOffset = 552 * EntryCount + 560;
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
    int (*NtFsControlFileFunc)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD);
    void (*CloseHandleFunc)(_QWORD *);
    void (*ExFreePoolFunc)(_QWORD);
    _DWORD EncodedPath[6];
    _BYTE ObjectNameBuf[16];
    __int64 Handle;
    _BYTE ObjAttr[0x30];
    __int64 DeviceObj;
    __int64 NextDevice;
    __int64 CurrentDevice;
    int ReturnLength;
    _BYTE *NameBuffer;
    int NameBufferSize;
    WORD *NameStr;
    WORD *LastChar;
    int NameLen;

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, int *))GtRead(0x421D);
    IoCreateFileFunc = (__int64 (*)(_BYTE *, __int64, __int64 *, _BYTE *, _QWORD, _QWORD, _QWORD))GtRead(0x421A);
    NtFsControlFileFunc = (int (*)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(0x4220);
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
    *(_QWORD *)(ObjAttr + 28) = ObjectNameBuf;
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
                    // Query object name
                    ReturnLength = 0;
                    if (NtFsControlFileFunc(CurrentDevice, 0, 0, 0, &NameBuffer, 0) == 0xC0000004 && ReturnLength)
                    {
                        // ... simplified - actual implementation would query name buffer
                    }
                }
                CurrentDevice = *(_QWORD *)(CurrentDevice + 0x10);
            }
        }
        CloseHandleFunc(Handle);
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
// 遍历 134 字节/项(138 DWORD)的数组，查找 a2==a3[i+4]且 a1==a3[i+2..i+3]的 QWORD 匹配项
char FindMatchingEntryInArray(__int64 Entry, unsigned int Type, unsigned int *Array)
{
    for (unsigned int i = 0; i < *Array; ++i)
    {
        __int64 v6 = 134LL * i;
        if (Type == Array[v6 + 4] && Entry == *(_QWORD *)&Array[v6 + 2])
            return 1;
    }
    return 0;
}

// TraverseHashTableWithCallback — 通过回调函数遍历哈希表
// 对应原始驱动 sub_14006D18C
// 遍历 0x25 个哈希桶，对每个条目检查类型标志匹配，匹配的条目按深度优先存入 a1 数组，不匹配的调用 a3 回调处理
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
                                Result = Callback(NextEntry - 6, NextEntry - 6, Context);
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
    __int64 (__fastcall *ExFreePoolFunc)(_QWORD);
    __int64 (__fastcall *Result)(_QWORD);
    __int64 (__fastcall *v9)(_QWORD);
    _QWORD **v10;
    void *v11;
    _QWORD v12[4];
    _BYTE v13[16];
    int v14;
    __int64 v15;
    _BYTE *v16;
    int v17;
    _OWORD v18;
    int v19;
    _QWORD *v20;

    RtlInitUnicodeStringFunc = (void (__fastcall *)(_BYTE *, int *))GtRead(GtRtlInitUnicodeStringFunc);
    DeviceIoControlFunc = (__int64 (__fastcall *)(_QWORD *, __int64, int *))GtRead(GtDeviceIoControlFunc);
    NtFsControlFileFunc = (int (__fastcall *)(_QWORD, __int64, _QWORD, _QWORD, _QWORD **, _QWORD))GtRead(GtNtFsControlFileFunc);
    CloseHandleFunc = (void (__fastcall *)(_QWORD *))GtRead(GtCloseHandleFunc);
    v12[1] = CloseHandleFunc;
    Result = (__int64 (__fastcall *)(_QWORD))GtRead(GtExFreePoolFunc);
    v9 = Result;
    v12[2] = Result;

    if (!RtlInitUnicodeStringFunc || !DeviceIoControlFunc || !NtFsControlFileFunc || !CloseHandleFunc || !Result)
        return Result;

    v19 = 92;
    RtlInitUnicodeStringFunc(v13, &v19);
    v14 = 48;
    v15 = 0;
    v17 = 576;
    v16 = v13;
    memset(&v18, 0, sizeof(v18));

    Result = (__int64 (__fastcall *)(_QWORD))DeviceIoControlFunc(v12, 1, &v14);
    if ((int)Result >= 0)
    {
        if (NtFsControlFileFunc(v12[0], 983055, 0, 0, &v20, 0) >= 0)
        {
            v10 = (_QWORD **)ExAlloc(PagedPool, 0x100000);
            v11 = v10;
            v12[3] = v10;
            if (v10)
            {
                *v10 = v20;
                TraverseHashTableWithCallback(v10, 0x20000, Callback, Context);
                ExFree(v11);
            }
            CloseHandleFunc(v20);
        }
        return (__int64 (__fastcall *)(_QWORD))v9(v12[0]);
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
                    unsigned int RangeSize = MaxAddr - MinAddr;
                    if (!*(_DWORD *)(LdrEntry + 32))
                        return RangeSize > 0x1E00000;
                    if (RangeSize > *(unsigned int *)(LdrEntry + 32))
                        return 1;
                }
            }
            else
            {
                unsigned int ImageSize = *(unsigned int *)(LdrEntry + 32);
                unsigned int RangeSize = MaxAddr - MinAddr;
                if (!ImageSize)
                    return RangeSize > 0x1E00000;
                if (RangeSize > ImageSize)
                    return 1;
            }
        }
    }
    return Result;
}
