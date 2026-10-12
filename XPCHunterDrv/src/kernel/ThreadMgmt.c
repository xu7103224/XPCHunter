// ThreadMgmt.c — 线程管理
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）

#include "XPCHunterDrv.h"

// 前向声明（函数实现位于文件末尾，供 CleanupThreadWithBuffer 调用）
const ULONG64 *RemoveOplockNodeByQwordKey(const ULONG64 **KeyArray, ULONG Offset, __int64 Context);
__int64 FindSystemRootEntry(_DWORD *ThreadInfoTable);
void EnumerateVadIterativeV2(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV2(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
_QWORD *ResetThreadStateIfMatch(__int64 Process, __int64 OutputBuffer);
ULONG64 EnumerateThreadListEntries(unsigned int *ListHead, unsigned int ListFieldOffset, char IsUserMode, unsigned int *OutputBuffer, unsigned int OutputSize, char EntryTypeValue);
void EnumerateVadIterativeV3(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV3(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadIterativeV4(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateVadRecursiveV4(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionRecursiveV1(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionEx(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionStub(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumerateFileMappingSectionByIndex(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize);
void EnumVadMemoryRegions(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize);
char QueryObjectNameString(ULONG64 Object, _QWORD *OutBuffer, _DWORD *OutSize);
char FindThreadEntry(_DWORD *OutputBuffer, __int64 Target, unsigned int *OutIndex, __int64 ExtraParam);
void NormalizeRelativePath(WORD *Path);
void PatchThreadImagePathWithWow64(__int64 Path);
__int64 StringCompareCaseInsensitiveV2(__int64 Str1, __int64 Str2);
__int64 WStringCompare(__int64 Str1, unsigned __int16 *Str2, unsigned int Length);
__int64 StringCompare3Way(__int64 Str1, unsigned __int16 *Str2, unsigned int Length);
__int16 *WStringCopy(__int16 *Dst, __int16 *Src);

// EnableThreadProtect — 启用线程保护
// 对应原始驱动 sub_140007AB4
char EnableThreadProtect(__int64 *Address, int InputSize, _QWORD *OutputBuffer, int OutputSize)
{
    ULONG64 ThreadAddress;

    if (!Address || !OutputBuffer || InputSize != 8 || OutputSize != 8)
        return 0;

    if ((ULONG64)Address >= MmUserProbeAddress || (ULONG64)(Address + 1) >= MmUserProbeAddress)
        return 0;
    if ((ULONG64)OutputBuffer >= MmUserProbeAddress || (ULONG64)(OutputBuffer + 1) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(Address, 8, 8);
    ProbeForWrite(OutputBuffer, 8, 8);

    ThreadAddress = *Address;
    if (ThreadAddress > (ULONG64)MmSystemRangeStart)
    {
        ULONG PageIndex;
        for (PageIndex = 0; PageIndex < 0x100 && MmIsAddressValid((PVOID)(ThreadAddress + PageIndex)); PageIndex++)
            ;
        if (PageIndex)
            *OutputBuffer = ThreadAddress;
    }
    return 0;
}

// DisableThreadProtect — 禁用线程保护
// 对应原始驱动 sub_140007BAC
char DisableThreadProtect(unsigned int *Address, int ContextSize)
{
    if (!Address || ContextSize != 32)
        return 0;
    if ((ULONG64)Address >= MmUserProbeAddress || (ULONG64)(Address + 8) >= MmUserProbeAddress)
        return 0;

    ProbeForRead(Address, 0x20, 4);
    if (!*(ULONG64 *)Address || !*((ULONG64 *)Address + 2) || !Address[2] || !*((ULONG64 *)Address + 3))
        return 0;

    if ((ULONG64)*((PVOID *)Address + 2) >= MmUserProbeAddress ||
        (ULONG64)*((PVOID *)Address + 2) + Address[2] >= MmUserProbeAddress)
        return 0;

    if (*((ULONG64 *)Address + 3) >= MmUserProbeAddress || *((ULONG64 *)Address + 3) + 8 >= MmUserProbeAddress)
        return 0;

    ProbeForRead(*((PVOID *)Address + 2), Address[2], 1);
    ProbeForWrite(*((volatile PVOID *)Address + 3), 8, 8);

    PVOID AllocBuffer = ExAlloc(NonPagedPool, Address[2]);
    if (!AllocBuffer)
        AllocBuffer = ExAlloc(PagedPool, Address[2]);
    if (AllocBuffer)
    {
        memmove(AllocBuffer, *((const void **)Address + 2), Address[2]);
        ExFree(AllocBuffer);
    }

    return 0;
}

// InitThreadCallback — 线程回调（补全空壳）
// 对应原始驱动 0x140010A0C（28 字节）
// 【⚠ 修正记录 2026-10-08】原为无参 `return 1;` 空壳，与实物不符：
//   原始是 **4 形参**的 TLV 回调，做实际的标志设置与字节复制。
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（18 行伪代码），按伪代码实现。
// 【参数】InputBuffer / BufferSize / OutputFlags / OutputBuffer
// 【逻辑】若 InputBuffer+1 >= BufferSize（越界）→ 置 *OutputFlags |= 2；
//   否则 OutputFlags[1] = 1，并把 InputBuffer 偏移 1 处的字节
//   复制到 OutputBuffer 偏移 6 处，返回该字节。
char InitThreadCallback(__int64 InputBuffer, unsigned __int64 BufferSize,
                        _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *BufferPos = (char *)(InputBuffer + 1);
    char Result;

    if ((unsigned __int64)BufferPos >= BufferSize)
    {
        *OutputFlags |= 2u;
        return 0;
    }
    OutputFlags[1] = 1;
    Result = *BufferPos;
    *(_BYTE *)(OutputBuffer + 6) = *BufferPos;
    return Result;
}

// ThreadCallbackRoutine — 线程回调例程
// 对应原始驱动 sub_140010A28
// 解析 TLV 格式的线程信息数据，提取类型字段和值到输出缓冲区
char ThreadCallbackRoutine(__int64 InputBuffer, ULONG64 BufferSize, _DWORD *OutputFlags, __int64 OutputBuffer)
{
    char *DataPtr;
    char FirstByte;
    char TypeField;
    char TypeHighBits;
    _DWORD *ValuePtr;
    UCHAR *ExtraBytePtr;
    __int64 OffsetIndex;
    __int64 OffsetBase;
    int ExtractedValue;

    DataPtr = (char *)(InputBuffer + 1);
    if ((ULONG64)DataPtr >= BufferSize)
        goto ErrorExit;

    OutputFlags[1] = 1;
    FirstByte = *DataPtr;
    *(UCHAR *)(OutputBuffer + 6) = *DataPtr;
    TypeField = FirstByte & 0xC7;
    TypeHighBits = TypeField & 0xC0;

    if ((TypeField & 0xC0) == 0xC0)
        return 0;

    if (*(UCHAR *)(OutputBuffer + 1) == 2)
    {
        if (TypeField == 6)
            goto Label10;
        if (TypeHighBits == 0x40)
        {
            ValuePtr = (_DWORD *)(DataPtr + 1);
            goto Label7;
        }
        if (TypeHighBits == (char)0x80)
            goto Label10;
    }
    else
    {
        if (TypeField == 5)
            goto Label_OffsetCheck;
        if ((TypeField & 7) == 4)
        {
            ExtraBytePtr = (UCHAR *)(DataPtr + 1);
            if ((ULONG64)ExtraBytePtr >= BufferSize)
                goto ErrorExit;
            *(UCHAR *)(OutputBuffer + 11) = *ExtraBytePtr;
            ValuePtr = (_DWORD *)(ExtraBytePtr + 1);
            OutputFlags[2] = 1;
            if (TypeField == 4 && (*ExtraBytePtr & 7) == 5)
                goto Label_DwordRead;
            if (TypeHighBits == 0x40)
                goto Label7;
            if (TypeHighBits == (char)0x80)
                goto Label_DwordRead;
            return 0;
        }
        if (TypeHighBits == 0x40)
        {
            OffsetIndex = OutputFlags[2];
            OffsetBase = OffsetIndex ? 2 : 1;
            DataPtr = &DataPtr[OffsetBase];
            if ((ULONG64)DataPtr >= BufferSize)
                goto ErrorExit;
            OutputFlags[3] = 1;
            ExtractedValue = DataPtr[OffsetIndex + 1];
            goto StoreValue;
        }
        if (TypeHighBits != (char)0x80)
            return 0;
    }

Label_OffsetCheck:
    OffsetIndex = OutputFlags[2];
    OffsetBase = OffsetIndex ? 5 : 4;
    DataPtr = &DataPtr[OffsetBase];
    if ((ULONG64)DataPtr >= BufferSize)
        goto ErrorExit;
    OutputFlags[3] = 4;
    ExtractedValue = *(int *)&DataPtr[OffsetIndex + 1];
    goto StoreValue;

Label7:
    if ((ULONG64)ValuePtr >= BufferSize)
        goto ErrorExit;
    OutputFlags[3] = 1;
    ExtractedValue = *(char *)ValuePtr;
    goto StoreValue;

Label10:
    DataPtr++;
    if ((ULONG64)(DataPtr + 1) >= BufferSize)
        goto ErrorExit;
    OutputFlags[3] = 2;
    ExtractedValue = *(short *)(DataPtr);
    goto StoreValue;

Label_DwordRead:
    DataPtr = (char *)ValuePtr + 3;
    if ((ULONG64)ValuePtr + 3 >= BufferSize)
        goto ErrorExit;
    OutputFlags[3] = 4;
    ExtractedValue = *ValuePtr;
    goto StoreValue;

StoreValue:
    *(int *)(OutputBuffer + 12) = ExtractedValue;
    return (char)DataPtr;

ErrorExit:
    *OutputFlags |= 2;
    return 0;
}

// MiniFilterOpLockPre — Oplock 预处理回调
// 对应原始驱动 sub_14001A454
char MiniFilterOpLockPre(PRKPROCESS ProcessObject, __int64 Unknown, ULONG64 UserBuffer, char IsQwordKey)
{
    char IsReferenced;
    KAPC_STATE ApcState;

    if (UserBuffer <= 0x1000 || UserBuffer >= MmUserProbeAddress)
        return 0;
    if (ValidateProcessObject(ProcessObject, NULL) != 1)
        return 0;

    IsReferenced = ReferenceObjectSafe((__int64)ProcessObject);
    KeStackAttachProcess(ProcessObject, &ApcState);

    if (IsQwordKey)
    {
        if (UserBuffer < MmUserProbeAddress && UserBuffer + 256 < MmUserProbeAddress)
        {
            ULONG i;
            for (i = 0; i < 0x20; i++)
                RemoveOplockNodeByDwordKey((unsigned int *)(UserBuffer + 8 * i), 0x3C, Unknown);
        }
    }
    else
    {
        if (UserBuffer < MmUserProbeAddress && UserBuffer + 512 < MmUserProbeAddress)
        {
            ULONG j;
            for (j = 0; j < 0x20; j++)
                RemoveOplockNodeByQwordKey((const ULONG64 **)(UserBuffer + 16 * j), 0x70, Unknown);
        }
    }

    KeUnstackDetachProcess(&ApcState);
    if (IsReferenced == 1)
        DereferenceObjectSafe((__int64)ProcessObject);

    return 1;
}

// MiniFilterOpLockPost — Oplock 后处理回调
// 对应原始驱动 sub_14001A5AC
char MiniFilterOpLockPost(PRKPROCESS ProcessObject, char IsQwordKey, __int64 Context)
{
    ULONG OplockOffset;
    _QWORD *OplockField, *OplockHead;
    char ResolveResult, IsReferenced;
    ULONG64 OplockOffsetVal;
    _QWORD ResolvedHead[2];
    KAPC_STATE ApcState;

    OplockOffset = IsQwordKey ? 2064 : 43;
    OplockOffsetVal = GtRead(OplockOffset);
    if (OplockOffsetVal == -1)
        return 0;

    OplockField = (_QWORD *)((char *)ProcessObject + OplockOffsetVal);
    if (MmIsAddressValid(OplockField) != 1)
        return 0;

    OplockHead = (_QWORD *)*OplockField;
    ResolvedHead[0] = *OplockField;

    if (IsQwordKey)
    {
        ResolveResult = ResolvePointerSafe(OplockHead, ResolvedHead);
        OplockHead = (_QWORD *)ResolvedHead[0];
        if (!ResolveResult)
            OplockHead = NULL;
        ResolvedHead[0] = (__int64)OplockHead;
    }

    if (!OplockHead || ValidateProcessObject(ProcessObject, NULL) != 1)
        return 0;

    IsReferenced = ReferenceObjectSafe((__int64)ProcessObject);
    KeStackAttachProcess(ProcessObject, &ApcState);

    if (IsQwordKey)
    {
        if (ResolvedHead[0] < MmUserProbeAddress && ResolvedHead[0] + 48 < MmUserProbeAddress)
        {
            ULONG *DwordKeyArray = (ULONG *)(ULONG_PTR)*(ULONG *)(ResolvedHead[0] + 12);
            if ((ULONG64)DwordKeyArray < MmUserProbeAddress && (ULONG64)(DwordKeyArray + 10) < MmUserProbeAddress)
            {
                RemoveOplockNodeByDwordKey(DwordKeyArray + 3, 0, Context);
                RemoveOplockNodeByDwordKey(DwordKeyArray + 5, 8, Context);
                RemoveOplockNodeByDwordKey(DwordKeyArray + 7, 0x10, Context);
            }
        }
    }
    else
    {
        if (ResolvedHead[0] < MmUserProbeAddress && ResolvedHead[0] + 96 < MmUserProbeAddress)
        {
            const ULONG64 **QwordKeyArray = *(const ULONG64 ***)(ResolvedHead[0] + 24);
            if ((ULONG64)QwordKeyArray < MmUserProbeAddress && (ULONG64)(QwordKeyArray + 9) < MmUserProbeAddress)
            {
                RemoveOplockNodeByQwordKey(QwordKeyArray + 2, 0, Context);
                RemoveOplockNodeByQwordKey(QwordKeyArray + 4, 0x10, Context);
                RemoveOplockNodeByQwordKey(QwordKeyArray + 6, 0x20, Context);
            }
        }
    }

    KeUnstackDetachProcess(&ApcState);
    if (IsReferenced == 1)
        DereferenceObjectSafe((__int64)ProcessObject);

    return 1;
}

// RemoveOplockNodeByDwordKey — 通过 DWORD 键移除 Oplock 节点
// 对应原始驱动 sub_14001A798
// 遍历双向链表查找匹配 Context 键值的条目，从链表中摘除并重新连接前后指针
ULONG64 RemoveOplockNodeByDwordKey(unsigned int *KeyArray, ULONG Offset, __int64 Context)
{
    unsigned int *CurrentEntry;
    unsigned int LoopCount;
    ULONG64 EntryBase;
    ULONG64 NextEntry;
    ULONG64 PrevEntry;

    CurrentEntry = (unsigned int *)(ULONG_PTR)*KeyArray;
    for (LoopCount = 0; ; LoopCount++)
    {
        if (CurrentEntry == KeyArray)
            break;
        if (LoopCount > 0x1000)
            break;
        EntryBase = (ULONG64)CurrentEntry - Offset;
        if (EntryBase >= MmUserProbeAddress)
            break;
        if (EntryBase + 72 >= MmUserProbeAddress)
            break;
        if (Context == *(unsigned int *)(EntryBase + 24))
        {
            NextEntry = *CurrentEntry;
            if (NextEntry < MmUserProbeAddress)
            {
                if (NextEntry + 8 < MmUserProbeAddress)
                {
                    PrevEntry = CurrentEntry[1];
                    if (PrevEntry < MmUserProbeAddress)
                    {
                        if (PrevEntry + 8 < MmUserProbeAddress)
                        {
                            *(_DWORD *)((ULONG_PTR)*CurrentEntry + 4) = (unsigned int)PrevEntry;
                            *(_DWORD *)(ULONG_PTR)CurrentEntry[1] = (unsigned int)*CurrentEntry;
                        }
                    }
                }
            }
            return NextEntry;
        }
        CurrentEntry = (unsigned int *)(ULONG_PTR)*CurrentEntry;
    }
    return (ULONG64)CurrentEntry;
}

// EnumProcessThreadInfo — 枚举进程线程信息
// 对应原始驱动 sub_14004D2AC
// 根据 a2 选择内核态(0)或用户态(1)线程列表
char EnumProcessThreadInfo(PRKPROCESS PROCESS, char IsUserMode, int *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    GLOBAL_TABLE_INDEX OffsetIndex;
    ULONG Offset;
    ULONG64 *pListHead;
    _QWORD *pListEntry;
    ULONG64 ListEntrySafe;
    char ResolveOk;
    _DWORD *TempBuffer;
    int SavedCount;
    UCHAR IsReferenced;
    ULONG64 EntrySize, ThreadListBase;
    ULONG TempRemainingSize, ThreadListOffset;
    unsigned int *ThreadListArray;
    char UserModeFlag;
    KAPC_STATE ApcState;

    OffsetIndex = IsUserMode ? GtEprocessModuleListOffset : GtEprocessField33;
    Offset = (ULONG)GtRead(OffsetIndex);
    if (Offset == (ULONG)-1) return Result;

    pListHead = (ULONG64 *)((char *)PROCESS + Offset);
    if (MmIsAddressValid(pListHead) != 1) return Result;

    pListEntry = (_QWORD *)*pListHead;
    ListEntrySafe = *pListHead;

    if (IsUserMode)
    {
        ResolveOk = ResolvePointerSafe(pListEntry, &ListEntrySafe);
        pListEntry = (_QWORD *)ListEntrySafe;
        if (!ResolveOk) pListEntry = NULL;
        ListEntrySafe = (ULONG64)pListEntry;
    }

    if (!pListEntry) return Result;

    TempBuffer = ExAlloc(PagedPool, BufferSize);
    if (!TempBuffer) return Result;

    SavedCount = *OutputBuffer;
    if (SavedCount)
        memmove(TempBuffer, OutputBuffer, (ULONG)(544 * (SavedCount - 1) + 552));
    *TempBuffer = SavedCount;

    if (ValidateProcessObject(PROCESS, NULL) != 1) goto Cleanup;
    IsReferenced = ReferenceObjectSafe((__int64)PROCESS);
    KeStackAttachProcess(PROCESS, &ApcState);

    if (IsUserMode)
    {
        if (ListEntrySafe < MmUserProbeAddress && ListEntrySafe + 48 < MmUserProbeAddress)
        {
            ThreadListBase = *(unsigned int *)(ListEntrySafe + 12);
            if (ThreadListBase < MmUserProbeAddress && ThreadListBase + 40 < MmUserProbeAddress)
            {
                TempRemainingSize = BufferSize;
                EnumerateThreadListEntries((unsigned int *)(ThreadListBase + 12), 0, 1, TempBuffer, BufferSize, 0);
                EnumerateThreadListEntries((unsigned int *)(ThreadListBase + 20), 8, 1, TempBuffer, TempRemainingSize, 0);
                ThreadListArray = (unsigned int *)(ThreadListBase + 28);
                UserModeFlag = 1;
                ThreadListOffset = 16;
                goto Enumerate;
            }
        }
    }
    else if (ListEntrySafe < MmUserProbeAddress && ListEntrySafe + 96 < MmUserProbeAddress)
    {
        EntrySize = *(_QWORD *)(ListEntrySafe + 24);
        if (EntrySize < MmUserProbeAddress && EntrySize + 72 < MmUserProbeAddress)
        {
            TempRemainingSize = BufferSize;
            EnumerateThreadListEntries((unsigned int *)(EntrySize + 16), 0, 0, TempBuffer, BufferSize, 0);
            EnumerateThreadListEntries((unsigned int *)(EntrySize + 32), 0x10, 0, TempBuffer, TempRemainingSize, 0);
            ThreadListArray = (unsigned int *)(EntrySize + 48);
            UserModeFlag = 0;
            ThreadListOffset = 32;
Enumerate:
            EnumerateThreadListEntries(ThreadListArray, ThreadListOffset, UserModeFlag, TempBuffer, TempRemainingSize, 0);
            TempRemainingSize = 1;
        }
    }

    KeUnstackDetachProcess(&ApcState);
    if (IsReferenced == 1) DereferenceObjectSafe((__int64)PROCESS);

Cleanup:
    if (*TempBuffer)
        memmove(OutputBuffer, TempBuffer, (ULONG)(544 * (*TempBuffer - 1) + 552));
    ExFree(TempBuffer);
    return Result;
}

// EnumerateThreadsInProcess — 枚举进程中的线程
// 对应原始驱动 sub_14004D094
// 附加到目标进程，从系统根目录地址读取线程列表
char EnumerateThreadsInProcess(ULONG64 BaseAddr, struct _KPROCESS *Process, char Use8ByteStep, int *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    _DWORD *TempBuffer;
    int SavedCount;
    UCHAR IsReferenced;
    ULONG j;
    __int64 i;
    KAPC_STATE ApcState;

    if (BaseAddr <= 0x1000 || BaseAddr >= MmUserProbeAddress) return Result;

    TempBuffer = ExAlloc(PagedPool, BufferSize);
    if (!TempBuffer) return Result;

    SavedCount = *OutputBuffer;
    if (SavedCount)
        memmove(TempBuffer, OutputBuffer, (ULONG)(544 * (SavedCount - 1) + 552));
    *TempBuffer = SavedCount;

    if (ValidateProcessObject(Process, NULL) == 1)
    {
        IsReferenced = ReferenceObjectSafe((__int64)Process);
        KeStackAttachProcess(Process, &ApcState);

        if (Use8ByteStep)
        {
            if (BaseAddr < MmUserProbeAddress && BaseAddr + 256 < MmUserProbeAddress)
            {
                for (i = 0; (ULONG)i < 0x20; i++)
                {
                    EnumerateThreadListEntries((unsigned int *)(BaseAddr + 8 * i), 0x3C, 1, TempBuffer, BufferSize, 1);
                    Result = 1;
                }
            }
        }
        else if (BaseAddr < MmUserProbeAddress && BaseAddr + 512 < MmUserProbeAddress)
        {
            for (j = 0; j < 0x20; j++)
            {
                EnumerateThreadListEntries((unsigned int *)(BaseAddr + 16 * j), 0x70, 0, TempBuffer, BufferSize, 1);
                Result = 1;
            }
        }

        KeUnstackDetachProcess(&ApcState);
        if (IsReferenced == 1) DereferenceObjectSafe((__int64)Process);
    }

    if (*TempBuffer)
        memmove(OutputBuffer, TempBuffer, (ULONG)(544 * (*TempBuffer - 1) + 552));
    ExFree(TempBuffer);

    return Result;
}

// CmdEnumThreads — 枚举线程命令处理函数
// 对应原始驱动 sub_14004B764
__int64 CmdEnumThreads(char **InputBuffer, int InputSize, _DWORD *OutputBuffer, int OutputSize)
{
    ULONG BuildNumber = (ULONG)GtRead(GtWindowsBuildNumber);
    char RetVal = 0;
    char *ProcessId;
    char Success;
    __int64 (*GetProcessNameFunc)(PEPROCESS);
    __int64 StartAddr;
    PEPROCESS Process;
    void *ImagePath;
    int ThreadIndex;
    WORD Result[8];

    if (InputSize != 8 || OutputSize != 520) return -1;

    ProbeForRead(InputBuffer, 8, 4);
    ProbeForWrite(OutputBuffer, 0x208, 1);
    ProcessId = *InputBuffer;
    memset(OutputBuffer, 0, 0x208);

    if (GetProcessImagePath(0, ProcessId, &ImagePath, &ThreadIndex, 0) == 1)
    {
        WStringCopyN((WORD *)OutputBuffer, (__int64)ImagePath, 0x104);
        *((WORD *)OutputBuffer + 259) = 0;
        ExFree(ImagePath);
        return 1;
    }

    Success = 0;
    if (BuildNumber >= 0x3839)
    {
        GetProcessNameFunc = (__int64 (*)(PEPROCESS))GtRead(16777);
        if (GetProcessNameFunc)
        {
            if (PsLookupProcessByProcessId(ProcessId, &Process) >= 0)
            {
                strcpy((char *)Result, "MemCompression");
                StartAddr = GetProcessNameFunc(Process);
                if (StringCompareCaseInsensitiveV2(StartAddr, (__int64)Result))
                {
                    if (BuildNumber >= 0x42EE)
                    {
                        strcpy((char *)Result, "Registry");
                        if (StringCompareCaseInsensitiveV2(StartAddr, (__int64)Result))
                            goto Cleanup;
                        OutputBuffer[0] = 6619218;
                        OutputBuffer[1] = 6881383;
                        OutputBuffer[2] = 7602291;
                        *(__int64 *)(OutputBuffer + 3) = 7929970;
                    }
                }
                else
                {
                    OutputBuffer[0] = 6619213;
                    OutputBuffer[1] = 4391021;
                    OutputBuffer[2] = 7143535;
                    OutputBuffer[3] = 7471216;
                    OutputBuffer[4] = 7536741;
                    OutputBuffer[5] = 6881395;
                    *((__int64 *)OutputBuffer + 3) = 7209071;
                }
                Success = 1;
                RetVal = 1;
Cleanup:
                ObfDereferenceObject(Process);
            }
        }
    }

    if (!Success && (ULONG64)(ProcessId - 1) <= 7)
    {
        OutputBuffer[0] = 7929939;
        OutputBuffer[1] = 7602291;
        *((__int64 *)OutputBuffer + 1) = 7143525;
        return 1;
    }

    return RetVal;
}

// DecryptAndCompareStrings — 解密并比较 VAD 文件名
// 对应原始驱动 sub_14004D9AC
// 对 System32 目录下的模块进行白名单过滤，匹配的从枚举结果中移除
void DecryptAndCompareStrings(__int64 Process, unsigned int *OutputBuffer, unsigned int StartIndex)
{
    ULONG Index = StartIndex;
    int EntryCount = *OutputBuffer;
    if (EntryCount <= (int)StartIndex) return;

    unsigned int *EntryPtr = OutputBuffer + 2;
    int ProcessType = (int)MatchSystemProcessName((_QWORD *)Process);
    if (!ProcessType) return;

    // 编码的白名单文件名数组（每 DWORD 编码 2 个宽字符，小端）
    _DWORD v47[7]    = {6881399, 7077998, 6750319, 7209071, 6619182, 6619256, 0}; // "winlogon.exe"
    _DWORD v43[9]    = {6422647, 7143525, 5701724, 7209065, 6750285, 7602285, 3014738, 7077988, 108}; // "wbem\\WinMgmtR.dll"
    _DWORD v27[6]    = {7405684, 6619253, 7929970, 6553646, 7077996, 0}; // "tquery.dll"
    _DWORD v45[6]    = {7471216, 6684783, 7733363, 3014755, 7077988, 108}; // "profsvc.dll"
    _DWORD v46[6]    = {6619255, 7602294, 7340129, 3014761, 7077988, 108}; // "wevtapi.dll"
    _DWORD v29[6]    = {6881399, 6815854, 7602292, 3014768, 7077988, 108}; // "winhttp.dll"
    _DWORD v28[6]    = {6619241, 7471206, 7143521, 3014757, 7077988, 108}; // "ieframe.dll"
    _DWORD v38[7]    = {7143529, 6750305, 7471205, 7536741, 6553646, 7077996, 0}; // "imageres.dll"
    _DWORD v42[9]    = {7471204, 7733353, 7471205, 6029427, 7667820, 6684769, 3014771, 7929971, 115}; // "drivers\\luafs.sys"
    wchar_t Str1[20] = L"drivers\\fltmgr.sys";
    _DWORD v37[7]    = {6553697, 7536756, 6815843, 7143525, 3014753, 7077988, 108}; // "adtschema.dll"
    _DWORD v18[4]    = {6881379, 6553646, 7077996, 0}; // "ci.dll"
    _DWORD v39[7]    = {6488179, 6619240, 7536740, 6488182, 6553646, 7077996, 0}; // "schedsvc.dll"
    _DWORD v32[7]    = {6619251, 7733362, 6488169, 7536741, 6619182, 6619256, 0}; // "services.exe"
    _DWORD v24[4]    = {7667831, 7667809, 7209061, 3014759}; // "wuaueng."
    _DWORD v26[6]    = {6881399, 7536750, 7602273, 6619182, 6619256, 0}; // "winsat.exe"
    wchar_t v19[12]  = L"pshed.dll";
    wchar_t v20[12]  = L"qmgr.dll";
    _DWORD v22[4]    = {6422644, 7536755, 6488182, 6553646}; // "tbssvc.d"
    wchar_t v21[12]  = L"gpsvc.dll";
    _DWORD v30[4]    = {6881380, 7536749, 7274602, 3014754}; // "dimsjob."
    _DWORD v40[5]    = {6619251, 7667828, 6357104, 6881392, 6553646}; // "setupapi.d"
    _DWORD v35[5]    = {6357106, 6357091, 6619239, 7602286, 6619182}; // "racagent.e"
    _DWORD v33[5]    = {7340140, 7536747, 7602277, 7340149, 6619182}; // "lpksetup.e"

    WORD *pStr1 = BuildSystem32Path();
    if (!pStr1) return;

    ULONG PathLen = (ULONG)GetStringLength(pStr1);

    while (Index < *OutputBuffer)
    {
        WORD *Dst = (WORD *)&EntryPtr[136 * Index];
        if (StringCompare3Way((__int64)pStr1, Dst + 16, PathLen) == 0)
        {
            __int64 Offset = 136 * Index;
            if (*((WORD *)&OutputBuffer[Offset + 8] + PathLen) == L'\\')
            {
                const wchar_t *FileName = (const wchar_t *)&OutputBuffer[Offset + 8] + PathLen + 1;

                // 按进程类型匹配白名单
                if (ProcessType == 1)
                {
                    // 任一白名单名匹配则移除；若全部不匹配，仅当 v33 匹配 "lpksetup.e" 时才移除
                    if (WStringCompareCaseInsensitive((__int64)v47, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v43, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v27, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v45, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v46, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v42, (__int64)FileName) &&
                        _wcsicmp(Str1, FileName) &&
                        WStringCompareCaseInsensitive((__int64)v37, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v18, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v39, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v32, (__int64)FileName) &&
                        WStringCompareCaseInsensitive((__int64)v24, (__int64)FileName) &&
                        _wcsicmp((const wchar_t *)v26, FileName) &&
                        _wcsicmp(v19, FileName) &&
                        _wcsicmp(v20, FileName) &&
                        _wcsicmp((const wchar_t *)v22, FileName) &&
                        _wcsicmp(v21, FileName) &&
                        _wcsicmp((const wchar_t *)v30, FileName) &&
                        _wcsicmp((const wchar_t *)v40, FileName) &&
                        _wcsicmp((const wchar_t *)v35, FileName))
                    {
                        // 全部不匹配：仅当 v33 也匹配时移除，否则保留
                        if (_wcsicmp((const wchar_t *)v33, FileName))
                            goto NotWhitelisted;
                    }
                    /* 任一匹配则继续移除 */
                }
                else if (ProcessType == 2)
                {
                    if (WStringCompareCaseInsensitive((__int64)v29, (__int64)FileName))
                        goto NotWhitelisted;
                }
                else if (ProcessType == 3)
                {
                    if (WStringCompareCaseInsensitive((__int64)v28, (__int64)FileName))
                        goto NotWhitelisted;
                }
                else if (ProcessType == 4)
                {
                    if (WStringCompareCaseInsensitive((__int64)v38, (__int64)FileName))
                        goto NotWhitelisted;
                }
                else
                    goto NotWhitelisted;

                // 匹配白名单，从枚举结果中移除该条目
                (*OutputBuffer)--;
                if (Index != (ULONG)(EntryCount - 1))
                {
                    __int64 NextOffset = 136 * (Index + 1);
                    memmove(Dst, &OutputBuffer[NextOffset], 544 * (EntryCount - Index - 1));
                }
                Index--;
            }
        }
    NotWhitelisted:
        Index++;
    }

    ExFree(pStr1);
}

// CleanupProcessThreads — 清理进程线程 VAD 枚举
// 对应原始驱动 sub_14004D554
// 根据构建号选择不同版本的 VAD 枚举函数，遍历 VadRoot
char CleanupProcessThreads(struct _KPROCESS *Process, unsigned int *OutputBuffer, unsigned int BufferSize)
{
    char Result = 0;
    ULONG VadOffset;
    _QWORD **ThreadCount;
    UCHAR EntryIndex;
    ULONG pThread;

    VadOffset = (ULONG)GtRead(GtEprocessField49);
    if (!VadOffset) return Result;

    ThreadCount = (_QWORD **)((char *)Process + VadOffset);
    if (MmIsAddressValid(ThreadCount) != 1) return Result;

    EntryIndex = 0;
    if (ValidateProcessObject(Process, NULL) == 1)
        EntryIndex = ReferenceObjectSafe((__int64)Process);

    ULONG BuildNum = (ULONG)GtRead(GtWindowsBuildNumber);
    if (BuildNum > 0xA28)
    {
        if (BuildNum == 3790)
        {
            EnumerateVadWithBufferV1(ThreadCount[1], OutputBuffer, BufferSize);
            EnumerateVadWithBufferV1(ThreadCount[2], OutputBuffer, BufferSize);
        }
        else if ((BuildNum >= 0x1770 && BuildNum <= 0x1772) || BuildNum == 7600 || BuildNum == 7601)
        {
            pThread = *OutputBuffer;
            EnumerateVadWithBufferV2(ThreadCount[1], OutputBuffer, BufferSize);
            EnumerateVadWithBufferV2(ThreadCount[2], OutputBuffer, BufferSize);
            DecryptAndCompareStrings((__int64)Process, OutputBuffer, pThread);
        }
        else if (BuildNum == 9200)
        {
            EnumerateVadWithBufferV3(ThreadCount[1], OutputBuffer, BufferSize);
            EnumerateVadWithBufferV3(ThreadCount[2], OutputBuffer, BufferSize);
        }
        else if (BuildNum >= 0x2580)
        {
            EnumerateVadWithBufferV4(*ThreadCount, OutputBuffer, BufferSize);
            EnumerateVadWithBufferV4(ThreadCount[1], OutputBuffer, BufferSize);
        }
    }
    else
        CleanupThreadWithBuffer(*ThreadCount, OutputBuffer, BufferSize);

    Result = 1;
    if (EntryIndex == 1)
        DereferenceObjectSafe((__int64)Process);

    return Result;
}

// CmdEnumThreadsEx — 扩展枚举线程命令处理
// 对应原始驱动 sub_14004CE68
// 从 32 字节输入缓冲区解析进程ID/进程对象/系统根目录/保护偏移
__int64 CmdEnumThreadsEx(void **Address, int InputSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    void *ThreadId;
    struct _KPROCESS *Teb, *ThreadCount;
    void *StartAddr, *ProcessId;
    NTSTATUS Result;
    __int64 SystemRootEntry;
    ULONG64 ThreadEntry;
    PEPROCESS Process;

    Process = NULL;
    if (InputSize != 32 || !Address ||
        (ULONG64)Address >= MmUserProbeAddress ||
        (ULONG64)(Address + 4) >= MmUserProbeAddress ||
        BufferSize <= 0x228 || !OutputBuffer ||
        (ULONG64)OutputBuffer >= MmUserProbeAddress ||
        (ULONG64)OutputBuffer + BufferSize >= MmUserProbeAddress)
        return Result;

    ProbeForRead(Address, 0x20, 4);
    ProbeForWrite(OutputBuffer, BufferSize, 1);
    memset(OutputBuffer, 0, BufferSize);
    *OutputBuffer = 0;

    ThreadId = *Address;
    Teb = (struct _KPROCESS *)Address[1];
    StartAddr = Address[2];
    ProcessId = Address[3];

    Result = PsLookupProcessByProcessId(ThreadId, &Process);
    ThreadCount = (struct _KPROCESS *)Process;
    if (Result < 0) ThreadCount = NULL;
    Process = (PEPROCESS)ThreadCount;
    if (!Teb) { if (Result >= 0) Teb = ThreadCount; }

    if (ValidateProcessObject(Teb, NULL) == 1)
    {
        EnumProcessThreadInfo(Teb, 1, OutputBuffer, BufferSize);
        EnumProcessThreadInfo(Teb, 0, OutputBuffer, BufferSize);
        EnumerateThreadsInProcess((ULONG64)StartAddr, Teb, 0, OutputBuffer, BufferSize);

        if (ProcessId && CheckProtectedEntry((__int64)Teb) == 1)
        {
            SystemRootEntry = FindSystemRootEntry(OutputBuffer);
            if (SystemRootEntry)
            {
                ThreadEntry = (ULONG64)ProcessId + SystemRootEntry;
                GtWrite(0x810 | 1, ThreadEntry);
                EnumerateThreadsInProcess(ThreadEntry, Teb, 1, OutputBuffer, BufferSize);
            }
        }
        CleanupProcessThreads(Teb, OutputBuffer, BufferSize);
        ResetThreadStateIfMatch((__int64)Teb, (__int64)OutputBuffer);
        ResetThreadStateFlag((__int64)Teb, (__int64)OutputBuffer);
    }

    if (Result >= 0) { ObfDereferenceObject(Process); Process = NULL; }
    return *OutputBuffer != 0;
}

// NormalizeRelativePath — 规范化相对路径
// 对应原始驱动 sub_14004D8A8
// 将以 \ 开头的相对路径拼接系统根目录路径转换为绝对路径
void NormalizeRelativePath(WORD *Path)
{
    WORD *inited;
    WORD *SuffixBuffer;
    WORD *Char;
    int StringLen;

    if (*Path == L'\\' && Path[1] && Path[1] != L'\\')
    {
        inited = InitSystemPath();
        if (!inited) return;

        SuffixBuffer = ExAlloc(PagedPool, 0x400);
        if (SuffixBuffer)
        {
            Char = WStringFindChar(Path + 1, L'\\');
            if (Char)
            {
                WStringCopyN(SuffixBuffer, (__int64)Char, 0x100);
                SuffixBuffer[255] = 0;
                WStringCopyN(Path, (__int64)inited, 0x100);
                Path[255] = 0;
                if (GetStringLength(Path) < 0xFF)
                {
                    StringLen = (int)GetStringLength(Path);
                    WStringConcat(Path, SuffixBuffer, 255 - StringLen);
                    Path[255] = 0;
                }
            }
            ExFree(SuffixBuffer);
        }
        ExFree(inited);
    }
}

// RemoveOplockNodeByQwordKey — 通过 QWORD 键移除 Oplock 节点
// 对应原始驱动 sub_14001A82C
// 遍历双向链表查找匹配 Context 键值的条目，从链表中摘除并重新连接前后指针
const ULONG64 *RemoveOplockNodeByQwordKey(const ULONG64 **KeyArray, ULONG Offset, __int64 Context)
{
    const ULONG64 *CurrentEntry;
    unsigned int LoopCount;
    ULONG64 EntryBase;
    const ULONG64 *NextEntry;
    ULONG64 PrevEntry;

    CurrentEntry = *KeyArray;
    for (LoopCount = 0; ; LoopCount++)
    {
        if (CurrentEntry == (const ULONG64 *)KeyArray)
            break;
        if (LoopCount > 0x1000)
            break;
        EntryBase = (ULONG64)CurrentEntry - Offset;
        if (EntryBase >= MmUserProbeAddress)
            break;
        if (EntryBase + 136 >= MmUserProbeAddress)
            break;
        if (Context == *(_QWORD *)(EntryBase + 48))
        {
            NextEntry = (const ULONG64 *)*CurrentEntry;
            if (*CurrentEntry < MmUserProbeAddress)
            {
                if ((unsigned __int64)(NextEntry + 2) < MmUserProbeAddress)
                {
                    PrevEntry = CurrentEntry[1];
                    if (PrevEntry < MmUserProbeAddress)
                    {
                        if (PrevEntry + 16 < MmUserProbeAddress)
                        {
                            *((_QWORD *)NextEntry + 1) = PrevEntry;
                            **((_QWORD **)CurrentEntry + 1) = *CurrentEntry;
                        }
                    }
                }
            }
            return NextEntry;
        }
        CurrentEntry = (const ULONG64 *)*CurrentEntry;
    }
    return CurrentEntry;
}

// FindThreadEntry — 查找线程条目是否已存在
// 对应原始驱动 sub_14004D714
// 遍历输出缓冲区中的线程条目，用于去重
char FindThreadEntry(_DWORD *OutputBuffer, __int64 Target, unsigned int *OutIndex, __int64 ExtraParam)
{
    ULONG EntryCount = *OutputBuffer;
    char Result = 1;
    ULONG Index;

    if (ExtraParam && EntryCount)
    {
        _QWORD *Entry = (_QWORD *)(OutputBuffer + 8);
        for (Index = 0; Index < EntryCount; Index++)
        {
            if (ExtraParam == *Entry)
            {
                if (OutIndex) *OutIndex = Index;
                return 0;
            }
            Entry += 68;
        }
    }

    for (Index = 0; Index < EntryCount; Index++)
    {
        if (Target == *(_QWORD *)(OutputBuffer + 4 + 68 * Index))
        {
            if (OutIndex) *OutIndex = Index;
            return 0;
        }
    }
    return Result;
}

// ResetThreadStateIfMatch — 匹配时重置线程状态
// 对应原始驱动 sub_14004CC0C（63 字节）
// 检查 CSRSS 进程对象是否匹配，若匹配且线程状态为 2 则重置线程状态和扩展状态
_QWORD *ResetThreadStateIfMatch(__int64 Process, __int64 OutputBuffer)
{
    _QWORD *result;

    result = (_QWORD *)GtRead(GtObjectTypeInfoPtr);
    if (result && *result == Process && *(_DWORD *)OutputBuffer == 2)
    {
        *(_BYTE *)(OutputBuffer + 8) = 0;
        *(_BYTE *)(OutputBuffer + 552) = 0;
    }
    return result;
}


// EnumerateThreadListEntries — 枚举线程列表条目
// 对应原始驱动 sub_14004E328（1010 字节）
// 遍历双向链表，从每个条目中提取线程信息。填充 544 字节每项的线程条目到输出缓冲区
ULONG64 EnumerateThreadListEntries(
    unsigned int *ListHead,
    unsigned int ListFieldOffset,
    char IsUserMode,
    unsigned int *OutputBuffer,
    unsigned int OutputSize,
    char EntryTypeValue)
{
    unsigned int pListHead;
    unsigned int *pCurrent;
    ULONG64 ResultCount;
    unsigned int ThreadEntry;
    unsigned int *ThreadId;
    __int64 ThreadIdValue;
    ULONG64 Field13;
    _OWORD Field14;
    __int64 Field15;
    _OWORD Fields32b;
    _OWORD Fields48b;
    _OWORD Fields64b;
    _OWORD Fields80;
    _OWORD Fields96;
    _OWORD Fields112;
    ULONG64 PathPtr;
    unsigned __int16 PathLength;
    unsigned int ThreadFlags;
    unsigned int ClampedLength;
    __int64 CurrentEntryOffset;
    unsigned int StringLength;
    const void *SrcPtr;
    unsigned int *DstEntry;
    __int64 ExistingEntryOffset;
    __int64 ExistingEntryBytes;
    __int64 ExistingEntryBytes2;
    __int64 ThreadFlagsVal;
    char IsUserModeLocal;
    unsigned int EntrySize;
    unsigned int ExistingEntryIndex;
    __int64 ExistingEntryBytes3;
    unsigned int *ListHeadLocal;
    unsigned int LoopCount;
    unsigned int EntryOffsetLocal;
    _OWORD Fields0;
    _OWORD Fields16;
    _OWORD Fields32;
    _OWORD Fields48;
    _OWORD Fields64;
    _OWORD Src;
    _OWORD Fields96b;
    _OWORD Fields112b;
    __int64 Fields128;
    int EncodedPrefix;
    __int64 EncodedPrefix2;

    IsUserModeLocal = IsUserMode;
    pListHead = *OutputBuffer;
    EntryOffsetLocal = ListFieldOffset;
    pCurrent = ListHead;
    ListHeadLocal = ListHead;
    ResultCount = 0;
    EncodedPrefix = 4128860;          // L"\\??\\"
    ThreadEntry = 544 * pListHead + 552;
    EncodedPrefix2 = 6029375;          // L"\\??\\" 续

    if (IsUserMode)
    {
        ThreadId = (unsigned int *)(ULONG_PTR)*ListHead;  // LIST_ENTRY Flink (72字节条目)
        EntrySize = 72;
    }
    else
    {
        ThreadId = *(unsigned int **)ListHead; // 136字节条目
        EntrySize = 136;
    }

    if (ThreadId != ListHead)
    {
        do
        {
            ResultCount = (unsigned int)(ResultCount + 1);
            LoopCount = (unsigned int)ResultCount;
            if ((unsigned int)ResultCount > 0x1000)
                break;

            Field13 = (ULONG64)ThreadId - ListFieldOffset;
            ResultCount = MmUserProbeAddress;
            if (Field13 >= MmUserProbeAddress)
                break;

            ResultCount = Field13 + EntrySize;
            if (ResultCount >= MmUserProbeAddress || ThreadEntry >= OutputSize)
                break;

            if (IsUserMode)
            {
                // 72字节 LIST_ENTRY 格式
                ThreadIdValue = *(unsigned int *)(Field13 + 24);
                ThreadFlags = *(_DWORD *)(Field13 + 32);
                PathLength = *(_WORD *)(Field13 + 36);
                PathPtr = *(unsigned int *)(Field13 + 40);
                Fields48.qword[0] = ThreadIdValue;
                Fields64.dword[0] = ThreadFlags;
                Fields64.word[4] = PathLength;
                Src.qword[0] = PathPtr;
            }
            else
            {
                // 136字节格式
                Field14 = *(_OWORD *)(Field13 + 16);
                Field15 = *(_QWORD *)(Field13 + 128);
                Fields0 = *(_OWORD *)Field13;
                Fields32b = *(_OWORD *)(Field13 + 32);
                Fields16 = Field14;
                Fields48b = *(_OWORD *)(Field13 + 48);
                Fields32 = Fields32b;
                Fields64b = *(_OWORD *)(Field13 + 64);
                Fields48 = Fields48b;
                Fields80 = *(_OWORD *)(Field13 + 80);
                Fields64 = Fields64b;
                Fields96 = *(_OWORD *)(Field13 + 96);
                Src = Fields80;
                Fields112 = *(_OWORD *)(Field13 + 112);
                Fields96b = Fields96;
                Fields112b = Fields112;
                Fields128 = Field15;
                PathPtr = (unsigned int)Src.dword[0];
                PathLength = Fields64.word[4];
                ThreadIdValue = Fields48.dword[0];
                ThreadFlags = Fields64.dword[0];
            }

            if (ThreadIdValue)
            {
                ClampedLength = PathLength;
                CurrentEntryOffset = 136LL * pListHead;
                if (PathLength > 0x1FEu)
                    ClampedLength = 510;

                *(_QWORD *)&OutputBuffer[CurrentEntryOffset + 4] = ThreadIdValue;

                if (ClampedLength > 2 && PathPtr < MmUserProbeAddress && PathPtr && PathPtr + ClampedLength < MmUserProbeAddress)
                {
                    *(_QWORD *)&OutputBuffer[CurrentEntryOffset + 8] = 0;
                    *((UCHAR *)OutputBuffer + CurrentEntryOffset + 2) = EntryTypeValue;
                    *(_QWORD *)&OutputBuffer[CurrentEntryOffset + 6] = ThreadFlags;
                    StringLength = (unsigned int)GetStringLength((PWSTR)&EncodedPrefix);
                    ExistingEntryBytes3 = StringLength;

                    if (ClampedLength <= StringLength || (unsigned int)WStringCompare((__int64)&EncodedPrefix, (unsigned __int16 *)PathPtr, StringLength))
                    {
                        SrcPtr = (const void *)PathPtr;
                    }
                    else
                    {
                        SrcPtr = (const void *)(PathPtr + 2LL * (unsigned int)ExistingEntryBytes3);
                        ClampedLength -= (unsigned int)(2 * ExistingEntryBytes3);
                    }
                    DstEntry = &OutputBuffer[CurrentEntryOffset + 10];
                    memmove(DstEntry, SrcPtr, ClampedLength);
                    *((_WORD *)&OutputBuffer[136 * pListHead + 10] + ((unsigned __int64)ClampedLength >> 1)) = 0;
                    *(WORD *)((UCHAR *)OutputBuffer + CurrentEntryOffset + 138) = 0;
                    NormalizeRelativePath((WORD *)DstEntry);

                    if (IsUserModeLocal == 1)
                        PatchThreadImagePathWithWow64((__int64)&OutputBuffer[CurrentEntryOffset + 10]);

                    if (FindThreadEntry(OutputBuffer, Fields48.qword[0], &ExistingEntryIndex, 0) == 1)
                    {
                        ThreadEntry += 544;
                        *OutputBuffer = ++pListHead;
                    }
                    else
                    {
                        ExistingEntryOffset = 136LL * ExistingEntryIndex;
                        ExistingEntryBytes3 = ExistingEntryOffset * 4;
                        *(WORD *)((UCHAR *)OutputBuffer + ExistingEntryOffset + 138) = 0;
                        *(WORD *)((UCHAR *)OutputBuffer + CurrentEntryOffset + 138) = 0;

                        if ((2LL * (unsigned int)GetStringLength((PWSTR)&OutputBuffer[ExistingEntryOffset + 10]) != ClampedLength
                            || (unsigned int)StringCompare3Way((__int64)OutputBuffer + ExistingEntryBytes3 + 40, (unsigned __int16 *)DstEntry, ClampedLength >> 1))
                            && ClampedLength > 2 * (unsigned __int64)(unsigned int)GetStringLength((PWSTR)((char *)OutputBuffer + ExistingEntryBytes3 + 40)))
                        {
                            ExistingEntryBytes = ExistingEntryBytes3;
                            *((_BYTE *)OutputBuffer + ExistingEntryBytes3 + 8) = EntryTypeValue;
                            if (ClampedLength > 0x1FE)
                                ClampedLength = 510;
                            memmove((char *)OutputBuffer + ExistingEntryBytes + 40, DstEntry, ClampedLength);
                            ExistingEntryBytes2 = ExistingEntryBytes3;
                            *((_WORD *)&OutputBuffer[136 * ExistingEntryIndex + 10] + ((unsigned __int64)ClampedLength >> 1)) = 0;
                            *(_WORD *)((char *)OutputBuffer + ExistingEntryBytes2 + 550) = 0;
                        }
                    }
                    pCurrent = ListHeadLocal;
                }
                else
                {
                    ThreadEntry = FindThreadEntry(OutputBuffer, ThreadIdValue, &ExistingEntryIndex, 0);
                    pCurrent = ListHeadLocal;
                    if (ThreadEntry == 1)
                    {
                        *((UCHAR *)OutputBuffer + CurrentEntryOffset + 2) = 1;
                        ThreadFlagsVal = Fields64.dword[0];
                        *(_QWORD *)&OutputBuffer[CurrentEntryOffset + 8] = 0;
                        *(_QWORD *)&OutputBuffer[CurrentEntryOffset + 6] = ThreadFlagsVal;
                        ThreadEntry += 544;
                        ++pListHead;
                        *(WORD *)((UCHAR *)OutputBuffer + CurrentEntryOffset + 10) = 0;
                        *OutputBuffer = pListHead;
                    }
                }
            }
            IsUserMode = IsUserModeLocal;
            ThreadId = IsUserModeLocal ? (unsigned int *)(ULONG_PTR)*ThreadId : *(unsigned int **)ThreadId;
            ResultCount = LoopCount;
            ListFieldOffset = EntryOffsetLocal;
        }
        while (ThreadId != pCurrent);
    }
    return ResultCount;
}

// FindSystemRootEntry — 在线程信息中查找系统根目录条目
// 比较进程名与编码的系统根目录模式，匹配时返回条目基址偏移
__int64 FindSystemRootEntry(_DWORD *ThreadInfoTable)
{
    __int64 Result;
    WORD *inited;
    ULONG EntryCount, EntryIndex;
    WORD *EntryPtr;
    _DWORD EncodedPath[13];
    __int64 EncodedPath2;

    Result = 0;
    EncodedPath[0] = 6029370; EncodedPath[1] = 6881367;
    EncodedPath[2] = 6553710; EncodedPath[11] = 7077996;
    EncodedPath2 = 7077996;
    EncodedPath[3] = 7798895; EncodedPath[4] = 6029427;
    EncodedPath[5] = 7929939; EncodedPath[6] = 5701747;
    EncodedPath[7] = 5701711; EncodedPath[8] = 3407926;
    EncodedPath[9] = 7209052; EncodedPath[10] = 6553716;
    EncodedPath[12] = 6553646;

    inited = InitSystemPath();
    if (!inited) return Result;

    EntryCount = *ThreadInfoTable;
    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++)
    {
        EntryPtr = (WORD *)(ThreadInfoTable + 136 * EntryIndex + 10);
        if (*inited == *EntryPtr &&
            WStringCompareCaseInsensitive((__int64)EncodedPath,
                (__int64)&ThreadInfoTable[136 * EntryIndex + 10] + 2) == 0)
        {
            Result = *(__int64 *)&ThreadInfoTable[136 * EntryIndex + 4];
            break;
        }
    }

    ExFree(inited);
    return Result;
}

// CleanupThreadWithBuffer — 清理线程 VAD 缓冲区(V1 版，Win7 以下)
// 对应原始驱动 sub_14004F03C
// 尝试分配 8MB 缓冲区用迭代方式遍历文件映射节区，失败则回退到递归方式
void CleanupThreadWithBuffer(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    PVOID Buffer = ExAlloc(PagedPool, 0x800000);
    if (Buffer)
    {
        EnumerateFileMappingSectionIterativeV1(VirtualAddress, (__int64)Buffer, 0x100000, OutputBuffer, BufferSize);
        ExFree(Buffer);
    }
    else
    {
        EnumerateFileMappingSectionRecursiveV1(VirtualAddress, 0, OutputBuffer, BufferSize);
    }
}

// EnumerateVadWithBufferV2 — 枚举 VAD 节点(V2 版，Win7/8)
// 对应原始驱动 sub_14004E964
// 尝试分配 8MB 缓冲区用迭代方式遍历 VAD 树，失败则回退到递归方式

// EnumerateVadWithBufferV3 — 枚举 VAD 节点(V3 版，Win8.1)
// 对应原始驱动 sub_14004EBAC
// 尝试分配 8MB 缓冲区用迭代方式遍历 VAD 树，失败则回退到递归方式
void EnumerateVadWithBufferV3(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    PVOID Buffer = ExAlloc(PagedPool, 0x800000);
    if (Buffer)
    {
        EnumerateVadIterativeV3(VirtualAddress, (__int64)Buffer, 0x100000, OutputBuffer, BufferSize);
        ExFree(Buffer);
    }
    else
    {
        EnumerateVadRecursiveV3(VirtualAddress, 0, OutputBuffer, BufferSize);
    }
}

// EnumerateVadWithBufferV4 — 枚举 VAD 节点(V4 版，Win10+)
// 对应原始驱动 sub_14004EC24
// 尝试分配 8MB 缓冲区用迭代方式遍历 VAD 树，失败则回退到递归方式
void EnumerateVadWithBufferV4(_QWORD *VirtualAddress, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    PVOID Buffer = ExAlloc(PagedPool, 0x800000);
    if (Buffer)
    {
        EnumerateVadIterativeV4(VirtualAddress, (__int64)Buffer, 0x100000, OutputBuffer, BufferSize);
        ExFree(Buffer);
    }
    else
    {
        EnumerateVadRecursiveV4(VirtualAddress, 0, OutputBuffer, BufferSize);
    }
}

// PatchThreadImagePathWithWow64 — 修补 Wow64 线程镜像路径
// 对应原始驱动 sub_1400784C4
// 将系统路径替换为 Wow64 路径
void PatchThreadImagePathWithWow64(__int64 Path)
{
    unsigned int StringLength = (unsigned int)GetStringLength((_WORD *)Path);
    if (StringLength)
    {
        _WORD *pSystem32Path = BuildSystem32Path();
        if (pSystem32Path)
        {
            unsigned int System32Len = (unsigned int)GetStringLength(pSystem32Path);
            if (System32Len <= StringLength
                && !(unsigned int)StringCompare3Way((__int64)pSystem32Path, (unsigned __int16 *)Path, System32Len)
                && StringLength >= 0x13)
            {
                *(_DWORD *)(Path + 28) = 7274615;
                *(_DWORD *)(Path + 32) = 3539063;
                *(_WORD *)(Path + 36) = 52;
            }
            ExFree(pSystem32Path);
        }
    }
}

// ResetThreadStateFlag — 重置线程状态标志
// 对应原始驱动 sub_14004CBD0
// 检查线程状态值是否 <=5，若匹配则重置线程状态字节为 0
__int64 ResetThreadStateFlag(__int64 Thread, __int64 FlagOffset)
{
    __int64 result = GtRead(GtEprocessField37);
    if ((_DWORD)result != -1 && *(_DWORD *)FlagOffset <= 5u)
    {
        result = (unsigned int)result;
        if (*(_DWORD *)((unsigned int)result + Thread) <= 8u)
            *(_BYTE *)(FlagOffset + 8) = 0;
    }
    return result;
}

// EnumerateFileMappingSection — 枚举文件映射节区(V1)
// 对应原始驱动 0x14004BE6C（617 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**，按伪代码 1:1 转写，
//   并用 capstone 原始字节复核（见【与 Ex 版的差异】的偏移证据）。
// 【与 EnumerateFileMappingSectionEx（0x14004C0D8）的差异】
//   1) 文件对象指针取 a1+0x28（Ex 取 a1+72=0x48），有效性探测长度 0x47（Ex 用 +55=0x37）；
//      capstone：`mov rbx, qword ptr [rcx + 0x28]`、`lea rcx, [rbx + 0x47]`；
//   2) 节头指针取 *(v6+0x30)（Ex 取 *(FileObject+64) 并与 ~0xF 对齐）；
//      capstone：`mov rbx, qword ptr [rbx + 0x30]`（无 and 掩码）；
//   3) 无构建号门控的节区类型检查（Ex 有 `GtRead(0x914) < 0x47BA` 分支）；
//   4) 入口判据用 FindThreadEntry(a2, VAD+0x18 << 12, ...) **仅单个** StartAddr，
//      不使用 VAD+0x1C 的高位扩展。
// 【参数】a1 = VAD 节点；a2 = 输出缓冲（每项 544 字节，首 DWORD 为已用项数）；
//   a3 = 缓冲字节数。
// 【布局】项基址 = 136 DWORD/项（544 字节）：+8 起始地址、+0x10 结束地址、
//   +0x18 节头指针、+0x20 名称（最多 0x1FE 字节）、+2 命中位。
// 【逻辑】
//   1) 若 544*已用项数 + 552 > a3 → 直接返回（空间不足）；
//   2) 取文件对象 v6 = *(a1+0x28)；三级有效性探测 + (*(v6+0x2C) & 0xA0)==0xA0；
//   3) 取节头 v7 = *(v6+0x30)；要求 v7 > MmSystemRangeStart、探测 v7 与 v7+0xB7 有效、
//      *v7==5 且 ((v7[1]-0xB8) & 0xFFDF)==0；
//   4) 若 FindThreadEntry(...) == 1（未命中已有条目）：
//      若 *(a1+0x1C) != *(a1+0x18) 且 QueryObjectNameString(v7, &Src, &NameLength)==1 →
//        以当前已用项数 EntryIndex 填充新条目（基址 = *(a1+0x18)<<12、
//        大小 = ((*(a1+0x1C)-*(a1+0x18)+1)<<12)、节头指针、名称），
//        写 *a2 = EntryIndex+1，随后 ExFree(Src)；
//      否则（命中已有条目）：用已命中索引 MatchIndex 定位条目，
//        若名称不同且新名更长 → 覆盖名称，随后 ExFree(Src)。
void __fastcall EnumerateFileMappingSection(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG   EntryIndex;         // v3
    __int64 FileObject;         // v6
    _WORD  *SectionHeader;      // v7
    void   *Src[2] = { 0, 0 };  // QueryObjectNameString 输出缓冲（[0]=缓冲指针）
    unsigned int MatchIndex = 0;    // v17（FindThreadEntry 输出）
    unsigned int NameLength = 0;    // v18
    __int64 EntryOffset;
    unsigned int StringLength;

    EntryIndex = *OutputBuffer;
    if ((unsigned int)(544 * (int)EntryIndex + 552) > BufferSize)   // 0x14004BE96
        return;

    FileObject = *(__int64 *)(VadNode + 0x28);                      // 0x14004BE9C
    if (!FileObject)                                                // 0x14004BEA3
        return;

    if (MmIsAddressValid((PVOID)FileObject) != 1                     // 0x14004BEAC
        || MmIsAddressValid((PVOID)(FileObject + 0x47)) != 1        // 0x14004BEBA
        || (*(UCHAR *)(FileObject + 0x2C) & 0xA0) != 0xA0)          // 0x14004BECC
        return;

    SectionHeader = *(_WORD **)(FileObject + 0x30);                 // 0x14004BEE3
    if ((ULONG64)SectionHeader <= (ULONG64)MmSystemRangeStart)      // 0x14004BEE7
        return;
    if (MmIsAddressValid(SectionHeader) != 1                        // 0x14004BEF3
        || MmIsAddressValid((char *)SectionHeader + 0xB7) != 1      // 0x14004BF01
        || *SectionHeader != 5                                      // 0x14004BF16
        || ((SectionHeader[1] - 0xB8) & 0xFFDF) != 0)               // 0x14004BF24
        return;

    if ((unsigned int)FindThreadEntry(OutputBuffer,                 // 0x14004BF50
                                      (unsigned __int64)*(unsigned int *)(VadNode + 0x18) << 12,
                                      &MatchIndex, (__int64)SectionHeader) != 1)
    {
        /* 命中已有条目：仅当名称更长时覆盖 */
        if ((unsigned int)QueryObjectNameString((ULONG64)SectionHeader, // 0x14004BF76
                                                (_QWORD *)Src, &NameLength) != 1)
            return;                                                 // 0x14004C018

        EntryOffset = 136LL * MatchIndex;                            // 0x14004C028
        HIWORD_LV(OutputBuffer[EntryOffset + 137]) = 0;              // 0x14004C035
        StringLength = (ULONG)GetStringLength((_WORD *)&OutputBuffer[EntryOffset + 10]);  // 0x14004C03E
        if (2LL * StringLength != NameLength                         // 0x14004C05B
            || (unsigned int)StringCompare3Way((__int64)&OutputBuffer[EntryOffset + 10],
                                               (unsigned __int16 *)Src[0], NameLength >> 1))
        {
            StringLength = (ULONG)GetStringLength((_WORD *)&OutputBuffer[EntryOffset + 10]);  // 0x14004C067
            if (NameLength > 2 * (ULONG64)StringLength)              // 0x14004C077
            {
                LOBYTE_LV(OutputBuffer[EntryOffset + 2]) = 1;        // 0x14004C079
                if (NameLength > 0x1FE)                              // 0x14004C08D
                    NameLength = 510;
                memmove(&OutputBuffer[EntryOffset + 10], Src[0], NameLength);  // 0x14004C099
                *((_WORD *)&OutputBuffer[136 * (ULONG)MatchIndex + 10]
                  + ((ULONG64)NameLength >> 1)) = 0;                 // 0x14004C0AE
                HIWORD_LV(OutputBuffer[EntryOffset + 137]) = 0;      // 0x14004C0B4
            }
        }
        ExFree(Src[0]);                                             // 0x14004C0BD
        return;
    }

    /* 未命中已有条目：追加新条目 */
    if (*(_DWORD *)(VadNode + 0x1C) != *(_DWORD *)(VadNode + 0x18)   // 0x14004BF61
        && (unsigned int)QueryObjectNameString((ULONG64)SectionHeader,   // 0x14004BF76
                                               (_QWORD *)Src, &NameLength) == 1)
    {
        EntryOffset = 136LL * EntryIndex;                            // 0x14004BF87
        LOBYTE_LV(OutputBuffer[EntryOffset + 2]) = 1;                // 0x14004BF8E
        *(__int64 *)&OutputBuffer[EntryOffset + 8] = (__int64)SectionHeader;   // 0x14004BF93
        *(__int64 *)&OutputBuffer[EntryOffset + 4] =
            (unsigned __int64)*(unsigned int *)(VadNode + 0x18) << 12;         // 0x14004BFA0
        *(__int64 *)&OutputBuffer[EntryOffset + 6] =
            (unsigned int)((*(_DWORD *)(VadNode + 0x1C) - *(_DWORD *)(VadNode + 0x18) + 1) << 12);  // 0x14004BFBB
        if (NameLength > 0x1FE)                                      // 0x14004BFC5
            NameLength = 510;
        memmove(&OutputBuffer[EntryOffset + 10], Src[0], NameLength);  // 0x14004BFD7
        *((_WORD *)&OutputBuffer[136 * EntryIndex + 10] + ((ULONG64)NameLength >> 1)) = 0;  // 0x14004BFEB
        HIWORD_LV(OutputBuffer[EntryOffset + 137]) = 0;              // 0x14004BFF1
        *OutputBuffer = EntryIndex + 1;                              // 0x14004BFFE
        ExFree(Src[0]);                                             // 0x14004C0BD
    }
}

// EnumerateFileMappingSectionEx — 枚举文件映射节区(扩展版)
// 对应原始驱动 sub_14004C0D8（715 字节）
// 从 VAD 节点提取文件对象信息，填充到输出缓冲区
void EnumerateFileMappingSectionEx(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG EntryIndex = *OutputBuffer;
    if ((unsigned int)(544 * (int)EntryIndex + 552) > BufferSize)
        return;

    __int64 *FileObjectPtr = *(__int64 **)(VadNode + 72);
    if (!FileObjectPtr)
        return;
    if (MmIsAddressValid(*(PVOID *)(VadNode + 72)) != 1 ||
        MmIsAddressValid((char *)FileObjectPtr + 55) != 1)
        return;

    __int64 FileObject = *FileObjectPtr;
    if (!FileObject)
        return;
    if (MmIsAddressValid((PVOID)FileObject) != 1 ||
        MmIsAddressValid((PVOID)(FileObject + 119)) != 1)
        return;

    bool IsValidSection = (ULONG)GtRead(GtWindowsBuildNumber) < 0x47BA
        ? (*(_DWORD *)(VadNode + 48) & 0x38) == 56
        : (*(_DWORD *)(VadNode + 48) & 0x380) == 896;

    if ((*(UCHAR *)(FileObject + 56) & 0xA0) != 0xA0 || !IsValidSection)
        return;

    WORD *FileHeader = (WORD *)(*(_QWORD *)(FileObject + 64) & 0xFFFFFFFFFFFFFFF0ULL);
    if ((ULONG64)FileHeader <= (ULONG64)MmSystemRangeStart)
        return;
    if (MmIsAddressValid(FileHeader) != 1 || MmIsAddressValid((char *)FileHeader + 183) != 1)
        return;
    if (*FileHeader != 5 || ((FileHeader[1] - 184) & 0xFFDF) != 0)
        return;

    ULONG64 StartAddr = *(ULONG *)(VadNode + 24) + ((ULONG64)*(UCHAR *)(VadNode + 32) << 32);
    ULONG64 EndAddr = *(ULONG *)(VadNode + 28) + ((ULONG64)*(UCHAR *)(VadNode + 33) << 32);
    ULONG ExistingEntryIndex;
    void *Src[2];
    ULONG ObjNameLength, StringLen, StringLenAligned;

    if (FindThreadEntry(OutputBuffer, StartAddr << 12, &ExistingEntryIndex, (__int64)FileHeader) == 1)
    {
        if (EndAddr != StartAddr && QueryObjectNameString((ULONG64)FileHeader, (_QWORD *)Src, &ObjNameLength) == 1)
        {
            __int64 EntryByteOffset = 136 * EntryIndex;
            LOBYTE_LV(OutputBuffer[EntryByteOffset + 2]) = 1;
            StringLen = ObjNameLength;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 8] = (__int64)FileHeader;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 4] = StartAddr << 12;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 6] = (EndAddr - StartAddr + 1) << 12;
            if (StringLen > 0x1FE) StringLen = 510;
            ObjNameLength = StringLen;
            StringLenAligned = StringLen;
            memmove(&OutputBuffer[EntryByteOffset + 10], Src[0], StringLen);
            *((WORD *)&OutputBuffer[136 * EntryIndex + 10] + (StringLenAligned >> 1)) = 0;
            HIWORD_LV(OutputBuffer[EntryByteOffset + 137]) = 0;
            *OutputBuffer = (ULONG)(EntryIndex + 1);
            ExFree(Src[0]);
        }
    }
    else if (QueryObjectNameString((ULONG64)FileHeader, (_QWORD *)Src, &ObjNameLength) == 1)
    {
        __int64 ExistingEntryOffset = 136 * ExistingEntryIndex;
        HIWORD_LV(OutputBuffer[ExistingEntryOffset + 137]) = 0;
        ULONG StringLen = (ULONG)GetStringLength((_WORD *)&OutputBuffer[ExistingEntryOffset + 10]);
        if (2 * StringLen != ObjNameLength ||
            StringCompare3Way((__int64)&OutputBuffer[ExistingEntryOffset + 10], (WORD *)Src[0], ObjNameLength >> 1))
        {
            ULONG ExistingStringLen = (ULONG)GetStringLength((_WORD *)&OutputBuffer[ExistingEntryOffset + 10]);
            if (ObjNameLength > 2 * (ULONG64)ExistingStringLen)
            {
                LOBYTE_LV(OutputBuffer[ExistingEntryOffset + 2]) = 1;
                ULONG ClampedStringLen = ObjNameLength > 0x1FE ? 510 : ObjNameLength;
                ObjNameLength = ClampedStringLen;
                memmove(&OutputBuffer[ExistingEntryOffset + 10], Src[0], ClampedStringLen);
                *((WORD *)&OutputBuffer[136 * (ULONG)ExistingEntryIndex + 10] + (ObjNameLength >> 1)) = 0;
                HIWORD_LV(OutputBuffer[ExistingEntryOffset + 137]) = 0;
            }
        }
        ExFree(Src[0]);
    }
}

// EnumerateFileMappingSectionStub — 枚举文件映射节区(存根验证版)
// 对应原始驱动 sub_14004C3A4
// V3 VAD 遍历使用的文件映射枚举存根：仅验证文件映射上下文中的文件对象指针有效性，不做实际枚举
void EnumerateFileMappingSectionStub(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (544 * *OutputBuffer + 552 <= BufferSize)
    {
        __int64 *FileObjectPtr = *(__int64 **)(VadNode + 72);
        if (FileObjectPtr)
        {
            if (MmIsAddressValid(*(PVOID *)(VadNode + 72)) == 1 &&
                MmIsAddressValid((char *)FileObjectPtr + 55) == 1)
            {
                __int64 FileObject = *FileObjectPtr;
                if (FileObject)
                    MmIsAddressValid((PVOID)FileObject);
            }
        }
    }
}

// EnumerateFileMappingSectionByIndex — 按索引枚举文件映射节区
// 对应原始驱动 sub_14004C940（653 字节） (V1 版本)
// V1 文件映射节区遍历，使用不同的 VAD 节点偏移和格式
void EnumerateFileMappingSectionByIndex(__int64 VadNode, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    ULONG EntryIndex = *OutputBuffer;
    if ((unsigned int)(544 * (int)EntryIndex + 552) > BufferSize)
        return;

    __int64 *FileObjectPtr = *(__int64 **)(VadNode + 72);
    if (!FileObjectPtr)
        return;
    if (MmIsAddressValid(*(PVOID *)(VadNode + 72)) != 1 ||
        MmIsAddressValid((char *)FileObjectPtr + 55) != 1)
        return;

    __int64 FileObject = *FileObjectPtr;
    if (!FileObject)
        return;
    if (MmIsAddressValid((PVOID)FileObject) != 1 ||
        MmIsAddressValid((PVOID)(FileObject + 119)) != 1)
        return;

    bool IsValidSection = (ULONG)GtRead(GtWindowsBuildNumber) < 0x47BA
        ? (*(_DWORD *)(VadNode + 48) & 0x38) == 56
        : (*(_DWORD *)(VadNode + 48) & 0x380) == 896;

    if ((*(UCHAR *)(FileObject + 56) & 0xA0) != 0xA0 || !IsValidSection)
        return;

    WORD *FileHeader = (WORD *)(*(_QWORD *)(FileObject + 64) & 0xFFFFFFFFFFFFFFF0ULL);
    if ((ULONG64)FileHeader <= (ULONG64)MmSystemRangeStart)
        return;
    if (MmIsAddressValid(FileHeader) != 1 || MmIsAddressValid((char *)FileHeader + 183) != 1)
        return;
    if (*FileHeader != 5 || ((FileHeader[1] - 184) & 0xFFDF) != 0)
        return;

    ULONG64 StartAddr = *(ULONG *)(VadNode + 24) + ((ULONG64)*(UCHAR *)(VadNode + 32) << 32);
    ULONG64 EndAddr = *(ULONG *)(VadNode + 28) + ((ULONG64)*(UCHAR *)(VadNode + 33) << 32);
    ULONG ExistingEntryIndex;
    void *Src[2];
    ULONG ObjNameLength, StringLen, StringLenAligned;

    if (FindThreadEntry(OutputBuffer, StartAddr << 12, &ExistingEntryIndex, (__int64)FileHeader) == 1)
    {
        if (EndAddr != StartAddr && QueryObjectNameString((ULONG64)FileHeader, (_QWORD *)Src, &ObjNameLength) == 1)
        {
            __int64 EntryByteOffset = 136 * EntryIndex;
            LOBYTE_LV(OutputBuffer[EntryByteOffset + 2]) = 1;
            StringLen = ObjNameLength;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 8] = (__int64)FileHeader;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 4] = StartAddr << 12;
            *(__int64 *)&OutputBuffer[EntryByteOffset + 6] = (EndAddr - StartAddr + 1) << 12;
            if (StringLen > 0x1FE) StringLen = 510;
            ObjNameLength = StringLen;
            StringLenAligned = StringLen;
            memmove(&OutputBuffer[EntryByteOffset + 10], Src[0], StringLen);
            *((WORD *)&OutputBuffer[136 * EntryIndex + 10] + (StringLenAligned >> 1)) = 0;
            HIWORD_LV(OutputBuffer[EntryByteOffset + 137]) = 0;
            *OutputBuffer = (ULONG)(EntryIndex + 1);
            ExFree(Src[0]);
        }
    }
    else if (QueryObjectNameString((ULONG64)FileHeader, (_QWORD *)Src, &ObjNameLength) == 1)
    {
        __int64 ExistingEntryOffset = 136 * ExistingEntryIndex;
        HIWORD_LV(OutputBuffer[ExistingEntryOffset + 137]) = 0;
        ULONG StringLen = (ULONG)GetStringLength((_WORD *)&OutputBuffer[ExistingEntryOffset + 10]);
        if (2 * StringLen != ObjNameLength ||
            StringCompare3Way((__int64)&OutputBuffer[ExistingEntryOffset + 10], (WORD *)Src[0], ObjNameLength >> 1))
        {
            ULONG ExistingStringLen = (ULONG)GetStringLength((_WORD *)&OutputBuffer[ExistingEntryOffset + 10]);
            if (ObjNameLength > 2 * (ULONG64)ExistingStringLen)
            {
                LOBYTE_LV(OutputBuffer[ExistingEntryOffset + 2]) = 1;
                ULONG ClampedStringLen = ObjNameLength > 0x1FE ? 510 : ObjNameLength;
                ObjNameLength = ClampedStringLen;
                memmove(&OutputBuffer[ExistingEntryOffset + 10], Src[0], ClampedStringLen);
                *((WORD *)&OutputBuffer[136 * (ULONG)ExistingEntryIndex + 10] + (ObjNameLength >> 1)) = 0;
                HIWORD_LV(OutputBuffer[ExistingEntryOffset + 137]) = 0;
            }
        }
        ExFree(Src[0]);
    }
}

// EnumerateVadRecursiveV2 — 递归枚举 VAD 树 V2 (Win7/8 版本)
// 对应原始驱动 sub_14004E9DC
// 递归遍历 VAD 树，偏移 95 处检查有效性，调用 EnumerateFileMappingSectionEx
void EnumerateVadRecursiveV2(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (Level >= 0x12C)
        return;

    _QWORD *CurrentNode = VirtualAddress;
    for (unsigned int i = Level; i < 0x12C; ++i)
    {
        if (!CurrentNode)
            break;

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateVadRecursiveV2((_QWORD *)CurrentNode[1], i + 1, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionEx((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) != 1)
            break;
        if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
            break;

        CurrentNode = (_QWORD *)CurrentNode[2];
    }
}

// EnumerateVadIterativeV2 — 迭代枚举 VAD 树 V2 (Win7/8 版本)
// 对应原始驱动 sub_14004EAA8
// 使用栈+迭代方式遍历 VAD 树，偏移 95 处检查有效性，调用 EnumerateFileMappingSectionEx
void EnumerateVadIterativeV2(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!VirtualAddress)
        return;

    int StackDepth = -1;
    _QWORD *CurrentNode = VirtualAddress;
    int Depth = -1;

    do
    {
        // 向左遍历到底
        while (CurrentNode)
        {
            if (Depth >= BufferElements - 1)
                break;
            if (MmIsAddressValid(CurrentNode) != 1)
                break;
            if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
                break;

            CurrentNode = (_QWORD *)CurrentNode[1];
            ++Depth;
        }

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionEx((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (Depth >= BufferElements - 1)
            break;

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
        {
            CurrentNode = (_QWORD *)CurrentNode[2];
            ++Depth;
        }
        else
        {
            CurrentNode = NULL;
        }

        // 回溯: 从栈中弹出节点
        while (Depth >= 0 && !CurrentNode)
        {
            --Depth;
        }
    }
    while (Depth >= 0);
}

// EnumerateVadRecursiveV3 — 递归枚举 VAD 树 V3 (Win8.1 版本)
// 对应原始驱动 sub_14004EE6C
// 递归遍历 VAD 树，偏移 127 处检查有效性，调用 EnumerateFileMappingSectionStub
void EnumerateVadRecursiveV3(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (Level >= 0x12C)
        return;

    _QWORD *CurrentNode = VirtualAddress;
    for (unsigned int i = Level; i < 0x12C; ++i)
    {
        if (!CurrentNode)
            break;

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumerateVadRecursiveV3((_QWORD *)CurrentNode[1], i + 1, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumerateFileMappingSectionStub((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) != 1)
            break;
        if (MmIsAddressValid((char *)CurrentNode + 127) != 1)
            break;

        CurrentNode = (_QWORD *)CurrentNode[2];
    }
}

// EnumerateVadIterativeV3 — 迭代枚举 VAD 树 V3 (Win8.1 版本)
// 对应原始驱动 sub_14004EF38（258 字节）
// 使用栈+迭代方式遍历 VAD 树，偏移 127 处检查有效性，调用 EnumerateFileMappingSectionStub
void EnumerateVadIterativeV3(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!VirtualAddress)
        return;

    int StackDepth = -1;
    _QWORD *CurrentNode = VirtualAddress;
    int Depth = -1;

    do
    {
        while (CurrentNode)
        {
            if (Depth >= BufferElements - 1)
                break;
            if (MmIsAddressValid(CurrentNode) != 1)
                break;
            if (MmIsAddressValid((char *)CurrentNode + 127) != 1)
                break;

            CurrentNode = (_QWORD *)CurrentNode[1];
            ++Depth;
        }

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumerateFileMappingSectionStub((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (Depth >= BufferElements - 1)
            break;

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
        {
            CurrentNode = (_QWORD *)CurrentNode[2];
            ++Depth;
        }
        else
        {
            CurrentNode = NULL;
        }

        while (Depth >= 0 && !CurrentNode)
        {
            --Depth;
        }
    }
    while (Depth >= 0);
}

// EnumerateVadRecursiveV4 — 递归枚举 VAD 树 V4 (Win10+ 版本)
// 对应原始驱动 sub_14004EC9C
// 递归遍历 VAD 树，偏移 127 处检查有效性，左子节点在 *a1(偏移0)，右子节点在 a1[1](偏移8)
// 调用 EnumVadMemoryRegions
void EnumerateVadRecursiveV4(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (Level >= 0x12C)
        return;

    _QWORD *CurrentNode = VirtualAddress;
    for (unsigned int i = Level; i < 0x12C; ++i)
    {
        if (!CurrentNode)
            break;

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumerateVadRecursiveV4((_QWORD *)*CurrentNode, i + 1, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumVadMemoryRegions((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) != 1)
            break;
        if (MmIsAddressValid((char *)CurrentNode + 127) != 1)
            break;

        CurrentNode = (_QWORD *)CurrentNode[1];
    }
}

// EnumerateVadIterativeV4 — 迭代枚举 VAD 树 V4 (Win10+ 版本)
// 对应原始驱动 sub_14004ED68（257 字节）
// 使用栈+迭代方式遍历 VAD 树，偏移 127 处检查有效性，左子节点在 *a1，右子节点在 a1[1]
// 调用 EnumVadMemoryRegions
void EnumerateVadIterativeV4(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!VirtualAddress)
        return;

    int StackDepth = -1;
    _QWORD *CurrentNode = VirtualAddress;
    int Depth = -1;

    do
    {
        while (CurrentNode)
        {
            if (Depth >= BufferElements - 1)
                break;
            if (MmIsAddressValid(CurrentNode) != 1)
                break;
            if (MmIsAddressValid((char *)CurrentNode + 127) != 1)
                break;

            CurrentNode = (_QWORD *)*CurrentNode;
            ++Depth;
        }

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
            EnumVadMemoryRegions((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (Depth >= BufferElements - 1)
            break;

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 127) == 1)
        {
            CurrentNode = (_QWORD *)CurrentNode[1];
            ++Depth;
        }
        else
        {
            CurrentNode = NULL;
        }

        while (Depth >= 0 && !CurrentNode)
        {
            --Depth;
        }
    }
    while (Depth >= 0);
}

// EnumerateFileMappingSectionRecursiveV1 — 递归枚举文件映射节区 V1
// 对应原始驱动 sub_14004F0B4（204 字节）
// 递归遍历旧版 VAD 树，调用 EnumerateFileMappingSectionByIndex
void EnumerateFileMappingSectionRecursiveV1(_QWORD *VirtualAddress, int Level, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (Level >= 0x12C)
        return;

    _QWORD *CurrentNode = VirtualAddress;
    for (unsigned int i = Level; i < 0x12C; ++i)
    {
        if (!CurrentNode)
            break;

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionRecursiveV1((_QWORD *)CurrentNode[1], i + 1, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionByIndex((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) != 1)
            break;
        if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
            break;

        CurrentNode = (_QWORD *)CurrentNode[2];
    }
}

// EnumerateFileMappingSectionIterativeV1 — 迭代枚举文件映射节区 V1
// 对应原始驱动 sub_14004F180（258 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x14004E860 —— 那落在
//   另一个函数 EnumerateThreadListEntries 内（不是函数起始）。
// 使用栈+迭代方式遍历旧版 VAD 树，调用 EnumerateFileMappingSectionByIndex
void EnumerateFileMappingSectionIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int BufferElements, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!VirtualAddress)
        return;

    int StackDepth = -1;
    _QWORD *CurrentNode = VirtualAddress;
    int Depth = -1;

    do
    {
        while (CurrentNode)
        {
            if (Depth >= BufferElements - 1)
                break;
            if (MmIsAddressValid(CurrentNode) != 1)
                break;
            if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
                break;

            CurrentNode = (_QWORD *)CurrentNode[1];
            ++Depth;
        }

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionByIndex((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (Depth >= BufferElements - 1)
            break;

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
        {
            CurrentNode = (_QWORD *)CurrentNode[2];
            ++Depth;
        }
        else
        {
            CurrentNode = NULL;
        }

        while (Depth >= 0 && !CurrentNode)
        {
            --Depth;
        }
    }
    while (Depth >= 0);
}

// EnumerateVadRecursiveV1 — 递归枚举 VAD 树 V1 (旧版)
// 对应原始驱动 sub_14004E794
// 递归遍历 VAD 树，偏移 95 处检查有效性，调用 EnumerateFileMappingSectionByIndex
void EnumerateVadRecursiveV1(_QWORD *VirtualAddress, int Depth, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (Depth >= 0x12C)
        return;

    _QWORD *CurrentNode = VirtualAddress;
    for (unsigned int i = Depth; i < 0x12C; ++i)
    {
        if (!CurrentNode)
            break;

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateVadRecursiveV1((_QWORD *)CurrentNode[1], i + 1, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionByIndex((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (MmIsAddressValid(CurrentNode) != 1)
            break;
        if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
            break;

        CurrentNode = (_QWORD *)CurrentNode[2];
    }
}

// EnumerateVadIterativeV1 — 迭代枚举 VAD 树 V1 (旧版)
// 对应原始驱动 sub_14004E860
// 使用栈+迭代方式遍历 VAD 树，偏移 95 处检查有效性，调用 EnumerateFileMappingSectionByIndex
void EnumerateVadIterativeV1(_QWORD *VirtualAddress, __int64 Buffer, int MaxSize, _DWORD *OutputBuffer, unsigned int BufferSize)
{
    if (!VirtualAddress)
        return;

    int StackDepth = -1;
    _QWORD *CurrentNode = VirtualAddress;
    int Depth = -1;

    do
    {
        // 向左遍历到底
        while (CurrentNode)
        {
            if (Depth >= MaxSize - 1)
                break;
            if (MmIsAddressValid(CurrentNode) != 1)
                break;
            if (MmIsAddressValid((char *)CurrentNode + 95) != 1)
                break;

            CurrentNode = (_QWORD *)CurrentNode[1];
            ++Depth;
        }

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
            EnumerateFileMappingSectionByIndex((__int64)CurrentNode, OutputBuffer, BufferSize);

        if (Depth >= MaxSize - 1)
            break;

        if (CurrentNode && MmIsAddressValid(CurrentNode) == 1 &&
            MmIsAddressValid((char *)CurrentNode + 95) == 1)
        {
            CurrentNode = (_QWORD *)CurrentNode[2];
            ++Depth;
        }
        else
        {
            CurrentNode = NULL;
        }

        // 回溯: 从栈中弹出节点
        while (Depth >= 0 && !CurrentNode)
        {
            --Depth;
        }
    }
    while (Depth >= 0);
}

// MatchSystemProcessName — 匹配系统进程名
// 对应原始驱动 sub_14004CC4C
// 根据构建号选择不同字符串格式，构建 "svchost.exe"/"explorer.exe" 等系统进程名，
// 从 GT 30 获取进程名偏移并比较。
// 返回 1(svchost)/2(Search*)/3(sidebar)/4(explorer)/0(不匹配)
__int64 MatchSystemProcessName(_QWORD *Process)
{
    char SvchostStr[12] = "svchost.exe";
    char ExplorerStr[13] = "explorer.exe";
    char SidebarStr[12] = "sidebar.exe";
    char SearchIndexerStr[18] = "SearchIndexer.exe";
    char SearchFilterHostStr[21] = "SearchFilterHost.exe";
    char SearchProtocolHostStr[23] = "SearchProtocolHost.exe";
    char ServiceHostStr[16] = "ServiceHost.exe";
    unsigned int Result = 0;

    unsigned int BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);

    unsigned int NameOffset = (unsigned int)GtRead(GtEprocessField30);
    if (NameOffset == -1)
        return Result;

    char *pProcessName = (char *)Process + NameOffset;

    if (StringCompareCaseInsensitiveV2((__int64)SvchostStr, (__int64)pProcessName) == 0)
        return 1;

    if (StringCompareCaseInsensitiveV2((__int64)ExplorerStr, (__int64)pProcessName) == 0)
        return 4;

    if (StringCompareCaseInsensitiveV2((__int64)SidebarStr, (__int64)pProcessName) == 0)
        return 3;

    if (BuildNumber > 0x1DB0)
    {
        if (StringCompareCaseInsensitiveV2((__int64)SearchIndexerStr, (__int64)pProcessName) == 0
            || StringCompareCaseInsensitiveV2((__int64)SearchFilterHostStr, (__int64)pProcessName) == 0
            || StringCompareCaseInsensitiveV2((__int64)SearchProtocolHostStr, (__int64)pProcessName) == 0)
            return 2;
    }
    else
    {
        if (StringCompareCaseInsensitiveV2((__int64)ServiceHostStr, (__int64)pProcessName) == 0)
            return 2;
    }

    return Result;
}

// CopyThreadContextTable — 复制线程上下文表
// 对应原始驱动 sub_1400571B0
// Moved from MemoryCleanup.c
__int64 CopyThreadContextTable(__int64 pSourceTable)
{
    __int64 *DestTable = GtAlloc(GtTotalSize|GtEprocessField144);
    char *CurrentEntry = (char *)DestTable + 4;
    __int64 DeltaOffset = pSourceTable - (__int64)DestTable;
    char Result = 0;
    for (int LoopCount = 28; LoopCount; LoopCount--)
    {
        *(_DWORD *)&CurrentEntry[DeltaOffset] = *(_DWORD *)CurrentEntry;
        if (*(_DWORD *)CurrentEntry && *((_DWORD *)CurrentEntry - 1) == 1)
        {
            Result = 1;
            *(_QWORD *)&CurrentEntry[DeltaOffset + 4] = *(_QWORD *)(CurrentEntry + 4);
            *(_OWORD *)&CurrentEntry[DeltaOffset + 22] = *(_OWORD *)(CurrentEntry + 12);
        }
        CurrentEntry += 48;
    }
    return Result;
}
