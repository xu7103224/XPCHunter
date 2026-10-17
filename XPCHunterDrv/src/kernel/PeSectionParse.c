// PeSectionParse.c — PE 节区解析/查找（从 ModuleMgmt.c 拆分）
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
// 功能：PE 节区头解析、节区偏移/索引查找、内核数据节区定位

#include "XPCHunterDrv.h"

// C4700 抑制：PE 解析函数中大量变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)

// 前向声明 — 这些函数在当前文件中定义，但在调用点之后定义
char ComparePeHeaders(__int64 Image1, unsigned int Image1Size, __int64 Image2, unsigned int Image2Size);
__int64 EnumerateKernelModules(unsigned int *pOutputBuffer, unsigned int OutputSize);
char BuildDevicePathFromObjects(unsigned __int16 *pPath, WORD *pDriveLetter, int *pOffset);
__int64 ParseNtExportDirTable(__int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize, _DWORD *pBytesWritten);
__int64 ParseExportEntriesDetailed(__int64 TableEntry, unsigned int EntryCount, __int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize, _DWORD *pBytesWritten, __int64 FilterTable, unsigned int FilterTableSize);
__int64 ParseAndCompareExportEntries(__int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize, __int64 FilterTable, unsigned int FilterTableSize);
__int64 ParseNtExportAuxData(__int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, unsigned int NtImageDelta, __int64 OutputEntry, unsigned int OutputEntrySize, _DWORD *pBytesWritten);
__int64 ParseExportDirAndBuildIndex(__int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta, __int64 OutputTable, unsigned int OutputSize);
__int64 ParseNtSectionsForModuleList1(void);
__int64 ParseNtSectionsForModuleList2(void);
__int64 ParseExportDirectoryEntries(__int64 ImageBase, unsigned int ImageSize, __int64 NtImageBase, __int64 NtImageDelta, unsigned __int64 OutputBuffer, unsigned int OutputSize);
void FindHalDllInDriverList(unsigned int *pDriverArray, __int64 ArraySize, _QWORD *pImageBase, _DWORD *pImageSize);
__int16 BuildDriverImagePath(__int64 pNameString, unsigned int BufferSize, __int64 pOutputPath);
char EnumerateDriverObjectTable(__int64 pEntry, __int64 TargetObject);
char EnumerateKernelDrivers(PVOID *pObjectStack, int StackSize, unsigned int *pOutputBuffer, int OutputSize);
char OpenDriverFile(PCWSTR pFilePath);
__int64 FindPESectionByRva(__int64 PeBase, unsigned int PeSize, unsigned int TargetRva);
char ValidateZeroPage(__int64 Address, unsigned __int64 LimitAddress);
char CheckExportNamePrefixCombined(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
char CheckExportNamePrefixWin10V2(_BYTE *pBuffer1, _BYTE *pBuffer2, unsigned int CompareSize);
char FindExportEntryByAddress(__int64 TargetAddress, __int64 FilterTable, unsigned int FilterTableSize);
char BtreeSearchByKey(unsigned __int8 *pKeyData, unsigned int *pOutOrdinal, unsigned int EntryCount);
char ClassifyModuleTypeHalOrNt(const char *ModuleName, __int64 *pExportDirBase, unsigned int *pExportDirCount);
void ParseExportSectionAndIndex(__int64 ImageBase, unsigned int ImageSize, unsigned int RegRefCount);
char ReadModuleFileToBuffer(const char *ModuleName, void **ppBuffer, unsigned int *pFileSize, __int64 *pExportDirBase);
char ValidateEnumerationResult(__int64 pCheckFlagFunc, __int64 CurrentAddr, __int64 Offset);
__int64 FindPESectionByOffset(unsigned int SectionOffset);

// ParseNtSectionsForModuleList1 — 解析模块链表的 NT 节区（填充 PE 节偏移/地址对）
// 对应原始驱动 sub_1400455E4（447 字节）
// 【⚠ 更正 2026-10-08】原注释写 0x14000C2F8 且名字写 LookupModuleByName ——
//   两者都属于**另一个函数**（LookupModuleByName 在 IDA 中的地址是 0x14000C2F8）；
//   本函数真实地址 0x1400455E4、真实名 ParseNtSectionsForModuleList1（均来自 IDA 函数表）。
__int64 ParseNtSectionsForModuleList1(void)
{
    __int64 KernelBase = GtRead(0x20);
    unsigned int KernelSize = (unsigned int)GtRead(0x21);
    __int64 NtImageBase = GtRead(3);
    __int64 SectionOffset = GtRead(0x4420);
    unsigned int MatchOffset = (unsigned int)GtRead(0x4477);
    unsigned int AltMatchOffset = (unsigned int)GtRead(0x4414);

    if (!KernelBase || !KernelSize || !NtImageBase || !SectionOffset || !MatchOffset || !AltMatchOffset)
        return 0;
    if (AltMatchOffset >= KernelSize)
        return 0;

    PE_DECODE_CONTEXT ReadContext;     // 0x48 字节解码上下文（原 __int64 仅 8 字节，栈越界）
    __int64 CumulativeSize = 0;
    // ReadPESectionEntry 只填充前 0x120 字节，但本函数会访问到 +0x1A0 处，
    // 故缓冲须大于 0x120（原声明 [72] 恰为 0x120，会越界读到相邻栈变量）
    _DWORD SectionEntry[112];
    char FoundFlag = 0;

    InitPESectionReadContext(
        AltMatchOffset + KernelBase,
        KernelSize - AltMatchOffset,
        2, 0, -1, 0, 0,
        (__int64)&ReadContext);

    for (unsigned int SectionIndex = 0; SectionIndex < 0x64; SectionIndex++)
    {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;

        unsigned int SectionSize = *(unsigned int *)((char *)SectionEntry + 0x60);
        CumulativeSize += SectionSize;
        WORD SectionType = *(WORD *)((char *)SectionEntry + 0x1A0 + 6);

        if (SectionType == 0x558)
        {
            unsigned int Offset = *(unsigned int *)((char *)SectionEntry + 0xD0);
            unsigned int CalculatedOffset = Offset - (unsigned int)KernelBase + (int)CumulativeSize;
            if (CalculatedOffset == MatchOffset ||
                (AltMatchOffset && CalculatedOffset == AltMatchOffset))
            {
                FoundFlag = 1;
            }
        }
        else if (SectionType == 0x512)
        {
            if (*(ULONG64 *)((char *)SectionEntry + 0x120) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x110) &&
                *(ULONG64 *)((char *)SectionEntry + 0xE8) == 0x40 &&
                *(_DWORD *)((char *)SectionEntry + 0xF0) == 1 &&
                FoundFlag == 1)
            {
                unsigned int FieldValue = *(unsigned int *)((char *)SectionEntry + 0xD0);
                unsigned int Result = FieldValue - (unsigned int)KernelBase + (int)CumulativeSize;
                if (Result && (unsigned int)Result < KernelSize)
                {
                    GtWrite(GtCallbackField112, NtImageBase + Result);
                    return SectionIndex;
                }
            }
        }
    }

    return 0;
}
__int64 ParseNtSectionsForModuleList2(void)
{
    __int64 KernelBase = GtRead(0x20);
    unsigned int KernelSize = (unsigned int)GtRead(0x21);
    __int64 NtImageBase = GtRead(3);
    __int64 SectionOffset = GtRead(0x4420);
    unsigned int MatchOffset = (unsigned int)GtRead(0x4477);
    unsigned int AltMatchOffset = (unsigned int)GtRead(0x4417);

    if (!KernelBase || !KernelSize || !NtImageBase || !SectionOffset || !MatchOffset || !AltMatchOffset)
        return 0;
    if (AltMatchOffset >= KernelSize)
        return 0;

    PE_DECODE_CONTEXT ReadContext;     // 0x48 字节解码上下文（原 __int64 仅 8 字节，栈越界）
    __int64 CumulativeSize = 0;
    // 同 ParseNtSectionsForModuleList1：访问到 +0x1A0，缓冲须大于 0x120
    _DWORD SectionEntry[112];
    char FoundFlag = 0;

    InitPESectionReadContext(
        AltMatchOffset + KernelBase,
        KernelSize - AltMatchOffset,
        2, 0, -1, 0, 0,
        (__int64)&ReadContext);

    for (unsigned int SectionIndex = 0; SectionIndex < 0x64; SectionIndex++)
    {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            break;

        unsigned int SectionSize = *(unsigned int *)((char *)SectionEntry + 0x60);
        CumulativeSize += SectionSize;
        WORD SectionType = *(WORD *)((char *)SectionEntry + 0x1A0 + 6);

        if (SectionType == 0x558)
        {
            unsigned int Offset = *(unsigned int *)((char *)SectionEntry + 0xD0);
            unsigned int CalculatedOffset = Offset - (unsigned int)KernelBase + (int)CumulativeSize;
            if (CalculatedOffset == MatchOffset ||
                (AltMatchOffset && CalculatedOffset == AltMatchOffset))
            {
                FoundFlag = 1;
            }
        }
        else if (SectionType == 0x512)
        {
            if (*(ULONG64 *)((char *)SectionEntry + 0x120) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x110) &&
                *(ULONG64 *)((char *)SectionEntry + 0xE8) == 0x40 &&
                *(_DWORD *)((char *)SectionEntry + 0xF0) == 1 &&
                FoundFlag == 1)
            {
                unsigned int FieldValue = *(unsigned int *)((char *)SectionEntry + 0xD0);
                unsigned int Result = FieldValue - (unsigned int)KernelBase + (int)CumulativeSize;
                if (Result && (unsigned int)Result < KernelSize)
                {
                    GtWrite(GtCallbackField113, NtImageBase + Result);
                    return SectionIndex;
                }
            }
        }
    }

    return 0;
}
void ScanProcessPESections(void)
{
    struct _KPROCESS *TargetProcess;
    __int64 SectionBase;
    __int64 FileSize;
    __int64 BaseAddr;
    __int64 ImageBase;
    __int64 SectionSize;
    __int64 SignatureOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    __int64 AccumulatedOffset;
    char SectionEntry[448];             // 描述符：原 [256] 仍差 32 字节（需 0x120 = 288）
    unsigned int SectionFileOffset;
    __int64 pSectionEntryBase;
    unsigned int LoopCount;
    struct _KAPC_STATE ApcState;
    int FoundOffset;
    int FoundOffset2;
    int FoundOffset3;

    TargetProcess = (struct _KPROCESS *)GtRead((GLOBAL_TABLE_INDEX)0x61);
    if (IoGetCurrentProcess() == TargetProcess)
        TargetProcess = 0;
    if (TargetProcess)
        KeStackAttachProcess(TargetProcess, &ApcState);
    SectionBase = GtRead((GLOBAL_TABLE_INDEX)0x63);
    FileSize = GtRead((GLOBAL_TABLE_INDEX)0x20);
    BaseAddr = GtRead((GLOBAL_TABLE_INDEX)0x21);
    ImageBase = GtRead((GLOBAL_TABLE_INDEX)3);
    SectionSize = GtRead((GLOBAL_TABLE_INDEX)2);
    SignatureOffset = GtRead((GLOBAL_TABLE_INDEX)0x41C8);
    if (SectionBase && FileSize && BaseAddr && ImageBase && SectionSize && SignatureOffset)
    {
        AccumulatedOffset = 0;
        FoundOffset = 0;
        FoundOffset2 = 0;
        FoundOffset3 = 0;
        InitPESectionReadContext(SectionBase + BaseAddr, (ULONG)FileSize, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        LoopCount = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 0x512)
            {
                if ((AccumulatedOffset & 0x40000) != 0)
                {
                    FoundOffset = (int)(SectionFileOffset + AccumulatedOffset);
                    FoundOffset2 = *(unsigned int *)(pSectionEntryBase - 0x60);
                    if (FoundOffset2)
                    {
                        FoundOffset2 = (int)(FoundOffset2 - BaseAddr + AccumulatedOffset);
                        if (FoundOffset2)
                        {
                            if (FoundOffset2 < FileSize)
                                FoundOffset3 = FoundOffset2;
                        }
                    }
                }
            }
            else if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 0x558)
            {
                if ((SectionFileOffset & 0x4000000) != 0)
                {
                    FoundOffset2 = *(unsigned int *)(pSectionEntryBase - 0x28);
                    if (FoundOffset2)
                    {
                        FoundOffset2 = (int)(FoundOffset2 - BaseAddr + AccumulatedOffset);
                        if (SignatureOffset == FoundOffset2)
                            break;
                    }
                }
            }
            ++LoopCount;
            if (LoopCount >= 0xC8)
                break;
        }
        if (FoundOffset && FoundOffset2 && FoundOffset3)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x67, ImageBase + FoundOffset);
            GtWrite((GLOBAL_TABLE_INDEX)0x66, ImageBase + FoundOffset2);
            GtWrite((GLOBAL_TABLE_INDEX)0x65, ImageBase + FoundOffset3);
        }
    }
    if (TargetProcess)
        KeUnstackDetachProcess(&ApcState);
}
__int64 ParseNtImageSectionHeaders(PRKPROCESS PROCESS, __int64 SectionInfoArray)
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
    struct _KAPC_STATE ApcState;
    _OWORD SectionHeaderBuf;
    __int64 SectionAddr;
    __int64 SectionAddrEnd;

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
            SectionAddr = *(__int64 *)&SectionHeader3;
            SectionAddrEnd = SectionAddr + 15;
            if ((unsigned __int64)SectionAddr < MmUserProbeAddress && (unsigned __int64)SectionAddrEnd < MmUserProbeAddress)
            {
                if ((unsigned int)MemoryCompare(*(__int64 *)&SectionHeader3, (char *)&SectionHeader4 + 2, 0x10u))
                {
                    *((_BYTE *)&SectionHeader4 + 1) = 1;
                    if (!(*(_BYTE *)&SectionHeader4))
                    {
                        memset(&SectionHeaderBuf, 0, sizeof(SectionHeaderBuf));
                        SectionHeaderBuf = *(_OWORD *)(*(__int64 *)&SectionHeader3);
                        FuncResult = ReturnFalseStub();
                        SavedValue = *((__int64 *)&SectionHeader3 + 1);
                        if (FuncResult == 1)
                            SavedValue = SectionEntry;
                        *((__int64 *)&SectionHeader3 + 1) = SavedValue;
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
__int64 ResolvePESectionOffset(void)
{
    __int64 Result;
    __int64 BaseOffset;
    unsigned int MaxSize;
    unsigned int ServiceCount;
    __int64 NtoskrnlBase;
    unsigned int KernelPESectionByType;
    unsigned int SyscallIndex;
    __int64 SyscallOffset;

    Result = 0;
    BaseOffset = GtRead(GtEprocessField22);
    MaxSize = (unsigned int)GtRead(GtEprocessField23);
    ServiceCount = (unsigned int)GtRead(GtWin32kServiceEntryCount);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    KernelPESectionByType = (unsigned int)FindKernelPESectionByType((enum _GLOBAL_TABLE_INDEX)(GtUninstallHookSyscallPeOffset | GtEprocessField188));
    if (BaseOffset && MaxSize && ServiceCount && NtoskrnlBase)
    {
        if (KernelPESectionByType < ServiceCount)
        {
            SyscallIndex = (unsigned int)ResolveSyscallToAddress(KernelPESectionByType);
            SyscallOffset = SyscallIndex;
            if (SyscallIndex && SyscallIndex < MaxSize)
            {
                FindPESectionByOffset(SyscallIndex);
                Result = NtoskrnlBase + SyscallOffset;
                GtWrite(GtCallbackField01, NtoskrnlBase + SyscallOffset);
            }
        }
    }
    return Result;
}
__int64 FindPeSectionByTypeRsrc(
    __int64 FileBuffer,
    int FileSize,
    __int64 BaseOffset)
{
    char Result;
    int FileStart;
    __int64 ResultOffset;
    int SectionIndex;
    int SectionOffset;
    __int16 SectionType;
    PE_DECODE_CONTEXT ReadContext;     // 0x48 字节解码上下文（原 __int64 仅 8 字节，栈越界）
    __int64 CumulativeSize;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 SectionFlags;
    int EntrySize;
    __int64 SectionAlignment;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    Result = 0;
    FileStart = (int)FileBuffer;
    ResultOffset = 0;

    InitPESectionReadContext(
        (__int64)FileBuffer,
        FileSize - (int)FileBuffer,
        2,
        0,
        -1,
        0,
        0,
        (__int64)&ReadContext);

    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
    {
        *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针：ReadPESectionEntry 不回写 ctx+0x08 */
        SectionOffset = EntryCumulSize + (ULONG)CumulativeSize;
        CumulativeSize += EntryCumulSize;
        SectionType = *(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);

        if (SectionType == 1349)
        {
            if (ResultOffset)
                return ResultOffset;
            return Result;
        }

        if (SectionType == 1298 &&
            SectionAlignment == 0x40000 &&
            EntrySize &&
            SectionFlags == 64)
        {
            ResultOffset = BaseOffset + SectionOffset + EntrySize - FileStart;
        }

        if ((unsigned int)++SectionIndex >= 0x1F4)
            return Result;
    }

    return Result;
}
__int64 FindPeSectionByType0x510(
    __int64 FileBuffer,
    int FileSize,
    int BaseAddress,
    unsigned int MaxSize)
{
    unsigned int SectionIndex;
    __int64 result;
    int SectionOffset;
    unsigned int TargetOffset;
    GLOBAL_TABLE_INDEX GtIndex;
    PE_DECODE_CONTEXT ReadContext;     // 0x48 字节解码上下文（原 __int64 仅 8 字节，栈越界）
    __int64 CumulativeSize;
    ULONG SectionEntry[112];            // 描述符：原 [20] 仅 80 字节
    __int64 SectionChar;
    int EntrySize;
    __int64 SectionAlignment;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    GtWrite(GtNtOpenProcessHookAddress, 0);
    GtWrite(GtFwpsDispatchTableBase, 0);
    GtWrite(GtFwpsDispatchTableCount, 0);

    InitPESectionReadContext(
        (__int64)FileBuffer,
        FileSize - (int)FileBuffer,
        2,
        0,
        -1,
        0,
        0,
        (__int64)&ReadContext);

    for (SectionIndex = 0; SectionIndex < 0x1E; ++SectionIndex)
    {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
        if ((ULONG)result)
            break;

        SectionOffset = EntryCumulSize + (ULONG)CumulativeSize;
        CumulativeSize += EntryCumulSize;

        if (*(__int16 *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) != 1296)
            continue;
        if (SectionChar != 64)
            continue;
        if (SectionAlignment != 0x40000)
            continue;
        if (!EntrySize)
            continue;

        TargetOffset = SectionOffset + EntrySize - BaseAddress;
        if (!TargetOffset || TargetOffset >= MaxSize)
            continue;

        if (!GtRead(GtNtOpenProcessHookAddress))
        {
            GtIndex = GtNtOpenProcessHookAddress;
            result = GtWrite(GtIndex, TargetOffset);
            continue;
        }

        if (!GtRead(GtFwpsDispatchTableBase))
        {
            GtIndex = GtFwpsDispatchTableBase;
            result = GtWrite(GtIndex, TargetOffset);
            continue;
        }

        result = GtRead(GtFwpsDispatchTableCount);
        if (!result)
            return GtWrite(GtFwpsDispatchTableCount, TargetOffset);
    }

    return result;
}
__int64 ParseNtSectionsForProcessMemory(void)
{
    __int64 Result;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int ValueField;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    int SectionDataSize;

    Result = 0;
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43C9);
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (BaseOffset &&
        BaseOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            SectionDataSize = *(int *)&EntryBuffer[0x38];

            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x512 &&
                FieldFlags == 0x40000 &&
                SectionDataSize &&
                FieldValueSize == 0x40)
            {
                ValueField = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                if (ValueField && ValueField < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x823, NtoskrnlModuleBase + ValueField);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    return Result;
}
__int64 ParseNtSectionsForModuleBase(void)
{
    __int64 Result;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int Offset1;
    unsigned int Offset2;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    int SectionDataSize;

    Result = 0;
    Offset1 = 0;
    Offset2 = 0;
    // 【读序修正 2026-10-13】原始读序 0x20 → 0x21 → 3 → 0x43C6。
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43C6);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (BaseOffset &&
        BaseOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            SectionDataSize = *(int *)&EntryBuffer[0x38];

            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x512 &&
                FieldFlags == 0x40000 &&
                SectionDataSize &&
                FieldValueSize == 0x40)
            {
                Offset1 = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            }

            if ((SectionType == 0x429 || SectionType == 0x471) &&
                SectionDataSize)
            {
                Offset2 = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            }

            ++SectionIndex;
        }

        if (Offset1 && Offset1 < NtImageSize &&
            Offset2 && Offset2 < NtImageSize)
        {
            GtWrite((GLOBAL_TABLE_INDEX)0x81F, Offset1);
            GtWrite((GLOBAL_TABLE_INDEX)0x820, Offset2);
            Result = 1;
        }
    }

    return Result;
}
__int64 ParseNtSectionsForRelocBase(void)
{
    __int64 Result;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int TargetRva;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int FieldValue;
    unsigned int TrackedOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 SectionFlags;
    __int64 FieldFlags;
    int FieldCount;
    int SectionDataSize;

    Result = 0;
    // 【读序修正 2026-10-13】原始读序为 0x20 → 0x21 → 3 → 0x43F9 → 0x43F0
    //   （见原始 0x1400430C0/0CD/0DA/0E7/0F4），原稿把 0x43F9/0x43F0 提前了。
    //   索引集合相同，仅顺序不同；此处按原始顺序调整以便差分逐项对齐。
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43F9);
    TargetRva = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43F0);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);

    if (BaseOffset &&
        BaseOffset < NtImageSize &&
        NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        NtoskrnlImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        TrackedOffset = 0;
        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            SectionFlags = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            FieldCount = *(int *)&EntryBuffer[0x30];
            SectionDataSize = *(int *)&EntryBuffer[0x38];

            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x558 &&
                (SectionFlags & 0x4000000) != 0 &&
                SectionDataSize)
            {
                FieldValue = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                if (FieldValue == TargetRva &&
                    TrackedOffset &&
                    TrackedOffset < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x829, NtoskrnlModuleBase + TrackedOffset);
                    Result = 1;
                    break;
                }
            }

            if (SectionType == 0x512 &&
                FieldFlags == 0x40000 &&
                FieldCount == 1 &&
                SectionDataSize)
            {
                TrackedOffset = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            }

            ++SectionIndex;
        }
    }

    return Result;
}
__int64 ParseProcessMemSections(void)
{
    __int64 Result;
    unsigned int BaseOffset;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    int NtoskrnlImageSize;
    unsigned int BuildNumber;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned short SectionType;
    unsigned int Phase1Offset;
    unsigned int Phase2Offset;
    unsigned int Phase2aOffset;
    unsigned int Phase2bOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    int SectionDataSize;
    __int64 FieldFlags;
    int FieldCount;

    Result = 0;
    // 【读序修正】原始读序 0x20 → 0x21 → 3 → 0x43EA。
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43EA);
    NtoskrnlImageSize = (int)GtRead(GtNtoskrnlImageSize);
    BuildNumber = (unsigned int)GtRead(GtWindowsBuildNumber);

    if (!BaseOffset ||
        BaseOffset >= NtImageSize ||
        !NtImageBase ||
        !NtImageSize ||
        !NtoskrnlModuleBase ||
        !NtoskrnlImageSize)
    {
        return Result;
    }

    // 第一阶段：扫描最多 6 个节区，查找 Type 0x558(1368) 的有效偏移
    InitPESectionReadContext(
        (__int64)(NtImageBase + BaseOffset),
        NtImageSize - BaseOffset,
        2,
        0,
        -1,
        0,
        0,
        (__int64)&DecodeContext);

    Phase1Offset = 0;
    SectionIndex = 0;
    while (SectionIndex < 6)
    {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
            break;

        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        CumulativeOffset = (int)CumulativeSize;

        SectionDataSize = *(int *)&EntryBuffer[0x38];
        SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

        if (SectionType == 0x558 && SectionDataSize)
        {
            unsigned int TempOffset = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            if (TempOffset && TempOffset < NtImageSize)
            {
                Phase1Offset = TempOffset;
                break;
            }
        }

        ++SectionIndex;
    }

    if (!Phase1Offset || Phase1Offset >= NtImageSize)
        return Result;

    // 第二阶段：根据构建号选择不同的查找策略
    Phase2Offset = 0;
    Phase2aOffset = 0;
    Phase2bOffset = 0;

    if (BuildNumber >= 0x2800)
    {
        // Win10 1511+：验证 Type 0x510(1296) 和 Type 0x50E(1294) 的匹配偏移
        InitPESectionReadContext(
            (__int64)(NtImageBase + Phase1Offset),
            NtImageSize - Phase1Offset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            SectionDataSize = *(int *)&EntryBuffer[0x38];
            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x510 &&
                FieldFlags == 0x40000 &&
                SectionDataSize)
            {
                Phase2aOffset = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            }

            if (SectionType == 0x50E &&
                FieldFlags == 0x40000 &&
                SectionDataSize)
            {
                Phase2bOffset = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
            }

            ++SectionIndex;
        }

        if (Phase2aOffset && Phase2aOffset < NtImageSize &&
            Phase2bOffset && Phase2bOffset < NtImageSize &&
            Phase2aOffset == Phase2bOffset)
        {
            Phase2Offset = Phase2aOffset;
        }
    }
    else
    {
        // < Win10 1511：查找 Type 0x50E(1294) 且 FieldCount==3 的节区
        InitPESectionReadContext(
            (__int64)(NtImageBase + Phase1Offset),
            NtImageSize - Phase1Offset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            FieldCount = *(int *)&EntryBuffer[0x30];
            SectionDataSize = *(int *)&EntryBuffer[0x38];
            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x50E &&
                FieldFlags == 0x40000 &&
                FieldCount == 3 &&
                SectionDataSize)
            {
                Phase2Offset = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                break;
            }

            ++SectionIndex;
        }
    }

    if (Phase2Offset && Phase2Offset < NtImageSize)
    {
        GtWrite((GLOBAL_TABLE_INDEX)0x828, NtoskrnlModuleBase + Phase2Offset);
        Result = 1;
    }

    return Result;
}
__int64 FindKernelDataSectionOffset(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) > 0x23F0)
        return FindKernelDataSectionOffsetWin8();
    else
        return FindKernelDataSectionOffsetWin7();
}
__int64 FindKernelDataSectionOffsetEx(void)
{
    __int64 Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlImageBase;
    int TargetSectionRva;
    unsigned int TargetOffset;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned int BaseOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    __int64 SectionFlags;
    __int64 FieldFlags;
    int SectionDataSize;
    unsigned short SectionType;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    TargetSectionRva = (int)GtRead((GLOBAL_TABLE_INDEX)0x43F0);
    BaseOffset = (unsigned int)GtRead(GtNtWriteFilePeSectionOffset);

    if (NtImageBase &&
        NtImageSize &&
        NtoskrnlImageBase &&
        TargetSectionRva &&
        BaseOffset &&
        BaseOffset < NtImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        TargetOffset = 0;
        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            SectionFlags = *(__int64 *)&EntryBuffer[0x20];
            SectionDataSize = *(int *)&EntryBuffer[0x38];
            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x558 &&
                (SectionFlags & 0x4000000) != 0 &&
                SectionDataSize)
            {
                unsigned int MatchRva = CumulativeOffset + SectionDataSize - (unsigned int)NtImageBase;
                if (MatchRva == (unsigned int)TargetSectionRva &&
                    TargetOffset &&
                    TargetOffset < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x822, NtoskrnlImageBase + TargetOffset);
                    Result = 1;
                    break;
                }
            }

            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            if (FieldFlags == 0x40000)
            {
                unsigned int RawDataSize = *(unsigned int *)&EntryBuffer[0x38];
                if (RawDataSize)
                    TargetOffset = CumulativeOffset + RawDataSize - (unsigned int)NtImageBase;
            }

            ++SectionIndex;
        }
    }

    return Result;
}
__int64 FindKernelDataSectionOffsetV2(void)
{
    __int64 Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    unsigned int BaseOffset;
    unsigned int SectionIndex;
    int CumulativeOffset;
    unsigned int FoundOffset;
    int FoundCount;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    unsigned short SectionType;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    unsigned int ValueField;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43C0);

    if (NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        BaseOffset &&
        BaseOffset < NtImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        FoundOffset = 0;
        FoundCount = 0;
        SectionIndex = 0;
        while (SectionIndex < 0x12C)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            ValueField = *(unsigned int *)&EntryBuffer[0x10];
            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x510 &&
                FieldFlags == 0x40000 &&
                FieldValueSize == 0x40 &&
                ValueField)
            {
                FoundOffset = ValueField - (unsigned int)NtImageBase + CumulativeOffset;
                FoundCount = 1;
            }

            if (FoundCount == 1 &&
                SectionType == 0x512 &&
                ValueField)
            {
                unsigned int Offset2 = ValueField - (unsigned int)NtImageBase + CumulativeOffset;
                if (Offset2 &&
                    Offset2 < NtImageSize &&
                    FoundOffset &&
                    FoundOffset < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x827, NtoskrnlModuleBase + FoundOffset);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    return Result;
}
__int64 FindKernelDataSectionOffsetV3(void)
{
    __int64 Result;
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlModuleBase;
    unsigned int BaseOffset;
    unsigned int SectionIndex;
    int CumulativeOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    char EntryBuffer[0x120];
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 pSectionEntryBase;
    unsigned short SectionType;
    __int64 FieldValueSize;
    __int64 FieldFlags;
    unsigned int ValueField;

    Result = 0;
    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlModuleBase = GtRead(GtNtoskrnlModuleBase);
    BaseOffset = (unsigned int)GtRead((GLOBAL_TABLE_INDEX)0x43BD);

    if (NtImageBase &&
        NtImageSize &&
        NtoskrnlModuleBase &&
        BaseOffset &&
        BaseOffset < NtImageSize)
    {
        InitPESectionReadContext(
            (__int64)(NtImageBase + BaseOffset),
            NtImageSize - BaseOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&DecodeContext);

        SectionIndex = 0;
        while (SectionIndex < 0x64)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            RtlZeroMemory(EntryBuffer, sizeof(EntryBuffer));

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&DecodeContext, (PULONG)EntryBuffer))
                break;

            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
            CumulativeSize += SectionSize;
            pSectionEntryBase = *(__int64 *)&EntryBuffer[0x48];
            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
            CumulativeOffset = (int)CumulativeSize;

            FieldValueSize = *(__int64 *)&EntryBuffer[0x20];
            FieldFlags = *(__int64 *)&EntryBuffer[0x28];
            ValueField = *(unsigned int *)&EntryBuffer[0x10];
            SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

            if (SectionType == 0x512 &&
                FieldFlags == 0x40000 &&
                FieldValueSize == 0x40 &&
                ValueField)
            {
                unsigned int FoundOffset = ValueField - (unsigned int)NtImageBase + CumulativeOffset;
                if (FoundOffset && FoundOffset < NtImageSize)
                {
                    GtWrite((GLOBAL_TABLE_INDEX)0x826, NtoskrnlModuleBase + FoundOffset);
                    Result = 1;
                    break;
                }
            }

            ++SectionIndex;
        }
    }

    return Result;
}
__int64 DispatchFindKernelDataSection(void)
{
    if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x42EE)
        return FindKernelDataSectionPair();
    else
        return FindKernelDataSectionOffsetWin10();
}
__int64 FindPESectionByOffset(unsigned int SectionOffset)
{
    __int64 BaseOffset;
    unsigned int MaxSize;
    __int64 NtoskrnlBase;
    int ImageSize;
    __int64 Result;
    unsigned int i;
    ULONG SectionEntry[112];        // 描述符：原 [14] 仅 56 字节（ReadPESectionEntry 写 0x120）
    PE_DECODE_CONTEXT Context;      // 0x48 字节解码上下文（原 char[16] 仅 16 字节，栈越界）
    int CurrentOffset;
    unsigned int ResultOffset;
    ULONG SectionSize;              // 描述符 +0xF0（指令长度）
    int EntrySize;                  // 描述符 +0x38（RVA 候选字段）

    BaseOffset = GtRead(GtEprocessField22);
    MaxSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    ImageSize = (int)GtRead(GtNtoskrnlImageSize);
    Result = GtRead(GtWindowsBuildNumber);

    if ((unsigned int)Result >= 0xA28
        && BaseOffset
        && MaxSize
        && NtoskrnlBase
        && ImageSize
        && SectionOffset
        && SectionOffset < MaxSize)
    {
        InitPESectionReadContext(
            (__int64)((ULONG64)SectionOffset + BaseOffset),
            (ULONG)(MaxSize - SectionOffset),
            2, 0, -1, 0, 0,
            (__int64)&Context);

        for (i = 0; i < 0x14; i++)
        {
            Result = ReadPESectionEntry((PUCHAR)&Context, SectionEntry);
            if (Result != 0)
                break;

            // 累计位置 = 本条长度 + 读指针（自增前的值）；随后推进读指针
            SectionSize = *(ULONG *)((PUCHAR)SectionEntry + 0xF0);
            CurrentOffset = (int)((ULONG)Context.ReadPtr + SectionSize);
            Context.ReadPtr += SectionSize;
            EntrySize = *(int *)((PUCHAR)SectionEntry + 0x38);

            // 检查节区类型是否为1368(0x558)或1369(0x559)
            // 类型取自描述符 +0x118 处指针所指向结构的 +6
            if ((unsigned short)(*(USHORT *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) - 1368) <= 1)
            {
                if (EntrySize)
                {
                    ResultOffset = (unsigned int)(CurrentOffset + EntrySize - (int)BaseOffset);
                    if (ResultOffset)
                    {
                        if (ResultOffset < MaxSize)
                        {
                            if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x1DB0)
                                FindPESectionByIndex(ResultOffset);
                            return GtWrite(GtCallbackField02, NtoskrnlBase + ResultOffset);
                        }
                    }
                }
            }
        }
    }
    return Result;
}
__int64 FindKernelDataSectionOffsetWin7(void)
{
    __int64 Result = 0;
    __int64 PeFileBase;
    unsigned int PeFileSize;
    __int64 NtoskrnlBase;
    __int64 PeScanBase2;
    __int64 PeScanBase3;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int EntryCount;
    char Phase1Found;
    ULONG EntryBuffer[0x80];

    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    PeScanBase2 = GtRead(GtNtoskrnlPeScanBase2);
    PeScanBase3 = GtRead(GtNtoskrnlPeScanBase3);
    if (!PeFileBase || !NtoskrnlBase || !PeScanBase2 || !PeScanBase3 || !PeFileSize)
        return 0;

    unsigned int ExportDirSize = *(unsigned int *)(PeFileBase + 0x3C);
    ExportDirSize = *(unsigned int *)(ExportDirSize + PeFileBase);
    if (!ExportDirSize || ExportDirSize >= PeFileSize)
        return 0;

    InitPESectionReadContext((__int64)((PUCHAR)PeFileBase + ExportDirSize), PeFileSize - ExportDirSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    EntryCount = 0;
    Phase1Found = 0;
    while (EntryCount < 0x64)
    {
            *(ULONG64 *)((PUCHAR)&PeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x58 >> 2];
        CumulativeSize = EntryBuffer[0x190 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x30 >> 2];
        EntryBuffer[0x190 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

        if (SectionType == 0x558)
        {
            __int64 F8 = EntryBuffer[0xF8 >> 2];
            if ((F8 & 0x4000000) && EntryBuffer[0x110 >> 2])
            {
                int Offset = (int)EntryBuffer[0x110 >> 2] - (int)PeFileBase + (int)CumulativeSize;
                if ((unsigned int)Offset == PeScanBase3)
                {
                    Phase1Found = 1;
                }
            }
        }
        else if (Phase1Found)
        {
            __int64 C0 = EntryBuffer[0xC0 >> 2];
            unsigned int D0 = EntryBuffer[0xD0 >> 2];
            if (C0 == 0x40000 && D0)
            {
                int Offset = (int)D0 - (int)PeFileBase + (int)CumulativeSize;
                if (Offset && (unsigned int)Offset < PeFileSize)
                {
                    Result = Offset + PeScanBase2;
                    GtWrite(GtKernelDataSectionOffset, Result);
                    break;
                }
            }
        }
        ++EntryCount;
    }

    return Result;
}
__int64 FindKernelDataSectionOffsetWin10(void)
{
    __int64 Result = 0;
    __int64 PeFileBase;
    unsigned int PeFileSize;
    __int64 NtoskrnlBase;
    __int64 PeScanBase3;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int EntryCount;
    int Offset1;
    int Offset2;
    ULONG EntryBuffer[0x80];

    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    PeScanBase3 = GtRead(GtNtoskrnlPeScanBase3);
    if (!PeFileBase || !NtoskrnlBase || !PeScanBase3 || !PeFileSize)
        return 0;

    InitPESectionReadContext((__int64)(PUCHAR)PeFileBase, PeFileSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    EntryCount = 0;
    Offset1 = 0;
    Offset2 = 0;
    while (EntryCount < 0x64)
    {
            *(ULONG64 *)((PUCHAR)&PeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x58 >> 2];
        CumulativeSize = EntryBuffer[0x190 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x30 >> 2];
        EntryBuffer[0x190 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

        if (SectionType == 0x512)
        {
            __int64 C0 = EntryBuffer[0xC0 >> 2];
            unsigned int D0 = EntryBuffer[0xD0 >> 2];
            __int64 F8 = EntryBuffer[0xF8 >> 2];
            if (C0 == 0x40000 && D0 && F8 == 0x40)
            {
                int Offset = (int)D0 - (int)PeFileBase + (int)CumulativeSize;
                if (Offset && (unsigned int)Offset < PeFileSize)
                    Offset1 = Offset;
            }
        }
        else if (SectionType == 0x471)
        {
            __int64 F8 = EntryBuffer[0xF8 >> 2];
            unsigned int D0 = EntryBuffer[0xD0 >> 2];
            if (F8 == 0x40000 && D0)
            {
                int Offset = (int)D0 - (int)PeFileBase + (int)CumulativeSize;
                if (Offset && (unsigned int)Offset < PeFileSize)
                    Offset2 = Offset;
            }
        }
        ++EntryCount;
    }

    if (Offset1 && Offset1 < (int)PeFileSize)
        GtWrite(GtKernelDataSectionOffset2, Offset1 + PeScanBase3);
    if (Offset2 && Offset2 < (int)PeFileSize)
        GtWrite(GtKernelDataSectionOffset3, Offset2 + PeScanBase3);

    Result = Offset1;
    return Result;
}
__int64 FindKernelDataSectionPair(void)
{
    __int64 Result = 0;
    __int64 PeFileBase;
    unsigned int PeFileSize;
    __int64 NtoskrnlBase;
    __int64 PeScanBase3;
    __int64 PeContext;
    unsigned int SectionSize;
    __int64 CumulativeSize;
    __int64 SectionDataPtr;
    unsigned short SectionType;
    unsigned int EntryCount;
    int Offset1;
    int Offset2;
    ULONG EntryBuffer[0x80];

    GtWrite(GtKernelDataSectionOffset2, 0);
    GtWrite(GtKernelDataSectionOffset3, 0);

    PeFileBase = GtRead(GtNtoskrnlPeFileBase);
    PeFileSize = (unsigned int)GtRead(GtNtoskrnlPeFileSize);
    NtoskrnlBase = GtRead(GtNtoskrnlModuleBase);
    PeScanBase3 = GtRead(GtNtoskrnlPeScanBase3);
    if (!PeFileBase || !NtoskrnlBase || !PeScanBase3 || !PeFileSize)
        return 0;

    InitPESectionReadContext((__int64)(PUCHAR)PeFileBase, PeFileSize, 2, (LONG64)&PeContext, -1, 0, 0, (__int64)&EntryBuffer);
    EntryCount = 0;
    Offset1 = 0;
    Offset2 = 0;
    while (EntryCount < 0x64)
    {
            *(ULONG64 *)((PUCHAR)&PeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = EntryBuffer[0x58 >> 2];
        CumulativeSize = EntryBuffer[0x190 >> 2];
        CumulativeSize += SectionSize;
        SectionDataPtr = EntryBuffer[0x30 >> 2];
        EntryBuffer[0x190 >> 2] = (ULONG)CumulativeSize;
        SectionType = *(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6);

        if (SectionType == 0x510)
        {
            __int64 F8 = EntryBuffer[0xF8 >> 2];
            __int64 C0 = EntryBuffer[0xC0 >> 2];
            unsigned int D0 = EntryBuffer[0xD0 >> 2];
            if (F8 == 0x40 && C0 == 0x40000 && D0)
            {
                int Offset = (int)D0 - (int)PeFileBase + (int)CumulativeSize;
                if (Offset)
                    Offset1 = Offset;
            }
        }
        else if (SectionType == 0x512)
        {
            __int64 C0 = EntryBuffer[0xC0 >> 2];
            __int64 F8 = EntryBuffer[0xF8 >> 2];
            unsigned int D0 = EntryBuffer[0xD0 >> 2];
            if (C0 == 0x40000 && F8 == 0x40 && D0)
            {
                int Offset = (int)D0 - (int)PeFileBase + (int)CumulativeSize;
                if (Offset)
                    Offset2 = Offset;
            }
        }

        // 检查偏移对是否相差 8 字节
        if (Offset1 && Offset2)
        {
            int Diff = Offset1 - Offset2;
            if (Diff < 0)
                Diff = Offset2 - Offset1;
            if (Diff == 8)
            {
                int Smaller = (Offset1 < Offset2) ? Offset1 : Offset2;
                if (Smaller && (unsigned int)Smaller < PeFileSize)
                {
                    GtWrite(GtKernelDataSectionOffset2, Smaller + PeScanBase3);
                    Result = Smaller;
                }
                break;
            }
        }
        ++EntryCount;
    }

    return Result;
}
__int64 FindPESectionByIndex(unsigned int SectionIndex)
{
    __int64 Result = 0;
    __int64 PeBase = GtRead(GtNtoskrnlModuleBase);
    unsigned int PeSize = (unsigned int)GtRead(GtNtoskrnlImageSize);
    if (!PeBase || !PeSize)
        return Result;
    if (MmIsAddressValid((void *)PeBase) != 1)
        return Result;
    if (SectionIndex >= 0x10)
        return Result;
    Result = 1;
    return Result;
}
char FindHalInitPatternOffsets(__int64 FileBuffer, unsigned int FileSize)
{
    char Result = 0;
    if (!FileBuffer || !FileSize || (unsigned __int64)FileBuffer < (unsigned __int64)MmSystemRangeStart)
        return Result;
    if (MmIsAddressValid((void *)FileBuffer) != 1)
        return Result;
    if (FileSize < 0x1000)
        return Result;
    Result = 1;
    return Result;
}
__int64 FindKernelDataSectionOffsetWin8(void)
{
    __int64 NtImageBase;
    unsigned int NtImageSize;
    __int64 NtoskrnlImageBase;
    __int64 Result = 0;
    int SectionOffset = 0;
    unsigned int SectionIndex;
    __int64 ComputedOffset;
    PE_DECODE_CONTEXT DecodeContext;   // 0x48 字节解码上下文（原名为 SectionContext，名字与角色不符；死写已删）
    __int64 AccumulatedOffset;
    ULONG SectionEntry[0x80];
    unsigned int RawDataSize;
    __int64 SectionCharacteristics;
    unsigned short SectionType;

    NtImageBase = GtRead(GtEprocessField22);
    NtImageSize = (unsigned int)GtRead(GtEprocessField23);
    NtoskrnlImageBase = GtRead(GtNtoskrnlModuleBase);
    Result = GtRead(GtNtoskrnlPeScanBase);
    if (NtImageBase && NtImageSize && NtoskrnlImageBase && (_DWORD)Result &&
        (unsigned int)Result < NtImageSize)
    {
        InitPESectionReadContext((__int64)((PUCHAR)NtImageBase + (unsigned int)Result),
            NtImageSize - (unsigned int)Result, 2, 0, -1, 0, 0, (__int64)&DecodeContext);
        SectionOffset = 0;
        AccumulatedOffset = 0;
        for (SectionIndex = 0; SectionIndex < 0x64; ++SectionIndex)
        {
            *(ULONG64 *)((PUCHAR)&DecodeContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            Result = ReadPESectionEntry((PUCHAR)&DecodeContext, SectionEntry);
            if ((_DWORD)Result)
                break;
            ComputedOffset = SectionEntry[0xF0 >> 2] + AccumulatedOffset;
            AccumulatedOffset += SectionEntry[0xF0 >> 2];
            SectionType = *(unsigned short *)((ULONG_PTR)SectionEntry[0x118 >> 2] + 6);
            RawDataSize = SectionEntry[0x78 >> 2];
            SectionCharacteristics = SectionEntry[0x88 >> 2];
            if (SectionType == 1296 && SectionCharacteristics == 0x40000 && RawDataSize)
            {
                SectionOffset = (int)(ComputedOffset + RawDataSize - NtImageBase);
            }
            else if (SectionType == 1298 && SectionCharacteristics == 0x40000)
            {
                if (RawDataSize)
                {
                    Result = ComputedOffset + RawDataSize - (unsigned int)NtImageBase;
                    if ((_DWORD)Result)
                    {
                        if ((unsigned int)Result < NtImageSize && SectionOffset == (_DWORD)Result)
                            return GtWrite(GtKernelDataSectionOffset, NtoskrnlImageBase + (unsigned int)Result);
                    }
                }
            }
        }
    }
    return Result;
}
