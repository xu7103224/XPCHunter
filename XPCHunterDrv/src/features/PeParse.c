// MissingFuncs.c — 暂未分配到各源文件的函数实现
// 1:1 复刻自 View++_Driver64.sys（PCHunter 驱动）
#include "XPCHunterDrv.h"

// C4700 抑制：各种函数中变量由间接路径初始化，编译器无法跟踪代码路径
#pragma warning(disable:4700)
#include <intrin.h>

// 前向声明 — 定义在 Protocol.c 中
extern NTSTATUS IrpReadCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// 前向声明 — 内部辅助函数
extern char OpenDeviceTarget(__int64 EncodedPath, __int64 *pDeviceHandle, __int64 *pDeviceObjectHandle);
extern __int64 GetDeviceObjectFromContext(__int64 DeviceHandle);
extern char GetDiskDriverInfo(char State, void *pBuffer, __int64 *pFuncTable);
extern char SetDiskDriverInfo(char State, char Flags, void *pBuffer);
extern char FindPeSectionByTypeRsrc(__int64 Buffer, unsigned int Size, __int64 Address);
extern char FindPatchThreadWindowsExport(__int64 FileBuffer, unsigned int FileSize);
extern __int64 ResolveKernelModuleIndexAddress(int ModuleId, int GtIndex);
extern __int64 ResolveAndStoreKernelModuleAddress(int ModuleId, int GtIndex);
extern __int64 ReadIoPortDataForProcess(__int64 CpuIndex, __int64 IoPortContext);
extern __int64 ReadWriteKernelMemory(void);

// =======================================================================
// 简单函数实现
// =======================================================================

__int64 FindHookTargetDataSection(__int64 ModuleBase, unsigned int ModuleSize, __int64 Context, __int64 RelocBase)
{
    __int64 result;
    int EndAddress;
    __int64 SectionBase;
    int SectionIndex;
    int MatchSize;
    unsigned int TargetOffset;
    unsigned int LoopIndex;
    int MatchSize2;
    __int16 SubType;
    __int64 ResultAddress;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    /* 【修正 2026-10-16】以下"字段"原始是 SectionEntry 描述符的偏移（ReadPESectionEntry 就地填充），
       不是独立局部变量。原实现声明为独立局部且从不赋值（恒 0）→ 扫描条件永不成立。
       偏移来源：原始 sub_14001D1EC 反汇编（描述符基址 rbp-0x148）。 */
#define EntryCharacteristics PE_DESC_ENTRY_SIZE(SectionEntry)   /* +0x38 */
#define FieldValue           PE_DESC_FIELD_VALUE(SectionEntry)  /* +0x50 */
#define EntryFlags           PE_DESC_FIELD_SIZE(SectionEntry)   /* +0x78 */
#define FieldValue2          PE_DESC_FIELD_VALUE2(SectionEntry) /* +0x88 */
#define SectionSize          PE_DESC_SECTION_SIZE(SectionEntry) /* +0xF0 */
#define SectionDataPtr       PE_DESC_SECTION_DATA(SectionEntry) /* +0x118 */
#define EntrySize            PE_DESC_ENTRY_SIZE(SectionEntry)   /* +0x38（同 EntryCharacteristics） */

    result = GtRead(GtFindHookTargetDataPeOffset);
    if ((_DWORD)result && (unsigned int)result < ModuleSize)
    {
        EndAddress = (int)(ModuleBase + ModuleSize);
        SectionBase = ModuleBase + (unsigned int)result;
        if ((unsigned int)GtRead(GtWindowsBuildNumber) >= 0x2800)
        {
            InitPESectionReadContext((__int64)SectionBase, (ULONG)(EndAddress - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            SectionIndex = 0;
            while (1)
            {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    goto LABEL_13;
                MatchSize = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368)
                {
                    if (EntryCharacteristics)
                        break;
                }
                if ((unsigned int)++SectionIndex >= 7)
                    goto LABEL_13;
            }
            TargetOffset = (unsigned int)(MatchSize + EntryCharacteristics - ModuleBase);
            if (TargetOffset && TargetOffset < ModuleSize)
                SectionBase = ModuleBase + TargetOffset;
        }
LABEL_13:
        InitPESectionReadContext((__int64)SectionBase, (ULONG)(EndAddress - SectionBase), 2, 0, -1, 0, 0, (__int64)&ReadContext);
        for (LoopIndex = 0; LoopIndex < 0xC8; ++LoopIndex)
        {
            result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)result)
                return result;
            MatchSize2 = (int)(SectionSize + CumulativeSize);
            CumulativeSize += SectionSize;
            SubType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            result = EntryFlags;
            if (SubType == 1298 && FieldValue2 == 0x40000 && EntryFlags)
            {
                result = MatchSize2 + EntryFlags - (unsigned int)ModuleBase;
                if ((_DWORD)result && (unsigned int)result < ModuleSize)
                {
                    ResultAddress = RelocBase + (unsigned int)result;
                    return GtWrite(GtCallbackField00, ResultAddress);
                }
            }
            else if (SubType == 1296
                && FieldValue2 == 65607
                && EntryFlags
                && EntrySize == 8
                && FieldValue == 64
                && EntryFlags < ModuleSize)
            {
                ResultAddress = RelocBase + EntryFlags;
                return GtWrite(GtCallbackField00, ResultAddress);
            }
        }
    }
    return result;
}
#undef EntryCharacteristics
#undef FieldValue
#undef EntryFlags
#undef FieldValue2
#undef SectionSize
#undef SectionDataPtr
#undef EntrySize

char ComparePeModuleSignature(char *pSignature1, __int64 Signature2, unsigned int SignatureSize)
{
    char Result;

    Result = 0;
    if (SignatureSize >= 0xD)
    {
        if ((unsigned int)MemoryCompare(Signature2, pSignature1, 0xDu))
        {
            if (!(unsigned int)MemoryCompare(Signature2, pSignature1, 8u))
                return pSignature1[12] == *(_BYTE *)(Signature2 + 12);
        }
        else
        {
            return 1;
        }
    }
    return Result;
}

char FindExportInFileByName(__int64 PeBase, unsigned int PeSize, __int64 OutEntry)
{
    char Result;
    __int64 ExportTableBase;
    unsigned int ExportByNameInPeBody;
    _WORD FuncNameBuffer[16];

    Result = 0;
    ExportTableBase = GtRead(GtFsFilterExportTable);
    if (ExportTableBase)
    {
        strcpy((char *)FuncNameBuffer, "ClassSpinDownPowerHandler");
        FuncNameBuffer[13] = 0;
        ExportByNameInPeBody = (unsigned int)FindExportByNameInPeBody((PUCHAR)PeBase, PeSize, (PCHAR)FuncNameBuffer, 0);
        if (ExportByNameInPeBody)
        {
            if (ExportByNameInPeBody < PeSize)
            {
                *(_DWORD *)(OutEntry + 4) = ExportByNameInPeBody;
                Result = 1;
                *(_QWORD *)(OutEntry + 8) = ExportTableBase + ExportByNameInPeBody;
            }
        }
    }
    return Result;
}

__int64 FixCreateFileRelocs(__int64 TargetBase, unsigned int TargetSize, __int64 Context, __int64 RelocBase)
{
    int Target1;
    int Target2;
    int Target3;
    __int64 Result;
    unsigned int LoopIndex1;
    int Offset1;
    unsigned int i;
    int Offset2;
    unsigned int LoopIndex2;
    int Offset3;
    unsigned int j;
    unsigned int FirstRelocOffset;
    unsigned int SecondRelocOffset;
    unsigned int LoopIndex3;
    int CurrentOffset;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    unsigned int EntrySize;
    int EntryFlags;
    __int64 SectionFlags;
    unsigned int SectionSize;
    __int64 SectionType;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    Target1 = (int)GtRead(GtNtWriteFilePeSectionOffset | GtObjectTypeField08);
    Target2 = (int)GtRead(GtTotalSize | GtObjectTypeField18);
    Target3 = (int)GtRead(GtTotalSize | GtEprocessField187 | 0x100);
    Result = GtRead(GtNtCreateFileSyscallResult);
    if (Target1 && Target2 && Target3 && (_DWORD)Result && (unsigned int)Result < TargetSize)
    {
        InitPESectionReadContext(
            TargetBase + (unsigned int)Result,
            TargetSize - (unsigned int)Result,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);
        for (LoopIndex1 = 0; LoopIndex1 < 0x3E8; ++LoopIndex1)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                break;
            /* 【重大修正 2026-10-17】以下字段都是**描述符内的槽**（偏移由原始 0x14001E044 的
               栈帧确定：SectionType=+0x38、EntryFlags=+0x40、SectionFlags=+0x50、EntrySize=+0x78、
               SectionSize=+0x88、EntryCumulSize=+0xF0、EntryDataPtr=+0x118）。旧移植把它们
               另立为独立局部且从不赋值 → 编译器把 `*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成
               绝对地址 [6] → 实机 0x7E。 */
            SectionType    = *(__int64 *)((PUCHAR)SectionEntry + 0x38);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x40);
            SectionFlags   = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntrySize      = *(unsigned int *)((PUCHAR)SectionEntry + 0x78);
            SectionSize    = *(unsigned int *)((PUCHAR)SectionEntry + 0x88);
            EntryCumulSize = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            EntryDataPtr   = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
            Offset1 = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
            {
                if (EntrySize)
                {
                    Result = Offset1 + EntrySize - (unsigned int)TargetBase;
                    if (Target1 == (_DWORD)Result)
                    {
                        Target1 = 0;
                        break;
                    }
                }
            }
        }
        if (!Target1)
        {
            for (i = 0; i < 0x3E8; ++i)
            {
                Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
            /* 【重大修正 2026-10-17】以下字段都是**描述符内的槽**（偏移由原始 0x14001E044 的
               栈帧确定：SectionType=+0x38、EntryFlags=+0x40、SectionFlags=+0x50、EntrySize=+0x78、
               SectionSize=+0x88、EntryCumulSize=+0xF0、EntryDataPtr=+0x118）。旧移植把它们
               另立为独立局部且从不赋值 → 编译器把 `*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成
               绝对地址 [6] → 实机 0x7E。 */
            SectionType    = *(__int64 *)((PUCHAR)SectionEntry + 0x38);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x40);
            SectionFlags   = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntrySize      = *(unsigned int *)((PUCHAR)SectionEntry + 0x78);
            SectionSize    = *(unsigned int *)((PUCHAR)SectionEntry + 0x88);
            EntryCumulSize = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            EntryDataPtr   = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
                Offset2 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
                {
                    if (EntrySize)
                    {
                        Result = Offset2 + EntrySize - (unsigned int)TargetBase;
                        if (Target2 == (_DWORD)Result)
                        {
                            Target2 = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (!Target2)
        {
            for (LoopIndex2 = 0; LoopIndex2 < 0x64; ++LoopIndex2)
            {
                Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
            /* 【重大修正 2026-10-17】以下字段都是**描述符内的槽**（偏移由原始 0x14001E044 的
               栈帧确定：SectionType=+0x38、EntryFlags=+0x40、SectionFlags=+0x50、EntrySize=+0x78、
               SectionSize=+0x88、EntryCumulSize=+0xF0、EntryDataPtr=+0x118）。旧移植把它们
               另立为独立局部且从不赋值 → 编译器把 `*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成
               绝对地址 [6] → 实机 0x7E。 */
            SectionType    = *(__int64 *)((PUCHAR)SectionEntry + 0x38);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x40);
            SectionFlags   = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntrySize      = *(unsigned int *)((PUCHAR)SectionEntry + 0x78);
            SectionSize    = *(unsigned int *)((PUCHAR)SectionEntry + 0x88);
            EntryCumulSize = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            EntryDataPtr   = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
                Offset3 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
                {
                    if (EntrySize)
                    {
                        Result = Offset3 + EntrySize - (unsigned int)TargetBase;
                        if (Target3 == (_DWORD)Result)
                        {
                            Target3 = 0;
                            break;
                        }
                    }
                }
            }
        }
        if (!Target3)
        {
            for (j = 0; j < 0x1E; ++j)
            {
                Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                if ((_DWORD)Result)
                    break;
            /* 【重大修正 2026-10-17】以下字段都是**描述符内的槽**（偏移由原始 0x14001E044 的
               栈帧确定：SectionType=+0x38、EntryFlags=+0x40、SectionFlags=+0x50、EntrySize=+0x78、
               SectionSize=+0x88、EntryCumulSize=+0xF0、EntryDataPtr=+0x118）。旧移植把它们
               另立为独立局部且从不赋值 → 编译器把 `*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成
               绝对地址 [6] → 实机 0x7E。 */
            SectionType    = *(__int64 *)((PUCHAR)SectionEntry + 0x38);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x40);
            SectionFlags   = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntrySize      = *(unsigned int *)((PUCHAR)SectionEntry + 0x78);
            SectionSize    = *(unsigned int *)((PUCHAR)SectionEntry + 0x88);
            EntryCumulSize = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            EntryDataPtr   = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1294
                    && (SectionFlags & 0x40000) != 0
                    && EntryFlags
                    && (SectionType & 0x40) != 0)
                {
                    FirstRelocOffset = 0;
                    SecondRelocOffset = 0;
                    for (LoopIndex3 = 0; LoopIndex3 < 0x1E; ++LoopIndex3)
                    {
                        Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                        if ((_DWORD)Result)
                            break;
            /* 【重大修正 2026-10-17】以下字段都是**描述符内的槽**（偏移由原始 0x14001E044 的
               栈帧确定：SectionType=+0x38、EntryFlags=+0x40、SectionFlags=+0x50、EntrySize=+0x78、
               SectionSize=+0x88、EntryCumulSize=+0xF0、EntryDataPtr=+0x118）。旧移植把它们
               另立为独立局部且从不赋值 → 编译器把 `*(WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6)` 折叠成
               绝对地址 [6] → 实机 0x7E。 */
            SectionType    = *(__int64 *)((PUCHAR)SectionEntry + 0x38);
            EntryFlags     = *(int *)((PUCHAR)SectionEntry + 0x40);
            SectionFlags   = *(__int64 *)((PUCHAR)SectionEntry + 0x50);
            EntrySize      = *(unsigned int *)((PUCHAR)SectionEntry + 0x78);
            SectionSize    = *(unsigned int *)((PUCHAR)SectionEntry + 0x88);
            EntryCumulSize = *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);
            EntryDataPtr   = *(__int64 *)((PUCHAR)SectionEntry + 0x118);
                        CurrentOffset = (int)(EntryCumulSize + CumulativeSize);
                        CumulativeSize += EntryCumulSize;
                        if (SectionType == 0x40000)
                        {
                            if (SectionSize)
                            {
                                if ((SectionFlags & 0x20) == 0 || FirstRelocOffset)
                                {
                                    if ((SectionFlags & 0x40) != 0 && FirstRelocOffset)
                                    {
                                        SecondRelocOffset = (unsigned int)(CurrentOffset + SectionSize - (unsigned int)TargetBase);
                                        break;
                                    }
                                }
                                else
                                {
                                    FirstRelocOffset = (unsigned int)(CurrentOffset + SectionSize - (unsigned int)TargetBase);
                                }
                            }
                        }
                    }
                    if (FirstRelocOffset && SecondRelocOffset)
                    {
                        GtWrite(GtCallbackField116, RelocBase + SecondRelocOffset);
                        return GtWrite(GtCallbackField117, RelocBase + FirstRelocOffset);
                    }
                    return Result;
                }
            }
        }
    }
    return Result;
}

__int64 ParseNtExportFunctions(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    __int64 SectionAlignment;
    int SectionType;
    __int64 MiscInfo;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    __int64 Result;
    int Phase1Offset;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    char HasDiscardable;
    char HasCodeSection;
    char Found418;
    char MsrFlag1;
    char MsrFlag2;
    int SavedEntryCount;
    __int64 NtoskrnlBase;
    unsigned int ImageBase;
    unsigned int ImageSize;
    unsigned int DataDirRva;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>，见 L362/408/660/713）
                            //   又被取址当解码上下文；不能只改类型，需按"角色拆分"处理
                            //   （与 ContextMgmt.c 的 PeContext、CumulativeSize 家族同源）
    char EntryBuffer[448];              // 描述符：原 [80] 仅 80 字节
    __int64 PeFileData;

    Result = 0;
    NtoskrnlBase = GtRead(3);
    ImageBase = (unsigned int)GtRead(0x22);
    ImageSize = (unsigned int)GtRead(0x20);
    DataDirRva = (unsigned int)GtRead(0x21);
    if (!NtoskrnlBase || !ImageBase || !ImageSize || !DataDirRva)
        return Result;
    PeFileData = *(__int64 *)(ULONG_PTR)(ImageBase + 0x28);
    if (!PeFileData || (unsigned int)PeFileData >= DataDirRva)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((__int64)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, 0, -1, 0, 0, (__int64)&PeContext);
    HasDiscardable = 0;
    HasCodeSection = 0;
    Found418 = 0;
    MsrFlag1 = 0;
    MsrFlag2 = 0;
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
            *(ULONG64 *)((PUCHAR)&PeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x558)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment & 0x4000000)
            {
                FieldValue = *(int *)&EntryBuffer[0x20];
                if (FieldValue && HasDiscardable == 1)
                {
                    int Offset = FieldValue - (int)ImageSize + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < DataDirRva)
                    {
                        Phase1Offset = Offset;
                        break;
                    }
                }
            }
        }
        ++Phase1Count;
    }
    HasDiscardable = 0;
    HasCodeSection = 0;
    MsrFlag1 = 0;
    MsrFlag2 = 0;
    memset(Dst, 0, sizeof(Dst));
    LoopIndex = 0;
    SavedEntryCount = 0;
    PeContext = 0;
    InitPESectionReadContext((__int64)(ImageSize + Phase1Offset), DataDirRva + ImageSize - (ImageSize + Phase1Offset), 2, 0, -1, 0, 0, (__int64)&PeContext);
    while (LoopIndex < 0x1F4)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (!HasCodeSection)
        {
            if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x430)
            {
                if (!HasDiscardable)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment & 0x4000)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                        {
                            if (CumulativeSize == 0x400000000LL)
                            {
                                MiscInfo = *(__int64 *)&EntryBuffer[0x30 + 0x10];
                                if (MiscInfo == 0)
                                    HasCodeSection = 1;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x4DB)
            {
                if (!HasDiscardable)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment & 0x4000)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                        {
                            if (CumulativeSize == 0x20)
                                HasCodeSection = 1;
                        }
                    }
                }
            }
            else
            {
                if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0xFE)
                    HasDiscardable = 1;
            }
        }
        if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0xFE)
        {
            if (Phase1Offset && (unsigned int)Phase1Offset < DataDirRva)
            {
                if (MsrFlag1 == 0)
                    GtWrite(0x813, NtoskrnlBase + Phase1Offset);
                else if (MsrFlag2 != 0)
                    GtWrite(0x815, NtoskrnlBase + Phase1Offset);
                if (GtRead(0x813) && GtRead(0x815))
                    return Result;
            }
        }
        else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x512)
        {
            if (CumulativeSize == 0x40000)
            {
                EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                if (EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(int *)&EntryBuffer[0x18];
                        if ((SectionType & 0xFFFFFFFD) == 0)
                        {
                            Phase1Offset = EntrySize - (int)ImageSize + (int)CumulativeSize;
                        }
                    }
                }
            }
        }
        else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x53D)
        {
            if (CumulativeSize == 0x800000)
            {
                MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                if (MiscInfo == 0xC0000083)
                    MsrFlag1 = 1;
                else if (MiscInfo == 0xC0000082)
                    MsrFlag2 = 1;
            }
        }
        else if (HasCodeSection)
        {
            if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x512)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x40)
                    {
                        SectionType = *(int *)&EntryBuffer[0x18];
                        if (SectionType < 0x10)
                        {
                            Dst[SectionType] = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                                return Result;
                            SectionSize = *(unsigned int *)&EntryBuffer[0x38];
                            CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
                            CumulativeSize += SectionSize;
                            SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
                            *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
                            if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x512 &&
                                CumulativeSize == 0x40000 && EntrySize)
                            {
                                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                if (SectionAlignment == 0x40)
                                    Dst[SectionType] = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x418)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                    if (SectionAlignment == 0x80000)
                    {
                        MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                        if (MiscInfo == 0)
                        {
                            Found418 = 1;
                            int Offset = EntrySize - (int)ImageSize + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < DataDirRva)
                            {
                                if (!*(char *)(NtoskrnlBase + Offset))
                                    HasCodeSection = 0;
                                else
                                {
                                    if (GtRead(0x90D))
                                    {
                                        void *Fiber = j_GetCurrentFiber();
                                        if (Fiber)
                                            HasCodeSection = (*(char *)(GtRead(0x90D) + (__int64)Fiber) == 1) ? 2 : 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x4DA)
            {
                if (CumulativeSize == 0x40000 && EntrySize)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x90D))
                    {
                        if (EntrySize)
                        {
                            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                            if (SectionAlignment == 0x10041)
                            {
                                if (Found418)
                                    Dst[0] = SavedEntryCount;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x13E)
            {
                if (Dst[1] == 1)
                {
                    if (SavedEntryCount >= Dst[0] + 5)
                    {
                        if (HasCodeSection == 1)
                        {
                            FieldValue = *(int *)&EntryBuffer[0x20];
                            int Offset = FieldValue - (int)ImageSize + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < DataDirRva)
                            {
                                __int64 CheckAddr = NtoskrnlBase + Offset;
                                __int64 CurrentCumulative = CumulativeSize;
                                if (CheckAddr > CurrentCumulative || CheckAddr + 0x100 <= CurrentCumulative)
                                {
                                    if (CurrentCumulative > CheckAddr || CurrentCumulative + 0x100 <= CheckAddr)
                                    {
                                        if (ParseNtDataSectionRelocs((__int64)Dst, (int)NtoskrnlBase, (int)ImageSize, (_OWORD *)(ULONG_PTR)DataDirRva))
                                            HasCodeSection = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x510)
            {
                if (SectionAlignment == 0x40 && CumulativeSize == 0x40)
                {
                    /* match */
                }
            }
        }
        ++LoopIndex;
    }
    return Result;
}

__int64 ParseNtExportFunctionsV2(void)
{
    __int64 SectionDataPtr;
    unsigned int SectionSize;
    int FieldValue;
    __int64 SectionAlignment;
    int SectionType;
    __int64 MiscInfo;
    unsigned int EntrySize;
    __int64 CumulativeSize;
    __int64 Result;
    int Phase1Offset;
    int Phase1Type;
    unsigned int Phase1Count;
    unsigned int LoopIndex;
    int Dst[16];
    char HasDiscardable;
    char HasCodeSection;
    int DstIndex;
    unsigned int SavedEntryCount;
    __int64 NtoskrnlBase;
    unsigned int ImageBase;
    unsigned int DataDirRva;
    unsigned int ImageSize;
    __int64 PeContext;      // ⚠ 别名变量：既被当整数赋值（PeContext = <int>，见 L362/408/660/713）
                            //   又被取址当解码上下文；不能只改类型，需按"角色拆分"处理
                            //   （与 ContextMgmt.c 的 PeContext、CumulativeSize 家族同源）
    char EntryBuffer[448];              // 描述符：原 [80] 仅 80 字节
    __int64 PeFileData;

    Result = 0;
    NtoskrnlBase = GtRead(3);
    ImageBase = (unsigned int)GtRead(0x22);
    DataDirRva = (unsigned int)GtRead(0x20);
    ImageSize = (unsigned int)GtRead(0x21);
    if (!NtoskrnlBase || !ImageBase || !DataDirRva || !ImageSize)
        return Result;
    PeFileData = *(__int64 *)(ULONG_PTR)(ImageBase + 0x28);
    if (!PeFileData || (unsigned int)PeFileData >= ImageSize)
        return Result;
    PeContext = 0;
    InitPESectionReadContext((__int64)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, 0, -1, 0, 0, (__int64)&PeContext);
    HasDiscardable = 0;
    Phase1Offset = 0;
    Phase1Type = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
            *(ULONG64 *)((PUCHAR)&PeContext + 0x08) += *(unsigned int *)((PUCHAR)EntryBuffer + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x558)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment & 0x4000000)
            {
                FieldValue = *(int *)&EntryBuffer[0x20];
                if (FieldValue && HasDiscardable == 1)
                {
                    int Offset = FieldValue - (int)DataDirRva + (int)CumulativeSize;
                    if (Offset && (unsigned int)Offset < ImageSize)
                    {
                        Phase1Offset = Offset;
                        Phase1Type = Phase1Count;
                    }
                }
            }
        }
        else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x4D7)
        {
            SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
            if (SectionAlignment == 0x20 && CumulativeSize == 0x20)
            {
                SectionType = *(int *)&EntryBuffer[0x18];
                if (SectionType == 1)
                {
                    if (*(int *)&EntryBuffer[0x10] == 1 && Phase1Type && Phase1Type + 10 > (int)Phase1Count)
                        break;
                }
            }
        }
        ++Phase1Count;
    }
    if (!Phase1Offset)
        return Result;
    memset(Dst, 0, sizeof(Dst));
    Phase1Count = 0;
    PeContext = 0;
    InitPESectionReadContext((__int64)(DataDirRva + Phase1Offset), ImageSize + DataDirRva - (DataDirRva + Phase1Offset), 2, 0, -1, 0, 0, (__int64)&PeContext);
    HasCodeSection = 0;
    HasDiscardable = 0;
    LoopIndex = 0;
    SavedEntryCount = 0;
    while (LoopIndex < 0x1F4)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (!HasCodeSection)
        {
            if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x430)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment & 0x4000)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                    {
                        if (CumulativeSize == 0x400000000LL)
                        {
                            MiscInfo = *(__int64 *)&EntryBuffer[0x40];
                            if (MiscInfo == 0)
                                HasCodeSection = 1;
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x4DB)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment & 0x4000)
                {
                    if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x80E))
                    {
                        if (CumulativeSize == 0x20)
                            HasCodeSection = 1;
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x510)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment == 0x20 && (CumulativeSize & 0x4000))
                {
                    if (*(unsigned int *)&EntryBuffer[0x20] == (unsigned int)GtRead(0x80E))
                        HasCodeSection = 1;
                }
            }
        }
        if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0xFE)
        {
            if (Phase1Offset && (unsigned int)Phase1Offset < ImageSize)
            {
                if (HasDiscardable == 0)
                    GtWrite(0x813, NtoskrnlBase + Phase1Offset);
                else
                    GtWrite(0x815, NtoskrnlBase + Phase1Offset);
                if (GtRead(0x813) && GtRead(0x815))
                    return Result;
            }
        }
        else if (HasCodeSection)
        {
            if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x512)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize)
                    {
                        SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                        if (SectionAlignment == 0x40)
                        {
                            SectionType = *(int *)&EntryBuffer[0x18];
                            if (SectionType < 0x10)
                            {
                                Dst[SectionType] = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                                if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
                                    return Result;
                                SectionSize = *(unsigned int *)&EntryBuffer[0x38];
                                CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
                                CumulativeSize += SectionSize;
                                SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
                                *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
                                if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x512 &&
                                    CumulativeSize == 0x40000 && EntrySize)
                                {
                                    SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                    if (SectionAlignment == 0x40)
                                        Dst[SectionType] = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x418)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize && CumulativeSize == 0x80000)
                    {
                        MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                        if (MiscInfo == 0)
                        {
                            int Offset = EntrySize - (int)DataDirRva + (int)CumulativeSize;
                            if (Offset && (unsigned int)Offset < ImageSize)
                            {
                                if (!*(char *)(NtoskrnlBase + Offset))
                                    Phase1Count = 0;
                                else
                                {
                                    if (GtRead(0x90D))
                                    {
                                        void *Fiber = j_GetCurrentFiber();
                                        if (Fiber)
                                            Phase1Count = (*(char *)(GtRead(0x90D) + (__int64)Fiber) == 1) ? 2 : 1;
                                    }
                                }
                                HasCodeSection = 0;
                                HasDiscardable = 0;
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x4DA)
            {
                if (CumulativeSize == 0x40000)
                {
                    EntrySize = *(unsigned int *)&EntryBuffer[0x20];
                    if (EntrySize)
                    {
                        if (*(unsigned int *)&EntryBuffer[0x30] == (unsigned int)GtRead(0x90D))
                        {
                            if (EntrySize)
                            {
                                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                                if (SectionAlignment == 0x10041)
                                {
                                    DstIndex = 1;
                                    if (HasDiscardable)
                                        Dst[0] = SavedEntryCount;
                                }
                            }
                        }
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x510)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment == 0x40 && CumulativeSize == 0x40)
                {
                    SectionType = *(int *)&EntryBuffer[0x18];
                    if (SectionType == 2)
                    {
                        if (Dst[Dst[0x10]])
                            Phase1Offset = Dst[Dst[0x10]];
                    }
                }
            }
            else if (*(unsigned short *)(*(ULONG64 *)((PUCHAR)EntryBuffer + 0x118) + 6) == 0x53D)
            {
                if (CumulativeSize == 0x800000)
                {
                    MiscInfo = *(__int64 *)&EntryBuffer[0x30];
                    if (MiscInfo == 0xC0000083)
                        Phase1Type = 0;
                    else if (MiscInfo == 0xC0000082)
                        Phase1Type = 1;
                }
            }
        }
        ++SavedEntryCount;
        if (LoopIndex == 0)
            HasDiscardable = 0;
        ++LoopIndex;
    }
    return Result;
}

char ParseNtImageSections2(__int64 PeBase, unsigned int PeSize)
{
    unsigned int SectionRva;
    char TableBuilt;
    __int64 FileSize;
    unsigned int OptHeaderSize;
    char FoundInitSection;
    int SectionIndex;
    int SectionEnd;
    __int16 SectionType;
    unsigned int TargetRva;
    unsigned int TargetRva2;
    char FoundRelocSection;
    unsigned int LoopIndex;
    int SectionEnd2;
    __int16 SectionType2;
    unsigned int RelocRva;
    __int64 EntryIndex;
    unsigned int RelocBaseRva;
    __int64 TableSlot;
    __int64 FieldAddr;
    __int64 FieldOffset;
    _QWORD *pTargetEntry;
    __int64 EntryCount;
    unsigned __int64 *pFieldSrc;
    __int64 FieldRva;
    __int64 FillCount;
    char *pFillEntry;
    char TableBuilt2;
    unsigned int RelocRva2;
    __int64 NtoskrnlBase2;
    __int64 *pContextTable;
    __int64 *pTargetTable;
    unsigned __int64 ImageNtHeader;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    int FieldValue;
    int FieldValue2;
    __int64 SectionCharacteristics;
    unsigned int SectionEntryIndex;
    int FieldValueB;
    __int64 SectionDataPtr;
    int EntryIndex2;
    int FieldValueC;
    unsigned int SectionSize;
    __int64 SectionDataPtr2;
    _DWORD Dst[16];

    SectionRva = 0;
    TableBuilt = 0;
    TableBuilt2 = 0;
    FileSize = PeSize;
    NtoskrnlBase2 = GtRead(GtFltPeSectionOfs8 | GtEprocessField54);
    pContextTable = GtAlloc(GtEprocessModuleListOffset | GtPspExitThreadAddr | 0x3400);
    pTargetTable = GtAlloc((enum _GLOBAL_TABLE_INDEX)15650);
    if (NtoskrnlBase2)
    {
        OptHeaderSize = *(unsigned int *)(*(int *)(PeBase + 60) + PeBase + 40);
        ImageNtHeader = *(_QWORD *)(*(int *)(PeBase + 60) + PeBase + 48);
        if ((unsigned int)OptHeaderSize < (unsigned int)FileSize)
        {
            FoundInitSection = 0;
            InitPESectionReadContext((__int64)(PeBase + OptHeaderSize), (ULONG)(FileSize - OptHeaderSize), 2, 0, -1, 0, 0, (__int64)&ReadContext);
            SectionIndex = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
            {
                SectionEnd = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (SectionType == 1369)
                {
                    TargetRva = (unsigned int)(SectionEnd + FieldValue - PeBase);
                    if (TargetRva && TargetRva < (unsigned int)FileSize)
                        goto LABEL_8;
                }
                else if (SectionType == 1296 && SectionCharacteristics == 64 && SectionEntryIndex == 1)
                {
                    FoundInitSection = 1;
                }
                else if (SectionType == 1368)
                {
                    if (FoundInitSection == 1)
                    {
                        TargetRva = (unsigned int)(SectionEnd + FieldValue - PeBase);
                        if (TargetRva && TargetRva < (unsigned int)FileSize)
                        {
LABEL_8:
                            OptHeaderSize = TargetRva;
                            break;
                        }
                    }
                    FoundInitSection = 0;
                }
                if ((unsigned int)++SectionIndex >= 0x14)
                    break;
            }
        }
        if (OptHeaderSize && (unsigned int)OptHeaderSize < (unsigned int)FileSize)
        {
            InitPESectionReadContext(
                (__int64)(PeBase + (unsigned int)OptHeaderSize),
                (ULONG)(FileSize - OptHeaderSize),
                2, 0, -1, 0, 0,
                (__int64)&ReadContext);
            memset(Dst, 0, sizeof(Dst));
            RelocRva2 = 0;
            TargetRva2 = 0;
            FoundRelocSection = 0;
            for (LoopIndex = 0; LoopIndex < 0x1F4; ++LoopIndex)
            {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                SectionEnd2 = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                SectionType2 = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
                if (SectionType2 == 1298 && SectionDataPtr == 0x40000 && FieldValueB && SectionCharacteristics == 64)
                {
                    RelocRva = (unsigned int)(SectionEnd2 + FieldValueB - PeBase);
                    if (RelocRva && RelocRva < (unsigned int)FileSize && SectionEntryIndex < 0x10)
                    {
                        SectionRva = RelocRva2;
                        RelocRva2 = (unsigned int)(SectionEnd2 + FieldValueB - PeBase);
                        Dst[SectionEntryIndex] = RelocRva;
                    }
                }
                else if (SectionType2 == 1294 && (SectionCharacteristics & 0x14000) != 0 && (SectionCharacteristics & 0x40) != 0 && (FieldValueC & 0xF) != 4 && SectionDataPtr == 64)
                {
                    if ((unsigned int)(FieldValue2 - 112) > 0xD8 || (FieldValue2 & 7) != 0)
                    {
                        if (FieldValue2 == 80)
                        {
                            FieldAddr = (unsigned int)Dst[EntryIndex2];
                            if ((_DWORD)FieldAddr)
                            {
                                if ((unsigned int)FieldAddr < (unsigned int)FileSize)
                                {
                                    FieldOffset = (unsigned int)FieldAddr;
                                    if (FieldAddr + 224 <= FileSize)
                                    {
                                        pTargetEntry = pTargetTable + 1;
                                        EntryCount = 27;
                                        pFieldSrc = (unsigned __int64 *)(PeBase + FieldOffset + 8);
                                        do
                                        {
                                            if (*pFieldSrc > ImageNtHeader)
                                            {
                                                FieldRva = (unsigned int)*pFieldSrc - (unsigned int)ImageNtHeader;
                                                if ((unsigned int)FileSize > (unsigned int)FieldRva)
                                                {
                                                    *((_DWORD *)pTargetEntry - 1) = (DWORD)FieldRva;
                                                    *pTargetEntry = NtoskrnlBase2 + FieldRva;
                                                }
                                            }
                                            ++pFieldSrc;
                                            pTargetEntry += 6;
                                            --EntryCount;
                                        } while (EntryCount);
                                        TableBuilt = TableBuilt2;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        if (!FoundRelocSection)
                        {
                            TargetRva2 = SectionRva;
                            FoundRelocSection = 1;
                        }
                        EntryIndex = (unsigned int)(FieldValue2 - 112) >> 3;
                        if ((unsigned int)EntryIndex <= 0x1B)
                        {
                            RelocBaseRva = Dst[EntryIndex2];
                            if (RelocBaseRva)
                            {
                                TableSlot = 6 * EntryIndex;
                                if (!HIDWORD(pContextTable[TableSlot]))
                                {
                                    TableBuilt = 1;
                                    ((ULONG *)&pContextTable[TableSlot])[1] = (ULONG)RelocBaseRva;
                                    TableBuilt2 = 1;
                                    pContextTable[TableSlot + 1] = NtoskrnlBase2 + RelocBaseRva;
                                }
                            }
                        }
                    }
                }
            }
            if (TableBuilt == 1 && TargetRva2)
            {
                FillCount = 28;
                pFillEntry = (char *)pContextTable + 4;
                do
                {
                    if (!*(_DWORD *)pFillEntry)
                    {
                        *(_DWORD *)pFillEntry = TargetRva2;
                        *(_QWORD *)(pFillEntry + 4) = NtoskrnlBase2 + TargetRva2;
                    }
                    pFillEntry += 48;
                    --FillCount;
                } while (FillCount);
                return TableBuilt2;
            }
        }
    }
    return TableBuilt;
}

void ParseDriverInitSection(__int64 PeBuffer, unsigned int PeSize, __int64 RelocBase)
{
    int LoopIndex;
    unsigned int ExportByNameInPeBody;
    __int64 ExportOffset;
    unsigned int PESectionByName;
    unsigned int PESectionByNameReturnVa;
    unsigned int SectionEnd;
    int SectionEnd2;
    unsigned int TargetRva;
    int LoopIndex2;
    int SectionEnd3;
    __int16 SectionType;
    unsigned int RelocRva;
    unsigned int EntryIndex;
    int SectionEnd4;
    __int64 BaseOffset;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    int FieldValue;
    int FieldValue2;
    __int64 SectionCharacteristics;
    int FieldValue3;
    int FieldValue4;
    __int64 SectionFlags;
    unsigned int EntryCount;
    unsigned int SectionSize;
    __int64 SectionDataPtr;
    _QWORD FuncNameBuffer[2];
    _DWORD Dst[16];

    if (!RelocBase)
        return;

    LoopIndex = 0;
    strcpy((char *)FuncNameBuffer, "DllInitialize");
    FuncNameBuffer[1] = 0;
    ExportByNameInPeBody = (unsigned int)FindExportByNameInPeBody((PUCHAR)PeBuffer, PeSize, (char *)FuncNameBuffer, 0);
    ExportOffset = ExportByNameInPeBody;
    if (!ExportByNameInPeBody)
        return;
    if (ExportByNameInPeBody >= PeSize || ExportByNameInPeBody + 4096 >= PeSize)
        return;

    FuncNameBuffer[0] = 1414090313;  // "INIT" as DWORD
    PESectionByName = (unsigned int)FindPESectionByName((__int64)PeBuffer, PeSize, (__int64)FuncNameBuffer);
    PESectionByNameReturnVa = (unsigned int)FindPESectionByNameReturnVa((__int64)PeBuffer, PeSize, (__int64)FuncNameBuffer);
    if (!PESectionByName || !PESectionByNameReturnVa)
        return;
    if (PESectionByName >= PeSize || PESectionByNameReturnVa >= PeSize)
        return;

    SectionEnd = PESectionByNameReturnVa + PESectionByName;
    if (SectionEnd >= PeSize)
        return;

    InitPESectionReadContext((__int64)(PeBuffer + ExportOffset), 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
    {
        SectionEnd2 = SectionSize + (int)CumulativeSize;
        CumulativeSize += SectionSize;
        if ((unsigned __int16)(*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) - 1368) <= 1u)
        {
            if (FieldValue)
            {
                TargetRva = (unsigned int)(SectionEnd2 + FieldValue - PeBuffer);
                if (TargetRva && TargetRva < PeSize && (PESectionByName > TargetRva || TargetRva >= SectionEnd))
                {
                    ExportOffset = TargetRva;
                    break;
                }
            }
        }
        if ((unsigned int)++LoopIndex >= 0x14)
            break;
    }

    if ((unsigned int)ExportOffset < PeSize && (int)ExportOffset + 4096 < (int)PeSize)
    {
        InitPESectionReadContext((__int64)(PeBuffer + (unsigned int)ExportOffset), 4096, 2, 0, -1, 0, 0, (__int64)&ReadContext);
        memset(Dst, 0, sizeof(Dst));
        LoopIndex2 = 0;
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
        {
            SectionEnd3 = SectionSize + (int)CumulativeSize;
            CumulativeSize += SectionSize;
            SectionType = *(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6);
            if (SectionType == 1298 && SectionFlags == 0x40000)
            {
                if (FieldValue4 && SectionCharacteristics == 64)
                {
                    RelocRva = (unsigned int)(SectionEnd3 + FieldValue4 - PeBuffer);
                    if (RelocRva && RelocRva < PeSize)
                        Dst[FieldValue3] = RelocRva;
                }
            }
            if (SectionType == 1294 && SectionCharacteristics == 0x40000)
            {
                if (FieldValue2 && SectionFlags == 64 && EntryCount < 0x10)
                {
                    EntryIndex = (unsigned int)(SectionEnd3 + FieldValue2 - PeBuffer);
                    if (EntryIndex && EntryIndex < PeSize)
                    {
                        SectionEnd4 = Dst[EntryCount];
                        if (SectionEnd4 && EntryIndex == (unsigned int)SectionEnd4)
                        {
                            BaseOffset = EntryIndex;
                            GtWrite(GtFltPeSectionOfs6 | GtEprocessField22, EntryIndex);
                            GtWrite((enum _GLOBAL_TABLE_INDEX)(GtFltPeSectionAddr6 | GtEprocessField22), BaseOffset + RelocBase);
                            return;
                        }
                    }
                }
            }
            if ((unsigned int)++LoopIndex2 >= 0x12C)
                return;
        }
    }
}

__int64 ResolveCreateFileRelocs(__int64 TargetBase, ULONG TargetSize, __int64 Context, __int64 RelocBase)
{
    unsigned int SectionOffset;
    __int64 Result;
    int TargetOffset;
    char FoundFirstMatch;
    char FoundSecondStage;
    int LoopIndex;
    int CurrentOffset;
    PE_DECODE_CONTEXT ReadContext;      // 0x48 字节解码上下文（原 __int64 仅 8 字节）
    __int64 CumulativeSize;
    _DWORD SectionEntry[112];           // 描述符：原 [14] 仅 56 字节
    int EntrySize;
    __int64 SectionFlags;
    unsigned int SectionSize;
    int EntryField1;
    int EntryField2;
    unsigned int EntrySizeInner;
    __int64 SectionTypeInner;
    unsigned int EntryCumulSize;
    __int64 EntryDataPtr;

    SectionOffset = (unsigned int)GtRead(GtNtCreateFileSyscallResult);
    Result = GtRead(GtNtWriteFilePeSectionOffset | GtObjectTypeField08);
    TargetOffset = (int)Result;
    if (SectionOffset && SectionOffset < TargetSize && (_DWORD)Result && (unsigned int)Result < TargetSize)
    {
        InitPESectionReadContext(
            TargetBase + SectionOffset,
            TargetSize - SectionOffset,
            2,
            0,
            -1,
            0,
            0,
            (__int64)&ReadContext);
        FoundFirstMatch = 0;
        FoundSecondStage = 0;
        LoopIndex = 0;
        while (1)
        {
            *(ULONG64 *)((PUCHAR)&ReadContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                return Result;
            CurrentOffset = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) != 1368 || (SectionFlags & 0x4000000) == 0 || !EntrySize)
            {
                if (*(_WORD *)(*(ULONG64 *)((PUCHAR)SectionEntry + 0x118) + 6) == 1066 && (SectionTypeInner & 0x200000000LL) != 0)
                {
                    Result = 1;
                    if (EntryField2 == 16 && FoundFirstMatch == 1)
                        FoundSecondStage = 1;
                    goto NEXT_ITER;
                }
                Result = 1;
                goto NEXT_ITER;
            }
            Result = (unsigned int)(CurrentOffset + EntrySize - TargetBase);
            if ((_DWORD)Result != TargetOffset)
            {
                if (FoundSecondStage == 1)
                {
                    if ((_DWORD)Result && (unsigned int)Result < TargetSize)
                    {
                        InitPESectionReadContext(
                            (__int64)(TargetBase + (unsigned int)Result),
                            (ULONG)(TargetSize - Result),
                            2,
                            0,
                            -1,
                            0,
                            0,
                            (__int64)&ReadContext);
                        {
                            char FoundInnerResult;
                            unsigned int InnerRelocOffset;
                            int InnerLoopIndex;
                            int InnerCurrentOffset;

                            FoundInnerResult = 0;
                            InnerRelocOffset = 0;
                            InnerLoopIndex = 0;
                            while (1)
                            {
                                Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
                                if ((_DWORD)Result)
                                    break;
                                InnerCurrentOffset = (int)(EntryCumulSize + CumulativeSize);
                                CumulativeSize += EntryCumulSize;
                                if (SectionTypeInner == 0x40000 && (Result = EntrySizeInner) != 0)
                                {
                                    InnerRelocOffset = (unsigned int)(InnerCurrentOffset + EntrySizeInner - TargetBase);
                                }
                                else if (EntryField1 == 8)
                                {
                                    if (InnerRelocOffset)
                                    {
                                        if (InnerRelocOffset < TargetSize)
                                        {
                                            Result = GtWrite(GtCallbackField116, RelocBase + InnerRelocOffset);
                                            FoundInnerResult = 1;
                                        }
                                    }
                                }
                                else
                                {
                                    Result = 1;
                                    if (FoundInnerResult == 1 && SectionFlags == 0x40000)
                                    {
                                        Result = SectionSize;
                                        if (SectionSize)
                                        {
                                            Result = InnerCurrentOffset + SectionSize - (unsigned int)TargetBase;
                                            if ((_DWORD)Result)
                                            {
                                                if ((unsigned int)Result < TargetSize)
                                                    return GtWrite(GtCallbackField117, RelocBase + (unsigned int)Result);
                                            }
                                        }
                                    }
                                }
                                if ((unsigned int)++InnerLoopIndex >= 0x12C)
                                    return Result;
                            }
                        }
                    }
                    return Result;
                }
                Result = 1;
                goto NEXT_ITER;
            }
            Result = 1;
            FoundFirstMatch = 1;
NEXT_ITER:
            if ((unsigned int)++LoopIndex >= 0x3E8)
                return Result;
        }
    }
    return Result;
}

// ParseNtExportSectionsV3 — 解析 NT 导出节区 V3（按节序号填目标表）
// 对应原始驱动 0x140035AFC（781 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（150 行伪代码，字段名已由 IDA 标注），
//   故按伪代码实现 —— 而非此前默认的"出表 + 机械转写"。见待实现函数结构分析 §六。
// 【参数】ImageBase / ImageSize / pTargetTable（0x30 字节/项的目标表）
// 【逻辑】两段扫描：
//   段 1（上限 0x14）：从 PE 头 +0x28 定位初始节，扫节区；类型 1369 → 记录目标 RVA 跳出；
//     1296 且 +0x70==64 且 +0x58==1 → 置 FoundFlag；1368 且 FoundFlag 置位 → 记录 RVA 跳出
//   段 2（上限 0xC8）：memset Dst[16]；类型 1298 且 +0x88==0x40000 且 +0x38!=0 且 +0x70==64
//     → Dst[+0x58] = 偏移；类型 1139 → 清 Dst；类型 1294（多重条件：+0x50 带 0x14000/0x40、
//     +0xDC 低 4 位 != 4、+0x88==64、+0x38 落在 112..0x148 且 8 字节对齐）→
//     以 (+0x38-112)>>3 为槽号，把 Dst[+0x58] 写入 pTargetTable[槽号*0x30 + 4]，
//     并把 SectionBase + 该值写入 +8（仅在该槽 +4 尚为 0 时）
char ParseNtExportSectionsV3(__int64 ImageBase, unsigned int ImageSize, __int64 pTargetTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 SectionBase;
    ULONG InitSectionRva;
    char FoundFlag = 0;
    int ScanCount = 0;
    PE_DECODE_CONTEXT PESectionContext;
    __int64 ContextOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD Dst[16];
    ULONG TargetRva;

    PeOffset = *(int *)(ImageBase + 60);
    SectionBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x902);
    if (!SectionBase)
        return Result;

    InitSectionRva = *(ULONG *)(PeOffset + ImageBase + 40);
    if (InitSectionRva >= ImageSize)
        return Result;
    if ((unsigned int)(InitSectionRva + 4096) >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    ScanCount = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
    {
        ULONG CurrentRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
        ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 TypeValue = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (TypeValue == 1369)
        {
            TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (TargetRva && TargetRva < ImageSize)
            {
                InitSectionRva = TargetRva;
                break;
            }
        }
        else if (TypeValue == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            FoundFlag = 1;
        }
        else if (TypeValue == 1368 && FoundFlag == 1)
        {
            TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (TargetRva && TargetRva < ImageSize)
            {
                InitSectionRva = TargetRva;
                break;
            }
            FoundFlag = 0;
        }
        if ((unsigned int)++ScanCount >= 0x14)
            break;
    }

    if (InitSectionRva >= ImageSize || (unsigned int)(InitSectionRva + 4096) >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
    memset(Dst, 0, sizeof(Dst));
    for (ULONG LoopIndex = 0; LoopIndex < 0xC8; LoopIndex++)
    {
            *(ULONG64 *)((PUCHAR)&PESectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
            break;

        ULONG EntryRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
        ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 TypeValue2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (TypeValue2 == 1349)
            break;

        if (TypeValue2 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            ULONG RvaField = *(ULONG *)((char *)SectionEntry + 0x78);
            if (RvaField && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
            {
                ULONG v = EntryRva + RvaField - (ULONG)ImageBase;
                if (v && v < ImageSize)
                    Dst[*(ULONG *)((char *)SectionEntry + 0x58)] = v;
            }
        }
        if (TypeValue2 == 1139)
            memset(Dst, 0, sizeof(Dst));

        if (TypeValue2 == 1294)
        {
            ULONG SizeValue = *(ULONG *)((char *)SectionEntry + 0x50);
            ULONG ExtraFlags = *(ULONG *)((char *)SectionEntry + 0xDC);
            ULONG EntryOffsetVal = *(ULONG *)((char *)SectionEntry + 0x40);
            if ((SizeValue & 0x14000) && (SizeValue & 0x40) && (ExtraFlags & 0xF) != 4 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
                (EntryOffsetVal - 112) <= 0xD8 && (EntryOffsetVal & 7) == 0)
            {
                ULONG SlotIndex = (EntryOffsetVal - 112) >> 3;
                if (SlotIndex <= 0x1B)
                {
                    ULONG DstRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                    if (DstRva && !*(_DWORD *)(pTargetTable + 48 * SlotIndex + 4))
                    {
                        Result = 1;
                        *(_DWORD *)(pTargetTable + 48 * SlotIndex + 4) = DstRva;
                        *(_QWORD *)(pTargetTable + 48 * SlotIndex + 8) = SectionBase + DstRva;
                    }
                }
            }
        }
    }
    return Result;
}

// ParseNtFileForCallbackContext — 解析 NT 文件填充回调上下文表
// 对应原始驱动 0x14003E1F4（781 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（147 行伪代码），故按伪代码实现
//   （见待实现函数结构分析 §六：先试反编译，失败才走"出表+转写"）。
// 【参数】pFileBuffer / FileSize / pExportTable（0x30 字节/项）
// 【逻辑】与 ParseNtExportSectionsV3 **高度同构**（同一两段扫描、同样的类型码
//   1369/1296/1368/1298/1139/1294 与字段偏移），差异三处：
//   1) 镜像基址取自 GT 复合值 (GtFwpsDispatchTableCount|GtEprocessField184|GtEprocessField06)
//   2) 段 2 循环上限为 **0x3E8**（V3 为 0xC8）
//   3) 段 2 里 1298 型写**局部槽表 SlotAddresses**，由 1294 型消费（逻辑同 V3）
char ParseNtFileForCallbackContext(__int64 pFileBuffer, unsigned int FileSize, __int64 pExportTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 NtoskrnlBase;
    ULONG CurrentRva;
    char IsTargetSection = 0;
    int SectionIndex;
    PE_DECODE_CONTEXT SectionContext;
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD SlotAddresses[16];
    ULONG SectionRva, EntryRva, TargetRva;

    PeOffset = *(int *)(pFileBuffer + 60);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)(GtFwpsDispatchTableCount |
                                                       GtEprocessField184 | GtEprocessField06));
    if (!NtoskrnlBase)
        return Result;

    CurrentRva = *(ULONG *)(PeOffset + pFileBuffer + 40);
    if (CurrentRva >= FileSize || (unsigned int)(CurrentRva + 4096) >= FileSize)
        return Result;

    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        ULONG ComputedOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 1369)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
            if (SectionRva && SectionRva < FileSize) { CurrentRva = SectionRva; break; }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            IsTargetSection = 1;
        }
        else if (SectionType == 1368 && IsTargetSection == 1)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)pFileBuffer;
            if (SectionRva && SectionRva < FileSize) { CurrentRva = SectionRva; break; }
            IsTargetSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14) break;
    }

    if (CurrentRva >= FileSize || (unsigned int)(CurrentRva + 4096) >= FileSize)
        return Result;

    InitPESectionReadContext(pFileBuffer + CurrentRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    memset(SlotAddresses, 0, sizeof(SlotAddresses));
    for (ULONG I = 0; I < 0x3E8; I++)
    {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;
        ULONG ComputedOffset2 = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        if (SectionType2 == 1349) break;

        if (SectionType2 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            ULONG v = *(ULONG *)((char *)SectionEntry + 0x78);
            if (v && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
            {
                EntryRva = ComputedOffset2 + v - (ULONG)pFileBuffer;
                if (EntryRva && EntryRva < FileSize)
                    SlotAddresses[*(ULONG *)((char *)SectionEntry + 0x58)] = EntryRva;
            }
        }
        if (SectionType2 == 1139) memset(SlotAddresses, 0, sizeof(SlotAddresses));

        if (SectionType2 == 1294)
        {
            ULONG SecFlags = *(ULONG *)((char *)SectionEntry + 0x50);
            ULONG MiscFlags = *(ULONG *)((char *)SectionEntry + 0xDC);
            ULONG FieldOffset = *(ULONG *)((char *)SectionEntry + 0x40);
            if ((SecFlags & 0x14000) && (SecFlags & 0x40) && (MiscFlags & 0xF) != 4 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
                (FieldOffset - 112) <= 0xD8 && (FieldOffset & 7) == 0)
            {
                ULONG SlotIndex = (FieldOffset - 112) >> 3;
                if (SlotIndex <= 0x1B)
                {
                    TargetRva = SlotAddresses[*(ULONG *)((char *)SectionEntry + 0x90)];
                    if (TargetRva && !*(_DWORD *)(pExportTable + 48 * SlotIndex + 4))
                    {
                        Result = 1;
                        *(_DWORD *)(pExportTable + 48 * SlotIndex + 4) = TargetRva;
                        *(_QWORD *)(pExportTable + 48 * SlotIndex + 8) = NtoskrnlBase + TargetRva;
                    }
                }
            }
        }
    }
    return Result;
}

// ParseNtSectionsForContextTable — 解析 NT 节区填充上下文表（批量填 28 项）
// 对应原始驱动 0x140046FEC（767 字节）
// 【逆向来源】同上（可反编译，163 行伪代码）
// 【逻辑】段 1 与同族一致（定位目标节）；段 2 与前两个**不同**：不做槽位填写，
//   而是按构建号二选一确认目标节区后，把同一个 RVA **批量填满 28 项**
//   （每项 0x30：+4 = RVA、+8 = RVA + 镜像基址）：
//     - 构建号 == 9200(20480, Win10 1809) → 要求"0x1298 型且 +0x88==0x40000 且
//       +0x38!=0 且 +0x70==64"的节区出现**第 2 次**
//     - 其他构建号 → 先记 0x1298 型（+0x58==0 时）的 RVA，再由"1327 型且 +0x50 带 0x10"确认
char ParseNtSectionsForContextTable(__int64 ImageBase, unsigned int ImageSize, __int64 pOutputTable)
{
    __int64 PeOffset;
    char Result = 0;
    __int64 NtoskrnlBase;
    ULONG SectionDirRva;
    char IsTargetSection = 0;
    int SectionIndex;
    PE_DECODE_CONTEXT SectionContext;
    __int64 AccumulatedOffset = 0;
    _DWORD SectionEntry[112];
    ULONG SectionRva, ExportDirRva;
    int Win8SectionCount;

    PeOffset = *(int *)(ImageBase + 60);
    NtoskrnlBase = (__int64)GtRead((GLOBAL_TABLE_INDEX)0x8E0);
    if (!NtoskrnlBase)
        return Result;

    SectionDirRva = *(ULONG *)(PeOffset + ImageBase + 40);
    if (SectionDirRva >= ImageSize || (unsigned int)(SectionDirRva + 4096) >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        ULONG ComputedOffset = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)AccumulatedOffset;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType == 1369)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (SectionRva && SectionRva < ImageSize) { SectionDirRva = SectionRva; break; }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            IsTargetSection = 1;
        }
        else if (SectionType == 1368 && IsTargetSection == 1)
        {
            SectionRva = ComputedOffset + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (SectionRva && SectionRva < ImageSize) { SectionDirRva = SectionRva; break; }
            IsTargetSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x14) break;
    }

    if (SectionDirRva >= ImageSize || (unsigned int)(SectionDirRva + 4096) >= ImageSize)
        return Result;

    InitPESectionReadContext(ImageBase + SectionDirRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    ExportDirRva = 0;
    Win8SectionCount = 0;

    for (ULONG EntryIndex = 0; EntryIndex < 0xC8; EntryIndex++)
    {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            return Result;
        AccumulatedOffset += *(ULONG *)((char *)SectionEntry + 0xF0);

        if ((unsigned int)GtRead(GtWindowsBuildNumber) == 9200)
        {
            if (*(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1298 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x78) != 0 &&
                *(__int64 *)((char *)SectionEntry + 0x50) == 64)
            {
                if (++Win8SectionCount == 2)
                {
                    ULONG Rva = (ULONG)AccumulatedOffset + *(ULONG *)((char *)SectionEntry + 0x78) - (ULONG)ImageBase;
                    if (Rva >= ImageSize)
                        return Result;
                    for (ULONG k = 0; k < 28; k++)
                    {
                        *(_DWORD *)(pOutputTable + 48 * k + 4) = Rva;
                        *(_QWORD *)(pOutputTable + 48 * k + 8) = NtoskrnlBase + Rva;
                    }
                    return 1;
                }
            }
        }
        else
        {
            __int16 SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
            if (SectionType2 == 1298 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000 &&
                *(_DWORD *)((char *)SectionEntry + 0x78) != 0 &&
                *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                *(_DWORD *)((char *)SectionEntry + 0x58) == 0)
            {
                ExportDirRva = (ULONG)AccumulatedOffset + *(ULONG *)((char *)SectionEntry + 0x78) - (ULONG)ImageBase;
                if (ExportDirRva >= ImageSize)
                    ExportDirRva = 0;
            }
            else if (SectionType2 == 1327 &&
                     (*(UCHAR *)((char *)SectionEntry + 0x20) & 0x10) &&
                     ExportDirRva)
            {
                for (ULONG k = 0; k < 28; k++)
                {
                    *(_DWORD *)(pOutputTable + 48 * k + 4) = ExportDirRva;
                    *(_QWORD *)(pOutputTable + 48 * k + 8) = NtoskrnlBase + ExportDirRva;
                }
                return 1;
            }
        }
    }
    return Result;
}


// =========================================================================
// ReadNtFileForCallbackTable — 按模式读取驱动文件供回调表解析
// 对应原始驱动 0x1400355B4（0x179 = 377 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（38 行伪代码），按伪代码实现
// 【参数】pFileBuffer / pFileSize 为输出；VersionType 是模式（0/1/2），
//   与 InitCallbackFunctionTable 的模式一一对应。
// 【路径（由伪代码 EncodedPath[N] = <十进制> 赋值序列按 DWORD 索引重建并逐字节验证）】
//   前缀固定 \SystemRoot\system32\drivers，文件名按模式追加：
//     VersionType == 0 → fastfat.sys（FAT 文件系统驱动）
//     VersionType == 1 → exfat.sys （exFAT 文件系统驱动）
//     VersionType == 2 → ntfs.sys  （NTFS 文件系统驱动）
// 【逻辑】构造路径 → ReadFileRawData（返回 0 表示成功）→ ReadNtFileToBuffer 解析
//   → ExFree 原始数据；返回是否成功。与 ReadNtoskrnlForCallbackContext 同构。
// =========================================================================
bool ReadNtFileForCallbackTable(_QWORD *pFileBuffer, unsigned int *pFileSize, int VersionType)
{
    bool Result = 0;
    void *pRawData = NULL;
    size_t RawDataSize = 0;
    WCHAR EncodedPath[40];

    if (VersionType == 0)
        wcscpy(EncodedPath, L"\\SystemRoot\\system32\\drivers\\fastfat.sys");
    else if (VersionType == 1)
        wcscpy(EncodedPath, L"\\SystemRoot\\system32\\drivers\\exfat.sys");
    else if (VersionType == 2)
        wcscpy(EncodedPath, L"\\SystemRoot\\system32\\drivers\\ntfs.sys");
    else
        return Result;

    if (!(unsigned int)ReadFileRawData(EncodedPath, &pRawData, (ULONG *)&RawDataSize, 1))
    {
        Result = (ReadNtFileToBuffer((PUCHAR)pRawData, (ULONG)RawDataSize,
                                     (PUCHAR *)pFileBuffer, (PULONG)pFileSize) == 1);
        ExFree(pRawData);
    }
    return Result;
}

// =========================================================================
// ParseCallbackFunctionSections — 解析回调函数节区，填充目标表与备用表
// 对应原始驱动 0x140033FA8（0x3F8 = 1016 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（150 行伪代码，字段名已由 IDA 标注），
//   故按伪代码实现；0x120 字节描述符字段偏移由反汇编逐条核对为：
//     +0x38 RVA 字段、+0x50 大小/特征、+0x58 序号、+0x70 对齐值、+0x88 标志、
//     +0x90 Dst 读索引、+0xDC 额外标志、+0xF0 指令长度、
//     +0x118 指向类型 word 的指针（+6 处为节区类型码）
// 【参数】ImageBase / ImageSize / SectionBase（重定位基址）/ pTargetTable（0x30 项表）
//   / pAlternateTable / IsVersion2（char，模式 2 标志）
// =========================================================================
char ParseCallbackFunctionSections(
        __int64 ImageBase,
        unsigned int ImageSize,
        __int64 SectionBase,
        __int64 pTargetTable,
        __int64 pAlternateTable,
        char IsVersion2)
{
    char Result = 0;
    __int64 InitSectionRva;
    char FoundFlag;
    int ScanCount;
    ULONG BaseRva = 0;
    ULONG LoopIndex;
    PE_DECODE_CONTEXT PESectionContext;
    __int64 ContextOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD Dst[16];

    InitSectionRva = *(unsigned int *)(*(int *)(ImageBase + 60) + ImageBase + 40);
    if ((_DWORD)InitSectionRva)
    {
        if ((unsigned int)InitSectionRva >= ImageSize)
            return Result;
        if ((int)InitSectionRva + 4096 < (int)ImageSize)
        {
            FoundFlag = 0;
            InitPESectionReadContext(InitSectionRva + ImageBase, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
            ScanCount = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
            {
                ULONG CurrentRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
                ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
                __int16 TypeValue = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
                ULONG TargetRva;

                if (TypeValue == 1369)
                {
                    TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                    if (TargetRva && TargetRva < ImageSize)
                    {
                        InitSectionRva = TargetRva;
                        break;
                    }
                }
                else if (TypeValue == 1296 &&
                         *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                         *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
                {
                    FoundFlag = 1;
                }
                else if (TypeValue == 1368)
                {
                    if (FoundFlag == 1)
                    {
                        TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                        if (TargetRva && TargetRva < ImageSize)
                        {
                            InitSectionRva = TargetRva;
                            break;
                        }
                    }
                    FoundFlag = 0;
                }
                if ((unsigned int)++ScanCount >= 0x14)
                    break;
            }
        }
    }

    if ((unsigned int)InitSectionRva < ImageSize && (int)InitSectionRva + 4096 < (int)ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
        memset(Dst, 0, sizeof(Dst));
        BaseRva = 0;
        for (LoopIndex = 0; LoopIndex < 0x3E8; ++LoopIndex)
        {
            *(ULONG64 *)((PUCHAR)&PESectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            ULONG EntryRva;
            __int16 TypeValue2;
            ULONG SizeValue;
            ULONG RvaField;
            ULONG ExtraFlags;
            ULONG EntryOffsetVal;

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
                break;

            EntryRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
            ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
            TypeValue2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

            SizeValue = *(ULONG *)((char *)SectionEntry + 0x50);
            RvaField = *(ULONG *)((char *)SectionEntry + 0x78);
            ExtraFlags = *(ULONG *)((char *)SectionEntry + 0xDC);
            EntryOffsetVal = *(ULONG *)((char *)SectionEntry + 0x40);

            if (TypeValue2 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
            {
                if (RvaField && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
                {
                    ULONG v = EntryRva + RvaField - (ULONG)ImageBase;
                    if (v && v < ImageSize)
                        Dst[*(ULONG *)((char *)SectionEntry + 0x90)] = v;
                }
            }
            if (BaseRva)
            {
                if (TypeValue2 == 1296 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
                {
                    if (RvaField && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
                    {
                        ULONG v = EntryRva + RvaField - (ULONG)ImageBase;
                        if (v && v < ImageSize)
                            Dst[*(ULONG *)((char *)SectionEntry + 0x90)] = 0;
                    }
                }
            }
            if (TypeValue2 == 1294)
            {
                if ((SizeValue & 0x14000) != 0 && (SizeValue & 0x40) != 0 &&
                    (ExtraFlags & 0xF) != 4 && *(__int64 *)((char *)SectionEntry + 0x88) == 64)
                {
                    if ((unsigned int)(EntryOffsetVal - 112) > 0xD8 || (EntryOffsetVal & 7) != 0)
                    {
                        if (EntryOffsetVal == 80)
                        {
                            ULONG BaseRvaEntry = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (BaseRvaEntry && !BaseRva)
                            {
                                GLOBAL_TABLE_INDEX GtIndex = GtNtQueryVirtualMemoryFunc;
                                BaseRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                                if (IsVersion2 != 1)
                                    GtIndex = GtKeStackAttachProcessFunc;
                                GtWrite(GtIndex, SectionBase + BaseRvaEntry);
                            }
                        }
                    }
                    else
                    {
                        ULONG SlotIndex = (EntryOffsetVal - 112) >> 3;
                        if (SlotIndex <= 0x1B)
                        {
                            ULONG DstRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (DstRva && !*(_DWORD *)(pTargetTable + 48 * SlotIndex + 4))
                            {
                                Result = 1;
                                *(_DWORD *)(pTargetTable + 48 * SlotIndex + 4) = DstRva;
                                *(_QWORD *)(pTargetTable + 48 * SlotIndex + 8) = SectionBase + DstRva;
                            }
                        }
                    }
                }
                else if (SizeValue == 0x40000 && *(__int64 *)((char *)SectionEntry + 0x88) == 64)
                {
                    ULONG AltTargetRva = EntryRva + EntryOffsetVal - (ULONG)ImageBase;
                    if (AltTargetRva && AltTargetRva < ImageSize && AltTargetRva > BaseRva)
                    {
                        ULONG AltSlotIndex = (AltTargetRva - BaseRva - 8) >> 3;
                        if (AltSlotIndex < 0x1B)
                        {
                            ULONG AltDstRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (AltDstRva)
                            {
                                *(_DWORD *)(pAlternateTable + 48 * AltSlotIndex + 4) = AltDstRva;
                                *(_QWORD *)(pAlternateTable + 48 * AltSlotIndex + 8) = SectionBase + AltDstRva;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// ParseCallbackContextSections — 解析回调上下文章节，填充目标表与备用表
// 对应原始驱动 0x140034E7C（0x43E = 1086 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（165 行伪代码），按伪代码实现
// 【与 ParseCallbackFunctionSections 的差异（逐条比对伪代码得出）】
//   1) 无 IsVersion2 参数（5 参）；BaseRva 的 GtWrite 一律用
//      GtNtFreeVirtualMemoryFunc（不是二选一的分支）；
//   2) 多一个 1351/+0x50==0x40000 的**前置定基**分支：+0x38!=0 且 +0x110==224 且
//      目标 RVA 有效且 BaseRva 未定时，置 BaseRva 并 GtWrite，
//      然后以 ContextOffset 重新取 EntryRva；
//   3) 1294 主支槽步长写作 48*SlotIndex（与函数族其它处一致）。
// 【参数】ImageBase / ImageSize / SectionBase / pTargetTable / pAlternateTable
// =========================================================================
char ParseCallbackContextSections(
        __int64 ImageBase,
        unsigned int ImageSize,
        __int64 SectionBase,
        __int64 pTargetTable,
        __int64 pAlternateTable)
{
    char Result = 0;
    __int64 InitSectionRva;
    char FoundFlag;
    int ScanCount;
    ULONG BaseRva = 0;
    ULONG LoopIndex;
    PE_DECODE_CONTEXT PESectionContext;
    __int64 ContextOffset = 0;
    _DWORD SectionEntry[112];
    _DWORD Dst[16];

    InitSectionRva = *(unsigned int *)(*(int *)(ImageBase + 60) + ImageBase + 40);
    if ((_DWORD)InitSectionRva)
    {
        if ((unsigned int)InitSectionRva >= ImageSize)
            return Result;
        if ((int)InitSectionRva + 4096 < (int)ImageSize)
        {
            FoundFlag = 0;
            InitPESectionReadContext(InitSectionRva + ImageBase, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
            ScanCount = 0;
            while (!(unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
            {
                ULONG CurrentRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
                ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
                __int16 TypeValue = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
                ULONG TargetRva;

                if (TypeValue == 1369)
                {
                    TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                    if (TargetRva && TargetRva < ImageSize)
                    {
                        InitSectionRva = TargetRva;
                        break;
                    }
                }
                else if (TypeValue == 1296 &&
                         *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                         *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
                {
                    FoundFlag = 1;
                }
                else if (TypeValue == 1368)
                {
                    if (FoundFlag == 1)
                    {
                        TargetRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                        if (TargetRva && TargetRva < ImageSize)
                        {
                            InitSectionRva = TargetRva;
                            break;
                        }
                    }
                    FoundFlag = 0;
                }
                if ((unsigned int)++ScanCount >= 0x14)
                    break;
            }
        }
    }

    if ((unsigned int)InitSectionRva < ImageSize && (int)InitSectionRva + 4096 < (int)ImageSize)
    {
        InitPESectionReadContext(ImageBase + (unsigned int)InitSectionRva, 4096, 2, 0, -1, 0, 0, (__int64)&PESectionContext);
        memset(Dst, 0, sizeof(Dst));
        BaseRva = 0;
        for (LoopIndex = 0; LoopIndex < 0x3E8; ++LoopIndex)
        {
            *(ULONG64 *)((PUCHAR)&PESectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            ULONG EntryRva;
            __int16 TypeValue2;
            ULONG SizeValue;
            ULONG RvaField;
            ULONG ExtraFlags;
            ULONG EntryOffsetVal;

            if ((unsigned int)ReadPESectionEntry((PUCHAR)&PESectionContext, (PULONG)SectionEntry))
                return Result;

            EntryRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)ContextOffset;
            ContextOffset += *(ULONG *)((char *)SectionEntry + 0xF0);
            TypeValue2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

            SizeValue = *(ULONG *)((char *)SectionEntry + 0x50);
            RvaField = *(ULONG *)((char *)SectionEntry + 0x78);
            ExtraFlags = *(ULONG *)((char *)SectionEntry + 0xDC);
            EntryOffsetVal = *(ULONG *)((char *)SectionEntry + 0x40);

            if (TypeValue2 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
            {
                if (RvaField && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
                {
                    ULONG v = EntryRva + RvaField - (ULONG)ImageBase;
                    if (v && v < ImageSize)
                        Dst[*(ULONG *)((char *)SectionEntry + 0x90)] = v;
                }
            }
            if (BaseRva)
            {
                if (TypeValue2 == 1296 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
                {
                    if (RvaField && *(__int64 *)((char *)SectionEntry + 0x50) == 64)
                    {
                        ULONG v = EntryRva + RvaField - (ULONG)ImageBase;
                        if (v && v < ImageSize)
                            Dst[*(ULONG *)((char *)SectionEntry + 0x90)] = 0;
                    }
                }
            }
            // 1351 前置定基分支（本函数独有）
            if (TypeValue2 == 1351 && SizeValue == 0x40000)
            {
                if (EntryOffsetVal && *(__int64 *)((char *)SectionEntry + 0x70) == 224)
                {
                    ULONG TargetRva4 = EntryRva + EntryOffsetVal - (ULONG)ImageBase;
                    if (TargetRva4 && TargetRva4 < ImageSize && !BaseRva)
                    {
                        BaseRva = EntryRva + EntryOffsetVal - (ULONG)ImageBase;
                        GtWrite(GtNtFreeVirtualMemoryFunc, SectionBase + TargetRva4);
                        EntryRva = (ULONG)ContextOffset;
                    }
                }
            }
            if (TypeValue2 == 1294)
            {
                if ((SizeValue & 0x14000) != 0 && (SizeValue & 0x40) != 0 &&
                    (ExtraFlags & 0xF) != 4 && *(__int64 *)((char *)SectionEntry + 0x88) == 64)
                {
                    if ((unsigned int)(EntryOffsetVal - 112) > 0xD8 || (EntryOffsetVal & 7) != 0)
                    {
                        if (EntryOffsetVal == 80)
                        {
                            ULONG BaseRvaEntry = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (BaseRvaEntry && !BaseRva)
                            {
                                BaseRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                                GtWrite(GtNtFreeVirtualMemoryFunc, SectionBase + BaseRvaEntry);
                            }
                        }
                    }
                    else
                    {
                        ULONG SlotIndex = (EntryOffsetVal - 112) >> 3;
                        if (SlotIndex <= 0x1B)
                        {
                            ULONG DstRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (DstRva && !*(_DWORD *)(pTargetTable + 48 * SlotIndex + 4))
                            {
                                Result = 1;
                                *(_DWORD *)(pTargetTable + 48 * SlotIndex + 4) = DstRva;
                                *(_QWORD *)(pTargetTable + 48 * SlotIndex + 8) = SectionBase + DstRva;
                            }
                        }
                    }
                }
                else if (SizeValue == 0x40000 && *(__int64 *)((char *)SectionEntry + 0x88) == 64)
                {
                    ULONG AltTargetRva = EntryRva + EntryOffsetVal - (ULONG)ImageBase;
                    if (AltTargetRva && AltTargetRva < ImageSize && AltTargetRva > BaseRva)
                    {
                        ULONG AltSlotIndex = (AltTargetRva - BaseRva - 8) >> 3;
                        if (AltSlotIndex < 0x1B)
                        {
                            ULONG AltDstRva = Dst[*(ULONG *)((char *)SectionEntry + 0x90)];
                            if (AltDstRva)
                            {
                                *(_DWORD *)(pAlternateTable + 48 * AltSlotIndex + 4) = AltDstRva;
                                *(_QWORD *)(pAlternateTable + 48 * AltSlotIndex + 8) = SectionBase + AltDstRva;
                            }
                        }
                    }
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// ParseNtSectionHeaders2 — 解析 NT PE 节区头（磁盘信息版，4 参数）
// 对应原始驱动 0x1400485F0（1303 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（170 行伪代码），按伪代码实现。
// 【参数】ImageBase / ImageSize / ExportDataBase（填入 +8 时加的基址）/ OutputTable
// 【描述符字段（权威映射）】+0x38 段1 RVA / +0x50 ==64 / +0x58 序号 /
//   +0x78 1298 RVA / +0x88 Flags / +0xDC ExtraFlags / +0xF0 指令长度 /
//   +0x118 类型指针。特有的是 `VirtualSize`(+0x40) 在本函数里当槽偏移用，
//   `SectionField1`(+0x51?) 与 `NumberOfSections`(+0x58)、`Characteristics`(+0x78)
//   的命名来自反编译，按位置逐一对应到权威偏移。
// 【结构】三段：
//   1) 上限 0x1E：找 1369/1296/1368 得 ExportDirRva；
//   2) 按构建号 0x23F0 分两路：
//      构建号 < 0x23F0（Win7 路径）：找 1285→其后 1296(64,序2,0x40000) 置标志，
//        再遇 1368 且 +0x50 带 0x4000000 且有 +0x38 → 得 TargetRva；
//      构建号 >= 0x23F0（Win8+ 路径）：找 1341(+0x50==32, 序1, +0x88==0x800000,
//        +0x2C?==0xFFFF) 置标志，再遇 1296(64,序1,+0x88==64,标志置位) 后
//        读下一项，若 1368 且 +0x50 带 0x4000000 且有 RVA → 得 TargetRva
//        （并再读一项，若非 1368 则采用）；
//   3) 上限 0x64：从 TargetRva 起扫，1298/+0x88==0x40000 → Dst[序] = RVA；
//      1294（+0x50 带 0x14000/0x40、+0xDC 低4位!=4、+0x88==64、+0x40 落在 112..0x148
//      且 8 对齐）→ 以 (槽偏移-112)>>3 为表索引（<=0x1B），
//      把 Dst[+0x90] 写入 OutputTable[索引*0x30+4] 与 ExportDataBase+Dst 到 +8。
// 【说明】本函数的 `Label_58` 是三段共用入口，实现中以 goto 忠实还原。
// =========================================================================
char __fastcall ParseNtSectionHeaders2(
        __int64 ImageBase,
        unsigned int ImageSize,
        __int64 ExportDataBase,
        __int64 OutputTable)
{
    char Result = 0;
    ULONG ExportDirRva;
    char FoundDataSection;
    int SectionIndex;
    char FoundTargetSection;
    int SectionIndex2;
    ULONG TargetRva = 0;
    __int64 ExportDataBaseLocal;
    PE_DECODE_CONTEXT SectionContext;  // 0x48 字节解码上下文（原 __int64 仅 8 字节，栈越界）
    __int64 SectionDataRva = 0;
    _DWORD SectionEntry[112];
    ULONG LoopIndex;
    ULONG SectionEntryArray[16];

    ExportDirRva = *(unsigned int *)(*(int *)(ImageBase + 60) + ImageBase + 40);
    ExportDataBaseLocal = ExportDataBase;
    if ((unsigned int)ExportDirRva >= ImageSize)
        return Result;
    if ((int)ExportDirRva + 4096 >= (int)ImageSize)
        return Result;

    // ---- 段 1：定位导出目录（上限 0x1E）----
    FoundDataSection = 0;
    InitPESectionReadContext(ExportDirRva + ImageBase, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    SectionIndex = 0;
    while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
    {
        ULONG CurrentRva = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)SectionDataRva;
        SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
        __int16 SectionType = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);
        ULONG NewRva;

        if (SectionType == 1369)
        {
            NewRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
            if (NewRva && NewRva < ImageSize)
            {
                ExportDirRva = NewRva;
                break;
            }
        }
        else if (SectionType == 1296 &&
                 *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                 *(_DWORD *)((char *)SectionEntry + 0x58) == 1)
        {
            FoundDataSection = 1;
        }
        else if (SectionType == 1368)
        {
            if (FoundDataSection == 1)
            {
                NewRva = CurrentRva + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                if (NewRva && NewRva < ImageSize)
                {
                    ExportDirRva = NewRva;
                    break;
                }
            }
            FoundDataSection = 0;
        }
        if ((unsigned int)++SectionIndex >= 0x1E)
            break;
    }

    if ((unsigned int)ExportDirRva >= ImageSize || (int)ExportDirRva + 4096 >= (int)ImageSize)
        return Result;

    // ---- 段 2：按构建号分两路定位目标节 ----
    InitPESectionReadContext(ImageBase + ExportDirRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    FoundTargetSection = 0;
    SectionIndex2 = 0;

    if ((unsigned int)GtRead(GtWindowsBuildNumber) < 0x23F0)
    {
        // --- Win7 路径 ---
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
        {
            *(ULONG64 *)((PUCHAR)&SectionContext + 0x08) += *(unsigned int *)((PUCHAR)SectionEntry + 0xF0);   /* 【修正】推进读指针（原 ctx+0x08 槽；每轮解码前推进上一轮长度，首轮为 0）*/
            ULONG CurrentRva3 = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)SectionDataRva;
            SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
            __int16 SectionType2 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

            if (SectionType2 == 1285)
            {
                if (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
                {
                    SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
                    if (*(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1296 &&
                        *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                        *(_DWORD *)((char *)SectionEntry + 0x58) == 2 &&
                        *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
                    {
                        FoundTargetSection = 1;
                    }
                }
            }
            else if (FoundTargetSection == 1 && SectionType2 == 1368 &&
                     (*(ULONG64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
                     *(ULONG *)((char *)SectionEntry + 0x38))
            {
                TargetRva = CurrentRva3 + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                goto L_SCAN_SLOTS;
            }
            if ((unsigned int)++SectionIndex2 >= 0x1F4)
                return Result;
        }
    }
    else
    {
        // --- Win8+ 路径 ---
        while (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
        {
            SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
            __int16 SectionTypeWin7 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

            if (SectionTypeWin7 == 1341 &&
                *(__int64 *)((char *)SectionEntry + 0x50) == 32 &&
                *(_DWORD *)((char *)SectionEntry + 0x58) == 1 &&
                *(__int64 *)((char *)SectionEntry + 0x88) == 0x800000 &&
                *(_DWORD *)((char *)SectionEntry + 0x3C) == 0xFFFF)
            {
                FoundTargetSection = 1;
            }
            else if (SectionTypeWin7 == 1296 &&
                     *(__int64 *)((char *)SectionEntry + 0x50) == 64 &&
                     *(_DWORD *)((char *)SectionEntry + 0x58) == 1 &&
                     *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
                     FoundTargetSection == 1 &&
                     !(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            {
                ULONG CurrentRva2 = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)SectionDataRva;
                SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
                if (*(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) == 1368 &&
                    (*(ULONG64 *)((char *)SectionEntry + 0x50) & 0x4000000) != 0 &&
                    *(ULONG *)((char *)SectionEntry + 0x38))
                {
                    TargetRva = CurrentRva2 + *(ULONG *)((char *)SectionEntry + 0x38) - (ULONG)ImageBase;
                    if (!(unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry) &&
                        *(_WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6) != 1368)
                    {
                        goto L_SCAN_SLOTS;
                    }
                }
            }
            if ((unsigned int)++SectionIndex2 >= 0x1F4)
                return Result;
        }
    }
    return Result;

L_SCAN_SLOTS:
    // ---- 段 3：填表（上限 0x64）----
    if (!(TargetRva && TargetRva < ImageSize && TargetRva + 4096 < ImageSize))
        return Result;

    InitPESectionReadContext(ImageBase + TargetRva, 4096, 2, 0, -1, 0, 0, (__int64)&SectionContext);
    memset(SectionEntryArray, 0, sizeof(SectionEntryArray));

    for (LoopIndex = 0; LoopIndex < 0x64; LoopIndex++)
    {
        ULONG SectionCharacteristics;
        ULONG SectionAddr;
        __int16 SectionType3;

        if ((unsigned int)ReadPESectionEntry((PUCHAR)&SectionContext, (PULONG)SectionEntry))
            break;

        SectionCharacteristics = *(ULONG *)((char *)SectionEntry + 0x50);
        SectionAddr = *(ULONG *)((char *)SectionEntry + 0xF0) + (ULONG)SectionDataRva;
        SectionDataRva += *(ULONG *)((char *)SectionEntry + 0xF0);
        SectionType3 = *(WORD *)(*(__int64 *)((char *)SectionEntry + 0x118) + 6);

        if (SectionType3 == 1298 && *(__int64 *)((char *)SectionEntry + 0x88) == 0x40000)
        {
            ULONG RvaField = *(ULONG *)((char *)SectionEntry + 0x78);
            if (RvaField && *(ULONG *)((char *)SectionEntry + 0x50) == 64)
            {
                ULONG ExportRva = SectionAddr + RvaField - (ULONG)ImageBase;
                if (ExportRva && ExportRva < ImageSize)
                    SectionEntryArray[*(ULONG *)((char *)SectionEntry + 0x58)] = ExportRva;
            }
        }

        if (SectionType3 == 1294 &&
            (SectionCharacteristics & 0x14000) && (SectionCharacteristics & 0x40) &&
            (*(ULONG *)((char *)SectionEntry + 0xDC) & 0xF) != 4 &&
            *(__int64 *)((char *)SectionEntry + 0x88) == 64 &&
            (*(ULONG *)((char *)SectionEntry + 0x40) - 112) <= 0xD8 &&
            (*(ULONG *)((char *)SectionEntry + 0x40) & 7) == 0)
        {
            ULONG TableIndex = (*(ULONG *)((char *)SectionEntry + 0x40) - 112) >> 3;
            if (TableIndex <= 0x1B)
            {
                ULONG ExportAddr = SectionEntryArray[*(ULONG *)((char *)SectionEntry + 0x90)];
                if (ExportAddr && !*(_DWORD *)(OutputTable + 48 * TableIndex + 4))
                {
                    Result = 1;
                    *(_DWORD *)(OutputTable + 48 * TableIndex + 4) = ExportAddr;
                    *(_QWORD *)(OutputTable + 48 * TableIndex + 8) = ExportDataBaseLocal + ExportAddr;
                }
            }
        }
    }
    return Result;
}

// =========================================================================
// ParseExportDirForDiskInfo — 解析磁盘信息导出目录
// 对应原始驱动 0x140048410（478 字节）
// 【逆向来源】⚠ 本函数**可被 Hex-Rays 正常反编译**（90 行伪代码），按伪代码实现。
// 【参数】ImageBase / ImageSize / ExportDataBase（填入 +8 时加的基址）/ OutputTable
// 【依赖】DecodeUnicodeChar(输入指针, 缓冲末尾, 输出结构体)
//   ⚠ 第三个参数是 **0x30 字节的结构体**（IDA 栈帧给出的字段布局）：
//     +0x00 宽字符（6 WORD）  +0x0C 字段大小(FieldSize)
//     +0x10 字段偏移(FieldOffset)  +0x18 消耗字节数(CharsConsumed)
//     +0x28 字段类型指针(pFieldType)
//   本函数通过它逐条解析 NT 节区的"字段流"。
// 【结构】两段：
//   1) 上限 0x14：逐字段解码，遇类型 4302 且 (当前指针 + FieldSize) 落在文件内
//      → 把它作为新的导出目录 RVA；
//   2) 从该 RVA 起再逐字段解码：
//      类型 4280 且 FieldOffset > ExportDirSize 且 (FieldOffset-ExportDirSize) < ImageSize
//        且 FieldSize==52 → 置 FoundEntry；
//      类型 4267 且同样范围有效 → ExportSize = FieldOffset - ExportDirSize；
//      已置 FoundEntry 且类型 4280 且 FieldSize==116 → DataSize = FieldOffset - ExportDirSize，
//        然后填 28 项：**第 15 项用 DataSize，其余用 ExportSize**
//        （每项 +4=RVA、+8=ExportDataBase+RVA）。
// =========================================================================
char __fastcall ParseExportDirForDiskInfo(
        __int64 ImageBase,
        unsigned int ImageSize,
        __int64 ExportDataBase,
        __int64 OutputTable)
{
    __int64 NtHeaderOffset;
    unsigned int EntryIndex = 0;
    ULONG ExportDirRva;
    unsigned int ExportDirSize;
    unsigned __int8 *CurrentPos;
    int SectionIndex;
    unsigned __int64 SectionEnd;
    unsigned __int8 *CurrentPos2;
    unsigned int ExportSize = 0;
    char FoundEntry = 0;
    unsigned __int64 SectionEnd2;
    int CurrentType;
    unsigned int DataSize;
    _QWORD *OutputEntry;
    unsigned __int8 FieldBuf[0x30];
    char Result = 0;

    NtHeaderOffset = *(int *)(ImageBase + 60);
    ExportDirRva = *(unsigned int *)(NtHeaderOffset + ImageBase + 40);
    ExportDirSize = *(_DWORD *)(NtHeaderOffset + ImageBase + 48);
    if ((unsigned int)ExportDirRva >= ImageSize || (int)ExportDirRva + 4096 >= (int)ImageSize)
        return Result;

    // ---- 段 1：定位导出目录（上限 0x14）----
    CurrentPos = (unsigned __int8 *)(ImageBase + ExportDirRva);
    SectionIndex = 0;
    SectionEnd = ImageBase + ExportDirRva + 4096;
    while (DecodeUnicodeChar(CurrentPos, SectionEnd, (_WORD *)FieldBuf))
    {
        ULONG ExportDirRvaNew;
        CurrentPos += *(unsigned int *)(FieldBuf + 0x18);          // CharsConsumed
        if (*(int *)(FieldBuf + 0x28) == 4302)
        {
            ExportDirRvaNew = (ULONG)(ULONG_PTR)CurrentPos
                            + *(int *)(FieldBuf + 0x0C)            // FieldSize
                            - (ULONG)ImageBase;
            if (ExportDirRvaNew < ImageSize)
            {
                ExportDirRva = ExportDirRvaNew;
                break;
            }
        }
        if ((unsigned int)++SectionIndex >= 0x14)
            break;
    }

    if ((unsigned int)ExportDirRva >= ImageSize || (int)ExportDirRva + 4096 >= (int)ImageSize)
        return Result;

    // ---- 段 2：填表 ----
    CurrentPos2 = (unsigned __int8 *)(ImageBase + ExportDirRva);
    SectionEnd2 = (unsigned __int64)(CurrentPos2 + 4096);
    if (CurrentPos2 >= CurrentPos2 + 4096)
        return Result;

    while (DecodeUnicodeChar(CurrentPos2, SectionEnd2, (_WORD *)FieldBuf))
    {
        ULONG FieldOffset = *(unsigned int *)(FieldBuf + 0x10);
        ULONG FieldSize   = *(unsigned int *)(FieldBuf + 0x0C);

        CurrentType = *(int *)(FieldBuf + 0x28);

        if (CurrentType == 4280 &&
            FieldOffset > ExportDirSize &&
            ImageSize > (FieldOffset - ExportDirSize) &&
            FieldSize == 52)
        {
            FoundEntry = 1;
        }
        if (CurrentType == 4267 &&
            FieldOffset > ExportDirSize &&
            ImageSize > (FieldOffset - ExportDirSize))
        {
            ExportSize = FieldOffset - ExportDirSize;
        }
        if (FoundEntry == 1 && CurrentType == 4280 &&
            FieldOffset > ExportDirSize &&
            ImageSize > (FieldOffset - ExportDirSize) &&
            FieldSize == 116)
        {
            DataSize = FieldOffset - ExportDirSize;
            if (FieldOffset != ExportDirSize && ExportSize)
            {
                Result = 1;
                OutputEntry = (_QWORD *)(OutputTable + 8);
                do
                {
                    if (EntryIndex == 15)
                    {
                        *((_DWORD *)OutputEntry - 1) = DataSize;
                        *OutputEntry = ExportDataBase + DataSize;
                    }
                    else
                    {
                        *((_DWORD *)OutputEntry - 1) = ExportSize;
                        *OutputEntry = ExportDataBase + ExportSize;
                    }
                    ++EntryIndex;
                    OutputEntry += 6;
                }
                while (EntryIndex <= 0x1B);
            }
            return Result;
        }

        CurrentPos2 += *(unsigned int *)(FieldBuf + 0x18);
        if ((unsigned __int64)CurrentPos2 >= SectionEnd2)
            return Result;
    }
    return Result;
}