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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
    int EntryCharacteristics;
    __int64 FieldValue;
    unsigned int EntryFlags;
    __int64 FieldValue2;
    int EntrySize;
    unsigned int SectionSize;
    __int64 SectionDataPtr;

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
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    goto LABEL_13;
                MatchSize = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                if (*(_WORD *)(SectionDataPtr + 6) == 1368)
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
            SubType = *(_WORD *)(SectionDataPtr + 6);
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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
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
            Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                break;
            Offset1 = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
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
                Offset2 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
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
                Offset3 = (int)(EntryCumulSize + CumulativeSize);
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1368 && (SectionFlags & 0x4000000) != 0)
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
                CumulativeSize += EntryCumulSize;
                if (*(_WORD *)(EntryDataPtr + 6) == 1294
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
    __int64 PeContext;
    char EntryBuffer[80];
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
    InitPESectionReadContext((__int64)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, (LONG64)&PeContext, -1, 0, 0, 0);
    HasDiscardable = 0;
    HasCodeSection = 0;
    Found418 = 0;
    MsrFlag1 = 0;
    MsrFlag2 = 0;
    Phase1Offset = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            return Result;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
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
    InitPESectionReadContext((__int64)(ImageSize + Phase1Offset), DataDirRva + ImageSize - (ImageSize + Phase1Offset), 2, (LONG64)&PeContext, -1, 0, 0, 0);
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
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x430)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DB)
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
                if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
                    HasDiscardable = 1;
            }
        }
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
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
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
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
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x53D)
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
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
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
                            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512 &&
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x418)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DA)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x13E)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
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
    __int64 PeContext;
    char EntryBuffer[80];
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
    InitPESectionReadContext((__int64)(ImageBase + (unsigned int)PeFileData), DataDirRva + ImageSize - (ImageBase + (unsigned int)PeFileData), 2, (LONG64)&PeContext, -1, 0, 0, 0);
    HasDiscardable = 0;
    Phase1Offset = 0;
    Phase1Type = 0;
    Phase1Count = 0;
    while (Phase1Count < 0xC8)
    {
        if (ReadPESectionEntry((PUCHAR)&PeContext, (PULONG)EntryBuffer))
            break;
        SectionSize = *(unsigned int *)&EntryBuffer[0x38];
        CumulativeSize = *(__int64 *)&EntryBuffer[0x40];
        CumulativeSize += SectionSize;
        SectionDataPtr = *(__int64 *)&EntryBuffer[0x48];
        *(__int64 *)&EntryBuffer[0x40] = CumulativeSize;
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
            HasDiscardable = 1;
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x558)
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
        else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4D7)
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
    InitPESectionReadContext((__int64)(DataDirRva + Phase1Offset), ImageSize + DataDirRva - (DataDirRva + Phase1Offset), 2, (LONG64)&PeContext, -1, 0, 0, 0);
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
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x430)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DB)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
            {
                SectionAlignment = *(__int64 *)&EntryBuffer[0x28];
                if (SectionAlignment == 0x20 && (CumulativeSize & 0x4000))
                {
                    if (*(unsigned int *)&EntryBuffer[0x20] == (unsigned int)GtRead(0x80E))
                        HasCodeSection = 1;
                }
            }
        }
        if (*(unsigned short *)(SectionDataPtr + 6) == 0xFE)
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
            if (*(unsigned short *)(SectionDataPtr + 6) == 0x512)
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
                                if (*(unsigned short *)(SectionDataPtr + 6) == 0x512 &&
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x418)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x4DA)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x510)
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
            else if (*(unsigned short *)(SectionDataPtr + 6) == 0x53D)
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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
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
                SectionType = *(_WORD *)(SectionDataPtr2 + 6);
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
                if ((unsigned int)ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry))
                    break;
                SectionEnd2 = (int)(SectionSize + CumulativeSize);
                CumulativeSize += SectionSize;
                SectionType2 = *(_WORD *)(SectionDataPtr2 + 6);
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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
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
    PESectionByName = (unsigned int)FindPESectionByName((PUCHAR)PeBuffer, (PCHAR)FuncNameBuffer);
    PESectionByNameReturnVa = (unsigned int)FindPESectionByNameReturnVa((PUCHAR)PeBuffer, (PCHAR)FuncNameBuffer);
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
        if ((unsigned __int16)(*(_WORD *)(SectionDataPtr + 6) - 1368) <= 1u)
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
            SectionType = *(_WORD *)(SectionDataPtr + 6);
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
    __int64 ReadContext;
    __int64 CumulativeSize;
    _DWORD SectionEntry[14];
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
            Result = ReadPESectionEntry((PUCHAR)&ReadContext, SectionEntry);
            if ((_DWORD)Result)
                return Result;
            CurrentOffset = (int)(EntryCumulSize + CumulativeSize);
            CumulativeSize += EntryCumulSize;
            if (*(_WORD *)(EntryDataPtr + 6) != 1368 || (SectionFlags & 0x4000000) == 0 || !EntrySize)
            {
                if (*(_WORD *)(EntryDataPtr + 6) == 1066 && (SectionTypeInner & 0x200000000LL) != 0)
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
